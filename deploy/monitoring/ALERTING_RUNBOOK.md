# Alert receiver qualification runbook

Northstar supplies Prometheus rules, but it cannot choose an operator's pager,
chat, e-mail or managed monitoring tenant. A release is not qualified merely
because `promtool check rules` succeeds. Configure Alertmanager or an equivalent
managed receiver outside the public application network, then retain one
completed record per deployment and release candidate.

## Required controls

- Keep receiver URLs, API keys and routing identities in a mounted secret or
  the managed platform; never commit them or interpolate them into alert labels.
- Authenticate and encrypt Prometheus-to-Alertmanager and receiver traffic.
- Route `critical` and `warning` independently, with an owned escalation target
  and an explicit after-hours policy.
- Group on stable operational labels only. Do not add JIDs, usernames, domains,
  report IDs, request IDs or stanza content.
- Set bounded repeat intervals and inhibition so a database outage does not
  create an unbounded alert storm.
- Restrict silence creation and record its actor, reason and expiry. A silence
  without an expiry is not an acceptable production default.

## Qualification exercise

1. Record the Northstar commit and binary/container digest, Prometheus and
   Alertmanager/managed-service versions, rule-file SHA-256, deployment name,
   UTC start time and the people participating.
2. Inject a reversible synthetic metric or use a dedicated test rule routed to
   the real receiver. Do not stop the production database merely to test paging.
3. Record rule evaluation time, Alertmanager receipt, first notification,
   human acknowledgement and escalation time. Capture redacted screenshots or
   provider event IDs without credentials or user data.
4. Exercise one finite silence, prove that it expires, and verify that an
   unrelated `critical` route is not silenced.
5. Remove the synthetic condition and record the resolved notification. Confirm
   that the alert and its annotations contain no private or high-cardinality
   values.
6. Store the signed/tamper-controlled exercise record with release evidence and
   schedule the next drill. Repeat after receiver, routing, rule or credential
   changes.

### Isolated lab rehearsal

If a VM soak is active, wait for it to finish before changing lab processes.
Run the script's `self-test` command on an isolated lab host. The script uses
loopback only. Create a
private state directory with `init`, then generate three temporary configs
with `config`. They scrape the fixture on `127.0.0.1:18993`, evaluate
`NorthstarAlertDeliveryDrill` every five seconds with a ten-second `for`, and
route firing and resolved notifications to the fixture's loopback webhook.
The metric supplies the unique `drill_id`; the rule adds only the fixed
`severity: critical` label. Keep Prometheus and Alertmanager on loopback and
use offline, version-pinned binaries. Do not replace the deployed rule file
or interrupt Northstar to create this alert.

```sh
python3 scripts/local-alert-drill.py self-test
python3 scripts/local-alert-drill.py init PRIVATE_STATE_DIR
python3 scripts/local-alert-drill.py config PRIVATE_STATE_DIR
python3 scripts/local-alert-drill.py serve PRIVATE_STATE_DIR --port 18993
```

Use `promtool check config PRIVATE_STATE_DIR/prometheus.yml`,
`promtool check rules PRIVATE_STATE_DIR/drill-rules.yml`, and
`amtool check-config PRIVATE_STATE_DIR/alertmanager.yml` from the pinned
binaries. Start the temporary Prometheus with those files and an isolated
storage path under `PRIVATE_STATE_DIR`, listening on `127.0.0.1:19090`; start
Alertmanager with its generated file and a separate storage path, listening on
`127.0.0.1:19093`. Start `serve` first, then each of these in a separate
terminal:

```sh
prometheus --config.file=PRIVATE_STATE_DIR/prometheus.yml \
  --storage.tsdb.path=PRIVATE_STATE_DIR/prometheus-data \
  --web.listen-address=127.0.0.1:19090
alertmanager --config.file=PRIVATE_STATE_DIR/alertmanager.yml \
  --storage.path=PRIVATE_STATE_DIR/alertmanager-data \
  --web.listen-address=127.0.0.1:19093
```

If another
loopback process owns a port, create a fresh drill directory and pass distinct
port numbers to `config`; use the same fixture port for `serve`. Stop all three
temporary processes after collecting evidence. The `config` output and report
contain the config SHA-256 hashes; record binary versions and process commands
as well.

Run `python3 scripts/local-alert-drill.py on PRIVATE_STATE_DIR`, verify the
alert moves from pending to firing at Prometheus `/api/v1/alerts`, then record
Alertmanager receipt at `/api/v2/alerts` or in its own log. Save both API
responses or redacted logs with UTC timestamps and the same `drill_id`.
Verify the `firing_received` record, have the
named operator inspect the notification, and run
`python3 scripts/local-alert-drill.py ack PRIVATE_STATE_DIR --actor OPERATOR`.
Run `python3 scripts/local-alert-drill.py off PRIVATE_STATE_DIR`, wait for
the Prometheus alert to clear and for `resolved_received`, then save the output of
`python3 scripts/local-alert-drill.py report PRIVATE_STATE_DIR` and the private
`events.jsonl`. Capture the UTC time of each step and the first real receiver
notification separately. The local webhook proves the routing plumbing; it
does not prove delivery to a pager or a person. Finish the qualification with
the actual receiver and escalation route from the steps above.
The report's `fixture_sequence_complete` field checks only local event order;
it is not evidence that Prometheus or Alertmanager sent those events. Retain
their logs or API observations with the report.

This synthetic alert changes no service data, so its RTO and RPO are *not
applicable*. In the separate restore or rollback drill, record the failure
start and restored service time for RTO, and the latest durable write before
failure and latest recovered write for RPO. Record both targets before the
drill, the measured intervals and any unrecovered record IDs. Do not report
notification latency as recovery time.

## Evidence record

```text
Northstar commit / image digest:
Rules SHA-256:
Prometheus version:
Alertmanager or managed receiver version:
Deployment / UTC interval:
Warning route and owner:
Critical route and owner:
Synthetic event ID:
Evaluation -> receiver latency:
Receiver -> human acknowledgement latency:
Escalation result:
Silence actor/reason/expiry result:
Resolved notification result:
Service recovery target / measured RTO (or not applicable):
Data recovery target / measured RPO (or not applicable):
Privacy/cardinality review:
Evidence location and approver:
Open follow-up issues:
```

This drill is deployment evidence, not source-code evidence. Repository CI can
validate rule syntax and metric names but cannot prove delivery to an external
person or service.

## Clustered MUC response

`NorthstarClusterMucAuthorityRejected` means a cached actor no longer matches
its PostgreSQL room/occupancy lease. Remove the node from rotation, retain the
room epoch plus connection/occupancy identifiers from structured logs, and let
the ordered PostgreSQL reconciliation complete. Never repair this by copying a
Redis occupant hash or extending a lease manually.

For `NorthstarClusterMucOutboxBacklog`, verify PostgreSQL health, the supervised
`cluster-muc-outbox` worker heartbeat, instance authority and the target node's
exact local/SM/federated endpoint. Redis wake loss alone is not data loss: the
worker polls PostgreSQL. Do not clear an earlier per-room row merely to unblock
a later sequence.

`NorthstarClusterMucDeadLetters` is critical. Quiesce management changes for
the affected room, preserve the immutable operation UUID, event UUID/sequence,
target node and exact audience incarnation, and determine whether the endpoint
is permanently unavailable or the worker has a rendering/transport defect.
Any operator replay must reuse the original stable event identity; never create
a replacement mutation. A full dead-letter shard intentionally fails closed
and leaves the source outbox row pending until bounded cleanup frees capacity.

## PubSub and PEP admission pressure

`NorthstarPubSubMutationAdmissionPressure` means at least one mutation could
not enter the fixed process-local owner/collection/transaction gate within two
seconds, or its bounded PostgreSQL lock window expired. The request was rolled
back and answered with XMPP `resource-constraint`; it was not accepted without
its durable event projection. Compare the rejection counter with the current
waiter/active gauges, database lock telemetry and the event-outbox backlog.

Identify repeated owner or subscriber identities only in access-controlled
structured logs—never add them as metric labels. If active stays at its bound,
inspect long transactions and cross-node advisory-lock holders. Do not raise
the PostgreSQL pool size as the first response: the gate deliberately reserves
shared connections for authentication, message routing and readiness. Remove
an abusive source or repair the lock holder, then confirm waiter and active
gauges return to zero and a normal XEP-0060 publish succeeds.
