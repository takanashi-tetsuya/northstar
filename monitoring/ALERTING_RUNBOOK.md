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
