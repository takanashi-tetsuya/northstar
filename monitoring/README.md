# Northstar monitoring

The optional Compose profile starts Prometheus 3.12.0 and Grafana 13.1.0 on
loopback-only ports. Generate the external
`/etc/northstar/secrets/grafana_admin_password` (or configured equivalent)
before the first start, then run:

```sh
sudo docker compose --profile monitoring up -d
```

- Prometheus: `http://127.0.0.1:9090`
- Grafana: `http://127.0.0.1:3000` (user `admin`; password from the secret file)
- Northstar liveness: `/healthz`
- Northstar dependency readiness: `/readyz`
- Prometheus exposition: `/metrics`

`alerts.yml` contains local alerting rules but no notification receiver.
Connect Prometheus to an Alertmanager or configure an equivalent managed
receiver before production. Dashboard counters survive only in Prometheus;
Northstar's in-process counters reset on restart.

The overview dashboard includes p95 latency for authentication, selected
database service boundaries, message routing, durable outbox attempts, Redis
control-plane work and HTTP Upload. These histograms use fixed buckets and no
labels; do not add JIDs, usernames, domains or request IDs as labels. The
included thresholds are conservative starting points, not an SLA. Establish a
normal target-host baseline, then tune the alert rules and perform an actual
Alertmanager/managed-receiver notification and recovery drill.

Data-governance panels and alerts use only fixed-cardinality totals and
aggregate gauges: active holds, preserved offline evidence, active/expired
export leases, bounded cleanup, cursor rejections, hold-operation failures and
audit-export failures. Never add a hold ID,
authority reference, account, JID, room, report or request ID as a metric
label. A hold/audit failure is fail-closed: reconcile its idempotency record
and access audit before retrying, and do not bypass the database guards.

Deployment-capacity metrics are also fixed-cardinality: the PostgreSQL
authority epoch, global used/limit pairs for accounts, MUC rooms, live
bindings and retained SM rows, plus the two per-account limits. Treat a
reservation rejection as a policy/capacity event and any routable-session
lease loss as critical; the server disconnects that route fail closed.

Shared-upload metrics are fixed-cardinality as well. They expose separate
promotion, stage-deletion, object-deletion and terminal-cleanup outcomes, plus
credential-refresh, manifest-scrub and integrity failures. Queue-depth,
dead-letter, persistent-scrub-failure, capped due-obligation, oldest-overdue and
capacity-ledger-mismatch gauges
are refreshed by the supervised reconciliation worker, so scraping `/metrics`
does not create upload-table queries. Treat any integrity failure as critical;
preserve the immutable object and PostgreSQL locator evidence instead of
overwriting or manually deleting either side. A nonzero dead-letter or
persistent-scrub-failure gauge also degrades readiness and requires a fenced,
evidence-preserving reconciliation rather than a blind queue reset.
The supervised worker additionally performs a low-frequency, statement-snapshot
comparison of every trigger-maintained upload capacity counter with the durable
slot/job/cleanup facts. A mismatch is critical and is never auto-corrected,
because rewriting the ledger could erase evidence or under-account retained
object-store bytes.

OMEMO source-transfer polling exposes four unlabeled counters:
`xmpp_omemo_recovery_poll_requests_total`,
`xmpp_omemo_recovery_poll_rate_limited_total`,
`xmpp_omemo_recovery_poll_concurrency_rejected_total` and
`xmpp_omemo_recovery_poll_not_found_total`. The last intentionally combines an
unknown transfer, wrong capability and expired capability; do not split it by
reason or add IP/account/transfer labels. Sustained admission rejection should
be handled at the edge and investigated as abuse, not by increasing the
PostgreSQL connection pool.

Experimental cluster metrics deliberately expose only fixed-cardinality state
and counters. Operational state `0` is single-node/disabled and `2` is healthy;
states `1`, `3`, `4` and `5` all make `/readyz` fail. State `4` is the bounded
`durable_direct_only` mode, not a healthy substitute. Any PostgreSQL
key/instance-authority failure makes both cluster policies fail fast. Investigate
authentication/replay counter increases as security events and follow the
key/instance/listener/session/MUC recovery order in
[`docs/CLUSTERING.md`](../docs/CLUSTERING.md); never silence the readiness gate
to return a degraded node to service.

Use the [alert receiver qualification runbook](ALERTING_RUNBOOK.md) to record
delivery, escalation, finite silence and resolved-notification evidence. CI
checks rule syntax with the pinned Prometheus `promtool`, but it cannot prove
that an external receiver or on-call human was reached.
