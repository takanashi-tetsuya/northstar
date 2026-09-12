# Migration ledger: `northstar-xep-0191`

## Scope

This crate extracts XEP-0191 command parsing, canonical blocking-pattern
matching, safe response fragments and deterministic presence-transition
planning. It is capability-free: it receives already authorized roster and
directed-presence facts and returns an explicit effect plan.

## Legacy mapping

| Legacy location | Extracted responsibility |
| --- | --- |
| `src/xmpp/protocol/blocking.rs` | strict IQ command parsing and safe blocklist/push payloads |
| `src/xmpp/xml_util.rs` blocking helpers | canonical `BlockPattern` matching and bounded item validation |
| `src/services/blocking.rs` | application adapter will authorize, transact and execute `BlockingMutation` plans |
| `src/db/roster.rs` block matching | shared canonical pattern semantics; SQL persistence remains outside this crate |

## Authority boundary

The crate cannot access PostgreSQL, Redis, session tables, transports,
`AppState`, clocks or randomness. Account authentication, atomic persistence,
cluster fan-out, push delivery, presence snapshots and transport failure policy
belong to the blocking/roster application service.

Read-only `GetBlocklist` is structurally separate from `BlockingMutation`.
Consequently a query cannot accidentally generate pushes or presence changes.
The application service must derive the `changed` pattern set in the same
transaction that updates durable blocking truth, then execute or durably queue
the returned effects.

## Relationship to XEP-0016

XEP-0191 and privacy lists must not maintain independent policy truth. A future
`northstar-roster-policy` application library will own the effective inbound
and outbound decision and translate XEP-0191 mutations into the default privacy
policy where compatibility is enabled. Neither wire crate may call the other or
own persistence.

## Integration steps

1. Remove the temporary crate-local `[workspace]` and add the crate to the root
   workspace.
2. Adapt the blocking IQ route to `parse_iq`; map typed errors to the existing
   stanza error vocabulary.
3. Move authorization and the database transaction behind a blocking
   application-service interface.
4. Compute `changed` patterns from the committed mutation and pass immutable
   roster/directed-presence facts to `plan_blocking_effects`.
5. Deliver pushes only to resources that requested the blocklist and durably
   reconcile a missed push before accepting further blocking commands on that
   resource.
6. Execute presence transitions through the presence service; do not give this
   crate transport or session-table access.
7. Delete root duplicate parsers/matchers only after XEP-0191, XEP-0016,
   multi-resource push and presence transition suites pass.
