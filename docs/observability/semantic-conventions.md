# Telemetry semantic conventions

Northstar telemetry is deliberately low-cardinality. Every record may carry
`service`, `rpc`, `event`, `db`, `kafka` and `stanza_kind` dimensions. These
are bounded, deployment-owned vocabulary values; raw user identifiers are not
valid metric labels.

Trace context uses W3C `traceparent` with non-zero trace and span IDs. The
`foundation-telemetry` validator rejects malformed context before propagation.
Correlation and causation IDs are carried as bounded metadata, never as
labels.

Normal traffic is sampled under a configured head budget. Errors and
high-latency operations are retained by the Collector tail policy. Telemetry
export is best effort with a bounded queue: when a backend is unavailable,
business work continues and the drop counter is exported when the pipeline
recovers.

Never record raw XML, message bodies, passwords, SCRAM exchanges, bearer
tokens, JIDs, IP addresses, room IDs or archive IDs. Use the security
pseudonymization boundary for the rare operational correlation that requires
one.
