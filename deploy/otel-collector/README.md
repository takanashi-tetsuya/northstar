# OpenTelemetry Collector contract

The Collector is the only component allowed to export Northstar telemetry to
external backends. Services emit bounded trace/metric/log records and remain
available when the Collector is unavailable; a bounded buffer and a drop
counter make loss observable instead of blocking request paths.

The deployment must configure:

- OTLP gRPC/HTTP receivers on a private network only;
- memory limiting and batch processors before any exporter;
- attribute filtering that removes raw JIDs, IPs, message IDs, room IDs,
  stanza bodies, passwords, SCRAM transcripts and bearer material;
- retry with a bounded queue and explicit drop metrics; and
- separate exporters/credentials per environment.

`foundation-telemetry` defines the service/rpc/event/db/kafka/stanza semantic
dimensions and rejects user-derived high-cardinality labels. Production
operators must add the backend-specific exporter and pin its image digest in
the deployment repository.
