# M04-02 observability checkpoint

The telemetry foundation now has explicit privacy and boundedness rules. It
does not claim that an OTLP backend is already provisioned for production.

## Delivered

- `DistributedTraceContext::validate` enforces W3C traceparent shape and
  rejects all-zero trace/span identifiers before propagation.
- `MetricDimensions` accepts only bounded deployment vocabulary values for
  service, RPC, event, database, Kafka and stanza kind. User-derived labels
  such as JIDs and IP addresses are rejected instead of merely sanitized.
- `BoundedTelemetryBuffer` drops the oldest record at a fixed capacity and
  exports a drop count, so an unavailable Collector cannot block business
  work or grow memory without bound.
- `SamplingPolicy` validates a bounded head-sampling percentage and tail
  latency threshold.
- `deploy/otel-collector/config.example.yaml` and
  `docs/observability/semantic-conventions.md` define private OTLP ingress,
  memory limits, batching and removal of sensitive attributes.

## Evidence

```text
cargo test --locked -p foundation-telemetry --all-targets  # 4 passed
cargo clippy --locked -p foundation-telemetry --all-targets -- -D warnings
```

Collector image pinning, backend credentials, tail-sampling processor and
cross-service Edge→Ingress→Kafka→Delivery trace evidence remain deployment
work in later M22–M25 tasks.
