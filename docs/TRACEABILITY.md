# Northstar implementation and evidence traceability

This index links selected current engineering/release controls and every `Core`
protocol profile to implementation, schema, automated harness and authoritative
documentation. The sole current backlog authority is
[KNOWN_ISSUES.md](KNOWN_ISSUES.md); archived plans and reports are historical
inputs only and never create current issue IDs or release claims. This index is
a navigation and consistency artifact: an `Implemented` row means the code
exists in this checkout, not that an external interoperability, production-load
or disaster-recovery exercise has been performed. `Verified-local` is used only
when a repository-local automated evidence path exists; the final release
record must still name the exact commit and results actually executed.

Allowed lifecycle states are `Confirmed`, `Planned`, `Implemented`,
`Verified-local`, `Verified-external`, `Accepted-boundary` and `Historical`.
The CI documentation gate validates current issue IDs only from
`KNOWN_ISSUES.md`, validates the rows present in this index, and requires every
`Core` row in the XEP matrix to appear exactly once here. Historical plans are
checked only for an explicit archive banner.

## Issue index

| Issue | State | Implementation / schema | Automated evidence | Authoritative documentation |
| --- | --- | --- | --- | --- |
| DOC-001 | Implemented | [messaging.rs](../src/xmpp/protocol/messaging.rs) | [documentation gate](../scripts/check-documentation-consistency.mjs) | [known issues](KNOWN_ISSUES.md) |
| DOC-002 | Implemented | [cluster.rs](../src/cluster.rs), [PubSub outbox](../src/db/pubsub_outbox.rs) | [documentation gate](../scripts/check-documentation-consistency.mjs) | [clustering](CLUSTERING.md) |
| DOC-003 | Implemented | [pubsub.rs](../src/xmpp/protocol/pubsub.rs) | [PubSub wire harness](../scripts/pubsub-wire-wsl.sh) | [XEP matrix](../XEP_MATRIX.md) |
| DOC-004 | Implemented | [S2S outbox](../src/db/s2s.rs) | [S2S database harness](../scripts/s2s-db-wsl.sh) | [production operations](PRODUCTION_OPERATIONS.md) |
| DOC-005 | Implemented | [cluster runtime](../src/cluster.rs) | [cluster harness](../scripts/cluster-wsl.sh) | [clustering](CLUSTERING.md) |
| DOC-006 | Implemented | [load harness](../scripts/load-1000-production-wsl.py) | [production-envelope runner](../scripts/load-1000-production-wsl.sh) | [README](../README.md) |
| DOC-007 | Implemented | [abuse authority](../src/db/abuse_keys.rs), [configuration](../src/config.rs) | [key deployment harness](../scripts/abuse-key-deployment-db-wsl.sh) | [abuse audit](ABUSE_AND_MODERATION_PRODUCTION_AUDIT.md) |
| DB-MANIFEST | Implemented | [migration 0125](../migrations/0125_registration_control_fail_closed.sql), [embedded migrator](../src/db/mod.rs) | [migration version gate](../scripts/check-migration-versions.sh), [documentation gate](../scripts/check-documentation-consistency.mjs) | [database roles](DATABASE_ROLES.md), [release checklist](RELEASE_CHECKLIST.md) |
| CORE-XML | Confirmed | [structural builder](../src/xmpp/xml_builder.rs) | [outbound XML gate](../scripts/check-outbound-xml-construction.mjs), [parser harness](../scripts/parser-robustness-wsl.sh) | [known issues](KNOWN_ISSUES.md) |
| CORE-JID | Implemented | [identity audit](../src/identity_audit.rs), [canonical JID](../src/jid.rs) | [identity audit harness](../scripts/identity-audit-db-wsl.sh) | [identity audit](IDENTITY_AUDIT.md) |
| DUR-C2S | Implemented | [durable delivery fence](../src/outbound.rs), [migration 0083](../migrations/0083_sm_durable_delivery_fences.sql) | [SM database harness](../scripts/sm-db-wsl.sh), [offline replay harness](../scripts/offline-replay-db-wsl.sh) | [architecture](ARCHITECTURE.md) |
| DUR-S2S-NOSTORE | Implemented | [S2S routing](../src/s2s/outbound.rs) | [federation harness](../scripts/federation-wsl.sh) | [production operations](PRODUCTION_OPERATIONS.md) |
| DUR-PUBSUB | Implemented | [event outbox](../src/db/pubsub_outbox.rs), [migration 0085](../migrations/0085_pubsub_event_outbox.sql) | [outbox database harness](../scripts/pubsub-outbox-db-wsl.sh) | [outbox design](PUBSUB_EVENT_OUTBOX.md) |
| SEC-POW | Implemented | [anti-abuse service](../src/abuse.rs), [migration 0084](../migrations/0084_pow_intent_v2.sql) | [PoW gate](../scripts/check-abuse.mjs), [database harness](../scripts/message-pow-db-wsl.sh) | [PoW v2 design](POW_INTENT_V2.md) |
| SEC-BACKUP | Verified-local | [backup verifier](../scripts/backup-security.py) | [offline fault harness](../scripts/backup-security-offline.sh) | [backup security](BACKUP_SECURITY.md) |
| ARCH-SVC | Implemented | [PubSub application service](../src/services/pubsub.rs), [application state](../src/state.rs) | [architecture budget](../scripts/check-architecture-boundaries.mjs) | [architecture](ARCHITECTURE.md) |
| CLU-POLICY | Implemented | [cluster failure state machine](../src/cluster.rs), [configuration](../src/config.rs) | Experimental: pure policy/recovery-order models plus [cluster harness](../scripts/cluster-wsl.sh); runtime execution remains a release gate | [clustering](CLUSTERING.md) |
| CLU-SIGN | Implemented | [signed envelopes](../src/cluster_security.rs), [key/instance/replay authority](../src/db/cluster_keys.rs), [migration 0088](../migrations/0088_cluster_key_authority.sql), [persistent replay migration 0095](../migrations/0095_cluster_replay_fence.sql) | Experimental: pure tamper/replay/ACL/key-overlap/instance-fence models plus [cluster harness](../scripts/cluster-wsl.sh); runtime execution remains a release gate | [clustering](CLUSTERING.md) |
| CLU-MUC | Implemented | [MUC application service](../src/services/muc.rs), [MUC authority/outbox](../src/db/cluster_muc.rs), [migration 0089](../migrations/0089_cluster_muc_authority.sql), [transport receipt/handoff migration 0094](../migrations/0094_cluster_muc_delivery_receipts.sql) | Experimental: pure exact actor/target, self-registration, invitation-membership, nickname-ABA, stable operation/event, recreated-room epoch, bounded-retention and SQL-fence models plus ignored PostgreSQL/[two-node fixture](../scripts/muc-cluster-wsl.sh); runtime execution remains a release gate | [clustering](CLUSTERING.md), [known issues](KNOWN_ISSUES.md) |
| CLU-STORAGE | Implemented | [upload store](../src/storage.rs), [direct-final S3 backend](../src/storage/s3.rs), [durable cleanup/scrub worker](../src/upload_worker.rs), [migration 0091](../migrations/0091_shared_upload_storage.sql) | Runtime qualification pending: pure fake-store crash/late-appearance/node-A→node-B/client-swap tests plus an ignored [loopback MinIO fixture](../deploy/docker-compose.minio-test.yml); target-provider two-node, kill-point, rotation, lifecycle and restore runs remain release gates | [upload storage contract](UPLOAD_STORAGE.md), [clustering](CLUSTERING.md) |
| CLU-QUOTA | Implemented | [capacity ledger](../src/db/capacity.rs), [migration 0090](../migrations/0090_deployment_capacity_ledger.sql), [configuration](../src/config.rs) | pure shard/authority/error tests and ignored isolated-PostgreSQL global/owner/lease fixture; multi-node crash run remains a release gate | [capacity design](DEPLOYMENT_CAPACITY.md) |
| CLU-KEY | Implemented | [key authority](../src/db/abuse_keys.rs), [migration 0082](../migrations/0082_abuse_key_deployment.sql) | [key deployment harness](../scripts/abuse-key-deployment-db-wsl.sh) | [abuse audit](ABUSE_AND_MODERATION_PRODUCTION_AUDIT.md) |
| CLU-TEST | Implemented | [cluster harness](../scripts/cluster-wsl.py), [MUC fixture](../scripts/muc-cluster-wsl.sh) | Experimental source-defined Redis/PG direction, signature tamper/replay/version, instance/key lease and CLU-MUC recovery cases; execution remains a separately authorized isolated release gate | [clustering](CLUSTERING.md), [known issues](KNOWN_ISSUES.md) |
| FED-REVOCATION | Implemented | [CRL classification and certificate-session registry](../src/crl.rs), [atomic generation/reload](../src/tls.rs), [C2S lifecycle](../src/xmpp/protocol.rs), [S2S lifecycle](../src/s2s) | pure exact-cancellation/classification/pin-policy tests plus [generated CRL fixture](../scripts/generate-crl-fixture-wsl.sh); external CA rotation remains a release gate | [production operations](PRODUCTION_OPERATIONS.md) |
| FED-CERT | Implemented | [TLS policy](../src/tls.rs), [per-connection binding selection](../src/xmpp/mod.rs) | [TLS unit tests](../src/tls.rs), [TLS security harness](../scripts/test-certificate-security.sh) | [production operations](PRODUCTION_OPERATIONS.md); external RSA/ECDSA/Ed25519 TLS matrix remains a release gate |
| FED-S2S | Accepted-boundary | [S2S implementation](../src/s2s) | [federation harness](../scripts/federation-wsl.sh) | [XEP matrix](../XEP_MATRIX.md) |
| FED-COMPONENT | Accepted-boundary | [component implementation](../src/components.rs) | [component harness](../scripts/component-runtime-wsl.sh) | [component evidence](COMPONENT_PROTOCOL_EVIDENCE.md) |
| FED-BOSH | Accepted-boundary | [BOSH implementation](../src/bosh.rs), [bounded ACK ownership migration](../migrations/0096_bosh_ack_ownership_bounds.sql) | [transport conformance](../scripts/transport-conformance.py) plus pure count/byte/age models | [production operations](PRODUCTION_OPERATIONS.md) |
| DATA-RETENTION | Implemented | [policy and hold-aware retention worker](../src/retention.rs), [data lifecycle storage](../src/db/data_lifecycle.rs) | [retention database harness](../scripts/retention-db-wsl.sh) | [data lifecycle contract](DATA_LIFECYCLE.md); ignored PostgreSQL fixture remains an explicit release gate |
| DATA-HOLD | Implemented | [typed hold storage, frozen export leases and keyset/hash continuation](../src/db/data_lifecycle.rs), [signed scope-bound governance API](../src/api/data_lifecycle.rs), [lease migration](../migrations/0092_governance_export_pagination.sql) | [retention database harness](../scripts/retention-db-wsl.sh), pure cursor/chain tests | [data lifecycle contract](DATA_LIFECYCLE.md); external legal authority is a deployment boundary |
| DATA-AUDIT | Implemented | [immutable bounded audit storage, fixed high-water lease and chained keyset export](../src/db/data_lifecycle.rs), [signed scope-bound governance API](../src/api/data_lifecycle.rs), [lease migration](../migrations/0092_governance_export_pagination.sql) | [retention database harness](../scripts/retention-db-wsl.sh), pure cursor/chain tests | [data lifecycle contract](DATA_LIFECYCLE.md); chain roots require independent WORM/KMS anchoring |
| API-MAM | Implemented | [history API](../src/api/users.rs) | [MAM database harness](../scripts/mam-db-wsl.sh) | [OpenAPI](openapi.yaml) |
| API-DOCS | Implemented | [HTTP router](../src/api/mod.rs), [pinned Swagger UI](../third_party/swagger-ui/README.md) | [Swagger artifact gate](../scripts/verify-swagger-ui-artifacts.mjs) | [OpenAPI](openapi.yaml) |
| OPS-METRICS | Implemented | [metrics registry](../src/metrics.rs) | [metrics unit tests](../src/metrics.rs) | [production operations](PRODUCTION_OPERATIONS.md) |
| OPS-ALERT | Planned | [Prometheus rules](../monitoring/alerts.yml) | [release preflight](../scripts/release-preflight.sh) | [receiver qualification runbook](../monitoring/ALERTING_RUNBOOK.md) |
| UPLOAD-DELETE | Implemented | [upload API](../src/api/upload.rs), [upload storage](../src/db/upload.rs) | [upload database harness](../scripts/upload-db-wsl.sh) | [OpenAPI](openapi.yaml) |
| UPLOAD-SCAN | Accepted-boundary | [upload API](../src/api/upload.rs) | [upload archive verifier](../scripts/verify-upload-archive.py) | [current DESIGN-UPLOAD-SCAN boundary](KNOWN_ISSUES.md), [upload storage contract](UPLOAD_STORAGE.md) |
| ADMIN-AMBIGUITY | Implemented | [operation runtime](../src/operation_runtime.rs), [operations API](../src/api/operations.rs) | [operation database harness](../scripts/api-operations-db-wsl.sh) | [OpenAPI](openapi.yaml) |
| WEB-KEY-MIGRATION | Implemented | [one-time transfer crypto](../web/omemo-recovery.mjs), [browser device fence](../web/omemo.js), [server authority](../src/db/omemo_recovery.rs), [migration 0093](../migrations/0093_omemo_recovery_transfer.sql) | [package/authentication gate](../scripts/check-omemo-recovery.mjs), [OMEMO static gate](../scripts/check-omemo.mjs), ignored isolated-PostgreSQL single-consumer fixture; two-browser runtime remains a release gate | [device-transfer threat model](OMEMO_DEVICE_TRANSFER.md) |
| WEB-INTEROP | Planned | [browser client](../web/client.js) | [browser E2E](../scripts/web-e2e.cjs) | [current EXT-CLIENT gate](KNOWN_ISSUES.md), [release checklist](RELEASE_CHECKLIST.md) |
| WEB-SUPPLY-CHAIN | Accepted-boundary | [vendored source and qualification record](../third_party/libomemo.js/README.md) | [archive/WASM audit](../scripts/audit-libomemo-source.mjs), [fail-closed qualification gate](../scripts/verify-libomemo-rebuild-qualification.mjs), [offline two-builder runner](../scripts/rebuild-libomemo-hermetic.mjs) | [supply-chain policy](WEB_CRYPTO_SUPPLY_CHAIN.md); 2.0.2 provenance is traced but missing compiler/signature/npm evidence prevents a reproducible-source claim |

## Core protocol evidence

Each row points to the narrowest repository harness that includes the named
profile. A harness reference does not claim that it ran for the current commit;
the release evidence record must retain its exit result and environment.

| Standard | Automated evidence |
| --- | --- |
| RFC 7395 | [transport conformance](../scripts/transport-conformance.py) |
| XEP-0124 | [transport conformance](../scripts/transport-conformance.py) |
| XEP-0206 | [integration harness](../scripts/integration-wsl.py) |
| XEP-0030 | [integration harness](../scripts/integration-wsl.py) |
| XEP-0004 | [PubSub wire harness](../scripts/pubsub-wire-wsl.py) |
| XEP-0016 | [privacy database harness](../scripts/privacy-db-wsl.sh) |
| XEP-0048 | [profile storage harness](../scripts/profile-storage-runtime-wsl.py) |
| XEP-0049 | [profile storage harness](../scripts/profile-storage-runtime-wsl.py) |
| XEP-0050 | [authentication/admin harness](../scripts/auth-admin-db-wsl.sh) |
| XEP-0059 | [MAM database harness](../scripts/mam-db-wsl.sh) |
| XEP-0060 | [PubSub database harness](../scripts/pubsub-db-wsl.sh) |
| XEP-0163 | [OMEMO runtime harness](../scripts/omemo-runtime-wsl.py) |
| XEP-0248 | [PubSub database harness](../scripts/pubsub-db-wsl.sh) |
| XEP-0077 | [message PoW wire harness](../scripts/message-pow-wire-wsl.py) |
| XEP-0084 | [profile storage harness](../scripts/profile-storage-runtime-wsl.py) |
| XEP-0082 | [integration harness](../scripts/integration-wsl.py) |
| XEP-0092 | [integration harness](../scripts/integration-wsl.py) |
| XEP-0114 | [component runtime harness](../scripts/component-runtime-wsl.py) |
| XEP-0157 | [integration harness](../scripts/integration-wsl.py) |
| XEP-0115 | [integration harness](../scripts/integration-wsl.py) |
| XEP-0133 | [authentication/admin harness](../scripts/auth-admin-db-wsl.sh) |
| XEP-0153 | [profile storage harness](../scripts/profile-storage-runtime-wsl.py) |
| XEP-0184 | [integration harness](../scripts/integration-wsl.py) |
| XEP-0185 | [federation harness](../scripts/federation-wsl.py) |
| XEP-0191 | [integration harness](../scripts/integration-wsl.py) |
| XEP-0198 | [SM database harness](../scripts/sm-db-wsl.sh) |
| XEP-0199 | [1,000-session harness](../scripts/load-1000-production-wsl.py) |
| XEP-0202 | [integration harness](../scripts/integration-wsl.py) |
| XEP-0203 | [integration harness](../scripts/integration-wsl.py) |
| XEP-0215 | [integration harness](../scripts/integration-wsl.py) |
| XEP-0223 | [PubSub wire harness](../scripts/pubsub-wire-wsl.py) |
| XEP-0220 | [federation harness](../scripts/federation-wsl.py) |
| XEP-0227 | [PIE database harness](../scripts/pie-db-wsl.sh) |
| XEP-0237 | [integration harness](../scripts/integration-wsl.py) |
| XEP-0280 | [cluster harness](../scripts/cluster-wsl.py) |
| XEP-0313 | [MAM database harness](../scripts/mam-db-wsl.sh) |
| XEP-0320 | [Jingle full-JID gate](../scripts/test-jingle-full-jid-gate.py) |
| XEP-0334 | [integration harness](../scripts/integration-wsl.py) |
| XEP-0352 | [integration harness](../scripts/integration-wsl.py) |
| XEP-0353 | [integration harness](../scripts/integration-wsl.py) |
| XEP-0359 | [message restart harness](../scripts/message-family-restart-wsl.py) |
| XEP-0363 | [upload database harness](../scripts/upload-db-wsl.sh) |
| XEP-0369 | [MIX runtime harness](../scripts/mix-runtime-wsl.py) |
| XEP-0386 | [integration harness](../scripts/integration-wsl.py) |
| XEP-0388 | [integration harness](../scripts/integration-wsl.py) |
| XEP-0398 | [profile storage harness](../scripts/profile-storage-runtime-wsl.py) |
| XEP-0402 | [profile storage harness](../scripts/profile-storage-runtime-wsl.py) |
| XEP-0403 | [MIX runtime harness](../scripts/mix-runtime-wsl.py) |
| XEP-0404 | [MIX runtime harness](../scripts/mix-runtime-wsl.py) |
| XEP-0405 | [MIX federation harness](../scripts/mix-federation-runtime-wsl.py) |
| XEP-0406 | [MIX database harness](../scripts/mix-family-db-wsl.sh) |
| XEP-0407 | [MIX runtime harness](../scripts/mix-runtime-wsl.py) |
| XEP-0410 | [MUC database harness](../scripts/muc-db-wsl.sh) |
| XEP-0421 | [MUC database harness](../scripts/muc-db-wsl.sh) |
| XEP-0424 | [message restart harness](../scripts/message-family-restart-wsl.py) |
| XEP-0425 | [MUC database harness](../scripts/muc-db-wsl.sh) |
| XEP-0440 | [authentication/admin harness](../scripts/auth-admin-db-wsl.sh) |
| XEP-0441 | [MAM database harness](../scripts/mam-db-wsl.sh) |
| XEP-0478 | [parser robustness harness](../scripts/parser-robustness-wsl.sh) |
| XEP-0484 | [authentication/admin harness](../scripts/auth-admin-db-wsl.sh) |

## Evidence interpretation

- Repository unit and fixture paths are automated-local evidence only after
  their result is captured for the exact checkout.
- A PostgreSQL, Redis, browser, Gajim, federation, load or restore script is not
  silently executed by this index.
- Standards marked `Partial`, `Experimental` or `Pass-through` remain governed
  by the exact scope in the XEP matrix and are not promoted by omission here.
- External DNS, certificates, independent peers, target hardware, notification
  receivers and third-party audit evidence must be recorded outside the source
  tree and linked from the release record.
