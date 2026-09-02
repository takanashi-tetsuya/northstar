# Changelog

All notable Northstar changes are documented here. Protocol support claims are
normative only in [XEP_MATRIX.md](XEP_MATRIX.md), and unresolved release
boundaries are normative only in [docs/KNOWN_ISSUES.md](docs/KNOWN_ISSUES.md).

## [0.2.0] - 2026-09-01

- The complete change set from the previous committed `0.1.0` baseline is
  recorded in the [0.2 development changelog](changelog/v0.2.md).
- Cargo, Compose, OCI, backup and OpenAPI metadata now identify the current
  pre-1.0 development line as `0.2.0`. Version `1.0.0` is reserved until one
  exact artifact and target environment satisfy every applicable production
  qualification gate in the release checklist.
- Rebuilt the current documentation set around one compatibility matrix, one
  known-issues register, an operations manual, a release checklist and an
  explicitly historical archive; added a loopback-only development profile and
  contributor/security policies.
- Pinned the release Rust toolchain, added Cargo repository metadata, and added
  OCI source/revision/version/license labels plus project license notices to all
  Northstar images.
- Added tag-driven release preparation for `0.2.0`. It builds a complete Linux
  AMD64 tarball plus raw ELF binary and a complete Windows AMD64 ZIP plus raw
  executable, generates `SHA256SUMS` and GitHub build provenance, publishes the
  `northstar`, `northstar-backup` and `northstar-database-grants` Linux AMD64
  images to GHCR, records their exact refs in `IMAGE_DIGESTS`, and prepares a
  draft GitHub Release for manual review. This changelog does not claim that the
  draft has been published or predeclare hashes from a run that has not occurred.
- Added `deploy/docker-compose.release.yml` for deploying the three release
  images without a local build. It requires Docker Compose `2.24.4` or newer;
  production operators replace the convenient `:0.2.0` defaults with the exact
  digest refs from the successful tag run.
- Added a side-effect-free `xmpp-server --version` identity check. Linux AMD64
  remains the production baseline; the Windows AMD64 package is for development
  and evaluation.
- Production preflight now validates the independent command database role and
  fails closed when its Compose/Docker validation cannot run. Parser fuzzing now
  joins the heavy runtime envelopes as a scheduled/manual-only CI job instead
  of running on ordinary push or pull-request events.
- Hardened incremental XML framing against stale UTF-8 byte offsets when a
  defensive adapter replaces a rejected incomplete buffer. RFC 7395 parsing now
  explicitly resets pending per-message scan state without discarding the XML
  entity's declaration state.
- PubSub Atom notification summaries now enforce their byte ceiling at a UTF-8
  character boundary instead of panicking when the limit intersects a
  multibyte character.
- Registration now fails closed if its durable runtime control row is missing;
  migration `0125` replaces the capability without weakening schema or role
  isolation. `INVITATION_REQUIRED` is documented as the shared REST/XEP-0077
  invitation-policy switch.
- CI now hashes canonical LF-only migration bytes, pins the exact Rust 1.97.1
  builder digest, uses a genuinely loopback PostgreSQL runtime fixture, and
  exercises production-shaped upload capacity and disaster-recovery rollback.
- CI runtime fixtures now emit redacted, fixture-specific failure annotations,
  so failures remain diagnosable without replaying privileged or adversarial
  network tests on a developer workstation. The two-domain federation fixture
  also retries harmless duplicate ephemeral-port selections while keeping
  explicit operator-supplied port collisions fatal.
- The quoted-schema database-role fixture now replays each ordinary migration
  in its own transaction while honoring explicit `-- no-transaction`
  migrations, matching SQLx's migration contract. This preserves the atomic
  table-lock cut-overs in `0126`/`0128` without placing concurrent-index
  migrations `0035`–`0037` in an invalid transaction block.
- Runtime schema attestation now follows the connection's already pinned
  schema, so privilege-separated and isolated-schema deployments cannot read a
  different `public` migration ledger. Authentication database fixtures also
  use one fresh schema per exact test.
- Strict XEP-0198 same-device policy no longer issues an unusable resume bearer
  to legacy SASL clients that cannot present a SASL2/XEP-0388 device UUID; they
  retain ordinary Stream Management with `resume=false`.
- Competing XEP-0198 resume claims are now event driven. Migration `0127`
  versions every durable SM transition and emits a commit-ordered,
  schema/session/version-only PostgreSQL notification. A supervised dedicated
  listener fans these hints into race-safe session watches; subscribe-then-
  recheck closes lost wakeups, while exact route/cancellation/database lease
  boundaries replace the former fixed 10 ms and 500 ms polling loops.
- Migration `0127` now uses PostgreSQL's unqualified `LEAST`/`GREATEST`
  special expressions. Schema-qualifying these parser expressions as catalog
  functions made a fresh migration fail before the server could start; both
  static SQL guards and the authenticated migration ledger cover the repair.
- SM notifications now advance a one-shot process-local edge sequence instead
  of trusting the retained payload version for deduplication. A stale or forged
  high `state_version` causes at most one extra authoritative read and cannot
  make the waiter spin or suppress a later lower real notification.
- Pending resume claims release their process memory reservation between
  authority probes. Exact local live owners may be cancelled only when the
  full JID, connection, account and SM session incarnation all match; cross-node
  ownership remains database-authoritative. Listener reconnect generation,
  participant RAII and Arc-identity cleanup prevent silent notification gaps
  and stale watch-slot accumulation.
- Counted durable stanzas on connections without active Stream Management now
  remain owned by the socket write-boundary completion path. A debug-only
  assertion previously treated this valid path as impossible and could panic a
  C2S WebSocket actor during ordinary durable delivery.
- Administrative kick and actor shutdown now complete one exact RFC 7395
  terminal sequence. Live writes remain cancellable, but the already-latched
  cancellation can no longer cancel its own `<close/>` and WebSocket Close
  frames; a one-shot state prevents duplicate shutdown sequences.
- Explicit terminal protocol actions now own the whole bounded WebSocket
  sequence: final IQ replies, any terminal stanza, the RFC 7395 `<close/>`, and
  the WebSocket Close frame. Account deletion and password replacement may
  revoke every account resource before returning, but that cancellation can no
  longer overtake the initiating connection's final result; ordinary live and
  Stream Management writes remain cancellation-aware.
- Upload capability projections now explicitly convert the historical
  `VARCHAR(255)` content type to their declared PostgreSQL `TEXT` return type,
  preventing first PUT and public-file retrieval failures.
- Federated MIX-PAM completion now distinguishes direct `<join/>` and
  `<leave/>` success payloads. Remote leave previously reached the strict join
  parser, leaving the local PAM operation pending until timeout even though the
  peer had completed it successfully.
- Orderly shutdown now drains the already-claimed MIX and PAM delivery batch
  before its worker exits. This prevents a cancelled future from retaining the
  per-recipient head lease and blocking post-restart messages until lease
  expiry.
- Upload database fixtures now isolate incompatible immutable capacity-policy
  profiles in separate schemas. Authentication publication tests also verify
  that expiry cleanup uses `SKIP LOCKED` without deleting a protected lease,
  then reclaims it after the publication transaction releases the lock.
- Protocol integration now treats the equivalent XML empty-element forms
  `<unblock/>` and `<unblock></unblock>` alike. The abuse-key rotation test also
  expires each generated proof while exercising issuance-window continuity, so
  the independent active-challenge ceiling cannot mask the intended boundary.
- Orderly server shutdown now closes outbound S2S actors at debug level without
  incrementing federation-failure metrics. Cancellation diagnostics distinguish
  that lifecycle event from a live certificate session explicitly revoked by
  the active CRL.
- Single-node MUC subject changes now use their own transactionally authorized
  path instead of requiring a clustered occupancy row. Local and federated room
  actors are revalidated against the exact room epoch, account/affiliation and
  role before the subject changes; plaintext subjects update room state without
  entering MAM when encrypted-only archive policy is active. Clustered rooms
  continue to use their durable operation/outbox path.
- CI protocol fixtures now use an explicit RFC-compatible low-cost SCRAM profile
  instead of running production password-hardening parameters in a debug build,
  and isolate runtime logs. Concurrent report/appeal validation now treats the
  global idempotency admission lock's documented `Busy` result as retryable
  rather than as an impossible test outcome.
- Single-node federated MUC moderators can now approve voice requests without a
  nonexistent clustered occupancy row. The room, authenticated remote actor and
  target transport incarnation are revalidated under the room mutation gate
  before the participant role is broadcast.
- Message retraction tombstones retain only structurally valid direct
  XEP-0359 `stanza-id` elements, and personal MAM output reasserts the queried
  account's archive UUID as its authoritative ID. This repairs historical
  tombstones while preserving valid provenance from other authorities.
- The concurrent PoW capacity regression now expires the exact challenge
  returned by its successful account request, so challenges created by earlier
  isolated-database cases cannot make the restart/capacity assertion flaky. It
  also removes only the challenge UUIDs and randomized global-capacity rows it
  created before the next test reuses that isolated schema.
- The federation no-store persistence probe now terminates its temporary
  PL/pgSQL trigger function correctly; the missing dollar-quote delimiter had
  stopped the fixture before it could exercise the live S2S route.
- The same federation probe now sets its isolated schema through connection
  options. Its former `SET; SELECT` command returned `SET\n0`, falsely
  reporting persisted content even though every durable projection count was
  zero; the exact zero-persistence assertion remains unchanged.
- OMEMO 2/SCE validation now keeps XEP-0420's required direct `<store/>`
  structural marker separate from XEP-0334 persistence policy. A message that
  also carries `<no-store/>` is accepted for an existing authenticated live S2S
  route while remaining ineligible for the S2S outbox, MAM and offline storage;
  omitting the required `<store/>` from a payload message remains an error.
  Failed volatile route admission now emits a domain-only debug diagnostic
  without logging stanza content.
- Protocol integration derives its exact six-row personal archive delta from
  a pre-flow baseline, accounting for one retained self-message tombstone, its
  separately auditable retraction action and both owner projections of two
  encrypted peer messages. It also verifies the tombstone/action shapes.
- The session-identity PostgreSQL fixture now creates a structurally valid
  capability-backed admin command session after migration 0108 made its
  32-byte bearer hash mandatory.
- The durable MUC-invitation failure fixture now includes the complete
  retention and legal-hold authority relations read by production admission,
  and uses fully addressed server-authoritative federation stanzas. It now
  proves that the injected outbox trigger is the actual failure source before
  checking transaction rollback, instead of passing because of a missing
  fixture relation or pre-admission stanza validation.
- Runtime table privileges now come from one complete positive relation
  manifest rather than a broad CRUD grant followed by exception revocations.
  Grant reconciliation, existing-volume audit, Rust startup attestation and
  static migration-lifecycle checks consume the same per-table SELECT/INSERT/
  UPDATE/DELETE policy. A new, removed or reclassified table that is not
  reflected in the manifest fails closed; owner-held tables, immutable
  journals and MIX capacity authorities retain their exact least-privilege
  profiles.
- The MIX runtime fixture now establishes an ordered recipient outbox/capability
  barrier before live group delivery, separates C2S admission from asynchronous
  delivery, keeps the normal delivery deadline so latency regressions remain
  visible, and retains fixture-owned rolling logs on failure.
- MIX capacity release is now a write-once, transactionally consumed
  PostgreSQL journal rather than a
  hot-bucket mutation in the delivered stanza's ACK transaction. Recipient and
  final event deletion atomically append independent release facts without a
  capacity advisory lock; the next producer folds every currently eligible
  fact into the exact ledger before checking the row/byte ceilings. All
  delivery-producing application-service operations share a fair clone-safe
  gate before PgPool checkout, then take the blocking schema-local database
  fence as the transaction's first statement. Same-process contention neither
  consumes waiting pool connections nor becomes a false capacity rejection;
  cross-process writers wait before owning any business row lock. Normal ACKs
  therefore cannot return `55P03` merely
  because another producer is reserving capacity. ACK deletes only its exact
  leased recipient, so even a 5,000-recipient event has no shared completion
  lock; bounded `SKIP LOCKED` GC remains a maintenance optimization for empty
  events and sequence rows, not the admission correctness path.
  Runtime has read-only access to release facts: owner-held trigger functions
  append them and one allowlisted SECURITY DEFINER drain applies and deletes
  them atomically. The existing event-leading recipient unique index keeps
  drain/GC parent probes indexed at the 100,000-row queue ceiling.
  Concurrent dead-letter requeues elect one event-template creator with
  `INSERT ... ON CONFLICT DO NOTHING RETURNING`, so only the physical creator
  reserves template capacity, and multi-recipient producers acquire global
  recipient sequence rows in canonical JID order.
  PostgreSQL/I/O failure leaves the durable 90-second lease for ordinary
  at-least-once recovery instead of entering a timing-based retry loop, and the
  authoritative stanza ID remains the recipient-side deduplication key.
  The isolated MIX database suite now holds the producer fence while committing
  an ACK, then proves release reconciliation rollback and committed recovery are
  both exact.
  Migration 0126 is a stopped-writer cut-over: every pre-0126 runtime and MIX
  worker must be stopped before it is applied, and old/new writers must not run
  concurrently.
- Migration 0128 makes capacity reclamation authoritative instead of
  timing-dependent. MIX delivery orphan cleanup and release-ledger folding
  commit before producer admission, so a later hard-cap rejection cannot roll
  back the progress needed to leave a false-full state. A completion that
  commits after that reconciliation is a later linearized state transition;
  the following admission observes it without relying on a fixed retry count,
  worker page size or maintenance cadence.
- MIX-PAM now uses owner-maintained exact global/per-account counters under a
  fixed lock order. A clone-shared FIFO service gate precedes PgPool checkout;
  runtime has no direct counter or operation INSERT/DELETE authority, and the
  insertion capability atomically revalidates the enabled account, pending
  membership and durable S2S outbox projection. Startup fails closed on counter
  drift. The 10,000-global/64-per-account ceilings remain explicit hard resource
  boundaries, not contention or reclamation retries.
- The asynchronous verified-capability presence fallback is now an atomic
  insert-if-absent operation under the channel lock. A delayed capability job
  can no longer overwrite a newer explicit MIX presence such as
  `<show>away</show>` with a synthetic empty available state.
- XEP-0115 processing now keeps one authoritative observation per accepted
  available full JID. Local ownership is fenced by the exact connection and
  observation generation; federated ownership adds both the authenticated
  connection and a same-stream observation ID. Available/unavailable changes,
  disco correlation and their PEP/MIX side effects cross the same per-resource
  ordering boundary, so a stale response or teardown cannot recreate a newer
  resource state.
- Verified observations retain the complete bounded `+notify` projection and
  the two MIX feature decisions they consume. Raw disco XML and cross-resource
  summary reuse are optional byte-bounded caches: expiry or eviction can cause
  another query or a disco proxy miss, but cannot change PEP/MIX interest.
  Pending effect bits live on the observation; the bounded wake queue is only a
  deduplicated scheduling hint. Saturation/worker restart requests an immediate
  rescan, while failures sleep to the earliest retained retry deadline; separate
  alternating local/federated ready queues prevent starvation without a fixed
  polling loop. Retry timestamps affect when work runs, never whether accepted
  semantic work still exists. Explicit global/per-domain federated-resource
  ceilings reject the presence with `resource-constraint` before routing.
  Independent observation-summary byte pressure leaves verification pending
  for later retry instead of
  recording truncated or negative OMEMO/PEP/MIX interest.
- Production qualification still requires the target-environment and external
  gates in [the release checklist](docs/RELEASE_CHECKLIST.md).

## [0.1.0] - Historical baseline

- Initial pre-1.0 Northstar baseline at Git commit
  `998396915ab38a9deadf47ae871be561e11f7ef2`, with migrations `0001`–`0013`.
- The complete delta from this baseline to `0.2.0` is maintained in
  [the 0.2 development changelog](changelog/v0.2.md).

## Historical development snapshots

Point-in-time handoff, validation and planning reports are retained under
[`docs/archive/`](docs/archive/). They are evidence of prior work, not current
feature or security declarations.

[0.2.0]: https://github.com/takanashi-tetsuya/northstar/releases/tag/v0.2.0
[0.1.0]: https://github.com/takanashi-tetsuya/northstar/commit/998396915ab38a9deadf47ae871be561e11f7ef2
