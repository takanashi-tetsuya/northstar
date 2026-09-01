# SASL2, FAST and Bind2 production evidence

This document records the implemented Northstar profile for XEP-0388, XEP-0484 and XEP-0386. It maps normative behavior to wire, in-memory state and PostgreSQL evidence. It is deliberately narrower than a claim to implement unadvertised future SASL2 task extensions.

## Verified profile

| Area | Implemented behavior | Primary implementation | Automated evidence |
| --- | --- | --- | --- |
| Secure negotiation | SASL2 is advertised only after native TLS or a trusted HTTPS proxy assertion. STARTTLS and Direct TLS use actual TLS channel state; WebSocket and BOSH use the same `ProtocolSession` after proxy provenance checks | `src/xmpp/protocol.rs`, `src/xmpp/protocol/sasl2.rs`, `src/xmpp/mod.rs`, `src/bosh.rs` | `XMPP_TEST_ONLY_SASL=true bash scripts/integration-wsl.sh` exercises STARTTLS, Direct TLS, WebSocket and BOSH |
| Password mechanisms | PLAIN, SCRAM-SHA-256 and SCRAM-SHA-256-PLUS share the SASL mechanism engine but keep SASL2 framing/state separate from legacy SASL | `src/auth.rs`, `src/xmpp/protocol/sasl2.rs`, `src/xmpp/protocol/dispatch.rs` | Real Direct-TLS PLAIN/SCRAM/PLUS handshakes; positive and negative authzid cases; mixed legacy/SASL2 retry ceiling |
| Channel binding | SCRAM-PLUS validates the GS2 header and exact `tls-server-end-point` or `tls-exporter` bytes. FAST ENDPOINT/EXPORTER mechanisms are advertised only when their binding exists; an Ed25519-signed certificate has no fabricated endpoint digest and continues with exporter when available | `src/auth.rs`, `src/tls.rs`, `src/xmpp/mod.rs` | Unit tests validate capability selection, downgrade and binding mismatch; Direct-TLS SCRAM-PLUS computes RFC 5929 endpoint bytes only for certificate signatures with a defined digest |
| Stream identity | A protected stream `from`, when supplied, must be a canonical local bare JID for the configured domain and must match the authenticated account. FAST requires it | `src/xmpp/protocol/sasl2.rs::parse_stream_open`, `complete_sasl2`, `authenticate_fast` | TCP stream-open parser tests and live successful/mismatched authentication cases |
| SASL2 XML/state | `<initial-response/>`, `<user-agent/>` and extension elements are order-checked, bounded and single-use. User-agent IDs are RFC 4122 UUIDv4. During an exchange only SASL2 response/abort is accepted | `src/xmpp/protocol/sasl2.rs`, `src/xmpp/protocol/dispatch.rs` | 14 focused parser/state tests plus live malformed Base64, out-of-order and non-SASL-during-exchange probes |
| Base64 boundary | SASL2 uses an empty element for a zero-length response. It rejects the legacy RFC 6120 single `=` sentinel, while legacy SASL retains that compatibility rule | `normalize_sasl2_base64_payload`, `normalize_base64_payload` | Focused unit and live Direct-TLS tests |
| Success sequencing | Inline results are inside SASL2 `<success/>`; applicable stream features follow immediately without a restart. A successful SM resume sends success, then features, then replayed stanzas, with separate WebSocket frames | `Action::Resume.post_control`, TCP/WebSocket/BOSH action drivers | WebSocket SASL2 resume test waits for features, asserts `<resumed/>`, and asserts Bind2 was skipped |
| Bind2 resource | One non-empty prepared tag may appear before inline features. Northstar adds an unpredictable UUID suffix and returns the full authorization identifier | `parse_bind`, `complete_sasl2`, `bind_resource_sasl2_internal` | Parser order/empty-tag tests and live STARTTLS/Direct-TLS/WebSocket/BOSH Bind2 assertions |
| Bind2 inline features | Carbons must enable, CSI selects initial state, and SM enable returns `<enabled/>` or `<failed/>` inside `<bound/>`. MAM start/end metadata is captured before binding | `src/xmpp/protocol/sasl2.rs`, `src/xmpp/protocol/sm.rs` | Live inline Carbons/CSI/SM enable; archive boundary and failure paths remain covered by Rust/DB suites |
| Resume-before-bind | Inline SM resume runs first. Success reuses the old full JID and ignores Bind2; failure is included and processing continues to a fresh Bind2 request | `complete_sasl2`, `resume_values_with_fast` | Live WebSocket success path plus focused SM/DB tests for claim, activation and failures |
| Visibility/rollback | Local and cluster routes are reserved non-routable. FAST state, login epoch and auth generation commit before route activation. Replaced suspended SM teardown occurs only after commit, so a failed auth transaction cannot destroy the previous session | `bind_resource_sasl2_internal`, `Action::SendManyThenActivate`, transport drivers | Deferred-FK commit failure and explicit rollback tests; wire success is activated only after the success control reaches the transport |
| FAST proof | Tokens are derived from the mounted master key and row nonce, pinned to user, installation UUID and mechanism. PostgreSQL stores a digest, not the bearer. Initiator/responder HMACs are directional and compared in constant time | `src/auth.rs`, `src/db/fast.rs` | Unit identity/proof tests and live server responder-proof verification |
| FAST replay/concurrency | Explicit counters are monotonically advanced under row locks; a duplicate across concurrent pools succeeds at most once. Without TLS early data, a client may omit a count and the server still advances a private counter | `authenticate_fast_token` | Random-schema PostgreSQL test and live duplicate-count rejection |
| FAST rotation | A client installation has one current and one pending slot across mechanisms. A used pending token promotes to current and deletes the older token. Repeated issuance replaces only the pending slot and preserves the strong-auth chain | `issue_fast_token_in_transaction`, `finalize_fast_token_in_transaction`, `commit_fast_state_in_transaction` | Random-schema positive rotation-window, two-slot and promotion assertions |
| FAST expiry/revocation | Database expiry, strong-auth deadline, account disablement, password/auth generation and explicit invalidate all fail closed. Rotation cannot extend the original strong-auth deadline | `src/db/fast.rs`, credential mutation transactions | Random-schema expiry/restart, explicit invalidation, generation/status revocation and inherited-deadline assertions |
| Database/connection failure | Authentication database errors return temporary failure internally without masquerading as a bad password. Commit-time SQL failure rolls back token promotion/issuance and login epoch. A failed transport write leaves a reserved route non-routable and normal connection teardown removes it | `process_sasl_step`, `commit_sasl2_unbound_state`, `bind_resource_sasl2_internal`, transport drivers | Deferred foreign-key commit fault, invalid issuance fault and transaction rollback assertions; abrupt WebSocket disconnect followed by successful durable SM resume |

## State transition summary

1. The secure stream advertises legacy SASL and SASL2 independently. SASL2 inline capabilities contain SM resume, Bind2 and FAST; Bind2 advertises only Carbons, CSI and SM features which Northstar can actually process.
2. The parser validates the entire `<authenticate/>` shape before creating a SASL2 context. No inline mutation occurs on a parser or authentication failure.
3. PLAIN/SCRAM completes credential verification, or FAST verifies its installation-bound proof and consumes a replay counter. FAST promotion, invalidation and replacement issuance are still staged.
4. Inline SM resume is attempted first. A successful claim atomically commits SM activation, FAST changes and the user-agent epoch. Bind2 is ignored. A failed claim contributes `<failed/>` and allows Bind2 to continue.
5. Bind2 preflights MAM metadata, reserves non-routable local/cluster ownership, and commits auth-generation, user-agent epoch and FAST state in one PostgreSQL transaction.
6. Carbons/CSI and optional SM enable are applied. Optional SM enable failure is reported inside `<bound/>`; it does not fabricate an authentication failure after the bind has committed.
7. The transport writes SASL2 success, activates the committed route, writes the mandatory stream features, then releases replay/deferred work. TCP and WebSocket wait for their write futures; BOSH preserves the same order in the session response queue.

## Reproducible evidence

The following commands were run successfully on 2026-08-27:

```text
cargo test --locked xmpp::protocol::sasl2::tests:: -- --nocapture
# 14 passed, 0 failed

XMPP_TEST_ONLY_SASL=true bash scripts/integration-wsl.sh
# STARTTLS, Direct TLS, WebSocket and BOSH SASL2/Bind2/FAST passed
# FAST credential survived an actual server-process stop/start while reusing
# the same random PostgreSQL schema and mounted token-encryption key

AUTH_ADMIN_TEST_SCOPE=fast bash scripts/auth-admin-db-wsl.sh
# durable FAST test: 1 passed
# Bind2/FAST rollback test: 1 passed
```

Both shell runners create a cryptographically random schema in the dedicated `xmpp_test` database, refuse unexpected database/schema names, and remove the schema on success or failure.

## Deliberate boundaries

- TLS 0-RTT is neither advertised nor accepted. XEP-0484 counters are therefore optional for ordinary TLS; supplied counters remain strictly enforced.
- Northstar does not advertise future SASL2 task protocols, SASL security layers, or SASL EXTERNAL for C2S.
- FAST survives a process restart only when the operator mounts the same `FAST_TOKEN_SECRET_FILE`. Enumeration-resistant SCRAM for a missing or unusable account independently requires `DUMMY_SCRAM_SECRET_FILE`; the dummy salt and verifier are deployment-keyed, account-specific and mechanism-specific, but cannot authenticate. Production and clustered startup fail closed unless both protected files exist and contain independent 32-4096-byte values. They must never be copied, reused, or derived from one another.
- The explicit Redis-free, all-loopback reserved-domain development policy has separate FAST and dummy-SCRAM opt-ins. Each missing capability receives fresh independent process-local entropy. Enabling one opt-in never supplies the other; an ephemeral FAST key intentionally invalidates every FAST credential on restart, while an ephemeral dummy key only changes the indistinguishable failure transcript material.
- BOSH and WebSocket are considered secure only after trusted proxy provenance checks. The production proxy must terminate HTTPS correctly; an arbitrary forwarded header from an untrusted peer is rejected.
- The test certificate is isolated and short-lived. It proves protocol/channel-binding behavior, not public PKI issuance or operator certificate rotation.
