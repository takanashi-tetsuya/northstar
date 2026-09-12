# Migration Ledger: `northstar-abuse-policy`

## 1. Executive Summary & Purpose

`northstar-abuse-policy` is a capability-free, deterministic Rust library crate extracted from `src/abuse.rs` and related anti-abuse configuration in `src/config.rs`. It encapsulates pure cryptographic PoW binding algorithms, $n^2$ computational work escalation, exponential cooldown schedules, sliding-window state transition functions, and rate admission decisions for the Northstar XMPP server.

### Crate Specifications
- **Package Name**: `northstar-abuse-policy`
- **Path**: `crates/northstar-abuse-policy`
- **Edition**: Rust 2021
- **MSRV**: 1.97
- **License**: AGPL-3.0-only
- **Safety Policy**: `#![forbid(unsafe_code)]`
- **Publish**: `false`
- **Dependencies Allowed & Used**: `base64` (0.22), `chrono` (0.4, default-features=false, features=["serde"]), `hmac` (0.12), `serde` (1.0), `serde_json` (1.0), `sha2` (0.10), `subtle` (2.6), `thiserror` (2.0), `uuid` (1.12, default-features=false, features=["serde"]).
- **Capability Isolation**: Absolutely no database (PgPool/SQLx), network (Tokio/Axum), sockets, filesystem, environment, logging/tracing, AppState, global mutable state, random number generator (`rand`, `OsRng`, `thread_rng`), or wall-clock access (`SystemTime`, `Instant::now()`, `Utc::now()`).
- **Deterministic Production & Test Suites**: Both production routines and test fixtures operate strictly with explicit, injected timestamps (e.g. fixed RFC3339 values) and deterministic UUID constants, guaranteeing zero capability leaks across the entire crate.

---

## 2. Module Map & Extracted Symbols

The monolithic anti-abuse logic has been separated into six focused, orthogonal modules:

| Module | Extracted Symbols & Types | Purpose |
|---|---|---|
| `model` | `AbuseAction`, `ActorDimension`, `WorkRequirement`, `PowIntentRequest`, `PowIntentView`, `PowIntent`, `PowProof`, `PowChallenge`, `ContentIdentityPurpose`, `ContentIdentityAuthenticator`, `ContentIdentityAuthenticators`, `MessageAdmissionRequest`, `MessageDedupeCandidate`, `MessageDedupeIdentity`, `GuardError`, `IntentError`, `canonical_pow_path`, `action_accepts_intent`, `canonical_json_body_digest`, Protocol/Storage Constants | Typed domain entities, actor dimensions (without storing raw IP/user identifiers), semantic action intents, content identity authenticators, and protocol error types. |
| `config` | `AbuseConfig`, `AbuseConfigBuilder`, `ConfigError` | Anti-abuse configuration parameters with strict boundary validation rejecting zero intervals, non-monotonic steps, unsafe work bounds, and arithmetic overflow. |
| `escalation` | `Policy`, `policy`, `step_from_events`, `calculate_work_factor`, `hard_wait_seconds`, `build_requirement`, `prefetched_message_challenge_remains_sufficient`, `ABUSE_NOTICE` | $n^2$ quadratic computational work escalation, action-specific burst allowances, stepped hard delay gates, and client notice generation. |
| `cooldown` | `penalty_cooldown_interval`, `decayed_penalty`, `max_penalty_decay_horizon`, `punish_penalty_and_wait`, `minimum_key_rotation_overlap`, `trim_event_timestamps_utc`, `decay_penalty_level_utc` | Exponential penalty cooldown calculations ($base \times 2^{level}$), geometric decay horizon ($step \times 2046$), failure wait progression ($2^{\min(p, 9)}$), and key rotation overlap horizon. |
| `pow` | `derive_actor_key_secret`, `actor_key_id`, `subject_hash`, `opaque_actor_key`, `opaque_challenge_capacity_key`, `compute_pow_prefix`, `verify_pow_prefix_binding`, `verify_pow_nonce`, `PowVerifyError`, `derive_content_identity_key`, `compute_content_identity_authenticator`, `compute_content_identity_authenticators` | Cryptographic PoW challenge prefix binding, constant-time verification, SHA-256 target difficulty validation, actor pseudonymization, and least-authority content identity subkey derivations. |
| `admission` | `message_admission_lock_id`, `message_admission_capacity_shard`, `message_admission_identity_digest`, `message_admission_material`, `resolve_message_admission_identity`, `build_message_dedupe_identity`, `ActorStateSnapshot`, `decay_actor_state_snapshot`, `record_success_in_snapshot`, `record_failure_in_snapshot`, `merge_previous_actor_snapshot`, `requirement_from_snapshots`, `evaluate_challenge_proof`, `ChallengeVerificationContext` | Pure deterministic admission decisions, message deduplication keys, capacity shard distribution (0..64), and injected-time state transition functions. |

---

## 3. Separation of Responsibilities: Policy vs. Server Adapters

To maintain strict architectural boundaries, capability-free policy is cleanly isolated from server-owned IO, concurrency, and persistence authority:

```text
+-------------------------------------------------------------------------+
|                  Server Adapters (rust-xmpp-server)                     |
|                                                                         |
|  - PostgreSQL connection pool & transaction management (PgPool/sqlx)    |
|  - Transaction advisory try-locks (pg_try_advisory_xact_lock)           |
|  - Cross-process concurrency gates (db_state_gates Tokio mutexes)       |
|  - Physical secret loading from disk (ABUSE_STATE_HMAC_KEY_FILE)        |
|  - Deployment key authority & database migrations (abuse_key_deployments)|
|  - Wall-clock source (clock_timestamp() / Utc::now())                   |
+------------------------------------+------------------------------------+
                                     |
                          calls pure functions & types
                                     v
+-------------------------------------------------------------------------+
|             Pure Policy Crate (northstar-abuse-policy)                  |
|                                                                         |
|  - Deterministic state transitions (ActorStateSnapshot)                 |
|  - Bounded arithmetic & geometric cooldown decays                       |
|  - Quadratic n^2 work factor calculations & hard wait thresholds        |
|  - SHA-256 target difficulty & nonce validation                         |
|  - Semantic PoW v2 intent bindings & canonical JSON body hashing        |
|  - Capacity shard calculations & message deduplication material        |
+-------------------------------------------------------------------------+
```

---

## 4. Callers in `src/` (Migration Ledger)

The following call sites in `src/` reference abuse functionality and will transition to `northstar_abuse_policy`:

| Caller File | Referenced Symbols | Adapter / Usage Description |
|---|---|---|
| `src/abuse.rs` | `AbuseGuard`, `AbuseConfig`, `AbuseAction`, `PowIntent`, `PowProof`, `PowChallenge`, `WorkRequirement`, `MessageAdmissionRequest`, etc. | Core server adapter containing PostgreSQL transaction handling, in-memory DashMap caches, and background cleanup jobs. |
| `src/config.rs` | `pow_base_work_factor`, `pow_max_work_factor`, `abuse_window_seconds`, `abuse_cooldown_seconds`, `abuse_max_wait_seconds`, `abuse_message_free_burst`, `pow_max_device_seconds` | Configuration validation rules enforcing positive intervals and work bounds. |
| `src/state.rs` | `AbuseGuard::new_persistent_for_deployment`, `AbuseConfig` | Server runtime state initialization and key mounting. |
| `src/db/abuse_keys.rs` | `AbuseKeyDeploymentIdentity`, `reconcile_abuse_key_deployment`, `minimum_key_rotation_overlap` | Database deployment authority for rotating HMAC keys and fencing legacy generations. |
| `src/db/api_control.rs` | `AbuseConfig` | Test fixtures for API control rate limiting. |
| `src/db/archive.rs` | `AbuseConfig` | Test fixtures for message archive abuse tests. |
| `src/db/reports.rs` | `AbuseConfig` | User abuse reporting fixtures. |
| `src/db/users.rs` | `AbuseConfig` | User registration abuse fixtures. |
| `src/xmpp/protocol/misc.rs` | `AbuseGuard`, `AbuseConfig` | XMPP protocol ping and ad-hoc rate checks. |

---

## 5. Ambiguities, Legacy Formulas, and Security Debt

During structural extraction, the following legacy formula behaviors and design characteristics were analyzed and preserved:

1. **Penalty Multiplier Clamping Inconsistencies**:
   - In `build_requirement`: `penalty_multiplier = 1 << penalty.min(20)` (work factor multiplier).
   - In `hard_wait_seconds`: `multiplier = 1 << penalty.min(8)` (delay multiplier capped at 256x).
   - In `punish_penalty_and_wait` / `punish_db_states`: `wait = 2^penalty.min(9)` (failure delay capped at 512s).
   - In `penalty_cooldown_interval`: `1 << penalty.min(10)` (cooldown duration capped at 1024x base step).
   - *Resolution*: These distinct caps are intentional: work factor scales up to level 20 for extreme compute hardness, delay gates cap at level 8/9 to prevent deadlocks, and cooldown interval caps at level 10 to match the 10-level state ceiling (`MAX_PENALTY_LEVEL = 10`).

2. **Carrier-Grade NAT Shared IP Division (`events.len() / 20`)**:
   - In `requirement_from_snapshots` and `requirement_from_db`, when an actor list contains multiple identifiers (e.g. Account + IP + Behavior), the IP dimension is treated as a shared carrier-grade NAT signal. Its event count is divided by 20, allowing high-density NAT users to avoid consuming each other's free bursts while still serving as a high-volume circuit breaker against network floods.
   - *Resolution*: Preserved exactly in `ActorDimension::is_shared_ip` and `requirement_from_snapshots`.

3. **In-Memory vs. Persistent Authority Divergence**:
   - Legacy `src/abuse.rs` implemented two parallel paths: an in-memory `Instant` + `DashMap` mode for unit tests and a persistent `chrono::DateTime<Utc>` + PostgreSQL mode for production.
   - *Resolution*: `northstar-abuse-policy` unifies deterministic state transitions using injected timestamps (`chrono::DateTime<Utc>` or `Duration`), allowing the same pure logic to be used across unit tests, memory caches, and PostgreSQL persistence adapters.

4. **Prefetched Message Challenge Relaxation**:
   - Legitimate XMPP clients prefetch PoW challenges for outgoing messages. If previous sends advance the actor sequence number, a prefetched challenge is still accepted provided the live requirement has not increased in work factor or hard delay and no retry cooldown is active.
   - *Resolution*: Encapsulated in `prefetched_message_challenge_remains_sufficient`.

---

## 6. Future Integration Steps

1. In root `Cargo.toml`, add:
   ```toml
   [workspace]
   members = [
       ".",
       "crates/northstar-abuse-policy",
       # ...
   ]
   ```
2. Remove the temporary `[workspace]` header from `crates/northstar-abuse-policy/Cargo.toml`.
3. In root `Cargo.toml` dependencies:
   ```toml
   northstar-abuse-policy = { path = "crates/northstar-abuse-policy" }
   ```
4. Refactor `src/abuse.rs` into a pure adapter layer that delegates calculations, intent validation, and state snapshots to `northstar_abuse_policy`.
