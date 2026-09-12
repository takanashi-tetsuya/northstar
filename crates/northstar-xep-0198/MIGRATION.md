# Migration Ledger: `northstar-xep-0198`

## 1. Overview & Extraction Scope
`northstar-xep-0198` is a capability-free, transport-neutral wire protocol and deterministic state-machine library implementing XEP-0198 (Stream Management) for Northstar.

- **Crate**: `crates/northstar-xep-0198`
- **Edition / Toolchain**: Rust 2021, rust-version 1.97, AGPL-3.0-only, publish = false, `#![forbid(unsafe_code)]`
- **Allowed Dependencies**: `northstar-xep-core`, `roxmltree`, `thiserror`, `serde` (optional).
- **Forbidden Dependencies**: SQLx/PgPool, Redis, Tokio, Axum, sockets, filesystem, env, AppState, global state, logging, wall-clock access, UUID/random ID generation, persistence, worker spawning, transport writes, TLS and HTTP.

---

## 2. Source Files & Symbol Mapping

| Legacy Source Location | Extracted Symbol / Function | Extracted Target Module (`northstar-xep-0198`) |
| :--- | :--- | :--- |
| `src/xmpp/sm_counter.rs` (13-20) | `acknowledgement_delta` | `counter::acknowledgement_delta`, `counter::SmCounter::validate_ack` |
| `src/xmpp/protocol/sm.rs` (1539-1545) | `valid_sm_control` | `wire::is_valid_sm_control` |
| `src/xmpp/protocol/sm.rs` (1547-1549) | `resumed_offline_replay_eligible` | `negotiation::resumed_offline_replay_eligible` |
| `src/xmpp/protocol/sm.rs` (163-169) | `resumability_allowed` | `negotiation::resumability_allowed` |
| `src/xmpp/protocol/sm.rs` (175-314) | `enable_sm_inline` (negotiation decision) | `negotiation::negotiate_enable`, `state::SmStateMachine::enable` |
| `src/xmpp/protocol/sm.rs` (316-384) | `stream_management` (wire dispatch & parsing) | `wire::parse_enable`, `wire::parse_resume`, `wire::parse_r`, `wire::parse_a` |
| `src/xmpp/protocol/sm.rs` (385-403) | `resume` (wire parsing & validation) | `wire::parse_resume`, `wire::ResumeElement` |
| `src/xmpp/protocol/sm.rs` (1449-1519) | `acknowledge` (queue removal & ack validation) | `state::SmStateMachine::handle_ack_answer`, `queue::UnackedQueue::acknowledge` |
| `src/xmpp/protocol/sm.rs` (1555-1581) | `stage_muc_replay_suffix` | `queue::UnackedQueue::stage_suffix` |
| `src/xmpp/protocol/sm.rs` (1601-1614) | `handled_count_too_high_stream_error` | `wire::build_handled_count_too_high_stream_error` |
| `src/xmpp/protocol/sm.rs` (1521-1536) | `reset_sm` | `state::SmStateMachine::new`, `state::SmStateMachine::close` |
| `src/db/sm.rs` (123-157) | `SmIpPolicy`, `peer_ip_matches` | `negotiation::IpBindingPolicy`, `negotiation::peer_ip_matches` |

---

## 3. Exported Public API

The crate is organized into focused, capability-free modules:

### `counter`
- `pub struct SmCounter(pub u32)`: A typed 32-bit counter wrapper implementing modular 2^32 arithmetic (`wrapping_add`, `wrapping_sub`, `increment`, `advance`, `advance_by`, `forward_distance_to`).
- `pub fn acknowledgement_delta(previous: u32, received: u32, outstanding: usize) -> Option<usize>`: Validates whether `received` is within the forward bounded window $\le \text{outstanding}$ modulo 2^32.
- `SmCounter::validate_ack(last_acked, received, outstanding, outbound_sent) -> Result<usize, AckError>`.

### `wire`
- Stanza elements:
  - `EnableElement { resume: bool, max: Option<u32>, location: Option<String> }`
  - `EnabledElement { id: Option<String>, resume: bool, max: Option<u32>, location: Option<String> }`
  - `ResumeElement { previd: String, h: SmCounter }`
  - `ResumedElement { previd: String, h: SmCounter, location: Option<String> }`
  - `FailedElement { h: Option<SmCounter>, reason: FailedReason, custom_condition: Option<String> }`
  - `AckRequestElement` (`<r/>`)
  - `AckAnswerElement { h: SmCounter }` (`<a/>`)
- Parsers:
  - `parse_enable(node: Node) -> Result<EnableElement, WireError>`
  - `parse_enabled(node: Node) -> Result<EnabledElement, WireError>`
  - `parse_resume(node: Node) -> Result<ResumeElement, WireError>`
  - `parse_resumed(node: Node) -> Result<ResumedElement, WireError>`
  - `parse_failed(node: Node) -> Result<FailedElement, WireError>`
  - `parse_r(node: Node) -> Result<AckRequestElement, WireError>`
  - `parse_a(node: Node) -> Result<AckAnswerElement, WireError>`
- Builders:
  - `build_enable(resume, max, location) -> String`
  - `build_enabled(id, resume, max, location) -> String`
  - `build_resume(previd, h) -> String`
  - `build_resumed(previd, h, location) -> String`
  - `build_failed(reason, h) -> String`
  - `build_failed_str(condition_name) -> String`
  - `build_r() -> &'static str`
  - `build_a(h) -> String`
  - `build_handled_count_too_high_stream_error(received, sent) -> String`
- Validation helpers:
  - `is_valid_sm_control(node: Node, allowed_attributes: &[&str]) -> bool`
  - `is_valid_previd(previd: &str) -> bool`
  - `is_valid_location(location: &str) -> bool`

### `queue`
- `pub struct UnackedEntry<T = String> { payload: T, byte_size: usize, sequence: SmCounter }`
- `pub struct UnackedQueue<T = String>`:
  - Methods: `new(max_stanzas, max_bytes)`, `len()`, `is_empty()`, `total_bytes()`, `max_stanzas()`, `max_bytes()`, `entries()`, `push_back(payload, byte_size, sequence)`, `acknowledge(count)`, `replay_payloads()`, `clear()`, `stage_suffix(suffix, start_sequence)`.

### `negotiation`
- `pub struct EnableConfig { server_max_timeout_seconds: u32, allow_resumption: bool, require_same_device: bool }`
- `pub struct NegotiatedEnable { resume: bool, timeout_seconds: u32, location: Option<String> }`
- `pub fn negotiate_enable(client_request, config, has_device_id) -> NegotiatedEnable`
- `pub fn resumability_allowed(requested_resume, require_same_device, has_device_id) -> bool`
- `pub fn resumed_offline_replay_eligible(available: bool, priority: i16) -> bool`
- `pub enum IpBindingPolicy { None, Exact, Subnet }`
- `pub fn peer_ip_matches(policy, expected, actual) -> bool`
- `pub fn same_device_matches(stored_device, claimant_device, require_same_device) -> bool`

### `state`
- `pub enum SmState { Disabled, Active(ActiveSession), Suspended(SuspendedSession), Expired, Failed(FailedReason), Terminated }`
- `pub struct ActiveSession { inbound_h, outbound_h, acked_h, unacked_queue, resume_allowed, resume_id, resume_timeout_seconds }`
- `pub struct SuspendedSession { inbound_h, outbound_h, acked_h, unacked_queue, resume_id, resume_timeout_seconds, suspended_at, expires_at }`
- `pub struct ResumeSuccessOutcome { resumed_element, acknowledged_on_resume, replay_stanzas }`
- `pub struct SmStateMachine`:
  - Methods with injected time:
    - `enable(request, config, resume_id, has_device_id) -> Result<EnabledElement, SmError>`
    - `record_inbound_stanza() -> Result<SmCounter, SmError>`
    - `record_outbound_stanza(stanza, byte_size) -> Result<SmCounter, SmError>`
    - `handle_ack_request() -> Result<AckAnswerElement, SmError>`
    - `handle_ack_answer(h) -> Result<Vec<UnackedEntry<String>>, SmError>`
    - `suspend(now: u64) -> Result<(), SmError>`
    - `check_expiry(now: u64) -> bool`
    - `resume(request, now: u64) -> Result<ResumeSuccessOutcome, SmError>`
    - `close()`
    - `fail(reason)`

### `error`
- `FailedReason`: Standard RFC 6120 condition enum (`BadRequest`, `Conflict`, `ItemNotFound`, `UnexpectedRequest`, `ResourceConstraint`, `UndefinedCondition`, etc.).
- `WireError`, `AckError`, `NegotiationError`, `QueueError`, `StateError`, `SmError`.

---

## 4. Server-Owned Authority (Deliberately Excluded)
The following capabilities remain strictly server-owned and are deliberately excluded from this crate:
1. **Durable Database Persistence**: PostgreSQL schema, SQL queries (`src/db/sm.rs`), transaction lifecycle, durable unacked queue checkpointing, session creation triggers.
2. **Session Ownership & Fencing**: `SessionRouteClaimProof`, DashMap route table, cluster registration, ABA route removal detection, takeover mutexes.
3. **Cryptographic Identity & Bearer Token Generation**: Random 256-bit bearer generation (`rand::thread_rng()`), SHA-256 bearer hashing (`sm_resume_token_hash`), token storage.
4. **Memory Capacity Governor**: Process-wide transient memory reservations (`SmMemoryGovernor`, `CapacityReservation`).
5. **Transport Drivers & Retransmission**: Socket I/O, TLS termination, BOSH/WebSocket frame writing, async timers, Tokio channels and tasks.
6. **MUC Presence & Offline Replay**: Presence gate mutexes (`mix_presence_gate`), MUC occupant reconstruction, account offline message replay task scheduling.

---

## 5. Suspected Legacy Defects & Inconsistencies

During the extraction of `src/xmpp/protocol/sm.rs`, `src/db/sm.rs`, and `src/xmpp/sm_counter.rs`, the following subtleties and legacy semantics were cataloged:

1. **Boolean Parsing in `<enable resume='...'/>`**:
   - *Legacy Semantics*: `src/xmpp/protocol/sm.rs` accepted `"true"`, `"false"`, `"1"`, and `"0"`.
   - *Specification*: XEP-0198 §3 uses standard XML xs:boolean values (`true`, `false`, `1`, `0`).
   - *Status in extracted crate*: Fully supported via `parse_xml_bool` rejecting any other string.

2. **Handled Count Wrapping & Impossible ACKs**:
   - *Legacy Semantics*: `src/xmpp/sm_counter.rs` checked `delta <= outstanding`. When delta $> \text{outstanding}$, the session was torn down with stream error `<stream:error><undefined-condition/><handled-count-too-high h='...' send-count='...'/></stream:error>`.
   - *Specification*: XEP-0198 §6 requires a stream error if `h` is greater than the number of stanzas sent.
   - *Status in extracted crate*: `AckError::HandledCountTooHigh` and builder `build_handled_count_too_high_stream_error` preserve this exact format.

3. **Stanza Error vs Stream Error in `<failed/>`**:
   - *Legacy Semantics*: `src/xmpp/protocol/sm.rs` emitted `<failed xmlns='urn:xmpp:sm:3'><condition-name xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></failed>`.
   - *Specification*: XEP-0198 §4 allows stanza error conditions as children of `<failed/>`.
   - *Status in extracted crate*: `FailedReason` generates standard `<condition xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>` children.

4. **Inbound Stanza Counting Exclusions**:
   - *Specification*: XEP-0198 §3 states that only stanzas (`<message/>`, `<presence/>`, `<iq/>`) increment `h`. Stream management elements (`<enable/>`, `<r/>`, `<a/>`, etc.) and stream framing do not.
   - *Status in extracted crate*: `record_inbound_stanza()` and `record_outbound_stanza()` are called explicitly for stanzas only.

---

## 6. Future Root Integration Steps

1. **Root `Cargo.toml` update**:
   ```toml
   [workspace]
   members = [
       ".",
       "crates/northstar-xep-0198",
       # ... other crates
   ]

   [dependencies]
   northstar-xep-0198 = { path = "crates/northstar-xep-0198" }
   ```

2. **Replace legacy duplicated logic**:
   - Use `northstar_xep_0198::wire` parsers and builders in `src/xmpp/protocol/sm.rs`.
   - Replace `src/xmpp/sm_counter.rs` with `northstar_xep_0198::counter`.
   - Use `northstar_xep_0198::negotiation` for policy decisions.
