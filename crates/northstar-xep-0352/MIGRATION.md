# Migration Ledger: `northstar-xep-0352`

## 1. Overview & Extraction Scope
`northstar-xep-0352` is a capability-free, transport-neutral wire protocol, state machine, delivery classification, and bounded queue library implementing XEP-0352 (Client State Indication) for Northstar.

- **Crate**: `crates/northstar-xep-0352`
- **Edition / Toolchain**: Rust 2021, rust-version 1.97, AGPL-3.0-only, publish = false, `#![forbid(unsafe_code)]`
- **Allowed Dependencies**: `northstar-xep-core`, `roxmltree`, `thiserror`, `serde` (optional).
- **Forbidden Dependencies**: SQLx/PgPool, Redis, Tokio, Axum, sockets, filesystem, env, AppState, global state, logging, wall-clock access, persistence, worker spawning, transport writes, TLS and HTTP.

---

## 2. Source Files & Symbol Mapping

| Legacy Source Location | Extracted Symbol / Function | Extracted Target Module (`northstar-xep-0352`) |
| :--- | :--- | :--- |
| `src/xmpp/protocol/csi.rs` (95-99) | `valid_indication` | `wire::is_valid_indication_node`, `wire::parse_indication_node` |
| `src/xmpp/protocol/csi.rs` (101-189) | `deferrable_key` | `policy::classify_stanza`, `policy::CoalescingKey`, `policy::canonicalize_jid` |
| `src/xmpp/protocol/csi.rs` (45-85) | `defer_stanza` | `queue::DeferredQueue::enqueue` |
| `src/xmpp/protocol/csi.rs` (87-93) | `drain_deferred` | `queue::DeferredQueue::drain_all` |
| `src/xmpp/protocol/csi.rs` (12-29) | `client_state` | `state::CsiStateMachine::apply_indication` |
| `src/xmpp/protocol/csi.rs` (34-43) | `csi_filter_outbound` | `policy::classify_stanza` + `queue::DeferredQueue` |
| `src/xmpp/protocol/dispatch.rs` (152-164) | CSI stream dispatch & error handling | `wire::parse_indication`, `state::CsiStateMachine` |
| `src/xmpp/protocol/sasl2.rs` (20, 257-275, 1392-1393) | SASL2 Bind2 CSI feature indication | `wire::CsiIndication`, `state::CsiStateMachine::with_initial_state` |

---

## 3. Exported Public API

The crate is organized into focused, capability-free modules:

### `wire`
- `pub const NAMESPACE: &str = "urn:xmpp:csi:0"`
- `pub enum CsiIndication { Active, Inactive }`
- `pub fn parse_indication(xml: &str) -> Result<CsiIndication, WireError>`
- `pub fn parse_indication_node(root: Node) -> Result<CsiIndication, WireError>`
- `pub fn is_valid_indication_node(root: Node) -> bool`
- Builders: `build_active()`, `build_inactive()`, `build_indication(indication)`, `build_stream_feature()`

### `state`
- `pub enum CsiState { Active, Inactive }` (default is `Active` per XEP-0352 §3)
- `pub enum TransitionOutcome { Changed { from: CsiState, to: CsiState }, Unchanged { state: CsiState } }`
- `pub struct CsiStateMachine`:
  - `new()`, `with_initial_state(initial)`
  - `state()`, `is_active()`, `is_inactive()`, `transition_count()`
  - `apply_indication(indication) -> TransitionOutcome`
  - `set_active() -> TransitionOutcome`, `set_inactive() -> TransitionOutcome`, `reset()`

### `policy`
- `pub enum DeliveryAction { Immediate, Defer(CoalescingKey), Discard }`
- `pub struct StanzaMetadata { is_durable: bool, has_transport_receipt: bool, is_carbon: bool, custom_bypass: bool }`
- `pub enum CoalescingKey { Presence { from: String }, ChatState { from: String }, PepEvent { from: String, node: String, item_keys: Vec<String> }, Custom(String) }`
- `pub fn canonicalize_jid(jid: &str) -> Option<String>` (lowercases bare address, preserves RFC 7622 resource case)
- `pub fn classify_stanza(stanza_xml: &str, metadata: &StanzaMetadata, config: &CsiPolicyConfig) -> DeliveryAction`
- `pub enum OverflowPolicy { Disconnect, Reject, Persist, DropOldest }`
- `pub struct CsiPolicyConfig { max_deferred_stanzas, max_deferred_bytes, overflow_policy, discard_typing_on_inactive, allow_presence_coalescing, allow_chatstate_coalescing, allow_pep_coalescing }`

### `queue`
- `pub struct DeferredEntry<T> { payload: T, key: Option<String>, byte_size: usize, sequence: u64 }`
- `pub struct DeferredQueue<T>`:
  - `new(config)`, `with_bounds(max_stanzas, max_bytes)`
  - `len()`, `is_empty()`, `total_bytes()`, `config()`, `config_mut()`, `clear()`, `iter()`
  - `enqueue(payload: T, byte_size: usize, key: Option<CoalescingKey>) -> EnqueueResult<T>`
  - `drain_all() -> Vec<T>` (FIFO insertion order flush)
  - `drain_entries() -> Vec<DeferredEntry<T>>`
- `pub enum EnqueueResult<T> { Enqueued { replaced_previous: Option<T> }, Overflow { decision: OverflowDecision<T> }, Discarded { discarded_item: T } }`
- `pub enum OverflowDecision<T> { Disconnect { ... }, Reject { ... }, Persist { ... }, EvictedOldest { evicted: Vec<T>, replaced_previous: Option<T> } }`

### `error`
- `WireError`: `MalformedXml`, `NotAnElement`, `UnexpectedNamespace`, `UnexpectedTagName`, `AttributesNotPermitted`, `ChildrenNotPermitted`, `TextContentNotPermitted`.
- `PolicyError`: `ZeroMaxStanzas`, `ZeroMaxBytes`.
- `StateError`: `Unauthenticated`.
- `QueueError`: `Overflow`.
- `CsiError`: Aggregate enum over all module error types.

---

## 4. CSI vs XEP-0198 Durability Adapter Boundary

A strict boundary exists between CSI traffic throttling and XEP-0198 Stream Management / database persistence:

1. **Ephemeral vs Durable**:
   - CSI operates purely on transient, replaceable soft-state signals (such as presence broadcasts, standalone chat states, and cacheable PEP events).
   - XEP-0198 handles guaranteed delivery, unacknowledged stanza replay buffers, and transport sequence counting.
2. **Fence Invariance**:
   - Any outbound item possessing a `durable_delivery` fence (database transaction / message claim) or a `transport_receipt` marker MUST bypass CSI deferral (`DeliveryAction::Immediate`).
   - Allowing durable stanzas into a coalescing queue risks orphaning database transaction locks or reordering Stream Management / BOSH acknowledgement frames.
3. **Activation Flush Boundary**:
   - When an inactive client transitions back to `<active/>`, CSI flushes all deferred stanzas into the transport pipeline in strictly deterministic FIFO insertion order before any new outbound stanzas are sent.

---

## 5. Suspected Legacy Defects & Recorded Migration Debt

During the extraction and analysis of `src/xmpp/protocol/csi.rs`, the following subtleties and defects were identified and cataloged:

1. **Silent Stanza Loss on Queue Overflow**:
   - *Legacy Semantics*: `defer_stanza` in `src/xmpp/protocol/csi.rs` silently invoked `deferred.pop_front()` when `MAX_DEFERRED_STANZAS` (512) or `MAX_DEFERRED_BYTES` (2 MiB) was reached. Dropped stanzas vanished without auditing or server notifications.
   - *Extracted Improvement*: `DeferredQueue` provides explicit `OverflowPolicy` (`Disconnect`, `Reject`, `Persist`, `DropOldest`) returning `EnqueueResult::Overflow` with all displaced items so the server adapter can log, persist, or disconnect without silent loss.
2. **Resource Case Normalization in Presence Keys**:
   - *Legacy Semantics*: RFC 7622 resourceparts are opaque strings. In legacy `csi.rs`, lowercasing local/domain while preserving resource case was verified by unit tests.
   - *Extracted Status*: `policy::canonicalize_jid` faithfully preserves resource case while normalizing local and domain parts.
3. **Discardable Typing Indicators**:
   - *Specification*: XEP-0352 §3.3 notes servers may discard transient typing indications while clients are inactive.
   - *Extracted Status*: Configurable via `CsiPolicyConfig::discard_typing_on_inactive`, which emits `DeliveryAction::Discard`.

---

## 6. Future Root Integration Steps

1. **Root `Cargo.toml` update**:
   ```toml
   [workspace]
   members = [
       ".",
       "crates/northstar-xep-0352",
       # ... other crates
   ]

   [dependencies]
   northstar-xep-0352 = { path = "crates/northstar-xep-0352" }
   ```

2. **Replace legacy duplicated logic**:
   - Use `northstar_xep_0352::wire` in `src/xmpp/protocol/dispatch.rs` and `src/xmpp/protocol/csi.rs`.
   - Replace manual queue buffers in `ProtocolSession` with `northstar_xep_0352::queue::DeferredQueue`.
   - Use `northstar_xep_0352::policy::classify_stanza` for all outbound traffic filtering.
