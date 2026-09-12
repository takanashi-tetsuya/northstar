# Migration & Architectural Split: `northstar-xml-framing`

## 1. Source File
- **Source:** [`src/xmpp/framing.rs`](file:///c:/Users/Admin/Documents/XMPP/src/xmpp/framing.rs)
- **Target Crate:** [`crates/northstar-xml-framing`](file:///c:/Users/Admin/Documents/XMPP/crates/northstar-xml-framing)
- **Target Main Entry:** [`crates/northstar-xml-framing/src/lib.rs`](file:///c:/Users/Admin/Documents/XMPP/crates/northstar-xml-framing/src/lib.rs)

---

## 2. API Map

| Symbol / Item | Original Scope (`src/xmpp/framing.rs`) | New Public API (`northstar-xml-framing`) | Description |
| :--- | :--- | :--- | :--- |
| `XmlEntityFramer` | `pub(crate) struct XmlEntityFramer` | `pub struct XmlEntityFramer` | State machine tracking per-XML-entity framing state across reads (depth stack, declaration status, stream QName). |
| `XmlEntityFramer::new()` | *(via Default)* | `pub fn new() -> Self` | Constructor initializing a clean framer instance. |
| `XmlEntityFramer::reset_entity(&mut self)` | `pub(crate) fn reset_entity` | `pub fn reset_entity(&mut self)` | Resets entity-level state (e.g. after TLS/SASL restart). |
| `XmlEntityFramer::reset_pending_frame(&mut self)` | `pub(crate) fn reset_pending_frame` | `pub fn reset_pending_frame(&mut self)` | Forgets partial frame scan while preserving entity declaration status (used for WebSocket messages). |
| `XmlEntityFramer::take_frame(&mut self, buffer)` | `pub(crate) fn take_frame` | `pub fn take_frame(&mut self, buffer: &mut String) -> Result<Option<String>>` | Scans buffer for a complete top-level XML frame / stream tag and drains it. |
| `take_frame(buffer)` | `pub fn take_frame` | `pub fn take_frame(buffer: &mut String) -> Result<Option<String>>` | Stateless convenience wrapper using a default entity framer. |
| `XmlFramingError` | `enum XmlFramingError` | `pub enum XmlFramingError` | Typed error classification (`Restricted`, `UnsupportedEncoding`, `ResourceLimit`). |
| `stream_error_condition(error)` | `pub(crate) fn stream_error_condition` | `pub fn stream_error_condition(error: &anyhow::Error) -> &'static str` | Maps any error to RFC 6120 stream error condition strings (`restricted-xml`, `unsupported-encoding`, `policy-violation`, `not-well-formed`). |
| `resource_limit(limit)` | `pub(crate) fn resource_limit` | `pub fn resource_limit(limit: &'static str) -> anyhow::Error` | Constructs a resource limit error. |
| `unsupported_encoding()` | `pub(crate) fn unsupported_encoding` | `pub fn unsupported_encoding() -> anyhow::Error` | Constructs an unsupported encoding error. |
| `restricted(feature)` | `fn restricted` | `pub fn restricted(feature: &'static str) -> anyhow::Error` | Constructs a restricted XML error. |
| `is_xml_whitespace(c)` | `pub(crate) fn is_xml_whitespace` | `pub fn is_xml_whitespace(character: char) -> bool` | Exact XML 1.0 whitespace check (`' '`, `'\t'`, `'\r'`, `'\n'`). |
| `is_xml_10_char(c)` | `fn is_xml_10_char` | `pub fn is_xml_10_char(character: char) -> bool` | Character range check against XML 1.0 Section 2.2 Char production. |
| `reject_forbidden_xml_10_chars(xml)` | `fn reject_forbidden_xml_10_chars` | `pub fn reject_forbidden_xml_10_chars(xml: &str) -> Result<()>` | Rejects any characters forbidden by XML 1.0. |
| `MAX_XML_DEPTH` | `const MAX_XML_DEPTH: usize = 256` | `pub const MAX_XML_DEPTH: usize = 256` | Maximum nested element depth. |
| `MAX_XML_ELEMENTS` | `const MAX_XML_ELEMENTS: usize = 16_384` | `pub const MAX_XML_ELEMENTS: usize = 16_384` | Maximum elements per top-level frame. |
| `MAX_XML_ATTRIBUTES_PER_ELEMENT` | `const MAX_XML_ATTRIBUTES_PER_ELEMENT: usize = 128` | `pub const MAX_XML_ATTRIBUTES_PER_ELEMENT: usize = 128` | Maximum attributes per XML element. |
| `MAX_XML_START_TAG_BYTES` | `const MAX_XML_START_TAG_BYTES: usize = 64 * 1024` | `pub const MAX_XML_START_TAG_BYTES: usize = 64 * 1024` | Maximum byte length of a start-tag before completion. |
| `MAX_XML_DECLARATION_BYTES` | `const MAX_XML_DECLARATION_BYTES: usize = 1_024` | `pub const MAX_XML_DECLARATION_BYTES: usize = 1_024` | Maximum byte length of an XML declaration. |

---

## 3. Temporary Duplication

- `crates/northstar-xml-framing` is introduced in parallel as a self-contained, zero-dependency library crate.
- `src/xmpp/framing.rs` currently remains unchanged in the root crate to avoid modifying any root manifest, lockfile, or shared integration state during parallel extraction.
- In a subsequent integration step, `src/xmpp/framing.rs` will be turned into a thin re-export module delegating all types and functions to `northstar-xml-framing`.

---

## 4. Exact Future `src/xmpp/framing.rs` Compatibility Re-export

When integrating `northstar-xml-framing` into the root crate, `src/xmpp/framing.rs` should be replaced with the following exact re-exports:

```rust
pub use northstar_xml_framing::{
    is_xml_whitespace, resource_limit, stream_error_condition, take_frame, unsupported_encoding,
    XmlEntityFramer, XmlFramingError, MAX_XML_ATTRIBUTES_PER_ELEMENT, MAX_XML_DECLARATION_BYTES,
    MAX_XML_DEPTH, MAX_XML_ELEMENTS, MAX_XML_START_TAG_BYTES,
};
```

And in `Cargo.toml`:
```toml
[workspace]
members = [
    ".",
    "crates/northstar-xep-core",
    "crates/northstar-xep-0184",
    "crates/northstar-xep-0092",
    "crates/northstar-xep-0199",
    "crates/northstar-xep-0202",
    "crates/northstar-xml-framing",
]

[dependencies]
northstar-xml-framing = { path = "crates/northstar-xml-framing" }
```

---

## 5. Transport Consumers

The framing logic extracted into this crate is consumed by all XMPP transport mechanisms in Northstar:

1. **C2S TCP/TLS Transport (`src/xmpp/mod.rs`)**:
   - Manages incremental reads from client TCP streams into persistent session buffers.
   - Handles RFC 6120 stream resets on `<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>` and `<authenticate xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>` via `framer.reset_entity()`.
   - Dispatches framing errors to RFC 6120 stream error conditions (`restricted-xml`, `policy-violation`, `not-well-formed`, `unsupported-encoding`) via `stream_error_condition(&error)`.

2. **S2S Inbound/Outbound Transport (`src/s2s/inbound.rs`, `src/s2s/util.rs`)**:
   - Frames inbound server-to-server streams and dialback connections.
   - Enforces structural limits (`MAX_XML_DEPTH`, `MAX_XML_ELEMENTS`, `MAX_XML_ATTRIBUTES_PER_ELEMENT`) before stanza parsing.
   - Maps framing errors directly to S2S stream error closures.

3. **RFC 7395 WebSocket Transport (`src/transport_parsing.rs`, `src/xmpp/mod.rs`)**:
   - Parses RFC 7395 text frames containing `<open/>`, `<close/>`, and standalone stanzas.
   - Uses `framer.reset_pending_frame()` between distinct WebSocket text frames to prevent scan state bleed-through if a malformed message is encountered, while preserving XML declaration entity history.
   - Validates single-frame boundaries and whitespace padding using `is_xml_whitespace`.

4. **BOSH / HTTP Binding (`src/transport_parsing.rs`)**:
   - Validates XML entity framing and ensures request bodies contain well-formed `<body/>` wrapper frames without exceeding resource ceilings.

5. **HTTP Upload & S2S DNS Framing Verification (`src/api/upload.rs`, `src/s2s/dns.rs`)**:
   - Verifies transport-level framing headers and enforces structural payload constraints.

---

## 6. Invariants

The `northstar-xml-framing` crate strictly maintains the following security and correctness invariants:

1. **Memory & Parsing Ceilings**:
   - `MAX_XML_DEPTH` (256): Prevents stack overflow and quadratic traversal on deeply nested XML trees.
   - `MAX_XML_ELEMENTS` (16,384): Bounds total element allocations per stanza frame before DOM expansion in `roxmltree`.
   - `MAX_XML_ATTRIBUTES_PER_ELEMENT` (128): Limits attribute parsing cost and hash table denial-of-service.
   - `MAX_XML_START_TAG_BYTES` (64 KiB): Bounds memory buffering for unclosed start tags.
   - `MAX_XML_DECLARATION_BYTES` (1 KiB): Rejects maliciously long declaration preambles.

2. **XML 1.0 Character Compliance**:
   - Characters outside `0x09 | 0x0A | 0x0D | 0x20..=0xD7FF | 0xE000..=0xFFFD | 0x10000..=0x10FFFF` (such as NUL `\0`, Bell `\x07`, or noncharacters `\u{FFFE}`/`\u{FFFF}`) are rejected as `not-well-formed` before structural policy ceilings trigger.

3. **UTF-8 Character Boundary Totality**:
   - All incremental cursor positions (`cursor`, `start`, `name_end`) are checked with `offsets_are_safe_for` before indexing into `str` slices.
   - When caller buffers are truncated, cleared, or replaced, state is defensively reset rather than causing panic or slice boundary misalignment.

4. **Restricted XML Feature Prohibition (RFC 6120 §11.1)**:
   - Forbids XML Comments (`<!-- ... -->`).
   - Forbids Processing Instructions (`<?target ... ?>`).
   - Forbids DTDs / Document Type Declarations (`<!DOCTYPE ... >`, `<!ENTITY ... >`).
   - Forbids non-predefined entity references (allowing only `&amp;`, `&lt;`, `&gt;`, `&apos;`, `&quot;`, and numeric character references `&#...;`, `&#x...;`).

5. **XML Declaration Placement & Grammar**:
   - XML declaration (`<?xml ... ?>`) is only permitted at the very beginning of an XML entity (before any whitespace or stanzas).
   - Only XML version `1.0` is accepted; encoding must be `UTF-8` (case-insensitive).
   - Only `version`, `encoding`, and `standalone` attributes in valid XML declaration order are allowed.

6. **Balanced Depth Tracking**:
   - Matches opening and closing QNames accurately across nested stanzas (e.g. MAM results containing forwarded messages).
   - Self-closing elements (`<x/>`) do not allocate on the element balancing stack.

---

## 7. Known Integration Risks & Mitigations

1. **`anyhow` Error Downcasting Across Crate Boundaries**:
   - *Risk:* `stream_error_condition` uses `error.downcast_ref::<XmlFramingError>()`. If the root crate and `northstar-xml-framing` compile against different versions of `thiserror` or different type IDs, downcasting could fail and default to `"not-well-formed"`.
   - *Mitigation:* Both root and `northstar-xml-framing` specify `thiserror = "2.0"` and `anyhow = "1.0"`. `XmlFramingError` is public and `stream_error_condition` is exported directly from `northstar-xml-framing`.

2. **Buffer Retain-and-Append Contract**:
   - *Risk:* Transports maintaining long-lived buffers must ensure `framer.reset_entity()` is called on TLS/SASL restart, and `framer.reset_pending_frame()` is called on per-frame boundaries (e.g. WebSocket).
   - *Mitigation:* Invariant totality checks (`offsets_are_safe_for`) prevent crashes if a transport violates buffer continuity, safely resetting cursor progress.

3. **Zero External Dependency Guarantee**:
   - *Risk:* Introducing dependencies like `roxmltree`, `tokio`, or `tracing` would couple framing to specific runtime or DOM implementations.
   - *Mitigation:* `northstar-xml-framing` depends exclusively on `anyhow` and `thiserror`. Declaration attribute parsing is implemented with zero-allocation slicing.
