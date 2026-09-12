# Migration & Architecture Guide: 
orthstar-xep-0059

This document records the extraction of the canonical, capability-free XEP-0059 Result Set Management (RSM) library into crates/northstar-xep-0059, cataloging all current duplicate implementations across the Northstar codebase, detailed semantic differences, and the future integration plan.

---

## 1. Executive Summary & Invariants

- **Crate Name**: 
orthstar-xep-0059
- **Location**: crates/northstar-xep-0059
- **Specification**: [XEP-0059: Result Set Management](https://xmpp.org/extensions/xep-0059.html) (Version 1.0.0)
- **Policy**: Pure capability-free library crate (#![forbid(unsafe_code)], Rust 2021, ust-version = 1.97, publish = false, license = AGPL-3.0-only).
- **Dependencies**: 
orthstar-xep-core, oxmltree = 0.20, 	hiserror = 2.0, serde = 1.0 (optional).
- **Forbidden Capabilities**: No database engines (sqlx, PgPool), caches (edis), async runtimes (	okio), networking/sockets, filesystem, environment access, logging engines (	racing/log), delivery routing, or global state (AppState).

---

## 2. Catalog of Duplicate RSM Implementations in Northstar

Prior to the creation of 
orthstar-xep-0059, RSM parsing, serialization, and pagination logic was duplicated and fragmented across 8 distinct areas of the server codebase:

| Location | Component / Symbol | Responsibilities & Quirks | Target Replacement in 
orthstar-xep-0059 |
| :--- | :--- | :--- | :--- |
| crates/northstar-xep-0060/src/rsm.rs | RsmRequest, RsmResponse, parse_rsm_element, uild_rsm_set, paginate_items | Temporary internal PubSub copy. Hardcoded MAX_RSM_PAGE_SIZE = 1_000 and MAX_RSM_INDEX = 1_000_000. Direct mapping to PubSubError. | 
orthstar_xep_0059::{RsmRequest, RsmResponse, parse_rsm_element, build_rsm_set, paginate_items, RsmBounds::PUBSUB} |
| src/mam_pubsub_parsing.rs | parse_mam_rsm, parse_pubsub_rsm, MamRsmPage, PubSubRsmRequest | Dual parser implementation for MAM (100 item cap) and PubSub (1000 item cap). Handled string errors (bad-request, resource-constraint). | 
orthstar_xep_0059::{parse_rsm_element_with_bounds, RsmBounds::MAM, RsmBounds::PUBSUB, PagingDirective} |
| src/xmpp/protocol/discovery.rs | DiscoItemsRequest, parse_disco_items_request, disco_rsm_result | Ad-hoc RSM parser embedded in disco logic with 100 max cap. Standalone string builder disco_rsm_result_element. | 
orthstar_xep_0059::{parse_rsm_from_parent_with_bounds, build_rsm_set, RsmBounds::DISCOVERY} |
| src/xmpp/protocol/mam.rs | ParsedMamRsmPage, inline fin/set XML rendering | Manual <fin> and <set> XML element construction for personal MAM responses. | 
orthstar_xep_0059::{RsmFin, build_mam_fin, build_rsm_set} |
| src/xmpp/protocol/mix.rs | Inline MAM fin/set response formatting | Manual XML element builder in handle_mam_query. | 
orthstar_xep_0059::{RsmFin, build_mam_fin} |
| src/xmpp/protocol/federated_muc.rs | Inline MAM fin/set response formatting | Manual XML element builder in federated MAM response pipeline. | 
orthstar_xep_0059::{RsmFin, build_mam_fin} |
| src/db/archive.rs & src/db/mix.rs | MamRsmPage | Database query cursor enum (First, Last, Before(Uuid), After(Uuid), Index(i64)). | Maps 1:1 with 
orthstar_xep_0059::PagingDirective. |
| src/api/users.rs | REST API query mapper | REST query parameters (sm_after, sm_before, sm_index, sm_page) mapped to MamRsmPage. | Compatible with 
orthstar_xep_0059::PagingDirective. |

---

## 3. Protocol Semantics, Invariants, and Edge Cases

The 
orthstar-xep-0059 crate strictly implements the canonical XEP-0059 specification:

1. **Empty <before/> vs Specified <before>id</before>**:
   - <before/> or <before></before> (empty text) requests the *last page* of results (XEP-0059 §2.5). Typed as BeforeCursor::LastPage.
   - <before>id</before> requests the page of results *preceding* id. Typed as BeforeCursor::Item(id).
   - Missing <before> tag is represented as None.

2. **Empty <after/> Prohibited**:
   - While empty <before/> has a standardized last-page meaning, <after/> with empty or whitespace-only text is strictly invalid and rejected with RsmError::EmptyCursor(after).

3. **Mutual Exclusion**:
   - A client MUST NOT provide more than one of <after>, <before>, or <index> in a single <set> request.
   - Any conflicting combination is rejected with RsmError::MutuallyExclusiveCursors.

4. **Result Set Size Querying (<max>0</max>)**:
   - Per XEP-0059 §2.7, <max>0</max> asks for the total size of the result set without returning any items.
   - paginate_slice and paginate_items handle max == 0 by returning an empty slice/vector and setting count = Some(total) with irst = None and last = None.

5. **Empty Result Set Semantics**:
   - Per XEP-0059 §2.6, if a query yields 0 items, <set> MUST omit <first> and <last>, returning only <count>0</count> (or omitting first/last when <count> is provided).
   - RsmResponse::empty(count) and is_empty_page() guarantee safe compliance.

6. **Configurable Operational Bounds**:
   - RsmBounds allows subsystems to define their own limits while sharing parser logic:
     - RsmBounds::MAM: max_page_size = 100, max_cursor_bytes = 1024, max_index = 1_000_000.
     - RsmBounds::DISCOVERY: max_page_size = 100, max_cursor_bytes = 1024, max_index = 1_000_000.
     - RsmBounds::PUBSUB: max_page_size = 1000, max_cursor_bytes = 1024, max_index = 1_000_000.
     - RsmBounds::DEFAULT: max_page_size = 1000, max_cursor_bytes = 1024, max_index = 1_000_000.

7. **Error Mapping**:
   - RsmError::to_xmpp_error_condition() provides deterministic mapping to RFC 6120 stanza error conditions:
     - IndexLimitExceeded -> resource-constraint
     - ItemNotFound -> item-not-found
     - Syntax, attribute, namespace, duplicate, or malformed errors -> bad-request

8. **Pure Zero-Copy In-Memory Pagination**:
   - paginate_slice works directly over &'a [T] without cloning elements, returning (&'a [T], RsmResponse).
   - paginate_items provides owned (Vec<T>, RsmResponse) for cloning callers.

---

## 4. Server Integration & Adapter Roadmap

During the root integration phase, existing duplicate implementations should be migrated as follows:

1. **Workspace Registration**:
   - Add crates/northstar-xep-0059 to the root Cargo.toml workspace.members array.
   - Remove the temporary [workspace] header from crates/northstar-xep-0059/Cargo.toml.

2. **
orthstar-xep-0060 Integration**:
   - Add 
orthstar-xep-0059 = { path = ../northstar-xep-0059 } to crates/northstar-xep-0060/Cargo.toml.
   - In crates/northstar-xep-0060/src/rsm.rs, re-export or alias types from 
orthstar_xep_0059.

3. **src/mam_pubsub_parsing.rs**:
   - Replace internal parse_mam_rsm and parse_pubsub_rsm with 
orthstar_xep_0059::parse_rsm_element_with_bounds(&RsmBounds::MAM) and &RsmBounds::PUBSUB.
   - Replace PubSubRsmRequest with 
orthstar_xep_0059::RsmRequest.

4. **Service Discovery (src/xmpp/protocol/discovery.rs)**:
   - Replace parse_disco_items_request inline RSM parsing with 
orthstar_xep_0059::parse_rsm_from_parent_with_bounds(&RsmBounds::DISCOVERY).
   - Replace disco_rsm_result_element with 
orthstar_xep_0059::build_rsm_set_raw.

5. **MAM & MIX Response Rendering**:
   - Replace manual <fin> and <set> generation in mam.rs, mix.rs, and ederated_muc.rs with 
orthstar_xep_0059::build_mam_fin.
