# Migration Ledger: `northstar-xep-0045`

## 1. Overview & Extraction Scope
`northstar-xep-0045` is a capability-free, transport-neutral domain and wire-protocol crate implementing XEP-0045 (Multi-User Chat) for Northstar.

- **Crate**: `crates/northstar-xep-0045`
- **Edition / Toolchain**: Rust 2021, rust-version 1.97, AGPL-3.0-only, publish = false, `#![forbid(unsafe_code)]`
- **Allowed Dependencies**: `northstar-xep-core`, `northstar-xmpp-types`, `roxmltree`, `thiserror`, `serde` (optional).
- **Forbidden Dependencies**: SQLx/PgPool, Redis, Tokio, Axum, sockets, filesystem, env, AppState, global state, logging, workers, migrations, persistence, cluster ownership, event sequencing, outbox/delivery, federation transport, and HTTP.

---

## 2. Source Files & Symbol Mapping

| Legacy Source Location | Extracted Symbol / Function | Extracted Target Module (`northstar-xep-0045`) |
| :--- | :--- | :--- |
| `src/xmpp/protocol/muc.rs` (329-441) | `muc_room_configuration_form` | `form::build_room_configuration_form` |
| `src/xmpp/protocol/muc.rs` (3932-4010) | Form submission parsing & validation | `form::parse_room_configuration_submit`, `form::RoomConfig` |
| `src/xmpp/protocol/muc.rs` (444-470) | `can_retrieve_muc_affiliation_list` | `permissions::evaluate_affiliation_list_access` |
| `src/xmpp/protocol/muc.rs` (472-484) | `should_broadcast_offline_affiliation_change` | `permissions::should_broadcast_offline_affiliation_change` |
| `src/xmpp/protocol/muc.rs` (485-505) | `muc_offline_affiliation_change_notice` | `presence::build_offline_affiliation_notice` |
| `src/xmpp/protocol/muc.rs` (667-745) | `parse_muc_history_request` | `message::parse_history_request`, `message::MucHistoryRequest` |
| `src/xmpp/protocol/muc.rs` (747-768) | `apply_muc_history_bounds` | `message::apply_history_bounds` |
| `src/xmpp/protocol/muc.rs` (770-792) | `current_muc_subject_stanza` | `message::build_subject_message` |
| `src/xmpp/protocol/muc.rs` (806-818) | `is_allowed_muc_presence_payload_namespace` | `presence::is_allowed_muc_presence_payload_namespace` |
| `src/xmpp/protocol/muc.rs` (854-889) | `parse_muc_subject_command` | `message::parse_subject_command` |
| `src/xmpp/protocol/muc.rs` (988-1038) | `parse_muc_invitation_decline` | `message::parse_invitation_decline`, `message::InvitationDecline` |
| `src/xmpp/protocol/muc.rs` (1040-1111) | `parse_muc_voice_form` | `admin::parse_voice_form`, `admin::VoiceForm` |
| `src/xmpp/protocol/muc.rs` (2300-2375) | Mediated invite parsing & builder | `message::parse_mediated_invites`, `message::build_mediated_invite_message` |
| `src/xmpp/protocol/muc.rs` (3787-3805) | Owner destroy parsing | `admin::parse_owner_destroy`, `admin::OwnerDestroy` |
| `src/xmpp/protocol/muc.rs` (4430), `src/xmpp/xml_util.rs` (434-451) | `valid_muc_room`, `valid_muc_nick`, `prepare_muc_nick` | `address::RoomName`, `address::OccupantNick`, `address::is_valid_room_name`, `address::is_valid_occupant_nick` |
| `src/xmpp/protocol/muc.rs` (4878-5029), `src/xmpp/xml_util.rs` (480-600) | `muc_presence_stanza`, `muc_presence_stanza_with_status` | `presence::build_muc_presence`, `presence::build_nick_change_presence` |
| `src/xmpp/protocol/muc.rs` (6079-6209) | Admin query parsing & response builder | `admin::parse_admin_query`, `admin::build_admin_query_result`, `admin::AdminItem` |
| `src/xmpp/protocol/muc.rs` (6330-6458) | Role / affiliation change permission matrices | `affiliation::Affiliation::can_modify_affiliation`, `role::Role::can_modify_role` |
| `src/xmpp/xml_util.rs` (474-478) | `muc_occupant_key` | `address::occupant_key` |
| `src/xmpp/xml_util.rs` (625-651) | `muc_destroy_presence` | `presence::build_destroy_presence` |

---

## 3. Exported Public API

The crate is structured into focused modules:

### `affiliation`
- `pub enum Affiliation { Owner, Admin, Member, None, Outcast }`
- `pub enum AffiliationError { Forbidden, NotAllowed, SelfBanConflict, InvalidAffiliation }`
- Methods: `as_str()`, `from_str_name()`, `rank()`, `is_privileged()`, `is_member_or_above()`, `can_modify_affiliation()`.

### `role`
- `pub enum Role { Moderator, Participant, Visitor, None }`
- `pub enum RoleError { Forbidden, NotAllowed, InvalidRole }`
- Methods: `as_str()`, `from_str_name()`, `rank()`, `is_voice()`, `is_moderator()`, `default_for(affiliation, moderated_room)`, `can_modify_role()`.

### `status_code`
- `pub enum StatusCode { NonAnonymous (100), ConfigChanged (104), SelfPresence (110), LoggingEnabled (170), LoggingDisabled (171), NonAnonymousShow (172), SemiAnonymousShow (173), FullyAnonymousShow (174), RoomCreated (201), NickAssigned (210), Banned (301), NewNickname (303), Kicked (307), AffiliationLost (321), MembersOnlyRemoval (322), SystemShutdown (332), Disconnected (333), Custom(u16) }`
- Methods: `from_u16()`, `as_u16()`, `is_removal()`, `is_informational()`, `description()`.

### `address`
- `pub struct RoomName` (1..=255 UTF-8 bytes, RFC 7622 PRECIS localpart validation, no whitespace/disallowed characters).
- `pub struct OccupantNick` (1..=128 UTF-8 bytes, RFC 8265 PRECIS `OpaqueString` case-preserving resourcepart validation).
- `pub struct MucRoomJid` (validated bare room address `room@service`).
- `pub struct MucOccupantJid` (validated full occupant address `room@service/nick`).
- `pub fn occupant_key(room_jid: &str, nick: &str) -> Result<String, AddressError>`.
- `pub fn is_valid_room_name(value: &str) -> bool`.
- `pub fn is_valid_occupant_nick(value: &str) -> bool`.

### `form`
- `pub struct RoomConfig` (domain configuration fields: title, description, persistent, members_only, public, moderated, non_anonymous, max_occupants [2..=1000], password_protected, room_secret, allow_subject_change, allow_invites, allow_private_messages, logging_enabled, allow_registration).
- `pub enum PrivateMessagePolicy { Anyone, None }`.
- `pub fn build_room_configuration_form(config: &RoomConfig, fallback_room_name: &str) -> String`.
- `pub fn parse_room_configuration_submit(form_node: Node, base_config: &RoomConfig) -> Result<RoomConfig, FormError>`.

### `permissions`
- `pub enum PermissionDecision { Allowed, Denied(PermissionDeniedReason) }`.
- `pub enum PermissionDeniedReason { Forbidden, RegistrationRequired, NotAuthorized, Conflict, ServiceUnavailable, ItemNotFound, NotAllowed, BadRequest, NotAcceptable }`.
- Pure evaluation functions:
  - `evaluate_room_configuration_access(...)`
  - `evaluate_room_join(...)`
  - `evaluate_discussion_message(...)`
  - `evaluate_subject_change(...)`
  - `evaluate_invitation(...)`
  - `evaluate_affiliation_list_access(...)`
  - `evaluate_role_list_access(...)`
  - `should_broadcast_offline_affiliation_change(...)`

### `transitions`
- `pub struct OccupantSnapshot`.
- `pub struct JoinOutcome`.
- `pub struct NickChangeOutcome`.
- `pub struct AffiliationChangeOutcome`.
- `pub struct RoleChangeOutcome`.
- `pub struct RoomPolicyUpdateDiff`.
- Pure state computation functions:
  - `compute_join_transition(...)`
  - `compute_nick_change_transition(...)`
  - `compute_affiliation_change_transition(...)`
  - `compute_role_change_transition(...)`
  - `evaluate_room_policy_update(...)`

### `message`
- `pub struct MediatedInvite { to: String, reason: Option<String> }`.
- `pub struct InvitationDecline { to: String, reason: Option<String> }`.
- `pub struct MucHistoryRequest { max_stanzas: usize, max_chars: Option<usize>, seconds: Option<u64>, since: Option<String> }`.
- `pub fn parse_mediated_invites(root: Node) -> Result<Vec<MediatedInvite>, MessageError>`.
- `pub fn build_mediated_invite_message(...) -> String`.
- `pub fn parse_invitation_decline(root: Node) -> Result<Option<InvitationDecline>, MessageError>`.
- `pub fn build_invitation_decline_message(...) -> String`.
- `pub fn parse_subject_command(root: Node) -> Result<Option<String>, MessageError>`.
- `pub fn build_subject_message(...) -> String`.
- `pub fn parse_history_request(root: Node) -> Result<MucHistoryRequest, MessageError>`.
- `pub fn apply_history_bounds(stanzas: Vec<String>, request: MucHistoryRequest) -> Vec<String>`.

### `presence`
- `pub struct MucJoinRequest { password: Option<String>, history: MucHistoryRequest }`.
- `pub struct MucUserItem { affiliation: Affiliation, role: Role, jid: Option<String>, nick: Option<String>, actor_nick: Option<String>, reason: Option<String> }`.
- `pub struct MucDestroyPayload { alternate_jid: Option<String>, reason: Option<String>, password: Option<String> }`.
- `pub struct MucUserPresencePayload { item: Option<MucUserItem>, status_codes: Vec<StatusCode>, destroy: Option<MucDestroyPayload> }`.
- `pub fn parse_muc_join_request(root: Node) -> Result<Option<MucJoinRequest>, PresenceError>`.
- `pub fn parse_muc_user_presence(root: Node) -> Result<Option<MucUserPresencePayload>, PresenceError>`.
- `pub fn build_muc_presence(...) -> String`.
- `pub fn build_nick_change_presence(...) -> String`.
- `pub fn build_destroy_presence(...) -> String`.
- `pub fn build_offline_affiliation_notice(...) -> String`.
- `pub fn is_allowed_muc_presence_payload_namespace(ns: &str) -> bool`.

### `admin`
- `pub struct AdminItem`.
- `pub struct AdminQuery`.
- `pub struct OwnerDestroy`.
- `pub enum VoiceForm { Request, Approval { jid: String, nick: String, allow: bool } }`.
- `pub fn parse_admin_query(query: Node) -> Result<AdminQuery, AdminError>`.
- `pub fn build_admin_query_result(items: &[AdminItem]) -> String`.
- `pub fn parse_owner_destroy(destroy: Node) -> Result<OwnerDestroy, AdminError>`.
- `pub fn build_owner_destroy(...) -> String`.
- `pub fn parse_voice_form(root: Node) -> Result<Option<VoiceForm>, AdminError>`.
- `pub fn build_voice_request_form() -> String`.
- `pub fn build_voice_approval_form(...) -> String`.

---

## 4. Server-Owned Authority (Deliberately Excluded)
The following runtime, persistence, and infrastructural capabilities remain strictly server-owned and are deliberately excluded from this crate:
1. **Database & Storage**: PostgreSQL schemas, migrations, `PgPool`, SQL queries (`src/db/muc.rs`, `src/db/cluster_muc.rs`), Argon2 password hashing computations, MAM history persistence, retention policies.
2. **Cluster & Transport**: Redis pub/sub, node leases, cluster epochs, occupancy registration caches, inter-node fan-out, outbox queues.
3. **Session & Routing**: Tokio async tasks, connection UUIDs, stream management session resumption, live occupant registries (`DashMap`), delivery pipelines.
4. **XEP-0421 Occupant Identifiers**: HMAC-SHA-256 room secret key derivation is a server-side cryptographic service.
5. **OMEMO Integration**: Real-JID disclosure rules for encryption are modeled as policy inputs (`non_anonymous: bool`), not hardcoded protocol constraints.

---

## 5. Temporary Duplication
During this extraction phase:
- `crates/northstar-xep-0045` operates as an independent, standalone library crate.
- `src/xmpp/protocol/muc.rs`, `src/xmpp/protocol/federated_muc.rs`, `src/db/muc.rs`, and `src/xmpp/xml_util.rs` remain untouched.
- Both protocol logic implementations are functionally interchangeable and can be migrated file-by-file without breaking existing builds.

---

## 6. Future Root Integration Steps

1. **Root `Cargo.toml` update**:
   ```toml
   [workspace]
   members = [
       ".",
       "crates/northstar-xep-0045",
       # ... other crates
   ]

   [dependencies]
   northstar-xep-0045 = { path = "crates/northstar-xep-0045" }
   ```

2. **Remove crate-local `[workspace]` header**:
   Remove `[workspace]` from `crates/northstar-xep-0045/Cargo.toml` when joining the root workspace.

3. **Replace legacy duplicated logic**:
   - Re-export wire builders and parsers from `northstar-xep-0045` in `src/xmpp/xml_util.rs` and `src/xmpp/protocol/muc.rs`.
   - Update `MucRoom` and `AppState` to use typed `Affiliation`, `Role`, `StatusCode`, and `RoomConfig`.
   - Replace manual XML parsing in `muc_presence`, `muc_message`, `muc_admin_set`, `muc_owner_set` with crate parsers.

---

## 7. Consumers to Migrate

1. **Protocol Handlers**:
   - `src/xmpp/protocol/muc.rs`: Local occupant join, leave, presence fan-out, subject, invites, voice requests, owner/admin IQs.
   - `src/xmpp/protocol/federated_muc.rs`: S2S remote occupant presence, message routing, history access, and federated affiliations.
   - `src/xmpp/protocol/disco.rs`: Service discovery feature advertisement (XEP-0045 disco features and identities).

2. **Database Repositories**:
   - `src/db/muc.rs`: Room creation, room configuration form updates, affiliation tables, history queries.
   - `src/db/cluster_muc.rs`: Clustered occupancy state transitions, eviction tracking.

3. **HTTP / Admin APIs**:
   - `src/api/admin.rs`: Room destruction and affiliation management endpoints.

4. **Stream Management & Session Restoration**:
   - `src/xmpp/protocol/sm.rs`: Rejoining MUC rooms on resumed XEP-0198 sessions.

---

## 8. Suspected Legacy Defects & Inconsistencies

During the extraction and analysis of `src/xmpp/protocol/muc.rs`, `src/xmpp/protocol/federated_muc.rs`, and `src/db/muc.rs`, the following ambiguities and legacy inconsistencies were identified:

1. **MUC Admin IQ Batch Role Modifications**:
   - *Legacy Behavior*: `src/xmpp/protocol/muc.rs` line 6299 explicitly rejects MUC Admin IQ requests containing multiple `<item role="..."/>` children (`if role_count > 1 { return Err(bad-request); }`), while permitting batch affiliation changes.
   - *XEP-0045 Specification*: Section 8.2 allows multiple role change items in a single IQ-set.
   - *Status in extracted crate*: `admin::parse_admin_query` accepts arbitrary numbers of items; `Role::can_modify_role` validates each item independently.

2. **Affiliation List Visibility in Members-Only Rooms**:
   - *Legacy Behavior*: `src/xmpp/protocol/muc.rs` line 444 (`can_retrieve_muc_affiliation_list`) permits members of members-only, non-anonymous rooms to retrieve `owner` and `admin` lists in addition to `member`.
   - *XEP-0045 Specification*: Section 9.5 specifies that non-privileged members may only retrieve the `member` list. The server notes this as an extension for OMEMO encryption key discovery.
   - *Status in extracted crate*: Preserved as an explicit policy evaluation parameter (`evaluate_affiliation_list_access(requester, requested, members_only, non_anonymous)`).

3. **Subject Change Command Exclusivity**:
   - *Legacy Behavior*: `src/xmpp/protocol/muc.rs` line 854 (`parse_muc_subject_command`) rejects messages containing both `<subject/>` and `<body/>`/`<thread/>` from mutating the persistent room subject, treating them as normal discussion.
   - *XEP-0045 Specification*: Section 7.2.16 states that subject changes can be accompanied by descriptive message bodies in some implementations, but subject-only groupchat messages are standard for atomic mutations.
   - *Status in extracted crate*: Extracted as `parse_subject_command` adhering to the legacy safe semantics (subject-only groupchat message mutates subject).

4. **Status Code 322 vs 321 on Members-Only Policy Update**:
   - *Legacy Behavior*: `src/xmpp/protocol/muc.rs` line 4276 emits status code 322 when evicting non-members upon making a room members-only.
   - *XEP-0045 Specification*: Status code 321 represents removal due to affiliation change, while 322 represents removal because room became members-only. Both are supported in `StatusCode`.
   - *Status in extracted crate*: `StatusCode::MembersOnlyRemoval` (322) and `StatusCode::AffiliationLost` (321) are distinctly typed.

5. **Administrative Reserve Join Calculation**:
   - *Legacy Behavior*: `src/xmpp/protocol/muc.rs` line 5683 hardcodes `room.max_occupants + 10` for owner/admin joins when room capacity is exhausted.
   - *Status in extracted crate*: `permissions::evaluate_room_join` accepts `admin_capacity_reserve: usize` as a pure, configurable parameter.
