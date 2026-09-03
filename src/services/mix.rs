//! Application-service boundary for XEP-0369/XEP-0405 MIX.
//!
//! The protocol module owns XML parsing and stanza error mapping. This type is
//! the only MIX capability exposed by `AppState`; it owns PostgreSQL access,
//! cross-table transactions and durable federation admission.

use crate::abuse::{MixMessageContentKeyring, MixRetractionContentKeyring};
use crate::db;
use anyhow::Result;
use chrono::{DateTime, Utc};
use northstar_xml_builder::XmlElement;
use sqlx::PgPool;
use std::collections::BTreeSet;
use std::sync::Arc;
use tokio::sync::{Mutex, MutexGuard};
use uuid::Uuid;

// XEP-0369 node identifiers owned by the application boundary.  The repository
// keeps identically-valued storage constants; protocol code may only name
// these.
pub(crate) const NODE_MESSAGES: &str = "urn:xmpp:mix:nodes:messages";
pub(crate) const NODE_PRESENCE: &str = "urn:xmpp:mix:nodes:presence";
pub(crate) const NODE_PARTICIPANTS: &str = "urn:xmpp:mix:nodes:participants";
pub(crate) const NODE_INFO: &str = "urn:xmpp:mix:nodes:info";
pub(crate) const NODE_CONFIG: &str = "urn:xmpp:mix:nodes:config";
pub(crate) const NODE_ALLOWED: &str = "urn:xmpp:mix:nodes:allowed";
pub(crate) const NODE_BANNED: &str = "urn:xmpp:mix:nodes:banned";
pub(crate) const NODE_JIDMAP: &str = "urn:xmpp:mix:nodes:jidmap";
pub(crate) const NODE_AVATAR_DATA: &str = "urn:xmpp:avatar:data";
pub(crate) const NODE_AVATAR_METADATA: &str = "urn:xmpp:avatar:metadata";
pub(crate) const CORE_NODES: [&str; 4] =
    [NODE_MESSAGES, NODE_PRESENCE, NODE_PARTICIPANTS, NODE_INFO];
pub(crate) const ALL_NODES: [&str; 10] = [
    NODE_MESSAGES,
    NODE_PRESENCE,
    NODE_PARTICIPANTS,
    NODE_INFO,
    NODE_CONFIG,
    NODE_ALLOWED,
    NODE_BANNED,
    NODE_JIDMAP,
    NODE_AVATAR_DATA,
    NODE_AVATAR_METADATA,
];

/// A MIX channel's authoritative configuration as observed by the protocol
/// layer. Field names deliberately mirror the repository row so the mapping in
/// this service is a pure, reviewable translation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MixChannel {
    pub(crate) id: Uuid,
    pub(crate) revision: i64,
    pub(crate) service_domain: String,
    pub(crate) localpart: String,
    pub(crate) creator_jid: String,
    pub(crate) name: Option<String>,
    pub(crate) description: Option<String>,
    pub(crate) contacts: Vec<String>,
    pub(crate) access_model: String,
    pub(crate) jid_visibility: String,
    pub(crate) nick_required: bool,
    pub(crate) max_participants: i32,
    pub(crate) max_events: i32,
    pub(crate) allow_private_messages: bool,
    pub(crate) allow_participant_invites: bool,
    pub(crate) allow_user_message_retraction: bool,
    pub(crate) administrator_retraction_rights: String,
    pub(crate) enforce_registered_nick: bool,
}

impl MixChannel {
    pub(crate) fn jid(&self) -> String {
        format!("{}@{}", self.localpart, self.service_domain)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MixParticipant {
    pub(crate) participant_id: Uuid,
    pub(crate) jid: String,
    pub(crate) nick: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MixParticipantPreference {
    pub(crate) jid_visibility: String,
    pub(crate) private_messages: String,
    pub(crate) vcard: String,
    pub(crate) share_presence: bool,
}

impl Default for MixParticipantPreference {
    fn default() -> Self {
        Self {
            jid_visibility: "default".to_owned(),
            private_messages: "allow".to_owned(),
            vcard: "block".to_owned(),
            share_presence: true,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MixEvent {
    pub(crate) id: Uuid,
    pub(crate) item_id: String,
    pub(crate) payload: String,
    pub(crate) created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MixEventPage {
    pub(crate) events: Vec<MixEvent>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MixReadOutcome<T> {
    Found(T),
    Unauthorized,
    NotFound,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MixMamPage {
    pub(crate) events: Vec<MixEvent>,
    pub(crate) total: i64,
    pub(crate) first_index: i64,
    pub(crate) complete: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MixPresenceItem {
    pub(crate) item_id: String,
    pub(crate) payload: String,
    pub(crate) source_full_jid: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MixPresenceProbeTarget {
    pub(crate) channel_jid: String,
    pub(crate) participant_jid: String,
}

#[derive(Clone, Debug)]
pub(crate) struct ClaimedMixDelivery {
    pub(crate) delivery_id: Uuid,
    pub(crate) event_id: Uuid,
    pub(crate) channel_id: Uuid,
    pub(crate) channel_jid: String,
    pub(crate) recipient: MixParticipant,
    pub(crate) stanza: String,
    pub(crate) authoritative_stanza_id: Option<Uuid>,
    pub(crate) archive: bool,
    pub(crate) encrypted: bool,
    pub(crate) attempt_count: i32,
    pub(crate) lease_token: Uuid,
    pub(crate) created_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub(crate) struct ClaimedPamResult {
    pub(crate) operation_id: Uuid,
    pub(crate) user_id: Uuid,
    pub(crate) requester_full_jid: String,
    pub(crate) response_xml: String,
    pub(crate) attempt_count: i32,
    pub(crate) lease_token: Uuid,
}

#[allow(dead_code)] // MIX admin HTTP wiring is intentionally left to the root integration pass.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MixDeliveryDeadLetter {
    pub(crate) dead_letter_id: Uuid,
    pub(crate) delivery_id: Uuid,
    pub(crate) event_id: Uuid,
    pub(crate) channel_id: Uuid,
    pub(crate) channel_jid: String,
    pub(crate) recipient_jid: String,
    pub(crate) attempt_count: i32,
    pub(crate) terminal_reason: String,
    pub(crate) last_error: Option<String>,
    pub(crate) failed_at: DateTime<Utc>,
}

impl From<db::MixPresenceProbeTarget> for MixPresenceProbeTarget {
    fn from(target: db::MixPresenceProbeTarget) -> Self {
        Self {
            channel_jid: target.channel_jid,
            participant_jid: target.participant_jid,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExpiredMixPresence {
    pub(crate) channel_id: Uuid,
    pub(crate) participant: MixParticipant,
    pub(crate) item_id: String,
    pub(crate) payload: String,
    pub(crate) source_full_jid: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PamMembership {
    pub(crate) id: Uuid,
    pub(crate) user_id: Uuid,
    pub(crate) channel_jid: String,
    pub(crate) participant_id: Option<String>,
    pub(crate) state: String,
    pub(crate) request_id: Option<String>,
    pub(crate) client_request_id: Option<String>,
    pub(crate) requester_full_jid: Option<String>,
    pub(crate) subscriptions: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MixInvitationProof {
    pub(crate) inviter_jid: String,
    pub(crate) invitee_jid: String,
    pub(crate) channel_jid: String,
    pub(crate) token: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MixDiscoPage {
    pub(crate) channels: Vec<MixChannel>,
    pub(crate) total: i64,
    pub(crate) first_index: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ArchiveBoundary {
    pub(crate) id: Uuid,
    pub(crate) created_at: chrono::DateTime<chrono::Utc>,
}

/// Owned MIX join request. The repository keeps its borrowed view; this copy
/// is what the protocol layer constructs from parsed XML.
#[derive(Clone, Debug)]
pub(crate) struct JoinMixRequest {
    pub(crate) actor_jid: String,
    pub(crate) nick: Option<String>,
    pub(crate) nodes: Vec<String>,
    /// Set only for a local MIX-PAM operation. The membership is committed in
    /// the same transaction as the local channel participant.
    pub(crate) pam_user_id: Option<Uuid>,
    /// A XEP-0407 invitation is consumed atomically with an allow-list join.
    pub(crate) invitation: Option<MixInvitationProof>,
    /// XEP-0404 preferences supplied with the join. Missing preferences use
    /// the specification defaults and are committed with membership.
    pub(crate) preference: Option<MixParticipantPreference>,
    /// Selects the anonymous-profile namespace on the direct Core result.
    pub(crate) anonymous_profile: bool,
}

/// Owned MIX-PAM federation request.  Keeping every parsed value owned at the
/// application boundary prevents an outstanding asynchronous request from
/// retaining protocol-buffer borrows and gives the service one place to bind
/// the account UUID to the authenticated canonical actor.
#[derive(Clone, Debug)]
pub(crate) struct BeginRemotePamJoin {
    pub(crate) user_id: Uuid,
    pub(crate) actor_jid: String,
    pub(crate) channel_jid: String,
    pub(crate) nick: Option<String>,
    pub(crate) nodes: Vec<String>,
    pub(crate) request_id: String,
    pub(crate) client_request_id: String,
    pub(crate) requester_full_jid: String,
    pub(crate) request_digest: [u8; 32],
    pub(crate) remote_domain: String,
    pub(crate) outbound_stanza: String,
    pub(crate) policy: S2sOutboxPolicy,
}

#[derive(Clone, Debug)]
pub(crate) struct BeginRemotePamLeave {
    pub(crate) user_id: Uuid,
    pub(crate) actor_jid: String,
    pub(crate) channel_jid: String,
    pub(crate) request_id: String,
    pub(crate) client_request_id: String,
    pub(crate) requester_full_jid: String,
    pub(crate) request_digest: [u8; 32],
    pub(crate) remote_domain: String,
    pub(crate) outbound_stanza: String,
    pub(crate) policy: S2sOutboxPolicy,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PamOperationReplay {
    Miss,
    Pending,
    Replay(String),
    Conflict,
}

#[derive(Clone, Debug)]
pub(crate) struct RemotePamCompletion {
    pub(crate) response_xml: String,
    pub(crate) membership: Option<PamMembership>,
    pub(crate) applied: bool,
    pub(crate) roster_removed: Option<bool>,
}

#[derive(Clone, Debug)]
pub(crate) enum RemotePamCompletionOutcome {
    Applied(RemotePamCompletion),
    Replay(RemotePamCompletion),
    Conflict,
    Missing,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct RemotePamJoin<'a> {
    pub(crate) participant_id: &'a str,
    pub(crate) subscriptions: &'a [String],
    pub(crate) nick: Option<&'a str>,
}

/// Idempotent personal archive projection for a reflected MIX message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SourceArchiveAdmission {
    Stored(Uuid),
    Replay(Uuid),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CreateChannelOutcome {
    Created(Uuid),
    Conflict,
    QuotaExceeded,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum JoinChannelOutcome {
    Joined {
        participant: MixParticipant,
        preference: MixParticipantPreference,
        subscriptions: Vec<String>,
        newly_joined: bool,
        /// The roster service's own boundary type: MIX-PAM projects channel
        /// participation into the owner's roster through that service.
        roster_change: Option<Box<northstar_roster_core::RosterChange>>,
    },
    Banned,
    NotAllowed,
    Full,
    MissingNick,
    NickConflict,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StoreEventOutcome {
    Stored(Uuid),
    Replay(Uuid),
    NotParticipant,
    Conflict,
    TooLarge,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StoreMixMessageAdmission {
    pub(crate) outcome: StoreEventOutcome,
    /// Audience captured while the channel lock and archive transaction were
    /// still held. Join/leave/subscription changes use the same lock, so a
    /// committed message has one linearizable recipient set.
    pub(crate) recipients: Vec<MixParticipant>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MixMutationAdmission {
    pub(crate) channel: MixChannel,
    pub(crate) node: String,
    pub(crate) item_id: String,
    pub(crate) payload: String,
    pub(crate) recipients: Vec<MixParticipant>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LeaveMixOutcome {
    pub(crate) participant: MixParticipant,
    pub(crate) presence_items: Vec<MixPresenceItem>,
    pub(crate) roster_change: Option<northstar_roster_core::RosterChange>,
}

#[derive(Clone, Debug)]
pub(crate) enum PresenceOutcome {
    Published,
    Retracted,
    Unchanged,
    NotSharing,
    NotParticipant,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct UpdateSubscriptionsOutcome {
    pub(crate) subscriptions: Vec<String>,
    pub(crate) participant: MixParticipant,
    pub(crate) removed_presence: Vec<MixPresenceItem>,
}

#[derive(Clone, Debug)]
pub(crate) struct MixParticipantPreferenceUpdateOutcome {
    pub(crate) participant: MixParticipant,
    pub(crate) roster_changes: Vec<(Uuid, northstar_roster_core::RosterChange)>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct AccessChangeOutcome {
    pub(crate) removed_participants: Vec<Uuid>,
    pub(crate) removed_local_users: Vec<Uuid>,
    /// Current presence items removed as a consequence of a ban.  The
    /// protocol layer uses these to publish the mandatory unavailable
    /// transition instead of leaving subscribers with a ghost resource.
    pub(crate) removed_presence: Vec<(MixParticipant, Vec<MixPresenceItem>)>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SetNickError {
    NotParticipant,
    Conflict,
}

#[derive(Clone, Debug)]
pub(crate) enum RegisterMixNickOutcome {
    Registered { nick: String },
    Conflict,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RetractMixMessageOutcome {
    Retracted,
    Replay(Uuid),
    Conflict,
    NotFound,
    Forbidden,
}

#[derive(Clone, Debug)]
pub(crate) struct MixReplayIdentity {
    pub(crate) client_id: String,
    pub(crate) canonical_semantics: Vec<u8>,
}

pub(crate) struct StoreMixMessageRequest<'a> {
    pub(crate) channel_id: Uuid,
    pub(crate) actor: &'a str,
    pub(crate) item_id: &'a str,
    pub(crate) payload: &'a str,
    pub(crate) identity: Option<MixReplayIdentity>,
    pub(crate) delivery_payload: &'a str,
    pub(crate) visible_jid: Option<&'a str>,
    pub(crate) encrypted: bool,
}

pub(crate) struct RetractMixMessageRequest<'a> {
    pub(crate) channel_id: Uuid,
    pub(crate) actor: &'a str,
    pub(crate) target_id: Uuid,
    pub(crate) retraction_id: Uuid,
    pub(crate) tombstone_payload: &'a str,
    pub(crate) retraction_payload: &'a str,
    pub(crate) identity: Option<MixReplayIdentity>,
    pub(crate) visible_jid: Option<&'a str>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MixBusinessReplay {
    Miss,
    Replay(Uuid),
    Conflict,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RetractMixMessageAdmission {
    pub(crate) outcome: RetractMixMessageOutcome,
    pub(crate) recipients: Vec<MixParticipant>,
}

/// Owned channel information update built from a parsed XEP-0060 publish.
#[derive(Clone, Debug)]
pub(crate) struct MixInfoUpdate {
    pub(crate) item_id: String,
    pub(crate) expected_revision: i64,
    pub(crate) name: Option<String>,
    pub(crate) description: Option<String>,
    pub(crate) contacts: Vec<String>,
}

/// Owned channel configuration update built from a parsed XEP-0060 publish.
#[derive(Clone, Debug)]
pub(crate) struct MixConfigUpdate {
    pub(crate) item_id: String,
    pub(crate) expected_revision: i64,
    pub(crate) access_model: String,
    pub(crate) jid_visibility: String,
    pub(crate) nick_required: bool,
    pub(crate) max_participants: i32,
    pub(crate) max_events: i32,
    pub(crate) allow_private_messages: bool,
    pub(crate) allow_participant_invites: bool,
    pub(crate) allow_user_message_retraction: bool,
    pub(crate) administrator_retraction_rights: String,
    pub(crate) enforce_registered_nick: bool,
}

/// Owned administrator role replacement; `None` preserves the current list.
#[derive(Clone, Debug)]
pub(crate) struct MixRoleUpdate {
    pub(crate) owners: Option<Vec<String>>,
    pub(crate) administrators: Option<Vec<String>>,
}

#[derive(Clone, Debug)]
pub(crate) enum MixMutationOutcome {
    Applied(Box<MixMutationAdmission>),
    Conflict,
    Forbidden,
    NotFound,
}

/// Owned mirror of the federation admission policy the protocol reads from
/// the S2S router before batching a federated MAM response stream.
#[derive(Clone, Copy, Debug)]
pub(crate) struct S2sOutboxPolicy {
    pub(crate) ttl_seconds: u64,
    pub(crate) max_rows: i64,
    pub(crate) max_bytes: i64,
    pub(crate) max_per_domain: i64,
}

/// Authenticated identity and exact replay key for one remote mutating IQ.
/// Production protocol code must attach this context to the repository
/// mutation so state, result journal and S2S outbox share one transaction.
#[derive(Clone, Debug)]
pub(crate) struct FederatedMixMutation {
    pub(crate) authenticated_domain: String,
    pub(crate) actor_jid: String,
    pub(crate) request_id: String,
    pub(crate) request_digest: [u8; 32],
    pub(crate) addressed: String,
    pub(crate) reply_to: String,
    pub(crate) policy: S2sOutboxPolicy,
}

fn federated_mutation_db(context: &FederatedMixMutation) -> db::FederatedMixMutation {
    db::FederatedMixMutation {
        authenticated_domain: context.authenticated_domain.clone(),
        actor_jid: context.actor_jid.clone(),
        request_id: context.request_id.clone(),
        request_digest: context.request_digest,
        addressed: context.addressed.clone(),
        reply_to: context.reply_to.clone(),
        policy: db::S2sOutboxPolicy {
            ttl_seconds: context.policy.ttl_seconds,
            max_rows: context.policy.max_rows,
            max_bytes: context.policy.max_bytes,
            max_per_domain: context.policy.max_per_domain,
        },
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum FederatedMixIqReplay {
    Miss,
    Replay(String),
    Conflict,
}

impl From<db::S2sOutboxPolicy> for S2sOutboxPolicy {
    fn from(policy: db::S2sOutboxPolicy) -> Self {
        Self {
            ttl_seconds: policy.ttl_seconds,
            max_rows: policy.max_rows,
            max_bytes: policy.max_bytes,
            max_per_domain: policy.max_per_domain,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct VCardRecord {
    pub(crate) payload_vcard_temp: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PepNodeConfig {
    pub(crate) access_model: String,
    pub(crate) max_items: i32,
    pub(crate) persist_items: bool,
    pub(crate) send_last_published_item: String,
    pub(crate) deliver_notifications: bool,
    pub(crate) roster_groups_allowed: Vec<String>,
    pub(crate) access_whitelist: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MixMucMirror {
    pub(crate) mix_channel_id: Uuid,
    pub(crate) muc_room_id: Uuid,
    pub(crate) localpart: String,
    pub(crate) mix_domain: String,
}

/// MIX-owned XEP-0059 page selector. The MAM slice keeps its own vocabulary;
/// MIX parses the same forms into this boundary type so the repository never
/// receives a protocol-shaped query directly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MamRsmPage {
    First,
    Last,
    Before(Uuid),
    After(Uuid),
    /// XEP-0059 section 2.6 page retrieval by zero-based result index.
    /// The protocol parser applies a production bound before this reaches
    /// PostgreSQL; keeping it in the shared query type makes personal, MUC,
    /// federated-MUC and MIX archives use the same semantics.
    Index(i64),
}

/// MIX-owned archive query consumed by `mix_mam_page*`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MamArchiveQuery {
    pub(crate) with_jid: Option<String>,
    pub(crate) start: Option<DateTime<Utc>>,
    pub(crate) end: Option<DateTime<Utc>>,
    pub(crate) before_id: Option<Uuid>,
    pub(crate) after_id: Option<Uuid>,
    pub(crate) ids: Vec<Uuid>,
    pub(crate) page: MamRsmPage,
    pub(crate) max: i64,
}

impl From<db::MamArchiveQuery> for MamArchiveQuery {
    fn from(query: db::MamArchiveQuery) -> Self {
        Self {
            with_jid: query.with_jid,
            start: query.start,
            end: query.end,
            before_id: query.before_id,
            after_id: query.after_id,
            ids: query.ids,
            page: match query.page {
                db::MamRsmPage::First => MamRsmPage::First,
                db::MamRsmPage::Last => MamRsmPage::Last,
                db::MamRsmPage::Before(id) => MamRsmPage::Before(id),
                db::MamRsmPage::After(id) => MamRsmPage::After(id),
                db::MamRsmPage::Index(index) => MamRsmPage::Index(index),
            },
            max: query.max,
        }
    }
}

fn mam_query_db(query: &MamArchiveQuery) -> db::MamArchiveQuery {
    db::MamArchiveQuery {
        with_jid: query.with_jid.clone(),
        start: query.start,
        end: query.end,
        before_id: query.before_id,
        after_id: query.after_id,
        ids: query.ids.clone(),
        page: match query.page {
            MamRsmPage::First => db::MamRsmPage::First,
            MamRsmPage::Last => db::MamRsmPage::Last,
            MamRsmPage::Before(id) => db::MamRsmPage::Before(id),
            MamRsmPage::After(id) => db::MamRsmPage::After(id),
            MamRsmPage::Index(index) => db::MamRsmPage::Index(index),
        },
        max: query.max,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MixMucLinkOutcome {
    Linked,
    AlreadyLinked,
    MissingCounterpart,
    NotCommonOwner,
    Conflict,
}

/// Minimum enabled local identity needed by MIX/PEP/vCard relays.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MixAccount {
    pub(crate) id: Uuid,
    pub(crate) username: String,
}

/// Business target for one MIX access-list mutation.
///
/// This deliberately lives at the application-service boundary: protocol
/// handlers select an XEP-0406 operation, while the repository retains the
/// persistence representation and transaction semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MixAccessList {
    Allowed,
    Banned,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MixAccessEntryOperation<'a> {
    Publish { reason: Option<&'a str> },
    Retract,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MixAccessEntryUpdate<'a> {
    pub(crate) channel_id: Uuid,
    pub(crate) actor: &'a str,
    pub(crate) pattern: &'a str,
    pub(crate) list: MixAccessList,
    pub(crate) operation: MixAccessEntryOperation<'a>,
}

#[derive(Clone)]
pub(crate) struct MixService {
    pool: PgPool,
    message_identity: MixMessageContentKeyring,
    retraction_identity: MixRetractionContentKeyring,
    /// Fair, process-local admission gate. Every application operation that
    /// can add a durable MIX delivery acquires this before asking PgPool for a
    /// transaction. PostgreSQL keeps the cross-process authority; this gate
    /// prevents ordinary same-process concurrency from occupying a pool of
    /// connections while queued behind that authority.
    delivery_admission: Arc<Mutex<()>>,
    /// Clone-shared FIFO gate for the durable MIX-PAM operation counter. It is
    /// acquired before repository code can check out a PostgreSQL connection,
    /// so one process contributes at most one waiter to the cross-process
    /// singleton authority while unrelated database work retains pool access.
    pam_capacity_admission: Arc<Mutex<()>>,
}

macro_rules! delegate {
    ($(#[$meta:meta])* $name:ident($($arg:ident : $ty:ty),* $(,)?) -> $ret:ty => $path:path;) => {
        $(#[$meta])*
        pub(crate) async fn $name(&self, $($arg: $ty),*) -> Result<$ret> {
            $path(&self.pool, $($arg),*).await
        }
    };
}

impl MixService {
    pub(crate) fn new(
        pool: PgPool,
        message_identity: MixMessageContentKeyring,
        retraction_identity: MixRetractionContentKeyring,
    ) -> Self {
        Self {
            pool,
            message_identity,
            retraction_identity,
            delivery_admission: Arc::new(Mutex::new(())),
            pam_capacity_admission: Arc::new(Mutex::new(())),
        }
    }

    async fn delivery_admission_guard(&self) -> MutexGuard<'_, ()> {
        self.delivery_admission.lock().await
    }

    async fn pam_capacity_admission_guard(&self) -> MutexGuard<'_, ()> {
        self.pam_capacity_admission.lock().await
    }

    #[cfg(test)]
    pub(crate) fn new_with_test_keyrings(pool: PgPool) -> Self {
        Self::new(
            pool,
            crate::abuse::test_mix_message_content_keyring(),
            crate::abuse::test_mix_retraction_content_keyring(),
        )
    }

    /// Atomically link existing same-localpart MIX and MUC entities after the
    /// repository proves that the authenticated bare JID still owns both.
    /// The protocol receives only a typed business outcome, never the pool or
    /// the repository's cross-table mutation primitive.
    pub(crate) async fn link_local_muc_mirror(
        &self,
        mix_domain: &str,
        localpart: &str,
        actor_bare_jid: &str,
        local_domain: &str,
    ) -> Result<MixMucLinkOutcome> {
        Ok(map_mix_muc_link_outcome(
            db::link_mix_muc_by_localpart(
                &self.pool,
                mix_domain,
                localpart,
                actor_bare_jid,
                local_domain,
            )
            .await?,
        ))
    }

    pub(crate) async fn create_mix_channel(
        &self,
        service_domain: &str,
        requested_localpart: Option<&str>,
        creator_jid: &str,
        max_channels_per_owner: i64,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<(CreateChannelOutcome, String)> {
        let federated = federated.map(federated_mutation_db);
        let (outcome, localpart) = db::create_mix_channel(
            &self.pool,
            service_domain,
            requested_localpart,
            creator_jid,
            max_channels_per_owner,
            self,
            federated.as_ref(),
        )
        .await?;
        Ok((create_outcome(outcome), localpart))
    }
    pub(crate) async fn mix_channel(
        &self,
        service_domain: &str,
        localpart: &str,
    ) -> Result<Option<MixChannel>> {
        Ok(db::mix_channel(&self.pool, service_domain, localpart)
            .await?
            .map(map_channel))
    }
    pub(crate) async fn discoverable_mix_channel_page(
        &self,
        service_domain: &str,
        requester: &str,
        after: Option<&str>,
        before: Option<Option<&str>>,
        max: i64,
    ) -> Result<Option<MixDiscoPage>> {
        Ok(db::discoverable_mix_channel_page(
            &self.pool,
            service_domain,
            requester,
            after,
            before,
            max,
        )
        .await?
        .map(|page| MixDiscoPage {
            channels: page.channels.into_iter().map(map_channel).collect(),
            total: page.total,
            first_index: page.first_index,
        }))
    }
    delegate!(mix_role(channel_id: Uuid, jid: &str) -> Option<String> => db::mix_role;);
    pub(crate) async fn mix_channel_discoverable_to(
        &self,
        channel: &MixChannel,
        actor: &str,
    ) -> Result<bool> {
        db::mix_channel_discoverable_to(&self.pool, &channel_db(channel), actor).await
    }
    pub(crate) async fn destroy_mix_channel(
        &self,
        channel_id: Uuid,
        actor: &str,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<bool> {
        let federated = federated.map(federated_mutation_db);
        let _admission = self.delivery_admission_guard().await;
        db::destroy_mix_channel(&self.pool, channel_id, actor, self, federated.as_ref()).await
    }
    pub(crate) async fn join_mix_channel(
        &self,
        channel_id: Uuid,
        request: JoinMixRequest,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<JoinChannelOutcome> {
        // The repository borrows the parsed request; owned invitation and
        // preference mirrors are materialized here so their lifetimes cover
        // the awaited transaction.
        let db_invitation = request
            .invitation
            .as_ref()
            .map(db::MixInvitationProof::from);
        let db_preference = request
            .preference
            .as_ref()
            .map(db::MixParticipantPreference::from);
        let federated = federated.map(federated_mutation_db);
        let _admission = self.delivery_admission_guard().await;
        let outcome = db::join_mix_channel(
            &self.pool,
            channel_id,
            db::JoinMixRequest {
                actor_jid: &request.actor_jid,
                nick: request.nick.as_deref(),
                nodes: &request.nodes,
                pam_user_id: request.pam_user_id,
                invitation: db_invitation.as_ref(),
                preference: db_preference.as_ref(),
                anonymous_profile: request.anonymous_profile,
            },
            self,
            federated.as_ref(),
        )
        .await?;
        Ok(join_outcome(outcome))
    }
    pub(crate) async fn mix_participant(
        &self,
        channel_id: Uuid,
        jid: &str,
    ) -> Result<Option<MixParticipant>> {
        Ok(db::mix_participant(&self.pool, channel_id, jid)
            .await?
            .map(map_participant))
    }
    pub(crate) async fn mix_participant_by_id(
        &self,
        channel_id: Uuid,
        participant_id: Uuid,
    ) -> Result<Option<MixParticipant>> {
        Ok(
            db::mix_participant_by_id(&self.pool, channel_id, participant_id)
                .await?
                .map(map_participant),
        )
    }
    delegate!(mix_presence_source_jid(channel_id: Uuid, item_id: &str) -> Option<String> => db::mix_presence_source_jid;);
    pub(crate) async fn expire_unrefreshed_mix_presence(
        &self,
        cutoff: DateTime<Utc>,
    ) -> Result<Vec<ExpiredMixPresence>> {
        let _admission = self.delivery_admission_guard().await;
        Ok(
            db::expire_unrefreshed_mix_presence(&self.pool, cutoff, self)
                .await?
                .into_iter()
                .map(|expired| ExpiredMixPresence {
                    channel_id: expired.channel_id,
                    participant: map_participant(expired.participant),
                    item_id: expired.item_id,
                    payload: expired.payload,
                    source_full_jid: expired.source_full_jid,
                })
                .collect(),
        )
    }
    pub(crate) async fn update_mix_subscriptions(
        &self,
        channel_id: Uuid,
        actor: &str,
        subscribe: &[String],
        unsubscribe: &[String],
        federated: Option<&FederatedMixMutation>,
    ) -> Result<Option<UpdateSubscriptionsOutcome>> {
        let federated = federated.map(federated_mutation_db);
        let _admission = self.delivery_admission_guard().await;
        Ok(db::update_mix_subscriptions(
            &self.pool,
            channel_id,
            actor,
            subscribe,
            unsubscribe,
            self,
            federated.as_ref(),
        )
        .await?
        .map(|outcome| UpdateSubscriptionsOutcome {
            subscriptions: outcome.subscriptions,
            participant: map_participant(outcome.participant),
            removed_presence: outcome
                .removed_presence
                .into_iter()
                .map(presence_item)
                .collect(),
        }))
    }
    pub(crate) async fn set_mix_nick(
        &self,
        channel_id: Uuid,
        actor: &str,
        nick: &str,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<std::result::Result<MixParticipant, SetNickError>> {
        let federated = federated.map(federated_mutation_db);
        let _admission = self.delivery_admission_guard().await;
        Ok(
            match db::set_mix_nick(
                &self.pool,
                channel_id,
                actor,
                nick,
                self,
                federated.as_ref(),
            )
            .await?
            {
                Ok(stored_participant) => Ok(map_participant(stored_participant)),
                Err(db::SetNickError::NotParticipant) => Err(SetNickError::NotParticipant),
                Err(db::SetNickError::Conflict) => Err(SetNickError::Conflict),
            },
        )
    }
    pub(crate) async fn leave_mix_channel(
        &self,
        channel_id: Uuid,
        actor: &str,
        pam_user_id: Option<Uuid>,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<Option<LeaveMixOutcome>> {
        let federated = federated.map(federated_mutation_db);
        let _admission = self.delivery_admission_guard().await;
        Ok(db::leave_mix_channel(
            &self.pool,
            channel_id,
            actor,
            pam_user_id,
            self,
            federated.as_ref(),
        )
        .await?
        .map(|left| LeaveMixOutcome {
            participant: map_participant(left.participant),
            presence_items: left.presence_items.into_iter().map(presence_item).collect(),
            roster_change: left.roster_change,
        }))
    }
    pub(crate) async fn store_mix_presence(
        &self,
        channel_id: Uuid,
        actor_bare: &str,
        actor_full: &str,
        payload: &str,
        unavailable: bool,
    ) -> Result<PresenceOutcome> {
        let _admission = self.delivery_admission_guard().await;
        Ok(presence_outcome(
            db::store_mix_presence(
                &self.pool,
                channel_id,
                actor_bare,
                actor_full,
                payload,
                unavailable,
                self,
            )
            .await?,
        ))
    }
    pub(crate) async fn ensure_mix_presence(
        &self,
        channel_id: Uuid,
        actor_bare: &str,
        actor_full: &str,
        payload: &str,
    ) -> Result<PresenceOutcome> {
        let _admission = self.delivery_admission_guard().await;
        Ok(presence_outcome(
            db::ensure_mix_presence(
                &self.pool, channel_id, actor_bare, actor_full, payload, self,
            )
            .await?,
        ))
    }
    pub(crate) async fn store_mix_message(
        &self,
        request: StoreMixMessageRequest<'_>,
    ) -> Result<StoreMixMessageAdmission> {
        let StoreMixMessageRequest {
            channel_id,
            actor,
            item_id,
            payload,
            identity,
            delivery_payload,
            visible_jid,
            encrypted,
        } = request;
        let authenticators = identity
            .as_ref()
            .map(|identity| {
                Ok::<_, anyhow::Error>(
                    self.message_identity
                        .authenticators(&identity.canonical_semantics),
                )
            })
            .transpose()?;
        let db_identity =
            identity
                .as_ref()
                .zip(authenticators.as_ref())
                .map(|(identity, authenticators)| {
                    let primary = authenticators.primary();
                    db::MixBusinessIdentity {
                        client_id: &identity.client_id,
                        semantic_key_id: primary.key_id(),
                        semantic_mac: primary.mac(),
                    }
                });
        let _admission = self.delivery_admission_guard().await;
        let admission = db::store_mix_message(
            &self.pool,
            channel_id,
            actor,
            item_id,
            payload,
            db_identity,
            delivery_payload,
            visible_jid,
            encrypted,
            self,
        )
        .await?;
        let outcome = match admission.outcome {
            db::StoreEventOutcome::Existing(existing) => {
                let exact = authenticators.as_ref().is_some_and(|authenticators| {
                    existing.target_id.is_none()
                        && authenticators
                            .verifies(&existing.semantic_key_id, &existing.semantic_mac)
                });
                if exact {
                    StoreEventOutcome::Replay(existing.authoritative_id)
                } else {
                    StoreEventOutcome::Conflict
                }
            }
            outcome => store_event_outcome(outcome),
        };
        Ok(StoreMixMessageAdmission {
            outcome,
            recipients: admission
                .recipients
                .into_iter()
                .map(map_participant)
                .collect(),
        })
    }

    /// Consult the immutable replay commitment before any mutable participant
    /// or permission check. A miss never writes; first execution is still
    /// admitted only inside the channel transaction.
    pub(crate) async fn lookup_mix_message_replay(
        &self,
        channel_id: Uuid,
        actor: &str,
        identity: &MixReplayIdentity,
    ) -> Result<MixBusinessReplay> {
        let authenticators = self
            .message_identity
            .authenticators(&identity.canonical_semantics);
        let existing = db::lookup_mix_business_intent(
            &self.pool,
            channel_id,
            actor,
            "message",
            &identity.client_id,
        )
        .await?;
        Ok(match existing {
            None => MixBusinessReplay::Miss,
            Some(existing)
                if existing.target_id.is_none()
                    && authenticators
                        .verifies(&existing.semantic_key_id, &existing.semantic_mac) =>
            {
                MixBusinessReplay::Replay(existing.authoritative_id)
            }
            Some(_) => MixBusinessReplay::Conflict,
        })
    }

    pub(crate) async fn lookup_mix_retraction_replay(
        &self,
        channel_id: Uuid,
        actor: &str,
        target_id: Uuid,
        identity: &MixReplayIdentity,
    ) -> Result<MixBusinessReplay> {
        let authenticators = self
            .retraction_identity
            .authenticators(&identity.canonical_semantics);
        let existing = db::lookup_mix_business_intent(
            &self.pool,
            channel_id,
            actor,
            "retraction",
            &identity.client_id,
        )
        .await?;
        Ok(match existing {
            None => MixBusinessReplay::Miss,
            Some(existing)
                if existing.target_id == Some(target_id)
                    && authenticators
                        .verifies(&existing.semantic_key_id, &existing.semantic_mac) =>
            {
                MixBusinessReplay::Replay(existing.authoritative_id)
            }
            Some(_) => MixBusinessReplay::Conflict,
        })
    }
    pub(crate) async fn authorized_mix_event_page(
        &self,
        channel_id: Uuid,
        actor: &str,
        node: &str,
        before: Option<(DateTime<Utc>, Uuid)>,
        limit: i64,
    ) -> Result<MixReadOutcome<MixEventPage>> {
        Ok(
            match db::authorized_mix_event_page(&self.pool, channel_id, actor, node, before, limit)
                .await?
            {
                db::MixReadOutcome::Found(page) => MixReadOutcome::Found(MixEventPage {
                    events: page.events.into_iter().map(event).collect(),
                }),
                db::MixReadOutcome::Unauthorized => MixReadOutcome::Unauthorized,
                db::MixReadOutcome::NotFound => MixReadOutcome::NotFound,
            },
        )
    }
    pub(crate) async fn publish_mix_avatar(
        &self,
        channel_id: Uuid,
        actor: &str,
        node: &str,
        item_id: &str,
        payload: &str,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<bool> {
        let federated = federated.map(federated_mutation_db);
        let _admission = self.delivery_admission_guard().await;
        db::publish_mix_avatar(
            &self.pool,
            channel_id,
            actor,
            node,
            item_id,
            payload,
            self,
            federated.as_ref(),
        )
        .await
    }

    pub(crate) async fn retract_mix_avatar(
        &self,
        channel_id: Uuid,
        actor: &str,
        node: &str,
        item_id: &str,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<bool> {
        let federated = federated.map(federated_mutation_db);
        let _admission = self.delivery_admission_guard().await;
        db::retract_mix_avatar(
            &self.pool,
            channel_id,
            actor,
            node,
            item_id,
            self,
            federated.as_ref(),
        )
        .await
    }
    pub(crate) async fn authorized_mix_mam_page(
        &self,
        channel_id: Uuid,
        actor: &str,
        viewer_id: Option<Uuid>,
        query: &MamArchiveQuery,
    ) -> Result<MixReadOutcome<MixMamPage>> {
        Ok(
            match db::authorized_mix_mam_page(
                &self.pool,
                channel_id,
                actor,
                viewer_id,
                &mam_query_db(query),
            )
            .await?
            {
                db::MixReadOutcome::Found(page) => MixReadOutcome::Found(mam_page(page)),
                db::MixReadOutcome::Unauthorized => MixReadOutcome::Unauthorized,
                db::MixReadOutcome::NotFound => MixReadOutcome::NotFound,
            },
        )
    }
    pub(crate) async fn authorized_mix_mam_boundaries(
        &self,
        channel_id: Uuid,
        actor: &str,
        viewer_id: Option<Uuid>,
    ) -> Result<MixReadOutcome<(Option<ArchiveBoundary>, Option<ArchiveBoundary>)>> {
        Ok(
            match db::authorized_mix_mam_boundaries(&self.pool, channel_id, actor, viewer_id)
                .await?
            {
                db::MixReadOutcome::Found((first, last)) => {
                    MixReadOutcome::Found((first.map(boundary), last.map(boundary)))
                }
                db::MixReadOutcome::Unauthorized => MixReadOutcome::Unauthorized,
                db::MixReadOutcome::NotFound => MixReadOutcome::NotFound,
            },
        )
    }
    pub(crate) async fn authorized_mix_access_entries(
        &self,
        channel_id: Uuid,
        actor: &str,
        banned: bool,
        limit: i64,
    ) -> Result<MixReadOutcome<Vec<String>>> {
        Ok(
            match db::authorized_mix_access_entries(&self.pool, channel_id, actor, banned, limit)
                .await?
            {
                db::MixReadOutcome::Found(entries) => MixReadOutcome::Found(entries),
                db::MixReadOutcome::Unauthorized => MixReadOutcome::Unauthorized,
                db::MixReadOutcome::NotFound => MixReadOutcome::NotFound,
            },
        )
    }
    pub(crate) async fn update_mix_info(
        &self,
        channel_id: Uuid,
        actor: &str,
        update: MixInfoUpdate,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<MixMutationOutcome> {
        let federated = federated.map(federated_mutation_db);
        let _admission = self.delivery_admission_guard().await;
        Ok(
            match db::update_mix_info(
                &self.pool,
                channel_id,
                actor,
                db::MixInfoUpdate {
                    item_id: &update.item_id,
                    expected_revision: update.expected_revision,
                    name: update.name.as_deref(),
                    description: update.description.as_deref(),
                    contacts: &update.contacts,
                },
                self,
                federated.as_ref(),
            )
            .await?
            {
                db::MixMutationOutcome::Applied(admission) => {
                    MixMutationOutcome::Applied(Box::new(mutation_admission(*admission)))
                }
                db::MixMutationOutcome::Conflict => MixMutationOutcome::Conflict,
                db::MixMutationOutcome::Forbidden => MixMutationOutcome::Forbidden,
                db::MixMutationOutcome::NotFound => MixMutationOutcome::NotFound,
            },
        )
    }

    pub(crate) async fn update_mix_config(
        &self,
        channel_id: Uuid,
        actor: &str,
        update: MixConfigUpdate,
        roles: MixRoleUpdate,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<MixMutationOutcome> {
        let federated = federated.map(federated_mutation_db);
        let _admission = self.delivery_admission_guard().await;
        Ok(
            match db::update_mix_config(
                &self.pool,
                channel_id,
                actor,
                db::MixConfigUpdate {
                    item_id: &update.item_id,
                    expected_revision: update.expected_revision,
                    access_model: &update.access_model,
                    jid_visibility: &update.jid_visibility,
                    nick_required: update.nick_required,
                    max_participants: update.max_participants,
                    max_events: update.max_events,
                    allow_private_messages: update.allow_private_messages,
                    allow_participant_invites: update.allow_participant_invites,
                    allow_user_message_retraction: update.allow_user_message_retraction,
                    administrator_retraction_rights: &update.administrator_retraction_rights,
                    enforce_registered_nick: update.enforce_registered_nick,
                },
                db::MixRoleUpdate {
                    owners: roles.owners.as_deref(),
                    administrators: roles.administrators.as_deref(),
                },
                self,
                federated.as_ref(),
            )
            .await?
            {
                db::MixMutationOutcome::Applied(admission) => {
                    MixMutationOutcome::Applied(Box::new(mutation_admission(*admission)))
                }
                db::MixMutationOutcome::Conflict => MixMutationOutcome::Conflict,
                db::MixMutationOutcome::Forbidden => MixMutationOutcome::Forbidden,
                db::MixMutationOutcome::NotFound => MixMutationOutcome::NotFound,
            },
        )
    }

    pub(crate) async fn set_mix_access_entry(
        &self,
        update: MixAccessEntryUpdate<'_>,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<Option<AccessChangeOutcome>> {
        let list = match update.list {
            MixAccessList::Allowed => db::MixAccessList::Allowed,
            MixAccessList::Banned => db::MixAccessList::Banned,
        };
        let operation = match update.operation {
            MixAccessEntryOperation::Publish { reason } => {
                db::MixAccessEntryOperation::Publish { reason }
            }
            MixAccessEntryOperation::Retract => db::MixAccessEntryOperation::Retract,
        };
        let federated = federated.map(federated_mutation_db);
        let _admission = self.delivery_admission_guard().await;
        Ok(db::set_mix_access_entry(
            &self.pool,
            db::MixAccessEntryUpdate {
                channel_id: update.channel_id,
                actor: update.actor,
                pattern: update.pattern,
                list,
                operation,
            },
            self,
            federated.as_ref(),
        )
        .await?
        .map(access_change_outcome))
    }
    pub(crate) async fn register_mix_nick(
        &self,
        service_domain: &str,
        actor: &str,
        nick: &str,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<RegisterMixNickOutcome> {
        let federated = federated.map(federated_mutation_db);
        let _admission = self.delivery_admission_guard().await;
        Ok(
            match db::register_mix_nick(
                &self.pool,
                service_domain,
                actor,
                nick,
                self,
                federated.as_ref(),
            )
            .await?
            {
                db::RegisterMixNickOutcome::Registered { nick } => {
                    RegisterMixNickOutcome::Registered { nick }
                }
                db::RegisterMixNickOutcome::Conflict => RegisterMixNickOutcome::Conflict,
            },
        )
    }
    pub(crate) async fn mix_participant_preference(
        &self,
        channel_id: Uuid,
        actor: &str,
    ) -> Result<Option<MixParticipantPreference>> {
        Ok(
            db::mix_participant_preference(&self.pool, channel_id, actor)
                .await?
                .map(map_preference),
        )
    }
    pub(crate) async fn update_mix_participant_preference(
        &self,
        channel_id: Uuid,
        actor: &str,
        preference: &MixParticipantPreference,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<Option<MixParticipantPreferenceUpdateOutcome>> {
        let federated = federated.map(federated_mutation_db);
        let _admission = self.delivery_admission_guard().await;
        Ok(db::update_mix_participant_preference(
            &self.pool,
            channel_id,
            actor,
            &preference_db(preference),
            self,
            federated.as_ref(),
        )
        .await?
        .map(|outcome| MixParticipantPreferenceUpdateOutcome {
            participant: map_participant(outcome.participant),
            roster_changes: outcome.roster_changes,
        }))
    }
    pub(crate) async fn authorized_mix_jid_map_entries(
        &self,
        channel_id: Uuid,
        actor: &str,
        limit: i64,
    ) -> Result<MixReadOutcome<Vec<(String, String)>>> {
        Ok(
            match db::authorized_mix_jid_map_entries(&self.pool, channel_id, actor, limit).await? {
                db::MixReadOutcome::Found(entries) => MixReadOutcome::Found(entries),
                db::MixReadOutcome::Unauthorized => MixReadOutcome::Unauthorized,
                db::MixReadOutcome::NotFound => MixReadOutcome::NotFound,
            },
        )
    }
    pub(crate) async fn issue_mix_invitation(
        &self,
        channel_id: Uuid,
        inviter: &str,
        invitee: &str,
        token: &str,
        lifetime: chrono::Duration,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<bool> {
        let federated = federated.map(federated_mutation_db);
        db::issue_mix_invitation(
            &self.pool,
            channel_id,
            inviter,
            invitee,
            token,
            lifetime,
            self,
            federated.as_ref(),
        )
        .await
    }
    pub(crate) async fn mix_private_message_recipient(
        &self,
        channel_id: Uuid,
        sender: &str,
        recipient_id: Uuid,
    ) -> Result<Option<(MixParticipant, MixParticipant)>> {
        Ok(
            db::mix_private_message_recipient(&self.pool, channel_id, sender, recipient_id)
                .await?
                .map(|(sender, recipient)| (map_participant(sender), map_participant(recipient))),
        )
    }
    pub(crate) async fn retract_mix_message(
        &self,
        request: RetractMixMessageRequest<'_>,
    ) -> Result<RetractMixMessageAdmission> {
        let RetractMixMessageRequest {
            channel_id,
            actor,
            target_id,
            retraction_id,
            tombstone_payload,
            retraction_payload,
            identity,
            visible_jid,
        } = request;
        let authenticators = identity
            .as_ref()
            .map(|identity| {
                Ok::<_, anyhow::Error>(
                    self.retraction_identity
                        .authenticators(&identity.canonical_semantics),
                )
            })
            .transpose()?;
        let db_identity =
            identity
                .as_ref()
                .zip(authenticators.as_ref())
                .map(|(identity, authenticators)| {
                    let primary = authenticators.primary();
                    db::MixBusinessIdentity {
                        client_id: &identity.client_id,
                        semantic_key_id: primary.key_id(),
                        semantic_mac: primary.mac(),
                    }
                });
        let _admission = self.delivery_admission_guard().await;
        let admission = db::retract_mix_message(
            &self.pool,
            channel_id,
            actor,
            target_id,
            retraction_id,
            tombstone_payload,
            retraction_payload,
            db_identity,
            visible_jid,
            self,
        )
        .await?;
        Ok(retract_mix_message_admission(admission, |existing| {
            let exact = authenticators.as_ref().is_some_and(|authenticators| {
                existing.target_id == Some(target_id)
                    && authenticators.verifies(&existing.semantic_key_id, &existing.semantic_mac)
            });
            if exact {
                RetractMixMessageOutcome::Replay(existing.authoritative_id)
            } else {
                RetractMixMessageOutcome::Conflict
            }
        }))
    }
    pub(crate) async fn begin_remote_pam_join(
        &self,
        request: BeginRemotePamJoin,
    ) -> Result<PamOperationReplay> {
        let _admission = self.pam_capacity_admission_guard().await;
        Ok(map_pam_replay(
            db::begin_remote_pam_join(
                &self.pool,
                db::BeginRemotePamJoin {
                    user_id: request.user_id,
                    actor_jid: &request.actor_jid,
                    channel_jid: &request.channel_jid,
                    nick: request.nick.as_deref(),
                    nodes: &request.nodes,
                    request_id: &request.request_id,
                    client_request_id: &request.client_request_id,
                    requester_full_jid: &request.requester_full_jid,
                    request_digest: &request.request_digest,
                    remote_domain: &request.remote_domain,
                    outbound_stanza: &request.outbound_stanza,
                    policy: db::S2sOutboxPolicy {
                        ttl_seconds: request.policy.ttl_seconds,
                        max_rows: request.policy.max_rows,
                        max_bytes: request.policy.max_bytes,
                        max_per_domain: request.policy.max_per_domain,
                    },
                },
            )
            .await?,
        ))
    }

    pub(crate) async fn lookup_remote_pam_operation(
        &self,
        user_id: Uuid,
        requester_full_jid: &str,
        client_request_id: &str,
        request_digest: &[u8; 32],
    ) -> Result<PamOperationReplay> {
        Ok(map_pam_replay(
            db::lookup_remote_pam_operation(
                &self.pool,
                user_id,
                requester_full_jid,
                client_request_id,
                request_digest,
            )
            .await?,
        ))
    }

    pub(crate) async fn begin_remote_pam_leave(
        &self,
        request: BeginRemotePamLeave,
    ) -> Result<PamOperationReplay> {
        let _admission = self.pam_capacity_admission_guard().await;
        Ok(map_pam_replay(
            db::begin_remote_pam_leave(
                &self.pool,
                db::BeginRemotePamLeave {
                    user_id: request.user_id,
                    actor_jid: &request.actor_jid,
                    channel_jid: &request.channel_jid,
                    request_id: &request.request_id,
                    client_request_id: &request.client_request_id,
                    requester_full_jid: &request.requester_full_jid,
                    request_digest: &request.request_digest,
                    remote_domain: &request.remote_domain,
                    outbound_stanza: &request.outbound_stanza,
                    policy: db::S2sOutboxPolicy {
                        ttl_seconds: request.policy.ttl_seconds,
                        max_rows: request.policy.max_rows,
                        max_bytes: request.policy.max_bytes,
                        max_per_domain: request.policy.max_per_domain,
                    },
                },
            )
            .await?,
        ))
    }

    pub(crate) async fn complete_remote_pam_success(
        &self,
        authenticated_domain: &str,
        channel_jid: &str,
        recipient_bare: &str,
        request_id: &str,
        response_digest: &[u8; 32],
        join: Option<RemotePamJoin<'_>>,
    ) -> Result<RemotePamCompletionOutcome> {
        let join = join.map(|join| db::RemotePamJoin {
            participant_id: join.participant_id,
            subscriptions: join.subscriptions,
            nick: join.nick,
        });
        Ok(map_pam_completion(
            db::complete_remote_pam_success(
                &self.pool,
                authenticated_domain,
                channel_jid,
                recipient_bare,
                request_id,
                response_digest,
                join,
                self,
            )
            .await?,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn complete_remote_pam_error(
        &self,
        authenticated_domain: &str,
        channel_jid: &str,
        recipient_bare: &str,
        request_id: &str,
        response_digest: &[u8; 32],
        error_type: &str,
        condition: &str,
    ) -> Result<RemotePamCompletionOutcome> {
        Ok(map_pam_completion(
            db::complete_remote_pam_error(
                &self.pool,
                authenticated_domain,
                channel_jid,
                recipient_bare,
                request_id,
                response_digest,
                error_type,
                condition,
                self,
            )
            .await?,
        ))
    }
    pub(crate) async fn pam_memberships(&self, user_id: Uuid) -> Result<Vec<PamMembership>> {
        Ok(db::pam_memberships(&self.pool, user_id)
            .await?
            .into_iter()
            .map(pam_membership)
            .collect())
    }
    pub(crate) async fn pam_membership(
        &self,
        user_id: Uuid,
        channel_jid: &str,
    ) -> Result<Option<PamMembership>> {
        Ok(db::pam_membership(&self.pool, user_id, channel_jid)
            .await?
            .map(pam_membership))
    }
    delegate!(local_pam_users_for_channel(channel_jid: &str) -> Vec<Uuid> => db::local_pam_users_for_channel;);
    pub(crate) async fn reconcile_expired_remote_pam(&self, limit: i64) -> Result<u64> {
        db::reconcile_expired_remote_pam(&self.pool, limit, self).await
    }

    pub(crate) async fn claim_pam_results(&self, limit: i64) -> Result<Vec<ClaimedPamResult>> {
        Ok(db::claim_pam_results(&self.pool, limit)
            .await?
            .into_iter()
            .map(|result| ClaimedPamResult {
                operation_id: result.operation_id,
                user_id: result.user_id,
                requester_full_jid: result.requester_full_jid,
                response_xml: result.response_xml,
                attempt_count: result.attempt_count,
                lease_token: result.lease_token,
            })
            .collect())
    }

    delegate!(renew_pam_result_lease(operation_id: Uuid, lease_token: Uuid) -> bool => db::renew_pam_result_lease;);
    delegate!(acknowledge_pam_result(operation_id: Uuid, lease_token: Uuid) -> bool => db::acknowledge_pam_result;);
    delegate!(defer_pam_result(operation_id: Uuid, lease_token: Uuid, delay_seconds: i64) -> bool => db::defer_pam_result;);
    delegate!(retry_pam_result(operation_id: Uuid, lease_token: Uuid, attempt_count: i32, error: &str) -> bool => db::retry_pam_result;);
    pub(crate) async fn prune_expired_pam_results(&self, limit: i64) -> Result<u64> {
        let _admission = self.pam_capacity_admission_guard().await;
        db::prune_expired_pam_results(&self.pool, limit).await
    }

    pub(crate) async fn find_enabled_user(&self, username: &str) -> Result<Option<MixAccount>> {
        Ok(db::find_enabled_user(&self.pool, username)
            .await?
            .map(|user| MixAccount {
                id: user.id,
                username: user.username,
            }))
    }

    pub(crate) async fn find_enabled_user_by_id(
        &self,
        user_id: Uuid,
    ) -> Result<Option<MixAccount>> {
        Ok(db::find_enabled_user_by_id(&self.pool, user_id)
            .await?
            .map(|user| MixAccount {
                id: user.id,
                username: user.username,
            }))
    }
    delegate!(is_blocked(owner_id: Uuid, candidate: &str) -> bool => db::is_blocked;);
    pub(crate) async fn pep_node(
        &self,
        owner_id: Uuid,
        node: &str,
    ) -> Result<Option<PepNodeConfig>> {
        Ok(db::pep_node(&self.pool, owner_id, node)
            .await?
            .map(|config| PepNodeConfig {
                access_model: config.access_model,
                max_items: config.max_items,
                persist_items: config.persist_items,
                send_last_published_item: config.send_last_published_item,
                deliver_notifications: config.deliver_notifications,
                roster_groups_allowed: config.roster_groups_allowed,
                access_whitelist: config.access_whitelist,
            }))
    }
    delegate!(pep_items(owner_id: Uuid, node: &str, item_id: Option<&str>, limit: i64) -> Vec<(String, String)> => db::pep_items;);
    pub(crate) async fn get_vcard(&self, user_id: Uuid) -> Result<VCardRecord> {
        let record = db::get_vcard(&self.pool, user_id).await?;
        Ok(VCardRecord {
            payload_vcard_temp: record.payload_vcard_temp,
        })
    }
    pub(crate) async fn latest_roster_change_for_contact(
        &self,
        user_id: Uuid,
        contact_jid: &str,
    ) -> Result<Option<northstar_roster_core::RosterChange>> {
        db::latest_roster_change_for_contact(&self.pool, user_id, contact_jid).await
    }
    pub(crate) async fn mix_muc_mirror_for_mix(
        &self,
        mix_channel_id: Uuid,
    ) -> Result<Option<MixMucMirror>> {
        Ok(db::mix_muc_mirror_for_mix(&self.pool, mix_channel_id)
            .await?
            .map(mix_muc_mirror))
    }
    pub(crate) async fn mix_muc_mirror_for_muc(
        &self,
        muc_room_id: Uuid,
    ) -> Result<Option<MixMucMirror>> {
        Ok(db::mix_muc_mirror_for_muc(&self.pool, muc_room_id)
            .await?
            .map(mix_muc_mirror))
    }
    delegate!(mix_muc_mirror_service_complete(mix_domain: &str) -> bool => db::mix_muc_mirror_service_complete;);
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn archive_mix_message_once(
        &self,
        personal_archive_id: Uuid,
        owner_id: Uuid,
        channel_jid: &str,
        authoritative_stanza_id: Uuid,
        stanza: &str,
        encrypted: bool,
        client_stanza_id: Option<&str>,
    ) -> Result<SourceArchiveAdmission> {
        Ok(
            match db::archive_mix_message_once(
                &self.pool,
                personal_archive_id,
                owner_id,
                channel_jid,
                authoritative_stanza_id,
                stanza,
                encrypted,
                client_stanza_id,
            )
            .await?
            {
                db::SourceArchiveAdmission::Stored(id) => SourceArchiveAdmission::Stored(id),
                db::SourceArchiveAdmission::Replay(id) => SourceArchiveAdmission::Replay(id),
            },
        )
    }

    /// Admit one ordered federation response stream atomically. A capacity or
    /// validation failure rolls the complete stream back, so the remote peer
    /// cannot observe a MAM prefix without its terminal result (or vice versa).
    pub(crate) async fn enqueue_s2s_response_batch(
        &self,
        target_domain: &str,
        responses: &[String],
        policy: S2sOutboxPolicy,
    ) -> Result<()> {
        let policy = db::S2sOutboxPolicy {
            ttl_seconds: policy.ttl_seconds,
            max_rows: policy.max_rows,
            max_bytes: policy.max_bytes,
            max_per_domain: policy.max_per_domain,
        };
        let mut transaction = self.pool.begin().await?;
        for response in responses {
            db::enqueue_s2s_outbox_in_transaction(
                &mut transaction,
                target_domain,
                response,
                None,
                policy,
            )
            .await?;
        }
        transaction.commit().await?;
        Ok(())
    }

    pub(crate) async fn federated_mix_iq_replay(
        &self,
        authenticated_domain: &str,
        actor_jid: &str,
        request_id: &str,
        request_digest: &[u8; 32],
    ) -> Result<FederatedMixIqReplay> {
        Ok(
            match db::federated_mix_iq_replay(
                &self.pool,
                authenticated_domain,
                actor_jid,
                request_id,
                request_digest,
            )
            .await?
            {
                db::FederatedMixIqReplay::Miss => FederatedMixIqReplay::Miss,
                db::FederatedMixIqReplay::Replay(response) => {
                    FederatedMixIqReplay::Replay(response)
                }
                db::FederatedMixIqReplay::Conflict => FederatedMixIqReplay::Conflict,
            },
        )
    }

    pub(crate) async fn admit_federated_mix_iq_result(
        &self,
        authenticated_domain: &str,
        actor_jid: &str,
        request_id: &str,
        request_digest: &[u8; 32],
        response: &str,
        policy: S2sOutboxPolicy,
    ) -> Result<FederatedMixIqReplay> {
        let policy = db::S2sOutboxPolicy {
            ttl_seconds: policy.ttl_seconds,
            max_rows: policy.max_rows,
            max_bytes: policy.max_bytes,
            max_per_domain: policy.max_per_domain,
        };
        Ok(
            match db::admit_federated_mix_iq_result(
                &self.pool,
                authenticated_domain,
                actor_jid,
                request_id,
                request_digest,
                response,
                policy,
            )
            .await?
            {
                db::FederatedMixIqReplay::Miss => FederatedMixIqReplay::Miss,
                db::FederatedMixIqReplay::Replay(response) => {
                    FederatedMixIqReplay::Replay(response)
                }
                db::FederatedMixIqReplay::Conflict => FederatedMixIqReplay::Conflict,
            },
        )
    }

    pub(crate) async fn claim_mix_deliveries(
        &self,
        limit: i64,
        max_bytes: i64,
    ) -> Result<Vec<ClaimedMixDelivery>> {
        Ok(db::claim_mix_deliveries(&self.pool, limit, max_bytes)
            .await?
            .into_iter()
            .map(|delivery| ClaimedMixDelivery {
                delivery_id: delivery.delivery_id,
                event_id: delivery.event_id,
                channel_id: delivery.channel_id,
                channel_jid: delivery.channel_jid,
                recipient: map_participant(delivery.recipient),
                stanza: delivery.stanza,
                authoritative_stanza_id: delivery.authoritative_stanza_id,
                archive: delivery.archive,
                encrypted: delivery.encrypted,
                attempt_count: delivery.attempt_count,
                lease_token: delivery.lease_token,
                created_at: delivery.created_at,
            })
            .collect())
    }

    pub(crate) async fn prune_expired_business_intents(&self, limit: i64) -> Result<u64> {
        db::prune_expired_mix_business_intents(&self.pool, limit).await
    }

    pub(crate) async fn prune_expired_federated_iq_results(&self, limit: i64) -> Result<u64> {
        db::prune_expired_federated_mix_iq_results(&self.pool, limit).await
    }

    pub(crate) async fn acknowledge_mix_delivery(
        &self,
        delivery_id: Uuid,
        lease_token: Uuid,
    ) -> Result<bool> {
        db::acknowledge_mix_delivery(&self.pool, delivery_id, lease_token).await
    }

    pub(crate) async fn renew_mix_delivery_lease(
        &self,
        delivery_id: Uuid,
        lease_token: Uuid,
    ) -> Result<bool> {
        db::renew_mix_delivery_lease(&self.pool, delivery_id, lease_token).await
    }

    pub(crate) async fn dead_letter_mix_delivery(
        &self,
        delivery_id: Uuid,
        lease_token: Uuid,
        terminal_reason: &str,
        error: &str,
    ) -> Result<bool> {
        db::dead_letter_mix_delivery(&self.pool, delivery_id, lease_token, terminal_reason, error)
            .await
    }

    pub(crate) async fn retry_mix_delivery(
        &self,
        delivery_id: Uuid,
        lease_token: Uuid,
        attempt_count: i32,
        error: &str,
    ) -> Result<bool> {
        db::retry_mix_delivery(&self.pool, delivery_id, lease_token, attempt_count, error).await
    }

    pub(crate) async fn defer_mix_delivery(
        &self,
        delivery_id: Uuid,
        lease_token: Uuid,
        delay_seconds: i64,
    ) -> Result<bool> {
        db::defer_mix_delivery(&self.pool, delivery_id, lease_token, delay_seconds).await
    }

    #[allow(dead_code)] // Exposed for the pending admin recovery endpoint wiring.
    pub(crate) async fn mix_delivery_dead_letters(
        &self,
        before: Option<(DateTime<Utc>, Uuid)>,
        limit: i64,
    ) -> Result<Vec<MixDeliveryDeadLetter>> {
        Ok(db::mix_delivery_dead_letters(&self.pool, before, limit)
            .await?
            .into_iter()
            .map(|dead| MixDeliveryDeadLetter {
                dead_letter_id: dead.dead_letter_id,
                delivery_id: dead.delivery_id,
                event_id: dead.event_id,
                channel_id: dead.channel_id,
                channel_jid: dead.channel_jid,
                recipient_jid: dead.recipient_jid,
                attempt_count: dead.attempt_count,
                terminal_reason: dead.terminal_reason,
                last_error: dead.last_error,
                failed_at: dead.failed_at,
            })
            .collect())
    }

    #[allow(dead_code)] // Exposed for the pending admin recovery endpoint wiring.
    pub(crate) async fn requeue_mix_delivery_dead_letter(
        &self,
        dead_letter_id: Uuid,
    ) -> Result<bool> {
        let _admission = self.delivery_admission_guard().await;
        db::requeue_mix_delivery_dead_letter(&self.pool, dead_letter_id).await
    }

    pub(crate) fn valid_stable_participant_id(value: &str) -> bool {
        db::valid_stable_participant_id(value)
    }

    pub(crate) fn mix_timestamp_item_id() -> String {
        db::mix_timestamp_item_id()
    }

    pub(crate) fn valid_join_nodes(nodes: &[String]) -> Result<Vec<String>> {
        db::valid_join_nodes(nodes)
    }

    pub(crate) fn prepare_mix_nick(nick: &str) -> Result<String> {
        db::prepare_mix_nick(nick)
    }

    pub(crate) fn canonical_mix_access_pattern(pattern: &str) -> Result<String> {
        db::canonical_mix_access_pattern(pattern)
    }

    pub(crate) fn participant_jid_visible(
        channel: &MixChannel,
        preference: &MixParticipantPreference,
    ) -> bool {
        db::participant_jid_visible(&channel_db(channel), &preference_db(preference))
    }
}

fn mix_preference_result_form(preference: &db::MixParticipantPreference) -> String {
    let value = |variable: &'static str, kind: Option<&'static str>, text: &str| {
        XmlElement::new("field")
            .attr("var", variable)
            .optional_attr("type", kind)
            .child(XmlElement::new("value").text(text))
    };
    XmlElement::namespaced("x", "jabber:x:data")
        .attr("type", "result")
        .child(value("FORM_TYPE", Some("hidden"), "urn:xmpp:mix:anon:0"))
        .child(value("JID Visibility", None, &preference.jid_visibility))
        .child(value(
            "Private Messages",
            None,
            &preference.private_messages,
        ))
        .child(value("vCard", None, &preference.vcard))
        .child(value(
            "Presence",
            None,
            if preference.share_presence {
                "share"
            } else {
                "not share"
            },
        ))
        .finish()
}

fn render_federated_mix_iq_result(
    context: &db::FederatedMixMutation,
    success: &db::FederatedMixSuccess,
) -> Result<String> {
    let payload = match success {
        db::FederatedMixSuccess::Create { channel } => {
            XmlElement::namespaced("create", "urn:xmpp:mix:core:1")
                .attr("channel", channel)
                .finish()
        }
        db::FederatedMixSuccess::Destroy { channel } => {
            XmlElement::namespaced("destroy", "urn:xmpp:mix:core:1")
                .attr("channel", channel)
                .finish()
        }
        db::FederatedMixSuccess::RegisterNick { nick } => {
            XmlElement::namespaced("register", "urn:xmpp:mix:misc:0")
                .child(XmlElement::new("nick").text(nick))
                .finish()
        }
        db::FederatedMixSuccess::Join {
            participant,
            subscriptions,
            preference,
            anonymous_profile,
        } => {
            let mut join = XmlElement::namespaced(
                "join",
                if *anonymous_profile {
                    "urn:xmpp:mix:anon:0"
                } else {
                    "urn:xmpp:mix:core:1"
                },
            )
            .attr("id", participant.participant_id);
            for node in subscriptions {
                join.push_child(XmlElement::new("subscribe").attr("node", node));
            }
            if let Some(nick) = participant.nick.as_deref() {
                join.push_child(XmlElement::new("nick").text(nick));
            }
            if let Some(preference) = preference {
                join.push_validated_fragment(&mix_preference_result_form(preference))?;
            }
            join.finish()
        }
        db::FederatedMixSuccess::Leave => {
            XmlElement::namespaced("leave", "urn:xmpp:mix:core:1").finish()
        }
        db::FederatedMixSuccess::SetNick { nick } => {
            XmlElement::namespaced("setnick", "urn:xmpp:mix:core:1")
                .child(XmlElement::new("nick").text(nick))
                .finish()
        }
        db::FederatedMixSuccess::UpdateSubscriptions { subscriptions } => {
            let mut update = XmlElement::namespaced("update-subscription", "urn:xmpp:mix:core:1");
            for node in subscriptions {
                update.push_child(XmlElement::new("subscribe").attr("node", node));
            }
            update.finish()
        }
        db::FederatedMixSuccess::PubSubPublish { node, item_id } => {
            XmlElement::namespaced("pubsub", "http://jabber.org/protocol/pubsub")
                .child(
                    XmlElement::new("publish")
                        .attr("node", node)
                        .child(XmlElement::new("item").attr("id", item_id)),
                )
                .finish()
        }
        db::FederatedMixSuccess::PubSubEmpty => {
            XmlElement::namespaced("pubsub", "http://jabber.org/protocol/pubsub").finish()
        }
        db::FederatedMixSuccess::Preference { preference } => {
            XmlElement::namespaced("user-preference", "urn:xmpp:mix:anon:0")
                .validated_fragment(&mix_preference_result_form(preference))?
                .finish()
        }
        db::FederatedMixSuccess::Invitation {
            inviter,
            invitee,
            channel,
            token,
        } => XmlElement::namespaced("invite", "urn:xmpp:mix:misc:0")
            .child(
                XmlElement::new("invitation")
                    .child(XmlElement::new("inviter").text(inviter))
                    .child(XmlElement::new("invitee").text(invitee))
                    .child(XmlElement::new("channel").text(channel))
                    .child(XmlElement::new("token").text(token)),
            )
            .finish(),
    };
    Ok(XmlElement::namespaced("iq", "jabber:client")
        .attr("type", "result")
        .attr("from", &context.addressed)
        .attr("to", &context.reply_to)
        .attr("id", &context.request_id)
        .validated_fragment(&payload)?
        .finish())
}

impl db::MixEventPayloadRenderer for MixService {
    fn info_payload(&self, channel: &db::MixChannel) -> String {
        render_info_payload(channel)
    }

    fn config_payload(
        &self,
        channel: &db::MixChannel,
        last_changed_by: &str,
        owners: &BTreeSet<String>,
        administrators: &BTreeSet<String>,
    ) -> String {
        render_config_payload(channel, last_changed_by, owners, administrators)
    }

    fn participant_payload(
        &self,
        channel: &db::MixChannel,
        participant: &db::MixParticipant,
        preference: &db::MixParticipantPreference,
    ) -> String {
        render_participant_payload(channel, participant, preference)
    }

    fn access_payload(&self, pattern: &str) -> String {
        render_access_payload(pattern)
    }

    fn presence_delivery_stanza(&self, delivery: db::MixPresenceDelivery<'_>) -> Result<String> {
        let db::MixPresenceDelivery {
            channel,
            participant,
            preference,
            recipient,
            item_id,
            actor_full,
            children,
            unavailable,
        } = delivery;
        let encoded = crate::jid::CanonicalJid::parse(item_id)?;
        anyhow::ensure!(
            encoded.resourcepart().is_some(),
            "MIX reflected presence requires an encoded full JID"
        );
        let mut mix = XmlElement::namespaced("mix", "urn:xmpp:mix:presence:0");
        if db::participant_jid_visible(channel, preference) {
            mix.push_child(XmlElement::new("jid").text(actor_full));
        }
        if let Some(nick) = participant.nick.as_deref() {
            mix.push_child(XmlElement::new("nick").text(nick));
        }
        let mut presence = XmlElement::namespaced("presence", "jabber:client")
            .attr("from", encoded.to_string())
            .attr("to", &recipient.jid)
            .attr("id", Uuid::new_v4())
            .optional_attr("type", unavailable.then_some("unavailable"))
            .child(mix);
        presence.push_validated_fragment(children)?;
        Ok(presence.finish())
    }

    fn node_event_stanza(
        &self,
        channel: &db::MixChannel,
        recipient: &db::MixParticipant,
        node: &str,
        item_id: &str,
        payload: Option<&str>,
        retract: bool,
    ) -> Result<String> {
        let mut items = XmlElement::new("items").attr("node", node);
        if retract {
            items.push_child(XmlElement::new("retract").attr("id", item_id));
        } else {
            let mut item = XmlElement::new("item").attr("id", item_id);
            if let Some(payload) = payload {
                item.push_validated_fragment(payload)?;
            }
            items.push_child(item);
        }
        Ok(XmlElement::namespaced("message", "jabber:client")
            .attr("from", channel.jid())
            .attr("to", &recipient.jid)
            .attr("id", Uuid::new_v4())
            .child(
                XmlElement::namespaced("event", "http://jabber.org/protocol/pubsub#event")
                    .child(items),
            )
            .finish())
    }

    fn message_delivery_stanza(
        &self,
        channel: &db::MixChannel,
        sender: &db::MixParticipant,
        recipient: &db::MixParticipant,
        authoritative_id: Uuid,
        payload: &str,
        visible_jid: Option<&str>,
    ) -> Result<String> {
        let participant_address = format!("{}/{}", channel.jid(), sender.participant_id);
        let mut stanza = XmlElement::namespaced("message", "jabber:client")
            .attr("from", &participant_address)
            .attr("to", &recipient.jid)
            .attr("id", authoritative_id)
            .attr("type", "groupchat")
            .validated_fragment(payload)?;
        let mut identity = XmlElement::namespaced("mix", "urn:xmpp:mix:core:1");
        if let Some(nick) = sender.nick.as_deref() {
            identity.push_child(XmlElement::new("nick").text(nick));
        }
        if let Some(jid) = visible_jid {
            identity.push_child(XmlElement::new("jid").text(jid));
        }
        stanza.push_child(identity);
        Ok(crate::xmpp::xml_util::add_stanza_id(
            &stanza.finish(),
            &channel.jid(),
            authoritative_id,
        ))
    }

    fn retraction_delivery_stanza(
        &self,
        channel: &db::MixChannel,
        sender: &db::MixParticipant,
        recipient: &db::MixParticipant,
        authoritative_id: Uuid,
        target_id: Uuid,
        visible_jid: Option<&str>,
    ) -> Result<String> {
        let payload = XmlElement::namespaced("retract", "urn:xmpp:mix:misc:0")
            .attr("id", target_id)
            .finish();
        self.message_delivery_stanza(
            channel,
            sender,
            recipient,
            authoritative_id,
            &payload,
            visible_jid,
        )
    }

    fn federated_iq_result(
        &self,
        context: &db::FederatedMixMutation,
        success: &db::FederatedMixSuccess,
    ) -> Result<String> {
        render_federated_mix_iq_result(context, success)
    }

    fn pam_join_result(&self, result: db::PamJoinResult<'_>) -> Result<String> {
        let db::PamJoinResult {
            client_request_id,
            actor_bare,
            requester_full_jid,
            channel_jid,
            participant_id,
            subscriptions,
            nick,
        } = result;
        anyhow::ensure!(
            db::valid_stable_participant_id(participant_id),
            "invalid MIX stable participant id"
        );
        let channel = crate::jid::CanonicalJid::parse_bare(channel_jid)?;
        let channel_localpart = channel
            .localpart()
            .ok_or_else(|| anyhow::anyhow!("MIX channel requires a localpart"))?;
        let localpart = format!("{participant_id}#{channel_localpart}");
        let participant_jid =
            crate::jid::CanonicalJid::parse_bare(&format!("{localpart}@{}", channel.domainpart()))?;
        anyhow::ensure!(
            participant_jid.localpart() == Some(localpart.as_str()),
            "MIX participant identifier is not a canonical localpart"
        );
        let mut join = XmlElement::namespaced("join", "urn:xmpp:mix:core:1")
            .attr("jid", participant_jid.to_string());
        for node in subscriptions {
            join.push_child(XmlElement::new("subscribe").attr("node", node));
        }
        if let Some(nick) = nick {
            join.push_child(XmlElement::new("nick").text(nick));
        }
        let payload = XmlElement::namespaced("client-join", "urn:xmpp:mix:pam:2")
            .child(join)
            .finish();
        Ok(XmlElement::namespaced("iq", "jabber:client")
            .attr("type", "result")
            .attr("from", actor_bare)
            .attr("to", requester_full_jid)
            .attr("id", client_request_id)
            .validated_fragment(&payload)?
            .finish())
    }

    fn pam_leave_result(
        &self,
        client_request_id: &str,
        actor_bare: &str,
        requester_full_jid: &str,
        channel_jid: &str,
    ) -> Result<String> {
        let payload = XmlElement::namespaced("client-leave", "urn:xmpp:mix:pam:2")
            .attr("channel", channel_jid)
            .child(XmlElement::namespaced("leave", "urn:xmpp:mix:core:1"))
            .finish();
        Ok(XmlElement::namespaced("iq", "jabber:client")
            .attr("type", "result")
            .attr("from", actor_bare)
            .attr("to", requester_full_jid)
            .attr("id", client_request_id)
            .validated_fragment(&payload)?
            .finish())
    }

    fn pam_error_result(
        &self,
        client_request_id: &str,
        actor_bare: &str,
        requester_full_jid: &str,
        error_type: &str,
        condition: &str,
    ) -> Result<String> {
        anyhow::ensure!(
            matches!(
                error_type,
                "auth" | "cancel" | "continue" | "modify" | "wait"
            ),
            "invalid PAM stanza error type"
        );
        let condition =
            XmlElement::dynamic(condition)?.attr("xmlns", "urn:ietf:params:xml:ns:xmpp-stanzas");
        let error = XmlElement::new("error")
            .attr("type", error_type)
            .child(condition);
        Ok(XmlElement::namespaced("iq", "jabber:client")
            .attr("type", "error")
            .attr("from", actor_bare)
            .attr("to", requester_full_jid)
            .attr("id", client_request_id)
            .child(error)
            .finish())
    }
}

fn map_mix_muc_link_outcome(outcome: db::LinkMixMucOutcome) -> MixMucLinkOutcome {
    match outcome {
        db::LinkMixMucOutcome::Linked => MixMucLinkOutcome::Linked,
        db::LinkMixMucOutcome::AlreadyLinked => MixMucLinkOutcome::AlreadyLinked,
        db::LinkMixMucOutcome::MissingCounterpart => MixMucLinkOutcome::MissingCounterpart,
        db::LinkMixMucOutcome::NotCommonOwner => MixMucLinkOutcome::NotCommonOwner,
        db::LinkMixMucOutcome::Conflict => MixMucLinkOutcome::Conflict,
    }
}

// ---------------------------------------------------------------------------
// Explicit repository <-> boundary translations. Every MIX DTO crossing into
// the protocol layer passes through exactly one of these functions; field
// names mirror the repository row so each mapping is reviewable by diff.
// ---------------------------------------------------------------------------

fn map_channel(channel: db::MixChannel) -> MixChannel {
    MixChannel {
        id: channel.id,
        revision: channel.revision,
        service_domain: channel.service_domain,
        localpart: channel.localpart,
        creator_jid: channel.creator_jid,
        name: channel.name,
        description: channel.description,
        contacts: channel.contacts,
        access_model: channel.access_model,
        jid_visibility: channel.jid_visibility,
        nick_required: channel.nick_required,
        max_participants: channel.max_participants,
        max_events: channel.max_events,
        allow_private_messages: channel.allow_private_messages,
        allow_participant_invites: channel.allow_participant_invites,
        allow_user_message_retraction: channel.allow_user_message_retraction,
        administrator_retraction_rights: channel.administrator_retraction_rights,
        enforce_registered_nick: channel.enforce_registered_nick,
    }
}

fn channel_db(channel: &MixChannel) -> db::MixChannel {
    db::MixChannel {
        id: channel.id,
        revision: channel.revision,
        service_domain: channel.service_domain.clone(),
        localpart: channel.localpart.clone(),
        creator_jid: channel.creator_jid.clone(),
        name: channel.name.clone(),
        description: channel.description.clone(),
        contacts: channel.contacts.clone(),
        access_model: channel.access_model.clone(),
        jid_visibility: channel.jid_visibility.clone(),
        nick_required: channel.nick_required,
        max_participants: channel.max_participants,
        max_events: channel.max_events,
        allow_private_messages: channel.allow_private_messages,
        allow_participant_invites: channel.allow_participant_invites,
        allow_user_message_retraction: channel.allow_user_message_retraction,
        administrator_retraction_rights: channel.administrator_retraction_rights.clone(),
        enforce_registered_nick: channel.enforce_registered_nick,
    }
}

fn map_participant(participant: db::MixParticipant) -> MixParticipant {
    MixParticipant {
        participant_id: participant.participant_id,
        jid: participant.jid,
        nick: participant.nick,
    }
}

#[cfg(test)]
fn participant_db(participant: &MixParticipant) -> db::MixParticipant {
    db::MixParticipant {
        participant_id: participant.participant_id,
        jid: participant.jid.clone(),
        nick: participant.nick.clone(),
    }
}

fn map_preference(preference: db::MixParticipantPreference) -> MixParticipantPreference {
    MixParticipantPreference {
        jid_visibility: preference.jid_visibility,
        private_messages: preference.private_messages,
        vcard: preference.vcard,
        share_presence: preference.share_presence,
    }
}

fn preference_db(preference: &MixParticipantPreference) -> db::MixParticipantPreference {
    db::MixParticipantPreference {
        jid_visibility: preference.jid_visibility.clone(),
        private_messages: preference.private_messages.clone(),
        vcard: preference.vcard.clone(),
        share_presence: preference.share_presence,
    }
}

fn event(event: db::MixEvent) -> MixEvent {
    MixEvent {
        id: event.id,
        item_id: event.item_id,
        payload: event.payload,
        created_at: event.created_at,
    }
}

fn mutation_admission(admission: db::MixMutationAdmission) -> MixMutationAdmission {
    MixMutationAdmission {
        channel: map_channel(admission.channel),
        node: admission.node,
        item_id: admission.item_id,
        payload: admission.payload,
        recipients: admission
            .recipients
            .into_iter()
            .map(map_participant)
            .collect(),
    }
}

fn retract_mix_message_admission(
    admission: db::RetractMixMessageAdmission,
    existing_outcome: impl FnOnce(&db::MixIntentEvidence) -> RetractMixMessageOutcome,
) -> RetractMixMessageAdmission {
    let outcome = match &admission.outcome {
        db::RetractMixMessageOutcome::Existing(existing) => existing_outcome(existing),
        db::RetractMixMessageOutcome::Retracted => RetractMixMessageOutcome::Retracted,
        db::RetractMixMessageOutcome::NotFound => RetractMixMessageOutcome::NotFound,
        db::RetractMixMessageOutcome::Forbidden => RetractMixMessageOutcome::Forbidden,
    };
    RetractMixMessageAdmission {
        outcome,
        recipients: admission
            .recipients
            .into_iter()
            .map(map_participant)
            .collect(),
    }
}

fn presence_item(item: db::MixPresenceItem) -> MixPresenceItem {
    MixPresenceItem {
        item_id: item.item_id,
        payload: item.payload,
        source_full_jid: item.source_full_jid,
    }
}

fn pam_membership(membership: db::PamMembership) -> PamMembership {
    PamMembership {
        id: membership.id,
        user_id: membership.user_id,
        channel_jid: membership.channel_jid,
        participant_id: membership.participant_id,
        state: membership.state,
        request_id: membership.request_id,
        client_request_id: membership.client_request_id,
        requester_full_jid: membership.requester_full_jid,
        subscriptions: membership.subscriptions,
    }
}

fn map_pam_replay(replay: db::PamOperationReplay) -> PamOperationReplay {
    match replay {
        db::PamOperationReplay::Miss => PamOperationReplay::Miss,
        db::PamOperationReplay::Pending => PamOperationReplay::Pending,
        db::PamOperationReplay::Replay(response) => PamOperationReplay::Replay(response),
        db::PamOperationReplay::Conflict => PamOperationReplay::Conflict,
    }
}

fn map_pam_completion(outcome: db::RemotePamCompletionOutcome) -> RemotePamCompletionOutcome {
    fn completion(value: db::RemotePamCompletion) -> RemotePamCompletion {
        RemotePamCompletion {
            response_xml: value.response_xml,
            membership: value.membership.map(pam_membership),
            applied: value.applied,
            roster_removed: value.roster_removed,
        }
    }
    match outcome {
        db::RemotePamCompletionOutcome::Applied(value) => {
            RemotePamCompletionOutcome::Applied(completion(value))
        }
        db::RemotePamCompletionOutcome::Replay(value) => {
            RemotePamCompletionOutcome::Replay(completion(value))
        }
        db::RemotePamCompletionOutcome::Conflict => RemotePamCompletionOutcome::Conflict,
        db::RemotePamCompletionOutcome::Missing => RemotePamCompletionOutcome::Missing,
    }
}

fn boundary(boundary: db::ArchiveBoundary) -> ArchiveBoundary {
    ArchiveBoundary {
        id: boundary.id,
        created_at: boundary.created_at,
    }
}

fn mix_muc_mirror(mirror: db::MixMucMirror) -> MixMucMirror {
    MixMucMirror {
        mix_channel_id: mirror.mix_channel_id,
        muc_room_id: mirror.muc_room_id,
        localpart: mirror.localpart,
        mix_domain: mirror.mix_domain,
    }
}

fn mam_page(page: db::MixMamPage) -> MixMamPage {
    MixMamPage {
        events: page.events.into_iter().map(event).collect(),
        total: page.total,
        first_index: page.first_index,
        complete: page.complete,
    }
}

fn create_outcome(outcome: db::CreateChannelOutcome) -> CreateChannelOutcome {
    match outcome {
        db::CreateChannelOutcome::Created(id) => CreateChannelOutcome::Created(id),
        db::CreateChannelOutcome::Conflict => CreateChannelOutcome::Conflict,
        db::CreateChannelOutcome::QuotaExceeded => CreateChannelOutcome::QuotaExceeded,
    }
}

fn store_event_outcome(outcome: db::StoreEventOutcome) -> StoreEventOutcome {
    match outcome {
        db::StoreEventOutcome::Stored(id) => StoreEventOutcome::Stored(id),
        db::StoreEventOutcome::Existing(_) => {
            unreachable!("existing MIX identity is resolved by the service keyring")
        }
        db::StoreEventOutcome::NotParticipant => StoreEventOutcome::NotParticipant,
        db::StoreEventOutcome::Conflict => StoreEventOutcome::Conflict,
        db::StoreEventOutcome::TooLarge => StoreEventOutcome::TooLarge,
    }
}

fn join_outcome(outcome: db::JoinChannelOutcome) -> JoinChannelOutcome {
    match outcome {
        db::JoinChannelOutcome::Joined {
            participant,
            preference,
            subscriptions,
            newly_joined,
            roster_change,
        } => JoinChannelOutcome::Joined {
            participant: map_participant(participant),
            preference: map_preference(preference),
            subscriptions,
            newly_joined,
            roster_change,
        },
        db::JoinChannelOutcome::Banned => JoinChannelOutcome::Banned,
        db::JoinChannelOutcome::NotAllowed => JoinChannelOutcome::NotAllowed,
        db::JoinChannelOutcome::Full => JoinChannelOutcome::Full,
        db::JoinChannelOutcome::MissingNick => JoinChannelOutcome::MissingNick,
        db::JoinChannelOutcome::NickConflict => JoinChannelOutcome::NickConflict,
    }
}

fn presence_outcome(outcome: db::PresenceOutcome) -> PresenceOutcome {
    match outcome {
        db::PresenceOutcome::Published => PresenceOutcome::Published,
        db::PresenceOutcome::Retracted => PresenceOutcome::Retracted,
        db::PresenceOutcome::Unchanged => PresenceOutcome::Unchanged,
        db::PresenceOutcome::NotSharing => PresenceOutcome::NotSharing,
        db::PresenceOutcome::NotParticipant => PresenceOutcome::NotParticipant,
    }
}

fn access_change_outcome(outcome: db::AccessChangeOutcome) -> AccessChangeOutcome {
    AccessChangeOutcome {
        removed_participants: outcome.removed_participants,
        removed_local_users: outcome.removed_local_users,
        removed_presence: outcome
            .removed_presence
            .into_iter()
            .map(|(participant, items)| {
                (
                    map_participant(participant),
                    items.into_iter().map(presence_item).collect(),
                )
            })
            .collect(),
    }
}

impl From<&MixInvitationProof> for db::MixInvitationProof {
    fn from(proof: &MixInvitationProof) -> Self {
        db::MixInvitationProof {
            inviter_jid: proof.inviter_jid.clone(),
            invitee_jid: proof.invitee_jid.clone(),
            channel_jid: proof.channel_jid.clone(),
            token: proof.token.clone(),
        }
    }
}

impl From<&MixParticipantPreference> for db::MixParticipantPreference {
    fn from(preference: &MixParticipantPreference) -> Self {
        preference_db(preference)
    }
}

fn form_field(
    name: &str,
    field_type: Option<&str>,
    values: impl IntoIterator<Item = String>,
) -> XmlElement {
    let mut field = XmlElement::new("field").attr("var", name);
    if let Some(field_type) = field_type {
        field = field.attr("type", field_type);
    }
    for value in values {
        field.push_child(XmlElement::new("value").text(value));
    }
    field
}

fn value_field(name: &str, value: impl ToString) -> XmlElement {
    form_field(name, None, [value.to_string()])
}

fn render_info_payload(channel: &db::MixChannel) -> String {
    let mut form = XmlElement::namespaced("x", "jabber:x:data").attr("type", "result");
    form.push_child(form_field(
        "FORM_TYPE",
        Some("hidden"),
        ["urn:xmpp:mix:core:1".to_owned()],
    ));
    if let Some(name) = &channel.name {
        form.push_child(value_field("Name", name));
    }
    if let Some(description) = &channel.description {
        form.push_child(value_field("Description", description));
    }
    if !channel.contacts.is_empty() {
        form.push_child(form_field(
            "Contact",
            None,
            channel.contacts.iter().cloned(),
        ));
    }
    form.push_child(value_field(
        "JID Visibility",
        match channel.jid_visibility.as_str() {
            "visible" => "jid-mandatory-visible",
            "maybe" => "jid-maybe-visible",
            _ => "jid-hidden",
        },
    ));
    form.finish()
}

fn render_config_payload(
    channel: &db::MixChannel,
    last_changed_by: &str,
    owners: &BTreeSet<String>,
    administrators: &BTreeSet<String>,
) -> String {
    let mut form = XmlElement::namespaced("x", "jabber:x:data").attr("type", "result");
    form.push_child(form_field(
        "FORM_TYPE",
        Some("hidden"),
        ["urn:xmpp:mix:admin:0".to_owned()],
    ));
    form.push_child(value_field("Last Change Made By", last_changed_by));
    form.push_child(form_field("Owner", None, owners.iter().cloned()));
    if !administrators.is_empty() {
        form.push_child(form_field(
            "Administrator",
            None,
            administrators.iter().cloned(),
        ));
    }
    form.push_child(form_field(
        "Nodes Present",
        None,
        [
            "participants",
            "presence",
            "information",
            "allowed",
            "banned",
            "jidmap-visible",
            "avatar",
        ]
        .into_iter()
        .map(str::to_owned),
    ));
    for (name, value) in [
        ("Messages Node Subscription", "participants"),
        ("Presence Node Subscription", "participants"),
        ("Participants Node Subscription", "participants"),
        (
            "Information Node Subscription",
            if channel.access_model == "open" {
                "anyone"
            } else {
                "participants"
            },
        ),
        ("Allowed Node Subscription", "admins"),
        ("Banned Node Subscription", "admins"),
        ("Configuration Node Access", "admins"),
        ("Information Node Update Rights", "admins"),
        ("Avatar Nodes Update Rights", "admins"),
        (
            "JID Visibility",
            match channel.jid_visibility.as_str() {
                "visible" => "jid-mandatory-visible",
                "maybe" => "jid-maybe-visible",
                _ => "jid-hidden",
            },
        ),
        ("Mandatory Nicks", bool_value(channel.nick_required)),
        ("Participants Must Provide Presence", "0"),
        ("Open Presence", "0"),
        (
            "User Message Retraction",
            bool_value(channel.allow_user_message_retraction),
        ),
        (
            "Administrator Message Retraction Rights",
            if channel.administrator_retraction_rights == "administrators" {
                "admins"
            } else {
                &channel.administrator_retraction_rights
            },
        ),
        (
            "Participation Addition by Invitation from Participant",
            bool_value(channel.allow_participant_invites),
        ),
        (
            "Private Messages",
            bool_value(channel.allow_private_messages),
        ),
        (
            "Enforce Registered Nick",
            bool_value(channel.enforce_registered_nick),
        ),
        ("access_model", &channel.access_model),
    ] {
        form.push_child(value_field(name, value));
    }
    form.push_child(value_field("max_participants", channel.max_participants));
    form.push_child(value_field("max_events", channel.max_events));
    form.finish()
}

fn bool_value(value: bool) -> &'static str {
    if value {
        "1"
    } else {
        "0"
    }
}

fn render_participant_payload(
    channel: &db::MixChannel,
    participant: &db::MixParticipant,
    preference: &db::MixParticipantPreference,
) -> String {
    let mut element = XmlElement::namespaced("participant", "urn:xmpp:mix:core:1");
    if let Some(nick) = &participant.nick {
        element.push_child(XmlElement::new("nick").text(nick));
    }
    if db::participant_jid_visible(channel, preference) {
        element.push_child(XmlElement::new("jid").text(&participant.jid));
    }
    element.finish()
}

fn render_access_payload(pattern: &str) -> String {
    XmlElement::namespaced("jid", "urn:xmpp:mix:admin:0")
        .text(pattern)
        .finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::postgres::PgPoolOptions;

    #[tokio::test]
    async fn delivery_admission_gate_is_clone_shared_and_fifo() {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgresql://localhost/northstar_gate_unit_test")
            .expect("a lazy test pool does not connect");
        let service = MixService::new_with_test_keyrings(pool);
        let first = service.clone();
        let second = service.clone();
        assert!(Arc::ptr_eq(
            &service.delivery_admission,
            &first.delivery_admission
        ));

        let held = service.delivery_admission_guard().await;
        let (ready_tx, mut ready_rx) = tokio::sync::mpsc::unbounded_channel();
        let (order_tx, mut order_rx) = tokio::sync::mpsc::unbounded_channel();
        let first_ready = ready_tx.clone();
        let first_order = order_tx.clone();
        let first_waiter = tokio::spawn(async move {
            first_ready.send(()).expect("test receiver remains open");
            let _guard = first.delivery_admission_guard().await;
            first_order.send(1_u8).expect("test receiver remains open");
        });
        ready_rx.recv().await.expect("first waiter started");
        tokio::task::yield_now().await;

        let second_waiter = tokio::spawn(async move {
            ready_tx.send(()).expect("test receiver remains open");
            let _guard = second.delivery_admission_guard().await;
            order_tx.send(2_u8).expect("test receiver remains open");
        });
        ready_rx.recv().await.expect("second waiter started");
        tokio::task::yield_now().await;
        drop(held);

        assert_eq!(order_rx.recv().await, Some(1));
        assert_eq!(order_rx.recv().await, Some(2));
        first_waiter.await.expect("first waiter completed");
        second_waiter.await.expect("second waiter completed");
    }

    #[tokio::test]
    async fn pam_capacity_admission_gate_is_clone_shared_and_fifo() {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgresql://localhost/northstar_pam_gate_unit_test")
            .expect("a lazy test pool does not connect");
        let service = MixService::new_with_test_keyrings(pool);
        let first = service.clone();
        let second = service.clone();
        assert!(Arc::ptr_eq(
            &service.pam_capacity_admission,
            &first.pam_capacity_admission
        ));

        let held = service.pam_capacity_admission_guard().await;
        let (ready_tx, mut ready_rx) = tokio::sync::mpsc::unbounded_channel();
        let (order_tx, mut order_rx) = tokio::sync::mpsc::unbounded_channel();
        let first_ready = ready_tx.clone();
        let first_order = order_tx.clone();
        let first_waiter = tokio::spawn(async move {
            first_ready.send(()).expect("test receiver remains open");
            let _guard = first.pam_capacity_admission_guard().await;
            first_order.send(1_u8).expect("test receiver remains open");
        });
        ready_rx.recv().await.expect("first waiter started");
        tokio::task::yield_now().await;

        let second_waiter = tokio::spawn(async move {
            ready_tx.send(()).expect("test receiver remains open");
            let _guard = second.pam_capacity_admission_guard().await;
            order_tx.send(2_u8).expect("test receiver remains open");
        });
        ready_rx.recv().await.expect("second waiter started");
        tokio::task::yield_now().await;
        drop(held);

        assert_eq!(order_rx.recv().await, Some(1));
        assert_eq!(order_rx.recv().await, Some(2));
        first_waiter.await.expect("first waiter completed");
        second_waiter.await.expect("second waiter completed");
    }

    #[test]
    fn mix_muc_repository_outcomes_map_without_collapsing_authority_failures() {
        for (repository, service) in [
            (db::LinkMixMucOutcome::Linked, MixMucLinkOutcome::Linked),
            (
                db::LinkMixMucOutcome::AlreadyLinked,
                MixMucLinkOutcome::AlreadyLinked,
            ),
            (
                db::LinkMixMucOutcome::MissingCounterpart,
                MixMucLinkOutcome::MissingCounterpart,
            ),
            (
                db::LinkMixMucOutcome::NotCommonOwner,
                MixMucLinkOutcome::NotCommonOwner,
            ),
            (db::LinkMixMucOutcome::Conflict, MixMucLinkOutcome::Conflict),
        ] {
            assert_eq!(map_mix_muc_link_outcome(repository), service);
        }
    }

    fn channel() -> db::MixChannel {
        db::MixChannel {
            id: Uuid::new_v4(),
            revision: 0,
            service_domain: "mix.example.test".to_owned(),
            localpart: "security".to_owned(),
            creator_jid: "owner@example.test".to_owned(),
            name: Some("</value><evil xmlns='urn:evil'>name</evil><value>".to_owned()),
            description: Some("description & <tag>\u{202e}".to_owned()),
            contacts: vec!["contact@example.test".to_owned()],
            access_model: "open".to_owned(),
            jid_visibility: "visible".to_owned(),
            nick_required: false,
            max_participants: 100,
            max_events: 1_000,
            allow_private_messages: true,
            allow_participant_invites: true,
            allow_user_message_retraction: true,
            administrator_retraction_rights: "administrators".to_owned(),
            enforce_registered_nick: false,
        }
    }

    fn assert_no_injected_element(xml: &str, expected_text: &str) {
        let document = roxmltree::Document::parse(xml).expect("builder output must parse");
        assert!(document
            .descendants()
            .filter(|node| node.is_element())
            .all(|node| node.tag_name().name() != "evil"));
        assert!(document
            .descendants()
            .filter_map(|node| node.text())
            .any(|text| text == expected_text));
    }

    #[test]
    fn info_and_config_payloads_escape_untrusted_text_and_namespaces() {
        let channel = channel();
        let info = render_info_payload(&channel);
        assert_no_injected_element(&info, "</value><evil xmlns='urn:evil'>name</evil><value>");
        let document = roxmltree::Document::parse(&info).unwrap();
        assert_eq!(
            document.root_element().tag_name().namespace(),
            Some("jabber:x:data")
        );

        let malicious = "</value><evil xmlns='urn:evil'>owner</evil><value>".to_owned();
        let owners = BTreeSet::from([malicious.clone()]);
        let administrators = BTreeSet::from(["admin&<@example.test".to_owned()]);
        let config = render_config_payload(&channel, &malicious, &owners, &administrators);
        assert_no_injected_element(&config, &malicious);
        let config_document = roxmltree::Document::parse(&config).unwrap();
        assert_eq!(
            config_document.root_element().tag_name().namespace(),
            Some("jabber:x:data")
        );
    }

    #[test]
    fn participant_and_access_payloads_cannot_inject_siblings() {
        let channel = channel();
        let participant = db::MixParticipant {
            participant_id: Uuid::new_v4(),
            jid: "</jid><evil xmlns='urn:evil'>jid</evil><jid>".to_owned(),
            nick: Some("</nick><evil xmlns='urn:evil'>nick</evil><nick>".to_owned()),
        };
        let payload = render_participant_payload(
            &channel,
            &participant,
            &db::MixParticipantPreference::default(),
        );
        assert_no_injected_element(&payload, &participant.jid);
        let document = roxmltree::Document::parse(&payload).unwrap();
        assert_eq!(
            document.root_element().tag_name().namespace(),
            Some("urn:xmpp:mix:core:1")
        );

        let pattern = "</jid><evil xmlns='urn:evil'>domain</evil><jid>";
        let access = render_access_payload(pattern);
        assert_no_injected_element(&access, pattern);
        assert_eq!(
            roxmltree::Document::parse(&access)
                .unwrap()
                .root_element()
                .tag_name()
                .namespace(),
            Some("urn:xmpp:mix:admin:0")
        );
    }

    // -- DTO boundary contract tests -------------------------------------
    //
    // The mirrors exist so the protocol layer never names a `db::` type. These
    // tests pin every mapped field and both translation directions, so a
    // repository column or boundary field added on one side only fails here
    // instead of silently dropping data at the service edge.

    #[test]
    fn mix_node_vocabulary_matches_the_repository_constants() {
        assert_eq!(NODE_MESSAGES, db::NODE_MESSAGES);
        assert_eq!(NODE_PRESENCE, db::NODE_PRESENCE);
        assert_eq!(NODE_PARTICIPANTS, db::NODE_PARTICIPANTS);
        assert_eq!(NODE_INFO, db::NODE_INFO);
        assert_eq!(NODE_CONFIG, db::NODE_CONFIG);
        assert_eq!(NODE_ALLOWED, db::NODE_ALLOWED);
        assert_eq!(NODE_BANNED, db::NODE_BANNED);
        assert_eq!(NODE_JIDMAP, db::NODE_JIDMAP);
        assert_eq!(NODE_AVATAR_DATA, db::NODE_AVATAR_DATA);
        assert_eq!(NODE_AVATAR_METADATA, db::NODE_AVATAR_METADATA);
        assert_eq!(ALL_NODES, db::ALL_NODES);
    }

    #[test]
    fn channel_map_preserves_every_field_and_round_trips() {
        let row = channel();
        let mapped = map_channel(row.clone());
        assert_eq!(mapped.id, row.id);
        assert_eq!(mapped.service_domain, row.service_domain);
        assert_eq!(mapped.localpart, row.localpart);
        assert_eq!(mapped.creator_jid, row.creator_jid);
        assert_eq!(mapped.name, row.name);
        assert_eq!(mapped.description, row.description);
        assert_eq!(mapped.contacts, row.contacts);
        assert_eq!(mapped.access_model, row.access_model);
        assert_eq!(mapped.jid_visibility, row.jid_visibility);
        assert_eq!(mapped.nick_required, row.nick_required);
        assert_eq!(mapped.max_participants, row.max_participants);
        assert_eq!(mapped.max_events, row.max_events);
        assert_eq!(mapped.allow_private_messages, row.allow_private_messages);
        assert_eq!(
            mapped.allow_participant_invites,
            row.allow_participant_invites
        );
        assert_eq!(
            mapped.allow_user_message_retraction,
            row.allow_user_message_retraction
        );
        assert_eq!(
            mapped.administrator_retraction_rights,
            row.administrator_retraction_rights
        );
        assert_eq!(mapped.enforce_registered_nick, row.enforce_registered_nick);
        assert_eq!(mapped.jid(), row.jid());

        let round_trip = channel_db(&mapped);
        assert_eq!(round_trip.id, row.id);
        assert_eq!(round_trip.service_domain, row.service_domain);
        assert_eq!(round_trip.localpart, row.localpart);
        assert_eq!(round_trip.creator_jid, row.creator_jid);
        assert_eq!(round_trip.name, row.name);
        assert_eq!(round_trip.description, row.description);
        assert_eq!(round_trip.contacts, row.contacts);
        assert_eq!(round_trip.access_model, row.access_model);
        assert_eq!(round_trip.jid_visibility, row.jid_visibility);
        assert_eq!(round_trip.nick_required, row.nick_required);
        assert_eq!(round_trip.max_participants, row.max_participants);
        assert_eq!(round_trip.max_events, row.max_events);
        assert_eq!(
            round_trip.allow_private_messages,
            row.allow_private_messages
        );
        assert_eq!(
            round_trip.allow_participant_invites,
            row.allow_participant_invites
        );
        assert_eq!(
            round_trip.allow_user_message_retraction,
            row.allow_user_message_retraction
        );
        assert_eq!(
            round_trip.administrator_retraction_rights,
            row.administrator_retraction_rights
        );
        assert_eq!(
            round_trip.enforce_registered_nick,
            row.enforce_registered_nick
        );
    }

    #[test]
    fn participant_and_preference_maps_preserve_fields_and_defaults_agree() {
        let row = db::MixParticipant {
            participant_id: Uuid::new_v4(),
            jid: "alice@example.test".to_owned(),
            nick: Some("Alice".to_owned()),
        };
        let mapped = map_participant(row.clone());
        assert_eq!(mapped.participant_id, row.participant_id);
        assert_eq!(mapped.jid, row.jid);
        assert_eq!(mapped.nick, row.nick);
        let round_trip = participant_db(&mapped);
        assert_eq!(round_trip.participant_id, row.participant_id);
        assert_eq!(round_trip.jid, row.jid);
        assert_eq!(round_trip.nick, row.nick);

        let db_default = db::MixParticipantPreference::default();
        let preference = map_preference(db_default.clone());
        assert_eq!(preference, MixParticipantPreference::default());
        assert_eq!(preference_db(&preference), db_default);
    }

    #[test]
    fn pam_membership_map_preserves_every_field() {
        let row = db::PamMembership {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            channel_jid: "room@mix.example.test".to_owned(),
            participant_id: Some("stable-id".to_owned()),
            state: "pending_join".to_owned(),
            request_id: Some("request-1".to_owned()),
            client_request_id: Some("client-1".to_owned()),
            requester_full_jid: Some("alice@example.test/Phone".to_owned()),
            subscriptions: vec![NODE_MESSAGES.to_owned(), NODE_PRESENCE.to_owned()],
        };
        let mapped = pam_membership(row.clone());
        assert_eq!(mapped.id, row.id);
        assert_eq!(mapped.user_id, row.user_id);
        assert_eq!(mapped.channel_jid, row.channel_jid);
        assert_eq!(mapped.participant_id, row.participant_id);
        assert_eq!(mapped.state, row.state);
        assert_eq!(mapped.request_id, row.request_id);
        assert_eq!(mapped.client_request_id, row.client_request_id);
        assert_eq!(mapped.requester_full_jid, row.requester_full_jid);
        assert_eq!(mapped.subscriptions, row.subscriptions);
    }

    #[test]
    fn event_and_page_maps_preserve_ordering_and_metadata() {
        let row = db::MixEvent {
            id: Uuid::new_v4(),
            item_id: db::mix_timestamp_item_id(),
            payload: "<body/>".to_owned(),
            created_at: Utc::now(),
        };
        let mapped = event(row.clone());
        assert_eq!(mapped.id, row.id);
        assert_eq!(mapped.item_id, row.item_id);
        assert_eq!(mapped.payload, row.payload);
        assert_eq!(mapped.created_at, row.created_at);

        let page = db::MixEventPage {
            events: vec![row.clone()],
        };
        let mapped_page = MixEventPage {
            events: page.events.clone().into_iter().map(event).collect(),
        };
        assert_eq!(
            page.events.iter().map(|e| e.id).collect::<Vec<_>>(),
            mapped_page.events.iter().map(|e| e.id).collect::<Vec<_>>(),
            "event order must be preserved"
        );
    }

    #[test]
    fn mam_page_and_boundary_maps_preserve_paging_metadata() {
        let first = db::ArchiveBoundary {
            id: Uuid::new_v4(),
            created_at: Utc::now(),
        };
        let last = db::ArchiveBoundary {
            id: Uuid::new_v4(),
            created_at: Utc::now(),
        };
        let mapped_page = mam_page(db::MixMamPage {
            events: Vec::new(),
            total: 42,
            first_index: 7,
            complete: false,
        });
        assert_eq!(mapped_page.total, 42);
        assert_eq!(mapped_page.first_index, 7);
        assert!(!mapped_page.complete);
        assert!(mapped_page.events.is_empty());

        let first_id = first.id;
        let last_id = last.id;
        let (mapped_first, mapped_last) = (Some(boundary(first)), Some(boundary(last)));
        assert_eq!(mapped_first.as_ref().map(|b| b.id), Some(first_id));
        assert_eq!(mapped_last.as_ref().map(|b| b.id), Some(last_id));
    }

    #[test]
    fn mam_query_translates_every_rsm_shape_in_both_directions() {
        let shapes = [
            db::MamRsmPage::First,
            db::MamRsmPage::Last,
            db::MamRsmPage::Before(Uuid::new_v4()),
            db::MamRsmPage::After(Uuid::new_v4()),
            db::MamRsmPage::Index(17),
        ];
        for page in shapes {
            let db_query = db::MamArchiveQuery {
                with_jid: Some("peer@example.test".to_owned()),
                start: Some(Utc::now()),
                end: None,
                before_id: None,
                after_id: Some(Uuid::new_v4()),
                ids: vec![Uuid::new_v4()],
                page,
                max: 25,
            };
            let mapped = MamArchiveQuery::from(db_query.clone());
            assert_eq!(mapped.with_jid, db_query.with_jid);
            assert_eq!(mapped.start, db_query.start);
            assert_eq!(mapped.end, db_query.end);
            assert_eq!(mapped.before_id, db_query.before_id);
            assert_eq!(mapped.after_id, db_query.after_id);
            assert_eq!(mapped.ids, db_query.ids);
            assert_eq!(mapped.max, db_query.max);
            match (db_query.page, mapped.page) {
                (db::MamRsmPage::First, MamRsmPage::First)
                | (db::MamRsmPage::Last, MamRsmPage::Last) => {}
                (db::MamRsmPage::Before(a), MamRsmPage::Before(b)) => assert_eq!(a, b),
                (db::MamRsmPage::After(a), MamRsmPage::After(b)) => assert_eq!(a, b),
                (db::MamRsmPage::Index(a), MamRsmPage::Index(b)) => assert_eq!(a, b),
                _ => panic!("MIX RSM shape changed during translation"),
            }
            let round_trip = mam_query_db(&mapped);
            assert_eq!(round_trip.with_jid, db_query.with_jid);
            assert_eq!(round_trip.max, db_query.max);
        }
    }

    #[test]
    fn s2s_policy_and_probe_target_maps_preserve_admission_bounds() {
        let policy = db::S2sOutboxPolicy {
            ttl_seconds: 600,
            max_rows: 1_024,
            max_bytes: 1_048_576,
            max_per_domain: 128,
        };
        let mapped: S2sOutboxPolicy = policy.into();
        assert_eq!(mapped.ttl_seconds, 600);
        assert_eq!(mapped.max_rows, 1_024);
        assert_eq!(mapped.max_bytes, 1_048_576);
        assert_eq!(mapped.max_per_domain, 128);

        let probe = db::MixPresenceProbeTarget {
            channel_jid: "room@mix.example.test".to_owned(),
            participant_jid: "alice@remote.test/Phone".to_owned(),
        };
        let mapped: MixPresenceProbeTarget = probe.into();
        assert_eq!(mapped.channel_jid, "room@mix.example.test");
        assert_eq!(mapped.participant_jid, "alice@remote.test/Phone");
    }

    #[test]
    fn access_change_map_preserves_removal_observations() {
        let participant_row = db::MixParticipant {
            participant_id: Uuid::new_v4(),
            jid: "alice@example.test".to_owned(),
            nick: None,
        };
        let presence_row = db::MixPresenceItem {
            item_id: "item-1".to_owned(),
            payload: "<presence/>".to_owned(),
            source_full_jid: Some("alice@example.test/Phone".to_owned()),
        };
        let mapped = access_change_outcome(db::AccessChangeOutcome {
            removed_participants: vec![Uuid::new_v4()],
            removed_local_users: vec![Uuid::new_v4()],
            removed_presence: vec![(participant_row.clone(), vec![presence_row.clone()])],
        });
        assert_eq!(mapped.removed_participants.len(), 1);
        assert_eq!(mapped.removed_local_users.len(), 1);
        assert_eq!(mapped.removed_presence.len(), 1);
        assert_eq!(
            mapped.removed_presence[0].0.participant_id,
            participant_row.participant_id
        );
        assert_eq!(mapped.removed_presence[0].1[0].item_id, "item-1");
    }

    #[test]
    fn outcome_maps_preserve_retraction_store_and_join_variants() {
        for (repository, service) in [
            (
                db::RetractMixMessageOutcome::Retracted,
                RetractMixMessageOutcome::Retracted,
            ),
            (
                db::RetractMixMessageOutcome::NotFound,
                RetractMixMessageOutcome::NotFound,
            ),
            (
                db::RetractMixMessageOutcome::Forbidden,
                RetractMixMessageOutcome::Forbidden,
            ),
        ] {
            let admission = retract_mix_message_admission(
                db::RetractMixMessageAdmission {
                    outcome: repository,
                    recipients: vec![db::MixParticipant {
                        participant_id: Uuid::new_v4(),
                        jid: "alice@example.test".to_owned(),
                        nick: None,
                    }],
                },
                |_| panic!("test case must not contain an existing replay intent"),
            );
            assert_eq!(admission.outcome, service);
        }

        for repository in [
            db::StoreEventOutcome::Stored(Uuid::new_v4()),
            db::StoreEventOutcome::NotParticipant,
            db::StoreEventOutcome::Conflict,
            db::StoreEventOutcome::TooLarge,
        ] {
            let mapped = store_event_outcome(repository.clone());
            match (repository, mapped) {
                (db::StoreEventOutcome::Stored(a), StoreEventOutcome::Stored(b)) => {
                    assert_eq!(a, b)
                }
                (db::StoreEventOutcome::NotParticipant, StoreEventOutcome::NotParticipant) => {}
                (db::StoreEventOutcome::Conflict, StoreEventOutcome::Conflict) => {}
                (db::StoreEventOutcome::TooLarge, StoreEventOutcome::TooLarge) => {}
                _ => panic!("store-event outcome variant changed during translation"),
            }
        }

        for repository in [
            db::CreateChannelOutcome::Created(Uuid::new_v4()),
            db::CreateChannelOutcome::Conflict,
            db::CreateChannelOutcome::QuotaExceeded,
        ] {
            let mapped = create_outcome(repository);
            match (repository, mapped) {
                (db::CreateChannelOutcome::Created(a), CreateChannelOutcome::Created(b)) => {
                    assert_eq!(a, b)
                }
                (db::CreateChannelOutcome::Conflict, CreateChannelOutcome::Conflict) => {}
                (db::CreateChannelOutcome::QuotaExceeded, CreateChannelOutcome::QuotaExceeded) => {}
                _ => panic!("create-channel outcome variant changed during translation"),
            }
        }

        let joined = join_outcome(db::JoinChannelOutcome::Joined {
            participant: db::MixParticipant {
                participant_id: Uuid::new_v4(),
                jid: "alice@example.test".to_owned(),
                nick: Some("Alice".to_owned()),
            },
            preference: db::MixParticipantPreference::default(),
            subscriptions: vec![NODE_MESSAGES.to_owned()],
            newly_joined: true,
            roster_change: None,
        });
        assert!(matches!(
            joined,
            JoinChannelOutcome::Joined {
                newly_joined: true,
                ..
            }
        ));
        assert!(matches!(
            join_outcome(db::JoinChannelOutcome::Banned),
            JoinChannelOutcome::Banned
        ));
        assert!(matches!(
            join_outcome(db::JoinChannelOutcome::NotAllowed),
            JoinChannelOutcome::NotAllowed
        ));
        assert!(matches!(
            join_outcome(db::JoinChannelOutcome::Full),
            JoinChannelOutcome::Full
        ));
        assert!(matches!(
            join_outcome(db::JoinChannelOutcome::MissingNick),
            JoinChannelOutcome::MissingNick
        ));
        assert!(matches!(
            join_outcome(db::JoinChannelOutcome::NickConflict),
            JoinChannelOutcome::NickConflict
        ));

        assert!(matches!(
            presence_outcome(db::PresenceOutcome::Unchanged),
            PresenceOutcome::Unchanged
        ));
        assert!(matches!(
            presence_outcome(db::PresenceOutcome::NotSharing),
            PresenceOutcome::NotSharing
        ));
        assert!(matches!(
            presence_outcome(db::PresenceOutcome::NotParticipant),
            PresenceOutcome::NotParticipant
        ));
    }
}
