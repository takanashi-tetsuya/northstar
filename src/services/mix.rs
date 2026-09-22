//! Application-service boundary for XEP-0369/XEP-0405 MIX.
//!
//! The service owns replay proofs, admission limits and committed delivery wakes.
//! Repository operations preserve each cross-table transaction.

use crate::abuse::{MixMessageContentKeyring, MixRetractionContentKeyring};
use anyhow::Result;
use chrono::{DateTime, Utc};
use northstar_xml_builder::XmlElement;
use std::collections::BTreeSet;
use std::sync::Arc;
use tokio::sync::{watch, Mutex, MutexGuard, OwnedSemaphorePermit};
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
/// Transaction-ordered PostgreSQL wake channel for durable MIX delivery.
///
/// The notification payload is only the database schema that committed the
/// row.  It is never authorization data: workers still claim the fenced row
/// from PostgreSQL before producing any externally visible effect.
pub(crate) const MIX_DELIVERY_WAKE_NOTIFICATION_CHANNEL: &str = "northstar_mix_delivery_v1";
pub(crate) const SUBSCRIBABLE_NODES: [&str; 6] = [
    NODE_MESSAGES,
    NODE_PRESENCE,
    NODE_PARTICIPANTS,
    NODE_INFO,
    NODE_AVATAR_DATA,
    NODE_AVATAR_METADATA,
];
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
    pub(crate) route_wake_generation: i64,
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
pub(crate) use northstar_federation_core::S2sOutboxPolicy;

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum FederatedMixIqReplay {
    Miss,
    Replay(String),
    Conflict,
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

/// Process-local observation of a durable MIX-outbox change.
///
/// PostgreSQL rows remain the sole delivery authority.  This value is only a
/// monotonic wake generation: `watch` retains it until every receiver has
/// observed it, so a database notification that arrives between a worker's
/// claim and its next wait cannot be lost.  The dedicated PostgreSQL listener
/// advances the same generation after reconnecting, forcing a fresh durable
/// probe for notifications that may have been missed during that gap.
#[derive(Debug)]
pub(crate) struct MixDeliveryWakeBroker {
    schema: String,
    sender: watch::Sender<u64>,
}

impl MixDeliveryWakeBroker {
    #[cfg(test)]
    pub(crate) fn for_test() -> Arc<Self> {
        Self::new("public".to_owned()).expect("test wake schema is valid")
    }

    fn new(schema: String) -> Result<Arc<Self>> {
        anyhow::ensure!(
            !schema.is_empty()
                && schema.len() <= 63
                && !schema.contains('\0')
                && schema != "pg_catalog"
                && schema != "information_schema",
            "invalid PostgreSQL schema for MIX outbox wake listener"
        );
        let (sender, _) = watch::channel(0_u64);
        Ok(Arc::new(Self { schema, sender }))
    }

    fn advance(&self) {
        // A u64 wrap would require more than 5.8e11 committed outbox changes
        // per second for a year.  `watch` also records its own change version,
        // so a theoretical numeric wrap cannot erase an already published
        // edge for a live receiver.
        // `send_modify` serializes the read/advance/publish operation inside
        // the watch state. A separate atomic increment followed by
        // `send_replace` could publish generations out of numeric order under
        // concurrent local commits and listener notifications.
        self.sender
            .send_modify(|generation| *generation = generation.wrapping_add(1));
    }

    /// Record a local mutation only after its transaction-returning service
    /// call has completed successfully.  The database trigger publishes the
    /// same committed fact to other processes; this direct edge avoids making
    /// the writer wait for its own listener under CPU pressure.
    pub(crate) fn publish_local_commit(&self) {
        self.advance();
    }

    /// A listener start, transparent reconnect, or terminal receive error
    /// may have missed a PostgreSQL notification.  Wake every lane so it
    /// performs an authoritative claim; the periodic scan remains the final
    /// recovery path if PostgreSQL itself is unavailable.
    pub(crate) fn publish_listener_transition(&self) {
        self.advance();
    }

    /// Accept the bounded, non-secret schema payload emitted by migration
    /// 0133.  An unexpected payload has no authority and must not generate
    /// unrelated cross-schema load.
    pub(crate) fn accept_committed_notification(&self, schema: &str) -> bool {
        if schema != self.schema {
            return false;
        }
        self.advance();
        true
    }

    pub(crate) fn subscribe(&self) -> MixDeliveryWakeSubscription {
        MixDeliveryWakeSubscription {
            receiver: self.sender.subscribe(),
        }
    }

    #[cfg(test)]
    fn generation(&self) -> u64 {
        *self.sender.borrow()
    }
}

/// One MIX outbox lane's lossless local wake receiver.
pub(crate) struct MixDeliveryWakeSubscription {
    receiver: watch::Receiver<u64>,
}

impl MixDeliveryWakeSubscription {
    /// `watch` retains an unseen value.  Therefore this resolves immediately
    /// for a notification that happened before a lane installed its next
    /// wait, rather than relying on an edge-triggered `Notify` permit.
    pub(crate) async fn changed(&mut self) -> bool {
        self.receiver.changed().await.is_ok()
    }
}

#[derive(Clone)]
pub(crate) struct MixService<R> {
    repository: R,
    message_identity: MixMessageContentKeyring,
    retraction_identity: MixRetractionContentKeyring,
    /// The bounded durable MIX outbox budget derived once from the configured
    /// primary application-pool capacity.  Protocol code gets this typed
    /// scheduling limit rather than a raw database-pool capability.
    outbox_background_budget: usize,
    /// Fair, process-local admission gate. Every application operation that
    /// can add a durable MIX delivery acquires this before asking database connection for a
    /// transaction. PostgreSQL keeps the cross-process authority; this gate
    /// prevents ordinary same-process concurrency from occupying a pool of
    /// connections while queued behind that authority.
    delivery_admission: Arc<Mutex<()>>,
    /// Clone-shared FIFO gate for the durable MIX-PAM operation counter. It is
    /// acquired before repository code can check out a PostgreSQL connection,
    /// so one process contributes at most one waiter to the cross-process
    /// singleton authority while unrelated database work retains pool access.
    pam_capacity_admission: Arc<Mutex<()>>,
    /// Application-owned admission for short durable outbox database turns.
    /// The same capability is shared with PubSub and clustered MUC delivery;
    /// no individual XEP worker can independently consume the primary pool's
    /// foreground reserve.
    outbox_db_admission: crate::services::durable_outbox::DurableOutboxDatabaseAdmission,
    /// Shared cross-process/listener wake broker for the durable delivery
    /// lane. It carries no stanza data and is not a second delivery authority.
    /// MIX-PAM has a distinct eligibility model and deliberately retains its
    /// own periodic recovery until it receives a typed wake.
    delivery_wake: Arc<MixDeliveryWakeBroker>,
}

pub(crate) trait MixRepository: Send + Sync {
    fn link_local_muc_mirror(
        &self,
        mix_domain: &str,
        localpart: &str,
        actor_bare_jid: &str,
        local_domain: &str,
    ) -> impl std::future::Future<Output = Result<MixMucLinkOutcome>> + Send;
    fn create_mix_channel(
        &self,
        service_domain: &str,
        requested_localpart: Option<&str>,
        creator_jid: &str,
        max_channels_per_owner: i64,
        federated: Option<&FederatedMixMutation>,
    ) -> impl std::future::Future<Output = Result<(CreateChannelOutcome, String)>> + Send;
    fn mix_channel(
        &self,
        service_domain: &str,
        localpart: &str,
    ) -> impl std::future::Future<Output = Result<Option<MixChannel>>> + Send;
    fn discoverable_mix_channel_page(
        &self,
        service_domain: &str,
        requester: &str,
        after: Option<&str>,
        before: Option<Option<&str>>,
        max: i64,
    ) -> impl std::future::Future<Output = Result<Option<MixDiscoPage>>> + Send;
    fn mix_role(
        &self,
        channel_id: Uuid,
        jid: &str,
    ) -> impl std::future::Future<Output = Result<Option<String>>> + Send;
    fn mix_channel_discoverable_to(
        &self,
        channel: &MixChannel,
        actor: &str,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn destroy_mix_channel(
        &self,
        channel_id: Uuid,
        actor: &str,
        federated: Option<&FederatedMixMutation>,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn join_mix_channel(
        &self,
        channel_id: Uuid,
        request: JoinMixRequest,
        federated: Option<&FederatedMixMutation>,
    ) -> impl std::future::Future<Output = Result<JoinChannelOutcome>> + Send;
    fn mix_participant(
        &self,
        channel_id: Uuid,
        jid: &str,
    ) -> impl std::future::Future<Output = Result<Option<MixParticipant>>> + Send;
    fn mix_participant_by_id(
        &self,
        channel_id: Uuid,
        participant_id: Uuid,
    ) -> impl std::future::Future<Output = Result<Option<MixParticipant>>> + Send;
    fn mix_presence_source_jid(
        &self,
        channel_id: Uuid,
        item_id: &str,
    ) -> impl std::future::Future<Output = Result<Option<String>>> + Send;
    fn expire_unrefreshed_mix_presence(
        &self,
        cutoff: DateTime<Utc>,
    ) -> impl std::future::Future<Output = Result<Vec<ExpiredMixPresence>>> + Send;
    fn update_mix_subscriptions(
        &self,
        channel_id: Uuid,
        actor: &str,
        subscribe: &[String],
        unsubscribe: &[String],
        federated: Option<&FederatedMixMutation>,
    ) -> impl std::future::Future<Output = Result<Option<UpdateSubscriptionsOutcome>>> + Send;
    fn set_mix_nick(
        &self,
        channel_id: Uuid,
        actor: &str,
        nick: &str,
        federated: Option<&FederatedMixMutation>,
    ) -> impl std::future::Future<Output = Result<std::result::Result<MixParticipant, SetNickError>>>
           + Send;
    fn leave_mix_channel(
        &self,
        channel_id: Uuid,
        actor: &str,
        pam_user_id: Option<Uuid>,
        federated: Option<&FederatedMixMutation>,
    ) -> impl std::future::Future<Output = Result<Option<LeaveMixOutcome>>> + Send;
    fn store_mix_presence(
        &self,
        channel_id: Uuid,
        actor_bare: &str,
        actor_full: &str,
        payload: &str,
        unavailable: bool,
    ) -> impl std::future::Future<Output = Result<PresenceOutcome>> + Send;
    fn ensure_mix_presence(
        &self,
        channel_id: Uuid,
        actor_bare: &str,
        actor_full: &str,
        payload: &str,
    ) -> impl std::future::Future<Output = Result<PresenceOutcome>> + Send;
    fn store_mix_message(
        &self,
        request: StoreMixMessageRequest<'_>,
        authenticators: Option<&crate::abuse::ContentIdentityAuthenticators>,
    ) -> impl std::future::Future<Output = Result<StoreMixMessageAdmission>> + Send;
    fn lookup_mix_message_replay(
        &self,
        channel_id: Uuid,
        actor: &str,
        identity: &MixReplayIdentity,
        authenticators: &crate::abuse::ContentIdentityAuthenticators,
    ) -> impl std::future::Future<Output = Result<MixBusinessReplay>> + Send;
    fn lookup_mix_retraction_replay(
        &self,
        channel_id: Uuid,
        actor: &str,
        target_id: Uuid,
        identity: &MixReplayIdentity,
        authenticators: &crate::abuse::ContentIdentityAuthenticators,
    ) -> impl std::future::Future<Output = Result<MixBusinessReplay>> + Send;
    fn authorized_mix_event_page(
        &self,
        channel_id: Uuid,
        actor: &str,
        node: &str,
        before: Option<(DateTime<Utc>, Uuid)>,
        limit: i64,
    ) -> impl std::future::Future<Output = Result<MixReadOutcome<MixEventPage>>> + Send;
    fn publish_mix_avatar(
        &self,
        channel_id: Uuid,
        actor: &str,
        node: &str,
        item_id: &str,
        payload: &str,
        federated: Option<&FederatedMixMutation>,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn retract_mix_avatar(
        &self,
        channel_id: Uuid,
        actor: &str,
        node: &str,
        item_id: &str,
        federated: Option<&FederatedMixMutation>,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn authorized_mix_mam_page(
        &self,
        channel_id: Uuid,
        actor: &str,
        viewer_id: Option<Uuid>,
        query: &MamArchiveQuery,
    ) -> impl std::future::Future<Output = Result<MixReadOutcome<MixMamPage>>> + Send;
    fn authorized_mix_mam_boundaries(
        &self,
        channel_id: Uuid,
        actor: &str,
        viewer_id: Option<Uuid>,
    ) -> impl std::future::Future<
        Output = Result<MixReadOutcome<(Option<ArchiveBoundary>, Option<ArchiveBoundary>)>>,
    > + Send;
    fn authorized_mix_access_entries(
        &self,
        channel_id: Uuid,
        actor: &str,
        banned: bool,
        limit: i64,
    ) -> impl std::future::Future<Output = Result<MixReadOutcome<Vec<String>>>> + Send;
    fn update_mix_info(
        &self,
        channel_id: Uuid,
        actor: &str,
        update: MixInfoUpdate,
        federated: Option<&FederatedMixMutation>,
    ) -> impl std::future::Future<Output = Result<MixMutationOutcome>> + Send;
    fn update_mix_config(
        &self,
        channel_id: Uuid,
        actor: &str,
        update: MixConfigUpdate,
        roles: MixRoleUpdate,
        federated: Option<&FederatedMixMutation>,
    ) -> impl std::future::Future<Output = Result<MixMutationOutcome>> + Send;
    fn set_mix_access_entry(
        &self,
        update: MixAccessEntryUpdate<'_>,
        federated: Option<&FederatedMixMutation>,
    ) -> impl std::future::Future<Output = Result<Option<AccessChangeOutcome>>> + Send;
    fn register_mix_nick(
        &self,
        service_domain: &str,
        actor: &str,
        nick: &str,
        federated: Option<&FederatedMixMutation>,
    ) -> impl std::future::Future<Output = Result<RegisterMixNickOutcome>> + Send;
    fn mix_participant_preference(
        &self,
        channel_id: Uuid,
        actor: &str,
    ) -> impl std::future::Future<Output = Result<Option<MixParticipantPreference>>> + Send;
    fn update_mix_participant_preference(
        &self,
        channel_id: Uuid,
        actor: &str,
        preference: &MixParticipantPreference,
        federated: Option<&FederatedMixMutation>,
    ) -> impl std::future::Future<Output = Result<Option<MixParticipantPreferenceUpdateOutcome>>> + Send;
    fn authorized_mix_jid_map_entries(
        &self,
        channel_id: Uuid,
        actor: &str,
        limit: i64,
    ) -> impl std::future::Future<Output = Result<MixReadOutcome<Vec<(String, String)>>>> + Send;
    fn issue_mix_invitation(
        &self,
        channel_id: Uuid,
        inviter: &str,
        invitee: &str,
        token: &str,
        lifetime: chrono::Duration,
        federated: Option<&FederatedMixMutation>,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn mix_private_message_recipient(
        &self,
        channel_id: Uuid,
        sender: &str,
        recipient_id: Uuid,
    ) -> impl std::future::Future<Output = Result<Option<(MixParticipant, MixParticipant)>>> + Send;
    fn retract_mix_message(
        &self,
        request: RetractMixMessageRequest<'_>,
        authenticators: Option<&crate::abuse::ContentIdentityAuthenticators>,
    ) -> impl std::future::Future<Output = Result<RetractMixMessageAdmission>> + Send;
    fn begin_remote_pam_join(
        &self,
        request: BeginRemotePamJoin,
    ) -> impl std::future::Future<Output = Result<PamOperationReplay>> + Send;
    fn lookup_remote_pam_operation(
        &self,
        user_id: Uuid,
        requester_full_jid: &str,
        client_request_id: &str,
        request_digest: &[u8; 32],
    ) -> impl std::future::Future<Output = Result<PamOperationReplay>> + Send;
    fn begin_remote_pam_leave(
        &self,
        request: BeginRemotePamLeave,
    ) -> impl std::future::Future<Output = Result<PamOperationReplay>> + Send;
    fn complete_remote_pam_success(
        &self,
        authenticated_domain: &str,
        channel_jid: &str,
        recipient_bare: &str,
        request_id: &str,
        response_digest: &[u8; 32],
        join: Option<RemotePamJoin<'_>>,
    ) -> impl std::future::Future<Output = Result<RemotePamCompletionOutcome>> + Send;
    #[allow(clippy::too_many_arguments)]
    fn complete_remote_pam_error(
        &self,
        authenticated_domain: &str,
        channel_jid: &str,
        recipient_bare: &str,
        request_id: &str,
        response_digest: &[u8; 32],
        error_type: &str,
        condition: &str,
    ) -> impl std::future::Future<Output = Result<RemotePamCompletionOutcome>> + Send;
    fn pam_memberships(
        &self,
        user_id: Uuid,
    ) -> impl std::future::Future<Output = Result<Vec<PamMembership>>> + Send;
    fn pam_membership(
        &self,
        user_id: Uuid,
        channel_jid: &str,
    ) -> impl std::future::Future<Output = Result<Option<PamMembership>>> + Send;
    fn local_pam_users_for_channel(
        &self,
        channel_jid: &str,
    ) -> impl std::future::Future<Output = Result<Vec<Uuid>>> + Send;
    fn reconcile_expired_remote_pam(
        &self,
        limit: i64,
    ) -> impl std::future::Future<Output = Result<u64>> + Send;
    fn claim_pam_results(
        &self,
        limit: i64,
    ) -> impl std::future::Future<Output = Result<Vec<ClaimedPamResult>>> + Send;
    fn renew_pam_result_lease(
        &self,
        operation_id: Uuid,
        lease_token: Uuid,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn acknowledge_pam_result(
        &self,
        operation_id: Uuid,
        lease_token: Uuid,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn defer_pam_result(
        &self,
        operation_id: Uuid,
        lease_token: Uuid,
        delay_seconds: i64,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn retry_pam_result(
        &self,
        operation_id: Uuid,
        lease_token: Uuid,
        attempt_count: i32,
        error: &str,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn prune_expired_pam_results(
        &self,
        limit: i64,
    ) -> impl std::future::Future<Output = Result<u64>> + Send;
    fn find_enabled_user(
        &self,
        username: &str,
    ) -> impl std::future::Future<Output = Result<Option<MixAccount>>> + Send;

    fn find_enabled_user_by_id(
        &self,
        user_id: Uuid,
    ) -> impl std::future::Future<Output = Result<Option<MixAccount>>> + Send;
    fn is_blocked(
        &self,
        owner_id: Uuid,
        candidate: &str,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;

    fn pep_node(
        &self,
        owner_id: Uuid,
        node: &str,
    ) -> impl std::future::Future<Output = Result<Option<PepNodeConfig>>> + Send;
    fn pep_items(
        &self,
        owner_id: Uuid,
        node: &str,
        item_id: Option<&str>,
        limit: i64,
    ) -> impl std::future::Future<Output = Result<Vec<(String, String)>>> + Send;
    fn get_vcard(
        &self,
        user_id: Uuid,
    ) -> impl std::future::Future<Output = Result<VCardRecord>> + Send;
    fn latest_roster_change_for_contact(
        &self,
        user_id: Uuid,
        contact_jid: &str,
    ) -> impl std::future::Future<Output = Result<Option<northstar_roster_core::RosterChange>>> + Send;
    fn mix_muc_mirror_for_mix(
        &self,
        mix_channel_id: Uuid,
    ) -> impl std::future::Future<Output = Result<Option<MixMucMirror>>> + Send;
    fn mix_muc_mirror_for_muc(
        &self,
        muc_room_id: Uuid,
    ) -> impl std::future::Future<Output = Result<Option<MixMucMirror>>> + Send;
    fn mix_muc_mirror_service_complete(
        &self,
        mix_domain: &str,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    #[allow(clippy::too_many_arguments)]
    fn archive_mix_message_once(
        &self,
        personal_archive_id: Uuid,
        owner_id: Uuid,
        channel_jid: &str,
        authoritative_stanza_id: Uuid,
        stanza: &str,
        encrypted: bool,
        client_stanza_id: Option<&str>,
    ) -> impl std::future::Future<Output = Result<SourceArchiveAdmission>> + Send;

    fn enqueue_s2s_response_batch(
        &self,
        target_domain: &str,
        responses: &[String],
        policy: S2sOutboxPolicy,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
    fn federated_mix_iq_replay(
        &self,
        authenticated_domain: &str,
        actor_jid: &str,
        request_id: &str,
        request_digest: &[u8; 32],
    ) -> impl std::future::Future<Output = Result<FederatedMixIqReplay>> + Send;
    fn admit_federated_mix_iq_result(
        &self,
        authenticated_domain: &str,
        actor_jid: &str,
        request_id: &str,
        request_digest: &[u8; 32],
        response: &str,
        policy: S2sOutboxPolicy,
    ) -> impl std::future::Future<Output = Result<FederatedMixIqReplay>> + Send;
    fn claim_mix_deliveries(
        &self,
        limit: i64,
        max_bytes: i64,
    ) -> impl std::future::Future<Output = Result<Vec<ClaimedMixDelivery>>> + Send;
    fn maintain_mix_delivery_retention(
        &self,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
    fn prune_expired_business_intents(
        &self,
        limit: i64,
    ) -> impl std::future::Future<Output = Result<u64>> + Send;
    fn prune_expired_federated_iq_results(
        &self,
        limit: i64,
    ) -> impl std::future::Future<Output = Result<u64>> + Send;
    fn acknowledge_mix_delivery(
        &self,
        delivery_id: Uuid,
        lease_token: Uuid,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn fence_mix_socket_write(
        &self,
        source: crate::outbound::MixDelivery,
    ) -> impl std::future::Future<Output = Result<crate::outbound::MixDelivery>> + Send;
    fn transfer_mix_delivery_to_cluster(
        &self,
        source: crate::outbound::MixDelivery,
        node_id: &str,
        request_id: Uuid,
        ttl_seconds: u64,
    ) -> impl std::future::Future<Output = Result<crate::outbound::MixDelivery>> + Send;
    fn release_mix_cluster_delivery(
        &self,
        source: crate::outbound::MixDelivery,
        node_id: &str,
        request_id: Uuid,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn transfer_mix_delivery_to_bosh(
        &self,
        source: crate::outbound::MixDelivery,
        session_id: Uuid,
        ttl_seconds: u64,
    ) -> impl std::future::Future<Output = Result<crate::outbound::MixDelivery>> + Send;
    fn renew_mix_delivery_lease(
        &self,
        delivery_id: Uuid,
        lease_token: Uuid,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn dead_letter_mix_delivery(
        &self,
        delivery_id: Uuid,
        lease_token: Uuid,
        terminal_reason: &str,
        error: &str,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn retry_mix_delivery(
        &self,
        delivery_id: Uuid,
        lease_token: Uuid,
        _claimed_attempt_count: i32,
        route_wake_generation: i64,
        error: &str,
    ) -> impl std::future::Future<Output = Result<MixDeliveryRetryOutcome>> + Send;
    fn defer_mix_delivery(
        &self,
        delivery_id: Uuid,
        lease_token: Uuid,
        route_wake_generation: i64,
        delay_seconds: i64,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn wake_mix_delivery_recipient(
        &self,
        recipient_jid: &str,
    ) -> impl std::future::Future<Output = Result<u64>> + Send;
    #[allow(dead_code)]
    fn mix_delivery_dead_letters(
        &self,
        before: Option<(DateTime<Utc>, Uuid)>,
        limit: i64,
    ) -> impl std::future::Future<Output = Result<Vec<MixDeliveryDeadLetter>>> + Send;
    #[allow(dead_code)]
    fn requeue_mix_delivery_dead_letter(
        &self,
        dead_letter_id: Uuid,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
}

impl<R: MixRepository> MixService<R> {
    #[cfg(test)]
    pub(crate) fn new(
        repository: R,
        message_identity: MixMessageContentKeyring,
        retraction_identity: MixRetractionContentKeyring,
        primary_pool_max_connections: u32,
        schema: String,
    ) -> Result<Self> {
        Self::new_with_outbox_database_admission(
            repository,
            message_identity,
            retraction_identity,
            crate::services::durable_outbox::DurableOutboxDatabaseAdmission::for_primary_pool(
                primary_pool_max_connections,
            ),
            schema,
        )
    }

    pub(crate) fn new_with_outbox_database_admission(
        repository: R,
        message_identity: MixMessageContentKeyring,
        retraction_identity: MixRetractionContentKeyring,
        outbox_db_admission: crate::services::durable_outbox::DurableOutboxDatabaseAdmission,
        schema: String,
    ) -> Result<Self> {
        let outbox_background_budget = outbox_db_admission.capacity();
        Ok(Self {
            repository,
            message_identity,
            retraction_identity,
            outbox_background_budget,
            delivery_admission: Arc::new(Mutex::new(())),
            pam_capacity_admission: Arc::new(Mutex::new(())),
            outbox_db_admission,
            delivery_wake: MixDeliveryWakeBroker::new(schema)?,
        })
    }

    /// Maximum concurrent durable MIX outbox operations permitted for this
    /// process.  The service owns the primary-pool capacity policy so callers
    /// cannot infer it by reaching into a `database connection`.
    pub(crate) const fn outbox_background_budget(&self) -> usize {
        self.outbox_background_budget
    }

    async fn delivery_admission_guard(&self) -> MutexGuard<'_, ()> {
        self.delivery_admission.lock().await
    }

    async fn pam_capacity_admission_guard(&self) -> MutexGuard<'_, ()> {
        self.pam_capacity_admission.lock().await
    }

    async fn outbox_db_admission_guard(&self) -> OwnedSemaphorePermit {
        self.outbox_db_admission.acquire().await
    }

    /// Subscribe one durable MIX worker lane before it evaluates its next
    /// wait.  A committed PostgreSQL wake arriving while the lane is busy is
    /// retained by the subscription and causes an immediate next claim.
    pub(crate) fn subscribe_delivery_wake(&self) -> MixDeliveryWakeSubscription {
        self.delivery_wake.subscribe()
    }

    /// Expose the broker only to the existing dedicated PostgreSQL listener.
    /// Protocol handlers receive subscriptions, never a raw notification
    /// sender, so they cannot turn uncommitted input into a wake fact.
    pub(crate) fn delivery_wake_broker(&self) -> Arc<MixDeliveryWakeBroker> {
        Arc::clone(&self.delivery_wake)
    }

    fn publish_delivery_local_commit(&self) {
        self.delivery_wake.publish_local_commit();
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
        self.repository
            .link_local_muc_mirror(mix_domain, localpart, actor_bare_jid, local_domain)
            .await
    }

    pub(crate) async fn create_mix_channel(
        &self,
        service_domain: &str,
        requested_localpart: Option<&str>,
        creator_jid: &str,
        max_channels_per_owner: i64,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<(CreateChannelOutcome, String)> {
        self.repository
            .create_mix_channel(
                service_domain,
                requested_localpart,
                creator_jid,
                max_channels_per_owner,
                federated,
            )
            .await
    }
    pub(crate) async fn mix_channel(
        &self,
        service_domain: &str,
        localpart: &str,
    ) -> Result<Option<MixChannel>> {
        self.repository.mix_channel(service_domain, localpart).await
    }
    pub(crate) async fn discoverable_mix_channel_page(
        &self,
        service_domain: &str,
        requester: &str,
        after: Option<&str>,
        before: Option<Option<&str>>,
        max: i64,
    ) -> Result<Option<MixDiscoPage>> {
        self.repository
            .discoverable_mix_channel_page(service_domain, requester, after, before, max)
            .await
    }
    pub(crate) async fn mix_role(&self, channel_id: Uuid, jid: &str) -> Result<Option<String>> {
        self.repository.mix_role(channel_id, jid).await
    }
    pub(crate) async fn mix_channel_discoverable_to(
        &self,
        channel: &MixChannel,
        actor: &str,
    ) -> Result<bool> {
        self.repository
            .mix_channel_discoverable_to(channel, actor)
            .await
    }
    pub(crate) async fn destroy_mix_channel(
        &self,
        channel_id: Uuid,
        actor: &str,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<bool> {
        let _admission = self.delivery_admission_guard().await;
        self.repository
            .destroy_mix_channel(channel_id, actor, federated)
            .await
    }
    pub(crate) async fn join_mix_channel(
        &self,
        channel_id: Uuid,
        request: JoinMixRequest,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<JoinChannelOutcome> {
        let _admission = self.delivery_admission_guard().await;
        self.repository
            .join_mix_channel(channel_id, request, federated)
            .await
    }
    pub(crate) async fn mix_participant(
        &self,
        channel_id: Uuid,
        jid: &str,
    ) -> Result<Option<MixParticipant>> {
        self.repository.mix_participant(channel_id, jid).await
    }
    pub(crate) async fn mix_participant_by_id(
        &self,
        channel_id: Uuid,
        participant_id: Uuid,
    ) -> Result<Option<MixParticipant>> {
        self.repository
            .mix_participant_by_id(channel_id, participant_id)
            .await
    }
    pub(crate) async fn mix_presence_source_jid(
        &self,
        channel_id: Uuid,
        item_id: &str,
    ) -> Result<Option<String>> {
        self.repository
            .mix_presence_source_jid(channel_id, item_id)
            .await
    }
    pub(crate) async fn expire_unrefreshed_mix_presence(
        &self,
        cutoff: DateTime<Utc>,
    ) -> Result<Vec<ExpiredMixPresence>> {
        let _admission = self.delivery_admission_guard().await;
        self.repository
            .expire_unrefreshed_mix_presence(cutoff)
            .await
    }
    pub(crate) async fn update_mix_subscriptions(
        &self,
        channel_id: Uuid,
        actor: &str,
        subscribe: &[String],
        unsubscribe: &[String],
        federated: Option<&FederatedMixMutation>,
    ) -> Result<Option<UpdateSubscriptionsOutcome>> {
        let _admission = self.delivery_admission_guard().await;
        self.repository
            .update_mix_subscriptions(channel_id, actor, subscribe, unsubscribe, federated)
            .await
    }
    pub(crate) async fn set_mix_nick(
        &self,
        channel_id: Uuid,
        actor: &str,
        nick: &str,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<std::result::Result<MixParticipant, SetNickError>> {
        let _admission = self.delivery_admission_guard().await;
        self.repository
            .set_mix_nick(channel_id, actor, nick, federated)
            .await
    }
    pub(crate) async fn leave_mix_channel(
        &self,
        channel_id: Uuid,
        actor: &str,
        pam_user_id: Option<Uuid>,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<Option<LeaveMixOutcome>> {
        let _admission = self.delivery_admission_guard().await;
        self.repository
            .leave_mix_channel(channel_id, actor, pam_user_id, federated)
            .await
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
        self.repository
            .store_mix_presence(channel_id, actor_bare, actor_full, payload, unavailable)
            .await
    }
    pub(crate) async fn ensure_mix_presence(
        &self,
        channel_id: Uuid,
        actor_bare: &str,
        actor_full: &str,
        payload: &str,
    ) -> Result<PresenceOutcome> {
        let _admission = self.delivery_admission_guard().await;
        self.repository
            .ensure_mix_presence(channel_id, actor_bare, actor_full, payload)
            .await
    }
    pub(crate) async fn store_mix_message(
        &self,
        request: StoreMixMessageRequest<'_>,
    ) -> Result<StoreMixMessageAdmission> {
        let authenticators = request.identity.as_ref().map(|identity| {
            self.message_identity
                .authenticators(&identity.canonical_semantics)
        });
        let _admission = self.delivery_admission_guard().await;
        let result = self
            .repository
            .store_mix_message(request, authenticators.as_ref())
            .await?;
        if matches!(&result.outcome, StoreEventOutcome::Stored(_)) && !result.recipients.is_empty()
        {
            self.publish_delivery_local_commit();
        }
        Ok(result)
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
        self.repository
            .lookup_mix_message_replay(channel_id, actor, identity, &authenticators)
            .await
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
        self.repository
            .lookup_mix_retraction_replay(channel_id, actor, target_id, identity, &authenticators)
            .await
    }
    pub(crate) async fn authorized_mix_event_page(
        &self,
        channel_id: Uuid,
        actor: &str,
        node: &str,
        before: Option<(DateTime<Utc>, Uuid)>,
        limit: i64,
    ) -> Result<MixReadOutcome<MixEventPage>> {
        self.repository
            .authorized_mix_event_page(channel_id, actor, node, before, limit)
            .await
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
        let _admission = self.delivery_admission_guard().await;
        self.repository
            .publish_mix_avatar(channel_id, actor, node, item_id, payload, federated)
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
        let _admission = self.delivery_admission_guard().await;
        self.repository
            .retract_mix_avatar(channel_id, actor, node, item_id, federated)
            .await
    }
    pub(crate) async fn authorized_mix_mam_page(
        &self,
        channel_id: Uuid,
        actor: &str,
        viewer_id: Option<Uuid>,
        query: &MamArchiveQuery,
    ) -> Result<MixReadOutcome<MixMamPage>> {
        self.repository
            .authorized_mix_mam_page(channel_id, actor, viewer_id, query)
            .await
    }
    pub(crate) async fn authorized_mix_mam_boundaries(
        &self,
        channel_id: Uuid,
        actor: &str,
        viewer_id: Option<Uuid>,
    ) -> Result<MixReadOutcome<(Option<ArchiveBoundary>, Option<ArchiveBoundary>)>> {
        self.repository
            .authorized_mix_mam_boundaries(channel_id, actor, viewer_id)
            .await
    }
    pub(crate) async fn authorized_mix_access_entries(
        &self,
        channel_id: Uuid,
        actor: &str,
        banned: bool,
        limit: i64,
    ) -> Result<MixReadOutcome<Vec<String>>> {
        self.repository
            .authorized_mix_access_entries(channel_id, actor, banned, limit)
            .await
    }
    pub(crate) async fn update_mix_info(
        &self,
        channel_id: Uuid,
        actor: &str,
        update: MixInfoUpdate,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<MixMutationOutcome> {
        let _admission = self.delivery_admission_guard().await;
        self.repository
            .update_mix_info(channel_id, actor, update, federated)
            .await
    }

    pub(crate) async fn update_mix_config(
        &self,
        channel_id: Uuid,
        actor: &str,
        update: MixConfigUpdate,
        roles: MixRoleUpdate,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<MixMutationOutcome> {
        let _admission = self.delivery_admission_guard().await;
        self.repository
            .update_mix_config(channel_id, actor, update, roles, federated)
            .await
    }

    pub(crate) async fn set_mix_access_entry(
        &self,
        update: MixAccessEntryUpdate<'_>,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<Option<AccessChangeOutcome>> {
        let _admission = self.delivery_admission_guard().await;
        self.repository
            .set_mix_access_entry(update, federated)
            .await
    }
    pub(crate) async fn register_mix_nick(
        &self,
        service_domain: &str,
        actor: &str,
        nick: &str,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<RegisterMixNickOutcome> {
        let _admission = self.delivery_admission_guard().await;
        self.repository
            .register_mix_nick(service_domain, actor, nick, federated)
            .await
    }
    pub(crate) async fn mix_participant_preference(
        &self,
        channel_id: Uuid,
        actor: &str,
    ) -> Result<Option<MixParticipantPreference>> {
        self.repository
            .mix_participant_preference(channel_id, actor)
            .await
    }
    pub(crate) async fn update_mix_participant_preference(
        &self,
        channel_id: Uuid,
        actor: &str,
        preference: &MixParticipantPreference,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<Option<MixParticipantPreferenceUpdateOutcome>> {
        let _admission = self.delivery_admission_guard().await;
        self.repository
            .update_mix_participant_preference(channel_id, actor, preference, federated)
            .await
    }
    pub(crate) async fn authorized_mix_jid_map_entries(
        &self,
        channel_id: Uuid,
        actor: &str,
        limit: i64,
    ) -> Result<MixReadOutcome<Vec<(String, String)>>> {
        self.repository
            .authorized_mix_jid_map_entries(channel_id, actor, limit)
            .await
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
        self.repository
            .issue_mix_invitation(channel_id, inviter, invitee, token, lifetime, federated)
            .await
    }
    pub(crate) async fn mix_private_message_recipient(
        &self,
        channel_id: Uuid,
        sender: &str,
        recipient_id: Uuid,
    ) -> Result<Option<(MixParticipant, MixParticipant)>> {
        self.repository
            .mix_private_message_recipient(channel_id, sender, recipient_id)
            .await
    }
    pub(crate) async fn retract_mix_message(
        &self,
        request: RetractMixMessageRequest<'_>,
    ) -> Result<RetractMixMessageAdmission> {
        let authenticators = request.identity.as_ref().map(|identity| {
            self.retraction_identity
                .authenticators(&identity.canonical_semantics)
        });
        let _admission = self.delivery_admission_guard().await;
        let result = self
            .repository
            .retract_mix_message(request, authenticators.as_ref())
            .await?;
        if matches!(&result.outcome, RetractMixMessageOutcome::Retracted)
            && !result.recipients.is_empty()
        {
            self.publish_delivery_local_commit();
        }
        Ok(result)
    }
    pub(crate) async fn begin_remote_pam_join(
        &self,
        request: BeginRemotePamJoin,
    ) -> Result<PamOperationReplay> {
        let _admission = self.pam_capacity_admission_guard().await;
        self.repository.begin_remote_pam_join(request).await
    }

    pub(crate) async fn lookup_remote_pam_operation(
        &self,
        user_id: Uuid,
        requester_full_jid: &str,
        client_request_id: &str,
        request_digest: &[u8; 32],
    ) -> Result<PamOperationReplay> {
        self.repository
            .lookup_remote_pam_operation(
                user_id,
                requester_full_jid,
                client_request_id,
                request_digest,
            )
            .await
    }

    pub(crate) async fn begin_remote_pam_leave(
        &self,
        request: BeginRemotePamLeave,
    ) -> Result<PamOperationReplay> {
        let _admission = self.pam_capacity_admission_guard().await;
        self.repository.begin_remote_pam_leave(request).await
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
        self.repository
            .complete_remote_pam_success(
                authenticated_domain,
                channel_jid,
                recipient_bare,
                request_id,
                response_digest,
                join,
            )
            .await
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
        self.repository
            .complete_remote_pam_error(
                authenticated_domain,
                channel_jid,
                recipient_bare,
                request_id,
                response_digest,
                error_type,
                condition,
            )
            .await
    }
    pub(crate) async fn pam_memberships(&self, user_id: Uuid) -> Result<Vec<PamMembership>> {
        self.repository.pam_memberships(user_id).await
    }
    pub(crate) async fn pam_membership(
        &self,
        user_id: Uuid,
        channel_jid: &str,
    ) -> Result<Option<PamMembership>> {
        self.repository.pam_membership(user_id, channel_jid).await
    }
    pub(crate) async fn local_pam_users_for_channel(&self, channel_jid: &str) -> Result<Vec<Uuid>> {
        self.repository
            .local_pam_users_for_channel(channel_jid)
            .await
    }
    pub(crate) async fn reconcile_expired_remote_pam(&self, limit: i64) -> Result<u64> {
        let _outbox_db_admission = self.outbox_db_admission_guard().await;
        self.repository.reconcile_expired_remote_pam(limit).await
    }

    pub(crate) async fn claim_pam_results(&self, limit: i64) -> Result<Vec<ClaimedPamResult>> {
        tracing::debug!(
            available_permits = self.outbox_db_admission.available_permits(),
            "MIX PAM result claim waiting for database admission"
        );
        let _outbox_db_admission = self.outbox_db_admission_guard().await;
        self.repository.claim_pam_results(limit).await
    }

    pub(crate) async fn renew_pam_result_lease(
        &self,
        operation_id: Uuid,
        lease_token: Uuid,
    ) -> Result<bool> {
        let _outbox_db_admission = self.outbox_db_admission_guard().await;
        self.repository
            .renew_pam_result_lease(operation_id, lease_token)
            .await
    }

    pub(crate) async fn acknowledge_pam_result(
        &self,
        operation_id: Uuid,
        lease_token: Uuid,
    ) -> Result<bool> {
        let _outbox_db_admission = self.outbox_db_admission_guard().await;
        self.repository
            .acknowledge_pam_result(operation_id, lease_token)
            .await
    }

    pub(crate) async fn defer_pam_result(
        &self,
        operation_id: Uuid,
        lease_token: Uuid,
        delay_seconds: i64,
    ) -> Result<bool> {
        let _outbox_db_admission = self.outbox_db_admission_guard().await;
        self.repository
            .defer_pam_result(operation_id, lease_token, delay_seconds)
            .await
    }

    pub(crate) async fn retry_pam_result(
        &self,
        operation_id: Uuid,
        lease_token: Uuid,
        attempt_count: i32,
        error: &str,
    ) -> Result<bool> {
        let _outbox_db_admission = self.outbox_db_admission_guard().await;
        self.repository
            .retry_pam_result(operation_id, lease_token, attempt_count, error)
            .await
    }

    pub(crate) async fn prune_expired_pam_results(&self, limit: i64) -> Result<u64> {
        let _outbox_db_admission = self.outbox_db_admission_guard().await;
        let _admission = self.pam_capacity_admission_guard().await;
        self.repository.prune_expired_pam_results(limit).await
    }

    pub(crate) async fn find_enabled_user(&self, username: &str) -> Result<Option<MixAccount>> {
        self.repository.find_enabled_user(username).await
    }

    /// Read a local recipient while processing a claimed durable MIX outbox
    /// row.  This is deliberately separate from [`Self::find_enabled_user`]:
    /// live ingress must not wait behind background work, while a durable
    /// worker must leave the service-owned foreground connection reserve
    /// intact.  The permit is released before the caller performs any socket,
    /// cluster, or federation I/O.
    pub(crate) async fn outbox_find_enabled_user(
        &self,
        username: &str,
    ) -> Result<Option<MixAccount>> {
        tracing::debug!(
            available_permits = self.outbox_db_admission.available_permits(),
            "MIX durable local-account lookup waiting for database admission"
        );
        let _outbox_db_admission = self.outbox_db_admission_guard().await;
        self.repository.find_enabled_user(username).await
    }

    pub(crate) async fn find_enabled_user_by_id(
        &self,
        user_id: Uuid,
    ) -> Result<Option<MixAccount>> {
        self.repository.find_enabled_user_by_id(user_id).await
    }
    pub(crate) async fn is_blocked(&self, owner_id: Uuid, candidate: &str) -> Result<bool> {
        self.repository.is_blocked(owner_id, candidate).await
    }

    /// Outbox-only variant of the live privacy lookup.  Keep the permit
    /// scoped to this database await rather than to the enclosing durable
    /// delivery attempt, which can wait on a local transport or remote peer.
    pub(crate) async fn outbox_is_blocked(&self, owner_id: Uuid, candidate: &str) -> Result<bool> {
        let _outbox_db_admission = self.outbox_db_admission_guard().await;
        self.repository.is_blocked(owner_id, candidate).await
    }

    /// Resolve the cluster authority route for a claimed durable outbox row.
    ///
    /// `ClusterManager::lookup_nodes` reads the Redis-backed session-route
    /// authority. It is not part of the PostgreSQL outbox transaction, so it
    /// must not retain a scarce outbox database-admission permit while waiting
    /// for the Redis authority pool. The caller preserves the lookup's own
    /// timeout and error semantics.
    pub(crate) async fn outbox_lookup_cluster_nodes(
        &self,
        cluster: &crate::cluster::ClusterManager,
        jid: &str,
    ) -> Result<Vec<String>> {
        cluster.lookup_nodes(jid).await
    }

    /// Durably admit a claimed MIX outbox stanza to federation.
    ///
    /// `FederationRouter::send` is an S2S *outbox admission* operation here:
    /// it performs one PostgreSQL enqueue/commit followed only by local,
    /// non-awaiting wake-ups. It does not open a peer connection or write a
    /// socket. The permit is consequently released before the S2S dispatcher
    /// performs any network work, while preserving component-route wake-up
    /// semantics owned by the router.
    pub(crate) async fn outbox_admit_federated_stanza(
        &self,
        federation: &crate::s2s::FederationRouter,
        target_domain: &str,
        stanza: String,
    ) -> bool {
        let _outbox_db_admission = self.outbox_db_admission_guard().await;
        federation.send(target_domain, stanza, None).await
    }
    pub(crate) async fn pep_node(
        &self,
        owner_id: Uuid,
        node: &str,
    ) -> Result<Option<PepNodeConfig>> {
        self.repository.pep_node(owner_id, node).await
    }
    pub(crate) async fn pep_items(
        &self,
        owner_id: Uuid,
        node: &str,
        item_id: Option<&str>,
        limit: i64,
    ) -> Result<Vec<(String, String)>> {
        self.repository
            .pep_items(owner_id, node, item_id, limit)
            .await
    }
    pub(crate) async fn get_vcard(&self, user_id: Uuid) -> Result<VCardRecord> {
        self.repository.get_vcard(user_id).await
    }
    pub(crate) async fn latest_roster_change_for_contact(
        &self,
        user_id: Uuid,
        contact_jid: &str,
    ) -> Result<Option<northstar_roster_core::RosterChange>> {
        self.repository
            .latest_roster_change_for_contact(user_id, contact_jid)
            .await
    }
    pub(crate) async fn mix_muc_mirror_for_mix(
        &self,
        mix_channel_id: Uuid,
    ) -> Result<Option<MixMucMirror>> {
        self.repository.mix_muc_mirror_for_mix(mix_channel_id).await
    }
    pub(crate) async fn mix_muc_mirror_for_muc(
        &self,
        muc_room_id: Uuid,
    ) -> Result<Option<MixMucMirror>> {
        self.repository.mix_muc_mirror_for_muc(muc_room_id).await
    }
    pub(crate) async fn mix_muc_mirror_service_complete(&self, mix_domain: &str) -> Result<bool> {
        self.repository
            .mix_muc_mirror_service_complete(mix_domain)
            .await
    }
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
        self.repository
            .archive_mix_message_once(
                personal_archive_id,
                owner_id,
                channel_jid,
                authoritative_stanza_id,
                stanza,
                encrypted,
                client_stanza_id,
            )
            .await
    }

    /// Idempotently archive one claimed durable MIX delivery under the same
    /// bounded outbox database budget as its claim and completion fence.
    /// This preserves the normal archive/replay result exactly, but does not
    /// allow the caller to retain a database permit while routing the stanza.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn outbox_archive_mix_message_once(
        &self,
        personal_archive_id: Uuid,
        owner_id: Uuid,
        channel_jid: &str,
        authoritative_stanza_id: Uuid,
        stanza: &str,
        encrypted: bool,
        client_stanza_id: Option<&str>,
    ) -> Result<SourceArchiveAdmission> {
        let _outbox_db_admission = self.outbox_db_admission_guard().await;
        self.repository
            .archive_mix_message_once(
                personal_archive_id,
                owner_id,
                channel_jid,
                authoritative_stanza_id,
                stanza,
                encrypted,
                client_stanza_id,
            )
            .await
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
        self.repository
            .enqueue_s2s_response_batch(target_domain, responses, policy)
            .await
    }

    pub(crate) async fn federated_mix_iq_replay(
        &self,
        authenticated_domain: &str,
        actor_jid: &str,
        request_id: &str,
        request_digest: &[u8; 32],
    ) -> Result<FederatedMixIqReplay> {
        self.repository
            .federated_mix_iq_replay(authenticated_domain, actor_jid, request_id, request_digest)
            .await
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
        self.repository
            .admit_federated_mix_iq_result(
                authenticated_domain,
                actor_jid,
                request_id,
                request_digest,
                response,
                policy,
            )
            .await
    }

    pub(crate) async fn claim_mix_deliveries(
        &self,
        limit: i64,
        max_bytes: i64,
    ) -> Result<Vec<ClaimedMixDelivery>> {
        tracing::debug!(
            available_permits = self.outbox_db_admission.available_permits(),
            "MIX delivery claim waiting for database admission"
        );
        let _admission = self.outbox_db_admission_guard().await;
        self.repository.claim_mix_deliveries(limit, max_bytes).await
    }

    /// Keep MIX retention bounded without putting cleanup ahead of a live
    /// recipient claim. This remains a short repository-only turn under the
    /// private outbox admission capability.
    pub(crate) async fn maintain_mix_delivery_retention(&self) -> Result<()> {
        let _admission = self.outbox_db_admission_guard().await;
        self.repository.maintain_mix_delivery_retention().await
    }

    pub(crate) async fn prune_expired_business_intents(&self, limit: i64) -> Result<u64> {
        let _admission = self.outbox_db_admission_guard().await;
        self.repository.prune_expired_business_intents(limit).await
    }

    pub(crate) async fn prune_expired_federated_iq_results(&self, limit: i64) -> Result<u64> {
        let _admission = self.outbox_db_admission_guard().await;
        self.repository
            .prune_expired_federated_iq_results(limit)
            .await
    }

    pub(crate) async fn acknowledge_mix_delivery(
        &self,
        delivery_id: Uuid,
        lease_token: Uuid,
    ) -> Result<bool> {
        let _admission = self.outbox_db_admission_guard().await;
        let result = self
            .repository
            .acknowledge_mix_delivery(delivery_id, lease_token)
            .await?;
        if result {
            self.publish_delivery_local_commit();
        }
        Ok(result)
    }

    /// Give a direct C2S writer a rotated, bounded MIX source lease before
    /// it can place bytes on TCP/WebSocket. The protocol layer receives no
    /// SQL capability and must treat the returned token as writer-private.
    pub(crate) async fn fence_mix_socket_write(
        &self,
        source: crate::outbound::MixDelivery,
    ) -> Result<crate::outbound::MixDelivery> {
        let _admission = self.outbox_db_admission_guard().await;
        self.repository.fence_mix_socket_write(source).await
    }

    /// Persist a remote-node ownership fence before a signed cluster command
    /// is allowed to enqueue this exact MIX source on the destination node.
    pub(crate) async fn transfer_mix_delivery_to_cluster(
        &self,
        source: crate::outbound::MixDelivery,
        node_id: &str,
        request_id: Uuid,
        ttl_seconds: u64,
    ) -> Result<crate::outbound::MixDelivery> {
        let _admission = self.outbox_db_admission_guard().await;
        self.repository
            .transfer_mix_delivery_to_cluster(source, node_id, request_id, ttl_seconds)
            .await
    }

    /// Release only the exact remote-node MIX hand-off which never reached a
    /// local durable boundary. A later transfer is never overwritten.
    pub(crate) async fn release_mix_cluster_delivery(
        &self,
        source: crate::outbound::MixDelivery,
        node_id: &str,
        request_id: Uuid,
    ) -> Result<bool> {
        let _admission = self.outbox_db_admission_guard().await;
        let result = self
            .repository
            .release_mix_cluster_delivery(source, node_id, request_id)
            .await?;
        if result {
            self.publish_delivery_local_commit();
        }
        Ok(result)
    }

    /// Persist a typed BOSH owner for a claimed MIX recipient row. This is a
    /// transport transfer, not a delivery acknowledgement: client BOSH ACK
    /// processing remains responsible for the final exact source deletion.
    pub(crate) async fn transfer_mix_delivery_to_bosh(
        &self,
        source: crate::outbound::MixDelivery,
        session_id: Uuid,
        ttl_seconds: u64,
    ) -> Result<crate::outbound::MixDelivery> {
        let _admission = self.outbox_db_admission_guard().await;
        self.repository
            .transfer_mix_delivery_to_bosh(source, session_id, ttl_seconds)
            .await
    }

    pub(crate) async fn renew_mix_delivery_lease(
        &self,
        delivery_id: Uuid,
        lease_token: Uuid,
    ) -> Result<bool> {
        let _admission = self.outbox_db_admission_guard().await;
        self.repository
            .renew_mix_delivery_lease(delivery_id, lease_token)
            .await
    }

    pub(crate) async fn dead_letter_mix_delivery(
        &self,
        delivery_id: Uuid,
        lease_token: Uuid,
        terminal_reason: &str,
        error: &str,
    ) -> Result<bool> {
        let _admission = self.outbox_db_admission_guard().await;
        let result = self
            .repository
            .dead_letter_mix_delivery(delivery_id, lease_token, terminal_reason, error)
            .await?;
        if result {
            self.publish_delivery_local_commit();
        }
        Ok(result)
    }

    pub(crate) async fn retry_mix_delivery(
        &self,
        delivery_id: Uuid,
        lease_token: Uuid,
        _claimed_attempt_count: i32,
        route_wake_generation: i64,
        error: &str,
    ) -> Result<bool> {
        let _admission = self.outbox_db_admission_guard().await;
        let result = self
            .repository
            .retry_mix_delivery(
                delivery_id,
                lease_token,
                _claimed_attempt_count,
                route_wake_generation,
                error,
            )
            .await?;
        match result {
            MixDeliveryRetryOutcome::LeaseLost => Ok(false),
            MixDeliveryRetryOutcome::Retried => Ok(true),
            MixDeliveryRetryOutcome::RouteWokenAtAttemptLimit
            | MixDeliveryRetryOutcome::DeadLettered => {
                self.publish_delivery_local_commit();
                Ok(true)
            }
        }
    }

    pub(crate) async fn defer_mix_delivery(
        &self,
        delivery_id: Uuid,
        lease_token: Uuid,
        route_wake_generation: i64,
        delay_seconds: i64,
    ) -> Result<bool> {
        let _admission = self.outbox_db_admission_guard().await;
        self.repository
            .defer_mix_delivery(
                delivery_id,
                lease_token,
                route_wake_generation,
                delay_seconds,
            )
            .await
    }

    /// A locally verified MIX-capable resource can make an already-persisted
    /// delivery head routable sooner than its timer recovery probe. The
    /// database row remains the delivery authority; this advances its durable
    /// route epoch and brings an unleased head's next claim forward.
    pub(crate) async fn wake_mix_delivery_recipient(&self, recipient_jid: &str) -> Result<u64> {
        let _admission = self.outbox_db_admission_guard().await;
        let result = self
            .repository
            .wake_mix_delivery_recipient(recipient_jid)
            .await?;
        if result > 0 {
            self.publish_delivery_local_commit();
        }
        Ok(result)
    }

    #[allow(dead_code)] // Exposed for the pending admin recovery endpoint wiring.
    pub(crate) async fn mix_delivery_dead_letters(
        &self,
        before: Option<(DateTime<Utc>, Uuid)>,
        limit: i64,
    ) -> Result<Vec<MixDeliveryDeadLetter>> {
        let _admission = self.outbox_db_admission_guard().await;
        self.repository
            .mix_delivery_dead_letters(before, limit)
            .await
    }

    #[allow(dead_code)] // Exposed for the pending admin recovery endpoint wiring.
    pub(crate) async fn requeue_mix_delivery_dead_letter(
        &self,
        dead_letter_id: Uuid,
    ) -> Result<bool> {
        let _admission = self.delivery_admission_guard().await;
        let _outbox_db_admission = self.outbox_db_admission_guard().await;
        let result = self
            .repository
            .requeue_mix_delivery_dead_letter(dead_letter_id)
            .await?;
        if result {
            self.publish_delivery_local_commit();
        }
        Ok(result)
    }
}

fn mix_preference_result_form(preference: &MixParticipantPreference) -> String {
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
    context: &FederatedMixMutation,
    success: &FederatedMixSuccess,
) -> Result<String> {
    let payload = match success {
        FederatedMixSuccess::Create { channel } => {
            XmlElement::namespaced("create", "urn:xmpp:mix:core:1")
                .attr("channel", channel)
                .finish()
        }
        FederatedMixSuccess::Destroy { channel } => {
            XmlElement::namespaced("destroy", "urn:xmpp:mix:core:1")
                .attr("channel", channel)
                .finish()
        }
        FederatedMixSuccess::RegisterNick { nick } => {
            XmlElement::namespaced("register", "urn:xmpp:mix:misc:0")
                .child(XmlElement::new("nick").text(nick))
                .finish()
        }
        FederatedMixSuccess::Join {
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
        FederatedMixSuccess::Leave => {
            XmlElement::namespaced("leave", "urn:xmpp:mix:core:1").finish()
        }
        FederatedMixSuccess::SetNick { nick } => {
            XmlElement::namespaced("setnick", "urn:xmpp:mix:core:1")
                .child(XmlElement::new("nick").text(nick))
                .finish()
        }
        FederatedMixSuccess::UpdateSubscriptions { subscriptions } => {
            let mut update = XmlElement::namespaced("update-subscription", "urn:xmpp:mix:core:1");
            for node in subscriptions {
                update.push_child(XmlElement::new("subscribe").attr("node", node));
            }
            update.finish()
        }
        FederatedMixSuccess::PubSubPublish { node, item_id } => {
            XmlElement::namespaced("pubsub", "http://jabber.org/protocol/pubsub")
                .child(
                    XmlElement::new("publish")
                        .attr("node", node)
                        .child(XmlElement::new("item").attr("id", item_id)),
                )
                .finish()
        }
        FederatedMixSuccess::PubSubEmpty => {
            XmlElement::namespaced("pubsub", "http://jabber.org/protocol/pubsub").finish()
        }
        FederatedMixSuccess::Preference { preference } => {
            XmlElement::namespaced("user-preference", "urn:xmpp:mix:anon:0")
                .validated_fragment(&mix_preference_result_form(preference))?
                .finish()
        }
        FederatedMixSuccess::Invitation {
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

#[derive(Clone)]
pub(crate) struct MixPayloads;

impl MixEventPayloadRenderer for MixPayloads {
    fn info_payload(&self, channel: &MixChannel) -> String {
        render_info_payload(channel)
    }

    fn config_payload(
        &self,
        channel: &MixChannel,
        last_changed_by: &str,
        owners: &BTreeSet<String>,
        administrators: &BTreeSet<String>,
    ) -> String {
        render_config_payload(channel, last_changed_by, owners, administrators)
    }

    fn participant_payload(
        &self,
        channel: &MixChannel,
        participant: &MixParticipant,
        preference: &MixParticipantPreference,
    ) -> String {
        render_participant_payload(channel, participant, preference)
    }

    fn access_payload(&self, pattern: &str) -> String {
        render_access_payload(pattern)
    }

    fn presence_delivery_stanza(&self, delivery: MixPresenceDelivery<'_>) -> Result<String> {
        let MixPresenceDelivery {
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
        if participant_jid_visible(channel, preference) {
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
        channel: &MixChannel,
        recipient: &MixParticipant,
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
        channel: &MixChannel,
        sender: &MixParticipant,
        recipient: &MixParticipant,
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
        channel: &MixChannel,
        sender: &MixParticipant,
        recipient: &MixParticipant,
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
        context: &FederatedMixMutation,
        success: &FederatedMixSuccess,
    ) -> Result<String> {
        render_federated_mix_iq_result(context, success)
    }

    fn pam_join_result(&self, result: PamJoinResult<'_>) -> Result<String> {
        let PamJoinResult {
            client_request_id,
            actor_bare,
            requester_full_jid,
            channel_jid,
            participant_id,
            subscriptions,
            nick,
        } = result;
        anyhow::ensure!(
            valid_stable_participant_id(participant_id),
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

fn render_info_payload(channel: &MixChannel) -> String {
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
    channel: &MixChannel,
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
    channel: &MixChannel,
    participant: &MixParticipant,
    preference: &MixParticipantPreference,
) -> String {
    let mut element = XmlElement::namespaced("participant", "urn:xmpp:mix:core:1");
    if let Some(nick) = &participant.nick {
        element.push_child(XmlElement::new("nick").text(nick));
    }
    if participant_jid_visible(channel, preference) {
        element.push_child(XmlElement::new("jid").text(&participant.jid));
    }
    element.finish()
}

fn render_access_payload(pattern: &str) -> String {
    XmlElement::namespaced("jid", "urn:xmpp:mix:admin:0")
        .text(pattern)
        .finish()
}

#[derive(Clone, Debug)]
pub(crate) enum FederatedMixSuccess {
    Create {
        channel: String,
    },
    Destroy {
        channel: String,
    },
    RegisterNick {
        nick: String,
    },
    Join {
        participant: MixParticipant,
        subscriptions: Vec<String>,
        preference: Option<MixParticipantPreference>,
        anonymous_profile: bool,
    },
    Leave,
    SetNick {
        nick: String,
    },
    UpdateSubscriptions {
        subscriptions: Vec<String>,
    },
    PubSubPublish {
        node: String,
        item_id: String,
    },
    PubSubEmpty,
    Preference {
        preference: MixParticipantPreference,
    },
    Invitation {
        inviter: String,
        invitee: String,
        channel: String,
        token: String,
    },
}

pub(crate) struct MixPresenceDelivery<'a> {
    pub channel: &'a MixChannel,
    pub participant: &'a MixParticipant,
    pub preference: &'a MixParticipantPreference,
    pub recipient: &'a MixParticipant,
    pub item_id: &'a str,
    pub actor_full: &'a str,
    pub children: &'a str,
    pub unavailable: bool,
}

pub(crate) struct PamJoinResult<'a> {
    pub client_request_id: &'a str,
    pub actor_bare: &'a str,
    pub requester_full_jid: &'a str,
    pub channel_jid: &'a str,
    pub participant_id: &'a str,
    pub subscriptions: &'a [String],
    pub nick: Option<&'a str>,
}

pub(crate) trait MixEventPayloadRenderer: Sync {
    fn info_payload(&self, channel: &MixChannel) -> String;
    fn config_payload(
        &self,
        channel: &MixChannel,
        last_changed_by: &str,
        owners: &BTreeSet<String>,
        administrators: &BTreeSet<String>,
    ) -> String;
    fn participant_payload(
        &self,
        channel: &MixChannel,
        participant: &MixParticipant,
        preference: &MixParticipantPreference,
    ) -> String;
    fn access_payload(&self, pattern: &str) -> String;
    fn presence_delivery_stanza(&self, delivery: MixPresenceDelivery<'_>) -> Result<String>;
    fn node_event_stanza(
        &self,
        channel: &MixChannel,
        recipient: &MixParticipant,
        node: &str,
        item_id: &str,
        payload: Option<&str>,
        retract: bool,
    ) -> Result<String>;
    fn message_delivery_stanza(
        &self,
        channel: &MixChannel,
        sender: &MixParticipant,
        recipient: &MixParticipant,
        authoritative_id: Uuid,
        payload: &str,
        visible_jid: Option<&str>,
    ) -> Result<String>;
    fn retraction_delivery_stanza(
        &self,
        channel: &MixChannel,
        sender: &MixParticipant,
        recipient: &MixParticipant,
        authoritative_id: Uuid,
        target_id: Uuid,
        visible_jid: Option<&str>,
    ) -> Result<String>;
    fn federated_iq_result(
        &self,
        context: &FederatedMixMutation,
        success: &FederatedMixSuccess,
    ) -> Result<String>;
    fn pam_join_result(&self, result: PamJoinResult<'_>) -> Result<String>;
    fn pam_leave_result(
        &self,
        client_request_id: &str,
        actor_bare: &str,
        requester_full_jid: &str,
        channel_jid: &str,
    ) -> Result<String>;
    fn pam_error_result(
        &self,
        client_request_id: &str,
        actor_bare: &str,
        requester_full_jid: &str,
        error_type: &str,
        condition: &str,
    ) -> Result<String>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MixDeliveryRetryOutcome {
    /// The exact lease was no longer owned when finalization began.
    LeaseLost,
    /// The row was retained with the normal retry backoff (or a newer wake
    /// advanced a non-terminal retry to now).
    Retried,
    /// A newer route wake defeated the terminal boundary and released the
    /// existing attempt count for one immediate fresh claim.
    RouteWokenAtAttemptLimit,
    /// The unchanged route epoch reached the normal terminal attempt limit.
    DeadLettered,
}

pub(crate) fn valid_stable_participant_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1023
        && !value.contains('@')
        && !value.contains('/')
        && !value.contains('#')
}
pub(crate) fn mix_timestamp_item_id() -> String {
    Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)
}
pub(crate) fn valid_join_nodes(nodes: &[String]) -> Result<Vec<String>> {
    let mut unique = std::collections::BTreeSet::new();
    anyhow::ensure!(
        nodes.len() <= SUBSCRIBABLE_NODES.len(),
        "too many MIX subscriptions"
    );
    for node in nodes {
        anyhow::ensure!(
            SUBSCRIBABLE_NODES.contains(&node.as_str()),
            "unknown MIX subscription node"
        );
        unique.insert(node.clone());
    }
    Ok(unique.into_iter().collect())
}
pub(crate) fn prepare_mix_nick(nick: &str) -> Result<String> {
    crate::jid::prepare_resourcepart(nick)
}
pub(crate) fn canonical_mix_access_pattern(pattern: &str) -> Result<String> {
    crate::jid::CanonicalJid::parse_bare(pattern).map(|jid| jid.to_string())
}
pub(crate) fn participant_jid_visible(
    channel: &MixChannel,
    preference: &MixParticipantPreference,
) -> bool {
    match channel.jid_visibility.as_str() {
        "visible" => true,
        "hidden" => false,
        "maybe" => preference.jid_visibility == "always",
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::postgres::PgPoolOptions;

    #[test]
    fn outbox_background_budget_scales_with_the_configured_primary_pool() {
        // A one-connection configuration has no spare foreground slot, so it
        // retains a single durable worker. At two connections, the listener
        // stress profile gets one background worker and one foreground slot.
        assert_eq!(
            crate::services::durable_outbox::DurableOutboxDatabaseAdmission::capacity_for_primary_pool(1),
            1
        );
        assert_eq!(
            crate::services::durable_outbox::DurableOutboxDatabaseAdmission::capacity_for_primary_pool(2),
            1
        );
        assert_eq!(
            crate::services::durable_outbox::DurableOutboxDatabaseAdmission::capacity_for_primary_pool(3),
            2
        );
        assert_eq!(
            crate::services::durable_outbox::DurableOutboxDatabaseAdmission::capacity_for_primary_pool(17),
            16
        );
        assert_eq!(
            crate::services::durable_outbox::DurableOutboxDatabaseAdmission::capacity_for_primary_pool(32),
            16
        );
        assert_eq!(
            crate::services::durable_outbox::DurableOutboxDatabaseAdmission::capacity_for_primary_pool(u32::MAX),
            16
        );
    }

    #[tokio::test]
    async fn delivery_wake_retains_commits_and_listener_gap_transitions() {
        let broker = MixDeliveryWakeBroker::new("northstar_wake_test".to_owned())
            .expect("test schema is valid");
        let mut receiver = broker.subscribe();
        let initial = broker.generation();

        // Publish before the worker installs its `changed()` future. A
        // retained watch value must resolve immediately instead of losing the
        // edge as `Notify::notify_one()` could.
        broker.publish_local_commit();
        assert_eq!(broker.generation(), initial.wrapping_add(1));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), receiver.changed(),)
                .await
                .expect("retained local delivery wake must not wait")
        );

        // A listener reconnect is deliberately a wake even when no payload
        // was observed: a notification can have committed during the gap.
        broker.publish_listener_transition();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), receiver.changed(),)
                .await
                .expect("listener-gap transition must wake a durable probe")
        );

        let before_foreign = broker.generation();
        assert!(!broker.accept_committed_notification("other_schema"));
        assert_eq!(broker.generation(), before_foreign);
        assert!(broker.accept_committed_notification("northstar_wake_test"));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), receiver.changed(),)
                .await
                .expect("schema-matched PostgreSQL wake must be retained")
        );
    }

    #[test]
    fn delivery_wake_generation_is_monotonic_under_concurrent_publishers() {
        let broker = MixDeliveryWakeBroker::new("northstar_wake_test".to_owned())
            .expect("test schema is valid");
        let publishers = 128_u64;
        std::thread::scope(|scope| {
            for _ in 0..publishers {
                let broker = Arc::clone(&broker);
                scope.spawn(move || broker.publish_local_commit());
            }
        });
        assert_eq!(broker.generation(), publishers);
    }

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
    async fn outbox_db_admission_gate_is_clone_shared_and_fifo() {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgresql://localhost/northstar_outbox_gate_unit_test")
            .expect("a lazy test pool does not connect");
        // A two-connection primary pool leaves one foreground connection and
        // therefore gives this outbox gate exactly one FIFO permit.
        let service = MixService::new(
            crate::db::mix_repository::PostgresMixRepository::new(pool),
            crate::abuse::test_mix_message_content_keyring(),
            crate::abuse::test_mix_retraction_content_keyring(),
            2,
            "public".to_owned(),
        )
        .expect("test MIX service schema is valid");
        assert_eq!(service.outbox_background_budget(), 1);
        assert_eq!(service.outbox_db_admission.available_permits(), 1);
        let first = service.clone();
        let second = service.clone();
        assert!(service
            .outbox_db_admission
            .shares_with(&first.outbox_db_admission));

        let held = service.outbox_db_admission_guard().await;
        let (ready_tx, mut ready_rx) = tokio::sync::mpsc::unbounded_channel();
        let (order_tx, mut order_rx) = tokio::sync::mpsc::unbounded_channel();
        let first_ready = ready_tx.clone();
        let first_order = order_tx.clone();
        let first_waiter = tokio::spawn(async move {
            first_ready.send(()).expect("test receiver remains open");
            let _guard = first.outbox_db_admission_guard().await;
            first_order.send(1_u8).expect("test receiver remains open");
        });
        ready_rx.recv().await.expect("first waiter started");
        tokio::task::yield_now().await;

        let second_waiter = tokio::spawn(async move {
            ready_tx.send(()).expect("test receiver remains open");
            let _guard = second.outbox_db_admission_guard().await;
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
    async fn outbox_db_admission_permits_match_the_service_budget() {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgresql://localhost/northstar_outbox_gate_budget_unit_test")
            .expect("a lazy test pool does not connect");
        let service = MixService::new(
            crate::db::mix_repository::PostgresMixRepository::new(pool),
            crate::abuse::test_mix_message_content_keyring(),
            crate::abuse::test_mix_retraction_content_keyring(),
            3,
            "public".to_owned(),
        )
        .expect("test MIX service schema is valid");
        assert_eq!(service.outbox_background_budget(), 2);
        assert_eq!(service.outbox_db_admission.available_permits(), 2);
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

    fn channel() -> MixChannel {
        MixChannel {
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
        let participant = MixParticipant {
            participant_id: Uuid::new_v4(),
            jid: "</jid><evil xmlns='urn:evil'>jid</evil><jid>".to_owned(),
            nick: Some("</nick><evil xmlns='urn:evil'>nick</evil><nick>".to_owned()),
        };
        let payload = render_participant_payload(
            &channel,
            &participant,
            &MixParticipantPreference::default(),
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
}
