//! Defines the MIX repository port, shared models, operation boundary data, and preference defaults.

use super::*;

/// A MIX channel's authoritative configuration as observed by the protocol
/// layer. Field names deliberately mirror the repository row so the mapping in
/// this service is a pure, reviewable translation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MixChannel {
    pub id: Uuid,
    pub revision: i64,
    pub service_domain: String,
    pub localpart: String,
    pub creator_jid: String,
    pub name: Option<String>,
    pub description: Option<String>,
    pub contacts: Vec<String>,
    pub access_model: String,
    pub jid_visibility: String,
    pub nick_required: bool,
    pub max_participants: i32,
    pub max_events: i32,
    pub allow_private_messages: bool,
    pub allow_participant_invites: bool,
    pub allow_user_message_retraction: bool,
    pub administrator_retraction_rights: String,
    pub enforce_registered_nick: bool,
}

impl MixChannel {
    pub fn jid(&self) -> String {
        format!("{}@{}", self.localpart, self.service_domain)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MixParticipantPreference {
    pub jid_visibility: String,
    pub private_messages: String,
    pub vcard: String,
    pub share_presence: bool,
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

/// Retained returned-only compatibility DTO; observed workers own core attempts.
#[derive(Clone, Debug)]
pub struct ClaimedMixDelivery {
    pub delivery_id: Uuid,
    pub event_id: Uuid,
    pub channel_id: Uuid,
    pub channel_jid: String,
    pub recipient: MixParticipant,
    pub stanza: String,
    pub authoritative_stanza_id: Option<Uuid>,
    pub archive: bool,
    pub encrypted: bool,
    pub attempt_count: i32,
    pub lease_token: Uuid,
    pub route_wake_generation: i64,
}

#[derive(Clone, Debug)]
pub struct ClaimedPamResult {
    pub operation_id: Uuid,
    pub user_id: Uuid,
    pub requester_full_jid: String,
    pub response_xml: String,
    pub attempt_count: i32,
    pub lease_token: Uuid,
}

#[allow(dead_code)] // MIX admin HTTP wiring is intentionally left to the root integration pass.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MixDeliveryDeadLetter {
    pub dead_letter_id: Uuid,
    pub delivery_id: Uuid,
    pub event_id: Uuid,
    pub channel_id: Uuid,
    pub channel_jid: String,
    pub recipient_jid: String,
    pub attempt_count: i32,
    pub terminal_reason: String,
    pub last_error: Option<String>,
    pub failed_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpiredMixPresence {
    pub channel_id: Uuid,
    pub participant: MixParticipant,
    pub item_id: String,
    pub payload: String,
    pub source_full_jid: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PamMembership {
    pub id: Uuid,
    pub user_id: Uuid,
    pub channel_jid: String,
    pub participant_id: Option<String>,
    pub state: String,
    pub request_id: Option<String>,
    pub client_request_id: Option<String>,
    pub requester_full_jid: Option<String>,
    pub subscriptions: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MixInvitationProof {
    pub inviter_jid: String,
    pub invitee_jid: String,
    pub channel_jid: String,
    pub token: String,
}

/// Owned MIX join request. The repository keeps its borrowed view; this copy
/// is what the protocol layer constructs from parsed XML.
#[derive(Clone, Debug)]
pub struct JoinMixRequest {
    pub actor_jid: String,
    pub nick: Option<String>,
    pub nodes: Vec<String>,
    /// Set only for a local MIX-PAM operation. The membership is committed in
    /// the same transaction as the local channel participant.
    pub pam_user_id: Option<Uuid>,
    /// A XEP-0407 invitation is consumed atomically with an allow-list join.
    pub invitation: Option<MixInvitationProof>,
    /// XEP-0404 preferences supplied with the join. Missing preferences use
    /// the specification defaults and are committed with membership.
    pub preference: Option<MixParticipantPreference>,
    /// Selects the anonymous-profile namespace on the direct Core result.
    pub anonymous_profile: bool,
}

/// Owned MIX-PAM federation request.  Keeping every parsed value owned at the
/// application boundary prevents an outstanding asynchronous request from
/// retaining protocol-buffer borrows and gives the service one place to bind
/// the account UUID to the authenticated canonical actor.
#[derive(Clone, Debug)]
pub struct BeginRemotePamJoin {
    pub user_id: Uuid,
    pub actor_jid: String,
    pub channel_jid: String,
    pub nick: Option<String>,
    pub nodes: Vec<String>,
    pub request_id: String,
    pub client_request_id: String,
    pub requester_full_jid: String,
    pub request_digest: [u8; 32],
    pub remote_domain: String,
    pub outbound_stanza: String,
    pub policy: S2sOutboxPolicy,
}

#[derive(Clone, Debug)]
pub struct BeginRemotePamLeave {
    pub user_id: Uuid,
    pub actor_jid: String,
    pub channel_jid: String,
    pub request_id: String,
    pub client_request_id: String,
    pub requester_full_jid: String,
    pub request_digest: [u8; 32],
    pub remote_domain: String,
    pub outbound_stanza: String,
    pub policy: S2sOutboxPolicy,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PamOperationReplay {
    Miss,
    Pending,
    Replay(String),
    Conflict,
}

#[derive(Clone, Debug)]
pub struct RemotePamCompletion {
    pub response_xml: String,
    pub membership: Option<PamMembership>,
    pub applied: bool,
    pub roster_removed: Option<bool>,
}

#[derive(Clone, Debug)]
pub enum RemotePamCompletionOutcome {
    Applied(RemotePamCompletion),
    Replay(RemotePamCompletion),
    Conflict,
    Missing,
}

#[derive(Clone, Copy, Debug)]
pub struct RemotePamJoin<'a> {
    pub participant_id: &'a str,
    pub subscriptions: &'a [String],
    pub nick: Option<&'a str>,
}

/// Idempotent personal archive projection for a reflected MIX message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceArchiveAdmission {
    Stored(Uuid),
    Replay(Uuid),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CreateChannelOutcome {
    Created(Uuid),
    Conflict,
    QuotaExceeded,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JoinChannelOutcome {
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MixMutationAdmission {
    pub channel: MixChannel,
    pub node: String,
    pub item_id: String,
    pub payload: String,
    pub recipients: Vec<MixParticipant>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeaveMixOutcome {
    pub participant: MixParticipant,
    pub presence_items: Vec<MixPresenceItem>,
    pub roster_change: Option<northstar_roster_core::RosterChange>,
}

#[derive(Clone, Debug)]
pub enum PresenceOutcome {
    Published,
    Retracted,
    Unchanged,
    NotSharing,
    NotParticipant,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdateSubscriptionsOutcome {
    pub subscriptions: Vec<String>,
    pub participant: MixParticipant,
    pub removed_presence: Vec<MixPresenceItem>,
}

#[derive(Clone, Debug)]
pub struct MixParticipantPreferenceUpdateOutcome {
    pub participant: MixParticipant,
    pub roster_changes: Vec<(Uuid, northstar_roster_core::RosterChange)>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AccessChangeOutcome {
    pub removed_participants: Vec<Uuid>,
    pub removed_local_users: Vec<Uuid>,
    /// Current presence items removed as a consequence of a ban.  The
    /// protocol layer uses these to publish the mandatory unavailable
    /// transition instead of leaving subscribers with a ghost resource.
    pub removed_presence: Vec<(MixParticipant, Vec<MixPresenceItem>)>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetNickError {
    NotParticipant,
    Conflict,
}

#[derive(Clone, Debug)]
pub enum RegisterMixNickOutcome {
    Registered { nick: String },
    Conflict,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetractMixMessageOutcome {
    Retracted,
    Replay(Uuid),
    Conflict,
    NotFound,
    Forbidden,
}

pub struct StoreMixMessageRequest<'a> {
    pub channel_id: Uuid,
    pub actor: &'a str,
    pub item_id: &'a str,
    pub payload: &'a str,
    pub identity: Option<MixReplayIdentity>,
    pub delivery_payload: &'a str,
    pub visible_jid: Option<&'a str>,
    pub encrypted: bool,
}

pub struct RetractMixMessageRequest<'a> {
    pub channel_id: Uuid,
    pub actor: &'a str,
    pub target_id: Uuid,
    pub retraction_id: Uuid,
    pub tombstone_payload: &'a str,
    pub retraction_payload: &'a str,
    pub identity: Option<MixReplayIdentity>,
    pub visible_jid: Option<&'a str>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetractMixMessageAdmission {
    pub outcome: RetractMixMessageOutcome,
    pub recipients: Vec<MixParticipant>,
}

/// Owned channel information update built from a parsed XEP-0060 publish.
#[derive(Clone, Debug)]
pub struct MixInfoUpdate {
    pub item_id: String,
    pub expected_revision: i64,
    pub name: Option<String>,
    pub description: Option<String>,
    pub contacts: Vec<String>,
}

/// Owned channel configuration update built from a parsed XEP-0060 publish.
#[derive(Clone, Debug)]
pub struct MixConfigUpdate {
    pub item_id: String,
    pub expected_revision: i64,
    pub access_model: String,
    pub jid_visibility: String,
    pub nick_required: bool,
    pub max_participants: i32,
    pub max_events: i32,
    pub allow_private_messages: bool,
    pub allow_participant_invites: bool,
    pub allow_user_message_retraction: bool,
    pub administrator_retraction_rights: String,
    pub enforce_registered_nick: bool,
}

/// Owned administrator role replacement; `None` preserves the current list.
#[derive(Clone, Debug)]
pub struct MixRoleUpdate {
    pub owners: Option<Vec<String>>,
    pub administrators: Option<Vec<String>>,
}

#[derive(Clone, Debug)]
pub enum MixMutationOutcome {
    Applied(Box<MixMutationAdmission>),
    Conflict,
    Forbidden,
    NotFound,
}

/// Authenticated identity and exact replay key for one remote mutating IQ.
/// Production protocol code must attach this context to the repository
/// mutation so state, result journal and S2S outbox share one transaction.
#[derive(Clone, Debug)]
pub struct FederatedMixMutation {
    pub authenticated_domain: String,
    pub actor_jid: String,
    pub request_id: String,
    pub request_digest: [u8; 32],
    pub addressed: String,
    pub reply_to: String,
    pub policy: S2sOutboxPolicy,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FederatedMixIqReplay {
    Miss,
    Replay(String),
    Conflict,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MixMucLinkOutcome {
    Linked,
    AlreadyLinked,
    MissingCounterpart,
    NotCommonOwner,
    Conflict,
}

/// Minimum enabled local identity needed by MIX/PEP/vCard relays.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MixAccount {
    pub id: Uuid,
    pub username: String,
}

/// Business target for one MIX access-list mutation.
///
/// This deliberately lives at the application-service boundary: protocol
/// handlers select an XEP-0406 operation, while the repository retains the
/// persistence representation and transaction semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MixAccessList {
    Allowed,
    Banned,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MixAccessEntryOperation<'a> {
    Publish { reason: Option<&'a str> },
    Retract,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MixAccessEntryUpdate<'a> {
    pub channel_id: Uuid,
    pub actor: &'a str,
    pub pattern: &'a str,
    pub list: MixAccessList,
    pub operation: MixAccessEntryOperation<'a>,
}

pub trait MixRepository: Send + Sync {
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
        authenticators: Option<&northstar_abuse_policy::ContentIdentityAuthenticators>,
    ) -> impl std::future::Future<Output = Result<StoreMixMessageAdmission>> + Send;
    fn store_mix_message_observed(
        &self,
        request: &foreground::StoreRequest,
        authenticators: Option<&northstar_abuse_policy::ContentIdentityAuthenticators>,
    ) -> impl std::future::Future<Output = Result<StoreMixMessageAdmission>> + Send;
    fn lookup_mix_message_replay_observed(
        &self,
        request: &foreground::ReplayRequest,
        authenticators: &northstar_abuse_policy::ContentIdentityAuthenticators,
    ) -> impl std::future::Future<Output = Result<MixBusinessReplay>> + Send;
    fn lookup_mix_message_replay(
        &self,
        channel_id: Uuid,
        actor: &str,
        identity: &MixReplayIdentity,
        authenticators: &northstar_abuse_policy::ContentIdentityAuthenticators,
    ) -> impl std::future::Future<Output = Result<MixBusinessReplay>> + Send;
    fn lookup_mix_retraction_replay(
        &self,
        channel_id: Uuid,
        actor: &str,
        target_id: Uuid,
        identity: &MixReplayIdentity,
        authenticators: &northstar_abuse_policy::ContentIdentityAuthenticators,
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
        authenticators: Option<&northstar_abuse_policy::ContentIdentityAuthenticators>,
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
    fn claim_mix_deliveries_observed(
        &self,
        request: &outbox::core::ClaimRequest,
    ) -> impl std::future::Future<Output = Result<outbox::core::Rows>> + Send;
    fn archive_mix_message_once_observed(
        &self,
        request: &outbox::core::ArchiveRequest,
    ) -> impl std::future::Future<Output = Result<outbox::core::ArchiveResult>> + Send;
    fn renew_mix_delivery_lease_observed(
        &self,
        request: &outbox::core::RenewalRequest,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn settle_mix_delivery_observed(
        &self,
        request: &outbox::core::SettlementRequest,
    ) -> impl std::future::Future<Output = Result<outbox::core::SettlementResult>> + Send;
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
        observation: Option<&northstar_delivery_core::native_write::AckRequest>,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn fence_mix_socket_write(
        &self,
        source: northstar_delivery_core::MixDelivery,
    ) -> impl std::future::Future<Output = Result<northstar_delivery_core::MixDelivery>> + Send;
    fn transfer_mix_delivery_to_cluster(
        &self,
        source: northstar_delivery_core::MixDelivery,
        node_id: &str,
        request_id: Uuid,
        ttl_seconds: u64,
    ) -> impl std::future::Future<Output = Result<northstar_delivery_core::MixDelivery>> + Send;
    fn release_mix_cluster_delivery(
        &self,
        source: northstar_delivery_core::MixDelivery,
        node_id: &str,
        request_id: Uuid,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn transfer_mix_delivery_to_bosh(
        &self,
        request: &northstar_delivery_core::bosh_ownership::TransferRequest,
    ) -> impl std::future::Future<Output = Result<northstar_delivery_core::MixDelivery>> + Send;
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
