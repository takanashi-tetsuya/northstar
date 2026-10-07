//! One-use supplied repository replies. Every unneeded trait method rejects.
//! No SQL, timers, network, spawned tasks or self-produced transport completions.
use super::*;
use crate::services::mix::foreground;
use crate::services::mix::*;
use chrono::{DateTime, Utc};
use northstar_room_application::mix as foreground_core;
use northstar_room_core::mix as room;
use std::sync::Mutex;

#[derive(Clone)]
pub(crate) struct ControlledRepository(pub(super) Arc<Mutex<Supplied>>, pub(super) Recorder);
#[derive(Default)]
pub(super) struct Supplied {
    pub(super) claim: Option<(Arc<mix_worker::Row>, wire::CommitCut, ClaimCapture)>,
    pub(super) last_claim_observation: Option<mix_worker::ClaimObservation>,
    pub(super) archive: Option<wire::ArchiveInput>,
    pub(super) account: Option<Uuid>,
    pub(super) privacy: Option<bool>,
    pub(super) settlement: Option<(wire::CommitCut, bool)>,
    pub(super) native: Option<wire::DurableNative>,
    pub(super) native_ack: Option<(wire::CommitCut, crate::outbound::MixDelivery)>,
    pub(super) transfer: Option<wire::BoshTransferReply>,
    pub(super) fresh: Option<(room::Stored, wire::CommitCut)>,
    pub(super) replay: Option<Option<room::Existing>>,
    pub(super) worker: Option<WorkerCapture>,
    pub(super) foreground: Option<ForegroundCapture>,
}
impl ControlledRepository {
    fn unused(&self, name: &str) -> anyhow::Error {
        anyhow::anyhow!("Stage4 repository method has no supplied reply: {name}")
    }
}
#[allow(unused_variables)]
impl MixRepository for ControlledRepository {
    fn link_local_muc_mirror(
        &self,
        mix_domain: &str,
        localpart: &str,
        actor_bare_jid: &str,
        local_domain: &str,
    ) -> impl std::future::Future<Output = Result<MixMucLinkOutcome>> + Send {
        std::future::ready(Err(self.unused("link_local_muc_mirror")))
    }
    fn create_mix_channel(
        &self,
        service_domain: &str,
        requested_localpart: Option<&str>,
        creator_jid: &str,
        max_channels_per_owner: i64,
        federated: Option<&FederatedMixMutation>,
    ) -> impl std::future::Future<Output = Result<(CreateChannelOutcome, String)>> + Send {
        std::future::ready(Err(self.unused("create_mix_channel")))
    }
    fn mix_channel(
        &self,
        service_domain: &str,
        localpart: &str,
    ) -> impl std::future::Future<Output = Result<Option<MixChannel>>> + Send {
        std::future::ready(Err(self.unused("mix_channel")))
    }
    fn discoverable_mix_channel_page(
        &self,
        service_domain: &str,
        requester: &str,
        after: Option<&str>,
        before: Option<Option<&str>>,
        max: i64,
    ) -> impl std::future::Future<Output = Result<Option<MixDiscoPage>>> + Send {
        std::future::ready(Err(self.unused("discoverable_mix_channel_page")))
    }
    fn mix_role(
        &self,
        channel_id: Uuid,
        jid: &str,
    ) -> impl std::future::Future<Output = Result<Option<String>>> + Send {
        std::future::ready(Err(self.unused("mix_role")))
    }
    fn mix_channel_discoverable_to(
        &self,
        channel: &MixChannel,
        actor: &str,
    ) -> impl std::future::Future<Output = Result<bool>> + Send {
        std::future::ready(Err(self.unused("mix_channel_discoverable_to")))
    }
    fn destroy_mix_channel(
        &self,
        channel_id: Uuid,
        actor: &str,
        federated: Option<&FederatedMixMutation>,
    ) -> impl std::future::Future<Output = Result<bool>> + Send {
        std::future::ready(Err(self.unused("destroy_mix_channel")))
    }
    fn join_mix_channel(
        &self,
        channel_id: Uuid,
        request: JoinMixRequest,
        federated: Option<&FederatedMixMutation>,
    ) -> impl std::future::Future<Output = Result<JoinChannelOutcome>> + Send {
        std::future::ready(Err(self.unused("join_mix_channel")))
    }
    fn mix_participant(
        &self,
        channel_id: Uuid,
        jid: &str,
    ) -> impl std::future::Future<Output = Result<Option<MixParticipant>>> + Send {
        std::future::ready(Err(self.unused("mix_participant")))
    }
    fn mix_participant_by_id(
        &self,
        channel_id: Uuid,
        participant_id: Uuid,
    ) -> impl std::future::Future<Output = Result<Option<MixParticipant>>> + Send {
        std::future::ready(Err(self.unused("mix_participant_by_id")))
    }
    fn mix_presence_source_jid(
        &self,
        channel_id: Uuid,
        item_id: &str,
    ) -> impl std::future::Future<Output = Result<Option<String>>> + Send {
        std::future::ready(Err(self.unused("mix_presence_source_jid")))
    }
    fn expire_unrefreshed_mix_presence(
        &self,
        cutoff: DateTime<Utc>,
    ) -> impl std::future::Future<Output = Result<Vec<ExpiredMixPresence>>> + Send {
        std::future::ready(Err(self.unused("expire_unrefreshed_mix_presence")))
    }
    fn update_mix_subscriptions(
        &self,
        channel_id: Uuid,
        actor: &str,
        subscribe: &[String],
        unsubscribe: &[String],
        federated: Option<&FederatedMixMutation>,
    ) -> impl std::future::Future<Output = Result<Option<UpdateSubscriptionsOutcome>>> + Send {
        std::future::ready(Err(self.unused("update_mix_subscriptions")))
    }
    fn set_mix_nick(
        &self,
        channel_id: Uuid,
        actor: &str,
        nick: &str,
        federated: Option<&FederatedMixMutation>,
    ) -> impl std::future::Future<Output = Result<std::result::Result<MixParticipant, SetNickError>>>
           + Send {
        std::future::ready(Err(self.unused("set_mix_nick")))
    }
    fn leave_mix_channel(
        &self,
        channel_id: Uuid,
        actor: &str,
        pam_user_id: Option<Uuid>,
        federated: Option<&FederatedMixMutation>,
    ) -> impl std::future::Future<Output = Result<Option<LeaveMixOutcome>>> + Send {
        std::future::ready(Err(self.unused("leave_mix_channel")))
    }
    fn store_mix_presence(
        &self,
        channel_id: Uuid,
        actor_bare: &str,
        actor_full: &str,
        payload: &str,
        unavailable: bool,
    ) -> impl std::future::Future<Output = Result<PresenceOutcome>> + Send {
        std::future::ready(Err(self.unused("store_mix_presence")))
    }
    fn ensure_mix_presence(
        &self,
        channel_id: Uuid,
        actor_bare: &str,
        actor_full: &str,
        payload: &str,
    ) -> impl std::future::Future<Output = Result<PresenceOutcome>> + Send {
        std::future::ready(Err(self.unused("ensure_mix_presence")))
    }
    fn store_mix_message(
        &self,
        request: StoreMixMessageRequest<'_>,
        authenticators: Option<&crate::abuse::ContentIdentityAuthenticators>,
    ) -> impl std::future::Future<Output = Result<StoreMixMessageAdmission>> + Send {
        std::future::ready(Err(self.unused("store_mix_message")))
    }
    fn lookup_mix_message_replay(
        &self,
        channel_id: Uuid,
        actor: &str,
        identity: &MixReplayIdentity,
        authenticators: &crate::abuse::ContentIdentityAuthenticators,
    ) -> impl std::future::Future<Output = Result<MixBusinessReplay>> + Send {
        std::future::ready(Err(self.unused("lookup_mix_message_replay")))
    }
    fn lookup_mix_retraction_replay(
        &self,
        channel_id: Uuid,
        actor: &str,
        target_id: Uuid,
        identity: &MixReplayIdentity,
        authenticators: &crate::abuse::ContentIdentityAuthenticators,
    ) -> impl std::future::Future<Output = Result<MixBusinessReplay>> + Send {
        std::future::ready(Err(self.unused("lookup_mix_retraction_replay")))
    }
    fn authorized_mix_event_page(
        &self,
        channel_id: Uuid,
        actor: &str,
        node: &str,
        before: Option<(DateTime<Utc>, Uuid)>,
        limit: i64,
    ) -> impl std::future::Future<Output = Result<MixReadOutcome<MixEventPage>>> + Send {
        std::future::ready(Err(self.unused("authorized_mix_event_page")))
    }
    fn publish_mix_avatar(
        &self,
        channel_id: Uuid,
        actor: &str,
        node: &str,
        item_id: &str,
        payload: &str,
        federated: Option<&FederatedMixMutation>,
    ) -> impl std::future::Future<Output = Result<bool>> + Send {
        std::future::ready(Err(self.unused("publish_mix_avatar")))
    }
    fn retract_mix_avatar(
        &self,
        channel_id: Uuid,
        actor: &str,
        node: &str,
        item_id: &str,
        federated: Option<&FederatedMixMutation>,
    ) -> impl std::future::Future<Output = Result<bool>> + Send {
        std::future::ready(Err(self.unused("retract_mix_avatar")))
    }
    fn authorized_mix_mam_page(
        &self,
        channel_id: Uuid,
        actor: &str,
        viewer_id: Option<Uuid>,
        query: &MamArchiveQuery,
    ) -> impl std::future::Future<Output = Result<MixReadOutcome<MixMamPage>>> + Send {
        std::future::ready(Err(self.unused("authorized_mix_mam_page")))
    }
    fn authorized_mix_mam_boundaries(
        &self,
        channel_id: Uuid,
        actor: &str,
        viewer_id: Option<Uuid>,
    ) -> impl std::future::Future<
        Output = Result<MixReadOutcome<(Option<ArchiveBoundary>, Option<ArchiveBoundary>)>>,
    > + Send {
        std::future::ready(Err(self.unused("authorized_mix_mam_boundaries")))
    }
    fn authorized_mix_access_entries(
        &self,
        channel_id: Uuid,
        actor: &str,
        banned: bool,
        limit: i64,
    ) -> impl std::future::Future<Output = Result<MixReadOutcome<Vec<String>>>> + Send {
        std::future::ready(Err(self.unused("authorized_mix_access_entries")))
    }
    fn update_mix_info(
        &self,
        channel_id: Uuid,
        actor: &str,
        update: MixInfoUpdate,
        federated: Option<&FederatedMixMutation>,
    ) -> impl std::future::Future<Output = Result<MixMutationOutcome>> + Send {
        std::future::ready(Err(self.unused("update_mix_info")))
    }
    fn update_mix_config(
        &self,
        channel_id: Uuid,
        actor: &str,
        update: MixConfigUpdate,
        roles: MixRoleUpdate,
        federated: Option<&FederatedMixMutation>,
    ) -> impl std::future::Future<Output = Result<MixMutationOutcome>> + Send {
        std::future::ready(Err(self.unused("update_mix_config")))
    }
    fn set_mix_access_entry(
        &self,
        update: MixAccessEntryUpdate<'_>,
        federated: Option<&FederatedMixMutation>,
    ) -> impl std::future::Future<Output = Result<Option<AccessChangeOutcome>>> + Send {
        std::future::ready(Err(self.unused("set_mix_access_entry")))
    }
    fn register_mix_nick(
        &self,
        service_domain: &str,
        actor: &str,
        nick: &str,
        federated: Option<&FederatedMixMutation>,
    ) -> impl std::future::Future<Output = Result<RegisterMixNickOutcome>> + Send {
        std::future::ready(Err(self.unused("register_mix_nick")))
    }
    fn mix_participant_preference(
        &self,
        channel_id: Uuid,
        actor: &str,
    ) -> impl std::future::Future<Output = Result<Option<MixParticipantPreference>>> + Send {
        std::future::ready(Err(self.unused("mix_participant_preference")))
    }
    fn update_mix_participant_preference(
        &self,
        channel_id: Uuid,
        actor: &str,
        preference: &MixParticipantPreference,
        federated: Option<&FederatedMixMutation>,
    ) -> impl std::future::Future<Output = Result<Option<MixParticipantPreferenceUpdateOutcome>>> + Send
    {
        std::future::ready(Err(self.unused("update_mix_participant_preference")))
    }
    fn authorized_mix_jid_map_entries(
        &self,
        channel_id: Uuid,
        actor: &str,
        limit: i64,
    ) -> impl std::future::Future<Output = Result<MixReadOutcome<Vec<(String, String)>>>> + Send
    {
        std::future::ready(Err(self.unused("authorized_mix_jid_map_entries")))
    }
    fn issue_mix_invitation(
        &self,
        channel_id: Uuid,
        inviter: &str,
        invitee: &str,
        token: &str,
        lifetime: chrono::Duration,
        federated: Option<&FederatedMixMutation>,
    ) -> impl std::future::Future<Output = Result<bool>> + Send {
        std::future::ready(Err(self.unused("issue_mix_invitation")))
    }
    fn mix_private_message_recipient(
        &self,
        channel_id: Uuid,
        sender: &str,
        recipient_id: Uuid,
    ) -> impl std::future::Future<Output = Result<Option<(MixParticipant, MixParticipant)>>> + Send
    {
        std::future::ready(Err(self.unused("mix_private_message_recipient")))
    }
    fn retract_mix_message(
        &self,
        request: RetractMixMessageRequest<'_>,
        authenticators: Option<&crate::abuse::ContentIdentityAuthenticators>,
    ) -> impl std::future::Future<Output = Result<RetractMixMessageAdmission>> + Send {
        std::future::ready(Err(self.unused("retract_mix_message")))
    }
    fn begin_remote_pam_join(
        &self,
        request: BeginRemotePamJoin,
    ) -> impl std::future::Future<Output = Result<PamOperationReplay>> + Send {
        std::future::ready(Err(self.unused("begin_remote_pam_join")))
    }
    fn lookup_remote_pam_operation(
        &self,
        user_id: Uuid,
        requester_full_jid: &str,
        client_request_id: &str,
        request_digest: &[u8; 32],
    ) -> impl std::future::Future<Output = Result<PamOperationReplay>> + Send {
        std::future::ready(Err(self.unused("lookup_remote_pam_operation")))
    }
    fn begin_remote_pam_leave(
        &self,
        request: BeginRemotePamLeave,
    ) -> impl std::future::Future<Output = Result<PamOperationReplay>> + Send {
        std::future::ready(Err(self.unused("begin_remote_pam_leave")))
    }
    fn complete_remote_pam_success(
        &self,
        authenticated_domain: &str,
        channel_jid: &str,
        recipient_bare: &str,
        request_id: &str,
        response_digest: &[u8; 32],
        join: Option<RemotePamJoin<'_>>,
    ) -> impl std::future::Future<Output = Result<RemotePamCompletionOutcome>> + Send {
        std::future::ready(Err(self.unused("complete_remote_pam_success")))
    }
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
    ) -> impl std::future::Future<Output = Result<RemotePamCompletionOutcome>> + Send {
        std::future::ready(Err(self.unused("complete_remote_pam_error")))
    }
    fn pam_memberships(
        &self,
        user_id: Uuid,
    ) -> impl std::future::Future<Output = Result<Vec<PamMembership>>> + Send {
        std::future::ready(Err(self.unused("pam_memberships")))
    }
    fn pam_membership(
        &self,
        user_id: Uuid,
        channel_jid: &str,
    ) -> impl std::future::Future<Output = Result<Option<PamMembership>>> + Send {
        std::future::ready(Err(self.unused("pam_membership")))
    }
    fn local_pam_users_for_channel(
        &self,
        channel_jid: &str,
    ) -> impl std::future::Future<Output = Result<Vec<Uuid>>> + Send {
        std::future::ready(Err(self.unused("local_pam_users_for_channel")))
    }
    fn reconcile_expired_remote_pam(
        &self,
        limit: i64,
    ) -> impl std::future::Future<Output = Result<u64>> + Send {
        std::future::ready(Err(self.unused("reconcile_expired_remote_pam")))
    }
    fn claim_pam_results(
        &self,
        limit: i64,
    ) -> impl std::future::Future<Output = Result<Vec<ClaimedPamResult>>> + Send {
        std::future::ready(Err(self.unused("claim_pam_results")))
    }
    fn renew_pam_result_lease(
        &self,
        operation_id: Uuid,
        lease_token: Uuid,
    ) -> impl std::future::Future<Output = Result<bool>> + Send {
        std::future::ready(Err(self.unused("renew_pam_result_lease")))
    }
    fn acknowledge_pam_result(
        &self,
        operation_id: Uuid,
        lease_token: Uuid,
    ) -> impl std::future::Future<Output = Result<bool>> + Send {
        std::future::ready(Err(self.unused("acknowledge_pam_result")))
    }
    fn defer_pam_result(
        &self,
        operation_id: Uuid,
        lease_token: Uuid,
        delay_seconds: i64,
    ) -> impl std::future::Future<Output = Result<bool>> + Send {
        std::future::ready(Err(self.unused("defer_pam_result")))
    }
    fn retry_pam_result(
        &self,
        operation_id: Uuid,
        lease_token: Uuid,
        attempt_count: i32,
        error: &str,
    ) -> impl std::future::Future<Output = Result<bool>> + Send {
        std::future::ready(Err(self.unused("retry_pam_result")))
    }
    fn prune_expired_pam_results(
        &self,
        limit: i64,
    ) -> impl std::future::Future<Output = Result<u64>> + Send {
        std::future::ready(Err(self.unused("prune_expired_pam_results")))
    }
    fn find_enabled_user_by_id(
        &self,
        user_id: Uuid,
    ) -> impl std::future::Future<Output = Result<Option<MixAccount>>> + Send {
        std::future::ready(Err(self.unused("find_enabled_user_by_id")))
    }
    fn pep_node(
        &self,
        owner_id: Uuid,
        node: &str,
    ) -> impl std::future::Future<Output = Result<Option<PepNodeConfig>>> + Send {
        std::future::ready(Err(self.unused("pep_node")))
    }
    fn pep_items(
        &self,
        owner_id: Uuid,
        node: &str,
        item_id: Option<&str>,
        limit: i64,
    ) -> impl std::future::Future<Output = Result<Vec<(String, String)>>> + Send {
        std::future::ready(Err(self.unused("pep_items")))
    }
    fn get_vcard(
        &self,
        user_id: Uuid,
    ) -> impl std::future::Future<Output = Result<VCardRecord>> + Send {
        std::future::ready(Err(self.unused("get_vcard")))
    }
    fn latest_roster_change_for_contact(
        &self,
        user_id: Uuid,
        contact_jid: &str,
    ) -> impl std::future::Future<Output = Result<Option<northstar_roster_core::RosterChange>>> + Send
    {
        std::future::ready(Err(self.unused("latest_roster_change_for_contact")))
    }
    fn mix_muc_mirror_for_mix(
        &self,
        mix_channel_id: Uuid,
    ) -> impl std::future::Future<Output = Result<Option<MixMucMirror>>> + Send {
        std::future::ready(Err(self.unused("mix_muc_mirror_for_mix")))
    }
    fn mix_muc_mirror_for_muc(
        &self,
        muc_room_id: Uuid,
    ) -> impl std::future::Future<Output = Result<Option<MixMucMirror>>> + Send {
        std::future::ready(Err(self.unused("mix_muc_mirror_for_muc")))
    }
    fn mix_muc_mirror_service_complete(
        &self,
        mix_domain: &str,
    ) -> impl std::future::Future<Output = Result<bool>> + Send {
        std::future::ready(Err(self.unused("mix_muc_mirror_service_complete")))
    }
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
    ) -> impl std::future::Future<Output = Result<SourceArchiveAdmission>> + Send {
        std::future::ready(Err(self.unused("archive_mix_message_once")))
    }
    fn enqueue_s2s_response_batch(
        &self,
        target_domain: &str,
        responses: &[String],
        policy: S2sOutboxPolicy,
    ) -> impl std::future::Future<Output = Result<()>> + Send {
        std::future::ready(Err(self.unused("enqueue_s2s_response_batch")))
    }
    fn federated_mix_iq_replay(
        &self,
        authenticated_domain: &str,
        actor_jid: &str,
        request_id: &str,
        request_digest: &[u8; 32],
    ) -> impl std::future::Future<Output = Result<FederatedMixIqReplay>> + Send {
        std::future::ready(Err(self.unused("federated_mix_iq_replay")))
    }
    fn admit_federated_mix_iq_result(
        &self,
        authenticated_domain: &str,
        actor_jid: &str,
        request_id: &str,
        request_digest: &[u8; 32],
        response: &str,
        policy: S2sOutboxPolicy,
    ) -> impl std::future::Future<Output = Result<FederatedMixIqReplay>> + Send {
        std::future::ready(Err(self.unused("admit_federated_mix_iq_result")))
    }
    fn claim_mix_deliveries(
        &self,
        limit: i64,
        max_bytes: i64,
    ) -> impl std::future::Future<Output = Result<Vec<ClaimedMixDelivery>>> + Send {
        std::future::ready(Err(self.unused("claim_mix_deliveries")))
    }
    fn maintain_mix_delivery_retention(
        &self,
    ) -> impl std::future::Future<Output = Result<()>> + Send {
        std::future::ready(Err(self.unused("maintain_mix_delivery_retention")))
    }
    fn prune_expired_business_intents(
        &self,
        limit: i64,
    ) -> impl std::future::Future<Output = Result<u64>> + Send {
        std::future::ready(Err(self.unused("prune_expired_business_intents")))
    }
    fn prune_expired_federated_iq_results(
        &self,
        limit: i64,
    ) -> impl std::future::Future<Output = Result<u64>> + Send {
        std::future::ready(Err(self.unused("prune_expired_federated_iq_results")))
    }
    fn transfer_mix_delivery_to_cluster(
        &self,
        source: crate::outbound::MixDelivery,
        node_id: &str,
        request_id: Uuid,
        ttl_seconds: u64,
    ) -> impl std::future::Future<Output = Result<crate::outbound::MixDelivery>> + Send {
        std::future::ready(Err(self.unused("transfer_mix_delivery_to_cluster")))
    }
    fn release_mix_cluster_delivery(
        &self,
        source: crate::outbound::MixDelivery,
        node_id: &str,
        request_id: Uuid,
    ) -> impl std::future::Future<Output = Result<bool>> + Send {
        std::future::ready(Err(self.unused("release_mix_cluster_delivery")))
    }
    fn renew_mix_delivery_lease(
        &self,
        delivery_id: Uuid,
        lease_token: Uuid,
    ) -> impl std::future::Future<Output = Result<bool>> + Send {
        std::future::ready(Err(self.unused("renew_mix_delivery_lease")))
    }
    fn dead_letter_mix_delivery(
        &self,
        delivery_id: Uuid,
        lease_token: Uuid,
        terminal_reason: &str,
        error: &str,
    ) -> impl std::future::Future<Output = Result<bool>> + Send {
        std::future::ready(Err(self.unused("dead_letter_mix_delivery")))
    }
    fn retry_mix_delivery(
        &self,
        delivery_id: Uuid,
        lease_token: Uuid,
        _claimed_attempt_count: i32,
        route_wake_generation: i64,
        error: &str,
    ) -> impl std::future::Future<Output = Result<MixDeliveryRetryOutcome>> + Send {
        std::future::ready(Err(self.unused("retry_mix_delivery")))
    }
    fn defer_mix_delivery(
        &self,
        delivery_id: Uuid,
        lease_token: Uuid,
        route_wake_generation: i64,
        delay_seconds: i64,
    ) -> impl std::future::Future<Output = Result<bool>> + Send {
        std::future::ready(Err(self.unused("defer_mix_delivery")))
    }
    fn wake_mix_delivery_recipient(
        &self,
        recipient_jid: &str,
    ) -> impl std::future::Future<Output = Result<u64>> + Send {
        std::future::ready(Err(self.unused("wake_mix_delivery_recipient")))
    }
    #[allow(dead_code)]
    fn mix_delivery_dead_letters(
        &self,
        before: Option<(DateTime<Utc>, Uuid)>,
        limit: i64,
    ) -> impl std::future::Future<Output = Result<Vec<MixDeliveryDeadLetter>>> + Send {
        std::future::ready(Err(self.unused("mix_delivery_dead_letters")))
    }
    #[allow(dead_code)]
    fn requeue_mix_delivery_dead_letter(
        &self,
        dead_letter_id: Uuid,
    ) -> impl std::future::Future<Output = Result<bool>> + Send {
        std::future::ready(Err(self.unused("requeue_mix_delivery_dead_letter")))
    }
    async fn store_mix_message_observed(
        &self,
        request: &foreground::StoreRequest,
        _authenticators: Option<&crate::abuse::ContentIdentityAuthenticators>,
    ) -> Result<StoreMixMessageAdmission> {
        let ((stored, cut), capture) = {
            let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
            (
                state
                    .fresh
                    .take()
                    .ok_or_else(|| self.unused("store_mix_message_observed"))?,
                state.foreground.clone(),
            )
        };
        let admission = room::Admission {
            outcome: room::Outcome::Stored(stored.authoritative_id),
            recipients: stored.projection.as_ref().map_or_else(Vec::new, |p| {
                p.recipients.iter().map(|r| r.participant.clone()).collect()
            }),
        };
        foreground_core::commit_observed(
            async {
                if let Some(capture) = &capture {
                    capture.snapshot(wire::Cut::PortEntry);
                } else {
                    missing(&self.1);
                }
                supplied_commit(cut).await
            },
            request,
            stored,
        )
        .await
        .map_err(|e| match e {
            foreground_core::CommitError::Observation(e) => anyhow::Error::from(e),
            foreground_core::CommitError::Commit(e) => e,
        })?;
        if let Some(capture) = &capture {
            capture.snapshot(wire::Cut::PortReturn);
        } else {
            missing(&self.1);
        }
        Ok(admission)
    }
    async fn lookup_mix_message_replay_observed(
        &self,
        request: &foreground::ReplayRequest,
        authenticators: &crate::abuse::ContentIdentityAuthenticators,
    ) -> Result<MixBusinessReplay> {
        let (raw, capture) = {
            let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
            (
                state
                    .replay
                    .take()
                    .ok_or_else(|| self.unused("lookup_mix_message_replay_observed"))?,
                state.foreground.clone(),
            )
        };
        let Some(raw) = raw else {
            request.observed_miss()?;
            if let Some(capture) = &capture {
                capture.snapshot(wire::Cut::PortReturn);
            } else {
                missing(&self.1);
            }
            return Ok(MixBusinessReplay::Miss);
        };
        request.observed_existing(raw.clone())?;
        if let Some(capture) = &capture {
            capture.snapshot(wire::Cut::PortEntry);
        } else {
            missing(&self.1);
        }
        let replay = if raw.target_id.is_none()
            && authenticators.verifies(&raw.semantic_key_id, &raw.semantic_mac)
        {
            MixBusinessReplay::Replay(raw.authoritative_id)
        } else {
            MixBusinessReplay::Conflict
        };
        request.authenticated(&raw, replay)?;
        if let Some(capture) = &capture {
            capture.snapshot(wire::Cut::PortReturn);
        } else {
            missing(&self.1);
        }
        Ok(replay)
    }
    async fn find_enabled_user(&self, username: &str) -> Result<Option<MixAccount>> {
        let id = self
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .account
            .take()
            .ok_or_else(|| self.unused("find_enabled_user"))?;
        Ok(Some(MixAccount {
            id,
            username: username.to_owned(),
        }))
    }
    async fn is_blocked(&self, _owner_id: Uuid, _candidate: &str) -> Result<bool> {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .privacy
            .take()
            .ok_or_else(|| self.unused("is_blocked"))
    }
    async fn claim_mix_deliveries_observed(
        &self,
        request: &mix_worker::ClaimRequest,
    ) -> Result<mix_worker::Rows> {
        let (row, cut, capture) = self
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .claim
            .take()
            .ok_or_else(|| self.unused("claim_mix_deliveries_observed"))?;
        let entered = request.enter_statement()?;
        capture.snapshot(wire::Cut::PortEntry);
        supplied_commit(cut).await?;
        let rows: mix_worker::Rows = vec![row].into();
        request.received(entered, rows.clone())?;
        capture.snapshot(wire::Cut::PortReturn);
        Ok(rows)
    }
    async fn archive_mix_message_once_observed(
        &self,
        request: &mix_worker::ArchiveRequest,
    ) -> Result<mix_worker::ArchiveResult> {
        let (reply, capture) = {
            let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
            (
                state
                    .archive
                    .take()
                    .ok_or_else(|| self.unused("archive_mix_message_once_observed"))?,
                state.worker.clone(),
            )
        };
        let result = match reply.reply {
            wire::ArchiveReply::StoreCandidate(_) => {
                mix_worker::ArchiveResult::Stored(request.command().personal_archive_id)
            }
            wire::ArchiveReply::Replay(r) => {
                mix_worker::ArchiveResult::Replay(r.original_archive_id.0)
            }
        };
        mix_worker::archive_commit_observed(
            async {
                if let Some(capture) = &capture {
                    capture.snapshot(wire::Cut::PortEntry);
                } else {
                    missing(&self.1);
                }
                supplied_commit(reply.commit).await
            },
            request,
            result,
        )
        .await
        .map_err(outbox::commit_error)?;
        if let Some(capture) = &capture {
            capture.snapshot(wire::Cut::PortReturn);
        } else {
            missing(&self.1);
        }
        Ok(result)
    }
    async fn renew_mix_delivery_lease_observed(
        &self,
        _request: &mix_worker::RenewalRequest,
    ) -> Result<bool> {
        // Saved scope cannot reach the unchanged ten-second first renewal in
        // its five-second envelope. An unexpected call rejects rather than
        // claiming an active renewal or inventing a successful statement.
        Err(self.unused("renew_mix_delivery_lease_observed"))
    }
    async fn settle_mix_delivery_observed(
        &self,
        request: &mix_worker::SettlementRequest,
    ) -> Result<mix_worker::SettlementResult> {
        let ((cut, updated), capture) = {
            let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
            (
                state
                    .settlement
                    .take()
                    .ok_or_else(|| self.unused("settle_mix_delivery_observed"))?,
                state.worker.clone(),
            )
        };
        ensure!(
            matches!(
                request.command(),
                mix_worker::SettlementCommand::Defer { .. }
            ),
            "only no-target Defer is supplied"
        );
        let result = mix_worker::SettlementResult::Defer(updated);
        // Production Defer is an autocommit statement, not COMMIT knowledge.
        let entered = request.enter_statement()?;
        if let Some(capture) = &capture {
            capture.snapshot(wire::Cut::PortEntry);
        } else {
            missing(&self.1);
        }
        supplied_commit(cut).await?;
        request.received(entered, result)?;
        if let Some(capture) = &capture {
            capture.snapshot(wire::Cut::PortReturn);
        } else {
            missing(&self.1);
        }
        Ok(result)
    }
    async fn fence_mix_socket_write(
        &self,
        source: crate::outbound::MixDelivery,
    ) -> Result<crate::outbound::MixDelivery> {
        let reply = self
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .native
            .take()
            .ok_or_else(|| self.unused("fence_mix_socket_write"))?;
        let returned = source_input(&reply.returned_fence);
        ensure!(
            source.delivery_id == returned.delivery_id,
            "native reply changed delivery identity"
        );
        self.0.lock().unwrap_or_else(|e| e.into_inner()).native_ack =
            Some((reply.ack_commit, returned));
        Ok(returned)
    }
    async fn acknowledge_mix_delivery(
        &self,
        delivery_id: Uuid,
        lease_token: Uuid,
        observation: Option<&northstar_delivery_core::native_write::AckRequest>,
    ) -> Result<bool> {
        use northstar_delivery_core::native_write::{self, AckDisposition};
        let (cut, source) = self
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .native_ack
            .take()
            .ok_or_else(|| self.unused("acknowledge_mix_delivery"))?;
        ensure!(
            source.delivery_id == delivery_id && source.lease_token == lease_token,
            "native ACK source mismatch"
        );
        let observation = observation.context("unobserved native ACK rejected")?;
        observation.validate_source(crate::outbound::TransportOwnershipSource::Mix(source))?;
        native_write::commit_observed(supplied_commit(cut), observation, AckDisposition::Deleted)
            .await
            .map_err(|e| match e {
                native_write::CommitError::Binding(e) => anyhow::Error::from(e),
                native_write::CommitError::Repository(e) => e,
            })?;
        Ok(true)
    }
    async fn transfer_mix_delivery_to_bosh(
        &self,
        request: &northstar_delivery_core::bosh_ownership::TransferRequest,
    ) -> Result<crate::outbound::MixDelivery> {
        use northstar_delivery_core::bosh_ownership::{self, CompletionError};
        let reply = self
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .transfer
            .take()
            .ok_or_else(|| self.unused("transfer_mix_delivery_to_bosh"))?;
        let returned = source_input(&reply.returned_source);
        bosh_ownership::transfer_commit_observed(supplied_commit(reply.commit), request, returned)
            .await
            .map_err(|e| match e {
                CompletionError::Binding(e) => anyhow::Error::from(e),
                CompletionError::Repository(e) => e,
            })?;
        Ok(returned)
    }
}
