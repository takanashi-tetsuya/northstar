use super::actor_host::{Event, Trace};
use anyhow::Result;
use northstar_federation_core::S2sOutboxPolicy;
use northstar_room_application::mix_service::*;
use northstar_time::{DateTime, Utc};
use std::sync::{Arc, Mutex};
use uuid::Uuid;
mod hosted_disco;

mod administration;
mod pam_delivery_repository;

#[derive(Clone)]
pub(super) struct MixStore {
    trace: Trace,
    pub(super) superseded: Arc<Mutex<bool>>,
}

impl MixStore {
    pub(super) fn new(trace: Trace) -> Self {
        Self {
            trace,
            superseded: Arc::new(Mutex::new(false)),
        }
    }
}

impl MixMamReadRepository for MixStore {
    async fn read_mix_mam(&self, _command: MixMamReadCommand) -> Result<MixMamReadOutcome> {
        panic!("unexpected repository call: read_mix_mam")
    }

    async fn admit_federated_mix_mam(
        &self,
        _command: MixMamReadCommand,
        _target_domain: &str,
        _policy: S2sOutboxPolicy,
        _render: impl FnOnce(MixMamReadOutcome) -> Result<Vec<String>> + Send,
    ) -> Result<MixMamAdmissionOutcome> {
        panic!("unexpected repository call: admit_federated_mix_mam")
    }
}

impl MixRepository for MixStore {
    #[allow(clippy::too_many_arguments)]
    async fn link_local_muc_mirror(
        &self,
        _mix_domain: &str,
        _localpart: &str,
        _actor_bare_jid: &str,
        _local_domain: &str,
    ) -> Result<MixMucLinkOutcome> {
        panic!("unexpected port call: link_local_muc_mirror")
    }

    #[allow(clippy::too_many_arguments)]
    async fn create_mix_channel(
        &self,
        _service_domain: &str,
        _requested_localpart: Option<&str>,
        _creator_jid: &str,
        _max_channels_per_owner: i64,
        _federated: Option<&FederatedMixMutation>,
    ) -> Result<(CreateChannelOutcome, String)> {
        panic!("unexpected port call: create_mix_channel")
    }

    #[allow(clippy::too_many_arguments)]
    async fn mix_channel(
        &self,
        _service_domain: &str,
        _localpart: &str,
    ) -> Result<Option<MixChannel>> {
        panic!("unexpected port call: mix_channel")
    }

    #[allow(clippy::too_many_arguments)]
    async fn discoverable_mix_channel_page(
        &self,
        _service_domain: &str,
        _requester: &str,
        _after: Option<&str>,
        _before: Option<Option<&str>>,
        _max: i64,
    ) -> Result<Option<MixDiscoPage>> {
        panic!("unexpected port call: discoverable_mix_channel_page")
    }

    #[allow(clippy::too_many_arguments)]
    async fn mix_role(&self, _channel_id: Uuid, _jid: &str) -> Result<Option<String>> {
        panic!("unexpected port call: mix_role")
    }

    #[allow(clippy::too_many_arguments)]
    async fn mix_channel_discoverable_to(
        &self,
        _channel: &MixChannel,
        _actor: &str,
    ) -> Result<bool> {
        panic!("unexpected port call: mix_channel_discoverable_to")
    }

    #[allow(clippy::too_many_arguments)]
    async fn destroy_mix_channel(
        &self,
        _channel_id: Uuid,
        _actor: &str,
        _federated: Option<&FederatedMixMutation>,
    ) -> Result<bool> {
        panic!("unexpected port call: destroy_mix_channel")
    }

    #[allow(clippy::too_many_arguments)]
    async fn join_mix_channel(
        &self,
        _channel_id: Uuid,
        _request: JoinMixRequest,
        _federated: Option<&FederatedMixMutation>,
    ) -> Result<JoinChannelOutcome> {
        panic!("unexpected port call: join_mix_channel")
    }

    #[allow(clippy::too_many_arguments)]
    async fn mix_participant(
        &self,
        _channel_id: Uuid,
        _jid: &str,
    ) -> Result<Option<MixParticipant>> {
        panic!("unexpected port call: mix_participant")
    }

    #[allow(clippy::too_many_arguments)]
    async fn expire_unrefreshed_mix_presence(
        &self,
        _cutoff: DateTime<Utc>,
    ) -> Result<Vec<ExpiredMixPresence>> {
        panic!("unexpected port call: expire_unrefreshed_mix_presence")
    }

    #[allow(clippy::too_many_arguments)]
    async fn update_mix_subscriptions(
        &self,
        _channel_id: Uuid,
        _actor: &str,
        _subscribe: &[String],
        _unsubscribe: &[String],
        _federated: Option<&FederatedMixMutation>,
    ) -> Result<Option<UpdateSubscriptionsOutcome>> {
        panic!("unexpected port call: update_mix_subscriptions")
    }

    #[allow(clippy::too_many_arguments)]
    async fn set_mix_nick(
        &self,
        _channel_id: Uuid,
        _actor: &str,
        _nick: &str,
        _federated: Option<&FederatedMixMutation>,
    ) -> Result<std::result::Result<MixParticipant, SetNickError>> {
        panic!("unexpected port call: set_mix_nick")
    }

    #[allow(clippy::too_many_arguments)]
    async fn leave_mix_channel(
        &self,
        _channel_id: Uuid,
        _actor: &str,
        _pam_user_id: Option<Uuid>,
        _federated: Option<&FederatedMixMutation>,
    ) -> Result<Option<LeaveMixOutcome>> {
        panic!("unexpected port call: leave_mix_channel")
    }

    #[allow(clippy::too_many_arguments)]
    async fn store_mix_presence(
        &self,
        _channel_id: Uuid,
        _actor_bare: &str,
        _actor_full: &str,
        _payload: &str,
        _unavailable: bool,
    ) -> Result<PresenceOutcome> {
        panic!("unexpected port call: store_mix_presence")
    }

    #[allow(clippy::too_many_arguments)]
    async fn ensure_mix_presence(
        &self,
        _channel_id: Uuid,
        _actor_bare: &str,
        _actor_full: &str,
        _payload: &str,
    ) -> Result<PresenceOutcome> {
        panic!("unexpected port call: ensure_mix_presence")
    }

    #[allow(clippy::too_many_arguments)]
    async fn store_mix_message(
        &self,
        _request: StoreMixMessageRequest<'_>,
        _authenticators: Option<&northstar_abuse_policy::ContentIdentityAuthenticators>,
    ) -> Result<StoreMixMessageAdmission> {
        panic!("unexpected port call: store_mix_message")
    }

    #[allow(clippy::too_many_arguments)]
    async fn store_mix_message_observed(
        &self,
        _request: &foreground::StoreRequest,
        _authenticators: Option<&northstar_abuse_policy::ContentIdentityAuthenticators>,
    ) -> Result<StoreMixMessageAdmission> {
        panic!("unexpected port call: store_mix_message_observed")
    }

    #[allow(clippy::too_many_arguments)]
    async fn lookup_mix_message_replay_observed(
        &self,
        _request: &foreground::ReplayRequest,
        _authenticators: &northstar_abuse_policy::ContentIdentityAuthenticators,
    ) -> Result<MixBusinessReplay> {
        panic!("unexpected port call: lookup_mix_message_replay_observed")
    }

    #[allow(clippy::too_many_arguments)]
    async fn lookup_mix_message_replay(
        &self,
        _channel_id: Uuid,
        _actor: &str,
        _identity: &MixReplayIdentity,
        _authenticators: &northstar_abuse_policy::ContentIdentityAuthenticators,
    ) -> Result<MixBusinessReplay> {
        panic!("unexpected port call: lookup_mix_message_replay")
    }

    #[allow(clippy::too_many_arguments)]
    async fn lookup_mix_retraction_replay(
        &self,
        _channel_id: Uuid,
        _actor: &str,
        _target_id: Uuid,
        _identity: &MixReplayIdentity,
        _authenticators: &northstar_abuse_policy::ContentIdentityAuthenticators,
    ) -> Result<MixBusinessReplay> {
        panic!("unexpected port call: lookup_mix_retraction_replay")
    }

    #[allow(clippy::too_many_arguments)]
    async fn authorized_mix_event_page(
        &self,
        _channel_id: Uuid,
        _actor: &str,
        _node: &str,
        _before: Option<(DateTime<Utc>, Uuid)>,
        _limit: i64,
    ) -> Result<MixReadOutcome<MixEventPage>> {
        panic!("unexpected port call: authorized_mix_event_page")
    }

    #[allow(clippy::too_many_arguments)]
    async fn publish_mix_avatar(
        &self,
        _channel_id: Uuid,
        _actor: &str,
        _node: &str,
        _item_id: &str,
        _payload: &str,
        _federated: Option<&FederatedMixMutation>,
    ) -> Result<bool> {
        panic!("unexpected port call: publish_mix_avatar")
    }

    #[allow(clippy::too_many_arguments)]
    async fn retract_mix_avatar(
        &self,
        _channel_id: Uuid,
        _actor: &str,
        _node: &str,
        _item_id: &str,
        _federated: Option<&FederatedMixMutation>,
    ) -> Result<bool> {
        panic!("unexpected port call: retract_mix_avatar")
    }

    #[allow(clippy::too_many_arguments)]
    async fn authorized_mix_access_entries(
        &self,
        _channel_id: Uuid,
        _actor: &str,
        _banned: bool,
        _limit: i64,
    ) -> Result<MixReadOutcome<Vec<String>>> {
        panic!("unexpected port call: authorized_mix_access_entries")
    }

    #[allow(clippy::too_many_arguments)]
    async fn update_mix_info(
        &self,
        _channel_id: Uuid,
        _actor: &str,
        _update: MixInfoUpdate,
        _federated: Option<&FederatedMixMutation>,
    ) -> Result<MixMutationOutcome> {
        panic!("unexpected port call: update_mix_info")
    }

    #[allow(clippy::too_many_arguments)]
    async fn update_mix_config(
        &self,
        _channel_id: Uuid,
        _actor: &str,
        _update: MixConfigUpdate,
        _roles: MixRoleUpdate,
        _federated: Option<&FederatedMixMutation>,
    ) -> Result<MixMutationOutcome> {
        panic!("unexpected port call: update_mix_config")
    }

    #[allow(clippy::too_many_arguments)]
    async fn set_mix_access_entry(
        &self,
        _update: MixAccessEntryUpdate<'_>,
        _federated: Option<&FederatedMixMutation>,
    ) -> Result<Option<AccessChangeOutcome>> {
        panic!("unexpected port call: set_mix_access_entry")
    }

    #[allow(clippy::too_many_arguments)]
    async fn register_mix_nick(
        &self,
        _service_domain: &str,
        _actor: &str,
        _nick: &str,
        _federated: Option<&FederatedMixMutation>,
    ) -> Result<RegisterMixNickOutcome> {
        panic!("unexpected port call: register_mix_nick")
    }

    #[allow(clippy::too_many_arguments)]
    async fn mix_participant_preference(
        &self,
        _channel_id: Uuid,
        _actor: &str,
    ) -> Result<Option<MixParticipantPreference>> {
        panic!("unexpected port call: mix_participant_preference")
    }

    #[allow(clippy::too_many_arguments)]
    async fn update_mix_participant_preference(
        &self,
        _channel_id: Uuid,
        _actor: &str,
        _preference: &MixParticipantPreference,
        _federated: Option<&FederatedMixMutation>,
    ) -> Result<Option<MixParticipantPreferenceUpdateOutcome>> {
        panic!("unexpected port call: update_mix_participant_preference")
    }

    #[allow(clippy::too_many_arguments)]
    async fn authorized_mix_jid_map_entries(
        &self,
        _channel_id: Uuid,
        _actor: &str,
        _limit: i64,
    ) -> Result<MixReadOutcome<Vec<(String, String)>>> {
        panic!("unexpected port call: authorized_mix_jid_map_entries")
    }

    #[allow(clippy::too_many_arguments)]
    async fn issue_mix_invitation(
        &self,
        _channel_id: Uuid,
        _inviter: &str,
        _invitee: &str,
        _token: &str,
        _lifetime: northstar_time::Duration,
        _federated: Option<&FederatedMixMutation>,
    ) -> Result<bool> {
        panic!("unexpected port call: issue_mix_invitation")
    }

    #[allow(clippy::too_many_arguments)]
    async fn mix_private_message_recipient(
        &self,
        _channel_id: Uuid,
        _sender: &str,
        _recipient_id: Uuid,
    ) -> Result<Option<(MixParticipant, MixParticipant)>> {
        panic!("unexpected port call: mix_private_message_recipient")
    }

    #[allow(clippy::too_many_arguments)]
    async fn retract_mix_message(
        &self,
        _request: RetractMixMessageRequest<'_>,
        _authenticators: Option<&northstar_abuse_policy::ContentIdentityAuthenticators>,
    ) -> Result<RetractMixMessageAdmission> {
        panic!("unexpected port call: retract_mix_message")
    }

    #[allow(clippy::too_many_arguments)]
    async fn find_enabled_user(&self, _username: &str) -> Result<Option<MixAccount>> {
        panic!("unexpected port call: find_enabled_user")
    }

    #[allow(clippy::too_many_arguments)]
    async fn find_enabled_user_by_id(&self, _user_id: Uuid) -> Result<Option<MixAccount>> {
        panic!("unexpected port call: find_enabled_user_by_id")
    }

    #[allow(clippy::too_many_arguments)]
    async fn is_blocked(&self, _owner_id: Uuid, _candidate: &str) -> Result<bool> {
        panic!("unexpected port call: is_blocked")
    }

    async fn relay_profile_snapshot(
        &self,
        _query: MixRelayProfileQuery,
    ) -> Result<MixRelayProfileResult> {
        panic!("unexpected port call: relay_profile_snapshot");
    }

    #[allow(clippy::too_many_arguments)]
    async fn latest_roster_change_for_contact(
        &self,
        _user_id: Uuid,
        _contact_jid: &str,
    ) -> Result<Option<northstar_roster_core::RosterChange>> {
        panic!("unexpected port call: latest_roster_change_for_contact")
    }

    #[allow(clippy::too_many_arguments)]
    async fn mix_muc_mirror_for_mix(&self, _mix_channel_id: Uuid) -> Result<Option<MixMucMirror>> {
        panic!("unexpected port call: mix_muc_mirror_for_mix")
    }

    #[allow(clippy::too_many_arguments)]
    async fn mix_muc_mirror_for_muc(&self, _muc_room_id: Uuid) -> Result<Option<MixMucMirror>> {
        panic!("unexpected port call: mix_muc_mirror_for_muc")
    }

    #[allow(clippy::too_many_arguments)]
    async fn mix_muc_mirror_service_complete(&self, _mix_domain: &str) -> Result<bool> {
        panic!("unexpected port call: mix_muc_mirror_service_complete")
    }

    #[allow(clippy::too_many_arguments)]
    async fn enqueue_s2s_response_batch(
        &self,
        _target_domain: &str,
        _responses: &[String],
        _policy: S2sOutboxPolicy,
    ) -> Result<()> {
        panic!("unexpected port call: enqueue_s2s_response_batch")
    }

    #[allow(clippy::too_many_arguments)]
    async fn federated_mix_iq_replay(
        &self,
        _authenticated_domain: &str,
        _actor_jid: &str,
        _request_id: &str,
        _request_digest: &[u8; 32],
    ) -> Result<FederatedMixIqReplay> {
        panic!("unexpected port call: federated_mix_iq_replay")
    }

    #[allow(clippy::too_many_arguments)]
    async fn admit_federated_mix_iq_result(
        &self,
        _authenticated_domain: &str,
        _actor_jid: &str,
        _request_id: &str,
        _request_digest: &[u8; 32],
        _response: &str,
        _policy: S2sOutboxPolicy,
    ) -> Result<FederatedMixIqReplay> {
        panic!("unexpected port call: admit_federated_mix_iq_result")
    }

    #[allow(clippy::too_many_arguments)]
    async fn prune_expired_business_intents(&self, _limit: i64) -> Result<u64> {
        panic!("unexpected port call: prune_expired_business_intents")
    }

    #[allow(clippy::too_many_arguments)]
    async fn prune_expired_federated_iq_results(&self, _limit: i64) -> Result<u64> {
        panic!("unexpected port call: prune_expired_federated_iq_results")
    }
}

impl MixPamRepository for MixStore {
    #[allow(clippy::too_many_arguments)]
    async fn begin_remote_pam_join(
        &self,
        _request: BeginRemotePamJoin,
    ) -> Result<PamOperationReplay> {
        panic!("unexpected port call: begin_remote_pam_join")
    }

    #[allow(clippy::too_many_arguments)]
    async fn lookup_remote_pam_operation(
        &self,
        _user_id: Uuid,
        _requester_full_jid: &str,
        _client_request_id: &str,
        _request_digest: &[u8; 32],
    ) -> Result<PamOperationReplay> {
        panic!("unexpected port call: lookup_remote_pam_operation")
    }

    #[allow(clippy::too_many_arguments)]
    async fn begin_remote_pam_leave(
        &self,
        _request: BeginRemotePamLeave,
    ) -> Result<PamOperationReplay> {
        panic!("unexpected port call: begin_remote_pam_leave")
    }

    #[allow(clippy::too_many_arguments)]
    async fn complete_remote_pam_success(
        &self,
        _authenticated_domain: &str,
        _channel_jid: &str,
        _recipient_bare: &str,
        _request_id: &str,
        _response_digest: &[u8; 32],
        _join: Option<RemotePamJoin<'_>>,
    ) -> Result<RemotePamCompletionOutcome> {
        panic!("unexpected port call: complete_remote_pam_success")
    }

    #[allow(clippy::too_many_arguments)]
    async fn complete_remote_pam_error(
        &self,
        _authenticated_domain: &str,
        _channel_jid: &str,
        _recipient_bare: &str,
        _request_id: &str,
        _response_digest: &[u8; 32],
        _error_type: &str,
        _condition: &str,
    ) -> Result<RemotePamCompletionOutcome> {
        panic!("unexpected port call: complete_remote_pam_error")
    }

    #[allow(clippy::too_many_arguments)]
    async fn pam_memberships(&self, _user_id: Uuid) -> Result<Vec<PamMembership>> {
        panic!("unexpected port call: pam_memberships")
    }

    #[allow(clippy::too_many_arguments)]
    async fn pam_membership(
        &self,
        _user_id: Uuid,
        _channel_jid: &str,
    ) -> Result<Option<PamMembership>> {
        panic!("unexpected port call: pam_membership")
    }

    #[allow(clippy::too_many_arguments)]
    async fn local_pam_users_for_channel(&self, _channel_jid: &str) -> Result<Vec<Uuid>> {
        panic!("unexpected port call: local_pam_users_for_channel")
    }

    #[allow(clippy::too_many_arguments)]
    async fn reconcile_expired_remote_pam(&self, _limit: i64) -> Result<u64> {
        panic!("unexpected port call: reconcile_expired_remote_pam")
    }

    #[allow(clippy::too_many_arguments)]
    async fn claim_pam_results(&self, _limit: i64) -> Result<Vec<ClaimedPamResult>> {
        panic!("unexpected port call: claim_pam_results")
    }

    #[allow(clippy::too_many_arguments)]
    async fn renew_pam_result_lease(
        &self,
        _operation_id: Uuid,
        _lease_token: Uuid,
    ) -> Result<bool> {
        panic!("unexpected port call: renew_pam_result_lease")
    }

    #[allow(clippy::too_many_arguments)]
    async fn acknowledge_pam_result(
        &self,
        _operation_id: Uuid,
        _lease_token: Uuid,
    ) -> Result<bool> {
        panic!("unexpected port call: acknowledge_pam_result")
    }

    #[allow(clippy::too_many_arguments)]
    async fn defer_pam_result(
        &self,
        _operation_id: Uuid,
        _lease_token: Uuid,
        _delay_seconds: i64,
    ) -> Result<bool> {
        panic!("unexpected port call: defer_pam_result")
    }

    #[allow(clippy::too_many_arguments)]
    async fn retry_pam_result(
        &self,
        _operation_id: Uuid,
        _lease_token: Uuid,
        _attempt_count: i32,
        _error: &str,
    ) -> Result<bool> {
        panic!("unexpected port call: retry_pam_result")
    }

    #[allow(clippy::too_many_arguments)]
    async fn prune_expired_pam_results(&self, _limit: i64) -> Result<u64> {
        panic!("unexpected port call: prune_expired_pam_results")
    }
}

impl MixDeliveryRepository for MixStore {
    async fn archive_verified_mix_reflection(
        &self,
        _request: VerifiedMixReflection<'_>,
    ) -> Result<ReflectedMixArchiveOutcome> {
        panic!("unexpected port call: archive_verified_mix_reflection")
    }

    #[allow(clippy::too_many_arguments)]
    async fn archive_mix_message_once(
        &self,
        _personal_archive_id: Uuid,
        _owner_id: Uuid,
        _channel_jid: &str,
        _authoritative_stanza_id: Uuid,
        _stanza: &str,
        _encrypted: bool,
        _client_stanza_id: Option<&str>,
    ) -> Result<SourceArchiveAdmission> {
        panic!("unexpected port call: archive_mix_message_once")
    }

    #[allow(clippy::too_many_arguments)]
    async fn claim_mix_deliveries(
        &self,
        _limit: i64,
        _max_bytes: i64,
    ) -> Result<Vec<ClaimedMixDelivery>> {
        panic!("unexpected port call: claim_mix_deliveries")
    }

    #[allow(clippy::too_many_arguments)]
    async fn claim_mix_deliveries_observed(
        &self,
        _request: &outbox::core::ClaimRequest,
    ) -> Result<outbox::core::Rows> {
        panic!("unexpected port call: claim_mix_deliveries_observed")
    }

    #[allow(clippy::too_many_arguments)]
    async fn archive_mix_message_once_observed(
        &self,
        _request: &outbox::core::ArchiveRequest,
    ) -> Result<outbox::core::ArchiveResult> {
        panic!("unexpected port call: archive_mix_message_once_observed")
    }

    #[allow(clippy::too_many_arguments)]
    async fn renew_mix_delivery_lease_observed(
        &self,
        _request: &outbox::core::RenewalRequest,
    ) -> Result<bool> {
        panic!("unexpected port call: renew_mix_delivery_lease_observed")
    }

    #[allow(clippy::too_many_arguments)]
    async fn settle_mix_delivery_observed(
        &self,
        _request: &outbox::core::SettlementRequest,
    ) -> Result<outbox::core::SettlementResult> {
        panic!("unexpected port call: settle_mix_delivery_observed")
    }

    #[allow(clippy::too_many_arguments)]
    async fn maintain_mix_delivery_retention(&self) -> Result<()> {
        panic!("unexpected port call: maintain_mix_delivery_retention")
    }

    #[allow(clippy::too_many_arguments)]
    async fn acknowledge_mix_delivery(
        &self,
        _delivery_id: Uuid,
        _lease_token: Uuid,
        _observation: Option<&northstar_delivery_core::native_write::AckRequest>,
    ) -> Result<bool> {
        panic!("unexpected port call: acknowledge_mix_delivery")
    }

    #[allow(clippy::too_many_arguments)]
    async fn fence_mix_socket_write(
        &self,
        _source: northstar_delivery_core::MixDelivery,
    ) -> Result<northstar_delivery_core::MixDelivery> {
        panic!("unexpected port call: fence_mix_socket_write")
    }

    #[allow(clippy::too_many_arguments)]
    async fn transfer_mix_delivery_to_cluster(
        &self,
        _source: northstar_delivery_core::MixDelivery,
        _node_id: &str,
        _request_id: Uuid,
        _ttl_seconds: u64,
    ) -> Result<northstar_delivery_core::MixDelivery> {
        panic!("unexpected port call: transfer_mix_delivery_to_cluster")
    }

    #[allow(clippy::too_many_arguments)]
    async fn release_mix_cluster_delivery(
        &self,
        _source: northstar_delivery_core::MixDelivery,
        _node_id: &str,
        _request_id: Uuid,
    ) -> Result<bool> {
        panic!("unexpected port call: release_mix_cluster_delivery")
    }

    #[allow(clippy::too_many_arguments)]
    async fn transfer_mix_delivery_to_bosh(
        &self,
        request: &northstar_delivery_core::bosh_ownership::TransferRequest,
    ) -> Result<northstar_delivery_core::MixDelivery> {
        self.trace.push(Event::Transfer {
            source: request.source(),
            session_id: request.session_id(),
            ttl_seconds: request.ttl_seconds(),
        });
        request.validate_for_io()?;
        if *self.superseded.lock().unwrap() {
            return Err(northstar_delivery_core::DurableDeliverySuperseded {
                message_id: super::actor_host::SUPERSEDED_MESSAGE,
            }
            .into());
        }
        let current = northstar_delivery_core::MixDelivery {
            lease_token: Uuid::from_u128(9003),
            ..request.source()
        };
        request.enter_commit(current)?.received();
        Ok(current)
    }

    #[allow(clippy::too_many_arguments)]
    async fn renew_mix_delivery_lease(
        &self,
        _delivery_id: Uuid,
        _lease_token: Uuid,
    ) -> Result<bool> {
        panic!("unexpected port call: renew_mix_delivery_lease")
    }

    #[allow(clippy::too_many_arguments)]
    async fn dead_letter_mix_delivery(
        &self,
        _delivery_id: Uuid,
        _lease_token: Uuid,
        _terminal_reason: &str,
        _error: &str,
    ) -> Result<bool> {
        panic!("unexpected port call: dead_letter_mix_delivery")
    }

    #[allow(clippy::too_many_arguments)]
    async fn retry_mix_delivery(
        &self,
        _delivery_id: Uuid,
        _lease_token: Uuid,
        _claimed_attempt_count: i32,
        _route_wake_generation: i64,
        _error: &str,
    ) -> Result<MixDeliveryRetryOutcome> {
        panic!("unexpected port call: retry_mix_delivery")
    }

    #[allow(clippy::too_many_arguments)]
    async fn defer_mix_delivery(
        &self,
        _delivery_id: Uuid,
        _lease_token: Uuid,
        _route_wake_generation: i64,
        _delay_seconds: i64,
    ) -> Result<bool> {
        panic!("unexpected port call: defer_mix_delivery")
    }

    #[allow(clippy::too_many_arguments)]
    async fn wake_mix_delivery_recipient(&self, _recipient_jid: &str) -> Result<u64> {
        panic!("unexpected port call: wake_mix_delivery_recipient")
    }

    #[allow(clippy::too_many_arguments)]
    async fn mix_delivery_dead_letters(
        &self,
        _before: Option<(DateTime<Utc>, Uuid)>,
        _limit: i64,
    ) -> Result<Vec<MixDeliveryDeadLetter>> {
        panic!("unexpected port call: mix_delivery_dead_letters")
    }

    #[allow(clippy::too_many_arguments)]
    async fn requeue_mix_delivery_dead_letter(&self, _dead_letter_id: Uuid) -> Result<bool> {
        panic!("unexpected port call: requeue_mix_delivery_dead_letter")
    }
}

mod pam_projection_repository;
#[cfg(test)]
mod presence_recovery;
