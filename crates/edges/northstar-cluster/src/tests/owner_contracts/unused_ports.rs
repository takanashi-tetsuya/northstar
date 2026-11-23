// Unrelated ports are explicit panic stubs: an unexpected fallback fails the test.
#[derive(Clone)]
pub(super) struct UnusedPorts;

mod administration;
mod direct_invitation_stub;
mod pam_delivery_repository;

mod mix {
    use super::UnusedPorts;
    use anyhow::Result;
    use northstar_room_application::mix_service::*;
    use northstar_time::{DateTime, Utc};
    use uuid::Uuid;

    impl MixMamReadRepository for UnusedPorts {
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

    impl MixRepository for UnusedPorts {
        async fn link_local_muc_mirror(
            &self,
            _mix_domain: &str,
            _localpart: &str,
            _actor_bare_jid: &str,
            _local_domain: &str,
        ) -> Result<MixMucLinkOutcome> {
            panic!("unused MixRepository::link_local_muc_mirror port");
        }

        async fn create_mix_channel(
            &self,
            _service_domain: &str,
            _requested_localpart: Option<&str>,
            _creator_jid: &str,
            _max_channels_per_owner: i64,
            _federated: Option<&FederatedMixMutation>,
        ) -> Result<(CreateChannelOutcome, String)> {
            panic!("unused MixRepository::create_mix_channel port");
        }

        async fn mix_channel(
            &self,
            _service_domain: &str,
            _localpart: &str,
        ) -> Result<Option<MixChannel>> {
            panic!("unused MixRepository::mix_channel port");
        }

        async fn discoverable_mix_channel_page(
            &self,
            _service_domain: &str,
            _requester: &str,
            _after: Option<&str>,
            _before: Option<Option<&str>>,
            _max: i64,
        ) -> Result<Option<MixDiscoPage>> {
            panic!("unused MixRepository::discoverable_mix_channel_page port");
        }

        async fn mix_role(&self, _channel_id: Uuid, _jid: &str) -> Result<Option<String>> {
            panic!("unused MixRepository::mix_role port");
        }

        async fn mix_channel_discoverable_to(
            &self,
            _channel: &MixChannel,
            _actor: &str,
        ) -> Result<bool> {
            panic!("unused MixRepository::mix_channel_discoverable_to port");
        }

        async fn destroy_mix_channel(
            &self,
            _channel_id: Uuid,
            _actor: &str,
            _federated: Option<&FederatedMixMutation>,
        ) -> Result<bool> {
            panic!("unused MixRepository::destroy_mix_channel port");
        }

        async fn join_mix_channel(
            &self,
            _channel_id: Uuid,
            _request: JoinMixRequest,
            _federated: Option<&FederatedMixMutation>,
        ) -> Result<JoinChannelOutcome> {
            panic!("unused MixRepository::join_mix_channel port");
        }

        async fn mix_participant(
            &self,
            _channel_id: Uuid,
            _jid: &str,
        ) -> Result<Option<MixParticipant>> {
            panic!("unused MixRepository::mix_participant port");
        }

        async fn expire_unrefreshed_mix_presence(
            &self,
            _cutoff: DateTime<Utc>,
        ) -> Result<Vec<ExpiredMixPresence>> {
            panic!("unused MixRepository::expire_unrefreshed_mix_presence port");
        }

        async fn update_mix_subscriptions(
            &self,
            _channel_id: Uuid,
            _actor: &str,
            _subscribe: &[String],
            _unsubscribe: &[String],
            _federated: Option<&FederatedMixMutation>,
        ) -> Result<Option<UpdateSubscriptionsOutcome>> {
            panic!("unused MixRepository::update_mix_subscriptions port");
        }

        async fn set_mix_nick(
            &self,
            _channel_id: Uuid,
            _actor: &str,
            _nick: &str,
            _federated: Option<&FederatedMixMutation>,
        ) -> Result<std::result::Result<MixParticipant, SetNickError>> {
            panic!("unused MixRepository::set_mix_nick port");
        }

        async fn leave_mix_channel(
            &self,
            _channel_id: Uuid,
            _actor: &str,
            _pam_user_id: Option<Uuid>,
            _federated: Option<&FederatedMixMutation>,
        ) -> Result<Option<LeaveMixOutcome>> {
            panic!("unused MixRepository::leave_mix_channel port");
        }

        async fn store_mix_presence(
            &self,
            _channel_id: Uuid,
            _actor_bare: &str,
            _actor_full: &str,
            _payload: &str,
            _unavailable: bool,
        ) -> Result<PresenceOutcome> {
            panic!("unused MixRepository::store_mix_presence port");
        }

        async fn ensure_mix_presence(
            &self,
            _channel_id: Uuid,
            _actor_bare: &str,
            _actor_full: &str,
            _payload: &str,
        ) -> Result<PresenceOutcome> {
            panic!("unused MixRepository::ensure_mix_presence port");
        }

        async fn store_mix_message(
            &self,
            _request: StoreMixMessageRequest<'_>,
            _authenticators: Option<&northstar_abuse_policy::ContentIdentityAuthenticators>,
        ) -> Result<StoreMixMessageAdmission> {
            panic!("unused MixRepository::store_mix_message port");
        }

        async fn store_mix_message_observed(
            &self,
            _request: &foreground::StoreRequest,
            _authenticators: Option<&northstar_abuse_policy::ContentIdentityAuthenticators>,
        ) -> Result<StoreMixMessageAdmission> {
            panic!("unused MixRepository::store_mix_message_observed port");
        }

        async fn lookup_mix_message_replay_observed(
            &self,
            _request: &foreground::ReplayRequest,
            _authenticators: &northstar_abuse_policy::ContentIdentityAuthenticators,
        ) -> Result<MixBusinessReplay> {
            panic!("unused MixRepository::lookup_mix_message_replay_observed port");
        }

        async fn lookup_mix_message_replay(
            &self,
            _channel_id: Uuid,
            _actor: &str,
            _identity: &MixReplayIdentity,
            _authenticators: &northstar_abuse_policy::ContentIdentityAuthenticators,
        ) -> Result<MixBusinessReplay> {
            panic!("unused MixRepository::lookup_mix_message_replay port");
        }

        async fn lookup_mix_retraction_replay(
            &self,
            _channel_id: Uuid,
            _actor: &str,
            _target_id: Uuid,
            _identity: &MixReplayIdentity,
            _authenticators: &northstar_abuse_policy::ContentIdentityAuthenticators,
        ) -> Result<MixBusinessReplay> {
            panic!("unused MixRepository::lookup_mix_retraction_replay port");
        }

        async fn authorized_mix_event_page(
            &self,
            _channel_id: Uuid,
            _actor: &str,
            _node: &str,
            _before: Option<(DateTime<Utc>, Uuid)>,
            _limit: i64,
        ) -> Result<MixReadOutcome<MixEventPage>> {
            panic!("unused MixRepository::authorized_mix_event_page port");
        }

        async fn publish_mix_avatar(
            &self,
            _channel_id: Uuid,
            _actor: &str,
            _node: &str,
            _item_id: &str,
            _payload: &str,
            _federated: Option<&FederatedMixMutation>,
        ) -> Result<bool> {
            panic!("unused MixRepository::publish_mix_avatar port");
        }

        async fn retract_mix_avatar(
            &self,
            _channel_id: Uuid,
            _actor: &str,
            _node: &str,
            _item_id: &str,
            _federated: Option<&FederatedMixMutation>,
        ) -> Result<bool> {
            panic!("unused MixRepository::retract_mix_avatar port");
        }

        async fn authorized_mix_access_entries(
            &self,
            _channel_id: Uuid,
            _actor: &str,
            _banned: bool,
            _limit: i64,
        ) -> Result<MixReadOutcome<Vec<String>>> {
            panic!("unused MixRepository::authorized_mix_access_entries port");
        }

        async fn update_mix_info(
            &self,
            _channel_id: Uuid,
            _actor: &str,
            _update: MixInfoUpdate,
            _federated: Option<&FederatedMixMutation>,
        ) -> Result<MixMutationOutcome> {
            panic!("unused MixRepository::update_mix_info port");
        }

        async fn update_mix_config(
            &self,
            _channel_id: Uuid,
            _actor: &str,
            _update: MixConfigUpdate,
            _roles: MixRoleUpdate,
            _federated: Option<&FederatedMixMutation>,
        ) -> Result<MixMutationOutcome> {
            panic!("unused MixRepository::update_mix_config port");
        }

        async fn set_mix_access_entry(
            &self,
            _update: MixAccessEntryUpdate<'_>,
            _federated: Option<&FederatedMixMutation>,
        ) -> Result<Option<AccessChangeOutcome>> {
            panic!("unused MixRepository::set_mix_access_entry port");
        }

        async fn register_mix_nick(
            &self,
            _service_domain: &str,
            _actor: &str,
            _nick: &str,
            _federated: Option<&FederatedMixMutation>,
        ) -> Result<RegisterMixNickOutcome> {
            panic!("unused MixRepository::register_mix_nick port");
        }

        async fn mix_participant_preference(
            &self,
            _channel_id: Uuid,
            _actor: &str,
        ) -> Result<Option<MixParticipantPreference>> {
            panic!("unused MixRepository::mix_participant_preference port");
        }

        async fn update_mix_participant_preference(
            &self,
            _channel_id: Uuid,
            _actor: &str,
            _preference: &MixParticipantPreference,
            _federated: Option<&FederatedMixMutation>,
        ) -> Result<Option<MixParticipantPreferenceUpdateOutcome>> {
            panic!("unused MixRepository::update_mix_participant_preference port");
        }

        async fn authorized_mix_jid_map_entries(
            &self,
            _channel_id: Uuid,
            _actor: &str,
            _limit: i64,
        ) -> Result<MixReadOutcome<Vec<(String, String)>>> {
            panic!("unused MixRepository::authorized_mix_jid_map_entries port");
        }

        async fn issue_mix_invitation(
            &self,
            _channel_id: Uuid,
            _inviter: &str,
            _invitee: &str,
            _token: &str,
            _lifetime: northstar_time::Duration,
            _federated: Option<&FederatedMixMutation>,
        ) -> Result<bool> {
            panic!("unused MixRepository::issue_mix_invitation port");
        }

        async fn mix_private_message_recipient(
            &self,
            _channel_id: Uuid,
            _sender: &str,
            _recipient_id: Uuid,
        ) -> Result<Option<(MixParticipant, MixParticipant)>> {
            panic!("unused MixRepository::mix_private_message_recipient port");
        }

        async fn retract_mix_message(
            &self,
            _request: RetractMixMessageRequest<'_>,
            _authenticators: Option<&northstar_abuse_policy::ContentIdentityAuthenticators>,
        ) -> Result<RetractMixMessageAdmission> {
            panic!("unused MixRepository::retract_mix_message port");
        }

        async fn find_enabled_user(&self, _username: &str) -> Result<Option<MixAccount>> {
            panic!("unused MixRepository::find_enabled_user port");
        }

        async fn find_enabled_user_by_id(&self, _user_id: Uuid) -> Result<Option<MixAccount>> {
            panic!("unused MixRepository::find_enabled_user_by_id port");
        }

        async fn is_blocked(&self, _owner_id: Uuid, _candidate: &str) -> Result<bool> {
            panic!("unused MixRepository::is_blocked port");
        }

        async fn relay_profile_snapshot(
            &self,
            _query: MixRelayProfileQuery,
        ) -> Result<MixRelayProfileResult> {
            panic!("unused MixRepository::relay_profile_snapshot port");
        }

        async fn latest_roster_change_for_contact(
            &self,
            _user_id: Uuid,
            _contact_jid: &str,
        ) -> Result<Option<northstar_roster_core::RosterChange>> {
            panic!("unused MixRepository::latest_roster_change_for_contact port");
        }

        async fn mix_muc_mirror_for_mix(
            &self,
            _mix_channel_id: Uuid,
        ) -> Result<Option<MixMucMirror>> {
            panic!("unused MixRepository::mix_muc_mirror_for_mix port");
        }

        async fn mix_muc_mirror_for_muc(&self, _muc_room_id: Uuid) -> Result<Option<MixMucMirror>> {
            panic!("unused MixRepository::mix_muc_mirror_for_muc port");
        }

        async fn mix_muc_mirror_service_complete(&self, _mix_domain: &str) -> Result<bool> {
            panic!("unused MixRepository::mix_muc_mirror_service_complete port");
        }

        async fn enqueue_s2s_response_batch(
            &self,
            _target_domain: &str,
            _responses: &[String],
            _policy: S2sOutboxPolicy,
        ) -> Result<()> {
            panic!("unused MixRepository::enqueue_s port");
        }

        async fn federated_mix_iq_replay(
            &self,
            _authenticated_domain: &str,
            _actor_jid: &str,
            _request_id: &str,
            _request_digest: &[u8; 32],
        ) -> Result<FederatedMixIqReplay> {
            panic!("unused MixRepository::federated_mix_iq_replay port");
        }

        async fn admit_federated_mix_iq_result(
            &self,
            _authenticated_domain: &str,
            _actor_jid: &str,
            _request_id: &str,
            _request_digest: &[u8; 32],
            _response: &str,
            _policy: S2sOutboxPolicy,
        ) -> Result<FederatedMixIqReplay> {
            panic!("unused MixRepository::admit_federated_mix_iq_result port");
        }

        async fn prune_expired_business_intents(&self, _limit: i64) -> Result<u64> {
            panic!("unused MixRepository::prune_expired_business_intents port");
        }

        async fn prune_expired_federated_iq_results(&self, _limit: i64) -> Result<u64> {
            panic!("unused MixRepository::prune_expired_federated_iq_results port");
        }
    }

    impl MixPamRepository for UnusedPorts {
        async fn begin_remote_pam_join(
            &self,
            _request: BeginRemotePamJoin,
        ) -> Result<PamOperationReplay> {
            panic!("unused MixRepository::begin_remote_pam_join port");
        }

        async fn lookup_remote_pam_operation(
            &self,
            _user_id: Uuid,
            _requester_full_jid: &str,
            _client_request_id: &str,
            _request_digest: &[u8; 32],
        ) -> Result<PamOperationReplay> {
            panic!("unused MixRepository::lookup_remote_pam_operation port");
        }

        async fn begin_remote_pam_leave(
            &self,
            _request: BeginRemotePamLeave,
        ) -> Result<PamOperationReplay> {
            panic!("unused MixRepository::begin_remote_pam_leave port");
        }

        async fn complete_remote_pam_success(
            &self,
            _authenticated_domain: &str,
            _channel_jid: &str,
            _recipient_bare: &str,
            _request_id: &str,
            _response_digest: &[u8; 32],
            _join: Option<RemotePamJoin<'_>>,
        ) -> Result<RemotePamCompletionOutcome> {
            panic!("unused MixRepository::complete_remote_pam_success port");
        }

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
            panic!("unused MixRepository::complete_remote_pam_error port");
        }

        async fn pam_memberships(&self, _user_id: Uuid) -> Result<Vec<PamMembership>> {
            panic!("unused MixRepository::pam_memberships port");
        }

        async fn pam_membership(
            &self,
            _user_id: Uuid,
            _channel_jid: &str,
        ) -> Result<Option<PamMembership>> {
            panic!("unused MixRepository::pam_membership port");
        }

        async fn local_pam_users_for_channel(&self, _channel_jid: &str) -> Result<Vec<Uuid>> {
            panic!("unused MixRepository::local_pam_users_for_channel port");
        }

        async fn reconcile_expired_remote_pam(&self, _limit: i64) -> Result<u64> {
            panic!("unused MixRepository::reconcile_expired_remote_pam port");
        }

        async fn claim_pam_results(&self, _limit: i64) -> Result<Vec<ClaimedPamResult>> {
            panic!("unused MixRepository::claim_pam_results port");
        }

        async fn renew_pam_result_lease(
            &self,
            _operation_id: Uuid,
            _lease_token: Uuid,
        ) -> Result<bool> {
            panic!("unused MixRepository::renew_pam_result_lease port");
        }

        async fn acknowledge_pam_result(
            &self,
            _operation_id: Uuid,
            _lease_token: Uuid,
        ) -> Result<bool> {
            panic!("unused MixRepository::acknowledge_pam_result port");
        }

        async fn defer_pam_result(
            &self,
            _operation_id: Uuid,
            _lease_token: Uuid,
            _delay_seconds: i64,
        ) -> Result<bool> {
            panic!("unused MixRepository::defer_pam_result port");
        }

        async fn retry_pam_result(
            &self,
            _operation_id: Uuid,
            _lease_token: Uuid,
            _attempt_count: i32,
            _error: &str,
        ) -> Result<bool> {
            panic!("unused MixRepository::retry_pam_result port");
        }

        async fn prune_expired_pam_results(&self, _limit: i64) -> Result<u64> {
            panic!("unused MixRepository::prune_expired_pam_results port");
        }
    }

    impl MixDeliveryRepository for UnusedPorts {
        async fn archive_verified_mix_reflection(
            &self,
            _request: VerifiedMixReflection<'_>,
        ) -> Result<ReflectedMixArchiveOutcome> {
            panic!("unused MixDeliveryRepository::archive_verified_mix_reflection port");
        }

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
            panic!("unused MixRepository::archive_mix_message_once port");
        }

        async fn claim_mix_deliveries(
            &self,
            _limit: i64,
            _max_bytes: i64,
        ) -> Result<Vec<ClaimedMixDelivery>> {
            panic!("unused MixRepository::claim_mix_deliveries port");
        }

        async fn claim_mix_deliveries_observed(
            &self,
            _request: &outbox::core::ClaimRequest,
        ) -> Result<outbox::core::Rows> {
            panic!("unused MixRepository::claim_mix_deliveries_observed port");
        }

        async fn archive_mix_message_once_observed(
            &self,
            _request: &outbox::core::ArchiveRequest,
        ) -> Result<outbox::core::ArchiveResult> {
            panic!("unused MixRepository::archive_mix_message_once_observed port");
        }

        async fn renew_mix_delivery_lease_observed(
            &self,
            _request: &outbox::core::RenewalRequest,
        ) -> Result<bool> {
            panic!("unused MixRepository::renew_mix_delivery_lease_observed port");
        }

        async fn settle_mix_delivery_observed(
            &self,
            _request: &outbox::core::SettlementRequest,
        ) -> Result<outbox::core::SettlementResult> {
            panic!("unused MixRepository::settle_mix_delivery_observed port");
        }

        async fn maintain_mix_delivery_retention(&self) -> Result<()> {
            panic!("unused MixRepository::maintain_mix_delivery_retention port");
        }

        async fn acknowledge_mix_delivery(
            &self,
            _delivery_id: Uuid,
            _lease_token: Uuid,
            _observation: Option<&northstar_delivery_core::native_write::AckRequest>,
        ) -> Result<bool> {
            panic!("unused MixRepository::acknowledge_mix_delivery port");
        }

        async fn fence_mix_socket_write(
            &self,
            _source: northstar_delivery_core::MixDelivery,
        ) -> Result<northstar_delivery_core::MixDelivery> {
            panic!("unused MixRepository::fence_mix_socket_write port");
        }

        async fn transfer_mix_delivery_to_cluster(
            &self,
            _source: northstar_delivery_core::MixDelivery,
            _node_id: &str,
            _request_id: Uuid,
            _ttl_seconds: u64,
        ) -> Result<northstar_delivery_core::MixDelivery> {
            panic!("unused MixRepository::transfer_mix_delivery_to_cluster port");
        }

        async fn release_mix_cluster_delivery(
            &self,
            _source: northstar_delivery_core::MixDelivery,
            _node_id: &str,
            _request_id: Uuid,
        ) -> Result<bool> {
            panic!("unused MixRepository::release_mix_cluster_delivery port");
        }

        async fn transfer_mix_delivery_to_bosh(
            &self,
            _request: &northstar_delivery_core::bosh_ownership::TransferRequest,
        ) -> Result<northstar_delivery_core::MixDelivery> {
            panic!("unused MixRepository::transfer_mix_delivery_to_bosh port");
        }

        async fn renew_mix_delivery_lease(
            &self,
            _delivery_id: Uuid,
            _lease_token: Uuid,
        ) -> Result<bool> {
            panic!("unused MixRepository::renew_mix_delivery_lease port");
        }

        async fn dead_letter_mix_delivery(
            &self,
            _delivery_id: Uuid,
            _lease_token: Uuid,
            _terminal_reason: &str,
            _error: &str,
        ) -> Result<bool> {
            panic!("unused MixRepository::dead_letter_mix_delivery port");
        }

        async fn retry_mix_delivery(
            &self,
            _delivery_id: Uuid,
            _lease_token: Uuid,
            _claimed_attempt_count: i32,
            _route_wake_generation: i64,
            _error: &str,
        ) -> Result<MixDeliveryRetryOutcome> {
            panic!("unused MixRepository::retry_mix_delivery port");
        }

        async fn defer_mix_delivery(
            &self,
            _delivery_id: Uuid,
            _lease_token: Uuid,
            _route_wake_generation: i64,
            _delay_seconds: i64,
        ) -> Result<bool> {
            panic!("unused MixRepository::defer_mix_delivery port");
        }

        async fn wake_mix_delivery_recipient(&self, _recipient_jid: &str) -> Result<u64> {
            panic!("unused MixRepository::wake_mix_delivery_recipient port");
        }

        async fn mix_delivery_dead_letters(
            &self,
            _before: Option<(DateTime<Utc>, Uuid)>,
            _limit: i64,
        ) -> Result<Vec<MixDeliveryDeadLetter>> {
            panic!("unused MixRepository::mix_delivery_dead_letters port");
        }

        async fn requeue_mix_delivery_dead_letter(&self, _dead_letter_id: Uuid) -> Result<bool> {
            panic!("unused MixRepository::requeue_mix_delivery_dead_letter port");
        }
    }
}

mod presence {
    use super::UnusedPorts;
    use anyhow::Result;
    use northstar_roster_application::presence::*;
    use northstar_time::{DateTime, Utc};
    use uuid::Uuid;

    impl PresenceRepository for UnusedPorts {
        async fn roster_subscriptions(&self, _owner_id: Uuid) -> Result<Vec<(String, String)>> {
            panic!("unused PresenceRepository::roster_subscriptions port");
        }

        async fn is_blocked_for_account(
            &self,
            _owner_id: Uuid,
            _owner_bare_jid: &str,
            _candidate: &str,
        ) -> Result<bool> {
            panic!("unused PresenceRepository::is_blocked_for_account port");
        }

        async fn privacy_denies(
            &self,
            _owner_id: Uuid,
            _active_list: Option<&str>,
            _candidate: &str,
            _kind: northstar_xep_0016::PrivacyStanzaKind,
        ) -> Result<bool> {
            panic!("unused PresenceRepository::privacy_denies port");
        }

        async fn avatar_hash(&self, _user_id: Uuid) -> Result<Option<String>> {
            panic!("unused PresenceRepository::avatar_hash port");
        }

        async fn find_enabled_user(&self, _username: &str) -> Result<Option<PresenceAccount>> {
            panic!("unused PresenceRepository::find_enabled_user port");
        }

        async fn roster_subscription(
            &self,
            _owner_id: Uuid,
            _contact: &str,
        ) -> Result<Option<String>> {
            panic!("unused PresenceRepository::roster_subscription port");
        }

        async fn replay_cutoff(&self) -> Result<DateTime<Utc>> {
            panic!("unused PresenceRepository::replay_cutoff port");
        }

        async fn claim_service_messages(&self, _user_id: Uuid) -> Result<Vec<ServiceMessageClaim>> {
            panic!("unused PresenceRepository::claim_service_messages port");
        }

        async fn complete_service_message_claim(
            &self,
            _user_id: Uuid,
            _claim: &ServiceMessageClaim,
        ) -> Result<bool> {
            panic!("unused PresenceRepository::complete_service_message_claim port");
        }

        async fn transition_remote_with_outbox(
            &self,
            _actor_id: Uuid,
            _expected_auth_generation: i64,
            _connection_id: Uuid,
            _local_domain: &str,
            _contact: &str,
            _kind: &str,
            _target_domain: &str,
            _stanza: &str,
            _bounce_to: Option<&str>,
            _policy: northstar_federation_core::S2sOutboxPolicy,
        ) -> Result<PresenceMutation<RemoteSubscriptionTransition>> {
            panic!("unused PresenceRepository::transition_remote_with_outbox port");
        }

        async fn transition_remote(
            &self,
            _actor_id: Uuid,
            _expected_auth_generation: i64,
            _connection_id: Uuid,
            _local_domain: &str,
            _contact: &str,
            _kind: &str,
        ) -> Result<PresenceMutation<RemoteSubscriptionTransition>> {
            panic!("unused PresenceRepository::transition_remote port");
        }

        async fn transition_local(
            &self,
            _request: LocalSubscriptionRequest<'_>,
        ) -> Result<PresenceMutation<LocalSubscriptionTransition>> {
            panic!("unused PresenceRepository::transition_local port");
        }

        async fn transition_inbound(
            &self,
            _recipient_id: Uuid,
            _local_domain: &str,
            _contact: &str,
            _kind: &str,
            _stanza: &str,
        ) -> Result<PresenceMutation<InboundSubscriptionTransition>> {
            panic!("unused PresenceRepository::transition_inbound port");
        }

        async fn cluster_authority_is_current(
            &self,
            _local_domain: &str,
            _owner_jid: &str,
            _owner_id: Uuid,
            _owner_auth_generation: i64,
            _recipient_jid: &str,
            _recipient_id: Uuid,
            _recipient_auth_generation: i64,
        ) -> Result<bool> {
            panic!("unused PresenceRepository::cluster_authority_is_current port");
        }
    }
}

mod message {
    use super::UnusedPorts;
    use anyhow::Result;
    use northstar_message_application::messaging::*;
    use northstar_message_core::{DirectPostCommitMode, DirectSpoolEligibility, MessageCommit};
    use northstar_room_core::DurableMucInviteOutcome;
    use northstar_xep_0016::PrivacyStanzaKind;
    use uuid::Uuid;

    impl northstar_message_application::PersonalMessageCommitRepository for UnusedPorts {
        type Error = anyhow::Error;

        async fn commit<'a>(
            &'a self,
            _: &'a ValidatedPersonalMessage<'a>,
        ) -> Result<MessageCommit> {
            panic!("unused personal commit port");
        }
    }

    impl northstar_message_application::direct_commit::DirectCommitRepository for UnusedPorts {
        type Error = anyhow::Error;

        async fn commit_direct<'a>(
            &'a self,
            _: &'a ValidatedPersonalMessage<'a>,
            _: DirectSpoolEligibility,
            _: Option<&'a dyn northstar_message_application::direct_commit::DirectCommitObserver>,
        ) -> Result<DirectPersonalMessageAdmission> {
            panic!("unused direct commit port");
        }
    }

    impl MessageRepository for UnusedPorts {
        fn direct_mode(&self) -> DirectPostCommitMode {
            panic!("unused MessageRepository::direct_mode port");
        }

        fn clustered_direct_admission_enabled(&self) -> bool {
            panic!("unused MessageRepository::clustered_direct_admission_enabled port");
        }

        async fn release_live_direct_claim(
            &self,
            _recipient_id: Uuid,
            _message_id: Uuid,
            _claim_id: Uuid,
        ) -> Result<bool> {
            panic!("unused MessageRepository::release_live_direct_claim port");
        }

        async fn authorize_outbound_message(
            &self,
            _owner_id: Uuid,
            _owner_bare_jid: &str,
            _active_privacy_list: Option<&str>,
            _target: &str,
        ) -> Result<OutboundPolicyDecision> {
            panic!("unused MessageRepository::authorize_outbound_message port");
        }

        async fn resolve_local_recipient(
            &self,
            _username: &str,
            _local_domain: &str,
            _sender_jid: &str,
        ) -> Result<LocalRecipientDecision> {
            panic!("unused MessageRepository::resolve_local_recipient port");
        }

        async fn default_recipient_privacy_denies(
            &self,
            _recipient_id: Uuid,
            _sender_jid: &str,
        ) -> Result<bool> {
            panic!("unused MessageRepository::default_recipient_privacy_denies port");
        }

        async fn privacy_allows_session(
            &self,
            _user_id: Uuid,
            _connection_id: Uuid,
            _active_privacy_list: Option<&str>,
            _peer: &str,
            _kind: PrivacyStanzaKind,
        ) -> Result<bool> {
            panic!("unused MessageRepository::privacy_allows_session port");
        }

        async fn admit_remote_muc_invite(
            &self,
            _request: &RemoteMucInviteAdmission<'_>,
        ) -> Result<RemoteMucInviteAdmissionOutcome> {
            panic!("unused MessageRepository::admit_remote_muc_invite port");
        }

        async fn admit_local_muc_invite(
            &self,
            _request: &LocalMucInviteAdmission<'_>,
        ) -> Result<DurableMucInviteOutcome> {
            panic!("unused MessageRepository::admit_local_muc_invite port");
        }

        async fn admit_history(
            &self,
            _candidates: &[ArchiveCandidate<'_>],
        ) -> Result<ArchiveAdmissionOutcome> {
            panic!("unused MessageRepository::admit_history port");
        }

        async fn store_offline(
            &self,
            _admission: OfflineMessageAdmission<'_>,
        ) -> Result<OfflineAdmissionOutcome> {
            panic!("unused MessageRepository::store_offline port");
        }
    }
}

mod wake {
    use super::UnusedPorts;
    use anyhow::Result;
    use northstar_message_application::direct_spool_wake::*;
    use northstar_security::cluster_keys::ClusterReadinessAuthority;
    use std::time::Duration;
    use uuid::Uuid;

    impl DirectSpoolWakeRepository for UnusedPorts {
        async fn cleanup(&self, _limit: i32) -> Result<i64> {
            panic!("unused DirectSpoolWakeRepository::cleanup port");
        }

        async fn claim(
            &self,
            _authority: &ClusterReadinessAuthority,
            _limit: i32,
        ) -> Result<Vec<ClaimedDirectSpoolWake>> {
            panic!("unused DirectSpoolWakeRepository::claim port");
        }

        async fn routes_page(
            &self,
            _authority: &ClusterReadinessAuthority,
            _recipient_id: Uuid,
            _after: Option<&str>,
            _limit: i32,
        ) -> Result<Vec<DirectSpoolWakeRoute>> {
            panic!("unused DirectSpoolWakeRepository::routes_page port");
        }

        async fn acknowledge_if_empty(
            &self,
            _authority: &ClusterReadinessAuthority,
            _recipient_id: Uuid,
            _revision: Uuid,
            _claim_token: Uuid,
        ) -> Result<bool> {
            panic!("unused DirectSpoolWakeRepository::acknowledge_if_empty port");
        }

        async fn defer(
            &self,
            _authority: &ClusterReadinessAuthority,
            _recipient_id: Uuid,
            _revision: Uuid,
            _claim_token: Uuid,
            _delay: Duration,
        ) -> Result<bool> {
            panic!("unused DirectSpoolWakeRepository::defer port");
        }
    }
}

mod sm {
    use super::UnusedPorts;
    use anyhow::Result;
    use northstar_room_application::muc_service::{CommittedRoomRetirement, MucRoomIncarnation};
    use northstar_room_application::sm_teardown_muc::*;
    use northstar_room_core::occupancy::MucOccupantRoute;
    use std::collections::HashSet;
    use uuid::Uuid;

    impl SmTeardownMucRepository for UnusedPorts {
        async fn room(&self, _localpart: &str) -> Result<Option<SmTeardownMucRoom>> {
            panic!("unused SmTeardownMucRepository::room port");
        }

        async fn affiliation(&self, _room_id: Uuid, _user_id: Uuid) -> Result<Option<String>> {
            panic!("unused SmTeardownMucRepository::affiliation port");
        }

        async fn blocked_local_audience(
            &self,
            _local_domain: &str,
            _occupant_jids: &[String],
            _stanza_senders: &[String],
        ) -> Result<HashSet<String>> {
            panic!("unused SmTeardownMucRepository::blocked_local_audience port");
        }

        async fn delete_temporary_room(
            &self,
            _room: MucRoomIncarnation,
        ) -> Result<Option<CommittedRoomRetirement>> {
            panic!("unused SmTeardownMucRepository::delete_temporary_room port");
        }

        async fn departed_room(
            &self,
            _localpart: &str,
            _route: &MucOccupantRoute,
            _sm_session_id: Uuid,
        ) -> Result<Option<MucRoomIncarnation>> {
            panic!("unused SmTeardownMucRepository::departed_room port");
        }

        async fn departure_observers(
            &self,
            _room: MucRoomIncarnation,
            _departed_nick: &str,
        ) -> Result<Vec<MucOccupantRoute>> {
            panic!("unused SmTeardownMucRepository::departure_observers port");
        }
    }
}

mod pam_projection_repository;
#[cfg(test)]
mod presence_recovery;
