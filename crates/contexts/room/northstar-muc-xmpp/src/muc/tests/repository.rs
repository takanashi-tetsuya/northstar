use super::*;
use northstar_room_application::muc_service::*;
use northstar_time::{DateTime, Utc};
use std::time::Duration;

mod addressed_delivery;
mod administration;
mod hosted_disco;
mod pam_delivery_repository;
mod pam_projection_repository;

// Unrelated ports fail loudly if a handler unexpectedly reaches them.
macro_rules! unused_async {
    ($(fn $name:ident(&self $(, $arg:ident: $ty:ty)*) -> $out:ty;)+) => {
        $(async fn $name(&self $(, $arg: $ty)*) -> $out {
            $(let _ = $arg;)*
            panic!("unexpected repository call: {}", stringify!($name));
        })+
    };
}

#[derive(Clone)]
pub(super) struct Repository(pub Arc<State>);

impl MucDiscussionRepository for Repository {
    type Error = anyhow::Error;

    fn admit_discussion<'a>(
        &'a self,
        command: &'a MucDiscussion,
    ) -> RepositoryFuture<'a, Self::Error> {
        Box::pin(async move {
            self.0.record(Event::Legacy(command.clone()));
            Ok(self.0.outcome(command))
        })
    }

    fn admit_discussion_observed<'a>(
        &'a self,
        request: &'a discussion_owner::Request,
    ) -> RepositoryFuture<'a, Self::Error> {
        Box::pin(async move {
            self.0.record(Event::Observed(request.command().clone()));
            let outcome = self.0.outcome(request.command());
            if matches!(
                outcome,
                MucDiscussionAdmission::Stored { .. } | MucDiscussionAdmission::Replay(_)
            ) {
                discussion_owner::commit_observed(
                    std::future::ready(Ok::<_, anyhow::Error>(())),
                    request,
                    outcome,
                )
                .await
                .map_err(|error| match error {
                    discussion_owner::CommitError::Observation(error) => anyhow::Error::from(error),
                    discussion_owner::CommitError::Commit(error) => error,
                })?;
            }
            Ok(outcome)
        })
    }
}

impl MucRepository for Repository {
    async fn local_room_snapshot(&self, localpart: &str) -> Result<Option<MucRoom>> {
        assert_eq!(localpart, "room");
        self.0.record(Event::Room);
        Ok(Some(MucRoom {
            logging_enabled: self.0.logging_enabled.load(Ordering::Relaxed),
            ..room()
        }))
    }

    async fn local_affiliation(&self, room_id: Uuid, user_id: Uuid) -> Result<Option<String>> {
        assert_eq!((room_id, user_id), (ROOM_ID, USER_ID));
        self.0.record(Event::Affiliation);
        Ok(Some("member".to_owned()))
    }

    async fn federated_affiliation(&self, room_id: Uuid, bare_jid: &str) -> Result<Option<String>> {
        assert_eq!((room_id, bare_jid), (ROOM_ID, "alice@remote.test"));
        self.0.record(Event::Affiliation);
        Ok(Some("member".to_owned()))
    }

    async fn local_message_by_id(
        &self,
        room_id: Uuid,
        message_id: Uuid,
    ) -> Result<Option<MucMessage>> {
        assert_eq!((room_id, message_id), (ROOM_ID, MESSAGE_ID));
        self.0.record(Event::MessageLookup);
        Ok(Some(MucMessage {
            sender_jid: SENDER.to_owned(),
            stanza: input(false, true).1,
            created_at: DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
        }))
    }

    async fn set_local_subject(
        &self,
        mutation: MucSubjectMutation<'_>,
        archive_stanza: Option<&str>,
        authority: MucActorAuthority,
    ) -> Result<MucSubjectOutcome> {
        assert_eq!(
            (
                mutation.room_id,
                mutation.sender_jid,
                mutation.nick,
                mutation.subject
            ),
            (ROOM_ID, SENDER, "Alice", "new topic")
        );
        assert_eq!(archive_stanza, Some(mutation.stanza));
        assert_eq!(authority.expected_room_epoch, ROOM_EPOCH);
        assert_eq!(authority.connection_uuid, CONNECTION_ID);
        self.0.record(Event::Subject(mutation.stanza.to_owned()));
        Ok(MucSubjectOutcome::Applied)
    }

    async fn set_local_cluster_subject(
        &self,
        operation_id: Uuid,
        expected_room_epoch: Uuid,
        expected_config_version: i64,
        actor: &ClusterMucOccupancyTarget,
        mutation: MucSubjectMutation<'_>,
        archive: ClusterMucSubjectArchive<'_>,
    ) -> Result<ClusterMucTransitionOutcome> {
        assert_eq!(
            (expected_room_epoch, expected_config_version),
            (ROOM_EPOCH, 1)
        );
        assert_eq!(actor, &cluster_target());
        assert_eq!(
            (
                mutation.room_id,
                mutation.sender_jid,
                mutation.nick,
                mutation.subject
            ),
            (ROOM_ID, SENDER, "Alice", "new topic")
        );
        assert!(archive.digest_archive);
        assert_eq!(archive.eligible_stanza, Some(mutation.stanza));
        self.0.record(Event::ClusterSubject(
            operation_id,
            mutation.stanza.to_owned(),
        ));
        Ok(ClusterMucTransitionOutcome::Applied)
    }

    async fn retract_local_message_and_archive_action(
        &self,
        mutation: MucRetractionMutation<'_>,
    ) -> Result<MucRetractionOutcome> {
        assert_eq!(
            (mutation.room_id, mutation.target_id),
            (ROOM_ID, MESSAGE_ID)
        );
        assert_eq!(
            (mutation.sender_jid, mutation.nick, mutation.actor_scope),
            (SENDER, "Alice", "alice@local.test")
        );
        assert_eq!(mutation.expected_stanza, input(false, true).1);
        assert_eq!(mutation.kind, MucRetractionKind::Author);
        assert_eq!(mutation.authority.expected_room_epoch, ROOM_EPOCH);
        self.0
            .record(Event::Retraction(mutation.action_stanza.to_owned()));
        Ok(MucRetractionOutcome::Applied)
    }

    async fn local_cluster_occupancy_target(
        &self,
        room_id: Uuid,
        occupant_incarnation: Uuid,
        connection_uuid: Uuid,
    ) -> Result<Option<ClusterMucOccupancyTarget>> {
        assert_eq!(
            (room_id, occupant_incarnation, connection_uuid),
            (ROOM_ID, OCCUPANT_EPOCH, CONNECTION_ID)
        );
        self.0.record(Event::Target);
        Ok(Some(cluster_target()))
    }

    async fn local_cluster_occupancy_target_by_nick(
        &self,
        room_id: Uuid,
        expected_room_epoch: Uuid,
        nick: &str,
    ) -> Result<Option<ClusterMucOccupancyTarget>> {
        assert_eq!(
            (room_id, expected_room_epoch, nick),
            (ROOM_ID, ROOM_EPOCH, "Alice")
        );
        self.0.record(Event::Target);
        Ok(Some(cluster_target()))
    }

    async fn renew_local_cluster_occupancy(
        &self,
        target: &ClusterMucOccupancyTarget,
        owner_node_id: &str,
        lease: Duration,
    ) -> Result<bool> {
        assert_eq!(target, &cluster_target());
        assert_eq!(owner_node_id, "node-original");
        assert_eq!(lease, Duration::from_secs(90));
        self.0.record(Event::Renew);
        Ok(true)
    }

    unused_async! {
        fn enabled_local_account(&self, username: &str) -> Result<Option<MucLocalAccount>>;
        fn is_blocked_for_account(&self, owner_id: Uuid, owner_bare_jid: &str, candidate: &str) -> Result<bool>;
        fn blocked_jids(&self, user_id: Uuid) -> Result<Vec<String>>;
        fn store_local_muc_offline(&self, configured_domain: &str, recipient_id: Uuid, sender_jid: &str, stanza: &str, encrypted: bool, policy: OfflineStorePolicy) -> Result<OfflineStoreOutcome>;
        fn local_history_since(&self, room_id: Uuid, limit: i64, since: Option<DateTime<Utc>>) -> Result<Vec<MucMessage>>;
        fn delete_expired_locked_room(&self, room_id: Uuid) -> Result<bool>;
        fn delete_temporary_room(&self, room_id: Uuid, room_epoch: Uuid, config_version: i64) -> Result<bool>;
        fn local_reserved_nick(&self, room_id: Uuid, user_id: Uuid) -> Result<Option<String>>;
        fn local_nick_reserved_for_other(&self, room_id: Uuid, user_id: Uuid, nick: &str) -> Result<bool>;
        fn federated_reserved_nick(&self, room_id: Uuid, bare_jid: &str) -> Result<Option<String>>;
        fn federated_nick_reserved_for_other(&self, room_id: Uuid, bare_jid: &str, nick: &str) -> Result<bool>;
        fn get_or_create_local_room(&self, localpart: &str, creator_id: Uuid, creator_full_jid: &str) -> Result<(MucRoom, bool)>;
        fn get_or_create_federated_room(&self, localpart: &str, creator_full_jid: &str) -> Result<(MucRoom, bool)>;
        fn public_room_page(&self, after: Option<&str>, before: Option<Option<&str>>, max: i64) -> Result<Option<MucDiscoPage>>;
        fn register_local_member(&self, room_id: Uuid, user_id: Uuid, nick: &str) -> Result<MucRegistrationOutcome>;
        fn unregister_local_member(&self, room_id: Uuid, user_id: Uuid) -> Result<bool>;
        fn register_federated_member(&self, room_id: Uuid, bare_jid: &str, nick: &str) -> Result<MucRegistrationOutcome>;
        fn unregister_federated_member(&self, room_id: Uuid, bare_jid: &str) -> Result<bool>;
        fn mutate_local_cluster_registration(&self, operation_id: Uuid, room_id: Uuid, expected_room_epoch: Uuid, expected_config_version: i64, principal: &ClusterMucPrincipal, actor_full_jid: &str, reserved_nick: Option<&str>) -> Result<ClusterMucRegistrationOutcome>;
        fn admit_local_invite_command(&self, configured_domain: &str, id: Uuid, room_id: Uuid, recipient_id: Uuid, sender_jid: &str, stanza: &str, encrypted: bool, policy: OfflineStorePolicy, cluster_authority: Option<&ClusterMucInviteAuthority>) -> Result<DurableMucInviteOutcome>;
        fn admit_federated_invite_command(&self, room_id: Uuid, invitee_bare_jid: &str, target_domain: &str, stanza: &str, bounce_to: Option<&str>, policy: FederatedInvitePolicy, cluster_authority: Option<&ClusterMucInviteAuthority>) -> Result<bool>;
        fn update_local_legacy_config(&self, room_id: Uuid, actor_full_jid: &str, config: MucConfigUpdate<'_>) -> Result<MucConfigurationOutcome>;
        fn cancel_locked_room(&self, room_id: Uuid, actor_full_jid: &str) -> Result<bool>;
        fn delete_room(&self, room_id: Uuid) -> Result<()>;
        fn set_local_legacy_affiliations_batch(&self, room_id: Uuid, changes: &[MucAffiliationChange]) -> Result<MucAffiliationBatchOutcome>;
        fn local_affiliations(&self, room_id: Uuid, affiliation: &str) -> Result<Vec<String>>;
        fn federated_affiliations(&self, room_id: Uuid, affiliation: &str) -> Result<Vec<String>>;
        fn authorized_admin_role_list(&self, configured_domain: &str, room_id: Uuid, expected_room_epoch: Uuid, user_id: Uuid, actor_scope: &str, asserted_local_role: &str, actor_target: Option<&ClusterMucOccupancyTarget>, clustered: bool, requested_role: &str) -> Result<MucAdminSnapshot<MucAdminRoleList>>;
        fn authorized_admin_affiliation_list(&self, configured_domain: &str, room_id: Uuid, expected_room_epoch: Uuid, user_id: Uuid, actor_scope: &str, requested_affiliation: &str) -> Result<MucAdminSnapshot<Vec<MucAdminAffiliationEntry>>>;
        fn claim_local_cluster_occupancy(&self, request: ClusterMucJoin<'_>) -> Result<ClusterMucJoinOutcome>;
        fn refresh_local_cluster_presence(&self, target: &ClusterMucOccupancyTarget, owner_node_id: &str, presence_payload: &str, lease: Duration) -> Result<bool>;
        fn transition_local_cluster_occupancy(&self, operation_id: Uuid, target: &ClusterMucOccupancyTarget, transition: MucOccupancyTransition, owner_node_id: &str, new_connection_uuid: Option<Uuid>, new_connection_epoch: Option<i64>, sm_session_id: Option<Uuid>, lease: Duration) -> Result<ClusterMucTransitionOutcome>;
        fn rebind_federated_cluster_occupancy(&self, operation_id: Uuid, target: &ClusterMucOccupancyTarget, owner_node_id: &str, authenticated_domain: &str, new_connection_uuid: Uuid, lease: Duration) -> Result<ClusterMucTransitionOutcome>;
        fn disconnect_local_cluster_occupancy(&self, operation_id: Uuid, target: &ClusterMucOccupancyTarget, owner_node_id: &str) -> Result<ClusterMucTransitionOutcome>;
        fn rename_local_cluster_occupancy(&self, operation_id: Uuid, target: &ClusterMucOccupancyTarget, owner_node_id: &str, new_nick: &str) -> Result<ClusterMucTransitionOutcome>;
        fn update_local_cluster_config(&self, operation_id: Uuid, room_id: Uuid, expected_room_epoch: Uuid, expected_config_version: i64, actor_target: &ClusterMucOccupancyTarget, principal: &ClusterMucPrincipal, actor_full_jid: &str, config: MucConfigUpdate<'_>) -> Result<ClusterMucConfigurationOutcome>;
        fn apply_local_cluster_affiliations_batch(&self, operation_id: Uuid, room_id: Uuid, expected_room_epoch: Uuid, expected_config_version: i64, actor_target: &ClusterMucOccupancyTarget, actor: &ClusterMucPrincipal, actor_full_jid: &str, changes: &[MucAffiliationChange]) -> Result<MucAffiliationBatchOutcome>;
        fn apply_local_cluster_admin_batch(&self, operation_id: Uuid, room_id: Uuid, expected_room_epoch: Uuid, expected_config_version: i64, actor_target: Option<&ClusterMucOccupancyTarget>, actor: &ClusterMucPrincipal, actor_full_jid: &str, local_domain: &str, changes: &[MucAdminBatchChange]) -> Result<MucAdminBatchOutcome>;
        fn kick_local_cluster_occupancy(&self, operation_id: Uuid, actor: &ClusterMucOccupancyTarget, target: &ClusterMucOccupancyTarget, reason: Option<&str>) -> Result<ClusterMucTransitionOutcome>;
        fn change_local_cluster_role(&self, operation_id: Uuid, actor: &ClusterMucOccupancyTarget, target: &ClusterMucOccupancyTarget, new_role: &str, reason: Option<&str>) -> Result<ClusterMucTransitionOutcome>;
        fn destroy_local_cluster_room(&self, operation_id: Uuid, room_id: Uuid, expected_room_epoch: Uuid, actor: Option<&ClusterMucOccupancyTarget>, authorization_source: &str, actor_jid: Option<&str>, alternate_jid: Option<&str>, reason: Option<&str>) -> Result<ClusterMucTransitionOutcome>;
        fn exact_local_cluster_occupancy_snapshot(&self, target: &ClusterMucOccupancyTarget) -> Result<Option<ClusterMucOccupancy>>;
        fn suspended_local_cluster_occupancy(&self, room_id: Uuid, room_epoch: Uuid, sm_session_id: Uuid, full_jid: &str, nick: &str) -> Result<Option<ClusterMucOccupancy>>;
        fn associate_local_cluster_sm_session(&self, target: &ClusterMucOccupancyTarget, owner_node_id: &str, sm_session_id: Uuid) -> Result<bool>;
        fn cluster_room_is_empty(&self, room_id: Uuid) -> Result<bool>;
        fn committed_wake(&self, operation_id: Uuid) -> Result<Option<ClusterMucWakeDescriptor>>;
    }
}

mod mix {
    use anyhow::Result;
    use northstar_abuse_policy::ContentIdentityAuthenticators;
    use northstar_room_application::mix_service::*;
    use northstar_time::{DateTime, Utc};
    use uuid::Uuid;

    pub(crate) struct UnusedMix;

    impl MixMamReadRepository for UnusedMix {
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

    impl MixRepository for UnusedMix {
        unused_async! {
            fn link_local_muc_mirror(&self, mix_domain: &str, localpart: &str, actor_bare_jid: &str, local_domain: &str) -> Result<MixMucLinkOutcome>;
            fn create_mix_channel(&self, service_domain: &str, requested_localpart: Option<&str>, creator_jid: &str, max_channels_per_owner: i64, federated: Option<&FederatedMixMutation>) -> Result<(CreateChannelOutcome, String)>;
            fn mix_channel(&self, service_domain: &str, localpart: &str) -> Result<Option<MixChannel>>;
            fn discoverable_mix_channel_page(&self, service_domain: &str, requester: &str, after: Option<&str>, before: Option<Option<&str>>, max: i64) -> Result<Option<MixDiscoPage>>;
            fn mix_role(&self, channel_id: Uuid, jid: &str) -> Result<Option<String>>;
            fn mix_channel_discoverable_to(&self, channel: &MixChannel, actor: &str) -> Result<bool>;
            fn destroy_mix_channel(&self, channel_id: Uuid, actor: &str, federated: Option<&FederatedMixMutation>) -> Result<bool>;
            fn join_mix_channel(&self, channel_id: Uuid, request: JoinMixRequest, federated: Option<&FederatedMixMutation>) -> Result<JoinChannelOutcome>;
            fn mix_participant(&self, channel_id: Uuid, jid: &str) -> Result<Option<MixParticipant>>;
            fn expire_unrefreshed_mix_presence(&self, cutoff: DateTime<Utc>) -> Result<Vec<ExpiredMixPresence>>;
            fn update_mix_subscriptions(&self, channel_id: Uuid, actor: &str, subscribe: &[String], unsubscribe: &[String], federated: Option<&FederatedMixMutation>) -> Result<Option<UpdateSubscriptionsOutcome>>;
            fn set_mix_nick(&self, channel_id: Uuid, actor: &str, nick: &str, federated: Option<&FederatedMixMutation>) -> Result<std::result::Result<MixParticipant, SetNickError>>;
            fn leave_mix_channel(&self, channel_id: Uuid, actor: &str, pam_user_id: Option<Uuid>, federated: Option<&FederatedMixMutation>) -> Result<Option<LeaveMixOutcome>>;
            fn store_mix_presence(&self, channel_id: Uuid, actor_bare: &str, actor_full: &str, payload: &str, unavailable: bool) -> Result<PresenceOutcome>;
            fn ensure_mix_presence(&self, channel_id: Uuid, actor_bare: &str, actor_full: &str, payload: &str) -> Result<PresenceOutcome>;
            fn store_mix_message(&self, request: StoreMixMessageRequest<'_>, authenticators: Option<&ContentIdentityAuthenticators>) -> Result<StoreMixMessageAdmission>;
            fn store_mix_message_observed(&self, request: &foreground::StoreRequest, authenticators: Option<&ContentIdentityAuthenticators>) -> Result<StoreMixMessageAdmission>;
            fn lookup_mix_message_replay_observed(&self, request: &foreground::ReplayRequest, authenticators: &ContentIdentityAuthenticators) -> Result<MixBusinessReplay>;
            fn lookup_mix_message_replay(&self, channel_id: Uuid, actor: &str, identity: &MixReplayIdentity, authenticators: &ContentIdentityAuthenticators) -> Result<MixBusinessReplay>;
            fn lookup_mix_retraction_replay(&self, channel_id: Uuid, actor: &str, target_id: Uuid, identity: &MixReplayIdentity, authenticators: &ContentIdentityAuthenticators) -> Result<MixBusinessReplay>;
            fn authorized_mix_event_page(&self, channel_id: Uuid, actor: &str, node: &str, before: Option<(DateTime<Utc>, Uuid)>, limit: i64) -> Result<MixReadOutcome<MixEventPage>>;
            fn publish_mix_avatar(&self, channel_id: Uuid, actor: &str, node: &str, item_id: &str, payload: &str, federated: Option<&FederatedMixMutation>) -> Result<bool>;
            fn retract_mix_avatar(&self, channel_id: Uuid, actor: &str, node: &str, item_id: &str, federated: Option<&FederatedMixMutation>) -> Result<bool>;
            fn authorized_mix_access_entries(&self, channel_id: Uuid, actor: &str, banned: bool, limit: i64) -> Result<MixReadOutcome<Vec<String>>>;
            fn update_mix_info(&self, channel_id: Uuid, actor: &str, update: MixInfoUpdate, federated: Option<&FederatedMixMutation>) -> Result<MixMutationOutcome>;
            fn update_mix_config(&self, channel_id: Uuid, actor: &str, update: MixConfigUpdate, roles: MixRoleUpdate, federated: Option<&FederatedMixMutation>) -> Result<MixMutationOutcome>;
            fn set_mix_access_entry(&self, update: MixAccessEntryUpdate<'_>, federated: Option<&FederatedMixMutation>) -> Result<Option<AccessChangeOutcome>>;
            fn register_mix_nick(&self, service_domain: &str, actor: &str, nick: &str, federated: Option<&FederatedMixMutation>) -> Result<RegisterMixNickOutcome>;
            fn mix_participant_preference(&self, channel_id: Uuid, actor: &str) -> Result<Option<MixParticipantPreference>>;
            fn update_mix_participant_preference(&self, channel_id: Uuid, actor: &str, preference: &MixParticipantPreference, federated: Option<&FederatedMixMutation>) -> Result<Option<MixParticipantPreferenceUpdateOutcome>>;
            fn authorized_mix_jid_map_entries(&self, channel_id: Uuid, actor: &str, limit: i64) -> Result<MixReadOutcome<Vec<(String, String)>>>;
            fn issue_mix_invitation(&self, channel_id: Uuid, inviter: &str, invitee: &str, token: &str, lifetime: northstar_time::Duration, federated: Option<&FederatedMixMutation>) -> Result<bool>;
            fn mix_private_message_recipient(&self, channel_id: Uuid, sender: &str, recipient_id: Uuid) -> Result<Option<(MixParticipant, MixParticipant)>>;
            fn retract_mix_message(&self, request: RetractMixMessageRequest<'_>, authenticators: Option<&ContentIdentityAuthenticators>) -> Result<RetractMixMessageAdmission>;
            fn find_enabled_user(&self, username: &str) -> Result<Option<MixAccount>>;
            fn find_enabled_user_by_id(&self, user_id: Uuid) -> Result<Option<MixAccount>>;
            fn is_blocked(&self, owner_id: Uuid, candidate: &str) -> Result<bool>;
            fn relay_profile_snapshot(&self, query: MixRelayProfileQuery) -> Result<MixRelayProfileResult>;
            fn latest_roster_change_for_contact(&self, user_id: Uuid, contact_jid: &str) -> Result<Option<northstar_roster_core::RosterChange>>;
            fn mix_muc_mirror_for_mix(&self, mix_channel_id: Uuid) -> Result<Option<MixMucMirror>>;
            fn mix_muc_mirror_for_muc(&self, muc_room_id: Uuid) -> Result<Option<MixMucMirror>>;
            fn mix_muc_mirror_service_complete(&self, mix_domain: &str) -> Result<bool>;
            fn enqueue_s2s_response_batch(&self, target_domain: &str, responses: &[String], policy: S2sOutboxPolicy) -> Result<()>;
            fn federated_mix_iq_replay(&self, authenticated_domain: &str, actor_jid: &str, request_id: &str, request_digest: &[u8; 32]) -> Result<FederatedMixIqReplay>;
            fn admit_federated_mix_iq_result(&self, authenticated_domain: &str, actor_jid: &str, request_id: &str, request_digest: &[u8; 32], response: &str, policy: S2sOutboxPolicy) -> Result<FederatedMixIqReplay>;
            fn prune_expired_business_intents(&self, limit: i64) -> Result<u64>;
            fn prune_expired_federated_iq_results(&self, limit: i64) -> Result<u64>;
        }
    }

    impl MixPamRepository for UnusedMix {
        unused_async! {
            fn begin_remote_pam_join(&self, request: BeginRemotePamJoin) -> Result<PamOperationReplay>;
            fn lookup_remote_pam_operation(&self, user_id: Uuid, requester_full_jid: &str, client_request_id: &str, request_digest: &[u8; 32]) -> Result<PamOperationReplay>;
            fn begin_remote_pam_leave(&self, request: BeginRemotePamLeave) -> Result<PamOperationReplay>;
            fn complete_remote_pam_success(&self, authenticated_domain: &str, channel_jid: &str, recipient_bare: &str, request_id: &str, response_digest: &[u8; 32], join: Option<RemotePamJoin<'_>>) -> Result<RemotePamCompletionOutcome>;
            fn complete_remote_pam_error(&self, authenticated_domain: &str, channel_jid: &str, recipient_bare: &str, request_id: &str, response_digest: &[u8; 32], error_type: &str, condition: &str) -> Result<RemotePamCompletionOutcome>;
            fn pam_memberships(&self, user_id: Uuid) -> Result<Vec<PamMembership>>;
            fn pam_membership(&self, user_id: Uuid, channel_jid: &str) -> Result<Option<PamMembership>>;
            fn local_pam_users_for_channel(&self, channel_jid: &str) -> Result<Vec<Uuid>>;
            fn reconcile_expired_remote_pam(&self, limit: i64) -> Result<u64>;
            fn claim_pam_results(&self, limit: i64) -> Result<Vec<ClaimedPamResult>>;
            fn renew_pam_result_lease(&self, operation_id: Uuid, lease_token: Uuid) -> Result<bool>;
            fn acknowledge_pam_result(&self, operation_id: Uuid, lease_token: Uuid) -> Result<bool>;
            fn defer_pam_result(&self, operation_id: Uuid, lease_token: Uuid, delay_seconds: i64) -> Result<bool>;
            fn retry_pam_result(&self, operation_id: Uuid, lease_token: Uuid, attempt_count: i32, error: &str) -> Result<bool>;
            fn prune_expired_pam_results(&self, limit: i64) -> Result<u64>;
        }
    }

    impl MixDeliveryRepository for UnusedMix {
        async fn archive_verified_mix_reflection(
            &self,
            _request: VerifiedMixReflection<'_>,
        ) -> Result<ReflectedMixArchiveOutcome> {
            panic!("unexpected port call: archive_verified_mix_reflection")
        }

        unused_async! {
            fn archive_mix_message_once(&self, personal_archive_id: Uuid, owner_id: Uuid, channel_jid: &str, authoritative_stanza_id: Uuid, stanza: &str, encrypted: bool, client_stanza_id: Option<&str>) -> Result<SourceArchiveAdmission>;
            fn claim_mix_deliveries(&self, limit: i64, max_bytes: i64) -> Result<Vec<ClaimedMixDelivery>>;
            fn claim_mix_deliveries_observed(&self, request: &outbox::core::ClaimRequest) -> Result<outbox::core::Rows>;
            fn archive_mix_message_once_observed(&self, request: &outbox::core::ArchiveRequest) -> Result<outbox::core::ArchiveResult>;
            fn renew_mix_delivery_lease_observed(&self, request: &outbox::core::RenewalRequest) -> Result<bool>;
            fn settle_mix_delivery_observed(&self, request: &outbox::core::SettlementRequest) -> Result<outbox::core::SettlementResult>;
            fn maintain_mix_delivery_retention(&self) -> Result<()>;
            fn acknowledge_mix_delivery(&self, delivery_id: Uuid, lease_token: Uuid, observation: Option<&northstar_delivery_core::native_write::AckRequest>) -> Result<bool>;
            fn fence_mix_socket_write(&self, source: northstar_delivery_core::MixDelivery) -> Result<northstar_delivery_core::MixDelivery>;
            fn transfer_mix_delivery_to_cluster(&self, source: northstar_delivery_core::MixDelivery, node_id: &str, request_id: Uuid, ttl_seconds: u64) -> Result<northstar_delivery_core::MixDelivery>;
            fn release_mix_cluster_delivery(&self, source: northstar_delivery_core::MixDelivery, node_id: &str, request_id: Uuid) -> Result<bool>;
            fn transfer_mix_delivery_to_bosh(&self, request: &northstar_delivery_core::bosh_ownership::TransferRequest) -> Result<northstar_delivery_core::MixDelivery>;
            fn renew_mix_delivery_lease(&self, delivery_id: Uuid, lease_token: Uuid) -> Result<bool>;
            fn dead_letter_mix_delivery(&self, delivery_id: Uuid, lease_token: Uuid, terminal_reason: &str, error: &str) -> Result<bool>;
            fn retry_mix_delivery(&self, delivery_id: Uuid, lease_token: Uuid, claimed_attempt_count: i32, route_wake_generation: i64, error: &str) -> Result<MixDeliveryRetryOutcome>;
            fn defer_mix_delivery(&self, delivery_id: Uuid, lease_token: Uuid, route_wake_generation: i64, delay_seconds: i64) -> Result<bool>;
            fn wake_mix_delivery_recipient(&self, recipient_jid: &str) -> Result<u64>;
            fn mix_delivery_dead_letters(&self, before: Option<(DateTime<Utc>, Uuid)>, limit: i64) -> Result<Vec<MixDeliveryDeadLetter>>;
            fn requeue_mix_delivery_dead_letter(&self, dead_letter_id: Uuid) -> Result<bool>;
        }
    }
}

pub(super) use mix::UnusedMix;

mod join_continuity;
#[cfg(test)]
mod lifecycle;
mod live_audience;
mod read_snapshots;

#[cfg(test)]
mod presence_recovery;
#[cfg(test)]
mod retirement_identity;
#[cfg(test)]
mod room_creation;
