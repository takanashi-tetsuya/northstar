use super::repository::UnusedRepository;
use super::*;

mod host_ports {
    use super::*;
    use crate::local_routes::muc::{
        MucOccupant, RestoreLocalMucOccupantsRequest, SuspendedMucEndpoint,
    };
    use crate::local_routes::session::{OnlineSession, SmPresenceEpoch, SmStagedRouteClaim};
    use crate::protocol::dispatch::route::ClientIqRoute;
    use crate::IqRouter;
    use dashmap::DashMap;
    use northstar_auth_application::account_teardown::FinalizeAccountDeletion;
    use northstar_auth_application::authentication::Sasl2FastTokenPolicy;
    use northstar_room_application::muc_service::LocalMucOccupantIdentity;
    use northstar_session_core::{JoinedMucMembership, LocalCapsEpoch};
    use roxmltree::Node;
    use std::time::Duration;
    use tokio_util::sync::CancellationToken;

    impl SessionIdentityHost for TestHost {
        #[allow(clippy::too_many_arguments)]
        fn c2s_resource_bind_timeout_seconds(&self) -> u64 {
            30
        }
        #[allow(clippy::too_many_arguments)]
        fn capacity_session_lease_seconds(&self) -> u64 {
            30
        }
        #[allow(clippy::too_many_arguments)]
        fn local_domain(&self) -> &str {
            "example.test"
        }
        #[allow(clippy::too_many_arguments)]
        fn tls_context(&self) -> &northstar_security::tls::TlsContext {
            panic!("unexpected host call: tls_context")
        }
        #[allow(clippy::too_many_arguments)]
        fn unauthenticated_timeout(&self) -> Duration {
            Duration::from_secs(30)
        }
        #[allow(clippy::too_many_arguments)]
        fn xmpp_extension_enabled(&self, _id: northstar_xep_core::XepId) -> bool {
            true
        }
        #[allow(clippy::too_many_arguments)]
        fn c2s_scram_sha1_enabled(&self) -> bool {
            false
        }
        #[allow(clippy::too_many_arguments)]
        fn muc_domain(&self) -> String {
            "conference.example.test".to_owned()
        }
        #[allow(clippy::too_many_arguments)]
        fn mix_domain(&self) -> String {
            "mix.example.test".to_owned()
        }
        #[allow(clippy::too_many_arguments)]
        fn pubsub_domain(&self) -> String {
            "pubsub.example.test".to_owned()
        }
        #[allow(clippy::too_many_arguments)]
        fn upload_domain(&self) -> String {
            "upload.example.test".to_owned()
        }
        #[allow(clippy::too_many_arguments)]
        fn http_upload_enabled(&self) -> bool {
            false
        }
        #[allow(clippy::too_many_arguments)]
        fn xmpp_external_route_domain_allowed(&self, _domain: &str) -> bool {
            true
        }
        #[allow(clippy::too_many_arguments)]
        fn xmpp_route_enabled(
            &self,
            _stanza: northstar_xep_core::StanzaKind,
            _namespace: &str,
            _local_name: &str,
        ) -> bool {
            true
        }
    }

    impl SessionAccountHost for TestHost {
        type AccountStore = UnusedRepository;
        type AuthenticationStore = UnusedRepository;
        type ChallengeStore = UnusedRepository;
        type LoginAbuseStore = UnusedRepository;
        #[allow(clippy::too_many_arguments)]
        fn account_service(
            &self,
        ) -> &northstar_auth_application::account::AccountService<Self::AccountStore> {
            &self.account
        }
        #[allow(clippy::too_many_arguments)]
        fn authentication_service(
            &self,
        ) -> &northstar_auth_application::authentication::AuthenticationService<
            Self::AuthenticationStore,
        > {
            &self.authentication
        }
        fn mam_enabled(&self) -> bool {
            self.mam_enabled
        }
        #[allow(clippy::too_many_arguments)]
        fn challenge_issue_service(
            &self,
        ) -> &northstar_abuse_application::challenge::ChallengeIssueService<Self::ChallengeStore>
        {
            &self.challenge
        }
        #[allow(clippy::too_many_arguments)]
        fn registration_is_closed(&self) -> bool {
            false
        }
        #[allow(clippy::too_many_arguments)]
        fn registration_requires_invitation(&self) -> bool {
            false
        }
        #[allow(clippy::too_many_arguments)]
        fn sasl2_fast_token_policy(&self) -> Sasl2FastTokenPolicy {
            Sasl2FastTokenPolicy {
                enabled: false,
                rotation_days: 1,
                ttl_days: 1,
                strong_reauth_max_days: 1,
            }
        }
        #[allow(clippy::too_many_arguments)]
        fn sasl_login_abuse_service(
            &self,
        ) -> &northstar_abuse_application::login::SaslLoginAbuseService<Self::LoginAbuseStore>
        {
            &self.login
        }
        #[allow(clippy::too_many_arguments)]
        async fn finalize_account_deletion(
            &self,
            _user_id: uuid::Uuid,
            _username: &str,
        ) -> Result<FinalizeAccountDeletion> {
            panic!("unexpected host call: finalize_account_deletion")
        }
        #[allow(clippy::too_many_arguments)]
        async fn disconnect_account(&self, _user_id: uuid::Uuid, _bare_account_jid: &str) -> () {
            panic!("unexpected host call: disconnect_account")
        }
    }

    impl SessionRoutesHost for TestHost {
        #[allow(clippy::too_many_arguments)]
        async fn claim_staged_binding_route(
            &self,
            _full_jid: &str,
            _connection_id: uuid::Uuid,
        ) -> anyhow::Result<bool> {
            assert_eq!(
                _full_jid,
                self.repository
                    .binding
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .as_str()
            );
            assert_eq!(_connection_id, Uuid::from_u128(302));
            Ok(true)
        }
        #[allow(clippy::too_many_arguments)]
        async fn finalize_resource_binding(
            &self,
            _connection_id: uuid::Uuid,
            _user_id: uuid::Uuid,
            _expected_auth_generation: i64,
            _full_jid: &str,
            _device_id: Option<uuid::Uuid>,
            _fast_plan: Option<&northstar_auth_application::authentication::FastCommitPlan>,
            _observation: Option<
                &northstar_auth_application::authentication::publication::PreparedCredential,
            >,
        ) -> anyhow::Result<northstar_session_application::sm::BindingFinalizationOutcome> {
            assert_eq!(_connection_id, Uuid::from_u128(302));
            assert_eq!(_user_id, Uuid::from_u128(303));
            assert_eq!(_expected_auth_generation, 2);
            assert_eq!(
                _full_jid,
                self.repository
                    .binding
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .as_str()
            );
            assert_eq!(_device_id, None);
            if _full_jid.starts_with("fixture@example.test/captured/") {
                assert!(_observation.is_none());
                self.events.lock().unwrap().push("bind finalized");
                return Ok(northstar_session_application::sm::BindingFinalizationOutcome::Committed {
        receipt: northstar_auth_application::authentication::CredentialCommitReceipt::new(None, None, Some(
            northstar_auth_application::authentication::BindingPublication {
                connection_id: _connection_id, user_id: _user_id, full_jid: _full_jid.to_owned(), lease_seconds: 30,
            },
        )),
    });
            }
            assert!(_fast_plan.is_none());
            let credential = _observation.unwrap().observation().snapshot();
            assert_eq!(
                credential.kind,
                northstar_session_core::publication::CredentialKind::Binding
            );
            assert!(!credential.service_started);
            self.replace_route();
            self.events.lock().unwrap().push("bind finalized");
            Ok(northstar_session_application::sm::BindingFinalizationOutcome::CredentialsExpired)
        }
        #[allow(clippy::too_many_arguments)]
        async fn release_staged_binding_route(
            &self,
            _full_jid: &str,
            _connection_id: uuid::Uuid,
        ) -> anyhow::Result<()> {
            self.routes
                .remove_if(_full_jid, |_, route| route.connection_id == _connection_id);
            Ok(())
        }
        #[allow(clippy::too_many_arguments)]
        fn remove_session_if_connection(
            &self,
            _key: &str,
            _connection_id: uuid::Uuid,
        ) -> Option<OnlineSession> {
            self.routes
                .remove_if(_key, |_, session| session.connection_id == _connection_id)
                .map(|(_, route)| route)
        }
        #[allow(clippy::too_many_arguments)]
        fn staged_session_is_current(
            &self,
            _key: &str,
            _connection_id: uuid::Uuid,
            _user_id: uuid::Uuid,
            _auth_generation: i64,
            _lifecycle: &Arc<AtomicU8>,
        ) -> bool {
            crate::local_routes::session_table::LocalSessionTable::new(Arc::clone(&self.routes))
                .staged_session_is_current(
                    _key,
                    _connection_id,
                    _user_id,
                    _auth_generation,
                    _lifecycle,
                )
        }
        #[allow(clippy::too_many_arguments)]
        fn try_stage_bound_session(&self, _key: String, _session: OnlineSession) -> bool {
            match self.routes.entry(_key) {
                dashmap::mapref::entry::Entry::Vacant(entry) => {
                    entry.insert(_session);
                    true
                }
                dashmap::mapref::entry::Entry::Occupied(_) => false,
            }
        }
        #[allow(clippy::too_many_arguments)]
        fn activate_session_if_current(
            &self,
            _full_jid: &str,
            _connection_id: uuid::Uuid,
            _user_id: uuid::Uuid,
            _auth_generation: i64,
            _lifecycle: &Arc<AtomicU8>,
            _disconnect: &CancellationToken,
        ) -> bool {
            crate::local_routes::session_table::activate_session_if_current_in(
                &self.routes,
                _full_jid,
                _connection_id,
                _user_id,
                _auth_generation,
                _lifecycle,
                _disconnect,
            )
        }
        #[allow(clippy::too_many_arguments)]
        async fn notify_remote_user_agent_replacement(
            &self,
            _account: &str,
            _user_id: uuid::Uuid,
            _device_id: uuid::Uuid,
            _epoch: i64,
        ) -> anyhow::Result<()> {
            assert_eq!(_account, "fixture@example.test");
            assert_eq!(_user_id, Uuid::from_u128(303));
            assert_eq!(_device_id, Uuid::from_u128(304));
            assert_eq!(_epoch, 7);
            self.events.lock().unwrap().push("remote notification");
            Ok(())
        }
        #[allow(clippy::too_many_arguments)]
        fn publish_user_agent_epoch_if_current(
            &self,
            _key: &str,
            _connection_id: uuid::Uuid,
            _user_id: uuid::Uuid,
            _auth_generation: i64,
            _lifecycle: &Arc<AtomicU8>,
            _user_agent_epoch: Option<i64>,
        ) -> bool {
            crate::local_routes::session_table::publish_user_agent_epoch_if_current_in(
                &self.routes,
                _key,
                _connection_id,
                _user_id,
                _auth_generation,
                _lifecycle,
                _user_agent_epoch,
            )
        }
        #[allow(clippy::too_many_arguments)]
        fn session_entries_for(&self, _jid: &str) -> Vec<(String, OnlineSession)> {
            crate::local_routes::session_table::session_entries_for_in(&self.routes, _jid)
        }
        #[allow(clippy::too_many_arguments)]
        async fn personal_message_remote_resource_exists(&self, _jid: &str) -> bool {
            panic!("unexpected host call: personal_message_remote_resource_exists")
        }
        #[allow(clippy::too_many_arguments)]
        async fn route_client_iq_to_remote_resource(&self, _full_jid: &str, _stanza: &str) -> bool {
            panic!("unexpected host call: route_client_iq_to_remote_resource")
        }
    }

    impl SessionCapsHost for TestHost {
        #[allow(clippy::too_many_arguments)]
        fn caps_by_jid(&self) -> &northstar_protocol_runtime::caps::CapsResourceIndex {
            &self.caps
        }
        #[allow(clippy::too_many_arguments)]
        fn federated_caps_gates(
            &self,
        ) -> &northstar_protocol_runtime::caps::FederatedCapsGateIndex {
            &self.caps_gates
        }
        #[allow(clippy::too_many_arguments)]
        fn caps_cache(&self) -> &northstar_protocol_runtime::caps::CapsCacheIndex {
            &self.caps_cache
        }
        #[allow(clippy::too_many_arguments)]
        fn caps_effect_dispatcher(
            &self,
        ) -> &Arc<northstar_protocol_runtime::caps::CapsEffectDispatcher> {
            &self.caps_dispatcher
        }
        #[allow(clippy::too_many_arguments)]
        fn local_caps_epoch_is_current(
            &self,
            _full_jid: &str,
            _epoch: LocalCapsEpoch,
            _expected_gate: Option<&Arc<tokio::sync::Mutex<()>>>,
        ) -> bool {
            crate::local_routes::session_table::LocalSessionTable::new(Arc::clone(&self.routes))
                .local_caps_epoch_is_current(_full_jid, _epoch, _expected_gate)
        }
        #[allow(clippy::too_many_arguments)]
        fn local_caps_observer_connection_is_current(
            &self,
            _full_jid: &str,
            _connection_id: uuid::Uuid,
            _expected_gate: &Arc<tokio::sync::Mutex<()>>,
        ) -> bool {
            crate::local_routes::session_table::LocalSessionTable::new(Arc::clone(&self.routes))
                .local_caps_observer_connection_is_current(
                    _full_jid,
                    _connection_id,
                    _expected_gate,
                )
        }
        #[allow(clippy::too_many_arguments)]
        fn pending_caps(&self) -> &northstar_protocol_runtime::caps::PendingCapsIndex {
            &self.pending_caps
        }
    }

    impl SessionSmHost for TestHost {
        type ReplayStore = UnusedRepository;
        type SmStore = UnusedRepository;
        #[allow(clippy::too_many_arguments)]
        fn replay_service(
            &self,
        ) -> &northstar_session_application::replay::ReplayService<Self::ReplayStore> {
            &self.replay_service
        }
        #[allow(clippy::too_many_arguments)]
        fn sm_memory_governor(
            &self,
        ) -> &Arc<northstar_session_application::sm_capacity::SmMemoryGovernor> {
            &self.governor
        }
        #[allow(clippy::too_many_arguments)]
        fn sm_service(&self) -> &northstar_session_application::sm::SmService<Self::SmStore> {
            &self.sm_service
        }
        #[allow(clippy::too_many_arguments)]
        async fn claim_sm_resume_route(
            &self,
            _full_jid: &str,
            _connection_id: uuid::Uuid,
            _session_id: uuid::Uuid,
            _claim_token: uuid::Uuid,
        ) -> anyhow::Result<bool> {
            assert_eq!(_full_jid, "fixture@example.test/captured");
            assert_eq!(_connection_id, Uuid::from_u128(302));
            assert_eq!(_session_id, Uuid::from_u128(401));
            assert_eq!(_claim_token, Uuid::from_u128(402));
            Ok(true)
        }
        #[allow(clippy::too_many_arguments)]
        async fn finalize_sm_resume(
            &self,
            _request: northstar_session_application::sm::SmResumeFinalizationRequest<'_>,
            _observation: Option<
                &northstar_auth_application::authentication::publication::PreparedCredential,
            >,
        ) -> anyhow::Result<northstar_session_application::sm::SmResumeFinalizationOutcome>
        {
            assert_eq!(_request.session_id, Uuid::from_u128(401));
            assert_eq!(_request.claim_token, Uuid::from_u128(402));
            assert_eq!(_request.connection_id, Uuid::from_u128(302));
            assert_eq!(_request.user_id, Uuid::from_u128(303));
            assert_eq!(_request.expected_auth_generation, 2);
            assert_eq!(_request.client_h, 3);
            assert_eq!(_request.acknowledged_count, 0);
            assert_eq!(
                _request.peer_ip,
                "192.0.2.8".parse::<std::net::IpAddr>().unwrap()
            );
            assert_eq!(_request.active_privacy_list, Some("captured-privacy"));
            assert_eq!(_request.ttl_seconds, 60);
            assert_eq!(_request.live_lease_seconds, 30);
            assert_eq!(_request.max_stanzas, 32);
            assert_eq!(_request.max_bytes, 16384);
            if let Some(plan) = _request.fast_plan {
                assert!(plan.token_id.is_none());
                assert!(plan.issue.is_none());
            }
            if self.resume_success || self.resume_contradiction {
                assert_eq!(_observation.is_none(), self.resume_success);
                return Ok(northstar_session_application::sm::SmResumeFinalizationOutcome::Committed(Box::new(
        northstar_session_application::sm::SmResumeFinalizationCommit {
            activated: northstar_session_application::sm::ActivatedSmSession { outbound_h: 3, unacked: vec![] },
            receipt: northstar_auth_application::authentication::CredentialCommitReceipt::new(None, None, Some(
                northstar_auth_application::authentication::BindingPublication {
                    connection_id: _request.connection_id, user_id: _request.user_id,
                    full_jid: "fixture@example.test/captured".to_owned(), lease_seconds: 30,
                },
            )),
        },
    )));
            }
            assert_eq!(
                _observation.unwrap().observation().snapshot().kind,
                northstar_session_core::publication::CredentialKind::Resume
            );
            self.replace_route();
            self.events.lock().unwrap().push("resume finalized");
            if self.resume_error {
                self.events.lock().unwrap().push("resume error returned");
                return Err(anyhow::anyhow!("unknown resume COMMIT reply"));
            }
            Ok(northstar_session_application::sm::SmResumeFinalizationOutcome::CredentialsExpired)
        }
        #[allow(clippy::too_many_arguments)]
        async fn release_exact_local_session_route(
            &self,
            _full_jid: &str,
            _connection_id: uuid::Uuid,
        ) -> anyhow::Result<()> {
            self.routes
                .remove_if(_full_jid, |_, route| route.connection_id == _connection_id);
            Ok(())
        }
        #[allow(clippy::too_many_arguments)]
        async fn revoke_sm_session_with_teardown(&self, _id: uuid::Uuid) -> anyhow::Result<()> {
            panic!("unexpected host call: revoke_sm_session_with_teardown")
        }
        #[allow(clippy::too_many_arguments)]
        fn sm_buffer_limits(&self) -> SmBufferLimits {
            northstar_session_application::sm::SmBufferLimits {
                max_unacked_stanzas: 32,
                max_unacked_bytes: 16384,
                max_snapshot_bytes: 32768,
            }
        }
        #[allow(clippy::too_many_arguments)]
        fn sm_ip_binding(&self) -> &str {
            "none"
        }
        #[allow(clippy::too_many_arguments)]
        fn sm_pending_route_removal_signal(
            &self,
            _key: &str,
            _old_connection_id: uuid::Uuid,
            _user_id: uuid::Uuid,
            _sm_session_id: uuid::Uuid,
            _cancel_live_route: bool,
        ) -> Option<tokio::sync::watch::Receiver<bool>> {
            panic!("unexpected host call: sm_pending_route_removal_signal")
        }
        #[allow(clippy::too_many_arguments)]
        fn sm_presence_epoch(&self, _key: &str) -> Option<SmPresenceEpoch> {
            None
        }
        #[allow(clippy::too_many_arguments)]
        fn sm_session_policy(&self) -> SmSessionPolicy {
            northstar_session_application::sm::SmSessionPolicy {
                require_same_device: false,
                resume_timeout_seconds: 60,
                live_lease_seconds: 30,
                claim_lease_seconds: 10,
                max_per_account: 4,
                max_global: 100,
            }
        }
        #[allow(clippy::too_many_arguments)]
        fn enqueue_sm_suspension_recovery(
            &self,
            _account: northstar_session_application::SessionCleanupAccount,
            _connection_id: uuid::Uuid,
            _session_id: uuid::Uuid,
            _snapshot: northstar_session_application::sm::SmSessionSnapshot,
            _ttl_seconds: u64,
            _endpoints: Vec<Arc<crate::local_routes::muc::SuspendedMucEndpoint>>,
            _capacity: northstar_session_application::sm_capacity::SmCapacityLease,
        ) -> bool {
            panic!("unexpected host call: enqueue_sm_suspension_recovery")
        }
        #[allow(clippy::too_many_arguments)]
        fn enqueue_sm_promote_recovery(
            &self,
            _connection_id: uuid::Uuid,
            _session_id: uuid::Uuid,
            _endpoints: Vec<Arc<crate::local_routes::muc::SuspendedMucEndpoint>>,
            _capacity: northstar_session_application::sm_capacity::SmCapacityLease,
        ) -> bool {
            panic!("unexpected host call: enqueue_sm_promote_recovery")
        }
        #[allow(clippy::too_many_arguments)]
        fn stage_sm_resumed_session(
            &self,
            _key: String,
            _candidate: OnlineSession,
            _claimant_user: uuid::Uuid,
            _claimed_sm_id: uuid::Uuid,
            _expected_gate: &Arc<tokio::sync::Mutex<()>>,
        ) -> SmStagedRouteClaim {
            crate::local_routes::session_table::stage_sm_resumed_session_in(
                &self.routes,
                _key,
                _candidate,
                _claimant_user,
                _claimed_sm_id,
                _expected_gate,
            )
        }
    }

    impl SessionMucHost for TestHost {
        type RestoredMuc = UnusedRepository;
        #[allow(clippy::too_many_arguments)]
        async fn associate_local_muc_sm_session(
            &self,
            _full_jid: &str,
            _connection_id: uuid::Uuid,
            _sm_session_id: uuid::Uuid,
            _memberships: &DashMap<String, JoinedMucMembership>,
        ) -> () {
            panic!("unexpected host call: associate_local_muc_sm_session")
        }
        #[allow(clippy::too_many_arguments)]
        fn remove_local_muc_occupant_exact(
            &self,
            _identity: LocalMucOccupantIdentity<'_>,
        ) -> Option<MucOccupant> {
            panic!("unexpected host call: remove_local_muc_occupant_exact")
        }
        #[allow(clippy::too_many_arguments)]
        async fn abort_local_muc_resume(
            &self,
            _restored: &Self::RestoredMuc,
            _snapshot_backed: bool,
        ) -> () {
            panic!("unexpected host call: abort_local_muc_resume")
        }
        #[allow(clippy::too_many_arguments)]
        async fn begin_suspended_muc_resume(
            &self,
            _endpoints: &[Arc<SuspendedMucEndpoint>],
            _base_stanzas: usize,
            _base_bytes: usize,
        ) -> bool {
            assert!(_endpoints.is_empty());
            assert_eq!(_base_stanzas, 0);
            assert_eq!(_base_bytes, 0);
            true
        }
        #[allow(clippy::too_many_arguments)]
        async fn checkpoint_local_muc_resume(&self, _restored: &Self::RestoredMuc) -> bool {
            true
        }
        #[allow(clippy::too_many_arguments)]
        fn clear_suspended_sm_capacity(&self, _endpoints: &[Arc<SuspendedMucEndpoint>]) {
            assert!(_endpoints.is_empty());
        }
        #[allow(clippy::too_many_arguments)]
        async fn commit_local_muc_resume(
            &self,
            _restored: Self::RestoredMuc,
            _sender: &crate::outbound::OutboundSender,
            _capacity: northstar_session_application::sm_capacity::SmCapacityLease,
        ) -> crate::local_routes::muc::CommittedLocalMucResume {
            panic!("unexpected host call: commit_local_muc_resume")
        }
        #[allow(clippy::too_many_arguments)]
        async fn mark_suspended_muc_durable(
            &self,
            _endpoints: Vec<Arc<SuspendedMucEndpoint>>,
        ) -> bool {
            assert!(_endpoints.is_empty());
            true
        }
        #[allow(clippy::too_many_arguments)]
        async fn pause_suspended_muc_delivery(
            &self,
            _sm_session_id: uuid::Uuid,
        ) -> Vec<Arc<SuspendedMucEndpoint>> {
            assert_eq!(_sm_session_id, Uuid::from_u128(401));
            vec![]
        }
        #[allow(clippy::too_many_arguments)]
        async fn restore_local_muc_occupants(
            &self,
            _request: RestoreLocalMucOccupantsRequest<'_>,
        ) -> Self::RestoredMuc {
            assert!(_request.memberships.is_empty());
            self.repository.clone()
        }
        #[allow(clippy::too_many_arguments)]
        async fn seal_suspended_muc_endpoints(
            &self,
            _endpoints: &[Arc<SuspendedMucEndpoint>],
        ) -> () {
            panic!("unexpected host call: seal_suspended_muc_endpoints")
        }
        super::occupant_iq::ports!();
        #[allow(clippy::too_many_arguments)]
        async fn blocked_muc_recipient_accounts(
            &self,
            _occupants: &[MucOccupant],
            _stanza_senders: &[String],
        ) -> std::collections::HashSet<String> {
            panic!("unexpected host call: blocked_muc_recipient_accounts")
        }
        #[allow(clippy::too_many_arguments)]
        async fn deliver_to_muc_occupant(&self, _occupant: &MucOccupant, _stanza: String) -> bool {
            panic!("unexpected host call: deliver_to_muc_occupant")
        }
    }

    impl SessionPresencePolicyHost for TestHost {
        type PresenceStore = UnusedRepository;
        type PrivacyStore = UnusedRepository;
        #[allow(clippy::too_many_arguments)]
        fn presence_service(
            &self,
        ) -> &northstar_roster_application::presence::PresenceService<Self::PresenceStore> {
            panic!("unexpected host call: presence_service")
        }
        #[allow(clippy::too_many_arguments)]
        async fn privacy_allows_session(
            &self,
            _session: &OnlineSession,
            _peer: &str,
            _kind: impl Into<northstar_roster_application::privacy::PrivacyStanzaKind> + Send,
        ) -> anyhow::Result<bool> {
            panic!("unexpected host call: privacy_allows_session")
        }
        #[allow(clippy::too_many_arguments)]
        fn privacy_service(
            &self,
        ) -> &northstar_roster_application::privacy::PrivacyService<Self::PrivacyStore> {
            panic!("unexpected host call: privacy_service")
        }
    }

    impl SessionMessageEffectsHost for TestHost {
        type PushStore = UnusedRepository;
        type S2sOutbox = UnusedRepository;
        #[allow(clippy::too_many_arguments)]
        fn push_service(
            &self,
        ) -> &northstar_message_application::push::PushService<Self::PushStore> {
            panic!("unexpected host call: push_service")
        }
        #[allow(clippy::too_many_arguments)]
        fn set_local_carbons_for_connection(
            &self,
            _key: &str,
            _connection_id: uuid::Uuid,
            _enabled: bool,
        ) -> bool {
            panic!("unexpected host call: set_local_carbons_for_connection")
        }
        #[allow(clippy::too_many_arguments)]
        fn federation_outbox(&self) -> &Self::S2sOutbox {
            panic!("unexpected host call: federation_outbox")
        }
    }

    impl SessionMixAckHost for TestHost {
        type MixStore = UnusedRepository;
        #[allow(clippy::too_many_arguments)]
        fn mix_service(
            &self,
        ) -> &northstar_room_application::mix_service::MixService<Self::MixStore> {
            panic!("unexpected host call: mix_service")
        }
    }

    impl SessionPubSubEffectsHost for TestHost {
        #[allow(clippy::too_many_arguments)]
        async fn dispatch_pubsub_authorization_response(
            _session: &ProtocolSession<Self>,
            _root: Node<'_, '_>,
        ) -> Result<bool>
        where
            Self: SessionHost,
        {
            panic!("unexpected host call: dispatch_pubsub_authorization_response")
        }
        #[allow(clippy::too_many_arguments)]
        async fn replay_pubsub_last_items(
            self: Arc<Self>,
            _outbound: crate::outbound::OutboundSender,
            _recipient_id: uuid::Uuid,
            _auth_generation: i64,
            _active_privacy_list: Option<String>,
            _connection_id: uuid::Uuid,
            _recipient: String,
            _show: &'static str,
        ) -> Result<()> {
            panic!("unexpected host call: replay_pubsub_last_items")
        }
    }

    impl SessionDispatchHost for TestHost {
        #[allow(clippy::too_many_arguments)]
        async fn dispatch_message(
            _session: &ProtocolSession<Self>,
            _root: Node<'_, '_>,
            _raw: &str,
            _client_raw: &str,
        ) -> Result<Action>
        where
            Self: SessionHost,
        {
            _session.host.messages.lock().unwrap().push((
                _raw.to_owned(),
                _client_raw.to_owned(),
                _session
                    .frame_executions
                    .auth_origin()
                    .unwrap()
                    .operation_id(),
            ));
            _session
                .host
                .frames
                .lock()
                .unwrap()
                .push(_session.frame_executions.auth_origin().unwrap());
            Ok(Action::None)
        }
        #[allow(clippy::too_many_arguments)]
        async fn dispatch_muc_message(
            _session: &ProtocolSession<Self>,
            _root: Node<'_, '_>,
            _raw: &str,
        ) -> Result<Action>
        where
            Self: SessionHost,
        {
            panic!("unexpected host call: dispatch_muc_message")
        }
        #[allow(clippy::too_many_arguments)]
        async fn dispatch_mix_message(
            _session: &ProtocolSession<Self>,
            _root: Node<'_, '_>,
            _raw: &str,
        ) -> Result<Option<Action>>
        where
            Self: SessionHost,
        {
            panic!("unexpected host call: dispatch_mix_message")
        }
        #[allow(clippy::too_many_arguments)]
        async fn dispatch_presence(
            _session: &mut ProtocolSession<Self>,
            _root: Node<'_, '_>,
            _raw: &str,
        ) -> Result<Action>
        where
            Self: SessionHost,
        {
            panic!("unexpected host call: dispatch_presence")
        }
        #[allow(clippy::too_many_arguments)]
        async fn dispatch_mix_iq(
            _session: &ProtocolSession<Self>,
            _raw: &str,
        ) -> Result<Option<Action>>
        where
            Self: SessionHost,
        {
            panic!("unexpected host call: dispatch_mix_iq")
        }
        #[allow(clippy::too_many_arguments)]
        fn iq_routes() -> &'static IqRouter<ClientIqRoute<Self>>
        where
            Self: SessionHost,
        {
            panic!("unexpected host call: iq_routes")
        }
    }

    impl SessionLifecycleHost for TestHost {
        type Cleanup = TestCleanup;
        #[allow(clippy::too_many_arguments)]
        fn drop_session(_session: &mut ProtocolSession<Self>)
        where
            Self: SessionHost,
        {
            _session
                .post_actions
                .abort_now(&_session.host.c2s_post_action_telemetry());
            _session.local_quiesced = true;
        }
        #[allow(clippy::too_many_arguments)]
        fn worker_registry(&self) -> &Arc<northstar_runtime::workers::WorkerRegistry> {
            &self.workers
        }
        #[allow(clippy::too_many_arguments)]
        fn session_cleanup(self: Arc<Self>) -> Self::Cleanup {
            TestCleanup {
                events: Arc::clone(&self.events),
            }
        }
    }

    impl SessionTelemetryHost for TestHost {
        #[allow(clippy::too_many_arguments)]
        fn c2s_authentication_telemetry(
            &self,
        ) -> northstar_session_application::telemetry::C2sAuthenticationTelemetry<'_> {
            northstar_session_application::telemetry::C2sAuthenticationTelemetry::new(
                &self.counter,
                &self.counter,
                &self.counter,
                &self.counter,
            )
        }
        #[allow(clippy::too_many_arguments)]
        fn c2s_post_action_telemetry(
            &self,
        ) -> northstar_session_application::post_actions::PostActionTelemetry<'_> {
            northstar_session_application::post_actions::PostActionTelemetry::new(
                &self.counter,
                &self.counter,
                &self.counter,
                &self.counter,
                &self.counter,
            )
        }
        #[allow(clippy::too_many_arguments)]
        fn outbound_stanza_telemetry(
            &self,
        ) -> northstar_session_application::telemetry::OutboundStanzaTelemetry<'_> {
            northstar_session_application::telemetry::OutboundStanzaTelemetry::new(&self.counter)
        }
        #[allow(clippy::too_many_arguments)]
        fn push_subscription_telemetry(
            &self,
        ) -> northstar_session_application::telemetry::PushSubscriptionTelemetry<'_> {
            panic!("unexpected host call: push_subscription_telemetry")
        }
        #[allow(clippy::too_many_arguments)]
        fn record_bosh_session_closed(&self) {
            panic!("unexpected host call: record_bosh_session_closed")
        }
        #[allow(clippy::too_many_arguments)]
        fn record_c2s_backpressure_disconnect(&self) {
            panic!("unexpected host call: record_c2s_backpressure_disconnect")
        }
        #[allow(clippy::too_many_arguments)]
        fn registration_telemetry(
            &self,
        ) -> northstar_session_application::telemetry::RegistrationTelemetry<'_> {
            northstar_session_application::telemetry::RegistrationTelemetry::new(
                &self.counter,
                &self.counter,
                &self.counter,
                &self.counter,
            )
        }
        #[allow(clippy::too_many_arguments)]
        fn sasl2_authentication_telemetry(
            &self,
        ) -> northstar_session_application::telemetry::Sasl2AuthenticationTelemetry<'_> {
            northstar_session_application::telemetry::Sasl2AuthenticationTelemetry::new(
                &self.counter,
                &self.counter,
            )
        }
        #[allow(clippy::too_many_arguments)]
        fn sasl2_authentication_timer(&self) -> northstar_telemetry::metrics::OwnedDurationTimer {
            {
                self.events.lock().unwrap().push("authentication timer");
                self.timer.start_owned_timer()
            }
        }
        #[allow(clippy::too_many_arguments)]
        fn session_bind_telemetry(
            &self,
        ) -> northstar_session_application::telemetry::SessionBindTelemetry<'_> {
            northstar_session_application::telemetry::SessionBindTelemetry::new(
                &self.counter,
                &self.counter,
            )
        }
        #[allow(clippy::too_many_arguments)]
        fn session_drop_fallback_telemetry(
            &self,
        ) -> northstar_session_application::telemetry::SessionDropFallbackTelemetry<'_> {
            panic!("unexpected host call: session_drop_fallback_telemetry")
        }
        #[allow(clippy::too_many_arguments)]
        fn sm_session_telemetry(
            &self,
        ) -> northstar_session_application::telemetry::SmSessionTelemetry<'_> {
            northstar_session_application::telemetry::SmSessionTelemetry::new(
                &self.counter,
                &self.counter,
            )
        }
        #[allow(clippy::too_many_arguments)]
        fn caps_effect_telemetry(
            &self,
        ) -> northstar_session_application::telemetry::CapsEffectTelemetry<'_> {
            northstar_session_application::telemetry::CapsEffectTelemetry::new(
                &self.counter,
                &self.counter,
                &self.counter,
                &self.timer,
            )
        }
        #[allow(clippy::too_many_arguments)]
        fn push_delivery_telemetry(
            &self,
        ) -> northstar_session_application::telemetry::PushDeliveryTelemetry<'_> {
            panic!("unexpected host call: push_delivery_telemetry")
        }
        #[allow(clippy::too_many_arguments)]
        fn inbound_stanza_telemetry(
            &self,
        ) -> northstar_session_application::telemetry::InboundStanzaTelemetry<'_> {
            northstar_session_application::telemetry::InboundStanzaTelemetry::new(&self.counter)
        }
        #[allow(clippy::too_many_arguments)]
        fn account_abuse_telemetry(
            &self,
        ) -> northstar_session_application::telemetry::AccountAbuseTelemetry<'_> {
            panic!("unexpected host call: account_abuse_telemetry")
        }
    }
}

pub(super) struct TestHost {
    pub(super) repository: UnusedRepository,
    mam_enabled: bool,
    pub(super) events: Arc<Mutex<Vec<&'static str>>>,
    pub(super) routes: Arc<dashmap::DashMap<String, crate::local_routes::session::OnlineSession>>,
    workers: Arc<northstar_runtime::workers::WorkerRegistry>,
    counter: AtomicU64,
    pub(super) timer: Arc<northstar_telemetry::metrics::DurationHistogram>,
    account: northstar_auth_application::account::AccountService<UnusedRepository>,
    pub(super) authentication:
        northstar_auth_application::authentication::AuthenticationService<UnusedRepository>,
    challenge: northstar_abuse_application::challenge::ChallengeIssueService<UnusedRepository>,
    login: northstar_abuse_application::login::SaslLoginAbuseService<UnusedRepository>,
    sm_service: northstar_session_application::sm::SmService<UnusedRepository>,
    replay_service: northstar_session_application::replay::ReplayService<UnusedRepository>,
    governor: Arc<northstar_session_application::sm_capacity::SmMemoryGovernor>,
    pub(super) messages: Mutex<Vec<(String, String, Uuid)>>,
    pub(super) frames: Mutex<Vec<crate::frame_execution::FrameExecution>>,
    pub(super) caps: northstar_protocol_runtime::caps::CapsResourceIndex,
    caps_gates: northstar_protocol_runtime::caps::FederatedCapsGateIndex,
    caps_cache: northstar_protocol_runtime::caps::CapsCacheIndex,
    caps_dispatcher: Arc<northstar_protocol_runtime::caps::CapsEffectDispatcher>,
    pending_caps: northstar_protocol_runtime::caps::PendingCapsIndex,
    pub(super) resume_success: bool,
    pub(super) resume_contradiction: bool,
    pub(super) resume_error: bool,
}

impl TestHost {
    pub(super) fn replace_route(&self) {
        let (route, _receiver) = crate::local_routes::session::test_online_session(
            Uuid::from_u128(303),
            3,
            Uuid::from_u128(999),
            "captured",
            4,
        );
        self.routes
            .insert("fixture@example.test/captured".to_owned(), route);
    }

    pub(super) fn new() -> Arc<Self> {
        Self::with_auth_profile(true, false)
    }

    pub(super) fn with_auth_profile(mam_enabled: bool, stale_generation: bool) -> Arc<Self> {
        let events = Arc::new(Mutex::new(Vec::new()));
        let repository = UnusedRepository {
            events: Arc::clone(&events),
            stale_generation,
            archive_boundary_calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            binding: Arc::new(Mutex::new(None)),
            replay_calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            replay_finished: Arc::new(tokio::sync::Notify::new()),
        };
        Arc::new(Self {
            events,
            mam_enabled,
            routes: Arc::new(dashmap::DashMap::new()),
            workers: northstar_runtime::workers::WorkerRegistry::new(),
            counter: AtomicU64::new(0),
            messages: Mutex::new(Vec::new()),
            frames: Mutex::new(Vec::new()),
            caps: northstar_protocol_runtime::caps::CapsResourceIndex::new(),
            caps_gates: northstar_protocol_runtime::caps::FederatedCapsGateIndex::new(),
            caps_cache: northstar_protocol_runtime::caps::CapsCacheIndex::new(),
            caps_dispatcher: northstar_protocol_runtime::caps::CapsEffectDispatcher::with_limits(
                4, 2,
            ),
            pending_caps: northstar_protocol_runtime::caps::PendingCapsIndex::new(),
            resume_success: false,
            resume_contradiction: false,
            resume_error: false,
            timer: Arc::new(northstar_telemetry::metrics::DurationHistogram::default()),
            account: northstar_auth_application::account::AccountService::new(
                repository.clone(),
                false,
                10,
                4096,
                false,
            ),
            authentication: northstar_auth_application::authentication::AuthenticationService::new(
                repository.clone(),
                Arc::new(Zeroizing::new(vec![0; 32])),
                4096,
                false,
            ),
            challenge: northstar_abuse_application::challenge::ChallengeIssueService::new(
                repository.clone(),
            ),
            login: northstar_abuse_application::login::SaslLoginAbuseService::new(
                repository.clone(),
            ),
            sm_service: northstar_session_application::sm::SmService::new(
                repository.clone(),
                "owner_tests".to_owned(),
            )
            .unwrap(),
            replay_service: northstar_session_application::replay::ReplayService::new(
                repository.clone(),
                "example.test",
                30,
            ),
            repository,
            governor: northstar_session_application::sm_capacity::SmMemoryGovernor::new(
                65536,
                32768,
                4,
                32768,
                Arc::new(northstar_session_application::sm_capacity::SmCapacityMetrics::default()),
            )
            .unwrap(),
        })
    }

    pub(super) fn session(self: &Arc<Self>) -> ProtocolSession<Self> {
        let (sender, _receiver) = tokio::sync::mpsc::channel(4);
        let mut session = ProtocolSession::new(
            Arc::clone(self),
            crate::outbound::OutboundSender::new(sender),
            true,
            ClientTransport::Bosh,
            None,
            "192.0.2.8".parse().unwrap(),
        );
        session.connection_id = Uuid::from_u128(302);
        session
    }
}

pub(super) struct TestCleanup {
    events: Arc<Mutex<Vec<&'static str>>>,
}

impl crate::session_cleanup::SessionCleanup for TestCleanup {
    type Quiesced = crate::session_cleanup::SessionCleanupPlan;
    fn quiesce(&self, plan: Self::Quiesced) -> Self::Quiesced {
        self.events.lock().unwrap().push("quiesce");
        plan
    }
    async fn finish(&self, _: Self::Quiesced) -> crate::session_cleanup::CleanupReport {
        self.events.lock().unwrap().push("finish");
        crate::session_cleanup::CleanupReport::default()
    }
    async fn clear_transferred_privacy(
        &self,
        _: Option<&northstar_session_application::SessionCleanupAccount>,
        _: Uuid,
    ) -> crate::session_cleanup::CleanupReport {
        panic!("ordinary finalization must not clear transferred privacy")
    }
}

mod caps_events;
mod occupant_iq;
