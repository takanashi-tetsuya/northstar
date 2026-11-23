use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub(super) struct UnusedRepository {
    pub(super) events: Arc<Mutex<Vec<&'static str>>>,
    pub(super) stale_generation: bool,
    pub(super) archive_boundary_calls: Arc<std::sync::atomic::AtomicUsize>,
    pub(super) binding: Arc<Mutex<Option<String>>>,
    pub(super) replay_calls: Arc<std::sync::atomic::AtomicUsize>,
    pub(super) replay_finished: Arc<tokio::sync::Notify>,
}

mod account_ports {
    use super::UnusedRepository;
    use anyhow::Result;
    use northstar_auth_application::account::*;
    use uuid::Uuid;

    impl AccountRepository for UnusedRepository {
        #[allow(clippy::too_many_arguments)]
        async fn register_http(
            &self,
            _request: HttpRegistrationRequest<'_>,
            _policy: AccountPolicy,
        ) -> Result<HttpRegistrationOutcome> {
            panic!("unexpected port call: register_http")
        }

        #[allow(clippy::too_many_arguments)]
        async fn verify_registration_guard(
            &self,
            _request: RegistrationGuardRequest<'_>,
        ) -> Result<RegistrationGuardOutcome> {
            panic!("unexpected port call: verify_registration_guard")
        }

        #[allow(clippy::too_many_arguments)]
        async fn register(
            &self,
            _request: RegistrationRequest<'_>,
            _policy: AccountPolicy,
            _password_work: northstar_security::password_work::PasswordWorkReservation,
        ) -> Result<RegistrationOutcome> {
            assert_eq!(_request.username, "fixture");
            assert_eq!(_request.password, "correct-horse-battery");
            assert_eq!(_request.invitation_token, None);
            assert_eq!(
                _request.intent,
                &northstar_abuse_policy::PowIntent::xmpp_registration(
                    "fixture",
                    "correct-horse-battery",
                    None
                )
            );
            assert_eq!(_request.subject, "registration:192.0.2.8");
            assert_eq!(_request.actors, ["ip:192.0.2.8"]);
            if let Some(proof) = _request.proof {
                assert_eq!(proof.challenge_id, Uuid::from_u128(0x55));
                assert_eq!(proof.nonce, "42");
            }
            self.events.lock().unwrap().push("registration guard");
            Ok(RegistrationOutcome::AbuseDenied(
                super::registration_requirement(),
            ))
        }

        #[allow(clippy::too_many_arguments)]
        async fn change_password(
            &self,
            _request: PasswordChangeRequest<'_>,
            _policy: AccountPolicy,
        ) -> Result<PasswordChangeOutcome> {
            assert_eq!(_request.user_id, Uuid::from_u128(303));
            assert_eq!(_request.expected_auth_generation, 2);
            assert_eq!(_request.password, "correct-horse-battery");
            assert_eq!(_request.proof.unwrap().nonce, "42");
            assert_eq!(_request.intent, &northstar_abuse_policy::PowIntent::xmpp(
            northstar_abuse_policy::AbuseAction::PasswordChange, "/xmpp/password-change",
            b"<query xmlns='jabber:iq:register'><password>correct-horse-battery</password></query>",
        ));
            self.events.lock().unwrap().push("password guarded");
            Ok(PasswordChangeOutcome::PasswordWorkOverloaded)
        }

        #[allow(clippy::too_many_arguments)]
        async fn quiesce_for_deletion(
            &self,
            _request: DeletionQuiesceRequest<'_>,
        ) -> Result<DeletionQuiesceOutcome> {
            assert_eq!(_request.user_id, Uuid::from_u128(303));
            assert_eq!(_request.expected_auth_generation, 2);
            assert_eq!(_request.proof.unwrap().nonce, "42");
            assert_eq!(
                _request.intent,
                &northstar_abuse_policy::PowIntent::xmpp(
                    northstar_abuse_policy::AbuseAction::PasswordChange,
                    "/xmpp/account-remove",
                    b"<query xmlns='jabber:iq:register'><remove/></query>",
                )
            );
            self.events.lock().unwrap().push("deletion guarded");
            Ok(DeletionQuiesceOutcome::Missing)
        }

        #[allow(clippy::too_many_arguments)]
        async fn delete_quiesced(&self, _user_id: Uuid) -> Result<Option<RemovedAccount>> {
            panic!("unexpected port call: delete_quiesced")
        }

        #[allow(clippy::too_many_arguments)]
        async fn claim_deletion_recovery(
            &self,
            _limit: i64,
            _lease_seconds: i64,
        ) -> Result<Vec<DeletionRecoveryJob>> {
            panic!("unexpected port call: claim_deletion_recovery")
        }

        #[allow(clippy::too_many_arguments)]
        async fn release_deletion_recovery(
            &self,
            _job: &DeletionRecoveryJob,
            _error_code: &str,
        ) -> Result<bool> {
            panic!("unexpected port call: release_deletion_recovery")
        }
    }
}

mod authentication_ports {
    use super::UnusedRepository;
    use northstar_auth_application::authentication::*;
    use northstar_auth_core as auth;
    use uuid::Uuid;

    impl AuthenticationRepository for UnusedRepository {
        #[allow(clippy::too_many_arguments)]
        async fn scram_credentials(
            &self,
            _username: &str,
            _algorithm: auth::ScramAlgorithm,
        ) -> AuthenticationResult<ScramCredentialSet> {
            panic!("unexpected port call: scram_credentials")
        }

        #[allow(clippy::too_many_arguments)]
        async fn authenticate_plain(
            &self,
            _username: &str,
            _password: &str,
            _policy: AuthenticationPolicy,
        ) -> AuthenticationResult<AuthenticatedAccount> {
            panic!("unexpected port call: authenticate_plain")
        }

        #[allow(clippy::too_many_arguments)]
        async fn account_by_id(&self, _user_id: Uuid) -> anyhow::Result<Option<LoadedAccount>> {
            panic!("unexpected port call: account_by_id")
        }

        #[allow(clippy::too_many_arguments)]
        async fn account_by_username(
            &self,
            _username: &str,
        ) -> anyhow::Result<Option<LoadedAccount>> {
            panic!("unexpected port call: account_by_username")
        }

        #[allow(clippy::too_many_arguments)]
        async fn generation_state(&self, _fence: AuthenticationFence) -> AuthenticationResult<()> {
            assert_eq!(_fence.user_id, Uuid::from_u128(303));
            assert_eq!(_fence.auth_generation, 2);
            if self.stale_generation {
                AuthenticationResult::StaleGeneration
            } else {
                AuthenticationResult::Authenticated(())
            }
        }

        #[allow(clippy::too_many_arguments)]
        async fn bind2_archive_boundaries(
            &self,
            _user_id: Uuid,
            _expected_auth_generation: i64,
        ) -> AuthenticationResult<(Option<ArchiveBoundary>, Option<ArchiveBoundary>)> {
            assert_eq!(_user_id, Uuid::from_u128(303));
            assert_eq!(_expected_auth_generation, 2);
            self.archive_boundary_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let start = ArchiveBoundary {
                id: Uuid::from_u128(1),
                created_at: northstar_time::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            };
            let end = ArchiveBoundary {
                id: Uuid::from_u128(2),
                created_at: northstar_time::DateTime::from_timestamp(1_700_000_001, 0).unwrap(),
            };
            AuthenticationResult::Authenticated((Some(start), Some(end)))
        }

        #[allow(clippy::too_many_arguments)]
        async fn authenticate_fast(
            &self,
            _request: FastProofRequest<'_>,
        ) -> AuthenticationResult<FastAuthenticationSuccess> {
            panic!("unexpected port call: authenticate_fast")
        }

        #[allow(clippy::too_many_arguments)]
        async fn commit_fast_with_login_epoch(
            &self,
            _user_id: Uuid,
            _expected_auth_generation: i64,
            _plan: &FastCommitPlan,
            _device_id: Option<Uuid>,
            _connection_id: Uuid,
        ) -> AuthenticationResult<CredentialCommitReceipt> {
            panic!("unexpected port call: commit_fast_with_login_epoch")
        }

        #[allow(clippy::too_many_arguments)]
        async fn commit_fast_with_login_epoch_observed(
            &self,
            _user_id: Uuid,
            _expected_auth_generation: i64,
            _plan: &FastCommitPlan,
            _device_id: Option<Uuid>,
            _connection_id: Uuid,
            _invocation: &publication::CredentialInvocation<'_>,
        ) -> AuthenticationResult<CredentialCommitReceipt> {
            use publication::{CredentialInvocation, CredentialPreparation, PreparationResult};
            assert_eq!(_user_id, Uuid::from_u128(303));
            assert_eq!(_expected_auth_generation, 2);
            assert_eq!(_device_id, None);
            assert_eq!(_connection_id, Uuid::from_u128(302));
            _invocation
                .enter_fast(
                    _user_id,
                    _expected_auth_generation,
                    _plan,
                    _device_id,
                    _connection_id,
                )
                .unwrap();
            CredentialInvocation::begin(Some(_invocation), std::future::ready(Ok::<(), ()>(())))
                .await
                .unwrap();
            CredentialInvocation::eligibility(
                Some(_invocation),
                std::future::ready(Ok::<_, ()>(Some(true))),
            )
            .await
            .unwrap();
            _invocation.transaction_returned();
            _invocation.preparation_entered(CredentialPreparation::Stage);
            _invocation.stage_returned(&Ok(None));
            _invocation.preparation_entered(CredentialPreparation::Fast);
            _invocation
                .preparation_returned(CredentialPreparation::Fast, PreparationResult::Present);
            CredentialInvocation::commit(Some(_invocation), std::future::ready(Ok::<(), ()>(())))
                .await
                .unwrap();
            let receipt = CredentialCommitReceipt::new(None, None, None);
            _invocation.constructed(&receipt);
            self.events.lock().unwrap().push("unbound committed");
            AuthenticationResult::Authenticated(receipt)
        }

        #[allow(clippy::too_many_arguments)]
        async fn publish_credential_commit(
            &self,
            _receipt: &CredentialCommitReceipt,
        ) -> AuthenticationResult<Option<i64>> {
            panic!("unexpected port call: publish_credential_commit")
        }

        #[allow(clippy::too_many_arguments)]
        async fn publish_credential_commit_observed(
            &self,
            _invocation: &publication::Invocation<'_>,
        ) -> AuthenticationResult<Option<i64>> {
            self.events.lock().unwrap().push("publication repository");
            _invocation.enter_repository().unwrap();
            _invocation
                .commit(std::future::ready(Ok::<(), std::io::Error>(())), Some(7))
                .await
                .unwrap();
            AuthenticationResult::Authenticated(Some(7))
        }
    }
}

mod challenge_ports {
    use super::UnusedRepository;
    use anyhow::Result;
    use northstar_abuse_application::challenge::*;
    use northstar_abuse_policy::PowChallenge;

    impl ChallengeIssueRepository for UnusedRepository {
        #[allow(clippy::too_many_arguments)]
        async fn issue(&self, _request: ChallengeIssueRequest<'_>) -> Result<PowChallenge> {
            assert_eq!(
                _request.action,
                northstar_abuse_policy::AbuseAction::Registration
            );
            assert_eq!(_request.subject, "registration:192.0.2.8");
            assert_eq!(_request.actors, ["ip:192.0.2.8"]);
            let intent = _request
                .intent
                .expect("registration challenge must be body-bound");
            assert_eq!(
                intent,
                &northstar_abuse_policy::PowIntent::xmpp_registration(
                    "fixture",
                    "correct-horse-battery",
                    None
                )
            );
            self.events.lock().unwrap().push("registration challenge");
            Ok(PowChallenge {
                version: 2,
                challenge_id: uuid::Uuid::from_u128(0x55),
                prefix: "test-prefix".to_owned(),
                key_id: "test-key".to_owned(),
                server_nonce: "test-nonce".to_owned(),
                issued_at: northstar_time::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
                expires_at: northstar_time::DateTime::from_timestamp(1_700_000_300, 0).unwrap(),
                expires_in_seconds: 300,
                intent: Some(intent.view()),
                requirement: super::registration_requirement(),
            })
        }
    }
}

mod login_ports {
    use super::UnusedRepository;
    use anyhow::Result;
    use northstar_abuse_application::login::*;
    use northstar_abuse_policy::WorkRequirement;

    impl SaslLoginAbuseRepository for UnusedRepository {
        #[allow(clippy::too_many_arguments)]
        async fn current_requirement(&self, _actors: &[String]) -> Result<WorkRequirement> {
            panic!("unexpected port call: current_requirement")
        }

        #[allow(clippy::too_many_arguments)]
        async fn record_failure(&self, _actors: &[String]) -> Result<()> {
            panic!("unexpected port call: record_failure")
        }
    }
}

mod sm_ports {
    use super::UnusedRepository;
    use anyhow::Result;
    use northstar_config::SmIpPolicy;
    use northstar_session_application::sm::*;
    use northstar_session_core::publication::CredentialInvocation;
    use uuid::Uuid;

    impl SmRepository for UnusedRepository {
        #[allow(clippy::too_many_arguments)]
        async fn revoke_session(&self, _session_id: Uuid) -> Result<()> {
            panic!("unexpected port call: revoke_session")
        }

        #[allow(clippy::too_many_arguments)]
        async fn create_session(
            &self,
            _request: SmSessionCreationRequest<'_>,
        ) -> Result<SmSessionCreationOutcome> {
            panic!("unexpected port call: create_session")
        }

        #[allow(clippy::too_many_arguments)]
        async fn claim_resume(
            &self,
            _request: SmResumeClaimRequest<'_>,
            _ip_policy: SmIpPolicy,
        ) -> Result<SmResumeClaimOutcome> {
            assert_eq!(_request.user_id, Uuid::from_u128(303));
            assert_eq!(
                _request.peer_ip,
                "192.0.2.8".parse::<std::net::IpAddr>().unwrap()
            );
            assert_eq!(_request.claim_lease_seconds, 10);
            self.events.lock().unwrap().push("resume claimed");
            Ok(SmResumeClaimOutcome::Claimed(Box::new(SmResumeClaim {
                session_id: Uuid::from_u128(401),
                claim_token: Uuid::from_u128(402),
                claim_deadline: std::time::Instant::now() + std::time::Duration::from_secs(60),
                full_jid: "fixture@example.test/captured".to_owned(),
                resource: "captured".to_owned(),
                resume_timeout_seconds: 60,
                inbound_h: 5,
                acked_h: 3,
                available: false,
                carbons: false,
                priority: 0,
                blocklist_requested: false,
                roster_requested: false,
                active_privacy_list: Some("captured-privacy".to_owned()),
                privacy_requested: true,
                user_agent_id: None,
                joined_rooms: vec![],
                directed_presence: vec![],
                last_presence: None,
                unacked: vec![],
            })))
        }

        #[allow(clippy::too_many_arguments)]
        async fn checkpoint_session(
            &self,
            _session_id: Uuid,
            _connection_id: Uuid,
            _snapshot: &SmSessionSnapshot,
            _ttl_seconds: u64,
            _live_lease_seconds: u64,
            _max_stanzas: usize,
            _max_bytes: usize,
            _observation: Option<&ownership::PreparedCheckpoint<'_>>,
        ) -> Result<SmCheckpointOutcome> {
            assert_eq!(_session_id, Uuid::from_u128(401));
            assert_eq!(_connection_id, Uuid::from_u128(302));
            assert!(_observation.is_none());
            Ok(SmCheckpointOutcome {
                updated: true,
                ownership: SmQueueOwnershipResolution::default(),
            })
        }

        #[allow(clippy::too_many_arguments)]
        async fn remove_live_muc_memberships(
            &self,
            _session_id: Uuid,
            _connection_id: Uuid,
            _memberships: &[SmMucMembership],
        ) -> Result<bool> {
            panic!("unexpected port call: remove_live_muc_memberships")
        }

        #[allow(clippy::too_many_arguments)]
        async fn checkpoint_and_acknowledge(
            &self,
            _session_id: Uuid,
            _connection_id: Uuid,
            _snapshot: &SmSessionSnapshot,
            _acknowledged: &[northstar_delivery_core::SmUnackedStanza],
            _ttl_seconds: u64,
            _live_lease_seconds: u64,
            _max_stanzas: usize,
            _max_bytes: usize,
            _observation: Option<&ownership::PreparedCheckpoint<'_>>,
        ) -> Result<SmCheckpointOutcome> {
            panic!("unexpected port call: checkpoint_and_acknowledge")
        }

        #[allow(clippy::too_many_arguments)]
        async fn acknowledge_delivery_batch(
            &self,
            _sources: &[northstar_delivery_core::TransportOwnershipSource],
            _observation: Option<&ownership::PreparedBatch<'_>>,
        ) -> Result<()> {
            assert!(_sources.is_empty());
            _observation.unwrap().request().no_persistence().unwrap();
            Ok(())
        }

        #[allow(clippy::too_many_arguments)]
        async fn reserve_binding(
            &self,
            _connection_id: Uuid,
            _user_id: Uuid,
            _expected_auth_generation: i64,
            _full_jid: &str,
            _lease_seconds: u64,
        ) -> Result<BindingReservationOutcome> {
            assert_eq!(_connection_id, Uuid::from_u128(302));
            assert_eq!(_user_id, Uuid::from_u128(303));
            assert_eq!(_expected_auth_generation, 2);
            assert!(
                _full_jid == "fixture@example.test/captured"
                    || _full_jid.starts_with("fixture@example.test/captured/")
            );
            *self.binding.lock().unwrap() = Some(_full_jid.to_owned());
            assert_eq!(_lease_seconds, 30);
            self.events.lock().unwrap().push("bind reserved");
            Ok(BindingReservationOutcome::Reserved)
        }

        #[allow(clippy::too_many_arguments)]
        async fn finalize_binding(
            &self,
            _connection_id: Uuid,
            _user_id: Uuid,
            _expected_auth_generation: i64,
            _full_jid: &str,
            _lease_seconds: u64,
            _device_id: Option<Uuid>,
            _fast_plan: Option<&northstar_auth_core::credential::FastCommitPlan>,
        ) -> Result<BindingFinalizationOutcome> {
            panic!("unexpected port call: finalize_binding")
        }

        #[allow(clippy::too_many_arguments)]
        async fn finalize_resume(
            &self,
            _request: SmResumeFinalizationRequest<'_>,
        ) -> Result<SmResumeFinalizationOutcome> {
            panic!("unexpected port call: finalize_resume")
        }

        #[allow(clippy::too_many_arguments)]
        async fn finalize_binding_observed(
            &self,
            _connection_id: Uuid,
            _user_id: Uuid,
            _expected_auth_generation: i64,
            _full_jid: &str,
            _lease_seconds: u64,
            _device_id: Option<Uuid>,
            _fast_plan: Option<&northstar_auth_core::credential::FastCommitPlan>,
            _invocation: &CredentialInvocation<'_>,
        ) -> Result<BindingFinalizationOutcome> {
            panic!("unexpected port call: finalize_binding_observed")
        }

        #[allow(clippy::too_many_arguments)]
        async fn finalize_resume_observed(
            &self,
            _request: SmResumeFinalizationRequest<'_>,
            _invocation: &CredentialInvocation<'_>,
        ) -> Result<SmResumeFinalizationOutcome> {
            panic!("unexpected port call: finalize_resume_observed")
        }

        #[allow(clippy::too_many_arguments)]
        async fn release_claim(&self, _session_id: Uuid, _claim_token: Uuid) -> Result<()> {
            assert_eq!(_session_id, Uuid::from_u128(401));
            assert_eq!(_claim_token, Uuid::from_u128(402));
            self.events.lock().unwrap().push("resume released");
            Ok(())
        }

        #[allow(clippy::too_many_arguments)]
        async fn release_live_session(&self, _connection_id: Uuid) -> Result<bool> {
            assert_eq!(_connection_id, Uuid::from_u128(302));
            self.events.lock().unwrap().push("bind released");
            Ok(true)
        }

        #[allow(clippy::too_many_arguments)]
        async fn suspend_exact_session(
            &self,
            _session_id: Uuid,
            _connection_id: Uuid,
            _user_id: Uuid,
            _expected_auth_generation: i64,
            _snapshot: &SmSessionSnapshot,
            _ttl_seconds: u64,
            _max_stanzas: usize,
            _max_bytes: usize,
        ) -> Result<bool> {
            panic!("unexpected port call: suspend_exact_session")
        }
    }
}

mod replay_ports {
    use super::UnusedRepository;
    use anyhow::Result;
    use northstar_session_application::replay::*;
    use northstar_time::{DateTime, Utc};
    use uuid::Uuid;

    impl ReplayLeaseRepository for UnusedRepository {
        #[allow(clippy::too_many_arguments)]
        async fn username(&self, _recipient_id: Uuid) -> Result<Option<String>> {
            assert_eq!(_recipient_id, Uuid::from_u128(303));
            Ok(Some("fixture".to_owned()))
        }

        #[allow(clippy::too_many_arguments)]
        async fn acquire_lease(
            &self,
            _recipient_id: Uuid,
            _resource: &str,
            _owner_token: Uuid,
            _cutoff: Option<DateTime<Utc>>,
            _lease_seconds: i64,
        ) -> Result<OfflineReplayLeaseAcquire> {
            assert_eq!(_recipient_id, Uuid::from_u128(303));
            assert_eq!(
                format!("fixture@example.test/{_resource}"),
                self.binding.lock().unwrap().as_ref().unwrap().as_str()
            );
            assert_eq!(_cutoff, None);
            assert_eq!(_lease_seconds, 90);
            let attempt = self
                .replay_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if attempt == 0 {
                self.events.lock().unwrap().push("replay busy");
                Ok(OfflineReplayLeaseAcquire::BusyUntil(
                    OfflineReplayBusyUntil {
                        expires_at: DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
                        retry_after: std::time::Duration::ZERO,
                    },
                ))
            } else {
                assert_eq!(attempt, 1);
                self.events.lock().unwrap().push("replay acquired");
                Ok(OfflineReplayLeaseAcquire::Acquired(OfflineReplayLease {
                    recipient_id: _recipient_id,
                    resource: _resource.to_owned(),
                    owner_token: _owner_token,
                    replay_started_at: DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
                }))
            }
        }
    }
    impl ReplayRepository for UnusedRepository {
        #[allow(clippy::too_many_arguments)]
        async fn claim_page(
            &self,
            _session: &ReplaySession,
            _active_privacy_list: Option<&str>,
            _bind2_mam_catchup: bool,
            _offline_ttl_days: i64,
        ) -> Result<ReplayPageOutcome> {
            assert_eq!(
                _session.owner_full_jid(),
                self.binding.lock().unwrap().as_ref().unwrap().as_str()
            );
            assert_eq!(_active_privacy_list, None);
            assert!(_bind2_mam_catchup);
            assert_eq!(_offline_ttl_days, 30);
            self.events.lock().unwrap().push("replay page");
            Ok(ReplayPageOutcome::Empty)
        }

        #[allow(clippy::too_many_arguments)]
        async fn renew_before_send(
            &self,
            _session: &ReplaySession,
            _page_claim_token: Uuid,
            _pending_ids: &[Uuid],
        ) -> Result<bool> {
            panic!("unexpected port call: renew_before_send")
        }

        #[allow(clippy::too_many_arguments)]
        async fn release_unsent(
            &self,
            _session: &ReplaySession,
            _page_claim_token: Uuid,
            _message_ids: &[Uuid],
        ) -> Result<u64> {
            panic!("unexpected port call: release_unsent")
        }

        #[allow(clippy::too_many_arguments)]
        async fn finish(&self, _session: &ReplaySession) -> Result<bool> {
            assert_eq!(
                _session.owner_full_jid(),
                self.binding.lock().unwrap().as_ref().unwrap().as_str()
            );
            self.events.lock().unwrap().push("replay finish");
            self.replay_finished.notify_one();
            Ok(true)
        }

        #[allow(clippy::too_many_arguments)]
        async fn pending_presence_page(
            &self,
            _recipient_id: Uuid,
            _owner_bare_jid: &str,
            _active_privacy_list: Option<&str>,
            _after: Option<&PendingPresenceCursor>,
            _domain: &str,
        ) -> Result<PendingPresencePage> {
            panic!("unexpected port call: pending_presence_page")
        }

        #[allow(clippy::too_many_arguments)]
        async fn fence_socket_write(
            &self,
            _delivery: northstar_delivery_core::DurableDelivery,
        ) -> Result<northstar_delivery_core::DurableDelivery> {
            panic!("unexpected port call: fence_socket_write")
        }

        #[allow(clippy::too_many_arguments)]
        async fn acknowledge_socket_write(
            &self,
            _delivery: northstar_delivery_core::DurableDelivery,
            _observation: Option<&northstar_delivery_core::native_write::AckRequest>,
        ) -> Result<()> {
            panic!("unexpected port call: acknowledge_socket_write")
        }

        #[allow(clippy::too_many_arguments)]
        async fn renew_bosh_fences(
            &self,
            _request: &northstar_delivery_core::bosh_ownership::response::RenewRequest,
        ) -> Result<()> {
            panic!("unexpected port call: renew_bosh_fences")
        }

        #[allow(clippy::too_many_arguments)]
        async fn acknowledge_bosh_responses(
            &self,
            _request: &northstar_delivery_core::bosh_ownership::response::AckRequest,
        ) -> Result<()> {
            panic!("unexpected port call: acknowledge_bosh_responses")
        }

        #[allow(clippy::too_many_arguments)]
        async fn bind_bosh_response_sources(
            &self,
            _request: &northstar_delivery_core::bosh_ownership::response::BindRequest,
        ) -> Result<northstar_delivery_core::bosh_ownership::BoshResponseOwnership> {
            panic!("unexpected port call: bind_bosh_response_sources")
        }

        #[allow(clippy::too_many_arguments)]
        async fn release_bosh_fences(&self, _session_id: Uuid) -> Result<()> {
            panic!("unexpected port call: release_bosh_fences")
        }
    }
}

mod presence_ports {
    use super::UnusedRepository;
    use anyhow::Result;
    use northstar_roster_application::presence::*;
    use northstar_time::{DateTime, Utc};
    use uuid::Uuid;

    impl PresenceRepository for UnusedRepository {
        #[allow(clippy::too_many_arguments)]
        async fn roster_subscriptions(&self, _owner_id: Uuid) -> Result<Vec<(String, String)>> {
            panic!("unexpected port call: roster_subscriptions")
        }

        #[allow(clippy::too_many_arguments)]
        async fn is_blocked_for_account(
            &self,
            _owner_id: Uuid,
            _owner_bare_jid: &str,
            _candidate: &str,
        ) -> Result<bool> {
            panic!("unexpected port call: is_blocked_for_account")
        }

        #[allow(clippy::too_many_arguments)]
        async fn privacy_denies(
            &self,
            _owner_id: Uuid,
            _active_list: Option<&str>,
            _candidate: &str,
            _kind: northstar_xep_0016::PrivacyStanzaKind,
        ) -> Result<bool> {
            panic!("unexpected port call: privacy_denies")
        }

        #[allow(clippy::too_many_arguments)]
        async fn avatar_hash(&self, _user_id: Uuid) -> Result<Option<String>> {
            panic!("unexpected port call: avatar_hash")
        }

        #[allow(clippy::too_many_arguments)]
        async fn find_enabled_user(&self, _username: &str) -> Result<Option<PresenceAccount>> {
            panic!("unexpected port call: find_enabled_user")
        }

        #[allow(clippy::too_many_arguments)]
        async fn roster_subscription(
            &self,
            _owner_id: Uuid,
            _contact: &str,
        ) -> Result<Option<String>> {
            panic!("unexpected port call: roster_subscription")
        }

        #[allow(clippy::too_many_arguments)]
        async fn replay_cutoff(&self) -> Result<DateTime<Utc>> {
            panic!("unexpected port call: replay_cutoff")
        }

        #[allow(clippy::too_many_arguments)]
        async fn claim_service_messages(&self, _user_id: Uuid) -> Result<Vec<ServiceMessageClaim>> {
            panic!("unexpected port call: claim_service_messages")
        }

        #[allow(clippy::too_many_arguments)]
        async fn complete_service_message_claim(
            &self,
            _user_id: Uuid,
            _claim: &ServiceMessageClaim,
        ) -> Result<bool> {
            panic!("unexpected port call: complete_service_message_claim")
        }

        #[allow(clippy::too_many_arguments)]
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
            _policy: northstar_roster_application::S2sOutboxPolicy,
        ) -> Result<PresenceMutation<RemoteSubscriptionTransition>> {
            panic!("unexpected port call: transition_remote_with_outbox")
        }

        #[allow(clippy::too_many_arguments)]
        async fn transition_remote(
            &self,
            _actor_id: Uuid,
            _expected_auth_generation: i64,
            _connection_id: Uuid,
            _local_domain: &str,
            _contact: &str,
            _kind: &str,
        ) -> Result<PresenceMutation<RemoteSubscriptionTransition>> {
            panic!("unexpected port call: transition_remote")
        }

        #[allow(clippy::too_many_arguments)]
        async fn transition_local(
            &self,
            _request: LocalSubscriptionRequest<'_>,
        ) -> Result<PresenceMutation<LocalSubscriptionTransition>> {
            panic!("unexpected port call: transition_local")
        }

        #[allow(clippy::too_many_arguments)]
        async fn transition_inbound(
            &self,
            _recipient_id: Uuid,
            _local_domain: &str,
            _contact: &str,
            _kind: &str,
            _stanza: &str,
        ) -> Result<PresenceMutation<InboundSubscriptionTransition>> {
            panic!("unexpected port call: transition_inbound")
        }

        #[allow(clippy::too_many_arguments)]
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
            panic!("unexpected port call: cluster_authority_is_current")
        }
    }
}

mod privacy_ports {
    use super::UnusedRepository;
    use anyhow::Result;
    use northstar_roster_application::privacy::*;
    use uuid::Uuid;

    impl PrivacyRepository for UnusedRepository {
        #[allow(clippy::too_many_arguments)]
        async fn clear_active_session(&self, _owner_id: Uuid, _connection_id: Uuid) -> Result<()> {
            panic!("unexpected port call: clear_active_session")
        }

        #[allow(clippy::too_many_arguments)]
        async fn overview(&self, _owner_id: Uuid) -> Result<PrivacyOverview> {
            panic!("unexpected port call: overview")
        }

        #[allow(clippy::too_many_arguments)]
        async fn list(&self, _owner_id: Uuid, _name: &str) -> Result<Option<PrivacyList>> {
            panic!("unexpected port call: list")
        }

        #[allow(clippy::too_many_arguments)]
        async fn select_active(
            &self,
            _owner_id: Uuid,
            _connection_id: Uuid,
            _name: Option<&str>,
        ) -> Result<PrivacySelectionOutcome> {
            panic!("unexpected port call: select_active")
        }

        #[allow(clippy::too_many_arguments)]
        async fn select_default(
            &self,
            _owner_id: Uuid,
            _name: Option<&str>,
        ) -> Result<PrivacySelectionOutcome> {
            panic!("unexpected port call: select_default")
        }

        #[allow(clippy::too_many_arguments)]
        async fn replace_list(
            &self,
            _owner_id: Uuid,
            _list: &PrivacyList,
        ) -> Result<PrivacyListMutationOutcome> {
            panic!("unexpected port call: replace_list")
        }

        #[allow(clippy::too_many_arguments)]
        async fn remove_list(
            &self,
            _owner_id: Uuid,
            _name: &str,
        ) -> Result<PrivacyListMutationOutcome> {
            panic!("unexpected port call: remove_list")
        }

        #[allow(clippy::too_many_arguments)]
        async fn denies(
            &self,
            _owner_id: Uuid,
            _active_privacy_list: Option<&str>,
            _candidate: &str,
            _kind: PrivacyStanzaKind,
        ) -> Result<bool> {
            panic!("unexpected port call: denies")
        }
    }
}

mod push_ports {
    use super::UnusedRepository;
    use anyhow::Result;
    use northstar_message_application::push::*;
    use uuid::Uuid;

    impl PushRepository for UnusedRepository {
        #[allow(clippy::too_many_arguments)]
        async fn enable(
            &self,
            _user_id: Uuid,
            _service_jid: &str,
            _node: &str,
            _options: Option<&str>,
        ) -> Result<PushEnableOutcome> {
            panic!("unexpected port call: enable")
        }

        #[allow(clippy::too_many_arguments)]
        async fn disable(
            &self,
            _user_id: Uuid,
            _service_jid: &str,
            _node: Option<&str>,
        ) -> Result<u64> {
            panic!("unexpected port call: disable")
        }

        #[allow(clippy::too_many_arguments)]
        async fn claim_batch(&self, _user_id: Uuid) -> Result<PushBatch> {
            panic!("unexpected port call: claim_batch")
        }

        #[allow(clippy::too_many_arguments)]
        async fn mark_unroutable(&self, _request_id: Uuid) -> Result<()> {
            panic!("unexpected port call: mark_unroutable")
        }

        #[allow(clippy::too_many_arguments)]
        async fn complete_response(
            &self,
            _request_id: Uuid,
            _sender_bare: &str,
            _kind: PushResponseKind,
        ) -> Result<PushResponseOutcome> {
            panic!("unexpected port call: complete_response")
        }

        #[allow(clippy::too_many_arguments)]
        async fn disable_from_service(
            &self,
            _target_username: &str,
            _service_jid: &str,
            _node: &str,
        ) -> Result<bool> {
            panic!("unexpected port call: disable_from_service")
        }
    }
}

mod pam_delivery_repository;

mod mix_ports {
    use super::UnusedRepository;
    use anyhow::Result;
    use northstar_federation_core::S2sOutboxPolicy;
    use northstar_room_application::mix_service::*;
    use northstar_time::{DateTime, Utc};
    use uuid::Uuid;

    impl MixMamReadRepository for UnusedRepository {
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

    impl MixRepository for UnusedRepository {
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
        async fn mix_muc_mirror_for_mix(
            &self,
            _mix_channel_id: Uuid,
        ) -> Result<Option<MixMucMirror>> {
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

    impl MixPamRepository for UnusedRepository {
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

    impl MixDeliveryRepository for UnusedRepository {
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
            _request: &northstar_delivery_core::bosh_ownership::TransferRequest,
        ) -> Result<northstar_delivery_core::MixDelivery> {
            panic!("unexpected port call: transfer_mix_delivery_to_bosh")
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
}

impl crate::local_routes::muc::RestoredMucOccupancy for UnusedRepository {
    fn failures(&self) -> &[northstar_session_application::sm::SmMucMembership] {
        &[]
    }
    fn replay_suffix(&self) -> &[String] {
        &[]
    }
    fn planned_memberships(&self) -> Vec<northstar_session_application::sm::SmMucMembership> {
        vec![]
    }
    fn planned_joined_rooms(&self) -> Vec<(String, northstar_session_core::JoinedMucMembership)> {
        vec![]
    }
}

impl northstar_federation_core::FederationOutboxAdmission for UnusedRepository {
    async fn admit<'a>(&'a self, _: &'a str, _: String) -> bool {
        panic!("unexpected federation admission")
    }
}
impl northstar_federation_core::FederationRoute for UnusedRepository {
    fn outbox_policy(&self) -> northstar_federation_core::S2sOutboxPolicy {
        panic!("unexpected federation policy")
    }
    fn wake_outbox(&self) {
        panic!("unexpected federation wake")
    }
    async fn send(&self, _: &str, _: String, _: Option<String>) -> bool {
        panic!("unexpected federation send")
    }
}

fn registration_requirement() -> northstar_abuse_policy::WorkRequirement {
    northstar_abuse_policy::WorkRequirement {
        action: "registration".to_owned(),
        step: 1,
        work_factor: 2,
        max_work_factor: 256,
        hard_wait_seconds: 0,
        retry_after_seconds: 0,
        cooldown_seconds: 0,
        approximate_max_device_seconds: 1,
        notice: "retry the same registration".to_owned(),
    }
}

#[cfg(test)]
mod presence_recovery;
