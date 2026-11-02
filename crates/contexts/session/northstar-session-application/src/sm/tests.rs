use super::{
    same_device_binding_matches, BindingFinalizationOutcome, BindingReservationOutcome,
    CredentialInvocation, SmAuthorityBroker, SmAuthorityNotification, SmResumeFinalizationOutcome,
    SmResumeFinalizationRequest, SmService,
};
use anyhow::Result;
use std::{
    net::IpAddr,
    sync::{Arc, Barrier},
    time::Duration,
};
use uuid::Uuid;

#[tokio::test]
async fn authority_subscription_retains_state_and_reconnect_wakes() {
    let broker = SmAuthorityBroker::new("public".to_owned()).unwrap();
    let session_id = Uuid::new_v4();
    let mut subscription = broker.subscribe(session_id);
    let before = subscription.probe_stamp();
    broker.publish_state(session_id, 7);
    subscription.changed().await;
    assert!(subscription.acknowledge_probe(6, before));
    let after_probe = subscription.probe_stamp();
    assert!(!subscription.acknowledge_probe(7, after_probe));

    let before_reconnect = subscription.probe_stamp();
    broker.publish_listener_transition();
    subscription.changed().await;
    assert!(subscription.acknowledge_probe(7, before_reconnect));
    drop(subscription);
    assert!(broker.sessions.is_empty());
}

#[test]
fn authority_notification_is_consumed_once_and_high_hint_cannot_stick() {
    let broker = SmAuthorityBroker::new("public".to_owned()).unwrap();
    let session_id = Uuid::new_v4();
    let mut subscription = broker.subscribe(session_id);

    let before_forged = subscription.probe_stamp();
    broker.publish_state(session_id, i64::MAX);
    assert!(subscription.acknowledge_probe(7, before_forged));
    let after_forged = subscription.probe_stamp();
    assert!(
        !subscription.acknowledge_probe(7, after_forged),
        "a retained high hint must not force another database probe"
    );

    // A later delivery with the same payload is still a fresh edge: an
    // attacker cannot pre-play a future state version and suppress its
    // real notification.
    let before_replayed = subscription.probe_stamp();
    broker.publish_state(session_id, i64::MAX);
    assert!(subscription.acknowledge_probe(7, before_replayed));

    // A later real version below the forged value is also a fresh edge.
    let before_real = subscription.probe_stamp();
    broker.publish_state(session_id, 8);
    assert!(subscription.acknowledge_probe(7, before_real));
    let after_real = subscription.probe_stamp();
    assert!(!subscription.acknowledge_probe(8, after_real));

    // A notification delivered during the probe needs no extra read when
    // the authoritative result identifies that exact event.
    let exact_session_id = Uuid::new_v4();
    let mut exact_subscription = broker.subscribe(exact_session_id);
    let before_exact = exact_subscription.probe_stamp();
    broker.publish_state(exact_session_id, 9);
    assert!(!exact_subscription.acknowledge_probe(9, before_exact));

    // A forged lower delivery cannot overwrite a coalesced real edge and
    // make a stale database result look exact.
    let masked_session_id = Uuid::new_v4();
    let mut masked_subscription = broker.subscribe(masked_session_id);
    let before_masked = masked_subscription.probe_stamp();
    broker.publish_state(masked_session_id, 8);
    broker.publish_state(masked_session_id, 7);
    assert!(masked_subscription.acknowledge_probe(7, before_masked));
}

#[tokio::test]
async fn authority_participant_registration_closes_receiver_construction_race() {
    let broker = SmAuthorityBroker::new("public".to_owned()).unwrap();
    let session_id = Uuid::new_v4();
    let old = broker.subscribe(session_id);
    let participant_registered = Arc::new(Barrier::new(2));
    let construct_receiver = Arc::new(Barrier::new(2));
    let task = {
        let broker = Arc::clone(&broker);
        let participant_registered = Arc::clone(&participant_registered);
        let construct_receiver = Arc::clone(&construct_receiver);
        std::thread::spawn(move || {
            broker.subscribe_after_participant(session_id, || {
                participant_registered.wait();
                construct_receiver.wait();
            })
        })
    };
    participant_registered.wait();
    drop(old);
    assert!(broker.sessions.contains_key(&session_id));
    construct_receiver.wait();
    let mut replacement = task.join().unwrap();
    broker.publish_state(session_id, 9);
    replacement.changed().await;
    assert!(replacement.acknowledge_probe(8, Default::default()));
    drop(replacement);
    assert!(broker.sessions.is_empty());
}

#[test]
fn authority_participant_registration_unwinds_without_leaking_a_slot() {
    let broker = SmAuthorityBroker::new("public".to_owned()).unwrap();
    let session_id = Uuid::new_v4();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe({
        let broker = Arc::clone(&broker);
        move || {
            let _ = broker.subscribe_after_participant(session_id, || {
                panic!("controlled receiver-construction interruption");
            });
        }
    }));
    assert!(result.is_err());
    assert!(broker.sessions.is_empty());
}

#[test]
fn authority_notification_payload_is_minimal_and_schema_scoped() {
    let session_id = Uuid::new_v4();
    let accepted =
        format!(r#"{{"schema":"tenant_a","session_id":"{session_id}","state_version":8}}"#);
    let event: SmAuthorityNotification = serde_json::from_str(&accepted).unwrap();
    assert_eq!(event.schema, "tenant_a");
    assert_eq!(event.session_id, session_id);
    assert_eq!(event.state_version, 8);
    let broker = SmAuthorityBroker::new("tenant_a".to_owned()).unwrap();
    let mut subscription = broker.subscribe(session_id);
    for invalid in [
        accepted.replace("tenant_a", "tenant_b"),
        accepted.replace(":8", ":0"),
        accepted.replace(":8", ":-1"),
        accepted.replace('}', ",\"extra\":true}"),
        "x".repeat(257),
        "not JSON".to_owned(),
    ] {
        assert!(!broker.accept_notification(&invalid));
        assert!(!subscription.acknowledge_probe(7, Default::default()));
    }
    let before = subscription.probe_stamp();
    assert!(broker.accept_notification(&accepted));
    assert!(subscription.acknowledge_probe(7, before));
    assert!(serde_json::from_str::<SmAuthorityNotification>(&format!(
        r#"{{"schema":"tenant_a","session_id":"{session_id}","state_version":8,"full_jid":"secret@example.test/resource"}}"#
    ))
    .is_err());
}

#[test]
fn strict_same_device_precheck_rejects_every_unprovable_binding() {
    let device = Uuid::new_v4();
    assert!(same_device_binding_matches(
        Some(device),
        Some(device),
        true
    ));
    assert!(!same_device_binding_matches(None, Some(device), true));
    assert!(!same_device_binding_matches(Some(device), None, true));
    assert!(!same_device_binding_matches(
        Some(device),
        Some(Uuid::new_v4()),
        true
    ));
    // Compatibility is an explicit operator choice, not an implicit
    // exception inside strict mode.
    assert!(same_device_binding_matches(None, None, false));
    assert!(same_device_binding_matches(None, Some(device), false));
}

#[derive(Clone, Copy)]
enum CredentialCut {
    PreCommitError,
    Pending,
    Error,
    Matching,
}
struct ResumeRepository {
    credential_cut: Option<CredentialCut>,
    device: Uuid,
    session: Uuid,
    token: Uuid,
    fail_release: bool,
    calls: std::sync::Mutex<Vec<&'static str>>,
}

impl super::SmRepository for ResumeRepository {
    async fn revoke_session(&self, _: Uuid) -> anyhow::Result<()> {
        unreachable!()
    }

    async fn claim_resume(
        &self,
        _request: super::SmResumeClaimRequest<'_>,
        policy: super::SmIpPolicy,
    ) -> anyhow::Result<super::SmResumeClaimOutcome> {
        assert_eq!(policy, super::SmIpPolicy::Exact);
        self.calls.lock().unwrap().push("claim");
        Ok(super::SmResumeClaimOutcome::Claimed(Box::new(
            super::SmResumeClaim {
                session_id: self.session,
                claim_token: self.token,
                claim_deadline: std::time::Instant::now() + Duration::from_secs(10),
                full_jid: "alice@example.test/phone".into(),
                resource: "phone".into(),
                resume_timeout_seconds: 30,
                inbound_h: 0,
                acked_h: 0,
                available: false,
                carbons: false,
                priority: 0,
                blocklist_requested: false,
                roster_requested: false,
                active_privacy_list: None,
                privacy_requested: false,
                user_agent_id: Some(self.device),
                joined_rooms: vec![],
                directed_presence: vec![],
                last_presence: None,
                unacked: vec![],
            },
        )))
    }
    async fn release_claim(&self, session: Uuid, token: Uuid) -> anyhow::Result<()> {
        assert_eq!((session, token), (self.session, self.token));
        self.calls.lock().unwrap().push("release");
        anyhow::ensure!(!self.fail_release, "release failed");
        Ok(())
    }
    async fn create_session(
        &self,
        _request: super::SmSessionCreationRequest<'_>,
    ) -> Result<super::SmSessionCreationOutcome> {
        panic!("unexpected persistence operation")
    }
    #[allow(clippy::too_many_arguments)]
    async fn checkpoint_session(
        &self,
        _session_id: Uuid,
        _connection_id: Uuid,
        _snapshot: &super::SmSessionSnapshot,
        _ttl_seconds: u64,
        _live_lease_seconds: u64,
        _max_stanzas: usize,
        _max_bytes: usize,
        _observation: Option<&super::ownership::PreparedCheckpoint<'_>>,
    ) -> Result<super::SmCheckpointOutcome> {
        panic!("unexpected persistence operation")
    }
    async fn remove_live_muc_memberships(
        &self,
        _session_id: Uuid,
        _connection_id: Uuid,
        _memberships: &[super::SmMucMembership],
    ) -> Result<bool> {
        panic!("unexpected persistence operation")
    }
    #[allow(clippy::too_many_arguments)]
    async fn checkpoint_and_acknowledge(
        &self,
        _session_id: Uuid,
        _connection_id: Uuid,
        _snapshot: &super::SmSessionSnapshot,
        _acknowledged: &[northstar_delivery_core::SmUnackedStanza],
        _ttl_seconds: u64,
        _live_lease_seconds: u64,
        _max_stanzas: usize,
        _max_bytes: usize,
        _observation: Option<&super::ownership::PreparedCheckpoint<'_>>,
    ) -> Result<super::SmCheckpointOutcome> {
        panic!("unexpected persistence operation")
    }
    async fn acknowledge_delivery_batch(
        &self,
        _sources: &[northstar_delivery_core::TransportOwnershipSource],
        _observation: Option<&super::ownership::PreparedBatch<'_>>,
    ) -> Result<()> {
        panic!("unexpected persistence operation")
    }
    async fn reserve_binding(
        &self,
        _connection_id: Uuid,
        _user_id: Uuid,
        _expected_auth_generation: i64,
        _full_jid: &str,
        _lease_seconds: u64,
    ) -> Result<BindingReservationOutcome> {
        panic!("unexpected persistence operation")
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
        panic!("unexpected persistence operation")
    }
    async fn finalize_resume(
        &self,
        _request: SmResumeFinalizationRequest<'_>,
    ) -> Result<SmResumeFinalizationOutcome> {
        panic!("unexpected persistence operation")
    }
    #[allow(clippy::too_many_arguments)]
    async fn finalize_binding_observed(
        &self,
        connection_id: Uuid,
        user_id: Uuid,
        expected_auth_generation: i64,
        full_jid: &str,
        lease_seconds: u64,
        device_id: Option<Uuid>,
        fast_plan: Option<&northstar_auth_core::credential::FastCommitPlan>,
        invocation: &CredentialInvocation<'_>,
    ) -> Result<BindingFinalizationOutcome> {
        use northstar_session_core::publication::{CredentialPreparation, PreparationResult};
        invocation.enter_binding(
            connection_id,
            user_id,
            expected_auth_generation,
            full_jid,
            lease_seconds,
            device_id,
            fast_plan,
        )?;
        assert_eq!(device_id, Some(self.device));
        assert_eq!(
            (
                connection_id,
                user_id,
                expected_auth_generation,
                full_jid,
                lease_seconds
            ),
            (
                Uuid::from_u128(3),
                Uuid::from_u128(2),
                7,
                "private@example.test/resource",
                43
            )
        );
        self.begin_credential(invocation).await;
        invocation.preparation_entered(CredentialPreparation::Binding);
        invocation.preparation_returned(CredentialPreparation::Binding, PreparationResult::Present);
        let stage =
            self.stage_credential(invocation, connection_id, user_id, expected_auth_generation);
        if fast_plan.is_some() {
            invocation.preparation_entered(CredentialPreparation::Fast);
            invocation
                .preparation_returned(CredentialPreparation::Fast, PreparationResult::Present);
        }
        self.commit_credential(invocation).await?;
        let receipt = northstar_auth_core::credential::CredentialCommitReceipt::new(
            None,
            Some(stage),
            Some(northstar_auth_core::credential::BindingPublication {
                connection_id,
                user_id,
                full_jid: full_jid.to_owned(),
                lease_seconds,
            }),
        );
        invocation.constructed(&receipt);
        Ok(BindingFinalizationOutcome::Committed { receipt })
    }
    async fn finalize_resume_observed(
        &self,
        request: SmResumeFinalizationRequest<'_>,
        invocation: &CredentialInvocation<'_>,
    ) -> Result<SmResumeFinalizationOutcome> {
        use northstar_session_core::publication::{CredentialPreparation, PreparationResult};
        invocation.enter_resume(&request)?;
        assert_eq!(
            (
                request.session_id,
                request.claim_token,
                request.user_agent_id
            ),
            (self.session, self.token, Some(self.device))
        );
        assert_eq!(
            (
                request.client_h,
                request.acknowledged_count,
                request.ttl_seconds,
                request.live_lease_seconds,
                request.max_stanzas,
                request.max_bytes
            ),
            (11, 2, 90, 43, 17, 801)
        );
        assert_eq!(request.peer_ip, "192.0.2.7".parse::<IpAddr>().unwrap());
        assert_eq!(request.active_privacy_list, Some("private-list"));
        self.begin_credential(invocation).await;
        let stage = self.stage_credential(
            invocation,
            request.connection_id,
            request.user_id,
            request.expected_auth_generation,
        );
        invocation.preparation_entered(CredentialPreparation::Activation);
        invocation.preparation_returned(
            CredentialPreparation::Activation,
            PreparationResult::Present,
        );
        if request.fast_plan.is_some() {
            invocation.preparation_entered(CredentialPreparation::Fast);
            invocation
                .preparation_returned(CredentialPreparation::Fast, PreparationResult::Present);
        }
        invocation.preparation_entered(CredentialPreparation::Privacy);
        invocation.preparation_returned(CredentialPreparation::Privacy, PreparationResult::Present);
        self.commit_credential(invocation).await?;
        let receipt =
            northstar_auth_core::credential::CredentialCommitReceipt::new(None, Some(stage), None);
        invocation.constructed(&receipt);
        Ok(SmResumeFinalizationOutcome::Committed(Box::new(
            super::SmResumeFinalizationCommit {
                activated: super::ActivatedSmSession {
                    outbound_h: 13,
                    unacked: Vec::new(),
                },
                receipt,
            },
        )))
    }
    async fn release_live_session(&self, _connection_id: Uuid) -> Result<bool> {
        panic!("unexpected persistence operation")
    }
    #[allow(clippy::too_many_arguments)]
    async fn suspend_exact_session(
        &self,
        _session_id: Uuid,
        _connection_id: Uuid,
        _user_id: Uuid,
        _expected_auth_generation: i64,
        _snapshot: &super::SmSessionSnapshot,
        _ttl_seconds: u64,
        _max_stanzas: usize,
        _max_bytes: usize,
    ) -> Result<bool> {
        panic!("unexpected persistence operation")
    }
}

impl ResumeRepository {
    async fn begin_credential(&self, invocation: &CredentialInvocation<'_>) {
        CredentialInvocation::begin(Some(invocation), std::future::ready(Ok::<(), ()>(())))
            .await
            .unwrap();
        CredentialInvocation::eligibility(
            Some(invocation),
            std::future::ready(Ok::<_, ()>(Some(true))),
        )
        .await
        .unwrap();
        invocation.transaction_returned();
    }
    fn stage_credential(
        &self,
        invocation: &CredentialInvocation<'_>,
        connection_id: Uuid,
        user_id: Uuid,
        auth_generation: i64,
    ) -> northstar_auth_core::credential::StagedLoginEpoch {
        invocation
            .preparation_entered(northstar_session_core::publication::CredentialPreparation::Stage);
        let stage = northstar_auth_core::credential::StagedLoginEpoch {
            operation_id: Uuid::from_u128(5),
            connection_id,
            user_id,
            auth_generation,
            device_id: self.device,
            epoch: 19,
        };
        invocation.stage_id(stage.operation_id);
        invocation.stage_returned(&Ok(Some(stage)));
        stage
    }
    async fn commit_credential(&self, invocation: &CredentialInvocation<'_>) -> Result<()> {
        let cut = self
            .credential_cut
            .expect("credential fake requires explicit finite cut");
        if matches!(cut, CredentialCut::PreCommitError) {
            anyhow::bail!("synthetic preparation error");
        }
        CredentialInvocation::commit(Some(invocation), async {
            if matches!(cut, CredentialCut::Pending) {
                std::future::pending::<()>().await;
            }
            if matches!(cut, CredentialCut::Error) {
                Err(std::io::Error::other("synthetic COMMIT error"))
            } else {
                Ok(())
            }
        })
        .await
        .map_err(northstar_session_core::publication::credential_error)
    }
}
#[tokio::test]
async fn observed_sm_services_preserve_exact_requests_and_commit_cuts() {
    use northstar_auth_core::credential::FastCommitPlan;
    use northstar_session_core::publication::{
        CredentialCall, CredentialKind, CredentialReturned, CredentialTerminal, PreparedCredential,
    };
    for kind in [CredentialKind::Binding, CredentialKind::Resume] {
        for cut in [
            CredentialCut::PreCommitError,
            CredentialCut::Pending,
            CredentialCut::Error,
            CredentialCut::Matching,
        ] {
            let service = SmService::new(
                ResumeRepository {
                    credential_cut: Some(cut),
                    device: Uuid::from_u128(4),
                    session: Uuid::from_u128(6),
                    token: Uuid::from_u128(8),
                    fail_release: false,
                    calls: std::sync::Mutex::new(Vec::new()),
                },
                "public".into(),
            )
            .unwrap();
            let prepared = PreparedCredential::new(Uuid::from_u128(1), Uuid::from_u128(3), 0, kind);
            let plan = FastCommitPlan {
                token_id: Some(Uuid::from_u128(10)),
                token_was_new: true,
                invalidate: true,
                issue: None,
            };
            let mut call = Box::pin(async {
                match kind {
                    CredentialKind::Binding => service
                        .finalize_binding_observed(
                            Uuid::from_u128(3),
                            Uuid::from_u128(2),
                            7,
                            "private@example.test/resource",
                            43,
                            Some(Uuid::from_u128(4)),
                            Some(&plan),
                            Some(&prepared),
                        )
                        .await
                        .map(|result| match result {
                            BindingFinalizationOutcome::Committed { receipt } => receipt,
                            _ => panic!("unexpected fake refusal"),
                        }),
                    CredentialKind::Resume => service
                        .finalize_resume_observed(
                            SmResumeFinalizationRequest {
                                session_id: Uuid::from_u128(6),
                                claim_token: Uuid::from_u128(8),
                                connection_id: Uuid::from_u128(3),
                                user_id: Uuid::from_u128(2),
                                expected_auth_generation: 7,
                                client_h: 11,
                                acknowledged_count: 2,
                                peer_ip: "192.0.2.7".parse().unwrap(),
                                user_agent_id: Some(Uuid::from_u128(4)),
                                active_privacy_list: Some("private-list"),
                                ttl_seconds: 90,
                                live_lease_seconds: 43,
                                max_stanzas: 17,
                                max_bytes: 801,
                                fast_plan: Some(&plan),
                            },
                            Some(&prepared),
                        )
                        .await
                        .map(|result| match result {
                            SmResumeFinalizationOutcome::Committed(commit) => {
                                assert_eq!(commit.activated.outbound_h, 13);
                                commit.receipt
                            }
                            _ => panic!("unexpected fake refusal"),
                        }),
                    CredentialKind::UnboundFast => unreachable!(),
                }
            });
            let result = futures::poll!(&mut call);
            if matches!(cut, CredentialCut::Pending) {
                assert!(result.is_pending());
                drop(call);
                let snapshot = prepared.observation().snapshot();
                assert_eq!(snapshot.commit, CredentialCall::Entered);
                assert_eq!(snapshot.returned, None);
                assert_eq!(snapshot.call_terminal, Some(CredentialTerminal::Cancelled));
            } else {
                let std::task::Poll::Ready(result) = result else {
                    panic!("finite fake unexpectedly pending")
                };
                drop(call);
                let snapshot = prepared.observation().snapshot();
                match result {
                    Ok(receipt) => {
                        assert_eq!(
                            snapshot.returned,
                            Some(if kind == CredentialKind::Binding {
                                CredentialReturned::BindingCommitted
                            } else {
                                CredentialReturned::ResumeCommitted
                            })
                        );
                        assert_eq!(
                            receipt.staged_login_epoch().unwrap().operation_id,
                            Uuid::from_u128(5)
                        );
                        assert!(prepared
                            .transfer(&receipt, Uuid::from_u128(1), Uuid::from_u128(3))
                            .is_ok());
                    }
                    Err(_) => {
                        assert_eq!(snapshot.returned, Some(CredentialReturned::Error));
                        assert_eq!(
                            snapshot.commit,
                            if matches!(cut, CredentialCut::PreCommitError) {
                                CredentialCall::NotEntered
                            } else {
                                CredentialCall::Err
                            }
                        );
                    }
                }
                assert_eq!(snapshot.call_terminal, Some(CredentialTerminal::Returned));
            }
        }
    }
}

#[tokio::test]
async fn resume_policy_releases_only_the_exact_mismatched_claim() {
    let device = Uuid::new_v4();
    let requested_device = Uuid::new_v4();
    for fail_release in [false, true] {
        let service = SmService::new(
            ResumeRepository {
                credential_cut: None,
                device,
                session: Uuid::new_v4(),
                token: Uuid::new_v4(),
                fail_release,
                calls: std::sync::Mutex::new(Vec::new()),
            },
            "public".into(),
        )
        .unwrap();
        let request = |user_agent_id, ip_binding| super::SmResumeClaimRequest {
            token_hash: &[7; 32],
            user_id: Uuid::new_v4(),
            peer_ip: "127.0.0.1".parse().unwrap(),
            user_agent_id,
            ip_binding,
            require_same_device: true,
            claim_lease_seconds: 10,
        };
        assert!(service
            .claim_resume(request(Some(device), "invalid"))
            .await
            .is_err());
        assert!(service.repository.calls.lock().unwrap().is_empty());
        assert!(matches!(
            service
                .claim_resume(request(Some(device), "exact"))
                .await
                .unwrap(),
            super::SmResumeClaimOutcome::Claimed(_)
        ));
        assert_eq!(*service.repository.calls.lock().unwrap(), ["claim"]);
        service.repository.calls.lock().unwrap().clear();
        let result = service
            .claim_resume(request(Some(requested_device), "exact"))
            .await;
        if fail_release {
            assert!(
                result.is_err(),
                "failed release must not be reported as a clean rejection"
            );
        } else {
            assert!(matches!(
                result.unwrap(),
                super::SmResumeClaimOutcome::Rejected
            ));
        }
        assert_eq!(
            *service.repository.calls.lock().unwrap(),
            ["claim", "release"]
        );
    }
}
