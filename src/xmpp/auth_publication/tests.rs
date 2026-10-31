use super::*;
use northstar_auth_application::authentication::publication::{HandlerReturn, Knowledge, Returned};
use northstar_auth_application::authentication::{BindingPublication, StagedLoginEpoch};
use std::{
    panic::AssertUnwindSafe,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    task::Waker,
};

async fn observed_unbound_owner(frame: &FrameExecution, connection: Uuid) -> KnownCredentialOwner {
    use northstar_auth_application::authentication::publication::{
        CredentialInvocation, CredentialKind, CredentialPreparation, PreparationResult,
    };
    use northstar_auth_application::authentication::FastCommitPlan;
    let prepared = frame
        .prepare_credential(CredentialKind::UnboundFast, connection)
        .unwrap();
    let plan = FastCommitPlan::default();
    let invocation = prepared
        .fast(Uuid::from_u128(2), 7, &plan, None, connection)
        .unwrap();
    invocation
        .enter_fast(Uuid::from_u128(2), 7, &plan, None, connection)
        .unwrap();
    CredentialInvocation::begin(Some(&invocation), std::future::ready(Ok::<(), ()>(())))
        .await
        .unwrap();
    CredentialInvocation::eligibility(
        Some(&invocation),
        std::future::ready(Ok::<_, ()>(Some(true))),
    )
    .await
    .unwrap();
    invocation.transaction_returned();
    invocation.preparation_entered(CredentialPreparation::Stage);
    invocation.stage_returned(&Ok(None));
    invocation.preparation_entered(CredentialPreparation::Fast);
    invocation.preparation_returned(CredentialPreparation::Fast, PreparationResult::Present);
    CredentialInvocation::commit(Some(&invocation), std::future::ready(Ok::<(), ()>(())))
        .await
        .unwrap();
    let receipt = CredentialCommitReceipt::new(None, None, None);
    invocation.constructed(&receipt);
    let result = AuthenticationResult::Authenticated(receipt);
    invocation.fast_returned(&result);
    drop(invocation);
    let AuthenticationResult::Authenticated(receipt) = result else {
        unreachable!()
    };
    KnownCredentialOwner::from_observed(receipt, frame.clone(), connection, &prepared).unwrap()
}
#[tokio::test]
async fn unknown_resume_and_successful_fallback_keep_distinct_original_frame_attempts() {
    {
        use northstar_auth_application::authentication::publication::{
            CredentialCall, CredentialKind, CredentialReturned,
        };
        let frame = FrameExecution::for_saved_case(
            super::super::protocol::ClientTransport::Bosh,
            "<authenticate/>",
            Uuid::from_u128(700),
        );
        let prepared = frame
            .prepare_credential(CredentialKind::Resume, Uuid::from_u128(302))
            .unwrap();
        let request = crate::services::sm::SmResumeFinalizationRequest {
            session_id: Uuid::from_u128(21),
            claim_token: Uuid::from_u128(22),
            connection_id: Uuid::from_u128(302),
            user_id: Uuid::from_u128(2),
            expected_auth_generation: 7,
            client_h: 4,
            acknowledged_count: 1,
            peer_ip: "192.0.2.8".parse().unwrap(),
            user_agent_id: None,
            active_privacy_list: None,
            ttl_seconds: 90,
            live_lease_seconds: 43,
            max_stanzas: 11,
            max_bytes: 901,
            fast_plan: None,
        };
        let invocation = prepared.resume(&request).unwrap();
        invocation.enter_resume(&request).unwrap();
        let receipt = CredentialCommitReceipt::new(None, None, None);
        invocation.constructed(&receipt);
        let result = Ok(crate::services::sm::SmResumeFinalizationOutcome::Committed(
            Box::new(crate::services::sm::SmResumeFinalizationCommit {
                activated: crate::services::sm::ActivatedSmSession {
                    outbound_h: 1,
                    unacked: Vec::new(),
                },
                receipt,
            }),
        ));
        invocation.resume_returned(&result);
        drop(invocation);
        let Ok(crate::services::sm::SmResumeFinalizationOutcome::Committed(commit)) = result else {
            unreachable!()
        };
        let error = KnownCredentialOwner::from_observed(
            commit.receipt,
            frame,
            Uuid::from_u128(302),
            &prepared,
        )
        .err()
        .expect("missing witness must reject ownership");
        assert!(credential_handoff_failed(&error));
        assert!(!credential_handoff_failed(&anyhow::anyhow!(
            "synthetic ordinary repository error"
        )));
        let snapshot = prepared.observation().snapshot();
        assert_eq!(snapshot.returned, Some(CredentialReturned::ResumeCommitted));
        assert_eq!(snapshot.commit, CredentialCall::NotEntered);
        assert!(!snapshot.return_matches);
        assert!(!snapshot.transferred);
    }
    use northstar_auth_application::authentication::publication::{
        CredentialCall, CredentialInvocation, CredentialKind, CredentialPreparation,
        CredentialReturned, PreparationResult,
    };
    let frame = FrameExecution::for_saved_case(
        super::super::protocol::ClientTransport::Bosh,
        "<authenticate/>",
        Uuid::from_u128(701),
    );
    let prepared = frame
        .prepare_credential(CredentialKind::Resume, Uuid::from_u128(302))
        .unwrap();
    let resume = prepared.observation();
    let request = crate::services::sm::SmResumeFinalizationRequest {
        session_id: Uuid::from_u128(21),
        claim_token: Uuid::from_u128(22),
        connection_id: Uuid::from_u128(302),
        user_id: Uuid::from_u128(2),
        expected_auth_generation: 7,
        client_h: 4,
        acknowledged_count: 1,
        peer_ip: "192.0.2.8".parse().unwrap(),
        user_agent_id: None,
        active_privacy_list: Some("private-resume-list"),
        ttl_seconds: 90,
        live_lease_seconds: 43,
        max_stanzas: 11,
        max_bytes: 901,
        fast_plan: None,
    };
    let invocation = prepared.resume(&request).unwrap();
    invocation.enter_resume(&request).unwrap();
    CredentialInvocation::begin(Some(&invocation), std::future::ready(Ok::<(), ()>(())))
        .await
        .unwrap();
    CredentialInvocation::eligibility(
        Some(&invocation),
        std::future::ready(Ok::<_, ()>(Some(true))),
    )
    .await
    .unwrap();
    invocation.transaction_returned();
    invocation.preparation_entered(CredentialPreparation::Stage);
    invocation.stage_returned(&Ok(None));
    for operation in [
        CredentialPreparation::Activation,
        CredentialPreparation::Privacy,
    ] {
        invocation.preparation_entered(operation);
        invocation.preparation_returned(operation, PreparationResult::Present);
    }
    assert!(
        CredentialInvocation::commit(Some(&invocation), std::future::ready(Err::<(), ()>(())))
            .await
            .is_err()
    );
    invocation.resume_returned(&Err(anyhow::anyhow!("synthetic lost resume COMMIT reply")));
    drop(invocation);
    let owner = observed_unbound_owner(&frame, Uuid::from_u128(302)).await;
    let publication = owner.observation().clone();
    let fallback = publication.credential().unwrap();
    frame.retain_auth_receipt(publication.clone()).unwrap();
    let holder = frame
        .run(async move {
            owner.seal(
                "<success/>",
                CapturedEffects {
                    route: RouteIntent::Unbound,
                    caps: None,
                    notification: None,
                },
            )
        })
        .await
        .unwrap();
    assert_eq!(resume.snapshot().commit, CredentialCall::Err);
    assert_eq!(resume.snapshot().returned, Some(CredentialReturned::Error));
    assert_eq!(resume.snapshot().ordinal, 0);
    assert!(!resume.snapshot().transferred);
    assert_eq!(fallback.snapshot().ordinal, 1);
    assert_eq!(fallback.snapshot().commit, CredentialCall::Ok);
    assert!(fallback.snapshot().transferred);
    assert_ne!(resume.snapshot().attempt, fallback.snapshot().attempt);
    assert_eq!(resume.snapshot().frame, fallback.snapshot().frame);
    assert_eq!(resume.snapshot().handler, Some(HandlerReturn::Completed));
    assert_eq!(fallback.snapshot().handler, Some(HandlerReturn::Completed));
    assert_eq!(publication.snapshot().terminal, None);
    drop(holder);
    assert_eq!(publication.snapshot().terminal, Some(Terminal::Abandoned));
    assert_eq!(resume.snapshot().commit, CredentialCall::Err);
}

pub(crate) fn fixture_control(control: &str, connection: Uuid) -> (AuthControlHolder, Observation) {
    let owner = KnownCredentialOwner::from_returned(
        CredentialCommitReceipt::new(None, None, None),
        None,
        connection,
    );
    let observation = owner.observation().clone();
    let holder = owner
        .seal(
            control,
            CapturedEffects {
                route: RouteIntent::Unbound,
                caps: None,
                notification: None,
            },
        )
        .unwrap();
    (holder, observation)
}
pub(crate) fn fixture_bound_control(
    control: &str,
    connection: Uuid,
    notify: bool,
) -> (AuthControlHolder, Observation) {
    let user = Uuid::from_u128(303);
    let device = Uuid::from_u128(304);
    let receipt = CredentialCommitReceipt::new(
        None,
        Some(StagedLoginEpoch {
            operation_id: Uuid::from_u128(301),
            connection_id: connection,
            user_id: user,
            device_id: device,
            auth_generation: 2,
            epoch: 999,
        }),
        Some(BindingPublication {
            connection_id: connection,
            user_id: user,
            full_jid: "fixture@example.test/captured".to_owned(),
            lease_seconds: 120,
        }),
    );
    let owner = KnownCredentialOwner::from_returned(receipt, None, connection);
    let observation = owner.observation().clone();
    let holder = owner
        .seal(control, fixture_bound_effects(connection, notify))
        .unwrap();
    (holder, observation)
}
fn fixture_bound_effects(connection: Uuid, notify: bool) -> CapturedEffects {
    let user = Uuid::from_u128(303);
    let device = Uuid::from_u128(304);
    let route = BoundRoute {
        key: "fixture@example.test/captured".to_owned(),
        user,
        generation: 2,
        connection,
        lifecycle: Arc::new(AtomicU8::new(0)),
        disconnect: CancellationToken::new(),
    };
    let caps = CapsIntent {
        presence: "<presence/>".to_owned(),
        key: route.key.clone(),
        connection,
        gate: Arc::new(tokio::sync::Mutex::new(())),
        generation: Arc::new(AtomicU64::new(9)),
    };
    let notification = notify.then(|| NotificationIntent {
        account: "fixture@example.test".to_owned(),
        user,
        device,
        excluded_key: route.key.clone(),
    });
    CapturedEffects {
        route: RouteIntent::Bound(route),
        caps: Some(caps),
        notification,
    }
}
#[derive(Clone, Copy, Default)]
enum Cut {
    #[default]
    Success,
    BeforeCommit,
    CommitPending,
    CommitError,
    BareSuccess,
    WrongReturn,
    RouteRejected,
    CapsPending,
    NotifyError,
}
struct FakePort {
    connection: Uuid,
    cut: Cut,
    events: Vec<&'static str>,
    routes: Vec<String>,
    caps_generation: Option<u64>,
    notification: Option<(String, Uuid, Uuid, String, i64)>,
}
impl FakePort {
    fn new(connection: Uuid, cut: Cut) -> Self {
        Self {
            connection,
            cut,
            events: Vec::new(),
            routes: Vec::new(),
            caps_generation: None,
            notification: None,
        }
    }
}
impl PublicationPort for FakePort {
    fn connection(&self) -> Uuid {
        self.connection
    }
    async fn publish(&mut self, invocation: &Invocation<'_>) -> AuthenticationResult<Option<i64>> {
        self.events.push("service");
        invocation.enter_service().unwrap();
        let result = if matches!(self.cut, Cut::BeforeCommit) {
            AuthenticationResult::BackendFailure(anyhow::anyhow!("controlled pre-COMMIT failure"))
        } else if invocation.receipt().staged_login_epoch().is_none()
            && invocation.receipt().binding_publication().is_none()
        {
            invocation.not_required().unwrap();
            AuthenticationResult::Authenticated(None)
        } else {
            invocation.enter_repository().unwrap();
            self.events.push("repository");
            if matches!(self.cut, Cut::BareSuccess) {
                AuthenticationResult::Authenticated(Some(7))
            } else {
                let cut = self.cut;
                let committed = invocation
                    .commit(
                        async {
                            if matches!(cut, Cut::CommitPending) {
                                std::future::pending::<()>().await;
                            }
                            if matches!(cut, Cut::CommitError) {
                                return Err(std::io::Error::other("controlled COMMIT reply loss"));
                            }
                            Ok(())
                        },
                        Some(7),
                    )
                    .await;
                match committed {
                    Ok(()) => AuthenticationResult::Authenticated(Some(
                        if matches!(cut, Cut::WrongReturn) {
                            8
                        } else {
                            7
                        },
                    )),
                    Err(error) => AuthenticationResult::BackendFailure(error.into()),
                }
            }
        };
        // Preserve the actual fake adapter return even when it mismatches;
        // the shared production sequence must reject it before effects.
        let _ = invocation.returned(&result);
        result
    }
    fn epoch_and_mapping(&mut self, route: &BoundRoute, epoch: Option<i64>) -> bool {
        self.events.push("route");
        self.routes.push(route.key.clone());
        assert_eq!(route.connection, self.connection);
        assert_eq!(route.user, Uuid::from_u128(303));
        assert_eq!(route.generation, 2);
        assert_eq!(epoch, Some(7));
        !matches!(self.cut, Cut::RouteRejected)
    }
    fn activate(&mut self, route: &BoundRoute) -> bool {
        self.events.push("activate");
        assert_eq!(route.key, "fixture@example.test/captured");
        true
    }
    async fn caps(&mut self, intent: Option<CapsIntent>) {
        self.events.push("caps");
        let caps = intent.expect("captured resume caps intent");
        assert_eq!(caps.key, "fixture@example.test/captured");
        assert_eq!(caps.connection, self.connection);
        assert_eq!(caps.presence, "<presence/>");
        self.caps_generation = Some(caps.generation.load(Ordering::Acquire));
        if matches!(self.cut, Cut::CapsPending) {
            std::future::pending::<()>().await;
        }
    }
    fn notify_local(&mut self, intent: &NotificationIntent, epoch: i64) {
        self.events.push("local_notification");
        self.notification = Some((
            intent.account.clone(),
            intent.user,
            intent.device,
            intent.excluded_key.clone(),
            epoch,
        ));
    }
    async fn notify_remote(&mut self, _: &NotificationIntent, _: i64) -> Result<()> {
        self.events.push("remote_notification");
        if matches!(self.cut, Cut::NotifyError) {
            anyhow::bail!("controlled notification failure");
        }
        Ok(())
    }
    fn rejected(&mut self, _: PublicationResult, _: Option<&anyhow::Error>) {
        self.events.push("rejected");
    }
    fn notification_deferred(&mut self, _: &anyhow::Error) {
        self.events.push("deferred");
    }
}
pub(crate) async fn publish_unbound_fixture(owners: Vec<OwnedPublication>) -> bool {
    for owner in owners {
        let mut port = FakePort::new(owner.connection(), Cut::Success);
        if !owner.publish(&mut port).await.transport_succeeded() {
            return false;
        }
        assert_eq!(port.events, ["service"]);
    }
    true
}
fn selected(holders: &[(&str, &AuthControlHolder)], rid: u64) -> SelectedControls {
    let mut selected = SelectedControls::new(
        holders
            .iter()
            .map(|(control, holder)| (*control, Some(*holder))),
    )
    .unwrap();
    selected.begin_exposure(rid).unwrap();
    selected.exposure(rid, true).unwrap();
    selected
}
fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

#[tokio::test]
async fn observed_control_joins_anchor_actual_bytes_and_native_or_bosh_transfer() {
    for native in [false, true] {
        let connection = Uuid::from_u128(302);
        let frame_id = Uuid::from_u128(720);
        let frame = FrameExecution::for_saved_case(
            if native {
                super::super::protocol::ClientTransport::Tcp
            } else {
                super::super::protocol::ClientTransport::Bosh
            },
            "<authenticate/>",
            frame_id,
        );
        let owner = observed_unbound_owner(&frame, connection).await;
        let publication = owner.observation().clone();
        let credential = publication.credential().unwrap();
        let credential_joins = credential.joins();
        let receipt_id = owner.receipt.as_ref().unwrap().publication_identity();
        assert_eq!(credential_joins.constructed_receipt, Some(receipt_id));
        assert_eq!(credential_joins.returned_receipt, Some(receipt_id));
        assert_eq!(credential_joins.transferred_receipt, Some(receipt_id));
        let control = "<success note='é'/>";
        let holder = owner
            .seal(
                control,
                CapturedEffects {
                    route: RouteIntent::Unbound,
                    caps: None,
                    notification: None,
                },
            )
            .unwrap();
        let joins = holder.join_observation();
        let alias = holder.join_observation();
        let introduced = joins.snapshot().introduced.unwrap();
        assert_eq!(introduced.control, publication.snapshot().control);
        assert_eq!(introduced.connection, connection);
        assert_eq!(introduced.frame, Some(frame_id));
        assert_eq!(introduced.receipt, receipt_id);
        assert_eq!(introduced.length, control.len());
        assert_eq!(
            introduced.digest,
            <[u8; 32]>::from(Sha256::digest(control.as_bytes())),
        );
        assert_ne!(introduced.length, control.chars().count());
        assert_eq!(introduced.publication.receipt, receipt_id);
        assert_eq!(introduced.publication.frame, Some(frame_id));
        assert_eq!(
            introduced.publication.credential,
            Some(credential_joins.owner),
        );
        assert_eq!(introduced.publication.begun_receipt, None);
        assert_eq!(joins.snapshot().transferred, None);
        let before = publication.snapshot();
        assert_eq!(joins.snapshot(), alias.snapshot());
        assert_eq!(publication.snapshot(), before);
        assert_eq!(credential.joins(), credential_joins);
        assert!(holder.validate_control("<changed/>").is_err());
        assert_eq!(joins.snapshot().introduced, Some(introduced));
        assert_eq!(joins.snapshot().transferred, None);

        let owners = if native {
            holder.recording().unwrap();
            vec![holder
                .clone()
                .write(control.to_owned(), |actual| async move {
                    assert_eq!(actual, control);
                    Ok(())
                })
                .await
                .unwrap()]
        } else {
            let selection = selected(&[(control, &holder)], 17);
            assert_eq!(joins.snapshot().transferred, None);
            selection.take_all().unwrap()
        };
        let transferred = joins.snapshot();
        assert_eq!(transferred.introduced, Some(introduced));
        assert_eq!(transferred.transferred, Some(introduced));
        assert_eq!(owners[0].receipt().publication_identity(), receipt_id);
        assert!(holder.recording().is_err());
        assert_eq!(joins.snapshot(), transferred);
        assert!(publish_unbound_fixture(owners).await);
        assert_eq!(publication.joins().begun_receipt, Some(receipt_id));
        assert_eq!(publication.snapshot().terminal, Some(Terminal::Completed));
        assert_eq!(joins.snapshot(), transferred);
        assert_eq!(alias.snapshot(), transferred);
    }
}

#[test]
fn control_join_read_handle_does_not_retain_authority_or_invent_credential_history() {
    let (holder, publication) = fixture_control("<success/>", Uuid::from_u128(302));
    let joins = holder.join_observation();
    let before = joins.snapshot();
    let introduced = before.introduced.unwrap();
    assert_eq!(introduced.frame, None);
    assert_eq!(introduced.publication.credential, None);
    assert_eq!(introduced.receipt, publication.joins().receipt);
    assert_eq!(before.transferred, None);
    let before_publication = publication.snapshot();
    for _ in 0..3 {
        assert_eq!(joins.snapshot(), before);
        assert_eq!(publication.snapshot(), before_publication);
    }
    drop(holder);
    assert_eq!(publication.snapshot().terminal, Some(Terminal::Abandoned));
    assert_eq!(joins.snapshot(), before);
    assert_eq!(publication.joins().begun_receipt, None);
}

#[tokio::test]
async fn control_joins_expose_reassigned_receipts_after_sealed_introduction() {
    let connection = Uuid::from_u128(302);
    let frame = FrameExecution::for_saved_case(
        super::super::protocol::ClientTransport::Bosh,
        "<authenticate/>",
        Uuid::from_u128(730),
    );
    let first = observed_unbound_owner(&frame, connection)
        .await
        .seal(
            "<success id='1'/>",
            CapturedEffects {
                route: RouteIntent::Unbound,
                caps: None,
                notification: None,
            },
        )
        .unwrap();
    let second_frame = FrameExecution::for_saved_case(
        super::super::protocol::ClientTransport::Bosh,
        "<authenticate/>",
        Uuid::from_u128(731),
    );
    let second = observed_unbound_owner(&second_frame, connection)
        .await
        .seal(
            "<success id='2'/>",
            CapturedEffects {
                route: RouteIntent::Unbound,
                caps: None,
                notification: None,
            },
        )
        .unwrap();
    let observations = [first.join_observation(), second.join_observation()];
    let introduced = observations
        .each_ref()
        .map(|observation| observation.snapshot().introduced.unwrap());
    assert_ne!(introduced[0].control, introduced[1].control);
    assert_ne!(introduced[0].receipt, introduced[1].receipt);
    assert_ne!(introduced[0].digest, introduced[1].digest);
    assert_eq!(introduced[0].publication.credential.unwrap().ordinal, 0);
    assert_eq!(introduced[1].publication.credential.unwrap().ordinal, 0);
    assert_ne!(introduced[0].frame, introduced[1].frame);
    assert_ne!(
        introduced[0].publication.credential.unwrap().attempt,
        introduced[1].publication.credential.unwrap().attempt,
    );

    // Reassign real receipts only after both control introductions. The
    // original control, frame and attempt associations remain unchanged.
    {
        let mut first = first.0.pending.lock().unwrap();
        let mut second = second.0.pending.lock().unwrap();
        std::mem::swap(
            &mut first.pending.as_mut().unwrap().receipt,
            &mut second.pending.as_mut().unwrap().receipt,
        );
    }
    let owners = selected(
        &[
            ("<success id='1'/>", &first),
            ("<success id='2'/>", &second),
        ],
        18,
    )
    .take_all()
    .unwrap();
    for (index, owner) in owners.into_iter().enumerate() {
        let observed = observations[index].snapshot();
        assert_eq!(observed.introduced, Some(introduced[index]));
        let transferred = observed.transferred.unwrap();
        assert_eq!(transferred.control, introduced[index].control);
        assert_eq!(transferred.digest, introduced[index].digest);
        assert_eq!(transferred.frame, introduced[index].frame);
        assert_eq!(transferred.connection, introduced[index].connection);
        assert_eq!(transferred.publication, introduced[index].publication);
        assert_eq!(transferred.receipt, introduced[1 - index].receipt);
        assert_ne!(transferred.receipt, transferred.publication.receipt);
        assert_eq!(transferred.receipt, owner.receipt().publication_identity());
        let publication = owner.observation().clone();
        let mut port = FakePort::new(connection, Cut::Success);
        assert_eq!(
            owner.publish(&mut port).await,
            PublicationResult::IntegrityRejected,
        );
        assert_eq!(port.events, ["rejected"]);
        assert_eq!(publication.joins().begun_receipt, None);
        assert_eq!(observations[index].snapshot(), observed);
    }
}

#[tokio::test]
async fn sealed_bytes_and_aliases_cannot_start_another_native_write() {
    let (holder, observation) = fixture_control("<success/>", Uuid::from_u128(302));
    let alias = holder.clone();
    holder.recording().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let observed_calls = calls.clone();
    assert!(alias
        .clone()
        .write("<different/>".to_owned(), move |_| async move {
            observed_calls.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
        .await
        .is_err());
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    let owner = holder
        .write("<success/>".to_owned(), |_| async { Ok(()) })
        .await
        .unwrap();
    assert!(alias.recording().is_err());
    let observed_calls = calls.clone();
    assert!(alias
        .write("<success/>".to_owned(), move |_| async move {
            observed_calls.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
        .await
        .is_err());
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    assert_eq!(observation.snapshot().transport, Transport::Written);
    assert!(publish_unbound_fixture(vec![owner]).await);
    assert_eq!(observation.snapshot().publication, Knowledge::NotRequired);
}

#[test]
fn duplicate_ids_addresses_and_changed_controls_fail_before_holder_locks() {
    let connection = Uuid::from_u128(302);
    let (first, _) = fixture_control("<success/>", connection);
    let alias = first.clone();
    assert!(
        SelectedControls::new([("<success/>", Some(&first)), ("<success/>", Some(&alias))])
            .is_err()
    );
    assert!(SelectedControls::new([("<changed/>", Some(&first))]).is_err());
    let (mut second, _) = fixture_control("<success/>", connection);
    let distinct = Arc::get_mut(&mut second.0).unwrap();
    distinct.id = first.0.id;
    distinct.observation = first.0.observation.clone();
    assert!(!Arc::ptr_eq(&first.0, &second.0));
    assert_eq!(
        SelectedControls::new([("<success/>", Some(&first)), ("<success/>", Some(&second))])
            .err()
            .unwrap()
            .to_string(),
        "duplicate auth control holder in selection"
    );
    assert!(first.0.pending.lock().unwrap().pending.is_some());
    assert!(second.0.pending.lock().unwrap().pending.is_some());
}

#[test]
fn selection_requires_its_own_exposure_and_validates_every_holder_before_take() {
    let connection = Uuid::from_u128(302);
    let (first, _) = fixture_control("<success id='1'/>", connection);
    let (second, _) = fixture_control("<success id='2'/>", connection);
    let selection = selected(
        &[
            ("<success id='1'/>", &first),
            ("<success id='2'/>", &second),
        ],
        10,
    );
    let replacement = SelectedControls::new([("<success id='1'/>", Some(&first))]).unwrap();
    assert!(
        replacement.take_all().is_err(),
        "a fresh selection cannot steal prior exposure authority"
    );
    // Controlled stale state in the second holder must not consume the first.
    second.0.pending.lock().unwrap().phase = HolderPhase::Taken;
    assert!(selection.take_all().is_err());
    assert!(first.0.pending.lock().unwrap().pending.is_some());
    assert!(second.0.pending.lock().unwrap().pending.is_some());
}

#[tokio::test]
async fn unbound_selected_control_does_not_take_queued_bind_owner() {
    use northstar_auth_application::authentication::publication::{
        CredentialCall, CredentialInvocation, CredentialKind, CredentialPreparation,
        PreparationResult,
    };
    let connection = Uuid::from_u128(302);
    let unbound_frame = FrameExecution::for_saved_case(
        super::super::protocol::ClientTransport::Bosh,
        "<authenticate/>",
        Uuid::from_u128(710),
    );
    let u_owner = observed_unbound_owner(&unbound_frame, connection).await;
    let u = u_owner.observation().clone();
    let unbound = u_owner
        .seal(
            "<success/>",
            CapturedEffects {
                route: RouteIntent::Unbound,
                caps: None,
                notification: None,
            },
        )
        .unwrap();
    let bound_frame = FrameExecution::for_saved_case(
        super::super::protocol::ClientTransport::Bosh,
        "<iq/>",
        Uuid::from_u128(711),
    );
    let prepared = bound_frame
        .prepare_credential(CredentialKind::Binding, connection)
        .unwrap();
    let invocation = prepared
        .binding(
            connection,
            Uuid::from_u128(303),
            2,
            "fixture@example.test/captured",
            120,
            Some(Uuid::from_u128(304)),
            None,
        )
        .unwrap();
    invocation
        .enter_binding(
            connection,
            Uuid::from_u128(303),
            2,
            "fixture@example.test/captured",
            120,
            Some(Uuid::from_u128(304)),
            None,
        )
        .unwrap();
    CredentialInvocation::begin(Some(&invocation), std::future::ready(Ok::<(), ()>(())))
        .await
        .unwrap();
    CredentialInvocation::eligibility(
        Some(&invocation),
        std::future::ready(Ok::<_, ()>(Some(true))),
    )
    .await
    .unwrap();
    invocation.transaction_returned();
    invocation.preparation_entered(CredentialPreparation::Binding);
    invocation.preparation_returned(CredentialPreparation::Binding, PreparationResult::Present);
    invocation.preparation_entered(CredentialPreparation::Stage);
    let stage = StagedLoginEpoch {
        operation_id: Uuid::from_u128(301),
        connection_id: connection,
        user_id: Uuid::from_u128(303),
        device_id: Uuid::from_u128(304),
        auth_generation: 2,
        epoch: 999,
    };
    invocation.stage_id(stage.operation_id);
    invocation.stage_returned(&Ok(Some(stage)));
    CredentialInvocation::commit(Some(&invocation), std::future::ready(Ok::<(), ()>(())))
        .await
        .unwrap();
    let receipt = CredentialCommitReceipt::new(
        None,
        Some(stage),
        Some(BindingPublication {
            connection_id: connection,
            user_id: Uuid::from_u128(303),
            full_jid: "fixture@example.test/captured".to_owned(),
            lease_seconds: 120,
        }),
    );
    invocation.constructed(&receipt);
    let result = Ok(crate::services::sm::BindingFinalizationOutcome::Committed { receipt });
    invocation.binding_returned(&result);
    drop(invocation);
    let Ok(crate::services::sm::BindingFinalizationOutcome::Committed { receipt }) = result else {
        unreachable!()
    };
    let owner =
        KnownCredentialOwner::from_observed(receipt, bound_frame, connection, &prepared).unwrap();
    let b = owner.observation().clone();
    let bound = owner
        .seal(
            "<iq type='result'/>",
            fixture_bound_effects(connection, true),
        )
        .unwrap();
    let u_credential = u.credential().unwrap();
    let b_credential = b.credential().unwrap();
    assert_eq!(u_credential.snapshot().commit, CredentialCall::Ok);
    assert_eq!(b_credential.snapshot().commit, CredentialCall::Ok);
    assert_ne!(
        u_credential.snapshot().attempt,
        b_credential.snapshot().attempt
    );
    let prior = b.snapshot();
    let prior_credential = b_credential.snapshot();
    let owners = selected(&[("<success/>", &unbound)], 10)
        .take_all()
        .unwrap();
    assert!(publish_unbound_fixture(owners).await);
    assert_eq!(u.snapshot().publication, Knowledge::NotRequired);
    assert_eq!(u.snapshot().terminal, Some(Terminal::Completed));
    assert_eq!(b.snapshot(), prior);
    assert_eq!(b_credential.snapshot(), prior_credential);
    assert!(bound.0.pending.lock().unwrap().pending.is_some());
}

#[tokio::test]
async fn shared_sequence_uses_captured_effects_and_preserves_deferred_success() {
    for cut in [Cut::Success, Cut::NotifyError] {
        let connection = Uuid::from_u128(302);
        let (holder, observation) = fixture_bound_control("<success/>", connection, true);
        let mut owners = selected(&[("<success/>", &holder)], 10).take_all().unwrap();
        let mut port = FakePort::new(connection, cut);
        let result = owners.pop().unwrap().publish(&mut port).await;
        assert_eq!(
            result,
            if matches!(cut, Cut::NotifyError) {
                PublicationResult::CompletedWithDeferredNotification
            } else {
                PublicationResult::Completed
            }
        );
        assert_eq!(
            &port.events[..6],
            [
                "service",
                "repository",
                "route",
                "activate",
                "caps",
                "local_notification"
            ]
        );
        assert_eq!(port.caps_generation, Some(9));
        assert_eq!(
            port.notification,
            Some((
                "fixture@example.test".to_owned(),
                Uuid::from_u128(303),
                Uuid::from_u128(304),
                "fixture@example.test/captured".to_owned(),
                7
            ))
        );
        assert_eq!(
            observation.snapshot().publication,
            Knowledge::ReceiptKnown(Some(7))
        );
        assert_eq!(
            observation.snapshot().returned,
            Some(Returned::Authenticated(Some(7)))
        );
        assert!(observation.completed());
    }
}

#[tokio::test]
async fn failed_or_unwitnessed_publication_never_starts_route_effects() {
    for cut in [
        Cut::BeforeCommit,
        Cut::CommitError,
        Cut::BareSuccess,
        Cut::WrongReturn,
    ] {
        let connection = Uuid::from_u128(302);
        let (holder, observation) = fixture_bound_control("<success/>", connection, false);
        let owner = selected(&[("<success/>", &holder)], 10)
            .take_all()
            .unwrap()
            .pop()
            .unwrap();
        let mut port = FakePort::new(connection, cut);
        assert!(!owner.publish(&mut port).await.transport_succeeded());
        assert!(!port.events.contains(&"route"));
        assert_eq!(
            observation.snapshot().transport,
            Transport::BoshAccepted { rid: 10 }
        );
        assert_eq!(
            observation.snapshot().publication,
            match cut {
                Cut::CommitError => Knowledge::CommitCallEntered,
                Cut::WrongReturn => Knowledge::ReceiptKnown(Some(7)),
                _ => Knowledge::BeforeCommit,
            }
        );
    }
}

#[tokio::test]
async fn fifo_failure_keeps_completed_prefix_and_retires_only_selected_suffix() {
    let connection = Uuid::from_u128(302);
    let (u, u_observation) = fixture_control("<success id='u'/>", connection);
    let (b, b_observation) = fixture_bound_control("<success id='b'/>", connection, false);
    let (suffix, suffix_observation) = fixture_control("<success id='suffix'/>", connection);
    let (_queued, queued_observation) = fixture_control("<success id='queued'/>", connection);
    let prior = queued_observation.snapshot();
    let mut owners = selected(
        &[
            ("<success id='u'/>", &u),
            ("<success id='b'/>", &b),
            ("<success id='suffix'/>", &suffix),
        ],
        10,
    )
    .take_all()
    .unwrap()
    .into_iter();
    let mut port = FakePort::new(connection, Cut::RouteRejected);
    assert_eq!(
        owners.next().unwrap().publish(&mut port).await,
        PublicationResult::Completed
    );
    assert_eq!(
        owners.next().unwrap().publish(&mut port).await,
        PublicationResult::RouteRejected
    );
    drop(owners);
    assert_eq!(u_observation.snapshot().terminal, Some(Terminal::Completed));
    assert_eq!(
        b_observation.snapshot().publication,
        Knowledge::ReceiptKnown(Some(7))
    );
    assert_eq!(
        suffix_observation.snapshot().terminal,
        Some(Terminal::ExposedNotAttempted)
    );
    assert_eq!(
        suffix_observation.snapshot().publication,
        Knowledge::NotStarted
    );
    assert_eq!(queued_observation.snapshot(), prior);
}

#[test]
fn commit_or_caps_cancel_keeps_transport_and_prior_publication_facts() {
    for cut in [Cut::CommitPending, Cut::CapsPending] {
        let connection = Uuid::from_u128(302);
        let (holder, observation) = fixture_bound_control("<success/>", connection, false);
        let owner = selected(&[("<success/>", &holder)], 10)
            .take_all()
            .unwrap()
            .pop()
            .unwrap();
        let mut port = FakePort::new(connection, cut);
        let mut future = Box::pin(owner.publish(&mut port));
        assert!(poll_once(future.as_mut()).is_pending());
        drop(future);
        let snapshot = observation.snapshot();
        assert_eq!(snapshot.terminal, Some(Terminal::Cancelled));
        assert_eq!(snapshot.transport, Transport::BoshAccepted { rid: 10 });
        assert_eq!(
            snapshot.publication,
            if matches!(cut, Cut::CommitPending) {
                Knowledge::CommitCallEntered
            } else {
                Knowledge::ReceiptKnown(Some(7))
            }
        );
        assert_eq!(
            snapshot.effects.caps_entered,
            matches!(cut, Cut::CapsPending)
        );
        assert!(!snapshot.effects.caps_returned);
    }
}

#[tokio::test]
async fn completed_handler_transfers_publication_lifetime_to_its_control() {
    let execution = FrameExecution::for_saved_case(
        super::super::protocol::ClientTransport::Bosh,
        "<authenticate/>",
        Uuid::from_u128(350),
    );
    let owner = observed_unbound_owner(&execution, Uuid::from_u128(302)).await;
    let observation = owner.observation().clone();
    let credential = observation.credential().unwrap();
    assert!(credential.snapshot().transferred);

    let wrong = FrameExecution::for_saved_case(
        super::super::protocol::ClientTransport::Bosh,
        "<iq/>",
        Uuid::from_u128(351),
    );
    assert_eq!(
        wrong
            .retain_auth_receipt(observation.clone())
            .unwrap_err()
            .to_string(),
        "auth receipt belongs to another frame"
    );
    wrong.run(async { Ok(()) }).await.unwrap();
    assert_eq!(observation.snapshot().handler, None);
    execution.retain_auth_receipt(observation.clone()).unwrap();
    let holder = execution
        .run(async move {
            owner.seal(
                "<success/>",
                CapturedEffects {
                    route: RouteIntent::Unbound,
                    caps: None,
                    notification: None,
                },
            )
        })
        .await
        .unwrap();
    assert_eq!(
        observation.snapshot().handler,
        Some(HandlerReturn::Completed)
    );
    assert_eq!(
        credential.snapshot().handler,
        Some(HandlerReturn::Completed)
    );
    assert_eq!(
        credential.snapshot().commit,
        northstar_auth_application::authentication::publication::CredentialCall::Ok
    );
    assert_eq!(observation.snapshot().terminal, None);
    assert_eq!(observation.snapshot().frame, Some(Uuid::from_u128(350)));
    let owners = selected(&[("<success/>", &holder)], 10).take_all().unwrap();
    assert!(publish_unbound_fixture(owners).await);
    assert_eq!(
        observation.snapshot().handler,
        Some(HandlerReturn::Completed)
    );
    assert_eq!(observation.snapshot().terminal, Some(Terminal::Completed));
}

#[derive(Default)]
struct MemoryWrite {
    bytes: Vec<u8>,
    fail_at: Option<usize>,
    fail_flush: bool,
    flushes: usize,
}
impl tokio::io::AsyncWrite for MemoryWrite {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if this.fail_at.is_some_and(|limit| this.bytes.len() >= limit) {
            return Poll::Ready(Err(std::io::Error::other("controlled partial write")));
        }
        let count = bytes.len().min(3).min(
            this.fail_at
                .map_or(usize::MAX, |limit| limit - this.bytes.len()),
        );
        this.bytes.extend_from_slice(&bytes[..count]);
        Poll::Ready(Ok(count))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        this.flushes += 1;
        if this.fail_flush {
            Poll::Ready(Err(std::io::Error::other("controlled flush failure")))
        } else {
            Poll::Ready(Ok(()))
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn actual_tcp_send_partial_and_flush_failure_never_publish_authentication() {
    for flush_failure in [false, true] {
        let connection = Uuid::from_u128(302);
        let (holder, observation) = fixture_bound_control("<success/>", connection, false);
        holder.recording().unwrap();
        let mut io = MemoryWrite {
            fail_at: (!flush_failure).then_some(1),
            fail_flush: flush_failure,
            ..MemoryWrite::default()
        };
        let writer = &mut io;
        let result = holder
            .write("<success/>".to_owned(), |control| async move {
                super::super::send(writer, &control).await
            })
            .await;
        assert!(result.is_err());
        assert_eq!(
            io.bytes.len(),
            if flush_failure { "<success/>".len() } else { 1 }
        );
        assert_eq!(io.flushes, usize::from(flush_failure));
        assert_eq!(observation.snapshot().transport, Transport::WriteEntered);
        assert_eq!(observation.snapshot().publication, Knowledge::NotStarted);
    }
}

#[tokio::test]
async fn actual_tcp_write_survives_publication_failure_and_caps_cancellation() {
    for cut in [Cut::BeforeCommit, Cut::CommitPending, Cut::CapsPending] {
        let connection = Uuid::from_u128(302);
        let (holder, observation) = fixture_bound_control("<success/>", connection, false);
        holder.recording().unwrap();
        let mut io = MemoryWrite::default();
        let writer = &mut io;
        let owner = holder
            .write("<success/>".to_owned(), |control| async move {
                super::super::send(writer, &control).await
            })
            .await
            .unwrap();
        assert_eq!(io.bytes, b"<success/>");
        assert_eq!(io.flushes, 1);
        let mut port = FakePort::new(connection, cut);
        let mut future = Box::pin(owner.publish(&mut port));
        let polled = poll_once(future.as_mut());
        if matches!(cut, Cut::BeforeCommit) {
            assert!(matches!(
                polled,
                Poll::Ready(PublicationResult::BackendFailure)
            ));
        } else {
            assert!(polled.is_pending());
        }
        drop(future);
        let snapshot = observation.snapshot();
        assert_eq!(snapshot.transport, Transport::Written);
        assert_eq!(
            snapshot.publication,
            match cut {
                Cut::BeforeCommit => Knowledge::BeforeCommit,
                Cut::CommitPending => Knowledge::CommitCallEntered,
                _ => Knowledge::ReceiptKnown(Some(7)),
            }
        );
        assert_eq!(
            snapshot.terminal,
            Some(if matches!(cut, Cut::BeforeCommit) {
                Terminal::Failed
            } else {
                Terminal::Cancelled
            })
        );
    }
}

#[tokio::test]
async fn actual_websocket_live_write_gate_preserves_success_and_cancellation() {
    for cancel in [0, 1, 2, 3] {
        let connection = Uuid::from_u128(302);
        let (holder, observation) = fixture_control("<success/>", connection);
        holder.recording().unwrap();
        let shutdown = CancellationToken::new();
        let revoke = CancellationToken::new();
        let backpressure = CancellationToken::new();
        match cancel {
            1 => shutdown.cancel(),
            2 => revoke.cancel(),
            3 => backpressure.cancel(),
            _ => {}
        }
        let signals = super::super::protocol::SessionTerminationSignals::from_test_tokens(
            revoke,
            backpressure,
        );
        let cancellation = super::super::WebSocketSendCancellation {
            actor_shutdown: &shutdown,
            signals: &signals,
        };
        let polls = Arc::new(AtomicUsize::new(0));
        let write_polls = polls.clone();
        let result = holder
            .write("<success/>".to_owned(), |control| async move {
                assert_eq!(control, "<success/>");
                let sent = super::super::bounded_websocket_live_write(
                    async move {
                        write_polls.fetch_add(1, Ordering::Relaxed);
                        Ok::<(), std::io::Error>(())
                    },
                    &cancellation,
                )
                .await;
                ensure!(sent, "controlled WS cancellation");
                Ok(())
            })
            .await;
        assert_eq!(polls.load(Ordering::Relaxed), usize::from(cancel == 0));
        if cancel == 0 {
            assert!(publish_unbound_fixture(vec![result.unwrap()]).await);
            assert_eq!(observation.snapshot().transport, Transport::Written);
        } else {
            assert!(result.is_err());
            assert_eq!(observation.snapshot().publication, Knowledge::NotStarted);
        }
    }
}

struct PanicChild {
    _owner: OwnedPublication,
    ready: bool,
    panic_poll: bool,
    dropped: Arc<AtomicBool>,
}
impl Future for PanicChild {
    type Output = PublicationResult;
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        if self.panic_poll {
            panic!("controlled auth poll panic");
        }
        if self.ready {
            Poll::Ready(PublicationResult::Completed)
        } else {
            Poll::Pending
        }
    }
}
impl Drop for PanicChild {
    fn drop(&mut self) {
        assert_eq!(
            self._owner.observation().snapshot().terminal,
            None,
            "child must be destroyed before publication retirement"
        );
        self.dropped.store(true, Ordering::Release);
        if !self.panic_poll {
            panic!("controlled auth child destructor panic");
        }
    }
}
#[test]
fn publication_child_drop_and_caught_poll_panics_retire_after_destruction() {
    for (ready, panic_poll) in [(false, false), (true, false), (false, true)] {
        let connection = Uuid::from_u128(302);
        let (holder, observation) = fixture_control("<success/>", connection);
        let owner = selected(&[("<success/>", &holder)], 10)
            .take_all()
            .unwrap()
            .pop()
            .unwrap();
        let dropped = Arc::new(AtomicBool::new(false));
        let child_dropped = dropped.clone();
        let mut future = Box::pin(owner.run(move |owner| PanicChild {
            _owner: owner,
            ready,
            panic_poll,
            dropped: child_dropped,
        }));
        let polled = std::panic::catch_unwind(AssertUnwindSafe(|| poll_once(future.as_mut())));
        if ready || panic_poll {
            assert!(polled.is_err());
        } else {
            assert!(matches!(polled, Ok(Poll::Pending)));
        }
        let _ = std::panic::catch_unwind(AssertUnwindSafe(|| drop(future)));
        assert!(dropped.load(Ordering::Acquire));
        assert_eq!(observation.snapshot().terminal, Some(Terminal::Panicked));
    }
}
