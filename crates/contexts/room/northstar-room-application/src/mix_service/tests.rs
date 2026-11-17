use super::*;

mod holders;
mod repository;
use repository::{Reply, Repository};

fn recording_service(repository: Repository) -> MixService<Repository> {
    let generations = Arc::new(Vec::new());
    MixService::new_with_outbox_database_admission(
        repository,
        "LOCAL.test".into(),
        MixMessageContentKeyring::new(Arc::clone(&generations)),
        MixRetractionContentKeyring::new(generations),
        northstar_runtime::durable_outbox::DurableOutboxDatabaseAdmission::for_primary_pool(2),
        "public".into(),
    )
    .unwrap()
}

async fn database_turn<T>(
    service: &MixService<Repository>,
    repository: &Repository,
    label: &str,
    while_blocked: impl FnOnce(),
    future: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    let held = service.outbox_db_admission_guard().await;
    let mut future = Box::pin(future);
    assert!(futures::poll!(&mut future).is_pending(), "{label}");
    assert!(repository.calls().is_empty(), "{label}");
    while_blocked();
    drop(held);
    let result = future.await;
    assert_eq!(repository.calls().len(), 1, "{label}");
    assert_eq!(
        service.outbox_db_admission.available_permits(),
        1,
        "{label}"
    );
    result
}

#[tokio::test]
async fn mix_service_preserves_execution_contracts() {
    crate::mix::assert_store_allocations_cannot_be_substituted();
    configured_foreground_service_binds_requests_and_wakes_only_committed_audiences().await;
    transport_acknowledgement_and_bosh_transfer_keep_exact_database_turns().await;
    observed_worker_turns_bind_results_and_wake_only_matching_settlements().await;
    holders::worker_holders_destroy_children_before_retirement_even_during_panics();
}

async fn configured_foreground_service_binds_requests_and_wakes_only_committed_audiences() {
    use crate::mix::{Knowledge, ReadReturned, Returned, Wake};
    let fixture = test_service(2);
    let configured = MixService::new_with_outbox_database_admission(
        Repository::default(),
        "EXAMPLE.test".into(),
        fixture.message_identity,
        fixture.retraction_identity,
        fixture.outbox_db_admission,
        "public".into(),
    )
    .unwrap();
    let mut ingress = foreground::fixture::prepared(false).ingress().clone();
    ingress.channel_jid = "room@mix.example.test".into();
    assert!(
        configured.prepare_mix_foreground(ingress).is_ok(),
        "configured canonical subdomain"
    );
    assert!(
        matches!(
            configured
                .prepare_mix_foreground(foreground::fixture::prepared(false).ingress().clone()),
            Err(foreground::Rejected::Input)
        ),
        "default domain is not authority"
    );
    for (label, reply, audience) in [
        ("committed audience", Reply::Stored(true), true),
        ("committed empty audience", Reply::Stored(false), false),
        ("returned without receipt", Reply::ReturnedOnly, false),
        ("repository error", Reply::Error, false),
    ] {
        let owner = foreground::Observation::new(foreground::fixture::prepared(false));
        let request = owner
            .store_request(foreground::fixture::command(false))
            .unwrap();
        let repository = Repository {
            reply,
            request_address: Some(std::ptr::from_ref(&request) as usize),
            ..Repository::default()
        };
        let service = recording_service(repository.clone());
        assert_eq!(service.configured_mix_domain, "mix.local.test", "{label}");
        assert!(
            service
                .prepare_mix_foreground(foreground::fixture::prepared(false).ingress().clone())
                .is_ok(),
            "{label}"
        );
        let mut foreign = foreground::fixture::prepared(false).ingress().clone();
        foreign.channel_jid = "room@mix.attacker.test".into();
        assert!(
            matches!(
                service.prepare_mix_foreground(foreign.clone()),
                Err(foreground::Rejected::Input)
            ),
            "{label}"
        );
        let foreign_owner = foreground::Observation::new(foreground::PreparedIngress::new(foreign));
        let foreign_request = foreign_owner
            .store_request(foreground::fixture::command(false))
            .unwrap();
        assert!(
            service
                .store_mix_message_observed(&foreign_request)
                .await
                .is_err(),
            "foreign store"
        );
        assert!(!foreign_owner.snapshot().repository_started);
        assert!(repository.calls().is_empty());
        let held = service.delivery_admission_guard().await;
        let clone = service.clone();
        let mut store = Box::pin(clone.store_mix_message_observed(&request));
        assert!(futures::poll!(&mut store).is_pending(), "{label}");
        assert!(repository.calls().is_empty(), "{label}");
        assert!(!owner.snapshot().repository_started, "{label}");
        drop(held);
        let std::task::Poll::Ready(result) = futures::poll!(&mut store) else {
            panic!("{label}: finite repository must return with its receipt")
        };
        drop(store);
        assert_eq!(repository.calls(), ["observed_store"], "{label}");
        assert_eq!(
            service.delivery_wake.generation(),
            u64::from(audience),
            "{label}"
        );
        let snapshot = owner.snapshot();
        assert!(snapshot.repository_started, "{label}");
        match reply {
            Reply::Stored(has_audience) => {
                assert_eq!(
                    *result.unwrap(),
                    foreground::fixture::returned(has_audience),
                    "{label}"
                );
                let Knowledge::ReceiptKnown(fact) = snapshot.knowledge else {
                    panic!("{label}: receipt missing")
                };
                assert_eq!(*fact, foreground::fixture::stored(has_audience), "{label}");
                assert_eq!(
                    snapshot.returned,
                    Some(Returned::AcceptedStored(Uuid::from_u128(72))),
                    "{label}"
                );
                assert_eq!(
                    snapshot.wake,
                    if audience {
                        Wake::Invoked
                    } else {
                        Wake::Unavailable
                    },
                    "{label}"
                );
            }
            Reply::ReturnedOnly => {
                assert_eq!(
                    result.unwrap_err().downcast_ref::<foreground::Rejected>(),
                    Some(&foreground::Rejected::MissingReceipt),
                    "{label}"
                );
                assert_eq!(snapshot.knowledge, Knowledge::NoCommitRequested, "{label}");
                assert_eq!(
                    snapshot.returned,
                    Some(Returned::Admission(Arc::new(
                        foreground::fixture::returned(true)
                    ))),
                    "{label}"
                );
            }
            Reply::Error => {
                assert_eq!(
                    result.unwrap_err().to_string(),
                    "recorded repository failure",
                    "{label}"
                );
                assert_eq!(snapshot.returned, Some(Returned::Error), "{label}");
            }
            _ => unreachable!(),
        }
        assert!(
            service.store_mix_message_observed(&request).await.is_err(),
            "no second store"
        );
        assert_eq!(repository.calls().len(), 1);
        assert_eq!(service.delivery_wake.generation(), u64::from(audience));
    }

    let owner = foreground::Observation::new(foreground::fixture::prepared(false));
    let request = owner
        .store_request(foreground::fixture::command(false))
        .unwrap();
    let repository = Repository {
        reply: Reply::PendingCommit,
        request_address: Some(std::ptr::from_ref(&request) as usize),
        ..Repository::default()
    };
    let service = recording_service(repository.clone());
    let clone = service.clone();
    let mut store = Box::pin(clone.store_mix_message_observed(&request));
    assert!(
        futures::poll!(&mut store).is_pending(),
        "actual commit pending"
    );
    assert_eq!(
        owner.snapshot().knowledge,
        Knowledge::CommitCallEntered(Arc::new(foreground::fixture::stored(true)))
    );
    assert_eq!(owner.snapshot().returned, None);
    assert_eq!(repository.calls(), ["observed_store"]);
    let mut next = Box::pin(service.delivery_admission_guard());
    assert!(
        futures::poll!(&mut next).is_pending(),
        "permit spans actual commit"
    );
    drop(store);
    drop(next.await);
    assert_eq!(service.delivery_wake.generation(), 0);
    assert_eq!(owner.snapshot().wake, Wake::Unavailable);

    for (label, foreign) in [("configured replay", false), ("foreign replay", true)] {
        let mut ingress = foreground::fixture::prepared(true).ingress().clone();
        if foreign {
            ingress.channel_jid = "room@mix.attacker.test".into();
        }
        let owner = foreground::Observation::new(foreground::PreparedIngress::new(ingress));
        let request = owner.replay_request().unwrap().unwrap();
        let repository = Repository {
            reply: Reply::Stored(false),
            request_address: Some(std::ptr::from_ref(&request) as usize),
            ..Repository::default()
        };
        let service = recording_service(repository.clone());
        let result = service.lookup_mix_message_replay_observed(&request).await;
        if foreign {
            assert!(result.is_err(), "{label}");
            assert!(repository.calls().is_empty(), "{label}");
            assert!(!owner.snapshot().replay.started, "{label}");
        } else {
            assert_eq!(result.unwrap(), MixBusinessReplay::Miss, "{label}");
            assert_eq!(repository.calls(), ["observed_replay"], "{label}");
            assert_eq!(
                owner.snapshot().replay.returned,
                Some(ReadReturned::Outcome(MixBusinessReplay::Miss)),
                "{label}"
            );
        }
        assert_eq!(service.delivery_wake.generation(), 0, "{label}");
    }

    let prepared = foreground::fixture::prepared(false);
    let slot = foreground::MixForegroundSlot::default();
    let owner = slot.register(&prepared).unwrap();
    let same = slot.register(&prepared).unwrap();
    let before = owner.snapshot();
    assert!(
        matches!(
            slot.register(&foreground::fixture::prepared(false)),
            Err(foreground::Rejected::Input)
        ),
        "conflicting registration"
    );
    assert_eq!(owner.snapshot(), before);
    owner
        .store_request(foreground::fixture::command(false))
        .unwrap();
    assert!(
        matches!(
            same.store_request(foreground::fixture::command(false)),
            Err(foreground::Rejected::AlreadyIssued)
        ),
        "same slot owner"
    );
    let retired = slot.retire(foreground::TerminalReason::Cancelled).unwrap();
    assert!(
        matches!(slot.register(&prepared), Err(foreground::Rejected::Retired)),
        "retired registration"
    );
    assert_eq!(
        slot.retire(foreground::TerminalReason::Completed),
        Some(retired)
    );
    let empty = foreground::MixForegroundSlot::default();
    assert!(empty
        .retire(foreground::TerminalReason::Cancelled)
        .is_none());
    assert!(
        matches!(
            empty.register(&prepared),
            Err(foreground::Rejected::Retired)
        ),
        "retired empty slot"
    );
    let directly_retired = foreground::MixForegroundSlot::default();
    directly_retired
        .register(&prepared)
        .unwrap()
        .retire(foreground::TerminalReason::Cancelled);
    assert!(
        matches!(
            directly_retired.register(&prepared),
            Err(foreground::Rejected::Retired)
        ),
        "retired observation"
    );
}

async fn transport_acknowledgement_and_bosh_transfer_keep_exact_database_turns() {
    use northstar_delivery_core::{
        bosh_ownership, native_write, MixDelivery, TransportOwnershipSource,
    };
    let source = MixDelivery {
        delivery_id: Uuid::from_u128(101),
        lease_token: Uuid::from_u128(102),
    };
    for (label, observed, reply, expected_wake) in [
        ("legacy moved", false, Reply::Bool(true), 1),
        ("legacy lost token", false, Reply::Bool(false), 0),
        ("legacy failed", false, Reply::Error, 0),
        ("native moved", true, Reply::Bool(true), 1),
        ("native lost token", true, Reply::Bool(false), 0),
        ("native failed", true, Reply::Error, 0),
    ] {
        let observation =
            native_write::Observation::new(Some(TransportOwnershipSource::Mix(source)));
        observation
            .begin_record(Some(TransportOwnershipSource::Mix(source)))
            .unwrap();
        assert_eq!(
            observation.recorded(false).unwrap(),
            Some(TransportOwnershipSource::Mix(source))
        );
        observation
            .fenced(TransportOwnershipSource::Mix(source))
            .unwrap();
        observation.begin_write().unwrap();
        let request = observation
            .writer_completed(native_write::WriterResult::FullWrite)
            .unwrap()
            .unwrap()
            .begin_ack()
            .unwrap()
            .unwrap();
        let repository = Repository {
            reply,
            request_address: observed.then_some(std::ptr::from_ref(&request) as usize),
            ..Repository::default()
        };
        let service = recording_service(repository.clone());
        let clone = service.clone();
        let result = database_turn(&service, &repository, label, || {}, async {
            if observed {
                clone.acknowledge_mix_socket_write(&request).await
            } else {
                clone
                    .acknowledge_mix_delivery(source.delivery_id, source.lease_token)
                    .await
            }
        })
        .await;
        match reply {
            Reply::Bool(expected) => assert_eq!(result.unwrap(), expected, "{label}"),
            _ => assert_eq!(
                result.unwrap_err().to_string(),
                "recorded repository failure",
                "{label}"
            ),
        }
        assert_eq!(
            repository.calls(),
            [format!(
                "ack:{}:{}:{observed}",
                source.delivery_id, source.lease_token
            )],
            "{label}"
        );
        assert_eq!(service.delivery_wake.generation(), expected_wake, "{label}");
    }
    for (label, reply) in [
        ("bosh transferred", Reply::Bool(true)),
        ("bosh failed", Reply::Error),
    ] {
        let session_id = Uuid::from_u128(104);
        let operation = bosh_ownership::Operation::new(bosh_ownership::Scope {
            session_id,
            ttl_seconds: 47,
            kind: bosh_ownership::OperationKind::Outbound,
        });
        let request = operation.begin_transfer(source).unwrap();
        let repository = Repository {
            reply,
            request_address: Some(std::ptr::from_ref(&request) as usize),
            ..Repository::default()
        };
        let service = recording_service(repository.clone());
        let clone = service.clone();
        let result = database_turn(
            &service,
            &repository,
            label,
            || {},
            clone.transfer_mix_delivery_to_bosh(&request),
        )
        .await;
        if matches!(reply, Reply::Error) {
            assert_eq!(
                result.unwrap_err().to_string(),
                "recorded repository failure",
                "{label}"
            );
        } else {
            assert_eq!(
                result.unwrap(),
                MixDelivery {
                    lease_token: Uuid::from_u128(103),
                    ..source
                },
                "{label}"
            );
        }
        assert_eq!(
            repository.calls(),
            [format!("bosh:{source:?}:{session_id}:47")],
            "{label}"
        );
        assert_eq!(service.delivery_wake.generation(), 0, "{label}");
    }
}

async fn observed_worker_turns_bind_results_and_wake_only_matching_settlements() {
    use outbox::core::*;
    for (label, reply) in [
        ("worker success", Reply::Worker),
        ("worker error", Reply::Error),
    ] {
        let owner = ClaimObservation::new(ClaimCommand {
            limit: 1,
            max_bytes: 8 * 1024 * 1024,
        });
        let request = owner.request().unwrap();
        let repository = Repository {
            reply,
            request_address: Some(std::ptr::from_ref(&request) as usize),
            ..Repository::default()
        };
        let service = recording_service(repository.clone());
        let clone = service.clone();
        let result = database_turn(
            &service,
            &repository,
            label,
            || {
                assert!(
                    !owner.snapshot().started,
                    "{label}: start waits for admission"
                )
            },
            clone.claim_mix_deliveries_observed(&request),
        )
        .await;
        assert_eq!(
            repository.calls(),
            [format!("claim:{:?}", request.command())],
            "{label}"
        );
        assert!(owner.snapshot().started, "{label}");
        if matches!(reply, Reply::Error) {
            let Err(error) = result else {
                panic!("{label}: claim unexpectedly succeeded")
            };
            assert_eq!(error.to_string(), "recorded repository failure");
            assert_eq!(owner.snapshot().returned, Some(ClaimReturned::Error));
        } else {
            let attempts = result.unwrap();
            assert_eq!(attempts.len(), 1, "{label}");
            assert_eq!(
                owner.snapshot().returned,
                Some(ClaimReturned::Accepted(1)),
                "{label}"
            );
            assert_eq!(
                attempts[0].observation().row(),
                outbox::fixture::claimed_rows(false)[0].as_ref(),
                "{label}"
            );
            let ClaimKnowledge::StatementReceipt(rows) = owner.snapshot().knowledge else {
                panic!("{label}: claim receipt")
            };
            assert!(
                std::ptr::eq(rows[0].as_ref(), attempts[0].observation().row()),
                "{label}"
            );
            assert_eq!(rows[0].as_ref(), attempts[0].observation().row(), "{label}");
        }
        assert_eq!(service.delivery_wake.generation(), 0);

        let (owner, route) = outbox::fixture::route(true);
        let request = route
            .archive_request(
                Uuid::from_u128(401),
                Uuid::from_u128(402),
                Some("client-archive".into()),
            )
            .unwrap();
        let repository = Repository {
            reply,
            request_address: Some(std::ptr::from_ref(&request) as usize),
            ..Repository::default()
        };
        let service = recording_service(repository.clone());
        let clone = service.clone();
        let result = database_turn(
            &service,
            &repository,
            label,
            || {
                assert!(
                    !owner.snapshot().archive.started,
                    "{label}: start waits for admission"
                )
            },
            clone.outbox_archive_mix_message_once_observed(&request),
        )
        .await;
        assert_eq!(
            repository.calls(),
            [format!("archive:{:?}", request.command())],
            "{label}"
        );
        assert!(owner.snapshot().archive.started, "{label}");
        if matches!(reply, Reply::Error) {
            assert_eq!(
                result.unwrap_err().to_string(),
                "recorded repository failure",
                "{label}"
            );
            assert_eq!(
                owner.snapshot().archive.returned,
                Some(ArchiveReturned::Error),
                "{label}"
            );
        } else {
            assert_eq!(
                result.unwrap(),
                ArchiveResult::Stored(Uuid::from_u128(402)),
                "{label}"
            );
            assert_eq!(
                owner.snapshot().archive.knowledge,
                ArchiveKnowledge::ReceiptKnown(ArchiveResult::Stored(Uuid::from_u128(402))),
                "{label}"
            );
            assert_eq!(
                owner.snapshot().archive.returned,
                Some(ArchiveReturned::Outcome(ArchiveResult::Stored(
                    Uuid::from_u128(402)
                ))),
                "{label}"
            );
        }
        assert_eq!(service.delivery_wake.generation(), 0);

        let (owner, _route) = outbox::fixture::route(false);
        let request = owner.renewal_request().unwrap();
        let repository = Repository {
            reply,
            request_address: Some(std::ptr::from_ref(&request) as usize),
            ..Repository::default()
        };
        let service = recording_service(repository.clone());
        let clone = service.clone();
        let result = database_turn(
            &service,
            &repository,
            label,
            || {
                assert!(
                    !owner.snapshot().renewal.started,
                    "{label}: start waits for admission"
                )
            },
            clone.renew_mix_delivery_lease_observed(&request),
        )
        .await;
        assert_eq!(
            repository.calls(),
            [format!("renew:{:?}", request.source())],
            "{label}"
        );
        assert!(owner.snapshot().renewal.started, "{label}");
        if matches!(reply, Reply::Error) {
            assert_eq!(
                result.unwrap_err().to_string(),
                "recorded repository failure",
                "{label}"
            );
            assert_eq!(
                owner.snapshot().renewal.returned,
                Some(RenewalReturned::Error),
                "{label}"
            );
            assert!(owner.snapshot().aborted, "{label}");
        } else {
            assert!(result.unwrap(), "{label}");
            assert_eq!(
                owner.snapshot().renewal.returned,
                Some(RenewalReturned::Outcome(true)),
                "{label}"
            );
            assert_eq!(
                owner.snapshot().renewal.last_receipt,
                Some((1, true)),
                "{label}"
            );
        }
        assert!(!owner.snapshot().renewal.pending, "{label}");
        assert_eq!(service.delivery_wake.generation(), 0);
    }

    for (label, result, wake) in [
        ("ack moved", SettlementResult::Ack(true), true),
        ("ack token lost", SettlementResult::Ack(false), false),
        ("defer moved", SettlementResult::Defer(true), false),
        ("defer token lost", SettlementResult::Defer(false), false),
        (
            "retry token lost",
            SettlementResult::Retry(RetryResult::LeaseLost),
            false,
        ),
        (
            "retry scheduled",
            SettlementResult::Retry(RetryResult::Retried),
            false,
        ),
        (
            "retry route woken",
            SettlementResult::Retry(RetryResult::RouteWokenAtAttemptLimit),
            true,
        ),
        (
            "retry dead lettered",
            SettlementResult::Retry(RetryResult::DeadLettered),
            true,
        ),
        (
            "dead letter moved",
            SettlementResult::DeadLetter(true),
            true,
        ),
        (
            "dead letter not moved",
            SettlementResult::DeadLetter(false),
            false,
        ),
    ] {
        let (owner, request) = outbox::fixture::settlement(result.kind());
        let repository = Repository {
            reply: Reply::Settlement(result),
            request_address: Some(std::ptr::from_ref(&request) as usize),
            ..Repository::default()
        };
        let service = recording_service(repository.clone());
        let clone = service.clone();
        let returned = database_turn(
            &service,
            &repository,
            label,
            || {
                assert!(
                    !owner.snapshot().settlement.unwrap().started,
                    "{label}: start waits for admission"
                )
            },
            clone.settle_mix_delivery_observed(&request),
        )
        .await
        .unwrap();
        assert_eq!(returned, result, "{label}");
        assert_eq!(
            repository.calls(),
            [format!(
                "settle:{:?}:{:?}",
                request.source(),
                request.command()
            )],
            "{label}"
        );
        let settlement = owner.snapshot().settlement.unwrap();
        assert!(settlement.started, "{label}");
        assert_eq!(
            settlement.knowledge,
            SettlementKnowledge::ReceiptKnown(result),
            "{label}"
        );
        assert_eq!(
            settlement.returned,
            Some(SettlementReturned::Outcome(result)),
            "{label}"
        );
        assert_eq!(
            service.delivery_wake.generation(),
            u64::from(wake),
            "{label}"
        );
    }
    for kind in [
        SettlementKind::Ack,
        SettlementKind::Defer,
        SettlementKind::Retry,
        SettlementKind::DeadLetter,
    ] {
        let (owner, request) = outbox::fixture::settlement(kind);
        let repository = Repository {
            request_address: Some(std::ptr::from_ref(&request) as usize),
            ..Repository::default()
        };
        let service = recording_service(repository.clone());
        assert_eq!(
            database_turn(
                &service,
                &repository,
                "settlement error",
                || assert!(!owner.snapshot().settlement.unwrap().started),
                service.settle_mix_delivery_observed(&request)
            )
            .await
            .unwrap_err()
            .to_string(),
            "recorded repository failure"
        );
        assert_eq!(
            owner.snapshot().settlement.unwrap().returned,
            Some(SettlementReturned::Error)
        );
        assert_eq!(service.delivery_wake.generation(), 0);
    }

    let (owner, request) = outbox::fixture::settlement(SettlementKind::Ack);
    let repository = Repository {
        reply: Reply::Settlement(SettlementResult::Retry(RetryResult::DeadLettered)),
        request_address: Some(std::ptr::from_ref(&request) as usize),
        ..Repository::default()
    };
    let service = recording_service(repository);
    assert!(
        service
            .settle_mix_delivery_observed(&request)
            .await
            .is_err(),
        "mismatched wake result"
    );
    assert_eq!(
        owner.snapshot().settlement.unwrap().returned,
        Some(SettlementReturned::Error)
    );
    assert_eq!(service.delivery_wake.generation(), 0);

    let repository = Repository {
        reply: Reply::Bool(true),
        pause: Some(Arc::new(tokio::sync::Semaphore::new(0))),
        ..Repository::default()
    };
    let service = recording_service(repository.clone());
    let mut work =
        Box::pin(service.acknowledge_mix_delivery(Uuid::from_u128(501), Uuid::from_u128(502)));
    assert!(
        futures::poll!(&mut work).is_pending(),
        "pending repository owns permit"
    );
    assert_eq!(repository.calls().len(), 1);
    assert_eq!(service.outbox_db_admission.available_permits(), 0);
    let mut next = Box::pin(service.outbox_db_admission_guard());
    assert!(futures::poll!(&mut next).is_pending());
    drop(work);
    drop(next.await);
    assert_eq!(service.outbox_db_admission.available_permits(), 1);
    assert_eq!(service.delivery_wake.generation(), 0);
}

#[tokio::test]
async fn injected_budget_tracks_admission() {
    use northstar_runtime::durable_outbox::DurableOutboxDatabaseAdmission;
    for (label, pool, capacity) in [
        ("one turn", 2, 1),
        ("two turns", 3, 2),
        ("capped turns", 32, 16),
    ] {
        let admission = DurableOutboxDatabaseAdmission::for_primary_pool(pool);
        let fixture = test_service(pool);
        let service = MixService::new_with_outbox_database_admission(
            (),
            "local.test".into(),
            fixture.message_identity,
            fixture.retraction_identity,
            admission.clone(),
            "public".into(),
        )
        .unwrap();
        let clone = service.clone();
        assert_eq!(service.outbox_background_budget(), capacity, "{label}");
        let mut guards = Vec::new();
        for remaining in (0..capacity).rev() {
            guards.push(clone.outbox_db_admission_guard().await);
            assert_eq!(admission.available_permits(), remaining, "{label}");
        }
        let mut next = Box::pin(service.outbox_db_admission_guard());
        assert!(futures::poll!(&mut next).is_pending(), "{label}");
        drop(guards.pop());
        drop(next.await);
        drop(guards);
        assert_eq!(admission.available_permits(), capacity, "{label}");
    }
}

#[tokio::test]
async fn all_producers_wait_before_repository() {
    use futures::future::BoxFuture;
    let owner = foreground::Observation::new(foreground::fixture::prepared(false));
    let observed = owner
        .store_request(foreground::fixture::command(false))
        .unwrap();
    let repository = Repository {
        request_address: Some(std::ptr::from_ref(&observed) as usize),
        ..Repository::default()
    };
    let original = recording_service(repository.clone());
    let service = original.clone();
    let held = original.delivery_admission_guard().await;
    let channel_id = Uuid::from_u128(201);
    let actor = "owner@local.test";
    let full = "owner@local.test/device";
    let item = "unique-item";
    let payload = "<presence><status>ready</status></presence>";
    let federated = FederatedMixMutation {
        authenticated_domain: "local.test".into(),
        actor_jid: actor.into(),
        request_id: "mutation".into(),
        request_digest: [23; 32],
        addressed: "room@mix.local.test".into(),
        reply_to: full.into(),
        policy: S2sOutboxPolicy::new(70, 80, 900, 60),
    };
    let context = Some(&federated);
    let join = JoinMixRequest {
        actor_jid: actor.into(),
        nick: Some("Owner".into()),
        nodes: vec![NODE_MESSAGES.into()],
        pam_user_id: Some(Uuid::from_u128(202)),
        invitation: Some(MixInvitationProof {
            inviter_jid: "inviter@local.test".into(),
            invitee_jid: actor.into(),
            channel_jid: "room@mix.local.test".into(),
            token: "invitation-token".into(),
        }),
        preference: Some(MixParticipantPreference::default()),
        anonymous_profile: true,
    };
    let subscribe = vec![NODE_INFO.to_owned()];
    let unsubscribe = vec![NODE_PRESENCE.to_owned()];
    let info = MixInfoUpdate {
        item_id: item.into(),
        expected_revision: 17,
        name: Some("Room".into()),
        description: Some("Description".into()),
        contacts: vec![actor.into()],
    };
    let config = MixConfigUpdate {
        item_id: item.into(),
        expected_revision: 19,
        access_model: "whitelist".into(),
        jid_visibility: "visible".into(),
        nick_required: true,
        max_participants: 21,
        max_events: 22,
        allow_private_messages: false,
        allow_participant_invites: true,
        allow_user_message_retraction: false,
        administrator_retraction_rights: "owners".into(),
        enforce_registered_nick: true,
    };
    let roles = MixRoleUpdate {
        owners: Some(vec![actor.into()]),
        administrators: Some(vec!["admin@local.test".into()]),
    };
    let access = MixAccessEntryUpdate {
        channel_id,
        actor,
        pattern: "*@blocked.test",
        list: MixAccessList::Banned,
        operation: MixAccessEntryOperation::Publish {
            reason: Some("reason"),
        },
    };
    let preference = MixParticipantPreference {
        jid_visibility: "visible".into(),
        private_messages: "block".into(),
        vcard: "allow".into(),
        share_presence: false,
    };
    let cutoff = DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap();
    let target = Uuid::from_u128(203);
    let retraction = Uuid::from_u128(204);
    let mut cases: Vec<(&str, String, BoxFuture<'_, Result<()>>)> = Vec::new();
    macro_rules! case {
        ($label:literal, $method:ident($($argument:expr),*)) => {
            cases.push(($label, format!("{}:{:?}", stringify!($method), ($($argument,)*)),
                Box::pin(async { service.$method($($argument),*).await.map(|_| ()) })));
        };
    }
    case!(
        "destroy channel",
        destroy_mix_channel(channel_id, actor, context)
    );
    case!(
        "join channel",
        join_mix_channel(channel_id, join.clone(), context)
    );
    case!("expire presence", expire_unrefreshed_mix_presence(cutoff));
    case!(
        "subscriptions",
        update_mix_subscriptions(channel_id, actor, &subscribe, &unsubscribe, context)
    );
    case!(
        "set nick",
        set_mix_nick(channel_id, actor, "NewNick", context)
    );
    case!(
        "leave channel",
        leave_mix_channel(channel_id, actor, Some(Uuid::from_u128(202)), context)
    );
    case!(
        "store presence",
        store_mix_presence(channel_id, actor, full, payload, true)
    );
    case!(
        "ensure presence",
        ensure_mix_presence(channel_id, actor, full, payload)
    );
    cases.push((
        "legacy message",
        format!(
            "store_mix_message:{:?}",
            (
                channel_id,
                actor,
                item,
                payload,
                None::<MixReplayIdentity>,
                "<body>delivery</body>",
                Some(actor),
                true
            )
        ),
        Box::pin(async {
            service
                .store_mix_message(StoreMixMessageRequest {
                    channel_id,
                    actor,
                    item_id: item,
                    payload,
                    identity: None,
                    delivery_payload: "<body>delivery</body>",
                    visible_jid: Some(actor),
                    encrypted: true,
                })
                .await
                .map(|_| ())
        }),
    ));
    cases.push((
        "observed message",
        "observed_store".into(),
        Box::pin(async {
            service
                .store_mix_message_observed(&observed)
                .await
                .map(|_| ())
        }),
    ));
    case!(
        "publish avatar",
        publish_mix_avatar(channel_id, actor, NODE_AVATAR_DATA, item, payload, context)
    );
    case!(
        "retract avatar",
        retract_mix_avatar(channel_id, actor, NODE_AVATAR_METADATA, item, context)
    );
    case!(
        "update info",
        update_mix_info(channel_id, actor, info.clone(), context)
    );
    case!(
        "update config",
        update_mix_config(channel_id, actor, config.clone(), roles.clone(), context)
    );
    case!("access entry", set_mix_access_entry(access, context));
    case!(
        "register nick",
        register_mix_nick("mix.local.test", actor, "RegisteredNick", context)
    );
    case!(
        "participant preference",
        update_mix_participant_preference(channel_id, actor, &preference, context)
    );
    cases.push((
        "retract message",
        format!(
            "retract_mix_message:{:?}",
            (
                channel_id,
                actor,
                target,
                retraction,
                "<tombstone/>",
                "<retract/>",
                None::<MixReplayIdentity>,
                Some(actor)
            )
        ),
        Box::pin(async {
            service
                .retract_mix_message(RetractMixMessageRequest {
                    channel_id,
                    actor,
                    target_id: target,
                    retraction_id: retraction,
                    tombstone_payload: "<tombstone/>",
                    retraction_payload: "<retract/>",
                    identity: None,
                    visible_jid: Some(actor),
                })
                .await
                .map(|_| ())
        }),
    ));
    case!(
        "requeue dead letter",
        requeue_mix_delivery_dead_letter(Uuid::from_u128(205))
    );
    assert_eq!(cases.len(), 19);
    for (label, _, future) in &mut cases {
        assert!(futures::poll!(future.as_mut()).is_pending(), "{label}");
        assert!(repository.calls().is_empty(), "{label}");
    }
    drop(held);
    for (label, _, future) in cases.iter_mut().skip(1).rev() {
        assert!(
            futures::poll!(future.as_mut()).is_pending(),
            "FIFO: {label}"
        );
    }
    let mut expected = Vec::new();
    for (label, call, future) in cases {
        assert_eq!(
            future.await.unwrap_err().to_string(),
            "recorded repository failure",
            "{label}"
        );
        expected.push(call);
        assert_eq!(repository.calls(), expected, "{label}");
    }
    assert!(original.delivery_admission.try_lock().is_ok());
    assert_eq!(original.outbox_db_admission.available_permits(), 1);
}

#[tokio::test]
async fn pam_public_methods_wait_before_repository() {
    let repository = Repository::default();
    let original = recording_service(repository.clone());
    let service = original.clone();
    let join = BeginRemotePamJoin {
        user_id: Uuid::from_u128(301),
        actor_jid: "alice@local.test".into(),
        channel_jid: "room@mix.remote.test".into(),
        nick: Some("Alice".into()),
        nodes: vec![NODE_MESSAGES.into()],
        request_id: "remote-join".into(),
        client_request_id: "client-join".into(),
        requester_full_jid: "alice@local.test/phone".into(),
        request_digest: [31; 32],
        remote_domain: "mix.remote.test".into(),
        outbound_stanza: "<iq id='remote-join'/>".into(),
        policy: S2sOutboxPolicy::new(30, 40, 500, 20),
    };
    let leave = BeginRemotePamLeave {
        user_id: join.user_id,
        actor_jid: join.actor_jid.clone(),
        channel_jid: join.channel_jid.clone(),
        request_id: "remote-leave".into(),
        client_request_id: "client-leave".into(),
        requester_full_jid: join.requester_full_jid.clone(),
        request_digest: [32; 32],
        remote_domain: join.remote_domain.clone(),
        outbound_stanza: "<iq id='remote-leave'/>".into(),
        policy: join.policy,
    };
    let held = original.pam_capacity_admission_guard().await;
    let mut cancelled = Box::pin(service.begin_remote_pam_join(join.clone()));
    let mut joining = Box::pin(service.begin_remote_pam_join(join.clone()));
    let mut leaving = Box::pin(service.begin_remote_pam_leave(leave.clone()));
    let mut pruning = Box::pin(service.prune_expired_pam_results(37));
    assert!(
        futures::poll!(&mut cancelled).is_pending(),
        "cancelled join"
    );
    assert!(futures::poll!(&mut joining).is_pending(), "join");
    assert!(futures::poll!(&mut leaving).is_pending(), "leave");
    assert!(futures::poll!(&mut pruning).is_pending(), "prune");
    assert!(repository.calls().is_empty());
    drop(cancelled);
    drop(held);
    assert!(
        futures::poll!(&mut leaving).is_pending(),
        "leave stays behind join"
    );
    assert_eq!(
        joining.await.unwrap_err().to_string(),
        "recorded repository failure"
    );
    assert!(
        futures::poll!(&mut pruning).is_pending(),
        "prune stays behind leave"
    );
    assert_eq!(
        leaving.await.unwrap_err().to_string(),
        "recorded repository failure"
    );
    assert_eq!(
        pruning.await.unwrap_err().to_string(),
        "recorded repository failure"
    );
    assert_eq!(
        repository.calls(),
        [
            format!("begin_remote_pam_join:{:?}", (join,)),
            format!("begin_remote_pam_leave:{:?}", (leave,)),
            "prune_expired_pam_results:(37,)".into(),
        ]
    );
    assert!(original.pam_capacity_admission.try_lock().is_ok());
    assert_eq!(original.outbox_db_admission.available_permits(), 1);
}

fn test_service(primary_pool_max_connections: u32) -> MixService<()> {
    let generations = Arc::new(Vec::new());
    MixService::new(
        (),
        MixMessageContentKeyring::new(Arc::clone(&generations)),
        MixRetractionContentKeyring::new(generations),
        primary_pool_max_connections,
        "public".to_owned(),
    )
    .expect("test MIX service schema is valid")
}

#[test]
fn outbox_background_budget_scales_with_the_configured_primary_pool() {
    // A one-connection configuration has no spare foreground slot, so it
    // retains a single durable worker. At two connections, the listener
    // stress profile gets one background worker and one foreground slot.
    assert_eq!(
        northstar_runtime::durable_outbox::DurableOutboxDatabaseAdmission::capacity_for_primary_pool(
            1
        ),
        1
    );
    assert_eq!(
        northstar_runtime::durable_outbox::DurableOutboxDatabaseAdmission::capacity_for_primary_pool(
            2
        ),
        1
    );
    assert_eq!(
        northstar_runtime::durable_outbox::DurableOutboxDatabaseAdmission::capacity_for_primary_pool(
            3
        ),
        2
    );
    assert_eq!(
        northstar_runtime::durable_outbox::DurableOutboxDatabaseAdmission::capacity_for_primary_pool(
            17
        ),
        16
    );
    assert_eq!(
        northstar_runtime::durable_outbox::DurableOutboxDatabaseAdmission::capacity_for_primary_pool(
            32
        ),
        16
    );
    assert_eq!(
        northstar_runtime::durable_outbox::DurableOutboxDatabaseAdmission::capacity_for_primary_pool(
            u32::MAX
        ),
        16
    );
}

#[tokio::test]
async fn delivery_wake_retains_commits_and_listener_gap_transitions() {
    let broker =
        MixDeliveryWakeBroker::new("northstar_wake_test".to_owned()).expect("test schema is valid");
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
    let broker =
        MixDeliveryWakeBroker::new("northstar_wake_test".to_owned()).expect("test schema is valid");
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
    let service = test_service(32);
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
    // A two-connection primary pool leaves one foreground connection and
    // therefore gives this outbox gate exactly one FIFO permit.
    let service = test_service(2);
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
    let service = test_service(3);
    assert_eq!(service.outbox_background_budget(), 2);
    assert_eq!(service.outbox_db_admission.available_permits(), 2);
}

#[tokio::test]
async fn pam_capacity_admission_gate_is_clone_shared_and_fifo() {
    let service = test_service(32);
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
    let payload =
        render_participant_payload(&channel, &participant, &MixParticipantPreference::default());
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
