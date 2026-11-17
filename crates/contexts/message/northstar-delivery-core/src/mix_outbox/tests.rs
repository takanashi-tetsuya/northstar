//! Unit tests of the MIX outbox worker attempt, renewal, routing, archive and settlement commits.

use super::*;

fn row(archive: bool) -> Arc<Row> {
    Arc::new(Row {
        source: MixDelivery {
            delivery_id: Uuid::from_u128(1),
            lease_token: Uuid::from_u128(2),
        },
        event_id: Uuid::from_u128(3),
        channel_id: Uuid::from_u128(4),
        channel_jid: "room@mix.local.test".into(),
        participant_id: Uuid::from_u128(5),
        recipient_jid: "bob@local.test".into(),
        recipient_nick: None,
        stanza: "<message><body>event</body></message>".into(),
        authoritative_stanza_id: archive.then_some(Uuid::from_u128(6)),
        archive,
        encrypted: false,
        attempt_count: 19,
        route_wake_generation: 9,
    })
}
fn claim() -> (ClaimObservation, ClaimRequest) {
    let observation = ClaimObservation::new(ClaimCommand {
        limit: 2,
        max_bytes: 8 * 1024 * 1024,
    });
    let request = observation.request().unwrap();
    request.start().unwrap();
    (observation, request)
}
fn attempt(archive: bool) -> Attempt {
    let (_, request) = claim();
    let entered = request.enter_statement().unwrap();
    let rows: Rows = vec![row(archive)].into();
    request.received(entered, rows.clone()).unwrap();
    request.returned(rows).unwrap().pop().unwrap()
}
fn started_route(archive: bool) -> (Observation, RouteRequest) {
    let attempt = attempt(archive);
    let observation = attempt.observation();
    let request = attempt
        .route("<message to='bob@local.test'><body>event</body></message>".into())
        .unwrap();
    request.start().unwrap();
    (observation, request)
}
fn archive(request: &RouteRequest, result: ArchiveResult) -> ArchiveRequest {
    let archive = request
        .archive_request(
            Uuid::from_u128(7),
            Uuid::from_u128(8),
            Some(Uuid::from_u128(6).to_string()),
        )
        .unwrap();
    archive.start().unwrap();
    let entered = archive.enter_commit(result).unwrap();
    archive.received(entered).unwrap();
    archive.returned(result).unwrap();
    archive
}
fn settlement(kind: SettlementKind) -> (Observation, SettlementRequest) {
    let (observation, route) = started_route(false);
    let (result, command) = match kind {
        SettlementKind::Ack => (RouteResult::CompletedByWorker, SettlementCommand::Ack),
        SettlementKind::Defer => (
            RouteResult::Pending,
            SettlementCommand::Defer { delay_seconds: 30 },
        ),
        SettlementKind::Retry => (
            RouteResult::Retry,
            SettlementCommand::Retry {
                error: "route failed".into(),
            },
        ),
        SettlementKind::DeadLetter => (
            RouteResult::Permanent,
            SettlementCommand::DeadLetter {
                reason: "account-unavailable".into(),
                error: "disabled".into(),
            },
        ),
    };
    let closed = observation.close_renewal_scope().unwrap();
    let request = route
        .returned(result)
        .unwrap()
        .settlement(command, closed)
        .unwrap()
        .unwrap();
    (observation, request)
}

#[test]
fn claim_read_empty_mutating_empty_and_unknown_are_distinct() {
    let (read, request) = claim();
    request.read_empty().unwrap();
    assert!(request.returned(Vec::new().into()).unwrap().is_empty());
    assert_eq!(read.snapshot().knowledge, ClaimKnowledge::ReadEmpty);
    let (mutating, request) = claim();
    let entered = request.enter_statement().unwrap();
    let rows: Rows = Vec::new().into();
    request.received(entered, rows.clone()).unwrap();
    assert!(request.returned(rows).unwrap().is_empty());
    assert!(
        matches!(mutating.snapshot().knowledge, ClaimKnowledge::StatementReceipt(rows) if rows.is_empty())
    );
    let (unknown, request) = claim();
    let _entered = request.enter_statement().unwrap();
    request.failed().unwrap();
    assert_eq!(
        unknown.snapshot().knowledge,
        ClaimKnowledge::AutocommitStatementEntered
    );
    assert!(matches!(
        request.returned(vec![row(false)].into()),
        Err(Rejected::Returned)
    ));
}

#[test]
fn copied_claim_rows_or_statement_identity_cannot_mint_another_attempt() {
    let (first, a) = claim();
    let (second, b) = claim();
    let token = a.enter_statement().unwrap();
    let rows: Rows = vec![row(false)].into();
    assert_eq!(b.received(token, rows.clone()), Err(Rejected::Invocation));
    assert_eq!(
        second.snapshot().knowledge,
        ClaimKnowledge::NoStatementEntered
    );
    assert!(matches!(a.returned(rows), Err(Rejected::MissingReceipt)));
    assert!(matches!(
        first.snapshot().returned,
        Some(ClaimReturned::Rejected(_))
    ));
    let (_, request) = claim();
    let token = request.enter_statement().unwrap();
    let same = row(false);
    let repeated: Rows = vec![same.clone(), same].into();
    request.received(token, repeated.clone()).unwrap();
    assert!(matches!(request.returned(repeated), Err(Rejected::Result)));
    let (observation, request) = claim();
    let token = request.enter_statement().unwrap();
    let actual: Rows = vec![row(false)].into();
    request.received(token, actual.clone()).unwrap();
    let copied: Rows = actual
        .iter()
        .map(|row| Arc::new(row.as_ref().clone()))
        .collect::<Vec<_>>()
        .into();
    assert_eq!(actual, copied);
    assert!(!Arc::ptr_eq(&actual, &copied));
    assert!(matches!(
        request.returned(copied.clone()),
        Err(Rejected::MissingReceipt)
    ));
    assert_eq!(
        observation.snapshot().knowledge,
        ClaimKnowledge::StatementReceipt(actual)
    );
    assert_eq!(
        observation.snapshot().returned,
        Some(ClaimReturned::Rejected(copied))
    );
    let (_, request) = claim();
    let token = request.enter_statement().unwrap();
    let actual: Rows = vec![row(false)].into();
    request.received(token, actual.clone()).unwrap();
    assert_eq!(request.returned(actual.clone()).unwrap().len(), 1);
    assert!(matches!(request.returned(actual), Err(Rejected::Returned)));
}

#[test]
fn archive_false_and_optional_identity_rows_keep_their_existing_route_shape() {
    let (observation, route) = started_route(false);
    assert!(!route.row().archive);
    assert_eq!(route.row().authoritative_stanza_id, None);
    assert!(matches!(
        route.archive_request(Uuid::from_u128(7), Uuid::from_u128(8), None),
        Err(Rejected::Phase)
    ));
    let local = route.local_request("bob@local.test/phone".into()).unwrap();
    local.start().unwrap();
    local.returned(LocalResult::QueueFull).unwrap();
    let closed = observation.close_renewal_scope().unwrap();
    let settlement = route
        .returned(RouteResult::Pending)
        .unwrap()
        .settlement(SettlementCommand::Defer { delay_seconds: 30 }, closed)
        .unwrap()
        .unwrap();
    assert_eq!(
        settlement.source(),
        MixDelivery {
            delivery_id: Uuid::from_u128(1),
            lease_token: Uuid::from_u128(2)
        }
    );
    assert_eq!(
        observation.snapshot().archive.knowledge,
        ArchiveKnowledge::NoCommitEntered
    );
}

#[test]
fn archive_stored_and_original_id_replay_each_permit_routing_only_after_return() {
    for result in [
        ArchiveResult::Stored(Uuid::from_u128(8)),
        ArchiveResult::Replay(Uuid::from_u128(80)),
    ] {
        let (observation, route) = started_route(true);
        assert!(matches!(
            route.local_request("bob@local.test/phone".into()),
            Err(Rejected::MissingReceipt)
        ));
        let archive = archive(&route, result);
        assert_eq!(
            archive.command().stanza.as_ref(),
            "<message to='bob@local.test'><body>event</body></message>"
        );
        assert_eq!(
            observation.snapshot().archive.knowledge,
            ArchiveKnowledge::ReceiptKnown(result)
        );
        assert!(route.local_request("bob@local.test/phone".into()).is_ok());
        assert!(observation.snapshot().settlement.is_none());
    }
    let (observation, route) = started_route(true);
    let archive = route
        .archive_request(Uuid::from_u128(7), Uuid::from_u128(8), None)
        .unwrap();
    archive.start().unwrap();
    let token = archive
        .enter_commit(ArchiveResult::Replay(Uuid::from_u128(80)))
        .unwrap();
    archive.received(token).unwrap();
    archive.failed().unwrap();
    assert!(matches!(
        route.local_request("bob@local.test/phone".into()),
        Err(Rejected::MissingReceipt)
    ));
    assert_eq!(
        observation.snapshot().archive.knowledge,
        ArchiveKnowledge::ReceiptKnown(ArchiveResult::Replay(Uuid::from_u128(80)))
    );
    let closed = observation.close_renewal_scope().unwrap();
    assert!(route
        .returned(RouteResult::Retry)
        .unwrap()
        .settlement(
            SettlementCommand::Retry {
                error: "ordinary backend error".into()
            },
            closed
        )
        .unwrap()
        .is_some());
}

#[test]
fn contradictory_or_unobserved_archive_success_does_not_authorize_retry_settlement() {
    for received in [false, true] {
        let (observation, route) = started_route(true);
        let archive = route
            .archive_request(Uuid::from_u128(7), Uuid::from_u128(8), None)
            .unwrap();
        archive.start().unwrap();
        if received {
            let token = archive
                .enter_commit(ArchiveResult::Stored(Uuid::from_u128(8)))
                .unwrap();
            archive.received(token).unwrap();
        }
        assert_eq!(
            archive.returned(ArchiveResult::Replay(Uuid::from_u128(80))),
            Err(Rejected::MissingReceipt)
        );
        assert!(observation.snapshot().aborted);
        assert_eq!(
            observation.snapshot().archive.returned,
            Some(ArchiveReturned::Outcome(ArchiveResult::Replay(
                Uuid::from_u128(80)
            )))
        );
        if received {
            assert_eq!(
                observation.snapshot().archive.knowledge,
                ArchiveKnowledge::ReceiptKnown(ArchiveResult::Stored(Uuid::from_u128(8)))
            );
        }
        observation.close_renewal_scope().unwrap();
        assert!(matches!(
            route.returned(RouteResult::Retry),
            Err(Rejected::Phase)
        ));
        assert!(observation.snapshot().settlement.is_none());
    }
}

#[test]
fn every_typed_local_transfer_consumes_old_worker_settlement_before_outer_return() {
    for boundary in [
        TransferBoundary::SocketFenced(Uuid::from_u128(10)),
        TransferBoundary::SmPersisted(Uuid::from_u128(11)),
        TransferBoundary::BoshPersisted(Uuid::from_u128(12)),
    ] {
        let (observation, route) = started_route(false);
        let local = route.local_request("bob@local.test/phone".into()).unwrap();
        local.start().unwrap();
        local.enqueued().unwrap();
        local.returned(LocalResult::Transferred(boundary)).unwrap();
        assert_eq!(
            observation.snapshot().transfer,
            Some(TransferFact {
                target: "bob@local.test/phone".into(),
                boundary
            })
        );
        assert!(matches!(
            route.local_request("bob@local.test/other".into()),
            Err(Rejected::Transferred)
        ));
        let _closed = observation.close_renewal_scope().unwrap();
        assert!(matches!(
            route.returned(RouteResult::Retry),
            Err(Rejected::Transferred)
        ));
        assert_eq!(
            observation.snapshot().route_returned,
            Some(RouteResult::Retry)
        );
        assert!(observation.snapshot().settlement.is_none());
    }
}

#[test]
fn typed_cluster_transfer_is_bound_and_has_no_old_worker_settlement() {
    for boundary in [
        TransferBoundary::ClusterSocketFenced,
        TransferBoundary::ClusterSmPersisted,
        TransferBoundary::ClusterBoshPersisted,
    ] {
        let (observation, route) = started_route(false);
        let cluster = route.cluster_request("remote-node".into()).unwrap();
        cluster.start().unwrap();
        cluster.returned(Some(boundary)).unwrap();
        assert_eq!(cluster.source(), route.row().source);
        assert!(matches!(
            observation.renewal_request(),
            Err(Rejected::Transferred)
        ));
        let closed = observation.close_renewal_scope().unwrap();
        route
            .returned(RouteResult::Transferred)
            .unwrap()
            .transferred(closed)
            .unwrap();
        assert!(observation.snapshot().settlement.is_none());
    }
}

#[test]
fn route_effects_start_once_and_uncertain_prefix_cannot_be_reported_as_completed() {
    let (observation, route) = started_route(false);
    let local = route.local_request("bob@local.test/phone".into()).unwrap();
    assert_eq!(local.enqueued(), Err(Rejected::NotStarted));
    local.start().unwrap();
    assert_eq!(local.start(), Err(Rejected::Started));
    local.enqueued().unwrap();
    assert!(matches!(
        route.cluster_request("remote-node".into()),
        Err(Rejected::Phase)
    ));
    let _closed = observation.close_renewal_scope().unwrap();
    assert!(matches!(
        route.returned(RouteResult::CompletedByWorker),
        Err(Rejected::MissingReceipt)
    ));
    assert!(observation.snapshot().aborted);
    assert!(observation.snapshot().settlement.is_none());
    assert!(observation.snapshot().local[0].enqueued);
    let (_, route) = started_route(false);
    let cluster = route.cluster_request("remote-node".into()).unwrap();
    cluster.start().unwrap();
    assert_eq!(cluster.start(), Err(Rejected::Started));
}

#[test]
fn contradictory_local_return_remains_visible_and_prevents_another_effect() {
    let (observation, route) = started_route(false);
    let local = route.local_request("bob@local.test/phone".into()).unwrap();
    local.start().unwrap();
    local.enqueued().unwrap();
    assert_eq!(
        local.returned(LocalResult::QueueFull),
        Err(Rejected::Result)
    );
    assert_eq!(
        observation.snapshot().local[0].returned,
        Some(LocalResult::QueueFull)
    );
    assert!(observation.snapshot().aborted);
    assert!(matches!(
        route.local_request("bob@local.test/other".into()),
        Err(Rejected::Phase)
    ));
    observation.close_renewal_scope().unwrap();
    assert!(matches!(
        route.returned(RouteResult::CompletedByWorker),
        Err(Rejected::Phase)
    ));
    assert!(observation.snapshot().settlement.is_none());
}

#[test]
fn handoff_closed_preserves_enqueue_uncertainty_and_allows_the_existing_next_resource_path() {
    let (observation, route) = started_route(false);
    let first = route.local_request("bob@local.test/a".into()).unwrap();
    first.start().unwrap();
    first.enqueued().unwrap();
    first.returned(LocalResult::HandoffClosed).unwrap();
    let second = route.local_request("bob@local.test/b".into()).unwrap();
    second.start().unwrap();
    second.returned(LocalResult::QueueClosed).unwrap();
    assert_eq!(observation.snapshot().local.len(), 2);
    assert!(observation.snapshot().local[0].enqueued);
    let closed = observation.close_renewal_scope().unwrap();
    assert!(route
        .returned(RouteResult::Retry)
        .unwrap()
        .settlement(
            SettlementCommand::Retry {
                error: "handoff uncertain".into()
            },
            closed
        )
        .unwrap()
        .is_some());
}

#[test]
fn renewal_error_retains_knowledge_and_grants_no_new_renewal_or_settlement() {
    let (observation, route) = started_route(false);
    let renewal = observation.renewal_request().unwrap();
    renewal.start().unwrap();
    let _entered = renewal.enter_statement().unwrap();
    renewal.failed().unwrap();
    assert_eq!(
        observation.snapshot().renewal.knowledge,
        RenewalKnowledge::AutocommitStatementEntered
    );
    assert!(observation.snapshot().aborted);
    assert!(matches!(
        observation.renewal_request(),
        Err(Rejected::Phase)
    ));
    observation.close_renewal_scope().unwrap();
    assert!(matches!(
        route.returned(RouteResult::CompletedByWorker),
        Err(Rejected::Phase)
    ));
    assert!(observation.snapshot().settlement.is_none());
}

#[test]
fn dropped_pending_renewal_is_distinct_from_error_and_scope_closure_preserves_its_receipt() {
    let (observation, route) = started_route(false);
    let renewal = observation.renewal_request().unwrap();
    renewal.start().unwrap();
    let entered = renewal.enter_statement().unwrap();
    renewal.received(entered, true).unwrap();
    assert!(observation.snapshot().renewal.pending);
    let closed = observation.close_renewal_scope().unwrap();
    assert_eq!(renewal.returned(true), Err(Rejected::Phase));
    assert_eq!(observation.snapshot().renewal.last_receipt, Some((1, true)));
    assert!(!observation.snapshot().aborted);
    let settlement = route
        .returned(RouteResult::CompletedByWorker)
        .unwrap()
        .settlement(SettlementCommand::Ack, closed)
        .unwrap()
        .unwrap();
    settlement.start().unwrap();
    assert_eq!(
        observation.snapshot().settlement.as_ref().unwrap().kind,
        SettlementKind::Ack
    );
}

#[test]
fn renewal_false_is_a_statement_receipt_and_never_proves_row_absence() {
    let (observation, route) = started_route(false);
    let renewal = observation.renewal_request().unwrap();
    renewal.start().unwrap();
    let entered = renewal.enter_statement().unwrap();
    renewal.received(entered, false).unwrap();
    assert!(!renewal.returned(false).unwrap());
    assert_eq!(
        observation.snapshot().renewal.knowledge,
        RenewalKnowledge::StatementReceipt(false)
    );
    assert_eq!(observation.row().source.delivery_id, Uuid::from_u128(1));
    assert!(observation.snapshot().lease_lost);
    observation.close_renewal_scope().unwrap();
    assert!(matches!(
        route.returned(RouteResult::CompletedByWorker),
        Err(Rejected::LeaseLost)
    ));
    assert!(observation.snapshot().settlement.is_none());
}

#[test]
fn all_settlement_results_require_their_actual_matching_boundary_including_not_moved() {
    let results = [
        SettlementResult::Ack(true),
        SettlementResult::Ack(false),
        SettlementResult::Defer(true),
        SettlementResult::Defer(false),
        SettlementResult::DeadLetter(true),
        SettlementResult::DeadLetter(false),
        SettlementResult::Retry(RetryResult::LeaseLost),
        SettlementResult::Retry(RetryResult::Retried),
        SettlementResult::Retry(RetryResult::RouteWokenAtAttemptLimit),
        SettlementResult::Retry(RetryResult::DeadLettered),
    ];
    for result in results {
        let (observation, request) = settlement(result.kind());
        request.start().unwrap();
        let entered = if matches!(result, SettlementResult::Defer(_)) {
            request.enter_statement().unwrap()
        } else {
            request.enter_commit(result).unwrap()
        };
        request.received(entered, result).unwrap();
        assert_eq!(request.returned(result), Ok(result));
        assert_eq!(
            observation.snapshot().settlement.unwrap().knowledge,
            SettlementKnowledge::ReceiptKnown(result)
        );
        assert_eq!(request.returned(result), Err(Rejected::Returned));
        assert!(
            !observation.snapshot().lease_lost,
            "a settlement false is not a renewal failure or proof of row absence"
        );
    }
    let (observation, request) = settlement(SettlementKind::DeadLetter);
    request.start().unwrap();
    assert_eq!(
        request.returned(SettlementResult::DeadLetter(false)),
        Err(Rejected::MissingReceipt)
    );
    assert_eq!(
        observation.snapshot().settlement.unwrap().knowledge,
        SettlementKnowledge::NotEntered
    );
}

#[test]
fn settlement_kind_instance_duplicate_start_and_late_receipt_are_rejected() {
    let (a, first) = settlement(SettlementKind::Ack);
    let (b, second) = settlement(SettlementKind::Ack);
    first.start().unwrap();
    second.start().unwrap();
    assert_eq!(first.start(), Err(Rejected::Started));
    assert!(matches!(
        first.enter_commit(SettlementResult::DeadLetter(true)),
        Err(Rejected::Result)
    ));
    let entered = first.enter_commit(SettlementResult::Ack(false)).unwrap();
    assert_eq!(
        second.received(entered, SettlementResult::Ack(false)),
        Err(Rejected::Invocation)
    );
    assert_eq!(
        b.snapshot().settlement.unwrap().knowledge,
        SettlementKnowledge::NotEntered
    );
    let entered = second.enter_commit(SettlementResult::Ack(true)).unwrap();
    b.retire(TerminalReason::Cancelled);
    let frozen = b.snapshot();
    assert_eq!(
        second.received(entered, SettlementResult::Ack(true)),
        Err(Rejected::Retired)
    );
    assert_eq!(b.snapshot(), frozen);
    assert!(matches!(
        a.snapshot().settlement.unwrap().knowledge,
        SettlementKnowledge::CommitCallEntered(SettlementResult::Ack(false))
    ));
}

#[test]
fn unavailable_attempts_refuse_new_renewal_authority_without_changing_facts() {
    for (label, expected) in [
        ("transferred", Rejected::Transferred),
        ("lease_lost", Rejected::LeaseLost),
        ("aborted", Rejected::Phase),
        ("settlement_issued", Rejected::Settlement),
    ] {
        let (observation, route) = started_route(false);
        match label {
            "transferred" => {
                let cluster = route.cluster_request("node-b".into()).unwrap();
                cluster.start().unwrap();
                cluster
                    .returned(Some(TransferBoundary::ClusterSmPersisted))
                    .unwrap();
            }
            "lease_lost" => {
                let renewal = observation.renewal_request().unwrap();
                renewal.start().unwrap();
                let entered = renewal.enter_statement().unwrap();
                renewal.received(entered, false).unwrap();
            }
            "aborted" => {
                let renewal = observation.renewal_request().unwrap();
                renewal.start().unwrap();
                renewal.failed().unwrap();
            }
            "settlement_issued" => {
                let closed = observation.close_renewal_scope().unwrap();
                route
                    .returned(RouteResult::CompletedByWorker)
                    .unwrap()
                    .settlement(SettlementCommand::Ack, closed)
                    .unwrap()
                    .unwrap();
            }
            _ => unreachable!(),
        }
        let before = observation.snapshot();
        assert!(
            matches!(observation.renewal_request(), Err(error) if error == expected),
            "{label}"
        );
        assert_eq!(observation.snapshot(), before, "{label}");
    }
}

#[test]
fn local_and_cluster_returns_require_start_and_preserve_exact_transfer_targets() {
    for (label, boundary) in [
        ("cluster_socket", TransferBoundary::ClusterSocketFenced),
        ("cluster_sm", TransferBoundary::ClusterSmPersisted),
        ("cluster_bosh", TransferBoundary::ClusterBoshPersisted),
    ] {
        let (observation, route) = started_route(false);
        let local = route.local_request("bob@local.test/phone".into()).unwrap();
        let before = observation.snapshot();
        assert_eq!(
            local.returned(LocalResult::QueueClosed),
            Err(Rejected::NotStarted),
            "{label}"
        );
        assert_eq!(observation.snapshot(), before, "{label}");
        local.start().unwrap();
        assert_eq!(local.start(), Err(Rejected::Started), "{label}");
        local.returned(LocalResult::QueueClosed).unwrap();
        let cluster = route.cluster_request("node-b".into()).unwrap();
        assert_eq!(cluster.source(), route.row().source, "{label}");
        assert_eq!(cluster.stanza(), route.stanza(), "{label}");
        assert_eq!(cluster.recipient(), "bob@local.test", "{label}");
        assert_eq!(cluster.node(), "node-b", "{label}");
        let before = observation.snapshot();
        assert_eq!(
            cluster.returned(Some(boundary)),
            Err(Rejected::NotStarted),
            "{label}"
        );
        assert_eq!(observation.snapshot(), before, "{label}");
        cluster.start().unwrap();
        assert_eq!(cluster.start(), Err(Rejected::Started), "{label}");
        cluster.returned(Some(boundary)).unwrap();
        assert_eq!(
            observation.snapshot().transfer,
            Some(TransferFact {
                target: "node-b".into(),
                boundary
            }),
            "{label}"
        );
        let closed = observation.close_renewal_scope().unwrap();
        route
            .returned(RouteResult::Transferred)
            .unwrap()
            .transferred(closed)
            .unwrap();
        assert!(observation.snapshot().settlement.is_none(), "{label}");
    }
    let (observation, route) = started_route(false);
    let local = route.local_request("bob@local.test/phone".into()).unwrap();
    local.start().unwrap();
    assert_eq!(
        local.returned(LocalResult::Transferred(TransferBoundary::SmPersisted(
            Uuid::from_u128(11)
        ))),
        Err(Rejected::Result),
        "transfer_without_enqueue"
    );
    assert!(observation.snapshot().aborted, "transfer_without_enqueue");
    assert!(
        matches!(observation.renewal_request(), Err(Rejected::Transferred)),
        "transfer_without_enqueue"
    );
}

#[test]
fn renewal_receipts_bind_invocation_and_ordinal_and_contradictions_abort() {
    let (observation, _route) = started_route(false);
    let (foreign, _foreign_route) = started_route(false);
    let first = observation.renewal_request().unwrap();
    first.start().unwrap();
    let entered = first.enter_statement().unwrap();
    first.received(entered, true).unwrap();
    assert!(first.returned(true).unwrap());
    let second = observation.renewal_request().unwrap();
    second.start().unwrap();
    let entered = second.enter_statement().unwrap();
    let other = foreign.renewal_request().unwrap();
    other.start().unwrap();
    let foreign_entered = other.enter_statement().unwrap();
    let before = observation.snapshot();
    assert_eq!(
        second.received(foreign_entered, false),
        Err(Rejected::Invocation),
        "foreign_invocation"
    );
    assert_eq!(observation.snapshot(), before, "foreign_invocation");
    // An old ordinal on the same private invocation must also be inert.
    let stale = RenewalStatement {
        observation: observation.clone(),
        ordinal: 1,
    };
    assert_eq!(
        second.received(stale, false),
        Err(Rejected::Invocation),
        "stale_ordinal"
    );
    assert_eq!(observation.snapshot(), before, "stale_ordinal");
    second.received(entered, false).unwrap();
    assert_eq!(
        observation.snapshot().renewal.last_receipt,
        Some((2, false)),
        "lost_second_lease"
    );
    assert!(observation.snapshot().lease_lost, "lost_second_lease");
    assert!(!second.returned(false).unwrap());
    assert!(matches!(
        observation.renewal_request(),
        Err(Rejected::LeaseLost)
    ));

    for (label, known, returned) in [
        ("true_receipt_false_return", Some(true), false),
        ("false_receipt_true_return", Some(false), true),
        ("unobserved_success", None, true),
    ] {
        let (observation, route) = started_route(false);
        let renewal = observation.renewal_request().unwrap();
        renewal.start().unwrap();
        let entered = renewal.enter_statement().unwrap();
        if let Some(known) = known {
            renewal.received(entered, known).unwrap();
        } else {
            drop(entered);
        }
        assert_eq!(
            renewal.returned(returned),
            Err(Rejected::MissingReceipt),
            "{label}"
        );
        let snapshot = observation.snapshot();
        assert!(snapshot.aborted, "{label}");
        assert_eq!(
            snapshot.renewal.returned,
            Some(RenewalReturned::Outcome(returned)),
            "{label}"
        );
        assert_eq!(
            snapshot.renewal.knowledge,
            known.map_or(
                RenewalKnowledge::AutocommitStatementEntered,
                RenewalKnowledge::StatementReceipt
            ),
            "{label}"
        );
        assert_eq!(
            snapshot.renewal.last_receipt,
            known.map(|value| (1, value)),
            "{label}"
        );
        assert!(observation.renewal_request().is_err(), "{label}");
        observation.close_renewal_scope().unwrap();
        assert!(
            matches!(route.returned(RouteResult::Retry), Err(Rejected::Phase)),
            "{label}"
        );
        assert!(observation.snapshot().settlement.is_none(), "{label}");
    }
}

#[test]
fn closing_renewal_scope_preserves_pending_statement_and_receipt_facts() {
    for label in [
        "not_entered",
        "statement_pending",
        "lease_retained",
        "lease_lost",
    ] {
        let (observation, _route) = started_route(false);
        let renewal = observation.renewal_request().unwrap();
        renewal.start().unwrap();
        if label != "not_entered" {
            let entered = renewal.enter_statement().unwrap();
            if label == "statement_pending" {
                drop(entered);
            } else {
                renewal
                    .received(entered, label == "lease_retained")
                    .unwrap();
            }
        }
        let before = observation.snapshot().renewal;
        assert!(before.pending, "{label}");
        let _closed = observation.close_renewal_scope().unwrap();
        assert_eq!(observation.snapshot().renewal, before, "{label}");
        assert!(observation.snapshot().renewal_scope_closed, "{label}");
        let expected = if label == "lease_lost" {
            Rejected::LeaseLost
        } else {
            Rejected::Renewal
        };
        assert!(
            matches!(observation.renewal_request(), Err(error) if error == expected),
            "{label}"
        );
        assert_eq!(renewal.returned(true), Err(Rejected::Phase), "{label}");
        assert_eq!(observation.snapshot().renewal, before, "{label}");
    }
}

#[test]
fn settlement_requires_own_closed_scope_and_exact_outcome_command() {
    for (label, result, command) in [
        (
            "worker_ack",
            RouteResult::CompletedByWorker,
            SettlementCommand::Ack,
        ),
        (
            "pending_defer",
            RouteResult::Pending,
            SettlementCommand::Defer { delay_seconds: 37 },
        ),
        (
            "permanent_dead_letter",
            RouteResult::Permanent,
            SettlementCommand::DeadLetter {
                reason: "disabled".into(),
                error: "account disabled".into(),
            },
        ),
        (
            "failed_retry",
            RouteResult::Retry,
            SettlementCommand::Retry {
                error: "route failed".into(),
            },
        ),
    ] {
        let (observation, route) = started_route(false);
        let completion = route.returned(result).unwrap();
        // A matching invocation alone cannot substitute for scope closure.
        let unclosed = RenewalScopeClosed {
            observation: observation.clone(),
        };
        assert!(
            matches!(
                completion.settlement(command.clone(), unclosed),
                Err(Rejected::Renewal)
            ),
            "{label}"
        );
        assert!(observation.snapshot().settlement.is_none(), "{label}");

        let (observation, route) = started_route(false);
        let closed = observation.close_renewal_scope().unwrap();
        let wrong = if command.kind() == SettlementKind::Ack {
            SettlementCommand::Retry {
                error: "wrong kind".into(),
            }
        } else {
            SettlementCommand::Ack
        };
        assert!(
            matches!(
                route.returned(result).unwrap().settlement(wrong, closed),
                Err(Rejected::Settlement)
            ),
            "{label}"
        );
        assert!(observation.snapshot().settlement.is_none(), "{label}");

        let (observation, route) = started_route(false);
        let closed = observation.close_renewal_scope().unwrap();
        let request = route
            .returned(result)
            .unwrap()
            .settlement(command.clone(), closed)
            .unwrap()
            .unwrap();
        assert_eq!(request.source(), row(false).source, "{label}");
        assert_eq!(request.route_wake_generation(), 9, "{label}");
        assert_eq!(request.command(), &command, "{label}");
        assert!(observation.snapshot().renewal_scope_closed, "{label}");
        request.start().unwrap();
        assert_eq!(request.start(), Err(Rejected::Started), "{label}");
        assert!(
            matches!(observation.renewal_request(), Err(Rejected::Settlement)),
            "{label}"
        );
    }
    for label in ["scope_not_closed", "aborted"] {
        let (observation, request) = settlement(SettlementKind::Ack);
        {
            let mut state = observation.state();
            if label == "scope_not_closed" {
                state.snapshot.renewal_scope_closed = false;
            } else {
                state.snapshot.aborted = true;
            }
        }
        let before = observation.snapshot();
        assert_eq!(request.start(), Err(Rejected::Phase), "{label}");
        assert_eq!(observation.snapshot(), before, "{label}");
    }
}

#[test]
fn settlement_return_retains_mismatch_without_replacing_its_exact_receipt() {
    for (label, returned) in [
        ("contradictory_deletion", SettlementResult::Ack(false)),
        ("foreign_command", SettlementResult::DeadLetter(true)),
    ] {
        let (observation, request) = settlement(SettlementKind::Ack);
        request.start().unwrap();
        let entered = request.enter_commit(SettlementResult::Ack(true)).unwrap();
        request
            .received(entered, SettlementResult::Ack(true))
            .unwrap();
        assert_eq!(
            request.returned(returned),
            Err(Rejected::MissingReceipt),
            "{label}"
        );
        let snapshot = observation.snapshot().settlement.unwrap();
        assert_eq!(
            snapshot.knowledge,
            SettlementKnowledge::ReceiptKnown(SettlementResult::Ack(true)),
            "{label}"
        );
        assert_eq!(
            snapshot.returned,
            Some(SettlementReturned::Outcome(returned)),
            "{label}"
        );
        assert_eq!(
            request.returned(SettlementResult::Ack(true)),
            Err(Rejected::Returned),
            "{label}"
        );
        assert_eq!(
            observation.snapshot().settlement.unwrap(),
            snapshot,
            "{label}"
        );
    }
}

#[test]
fn worker_commits_observe_entry_before_poll_and_success_before_return() {
    use std::task::{Context, Poll, Waker};

    for kind in ["archive_stored", "archive_replay", "settlement"] {
        for (cut, result) in [
            ("cancelled", None),
            ("reply_lost", Some(Err("worker commit reply lost"))),
            ("committed", Some(Ok(()))),
            ("not_started", None),
        ] {
            let (observation, route) = started_route(true);
            let archive_result = if kind == "archive_replay" {
                ArchiveResult::Replay(Uuid::from_u128(80))
            } else {
                ArchiveResult::Stored(Uuid::from_u128(8))
            };
            let archive = route
                .archive_request(Uuid::from_u128(7), Uuid::from_u128(8), None)
                .unwrap();
            let (settlement_observation, settlement) = settlement(SettlementKind::Ack);
            let control = crate::test_support::CommitControl::default();
            let commit = control.future(|| {
                assert_ne!(cut, "not_started", "{kind} must bind before polling");
                if kind == "settlement" {
                    assert_eq!(
                        settlement_observation
                            .snapshot()
                            .settlement
                            .unwrap()
                            .knowledge,
                        SettlementKnowledge::CommitCallEntered(SettlementResult::Ack(false)),
                        "{kind}/{cut}"
                    );
                } else {
                    assert_eq!(
                        observation.snapshot().archive.knowledge,
                        ArchiveKnowledge::CommitCallEntered(archive_result),
                        "{kind}/{cut}"
                    );
                }
            });
            if cut != "not_started" {
                if kind == "settlement" {
                    settlement.start().unwrap();
                } else {
                    archive.start().unwrap();
                }
            }
            let mut future = Box::pin(async {
                if kind == "settlement" {
                    settlement_commit_observed(commit, &settlement, SettlementResult::Ack(false))
                        .await
                } else {
                    archive_commit_observed(commit, &archive, archive_result).await
                }
            });
            let first = future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()));
            if cut == "not_started" {
                assert!(
                    matches!(
                        first,
                        Poll::Ready(Err(CommitError::Observation(Rejected::NotStarted)))
                    ),
                    "{kind}/{cut}"
                );
            } else {
                assert!(first.is_pending(), "{kind}/{cut}");
                if let Some(result) = result {
                    control.result.set(Some(result));
                    let returned = future
                        .as_mut()
                        .poll(&mut Context::from_waker(Waker::noop()));
                    match (returned, result) {
                        (Poll::Ready(Ok(())), Ok(())) => {}
                        (Poll::Ready(Err(CommitError::Commit(error))), Err(expected)) => {
                            assert_eq!(error, expected, "{kind}/{cut}");
                        }
                        _ => panic!("unexpected worker result: {kind}/{cut}"),
                    }
                }
            }
            drop(future);
            assert_eq!(
                *control.events.borrow(),
                if cut == "not_started" {
                    vec!["drop"]
                } else if result.is_some() {
                    vec!["poll", "poll", "drop"]
                } else {
                    vec!["poll", "drop"]
                },
                "{kind}/{cut}"
            );
            if kind == "settlement" {
                let snapshot = settlement_observation.snapshot().settlement.unwrap();
                assert_eq!(
                    snapshot.knowledge,
                    if cut == "not_started" {
                        SettlementKnowledge::NotEntered
                    } else if result == Some(Ok(())) {
                        SettlementKnowledge::ReceiptKnown(SettlementResult::Ack(false))
                    } else {
                        SettlementKnowledge::CommitCallEntered(SettlementResult::Ack(false))
                    },
                    "{kind}/{cut}"
                );
                assert_eq!(snapshot.returned, None, "{kind}/{cut}");
            } else {
                let snapshot = observation.snapshot().archive;
                assert_eq!(
                    snapshot.knowledge,
                    if cut == "not_started" {
                        ArchiveKnowledge::NoCommitEntered
                    } else if result == Some(Ok(())) {
                        ArchiveKnowledge::ReceiptKnown(archive_result)
                    } else {
                        ArchiveKnowledge::CommitCallEntered(archive_result)
                    },
                    "{kind}/{cut}"
                );
                assert_eq!(snapshot.returned, None, "{kind}/{cut}");
            }
        }
    }
}

struct CloneProbe<T>(std::marker::PhantomData<T>);
trait NotClone {
    fn is_clone(&self) -> bool {
        false
    }
}
impl<T> NotClone for CloneProbe<T> {}
impl<T: Clone> CloneProbe<T> {
    fn is_clone(&self) -> bool {
        true
    }
}

#[test]
fn worker_requests_and_consuming_permissions_are_not_cloneable() {
    assert!(
        CloneProbe::<String>(std::marker::PhantomData).is_clone(),
        "positive_control"
    );
    assert!(
        !CloneProbe::<ClaimRequest>(std::marker::PhantomData).is_clone(),
        "claim_request"
    );
    assert!(
        !CloneProbe::<ClaimStatement>(std::marker::PhantomData).is_clone(),
        "claim_statement"
    );
    assert!(
        !CloneProbe::<Attempt>(std::marker::PhantomData).is_clone(),
        "attempt"
    );
    assert!(
        !CloneProbe::<RouteRequest>(std::marker::PhantomData).is_clone(),
        "route_request"
    );
    assert!(
        !CloneProbe::<ArchiveRequest>(std::marker::PhantomData).is_clone(),
        "archive_request"
    );
    assert!(
        !CloneProbe::<ArchiveCommit>(std::marker::PhantomData).is_clone(),
        "archive_commit"
    );
    assert!(
        !CloneProbe::<LocalRequest>(std::marker::PhantomData).is_clone(),
        "local_request"
    );
    assert!(
        !CloneProbe::<ClusterRequest>(std::marker::PhantomData).is_clone(),
        "cluster_request"
    );
    assert!(
        !CloneProbe::<RouteCompletion>(std::marker::PhantomData).is_clone(),
        "route_completion"
    );
    assert!(
        !CloneProbe::<RenewalScopeClosed>(std::marker::PhantomData).is_clone(),
        "renewal_scope_closed"
    );
    assert!(
        !CloneProbe::<RenewalRequest>(std::marker::PhantomData).is_clone(),
        "renewal_request"
    );
    assert!(
        !CloneProbe::<RenewalStatement>(std::marker::PhantomData).is_clone(),
        "renewal_statement"
    );
    assert!(
        !CloneProbe::<SettlementRequest>(std::marker::PhantomData).is_clone(),
        "settlement_request"
    );
    assert!(
        !CloneProbe::<SettlementBoundary>(std::marker::PhantomData).is_clone(),
        "settlement_boundary"
    );
}

#[test]
fn identical_source_ids_cannot_exchange_closed_renewal_scopes_or_archive_receipts() {
    let (first, a) = started_route(true);
    let (second, b) = started_route(true);
    let archive_a = a
        .archive_request(Uuid::from_u128(7), Uuid::from_u128(8), None)
        .unwrap();
    let archive_b = b
        .archive_request(Uuid::from_u128(7), Uuid::from_u128(8), None)
        .unwrap();
    archive_a.start().unwrap();
    archive_b.start().unwrap();
    let token = archive_a
        .enter_commit(ArchiveResult::Stored(Uuid::from_u128(8)))
        .unwrap();
    assert_eq!(archive_b.received(token), Err(Rejected::Invocation));
    assert_eq!(
        second.snapshot().archive.knowledge,
        ArchiveKnowledge::NoCommitEntered
    );
    let closed = second.close_renewal_scope().unwrap();
    archive_a.failed().unwrap();
    first.close_renewal_scope().unwrap();
    let completion = a.returned(RouteResult::Retry).unwrap();
    assert!(matches!(
        completion.settlement(
            SettlementCommand::Retry {
                error: "error".into()
            },
            closed
        ),
        Err(Rejected::Invocation)
    ));
    assert!(first.snapshot().settlement.is_none());
}
