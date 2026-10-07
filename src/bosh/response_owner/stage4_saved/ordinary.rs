//! Ordinary controls for actual BOSH response ownership and captured facts.
use super::*;
use crate::services::authentication::publication;
use crate::services::mix::outbox::core as worker;
use crate::xmpp::auth_publication::stage4_saved::{
    self as auth,
    ordinary::{self as input, fixed, list, text},
};
use crate::xmpp::protocol::mix::stage4_saved::{
    Bridge, ClaimSites, ForegroundSite, RouteHandle, RouteMap,
};

#[tokio::test]
async fn actual_selection_of_p_u_keeps_genuine_b_queued_until_teardown() {
    let recorder = input::recorder();
    let routes = RouteMap::new(recorder.clone());
    let bound = input::bound(
        wire::TransportKind::Bosh,
        wire::PublicationReply::BackendError(wire::Empty {}),
    );
    let (route, _queue) = routes.install_auth(&bound, 1).unwrap();
    let (u, u_read, u_publisher) = auth::build(
        &input::unbound(),
        None,
        recorder.clone(),
        input::credential_site(0),
    )
    .await
    .unwrap()
    .unwrap()
    .split();
    let (b, b_read, b_publisher) = auth::build(
        &bound,
        Some(route.clone()),
        recorder.clone(),
        input::credential_site(1),
    )
    .await
    .unwrap()
    .unwrap()
    .split();
    let b_before = b_read.live_snapshot();
    let b_joins_before = b_read.publication_joins();
    let p_open = "<presence><status>";
    let p_close = "</status></presence>";
    let padding = 16384usize - 256 - u.stanza.len() - p_open.len() - p_close.len();
    let p = format!("{p_open}{}{p_close}", "x".repeat(padding));
    let f = "<stream:features xmlns:stream=\"http://etherx.jabber.org/streams\"/>";
    let mut session = Session::new(input::session(2, 3, 22), recorder.clone()).unwrap();
    session.push_plain(p, 0).unwrap();
    session
        .push_auth(u, u_read.clone(), u_publisher, 1)
        .unwrap();
    session.push_plain(f.to_owned(), 2).unwrap();
    session
        .push_auth(b, b_read.clone(), b_publisher, 3)
        .unwrap();
    assert_eq!(session.output.len(), 4);
    assert_eq!(session.reads.len(), 2);
    assert_eq!(
        session
            .respond(BoshSite::new(0).unwrap(), wire::AuthDrive::Complete)
            .await
            .unwrap()
            .unwrap()
            .returned,
        Some(true)
    );
    let selected = session.last_selection.as_ref().unwrap().snapshot();
    assert_eq!(selected.status, SelectionReadStatus::Complete);
    assert_eq!(selected.selected_count, 2);
    assert!(!selected.items[0].unwrap().auth_marker);
    assert_eq!(
        selected.items[1]
            .unwrap()
            .sealed_association
            .unwrap()
            .control,
        u_read.control()
    );
    assert!(selected.items[2].is_none() && selected.items[3].is_none());
    assert_eq!(session.output.len(), 2);
    assert_eq!(session.output[0].stanza, f);
    assert_eq!(
        session.output[1]
            .auth_publication()
            .unwrap()
            .join_observation()
            .snapshot()
            .introduced
            .unwrap()
            .control,
        b_read.control()
    );
    assert_eq!(
        u_read.live_snapshot().terminal,
        Some(publication::Terminal::Completed)
    );
    assert_eq!(
        u_read.live_snapshot().publication,
        publication::Knowledge::NotRequired
    );
    assert_eq!(b_read.live_snapshot(), b_before);
    assert_eq!(b_read.publication_joins(), b_joins_before);
    assert_eq!(session.replay.len(), 1);
    assert!(!route.snapshot().unwrap().unwrap().routable);
    session.teardown().unwrap();
    assert_eq!(
        b_read.live_snapshot().terminal,
        Some(publication::Terminal::Abandoned)
    );
    assert_eq!(
        b_read.live_snapshot().publication,
        publication::Knowledge::NotStarted
    );
}
#[tokio::test]
async fn accepted_bosh_auth_backend_error_cannot_cache_or_activate() {
    let recorder = input::recorder();
    let bound = input::bound(
        wire::TransportKind::Bosh,
        wire::PublicationReply::BackendError(wire::Empty {}),
    );
    let routes = RouteMap::new(recorder.clone());
    let (route, _queue) = routes.install_auth(&bound, 1).unwrap();
    let (item, read, publisher) = auth::build(
        &bound,
        Some(route.clone()),
        recorder.clone(),
        input::credential_site(0),
    )
    .await
    .unwrap()
    .unwrap()
    .split();
    let receipt = read.credential_joins().returned_receipt;
    let mut session = Session::new(input::session(2, 3, 22), recorder).unwrap();
    session.push_auth(item, read.clone(), publisher, 0).unwrap();
    let run = session
        .respond(BoshSite::new(0).unwrap(), wire::AuthDrive::Complete)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(run.returned, Some(false));
    assert!(!run.dropped);
    let s = read.live_snapshot();
    assert_eq!(
        s.transport,
        publication::Transport::BoshAccepted { rid: 22 }
    );
    assert_eq!(s.returned, Some(publication::Returned::BackendFailure));
    assert_eq!(s.terminal, Some(publication::Terminal::Failed));
    assert_eq!(read.credential_joins().returned_receipt, receipt);
    assert_eq!(session.replay.len(), 0);
    assert_eq!(session.highest_responded, 0);
    assert!(!route.snapshot().unwrap().unwrap().routable);
}
#[tokio::test]
async fn accepted_bosh_pending_commit_has_separate_predrop_and_cancelled_cuts() {
    let recorder = input::recorder();
    let bound = input::bound(
        wire::TransportKind::Bosh,
        wire::PublicationReply::CommitPending(wire::EpochReply {
            epoch: wire::Nullable::Null(()),
        }),
    );
    let routes = RouteMap::new(recorder.clone());
    let (route, _queue) = routes.install_auth(&bound, 1).unwrap();
    let (item, read, publisher) = auth::build(
        &bound,
        Some(route),
        recorder.clone(),
        input::credential_site(0),
    )
    .await
    .unwrap()
    .unwrap()
    .split();
    let mut session = Session::new(input::session(2, 3, 22), recorder.clone()).unwrap();
    session.push_auth(item, read.clone(), publisher, 0).unwrap();
    let run = session
        .respond(
            BoshSite::new(0).unwrap(),
            wire::AuthDrive::DropPublicationCommit,
        )
        .await
        .unwrap()
        .unwrap();
    assert!(run.dropped);
    assert_eq!(run.returned, None);
    assert_eq!(
        read.live_snapshot().transport,
        publication::Transport::BoshAccepted { rid: 22 }
    );
    assert_eq!(
        read.live_snapshot().publication,
        publication::Knowledge::CommitCallEntered
    );
    assert_eq!(
        read.live_snapshot().terminal,
        Some(publication::Terminal::Cancelled)
    );
    assert!(session.replay.is_empty());
    let envelope = input::drain(&recorder);
    let fs = envelope.facts.as_slice();
    let position = |cut, terminal| {
        fs.iter().position(|f| matches!(&f.fact, wire::Fact::Control(wire::ControlFact::LivePublication(p)) if p.cut == cut && p.snapshot.terminal.get().copied() == terminal)).unwrap()
    };
    assert!(position(wire::Cut::AfterPoll, None) < position(wire::Cut::ChildDrop, None));
    assert!(
        position(wire::Cut::ChildDrop, None)
            < position(
                wire::Cut::AfterRunnerDrop,
                Some(wire::PublicationTerminal::Cancelled)
            )
    );
}
#[tokio::test]
async fn skipped_publication_stays_notstarted_and_baseline_has_no_cache_continuation() {
    let recorder = input::recorder();
    let bound = input::bound(
        wire::TransportKind::Bosh,
        wire::PublicationReply::BackendError(wire::Empty {}),
    );
    let routes = RouteMap::new(recorder.clone());
    let (route, _queue) = routes.install_auth(&bound, 1).unwrap();
    let (item, read, publisher) = auth::build(
        &bound,
        Some(route),
        recorder.clone(),
        input::credential_site(0),
    )
    .await
    .unwrap()
    .unwrap()
    .split();
    let mut session = Session::new(input::session(2, 3, 22), recorder).unwrap();
    session.push_auth(item, read.clone(), publisher, 0).unwrap();
    let operation = Operation::new(Scope {
        session_id: session.session_id(),
        ttl_seconds: 60,
        kind: OperationKind::Request,
    });
    let service = ReplayService::new(
        repository::Repository {
            session: session.session_id(),
            ordinal: 0,
            bind: session.input.bind.clone(),
            ack: None,
            recorder: session.recorder.clone(),
            used: Arc::new(std::sync::Mutex::new([false; 3])),
        },
        "stage4.example.test",
        1,
    );
    let mut fields = Fields {
        output: &mut session.output,
        output_bytes: &mut session.output_bytes,
        replay: &mut session.replay,
        governor: &session.governor,
        max_response_bytes: 16384,
        max_output_stanzas: 4,
        content_type: "text/xml",
        received_rid: Some(22),
    };
    let bound = prepare(
        &mut fields,
        Metadata {
            rid: 22,
            fingerprint: [0; 32],
            cache: true,
        },
        None,
        &operation,
        &ServiceReplay { service: &service },
    )
    .await
    .unwrap();
    let selection = bound.selection_observation();
    let bound = bound.for_connection(session.connection_id()).unwrap();
    let (sender, receiver) = oneshot::channel();
    let exposed = bound.expose(vec![sender]).unwrap();
    assert_eq!(
        selection.snapshot().items[0]
            .unwrap()
            .sealed_association
            .unwrap()
            .control,
        read.control()
    );
    assert_eq!(
        read.live_snapshot().publication,
        publication::Knowledge::NotStarted
    );
    assert!(read.publication_joins().begun_receipt.is_none());
    // Existing baseline compatibility finish explicitly rejects auth; do not
    // manufacture PublicationReadyResponse or add a second bypass branch.
    assert!(exposed
        .finish(
            &mut session.last_response,
            &mut session.highest_responded,
            &mut session.replay
        )
        .is_err());
    assert!(receiver.await.is_ok());
    assert!(session.replay.is_empty());
    assert_eq!(
        read.live_snapshot().terminal,
        Some(publication::Terminal::ExposedNotAttempted)
    );
    assert_eq!(read.live_snapshot().returned, None);
}

fn mix_inputs() -> (
    wire::DeliveryRow<wire::Id>,
    wire::WorkerAttemptInput,
    wire::RouteInput,
) {
    let row = wire::DeliveryRow {
        source: wire::MixSource {
            delivery_id: fixed(12),
            lease_token: fixed(13),
        },
        event_id: fixed(9),
        channel_id: fixed(10),
        channel_jid: text("c@mix.example.test"),
        participant_id: fixed(11),
        recipient_jid: text("u@example.test"),
        recipient_nick: wire::Nullable::Null(()),
        stanza: text("<message><body>ordinary</body></message>"),
        authoritative_stanza_id: wire::Nullable::Value(fixed(9)),
        archive: true,
        encrypted: false,
        attempt_count: 0,
        route_wake_generation: 1,
    };
    let route = wire::RouteInput {
        full_jid: text("u@example.test/m"),
        user_id: fixed(4),
        connection_id: fixed(7),
        auth_generation: 1,
        routable: true,
        disconnected: false,
        lifecycle: wire::Lifecycle::Active,
        caps: wire::CapsInput {
            connection_id: fixed(7),
            generation: 3,
            verified_features: list(vec![wire::CapabilityFeature::MixCore]),
        },
        provenance: wire::RouteProvenance::InitiallyPublished(wire::Empty {}),
    };
    let attempt = wire::WorkerAttemptInput {
        claim: wire::ClaimInput {
            limit: 1,
            max_bytes: 4096,
            lease_token: fixed(13),
            attempt_count: 0,
            route_wake_generation: 1,
            commit: wire::CommitCut::Complete,
        },
        archive: wire::ArchiveInput {
            reply: wire::ArchiveReply::StoreCandidate(wire::Empty {}),
            commit: wire::CommitCut::Complete,
        },
        route: wire::RouteEnvironment {
            enabled_account_id: fixed(4),
            privacy_blocked: false,
            targets: list(vec![route.clone()]),
            queue_capacity: 1,
        },
    };
    (row, attempt, route)
}
async fn complete_independent_mix(
    recorder: Capture,
    routes: RouteMap,
) -> (
    Session,
    worker::Observation,
    RouteHandle,
    mpsc::Receiver<OutboundItem>,
) {
    let bridge = Bridge::new("mix.example.test", recorder.clone()).unwrap();
    let (row, attempt, route_input) = mix_inputs();
    let (route, mut queue) = routes.install(&route_input, 1).unwrap();
    let row = bridge.initial_row(&row).unwrap();
    let mut run = Box::pin(
        bridge
            .claim(row, &attempt, ClaimSites::new(0).unwrap(), routes)
            .await
            .unwrap()
            .unwrap(),
    );
    assert!(futures::poll!(run.as_mut()).is_pending());
    let item = queue.try_recv().unwrap();
    run.record_dequeued(&route, 0, &item);
    let actual_worker = run.observation();
    let transferred = wire::MixSource {
        delivery_id: fixed(12),
        lease_token: fixed(14),
    };
    bridge
        .supply_bosh_transfer(&wire::BoshTransferReply {
            commit: wire::CommitCut::Complete,
            returned_source: transferred.clone(),
        })
        .unwrap();
    let mut session_input = input::session(7, 8, 11);
    session_input.bind.membership.mix_delivery_ids = list(vec![fixed(12)]);
    let mut session = Session::new(session_input, recorder.clone()).unwrap();
    assert!(session
        .push_mix(item, 0, BoshSite::new(0).unwrap(), &bridge.service())
        .await
        .unwrap()
        .unwrap());
    run.await.unwrap().unwrap();
    assert_eq!(
        actual_worker.snapshot().transfer.unwrap().boundary,
        worker::TransferBoundary::BoshPersisted(Uuid::from_u128(8))
    );
    assert!(actual_worker.snapshot().renewal_scope_closed);
    assert!(actual_worker.snapshot().settlement.is_none());
    assert_eq!(
        session
            .respond(BoshSite::new(1).unwrap(), wire::AuthDrive::Complete)
            .await
            .unwrap()
            .unwrap()
            .returned,
        Some(true)
    );
    assert_eq!(
        session.replay[0].durable_ownership.mix_delivery_ids,
        vec![Uuid::from_u128(12)]
    );
    (session, actual_worker, route, queue)
}
#[tokio::test]
async fn actual_mix_queue_bosh_transfer_response_and_ack_preserve_typed_retirement() {
    let recorder = input::recorder();
    let routes = RouteMap::new(recorder.clone());
    let (mut session, actual_worker, _route, _queue) =
        complete_independent_mix(recorder, routes).await;
    let transferred = wire::MixSource {
        delivery_id: fixed(12),
        lease_token: fixed(14),
    };
    let raw = format!(
        "<body xmlns='http://jabber.org/protocol/httpbind' rid='12' ack='11' sid='{}'/>",
        Uuid::from_u128(8)
    );
    let ack = wire::BoshAckInput {
        request: wire::BoshRequest {
            rid: 12,
            fingerprint: wire::sha256(raw.as_bytes()),
            request_xml: text(&raw),
            content_type: text("text/xml"),
            responders: list(vec![wire::Responder::Open]),
        },
        acknowledged_rid: 11,
        renewal: wire::CommitCut::Complete,
        commit: wire::CommitCut::Complete,
        deleted: transferred,
    };
    session
        .acknowledge(&ack, BoshSite::new(2).unwrap())
        .await
        .unwrap()
        .unwrap();
    // Normal ACK response is itself cached at its newer RID and empty-source
    // membership; only the old data response is evicted by the ACK.
    assert_eq!(session.replay.len(), 1);
    assert_eq!(session.replay[0].rid, 12);
    assert!(session.replay[0].durable_ownership.is_empty());
    assert_eq!(
        session
            .last_selection
            .as_ref()
            .unwrap()
            .snapshot()
            .selected_count,
        0
    );
    assert!(actual_worker.snapshot().settlement.is_none());
}
#[tokio::test]
async fn independent_mix_completion_precedes_bound_auth_failure_or_commit_drop() {
    for pending in [false, true] {
        let recorder = input::recorder();
        let routes = RouteMap::new(recorder.clone());
        let (m, worker, m_route, _m_queue) =
            complete_independent_mix(recorder.clone(), routes.clone()).await;
        let before = m.replay[0].response.body.clone();
        let publication = if pending {
            wire::PublicationReply::CommitPending(wire::EpochReply {
                epoch: wire::Nullable::Null(()),
            })
        } else {
            wire::PublicationReply::BackendError(wire::Empty {})
        };
        let bound = input::bound(wire::TransportKind::Bosh, publication);
        let (a_route, _a_queue) = routes.install_auth(&bound, 1).unwrap();
        assert_ne!(m_route.full_jid(), a_route.full_jid());
        assert_ne!(m_route.connection_id(), a_route.connection_id());
        assert!(!Arc::ptr_eq(&m_route.lifecycle(), &a_route.lifecycle()));
        let (item, read, publisher) = auth::build(
            &bound,
            Some(a_route.clone()),
            recorder.clone(),
            input::credential_site(0),
        )
        .await
        .unwrap()
        .unwrap()
        .split();
        let mut a = Session::new(input::session(2, 3, 22), recorder).unwrap();
        a.push_auth(item, read.clone(), publisher, 1).unwrap();
        assert_ne!(m.session_id(), a.session_id());
        let run = a
            .respond(
                BoshSite::new(2).unwrap(),
                if pending {
                    wire::AuthDrive::DropPublicationCommit
                } else {
                    wire::AuthDrive::Complete
                },
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(run.dropped, pending);
        assert_eq!(run.returned, if pending { None } else { Some(false) });
        assert_eq!(
            read.live_snapshot().terminal,
            Some(if pending {
                publication::Terminal::Cancelled
            } else {
                publication::Terminal::Failed
            })
        );
        assert!(a.replay.is_empty());
        assert!(!a_route.snapshot().unwrap().unwrap().routable);
        assert_eq!(m.replay[0].response.body, before);
        assert!(worker.snapshot().settlement.is_none());
        assert_eq!(m.replay[0].rid, 11);
        assert!(a.output.is_empty());
    }
}
#[tokio::test]
async fn actual_mix_queue_native_fence_flush_and_ack_complete_real_worker() {
    let recorder = input::recorder();
    let bridge = Bridge::new("mix.example.test", recorder.clone()).unwrap();
    let (row, attempt, route_input) = mix_inputs();
    let routes = RouteMap::new(recorder.clone());
    let (route, mut queue) = routes.install(&route_input, 1).unwrap();
    let row = bridge.initial_row(&row).unwrap();
    let mut run = Box::pin(
        bridge
            .claim(row, &attempt, ClaimSites::new(0).unwrap(), routes)
            .await
            .unwrap()
            .unwrap(),
    );
    assert!(futures::poll!(run.as_mut()).is_pending());
    let item = queue.try_recv().unwrap();
    run.record_dequeued(&route, 0, &item);
    let owner = run.observation();
    let native = wire::DurableNative {
        connection_id: fixed(7),
        write: input::write_ok(),
        returned_fence: wire::MixSource {
            delivery_id: fixed(12),
            lease_token: fixed(14),
        },
        ack_commit: wire::CommitCut::Complete,
    };
    bridge.supply_native(&native).unwrap();
    crate::xmpp::stage4_native::write_item(
        item,
        route.connection_id(),
        input::native_site(0),
        wire::ItemOwner::Mix(wire::MixItemOwner { attempt_ordinal: 0 }),
        native.write,
        Some(&bridge.service()),
        recorder,
    )
    .await
    .unwrap()
    .unwrap();
    run.await.unwrap().unwrap();
    assert_eq!(
        owner.snapshot().transfer.unwrap().boundary,
        worker::TransferBoundary::SocketFenced(route.connection_id())
    );
    assert!(owner.snapshot().settlement.is_none());
}
#[tokio::test]
async fn auth_activates_the_same_prestaged_queue_before_fresh_mix_projection_and_native_transfer() {
    let recorder = input::recorder();
    let routes = RouteMap::new(recorder.clone());
    let mut bound = input::bound(
        wire::TransportKind::Tcp,
        wire::PublicationReply::Committed(wire::EpochReply {
            epoch: wire::Nullable::Null(()),
        }),
    );
    // Input controls are generated by actual builders for this ordinary control;
    // this is not a saved-literal freeze or complete entry execution.
    bound.frame.frame_id = fixed(1);
    let (_, mut attempt, mut target) = mix_inputs();
    target.full_jid = text("u@example.test/r");
    target.connection_id = fixed(2);
    target.caps.connection_id = fixed(2);
    target.routable = false;
    target.provenance =
        wire::RouteProvenance::ActivatedByAuth(wire::ActivatedRoute { frame_id: fixed(1) });
    attempt.route.targets = list(vec![target.clone()]);
    let (route, mut queue) = routes.install(&target, 1).unwrap();
    routes.capture_lookup(
        wire::RouteLookupOwner::Auth(wire::OneId {
            id: observed::id(Uuid::from_u128(1)),
        }),
        route.full_jid(),
    );
    assert!(!route.snapshot().unwrap().unwrap().routable);
    let (auth_item, read, mut publisher) = auth::build(
        &bound,
        Some(route.clone()),
        recorder.clone(),
        input::credential_site(0),
    )
    .await
    .unwrap()
    .unwrap()
    .split();
    let actual_control_bytes = auth_item.stanza.clone();
    let enqueue =
        crate::outbound::RouteEnqueue::bind(auth_item, None, &actual_control_bytes).unwrap();
    route.sender().try_send_route_item(enqueue).unwrap();
    let same_auth_item = queue.try_recv().unwrap();
    let owner = crate::xmpp::stage4_native::write_auth(
        same_auth_item,
        route.connection_id(),
        input::native_site(0),
        input::write_ok(),
        recorder.clone(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        auth::publish_native(
            owner,
            &read,
            &mut publisher,
            wire::AuthDrive::Complete,
            &recorder,
            input::publication_site(0)
        )
        .await
        .unwrap()
        .unwrap()
        .returned,
        Some(true)
    );
    assert!(route.snapshot().unwrap().unwrap().routable);
    let bridge = Bridge::new("mix.example.test", recorder.clone()).unwrap();
    let foreground = wire::FreshForeground {
        frame: wire::Frame {
            frame_id: fixed(66),
            connection_id: fixed(7),
            transport: wire::TransportKind::Tcp,
            input: text("<message type='groupchat'><body>ordinary</body></message>"),
        },
        configured_domain: text("mix.example.test"),
        ingress: wire::MixIngress {
            channel_id: fixed(10),
            channel_jid: text("c@mix.example.test"),
            actor_bare: text("s@example.test"),
            actor_full: text("s@example.test/a"),
            children: text("<body>ordinary</body>"),
            encrypted: false,
            identity: wire::Nullable::Null(()),
        },
        command: wire::MixStoreCommand {
            channel_id: fixed(10),
            actor: text("s@example.test"),
            item_id: fixed(9),
            payload: text("<item/>"),
            identity: wire::Nullable::Null(()),
            delivery_payload: text("<body>ordinary</body>"),
            visible_jid: wire::Nullable::Null(()),
            encrypted: false,
        },
        stored: wire::Stored {
            authoritative_id: fixed(9),
            storage_id: fixed(19),
            channel_id: fixed(10),
            channel_jid: text("c@mix.example.test"),
            projection: wire::Nullable::Value(wire::DeliveryProjection {
                event_id: fixed(9),
                channel_id: fixed(10),
                channel_jid: text("c@mix.example.test"),
                stanza_template: text("<message><body>ordinary</body></message>"),
                authoritative_stanza_id: wire::Nullable::Value(fixed(9)),
                archive: true,
                encrypted: false,
                recipients: list(vec![wire::RecipientProjection {
                    participant: wire::Participant {
                        participant_id: fixed(11),
                        jid: text("u@example.test"),
                        nick: wire::Nullable::Null(()),
                    },
                    delivery_id: fixed(12),
                    sequence: 1,
                }]),
            }),
        },
        commit: wire::CommitCut::Complete,
    };
    let row = bridge
        .fresh(
            &foreground,
            &wire::FreshProjectionOrigin {
                foreground_frame: fixed(66),
                recipient_ordinal: 0,
                declared_delivery_id: fixed(12),
            },
            &attempt.claim,
            ForegroundSite::new(0).unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
    let mut run = Box::pin(
        bridge
            .claim(row, &attempt, ClaimSites::new(0).unwrap(), routes)
            .await
            .unwrap()
            .unwrap(),
    );
    assert!(futures::poll!(run.as_mut()).is_pending());
    let actual_item = queue.try_recv().unwrap();
    run.record_dequeued(&route, 1, &actual_item);
    let worker = run.observation();
    let native = wire::DurableNative {
        connection_id: fixed(2),
        write: input::write_ok(),
        returned_fence: wire::MixSource {
            delivery_id: fixed(12),
            lease_token: fixed(14),
        },
        ack_commit: wire::CommitCut::Complete,
    };
    bridge.supply_native(&native).unwrap();
    crate::xmpp::stage4_native::write_item(
        actual_item,
        route.connection_id(),
        input::native_site(1),
        wire::ItemOwner::Mix(wire::MixItemOwner { attempt_ordinal: 0 }),
        native.write,
        Some(&bridge.service()),
        recorder.clone(),
    )
    .await
    .unwrap()
    .unwrap();
    run.await.unwrap().unwrap();
    assert_eq!(
        worker.snapshot().transfer.unwrap().boundary,
        worker::TransferBoundary::SocketFenced(route.connection_id())
    );
    assert!(worker.snapshot().settlement.is_none());
    assert_eq!(worker.row().source.delivery_id, Uuid::from_u128(12));
    assert!(matches!(
        input::drain(&recorder).observation_status,
        wire::ObservationStatus::Complete(_)
    ));
}

#[tokio::test]
async fn semantic_observation_loss_does_not_replace_bosh_publication_or_cache_success() {
    let recorder = input::recorder();
    let (item, read, publisher) = auth::build(
        &input::unbound(),
        None,
        recorder.clone(),
        input::credential_site(0),
    )
    .await
    .unwrap()
    .unwrap()
    .split();
    let mut session = Session::new(input::session(2, 3, 22), recorder.clone()).unwrap();
    session.push_auth(item, read.clone(), publisher, 0).unwrap();
    observed::lost(&recorder);
    assert_eq!(
        session
            .respond(BoshSite::new(0).unwrap(), wire::AuthDrive::Complete)
            .await
            .unwrap()
            .unwrap()
            .returned,
        Some(true)
    );
    assert_eq!(
        read.live_snapshot().terminal,
        Some(publication::Terminal::Completed)
    );
    assert_eq!(session.replay.len(), 1);
    assert_eq!(session.replay[0].rid, 22);
    assert!(matches!(
        input::drain(&recorder).observation_status,
        wire::ObservationStatus::Lost(_)
    ));
}
#[tokio::test]
async fn semantic_observation_loss_does_not_replace_actual_renew_ack_or_empty_response() {
    let recorder = input::recorder();
    let routes = RouteMap::new(recorder.clone());
    let (mut session, worker, _route, _queue) =
        complete_independent_mix(recorder.clone(), routes).await;
    let raw = format!(
        "<body xmlns='http://jabber.org/protocol/httpbind' rid='12' ack='11' sid='{}'/>",
        Uuid::from_u128(8)
    );
    let ack = wire::BoshAckInput {
        request: wire::BoshRequest {
            rid: 12,
            fingerprint: wire::sha256(raw.as_bytes()),
            request_xml: text(&raw),
            content_type: text("text/xml"),
            responders: list(vec![wire::Responder::Open]),
        },
        acknowledged_rid: 11,
        renewal: wire::CommitCut::Complete,
        commit: wire::CommitCut::Complete,
        deleted: wire::MixSource {
            delivery_id: fixed(12),
            lease_token: fixed(14),
        },
    };
    observed::lost(&recorder);
    session
        .acknowledge(&ack, BoshSite::new(2).unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(session.highest_responded, 12);
    assert_eq!(session.replay.len(), 1);
    assert_eq!(session.replay[0].rid, 12);
    assert!(session.replay[0].durable_ownership.is_empty());
    assert!(worker.snapshot().settlement.is_none());
    assert!(matches!(
        input::drain(&recorder).observation_status,
        wire::ObservationStatus::Lost(_)
    ));
}
