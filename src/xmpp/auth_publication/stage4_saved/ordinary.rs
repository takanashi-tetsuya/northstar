//! Ordinary controls for actual credential and publication owners.
//! The fixed recorder scaffold establishes input labels for local observations;
//! scripted component variants are not complete accepted saved compositions.
//! None of these tests encodes or publishes a saved evidence contract.
use super::*;
use crate::services::authentication::publication as actual;
use crate::xmpp::protocol::mix::stage4_saved::RouteMap;

pub(crate) fn fixed(n: u128) -> wire::Id {
    wire::Id(Uuid::from_u128(n))
}
pub(crate) fn text<const N: usize>(value: &str) -> wire::Text<N> {
    wire::Text::new(value).unwrap()
}
pub(crate) fn list<T, const N: usize>(value: Vec<T>) -> wire::List<T, N> {
    wire::List::new(value).unwrap()
}
pub(crate) fn write_ok() -> wire::WriteScript {
    wire::WriteScript {
        chunk_limit: 4096,
        fail_after_accepted_bytes: wire::Nullable::Null(()),
        flush: wire::FlushReply::Ok,
    }
}
pub(crate) fn credential_site(n: u8) -> CredentialSite {
    CredentialSite::new(n).unwrap()
}
pub(crate) fn publication_site(n: u8) -> PublicationSite {
    PublicationSite::new(n).unwrap()
}
pub(crate) fn native_site(n: u8) -> crate::xmpp::stage4_native::NativeSite {
    crate::xmpp::stage4_native::NativeSite::new(n).unwrap()
}
pub(crate) fn bound(
    transport: wire::TransportKind,
    publication: wire::PublicationReply,
) -> wire::AuthInput {
    let mut control = wire::ControlInput::Binding(wire::BoundControlInput {
        iq_id: text("b1"),
        full_jid: text("u@example.test/r"),
        xml: text(""),
    });
    let xml = control_xml(&control).unwrap();
    let wire::ControlInput::Binding(c) = &mut control else {
        unreachable!()
    };
    c.xml = text(&xml);
    wire::AuthInput {
        frame: wire::Frame { frame_id: fixed(1), connection_id: fixed(2), transport, input: text("<iq type='set' id='b1'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>r</resource></bind></iq>") },
        user_id: fixed(4), auth_generation: 1, device_id: wire::Nullable::Null(()), ordinal: 0, credential_kind: wire::CredentialKind::Binding,
        binding: wire::Nullable::Value(wire::BindingInput { resource: text("r"), lease_seconds: 60, full_jid: text("u@example.test/r") }),
        preparation: wire::CredentialPreparationInput { generation_allowed: true, binding_reserved: true, stage_present: false, stage_epoch: wire::Nullable::Null(()), commit: wire::CommitCut::Complete },
        control, publication, notification_expected: false,
    }
}
pub(crate) fn unbound() -> wire::AuthInput {
    let mut input = bound(
        wire::TransportKind::Bosh,
        wire::PublicationReply::NoSql(wire::Empty {}),
    );
    input.frame.frame_id = fixed(5);
    input.frame.input = text("<authenticate xmlns='urn:xmpp:sasl:2'/>");
    input.credential_kind = wire::CredentialKind::UnboundFast;
    input.binding = wire::Nullable::Null(());
    input.preparation.binding_reserved = false;
    input.control = wire::ControlInput::UnboundFast(wire::UnboundControlInput {
        authorization_identifier: text("u@example.test"),
        xml: text(""),
    });
    let xml = control_xml(&input.control).unwrap();
    let wire::ControlInput::UnboundFast(c) = &mut input.control else {
        unreachable!()
    };
    c.xml = text(&xml);
    input
}
pub(crate) fn session(connection: u128, session: u128, rid: u64) -> wire::BoshSessionInput {
    let raw = format!(
        "<body xmlns='http://jabber.org/protocol/httpbind' rid='{rid}' sid='{}'/>",
        Uuid::from_u128(session)
    );
    wire::BoshSessionInput {
        connection_id: fixed(connection),
        session_id: fixed(session),
        ttl_seconds: 60,
        max_response_bytes: 16384,
        max_output_bytes: 65536,
        governor: wire::Governor {
            max_bytes: 65536,
            max_recovery_bytes: 65536,
            max_recovery_jobs: 2,
            max_snapshot_bytes: 65536,
        },
        response: wire::BoshRequest {
            rid,
            fingerprint: wire::sha256(raw.as_bytes()),
            request_xml: text(&raw),
            content_type: text("text/xml; charset=utf-8"),
            responders: list(vec![wire::Responder::Open]),
        },
        bind: wire::BoshReply {
            commit: wire::CommitCut::Complete,
            membership: wire::Membership {
                c2s_message_ids: list(vec![]),
                mix_delivery_ids: list(vec![]),
            },
        },
    }
}
fn scaffold() -> wire::ValidatedCase {
    let case = wire::Case {
        schema: text(wire::CASE_SCHEMA),
        case_id: text("ordinary-auth-owner-control"),
        adapter_contract: text(wire::ADAPTER_CONTRACT),
        composition: wire::Composition::BoshAuth(wire::BoshAuthInput {
            mix: wire::Nullable::Null(()),
            auth: wire::BoshAuthLane {
                bound: bound(
                    wire::TransportKind::Bosh,
                    wire::PublicationReply::BackendError(wire::Empty {}),
                ),
                session: session(2, 3, 22),
                drive: wire::AuthDrive::Complete,
            },
        }),
    };
    wire::decode(&serde_json::to_vec(&case).unwrap()).unwrap()
}
pub(crate) fn recorder() -> Capture {
    Arc::new(Mutex::new(wire::Recorder::new(&scaffold())))
}
/// Drain an ordinary observer for assertions only. No fd0/frame encoding.
pub(crate) fn drain(recorder: &Capture) -> wire::Envelope {
    let previous = {
        let mut guard = recorder.lock().unwrap_or_else(|p| p.into_inner());
        std::mem::replace(&mut *guard, wire::Recorder::new(&scaffold()))
    };
    previous.finish(wire::Execution::Complete).unwrap()
}
fn committed(epoch: Option<i64>) -> wire::PublicationReply {
    wire::PublicationReply::Committed(wire::EpochReply {
        epoch: facts::nullable(epoch),
    })
}

#[tokio::test]
async fn actual_binding_receipt_control_native_flush_and_same_route_publication_join() {
    let recorder = recorder();
    let input = bound(wire::TransportKind::Tcp, committed(None));
    let routes = RouteMap::new(recorder.clone());
    let (route, _receiver) = routes.install_auth(&input, 1).unwrap();
    assert!(!route.snapshot().unwrap().unwrap().routable);
    let (item, read, mut publisher) = build(
        &input,
        Some(route.clone()),
        recorder.clone(),
        credential_site(0),
    )
    .await
    .unwrap()
    .unwrap()
    .split();
    let c = read.credential.snapshot();
    let joins = read.credential.joins();
    assert!(
        c.service_started
            && c.repository_started
            && c.receipt_constructed
            && c.return_matches
            && c.transferred
    );
    assert_eq!(c.commit, actual::CredentialCall::Ok);
    assert_eq!(joins.constructed_receipt, joins.returned_receipt);
    assert_eq!(joins.returned_receipt, joins.transferred_receipt);
    let introduced = read.joins.snapshot().introduced.unwrap();
    assert_eq!(introduced.receipt, joins.returned_receipt.unwrap());
    let owner = crate::xmpp::stage4_native::write_auth(
        item,
        route.connection_id(),
        native_site(0),
        write_ok(),
        recorder.clone(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(read.live_snapshot().transport, actual::Transport::Written);
    assert!(!route.snapshot().unwrap().unwrap().routable);
    let result = publish_native(
        owner,
        &read,
        &mut publisher,
        wire::AuthDrive::Complete,
        &recorder,
        publication_site(0),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(result.returned, Some(true));
    assert!(!result.dropped);
    assert_eq!(
        read.live_snapshot().terminal,
        Some(actual::Terminal::Completed)
    );
    assert!(route.snapshot().unwrap().unwrap().routable);
    let transferred = read.joins.snapshot().transferred.unwrap();
    assert_eq!(introduced.receipt, transferred.receipt);
    assert_eq!(
        read.publication.joins().begun_receipt,
        Some(transferred.receipt)
    );
}
#[tokio::test]
async fn actual_staged_hint_is_independent_of_returned_publication_epoch() {
    let recorder = recorder();
    let mut input = bound(wire::TransportKind::Tcp, committed(Some(19)));
    input.device_id = wire::Nullable::Value(fixed(6));
    input.preparation.stage_present = true;
    input.preparation.stage_epoch = wire::Nullable::Value(7);
    let routes = RouteMap::new(recorder.clone());
    let (route, _receiver) = routes.install_auth(&input, 1).unwrap();
    let (item, read, mut publisher) = build(
        &input,
        Some(route.clone()),
        recorder.clone(),
        credential_site(0),
    )
    .await
    .unwrap()
    .unwrap()
    .split();
    assert!(read.credential.snapshot().stage_id.is_some());
    let owner = crate::xmpp::stage4_native::write_auth(
        item,
        route.connection_id(),
        native_site(0),
        write_ok(),
        recorder.clone(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(owner.receipt().staged_login_epoch().unwrap().epoch, 7);
    assert_eq!(
        publish_native(
            owner,
            &read,
            &mut publisher,
            wire::AuthDrive::Complete,
            &recorder,
            publication_site(0)
        )
        .await
        .unwrap()
        .unwrap()
        .returned,
        Some(true)
    );
    assert_eq!(
        route.snapshot().unwrap().unwrap().user_agent_epoch.get(),
        Some(&19)
    );
    assert_eq!(
        read.live_snapshot().publication,
        actual::Knowledge::ReceiptKnown(Some(19))
    );
}
#[tokio::test]
async fn actual_native_backend_error_keeps_written_control_and_known_credential() {
    let recorder = recorder();
    let input = bound(
        wire::TransportKind::Tcp,
        wire::PublicationReply::BackendError(wire::Empty {}),
    );
    let routes = RouteMap::new(recorder.clone());
    let (route, _receiver) = routes.install_auth(&input, 1).unwrap();
    let (item, read, mut publisher) = build(
        &input,
        Some(route.clone()),
        recorder.clone(),
        credential_site(0),
    )
    .await
    .unwrap()
    .unwrap()
    .split();
    let receipt = read.credential.joins().returned_receipt;
    let owner = crate::xmpp::stage4_native::write_auth(
        item,
        route.connection_id(),
        native_site(0),
        write_ok(),
        recorder.clone(),
    )
    .await
    .unwrap()
    .unwrap();
    let result = publish_native(
        owner,
        &read,
        &mut publisher,
        wire::AuthDrive::Complete,
        &recorder,
        publication_site(0),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(result.returned, Some(false));
    let s = read.live_snapshot();
    assert_eq!(s.transport, actual::Transport::Written);
    assert_eq!(s.returned, Some(actual::Returned::BackendFailure));
    assert_eq!(s.terminal, Some(actual::Terminal::Failed));
    assert_eq!(read.credential.joins().returned_receipt, receipt);
    assert!(!route.snapshot().unwrap().unwrap().routable);
}
#[tokio::test]
async fn pending_native_commit_is_observed_before_child_drop_and_cancelled_retirement() {
    let recorder = recorder();
    let input = bound(
        wire::TransportKind::Tcp,
        wire::PublicationReply::CommitPending(wire::EpochReply {
            epoch: wire::Nullable::Null(()),
        }),
    );
    let routes = RouteMap::new(recorder.clone());
    let (route, _receiver) = routes.install_auth(&input, 1).unwrap();
    let (item, read, mut publisher) = build(
        &input,
        Some(route.clone()),
        recorder.clone(),
        credential_site(0),
    )
    .await
    .unwrap()
    .unwrap()
    .split();
    let owner = crate::xmpp::stage4_native::write_auth(
        item,
        route.connection_id(),
        native_site(0),
        write_ok(),
        recorder.clone(),
    )
    .await
    .unwrap()
    .unwrap();
    let result = publish_native(
        owner,
        &read,
        &mut publisher,
        wire::AuthDrive::DropPublicationCommit,
        &recorder,
        publication_site(0),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(result.dropped);
    assert_eq!(result.returned, None);
    assert_eq!(
        read.live_snapshot().publication,
        actual::Knowledge::CommitCallEntered
    );
    assert_eq!(
        read.live_snapshot().terminal,
        Some(actual::Terminal::Cancelled)
    );
    let envelope = drain(&recorder);
    let facts = envelope.facts.as_slice();
    let live = |cut, terminal| {
        facts.iter().position(|f| matches!(&f.fact, wire::Fact::Control(wire::ControlFact::LivePublication(p)) if p.cut == cut && p.snapshot.terminal.get().copied() == terminal)).unwrap()
    };
    assert!(live(wire::Cut::AfterPoll, None) < live(wire::Cut::ChildDrop, None));
    assert!(
        live(wire::Cut::ChildDrop, None)
            < live(
                wire::Cut::AfterRunnerDrop,
                Some(wire::PublicationTerminal::Cancelled)
            )
    );
    assert!(matches!(
        envelope.observation_status,
        wire::ObservationStatus::Complete(_)
    ));
}
#[tokio::test]
async fn actual_unbound_owner_completes_nosql_without_repository_publication() {
    let recorder = recorder();
    let mut input = unbound();
    input.frame.transport = wire::TransportKind::Tcp;
    let (item, read, mut publisher) = build(&input, None, recorder.clone(), credential_site(0))
        .await
        .unwrap()
        .unwrap()
        .split();
    let owner = crate::xmpp::stage4_native::write_auth(
        item,
        input.frame.connection_id.0,
        native_site(0),
        write_ok(),
        recorder.clone(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        publish_native(
            owner,
            &read,
            &mut publisher,
            wire::AuthDrive::Complete,
            &recorder,
            publication_site(0)
        )
        .await
        .unwrap()
        .unwrap()
        .returned,
        Some(true)
    );
    let s = read.live_snapshot();
    assert_eq!(s.publication, actual::Knowledge::NotRequired);
    assert!(!s.repository_started);
    assert!(s.effects.unbound);
    assert_eq!(s.terminal, Some(actual::Terminal::Completed));
}
#[tokio::test]
async fn actual_partial_write_and_flush_failure_do_not_transfer_or_begin_auth() {
    for flush_failure in [false, true] {
        let recorder = recorder();
        let input = bound(wire::TransportKind::Tcp, committed(None));
        let routes = RouteMap::new(recorder.clone());
        let (route, _receiver) = routes.install_auth(&input, 1).unwrap();
        let (item, read, _publisher) = build(
            &input,
            Some(route.clone()),
            recorder.clone(),
            credential_site(0),
        )
        .await
        .unwrap()
        .unwrap()
        .split();
        let script = wire::WriteScript {
            chunk_limit: 4096,
            fail_after_accepted_bytes: if flush_failure {
                wire::Nullable::Null(())
            } else {
                wire::Nullable::Value(3)
            },
            flush: if flush_failure {
                wire::FlushReply::Error
            } else {
                wire::FlushReply::Ok
            },
        };
        assert!(crate::xmpp::stage4_native::write_auth(
            item,
            route.connection_id(),
            native_site(0),
            script,
            recorder
        )
        .await
        .unwrap()
        .is_err());
        assert_eq!(
            read.live_snapshot().transport,
            actual::Transport::WriteEntered
        );
        assert_eq!(
            read.live_snapshot().publication,
            actual::Knowledge::NotStarted
        );
        assert!(read.joins.snapshot().transferred.is_none());
        assert!(!route.snapshot().unwrap().unwrap().routable);
    }
}
#[tokio::test]
async fn mismatched_route_and_changed_control_literal_fail_before_sealed_authority() {
    let recorder = recorder();
    let input = bound(wire::TransportKind::Tcp, committed(None));
    let routes = RouteMap::new(recorder.clone());
    let (route, _receiver) = routes.install_auth(&input, 1).unwrap();
    let mut wrong = input.clone();
    wrong.auth_generation += 1;
    assert!(build(
        &wrong,
        Some(route.clone()),
        recorder.clone(),
        credential_site(0)
    )
    .await
    .unwrap()
    .is_err());
    let wire::ControlInput::Binding(control) = &mut wrong.control else {
        unreachable!()
    };
    control.xml = text("<iq/>");
    wrong.auth_generation = input.auth_generation;
    assert!(
        build(&wrong, Some(route.clone()), recorder, credential_site(0))
            .await
            .unwrap()
            .is_err()
    );
    assert!(!route.snapshot().unwrap().unwrap().routable);
}
#[tokio::test]
async fn disconnected_exact_route_rejects_activation_after_actual_publication_receipt() {
    let recorder = recorder();
    let input = bound(wire::TransportKind::Tcp, committed(None));
    let routes = RouteMap::new(recorder.clone());
    let (route, _receiver) = routes.install_auth(&input, 1).unwrap();
    let (item, read, mut publisher) = build(
        &input,
        Some(route.clone()),
        recorder.clone(),
        credential_site(0),
    )
    .await
    .unwrap()
    .unwrap()
    .split();
    let owner = crate::xmpp::stage4_native::write_auth(
        item,
        route.connection_id(),
        native_site(0),
        write_ok(),
        recorder.clone(),
    )
    .await
    .unwrap()
    .unwrap();
    route.disconnect().cancel();
    assert_eq!(
        publish_native(
            owner,
            &read,
            &mut publisher,
            wire::AuthDrive::Complete,
            &recorder,
            publication_site(0)
        )
        .await
        .unwrap()
        .unwrap()
        .returned,
        Some(false)
    );
    assert_eq!(
        read.live_snapshot().publication,
        actual::Knowledge::ReceiptKnown(None)
    );
    assert!(!route.snapshot().unwrap().unwrap().routable);
}
#[tokio::test]
async fn unsupported_notification_never_becomes_a_successful_noop_effect() {
    let recorder = recorder();
    let mut input = bound(wire::TransportKind::Tcp, committed(Some(19)));
    input.notification_expected = true;
    assert!(build(&input, None, recorder.clone(), credential_site(0))
        .await
        .unwrap()
        .is_err());
    assert!(matches!(
        drain(&recorder).observation_status,
        wire::ObservationStatus::Lost(_)
    ));
}

#[tokio::test]
async fn prior_semantic_loss_preserves_credential_native_and_publication_results() {
    let recorder = recorder();
    facts::lost(&recorder);
    let input = bound(wire::TransportKind::Tcp, committed(None));
    let routes = RouteMap::new(recorder.clone());
    let (route, _receiver) = routes.install_auth(&input, 1).unwrap();
    let (item, read, mut publisher) = build(
        &input,
        Some(route.clone()),
        recorder.clone(),
        credential_site(0),
    )
    .await
    .unwrap()
    .unwrap()
    .split();
    assert!(read.credential.snapshot().return_matches && read.credential.snapshot().transferred);
    let owner = crate::xmpp::stage4_native::write_auth(
        item,
        route.connection_id(),
        native_site(0),
        write_ok(),
        recorder.clone(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(read.live_snapshot().transport, actual::Transport::Written);
    let actual = publish_native(
        owner,
        &read,
        &mut publisher,
        wire::AuthDrive::Complete,
        &recorder,
        publication_site(0),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(actual.returned, Some(true));
    assert_eq!(
        read.live_snapshot().terminal,
        Some(actual::Terminal::Completed)
    );
    assert!(route.snapshot().unwrap().unwrap().routable);
    assert!(matches!(
        drain(&recorder).observation_status,
        wire::ObservationStatus::Lost(wire::LostObservation {
            reason: wire::Loss::MissingObservation,
            ..
        })
    ));
}
#[tokio::test]
async fn missing_native_introduction_projection_does_not_prevent_actual_write() {
    let recorder = recorder();
    let input = bound(wire::TransportKind::Tcp, committed(None));
    let routes = RouteMap::new(recorder.clone());
    let (route, _receiver) = routes.install_auth(&input, 1).unwrap();
    let (item, read, mut publisher) = build(
        &input,
        Some(route.clone()),
        recorder.clone(),
        credential_site(0),
    )
    .await
    .unwrap()
    .unwrap()
    .split();
    // Only the cfg(test) read cell is damaged, never holder/receipt authority.
    read.joins.0.lock().unwrap().introduced = None;
    let owner = crate::xmpp::stage4_native::write_auth(
        item,
        route.connection_id(),
        native_site(0),
        write_ok(),
        recorder.clone(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(read.live_snapshot().transport, actual::Transport::Written);
    assert_eq!(
        publish_native(
            owner,
            &read,
            &mut publisher,
            wire::AuthDrive::Complete,
            &recorder,
            publication_site(0)
        )
        .await
        .unwrap()
        .unwrap()
        .returned,
        Some(true)
    );
    assert_eq!(
        read.live_snapshot().terminal,
        Some(actual::Terminal::Completed)
    );
    assert!(matches!(
        drain(&recorder).observation_status,
        wire::ObservationStatus::Lost(_)
    ));
}
#[tokio::test]
async fn missing_callback_transfer_projection_does_not_replace_publication_with_false() {
    let recorder = recorder();
    let input = bound(wire::TransportKind::Tcp, committed(None));
    let routes = RouteMap::new(recorder.clone());
    let (route, _receiver) = routes.install_auth(&input, 1).unwrap();
    let (item, read, mut publisher) = build(
        &input,
        Some(route.clone()),
        recorder.clone(),
        credential_site(0),
    )
    .await
    .unwrap()
    .unwrap()
    .split();
    let owner = crate::xmpp::stage4_native::write_auth(
        item,
        route.connection_id(),
        native_site(0),
        write_ok(),
        recorder.clone(),
    )
    .await
    .unwrap()
    .unwrap();
    read.joins.0.lock().unwrap().transferred = None;
    assert_eq!(
        publish_native(
            owner,
            &read,
            &mut publisher,
            wire::AuthDrive::Complete,
            &recorder,
            publication_site(0)
        )
        .await
        .unwrap()
        .unwrap()
        .returned,
        Some(true)
    );
    assert!(route.snapshot().unwrap().unwrap().routable);
    assert_eq!(
        read.live_snapshot().terminal,
        Some(actual::Terminal::Completed)
    );
    assert!(matches!(
        drain(&recorder).observation_status,
        wire::ObservationStatus::Lost(_)
    ));
}
#[tokio::test]
async fn oversized_queue_fact_does_not_turn_a_bounded_native_write_into_io_failure() {
    let recorder = recorder();
    let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
    // Ordinary native owner component only: no saved literal qualification.
    // 16385 actual bytes fit five 4096-byte writes, but exceed QueueItem Text.
    let item = OutboundItem::with_transport_write_receipt("x".repeat(16385), sender);
    crate::xmpp::stage4_native::write_item(
        item,
        Uuid::from_u128(2),
        native_site(0),
        wire::ItemOwner::Muc(wire::MucItemOwner {
            frame: facts::id(Uuid::from_u128(1)),
            recipient_ordinal: 0,
        }),
        write_ok(),
        None,
        recorder.clone(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(receiver.try_recv().is_ok());
    assert!(matches!(
        drain(&recorder).observation_status,
        wire::ObservationStatus::Lost(_)
    ));
}
