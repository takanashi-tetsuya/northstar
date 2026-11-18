use super::*;
use std::sync::Mutex;
use uuid::Uuid;

mod host;
mod repository;

use host::TestHost;

#[tokio::test]
async fn protocol_sm_entries_retain_distinct_turns_and_actual_returned_outcomes() {
    use northstar_delivery_core::sm_ownership::{Purpose, Terminal};
    let host = TestHost::new();
    let mut session = host.session();
    let item = crate::outbound::OutboundItem::plain("<message/>".to_owned());
    assert!(!session.record_outbound_item(&item).await.unwrap());
    let record = session.sm.current_operation.as_ref().unwrap().clone();
    assert_eq!(record.snapshot().scope.purpose, Purpose::Record);
    assert_eq!(record.snapshot().scope.connection_id, session.connection_id);
    assert_eq!(record.snapshot().terminal, Some(Terminal::Returned));
    session
        .record_outbound_with_source("<presence/>", None)
        .await
        .unwrap();
    let source = session.sm.current_operation.as_ref().unwrap().clone();
    assert_eq!(source.snapshot().scope.purpose, Purpose::Record);
    session.checkpoint_sm().await.unwrap();
    let checkpoint = session.sm.current_operation.as_ref().unwrap().clone();
    assert_eq!(checkpoint.snapshot().scope.purpose, Purpose::Checkpoint);
    assert!(session.acknowledge(0).await.unwrap());
    let ack = session.sm.current_operation.as_ref().unwrap().clone();
    assert_eq!(ack.snapshot().scope.purpose, Purpose::Acknowledge { h: 0 });
    assert_eq!(ack.snapshot().terminal, Some(Terminal::Returned));
    assert_eq!(record.snapshot().scope.purpose, Purpose::Record);
    assert_eq!(source.snapshot().terminal, Some(Terminal::Returned));
    assert_eq!(checkpoint.snapshot().terminal, Some(Terminal::Returned));
    assert!(host.events.lock().unwrap().is_empty());
}

#[tokio::test]
async fn protocol_auth_adapter_publishes_only_the_captured_principal_and_route() {
    use crate::auth_publication::{
        CapturedEffects, KnownCredentialOwner, RouteIntent, SelectedControls,
    };
    use northstar_auth_application::authentication::{BindingPublication, CredentialCommitReceipt};
    for label in [
        "current",
        "missing principal",
        "user",
        "generation",
        "key",
        "lifecycle",
    ] {
        let host = TestHost::new();
        let mut session = host.session();
        let key = "fixture@example.test/captured";
        let user_id = Uuid::from_u128(303);
        let (route, _receiver) = crate::local_routes::session::test_online_session(
            user_id,
            2,
            session.connection_id,
            "captured",
            4,
        );
        route.routable.store(false, Ordering::Release);
        session.route_lifecycle = Arc::clone(&route.lifecycle);
        session.disconnect = route.disconnect.clone();
        host.routes.insert(key.to_owned(), route);
        session.authenticated = Some(
            northstar_auth_application::authentication::AuthenticatedAccount {
                id: user_id,
                username: "fixture".to_owned(),
                auth_generation: 2,
            },
        );
        session.registered_key = Some(key.to_owned());
        session.full_jid = Some(key.to_owned());
        let original = session
            .frame_executions
            .begin(ClientTransport::Bosh, "<iq/>");
        let owner = KnownCredentialOwner::from_returned(
            CredentialCommitReceipt::new(
                None,
                None,
                Some(BindingPublication {
                    connection_id: session.connection_id,
                    user_id,
                    full_jid: key.to_owned(),
                    lease_seconds: 30,
                }),
            ),
            Some(original.clone()),
            session.connection_id,
        );
        let observation = owner.observation().clone();
        original.retain_auth_receipt(observation.clone()).unwrap();
        session.pending_credential_commit = Some(owner);
        let holder = session
            .seal_auth_control("<iq type='result'/>", false)
            .unwrap();
        let mut selected = SelectedControls::new([("<iq type='result'/>", Some(&holder))]).unwrap();
        selected.begin_exposure(41).unwrap();
        selected.exposure(41, true).unwrap();
        let owner = selected.take_all().unwrap().pop().unwrap();
        original.run(async { Ok(()) }).await.unwrap();
        let later = session
            .frame_executions
            .begin(ClientTransport::Bosh, "<message/>");
        match label {
            "missing principal" => session.authenticated = None,
            "user" => session.authenticated.as_mut().unwrap().id = Uuid::from_u128(999),
            "generation" => session.authenticated.as_mut().unwrap().auth_generation += 1,
            "key" => session.registered_key = Some("fixture@example.test/replacement".to_owned()),
            "lifecycle" => session.route_lifecycle = Arc::new(AtomicU8::new(0)),
            "current" => {}
            _ => unreachable!(),
        }
        session.sm.resume_allowed = true;
        assert_eq!(
            session
                .publish_committed_authentication_and_route(owner)
                .await,
            label == "current",
            "{label}"
        );
        assert_eq!(
            host.events.lock().unwrap().as_slice(),
            ["publication repository"],
            "{label}"
        );
        assert_eq!(
            host.routes
                .get(key)
                .unwrap()
                .routable
                .load(Ordering::Acquire),
            label == "current",
            "{label}"
        );
        assert_eq!(
            session.user_agent_epoch,
            if label == "current" { Some(7) } else { None },
            "{label}"
        );
        assert_eq!(
            observation.snapshot().frame,
            Some(original.operation_id()),
            "{label}"
        );
        assert_ne!(
            observation.snapshot().frame,
            Some(later.operation_id()),
            "{label}"
        );
        assert_eq!(session.sm.resume_allowed, label == "current", "{label}");
        assert_eq!(
            session
                .frame_executions
                .auth_origin()
                .unwrap()
                .operation_id(),
            later.operation_id(),
            "{label}: publication changed the later frame"
        );

        // Compatibility explicitly has no origin even while another frame is current.
        if label == "current" {
            let owner = KnownCredentialOwner::from_returned(
                CredentialCommitReceipt::new(None, None, None),
                None,
                session.connection_id,
            );
            let holder = owner
                .seal(
                    "<success/>",
                    CapturedEffects {
                        route: RouteIntent::Unbound,
                        caps: None,
                        notification: None,
                    },
                )
                .unwrap();
            holder.recording().unwrap();
            let owner = holder
                .write("<success/>".to_owned(), |_| async { Ok(()) })
                .await
                .unwrap();
            assert!(
                session
                    .publish_committed_authentication_and_route(owner)
                    .await
            );
            assert_eq!(
                host.events.lock().unwrap().as_slice(),
                ["publication repository"]
            );
            assert_eq!(
                session
                    .frame_executions
                    .auth_origin()
                    .unwrap()
                    .operation_id(),
                later.operation_id()
            );
        }
    }
}

#[tokio::test]
async fn authentication_entries_create_and_drop_owned_timers_before_early_returns() {
    let host = TestHost::new();
    let mut session = host.session();
    session.secure_transport = false;
    let document = roxmltree::Document::parse("<authenticate xmlns='urn:xmpp:sasl:2'/>").unwrap();
    session
        .authenticate2(document.root_element())
        .await
        .unwrap();
    assert_eq!(Arc::strong_count(&host.timer), 1);
    let document = roxmltree::Document::parse("<response xmlns='urn:xmpp:sasl:2'/>").unwrap();
    session
        .sasl2_response(document.root_element())
        .await
        .unwrap();
    assert_eq!(Arc::strong_count(&host.timer), 1);
    let document = roxmltree::Document::parse("<abort xmlns='urn:xmpp:sasl:2'/>").unwrap();
    let _ = session.sasl2_abort(document.root_element());
    assert_eq!(Arc::strong_count(&host.timer), 1);
    assert_eq!(
        host.events.lock().unwrap().as_slice(),
        [
            "authentication timer",
            "authentication timer",
            "authentication timer"
        ]
    );
}

struct CleanupChildDrop(Arc<Mutex<Vec<&'static str>>>);
impl Drop for CleanupChildDrop {
    fn drop(&mut self) {
        self.0.lock().unwrap().push("child drop");
    }
}

#[tokio::test]
async fn protocol_finalization_quiesces_before_dropping_children_and_finishing() {
    let host = TestHost::new();
    let mut session = host.session();
    let marker = CleanupChildDrop(Arc::clone(&host.events));
    session
        .defer_after_transport("owner-test", async move {
            let _marker = marker;
            std::future::pending::<()>().await;
        })
        .unwrap();
    session.finalize().await;
    assert_eq!(session.route_lifecycle.load(Ordering::Acquire), 1);
    assert!(session.local_quiesced);
    assert_eq!(
        host.events.lock().unwrap().as_slice(),
        ["quiesce", "child drop", "finish"]
    );
    session.finalize().await;
    assert_eq!(
        host.events.lock().unwrap().as_slice(),
        ["quiesce", "child drop", "finish"]
    );
}

#[tokio::test]
async fn bind_and_resume_finalizers_receive_original_identity_and_preserve_replacements() {
    for label in ["binding", "resume"] {
        let host = TestHost::new();
        let mut session = host.session();
        let user = northstar_auth_application::authentication::AuthenticatedAccount {
            id: Uuid::from_u128(303),
            username: "fixture".to_owned(),
            auth_generation: 2,
        };
        session.authenticated = Some(user.clone());
        let frame = session
            .frame_executions
            .begin(ClientTransport::Bosh, "<iq/>");
        if label == "binding" {
            assert!(matches!(
                session
                    .bind_resource_internal(&user, "captured".to_owned())
                    .await
                    .unwrap(),
                Err(misc::ResourceBindingFailure::CredentialsExpired)
            ));
            assert_eq!(
                host.events.lock().unwrap().as_slice(),
                ["bind reserved", "bind finalized", "bind released"]
            );
        } else {
            let action = session
                .resume_values("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", 3)
                .await
                .unwrap();
            let Action::Send(xml) = action else {
                panic!("resume failure must return a control")
            };
            assert!(xml.contains("item-not-found"));
            assert_eq!(
                host.events.lock().unwrap().as_slice(),
                ["resume claimed", "resume finalized", "resume released"]
            );
        }
        let replacement = host.routes.get("fixture@example.test/captured").unwrap();
        assert_eq!(replacement.connection_id, Uuid::from_u128(999), "{label}");
        assert_eq!(replacement.auth_generation, 3, "{label}");
        assert_eq!(replacement.lifecycle.load(Ordering::Acquire), 0, "{label}");
        assert!(!replacement.disconnect.is_cancelled(), "{label}");
        assert!(session.pending_credential_commit.is_none(), "{label}");
        frame.run(async { Ok(()) }).await.unwrap();
    }
}

#[tokio::test]
async fn frame_ingress_dispatches_original_client_bytes_separately_from_authoritative_rewrites() {
    let host = TestHost::new();
    let mut session = host.session();
    session.authenticated = Some(
        northstar_auth_application::authentication::AuthenticatedAccount {
            id: Uuid::from_u128(303),
            username: "fixture".to_owned(),
            auth_generation: 2,
        },
    );
    session.full_jid = Some("fixture@example.test/captured".to_owned());
    session.negotiation.open(None, Some("ja".to_owned()));
    let client = "<message from='mallory@example.test/Other' to='bob@example.test'><body>exact client commitment</body></message>";
    assert!(matches!(
        session.process_frame(client).await.unwrap(),
        Action::None
    ));
    let original = host.frames.lock().unwrap()[0].clone();
    {
        let messages = host.messages.lock().unwrap();
        assert_eq!(messages.len(), 1);
        let (routed, received_client, operation) = &messages[0];
        assert_eq!(received_client, client);
        assert_eq!(*operation, original.operation_id());
        let document = roxmltree::Document::parse(routed).unwrap();
        let root = document.root_element();
        assert_eq!(
            root.attribute("from"),
            Some("fixture@example.test/captured")
        );
        assert_eq!(
            root.attribute(("http://www.w3.org/XML/1998/namespace", "lang")),
            Some("ja")
        );
        assert_ne!(routed, received_client);
    }
    assert!(session.frame_executions.auth_origin().is_none());
    assert!(matches!(
        session.process_frame("<broken").await.unwrap(),
        Action::CloseWith(_)
    ));
    assert_eq!(
        host.frames.lock().unwrap()[0].operation_id(),
        original.operation_id()
    );
    assert_eq!(host.messages.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn password_change_and_removal_forward_proofless_body_commitments_and_original_generation() {
    let host = TestHost::new();
    let mut session = host.session();
    session.authenticated = Some(
        northstar_auth_application::authentication::AuthenticatedAccount {
            id: Uuid::from_u128(303),
            username: "fixture".to_owned(),
            auth_generation: 2,
        },
    );
    for (label, payload, condition) in [
        (
            "password",
            "<password>correct-horse-battery</password>",
            "resource-constraint",
        ),
        ("removal", "<remove/>", "registration-required"),
    ] {
        let xml = format!("<query xmlns='jabber:iq:register'>{payload}<pow xmlns='urn:northstar:pow:1' challenge='00000000-0000-0000-0000-000000000055' nonce='42'/></query>");
        let document = roxmltree::Document::parse(&xml).unwrap();
        let action = session
            .change_password("account-change", document.root_element())
            .await
            .unwrap();
        let Action::Send(xml) = action else {
            panic!("{label}: expected refusal IQ")
        };
        assert!(xml.contains(condition), "{label}");
    }
    assert_eq!(
        host.events.lock().unwrap().as_slice(),
        ["password guarded", "deletion guarded"]
    );
}

#[derive(Clone, Default)]
struct ResumeErrorCapture(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for ResumeErrorCapture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl ResumeErrorCapture {
    fn install() -> (Self, tracing::subscriber::DefaultGuard) {
        // Match the frame trace fixture: a second registered subscriber keeps
        // callsite interest from depending on which test thread visits first.
        static GLOBAL_NO_OP: std::sync::Once = std::sync::Once::new();
        GLOBAL_NO_OP.call_once(|| {
            let _ = tracing::subscriber::set_global_default(
                tracing::subscriber::NoSubscriber::default(),
            );
        });
        let capture = Self::default();
        let writer = capture.clone();
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .json()
            .with_ansi(false)
            .with_max_level(tracing::Level::ERROR)
            .with_writer(move || writer.clone())
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);
        (capture, guard)
    }

    fn events(&self) -> Vec<serde_json::Value> {
        let bytes = self.0.lock().unwrap();
        std::str::from_utf8(&bytes)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
}

#[tokio::test]
async fn inline_resume_error_falls_back_to_a_distinct_unbound_attempt_on_the_original_frame() {
    use crate::auth_publication::SelectedControls;
    use crate::wire::sasl2::{parse_authenticate, Sasl2Context};
    use northstar_session_core::publication::{CredentialKind, HandlerReturn, Terminal};
    let (errors, _subscriber) = ResumeErrorCapture::install();
    let mut host = TestHost::new();
    Arc::get_mut(&mut host).unwrap().resume_error = true;
    let mut session = host.session();
    let frame = crate::frame_execution::FrameExecution::for_saved_case(
        ClientTransport::Bosh,
        "<authenticate/>",
        Uuid::from_u128(850),
    );
    session.frame_executions =
        crate::frame_execution::SessionExecutions::for_saved_frame(frame.clone());
    let document = roxmltree::Document::parse(
        "<authenticate xmlns='urn:xmpp:sasl:2' mechanism='PLAIN'><resume xmlns='urn:xmpp:sm:3' previd='AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8' h='3'/></authenticate>",
    ).unwrap();
    session.sasl2_state = Some(Sasl2Context {
        request: parse_authenticate(document.root_element()).unwrap(),
        fast_should_rotate: false,
        awaiting_initial_response: false,
        fast_token_id: None,
        fast_token_was_new: false,
        fast_invalidate: false,
        authenticated_generation: Some(2),
        inherited_fast_chain: None,
    });
    let user = northstar_auth_application::authentication::AuthenticatedAccount {
        id: Uuid::from_u128(303),
        username: "fixture".to_owned(),
        auth_generation: 2,
    };
    let action = session.complete_sasl2(user, None, false).await.unwrap();
    let Action::SendManyThenActivate(replies) = action else {
        panic!("unknown inline resume must still seal the fallback success")
    };
    let (bytes, holder) = replies.into_parts();
    assert!(bytes[0].contains("success"));
    // The SM wire builder normalizes the unrecognized internal-server-error
    // condition to undefined-condition. The error event distinguishes the
    // Unknown arm from Ok(_), which produces the same wire condition.
    let unknown_errors = errors
        .events()
        .into_iter()
        .filter(|event| event["fields"]["message"] == "inline SM resumption backend failed")
        .collect::<Vec<_>>();
    assert_eq!(unknown_errors.len(), 1, "Unknown arm was not entered");
    assert_eq!(
        unknown_errors[0]["fields"]["error"],
        "unknown resume COMMIT reply"
    );
    let success = roxmltree::Document::parse(&bytes[0]).unwrap();
    let failed = success
        .root_element()
        .children()
        .find(|node| {
            node.is_element()
                && node.tag_name().name() == "failed"
                && node.tag_name().namespace() == Some("urn:xmpp:sm:3")
        })
        .expect("inline resume failure");
    let condition = failed.first_element_child().unwrap();
    assert_eq!(condition.tag_name().name(), "undefined-condition");
    assert_eq!(
        condition.tag_name().namespace(),
        Some("urn:ietf:params:xml:ns:xmpp-stanzas")
    );
    holder.validate_control(&bytes[0]).unwrap();
    assert!(holder.validate_control("<resumed/>").is_err());
    let observation = SelectedControls::new([(bytes[0].as_str(), Some(&holder))])
        .unwrap()
        .observations()
        .pop()
        .unwrap();
    let credential = observation.credential().unwrap();
    let snapshot = credential.snapshot();
    assert_eq!(snapshot.kind, CredentialKind::UnboundFast);
    assert_eq!(snapshot.ordinal, 1);
    assert_eq!(snapshot.frame, Uuid::from_u128(850));
    assert!(snapshot.transferred);
    frame.run(async { Ok(()) }).await.unwrap();
    assert_eq!(
        credential.snapshot().handler,
        Some(HandlerReturn::Completed)
    );
    let later = session
        .frame_executions
        .begin(ClientTransport::Bosh, "<iq/>");
    let mut selection = SelectedControls::new([(bytes[0].as_str(), Some(&holder))]).unwrap();
    selection.begin_exposure(51).unwrap();
    selection.exposure(51, true).unwrap();
    let owner = selection.take_all().unwrap().pop().unwrap();
    assert!(
        session
            .publish_committed_authentication_and_route(owner)
            .await
    );
    assert_eq!(observation.snapshot().terminal, Some(Terminal::Completed));
    assert_eq!(observation.snapshot().frame, Some(frame.operation_id()));
    assert_ne!(observation.snapshot().frame, Some(later.operation_id()));
    assert_eq!(
        host.events.lock().unwrap().as_slice(),
        [
            "resume claimed",
            "resume finalized",
            "resume error returned",
            "resume released",
            "unbound committed"
        ]
    );
}

#[tokio::test]
async fn captured_caps_waits_on_original_gate_and_revalidates_original_connection() {
    use crate::auth_publication::{KnownCredentialOwner, PublicationPort as _, SelectedControls};
    use northstar_auth_application::authentication::{BindingPublication, CredentialCommitReceipt};
    use northstar_protocol_runtime::caps::CapsObservationOwner;
    use northstar_session_core::LocalCapsEpoch;
    let key = "fixture@example.test/captured";
    for label in ["current", "replaced connection", "replaced gate"] {
        let host = TestHost::new();
        let mut session = host.session();
        let (route, _receiver) = crate::local_routes::session::test_online_session(
            Uuid::from_u128(303),
            2,
            session.connection_id,
            "captured",
            4,
        );
        let gate = Arc::clone(&route.mix_presence_gate);
        let generation = Arc::clone(&route.caps_observation_generation);
        generation.store(11, Ordering::Release);
        session.route_lifecycle = Arc::clone(&route.lifecycle);
        session.presence.mix_presence_gate = Arc::clone(&gate);
        session.presence.caps_observation_generation = Arc::clone(&generation);
        session.presence.resumed_caps_presence = Some("<presence/>".to_owned());
        session.user_agent_id = Some(Uuid::from_u128(304));
        host.routes.insert(key.to_owned(), route);
        session.authenticated = Some(
            northstar_auth_application::authentication::AuthenticatedAccount {
                id: Uuid::from_u128(303),
                username: "fixture".to_owned(),
                auth_generation: 2,
            },
        );
        session.registered_key = Some(key.to_owned());
        session.pending_credential_commit = Some(KnownCredentialOwner::from_returned(
            CredentialCommitReceipt::new(
                None,
                Some(
                    northstar_auth_application::authentication::StagedLoginEpoch {
                        operation_id: Uuid::from_u128(301),
                        connection_id: session.connection_id,
                        user_id: Uuid::from_u128(303),
                        device_id: Uuid::from_u128(304),
                        auth_generation: 2,
                        epoch: 999,
                    },
                ),
                Some(BindingPublication {
                    connection_id: session.connection_id,
                    user_id: Uuid::from_u128(303),
                    full_jid: key.to_owned(),
                    lease_seconds: 30,
                }),
            ),
            None,
            session.connection_id,
        ));
        let holder = session.seal_auth_control("<resumed/>", true).unwrap();
        assert!(session.presence.resumed_caps_presence.is_none(), "{label}");
        let mut selection = SelectedControls::new([("<resumed/>", Some(&holder))]).unwrap();
        selection.begin_exposure(61).unwrap();
        selection.exposure(61, true).unwrap();
        let mut owner = selection.take_all().unwrap().pop().unwrap();
        let notification = owner.captured_effects().notification.as_ref().unwrap();
        assert_eq!(notification.account, "fixture@example.test", "{label}");
        assert_eq!(notification.user, Uuid::from_u128(303), "{label}");
        assert_eq!(notification.device, Uuid::from_u128(304), "{label}");
        assert_eq!(notification.excluded_key, key, "{label}");
        let intent = owner.effects().caps.take().unwrap();
        assert!(Arc::ptr_eq(&intent.gate, &gate), "{label}");
        assert!(Arc::ptr_eq(&intent.generation, &generation), "{label}");
        assert_eq!(intent.presence, "<presence/>", "{label}");
        assert_eq!(intent.key, key, "{label}");
        assert_eq!(intent.connection, Uuid::from_u128(302), "{label}");
        let newer_generation = Arc::new(AtomicU64::new(99));
        session.presence.mix_presence_gate = Arc::new(tokio::sync::Mutex::new(()));
        session.presence.caps_observation_generation = Arc::clone(&newer_generation);
        let held = gate.lock().await;
        let mut port = SessionAuthPublication {
            session: &mut session,
        };
        let mut publishing = Box::pin(port.caps(Some(intent)));
        assert!(
            futures::poll!(&mut publishing).is_pending(),
            "{label}: used a later gate"
        );
        if label == "replaced connection" {
            host.replace_route();
        } else if label == "replaced gate" {
            host.routes.get_mut(key).unwrap().mix_presence_gate =
                Arc::new(tokio::sync::Mutex::new(()));
        }
        drop(held);
        publishing.await;
        assert_eq!(newer_generation.load(Ordering::Acquire), 99, "{label}");
        assert_eq!(
            generation.load(Ordering::Acquire),
            if label == "current" { 12 } else { 11 },
            "{label}"
        );
        assert_eq!(
            host.caps.owner(key),
            if label == "current" {
                Some(CapsObservationOwner::Local(LocalCapsEpoch {
                    connection_id: Uuid::from_u128(302),
                    generation: 12,
                }))
            } else {
                None
            },
            "{label}"
        );
    }
}

#[tokio::test]
async fn standalone_and_inline_resume_seal_only_their_final_transport_envelopes() {
    use crate::wire::sasl2::{parse_authenticate, Sasl2Context};
    for label in ["standalone", "inline"] {
        let mut host = TestHost::new();
        Arc::get_mut(&mut host).unwrap().resume_success = true;
        let mut session = host.session();
        let user = northstar_auth_application::authentication::AuthenticatedAccount {
            id: Uuid::from_u128(303),
            username: "fixture".to_owned(),
            auth_generation: 2,
        };
        let action = if label == "standalone" {
            session.authenticated = Some(user);
            session
                .resume_values("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", 3)
                .await
                .unwrap()
        } else {
            let document = roxmltree::Document::parse(
                "<authenticate xmlns='urn:xmpp:sasl:2' mechanism='PLAIN'><resume xmlns='urn:xmpp:sm:3' previd='AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8' h='3'/></authenticate>",
            ).unwrap();
            session.sasl2_state = Some(Sasl2Context {
                request: parse_authenticate(document.root_element()).unwrap(),
                fast_should_rotate: false,
                awaiting_initial_response: false,
                fast_token_id: None,
                fast_token_was_new: false,
                fast_invalidate: false,
                authenticated_generation: Some(2),
                inherited_fast_chain: None,
            });
            session.complete_sasl2(user, None, false).await.unwrap()
        };
        let Action::Resume(payload) = action else {
            panic!("{label}: expected a replay payload")
        };
        let document = roxmltree::Document::parse(payload.control()).unwrap();
        assert_eq!(
            document.root_element().tag_name().name(),
            if label == "inline" {
                "success"
            } else {
                "resumed"
            },
            "{label}"
        );
        assert!(payload.activate_route, "{label}");
        let holder = payload
            .auth_publication
            .as_ref()
            .expect("terminal resume control owns publication")
            .clone();
        holder.validate_control(payload.control()).unwrap();
        if label == "inline" {
            let old_control = northstar_xep_0198::build_resumed(
                "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
                5,
                None,
            );
            assert!(
                holder.validate_control(&old_control).is_err(),
                "{label}: sealed the old inner control"
            );
        }
        assert!(session.pending_credential_commit.is_none(), "{label}");
        assert!(
            !host
                .routes
                .get("fixture@example.test/captured")
                .unwrap()
                .routable
                .load(Ordering::Acquire),
            "{label}"
        );
        holder.recording().unwrap();
        let control = payload.control().to_owned();
        let owner = holder
            .write(control.clone(), |written| async move {
                assert_eq!(written, control);
                Ok(())
            })
            .await
            .unwrap();
        assert!(
            session
                .publish_committed_authentication_and_route(owner)
                .await,
            "{label}"
        );
        assert!(
            host.routes
                .get("fixture@example.test/captured")
                .unwrap()
                .routable
                .load(Ordering::Acquire),
            "{label}"
        );
    }
}

#[tokio::test]
async fn contradictory_resume_success_closes_without_starting_an_unbound_fallback() {
    use crate::wire::sasl2::{parse_authenticate, Sasl2Context};
    let mut host = TestHost::new();
    Arc::get_mut(&mut host).unwrap().resume_contradiction = true;
    let mut session = host.session();
    let original = crate::frame_execution::FrameExecution::for_saved_case(
        ClientTransport::Bosh,
        "<authenticate/>",
        Uuid::from_u128(851),
    );
    session.frame_executions =
        crate::frame_execution::SessionExecutions::for_saved_frame(original.clone());
    let document = roxmltree::Document::parse(
        "<authenticate xmlns='urn:xmpp:sasl:2' mechanism='PLAIN'><resume xmlns='urn:xmpp:sm:3' previd='AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8' h='3'/></authenticate>",
    ).unwrap();
    session.sasl2_state = Some(Sasl2Context {
        request: parse_authenticate(document.root_element()).unwrap(),
        fast_should_rotate: false,
        awaiting_initial_response: false,
        fast_token_id: None,
        fast_token_was_new: false,
        fast_invalidate: false,
        authenticated_generation: Some(2),
        inherited_fast_chain: None,
    });
    let user = northstar_auth_application::authentication::AuthenticatedAccount {
        id: Uuid::from_u128(303),
        username: "fixture".to_owned(),
        auth_generation: 2,
    };
    assert!(matches!(
        session.complete_sasl2(user, None, false).await.unwrap(),
        Action::Close
    ));
    assert!(session.pending_credential_commit.is_none());
    assert!(!session.sm.resume_allowed);
    assert_eq!(host.events.lock().unwrap().as_slice(), ["resume claimed"]);
    // A fallback would already occupy this fixed-kind slot.
    let fallback = original
        .prepare_credential(
            northstar_session_core::publication::CredentialKind::UnboundFast,
            session.connection_id,
        )
        .unwrap();
    assert!(!fallback.observation().snapshot().service_started);
}

#[tokio::test]
async fn registration_transports_issue_only_body_bound_challenges_after_metered_submissions() {
    for label in ["legacy form", "iterative stream"] {
        let host = TestHost::new();
        let mut session = host.session();
        if label == "iterative stream" {
            let selection = roxmltree::Document::parse(
                "<register xmlns='urn:xmpp:register:0'><flow id='northstar-pow-v2'/></register>",
            )
            .unwrap();
            let Action::Send(initial) = session
                .handle_ibr_register(selection.root_element())
                .await
                .unwrap()
            else {
                panic!("initial registration form")
            };
            assert!(!initial.contains("urn:northstar:pow:challenge-id"));
            assert!(host.events.lock().unwrap().is_empty());
        }
        for proof in [false, true] {
            let form_type = if label == "legacy form" {
                "jabber:iq:register"
            } else {
                "urn:xmpp:register:0"
            };
            let mut fields = format!("<field var='FORM_TYPE' type='hidden'><value>{form_type}</value></field><field var='username'><value>fixture</value></field><field var='password'><value>correct-horse-battery</value></field><field var='urn:northstar:pow:version'><value>2</value></field>");
            if proof {
                fields.push_str("<field var='urn:northstar:pow:challenge-id'><value>00000000-0000-0000-0000-000000000055</value></field><field var='urn:northstar:pow:nonce'><value>42</value></field>");
            }
            let form = format!("<x xmlns='jabber:x:data' type='submit'>{fields}</x>");
            let xml = if label == "legacy form" {
                format!("<query xmlns='jabber:iq:register'>{form}</query>")
            } else {
                format!("<response xmlns='urn:xmpp:register:0'>{form}</response>")
            };
            let document = roxmltree::Document::parse(&xml).unwrap();
            let action = if label == "legacy form" {
                session
                    .register("registration", document.root_element())
                    .await
                    .unwrap()
            } else {
                session
                    .handle_ibr_response(document.root_element())
                    .await
                    .unwrap()
            };
            let Action::Send(challenge) = action else {
                panic!("{label}: metered submission must return a challenge")
            };
            roxmltree::Document::parse(&challenge).unwrap();
            assert!(challenge.contains("urn:northstar:pow:2"), "{label}");
            assert!(
                challenge.contains("00000000-0000-0000-0000-000000000055"),
                "{label}"
            );
            let expected = northstar_abuse_policy::PowIntent::xmpp_registration(
                "fixture",
                "correct-horse-battery",
                None,
            );
            assert!(
                challenge.contains(&expected.body_sha256_base64url()),
                "{label}"
            );
            let expected_calls = if proof { 4 } else { 2 };
            assert_eq!(host.events.lock().unwrap().len(), expected_calls, "{label}");
        }
        assert_eq!(
            host.events.lock().unwrap().as_slice(),
            [
                "registration guard",
                "registration challenge",
                "registration guard",
                "registration challenge"
            ],
            "{label}"
        );
    }
}

#[tokio::test]
async fn replacement_notifications_filter_local_routes_and_forward_captured_remote_identity() {
    use crate::auth_publication::{NotificationIntent, PublicationPort as _};
    let host = TestHost::new();
    let mut session = host.session();
    let user = Uuid::from_u128(303);
    let device = Uuid::from_u128(304);
    let excluded = "fixture@example.test/captured";
    let mut disconnects = Vec::new();
    for (ordinal, label, route_user, route_device, epoch, cancelled) in [
        (1, "older", user, Some(device), Some(6), true),
        (2, "equal", user, Some(device), Some(7), false),
        (3, "newer", user, Some(device), Some(8), false),
        (4, "no epoch", user, Some(device), None, false),
        (
            5,
            "different device",
            user,
            Some(Uuid::from_u128(999)),
            Some(6),
            false,
        ),
        (
            6,
            "different user",
            Uuid::from_u128(998),
            Some(device),
            Some(6),
            false,
        ),
        (7, "captured", user, Some(device), Some(6), false),
    ] {
        let (mut route, _receiver) = crate::local_routes::session::test_online_session(
            route_user,
            2,
            Uuid::from_u128(ordinal),
            label,
            4,
        );
        route.user_agent_id = route_device;
        route.user_agent_epoch = epoch;
        disconnects.push((label, route.disconnect.clone(), cancelled));
        host.routes
            .insert(format!("fixture@example.test/{label}"), route);
    }
    let intent = NotificationIntent {
        account: "fixture@example.test".to_owned(),
        user,
        device,
        excluded_key: excluded.to_owned(),
    };
    let mut port = SessionAuthPublication {
        session: &mut session,
    };
    port.notify_local(&intent, 7);
    for (label, token, cancelled) in disconnects {
        assert_eq!(token.is_cancelled(), cancelled, "{label}");
    }
    port.notify_remote(&intent, 7).await.unwrap();
    assert_eq!(
        host.events.lock().unwrap().as_slice(),
        ["remote notification"]
    );
}

#[tokio::test]
async fn protocol_muc_accessor_preserves_absence_conflict_and_retirement_errors() {
    use northstar_room_application::muc_service::discussion::{fixture, Rejected};
    let host = TestHost::new();
    let mut session = host.session();
    let application = fixture::application(fixture::Cut::Return);
    let prepared = application.prepare_discussion(fixture::command(true, true));
    let conflicting = application.prepare_discussion(fixture::command(true, true));
    assert!(session
        .muc_discussion_operation(&prepared)
        .unwrap()
        .is_none());
    let frame = session
        .frame_executions
        .begin(ClientTransport::Bosh, "<message/>");
    let original = session
        .muc_discussion_operation(&prepared)
        .unwrap()
        .unwrap();
    assert!(matches!(
        session.muc_discussion_operation(&conflicting),
        Err(Rejected::Input)
    ));
    frame.run(async { Ok(()) }).await.unwrap();
    let retired = original.snapshot();
    assert!(matches!(
        session.muc_discussion_operation(&prepared),
        Err(Rejected::Retired)
    ));
    assert_eq!(original.snapshot(), retired);
}

#[tokio::test]
async fn protocol_receipt_handoff_retains_the_attempt_captured_before_a_later_frame() {
    use northstar_auth_application::authentication::{AuthenticationResult, FastCommitPlan};
    use northstar_session_core::publication::CredentialKind;
    let host = TestHost::new();
    let mut session = host.session();
    let original = crate::frame_execution::FrameExecution::for_saved_case(
        ClientTransport::Bosh,
        "<authenticate/>",
        Uuid::from_u128(860),
    );
    session.frame_executions =
        crate::frame_execution::SessionExecutions::for_saved_frame(original.clone());
    let attempt = session
        .prepare_credential_attempt(CredentialKind::UnboundFast)
        .unwrap();
    let plan = FastCommitPlan::default();
    let AuthenticationResult::Authenticated(receipt) = host
        .authentication
        .commit_fast_with_login_epoch_observed(
            Uuid::from_u128(303),
            2,
            &plan,
            None,
            session.connection_id,
            attempt.prepared(),
        )
        .await
    else {
        panic!("credential fixture did not commit")
    };
    let later = session
        .frame_executions
        .begin(ClientTransport::Bosh, "<iq/>");
    session.retain_credential_commit(receipt, attempt).unwrap();
    let owner = session.pending_credential_commit.as_ref().unwrap();
    assert_eq!(
        owner.origin().unwrap().operation_id(),
        original.operation_id()
    );
    assert_eq!(
        owner.observation().snapshot().frame,
        Some(original.operation_id())
    );
    assert_eq!(
        owner.observation().credential().unwrap().snapshot().frame,
        original.operation_id()
    );
    assert_ne!(
        owner.observation().snapshot().frame,
        Some(later.operation_id())
    );
    assert_eq!(
        session
            .frame_executions
            .auth_origin()
            .unwrap()
            .operation_id(),
        later.operation_id()
    );
    assert_eq!(
        host.events.lock().unwrap().as_slice(),
        ["unbound committed"]
    );
}

#[tokio::test(start_paused = true)]
async fn bind2_defers_the_same_busy_replay_until_transport_publication() {
    use crate::wire::sasl2::{parse_authenticate, Sasl2Context};
    let host = TestHost::new();
    let mut session = host.session();
    let document = roxmltree::Document::parse(
        "<authenticate xmlns='urn:xmpp:sasl:2' mechanism='PLAIN'><bind xmlns='urn:xmpp:bind:0'><tag>captured</tag></bind></authenticate>",
    ).unwrap();
    session.sasl2_state = Some(Sasl2Context {
        request: parse_authenticate(document.root_element()).unwrap(),
        fast_should_rotate: false,
        awaiting_initial_response: false,
        fast_token_id: None,
        fast_token_was_new: false,
        fast_invalidate: false,
        authenticated_generation: Some(2),
        inherited_fast_chain: None,
    });
    let user = northstar_auth_application::authentication::AuthenticatedAccount {
        id: Uuid::from_u128(303),
        username: "fixture".to_owned(),
        auth_generation: 2,
    };
    let action = session.complete_sasl2(user, None, false).await.unwrap();
    let Action::SendManyThenActivate(replies) = action else {
        panic!("Bind 2 must return a sealed success")
    };
    assert_eq!(host.repository.replay_calls.load(Ordering::SeqCst), 0);
    let (bytes, holder) = replies.into_parts();
    holder.recording().unwrap();
    let owner = holder
        .write(bytes[0].clone(), |_| async { Ok(()) })
        .await
        .unwrap();
    assert!(
        session
            .publish_committed_authentication_and_route(owner)
            .await
    );
    assert_eq!(host.repository.replay_calls.load(Ordering::SeqCst), 0);
    let completed = host.repository.replay_finished.notified();
    session.start_post_action_tasks();
    tokio::time::timeout(std::time::Duration::from_secs(2), completed)
        .await
        .expect("Bind 2 did not run its deferred busy replay");
    assert_eq!(host.repository.replay_calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        host.events.lock().unwrap().as_slice(),
        [
            "bind reserved",
            "bind finalized",
            "publication repository",
            "replay busy",
            "replay acquired",
            "replay page",
            "replay finish",
        ]
    );
    let key = host.repository.binding.lock().unwrap().clone().unwrap();
    assert_eq!(session.full_jid.as_deref(), Some(key.as_str()));
    assert!(host
        .routes
        .get(&key)
        .unwrap()
        .routable
        .load(Ordering::Acquire));
    session.finalize().await;
}
