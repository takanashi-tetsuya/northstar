use super::{
    bare_message_route, degraded_local_direct_eligible, direct_delivery_mode,
    direct_spool_eligibility, durable_direct_delivery_allowed, message_pow_intent_payload,
    missing_user_message_should_error, mixes_personal_retraction_and_direct_invite,
    offline_storage_eligible, undelivered_disposition, wake_federation_outbox_after_commit,
    BareMessageRoute, DirectDeliveryMode, DirectSpoolEligibility, DurableAdmissionOutcome,
    MessagePostCommit, UndeliveredDisposition,
};
use northstar_abuse_policy::stanza::strip_pow_element;
use northstar_abuse_policy::{AbuseAction, PowIntent};
use northstar_message_core::durable_full_no_match_recovers;
use northstar_message_core::validation::strip_untrusted_direct_delays;
use northstar_message_core::{full_no_match_route, FullNoMatchRoute};
use northstar_xml_builder::rewrite::{set_from, set_root_attribute};
use roxmltree::Document;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

#[tokio::test]
async fn federation_outbox_wake_waits_for_durable_commit() {
    let wakes = Arc::new(AtomicUsize::new(0));
    let wake_count = Arc::clone(&wakes);
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (commit_tx, commit_rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        wake_federation_outbox_after_commit(
            async move {
                started_tx.send(()).unwrap();
                commit_rx.await.unwrap()
            },
            move || {
                wake_count.fetch_add(1, Ordering::SeqCst);
            },
        )
        .await
    });

    started_rx.await.unwrap();
    assert_eq!(wakes.load(Ordering::SeqCst), 0);
    commit_tx
        .send(Ok(DurableAdmissionOutcome::Stored {
            archive_written: true,
            post_commit: MessagePostCommit::WakeFederationOutbox,
        }))
        .unwrap();
    assert!(matches!(
        task.await.unwrap().unwrap(),
        DurableAdmissionOutcome::Stored { .. }
    ));
    assert_eq!(wakes.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn federation_outbox_wake_ignores_failed_and_non_stored_commits() {
    let wakes = AtomicUsize::new(0);
    let outcomes = [
        (Err(anyhow::anyhow!("injected commit failure")), true),
        (Ok(DurableAdmissionOutcome::Replay), false),
        (Ok(DurableAdmissionOutcome::AccountUnavailable), false),
        (
            Ok(DurableAdmissionOutcome::Stored {
                archive_written: false,
                post_commit: MessagePostCommit::RouteLocalDelivery {
                    delivery_id: uuid::Uuid::nil(),
                    recipient_id: uuid::Uuid::nil(),
                },
            }),
            false,
        ),
    ];
    for (outcome, expected_error) in outcomes {
        let result = wake_federation_outbox_after_commit(std::future::ready(outcome), || {
            wakes.fetch_add(1, Ordering::SeqCst);
        })
        .await;
        assert_eq!(result.is_err(), expected_error);
        assert_eq!(wakes.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn signal_only_messages_use_volatile_online_delivery() {
    for xml in [
        "<message type='chat'><received xmlns='urn:xmpp:receipts' id='m1'/></message>",
        "<message type='chat'><composing xmlns='http://jabber.org/protocol/chatstates'/></message>",
    ] {
        let document = Document::parse(xml).unwrap();
        assert_eq!(
            direct_delivery_mode(document.root_element()),
            DirectDeliveryMode::Volatile
        );
    }

    let durable = Document::parse("<message type='chat'><body>hello</body></message>").unwrap();
    assert_eq!(
        direct_delivery_mode(durable.root_element()),
        DirectDeliveryMode::Durable
    );

    let no_store = Document::parse(
        "<message type='chat'><body>private</body><no-store xmlns='urn:xmpp:hints'/></message>",
    )
    .unwrap();
    assert_eq!(
        direct_delivery_mode(no_store.root_element()),
        DirectDeliveryMode::VolatileExplicitNoStore
    );
    assert!(durable_direct_delivery_allowed(
        DirectDeliveryMode::Durable,
        true
    ));
    assert!(!durable_direct_delivery_allowed(
        DirectDeliveryMode::Durable,
        false
    ));
    assert!(!durable_direct_delivery_allowed(
        DirectDeliveryMode::Volatile,
        true
    ));
}

#[test]
fn degraded_direct_spool_accepts_only_bare_storage_eligible_content() {
    let accepted = [
        "<message type='chat'><body>hello</body></message>",
        "<message type='chat'><body>hello</body><composing xmlns='http://jabber.org/protocol/chatstates'/></message>",
        "<message type='normal'><body>hello</body></message>",
        "<message><body>hello</body></message>",
    ];
    for xml in accepted {
        let document = Document::parse(xml).unwrap();
        assert!(degraded_local_direct_eligible(
            document.root_element(),
            true,
            false,
            false,
        ));
    }

    let rejected = [
        "<message type='chat'><body>private</body><no-store xmlns='urn:xmpp:hints'/></message>",
        "<message type='chat'><composing xmlns='http://jabber.org/protocol/chatstates'/></message>",
        "<message type='chat'><composing xmlns='http://jabber.org/protocol/chatstates'/><store xmlns='urn:xmpp:hints'/></message>",
        "<message type='chat'><received xmlns='urn:xmpp:receipts' id='m1'/><store xmlns='urn:xmpp:hints'/></message>",
        "<message type='headline'><body>news</body></message>",
        "<message type='groupchat'><body>hello</body></message>",
        "<message type='chat'><body>join</body><x xmlns='jabber:x:conference' jid='room@conference.example.test'/></message>",
        "<message type='normal'><pubsub xmlns='http://jabber.org/protocol/pubsub' node='push'><affiliation affiliation='none' jid='push.example.test'/></pubsub><store xmlns='urn:xmpp:hints'/></message>",
    ];
    for xml in rejected {
        let document = Document::parse(xml).unwrap();
        assert!(
            !degraded_local_direct_eligible(document.root_element(), true, false, false,),
            "unexpected degraded spool eligibility: {xml}"
        );
    }

    let plain = Document::parse("<message type='chat'><body>hello</body></message>").unwrap();
    assert!(
        !degraded_local_direct_eligible(plain.root_element(), false, false, false,),
        "a full JID has no account-scoped spool fallback"
    );
    assert!(
        !degraded_local_direct_eligible(plain.root_element(), true, true, false,),
        "a retraction is a separate history mutation"
    );
    assert!(
        !degraded_local_direct_eligible(plain.root_element(), true, false, true,),
        "deployment encryption policy still applies"
    );
}

#[test]
fn account_privacy_denial_keeps_a_live_route_out_of_degraded_spool() {
    assert_eq!(
        direct_spool_eligibility(true, true),
        DirectSpoolEligibility::Eligible
    );
    assert_eq!(
        direct_spool_eligibility(true, false),
        DirectSpoolEligibility::LiveOnly
    );
    assert_eq!(
        direct_spool_eligibility(false, true),
        DirectSpoolEligibility::LiveOnly
    );
}

#[test]
fn routed_copy_preserves_private_marker_for_recipient_server() {
    let source = "<message to='bob@example.net' type='chat'><private xmlns='urn:xmpp:carbons:2'/><body>secret</body><pow xmlns='urn:northstar:pow:1' challenge='1' nonce='2'/></message>";
    let routed = strip_untrusted_direct_delays(&strip_pow_element(source), None);
    assert!(routed.contains("<private xmlns='urn:xmpp:carbons:2'/>"));
    assert!(!routed.contains("urn:northstar:pow:1"));
}

#[test]
fn mixed_retraction_and_direct_invite_is_rejected_before_branch_selection() {
    let mixed = Document::parse(
        "<message id='action'><retract xmlns='urn:xmpp:message-retract:1' id='target'/><x xmlns='jabber:x:conference' jid='room@conference.example.test'/></message>",
    )
    .unwrap();
    assert!(mixes_personal_retraction_and_direct_invite(
        mixed.root_element()
    ));

    let fallback = Document::parse(
        "<message id='action'><body>removed</body><retract xmlns='urn:xmpp:message-retract:1' id='target'/></message>",
    )
    .unwrap();
    assert!(!mixes_personal_retraction_and_direct_invite(
        fallback.root_element()
    ));
}

#[test]
fn message_pow_commits_client_bytes_not_server_routing_assertions() {
    let client = "<message xmlns='jabber:client' to='bob@example.test' type='chat'><body>one</body><pow xmlns='urn:northstar:pow:1' challenge='00000000-0000-0000-0000-000000000001' nonce='0'/></message>";
    let client_document = Document::parse(client).unwrap();
    let language = set_root_attribute(client, "xml:lang", "en");
    let authoritative = set_from(&language, "alice@example.test/phone");
    assert_ne!(
        message_pow_intent_payload(client),
        message_pow_intent_payload(&authoritative),
        "server assertions must be distinguishable from the client commitment"
    );

    let challenge = PowIntent::xmpp(
        AbuseAction::Message,
        "/xmpp/message",
        message_pow_intent_payload(client).as_bytes(),
    );
    // Dispatch retains `client` alongside `authoritative`; verification
    // therefore reconstructs exactly the intent the client requested.
    let verification = PowIntent::xmpp(
        AbuseAction::Message,
        "/xmpp/message",
        message_pow_intent_payload(client).as_bytes(),
    );
    assert_eq!(challenge, verification);
    assert_eq!(client_document.root_element().attribute("from"), None);

    let changed = client.replace("<body>one</body>", "<body>owe</body>");
    let changed = PowIntent::xmpp(
        AbuseAction::Message,
        "/xmpp/message",
        message_pow_intent_payload(&changed).as_bytes(),
    );
    assert_ne!(
        challenge, changed,
        "one client payload byte change must reject"
    );
}

#[test]
fn offline_storage_is_limited_to_normal_and_chat_messages() {
    for kind in [None, Some("normal"), Some("chat")] {
        let attribute = kind
            .map(|kind| format!(" type='{kind}'"))
            .unwrap_or_default();
        let xml = format!("<message{attribute}/>");
        let document = Document::parse(&xml).unwrap();
        assert!(offline_storage_eligible(document.root_element()));
    }
    for kind in ["groupchat", "headline", "error"] {
        let xml = format!("<message type='{kind}'/>");
        let document = Document::parse(&xml).unwrap();
        assert!(!offline_storage_eligible(document.root_element()));
    }
}

#[test]
fn rfc6121_message_routing_modes_are_type_specific() {
    assert_eq!(bare_message_route("normal"), BareMessageRoute::Primary);
    assert_eq!(bare_message_route("chat"), BareMessageRoute::Primary);
    assert_eq!(bare_message_route("headline"), BareMessageRoute::All);
    assert_eq!(bare_message_route("groupchat"), BareMessageRoute::Reject);
    assert_eq!(bare_message_route("error"), BareMessageRoute::Ignore);

    assert_eq!(full_no_match_route("chat"), FullNoMatchRoute::FallbackChat);
    for kind in ["normal", "groupchat", "headline"] {
        assert_eq!(full_no_match_route(kind), FullNoMatchRoute::Reject);
    }
    assert_eq!(full_no_match_route("error"), FullNoMatchRoute::Ignore);
    assert!(durable_full_no_match_recovers("normal", true));
    assert!(!durable_full_no_match_recovers("normal", false));
    assert!(!durable_full_no_match_recovers("chat", true));

    for kind in ["normal", "chat", "groupchat"] {
        assert!(missing_user_message_should_error(kind));
    }
    for kind in ["headline", "error"] {
        assert!(!missing_user_message_should_error(kind));
    }
}

#[test]
fn durable_direct_message_kinds_never_use_multi_resource_fanout() {
    for kind in ["normal", "chat"] {
        assert_ne!(bare_message_route(kind), BareMessageRoute::All);
    }
    assert_eq!(bare_message_route("headline"), BareMessageRoute::All);
}

#[test]
fn only_offline_admission_can_cross_the_personal_side_effect_boundary() {
    assert_eq!(
        undelivered_disposition("headline", true, true),
        UndeliveredDisposition::Drop
    );
    assert_eq!(
        undelivered_disposition("chat", false, true),
        UndeliveredDisposition::Drop
    );
    assert_eq!(
        undelivered_disposition("groupchat", true, true),
        UndeliveredDisposition::RejectCancel
    );
    assert_eq!(
        undelivered_disposition("chat", true, false),
        UndeliveredDisposition::RejectWait
    );
    for kind in ["normal", "chat"] {
        assert_eq!(
            undelivered_disposition(kind, true, true),
            UndeliveredDisposition::StoreOffline
        );
    }
}

#[test]
fn test_session_reports_the_authenticated_message_actor() {
    use crate::ports::MessageSession;
    use crate::test_support::{Session, State, ACTOR, ACTOR_CONNECTION, ACTOR_GENERATION, SENDER};

    let session = Session::new(State::default(), true);
    let actor = session.message_actor().unwrap();
    assert_eq!(actor.account_id, ACTOR);
    assert_eq!(actor.auth_generation, ACTOR_GENERATION);
    assert_eq!(actor.connection_id, ACTOR_CONNECTION);
    assert_eq!(actor.full_jid.to_string(), SENDER);
}

#[tokio::test]
async fn client_delivery_uses_the_hosts_event_source() {
    use crate::test_support::{Session, State, ACTOR, ACTOR_GENERATION, SENDER, TARGET};
    use northstar_message_core::ActorGenerationFence;
    use northstar_stream::transport::Action;
    use uuid::Uuid;

    let session = Session::new(State::default(), true);
    let client = format!("<message to='{TARGET}' type='chat'><body>event source</body></message>");
    let routed = set_from(&client, SENDER);
    let document = Document::parse(&routed).unwrap();
    let action = super::message(&session, document.root_element(), &routed, &client)
        .await
        .unwrap();
    assert!(matches!(action, Action::None));

    let committed = session.host.state.committed.lock().unwrap();
    let delivery = committed.as_ref().expect("committed client delivery");
    assert_eq!(
        delivery.actor_fence,
        Some(ActorGenerationFence {
            account_id: ACTOR,
            auth_generation: ACTOR_GENERATION,
        }),
    );
    let expected_id = Uuid::from_u128(0x101);
    assert_eq!(delivery.source.message_id, expected_id);
    let stanza = Document::parse(&delivery.stanza).unwrap();
    let stanza_id = stanza
        .root_element()
        .children()
        .find(|child| child.has_tag_name(("urn:xmpp:sid:0", "stanza-id")))
        .unwrap();
    assert_eq!(stanza_id.attribute("by"), Some(TARGET));
    assert_eq!(
        stanza_id.attribute("id"),
        Some(expected_id.to_string().as_str())
    );
    let delay = stanza
        .root_element()
        .children()
        .find(|child| child.has_tag_name(("urn:xmpp:delay", "delay")))
        .unwrap();
    assert_eq!(delay.attribute("stamp"), Some("2001-01-01T00:00:00Z"));
}

#[tokio::test]
async fn client_admission_preserves_commitment_before_routed_effects() {
    use crate::ports::MessageFrameStage;
    use crate::test_support::{Event, Session, State, ACTOR, SENDER, TARGET};
    use northstar_abuse_policy::message_admission::acceptance_fence;
    use northstar_stream::transport::Action;

    for (label, payload, rated, refused, retained, finalize_error) in [
        (
            "rated_content",
            "<body>original content</body>",
            true,
            false,
            true,
            false,
        ),
        (
            "encrypted_content",
            "<encrypted xmlns='urn:xmpp:omemo:2'>ciphertext</encrypted>",
            true,
            false,
            true,
            false,
        ),
        (
            "admission_refusal",
            "<body>refused content</body>",
            true,
            true,
            true,
            false,
        ),
        (
            "unrated_receipt",
            "<received xmlns='urn:xmpp:receipts' id='earlier'/>",
            false,
            false,
            true,
            false,
        ),
        (
            "unowned_acceptance",
            "<body>compatibility caller</body>",
            true,
            false,
            false,
            false,
        ),
        (
            "accepted_finalize_failure",
            "<body>accepted content</body>",
            true,
            false,
            true,
            true,
        ),
    ] {
        let mut session = Session::new(
            State {
                admission_conflict: refused,
                finalize_error,
                ..State::default()
            },
            retained,
        );
        session.mix = true;
        let commitment = format!("<message xmlns='jabber:client' to='{TARGET}' type='chat' id='client-id'>{payload}<origin-id xmlns='urn:xmpp:sid:0' id='original'/></message>");
        let proof = "<pow xmlns='urn:northstar:pow:1' challenge='00000000-0000-0000-0000-000000000031' nonce='fixed-nonce'/>";
        let client = commitment.replace(
            "</message>",
            &format!(
                "{proof}<delay xmlns='urn:xmpp:delay' stamp='2000-01-01T00:00:00Z'/></message>"
            ),
        );
        let routed = set_root_attribute(&set_from(&client, SENDER), "xml:lang", "ja");
        let document = Document::parse(&routed).unwrap();
        let action = super::message(&session, document.root_element(), &routed, &client)
            .await
            .unwrap();
        let events = session.host.state.events();
        let begins: Vec<_> = events
            .iter()
            .filter_map(|event| match event {
                Event::Begin(request, retained) => Some((request, *retained)),
                _ => None,
            })
            .collect();
        assert_eq!(
            begins.len(),
            usize::from(rated),
            "{label}: begin_before_effects"
        );
        if let Some((request, used_retained)) = begins.first() {
            assert_eq!(*used_retained, retained, "{label}: originating_begin");
            assert_eq!(request.actor_id, ACTOR, "{label}: actor");
            assert_eq!(
                request.account_bare, "alice@example.test",
                "{label}: account"
            );
            assert_eq!(request.normalized_target, TARGET, "{label}: target");
            assert_eq!(
                request.origin_id.as_deref(),
                Some("original"),
                "{label}: origin"
            );
            assert_eq!(
                request.pow_intent_payload, commitment,
                "{label}: client_commitment"
            );
            assert_ne!(
                request.pow_intent_payload, request.normalized_payload,
                "{label}: separate_authoritative_envelope"
            );
            assert_eq!(
                request.subject,
                format!("message:{ACTOR}"),
                "{label}: subject"
            );
            assert_eq!(
                request.actors,
                [
                    "ip:192.0.2.1".to_owned(),
                    format!("user:{ACTOR}"),
                    format!("behavior:{ACTOR}")
                ],
                "{label}: actors"
            );
            let proof = request.proof.as_ref().expect(label);
            assert_eq!(
                proof.challenge_id,
                uuid::Uuid::from_u128(49),
                "{label}: proof"
            );
            assert_eq!(proof.nonce, "fixed-nonce", "{label}: proof");
            let normalized = Document::parse(&request.normalized_payload).unwrap();
            assert_eq!(
                normalized.root_element().attribute("from"),
                Some("alice@example.test"),
                "{label}: normalized_sender"
            );
            assert!(
                !normalized
                    .descendants()
                    .any(|node| matches!(node.tag_name().name(), "pow" | "delay")),
                "{label}: stripped_admission"
            );
        }
        if refused {
            let Action::Send(error) = action else {
                panic!("{label}: refusal must return an error")
            };
            assert!(error.contains("conflict"), "{label}: refusal");
            assert!(
                !events.iter().any(|event| matches!(
                    event,
                    Event::Authorize(..) | Event::Mix(_) | Event::Finalize(..) | Event::Local(..)
                )),
                "{label}: zero_effects_after_refusal"
            );
        } else {
            assert!(matches!(action, Action::None), "{label}: accepted_result");
            let sanitized = set_root_attribute(&set_from(&commitment, SENDER), "xml:lang", "ja");
            assert!(
                events.contains(&Event::Mix(sanitized)),
                "{label}: stripped_routing"
            );
            assert!(
                events.contains(&Event::Authorize(
                    ACTOR,
                    "alice@example.test".to_owned(),
                    Some("sender-policy".to_owned()),
                    TARGET.to_owned()
                )),
                "{label}: exact_policy_request"
            );
            let finalizes: Vec<_> = events
                .iter()
                .filter(|event| matches!(event, Event::Finalize(..)))
                .collect();
            assert_eq!(
                finalizes.len(),
                usize::from(rated),
                "{label}: accepted_finalize"
            );
            if rated {
                assert_eq!(
                    finalizes[0],
                    &Event::Finalize(
                        acceptance_fence(&crate::test_support::lease().acceptance()),
                        retained
                    ),
                    "{label}: exact_finalize"
                );
                let begin = events
                    .iter()
                    .position(|event| matches!(event, Event::Begin(..)))
                    .unwrap();
                let route = events
                    .iter()
                    .position(|event| matches!(event, Event::Mix(_)))
                    .unwrap();
                let followup = events
                    .iter()
                    .position(|event| *event == Event::Stage(MessageFrameStage::Followup))
                    .unwrap();
                let finalize = events
                    .iter()
                    .position(|event| matches!(event, Event::Finalize(..)))
                    .unwrap();
                assert!(
                    begin < route && route < followup && followup < finalize,
                    "{label}: begin_route_finalize_order"
                );
                assert_eq!(
                    events.contains(&Event::Finalized),
                    !finalize_error,
                    "{label}: finalization_result"
                );
            }
        }
        assert_eq!(
            session.host.counters[3].load(Ordering::Relaxed),
            u64::from(finalize_error),
            "{label}: post_accept_failure_counter"
        );
    }
}

#[tokio::test]
async fn local_direct_continuation_retains_commit_and_originating_operation() {
    use crate::ports::MessageFrameStage;
    use crate::test_support::{
        poll_once, CommitAnswer, Event, Session, State, ACTOR, OPERATION, RECIPIENT, SENDER, TARGET,
    };
    use northstar_message_application::message_admission::witness::DirectOperationHandle;
    use northstar_message_core::DirectPostCommitMode;
    use northstar_stream::transport::Action;
    use std::sync::atomic::Ordering as AtomicOrdering;

    for (label, answer, retained, finalize_error, degrade) in [
        ("stored_original", CommitAnswer::Stored, true, false, false),
        ("unowned_route", CommitAnswer::Stored, false, false, false),
        ("replay_no_route", CommitAnswer::Replay, true, false, false),
        (
            "account_unavailable",
            CommitAnswer::Unavailable,
            true,
            false,
            false,
        ),
        (
            "unconfirmed_no_route",
            CommitAnswer::Error,
            true,
            false,
            false,
        ),
        (
            "receipt_survives_error",
            CommitAnswer::ReceiptThenError,
            true,
            false,
            false,
        ),
        (
            "finalize_failure_keeps_commit",
            CommitAnswer::Stored,
            true,
            true,
            false,
        ),
        (
            "health_after_finalize",
            CommitAnswer::Stored,
            true,
            false,
            true,
        ),
    ] {
        let (release, gate) = tokio::sync::oneshot::channel();
        let session = Session::new(
            State {
                answer,
                finalize_error,
                finalize_gate: std::sync::Mutex::new(Some(gate)),
                ..State::default()
            },
            retained,
        );
        let original = session.operation.lock().unwrap().clone();
        let client = "<message xmlns='jabber:client' to='bob@example.test' type='chat' id='original'><body>committed body</body><origin-id xmlns='urn:xmpp:sid:0' id='origin'/><pow xmlns='urn:northstar:pow:1' challenge='00000000-0000-0000-0000-000000000031' nonce='proof'/></message>";
        let routed = set_root_attribute(&set_from(client, SENDER), "xml:lang", "ja");
        let document = Document::parse(&routed).unwrap();
        let mut future = Box::pin(super::message(
            &session,
            document.root_element(),
            &routed,
            client,
        ));
        let first = poll_once(future.as_mut());
        let finalizes = !matches!(answer, CommitAnswer::Unavailable | CommitAnswer::Error);
        let mut events = session.host.state.events();
        let action = if finalizes {
            assert!(first.is_pending(), "{label}: finalize_pending");
            assert!(
                events
                    .iter()
                    .any(|event| matches!(event, Event::Commit(_, value) if *value == retained)),
                "{label}: application_before_finalization"
            );
            assert!(
                events
                    .iter()
                    .any(|event| matches!(event, Event::Finalize(_, value) if *value == retained)),
                "{label}: exact_finalize_owner"
            );
            assert!(
                !events.iter().any(|event| matches!(
                    event,
                    Event::Health
                        | Event::Local(..)
                        | Event::Rearm(_)
                        | Event::Carbon(..)
                        | Event::Push(_)
                        | Event::Stage(MessageFrameStage::Routing)
                )),
                "{label}: finalize_before_route"
            );
            let later = DirectOperationHandle::new(uuid::Uuid::from_u128(40));
            *session.operation.lock().unwrap() = Some(later.clone());
            if degrade {
                *session.host.state.mode.lock().unwrap() = DirectPostCommitMode::SpoolOnly;
            }
            release.send(()).unwrap();
            let result = future.await.unwrap();
            assert!(
                later.snapshot().reservation.is_none(),
                "{label}: later_frame_untouched"
            );
            assert!(
                later.snapshot().finalization.is_none(),
                "{label}: later_frame_untouched"
            );
            result
        } else {
            let std::task::Poll::Ready(result) = first else {
                panic!("{label}: refusal unexpectedly pending")
            };
            result.unwrap()
        };
        events.extend(session.host.state.events());
        let committed = session
            .host
            .state
            .committed
            .lock()
            .unwrap()
            .clone()
            .expect(label);
        assert_eq!(committed.actor, Some(ACTOR), "{label}: original_actor");
        assert_eq!(
            (committed.source.recipient_id, committed.source.claim_id),
            (RECIPIENT, Some(committed.source.message_id)),
            "{label}: exact_source"
        );
        assert_eq!(
            (&*committed.sender, &*committed.recipient),
            (SENDER, TARGET),
            "{label}: exact_address"
        );
        assert_eq!(
            committed.eligibility,
            DirectSpoolEligibility::Eligible,
            "{label}: spool_authority"
        );
        assert_eq!(committed.archives.len(), 2, "{label}: both_archive_owners");
        assert_eq!(committed.archives[0].1, ACTOR, "{label}: sender_archive");
        assert_eq!(
            committed.archives[1].1, RECIPIENT,
            "{label}: recipient_archive"
        );
        assert_eq!(
            committed.archives[1].0, committed.source.message_id,
            "{label}: committed_delivery_identity"
        );
        assert_eq!(committed.archives[0].2, TARGET, "{label}: sender_peer");
        assert_eq!(committed.archives[1].2, SENDER, "{label}: recipient_peer");
        for stanza in std::iter::once(&committed.stanza)
            .chain(committed.archives.iter().map(|archive| &archive.3))
        {
            let parsed = Document::parse(stanza).unwrap();
            assert_eq!(
                parsed.root_element().attribute("from"),
                Some(SENDER),
                "{label}: committed_sender"
            );
            assert!(
                !parsed
                    .descendants()
                    .any(|node| node.tag_name().name() == "pow"),
                "{label}: stripped_archive"
            );
            assert!(stanza.contains("committed body"), "{label}: original_bytes");
        }
        let identity = committed.identity.as_ref().unwrap();
        assert_eq!(
            (&*identity.0, &*identity.1, &*identity.2),
            ("alice@example.test", TARGET, "origin"),
            "{label}: original_identity"
        );
        let routes: Vec<_> = events
            .iter()
            .filter_map(|event| match event {
                Event::Local(connection, stanza, source) => Some((*connection, stanza, *source)),
                _ => None,
            })
            .collect();
        let live = answer == CommitAnswer::Stored && !degrade;
        assert_eq!(
            routes.len(),
            usize::from(live),
            "{label}: one_route_or_no_route"
        );
        if live {
            assert_eq!(
                routes[0].0,
                uuid::Uuid::from_u128(21),
                "{label}: approved_primary"
            );
            assert_eq!(
                routes[0].2,
                Some(committed.source),
                "{label}: original_delivery_fence"
            );
            assert_eq!(
                *routes[0].1, committed.archives[1].3,
                "{label}: committed_live_projection"
            );
            let route = events
                .iter()
                .position(|event| matches!(event, Event::Local(..)))
                .unwrap();
            assert!(
                matches!(events[route - 1], Event::Health),
                "{label}: health_before_handoff"
            );
            assert!(
                events[..route].contains(&Event::Stage(MessageFrameStage::Routing)),
                "{label}: routing_stage"
            );
        }
        if degrade || answer == CommitAnswer::ReceiptThenError {
            assert!(
                events.contains(&Event::Rearm(committed.source)),
                "{label}: recover_exact_claim"
            );
        }
        if finalizes {
            assert!(
                matches!(action, Action::None),
                "{label}: acceptance_retained"
            );
        } else {
            let Action::Send(error) = action else {
                panic!("{label}: expected stanza error")
            };
            let condition = if answer == CommitAnswer::Unavailable {
                "service-unavailable"
            } else {
                "resource-constraint"
            };
            assert!(error.contains(condition), "{label}: refusal_condition");
        }
        if let Some(original) = original {
            let snapshot = original.snapshot();
            assert_eq!(snapshot.operation, OPERATION, "{label}: original_operation");
            assert!(
                snapshot
                    .reservation
                    .unwrap()
                    .has_durable_reservation_receipt(),
                "{label}: retained_begin"
            );
            assert_eq!(
                snapshot.finalization.is_some(),
                finalizes,
                "{label}: retained_finalization"
            );
            assert!(snapshot.direct.is_some(), "{label}: retained_application");
        }
        if finalize_error {
            assert_eq!(
                events
                    .iter()
                    .filter(|event| matches!(event, Event::PostAcceptFailed))
                    .count(),
                1,
                "{label}: failure_count"
            );
            assert_eq!(
                session.host.counters[3].load(AtomicOrdering::Relaxed),
                0,
                "{label}: owner_failure_port"
            );
        }
    }
}
