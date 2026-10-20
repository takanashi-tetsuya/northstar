use super::{
    bare_message_route, degraded_local_direct_eligible, direct_delivery_mode,
    direct_spool_eligibility, durable_direct_delivery_allowed, full_no_match_route,
    message_pow_intent_payload, missing_user_message_should_error,
    mixes_personal_retraction_and_direct_invite, offline_storage_eligible, undelivered_disposition,
    wake_federation_outbox_after_commit, BareMessageRoute, DirectDeliveryMode,
    DirectSpoolEligibility, DurableAdmissionOutcome, FullNoMatchRoute, MessagePostCommit,
    UndeliveredDisposition,
};
use crate::{
    services::abuse::{AbuseAction, PowIntent},
    services::xml_util::{
        set_from, set_root_attribute, strip_pow_element, strip_untrusted_direct_delays,
    },
};
use northstar_message_core::durable_full_no_match_recovers;
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
