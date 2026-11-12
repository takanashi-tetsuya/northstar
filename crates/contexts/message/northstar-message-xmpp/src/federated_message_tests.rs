use super::*;
use roxmltree::Document;

#[test]
fn degraded_inbound_spool_accepts_only_recoverable_bare_messages() {
    for xml in [
        "<message type='chat'><body>hello</body></message>",
        "<message type='chat'><body>hello</body><composing xmlns='http://jabber.org/protocol/chatstates'/></message>",
        "<message type='normal'><body>hello</body></message>",
        "<message><body>hello</body></message>",
    ] {
        let document = Document::parse(xml).unwrap();
        assert!(degraded_inbound_direct_eligible(
            document.root_element(),
            true,
            false,
            false,
        ));
    }

    for xml in [
        "<message type='chat'><body>private</body><no-store xmlns='urn:xmpp:hints'/></message>",
        "<message type='chat'><composing xmlns='http://jabber.org/protocol/chatstates'/></message>",
        "<message type='chat'><composing xmlns='http://jabber.org/protocol/chatstates'/><store xmlns='urn:xmpp:hints'/></message>",
        "<message type='chat'><received xmlns='urn:xmpp:receipts' id='m1'/><store xmlns='urn:xmpp:hints'/></message>",
        "<message type='chat'><displayed xmlns='urn:xmpp:chat-markers:0' id='m1'/><store xmlns='urn:xmpp:hints'/></message>",
        "<message type='headline'><body>news</body></message>",
        "<message type='groupchat'><body>hello</body></message>",
        "<message type='chat'><body>join</body><x xmlns='jabber:x:conference' jid='room@conference.example.test'/></message>",
        "<message type='normal'><pubsub xmlns='http://jabber.org/protocol/pubsub' node='push'><affiliation affiliation='none' jid='push.example.test'/></pubsub><store xmlns='urn:xmpp:hints'/></message>",
    ] {
        let document = Document::parse(xml).unwrap();
        assert!(
            !degraded_inbound_direct_eligible(document.root_element(), true, false, false),
            "unexpected degraded spool eligibility: {xml}"
        );
    }

    let plain = Document::parse("<message type='chat'><body>hello</body></message>").unwrap();
    assert!(!degraded_inbound_direct_eligible(
        plain.root_element(),
        false,
        false,
        false,
    ));
    assert!(!degraded_inbound_direct_eligible(
        plain.root_element(),
        true,
        true,
        false,
    ));
    assert!(!degraded_inbound_direct_eligible(
        plain.root_element(),
        true,
        false,
        true,
    ));
    let encrypted = Document::parse(
        "<message type='chat'><encrypted xmlns='urn:xmpp:omemo:2'>ciphertext</encrypted></message>",
    )
    .unwrap();
    assert!(degraded_inbound_direct_eligible(
        encrypted.root_element(),
        true,
        false,
        true,
    ));
}

#[test]
fn degraded_inbound_postcommit_is_accepted_without_live_effects() {
    assert_eq!(
        inbound_live_effect(DirectPostCommitMode::Live, false),
        InboundLiveEffect::Proceed
    );
    assert_eq!(
        inbound_live_effect(DirectPostCommitMode::Live, true),
        InboundLiveEffect::Proceed
    );
    for mode in [
        DirectPostCommitMode::SpoolOnly,
        DirectPostCommitMode::Rejected,
    ] {
        assert_eq!(inbound_live_effect(mode, false), InboundLiveEffect::Reject);
        assert_eq!(
            inbound_live_effect(mode, true),
            InboundLiveEffect::AcceptedSpool
        );
    }
}

#[test]
fn degraded_inbound_privacy_uses_account_default_and_fences_live_only_admission() {
    assert_eq!(
        degraded_inbound_privacy_uses_default(DirectPostCommitMode::Live, true),
        Some(false)
    );
    assert_eq!(
        degraded_inbound_privacy_uses_default(DirectPostCommitMode::SpoolOnly, true),
        Some(true)
    );
    assert_eq!(
        degraded_inbound_privacy_uses_default(DirectPostCommitMode::SpoolOnly, false),
        None
    );
    assert_eq!(
        degraded_inbound_privacy_uses_default(DirectPostCommitMode::Rejected, true),
        None
    );
    assert_eq!(
        inbound_direct_spool_eligibility(true, false),
        DirectSpoolEligibility::Eligible
    );
    assert_eq!(
        inbound_direct_spool_eligibility(true, true),
        DirectSpoolEligibility::LiveOnly
    );
    assert_eq!(
        inbound_direct_spool_eligibility(false, false),
        DirectSpoolEligibility::LiveOnly
    );
}

#[test]
fn remote_history_identity_is_bound_to_the_authenticated_domain() {
    let document = Document::parse(
        "<message><stanza-id xmlns='urn:xmpp:sid:0' by='Alice@REMOTE.test' id='trusted'/><stanza-id xmlns='urn:xmpp:sid:0' by='mallory.test' id='ignored'/></message>",
    )
    .unwrap();
    assert_eq!(
        authoritative_remote_stanza_identity(document.root_element(), "remote.TEST"),
        Some((
            "Alice@REMOTE.test".to_owned(),
            "alice@remote.test".to_owned(),
            "trusted".to_owned()
        ))
    );
    assert!(
        authoritative_remote_stanza_identity(document.root_element(), "unrelated.test").is_none()
    );

    let ambiguous = Document::parse(
        "<message><stanza-id xmlns='urn:xmpp:sid:0' by='alice@remote.test' id='a'/><stanza-id xmlns='urn:xmpp:sid:0' by='remote.test' id='b'/></message>",
    )
    .unwrap();
    assert!(
        authoritative_remote_stanza_identity(ambiguous.root_element(), "remote.test").is_none()
    );
}

#[test]
fn message_delivery_errors_use_rfc6120_type_condition_pairs() {
    let request = Document::parse(
        "<message xmlns='jabber:server' from='alice@remote.test/a' to='bob@local.test'><body>hello</body></message>",
    )
    .unwrap();
    for (serialized, condition) in [
        (
            offline_quota_error(request.root_element()),
            "resource-constraint",
        ),
        (
            recipient_unavailable_error(request.root_element()),
            "recipient-unavailable",
        ),
    ] {
        let response = Document::parse(&serialized).unwrap();
        let error = response
            .root_element()
            .children()
            .find(|child| {
                child.is_element()
                    && child.tag_name().name() == "error"
                    && child.tag_name().namespace() == Some("jabber:server")
            })
            .unwrap();
        assert_eq!(error.attribute("type"), Some("wait"));
        assert!(error.children().any(|child| {
            child.is_element()
                && child.tag_name().name() == condition
                && child.tag_name().namespace() == Some("urn:ietf:params:xml:ns:xmpp-stanzas")
        }));
    }
}

#[test]
fn message_errors_never_generate_error_loops() {
    let ordinary = Document::parse(
        "<message xmlns='jabber:server' from='alice@remote.test/a' to='bob@local.test'><body>hello</body></message>",
    )
    .unwrap();
    assert!(
        inbound_message_error(ordinary.root_element(), "cancel", "service-unavailable").is_some()
    );

    let error = Document::parse(
        "<message xmlns='jabber:server' type='error' from='alice@remote.test/a' to='missing@local.test'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></message>",
    )
    .unwrap();
    assert!(inbound_message_error(error.root_element(), "cancel", "service-unavailable").is_none());
}

#[test]
fn remote_muc_private_messages_are_not_carbon_copied() {
    let private = Document::parse(
        "<message xmlns='jabber:client' type='chat' from='room@conference.remote.example/nick' to='alice@example.test/phone'><body>private</body></message>",
    )
    .unwrap();
    assert!(is_remote_muc_private_message(
        private.root_element(),
        "room@conference.remote.example/nick",
        "conference.remote.example"
    ));
    let direct = Document::parse(
        "<message xmlns='jabber:client' type='chat' from='bob@remote.example/phone' to='alice@example.test/phone'><body>direct</body></message>",
    )
    .unwrap();
    assert!(!is_remote_muc_private_message(
        direct.root_element(),
        "bob@remote.example/phone",
        "remote.example"
    ));
}
