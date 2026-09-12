//! Comprehensive integration tests for northstar-xep-0357.

use northstar_xep_0357::*;
use northstar_xep_core::{StanzaKind, XepId};
use roxmltree::Document;

// ──────────────────────────────────────────────────────────────────────────────
// Descriptor tests
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn descriptor_matches_manifest() {
    assert_eq!(DESCRIPTOR.id, XEP_ID);
    assert_eq!(DESCRIPTOR.id, XepId::new(357));
    assert_eq!(DESCRIPTOR.name, "Push Notifications");
    assert!(DESCRIPTOR.default_enabled);
    assert_eq!(DESCRIPTOR.dependencies, &[XepId::new(30)]);
    assert!(DESCRIPTOR.conflicts.is_empty());
    assert_eq!(DESCRIPTOR.disco_features, &[DISCO_FEATURE_PUSH]);
    assert_eq!(DESCRIPTOR.routes.len(), 2);

    assert!(DESCRIPTOR
        .routes
        .iter()
        .any(|r| r.stanza == StanzaKind::IqSet
            && r.namespace == XMLNS_PUSH
            && r.local_name == "enable"));
    assert!(DESCRIPTOR
        .routes
        .iter()
        .any(|r| r.stanza == StanzaKind::IqSet
            && r.namespace == XMLNS_PUSH
            && r.local_name == "disable"));
}

// ──────────────────────────────────────────────────────────────────────────────
// Enable parsing round-trips
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn enable_with_node_and_options_round_trips() {
    let xml = "<enable xmlns='urn:xmpp:push:0' jid='Push.Example.test' node='device-1'>\
        <x xmlns='jabber:x:data' type='submit'>\
            <field var='FORM_TYPE'><value>http://jabber.org/protocol/pubsub#publish-options</value></field>\
            <field var='secret'><value>opaque</value></field>\
        </x>\
    </enable>";
    let doc = Document::parse(xml).unwrap();
    let (req, _) = parse_enable(doc.root_element()).unwrap();
    assert_eq!(req.service_jid().to_string(), "push.example.test");
    assert_eq!(req.node_str(), "device-1");
    assert!(req.options.is_some());
    assert_eq!(
        req.options.as_ref().unwrap().get_value("secret"),
        Some("opaque")
    );

    // Build it back and verify it parses again
    let rebuilt = build_enable(
        &req.service_jid().to_string(),
        Some(req.node_str()),
        req.options.as_ref(),
    );
    assert!(rebuilt.contains("push.example.test"));
    assert!(rebuilt.contains("device-1"));
}

#[test]
fn enable_without_node_round_trips() {
    let xml = "<enable xmlns='urn:xmpp:push:0' jid='push.example.test'/>";
    let doc = Document::parse(xml).unwrap();
    let (req, opts_node) = parse_enable(doc.root_element()).unwrap();
    assert_eq!(req.service_jid().to_string(), "push.example.test");
    assert!(req.node().is_none());
    assert!(req.options.is_none());
    assert!(opts_node.is_none());

    // Build and verify
    let rebuilt = build_enable(&req.service_jid().to_string(), None, None);
    assert!(rebuilt.contains("jid='push.example.test'"));
    assert!(!rebuilt.contains("node="));
}

// ──────────────────────────────────────────────────────────────────────────────
// Malformed enable IQs
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn enable_rejects_full_jid_with_resource() {
    let xml = "<enable xmlns='urn:xmpp:push:0' jid='push.example.test/Resource' node='device'/>";
    let doc = Document::parse(xml).unwrap();
    let err = parse_enable(doc.root_element()).unwrap_err();
    assert!(matches!(err, PushError::JidMalformed(_)));
}

#[test]
fn enable_rejects_empty_node() {
    let xml = "<enable xmlns='urn:xmpp:push:0' jid='push.example.test' node=''/>";
    let doc = Document::parse(xml).unwrap();
    let err = parse_enable(doc.root_element()).unwrap_err();
    assert!(matches!(err, PushError::InvalidNode(_)));
}

#[test]
fn enable_rejects_missing_jid() {
    let xml = "<enable xmlns='urn:xmpp:push:0' node='device'/>";
    let doc = Document::parse(xml).unwrap();
    assert!(parse_enable(doc.root_element()).is_err());
}

#[test]
fn enable_rejects_unknown_child_elements() {
    let xml = "<enable xmlns='urn:xmpp:push:0' jid='push.example.test' node='device'>\
        <unknown/></enable>";
    let doc = Document::parse(xml).unwrap();
    assert!(parse_enable(doc.root_element()).is_err());
}

#[test]
fn enable_rejects_wrong_form_type() {
    let xml = "<enable xmlns='urn:xmpp:push:0' jid='push.example.test' node='device'>\
        <x xmlns='jabber:x:data' type='submit'>\
            <field var='FORM_TYPE'><value>wrong</value></field>\
        </x>\
    </enable>";
    let doc = Document::parse(xml).unwrap();
    assert!(parse_enable(doc.root_element()).is_err());
}

#[test]
fn enable_rejects_duplicate_form_type_field() {
    let xml = "<enable xmlns='urn:xmpp:push:0' jid='push.example.test' node='device'>\
        <x xmlns='jabber:x:data' type='submit'>\
            <field var='FORM_TYPE'><value>http://jabber.org/protocol/pubsub#publish-options</value></field>\
            <field var='FORM_TYPE'><value>http://jabber.org/protocol/pubsub#publish-options</value></field>\
        </x>\
    </enable>";
    let doc = Document::parse(xml).unwrap();
    assert!(parse_enable(doc.root_element()).is_err());
}

#[test]
fn enable_rejects_extra_attributes() {
    let xml = "<enable xmlns='urn:xmpp:push:0' jid='push.example.test' node='d' extra='bad'/>";
    let doc = Document::parse(xml).unwrap();
    assert!(parse_enable(doc.root_element()).is_err());
}

// ──────────────────────────────────────────────────────────────────────────────
// Disable parsing
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn disable_service_wide() {
    let xml = "<disable xmlns='urn:xmpp:push:0' jid='push.example.test'/>";
    let doc = Document::parse(xml).unwrap();
    let req = parse_disable(doc.root_element()).unwrap();
    assert_eq!(req.service_jid.to_string(), "push.example.test");
    assert!(req.node.is_none());
}

#[test]
fn disable_specific_node() {
    let xml = "<disable xmlns='urn:xmpp:push:0' jid='push.example.test' node='device'/>";
    let doc = Document::parse(xml).unwrap();
    let req = parse_disable(doc.root_element()).unwrap();
    assert_eq!(req.service_jid.to_string(), "push.example.test");
    assert_eq!(req.node.as_ref().unwrap().as_str(), "device");

    // Build round-trip
    let rebuilt = build_disable(
        &req.service_jid.to_string(),
        req.node.as_ref().map(|n| n.as_str()),
    );
    assert!(rebuilt.contains("node='device'"));
}

#[test]
fn disable_rejects_child_elements() {
    let xml = "<disable xmlns='urn:xmpp:push:0' jid='push.example.test'><x/></disable>";
    let doc = Document::parse(xml).unwrap();
    assert!(parse_disable(doc.root_element()).is_err());
}

#[test]
fn disable_rejects_text_content() {
    let xml = "<disable xmlns='urn:xmpp:push:0' jid='push.example.test'>text</disable>";
    let doc = Document::parse(xml).unwrap();
    assert!(parse_disable(doc.root_element()).is_err());
}

// ──────────────────────────────────────────────────────────────────────────────
// IQ target validation
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn iq_target_omitted_targets_own_account() {
    let doc = Document::parse("<iq type='set' id='1'/>").unwrap();
    assert!(iq_targets_own_account(
        doc.root_element(),
        "alice@example.test"
    ));
}

#[test]
fn iq_target_own_bare_jid_matches() {
    let doc = Document::parse("<iq type='set' id='1' to='Alice@Example.test'/>").unwrap();
    assert!(iq_targets_own_account(
        doc.root_element(),
        "alice@example.test"
    ));
}

#[test]
fn iq_target_other_jid_rejected() {
    let doc = Document::parse("<iq type='set' id='1' to='bob@example.test'/>").unwrap();
    assert!(!iq_targets_own_account(
        doc.root_element(),
        "alice@example.test"
    ));
}

// ──────────────────────────────────────────────────────────────────────────────
// Bounded identifiers
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn push_node_rejects_empty() {
    assert!(PushNode::new("").is_err());
}

#[test]
fn push_node_rejects_oversized() {
    let oversized = "x".repeat(1025);
    assert!(PushNode::new(oversized).is_err());
}

#[test]
fn push_node_rejects_control_chars() {
    assert!(PushNode::new("device\x00").is_err());
    assert!(PushNode::new("device\x7f").is_err());
}

#[test]
fn push_node_accepts_valid() {
    assert!(PushNode::new("device-1").is_ok());
    assert!(PushNode::new("x".repeat(1024)).is_ok());
}

// ──────────────────────────────────────────────────────────────────────────────
// Summary parsing and building
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn summary_round_trips() {
    let summary = PushSummary::new()
        .with_message_count(5)
        .with_pending_subscription_count(2);
    let xml = summary.to_data_form_xml();
    let parsed = PushSummary::parse_xml(&xml).unwrap();
    assert_eq!(parsed.message_count, Some(5));
    assert_eq!(parsed.pending_subscription_count, Some(2));
    assert!(parsed.last_message_sender.is_none());
    assert!(parsed.last_message_body.is_none());
}

#[test]
fn summary_notification_wrapper_round_trips() {
    let summary = PushSummary::new().with_message_count(1);
    let notification_xml = summary.to_notification_xml();
    assert!(notification_xml.contains("urn:xmpp:push:0"));
    assert!(notification_xml.contains("urn:xmpp:push:summary"));
    assert!(notification_xml.contains("message-count"));

    let doc = Document::parse(&notification_xml).unwrap();
    let parsed = PushSummary::parse_notification(doc.root_element()).unwrap();
    assert_eq!(parsed.message_count, Some(1));
}

#[test]
fn summary_rejects_missing_form_type() {
    let xml = "<x xmlns='jabber:x:data' type='form'>\
        <field var='message-count'><value>1</value></field>\
    </x>";
    assert!(PushSummary::parse_xml(xml).is_err());
}

#[test]
fn summary_rejects_wrong_form_type() {
    let xml = "<x xmlns='jabber:x:data' type='form'>\
        <field var='FORM_TYPE' type='hidden'><value>wrong</value></field>\
    </x>";
    assert!(PushSummary::parse_xml(xml).is_err());
}

#[test]
fn summary_rejects_duplicate_fields() {
    let xml = "<x xmlns='jabber:x:data' type='form'>\
        <field var='FORM_TYPE' type='hidden'><value>urn:xmpp:push:summary</value></field>\
        <field var='message-count'><value>1</value></field>\
        <field var='message-count'><value>2</value></field>\
    </x>";
    assert!(PushSummary::parse_xml(xml).is_err());
}

// ──────────────────────────────────────────────────────────────────────────────
// Encrypted-message privacy: disclosure policy
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn default_policy_never_leaks_body_or_sender() {
    let policy = DisclosurePolicy::default();
    assert!(policy.include_message_count);
    assert!(policy.include_pending_subscriptions);
    assert_eq!(policy.sender_disclosure, SenderDisclosure::Never);
    assert_eq!(policy.body_disclosure, BodyDisclosure::Never);

    let event = NotificationEvent {
        message_count: 3,
        pending_subscription_count: 1,
        sender: Some(northstar_xmpp_types::CanonicalJid::parse("alice@example.test").unwrap()),
        body: Some("Hello secret".to_owned()),
        encryption: MessageEncryption::Plaintext,
    };
    let summary = apply_disclosure_policy(&policy, &event);
    assert_eq!(summary.message_count, Some(3));
    assert_eq!(summary.pending_subscription_count, Some(1));
    assert!(summary.last_message_sender.is_none());
    assert!(summary.last_message_body.is_none());
}

#[test]
fn encrypted_message_never_leaks_plaintext_body() {
    // Even with PlaintextOnly disclosure, encrypted messages must not leak body
    let policy = DisclosurePolicy {
        include_message_count: true,
        include_pending_subscriptions: true,
        sender_disclosure: SenderDisclosure::BareJid,
        body_disclosure: BodyDisclosure::PlaintextOnly,
    };

    let event = NotificationEvent {
        message_count: 1,
        pending_subscription_count: 0,
        sender: Some(northstar_xmpp_types::CanonicalJid::parse("alice@example.test").unwrap()),
        body: Some("This body should never appear".to_owned()),
        encryption: MessageEncryption::Encrypted,
    };
    let summary = apply_disclosure_policy(&policy, &event);
    assert!(summary.last_message_body.is_none());
    // Sender should still be disclosed
    assert!(summary.last_message_sender.is_some());
}

#[test]
fn encrypted_message_with_truncated_disclosure_suppresses_body() {
    let policy = DisclosurePolicy {
        include_message_count: true,
        include_pending_subscriptions: false,
        sender_disclosure: SenderDisclosure::Never,
        body_disclosure: BodyDisclosure::Truncated(50),
    };

    let event = NotificationEvent {
        message_count: 1,
        pending_subscription_count: 0,
        sender: None,
        body: Some("Secret encrypted content".to_owned()),
        encryption: MessageEncryption::Encrypted,
    };
    let summary = apply_disclosure_policy(&policy, &event);
    assert!(summary.last_message_body.is_none());
}

#[test]
fn encrypted_message_with_redacted_disclosure_shows_placeholder() {
    let policy = DisclosurePolicy {
        include_message_count: true,
        include_pending_subscriptions: true,
        sender_disclosure: SenderDisclosure::Never,
        body_disclosure: BodyDisclosure::Redacted("[Encrypted Message]".to_owned()),
    };

    let event = NotificationEvent {
        message_count: 1,
        pending_subscription_count: 0,
        sender: None,
        body: Some("Secret".to_owned()),
        encryption: MessageEncryption::Encrypted,
    };
    let summary = apply_disclosure_policy(&policy, &event);
    assert_eq!(
        summary.last_message_body.as_deref(),
        Some("[Encrypted Message]")
    );
}

#[test]
fn plaintext_body_disclosed_when_authorized() {
    let policy = DisclosurePolicy {
        include_message_count: true,
        include_pending_subscriptions: true,
        sender_disclosure: SenderDisclosure::FullJid,
        body_disclosure: BodyDisclosure::PlaintextOnly,
    };

    let event = NotificationEvent {
        message_count: 1,
        pending_subscription_count: 0,
        sender: Some(
            northstar_xmpp_types::CanonicalJid::parse("alice@example.test/phone").unwrap(),
        ),
        body: Some("Hello!".to_owned()),
        encryption: MessageEncryption::Plaintext,
    };
    let summary = apply_disclosure_policy(&policy, &event);
    assert_eq!(summary.last_message_body.as_deref(), Some("Hello!"));
    assert!(summary.last_message_sender.is_some());
}

#[test]
fn truncated_body_disclosure() {
    let policy = DisclosurePolicy {
        include_message_count: true,
        include_pending_subscriptions: true,
        sender_disclosure: SenderDisclosure::Never,
        body_disclosure: BodyDisclosure::Truncated(5),
    };

    let event = NotificationEvent {
        message_count: 1,
        pending_subscription_count: 0,
        sender: None,
        body: Some("Hello, World!".to_owned()),
        encryption: MessageEncryption::Plaintext,
    };
    let summary = apply_disclosure_policy(&policy, &event);
    assert_eq!(summary.last_message_body.as_deref(), Some("Hello"));
}

// ──────────────────────────────────────────────────────────────────────────────
// Eligibility evaluation
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn offline_recipient_is_eligible() {
    let input = EligibilityInput {
        recipient_sessions: vec![],
        is_error_stanza: false,
        no_store: false,
        encryption: MessageEncryption::Plaintext,
        importance: MessageImportance::Normal,
        has_body: true,
    };
    let decision = evaluate_eligibility(&input);
    assert!(decision.is_eligible());
    assert_eq!(
        decision,
        EligibilityDecision::Eligible(EligibilityReason::OfflineRecipient)
    );
}

#[test]
fn active_session_suppresses_normal_push() {
    let input = EligibilityInput {
        recipient_sessions: vec![RecipientSessionState::Available { priority: 0 }],
        is_error_stanza: false,
        no_store: false,
        encryption: MessageEncryption::Plaintext,
        importance: MessageImportance::Normal,
        has_body: true,
    };
    let decision = evaluate_eligibility(&input);
    assert!(!decision.is_eligible());
    assert_eq!(
        decision,
        EligibilityDecision::Ineligible(IneligibilityReason::ActiveOnlineSession)
    );
}

#[test]
fn csi_inactive_triggers_push() {
    let input = EligibilityInput {
        recipient_sessions: vec![RecipientSessionState::CsiInactive],
        is_error_stanza: false,
        no_store: false,
        encryption: MessageEncryption::Plaintext,
        importance: MessageImportance::Normal,
        has_body: true,
    };
    let decision = evaluate_eligibility(&input);
    assert!(decision.is_eligible());
    assert_eq!(
        decision,
        EligibilityDecision::Eligible(EligibilityReason::CsiInactiveSession)
    );
}

#[test]
fn no_store_suppresses_push() {
    let input = EligibilityInput {
        recipient_sessions: vec![],
        is_error_stanza: false,
        no_store: true,
        encryption: MessageEncryption::Plaintext,
        importance: MessageImportance::Normal,
        has_body: true,
    };
    let decision = evaluate_eligibility(&input);
    assert!(!decision.is_eligible());
}

#[test]
fn error_stanza_suppresses_push() {
    let input = EligibilityInput {
        recipient_sessions: vec![],
        is_error_stanza: true,
        no_store: false,
        encryption: MessageEncryption::Plaintext,
        importance: MessageImportance::Normal,
        has_body: true,
    };
    let decision = evaluate_eligibility(&input);
    assert!(!decision.is_eligible());
}

#[test]
fn mention_on_active_session_still_eligible() {
    let input = EligibilityInput {
        recipient_sessions: vec![RecipientSessionState::Available { priority: 0 }],
        is_error_stanza: false,
        no_store: false,
        encryption: MessageEncryption::Plaintext,
        importance: MessageImportance::Mention,
        has_body: true,
    };
    let decision = evaluate_eligibility(&input);
    assert!(decision.is_eligible());
    assert_eq!(
        decision,
        EligibilityDecision::Eligible(EligibilityReason::UrgentMention)
    );
}

#[test]
fn empty_body_normal_message_is_ineligible() {
    let input = EligibilityInput {
        recipient_sessions: vec![],
        is_error_stanza: false,
        no_store: false,
        encryption: MessageEncryption::Plaintext,
        importance: MessageImportance::Normal,
        has_body: false,
    };
    let decision = evaluate_eligibility(&input);
    assert!(!decision.is_eligible());
}

// ──────────────────────────────────────────────────────────────────────────────
// Coalescing keys
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn coalesce_key_deterministic_round_trip() {
    let user = northstar_xmpp_types::CanonicalJid::parse_bare("alice@example.test").unwrap();
    let service = northstar_xmpp_types::CanonicalJid::parse_bare("push.example.test").unwrap();
    let node = PushNode::new("device-1").unwrap();

    let key = PushCoalesceKey::new(user, service, Some(node));
    let key_str = key.to_key_string();

    let parsed = PushCoalesceKey::parse(&key_str).unwrap();
    assert_eq!(key, parsed);
    assert_eq!(key_str, parsed.to_key_string());
}

#[test]
fn coalesce_key_without_node() {
    let user = northstar_xmpp_types::CanonicalJid::parse_bare("alice@example.test").unwrap();
    let service = northstar_xmpp_types::CanonicalJid::parse_bare("push.example.test").unwrap();

    let key = PushCoalesceKey::new(user, service, None);
    let key_str = key.to_key_string();
    assert!(key_str.ends_with('\0'));

    let parsed = PushCoalesceKey::parse(&key_str).unwrap();
    assert!(parsed.node().is_none());
    assert_eq!(key, parsed);
}

#[test]
fn coalesce_key_parse_rejects_invalid() {
    assert!(PushCoalesceKey::parse("invalid").is_err());
    assert!(PushCoalesceKey::parse("a\0b").is_err());
    assert!(PushCoalesceKey::parse("a\0b\0c\0d").is_err());
}

// ──────────────────────────────────────────────────────────────────────────────
// XML escaping
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn xml_escaping_attribute_values() {
    let xml = build_enable("push.example.test", Some("device&<>'\"1"), None);
    assert!(xml.contains("&amp;"));
    assert!(xml.contains("&lt;"));
    assert!(xml.contains("&gt;"));
    assert!(xml.contains("&apos;"));
    assert!(xml.contains("&quot;"));

    // Verify it round-trips through roxmltree
    let doc = Document::parse(&xml).unwrap();
    let enable = doc.root_element();
    assert_eq!(enable.attribute("node").unwrap(), "device&<>'\"1");
}

#[test]
fn notification_iq_escaping() {
    let summary = PushSummary::new().with_message_count(1);
    let xml = build_notification_iq(
        "server.example",
        "push.example.test",
        "push-<evil>",
        Some("node&amp;"),
        &summary,
        None,
    )
    .unwrap();
    assert!(xml.contains("&lt;evil&gt;"));
    assert!(xml.contains("&amp;amp;"));
}

// ──────────────────────────────────────────────────────────────────────────────
// Error mapping
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn error_stanza_error_mapping() {
    let err = PushError::BadRequest("test".to_owned());
    assert_eq!(err.as_stanza_error_condition(), "bad-request");
    assert_eq!(err.stanza_error_type(), "modify");

    let err = PushError::JidMalformed("test".to_owned());
    assert_eq!(err.as_stanza_error_condition(), "jid-malformed");
    assert_eq!(err.stanza_error_type(), "modify");

    let err = PushError::ResourceConstraint("test".to_owned());
    assert_eq!(err.as_stanza_error_condition(), "resource-constraint");
    assert_eq!(err.stanza_error_type(), "wait");

    let err = PushError::NotAllowed("test".to_owned());
    assert_eq!(err.as_stanza_error_condition(), "not-allowed");
    assert_eq!(err.stanza_error_type(), "cancel");

    let err = PushError::NotAuthorized("test".to_owned());
    assert_eq!(err.as_stanza_error_condition(), "not-authorized");
    assert_eq!(err.stanza_error_type(), "auth");
}

#[test]
fn error_xml_generation() {
    let err = PushError::BadRequest("test".to_owned());
    let xml = err.to_stanza_error_xml();
    assert!(xml.contains("<error type='modify'>"));
    assert!(xml.contains("<bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>"));
}

// ──────────────────────────────────────────────────────────────────────────────
// Publish options validation
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn publish_options_rejects_empty_form() {
    let xml = "<x xmlns='jabber:x:data' type='submit'/>";
    assert!(PublishOptions::parse_xml(xml).is_err());
}

#[test]
fn publish_options_rejects_wrong_submit_type() {
    let xml = "<x xmlns='jabber:x:data' type='result'>\
        <field var='FORM_TYPE'><value>http://jabber.org/protocol/pubsub#publish-options</value></field>\
    </x>";
    assert!(PublishOptions::parse_xml(xml).is_err());
}

#[test]
fn publish_options_rejects_duplicate_var() {
    let xml = "<x xmlns='jabber:x:data' type='submit'>\
        <field var='FORM_TYPE'><value>http://jabber.org/protocol/pubsub#publish-options</value></field>\
        <field var='key'><value>a</value></field>\
        <field var='key'><value>b</value></field>\
    </x>";
    assert!(PublishOptions::parse_xml(xml).is_err());
}

#[test]
fn publish_options_valid_round_trip() {
    let xml = "<x xmlns='jabber:x:data' type='submit'>\
        <field var='FORM_TYPE'><value>http://jabber.org/protocol/pubsub#publish-options</value></field>\
        <field var='secret'><value>tok123</value></field>\
    </x>";
    let opts = PublishOptions::parse_xml(xml).unwrap();
    assert_eq!(opts.get_value("secret"), Some("tok123"));

    let rebuilt = opts.to_xml();
    let reparsed = PublishOptions::parse_xml(&rebuilt).unwrap();
    assert_eq!(reparsed.get_value("secret"), Some("tok123"));
}

// ──────────────────────────────────────────────────────────────────────────────
// Delivery response types
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn delivery_response_types_are_distinct() {
    assert_ne!(
        DeliveryResponseKind::Success,
        DeliveryResponseKind::PermanentError
    );
    assert_ne!(
        DeliveryResponseKind::PermanentError,
        DeliveryResponseKind::TransientError
    );
    assert_ne!(
        DeliveryResponseOutcome::Completed,
        DeliveryResponseOutcome::SubscriptionDisabled
    );
    assert_ne!(
        DeliveryResponseOutcome::SenderMismatch,
        DeliveryResponseOutcome::Unknown
    );
    assert_ne!(
        DeliveryResponseOutcome::Expired,
        DeliveryResponseOutcome::Completed
    );
}

// ──────────────────────────────────────────────────────────────────────────────
// Notification IQ payload parsing
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn notification_iq_payload_round_trip() {
    let summary = PushSummary::new()
        .with_message_count(7)
        .with_pending_subscription_count(0);

    let iq_xml = build_notification_iq(
        "server.test",
        "push.test",
        "push-abc",
        Some("dev-1"),
        &summary,
        None,
    )
    .unwrap();

    // Extract the pubsub element from the IQ
    let doc = Document::parse(&iq_xml).unwrap();
    let pubsub = doc
        .root_element()
        .children()
        .find(|c| c.is_element() && c.tag_name().name() == "pubsub")
        .unwrap();

    let (node, parsed_summary) = parse_notification_iq_payload(pubsub).unwrap();
    assert_eq!(node.as_deref(), Some("dev-1"));
    assert_eq!(parsed_summary.message_count, Some(7));
    assert_eq!(parsed_summary.pending_subscription_count, Some(0));
}
