#![forbid(unsafe_code)]

use northstar_xep_0352::error::{PolicyError, WireError};
use northstar_xep_0352::policy::{
    canonicalize_jid, classify_stanza, CoalescingKey, CsiPolicyConfig, DeliveryAction,
    OverflowPolicy, StanzaMetadata,
};
use northstar_xep_0352::queue::{DeferredQueue, EnqueueResult, OverflowDecision};
use northstar_xep_0352::state::{CsiState, CsiStateMachine, TransitionOutcome};
use northstar_xep_0352::wire::{
    build_active, build_inactive, build_indication, build_stream_feature, is_valid_indication_node,
    parse_indication, parse_indication_node, CsiIndication,
};
use roxmltree::Document;

#[test]
fn test_wire_valid_indications() {
    let active_xml = "<active xmlns='urn:xmpp:csi:0'/>";
    let inactive_xml = "<inactive xmlns='urn:xmpp:csi:0'></inactive>";

    let parsed_active = parse_indication(active_xml).expect("parse active");
    assert_eq!(parsed_active, CsiIndication::Active);
    assert!(parsed_active.is_active());
    assert!(!parsed_active.is_inactive());
    assert_eq!(parsed_active.local_name(), "active");

    let parsed_inactive = parse_indication(inactive_xml).expect("parse inactive");
    assert_eq!(parsed_inactive, CsiIndication::Inactive);
    assert!(parsed_inactive.is_inactive());
    assert!(!parsed_inactive.is_active());
    assert_eq!(parsed_inactive.local_name(), "inactive");

    let doc_active = Document::parse(active_xml).unwrap();
    assert!(is_valid_indication_node(doc_active.root_element()));

    let doc_inactive = Document::parse(inactive_xml).unwrap();
    assert!(is_valid_indication_node(doc_inactive.root_element()));
}

#[test]
fn test_wire_rejects_malformed_and_non_empty_indications() {
    // Attributes not permitted
    let attr_xml = "<active xmlns='urn:xmpp:csi:0' id='unexpected'/>";
    let doc = Document::parse(attr_xml).unwrap();
    assert!(!is_valid_indication_node(doc.root_element()));
    assert_eq!(
        parse_indication_node(doc.root_element()),
        Err(WireError::AttributesNotPermitted)
    );

    // Whitespace / text not permitted
    let text_xml = "<inactive xmlns='urn:xmpp:csi:0'> </inactive>";
    let doc = Document::parse(text_xml).unwrap();
    assert!(!is_valid_indication_node(doc.root_element()));
    assert_eq!(
        parse_indication_node(doc.root_element()),
        Err(WireError::TextContentNotPermitted)
    );

    // Child elements not permitted
    let child_xml = "<active xmlns='urn:xmpp:csi:0'><child/></active>";
    let doc = Document::parse(child_xml).unwrap();
    assert!(!is_valid_indication_node(doc.root_element()));
    assert_eq!(
        parse_indication_node(doc.root_element()),
        Err(WireError::ChildrenNotPermitted)
    );

    // Wrong namespace
    let wrong_ns_xml = "<active xmlns='urn:wrong:ns'/>";
    let doc = Document::parse(wrong_ns_xml).unwrap();
    assert!(!is_valid_indication_node(doc.root_element()));
    assert!(matches!(
        parse_indication_node(doc.root_element()),
        Err(WireError::UnexpectedNamespace { .. })
    ));

    // Wrong tag name
    let wrong_tag_xml = "<unknown xmlns='urn:xmpp:csi:0'/>";
    let doc = Document::parse(wrong_tag_xml).unwrap();
    assert!(!is_valid_indication_node(doc.root_element()));
    assert!(matches!(
        parse_indication_node(doc.root_element()),
        Err(WireError::UnexpectedTagName { .. })
    ));

    // Non-XML
    assert!(matches!(
        parse_indication("<not xml"),
        Err(WireError::MalformedXml(_))
    ));
}

#[test]
fn test_wire_builders_roundtrip() {
    assert_eq!(build_active(), "<active xmlns='urn:xmpp:csi:0'/>");
    assert_eq!(build_inactive(), "<inactive xmlns='urn:xmpp:csi:0'/>");
    assert_eq!(
        build_indication(CsiIndication::Active),
        "<active xmlns='urn:xmpp:csi:0'/>"
    );
    assert_eq!(
        build_indication(CsiIndication::Inactive),
        "<inactive xmlns='urn:xmpp:csi:0'/>"
    );
    assert_eq!(build_stream_feature(), "<csi xmlns='urn:xmpp:csi:0'/>");

    assert_eq!(
        parse_indication(build_active()).unwrap(),
        CsiIndication::Active
    );
    assert_eq!(
        parse_indication(build_inactive()).unwrap(),
        CsiIndication::Inactive
    );
}

#[test]
fn test_state_machine_transitions_and_duplicates() {
    let mut sm = CsiStateMachine::new();
    assert_eq!(sm.state(), CsiState::Active);
    assert!(sm.is_active());
    assert!(!sm.is_inactive());
    assert_eq!(sm.transition_count(), 0);

    // Duplicate transition to Active
    let res = sm.apply_indication(CsiIndication::Active);
    assert_eq!(
        res,
        TransitionOutcome::Unchanged {
            state: CsiState::Active
        }
    );
    assert!(res.is_duplicate());
    assert!(!res.is_changed());
    assert_eq!(sm.transition_count(), 0);

    // Transition to Inactive
    let res = sm.apply_indication(CsiIndication::Inactive);
    assert_eq!(
        res,
        TransitionOutcome::Changed {
            from: CsiState::Active,
            to: CsiState::Inactive,
        }
    );
    assert!(res.is_changed());
    assert!(res.is_inactivation());
    assert!(!res.is_activation());
    assert_eq!(sm.state(), CsiState::Inactive);
    assert!(sm.is_inactive());
    assert_eq!(sm.transition_count(), 1);

    // Duplicate transition to Inactive
    let res = sm.set_inactive();
    assert_eq!(
        res,
        TransitionOutcome::Unchanged {
            state: CsiState::Inactive
        }
    );
    assert_eq!(sm.transition_count(), 1);

    // Transition to Active
    let res = sm.set_active();
    assert_eq!(
        res,
        TransitionOutcome::Changed {
            from: CsiState::Inactive,
            to: CsiState::Active,
        }
    );
    assert!(res.is_activation());
    assert_eq!(sm.state(), CsiState::Active);
    assert_eq!(sm.transition_count(), 2);

    // Reset
    sm.reset();
    assert_eq!(sm.state(), CsiState::Active);
    assert_eq!(sm.transition_count(), 0);

    // Custom initial state
    let sm_init = CsiStateMachine::with_initial_state(CsiState::Inactive);
    assert_eq!(sm_init.state(), CsiState::Inactive);
    assert!(sm_init.is_inactive());
}

#[test]
fn test_jid_canonicalization_preserves_resource_case() {
    assert_eq!(
        canonicalize_jid("ALICE@Example.test/Phone").unwrap(),
        "alice@example.test/Phone"
    );
    assert_eq!(
        canonicalize_jid("alice@example.test/phone").unwrap(),
        "alice@example.test/phone"
    );
    assert_ne!(
        canonicalize_jid("ALICE@Example.test/Phone").unwrap(),
        canonicalize_jid("alice@example.test/phone").unwrap()
    );
    assert_eq!(
        canonicalize_jid("BOB@EXAMPLE.ORG").unwrap(),
        "bob@example.org"
    );
    assert_eq!(
        canonicalize_jid("SERVER.ORG/Resource").unwrap(),
        "server.org/Resource"
    );
    assert_eq!(canonicalize_jid(""), None);
}

#[test]
fn test_policy_classification_presence_coalescing() {
    let config = CsiPolicyConfig::default();
    let meta = StanzaMetadata::transient();

    let p1 = "<presence from='alice@example.test/Phone'/>";
    let p2 = "<presence from='ALICE@Example.test/Phone'><show>away</show></presence>";
    let p3 = "<presence from='alice@example.test/Tablet' type='unavailable'/>";

    let c1 = classify_stanza(p1, &meta, &config);
    let c2 = classify_stanza(p2, &meta, &config);
    let c3 = classify_stanza(p3, &meta, &config);

    assert_eq!(
        c1,
        DeliveryAction::Defer(CoalescingKey::presence("alice@example.test/Phone"))
    );
    assert_eq!(
        c2,
        DeliveryAction::Defer(CoalescingKey::presence("alice@example.test/Phone"))
    );
    assert_eq!(
        c3,
        DeliveryAction::Defer(CoalescingKey::presence("alice@example.test/Tablet"))
    );

    // Subscription & probe presences are immediate
    for non_deferrable in [
        "<presence from='alice@example.test' type='subscribe'/>",
        "<presence from='alice@example.test' type='subscribed'/>",
        "<presence from='alice@example.test' type='unsubscribe'/>",
        "<presence from='alice@example.test' type='unsubscribed'/>",
        "<presence from='alice@example.test' type='probe'/>",
        "<presence from='alice@example.test' type='error'/>",
    ] {
        assert_eq!(
            classify_stanza(non_deferrable, &meta, &config),
            DeliveryAction::Immediate,
            "failed on {non_deferrable}"
        );
    }
}

#[test]
fn test_policy_classification_chat_states() {
    let config = CsiPolicyConfig::default();
    let meta = StanzaMetadata::transient();

    let composing = "<message from='bob@example.test/Phone'><composing xmlns='http://jabber.org/protocol/chatstates'/></message>";
    let paused = "<message from='bob@example.test/Phone'><paused xmlns='http://jabber.org/protocol/chatstates'/><stanza-id xmlns='urn:xmpp:sid:0' id='1' by='s@example.test'/></message>";
    let with_body = "<message from='bob@example.test/Phone'><body>Hello!</body><composing xmlns='http://jabber.org/protocol/chatstates'/></message>";
    let receipt = "<message from='bob@example.test/Phone'><received xmlns='urn:xmpp:receipts' id='1'/></message>";

    assert_eq!(
        classify_stanza(composing, &meta, &config),
        DeliveryAction::Defer(CoalescingKey::chat_state("bob@example.test/Phone"))
    );
    assert_eq!(
        classify_stanza(paused, &meta, &config),
        DeliveryAction::Defer(CoalescingKey::chat_state("bob@example.test/Phone"))
    );
    assert_eq!(
        classify_stanza(with_body, &meta, &config),
        DeliveryAction::Immediate
    );
    assert_eq!(
        classify_stanza(receipt, &meta, &config),
        DeliveryAction::Immediate
    );

    // Discard typing policy
    let discard_config = CsiPolicyConfig {
        discard_typing_on_inactive: true,
        ..CsiPolicyConfig::default()
    };
    assert_eq!(
        classify_stanza(composing, &meta, &discard_config),
        DeliveryAction::Discard
    );
    assert_eq!(
        classify_stanza(paused, &meta, &discard_config),
        DeliveryAction::Discard
    );

    let active_state = "<message from='bob@example.test/Phone'><active xmlns='http://jabber.org/protocol/chatstates'/></message>";
    assert_eq!(
        classify_stanza(active_state, &meta, &discard_config),
        DeliveryAction::Defer(CoalescingKey::chat_state("bob@example.test/Phone"))
    );
}

#[test]
fn test_policy_classification_pep_events() {
    let config = CsiPolicyConfig::default();
    let meta = StanzaMetadata::transient();

    let item_one = "<message from='pub@example.test'><event xmlns='http://jabber.org/protocol/pubsub#event'><items node='urn:test'><item id='one'><payload/></item></items></event></message>";
    let item_one_replaced = "<message from='pub@example.test'><event xmlns='http://jabber.org/protocol/pubsub#event'><items node='urn:test'><item id='one'><different_payload/></item></items></event></message>";
    let item_two = "<message from='pub@example.test'><event xmlns='http://jabber.org/protocol/pubsub#event'><items node='urn:test'><item id='two'/></items></event></message>";

    let key1 = match classify_stanza(item_one, &meta, &config) {
        DeliveryAction::Defer(key) => key,
        other => panic!("expected defer, got {other:?}"),
    };
    let key2 = match classify_stanza(item_one_replaced, &meta, &config) {
        DeliveryAction::Defer(key) => key,
        other => panic!("expected defer, got {other:?}"),
    };
    let key3 = match classify_stanza(item_two, &meta, &config) {
        DeliveryAction::Defer(key) => key,
        other => panic!("expected defer, got {other:?}"),
    };

    assert_eq!(key1, key2);
    assert_ne!(key1, key3);

    // Critical pubsub events bypass deferral
    for critical in [
        "<message from='pub@example.test'><event xmlns='http://jabber.org/protocol/pubsub#event'><subscription node='urn:test' subscription='none'/></event></message>",
        "<message from='pub@example.test'><event xmlns='http://jabber.org/protocol/pubsub#event'><delete node='urn:test'/></event></message>",
        "<message from='pub@example.test'><event xmlns='http://jabber.org/protocol/pubsub#event'><purge node='urn:test'/></event></message>",
    ] {
        assert_eq!(
            classify_stanza(critical, &meta, &config),
            DeliveryAction::Immediate,
            "failed on {critical}"
        );
    }
}

#[test]
fn test_important_stanzas_and_durable_fences_bypass_deferral() {
    let config = CsiPolicyConfig::default();

    // Durable metadata bypass
    let durable_meta = StanzaMetadata::durable();
    let soft_presence = "<presence from='alice@example.test/Phone'/>";
    assert_eq!(
        classify_stanza(soft_presence, &durable_meta, &config),
        DeliveryAction::Immediate
    );

    // Transport receipt metadata bypass
    let receipt_meta = StanzaMetadata::transport_receipt();
    assert_eq!(
        classify_stanza(soft_presence, &receipt_meta, &config),
        DeliveryAction::Immediate
    );

    // IQ stanzas bypass deferral
    let meta = StanzaMetadata::transient();
    assert_eq!(
        classify_stanza(
            "<iq type='get' from='alice@example.test/Phone' id='1'/>",
            &meta,
            &config
        ),
        DeliveryAction::Immediate
    );
    assert_eq!(
        classify_stanza(
            "<iq type='set' from='alice@example.test/Phone' id='2'/>",
            &meta,
            &config
        ),
        DeliveryAction::Immediate
    );
}

#[test]
fn test_deferred_queue_coalescing_and_fifo_flush_ordering() {
    let mut queue = DeferredQueue::<String>::with_bounds(10, 1024);

    let p1 = "<presence from='bob@example.test/Phone'><show>away</show></presence>".to_owned();
    let c1 = "<message from='bob@example.test/Phone'><composing xmlns='http://jabber.org/protocol/chatstates'/></message>".to_owned();
    let c2 = "<message from='bob@example.test/Phone'><paused xmlns='http://jabber.org/protocol/chatstates'/></message>".to_owned();
    let p2 = "<presence from='alice@example.test/Phone'/>".to_owned();

    let p_key = Some(CoalescingKey::presence("bob@example.test/Phone"));
    let c_key = Some(CoalescingKey::chat_state("bob@example.test/Phone"));
    let a_key = Some(CoalescingKey::presence("alice@example.test/Phone"));

    // Enqueue p1
    let r1 = queue.enqueue(p1.clone(), p1.len(), p_key.clone());
    assert_eq!(
        r1,
        EnqueueResult::Enqueued {
            replaced_previous: None
        }
    );
    assert_eq!(queue.len(), 1);

    // Enqueue c1
    let r2 = queue.enqueue(c1.clone(), c1.len(), c_key.clone());
    assert_eq!(
        r2,
        EnqueueResult::Enqueued {
            replaced_previous: None
        }
    );
    assert_eq!(queue.len(), 2);

    // Enqueue p2 (Alice)
    let r3 = queue.enqueue(p2.clone(), p2.len(), a_key.clone());
    assert_eq!(
        r3,
        EnqueueResult::Enqueued {
            replaced_previous: None
        }
    );
    assert_eq!(queue.len(), 3);

    // Enqueue c2 (coalesces with c1 in-place!)
    let r4 = queue.enqueue(c2.clone(), c2.len(), c_key.clone());
    assert_eq!(
        r4,
        EnqueueResult::Enqueued {
            replaced_previous: Some(c1.clone())
        }
    );
    assert_eq!(queue.len(), 3);

    // Activation flush returns items in deterministic FIFO insertion order (p1, c2, p2)
    let flushed = queue.drain_all();
    assert_eq!(flushed.len(), 3);
    assert_eq!(flushed[0], p1);
    assert_eq!(flushed[1], c2);
    assert_eq!(flushed[2], p2);

    assert_eq!(queue.len(), 0);
    assert_eq!(queue.total_bytes(), 0);
    assert!(queue.is_empty());
}

#[test]
fn test_no_silent_loss_overflow_policies() {
    // 1. Disconnect on overflow
    let config_disc = CsiPolicyConfig {
        max_deferred_stanzas: 2,
        overflow_policy: OverflowPolicy::Disconnect,
        ..CsiPolicyConfig::default()
    };
    let mut q_disc = DeferredQueue::<String>::new(config_disc);

    assert!(q_disc.enqueue("item1".into(), 5, None).is_enqueued());
    assert!(q_disc.enqueue("item2".into(), 5, None).is_enqueued());
    let r3 = q_disc.enqueue("item3".into(), 5, None);
    assert_eq!(
        r3,
        EnqueueResult::Overflow {
            decision: OverflowDecision::Disconnect {
                unhandled_item: "item3".into(),
                queued_count: 2,
                queued_bytes: 10,
            }
        }
    );
    assert_eq!(q_disc.len(), 2);

    // 2. Reject on overflow
    let config_rej = CsiPolicyConfig {
        max_deferred_stanzas: 2,
        overflow_policy: OverflowPolicy::Reject,
        ..CsiPolicyConfig::default()
    };
    let mut q_rej = DeferredQueue::<String>::new(config_rej);

    assert!(q_rej.enqueue("item1".into(), 5, None).is_enqueued());
    assert!(q_rej.enqueue("item2".into(), 5, None).is_enqueued());
    let r_rej = q_rej.enqueue("item3".into(), 5, None);
    assert_eq!(
        r_rej,
        EnqueueResult::Overflow {
            decision: OverflowDecision::Reject {
                rejected_item: "item3".into(),
            }
        }
    );
    assert_eq!(q_rej.len(), 2);

    // 3. Persist on overflow
    let config_pers = CsiPolicyConfig {
        max_deferred_stanzas: 2,
        overflow_policy: OverflowPolicy::Persist,
        ..CsiPolicyConfig::default()
    };
    let mut q_pers = DeferredQueue::<String>::new(config_pers);

    assert!(q_pers.enqueue("item1".into(), 5, None).is_enqueued());
    assert!(q_pers.enqueue("item2".into(), 5, None).is_enqueued());
    let r_pers = q_pers.enqueue("item3".into(), 5, None);
    assert_eq!(
        r_pers,
        EnqueueResult::Overflow {
            decision: OverflowDecision::Persist {
                item_to_persist: "item3".into(),
            }
        }
    );
    assert_eq!(q_pers.len(), 2);

    // 4. DropOldest (evicts and returns items explicitly to caller/adapter)
    let config_drop = CsiPolicyConfig {
        max_deferred_stanzas: 2,
        overflow_policy: OverflowPolicy::DropOldest,
        ..CsiPolicyConfig::default()
    };
    let mut q_drop = DeferredQueue::<String>::new(config_drop);

    assert!(q_drop.enqueue("item1".into(), 5, None).is_enqueued());
    assert!(q_drop.enqueue("item2".into(), 5, None).is_enqueued());
    let r_drop = q_drop.enqueue("item3".into(), 5, None);
    assert_eq!(
        r_drop,
        EnqueueResult::Overflow {
            decision: OverflowDecision::EvictedOldest {
                evicted: vec!["item1".into()],
                replaced_previous: None,
            }
        }
    );
    assert_eq!(q_drop.len(), 2);
    let remaining = q_drop.drain_all();
    assert_eq!(remaining, vec!["item2".to_string(), "item3".to_string()]);
}

#[test]
fn test_byte_limit_overflow_enforcement() {
    let config = CsiPolicyConfig {
        max_deferred_stanzas: 100,
        max_deferred_bytes: 20,
        overflow_policy: OverflowPolicy::DropOldest,
        ..CsiPolicyConfig::default()
    };
    let mut queue = DeferredQueue::<String>::new(config);

    assert!(queue.enqueue("12345678".into(), 8, None).is_enqueued()); // 8 bytes
    assert!(queue.enqueue("12345678".into(), 8, None).is_enqueued()); // 16 bytes
    assert_eq!(queue.total_bytes(), 16);

    // Adding 8 more bytes would exceed 20 bytes -> evicts first 8-byte entry
    let res = queue.enqueue("abcdefgh".into(), 8, None);
    assert_eq!(
        res,
        EnqueueResult::Overflow {
            decision: OverflowDecision::EvictedOldest {
                evicted: vec!["12345678".into()],
                replaced_previous: None,
            }
        }
    );
    assert_eq!(queue.total_bytes(), 16);
    assert_eq!(queue.len(), 2);
}

#[test]
fn test_policy_config_validation() {
    let mut valid = CsiPolicyConfig::default();
    assert_eq!(valid.validate(), Ok(()));

    valid.max_deferred_stanzas = 0;
    assert_eq!(valid.validate(), Err(PolicyError::ZeroMaxStanzas));

    valid.max_deferred_stanzas = 10;
    valid.max_deferred_bytes = 0;
    assert_eq!(valid.validate(), Err(PolicyError::ZeroMaxBytes));
}
