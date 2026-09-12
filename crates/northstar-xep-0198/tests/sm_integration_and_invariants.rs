#![forbid(unsafe_code)]

use northstar_xep_0198::*;
use northstar_xep_core::{resolve_features, FeatureSelection};
use roxmltree::Document;

#[test]
fn feature_catalog_resolution_integration() {
    let resolution = resolve_features(&[&DESCRIPTOR], &FeatureSelection::default());
    assert!(resolution.is_enabled(XEP_ID));
    assert_eq!(resolution.disco_features, vec![NAMESPACE]);
    assert_eq!(resolution.routes.len(), 4);
    assert_eq!(resolution.routes[0].1.local_name, "a");
    assert_eq!(resolution.routes[1].1.local_name, "enable");
    assert_eq!(resolution.routes[2].1.local_name, "r");
    assert_eq!(resolution.routes[3].1.local_name, "resume");
}

#[test]
fn wire_strictness_and_malformed_input_rejections() {
    // 1. Tag name / Namespace mismatch
    let doc = Document::parse("<wrong xmlns='urn:xmpp:sm:3'/>").unwrap();
    assert!(matches!(
        parse_enable(doc.root_element()),
        Err(WireError::UnexpectedTagName { .. })
    ));

    let doc = Document::parse("<enable xmlns='urn:wrong:ns'/>").unwrap();
    assert!(matches!(
        parse_enable(doc.root_element()),
        Err(WireError::UnexpectedNamespace { .. })
    ));

    // 2. Disallowed attributes
    let doc = Document::parse("<enable xmlns='urn:xmpp:sm:3' custom_attr='evil'/>").unwrap();
    assert!(matches!(
        parse_enable(doc.root_element()),
        Err(WireError::DisallowedAttribute(_))
    ));

    let doc =
        Document::parse("<resume xmlns='urn:xmpp:sm:3' previd='p1' h='0' extra='bad'/>").unwrap();
    assert!(matches!(
        parse_resume(doc.root_element()),
        Err(WireError::DisallowedAttribute(_))
    ));

    // 3. Child elements not permitted in SM controls
    let doc = Document::parse("<r xmlns='urn:xmpp:sm:3'><nested/></r>").unwrap();
    assert!(matches!(
        parse_r(doc.root_element()),
        Err(WireError::UnexpectedChildElements)
    ));

    // 4. Unexpected non-whitespace text
    let doc = Document::parse("<a xmlns='urn:xmpp:sm:3' h='5'>hello</a>").unwrap();
    assert!(parse_a(doc.root_element()).is_err());

    // 5. Malformed/Empty previd
    let doc = Document::parse("<resume xmlns='urn:xmpp:sm:3' previd='' h='5'/>").unwrap();
    assert!(matches!(
        parse_resume(doc.root_element()),
        Err(WireError::InvalidPrevid(_))
    ));

    // 6. Previd containing whitespace or control chars
    let doc = Document::parse("<resume xmlns='urn:xmpp:sm:3' previd='bad token' h='5'/>").unwrap();
    assert!(matches!(
        parse_resume(doc.root_element()),
        Err(WireError::InvalidPrevid(_))
    ));

    // 7. Location URI exceeding max bytes or containing whitespace
    let long_location = "a".repeat(MAX_LOCATION_BYTES + 1);
    let doc_str = format!("<enable xmlns='urn:xmpp:sm:3' location='{long_location}'/>");
    let doc = Document::parse(&doc_str).unwrap();
    assert!(matches!(
        parse_enable(doc.root_element()),
        Err(WireError::InvalidLocation(_))
    ));
}

#[test]
fn counter_wraparound_comprehensive_invariants() {
    let mut sent = SmCounter::new(u32::MAX - 2);
    let mut acked = SmCounter::new(u32::MAX - 2);

    // Outstanding = 5 stanzas sent across wrap
    sent.advance_by(5); // sent is now 2
    assert_eq!(sent.get(), 2);

    // Remote acknowledges 3 stanzas -> received is (u32::MAX + 1) % 2^32 = 0
    let delta = SmCounter::validate_ack(acked, SmCounter::new(0), 5, sent).unwrap();
    assert_eq!(delta, 3); // (MAX-2) to 0 is 3
    acked = SmCounter::new(0);

    // Remote acknowledges up to 2 -> remaining 2 stanzas
    let delta2 = SmCounter::validate_ack(acked, SmCounter::new(2), 2, sent).unwrap();
    assert_eq!(delta2, 2);
    acked = SmCounter::new(2);

    // Duplicate acknowledgement (delta 0)
    let delta_dup = SmCounter::validate_ack(acked, SmCounter::new(2), 0, sent).unwrap();
    assert_eq!(delta_dup, 0);

    // Impossible/future acknowledgement (received 3 when sent is 2, outstanding is 0)
    let ahead_err = SmCounter::validate_ack(acked, SmCounter::new(3), 0, sent);
    assert!(matches!(
        ahead_err,
        Err(AckError::HandledCountTooHigh {
            received: 3,
            sent: 2,
            outstanding: 0,
        })
    ));

    // Stale acknowledgement (received 1 when last acked is already 2)
    let stale_err = SmCounter::validate_ack(acked, SmCounter::new(1), 0, sent);
    assert!(matches!(
        stale_err,
        Err(AckError::HandledCountTooHigh { .. })
    ));
}

#[test]
fn replay_fifo_ordering_and_multi_cycle_resumption() {
    let mut sm = SmStateMachine::new(100, 10_000);
    let enable_req = EnableElement {
        resume: true,
        max: Some(120),
        location: None,
    };
    let config = EnableConfig::default();
    sm.enable(
        &enable_req,
        &config,
        Some("stable-resume-token".into()),
        false,
    )
    .unwrap();

    // Send 5 distinct stanzas
    for i in 1..=5 {
        sm.record_outbound_stanza(format!("<stanza id='{i}'/>"), 20)
            .unwrap();
    }

    // Ack first 2 stanzas
    let acked = sm.handle_ack_answer(SmCounter::new(2)).unwrap();
    assert_eq!(acked.len(), 2);
    assert_eq!(acked[0].payload, "<stanza id='1'/>");
    assert_eq!(acked[1].payload, "<stanza id='2'/>");

    // Inbound stanzas
    sm.record_inbound_stanza().unwrap();
    sm.record_inbound_stanza().unwrap();
    sm.record_inbound_stanza().unwrap();

    // Connection drops at time 5000
    sm.suspend(5000).unwrap();
    assert!(sm.is_suspended());

    // First Resume: client saw stanza 3 while in flight (sends h=3)
    let resume_req = ResumeElement {
        previd: "stable-resume-token".into(),
        h: SmCounter::new(3),
    };
    let outcome = sm.resume(&resume_req, 5030).unwrap();
    assert_eq!(outcome.resumed_element.h.get(), 3);
    assert_eq!(outcome.acknowledged_on_resume.len(), 1);
    assert_eq!(
        outcome.acknowledged_on_resume[0].payload,
        "<stanza id='3'/>"
    );
    assert_eq!(
        outcome.replay_stanzas,
        vec!["<stanza id='4'/>", "<stanza id='5'/>"]
    );
    assert!(sm.is_active());

    // Exchange more stanzas on resumed stream
    sm.record_outbound_stanza("<stanza id='6'/>".into(), 20)
        .unwrap();
    sm.record_inbound_stanza().unwrap(); // inbound_h is now 4

    // Second Disconnect at time 6000
    sm.suspend(6000).unwrap();
    assert!(sm.is_suspended());

    // Second Resume at time 6050
    let resume_req2 = ResumeElement {
        previd: "stable-resume-token".into(),
        h: SmCounter::new(5), // Client saw stanzas 4 and 5
    };
    let outcome2 = sm.resume(&resume_req2, 6050).unwrap();
    assert_eq!(outcome2.resumed_element.h.get(), 4);
    assert_eq!(outcome2.acknowledged_on_resume.len(), 2);
    assert_eq!(
        outcome2.acknowledged_on_resume[0].payload,
        "<stanza id='4'/>"
    );
    assert_eq!(
        outcome2.acknowledged_on_resume[1].payload,
        "<stanza id='5'/>"
    );
    assert_eq!(outcome2.replay_stanzas, vec!["<stanza id='6'/>"]);
}

#[test]
fn suspension_exact_expiry_boundaries() {
    let mut sm = SmStateMachine::new(10, 1000);
    sm.enable(
        &EnableElement {
            resume: true,
            max: Some(30),
            location: None,
        },
        &EnableConfig::default(),
        Some("tok".into()),
        false,
    )
    .unwrap();

    // Suspend at t = 1000, expires at t = 1030
    sm.suspend(1000).unwrap();

    // At t = 1030, exact boundary is valid (not yet strictly > 1030)
    assert!(!sm.check_expiry(1030));
    assert!(sm.is_suspended());

    // At t = 1031, expiry triggers
    assert!(sm.check_expiry(1031));
    assert_eq!(sm.state(), &SmState::Expired { expires_at: 1030 });
}

#[test]
fn handled_count_too_high_stream_error_structure() {
    let error_xml = build_handled_count_too_high_stream_error(100, 50);
    let doc = Document::parse(&error_xml).unwrap();
    let root = doc.root_element();
    assert_eq!(root.tag_name().name(), "error");
    assert_eq!(
        root.tag_name().namespace(),
        Some("http://etherx.jabber.org/streams")
    );

    let undefined = root
        .children()
        .find(|c| c.tag_name().name() == "undefined-condition")
        .unwrap();
    assert_eq!(
        undefined.tag_name().namespace(),
        Some("urn:ietf:params:xml:ns:xmpp-streams")
    );

    let count_err = root
        .children()
        .find(|c| c.tag_name().name() == "handled-count-too-high")
        .unwrap();
    assert_eq!(count_err.tag_name().namespace(), Some("urn:xmpp:sm:3"));
    assert_eq!(count_err.attribute("h"), Some("100"));
    assert_eq!(count_err.attribute("send-count"), Some("50"));
}
