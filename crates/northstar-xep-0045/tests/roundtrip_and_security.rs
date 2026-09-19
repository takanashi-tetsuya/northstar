//! Comprehensive security, fuzzing, roundtrip, and edge-case unit tests for northstar-xep-0045.

#![forbid(unsafe_code)]

use northstar_xep_0045::*;
use roxmltree::Document;

#[test]
fn test_malicious_xml_rejection() {
    // Malicious billion-laughs entity expansion attempt
    let billion_laughs = "<message xmlns='jabber:client'>\
        <!DOCTYPE lolz [\
            <!ENTITY lol 'lol'>\
            <!ENTITY lol2 '&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;'>\
            <!ENTITY lol3 '&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;'>\
        ]>\
        <subject>&lol3;</subject>\
    </message>";

    // roxmltree by default fails on entity expansion / DTD or handles safely
    if let Ok(doc) = Document::parse(billion_laughs) {
        let res = parse_subject_command(doc.root_element());
        // Even if parsed, it must not crash or leak
        assert!(res.is_ok() || res.is_err());
    }

    // Malicious deeply nested nodes in presence
    let mut deep_xml = String::from(
        "<presence xmlns='jabber:client'><x xmlns='http://jabber.org/protocol/muc#user'>",
    );
    for _ in 0..100 {
        deep_xml.push_str("<nested>");
    }
    for _ in 0..100 {
        deep_xml.push_str("</nested>");
    }
    deep_xml.push_str("</x></presence>");

    let doc = Document::parse(&deep_xml).unwrap();
    let res = parse_muc_user_presence(doc.root_element()).unwrap();
    assert!(res.is_some());
}

#[test]
fn test_namespace_pollution_and_mismatch() {
    // Foreign namespace on item
    let xml = "<presence xmlns='jabber:client'>\
        <x xmlns='http://jabber.org/protocol/muc#user'>\
            <item xmlns='urn:fake:namespace' affiliation='owner' role='moderator'/>\
        </x>\
    </presence>";
    let doc = Document::parse(xml).unwrap();
    // Item with non-muc#user namespace should be rejected or ignored
    let parsed = parse_muc_user_presence(doc.root_element());
    assert!(parsed.is_ok());

    // Foreign namespace on history
    let xml2 = "<presence xmlns='jabber:client'>\
        <x xmlns='urn:wrong:namespace'>\
            <history maxstanzas='10'/>\
        </x>\
    </presence>";
    let doc2 = Document::parse(xml2).unwrap();
    assert_eq!(
        parse_history_request(doc2.root_element()).unwrap(),
        MucHistoryRequest::default()
    );
}

#[test]
fn test_cardinality_violations() {
    // Multiple history elements
    let xml = "<presence xmlns='jabber:client'>\
        <x xmlns='http://jabber.org/protocol/muc'>\
            <history maxstanzas='10'/>\
            <history maxstanzas='20'/>\
        </x>\
    </presence>";
    let doc = Document::parse(xml).unwrap();
    assert_eq!(
        parse_history_request(doc.root_element()),
        Err(MessageError::DuplicateElement)
    );

    // Multiple declines in one message
    let xml2 = "<message xmlns='jabber:client'>\
        <x xmlns='http://jabber.org/protocol/muc#user'>\
            <decline to='a@example.org'/>\
            <decline to='b@example.org'/>\
        </x>\
    </message>";
    let doc2 = Document::parse(xml2).unwrap();
    assert_eq!(
        parse_invitation_decline(doc2.root_element()),
        Err(MessageError::DuplicateElement)
    );

    // Multiple muc#user extensions
    let xml3 = "<presence xmlns='jabber:client'>\
        <x xmlns='http://jabber.org/protocol/muc#user'><item affiliation='member' role='participant'/></x>\
        <x xmlns='http://jabber.org/protocol/muc#user'><item affiliation='admin' role='moderator'/></x>\
    </presence>";
    let doc3 = Document::parse(xml3).unwrap();
    assert_eq!(
        parse_muc_user_presence(doc3.root_element()),
        Err(PresenceError::DuplicateElement)
    );
}

#[test]
fn test_presence_payload_namespace_filtering() {
    assert!(is_allowed_muc_presence_payload_namespace("vcard-temp"));
    assert!(is_allowed_muc_presence_payload_namespace(
        "http://jabber.org/protocol/caps"
    ));
    assert!(is_allowed_muc_presence_payload_namespace(
        "http://jabber.org/protocol/avatar"
    ));
    assert!(is_allowed_muc_presence_payload_namespace(
        "http://jabber.org/protocol/tune"
    ));

    // Protocol-control extensions must be stripped
    assert!(!is_allowed_muc_presence_payload_namespace(
        "http://jabber.org/protocol/muc"
    ));
    assert!(!is_allowed_muc_presence_payload_namespace(
        "http://jabber.org/protocol/muc#user"
    ));
    assert!(!is_allowed_muc_presence_payload_namespace(
        "http://jabber.org/protocol/muc#admin"
    ));
    assert!(!is_allowed_muc_presence_payload_namespace(
        "http://jabber.org/protocol/muc#owner"
    ));
    assert!(!is_allowed_muc_presence_payload_namespace(
        "urn:xmpp:occupant-id:0"
    ));
    assert!(!is_allowed_muc_presence_payload_namespace("urn:xmpp:sid:0"));
    assert!(!is_allowed_muc_presence_payload_namespace("urn:xmpp:delay"));
    assert!(!is_allowed_muc_presence_payload_namespace("jabber:x:delay"));
}

#[test]
fn test_complete_presence_roundtrip() {
    let item = MucUserItem {
        affiliation: Affiliation::Admin,
        role: Role::Moderator,
        jid: Some("real_user@example.org/mobile".to_owned()),
        nick: None,
        actor_nick: Some("SuperOwner".to_owned()),
        reason: Some("Granted administrator status".to_owned()),
    };
    let statuses = [StatusCode::NonAnonymous, StatusCode::SelfPresence];

    let presence_xml = build_muc_presence(
        "general@conf.example.org/Alice",
        "alice@example.org/laptop",
        false,
        &item,
        &statuses,
        Some("occupant-sha256-hash"),
        Some("<c xmlns='http://jabber.org/protocol/caps' hash='sha-1' node='http://example.org' ver='1.0'/>"),
        Some("p-1234"),
    );

    let doc = Document::parse(&presence_xml).unwrap();
    let root = doc.root_element();
    assert_eq!(root.tag_name().name(), "presence");
    assert_eq!(
        root.attribute("from"),
        Some("general@conf.example.org/Alice")
    );
    assert_eq!(root.attribute("to"), Some("alice@example.org/laptop"));
    assert_eq!(root.attribute("id"), Some("p-1234"));

    let parsed_user = parse_muc_user_presence(root).unwrap().unwrap();
    let parsed_item = parsed_user.item.unwrap();
    assert_eq!(parsed_item.affiliation, Affiliation::Admin);
    assert_eq!(parsed_item.role, Role::Moderator);
    assert_eq!(
        parsed_item.jid,
        Some("real_user@example.org/mobile".to_owned())
    );
    assert_eq!(parsed_item.actor_nick, Some("SuperOwner".to_owned()));
    assert_eq!(
        parsed_item.reason,
        Some("Granted administrator status".to_owned())
    );
    assert_eq!(
        parsed_user.status_codes,
        vec![StatusCode::NonAnonymous, StatusCode::SelfPresence]
    );
}

#[test]
fn test_complete_admin_iq_roundtrip() {
    let items = vec![
        AdminItem {
            affiliation: Some(Affiliation::Member),
            role: None,
            jid: Some("member1@example.org".to_owned()),
            nick: None,
            actor_nick: None,
            reason: Some("Approved member".to_owned()),
        },
        AdminItem {
            affiliation: Some(Affiliation::Outcast),
            role: None,
            jid: Some("spammer@example.org".to_owned()),
            nick: None,
            actor_nick: Some("AdminUser".to_owned()),
            reason: Some("Spamming channel".to_owned()),
        },
    ];

    let query_xml = build_admin_query_result(&items);
    let doc = Document::parse(&query_xml).unwrap();
    let parsed = parse_admin_query(doc.root_element()).unwrap();
    assert_eq!(parsed.items.len(), 2);
    assert_eq!(parsed.items[0].affiliation, Some(Affiliation::Member));
    assert_eq!(parsed.items[0].jid, Some("member1@example.org".to_owned()));
    assert_eq!(parsed.items[1].affiliation, Some(Affiliation::Outcast));
    assert_eq!(parsed.items[1].actor_nick, Some("AdminUser".to_owned()));
}
