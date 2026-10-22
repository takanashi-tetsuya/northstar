//! Integration tests for northstar-xep-0313 MAM domain library.

use northstar_xep_0313::{
    build_extended_form, build_fin, build_fin_from_model, build_metadata, build_preferences,
    build_result_message, build_result_payload, evaluate_preference, is_empty_mam_command,
    parse_fin_element, parse_mam_preferences, parse_mam_query, parse_metadata_response,
    parse_result_element, reassert_archive_stanza_id, ArchiveId, DefaultPolicy, MamFin,
    MamMetadata, MamMetadataBoundary, MamRsmPage, UtcTimestamp, DESCRIPTOR, DISCO_FEATURE_MAM,
    DISCO_FEATURE_MAM_EXTENDED, XEP_ID, XMLNS_MAM,
};
use northstar_xep_core::{StanzaKind, XepId};
use roxmltree::Document;

#[test]
fn descriptor_matches_manifest() {
    assert_eq!(DESCRIPTOR.id, XEP_ID);
    assert_eq!(DESCRIPTOR.id, XepId::new(313));
    assert_eq!(DESCRIPTOR.name, "Message Archive Management");
    assert!(DESCRIPTOR.default_enabled);
    assert_eq!(DESCRIPTOR.dependencies, &[XepId::new(30), XepId::new(59)]);
    assert!(DESCRIPTOR.conflicts.is_empty());
    assert_eq!(
        DESCRIPTOR.disco_features,
        &[DISCO_FEATURE_MAM, DISCO_FEATURE_MAM_EXTENDED]
    );
    assert_eq!(DESCRIPTOR.routes.len(), 5);

    assert!(DESCRIPTOR
        .routes
        .iter()
        .any(|r| r.stanza == StanzaKind::IqSet
            && r.namespace == XMLNS_MAM
            && r.local_name == "query"));
    assert!(DESCRIPTOR
        .routes
        .iter()
        .any(|r| r.stanza == StanzaKind::IqGet
            && r.namespace == XMLNS_MAM
            && r.local_name == "query"));
    assert!(DESCRIPTOR
        .routes
        .iter()
        .any(|r| r.stanza == StanzaKind::IqGet
            && r.namespace == XMLNS_MAM
            && r.local_name == "metadata"));
    assert!(DESCRIPTOR
        .routes
        .iter()
        .any(|r| r.stanza == StanzaKind::IqGet
            && r.namespace == XMLNS_MAM
            && r.local_name == "prefs"));
    assert!(DESCRIPTOR
        .routes
        .iter()
        .any(|r| r.stanza == StanzaKind::IqSet
            && r.namespace == XMLNS_MAM
            && r.local_name == "prefs"));
}

#[test]
fn extended_query_parsing_and_normalization() {
    let xml = "<query xmlns='urn:xmpp:mam:2' queryid='q-100'>\
        <x xmlns='jabber:x:data' type='submit'>\
            <field var='FORM_TYPE' type='hidden'><value>urn:xmpp:mam:2</value></field>\
            <field var='with' type='jid-single'><value>Alice@EXAMPLE.test/Phone</value></field>\
            <field var='start' type='text-single'><value>2026-09-02T10:00:00Z</value></field>\
            <field var='end' type='text-single'><value>2026-09-02T18:00:00Z</value></field>\
            <field var='before-id' type='text-single'><value>11111111-1111-1111-1111-111111111111</value></field>\
            <field var='after-id' type='text-single'><value>22222222-2222-2222-2222-222222222222</value></field>\
            <field var='ids' type='list-multi'>\
                <value>33333333-3333-3333-3333-333333333333</value>\
                <value>44444444-4444-4444-4444-444444444444</value>\
            </field>\
        </x>\
        <set xmlns='http://jabber.org/protocol/rsm'>\
            <max>50</max>\
            <after>55555555-5555-5555-5555-555555555555</after>\
        </set>\
        <flip-page/>\
    </query>";

    let doc = Document::parse(xml).unwrap();
    let query = parse_mam_query(doc.root_element()).unwrap();

    assert_eq!(
        query.filter.with_jid.as_ref().map(|j| j.to_string()),
        Some("alice@example.test/Phone".to_owned())
    );
    assert_eq!(
        query.filter.start,
        Some(UtcTimestamp::parse("2026-09-02T10:00:00Z").unwrap())
    );
    assert_eq!(
        query.filter.end,
        Some(UtcTimestamp::parse("2026-09-02T18:00:00Z").unwrap())
    );
    assert_eq!(
        query.filter.before_id.as_ref().map(|id| id.as_str()),
        Some("11111111-1111-1111-1111-111111111111")
    );
    assert_eq!(
        query.filter.after_id.as_ref().map(|id| id.as_str()),
        Some("22222222-2222-2222-2222-222222222222")
    );
    assert_eq!(query.filter.ids.len(), 2);
    assert_eq!(
        query.page,
        MamRsmPage::After(ArchiveId::parse("55555555-5555-5555-5555-555555555555").unwrap())
    );
    assert_eq!(query.max, 50);
    assert_eq!(query.query_id.as_deref(), Some("q-100"));
    assert!(query.flip_page);
}

#[test]
fn query_error_matrix() {
    for (xml, expected_condition) in [
        (
            "<query xmlns='urn:xmpp:mam:2' node='unsupported'/>",
            "feature-not-implemented",
        ),
        (
            "<query xmlns='urn:xmpp:mam:2'><unknown/></query>",
            "feature-not-implemented",
        ),
        (
            "<query xmlns='urn:xmpp:mam:2'><x xmlns='jabber:x:data' type='submit'><field var='unknown'><value>x</value></field></x></query>",
            "feature-not-implemented",
        ),
        (
            "<query xmlns='urn:xmpp:mam:2'><x xmlns='jabber:x:data' type='submit'><field var='with'><value>a@b.test</value></field></x></query>",
            "bad-request", // Missing FORM_TYPE
        ),
        (
            "<query xmlns='urn:xmpp:mam:2'><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>wrong:type</value></field></x></query>",
            "bad-request",
        ),
        (
            "<query xmlns='urn:xmpp:mam:2'><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>urn:xmpp:mam:2</value></field><field var='start'><value>2026-09-02T18:00:00Z</value></field><field var='end'><value>2026-09-02T10:00:00Z</value></field></x></query>",
            "bad-request", // start > end
        ),
        (
            "<query xmlns='urn:xmpp:mam:2'><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>urn:xmpp:mam:2</value></field><field var='with'><value> malformed </value></field></x></query>",
            "jid-malformed",
        ),
        (
            "<query xmlns='urn:xmpp:mam:2'><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>urn:xmpp:mam:2</value></field><field var='before-id'><value>not-a-uuid</value></field></x></query>",
            "item-not-found",
        ),
        (
            "<query xmlns='urn:xmpp:mam:2'><set xmlns='http://jabber.org/protocol/rsm'><after>not-a-uuid</after></set></query>",
            "item-not-found",
        ),
        (
            "<query xmlns='urn:xmpp:mam:2'><set xmlns='http://jabber.org/protocol/rsm'><before/><after>11111111-1111-1111-1111-111111111111</after></set></query>",
            "bad-request",
        ),
        (
            "<query xmlns='urn:xmpp:mam:2'><set xmlns='http://jabber.org/protocol/rsm'><max>-1</max></set></query>",
            "bad-request",
        ),
        (
            "<query xmlns='urn:xmpp:mam:2'><set xmlns='http://jabber.org/protocol/rsm'><index>1000001</index></set></query>",
            "resource-constraint",
        ),
    ] {
        let doc = Document::parse(xml).unwrap();
        let err = parse_mam_query(doc.root_element()).unwrap_err();
        assert_eq!(
            err.as_stanza_error_condition(),
            expected_condition,
            "failed on fixture: {xml}"
        );
    }
}

#[test]
fn preferences_lifecycle_and_decision_rules() {
    let xml = "<prefs xmlns='urn:xmpp:mam:2' default='roster'>\
        <always>\
            <jid>Alice@example.test/Phone</jid>\
            <jid>bob@example.test</jid>\
        </always>\
        <never>\
            <jid>Alice@example.test</jid>\
            <jid>charlie@example.test</jid>\
        </never>\
    </prefs>";

    let doc = Document::parse(xml).unwrap();
    let prefs = parse_mam_preferences(doc.root_element()).unwrap();

    assert_eq!(prefs.default_policy, DefaultPolicy::Roster);
    assert_eq!(
        prefs.always,
        vec!["alice@example.test/Phone", "bob@example.test"]
    );
    assert_eq!(
        prefs.never,
        vec!["alice@example.test", "charlie@example.test"]
    );

    // Decision rules
    assert!(evaluate_preference(&prefs, "alice@example.test/Phone", false).unwrap());
    assert!(!evaluate_preference(&prefs, "alice@example.test/Desktop", true).unwrap());
    assert!(evaluate_preference(&prefs, "bob@example.test/Resource", false).unwrap());
    assert!(!evaluate_preference(&prefs, "charlie@example.test/Work", true).unwrap());
    assert!(evaluate_preference(&prefs, "stranger@example.test", true).unwrap());
    assert!(!evaluate_preference(&prefs, "stranger@example.test", false).unwrap());

    // Round-trip builder
    let built_xml = build_preferences(&prefs);
    let doc2 = Document::parse(&built_xml).unwrap();
    let round_tripped = parse_mam_preferences(doc2.root_element()).unwrap();
    assert_eq!(prefs, round_tripped);
}

#[test]
fn result_forwarded_round_trip() {
    let archive_id = "de305d54-75b4-431b-adb2-eb6b9e546013";
    let query_id = Some("q-abc");
    let stamp = "2026-09-02T15:25:08.123Z";
    let archived_stanza = "<message xmlns='jabber:client' to='alice@example.test' from='bob@example.test'><body>Hello Archive</body></message>";

    let result_xml = build_result_payload(archive_id, query_id, stamp, archived_stanza).unwrap();
    let doc = Document::parse(&result_xml).unwrap();
    let parsed_result = parse_result_element(doc.root_element()).unwrap();

    assert_eq!(parsed_result.id.as_str(), archive_id);
    assert_eq!(parsed_result.query_id.as_deref(), query_id);
    assert_eq!(parsed_result.delay_stamp.to_rfc3339_millis(), stamp);
    assert!(parsed_result.forwarded_stanza.contains("Hello Archive"));

    let msg_xml = build_result_message(
        "msg-1",
        "alice@example.test/Phone",
        Some("archive.example.test"),
        archive_id,
        query_id,
        stamp,
        archived_stanza,
    )
    .unwrap();
    assert!(msg_xml.contains("xmlns='jabber:client'"));
    assert!(msg_xml.contains("to='alice@example.test/Phone'"));
    assert!(msg_xml.contains("from='archive.example.test'"));
}

#[test]
fn fin_round_trip_and_flags() {
    let first_id = ArchiveId::parse("11111111-1111-1111-1111-111111111111").unwrap();
    let last_id = ArchiveId::parse("22222222-2222-2222-2222-222222222222").unwrap();

    let fin_model = MamFin {
        complete: true,
        stable: true,
        first: Some((first_id.clone(), Some(10))),
        last: Some(last_id.clone()),
        count: Some(100),
    };

    let xml = build_fin_from_model(&fin_model);
    let doc = Document::parse(&xml).unwrap();
    let parsed_fin = parse_fin_element(doc.root_element()).unwrap();

    assert_eq!(parsed_fin, fin_model);

    let raw_fin_xml = build_fin(false, false, None, None, None);
    assert_eq!(
        raw_fin_xml,
        "<fin xmlns='urn:xmpp:mam:2' complete='false' stable='false'/>"
    );

    assert!(build_extended_form().contains("urn:xmpp:mam:2"));
}

#[test]
fn metadata_round_trip() {
    let metadata = MamMetadata {
        start: Some(MamMetadataBoundary {
            id: ArchiveId::parse("11111111-1111-1111-1111-111111111111").unwrap(),
            timestamp: UtcTimestamp::parse("2026-09-01T00:00:00.000Z").unwrap(),
        }),
        end: Some(MamMetadataBoundary {
            id: ArchiveId::parse("22222222-2222-2222-2222-222222222222").unwrap(),
            timestamp: UtcTimestamp::parse("2026-09-02T00:00:00.000Z").unwrap(),
        }),
    };

    let xml = build_metadata(&metadata);
    let doc = Document::parse(&xml).unwrap();
    let parsed = parse_metadata_response(doc.root_element()).unwrap();

    assert_eq!(parsed, metadata);
}

#[test]
fn stanza_id_reassertion_and_forgery_removal() {
    let stanza = "<message xmlns='jabber:client'><stanza-id xmlns='urn:xmpp:sid:0' id='forged' by='Alice@Example.test'/><stanza-id xmlns='urn:xmpp:sid:0' id='remote' by='remote.test'/><body>Text</body></message>";
    let reasserted = reassert_archive_stanza_id(
        stanza,
        "alice@example.test",
        "de305d54-75b4-431b-adb2-eb6b9e546013",
    )
    .unwrap();

    assert!(!reasserted.contains("forged"));
    assert!(reasserted.contains("remote"));
    assert!(reasserted.contains("id='de305d54-75b4-431b-adb2-eb6b9e546013'"));
    assert!(reasserted.contains("by='alice@example.test'"));
}

#[test]
fn empty_get_commands_strictly_validated() {
    for (xml, name, expected) in [
        ("<query xmlns='urn:xmpp:mam:2'/>", "query", true),
        ("<metadata xmlns='urn:xmpp:mam:2'/>", "metadata", true),
        ("<prefs xmlns='urn:xmpp:mam:2'/>", "prefs", true),
        ("<query xmlns='urn:xmpp:mam:2' node='a'/>", "query", false),
        (
            "<metadata xmlns='urn:xmpp:mam:2'><start/></metadata>",
            "metadata",
            false,
        ),
        (
            "<prefs xmlns='urn:xmpp:mam:2' default='always'/>",
            "prefs",
            false,
        ),
    ] {
        let doc = Document::parse(xml).unwrap();
        assert_eq!(
            is_empty_mam_command(doc.root_element(), name),
            expected,
            "{xml}"
        );
    }
}
