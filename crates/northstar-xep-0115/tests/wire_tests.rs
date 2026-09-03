//! Wire parsing and XML builder tests for XEP-0115.

use northstar_xep_0115::{
    build_caps_element, build_disco_info_query, build_disco_info_request, parse_caps_from_presence,
    parse_caps_xml, parse_disco_info_xml, validate_disco_node_attribute, CapsAdvertisement,
    CapsError, DiscoInfo, ExtendedForm, FormField,
};
use roxmltree::Document;

#[test]
fn test_parse_caps_from_presence_stanzas() {
    let presence_xml = r#"
    <presence from='alice@example.com/Phone' to='bob@example.com'>
        <status>Online</status>
        <c xmlns='http://jabber.org/protocol/caps'
           hash='sha-1'
           node='http://code.google.com/p/exodus'
           ver='QgayPKawpkPSDYmwT/WM94uAlu0='
           ext='pmuc-v1 voice-v1'/>
    </presence>
    "#;

    let doc = Document::parse(presence_xml).unwrap();
    let caps = parse_caps_from_presence(doc.root_element())
        .unwrap()
        .expect("caps present");

    assert_eq!(caps.node, "http://code.google.com/p/exodus");
    assert_eq!(caps.ver, "QgayPKawpkPSDYmwT/WM94uAlu0=");
    assert_eq!(caps.hash.as_deref(), Some("sha-1"));
    assert_eq!(caps.ext.as_deref(), Some("pmuc-v1 voice-v1"));
}

#[test]
fn test_presence_without_caps_returns_none() {
    let presence_xml =
        "<presence from='alice@example.com/Phone'><status>Online</status></presence>";
    let doc = Document::parse(presence_xml).unwrap();
    let caps = parse_caps_from_presence(doc.root_element()).unwrap();
    assert!(caps.is_none());
}

#[test]
fn test_presence_with_multiple_caps_elements_rejected() {
    let presence_xml = r#"
    <presence>
        <c xmlns='http://jabber.org/protocol/caps' hash='sha-1' node='a' ver='v1'/>
        <c xmlns='http://jabber.org/protocol/caps' hash='sha-1' node='b' ver='v2'/>
    </presence>
    "#;
    let doc = Document::parse(presence_xml).unwrap();
    let err = parse_caps_from_presence(doc.root_element()).unwrap_err();
    assert!(matches!(err, CapsError::MalformedXml(_)));
}

#[test]
fn test_caps_builder_roundtrip_with_escaping() {
    let caps = CapsAdvertisement::new(
        "http://example.com/app?a=1&b=2",
        "ver'\"<>123",
        Some("sha-1"),
        Some("ext&1"),
    )
    .unwrap();

    let built = build_caps_element(&caps);
    let parsed = parse_caps_xml(&built).unwrap();

    assert_eq!(parsed.node, caps.node);
    assert_eq!(parsed.ver, caps.ver);
    assert_eq!(parsed.hash, caps.hash);
    assert_eq!(parsed.ext, caps.ext);
}

#[test]
fn test_disco_info_builder_and_xml_roundtrip() {
    let form = ExtendedForm::new(
        "urn:xmpp:test:form",
        vec![
            FormField::new("tag", vec!["rock & roll".to_owned()]).unwrap(),
            FormField::new("chars", vec!["<test>'\"".to_owned()]).unwrap(),
        ],
    )
    .unwrap();

    let disco = DiscoInfo::builder()
        .node("http://example.com#ver1")
        .add_identity("client", "pc", Some("en"), Some("App & Client <v1>"))
        .unwrap()
        .add_feature("urn:xmpp:receipts")
        .unwrap()
        .add_form(form)
        .build()
        .unwrap();

    let xml = build_disco_info_query(&disco);
    let parsed = parse_disco_info_xml(&xml).unwrap();

    assert_eq!(parsed.node, disco.node);
    assert_eq!(parsed.identities, disco.identities);
    assert_eq!(parsed.features, disco.features);
    assert_eq!(parsed.forms, disco.forms);
}

#[test]
fn test_build_disco_info_request() {
    let req = build_disco_info_request(
        "server.test",
        "alice@remote.test/Phone",
        "disco-1",
        "http://psi-im.org",
        "q07vdOuNhhwAxmUCydM3afswLBo=",
    );

    assert_eq!(
        req,
        "<iq type='get' from='server.test' to='alice@remote.test/Phone' id='disco-1'><query xmlns='http://jabber.org/protocol/disco#info' node='http://psi-im.org#q07vdOuNhhwAxmUCydM3afswLBo='/></iq>"
    );
}

#[test]
fn test_validate_disco_node_attribute() {
    let caps = CapsAdvertisement::new(
        "http://psi-im.org",
        "q07vdOuNhhwAxmUCydM3afswLBo=",
        Some("sha-1"),
        None::<&str>,
    )
    .unwrap();

    assert!(validate_disco_node_attribute(
        &caps,
        Some("http://psi-im.org#q07vdOuNhhwAxmUCydM3afswLBo=")
    )
    .is_ok());

    let err = validate_disco_node_attribute(&caps, Some("http://psi-im.org#wrong")).unwrap_err();
    assert!(matches!(err, CapsError::NodeMismatch { .. }));

    let err_none = validate_disco_node_attribute(&caps, None).unwrap_err();
    assert!(matches!(err_none, CapsError::NodeMismatch { .. }));
}
