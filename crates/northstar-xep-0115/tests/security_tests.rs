//! Security and boundary enforcement tests for XEP-0115.

use northstar_xep_0115::{
    parse_disco_info_xml, verify_caps_advertisement, CapsAdvertisement, CapsError, CapsKey,
    CapsScope, CapsValidationResult, DiscoInfo, ExtendedForm, Feature, FormField, Identity,
    MAX_DISCO_PAYLOAD_BYTES,
};

#[test]
fn test_oversized_payload_rejection() {
    let large_name = "A".repeat(MAX_DISCO_PAYLOAD_BYTES + 100);
    let xml = format!(
        "<query xmlns='http://jabber.org/protocol/disco#info'><identity category='client' type='pc' name='{large_name}'/></query>"
    );

    let err = parse_disco_info_xml(&xml).unwrap_err();
    assert!(matches!(err, CapsError::OversizedPayload { .. }));
}

#[test]
fn test_too_many_children_rejection() {
    let mut features = String::new();
    for i in 0..600 {
        features.push_str(&format!("<feature var='urn:test:{i}'/>"));
    }
    let xml = format!("<query xmlns='http://jabber.org/protocol/disco#info'>{features}</query>");

    let err = parse_disco_info_xml(&xml).unwrap_err();
    assert!(matches!(err, CapsError::TooManyChildren { .. }));
}

#[test]
fn test_control_character_rejection() {
    assert!(Identity::new("client\0", "pc", None::<&str>, None::<&str>).is_err());
    assert!(Identity::new("client", "pc\n", None::<&str>, None::<&str>).is_err());
    assert!(Identity::new("client", "pc", Some("en\r"), None::<&str>).is_err());
    assert!(Identity::new("client", "pc", None::<&str>, Some("Name\u{001b}")).is_err());

    assert!(Feature::new("urn:test\n").is_err());
    assert!(FormField::new("var\0", vec!["val".to_owned()]).is_err());
    assert!(FormField::new("var", vec!["val\u{0008}".to_owned()]).is_err());

    assert!(CapsAdvertisement::new("node\0", "ver", Some("sha-1"), None::<&str>).is_err());
    assert!(CapsAdvertisement::new("node", "ver\r\n", Some("sha-1"), None::<&str>).is_err());
    assert!(CapsAdvertisement::new("node", "ver", Some("sha-1\0"), None::<&str>).is_err());
    assert!(CapsAdvertisement::new("node", "ver", Some("sha-1"), Some("ext\0")).is_err());

    assert!(CapsKey::new("sha-1\0", "node", "ver").is_err());
    assert!(CapsKey::new("sha-1", "node\n", "ver").is_err());
    assert!(CapsKey::new("sha-1", "node", "ver\r").is_err());
}

#[test]
fn test_tampered_feature_fails_verification() {
    let authentic_disco = DiscoInfo::builder()
        .add_identity("client", "pc", None::<&str>, Some("Exodus 0.9.1"))
        .unwrap()
        .add_feature("http://jabber.org/protocol/caps")
        .unwrap()
        .add_feature("http://jabber.org/protocol/disco#info")
        .unwrap()
        .build()
        .unwrap();

    // Legitimate Exodus hash for 4 features:
    let authentic_caps = CapsAdvertisement::new(
        "http://code.google.com/p/exodus",
        "QgayPKawpkPSDYmwT/WM94uAlu0=",
        Some("sha-1"),
        None::<&str>,
    )
    .unwrap();

    // Adversary provides fewer features or spoofed capabilities:
    let result = verify_caps_advertisement(&authentic_caps, &authentic_disco);
    assert!(matches!(result, CapsValidationResult::Mismatch { .. }));
}

#[test]
fn test_tampered_identity_fails_verification() {
    let disco = DiscoInfo::builder()
        .node("http://code.google.com/p/exodus")
        .add_identity("server", "im", None::<&str>, Some("Exodus 0.9.1")) // spoofed identity
        .unwrap()
        .add_feature("http://jabber.org/protocol/caps")
        .unwrap()
        .add_feature("http://jabber.org/protocol/disco#info")
        .unwrap()
        .add_feature("http://jabber.org/protocol/disco#items")
        .unwrap()
        .add_feature("http://jabber.org/protocol/muc")
        .unwrap()
        .build()
        .unwrap();

    let caps = CapsAdvertisement::new(
        "http://code.google.com/p/exodus",
        "QgayPKawpkPSDYmwT/WM94uAlu0=",
        Some("sha-1"),
        None::<&str>,
    )
    .unwrap();

    let result = verify_caps_advertisement(&caps, &disco);
    assert!(matches!(result, CapsValidationResult::Mismatch { .. }));
}

#[test]
fn test_tampered_form_fails_verification() {
    let form = ExtendedForm::new(
        "urn:xmpp:dataforms:softwareinfo",
        vec![
            FormField::new("ip_version", vec!["ipv4".to_owned()]).unwrap(), // missing ipv6
            FormField::new("os", vec!["Mac OS X".to_owned()]).unwrap(),
            FormField::new("os_version", vec!["10.5.1".to_owned()]).unwrap(),
            FormField::new("software", vec!["Psi".to_owned()]).unwrap(),
            FormField::new("software_version", vec!["0.11".to_owned()]).unwrap(),
        ],
    )
    .unwrap();

    let disco = DiscoInfo::builder()
        .node("http://psi-im.org")
        .add_identity("client", "pc", Some("en"), Some("Psi 0.11"))
        .unwrap()
        .add_feature("http://jabber.org/protocol/caps")
        .unwrap()
        .add_feature("http://jabber.org/protocol/disco#info")
        .unwrap()
        .add_feature("http://jabber.org/protocol/disco#items")
        .unwrap()
        .add_feature("http://jabber.org/protocol/muc")
        .unwrap()
        .add_form(form)
        .build()
        .unwrap();

    let caps = CapsAdvertisement::new(
        "http://psi-im.org",
        "q07vdOuNhhwAxmUCydM3afswLBo=",
        Some("sha-1"),
        None::<&str>,
    )
    .unwrap();

    let result = verify_caps_advertisement(&caps, &disco);
    assert!(matches!(result, CapsValidationResult::Mismatch { .. }));
}

#[test]
fn test_unsupported_algorithm_handling() {
    let disco = DiscoInfo::default();
    let caps = CapsAdvertisement::new(
        "http://example.com",
        "v1",
        Some("md5"), // unapproved/unsupported algorithm
        None::<&str>,
    )
    .unwrap();

    let result = verify_caps_advertisement(&caps, &disco);
    assert!(matches!(
        result,
        CapsValidationResult::UnsupportedAlgorithm { .. }
    ));
}

#[test]
fn test_legacy_advertisement_without_hash() {
    let disco = DiscoInfo::default();
    let caps = CapsAdvertisement::new(
        "http://example.com",
        "1.0",
        None::<&str>, // legacy without hash
        Some("ext1"),
    )
    .unwrap();

    let result = verify_caps_advertisement(&caps, &disco);
    assert_eq!(result, CapsValidationResult::LegacyWithoutHash);
}

#[test]
fn test_scoped_algorithm_isolation() {
    let jid = "alice@example.test/Phone";
    let key = CapsKey::scoped("sha3-256", jid, "node1", "ver1").unwrap();
    assert_eq!(key.algorithm, "sha3-256");
    assert_eq!(key.node, "node1");
    assert_eq!(key.version, "ver1");
    assert_eq!(key.scope, CapsScope::FullJid(jid.to_owned()));

    let global = CapsKey::new("sha-1", "node1", "ver1").unwrap();
    assert_eq!(global.scope, CapsScope::Global);
    assert_ne!(key, global);

    assert!(CapsKey::scoped("sha3-256", "bad\n@example.test", "node", "ver").is_err());
}
