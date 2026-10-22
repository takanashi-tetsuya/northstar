//! Official test vectors from XEP-0115 specification.

use northstar_xep_0115::{
    compute_verification_string_and_ver, generate_canonical_verification_string, parse_caps_xml,
    parse_disco_info_xml, verify_caps_advertisement, CapsAdvertisement, CapsHashAlgorithm,
    DiscoInfo, ExtendedForm, FormField,
};

/// XEP-0115 Section 5.2 Example (Simple Generation Example: Exodus)
///
/// Identities:
///   category: 'client', type: 'pc', name: 'Exodus 0.9.1'
/// Features:
///   http://jabber.org/protocol/caps
///   http://jabber.org/protocol/disco#info
///   http://jabber.org/protocol/disco#items
///   http://jabber.org/protocol/muc
///
/// Canonical Verification String:
///   client/pc//Exodus 0.9.1<http://jabber.org/protocol/caps<http://jabber.org/protocol/disco#info<http://jabber.org/protocol/disco#items<http://jabber.org/protocol/muc<
///
/// SHA-1 Hash:
///   QgayPKawpkPSDYmwT/WM94uAlu0=
#[test]
fn test_official_vector_exodus_simple_example() {
    let disco = DiscoInfo::builder()
        .node("http://code.google.com/p/exodus")
        .add_identity("client", "pc", None::<&str>, Some("Exodus 0.9.1"))
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

    let canonical = generate_canonical_verification_string(&disco).unwrap();
    assert_eq!(
        canonical,
        "client/pc//Exodus 0.9.1<http://jabber.org/protocol/caps<http://jabber.org/protocol/disco#info<http://jabber.org/protocol/disco#items<http://jabber.org/protocol/muc<"
    );

    let (canon, sha1_ver) =
        compute_verification_string_and_ver(&CapsHashAlgorithm::Sha1, &disco).unwrap();
    assert_eq!(canon, canonical);
    assert_eq!(sha1_ver, "QgayPKawpkPSDYmwT/WM94uAlu0=");

    // Verify presence advertisement
    let caps = CapsAdvertisement::new(
        "http://code.google.com/p/exodus",
        "QgayPKawpkPSDYmwT/WM94uAlu0=",
        Some("sha-1"),
        None::<&str>,
    )
    .unwrap();

    let result = verify_caps_advertisement(&caps, &disco);
    assert!(result.is_valid());
    assert_eq!(result.key().unwrap().algorithm, "sha-1");
    assert_eq!(
        result.key().unwrap().node,
        "http://code.google.com/p/exodus"
    );
    assert_eq!(
        result.key().unwrap().version,
        "QgayPKawpkPSDYmwT/WM94uAlu0="
    );
}

/// XEP-0115 Section 5.3 Example (Complex Generation Example: Psi with multilingual identities and XEP-0128)
///
/// Identities:
///   category: 'client', type: 'pc', xml:lang: 'en', name: 'Psi 0.11'
///   category: 'client', type: 'pc', xml:lang: 'el', name: 'Ψ 0.11'
/// Features:
///   http://jabber.org/protocol/caps
///   http://jabber.org/protocol/disco#info
///   http://jabber.org/protocol/disco#items
///   http://jabber.org/protocol/muc
/// Form:
///   FORM_TYPE: 'urn:xmpp:dataforms:softwareinfo'
///   ip_version: ['ipv4', 'ipv6']
///   os: ['Mac']
///   os_version: ['10.5.1']
///   software: ['Psi']
///   software_version: ['0.11']
///
/// Canonical Verification String:
///   client/pc/el/Ψ 0.11<client/pc/en/Psi 0.11<http://jabber.org/protocol/caps<http://jabber.org/protocol/disco#info<http://jabber.org/protocol/disco#items<http://jabber.org/protocol/muc<urn:xmpp:dataforms:softwareinfo<ip_version<ipv4<ipv6<os<Mac<os_version<10.5.1<software<Psi<software_version<0.11<
///
/// SHA-1 Hash:
///   q07IKJEyjvHSyhy//CH0CxmKi8w=
#[test]
fn test_official_vector_psi_complex_example() {
    let form = ExtendedForm::new(
        "urn:xmpp:dataforms:softwareinfo",
        vec![
            FormField::new("ip_version", vec!["ipv4".to_owned(), "ipv6".to_owned()]).unwrap(),
            FormField::new("os", vec!["Mac".to_owned()]).unwrap(),
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
        .add_identity("client", "pc", Some("el"), Some("Ψ 0.11"))
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

    let canonical = generate_canonical_verification_string(&disco).unwrap();
    assert_eq!(
        canonical,
        "client/pc/el/Ψ 0.11<client/pc/en/Psi 0.11<http://jabber.org/protocol/caps<http://jabber.org/protocol/disco#info<http://jabber.org/protocol/disco#items<http://jabber.org/protocol/muc<urn:xmpp:dataforms:softwareinfo<ip_version<ipv4<ipv6<os<Mac<os_version<10.5.1<software<Psi<software_version<0.11<"
    );

    let (canon, sha1_ver) =
        compute_verification_string_and_ver(&CapsHashAlgorithm::Sha1, &disco).unwrap();
    assert_eq!(canon, canonical);
    assert_eq!(sha1_ver, "q07IKJEyjvHSyhy//CH0CxmKi8w=");

    let caps = CapsAdvertisement::new(
        "http://psi-im.org",
        "q07IKJEyjvHSyhy//CH0CxmKi8w=",
        Some("sha-1"),
        None::<&str>,
    )
    .unwrap();

    let result = verify_caps_advertisement(&caps, &disco);
    assert!(result.is_valid());
}

/// Test XML roundtrip with exact Section 5.3 Complex Generation Example XML query payload.
#[test]
fn test_official_vector_xml_parsing_psi_complex() {
    let xml = r#"
    <query xmlns='http://jabber.org/protocol/disco#info'
           node='http://psi-im.org#q07IKJEyjvHSyhy//CH0CxmKi8w='>
      <identity xml:lang='en' category='client' name='Psi 0.11' type='pc'/>
      <identity xml:lang='el' category='client' name='Ψ 0.11' type='pc'/>
      <feature var='http://jabber.org/protocol/caps'/>
      <feature var='http://jabber.org/protocol/disco#info'/>
      <feature var='http://jabber.org/protocol/disco#items'/>
      <feature var='http://jabber.org/protocol/muc'/>
      <x xmlns='jabber:x:data' type='result'>
        <field var='FORM_TYPE' type='hidden'>
          <value>urn:xmpp:dataforms:softwareinfo</value>
        </field>
        <field var='ip_version' type='text-multi' >
          <value>ipv4</value>
          <value>ipv6</value>
        </field>
        <field var='os'>
          <value>Mac</value>
        </field>
        <field var='os_version'>
          <value>10.5.1</value>
        </field>
        <field var='software'>
          <value>Psi</value>
        </field>
        <field var='software_version'>
          <value>0.11</value>
        </field>
      </x>
    </query>
    "#;

    let disco = parse_disco_info_xml(xml).unwrap();
    let canonical = generate_canonical_verification_string(&disco).unwrap();
    assert_eq!(
        canonical,
        "client/pc/el/Ψ 0.11<client/pc/en/Psi 0.11<http://jabber.org/protocol/caps<http://jabber.org/protocol/disco#info<http://jabber.org/protocol/disco#items<http://jabber.org/protocol/muc<urn:xmpp:dataforms:softwareinfo<ip_version<ipv4<ipv6<os<Mac<os_version<10.5.1<software<Psi<software_version<0.11<"
    );

    let caps_xml = "<c xmlns='http://jabber.org/protocol/caps' hash='sha-1' node='http://psi-im.org' ver='q07IKJEyjvHSyhy//CH0CxmKi8w='/>";
    let caps = parse_caps_xml(caps_xml).unwrap();

    let result = verify_caps_advertisement(&caps, &disco);
    assert!(result.is_valid());
}

/// Test SHA-256 and other hash algorithms on official test vector data.
#[test]
fn test_multi_hash_algorithms_on_official_vectors() {
    let disco = DiscoInfo::builder()
        .node("http://code.google.com/p/exodus")
        .add_identity("client", "pc", None::<&str>, Some("Exodus 0.9.1"))
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

    for (algo, expected_len) in [
        (CapsHashAlgorithm::Sha1, 28),   // 20 bytes -> 28 base64 chars
        (CapsHashAlgorithm::Sha224, 40), // 28 bytes -> 40 base64 chars
        (CapsHashAlgorithm::Sha256, 44), // 32 bytes -> 44 base64 chars
        (CapsHashAlgorithm::Sha384, 64), // 48 bytes -> 64 base64 chars
        (CapsHashAlgorithm::Sha512, 88), // 64 bytes -> 88 base64 chars
    ] {
        let (_, ver) = compute_verification_string_and_ver(&algo, &disco).unwrap();
        assert_eq!(ver.len(), expected_len);

        let caps = CapsAdvertisement::new(
            "http://code.google.com/p/exodus",
            ver,
            Some(algo.as_str()),
            None::<&str>,
        )
        .unwrap();

        let result = verify_caps_advertisement(&caps, &disco);
        assert!(result.is_valid());
        assert_eq!(result.key().unwrap().algorithm, algo.as_str());
    }
}
