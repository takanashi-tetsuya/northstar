//! Tests for XEP-0115 canonical verification string sorting, deduplication, and forms.

use northstar_xep_0115::{
    generate_canonical_verification_string, parse_disco_info_xml, CapsError, DiscoInfo,
    ExtendedForm, Feature, FormField, Identity,
};

#[test]
fn test_identity_sorting_order() {
    let disco = DiscoInfo::builder()
        // out-of-order identities
        .add_identity("client", "web", None::<&str>, Some("B"))
        .unwrap()
        .add_identity("client", "pc", Some("fr"), Some("A"))
        .unwrap()
        .add_identity("client", "pc", Some("en"), Some("Z"))
        .unwrap()
        .add_identity("client", "pc", None::<&str>, Some("A"))
        .unwrap()
        .add_identity("auth", "radius", None::<&str>, None::<&str>)
        .unwrap()
        .build()
        .unwrap();

    let canonical = generate_canonical_verification_string(&disco).unwrap();
    assert_eq!(
        canonical,
        "auth/radius//<client/pc//A<client/pc/en/Z<client/pc/fr/A<client/web//B<"
    );
}

#[test]
fn test_feature_sorting_order() {
    let disco = DiscoInfo::builder()
        .add_feature("urn:xmpp:receipts")
        .unwrap()
        .add_feature("http://jabber.org/protocol/disco#info")
        .unwrap()
        .add_feature("urn:xmpp:mam:2")
        .unwrap()
        .add_feature("http://jabber.org/protocol/caps")
        .unwrap()
        .build()
        .unwrap();

    let canonical = generate_canonical_verification_string(&disco).unwrap();
    assert_eq!(
        canonical,
        "http://jabber.org/protocol/caps<http://jabber.org/protocol/disco#info<urn:xmpp:mam:2<urn:xmpp:receipts<"
    );
}

#[test]
fn test_multiple_forms_and_field_sorting() {
    let form2 = ExtendedForm::new(
        "urn:xmpp:dataforms:media",
        vec![
            FormField::new("video", vec!["h264".to_owned(), "vp8".to_owned()]).unwrap(),
            FormField::new("audio", vec!["opus".to_owned(), "aac".to_owned()]).unwrap(),
        ],
    )
    .unwrap();

    let form1 = ExtendedForm::new(
        "urn:xmpp:dataforms:device",
        vec![
            FormField::new("model", vec!["Pixel 8".to_owned()]).unwrap(),
            FormField::new("brand", vec!["Google".to_owned()]).unwrap(),
        ],
    )
    .unwrap();

    let disco = DiscoInfo::builder()
        .add_form(form2) // out of order
        .add_form(form1)
        .build()
        .unwrap();

    let canonical = generate_canonical_verification_string(&disco).unwrap();
    assert_eq!(
        canonical,
        "urn:xmpp:dataforms:device<brand<Google<model<Pixel 8<urn:xmpp:dataforms:media<audio<aac<opus<video<h264<vp8<"
    );
}

#[test]
fn test_unicode_code_point_ordering() {
    let disco = DiscoInfo::builder()
        .add_identity("client", "pc", None::<&str>, Some("α-client")) // Greek alpha
        .unwrap()
        .add_identity("client", "pc", None::<&str>, Some("z-client")) // ASCII z
        .unwrap()
        .add_identity("client", "pc", None::<&str>, Some("a-client")) // ASCII a
        .unwrap()
        .add_identity("client", "pc", None::<&str>, Some("クライアント")) // Japanese Katakana
        .unwrap()
        .build()
        .unwrap();

    let canonical = generate_canonical_verification_string(&disco).unwrap();
    // In UTF-8 / i;octet: ASCII ('a', 'z') < Greek ('α') < Katakana ('ク')
    assert_eq!(
        canonical,
        "client/pc//a-client<client/pc//z-client<client/pc//α-client<client/pc//クライアント<"
    );
}

#[test]
fn test_duplicate_identity_rejection() {
    let identities = vec![
        Identity::new("client", "pc", Some("en"), Some("Exodus")).unwrap(),
        Identity::new("client", "pc", Some("en"), Some("Exodus")).unwrap(),
    ];
    let disco = DiscoInfo::new(None, identities, Vec::new(), Vec::new()).unwrap();

    let err = generate_canonical_verification_string(&disco).unwrap_err();
    assert!(matches!(err, CapsError::DuplicateIdentity(_)));
}

#[test]
fn test_duplicate_feature_rejection() {
    let features = vec![
        Feature::new("urn:xmpp:receipts").unwrap(),
        Feature::new("http://jabber.org/protocol/caps").unwrap(),
        Feature::new("urn:xmpp:receipts").unwrap(),
    ];
    let disco = DiscoInfo::new(None, Vec::new(), features, Vec::new()).unwrap();

    let err = generate_canonical_verification_string(&disco).unwrap_err();
    assert!(matches!(err, CapsError::DuplicateFeature(_)));
}

#[test]
fn test_duplicate_form_rejection() {
    let forms = vec![
        ExtendedForm::new(
            "urn:xmpp:dataforms:softwareinfo",
            vec![FormField::new("os", vec!["Linux".to_owned()]).unwrap()],
        )
        .unwrap(),
        ExtendedForm::new(
            "urn:xmpp:dataforms:softwareinfo",
            vec![FormField::new("os", vec!["Windows".to_owned()]).unwrap()],
        )
        .unwrap(),
    ];
    let disco = DiscoInfo::new(None, Vec::new(), Vec::new(), forms).unwrap();

    let err = generate_canonical_verification_string(&disco).unwrap_err();
    assert!(matches!(err, CapsError::DuplicateForm(_)));
}

#[test]
fn test_duplicate_form_field_rejection_in_builder() {
    let fields = vec![
        FormField::new("os", vec!["Linux".to_owned()]).unwrap(),
        FormField::new("os", vec!["Windows".to_owned()]).unwrap(),
    ];
    let err = ExtendedForm::new("urn:xmpp:dataforms:softwareinfo", fields).unwrap_err();
    assert!(matches!(err, CapsError::DuplicateFormField(_)));
}

#[test]
fn test_form_without_hidden_form_type_is_ignored() {
    // Non-hidden form_type field
    let xml = r#"
    <query xmlns='http://jabber.org/protocol/disco#info'>
      <feature var='http://jabber.org/protocol/caps'/>
      <x xmlns='jabber:x:data' type='result'>
        <field var='FORM_TYPE' type='text-single'>
          <value>urn:xmpp:dataforms:softwareinfo</value>
        </field>
        <field var='os'>
          <value>Linux</value>
        </field>
      </x>
    </query>
    "#;

    let disco = parse_disco_info_xml(xml).unwrap();
    let canonical = generate_canonical_verification_string(&disco).unwrap();
    // Form is ignored because FORM_TYPE is not hidden
    assert_eq!(canonical, "http://jabber.org/protocol/caps<");
}

#[test]
fn test_form_not_type_result_is_ignored() {
    let xml = r#"
    <query xmlns='http://jabber.org/protocol/disco#info'>
      <feature var='http://jabber.org/protocol/caps'/>
      <x xmlns='jabber:x:data' type='form'>
        <field var='FORM_TYPE' type='hidden'>
          <value>urn:xmpp:dataforms:softwareinfo</value>
        </field>
      </x>
    </query>
    "#;

    let disco = parse_disco_info_xml(xml).unwrap();
    let canonical = generate_canonical_verification_string(&disco).unwrap();
    assert_eq!(canonical, "http://jabber.org/protocol/caps<");
}

#[test]
fn test_form_with_differing_form_type_values_is_rejected() {
    let xml = r#"
    <query xmlns='http://jabber.org/protocol/disco#info'>
      <x xmlns='jabber:x:data' type='result'>
        <field var='FORM_TYPE' type='hidden'>
          <value>urn:xmpp:dataforms:first</value>
          <value>urn:xmpp:dataforms:second</value>
        </field>
      </x>
    </query>
    "#;

    let err = parse_disco_info_xml(xml).unwrap_err();
    assert!(matches!(err, CapsError::AmbiguousFormType));
}
