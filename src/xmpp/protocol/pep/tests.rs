use super::*;
use roxmltree::Document;

#[test]
fn bookmarks_event_contains_only_the_locked_changed_items() {
    let changed = "<item id='changed@conference.example.test'><conference xmlns='urn:xmpp:bookmarks:1' name='new'/></item>";
    let event = bookmarks2_items_event(&[("changed@conference.example.test", changed)])
        .unwrap()
        .unwrap();
    let document = Document::parse(&event).unwrap();
    let items = document.root_element();
    assert_eq!(items.tag_name().name(), "items");
    assert_eq!(items.attribute("node"), Some(BOOKMARKS2));
    let children = items
        .children()
        .filter(Node::is_element)
        .collect::<Vec<_>>();
    assert_eq!(children.len(), 1);
    assert_eq!(
        children[0].attribute("id"),
        Some("changed@conference.example.test")
    );
    assert!(bookmarks2_items_event(&[]).unwrap().is_none());
}

#[test]
fn c2s_pep_subscription_handlers_delegate_authority_to_the_service() {
    let source = super::module_source();
    let subscribe = source
        .split_once("async fn pep_subscribe(")
        .expect("PEP subscribe handler must remain identifiable")
        .1
        .split_once("async fn pep_unsubscribe(")
        .expect("PEP subscribe handler must end before unsubscribe")
        .0;
    let unsubscribe = source
        .split_once("async fn pep_unsubscribe(")
        .expect("PEP unsubscribe handler must remain identifiable")
        .1
        .split_once("async fn pep_target_owner(")
        .expect("PEP unsubscribe handler must end before target resolution")
        .0;
    for handler in [subscribe, unsubscribe] {
        for forbidden in [
            ".pep_node(",
            "pep_access_allowed(",
            "subscribe_pep_node_with_outbox(",
        ] {
            assert!(
                !handler.contains(forbidden),
                "PEP subscription authority escaped the service transaction: {forbidden}"
            );
        }
    }
    assert!(subscribe.contains(".subscribe_pep_node("));
    assert!(unsubscribe.contains(".unsubscribe_pep_node("));
}

#[test]
fn generated_or_canonicalized_pep_id_is_inserted_into_stored_item() {
    assert_eq!(
        normalized_pep_item("<item><value/></item>", "generated", true),
        "<item id='generated'><value/></item>"
    );
    assert_eq!(
        normalized_pep_item("<item/>", "generated", true),
        "<item id='generated'/>"
    );
    assert_eq!(
        normalized_pep_item(
            "<item id='ALICE@BÜCHER.example'><value/></item>",
            "alice@bücher.example",
            true,
        ),
        "<item id='alice@bücher.example'><value/></item>"
    );
}

#[test]
fn contact_notifications_preserve_the_rfc7622_ulabel_identity() {
    let canonical =
        northstar_pubsub_core::canonical_profile_item_id(CONTACTS, "TEMP@xn--bcher-kva.example")
            .unwrap();
    assert_eq!(canonical, "temp@bücher.example");

    let stored = normalized_pep_item(
        "<item id='TEMP@xn--bcher-kva.example'><vcard xmlns='urn:ietf:params:xml:ns:vcard-4.0'><fn><text>Temporary Contact</text></fn></vcard></item>",
        &canonical,
        true,
    );
    let event = published_event_items(CONTACTS, &[(canonical.clone(), stored)]).unwrap();
    assert!(event.contains("id='temp@bücher.example'"));
    assert!(!event.contains("xn--bcher-kva.example"));
    assert!(!event.contains("TEMP@"));
}

#[test]
fn omemo_device_list_rejects_duplicate_or_invalid_ids() {
    let valid = Document::parse(
        "<item xmlns='http://jabber.org/protocol/pubsub' id='current'><devices xmlns='urn:xmpp:omemo:2'><device id='1'/><device id='2'/></devices></item>",
    )
    .unwrap();
    assert!(valid_pep_payload(
        OMEMO_DEVICES,
        "current",
        valid.root_element()
    ));
    for xml in [
        "<item xmlns='http://jabber.org/protocol/pubsub'><devices xmlns='urn:xmpp:omemo:2'><device id='1'/><device id='1'/></devices></item>",
        "<item xmlns='http://jabber.org/protocol/pubsub'><devices xmlns='urn:xmpp:omemo:2'><device id='0'/></devices></item>",
        "<item xmlns='http://jabber.org/protocol/pubsub'><devices xmlns='urn:xmpp:omemo:2'/><extra/></item>",
        "<item xmlns='http://jabber.org/protocol/pubsub'><devices xmlns='urn:xmpp:omemo:2' xmlns:x='urn:example:attacker'><device id='1' x:label='spoofed'/></devices></item>",
    ] {
        let document = Document::parse(xml).unwrap();
        assert!(!valid_pep_payload(
            OMEMO_DEVICES,
            "current",
            document.root_element()
        ));
    }
}

#[test]
fn omemo_payloads_bound_labels_and_require_well_formed_base64_bundles() {
    let public_key = BASE64.encode([7_u8; 32]);
    let signature = BASE64.encode([8_u8; 64]);
    let prekeys = (1..=25)
        .map(|id| format!("<pk id='{id}'>{public_key}</pk>"))
        .collect::<String>();
    let bundle_xml = format!(
        "<item xmlns='http://jabber.org/protocol/pubsub' id='42'><bundle xmlns='urn:xmpp:omemo:2'><spk id='1'>{public_key}</spk><spks>{signature}</spks><ik>{public_key}</ik><prekeys>{prekeys}</prekeys></bundle></item>"
    );
    let bundle = Document::parse(&bundle_xml).unwrap();
    assert!(valid_pep_payload(
        OMEMO_BUNDLES,
        "42",
        bundle.root_element()
    ));
    let namespaced_bundle_xml = bundle_xml
        .replace(
            "<bundle xmlns='urn:xmpp:omemo:2'>",
            "<bundle xmlns='urn:xmpp:omemo:2' xmlns:x='urn:example:attacker'>",
        )
        .replace("<spk id='1'>", "<spk id='1' x:id='2'>");
    let namespaced_bundle = Document::parse(&namespaced_bundle_xml).unwrap();
    assert!(!valid_pep_payload(
        OMEMO_BUNDLES,
        "42",
        namespaced_bundle.root_element()
    ));

    for xml in [
        "<item xmlns='http://jabber.org/protocol/pubsub'><bundle xmlns='urn:xmpp:omemo:2'><spk id='1'>not-base64!</spk><spks>BAUG</spks><ik>BwgJ</ik><prekeys><pk id='1'>CgsM</pk></prekeys></bundle></item>",
        "<item xmlns='http://jabber.org/protocol/pubsub'><bundle xmlns='urn:xmpp:omemo:2'><spk id='1'>AQID</spk><spk id='2'>AQID</spk><spks>BAUG</spks><ik>BwgJ</ik><prekeys><pk id='1'>CgsM</pk></prekeys></bundle></item>",
        "<item xmlns='http://jabber.org/protocol/pubsub'><bundle xmlns='urn:xmpp:omemo:2'><spk id='1'>AQID</spk><spks>BAUG</spks><ik>BwgJ</ik><prekeys><pk id='1'>CgsM</pk><pk id='1'>DQ4P</pk></prekeys></bundle></item>",
    ] {
        let document = Document::parse(xml).unwrap();
        assert!(!valid_pep_payload(
            OMEMO_BUNDLES,
            "42",
            document.root_element()
        ));
    }

    let too_few = bundle_xml.replace(
        &prekeys,
        &(1..=24)
            .map(|id| format!("<pk id='{id}'>{public_key}</pk>"))
            .collect::<String>(),
    );
    let document = Document::parse(&too_few).unwrap();
    assert!(!valid_pep_payload(
        OMEMO_BUNDLES,
        "42",
        document.root_element()
    ));
    let short_key = bundle_xml.replacen(&public_key, "AQID", 1);
    let document = Document::parse(&short_key).unwrap();
    assert!(!valid_pep_payload(
        OMEMO_BUNDLES,
        "42",
        document.root_element()
    ));

    let unsigned_label = Document::parse(
        "<item xmlns='http://jabber.org/protocol/pubsub'><devices xmlns='urn:xmpp:omemo:2'><device id='1' label='phone'/></devices></item>",
    )
    .unwrap();
    // The receiving client, which has the referenced identity key, must
    // ignore an unsigned label. The server stores and forwards the device
    // announcement instead of blocking OMEMO initialization.
    assert!(valid_pep_payload(
        OMEMO_DEVICES,
        "current",
        unsigned_label.root_element()
    ));
    let signed_label_xml = format!(
        "<item xmlns='http://jabber.org/protocol/pubsub'><devices xmlns='urn:xmpp:omemo:2'><device id='1' label='phone' labelsig='{}'/></devices></item>",
        BASE64.encode([9_u8; 64])
    );
    let signed_label = Document::parse(&signed_label_xml).unwrap();
    assert!(valid_pep_payload(
        OMEMO_DEVICES,
        "current",
        signed_label.root_element()
    ));
    let bad_signature = Document::parse(
        "<item xmlns='http://jabber.org/protocol/pubsub'><devices xmlns='urn:xmpp:omemo:2'><device id='1' label='phone' labelsig='!'/></devices></item>",
    )
    .unwrap();
    assert!(valid_pep_payload(
        OMEMO_DEVICES,
        "current",
        bad_signature.root_element()
    ));
    let short_signature = Document::parse(
        "<item xmlns='http://jabber.org/protocol/pubsub'><devices xmlns='urn:xmpp:omemo:2'><device id='1' label='phone' labelsig='AQID'/></devices></item>",
    )
    .unwrap();
    assert!(valid_pep_payload(
        OMEMO_DEVICES,
        "current",
        short_signature.root_element()
    ));
    let oversized_signature = format!(
        "<item xmlns='http://jabber.org/protocol/pubsub'><devices xmlns='urn:xmpp:omemo:2'><device id='1' label='phone' labelsig='{}'/></devices></item>",
        "A".repeat(4_097)
    );
    let oversized_signature = Document::parse(&oversized_signature).unwrap();
    assert!(!valid_pep_payload(
        OMEMO_DEVICES,
        "current",
        oversized_signature.root_element()
    ));
}

#[test]
fn event_embedding_strips_only_item_root_pubsub_namespace() {
    let payload = "<item xmlns='http://jabber.org/protocol/pubsub' id='one'><payload xmlns='http://jabber.org/protocol/pubsub'><item xmlns='urn:nested'/></payload></item><items xmlns='http://jabber.org/protocol/pubsub'/>";
    assert_eq!(
        strip_pubsub_item_root_namespaces(payload).unwrap(),
        "<item id='one'><payload xmlns='http://jabber.org/protocol/pubsub'><item xmlns='urn:nested'/></payload></item><items xmlns='http://jabber.org/protocol/pubsub'/>"
    );
}

#[test]
fn publish_options_apply_omemo_defaults_and_reject_unknown_fields() {
    let xml = "<pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='urn:xmpp:omemo:2:bundles'/><publish-options><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>http://jabber.org/protocol/pubsub#publish-options</value></field><field var='pubsub#access_model'><value>open</value></field><field var='pubsub#max_items'><value>max</value></field></x></publish-options></pubsub>";
    let document = Document::parse(xml).unwrap();
    let options = publish_options(document.root_element(), OMEMO_BUNDLES).unwrap();
    assert!(options.explicit);
    assert_eq!(options.config.access_model, "open");
    assert_eq!(
        options.config.max_items,
        northstar_pubsub_core::PEP_MAX_ITEMS
    );

    let invalid = xml.replace("pubsub#max_items", "pubsub#unknown");
    let document = Document::parse(&invalid).unwrap();
    assert!(publish_options(document.root_element(), OMEMO_BUNDLES).is_err());
}

#[test]
fn bookmarks_require_private_persistent_publish_options() {
    let xml = "<pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='urn:xmpp:bookmarks:1'/><publish-options><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>http://jabber.org/protocol/pubsub#publish-options</value></field><field var='pubsub#persist_items'><value>true</value></field><field var='pubsub#max_items'><value>max</value></field><field var='pubsub#send_last_published_item'><value>never</value></field><field var='pubsub#access_model'><value>whitelist</value></field></x></publish-options></pubsub>";
    let document = Document::parse(xml).unwrap();
    let options = publish_options(document.root_element(), BOOKMARKS2).unwrap();
    assert!(options.explicit);
    assert_eq!(options.config.access_model, "whitelist");
    assert_eq!(
        options.config.max_items,
        northstar_pubsub_core::PEP_MAX_ITEMS
    );
    assert!(options.config.persist_items);
    assert_eq!(options.config.send_last_published_item, "never");

    for invalid in [
        xml.replace("<value>true</value>", "<value>false</value>"),
        xml.replace("<value>whitelist</value>", "<value>presence</value>"),
        xml.replace("<value>never</value>", "<value>sometimes</value>"),
    ] {
        let document = Document::parse(&invalid).unwrap();
        assert!(publish_options(document.root_element(), BOOKMARKS2).is_err());
    }
}

#[test]
fn bookmarks_validate_item_ids_and_payload_shape() {
    let valid = Document::parse(
        "<item xmlns='http://jabber.org/protocol/pubsub' id='room@conference.example'><conference xmlns='urn:xmpp:bookmarks:1' autojoin='true' name='Room'><nick>alice</nick><extensions><state xmlns='urn:example:state'/></extensions></conference></item>",
    )
    .unwrap();
    assert!(valid_pep_payload(
        BOOKMARKS2,
        "room@conference.example",
        valid.root_element()
    ));

    for (id, xml) in [
        (
            "room@conference.example/device",
            "<item xmlns='http://jabber.org/protocol/pubsub'><conference xmlns='urn:xmpp:bookmarks:1'/></item>",
        ),
        (
            "room@conference.example",
            "<item xmlns='http://jabber.org/protocol/pubsub'><conference xmlns='urn:xmpp:bookmarks:1' jid='other@example'/></item>",
        ),
        (
            "room@conference.example",
            "<item xmlns='http://jabber.org/protocol/pubsub'><conference xmlns='urn:xmpp:bookmarks:1' autojoin='yes'/></item>",
        ),
        (
            "room@conference.example",
            "<item xmlns='http://jabber.org/protocol/pubsub'><conference xmlns='urn:xmpp:bookmarks:1'><nick>a</nick><nick>b</nick></conference></item>",
        ),
        (
            "room@conference.example",
            "<item xmlns='http://jabber.org/protocol/pubsub'><conference xmlns='urn:xmpp:bookmarks:1'><password>secret</password><nick>late</nick></conference></item>",
        ),
        (
            "room@conference.example",
            "<item xmlns='http://jabber.org/protocol/pubsub'><conference xmlns='urn:xmpp:bookmarks:1'><nick><b xmlns='urn:example'>nested</b></nick></conference></item>",
        ),
        (
            "room@conference.example",
            "<item xmlns='http://jabber.org/protocol/pubsub'><conference xmlns='urn:xmpp:bookmarks:1'><state xmlns='urn:example:state'/></conference></item>",
        ),
    ] {
        let document = Document::parse(xml).unwrap();
        assert!(!valid_pep_payload(BOOKMARKS2, id, document.root_element()));
    }
}

#[test]
fn avatar_items_require_decoded_sha1_and_consistent_metadata() {
    let png = BASE64
        .decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGNgZGL+DwABFAEG1rmmRQAAAABJRU5ErkJggg==")
        .unwrap();
    let hash = Sha1::digest(&png)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let data_xml = format!(
        "<item xmlns='http://jabber.org/protocol/pubsub'><data xmlns='urn:xmpp:avatar:data'>{}</data></item>",
        BASE64.encode(&png)
    );
    let data = Document::parse(&data_xml).unwrap();
    assert!(valid_pep_payload(AVATAR_DATA, &hash, data.root_element()));
    let encoded = BASE64.encode(&png);
    let folded_data_xml =
        data_xml.replace(&encoded, &format!("{}\n{}", &encoded[..20], &encoded[20..]));
    let folded_data = Document::parse(&folded_data_xml).unwrap();
    assert!(valid_pep_payload(
        AVATAR_DATA,
        &hash,
        folded_data.root_element()
    ));
    let split_data_xml = data_xml.replace(
        &encoded,
        &format!("{}<![CDATA[{}]]>", &encoded[..20], &encoded[20..]),
    );
    let split_data = Document::parse(&split_data_xml).unwrap();
    assert!(valid_pep_payload(
        AVATAR_DATA,
        &hash,
        split_data.root_element()
    ));
    assert!(!valid_pep_payload(
        AVATAR_DATA,
        "0000000000000000000000000000000000000000",
        data.root_element()
    ));

    let fake_png = b"\x89PNG\r\n\x1a\nnot-an-image";
    let fake_hash = Sha1::digest(fake_png)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let fake_xml = format!(
        "<item xmlns='http://jabber.org/protocol/pubsub'><data xmlns='urn:xmpp:avatar:data'>{}</data></item>",
        BASE64.encode(fake_png)
    );
    let fake = Document::parse(&fake_xml).unwrap();
    assert!(!valid_pep_payload(
        AVATAR_DATA,
        &fake_hash,
        fake.root_element()
    ));

    let mut bad_crc = png.clone();
    bad_crc[30] ^= 1;
    assert!(!valid_png_image(&bad_crc));
    let mut trailing = png.clone();
    trailing.push(0);
    assert!(!valid_png_image(&trailing));

    let gif_only_xml = format!(
        "<item xmlns='http://jabber.org/protocol/pubsub'><metadata xmlns='urn:xmpp:avatar:metadata'><info bytes='5' id='{hash}' type='image/gif'/></metadata></item>"
    );
    let gif_only = Document::parse(&gif_only_xml).unwrap();
    assert!(!valid_pep_payload(
        AVATAR_METADATA,
        &hash,
        gif_only.root_element()
    ));

    let jpeg = [0xff, 0xd8, 0xff, 0xd9];
    let jpeg_hash = Sha1::digest(jpeg)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let jpeg_xml = format!(
        "<item xmlns='http://jabber.org/protocol/pubsub'><data xmlns='urn:xmpp:avatar:data'>{}</data></item>",
        BASE64.encode(jpeg)
    );
    let jpeg_data = Document::parse(&jpeg_xml).unwrap();
    assert!(!valid_pep_payload(
        AVATAR_DATA,
        &jpeg_hash,
        jpeg_data.root_element()
    ));

    let metadata_xml = format!(
        "<item xmlns='http://jabber.org/protocol/pubsub'><metadata xmlns='urn:xmpp:avatar:metadata'><info bytes='5' id='{hash}' type='image/png'/></metadata></item>"
    );
    let metadata = Document::parse(&metadata_xml).unwrap();
    assert!(valid_pep_payload(
        AVATAR_METADATA,
        &hash,
        metadata.root_element()
    ));
    assert!(!valid_pep_payload(
        AVATAR_METADATA,
        "0000000000000000000000000000000000000000",
        metadata.root_element()
    ));

    let clear = Document::parse(
        "<item xmlns='http://jabber.org/protocol/pubsub'><metadata xmlns='urn:xmpp:avatar:metadata'/></item>",
    )
    .unwrap();
    assert!(valid_pep_payload(
        AVATAR_METADATA,
        "current",
        clear.root_element()
    ));
}

#[test]
fn avatar_metadata_accepts_external_alternates_and_strict_pointers() {
    let png = BASE64
        .decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGNgZGL+DwABFAEG1rmmRQAAAABJRU5ErkJggg==")
        .unwrap();
    let hash = Sha1::digest(&png)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let external_only_xml = format!(
        "<item xmlns='http://jabber.org/protocol/pubsub'><metadata xmlns='urn:xmpp:avatar:metadata'><info bytes='{}' id='{hash}' type='IMAGE/PNG' url='HTTPS://avatars.example.test/a.png'/></metadata></item>",
        png.len()
    );
    let external_only = Document::parse(&external_only_xml).unwrap();
    assert!(valid_pep_payload(
        AVATAR_METADATA,
        &hash,
        external_only.root_element()
    ));

    let multiple_xml = format!(
        "<item xmlns='http://jabber.org/protocol/pubsub'><metadata xmlns='urn:xmpp:avatar:metadata'><info bytes='8' id='{hash}' type='image/png'/><info bytes='42' id='1111111111111111111111111111111111111111' type='video/mp4' url='https://avatars.example.test/a.mp4'/><pointer type='image/png'><x xmlns='urn:example:avatar-pointer'><account>alice</account></x></pointer></metadata></item>"
    );
    let multiple = Document::parse(&multiple_xml).unwrap();
    assert!(valid_pep_payload(
        AVATAR_METADATA,
        &hash,
        multiple.root_element()
    ));

    for invalid_xml in [
        format!(
            "<item xmlns='http://jabber.org/protocol/pubsub'><metadata xmlns='urn:xmpp:avatar:metadata'><info bytes='8' id='{hash}' type='image/png'/><pointer><x xmlns=''/></pointer></metadata></item>"
        ),
        format!(
            "<item xmlns='http://jabber.org/protocol/pubsub'><metadata xmlns='urn:xmpp:avatar:metadata'><info bytes='8' id='{hash}' type='image/png'/><pointer><x xmlns='urn:example:pointer'/></pointer><info bytes='8' id='{hash}' type='image/png'/></metadata></item>"
        ),
        format!(
            "<item xmlns='http://jabber.org/protocol/pubsub'><metadata xmlns='urn:xmpp:avatar:metadata'><info bytes='8' id='{hash}' type='image/' url='https://avatars.example.test/a'/></metadata></item>"
        ),
        format!(
            "<item xmlns='http://jabber.org/protocol/pubsub'><metadata xmlns='urn:xmpp:avatar:metadata'><info bytes='8' id='{hash}' type='image/png;profile=x' url='https://avatars.example.test/a'/></metadata></item>"
        ),
        format!(
            "<item xmlns='http://jabber.org/protocol/pubsub'><metadata xmlns='urn:xmpp:avatar:metadata'><info bytes='8' id='{hash}' type='image/png' url='http://'/></metadata></item>"
        ),
        format!(
            "<item xmlns='http://jabber.org/protocol/pubsub'><metadata xmlns='urn:xmpp:avatar:metadata'><info bytes='8' id='{hash}' type='image/png' url='ftp://avatars.example.test/a'/></metadata></item>"
        ),
        format!(
            "<item xmlns='http://jabber.org/protocol/pubsub'><metadata xmlns='urn:xmpp:avatar:metadata'>unexpected<info bytes='8' id='{hash}' type='image/png'/></metadata></item>"
        ),
        format!(
            "<item xmlns='http://jabber.org/protocol/pubsub'><metadata xmlns='urn:xmpp:avatar:metadata'><info bytes='8' id='{hash}' type='image/png'/><pointer>unexpected<x xmlns='urn:example:pointer'/></pointer></metadata></item>"
        ),
    ] {
        let invalid = Document::parse(&invalid_xml).unwrap();
        assert!(!valid_pep_payload(
            AVATAR_METADATA,
            &hash,
            invalid.root_element()
        ));
    }
}

#[test]
fn avatar_and_vcard_nodes_reject_non_public_or_non_persistent_options() {
    let base = "<pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='urn:xmpp:avatar:metadata'/><publish-options><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>http://jabber.org/protocol/pubsub#publish-options</value></field><field var='pubsub#access_model'><value>open</value></field><field var='pubsub#max_items'><value>1</value></field><field var='pubsub#persist_items'><value>true</value></field></x></publish-options></pubsub>";
    let document = Document::parse(base).unwrap();
    assert!(publish_options(document.root_element(), AVATAR_METADATA).is_ok());
    for invalid in [
        base.replace("<value>open</value>", "<value>presence</value>"),
        base.replace("<value>true</value>", "<value>false</value>"),
        base.replace("<value>1</value>", "<value>2</value>"),
    ] {
        let document = Document::parse(&invalid).unwrap();
        assert!(publish_options(document.root_element(), AVATAR_METADATA).is_err());
    }
}

#[test]
fn vcard4_event_is_a_pure_item_notification() {
    let stored = "<item id='current'><vcard xmlns='urn:ietf:params:xml:ns:vcard-4.0'><fn><text>Alice</text></fn></vcard></item>";
    let payload =
        published_event_items(VCARD4, &[("current".to_owned(), stored.to_owned())]).unwrap();
    assert_eq!(payload, "<item id='current'/>");
    assert!(!payload.contains("vcard"));
    assert_eq!(
        published_event_item(VCARD4, "current", stored).unwrap(),
        "<item id='current'/>"
    );
}

#[test]
fn vcard4_and_contact_nodes_reject_wrong_payload_shapes() {
    let card = Document::parse(
        "<item xmlns='http://jabber.org/protocol/pubsub'><vcard xmlns='urn:ietf:params:xml:ns:vcard-4.0'><fn><text>Alice</text></fn></vcard></item>",
    )
    .unwrap();
    assert!(valid_pep_payload(VCARD4, "generated", card.root_element()));
    assert!(valid_pep_payload(
        CONTACTS,
        "alice@example.test",
        card.root_element()
    ));
    assert!(!valid_pep_payload(
        CONTACTS,
        "not-a-jid",
        card.root_element()
    ));

    for xml in [
        "<item xmlns='http://jabber.org/protocol/pubsub'><vcard xmlns='urn:ietf:params:xml:ns:vcard-4.0'><fn><text>Alice\u{202e}txt.exe</text></fn></vcard></item>",
        "<item xmlns='http://jabber.org/protocol/pubsub'><vcard xmlns='urn:ietf:params:xml:ns:vcard-4.0'/></item>",
        "<item xmlns='http://jabber.org/protocol/pubsub'><vcard xmlns='urn:ietf:params:xml:ns:vcard-4.0'><FN><text>Alice</text></FN></vcard></item>",
        "<item xmlns='http://jabber.org/protocol/pubsub'><vcard xmlns='urn:ietf:params:xml:ns:vcard-4.0'><fn/></vcard></item>",
    ] {
        let invalid = Document::parse(xml).unwrap();
        assert!(!valid_pep_payload(
            VCARD4,
            "generated",
            invalid.root_element()
        ));
    }
}
