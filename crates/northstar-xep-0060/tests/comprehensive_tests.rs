use northstar_xep_0060::*;
use roxmltree::Document;

#[test]
fn rejects_malformed_xml_and_invalid_namespaces() {
    // Malformed XML
    assert!(Document::parse("<pubsub xmlns='http://jabber.org/protocol/pubsub'>").is_err());

    // Wrong namespace on envelope
    let doc =
        Document::parse("<pubsub xmlns='jabber:client'><create node='test'/></pubsub>").unwrap();
    assert!(parse_pubsub_envelope(doc.root_element(), "set").is_err());

    // Wrong child namespace inside entity pubsub envelope
    let doc = Document::parse("<pubsub xmlns='http://jabber.org/protocol/pubsub'><create xmlns='urn:custom' node='test'/></pubsub>").unwrap();
    assert!(parse_pubsub_envelope(doc.root_element(), "set").is_err());

    // Entity envelope with multiple operations that are not RSM
    let doc = Document::parse("<pubsub xmlns='http://jabber.org/protocol/pubsub'><create node='1'/><create node='2'/></pubsub>").unwrap();
    let env = parse_pubsub_envelope(doc.root_element(), "set").unwrap();
    assert!(parse_create_operation(&env.operations).is_err());
}

#[test]
fn rejects_invalid_cardinality_and_attributes() {
    // Retract with multiple unexpected attributes
    let doc = Document::parse("<pubsub xmlns='http://jabber.org/protocol/pubsub'><retract node='test' extra='bad'><item id='1'/></retract></pubsub>").unwrap();
    let env = parse_pubsub_envelope(doc.root_element(), "set").unwrap();
    assert!(parse_retract_operation(&env.operations).is_err());

    // Retract with no items
    let doc = Document::parse(
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'><retract node='test'/></pubsub>",
    )
    .unwrap();
    let env = parse_pubsub_envelope(doc.root_element(), "set").unwrap();
    let err = parse_retract_operation(&env.operations).unwrap_err();
    assert_eq!(err.pubsub_condition, Some("item-required"));

    // Subscribe with invalid JID
    let doc = Document::parse("<pubsub xmlns='http://jabber.org/protocol/pubsub'><subscribe node='test' jid='invalid@@@jid'/></pubsub>").unwrap();
    let env = parse_pubsub_envelope(doc.root_element(), "set").unwrap();
    let err = parse_subscribe_operation(&env.operations, NodeType::Leaf, false).unwrap_err();
    assert_eq!(err.pubsub_condition, Some("invalid-jid"));

    // Subscribe missing JID
    let doc = Document::parse(
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'><subscribe node='test'/></pubsub>",
    )
    .unwrap();
    let env = parse_pubsub_envelope(doc.root_element(), "set").unwrap();
    let err = parse_subscribe_operation(&env.operations, NodeType::Leaf, false).unwrap_err();
    assert_eq!(err.pubsub_condition, Some("jid-required"));
}

#[test]
fn test_item_retrieval_and_publish_access_matrix() {
    // Open node
    assert!(can_retrieve_pure(AccessModel::Open, None, false));
    assert!(can_retrieve_pure(
        AccessModel::Open,
        Some(Affiliation::None),
        false
    ));
    assert!(!can_retrieve_pure(
        AccessModel::Open,
        Some(Affiliation::Outcast),
        false
    ));

    // Whitelist node
    assert!(!can_retrieve_pure(AccessModel::Whitelist, None, false));
    assert!(!can_retrieve_pure(
        AccessModel::Whitelist,
        Some(Affiliation::None),
        false
    ));
    assert!(can_retrieve_pure(
        AccessModel::Whitelist,
        Some(Affiliation::Member),
        false
    ));
    assert!(can_retrieve_pure(
        AccessModel::Whitelist,
        Some(Affiliation::Publisher),
        false
    ));
    assert!(can_retrieve_pure(
        AccessModel::Whitelist,
        Some(Affiliation::Owner),
        false
    ));
    assert!(can_retrieve_pure(AccessModel::Whitelist, None, true));

    // Authorize node
    assert!(!can_retrieve_pure(AccessModel::Authorize, None, false));
    assert!(can_retrieve_pure(
        AccessModel::Authorize,
        Some(Affiliation::Member),
        false
    ));
    assert!(can_retrieve_pure(AccessModel::Authorize, None, true));

    // Publishers publish model
    assert!(can_publish_pure(
        PublishModel::Publishers,
        AccessModel::Open,
        Some(Affiliation::Owner),
        false
    ));
    assert!(can_publish_pure(
        PublishModel::Publishers,
        AccessModel::Open,
        Some(Affiliation::Publisher),
        false
    ));
    assert!(can_publish_pure(
        PublishModel::Publishers,
        AccessModel::Open,
        Some(Affiliation::PublishOnly),
        false
    ));
    assert!(!can_publish_pure(
        PublishModel::Publishers,
        AccessModel::Open,
        Some(Affiliation::Member),
        true
    ));

    // Subscribers publish model
    assert!(can_publish_pure(
        PublishModel::Subscribers,
        AccessModel::Authorize,
        None,
        true
    ));
    assert!(!can_publish_pure(
        PublishModel::Subscribers,
        AccessModel::Authorize,
        None,
        false
    ));
}

#[test]
fn test_node_configuration_invariants() {
    // Collection node automatically forces persist_items=false, deliver_payloads=false
    let mut config = NodeConfig {
        node_type: NodeType::Collection,
        persist_items: true,
        deliver_payloads: true,
        ..Default::default()
    };
    config.validate_and_normalize().unwrap();

    assert_eq!(config.node_type, NodeType::Collection);
    assert!(!config.persist_items);
    assert!(!config.deliver_payloads);
    assert_eq!(
        config.send_last_published_item,
        SendLastPublishedItem::Never
    );

    // Leaf node cannot have children
    let mut leaf = NodeConfig {
        node_type: NodeType::Leaf,
        children: vec!["child-1".to_string()],
        ..Default::default()
    };
    assert!(leaf.validate_and_normalize().is_err());
}

#[test]
fn test_owner_operations_and_event_builders() {
    // Event with item and retraction
    let item_xml = "<item id='item-1'><entry xmlns='http://www.w3.org/2005/Atom'><title>Post</title></entry></item>";
    let event = build_event_items("news", &[item_xml], &["retracted-1"]).unwrap();
    assert!(event.contains("node='news'"));
    assert!(event.contains("<retract id='retracted-1'/>"));

    // Event message wrapper with SubID and SHIM headers
    let children = build_subscription_event_children(
        &event,
        "sub-42",
        Some("collection-root"),
        Some("Post summary"),
        Some("2026-09-02T08:00:00Z"),
    )
    .unwrap();

    assert!(children.contains("<header name='SubID'>sub-42</header>"));
    assert!(children.contains("<header name='Collection'>collection-root</header>"));
    assert!(children.contains("<body>Post summary</body>"));
    assert!(children.contains("<delay xmlns='urn:xmpp:delay' stamp='2026-09-02T08:00:00Z'/>"));

    // Owner delete with redirect
    let del_event = build_event_delete("old-node", Some("xmpp:pubsub.example.com?;node=new-node"));
    assert!(del_event.contains("<redirect uri='xmpp:pubsub.example.com?;node=new-node'/>"));

    // Owner purge event
    let purge_event = build_event_purge("my-node");
    assert_eq!(
        purge_event,
        "<event xmlns='http://jabber.org/protocol/pubsub#event'><purge node='my-node'/></event>"
    );
}

#[test]
fn test_rsm_pagination_comprehensive() {
    let dataset = vec!["a", "b", "c", "d", "e", "f", "g", "h", "i", "j"];

    // Forward paging
    let mut req = RsmRequest {
        max: Some(3),
        ..Default::default()
    };
    let (p1, r1) = paginate_items(&dataset, &req, 10, |s| *s).unwrap();
    assert_eq!(p1, vec!["a", "b", "c"]);
    assert_eq!(r1.first, Some((0, "a".to_string())));
    assert_eq!(r1.last, Some("c".to_string()));
    assert_eq!(r1.count, 10);

    req.after = Some(r1.last.unwrap());
    let (p2, r2) = paginate_items(&dataset, &req, 10, |s| *s).unwrap();
    assert_eq!(p2, vec!["d", "e", "f"]);
    assert_eq!(r2.first, Some((3, "d".to_string())));

    // Backward paging before 'f'
    let req_before = RsmRequest {
        max: Some(2),
        before: Some(Some("f".to_string())),
        ..Default::default()
    };
    let (p_b, r_b) = paginate_items(&dataset, &req_before, 10, |s| *s).unwrap();
    assert_eq!(p_b, vec!["d", "e"]);
    assert_eq!(r_b.first, Some((3, "d".to_string())));

    // Non-existent cursor
    let req_bad = RsmRequest {
        after: Some("non-existent".to_string()),
        ..Default::default()
    };
    assert_eq!(
        paginate_items(&dataset, &req_bad, 10, |s| *s)
            .unwrap_err()
            .condition,
        "item-not-found"
    );
}
