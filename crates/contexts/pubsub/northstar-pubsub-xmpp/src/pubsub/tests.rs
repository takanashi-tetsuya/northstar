use super::{
    collection_edge_reply, config_equivalent, data_form_fields, disco_item_xml, disco_rsm_page,
    entity::{item_read_reply, subscription_options_reply},
    error_condition, node_config_form, node_disco_items, node_info_reply, normalized_bare,
    parse_node_config, parse_publish_options, parse_pubsub_rsm, parse_subscription_options,
    publish_batch_size_allowed, pubsub_policy_suppression_is_terminal, pubsub_rsm_page,
    reply_error, self_affiliations_reply, self_subscriptions_reply, serialize_pubsub_item,
    subscription_options_form, subscription_payload, valid_item_id, valid_node_id, DiscoItem,
    PubSubError, PubSubReply, MAX_PUBLISH_ITEMS, NODE_CONFIG_FORM, PUBLISH_OPTIONS_FORM,
    SERVICE_FEATURES, SUBSCRIBE_OPTIONS_FORM,
};
use northstar_pubsub_application::{
    PubSubCollectionDiscoChild, PubSubCollectionDiscoSnapshot, PubSubCollectionEdgeResult,
    PubSubCollectionItemSelection, PubSubItemQuery, PubSubItemRead, PubSubLeafDiscoSnapshot,
    PubSubLeafItemSelection, PubSubNodeInfo, PubSubNodeItems, PubSubOptionsNode, PubSubOptionsRead,
    PubSubSelfList,
};
use northstar_pubsub_core::{
    CollectionUpdateOutcome, CollectionVisibleItem, PubSubAffiliation, PubSubItem,
    PubSubNodeConfig, PubSubSubscription, PubSubSubscriptionOptions, SubscriptionLeasePatch,
    SubscriptionOptionsPatch,
};
use northstar_time::{DateTime, Utc};
use roxmltree::Document;

#[test]
fn collection_edge_results_preserve_xep_0248_errors() {
    assert!(matches!(
        collection_edge_reply(PubSubCollectionEdgeResult::Mutation(
            CollectionUpdateOutcome::Updated
        )),
        PubSubReply::Result(value) if value.is_empty()
    ));
    for (result, condition, pubsub_condition) in [
        (
            PubSubCollectionEdgeResult::MissingChild,
            "item-not-found",
            None,
        ),
        (
            PubSubCollectionEdgeResult::Mutation(CollectionUpdateOutcome::NotFound),
            "item-not-found",
            None,
        ),
        (
            PubSubCollectionEdgeResult::Mutation(CollectionUpdateOutcome::NotAssociated),
            "bad-request",
            None,
        ),
        (
            PubSubCollectionEdgeResult::Mutation(CollectionUpdateOutcome::NotCollection),
            "not-allowed",
            Some("invalid-options"),
        ),
        (
            PubSubCollectionEdgeResult::Mutation(CollectionUpdateOutcome::Forbidden),
            "forbidden",
            None,
        ),
        (
            PubSubCollectionEdgeResult::Mutation(CollectionUpdateOutcome::LimitExceeded),
            "not-allowed",
            Some("max-nodes-exceeded"),
        ),
        (
            PubSubCollectionEdgeResult::Mutation(CollectionUpdateOutcome::DepthExceeded),
            "not-allowed",
            Some("invalid-options"),
        ),
        (
            PubSubCollectionEdgeResult::Mutation(CollectionUpdateOutcome::Cycle),
            "not-allowed",
            Some("invalid-options"),
        ),
    ] {
        let reply = collection_edge_reply(result);
        assert_eq!(error_condition(&reply), Some(condition));
        match reply {
            PubSubReply::ExtendedError(error) => {
                assert_eq!(error.pubsub_condition, pubsub_condition);
            }
            PubSubReply::Error(_) => assert_eq!(pubsub_condition, None),
            PubSubReply::Result(_) => panic!("an error result became success"),
        }
    }
}

#[test]
fn atom_event_body_limit_never_splits_a_utf8_character() {
    let summary = format!("{}ƞ", "a".repeat(1_023));
    let event =
        format!("<entry xmlns='http://www.w3.org/2005/Atom'><summary>{summary}</summary></entry>");
    let body = northstar_xep_0060::extract_atom_event_body(&event)
        .unwrap()
        .unwrap();
    assert_eq!(body.len(), 1_023);
    assert_eq!(body, "a".repeat(1_023));
}

#[test]
fn pubsub_ownership_keys_use_precis_idna_and_bare_identity() {
    assert_eq!(
        normalized_bare("A\u{30a}LICE@B\u{fc}CHER.Example./Phone").unwrap(),
        normalized_bare("\u{e5}lice@b\u{fc}cher.example/tablet").unwrap()
    );
    assert_ne!(
        normalized_bare("alice@example.test/Phone").unwrap(),
        normalized_bare("alice@example.net/Phone").unwrap()
    );
    assert_ne!(
        normalized_bare("alice@example.test").unwrap(),
        normalized_bare("alice2@example.test").unwrap()
    );
}

#[test]
fn validates_pubsub_identifiers_without_leaking_generated_strings() {
    assert_eq!(valid_node_id(Some("news/world")), Some("news/world"));
    assert!(valid_node_id(Some("")).is_none());
    assert!(valid_node_id(Some("bad\nnode")).is_none());
    assert!(valid_item_id("item-1"));
    assert!(!valid_item_id("bad\u{7f}"));
}

#[test]
fn leaf_disco_items_use_name_and_never_masquerade_as_nodes() {
    let item = DiscoItem {
        node: "item<&1".to_owned(),
        title: None,
        published_item: true,
    };
    let xml = disco_item_xml("pubsub.example.test", &item);
    let document = Document::parse(&xml).unwrap();
    let root = document.root_element();
    assert_eq!(root.attribute("jid"), Some("pubsub.example.test"));
    assert_eq!(root.attribute("name"), Some("item<&1"));
    assert_eq!(root.attribute("node"), None);
}

#[test]
fn discovery_snapshot_errors_preserve_missing_redirect_and_forbidden() {
    let uri = "xmpp:pubsub.example.test?;node=new&view=1";
    for redirect in [None, Some(uri.to_owned())] {
        let replies = [
            node_info_reply(
                "old",
                PubSubNodeInfo::Missing {
                    redirect: redirect.clone(),
                },
            )
            .unwrap(),
            node_disco_items(PubSubNodeItems::Missing {
                redirect: redirect.clone(),
            })
            .unwrap_err(),
            self_subscriptions_reply(
                Some("old"),
                PubSubSelfList::Missing {
                    redirect: redirect.clone(),
                },
            ),
            self_affiliations_reply(PubSubSelfList::Missing {
                redirect: redirect.clone(),
            }),
        ];
        for reply in replies {
            if redirect.is_some() {
                let xml = super::pubsub_s2s_iq_error(
                    "i1",
                    "pubsub.example.test",
                    "remote.example.test",
                    &reply,
                );
                let document = Document::parse(&xml).unwrap();
                let gone = document
                    .descendants()
                    .find(|element| element.has_tag_name("gone"))
                    .unwrap();
                assert_eq!(gone.text(), Some(uri));
                assert_eq!(error_condition(&reply), Some("gone"));
            } else {
                assert!(matches!(reply, PubSubReply::Error("item-not-found")));
            }
        }
    }
    assert!(matches!(
        node_info_reply("private", PubSubNodeInfo::Forbidden).unwrap(),
        PubSubReply::Error("forbidden")
    ));
    for outcome in [PubSubNodeItems::Forbidden, PubSubNodeItems::UnsupportedKind] {
        assert!(matches!(
            node_disco_items(outcome),
            Err(PubSubReply::Error("forbidden"))
        ));
    }
}

#[test]
fn discovery_snapshot_items_keep_leaf_and_collection_cursor_keys() {
    let leaf = PubSubNodeItems::Leaf(PubSubLeafDiscoSnapshot {
        node_type: "leaf".to_owned(),
        access_model: "open".to_owned(),
        affiliation: None,
        subscribed: false,
        item_ids: vec!["alpha".to_owned(), "beta".to_owned()],
    });
    let collection = PubSubNodeItems::Collection(PubSubCollectionDiscoSnapshot {
        node_type: "collection".to_owned(),
        access_model: "open".to_owned(),
        affiliation: None,
        subscribed: false,
        children: vec![
            PubSubCollectionDiscoChild {
                node: "alpha".to_owned(),
                title: None,
            },
            PubSubCollectionDiscoChild {
                node: "beta".to_owned(),
                title: Some("Title".to_owned()),
            },
        ],
    });
    let rsm = Document::parse(
        "<set xmlns='http://jabber.org/protocol/rsm'><max>1</max><after>alpha</after></set>",
    )
    .unwrap();
    let request = parse_pubsub_rsm(rsm.root_element()).unwrap();
    for (outcome, expected_node, expected_name) in
        [(leaf, None, "beta"), (collection, Some("beta"), "Title")]
    {
        let items = node_disco_items(outcome).unwrap();
        let (items, rsm) = disco_rsm_page(items, &request, 100).unwrap();
        assert_eq!(items.len(), 1);
        assert!(rsm.contains("<first index='1'>beta</first><last>beta</last><count>2</count>"));
        let xml = disco_item_xml("pubsub.example.test", &items[0]);
        let document = Document::parse(&xml).unwrap();
        let item = document.root_element();
        assert_eq!(item.attribute("node"), expected_node);
        assert_eq!(item.attribute("name"), Some(expected_name));
    }
}

#[test]
fn self_list_snapshot_replies_preserve_filtered_and_unfiltered_xml() {
    for node_filter in [Some("n"), None] {
        let reply =
            self_subscriptions_reply(node_filter, PubSubSelfList::List(vec![subscription("id")]));
        let PubSubReply::Result(xml) = reply else {
            panic!("expected subscriptions result");
        };
        let document = Document::parse(&xml).unwrap();
        let entries = document.root_element().first_element_child().unwrap();
        assert_eq!(entries.tag_name().name(), "subscriptions");
        assert_eq!(entries.attribute("node"), node_filter);
        let entry = entries.first_element_child().unwrap();
        assert_eq!(entry.attribute("node"), Some("n"));
        assert_eq!(entry.attribute("subid"), Some("id"));
    }
    let reply = self_affiliations_reply(PubSubSelfList::List(vec![PubSubAffiliation {
        node: "n".to_owned(),
        jid: "alice@example.test".to_owned(),
        affiliation: "owner".to_owned(),
    }]));
    let PubSubReply::Result(xml) = reply else {
        panic!("expected affiliations result");
    };
    let document = Document::parse(&xml).unwrap();
    let entries = document.root_element().first_element_child().unwrap();
    assert_eq!(entries.tag_name().name(), "affiliations");
    assert_eq!(entries.attribute("node"), None);
    let entry = entries.first_element_child().unwrap();
    assert_eq!(entry.attribute("node"), Some("n"));
    assert_eq!(entry.attribute("affiliation"), Some("owner"));
}

#[test]
fn escapes_subscription_response_values() {
    let payload = subscription_payload(
        "a'node",
        "u&x@example.test",
        "subscribed",
        Some("sub&1"),
        None,
    );
    assert!(payload.contains("a&apos;node"));
    assert!(payload.contains("u&amp;x@example.test"));
    assert!(payload.contains("subid='sub&amp;1'"));
}

fn subscription(subid: &str) -> PubSubSubscription {
    PubSubSubscription {
        node: "n".to_owned(),
        jid: "alice@example.test/phone".to_owned(),
        state: "subscribed".to_owned(),
        subid: subid.to_owned(),
        deliver: true,
        digest: false,
        digest_frequency: 0,
        expire: None,
        include_body: false,
        show_values: Vec::new(),
        subscription_type: "items".to_owned(),
        subscription_depth: Some(1),
    }
}

#[test]
fn item_retrieval_enforces_subids_and_access_specific_errors() {
    let item_retrieval_access =
        |model, affiliation, subscriptions: &[PubSubSubscription], subid| {
            northstar_pubsub_core::item_retrieval_access(
                model,
                affiliation,
                subscriptions,
                subid,
                DateTime::UNIX_EPOCH,
                northstar_xep_0060::item_retrieval_access,
            )
            .map_err(PubSubReply::ExtendedError)
        };
    let subscriptions = [subscription("one"), subscription("two")];
    let missing_subid = item_retrieval_access("authorize", None, &subscriptions, None).unwrap_err();
    assert_eq!(error_condition(&missing_subid), Some("bad-request"));
    assert!(reply_error(&missing_subid)
        .error_payload()
        .1
        .contains("subid-required"));

    let invalid_subid =
        item_retrieval_access("authorize", None, &subscriptions, Some("wrong")).unwrap_err();
    assert_eq!(error_condition(&invalid_subid), Some("not-acceptable"));
    assert!(reply_error(&invalid_subid)
        .error_payload()
        .1
        .contains("invalid-subid"));
    assert!(item_retrieval_access("authorize", None, &subscriptions, Some("two")).is_ok());

    let closed = item_retrieval_access("whitelist", None, &[], None).unwrap_err();
    assert_eq!(error_condition(&closed), Some("not-allowed"));
    assert!(reply_error(&closed)
        .error_payload()
        .1
        .contains("closed-node"));

    let not_subscribed = item_retrieval_access("authorize", None, &[], None).unwrap_err();
    assert_eq!(error_condition(&not_subscribed), Some("not-authorized"));
    assert!(reply_error(&not_subscribed)
        .error_payload()
        .1
        .contains("not-subscribed"));

    assert_eq!(
        error_condition(&item_retrieval_access("open", Some("outcast"), &[], None).unwrap_err()),
        Some("forbidden")
    );

    let candidates = [
        PubSubSubscription {
            expire: Some(DateTime::UNIX_EPOCH),
            ..subscription("expired")
        },
        PubSubSubscription {
            state: "pending".to_owned(),
            ..subscription("pending")
        },
        subscription("active"),
    ];
    assert!(item_retrieval_access("authorize", None, &candidates, None).is_ok());
    let expired =
        item_retrieval_access("authorize", None, &candidates, Some("expired")).unwrap_err();
    assert_eq!(
        reply_error(&expired).pubsub_condition,
        Some("invalid-subid")
    );
}

fn snapshot_item_query(item_ids: &[String]) -> PubSubItemQuery<'_> {
    PubSubItemQuery {
        node: "n",
        requester: "alice@example.test",
        echoed_subid: None,
        leaf: Some(PubSubLeafItemSelection {
            item_ids,
            max_items: None,
        }),
        collection: PubSubCollectionItemSelection::Items {
            max_items: 100,
            max_xml_bytes: super::MAX_PUBLISH_XML_BYTES as i64,
        },
    }
}

#[test]
fn item_snapshot_errors_preserve_conditions_and_extensions() {
    let query = snapshot_item_query(&[]);
    for denial in [
        PubSubError::forbidden(),
        PubSubError::bad_request(),
        PubSubError::new("not-acceptable", "unsupported-access-model"),
        PubSubError::new("bad-request", "subid-required"),
        PubSubError::new("not-acceptable", "invalid-subid"),
        PubSubError::new("not-allowed", "closed-node"),
        PubSubError::new("not-authorized", "not-subscribed"),
    ] {
        let reply = item_read_reply(PubSubItemRead::Denied(denial.clone()), &query, None).unwrap();
        assert!(matches!(reply, PubSubReply::ExtendedError(error) if error == denial));
    }

    let uri = "xmpp:pubsub.example.test?;node=new";
    for (read, expected) in [
        (
            PubSubItemRead::Missing { redirect: None },
            PubSubError::item_not_found(),
        ),
        (
            PubSubItemRead::Missing {
                redirect: Some(uri.to_owned()),
            },
            PubSubError::moved(uri),
        ),
        (
            PubSubItemRead::NonPersistent,
            PubSubError::unsupported("persistent-items"),
        ),
        (PubSubItemRead::BadRequest, PubSubError::bad_request()),
        (
            PubSubItemRead::CollectionRsmUnsupported,
            PubSubError::unsupported("rsm"),
        ),
    ] {
        let reply = item_read_reply(read, &query, None).unwrap();
        assert_eq!(reply_error(&reply).as_ref(), &expected);
    }
}

#[test]
fn item_snapshot_replies_preserve_leaf_rsm_and_collection_grouping() {
    let query = snapshot_item_query(&[]);
    let leaf_items = || {
        ["newer", "older"]
            .into_iter()
            .map(|id| PubSubItem {
                item_id: id.to_owned(),
                xml_payload: format!("<item id='{id}'/>"),
                created_at: DateTime::UNIX_EPOCH,
            })
            .collect()
    };
    let rsm =
        Document::parse("<set xmlns='http://jabber.org/protocol/rsm'><after>newer</after></set>")
            .unwrap();
    let rsm = parse_pubsub_rsm(rsm.root_element()).unwrap();
    let reply = item_read_reply(
        PubSubItemRead::Leaf {
            max_items: 2,
            items: leaf_items(),
        },
        &query,
        Some(&rsm),
    )
    .unwrap();
    assert!(matches!(reply, PubSubReply::Result(xml) if xml == concat!(
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'><items node='n'><item id='older'/></items>",
        "<set xmlns='http://jabber.org/protocol/rsm'><first index='1'>older</first>",
        "<last>older</last><count>2</count></set></pubsub>"
    )));

    let requested_ids = ["newer".to_owned(), "older".to_owned(), "missing".to_owned()];
    let query_with_missing_id = snapshot_item_query(&requested_ids);
    let reply = item_read_reply(
        PubSubItemRead::Leaf {
            max_items: 2,
            items: leaf_items(),
        },
        &query_with_missing_id,
        None,
    )
    .unwrap();
    assert!(matches!(reply, PubSubReply::Error("item-not-found")));

    let read = PubSubItemRead::Collection {
        items: [("a", "newer"), ("a", "older"), ("b", "newer")]
            .into_iter()
            .map(|(node, id)| CollectionVisibleItem {
                node: node.to_owned(),
                xml_payload: format!("<item id='{id}'/>"),
            })
            .collect(),
    };
    let reply = item_read_reply(read, &query, None).unwrap();
    assert!(matches!(reply, PubSubReply::Result(xml) if xml == concat!(
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'><items node='a'>",
        "<item id='newer'/><item id='older'/></items><items node='b'><item id='newer'/></items></pubsub>"
    )));
}

#[test]
fn subscription_options_snapshot_replies_preserve_errors_and_form_fields() {
    let uri = "xmpp:pubsub.example.test?;node=new";
    for (read, expected) in [
        (
            PubSubOptionsRead::Missing { redirect: None },
            PubSubError::item_not_found(),
        ),
        (
            PubSubOptionsRead::Missing {
                redirect: Some(uri.to_owned()),
            },
            PubSubError::moved(uri),
        ),
        (
            PubSubOptionsRead::NotSubscribed,
            PubSubError::new("unexpected-request", "not-subscribed"),
        ),
        (
            PubSubOptionsRead::InvalidSubid,
            PubSubError::new("not-acceptable", "invalid-subid"),
        ),
    ] {
        let reply = subscription_options_reply(read, "n", "alice@example.test/phone").unwrap();
        assert_eq!(reply_error(&reply).as_ref(), &expected);
    }

    let mut subscription = subscription("sub&1");
    subscription.include_body = true;
    let read = PubSubOptionsRead::Ready {
        node: Box::new(PubSubOptionsNode {
            id: uuid::Uuid::nil(),
            node_type: "collection".to_owned(),
            payload_type: Some("http://www.w3.org/2005/Atom".to_owned()),
        }),
        subscription,
    };
    let reply = subscription_options_reply(read, "n", "alice@example.test/phone").unwrap();
    let PubSubReply::Result(xml) = reply else {
        panic!("expected options form: {reply:?}");
    };
    let document = Document::parse(&xml).unwrap();
    let options = document.root_element().first_element_child().unwrap();
    assert_eq!(options.attribute("node"), Some("n"));
    assert_eq!(options.attribute("jid"), Some("alice@example.test/phone"));
    assert_eq!(options.attribute("subid"), Some("sub&1"));
    let form = options.first_element_child().unwrap();
    assert_eq!(form.attribute("type"), Some("form"));
    assert_eq!(
        form.children()
            .filter_map(|field| field.attribute("var"))
            .collect::<Vec<_>>(),
        [
            "FORM_TYPE",
            "pubsub#deliver",
            "pubsub#digest",
            "pubsub#digest_frequency",
            "pubsub#expire",
            "pubsub#include_body",
            "pubsub#show-values",
            "pubsub#subscription_type",
            "pubsub#subscription_depth",
        ],
    );
}

#[test]
fn parses_and_round_trips_node_configuration() {
    let xml = "<configure xmlns='http://jabber.org/protocol/pubsub#owner'><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>http://jabber.org/protocol/pubsub#node_config</value></field><field var='pubsub#access_model'><value>authorize</value></field><field var='pubsub#max_items'><value>42</value></field><field var='pubsub#persist_items'><value>0</value></field></x></configure>";
    let document = Document::parse(xml).unwrap();
    let parsed = parse_node_config(document.root_element(), PubSubNodeConfig::default()).unwrap();
    assert_eq!(parsed.access_model, "authorize");
    assert_eq!(parsed.max_items, 42);
    assert!(!parsed.persist_items);
    let rendered = node_config_form(&parsed, "form");
    let rendered_doc = Document::parse(&rendered).unwrap();
    let fields = data_form_fields(rendered_doc.root_element());
    assert_eq!(fields["pubsub#max_items"], ["42"]);
    assert_eq!(fields["pubsub#children_association_policy"], ["owners"]);
    assert!(config_equivalent(&parsed, &parsed.clone()));
}

#[test]
fn rejects_non_submit_duplicate_and_multi_value_configuration_fields() {
    for xml in [
        "<configure xmlns='http://jabber.org/protocol/pubsub#owner'><x xmlns='jabber:x:data' type='form'><field var='FORM_TYPE'><value>http://jabber.org/protocol/pubsub#node_config</value></field></x></configure>",
        "<configure xmlns='http://jabber.org/protocol/pubsub#owner'><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>http://jabber.org/protocol/pubsub#node_config</value></field><field var='pubsub#max_items'><value>1</value><value>2</value></field></x></configure>",
        "<configure xmlns='http://jabber.org/protocol/pubsub#owner'><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>http://jabber.org/protocol/pubsub#node_config</value></field><field var='pubsub#max_items'><value>1</value></field><field var='pubsub#max_items'><value>2</value></field></x></configure>",
        "<configure xmlns='http://jabber.org/protocol/pubsub#owner'><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>http://jabber.org/protocol/pubsub#node_config</value></field></x><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>http://jabber.org/protocol/pubsub#node_config</value></field></x></configure>",
        "<configure xmlns='http://jabber.org/protocol/pubsub#owner'><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>http://jabber.org/protocol/pubsub#node_config</value><unexpected/></field></x></configure>",
    ] {
        let document = Document::parse(xml).unwrap();
        assert_eq!(
            parse_node_config(document.root_element(), PubSubNodeConfig::default())
                .unwrap_err(),
            "bad-request"
        );
    }
}

#[test]
fn unsupported_access_models_use_the_required_pubsub_error() {
    let xml = "<configure xmlns='http://jabber.org/protocol/pubsub#owner'><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>http://jabber.org/protocol/pubsub#node_config</value></field><field var='pubsub#access_model'><value>presence</value></field></x></configure>";
    let document = Document::parse(xml).unwrap();
    let condition =
        parse_node_config(document.root_element(), PubSubNodeConfig::default()).unwrap_err();
    assert_eq!(condition, "unsupported-access-model");

    let reply = super::node_config_parse_error(condition);
    assert_eq!(error_condition(&reply), Some("not-acceptable"));
    assert!(reply_error(&reply)
        .error_payload()
        .1
        .contains("unsupported-access-model"));
}

#[test]
fn collection_defaults_are_selected_with_the_registered_data_form() {
    let xml = format!(
        "<default xmlns='http://jabber.org/protocol/pubsub#owner'><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>{NODE_CONFIG_FORM}</value></field><field var='pubsub#node_type'><value>collection</value></field></x></default>"
    );
    let document = Document::parse(&xml).unwrap();
    assert_eq!(
        super::requested_default_node_type(document.root_element()).unwrap(),
        "collection"
    );

    for invalid in [
        "<default xmlns='http://jabber.org/protocol/pubsub#owner' type='collection'/>",
        "<default xmlns='http://jabber.org/protocol/pubsub#owner'><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>wrong</value></field></x></default>",
    ] {
        let document = Document::parse(invalid).unwrap();
        assert_eq!(
            error_condition(
                &super::requested_default_node_type(document.root_element()).unwrap_err()
            ),
            Some("bad-request")
        );
    }
}

#[test]
fn published_items_keep_inherited_namespaces_and_normalize_ids() {
    let document = Document::parse(
        "<pubsub xmlns='http://jabber.org/protocol/pubsub' xmlns:p='urn:test'><publish node='n'><item><p:value p:kind='demo'>a&amp;b</p:value></item></publish></pubsub>",
    )
    .unwrap();
    let item = document
        .descendants()
        .find(|node| node.is_element() && node.tag_name().name() == "item")
        .unwrap();
    let serialized = serialize_pubsub_item(item, "generated&amp;id").unwrap();
    let reparsed = Document::parse(&serialized).unwrap();
    let root = reparsed.root_element();
    assert_eq!(root.tag_name().namespace(), None);
    assert_eq!(root.attribute("id"), Some("generated&amp;id"));
    let payload = root.children().find(|node| node.is_element()).unwrap();
    assert_eq!(payload.tag_name().namespace(), Some("urn:test"));
    assert_eq!(payload.attribute(("urn:test", "kind")), Some("demo"));
    assert_eq!(payload.text(), Some("a&b"));
}

#[test]
fn subscription_options_round_trip_collection_fields() {
    let mut options = PubSubSubscriptionOptions::for_node_type("collection");
    options.digest = true;
    options.digest_frequency = 60_000;
    options.include_body = true;
    options.subscription_type = "all".to_owned();
    options.subscription_depth = None;
    options.show_values = vec!["chat".to_owned(), "online".to_owned()];
    let form = subscription_options_form(&options, "submit", true, "collection");
    let document = Document::parse(&form).unwrap();
    let parsed = parse_subscription_options(
        document.root_element(),
        "collection",
        true,
        DateTime::UNIX_EPOCH,
    )
    .unwrap()
    .apply_to(&PubSubSubscriptionOptions::for_node_type("collection"));
    assert!(parsed.digest);
    assert_eq!(parsed.digest_frequency, 60_000);
    assert!(parsed.include_body);
    assert_eq!(parsed.subscription_type, "all");
    assert_eq!(parsed.subscription_depth, None);
    assert_eq!(parsed.show_values, ["chat", "online"]);

    let invalid = form.replace("<value>true</value>", "<value>not-a-boolean</value>");
    let document = Document::parse(&invalid).unwrap();
    let reply = parse_subscription_options(
        document.root_element(),
        "collection",
        true,
        DateTime::UNIX_EPOCH,
    )
    .unwrap_err();
    assert_eq!(error_condition(&reply), Some("bad-request"));
    assert!(reply_error(&reply)
        .error_payload()
        .1
        .contains("invalid-options"));
}

#[test]
fn subscription_leases_are_clamped_to_the_service_maximum() {
    let xml = format!(
        "<x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>{SUBSCRIBE_OPTIONS_FORM}</value></field><field var='pubsub#expire'><value>2099-01-01T00:00:00Z</value></field></x>"
    );
    let document = Document::parse(&xml).unwrap();
    let before = DateTime::UNIX_EPOCH;
    let parsed =
        parse_subscription_options(document.root_element(), "leaf", false, before).unwrap();
    let Some(SubscriptionLeasePatch::Until(expiry)) = parsed.expire else {
        panic!("expected a deadline in the subscription patch");
    };
    assert!(expiry > before);
    assert!(expiry <= before + northstar_time::Duration::days(366));
    assert_eq!(
        expiry,
        before + northstar_time::Duration::days(super::MAX_SUBSCRIPTION_LEASE_DAYS)
    );
}

#[test]
fn subscription_options_parser_preserves_omitted_fields() {
    let xml = format!(
        "<x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>{SUBSCRIBE_OPTIONS_FORM}</value></field><field var='pubsub#deliver'><value>false</value></field><field var='pubsub#expire'><value/></field></x>"
    );
    let document = Document::parse(&xml).unwrap();
    let patch =
        parse_subscription_options(document.root_element(), "leaf", false, DateTime::UNIX_EPOCH)
            .unwrap();
    assert_eq!(
        patch,
        SubscriptionOptionsPatch {
            deliver: Some(false),
            expire: Some(SubscriptionLeasePatch::Clear),
            ..SubscriptionOptionsPatch::default()
        }
    );
}

#[test]
fn subscription_options_parser_rejects_expiry_at_or_before_request_time() {
    for deadline in ["1969-12-31T23:59:59Z", "1970-01-01T00:00:00Z"] {
        let xml = format!(
            "<x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>{SUBSCRIBE_OPTIONS_FORM}</value></field><field var='pubsub#expire'><value>{deadline}</value></field></x>"
        );
        let document = Document::parse(&xml).unwrap();
        let reply = parse_subscription_options(
            document.root_element(),
            "leaf",
            false,
            DateTime::UNIX_EPOCH,
        )
        .unwrap_err();
        assert!(matches!(
            &reply,
            PubSubReply::ExtendedError(error)
                if error == &PubSubError::new("bad-request", "invalid-options")
        ));
        for xml in [
            super::pubsub_iq_error("lease", "pubsub.example.test", &reply),
            super::pubsub_s2s_iq_error("lease", "pubsub.example.test", "remote.test", &reply),
        ] {
            let document = Document::parse(&xml).unwrap();
            let error = document
                .root_element()
                .children()
                .find(|child| child.is_element() && child.tag_name().name() == "error")
                .unwrap();
            assert_eq!(error.attribute("type"), Some("modify"));
            let conditions: Vec<_> = error
                .children()
                .filter(|node| node.is_element())
                .map(|node| (node.tag_name().namespace(), node.tag_name().name()))
                .collect();
            assert_eq!(
                conditions,
                [
                    (Some("urn:ietf:params:xml:ns:xmpp-stanzas"), "bad-request"),
                    (
                        Some("http://jabber.org/protocol/pubsub#errors"),
                        "invalid-options"
                    ),
                ]
            );
        }
    }
}

#[test]
fn durable_digest_waits_for_presence_but_stops_on_privacy_denial() {
    assert!(!pubsub_policy_suppression_is_terminal(0, 0));
    assert!(!pubsub_policy_suppression_is_terminal(0, 1));
    assert!(!pubsub_policy_suppression_is_terminal(1, 1));
    assert!(pubsub_policy_suppression_is_terminal(1, 0));
}

#[test]
fn extended_errors_use_pubsub_namespace_and_gone_carries_uri_text() {
    let unsupported = PubSubReply::ExtendedError(PubSubError::unsupported("publish"));
    let federated = super::pubsub_s2s_iq_error(
        "i0",
        "pubsub.example.test",
        "remote.example.test",
        &unsupported,
    );
    let document = Document::parse(&federated).unwrap();
    let iq = document.root_element();
    assert_eq!(iq.tag_name().namespace(), Some("jabber:server"));
    assert_eq!(iq.attribute("to"), Some("remote.example.test"));
    let unsupported_condition = document
        .descendants()
        .find(|node| {
            node.tag_name().name() == "unsupported"
                && node.tag_name().namespace() == Some("http://jabber.org/protocol/pubsub#errors")
        })
        .unwrap();
    assert_eq!(unsupported_condition.attribute("feature"), Some("publish"));

    let moved = super::pubsub_iq_error(
        "i1",
        "pubsub.example.test",
        &PubSubReply::ExtendedError(PubSubError::moved(
            "xmpp:pubsub.example.test?;node=new&amp;x".to_owned(),
        )),
    );
    let document = Document::parse(&moved).unwrap();
    let gone = document
        .descendants()
        .find(|node| node.tag_name().name() == "gone")
        .unwrap();
    assert_eq!(
        gone.text(),
        Some("xmpp:pubsub.example.test?;node=new&amp;x")
    );
}

#[test]
fn publish_options_require_the_distinct_form_type_and_known_fields() {
    let valid = format!(
        "<publish-options xmlns='http://jabber.org/protocol/pubsub'><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>{PUBLISH_OPTIONS_FORM}</value></field><field var='pubsub#max_items'><value>2</value></field></x></publish-options>"
    );
    let document = Document::parse(&valid).unwrap();
    let parsed =
        parse_publish_options(document.root_element(), PubSubNodeConfig::default()).unwrap();
    assert_eq!(parsed.max_items, 2);

    for invalid in [
        valid.replace(
            PUBLISH_OPTIONS_FORM,
            "http://jabber.org/protocol/pubsub#node_config",
        ),
        valid.replace(
            "</x>",
            "<field var='pubsub#vendor-extension'><value>1</value></field></x>",
        ),
    ] {
        let document = Document::parse(&invalid).unwrap();
        assert_eq!(
            parse_publish_options(document.root_element(), PubSubNodeConfig::default(),)
                .unwrap_err(),
            "bad-request"
        );
    }
}

#[test]
fn publish_batch_has_a_bounded_server_resource_ceiling() {
    // The protocol handler additionally compares this count with the
    // node's max_items and emits max-items-exceeded. This helper enforces
    // the independent hard ceiling before payload parsing/allocation.
    assert!(publish_batch_size_allowed(3));
    assert!(publish_batch_size_allowed(MAX_PUBLISH_ITEMS));
    assert!(!publish_batch_size_allowed(MAX_PUBLISH_ITEMS + 1));
}

#[test]
fn rsm_pages_have_stable_bounds_counts_and_strict_cursors() {
    let make_item = |id: &str| PubSubItem {
        item_id: id.to_owned(),
        xml_payload: format!("<item id='{id}'/>"),
        created_at: Utc::now(),
    };
    let items = || {
        ["newest", "middle", "oldest"]
            .into_iter()
            .map(make_item)
            .collect::<Vec<_>>()
    };

    let document = Document::parse(
        "<set xmlns='http://jabber.org/protocol/rsm'><max>1</max><after>newest</after></set>",
    )
    .unwrap();
    let request = parse_pubsub_rsm(document.root_element()).unwrap();
    let (page, metadata) = pubsub_rsm_page(items(), &request, 100).unwrap();
    assert_eq!(page[0].item_id, "middle");
    assert!(metadata.contains("<first index='1'>middle</first>"));
    assert!(metadata.contains("<count>3</count>"));

    let document =
        Document::parse("<set xmlns='http://jabber.org/protocol/rsm'><max>2</max><before/></set>")
            .unwrap();
    let request = parse_pubsub_rsm(document.root_element()).unwrap();
    let (page, _) = pubsub_rsm_page(items(), &request, 100).unwrap();
    assert_eq!(
        page.iter()
            .map(|item| item.item_id.as_str())
            .collect::<Vec<_>>(),
        ["middle", "oldest"]
    );

    let document =
        Document::parse("<set xmlns='http://jabber.org/protocol/rsm'><max>0</max></set>").unwrap();
    let request = parse_pubsub_rsm(document.root_element()).unwrap();
    let (page, metadata) = pubsub_rsm_page(items(), &request, 100).unwrap();
    assert!(page.is_empty());
    assert_eq!(
        metadata,
        "<set xmlns='http://jabber.org/protocol/rsm'><count>3</count></set>"
    );

    let document =
        Document::parse("<set xmlns='http://jabber.org/protocol/rsm'><after>missing</after></set>")
            .unwrap();
    let request = parse_pubsub_rsm(document.root_element()).unwrap();
    assert!(matches!(
        pubsub_rsm_page(items(), &request, 100),
        Err(PubSubReply::Error("item-not-found"))
    ));
}

#[test]
fn advertised_collection_and_rsm_feature_names_match_the_registry() {
    assert!(SERVICE_FEATURES.contains(&"multi-collections"));
    assert!(!SERVICE_FEATURES.contains(&"multi-collection"));
    assert!(SERVICE_FEATURES.contains(&"collections"));
    assert!(SERVICE_FEATURES.contains(&"rsm"));
}

#[test]
fn disco_rsm_supports_forward_reverse_zero_and_strict_cursor_pages() {
    let items = || {
        ["alpha", "beta", "gamma", "serverinfo"]
            .into_iter()
            .map(|node| DiscoItem {
                node: node.to_owned(),
                title: None,
                published_item: false,
            })
            .collect::<Vec<_>>()
    };
    let parse = |xml: &str| {
        let document = Document::parse(xml).unwrap();
        parse_pubsub_rsm(document.root_element()).unwrap()
    };
    let request =
        parse("<set xmlns='http://jabber.org/protocol/rsm'><max>1</max><after>alpha</after></set>");
    let (page, metadata) = disco_rsm_page(items(), &request, 100).unwrap();
    assert_eq!(page[0].node, "beta");
    assert!(metadata.contains("<first index='1'>beta</first>"));
    assert!(metadata.contains("<last>beta</last><count>4</count>"));

    let request = parse("<set xmlns='http://jabber.org/protocol/rsm'><max>2</max><before/></set>");
    let (page, metadata) = disco_rsm_page(items(), &request, 100).unwrap();
    assert_eq!(
        page.iter()
            .map(|item| item.node.as_str())
            .collect::<Vec<_>>(),
        ["gamma", "serverinfo"]
    );
    assert!(metadata.contains("<first index='2'>gamma</first>"));

    let request = parse(
        "<set xmlns='http://jabber.org/protocol/rsm'><max>1</max><before>gamma</before></set>",
    );
    assert_eq!(
        disco_rsm_page(items(), &request, 100).unwrap().0[0].node,
        "beta"
    );
    let request = parse("<set xmlns='http://jabber.org/protocol/rsm'><max>0</max></set>");
    let (page, metadata) = disco_rsm_page(items(), &request, 100).unwrap();
    assert!(page.is_empty());
    assert_eq!(
        metadata,
        "<set xmlns='http://jabber.org/protocol/rsm'><count>4</count></set>"
    );

    let request = parse("<set xmlns='http://jabber.org/protocol/rsm'><after>missing</after></set>");
    assert!(matches!(
        disco_rsm_page(items(), &request, 100),
        Err(PubSubReply::Error("item-not-found"))
    ));
    for invalid in [
        "<set xmlns='http://jabber.org/protocol/rsm'><after>alpha</after><before>gamma</before></set>",
        "<set xmlns='http://jabber.org/protocol/rsm'><max>1001</max></set>",
        "<set xmlns='http://jabber.org/protocol/rsm'><max>1</max><max>2</max></set>",
        "<set xmlns='http://jabber.org/protocol/rsm'>not-whitespace<max>1</max></set>",
    ] {
        let document = Document::parse(invalid).unwrap();
        assert!(matches!(
            parse_pubsub_rsm(document.root_element()),
            Err(PubSubReply::Error("bad-request"))
        ));
    }
}
