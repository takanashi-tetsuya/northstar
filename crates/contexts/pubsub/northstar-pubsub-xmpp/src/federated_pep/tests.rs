use super::*;
use northstar_pubsub_core::PepAccessDenial;
use roxmltree::Document;

#[test]
fn federated_pep_subscription_branch_has_no_split_authority_reads() {
    let source = include_str!("../federated_pep.rs");
    let branch = source
        .split_once("pub async fn federated_pep_subscription<")
        .expect("federated PEP subscription handler must remain identifiable")
        .1
        .split_once("\n}\n")
        .expect("federated PEP subscription handler must end")
        .0;
    for forbidden in [
        "db::pep_node(",
        "pep_access_allowed(",
        "subscribe_pep_node_with_outbox(",
        "db::unsubscribe_pep_node(",
    ] {
        assert!(
            !branch.contains(forbidden),
            "federated PEP policy escaped the service transaction: {forbidden}"
        );
    }
    assert!(branch.contains(".subscribe_pep_node("));
    assert!(branch.contains(".unsubscribe_pep_node("));
    assert!(branch.contains("PepSubscriptionActor"));
}

#[test]
fn federated_pep_item_read_maps_denial_to_cancel_without_a_pubsub_extension() {
    let to = "owner@example.test";
    let from = "reader@remote.test/phone";
    for outcome in [PepItemRead::OwnerMissing, PepItemRead::NodeMissing] {
        assert_eq!(
            federated_pep_item_reply("read", to, from, "news", None, outcome).unwrap(),
            s2s_iq_error("read", to, from, "item-not-found"),
        );
    }
    let xml = federated_pep_item_reply(
        "read",
        to,
        from,
        "news",
        None,
        PepItemRead::Denied(PepAccessDenial::NotInRosterGroup),
    )
    .unwrap();
    let doc = Document::parse(&xml).unwrap();
    let iq = doc.root_element();
    assert_eq!(iq.tag_name().namespace(), Some("jabber:server"));
    assert_eq!(iq.attribute("from"), Some(to));
    assert_eq!(iq.attribute("to"), Some(from));
    let error = iq.first_element_child().unwrap();
    assert_eq!(error.attribute("type"), Some("cancel"));
    let children = error
        .children()
        .filter(Node::is_element)
        .collect::<Vec<_>>();
    assert_eq!(children.len(), 1);
    assert_eq!(children[0].tag_name().name(), "not-authorized");
    assert_eq!(
        children[0].tag_name().namespace(),
        Some("urn:ietf:params:xml:ns:xmpp-stanzas")
    );
    let authorized = PepItemRead::Items {
        config: northstar_pubsub_core::default_pep_node_config("news"),
        items: Vec::new(),
    };
    assert_eq!(
        federated_pep_item_reply("read", to, from, "news", None, authorized).unwrap(),
        s2s_iq_error("read", to, from, "bad-request"),
    );
}

#[test]
fn federated_pep_item_selection_preserves_plain_ids_and_accepts_repeats() {
    let doc = Document::parse("<items xmlns='http://jabber.org/protocol/pubsub' subid='ignored' max_items='2'><item id='Room@BÜCHER.example'/><item id='Room@BÜCHER.example'/><item id='opaque'/></items>").unwrap();
    let selection = parse_pep_item_selection(doc.root_element(), None).unwrap();
    assert_eq!(selection.max_items, 2);
    assert_eq!(selection.item_ids, ["Room@BÜCHER.example", "opaque"]);
}
