use super::*;

const ROOM: &str = "room@conference.local.test";

#[test]
fn room_items_rsm_preserves_page_order_cursor_index_and_field_order() {
    let nicks = ["A", "B", "C", "D"].map(str::to_owned);
    for (after, before, expected, index) in [
        (Some("A"), None, ["B", "C"], 1),
        (None, Some(Some("D")), ["B", "C"], 1),
        (None, Some(None), ["C", "D"], 2),
    ] {
        let mut query = XmlElement::namespaced("query", "http://jabber.org/protocol/disco#items");
        let request = DiscoItemsRequest {
            node: None,
            max: 2,
            after: after.map(str::to_owned),
            before: before.map(|value| value.map(str::to_owned)),
        };
        assert!(append_room_items(&mut query, ROOM, &nicks, &request));
        let xml = query.finish();
        let document = roxmltree::Document::parse(&xml).unwrap();
        let children = document
            .root_element()
            .children()
            .filter(roxmltree::Node::is_element)
            .collect::<Vec<_>>();
        assert_eq!(children.len(), 3);
        assert_eq!(
            children[0].attribute("jid").unwrap(),
            format!("{ROOM}/{}", expected[0])
        );
        assert_eq!(
            children[1].attribute("jid").unwrap(),
            format!("{ROOM}/{}", expected[1])
        );
        let fields = children[2]
            .children()
            .filter(roxmltree::Node::is_element)
            .collect::<Vec<_>>();
        assert_eq!(
            fields
                .iter()
                .map(|field| field.tag_name().name())
                .collect::<Vec<_>>(),
            ["first", "last", "count"]
        );
        assert_eq!(fields[0].attribute("index").unwrap(), index.to_string());
        assert_eq!(fields[0].text(), Some(expected[0]));
        assert_eq!(fields[1].text(), Some(expected[1]));
        assert_eq!(fields[2].text(), Some("4"));
    }
    let mut query = XmlElement::new("query");
    let mut request = DiscoItemsRequest {
        node: None,
        max: 0,
        after: Some("missing".to_owned()),
        before: None,
    };
    assert!(!append_room_items(&mut query, ROOM, &nicks, &request));
    request.after = None;
    assert!(append_room_items(&mut query, ROOM, &nicks, &request));
    let xml = query.finish();
    let document = roxmltree::Document::parse(&xml).unwrap();
    let set = document.root_element().first_element_child().unwrap();
    assert_eq!(
        set.children().filter(roxmltree::Node::is_element).count(),
        1
    );
    assert_eq!(set.first_element_child().unwrap().text(), Some("4"));
}
