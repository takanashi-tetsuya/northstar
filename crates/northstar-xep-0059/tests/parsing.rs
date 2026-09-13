use northstar_xep_0059::{
    parse_rsm_from_parent, parse_rsm_response_str, parse_rsm_str, BeforeCursor, RsmError,
};
use roxmltree::Document;

#[test]
fn parses_valid_forward_paging_request() {
    let req = parse_rsm_str(
        "<set xmlns='http://jabber.org/protocol/rsm'><max>10</max><after>item-42</after></set>",
    )
    .unwrap();
    assert_eq!(req.max, Some(10));
    assert_eq!(req.after.as_deref(), Some("item-42"));
    assert_eq!(req.before, None);
    assert_eq!(req.index, None);
    assert!(!req.is_count_only());
}

#[test]
fn parses_valid_backward_paging_request() {
    let req = parse_rsm_str(
        "<set xmlns='http://jabber.org/protocol/rsm'><max>25</max><before>item-99</before></set>",
    )
    .unwrap();
    assert_eq!(req.max, Some(25));
    assert_eq!(req.after, None);
    assert_eq!(req.before, Some(BeforeCursor::Item("item-99".to_owned())));
    assert_eq!(req.raw_before(), Some(Some("item-99")));
}

#[test]
fn parses_valid_empty_before_last_page() {
    let req1 =
        parse_rsm_str("<set xmlns='http://jabber.org/protocol/rsm'><max>15</max><before/></set>")
            .unwrap();
    assert_eq!(req1.max, Some(15));
    assert_eq!(req1.before, Some(BeforeCursor::LastPage));
    assert_eq!(req1.raw_before(), Some(None));

    let req2 = parse_rsm_str(
        "<set xmlns='http://jabber.org/protocol/rsm'><max>15</max><before></before></set>",
    )
    .unwrap();
    assert_eq!(req2.before, Some(BeforeCursor::LastPage));
}

#[test]
fn parses_valid_indexed_paging() {
    let req = parse_rsm_str(
        "<set xmlns='http://jabber.org/protocol/rsm'><max>20</max><index>371</index></set>",
    )
    .unwrap();
    assert_eq!(req.max, Some(20));
    assert_eq!(req.index, Some(371));
}

#[test]
fn parses_valid_size_request() {
    let req =
        parse_rsm_str("<set xmlns='http://jabber.org/protocol/rsm'><max>0</max></set>").unwrap();
    assert_eq!(req.max, Some(0));
    assert!(req.is_count_only());
}

#[test]
fn parses_valid_response_with_first_last_count_index() {
    let resp = parse_rsm_response_str(
        "<set xmlns='http://jabber.org/protocol/rsm'>\
            <first index='0'>item-1</first>\
            <last>item-10</last>\
            <count>250</count>\
            <index>0</index>\
         </set>",
    )
    .unwrap();

    assert_eq!(resp.first_value(), Some("item-1"));
    assert_eq!(resp.first_index(), Some(0));
    assert_eq!(resp.last_value(), Some("item-10"));
    assert_eq!(resp.count_value(), Some(250));
    assert_eq!(resp.index, Some(0));
    assert!(!resp.is_empty_page());
}

#[test]
fn parses_valid_empty_response() {
    let resp = parse_rsm_response_str(
        "<set xmlns='http://jabber.org/protocol/rsm'><count>0</count></set>",
    )
    .unwrap();
    assert_eq!(resp.first, None);
    assert_eq!(resp.last, None);
    assert_eq!(resp.count, Some(0));
    assert!(resp.is_empty_page());
}

#[test]
fn rejects_conflicting_cursors() {
    let after_before = parse_rsm_str(
        "<set xmlns='http://jabber.org/protocol/rsm'><after>a</after><before>b</before></set>",
    );
    assert!(matches!(
        after_before,
        Err(RsmError::MutuallyExclusiveCursors(_))
    ));

    let after_empty_before = parse_rsm_str(
        "<set xmlns='http://jabber.org/protocol/rsm'><after>a</after><before/></set>",
    );
    assert!(matches!(
        after_empty_before,
        Err(RsmError::MutuallyExclusiveCursors(_))
    ));

    let after_index = parse_rsm_str(
        "<set xmlns='http://jabber.org/protocol/rsm'><after>a</after><index>10</index></set>",
    );
    assert!(matches!(
        after_index,
        Err(RsmError::MutuallyExclusiveCursors(_))
    ));

    let before_index = parse_rsm_str(
        "<set xmlns='http://jabber.org/protocol/rsm'><before>b</before><index>10</index></set>",
    );
    assert!(matches!(
        before_index,
        Err(RsmError::MutuallyExclusiveCursors(_))
    ));
}

#[test]
fn rejects_duplicate_elements() {
    assert!(matches!(
        parse_rsm_str("<set xmlns='http://jabber.org/protocol/rsm'><max>1</max><max>2</max></set>"),
        Err(RsmError::DuplicateElement("max"))
    ));

    assert!(matches!(
        parse_rsm_str(
            "<set xmlns='http://jabber.org/protocol/rsm'><after>a</after><after>b</after></set>"
        ),
        Err(RsmError::DuplicateElement("after"))
    ));

    assert!(matches!(
        parse_rsm_str("<set xmlns='http://jabber.org/protocol/rsm'><before/><before/></set>"),
        Err(RsmError::DuplicateElement("before"))
    ));

    assert!(matches!(
        parse_rsm_str(
            "<set xmlns='http://jabber.org/protocol/rsm'><index>0</index><index>1</index></set>"
        ),
        Err(RsmError::DuplicateElement("index"))
    ));
}

#[test]
fn rejects_empty_after() {
    assert!(matches!(
        parse_rsm_str("<set xmlns='http://jabber.org/protocol/rsm'><after/></set>"),
        Err(RsmError::EmptyCursor("after"))
    ));
    assert!(matches!(
        parse_rsm_str("<set xmlns='http://jabber.org/protocol/rsm'><after></after></set>"),
        Err(RsmError::EmptyCursor("after"))
    ));
}

#[test]
fn rejects_invalid_namespace_and_tag_names() {
    assert!(matches!(
        parse_rsm_str("<set xmlns='jabber:invalid:ns'><max>10</max></set>"),
        Err(RsmError::UnexpectedNamespace { .. })
    ));

    assert!(matches!(
        parse_rsm_str("<query xmlns='http://jabber.org/protocol/rsm'><max>10</max></query>"),
        Err(RsmError::UnexpectedTagName(_))
    ));

    assert!(matches!(
        parse_rsm_str("<set xmlns='http://jabber.org/protocol/rsm'><other>10</other></set>"),
        Err(RsmError::UnexpectedChildElement(_))
    ));
}

#[test]
fn rejects_custom_attributes_on_request_elements() {
    assert!(matches!(
        parse_rsm_str(
            "<set xmlns='http://jabber.org/protocol/rsm' custom='val'><max>10</max></set>"
        ),
        Err(RsmError::UnexpectedAttribute(_))
    ));

    assert!(matches!(
        parse_rsm_str(
            "<set xmlns='http://jabber.org/protocol/rsm'><max custom='val'>10</max></set>"
        ),
        Err(RsmError::UnexpectedAttribute(_))
    ));
}

#[test]
fn rejects_nested_elements_and_non_whitespace_text() {
    assert!(matches!(
        parse_rsm_str("<set xmlns='http://jabber.org/protocol/rsm'><max><nested/></max></set>"),
        Err(RsmError::UnexpectedChildElement(_))
    ));

    assert!(matches!(
        parse_rsm_str("<set xmlns='http://jabber.org/protocol/rsm'>stray-text<max>10</max></set>"),
        Err(RsmError::UnexpectedText)
    ));
}

#[test]
fn parses_rsm_from_parent_element() {
    let doc = Document::parse(
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'>\
            <items node='test'/>\
            <set xmlns='http://jabber.org/protocol/rsm'><max>50</max></set>\
         </pubsub>",
    )
    .unwrap();
    let rsm = parse_rsm_from_parent(doc.root_element()).unwrap();
    assert_eq!(rsm.unwrap().max, Some(50));

    let no_rsm_doc = Document::parse(
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'><items node='test'/></pubsub>",
    )
    .unwrap();
    assert_eq!(
        parse_rsm_from_parent(no_rsm_doc.root_element()).unwrap(),
        None
    );

    let dup_rsm_doc = Document::parse(
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'>\
            <items node='test'/>\
            <set xmlns='http://jabber.org/protocol/rsm'><max>50</max></set>\
            <set xmlns='http://jabber.org/protocol/rsm'><max>50</max></set>\
         </pubsub>",
    )
    .unwrap();
    assert!(matches!(
        parse_rsm_from_parent(dup_rsm_doc.root_element()),
        Err(RsmError::DuplicateElement("set"))
    ));
}
