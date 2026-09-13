use northstar_xep_0059::{
    build_mam_fin, build_rsm_request, build_rsm_set, build_rsm_set_raw, parse_rsm_response_str,
    parse_rsm_str, RsmFin, RsmFirstItem, RsmRequest, RsmResponse,
};

#[test]
fn builds_rsm_request_xml() {
    let req = RsmRequest::new().with_max(20).with_after("cursor-1");
    let xml = build_rsm_request(&req);
    assert_eq!(
        xml,
        "<set xmlns='http://jabber.org/protocol/rsm'><max>20</max><after>cursor-1</after></set>"
    );

    let req_before = RsmRequest::new().with_max(10).with_before_item("cursor-2");
    let xml_before = build_rsm_request(&req_before);
    assert_eq!(
        xml_before,
        "<set xmlns='http://jabber.org/protocol/rsm'><max>10</max><before>cursor-2</before></set>"
    );

    let req_last = RsmRequest::new().with_max(10).with_before_last_page();
    let xml_last = build_rsm_request(&req_last);
    assert_eq!(
        xml_last,
        "<set xmlns='http://jabber.org/protocol/rsm'><max>10</max><before/></set>"
    );

    let req_index = RsmRequest::new().with_max(10).with_index(50);
    let xml_index = build_rsm_request(&req_index);
    assert_eq!(
        xml_index,
        "<set xmlns='http://jabber.org/protocol/rsm'><max>10</max><index>50</index></set>"
    );
}

#[test]
fn builds_rsm_set_response_xml() {
    let resp = RsmResponse::new()
        .with_first(RsmFirstItem::with_index("item-1", 0))
        .with_last("item-10")
        .with_count(100);

    let xml = build_rsm_set(&resp);
    assert_eq!(
        xml,
        "<set xmlns='http://jabber.org/protocol/rsm'><first index='0'>item-1</first><last>item-10</last><count>100</count></set>"
    );
}

#[test]
fn builds_empty_rsm_set_response_xml() {
    let resp = RsmResponse::empty(0);
    let xml = build_rsm_set(&resp);
    assert_eq!(
        xml,
        "<set xmlns='http://jabber.org/protocol/rsm'><count>0</count></set>"
    );
}

#[test]
fn builds_rsm_set_raw_helper() {
    let xml = build_rsm_set_raw(Some((Some(5), "item-6")), Some("item-10"), Some(50));
    assert_eq!(
        xml,
        "<set xmlns='http://jabber.org/protocol/rsm'><first index='5'>item-6</first><last>item-10</last><count>50</count></set>"
    );
}

#[test]
fn builds_mam_fin_xml() {
    let fin = RsmFin::with_rsm(
        true,
        true,
        RsmResponse::new()
            .with_first(RsmFirstItem::with_index("uuid-1", 0))
            .with_last("uuid-10")
            .with_count(10),
    );
    let xml = build_mam_fin(&fin, "urn:xmpp:mam:2");
    assert_eq!(
        xml,
        "<fin xmlns='urn:xmpp:mam:2' complete='true' stable='true'><set xmlns='http://jabber.org/protocol/rsm'><first index='0'>uuid-1</first><last>uuid-10</last><count>10</count></set></fin>"
    );
}

#[test]
fn round_trip_request_building_and_parsing() {
    let requests = vec![
        RsmRequest::new().with_max(50),
        RsmRequest::new().with_max(10).with_after("cursor-abc"),
        RsmRequest::new()
            .with_max(10)
            .with_before_item("cursor-xyz"),
        RsmRequest::new().with_max(10).with_before_last_page(),
        RsmRequest::new().with_max(10).with_index(42),
        RsmRequest::new().with_max(0),
    ];

    for req in requests {
        let xml = build_rsm_request(&req);
        let parsed = parse_rsm_str(&xml).expect("round trip parse request");
        assert_eq!(req, parsed, "failed for XML: {xml}");
    }
}

#[test]
fn round_trip_response_building_and_parsing() {
    let responses = vec![
        RsmResponse::empty(0),
        RsmResponse::new()
            .with_first(RsmFirstItem::with_index("item-1", 0))
            .with_last("item-2")
            .with_count(10),
        RsmResponse::new()
            .with_first(RsmFirstItem::new("item-1"))
            .with_last("item-2")
            .with_count(10),
    ];

    for resp in responses {
        let xml = build_rsm_set(&resp);
        let parsed = parse_rsm_response_str(&xml).expect("round trip parse response");
        assert_eq!(resp, parsed, "failed for XML: {xml}");
    }
}
