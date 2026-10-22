use northstar_xep_0059::{parse_rsm_str_with_bounds, RsmBounds, RsmError, RsmRequest};

#[test]
fn enforces_custom_max_page_size() {
    let bounds = RsmBounds::MAM; // max_page_size = 100

    let valid = parse_rsm_str_with_bounds(
        "<set xmlns='http://jabber.org/protocol/rsm'><max>100</max></set>",
        &bounds,
    );
    assert!(valid.is_ok());

    let exceeded = parse_rsm_str_with_bounds(
        "<set xmlns='http://jabber.org/protocol/rsm'><max>101</max></set>",
        &bounds,
    );
    assert!(matches!(
        exceeded,
        Err(RsmError::MaxPageSizeExceeded {
            requested: 101,
            limit: 100
        })
    ));
}

#[test]
fn enforces_custom_max_cursor_bytes() {
    let bounds = RsmBounds::new(100, 10, 1000);

    let valid = parse_rsm_str_with_bounds(
        "<set xmlns='http://jabber.org/protocol/rsm'><after>1234567890</after></set>",
        &bounds,
    );
    assert!(valid.is_ok());

    let exceeded = parse_rsm_str_with_bounds(
        "<set xmlns='http://jabber.org/protocol/rsm'><after>12345678901</after></set>",
        &bounds,
    );
    assert!(matches!(
        exceeded,
        Err(RsmError::CursorLengthExceeded {
            length: 11,
            limit: 10
        })
    ));
}

#[test]
fn enforces_custom_max_index() {
    let bounds = RsmBounds::new(100, 1024, 1_000_000);

    let valid = parse_rsm_str_with_bounds(
        "<set xmlns='http://jabber.org/protocol/rsm'><index>1000000</index></set>",
        &bounds,
    );
    assert!(valid.is_ok());

    let exceeded = parse_rsm_str_with_bounds(
        "<set xmlns='http://jabber.org/protocol/rsm'><index>1000001</index></set>",
        &bounds,
    );
    assert!(matches!(
        exceeded,
        Err(RsmError::IndexLimitExceeded {
            requested: 1000001,
            limit: 1000000
        })
    ));
    assert!(exceeded.unwrap_err().is_resource_constraint());
}

#[test]
fn preset_mam_and_discovery_and_pubsub_bounds() {
    assert_eq!(RsmBounds::MAM.max_page_size, 100);
    assert_eq!(RsmBounds::DISCOVERY.max_page_size, 100);
    assert_eq!(RsmBounds::PUBSUB.max_page_size, 1000);
    assert_eq!(RsmBounds::DEFAULT.max_page_size, 1000);
}

#[test]
fn rejects_cursor_with_control_characters() {
    let bounds = RsmBounds::DEFAULT;

    let err_after = bounds.validate_cursor("item\x00bad", "after").unwrap_err();
    assert!(matches!(err_after, RsmError::InvalidCursor(..)));

    let err_before = bounds.validate_cursor("item\x1fbad", "before").unwrap_err();
    assert!(matches!(err_before, RsmError::InvalidCursor(..)));

    let req_after = RsmRequest::new().with_after("item\x07bad");
    assert!(matches!(
        req_after.validate(&bounds),
        Err(RsmError::InvalidCursor(..))
    ));

    let req_before = RsmRequest::new().with_before_item("item\x07bad");
    assert!(matches!(
        req_before.validate(&bounds),
        Err(RsmError::InvalidCursor(..))
    ));
}
