use super::*;

#[test]
fn roster_push_uses_supplied_uuid_in_decimal_form() {
    let push = roster_push_xml(
        "alice@example.test",
        "alice@example.test/phone",
        7,
        removed_roster_item_element("bob@example.test"),
        Uuid::from_u128(42),
    );
    let document = roxmltree::Document::parse(&push).unwrap();
    assert_eq!(document.root_element().attribute("id"), Some("roster-42"));
}

#[test]
fn roster_removal_uses_supplied_uuid_in_hyphenated_form() {
    let notice = roster_removal_presence(
        "alice@example.test",
        "bob@example.test",
        "unsubscribe",
        Uuid::from_u128(43),
    );
    let document = roxmltree::Document::parse(&notice).unwrap();
    assert_eq!(
        document.root_element().attribute("id"),
        Some("00000000-0000-0000-0000-00000000002b"),
    );
}
