use super::*;
use std::cell::Cell;

#[test]
fn privacy_push_uses_one_supplied_uuid_in_hyphenated_form() {
    let counter = Cell::new(42_u128);
    let push = privacy_push_base("alice@example.test", "quiet", || {
        let next = counter.get();
        counter.set(next + 1);
        Uuid::from_u128(next)
    })
    .unwrap();
    let document = roxmltree::Document::parse(&push).unwrap();
    assert_eq!(
        document.root_element().attribute("id"),
        Some("privacy-00000000-0000-0000-0000-00000000002a"),
    );
    assert_eq!(counter.get(), 43);
}
