use super::{item_needs_transport, ItemAdmission, LostItemClaim};

#[test]
fn only_a_ready_reservation_needs_transport() {
    assert!(item_needs_transport(ItemAdmission::Ready).unwrap());
    assert!(!item_needs_transport(ItemAdmission::Completed).unwrap());
    assert!(item_needs_transport(ItemAdmission::Stale)
        .unwrap_err()
        .is::<LostItemClaim>());
}
