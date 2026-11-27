use super::*;

#[test]
fn show_filtered_delivery_requires_a_matching_available_state() {
    let allowed = [
        "away".to_owned(),
        "dnd".to_owned(),
        "unavailable".to_owned(),
    ];
    assert!(show_matches(2, &allowed));
    assert!(show_matches(4, &allowed));
    assert!(!show_matches(0, &allowed));
    assert!(!show_matches(3, &allowed));
    assert!(!show_matches(10, &allowed));
}

#[test]
fn retry_depends_on_eligible_routes_and_policy_suppression() {
    assert!(!notification_requires_retry(false, true, false));
    assert!(notification_requires_retry(false, true, true));
    assert!(notification_requires_retry(false, false, false));
    assert!(!notification_requires_retry(true, true, true));
}
