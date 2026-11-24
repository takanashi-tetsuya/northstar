use super::{recipient_allows, spool_eligibility};
use northstar_message_core::DirectSpoolEligibility::{Eligible, LiveOnly};

#[test]
fn an_exact_local_selection_overrides_only_the_live_default() {
    assert!(recipient_allows(&[true, false], false));
    assert!(!recipient_allows(&[false, true], false));
    assert!(!recipient_allows(&[true], false));
    assert!(recipient_allows(&[true], true));
    assert_eq!(spool_eligibility(Eligible, true), LiveOnly);
    assert_eq!(spool_eligibility(Eligible, false), Eligible);
    assert_eq!(spool_eligibility(LiveOnly, false), LiveOnly);
}
