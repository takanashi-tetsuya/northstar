use super::{missing_full_jid_iq_needs_error, rejected_handoff};
use crate::protocol::Action;

#[test]
fn a_rejected_exact_handoff_never_answers_an_iq_response() {
    for kind in ["error", "result"] {
        assert!(matches!(
            rejected_handoff("request-id", missing_full_jid_iq_needs_error(kind)),
            Action::None
        ));
    }
}
