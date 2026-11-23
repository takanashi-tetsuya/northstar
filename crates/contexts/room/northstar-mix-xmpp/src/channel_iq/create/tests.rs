use super::*;
use uuid::Uuid;

#[test]
fn create_reply_preserves_committed_success_and_create_failure_mapping() {
    let render = |outcome| create_reply(outcome, "room", "request", "mix.test", "owner@test/pc");
    let success = render(CreateChannelOutcome::Created(Uuid::nil()));
    assert!(success.contains("type='result'"));
    assert!(success.contains("channel='room'"));
    let conflict = render(CreateChannelOutcome::Conflict);
    assert!(conflict.contains("type='cancel'"));
    assert!(conflict.contains("<conflict"));
    let quota = render(CreateChannelOutcome::QuotaExceeded);
    assert!(quota.contains("type='wait'"));
    assert!(quota.contains("<resource-constraint"));
}
