use super::*;
use uuid::Uuid;

fn route(connection: u128) -> ExactPresenceRoute {
    ExactPresenceRoute {
        account_id: Uuid::from_u128(1),
        auth_generation: 2,
        connection_id: Uuid::from_u128(connection),
        full_jid: format!("bob@example.test/{connection}"),
        node_id: None,
    }
}

#[test]
fn an_error_preserves_the_accepted_prefix_and_does_not_hide_later_accepts() {
    let mut outcome = DirectedDeliveryResult::default();
    assert!(outcome.record_attempt(route(3), Ok(DirectedEnqueue::Accepted)));
    assert!(!outcome.record_attempt(route(4), Err(anyhow::anyhow!("policy read failed"))));
    assert!(outcome.record_attempt(route(5), Ok(DirectedEnqueue::Accepted)));
    assert_eq!(outcome.accepted, [route(3), route(5)]);
    assert_eq!(outcome.remaining, [route(4)]);
    assert!(outcome.error.is_some());
}
