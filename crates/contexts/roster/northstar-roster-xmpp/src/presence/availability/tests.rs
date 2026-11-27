use super::*;
use uuid::Uuid;

const SCOPE: &str = "bob@example.test";
const FULL: &str = "bob@example.test/phone";

fn route(connection: u128) -> ExactPresenceRoute {
    ExactPresenceRoute {
        account_id: Uuid::from_u128(1),
        auth_generation: 2,
        connection_id: Uuid::from_u128(connection),
        full_jid: FULL.to_owned(),
        node_id: None,
    }
}

#[test]
fn local_grants_keep_the_acceptance_scope_and_connection() {
    let bare = grant(SCOPE, route(3));
    let full = grant(FULL, route(3));
    let entries = vec![bare.encode(), full.encode()];
    assert_eq!(grants_for_scope(entries.clone(), SCOPE), [bare]);
    assert_eq!(grants_for_scope(entries, FULL), [full]);
    assert!(newly_accepted_grants(Vec::new(), &[], SCOPE).is_empty());
}

#[test]
fn duplicate_at_capacity_keeps_one_grant_and_rebind_is_distinct() {
    let old = grant(SCOPE, route(3));
    let mut duplicate = route(3);
    duplicate.node_id = Some("other-node-perspective".into());
    assert!(newly_accepted_grants(vec![duplicate], std::slice::from_ref(&old), SCOPE).is_empty());
    let replacement = grant(SCOPE, route(4));
    assert_eq!(
        newly_accepted_grants(vec![route(4)], &[old], SCOPE),
        [replacement]
    );
    let capacity = northstar_presence_core::MAX_DIRECTED_PRESENCE_RECIPIENTS;
    assert!(!directed_presence_capacity_reached(capacity, true));
    assert!(directed_presence_capacity_reached(capacity, false));
}
