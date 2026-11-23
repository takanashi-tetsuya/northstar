use super::*;
use std::collections::HashSet;
use uuid::Uuid;

fn route(nick: &str, incarnation: u128) -> MucOccupantRoute {
    MucOccupantRoute {
        nick: nick.to_owned(),
        full_jid: format!("{nick}@example.test/phone"),
        connection_id: Uuid::from_u128(1),
        cluster_epoch: Uuid::from_u128(incarnation),
    }
}

#[test]
fn fanout_resolves_only_committed_exact_routes_hosted_here() {
    let exact = route("alice", 1);
    let reused = route("bob", 2);
    let remote = route("carol", 3);
    let audience = LiveAudience::new(vec![
        ("here".to_owned(), exact.clone()),
        ("here".to_owned(), reused),
        ("elsewhere".to_owned(), remote.clone()),
    ])
    .unwrap();
    let current = HashSet::from([exact.clone(), route("bob", 4), route("new", 5), remote]);
    let recipients = exact_live_recipients(&audience, "here", |route| current.get(route).cloned());
    assert_eq!(recipients, [exact]);
}
