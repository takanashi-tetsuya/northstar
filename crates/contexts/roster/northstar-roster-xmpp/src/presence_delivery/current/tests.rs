use super::*;
use northstar_stream::local_routes::session::test_online_session;

const OWNER: Uuid = Uuid::from_u128(40);
const CONNECTION: Uuid = Uuid::from_u128(41);
const TARGET: &str = "owner@example.test/phone";
const PEER: &str = "peer@example.test/tablet";

fn captured() -> PresenceRoute {
    PresenceRoute {
        exact: ExactPresenceRoute {
            account_id: OWNER,
            auth_generation: 2,
            connection_id: CONNECTION,
            full_jid: TARGET.to_owned(),
            node_id: None,
        },
        active_list: None,
    }
}

#[test]
fn directed_probe_matches_only_the_grant_and_connection_captured_for_that_resource() {
    let (owner, _output) = test_online_session(OWNER, 2, CONNECTION, "phone", 1);
    let (sibling, _sibling) = test_online_session(OWNER, 2, Uuid::from_u128(42), "laptop", 1);
    owner
        .directed_presence
        .insert("peer@example.test/tablet".to_owned());
    sibling
        .directed_presence
        .insert("peer@example.test".to_owned());
    assert!(probe_owner_is_current(&captured(), &owner, PEER, true));
    assert!(!probe_owner_is_current(
        &captured(),
        &owner,
        "peer@example.test/phone",
        true
    ));
    assert!(!probe_owner_is_current(&captured(), &sibling, PEER, true));
}

#[test]
fn a_blocked_requester_gets_no_status_when_another_node_found_no_available_route() {
    let decision = ProbeStatus::Silent.combine(ProbeStatus::Unavailable);
    assert!(probe_status_stanza(decision, TARGET, PEER, Some("probe")).is_none());
}

#[tokio::test]
async fn directed_grant_withdrawn_while_probe_is_paused_cannot_authorize_enqueue() {
    let (owner, _output) = test_online_session(OWNER, 2, CONNECTION, "phone", 1);
    owner.directed_presence.insert(PEER.to_owned());
    let sampled = owner.clone();
    let (grant_seen, captured_grant) = tokio::sync::oneshot::channel();
    let (resume, paused) = tokio::sync::oneshot::channel();
    let probe = tokio::spawn(async move {
        assert!(has_directed_grant(&sampled, PEER));
        grant_seen.send(()).unwrap();
        paused.await.unwrap();
        probe_owner_is_current(&captured(), &sampled, PEER, true)
    });
    captured_grant.await.unwrap();
    owner.directed_presence.remove(PEER);
    resume.send(()).unwrap();
    assert!(!probe.await.unwrap());
}
