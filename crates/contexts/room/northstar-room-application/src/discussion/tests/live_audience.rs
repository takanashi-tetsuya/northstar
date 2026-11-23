use super::*;
use northstar_room_core::occupancy::MucOccupantRoute;

fn audience() -> LiveAudience {
    LiveAudience::new(vec![(
        "node-a".to_owned(),
        MucOccupantRoute {
            nick: "Alice".to_owned(),
            full_jid: "alice@local.test/phone".to_owned(),
            connection_id: Uuid::from_u128(6),
            cluster_epoch: Uuid::from_u128(5),
        },
    )])
    .unwrap()
}

#[test]
fn fresh_receipt_moves_its_exact_audience_into_the_fanout_permit() {
    let (observation, request) = invocation(true, true);
    request.start().unwrap();
    let outcome = stored(&request);
    let audience = audience();
    ready(commit_observed_with_audience(
        std::future::ready(Ok::<(), ()>(())),
        &request,
        outcome,
        Some(audience.clone()),
    ))
    .unwrap();
    let permit = request
        .returned(outcome)
        .unwrap()
        .into_fanout(&observation)
        .unwrap()
        .unwrap();
    assert_eq!(permit.audience(), Some(&audience));
}

#[test]
fn replay_cannot_bind_an_audience_or_mint_a_fanout_permit() {
    let (observation, request) = invocation(true, true);
    request.start().unwrap();
    let outcome = MucDiscussionAdmission::Replay(Uuid::from_u128(10));
    assert!(matches!(
        ready(commit_observed_with_audience(
            std::future::ready(Ok::<(), ()>(())),
            &request,
            outcome,
            Some(audience()),
        )),
        Err(CommitError::Observation(Rejected::Result))
    ));
    ready(commit_observed(
        std::future::ready(Ok::<(), ()>(())),
        &request,
        outcome,
    ))
    .unwrap();
    assert!(request
        .returned(outcome)
        .unwrap()
        .into_fanout(&observation)
        .unwrap()
        .is_none());
}
