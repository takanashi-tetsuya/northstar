use super::*;
use uuid::Uuid;

fn remote(full_jid: &str, node: &str, presence: Option<(bool, i16)>) -> ExactMessageRoute {
    ExactMessageRoute {
        full_jid: full_jid.to_owned(),
        account_id: Uuid::nil(),
        auth_generation: 1,
        connection_id: Uuid::nil(),
        node_id: Some(node.to_owned()),
        available: presence.map(|(available, _)| available),
        priority: presence.map(|(_, priority)| priority),
    }
}

fn order(local: &[(String, Option<i16>)], remote: &[ExactMessageRoute]) -> Vec<String> {
    rank_primary_routes(local.iter().map(|target| (target, target.1)), remote)
        .into_iter()
        .map(|candidate| match candidate {
            PrimaryRouteCandidate::Local(target) => target.0.clone(),
            PrimaryRouteCandidate::Remote(route) => route.full_jid.clone(),
        })
        .collect()
}

#[test]
fn known_eligible_routes_rank_across_nodes_before_legacy_routes() {
    let local = [
        ("local".to_owned(), Some(5)),
        ("ineligible".to_owned(), None),
    ];
    let legacy_z = remote("legacy-z", "a", None);
    let legacy_a = remote("legacy-a", "a", None);
    let legacy_other = remote("legacy-other", "b", None);
    let negative = remote("negative", "a", Some((true, -1)));
    let unavailable = remote("unavailable", "a", Some((false, 127)));
    assert_eq!(
        order(
            &local,
            &[
                legacy_z.clone(),
                negative.clone(),
                remote("tie-on-b", "b", Some((true, 5))),
                remote("zero", "a", Some((true, 0))),
                unavailable.clone(),
                legacy_other.clone(),
                remote("high", "z", Some((true, 7))),
                remote("tie-on-a-z", "a", Some((true, 5))),
                remote("tie-on-a-a", "a", Some((true, 5))),
                legacy_a.clone(),
            ],
        ),
        [
            "high",
            "local",
            "tie-on-a-a",
            "tie-on-a-z",
            "tie-on-b",
            "zero",
            "legacy-a",
            "legacy-z",
            "legacy-other",
        ],
    );
    assert!(order(&[], &[negative, unavailable]).is_empty());
    assert_eq!(
        order(&local, &[legacy_other, legacy_z, legacy_a]),
        ["local", "legacy-a", "legacy-z", "legacy-other"],
    );
}
