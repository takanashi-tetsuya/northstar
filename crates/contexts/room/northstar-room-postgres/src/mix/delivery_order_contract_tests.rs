/// This pure contract model mirrors the `NOT EXISTS earlier` predicate in
/// `claim_mix_deliveries`. Database fixtures separately prove the SQL row
/// transition; the model prevents an expired-but-present predecessor from
/// being silently reclassified as terminal during A-phase review.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Predecessor {
    None,
    Live,
    ExpiredUnowned,
    Leased,
    SmOwned,
    BoshOwned,
    ClusterFenced,
    Terminalized,
}

const fn blocks_successor(predecessor: Predecessor) -> bool {
    !matches!(predecessor, Predecessor::None | Predecessor::Terminalized)
}

fn has_blocking_predecessor(
    entries: &[(&str, i64, Predecessor)],
    recipient: &str,
    delivery_sequence: i64,
) -> bool {
    entries
        .iter()
        .any(|(entry_recipient, entry_sequence, state)| {
            *entry_recipient == recipient
                && *entry_sequence < delivery_sequence
                && blocks_successor(*state)
        })
}

#[test]
fn mx08_expired_unowned_predecessor_blocks_until_terminalization() {
    assert!(blocks_successor(Predecessor::ExpiredUnowned));
    assert!(!blocks_successor(Predecessor::Terminalized));
}

#[test]
fn ordered_predecessor_contract_distinguishes_no_head_from_all_live_owners() {
    assert!(!blocks_successor(Predecessor::None));
    for predecessor in [
        Predecessor::Live,
        Predecessor::Leased,
        Predecessor::SmOwned,
        Predecessor::BoshOwned,
        Predecessor::ClusterFenced,
    ] {
        assert!(blocks_successor(predecessor));
    }
}

#[test]
fn mx09_and_mx11_scope_a_strict_head_to_its_recipient_ordering_domain() {
    let entries = [
        ("alice@example.test", 1, Predecessor::ExpiredUnowned),
        ("alice@example.test", 2, Predecessor::Terminalized),
        ("bob@example.test", 1, Predecessor::Live),
    ];
    assert!(has_blocking_predecessor(&entries, "alice@example.test", 2));
    assert!(!has_blocking_predecessor(&entries, "alice@example.test", 1));
    assert!(!has_blocking_predecessor(&entries, "carol@example.test", 2));
    assert!(has_blocking_predecessor(&entries, "bob@example.test", 2));
}
