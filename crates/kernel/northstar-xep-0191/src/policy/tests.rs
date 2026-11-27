use super::*;

#[test]
fn overlapping_coverage_and_other_policy_gate_transitions() {
    use PresenceTransition::*;

    let peer = CanonicalJid::parse("bob@example.test/Phone").unwrap();
    let covered = |patterns: &[&str]| {
        patterns
            .iter()
            .any(|pattern| BlockPattern::new(CanonicalJid::parse(pattern).unwrap()).matches(&peer))
    };
    let full = "bob@example.test/Phone";
    let bare = "bob@example.test";
    let domain = "example.test";
    assert_eq!(
        effective_presence_transition(
            covered(&[full, bare, domain]),
            covered(&[bare]),
            true,
            false
        ),
        None
    );
    assert_eq!(
        effective_presence_transition(
            covered(&[full]),
            covered(&["example.test/Phone"]),
            true,
            false
        ),
        Some(RestoreCurrent)
    );
    assert_eq!(
        effective_presence_transition(true, false, false, true),
        None
    );
    assert_eq!(
        effective_presence_transition(false, true, false, false),
        None
    );
    assert_eq!(
        effective_presence_transition(false, true, false, true),
        Some(SendUnavailable)
    );
    assert_eq!(effective_presence_transition(true, true, true, true), None);
}
