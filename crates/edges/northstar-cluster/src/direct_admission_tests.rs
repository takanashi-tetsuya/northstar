use super::*;

#[test]
fn direct_mode_rejects_unsafe_states_and_limits_spooling_to_eligible_stanzas() {
    let health = Arc::new(ClusterHealth::disabled());
    let admission = ClusterAdmission {
        health: Arc::clone(&health),
        direct_authority: None,
    };
    assert_eq!(admission.direct_mode(), DirectPostCommitMode::Live);
    assert!(admission
        .check_direct_eligibility(DirectSpoolEligibility::LiveOnly)
        .unwrap()
        .is_none());

    health
        .state
        .store(CLUSTER_DURABLE_DIRECT_ONLY, Ordering::Release);
    assert_eq!(admission.direct_mode(), DirectPostCommitMode::SpoolOnly);
    assert!(admission
        .check_direct_eligibility(DirectSpoolEligibility::LiveOnly)
        .is_err());
    // Even an eligible stanza must present this process's exact PG identity.
    assert!(admission
        .check_direct_eligibility(DirectSpoolEligibility::Eligible)
        .is_err());

    for state in [
        CLUSTER_RECONCILING,
        CLUSTER_FAIL_CLOSED,
        CLUSTER_SHUTDOWN_REQUIRED,
    ] {
        health.state.store(state, Ordering::Release);
        assert_eq!(admission.direct_mode(), DirectPostCommitMode::Rejected);
        assert!(admission
            .check_direct_eligibility(DirectSpoolEligibility::Eligible)
            .is_err());
    }
}
