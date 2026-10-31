use super::*;

#[test]
fn users_can_only_move_effective_cutoffs_earlier() {
    let limits = RetentionPolicyLimits {
        personal_mam_days: 365,
        offline_message_days: 30,
        moderation_evidence_days: 365,
    };
    let old = UserRetentionPolicy {
        personal_mam_days: Some(90),
        offline_message_days: Some(14),
        moderation_evidence_days: Some(180),
    };
    assert!(policy_does_not_extend(
        old,
        UserRetentionPolicy {
            personal_mam_days: Some(30),
            offline_message_days: Some(7),
            moderation_evidence_days: Some(90),
        },
        limits,
    ));
    assert!(!policy_does_not_extend(
        old,
        UserRetentionPolicy {
            personal_mam_days: None,
            ..old
        },
        limits,
    ));
    assert!(!valid_requested_days(Some(366), 365, 1));
    assert!(!valid_requested_days(Some(29), 365, 30));
}

#[test]
fn audit_chain_is_length_delimited_and_domain_separated() {
    let genesis = audit_chain_genesis(
        Uuid::from_u128(1),
        Uuid::from_u128(2),
        DateTime::from_timestamp_micros(1_700_000_000_000_000).unwrap(),
        99,
        None,
        None,
    );
    let one = chain_next(genesis, b"ab");
    let ambiguous = chain_next(genesis, b"a");
    assert_ne!(one, ambiguous);
    assert_eq!(hex(&genesis).len(), 64);

    // Carrying the page-one root produces exactly the same final root as
    // one uninterrupted walk over the rows.
    let page_one = chain_next(genesis, b"row-1");
    let page_two = chain_next(page_one, b"row-2");
    assert_eq!(
        page_two,
        chain_next(chain_next(genesis, b"row-1"), b"row-2")
    );
    assert_ne!(
        genesis,
        audit_chain_genesis(
            Uuid::from_u128(3),
            Uuid::from_u128(2),
            DateTime::from_timestamp_micros(1_700_000_000_000_000).unwrap(),
            99,
            None,
            None,
        )
    );
}

#[test]
fn governance_bounds_are_hard_limits() {
    assert_eq!(MAX_HOLD_TARGETS, 1_000);
    assert_eq!(MAX_GOVERNANCE_EXPORT_ROWS, 10_000);
    assert_eq!(GOVERNANCE_EXPORT_LEASE_SECONDS, 900);
    assert_eq!(
        GOVERNANCE_SNAPSHOT_ISOLATION_SQL,
        "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ"
    );
    let duplicated = [
        LegalHoldTarget::PersonalArchive(Uuid::nil()),
        LegalHoldTarget::PersonalArchive(Uuid::nil()),
    ];
    assert_ne!(
        duplicated.iter().copied().collect::<HashSet<_>>().len(),
        duplicated.len()
    );
}

#[test]
fn governance_export_migration_fences_release_retention_and_history() {
    let sql = include_str!("../../../../../migrations/0092_governance_export_pagination.sql");
    for invariant in [
        "governance_export_leases",
        "export.expires_at > clock_timestamp()",
        "legal hold has an active export lease",
        "log.id <= export.snapshot_max_id",
        "northstar_purge_governance_export_leases",
        "governance export lease history is immutable",
        "INTERVAL '15 minutes'",
    ] {
        assert!(sql.contains(invariant), "migration omits {invariant}");
    }
    assert!(HELD_RECORD_PAGE_SQL.contains("record_created_at <= $2"));
    assert!(
        HELD_RECORD_PAGE_SQL.contains("(resource_order,record_created_at,record_id) > ($3,$4,$5)")
    );
    assert!(AUDIT_EXPORT_PAGE_SQL.contains("id > $3 AND id <= $4"));
    assert!(AUDIT_EXPORT_PAGE_SQL.contains("target IS NOT DISTINCT FROM $5::TEXT"));
}
