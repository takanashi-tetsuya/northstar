use super::*;
use chrono::Duration;

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
    let sql = include_str!("../../../migrations/0092_governance_export_pagination.sql");
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

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn postgres_hold_cleanup_delete_release_and_audit_invariants() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(8)
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    let admin = Uuid::new_v4();
    let user = Uuid::new_v4();
    for (id, prefix, is_admin) in [
        (admin, "governance-admin", true),
        (user, "governance-user", false),
    ] {
        sqlx::query(
            "INSERT INTO users(id,username,password_hash,is_admin)
                 VALUES($1,$2,'test-only',$3)",
        )
        .bind(id)
        .bind(format!("{prefix}-{}", &id.simple().to_string()[..10]))
        .bind(is_admin)
        .execute(&pool)
        .await
        .unwrap();
    }
    let room = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO muc_rooms(id,localpart,owner_id,persistent)
             VALUES($1,$2,$3,TRUE)",
    )
    .bind(room)
    .bind(format!("hold-{}", &room.simple().to_string()[..10]))
    .bind(user)
    .execute(&pool)
    .await
    .unwrap();
    let old = Utc::now() - Duration::days(60);
    let personal = Uuid::new_v4();
    let muc = Uuid::new_v4();
    let offline = Uuid::new_v4();
    let encrypted_stanza = "<message><encrypted xmlns='urn:xmpp:omemo:2'/></message>";
    sqlx::query(
        "INSERT INTO message_archive(
                 id,owner_id,peer_jid,peer_full_jid,stanza,encrypted,created_at)
             VALUES($1,$2,'peer@example.test','peer@example.test/device',$3,TRUE,$4)",
    )
    .bind(personal)
    .bind(user)
    .bind(encrypted_stanza)
    .bind(old)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO muc_messages(
                 id,room_id,sender_jid,nick,stanza,encrypted,created_at)
             VALUES($1,$2,'sender@example.test/device','sender',$3,TRUE,$4)",
    )
    .bind(muc)
    .bind(room)
    .bind(encrypted_stanza)
    .bind(old)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO offline_messages(
                 id,recipient_id,sender_jid,stanza,encrypted,created_at)
             VALUES($1,$2,'sender@example.test',$3,TRUE,$4)",
    )
    .bind(offline)
    .bind(user)
    .bind(encrypted_stanza)
    .bind(old)
    .execute(&pool)
    .await
    .unwrap();
    let report = Uuid::new_v4();
    let evidence = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO abuse_reports(
                 id,reporter_id,reported_jid,category,description,status,
                 resolved_at,created_at,updated_at)
             VALUES($1,$2,'reported@example.test','spam','fixture','closed',$3,$3,$3)",
    )
    .bind(report)
    .bind(user)
    .bind(old)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO abuse_report_evidence(
                 id,report_id,sender_jid,body_text,encrypted,position,created_at)
             VALUES($1,$2,'reported@example.test','unverified decrypted text',TRUE,0,$3)",
    )
    .bind(evidence)
    .bind(report)
    .bind(old)
    .execute(&pool)
    .await
    .unwrap();

    let hold = Uuid::new_v4();
    let targets = [
        LegalHoldTarget::PersonalArchive(personal),
        LegalHoldTarget::MucArchiveRoom(room),
        LegalHoldTarget::OfflineMessage(offline),
        LegalHoldTarget::ReportEvidence(evidence),
    ];
    let mut tx = pool.begin().await.unwrap();
    create_legal_hold_in_tx(
        &mut tx,
        admin,
        &CreateLegalHold {
            id: hold,
            title: "isolated fixture",
            authority_reference: "case-fixture-1",
            reason: "verify atomic retention exclusion",
            targets: &targets,
            request_id: Uuid::new_v4(),
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let admin_session = crate::db::create_api_session(&pool, admin, 1)
        .await
        .unwrap();
    let access_key_sha256 = "ab".repeat(32);
    let summaries = list_legal_holds_audited(
        &pool,
        admin,
        0,
        &admin_session,
        false,
        100,
        &access_key_sha256,
    )
    .await
    .unwrap();
    assert!(summaries.iter().any(|summary| summary.id == hold));
    assert!(matches!(
        list_legal_holds_audited(
            &pool,
            admin,
            0,
            &admin_session,
            false,
            101,
            &access_key_sha256,
        )
        .await,
        Err(LegalHoldError::Invalid)
    ));
    let mut logout = pool.begin().await.unwrap();
    assert!(crate::db::delete_api_session_audited_in_tx(
        &mut logout,
        &admin_session,
        Uuid::new_v4(),
    )
    .await
    .unwrap());
    logout.commit().await.unwrap();
    assert!(matches!(
        list_legal_holds_audited(
            &pool,
            admin,
            0,
            &admin_session,
            false,
            100,
            &access_key_sha256,
        )
        .await,
        Err(LegalHoldError::Forbidden)
    ));

    for store in [
        crate::db::RetentionStore::PersonalMam,
        crate::db::RetentionStore::MucMam,
        crate::db::RetentionStore::OfflineMessages,
    ] {
        assert_eq!(
            crate::db::purge_resolved_retention_batch(&pool, store, Utc::now(), 30, 100)
                .await
                .unwrap(),
            0
        );
    }
    assert_eq!(
        crate::db::purge_resolved_moderation_batch(&pool, 30, 100)
            .await
            .unwrap(),
        0
    );
    assert!(sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(user)
        .execute(&pool)
        .await
        .is_err());
    assert!(sqlx::query("DELETE FROM muc_rooms WHERE id=$1")
        .bind(room)
        .execute(&pool)
        .await
        .is_err());

    // A transport ACK may delete its queue row, but the trigger retains
    // only the encrypted, server-visible stanza in the same transaction.
    sqlx::query("DELETE FROM offline_messages WHERE id=$1")
        .bind(offline)
        .execute(&pool)
        .await
        .unwrap();
    let snapshot: (bool, String) = sqlx::query_as(
        "SELECT encrypted,stanza FROM legal_hold_offline_snapshots
              WHERE hold_id=$1 AND message_id=$2",
    )
    .bind(hold)
    .bind(offline)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(snapshot.0);
    assert!(snapshot.1.contains("urn:xmpp:omemo:2"));

    // Export initialization and release serialize on the same legal_holds
    // row.  The lease is inserted before that row lock is released, so a
    // release which was already waiting must observe the lease and fail
    // closed after the export transaction commits.
    let mut first_export_tx = pool.begin().await.unwrap();
    let first_export = export_legal_hold_page_in_tx(
        &mut first_export_tx,
        admin,
        hold,
        1,
        Uuid::new_v4(),
        None,
        Uuid::new_v4(),
    )
    .await
    .unwrap();
    assert!(!first_export.complete);
    assert!(first_export.next.is_some());
    let release_pool = pool.clone();
    let blocked_release = tokio::spawn(async move {
        let mut tx = release_pool.begin().await.unwrap();
        let result = release_legal_hold_in_tx(
            &mut tx,
            admin,
            hold,
            "must wait for the frozen export",
            Uuid::new_v4(),
        )
        .await;
        tx.rollback().await.unwrap();
        result
    });
    tokio::task::yield_now().await;
    first_export_tx.commit().await.unwrap();
    assert!(matches!(
        blocked_release.await.unwrap(),
        Err(LegalHoldError::Conflict)
    ));

    let mut next = first_export.next;
    let mut previous_root = first_export.chain_root_sha256;
    while let Some(cursor) = next {
        let mut page_tx = pool.begin().await.unwrap();
        let page = export_legal_hold_page_in_tx(
            &mut page_tx,
            admin,
            hold,
            1,
            Uuid::new_v4(),
            Some(cursor),
            Uuid::new_v4(),
        )
        .await
        .unwrap();
        assert_eq!(page.chain_start_sha256, previous_root);
        previous_root = page.chain_root_sha256.clone();
        next = page.next;
        page_tx.commit().await.unwrap();
    }

    // The inverse race is also fail closed: when release owns the row lock
    // first, an initial export waits, then observes a released hold.  It
    // may return only a complete single page and must not create a lease
    // or continuation that claims the released payload is frozen.
    let mut release = pool.begin().await.unwrap();
    release_legal_hold_in_tx(
        &mut release,
        admin,
        hold,
        "fixture authority ended",
        Uuid::new_v4(),
    )
    .await
    .unwrap();
    let release_won_export_id = Uuid::new_v4();
    let released_export_pool = pool.clone();
    let released_export = tokio::spawn(async move {
        let mut tx = released_export_pool.begin().await.unwrap();
        let result = export_legal_hold_page_in_tx(
            &mut tx,
            admin,
            hold,
            MAX_GOVERNANCE_EXPORT_ROWS,
            release_won_export_id,
            None,
            Uuid::new_v4(),
        )
        .await;
        match result {
            Ok(page) => {
                tx.commit().await.unwrap();
                Ok(page)
            }
            Err(error) => {
                tx.rollback().await.unwrap();
                Err(error)
            }
        }
    });
    tokio::task::yield_now().await;
    release.commit().await.unwrap();
    let released_export = released_export.await.unwrap().unwrap();
    assert!(released_export.complete);
    assert!(released_export.next.is_none());
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM governance_export_leases WHERE id=$1")
            .bind(release_won_export_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        purge_released_hold_snapshots_batch(&pool, 30, 100)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        crate::db::purge_resolved_retention_batch(
            &pool,
            crate::db::RetentionStore::PersonalMam,
            Utc::now(),
            30,
            100,
        )
        .await
        .unwrap(),
        1
    );
    assert_eq!(
        crate::db::purge_resolved_retention_batch(
            &pool,
            crate::db::RetentionStore::MucMam,
            Utc::now(),
            30,
            100,
        )
        .await
        .unwrap(),
        1
    );
    assert_eq!(
        crate::db::purge_resolved_moderation_batch(&pool, 30, 100)
            .await
            .unwrap(),
        1
    );

    let old_audit = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO audit_log(action,target,details,request_id,created_at)
             VALUES('fixture.old',$1,'{}'::JSONB,$2,$3)",
    )
    .bind(old_audit.to_string())
    .bind(old_audit)
    .bind(old)
    .execute(&pool)
    .await
    .unwrap();
    assert!(
        sqlx::query("UPDATE audit_log SET action='tampered' WHERE request_id=$1")
            .bind(old_audit)
            .execute(&pool)
            .await
            .is_err()
    );
    assert_eq!(purge_audit_log_batch(&pool, 30, 100).await.unwrap(), 1);

    sqlx::query("DELETE FROM muc_rooms WHERE id=$1")
        .bind(room)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM users WHERE id=ANY($1)")
        .bind(vec![user, admin])
        .execute(&pool)
        .await
        .unwrap();
}
