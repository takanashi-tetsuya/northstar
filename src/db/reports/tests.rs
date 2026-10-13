use super::*;

fn solve_pow(challenge: &crate::abuse::PowChallenge) -> crate::abuse::PowProof {
    let target = u64::MAX / challenge.requirement.work_factor.max(1);
    for nonce in 0_u64.. {
        let nonce = nonce.to_string();
        let mut hasher = Sha256::new();
        hasher.update(challenge.prefix.as_bytes());
        hasher.update(nonce.as_bytes());
        let digest = hasher.finalize();
        if u64::from_be_bytes(digest[..8].try_into().unwrap()) <= target {
            return crate::abuse::PowProof {
                challenge_id: challenge.challenge_id,
                nonce,
            };
        }
    }
    unreachable!()
}

fn report_idempotency_request<'a>(
    actor_id: &'a Uuid,
    key: &'a str,
    target_scope: &'a [u8],
    body: &[u8],
) -> crate::db::IdempotencyRequest<'a> {
    crate::db::IdempotencyRequest {
        request_id: Uuid::new_v4(),
        actor_id: Some(*actor_id),
        principal_scope: actor_id.as_bytes(),
        capacity_scope: actor_id.as_bytes(),
        target_scope,
        principal_kind: crate::db::ApiPrincipalKind::User,
        method: "POST",
        route: "/api/v1/reports",
        idempotency_key: key,
        request_fingerprint: crate::db::api_request_fingerprint("application/json", body),
        ttl_seconds: 3600,
        lease_seconds: 180,
    }
}

fn acquired(outcome: crate::db::IdempotencyAcquire) -> crate::db::IdempotencyLease {
    match outcome {
        crate::db::IdempotencyAcquire::Acquired(lease) => lease,
        other => panic!("expected a newly acquired idempotency lease, got {other:?}"),
    }
}

#[test]
fn terminal_moderation_states_cannot_be_silently_reopened() {
    assert!(valid_moderation_transition(
        ModerationKind::Report,
        "submitted",
        "reviewing"
    ));
    assert!(valid_moderation_transition(
        ModerationKind::Appeal,
        "reviewing",
        "upheld"
    ));
    assert!(!valid_moderation_transition(
        ModerationKind::Report,
        "closed",
        "submitted"
    ));
    assert!(!valid_moderation_transition(
        ModerationKind::Appeal,
        "denied",
        "reviewing"
    ));
    assert!(!valid_moderation_transition(
        ModerationKind::Report,
        "closed",
        "closed"
    ));
}

#[test]
fn plaintext_evidence_uses_archive_body_and_omemo_is_explicitly_unverified() {
    let plaintext = "<message xmlns='jabber:client' from='peer@example.test/phone'><body>server copy</body></message>";
    let (_, body, source) = evidence_from_archive(plaintext, false, "forged copy").unwrap();
    assert_eq!(body, "server copy");
    assert_eq!(source, "server_verified_plaintext");

    let encrypted = "<message xmlns='jabber:client' from='peer@example.test/phone'><encrypted xmlns='urn:xmpp:omemo:2'/><body>This message is encrypted</body></message>";
    let (_, body, source) = evidence_from_archive(encrypted, true, "user decrypted text").unwrap();
    assert_eq!(body, "user decrypted text");
    assert_eq!(source, "user_decrypted_omemo_unverified");
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn report_evidence_is_owned_peer_bound_atomic_and_moderation_is_serialized() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(12)
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    let reporter = Uuid::new_v4();
    let other = Uuid::new_v4();
    let admin_a = Uuid::new_v4();
    let admin_b = Uuid::new_v4();
    for (id, prefix, admin) in [
        (reporter, "reporter", false),
        (other, "other", false),
        (admin_a, "admina", true),
        (admin_b, "adminb", true),
    ] {
        sqlx::query(
            "INSERT INTO users (id,username,password_hash,is_admin) VALUES ($1,$2,'test-only', $3)",
        )
        .bind(id)
        .bind(format!("{prefix}-{}", &id.simple().to_string()[..10]))
        .bind(admin)
        .execute(&pool)
        .await
        .unwrap();
    }
    let admin_a_session = crate::db::create_api_session(&pool, admin_a, 1)
        .await
        .unwrap();
    let admin_b_session = crate::db::create_api_session(&pool, admin_b, 1)
        .await
        .unwrap();
    let archive_id = Uuid::new_v4();
    sqlx::query("INSERT INTO message_archive (id,owner_id,peer_jid,peer_full_jid,stanza,encrypted,stanza_id) VALUES ($1,$2,'peer@example.test','peer@example.test/phone',$3,FALSE,'client-1')")
        .bind(archive_id).bind(reporter)
        .bind("<message xmlns='jabber:client' from='peer@example.test/phone'><body>authoritative body</body></message>")
        .execute(&pool).await.unwrap();
    let report = create_report(
        &pool,
        reporter,
        "peer@example.test",
        "spam",
        "description",
        &[ReportEvidenceInput {
            archive_id,
            client_message_id: Some("client-1".into()),
            body_text: "forged body".into(),
        }],
    )
    .await
    .unwrap();
    let row = sqlx::query("SELECT archive_id, body_text, sender_jid, evidence_source, archive_stanza_hash FROM abuse_report_evidence WHERE report_id=$1")
        .bind(report).fetch_one(&pool).await.unwrap();
    assert_eq!(row.get::<Uuid, _>("archive_id"), archive_id);
    assert_eq!(row.get::<String, _>("body_text"), "authoritative body");
    assert_eq!(
        row.get::<String, _>("sender_jid"),
        "peer@example.test/phone"
    );
    assert_eq!(
        row.get::<String, _>("evidence_source"),
        "server_verified_plaintext"
    );
    assert_eq!(row.get::<Vec<u8>, _>("archive_stanza_hash").len(), 32);

    let foreign_archive = Uuid::new_v4();
    sqlx::query("INSERT INTO message_archive (id,owner_id,peer_jid,peer_full_jid,stanza,encrypted) VALUES ($1,$2,'peer@example.test','peer@example.test/phone',$3,TRUE)")
        .bind(foreign_archive).bind(other)
        .bind("<message xmlns='jabber:client' from='peer@example.test/phone'><encrypted xmlns='urn:xmpp:omemo:2'/></message>")
        .execute(&pool).await.unwrap();
    assert!(matches!(
        create_report(
            &pool,
            reporter,
            "peer@example.test",
            "spam",
            "",
            &[ReportEvidenceInput {
                archive_id: foreign_archive,
                client_message_id: None,
                body_text: "claimed decrypt".into(),
            }]
        )
        .await,
        Err(ReportCreateError::InvalidEvidence(_))
    ));

    // Row locking permits exactly one competing terminal resolution.
    let left = {
        let pool = pool.clone();
        let session = admin_a_session.clone();
        tokio::spawn(async move {
            admin_update_report_api(&pool, report, admin_a, 0, &session, "actioned", "action a")
                .await
        })
    };
    let right = {
        let pool = pool.clone();
        let session = admin_b_session.clone();
        tokio::spawn(async move {
            admin_update_report_api(&pool, report, admin_b, 0, &session, "rejected", "action b")
                .await
        })
    };
    let outcomes = [left.await.unwrap(), right.await.unwrap()];
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, Err(ModerationUpdateError::InvalidTransition)))
            .count(),
        1
    );
    let appeal = create_appeal(
        &pool,
        report,
        reporter,
        "This is a sufficiently long appeal reason.",
    )
    .await
    .unwrap();
    assert!(matches!(
        create_appeal(
            &pool,
            report,
            reporter,
            "This is another sufficiently long appeal reason."
        )
        .await,
        Err(AppealCreateError::Conflict)
    ));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM audit_log WHERE actor_id=$1 AND action IN ('abuse.report.create','abuse.appeal.create')")
            .bind(reporter).fetch_one(&pool).await.unwrap(),
        2
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM abuse_appeals WHERE id=$1")
            .bind(appeal)
            .fetch_one(&pool)
            .await
            .unwrap(),
        1
    );

    sqlx::query(
        "UPDATE abuse_reports SET resolved_at=clock_timestamp()-INTERVAL '400 days' WHERE id=$1",
    )
    .bind(report)
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(
        purge_resolved_moderation_batch(&pool, 365, 100)
            .await
            .unwrap(),
        0,
        "a pending appeal must hold its report and evidence"
    );
    admin_update_appeal_api(
        &pool,
        appeal,
        admin_a,
        0,
        &admin_a_session,
        "denied",
        "appeal denied",
    )
    .await
    .unwrap();
    sqlx::query(
        "UPDATE abuse_appeals SET resolved_at=clock_timestamp()-INTERVAL '400 days' WHERE id=$1",
    )
    .bind(appeal)
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(
        purge_resolved_moderation_batch(&pool, 365, 100)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM abuse_report_evidence WHERE report_id=$1"
        )
        .bind(report)
        .fetch_one(&pool)
        .await
        .unwrap(),
        0,
        "expired copied message content must cascade"
    );

    sqlx::query("DELETE FROM users WHERE id = ANY($1)")
        .bind(vec![reporter, other, admin_a, admin_b])
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn report_and_appeal_transactions_are_idempotent_pow_atomic_and_serialized() {
    use crate::abuse::{AbuseAction, AbuseConfig, AbuseGuard, TransactionalGuardOutcome};
    use std::time::Duration;

    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(12)
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    let reporter = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test-only-invalid')")
        .bind(reporter)
        .bind(format!("atomic-{}", &reporter.simple().to_string()[..10]))
        .execute(&pool)
        .await
        .unwrap();
    let session = crate::db::create_api_session(&pool, reporter, 1)
        .await
        .unwrap();
    let archive_id = Uuid::new_v4();
    sqlx::query("INSERT INTO message_archive(id,owner_id,peer_jid,peer_full_jid,stanza,encrypted,stanza_id) VALUES($1,$2,'peer@example.test','peer@example.test/phone',$3,FALSE,'atomic-message')")
        .bind(archive_id)
        .bind(reporter)
        .bind("<message xmlns='jabber:client' from='peer@example.test/phone'><body>authoritative body</body></message>")
        .execute(&pool)
        .await
        .unwrap();
    let evidence = [ReportEvidenceInput {
        archive_id,
        client_message_id: Some("atomic-message".into()),
        body_text: "client copy is ignored".into(),
    }];
    let keyring = std::sync::Arc::new(
        crate::db::ApiControlKeyring::new(b"report-api-control-test-key-00000001", None).unwrap(),
    );
    let guard = AbuseGuard::new_persistent(
        AbuseConfig {
            base_work_factor: 2,
            max_work_factor: 1024,
            window: Duration::from_secs(60),
            cooldown_step: Duration::from_secs(60),
            max_wait: Duration::from_secs(900),
            message_free_burst: 6,
            approximate_max_device_seconds: 8,
        },
        pool.clone(),
        Some(b"report-abuse-test-key-at-least-32-bytes"),
        None,
    );
    let actors = vec![format!("user:{reporter}")];
    let subject = format!("report:{reporter}");
    let headers = std::collections::BTreeMap::from([
        ("cache-control".to_owned(), "no-store, max-age=0".to_owned()),
        ("content-type".to_owned(), "application/json".to_owned()),
    ]);

    let first_key = "report-atomic-key-0001".to_owned();
    let first_request = report_idempotency_request(&reporter, &first_key, b"", b"report-body-one");
    let first_challenge = guard
        .issue(AbuseAction::Report, &subject, &actors)
        .await
        .unwrap();
    let first_proof = solve_pow(&first_challenge);
    let mut tx = pool.begin().await.unwrap();
    assert!(
        crate::db::authorize_user_in_tx(&mut tx, reporter, 0, &session)
            .await
            .unwrap()
    );
    let first_lease = acquired(
        crate::db::acquire_idempotency_in_tx(&keyring, &mut tx, &first_request)
            .await
            .unwrap(),
    );
    assert!(matches!(
        crate::db::abuse_transaction_repository::verify_in_tx(
            &mut tx,
            &guard,
            AbuseAction::Report,
            &subject,
            &actors,
            Some(&first_proof),
            None,
        )
        .await
        .unwrap(),
        TransactionalGuardOutcome::Allowed
    ));
    assert!(
        crate::db::mark_idempotency_guard_verified_in_tx(&mut tx, &first_lease)
            .await
            .unwrap()
    );
    let first_report = create_report_in_tx(
        &mut tx,
        reporter,
        "peer@example.test",
        "spam",
        "first report",
        &evidence,
        Some(first_lease.request_id),
    )
    .await
    .unwrap();
    assert!(crate::db::complete_idempotency_in_tx(
        &keyring,
        &mut tx,
        &first_lease,
        201,
        &headers,
        first_report.to_string().as_bytes(),
    )
    .await
    .unwrap());
    tx.commit().await.unwrap();

    let mut replay_tx = pool.begin().await.unwrap();
    match crate::db::acquire_idempotency_in_tx(&keyring, &mut replay_tx, &first_request)
        .await
        .unwrap()
    {
        crate::db::IdempotencyAcquire::Replay(replay) => {
            assert_eq!(replay.status, 201);
            assert_eq!(replay.body, first_report.to_string().as_bytes());
        }
        other => panic!("expected committed report replay, got {other:?}"),
    }
    replay_tx.commit().await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM abuse_reports WHERE reporter_id=$1")
            .bind(reporter)
            .fetch_one(&pool)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM audit_log WHERE request_id=$1 AND action='abuse.report.create'"
        )
        .bind(first_lease.request_id)
        .fetch_one(&pool)
        .await
        .unwrap(),
        1
    );

    // A process failure after proof consumption but before commit restores
    // the challenge, guard state, reservation, report and audit together.
    let crash_key = "report-crash-key-0002".to_owned();
    let crash_request =
        report_idempotency_request(&reporter, &crash_key, b"", b"report-body-crash");
    let crash_challenge = guard
        .issue(AbuseAction::Report, &subject, &actors)
        .await
        .unwrap();
    let crash_proof = solve_pow(&crash_challenge);
    let mut crashed_tx = pool.begin().await.unwrap();
    let crashed_lease = acquired(
        crate::db::acquire_idempotency_in_tx(&keyring, &mut crashed_tx, &crash_request)
            .await
            .unwrap(),
    );
    assert!(matches!(
        crate::db::abuse_transaction_repository::verify_in_tx(
            &mut crashed_tx,
            &guard,
            AbuseAction::Report,
            &subject,
            &actors,
            Some(&crash_proof),
            None,
        )
        .await
        .unwrap(),
        TransactionalGuardOutcome::Allowed
    ));
    assert!(
        crate::db::mark_idempotency_guard_verified_in_tx(&mut crashed_tx, &crashed_lease)
            .await
            .unwrap()
    );
    let _ = create_report_in_tx(
        &mut crashed_tx,
        reporter,
        "peer@example.test",
        "spam",
        "rolled back",
        &evidence,
        Some(crashed_lease.request_id),
    )
    .await
    .unwrap();
    crashed_tx.rollback().await.unwrap();

    let mut retry_tx = pool.begin().await.unwrap();
    let retry_lease = acquired(
        crate::db::acquire_idempotency_in_tx(&keyring, &mut retry_tx, &crash_request)
            .await
            .unwrap(),
    );
    assert!(!retry_lease.guard_verified);
    assert!(matches!(
        crate::db::abuse_transaction_repository::verify_in_tx(
            &mut retry_tx,
            &guard,
            AbuseAction::Report,
            &subject,
            &actors,
            Some(&crash_proof),
            None,
        )
        .await
        .unwrap(),
        TransactionalGuardOutcome::Allowed
    ));
    assert!(
        crate::db::mark_idempotency_guard_verified_in_tx(&mut retry_tx, &retry_lease)
            .await
            .unwrap()
    );
    let retried_report = create_report_in_tx(
        &mut retry_tx,
        reporter,
        "peer@example.test",
        "spam",
        "committed retry",
        &evidence,
        Some(retry_lease.request_id),
    )
    .await
    .unwrap();
    assert!(crate::db::complete_idempotency_in_tx(
        &keyring,
        &mut retry_tx,
        &retry_lease,
        201,
        &headers,
        retried_report.to_string().as_bytes(),
    )
    .await
    .unwrap());
    retry_tx.commit().await.unwrap();

    // PostgreSQL-rejected NUL input is caught by the shared API validator,
    // then completed as a deterministic 400 in the same transaction as
    // proof consumption. It cannot become an infinite 500/retry loop.
    let invalid_key = "report-invalid-key-0003".to_owned();
    let invalid_request =
        report_idempotency_request(&reporter, &invalid_key, b"", b"report-body-invalid");
    let invalid_payload = crate::services::reports::ReportInput {
        reported_jid: "peer@example.test",
        category: "spam",
        evidence: vec![ReportEvidenceInput {
            archive_id,
            client_message_id: Some("atomic-message".into()),
            body_text: "invalid\0evidence".into(),
        }],
        description: Some("description"),
    };
    assert_eq!(
        crate::services::reports::report_validation_error(&invalid_payload),
        Some("report evidence is invalid")
    );
    let step_before_invalid = guard
        .current_requirement(AbuseAction::Report, &actors)
        .await
        .unwrap()
        .step;
    let invalid_challenge = guard
        .issue(AbuseAction::Report, &subject, &actors)
        .await
        .unwrap();
    let invalid_proof = solve_pow(&invalid_challenge);
    let mut invalid_tx = pool.begin().await.unwrap();
    let invalid_lease = acquired(
        crate::db::acquire_idempotency_in_tx(&keyring, &mut invalid_tx, &invalid_request)
            .await
            .unwrap(),
    );
    assert!(matches!(
        crate::db::abuse_transaction_repository::verify_in_tx(
            &mut invalid_tx,
            &guard,
            AbuseAction::Report,
            &subject,
            &actors,
            Some(&invalid_proof),
            None,
        )
        .await
        .unwrap(),
        TransactionalGuardOutcome::Allowed
    ));
    assert!(
        crate::db::mark_idempotency_guard_verified_in_tx(&mut invalid_tx, &invalid_lease)
            .await
            .unwrap()
    );
    assert!(crate::db::complete_idempotency_in_tx(
        &keyring,
        &mut invalid_tx,
        &invalid_lease,
        400,
        &headers,
        br#"{"error":{"code":"bad_request"}}"#,
    )
    .await
    .unwrap());
    invalid_tx.commit().await.unwrap();
    let mut invalid_replay_tx = pool.begin().await.unwrap();
    assert!(matches!(
        crate::db::acquire_idempotency_in_tx(&keyring, &mut invalid_replay_tx, &invalid_request,)
            .await
            .unwrap(),
        crate::db::IdempotencyAcquire::Replay(crate::db::IdempotentResponse { status: 400, .. })
    ));
    invalid_replay_tx.commit().await.unwrap();
    assert!(
        guard
            .current_requirement(AbuseAction::Report, &actors)
            .await
            .unwrap()
            .step
            > step_before_invalid
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM abuse_pow_challenges WHERE id=$1")
            .bind(invalid_challenge.challenge_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM abuse_reports WHERE reporter_id=$1")
            .bind(reporter)
            .fetch_one(&pool)
            .await
            .unwrap(),
        2
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM audit_log WHERE request_id=$1")
            .bind(invalid_lease.request_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );

    sqlx::query("UPDATE abuse_reports SET status='closed' WHERE id=$1")
        .bind(first_report)
        .execute(&pool)
        .await
        .unwrap();
    let concurrent_appeal = |key: &'static str, body: &'static [u8]| {
        let pool = pool.clone();
        let keyring = keyring.clone();
        let session = session.clone();
        let headers = headers.clone();
        async move {
            let request = report_idempotency_request(&reporter, key, first_report.as_bytes(), body);
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            loop {
                let mut tx = pool.begin().await.unwrap();
                assert!(
                    crate::db::authorize_user_in_tx(&mut tx, reporter, 0, &session)
                        .await
                        .unwrap()
                );
                let lease = match crate::db::acquire_idempotency_in_tx(&keyring, &mut tx, &request)
                    .await
                    .unwrap()
                {
                    crate::db::IdempotencyAcquire::Acquired(lease) => lease,
                    crate::db::IdempotencyAcquire::Busy {
                        retry_after_seconds,
                    } => {
                        tx.rollback().await.unwrap();
                        let remaining = deadline
                            .checked_duration_since(tokio::time::Instant::now())
                            .expect("appeal admission remained busy after five seconds");
                        tokio::time::sleep(
                            Duration::from_secs(retry_after_seconds.max(1)).min(remaining),
                        )
                        .await;
                        continue;
                    }
                    other => {
                        panic!("expected a newly acquired appeal lease, got {other:?}")
                    }
                };
                assert!(
                    crate::db::mark_idempotency_guard_verified_in_tx(&mut tx, &lease)
                        .await
                        .unwrap()
                );
                let status = match create_appeal_in_tx(
                    &mut tx,
                    first_report,
                    reporter,
                    "This is a sufficiently long concurrent appeal reason.",
                    Some(lease.request_id),
                )
                .await
                {
                    Ok(_) => 201,
                    Err(AppealCreateError::Conflict) => 409,
                    Err(AppealCreateError::Internal(error)) => {
                        panic!("appeal failed: {error:?}")
                    }
                };
                assert!(crate::db::complete_idempotency_in_tx(
                    &keyring,
                    &mut tx,
                    &lease,
                    status,
                    &headers,
                    status.to_string().as_bytes(),
                )
                .await
                .unwrap());
                tx.commit().await.unwrap();
                return status;
            }
        }
    };
    let (left, right) = tokio::join!(
        concurrent_appeal("appeal-race-key-0001", b"appeal-one"),
        concurrent_appeal("appeal-race-key-0002", b"appeal-two"),
    );
    let mut statuses = [left, right];
    statuses.sort_unstable();
    assert_eq!(statuses, [201, 409]);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM abuse_appeals WHERE report_id=$1")
            .bind(first_report)
            .fetch_one(&pool)
            .await
            .unwrap(),
        1
    );

    // The route template and key can match, but a different canonical
    // report UUID is still a different idempotent request.
    let target_key = "appeal-target-key-0003".to_owned();
    let first_target = report_idempotency_request(
        &reporter,
        &target_key,
        first_report.as_bytes(),
        b"same-appeal-body",
    );
    let mut target_tx = pool.begin().await.unwrap();
    let target_lease = acquired(
        crate::db::acquire_idempotency_in_tx(&keyring, &mut target_tx, &first_target)
            .await
            .unwrap(),
    );
    assert!(crate::db::complete_idempotency_in_tx(
        &keyring,
        &mut target_tx,
        &target_lease,
        409,
        &headers,
        b"conflict",
    )
    .await
    .unwrap());
    target_tx.commit().await.unwrap();
    let other_report_id = Uuid::new_v4();
    let other_target = report_idempotency_request(
        &reporter,
        &target_key,
        other_report_id.as_bytes(),
        b"same-appeal-body",
    );
    let mut conflict_tx = pool.begin().await.unwrap();
    assert!(matches!(
        crate::db::acquire_idempotency_in_tx(&keyring, &mut conflict_tx, &other_target)
            .await
            .unwrap(),
        crate::db::IdempotencyAcquire::FingerprintConflict
    ));
    conflict_tx.rollback().await.unwrap();
    pool.close().await;
}
