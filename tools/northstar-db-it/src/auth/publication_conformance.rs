use northstar_auth_application::authentication::{publication::*, *};
use northstar_auth_postgres::authentication::PostgresAuthenticationRepository;
use northstar_workflows::authentication_effects::WorkflowAuthenticationEffects;
use std::sync::Arc;
use uuid::Uuid;
use zeroize::Zeroizing;

#[tokio::test]
#[ignore = "requires the ordinary-role random schema and TEST_DATABASE_URL"]
async fn credential_publication_observes_commit_and_both_refusal_rollbacks() {
    let pool = crate::support::operation_mutation_pool().await;
    let user = Uuid::from_u128(0x573_6501);
    let device = Uuid::from_u128(0x573_6502);
    let connection = Uuid::from_u128(0x573_6503);
    sqlx::query(
        "INSERT INTO users(id,username,password_hash) VALUES($1,'publication-fence','test-only')",
    )
    .bind(user)
    .execute(&pool)
    .await
    .unwrap();
    let mut reservation = pool.begin().await.unwrap();
    assert_eq!(
        northstar_session_postgres::capacity::reserve_live_session_in_transaction(
            &mut reservation,
            connection,
            user,
            "publication-fence@example.test/phone",
            120,
            false,
        )
        .await
        .unwrap(),
        northstar_session_postgres::capacity::LiveSessionReservation::Reserved
    );
    reservation.commit().await.unwrap();
    let service = AuthenticationService::new(
        PostgresAuthenticationRepository::new(
            pool.clone(),
            Arc::new(Zeroizing::new(vec![41; 32])),
            WorkflowAuthenticationEffects,
        ),
        Arc::new(Zeroizing::new(vec![42; 32])),
        northstar_auth_core::MIN_SCRAM_ITERATIONS,
        false,
    );
    for (label, with_binding, expected_commit) in [
        ("stored epoch", false, true),
        ("missing binding reservation", true, false),
    ] {
        let mut tx = northstar_auth_postgres::users::lock_auth_generation(&pool, user, 0)
            .await
            .unwrap()
            .unwrap();
        let staged =
            northstar_auth_postgres::authentication::stage_login_epoch_in_transaction_observed(
                &mut tx,
                user,
                Some(device),
                0,
                connection,
                None,
            )
            .await
            .unwrap()
            .unwrap();
        tx.commit().await.unwrap();
        let receipt = CredentialCommitReceipt::new(
            None,
            Some(staged),
            with_binding.then(|| BindingPublication {
                connection_id: connection,
                user_id: user,
                full_jid: "publication-fence@example.test/missing".to_owned(),
                lease_seconds: 120,
            }),
        );
        let observation =
            Observation::returned_receipt(&receipt, Some(Uuid::from_u128(0x573_6504)));
        observation.sealed(with_binding, false).unwrap();
        observation.transport(Transport::Recording).unwrap();
        observation.transport(Transport::WriteEntered).unwrap();
        observation.transport(Transport::Written).unwrap();
        let invocation = observation.begin(&receipt).unwrap();
        let result = service
            .publish_credential_commit_observed(&invocation)
            .await;
        let snapshot = observation.snapshot();
        assert!(
            snapshot.service_started && snapshot.repository_started,
            "{label}"
        );
        assert!(snapshot.return_matches, "{label}");
        if expected_commit {
            assert!(
                matches!(result, AuthenticationResult::Authenticated(Some(epoch)) if epoch == staged.epoch),
                "{label}"
            );
            assert_eq!(
                snapshot.publication,
                Knowledge::ReceiptKnown(Some(staged.epoch)),
                "{label}"
            );
            assert_eq!(snapshot.rollback, Rollback::NotRequested, "{label}");
        } else {
            assert!(
                matches!(result, AuthenticationResult::ExpiredCredentials),
                "{label}"
            );
            assert_eq!(snapshot.rollback, Rollback::Returned, "{label}");
            assert_eq!(snapshot.publication, Knowledge::BeforeCommit, "{label}");
        }
        // Hold an independent session so none of these assertions can see a
        // write which was merely performed inside the publication transaction.
        let mut observer = pool.acquire().await.unwrap();
        let stage_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM user_agent_login_epoch_stages WHERE operation_id=$1)",
        )
        .bind(staged.operation_id)
        .fetch_one(&mut *observer)
        .await
        .unwrap();
        assert_eq!(stage_exists, !expected_commit, "{label}: stage consumption");
        drop(observer);
    }
    for (label, with_binding) in [
        ("compatibility commit", false),
        ("compatibility binding refusal", true),
    ] {
        let mut tx = northstar_auth_postgres::users::lock_auth_generation(&pool, user, 0)
            .await
            .unwrap()
            .unwrap();
        let staged =
            northstar_auth_postgres::authentication::stage_login_epoch_in_transaction_observed(
                &mut tx,
                user,
                Some(device),
                0,
                connection,
                None,
            )
            .await
            .unwrap()
            .unwrap();
        tx.commit().await.unwrap();
        let receipt = CredentialCommitReceipt::new(
            None,
            Some(staged),
            with_binding.then(|| BindingPublication {
                connection_id: connection,
                user_id: user,
                full_jid: "publication-fence@example.test/missing".into(),
                lease_seconds: 120,
            }),
        );
        let result = service.publish_credential_commit(&receipt).await;
        if with_binding {
            assert!(
                matches!(result, AuthenticationResult::ExpiredCredentials),
                "{label}"
            );
        } else {
            assert!(
                matches!(result, AuthenticationResult::Authenticated(Some(epoch)) if epoch == staged.epoch),
                "{label}"
            );
        }
        let mut observer = pool.acquire().await.unwrap();
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM user_agent_login_epoch_stages WHERE operation_id=$1)",
        )
        .bind(staged.operation_id)
        .fetch_one(&mut *observer)
        .await
        .unwrap();
        assert_eq!(
            exists, with_binding,
            "{label}: compatibility preserves the same commit and rollback state"
        );
    }
    let stale = CredentialCommitReceipt::new(
        None,
        Some(StagedLoginEpoch {
            operation_id: Uuid::from_u128(0x573_6505),
            connection_id: connection,
            user_id: user,
            device_id: device,
            auth_generation: 0,
            epoch: 999,
        }),
        None,
    );
    assert!(
        matches!(
            service.publish_credential_commit(&stale).await,
            AuthenticationResult::ExpiredCredentials
        ),
        "compatibility missing staged epoch"
    );
    let observation = Observation::returned_receipt(&stale, None);
    observation.sealed(false, false).unwrap();
    observation.transport(Transport::Recording).unwrap();
    observation.transport(Transport::WriteEntered).unwrap();
    observation.transport(Transport::Written).unwrap();
    let invocation = observation.begin(&stale).unwrap();
    assert!(matches!(
        service
            .publish_credential_commit_observed(&invocation)
            .await,
        AuthenticationResult::ExpiredCredentials
    ));
    assert_eq!(
        observation.snapshot().rollback,
        Rollback::Returned,
        "missing staged epoch"
    );
    assert_eq!(
        observation.snapshot().returned,
        Some(Returned::ExpiredCredentials)
    );
    let receipt = CredentialCommitReceipt::new(None, None, None);
    let observation = Observation::returned_receipt(&receipt, None);
    observation.sealed(false, false).unwrap();
    observation.transport(Transport::Recording).unwrap();
    observation.transport(Transport::WriteEntered).unwrap();
    observation.transport(Transport::Written).unwrap();
    let invocation = observation.begin(&receipt).unwrap();
    let held = [
        pool.acquire().await.unwrap(),
        pool.acquire().await.unwrap(),
        pool.acquire().await.unwrap(),
        pool.acquire().await.unwrap(),
    ];
    assert!(matches!(
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            service.publish_credential_commit_observed(&invocation)
        )
        .await
        .expect("publication without staged effects borrowed a database connection"),
        AuthenticationResult::Authenticated(None)
    ));
    let snapshot = observation.snapshot();
    assert!(snapshot.service_started && !snapshot.repository_started && snapshot.return_matches);
    assert_eq!(snapshot.publication, Knowledge::NotRequired);
    assert_eq!(snapshot.rollback, Rollback::NotRequested);
    drop(held);
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(user)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires the ordinary-role random schema and TEST_DATABASE_URL"]
async fn credential_generation_and_stage_observations_match_durable_rows() {
    let pool = crate::support::operation_mutation_pool().await;
    let user = Uuid::from_u128(0x573_8801);
    let device = Uuid::from_u128(0x573_8802);
    let connection = Uuid::from_u128(0x573_8803);
    sqlx::query(
        "INSERT INTO users(id,username,password_hash) VALUES($1,'credential-stage','test-only')",
    )
    .bind(user)
    .execute(&pool)
    .await
    .unwrap();
    for (label, expected_generation, exists) in [
        ("matching generation", 0, true),
        ("stale generation", 1, false),
    ] {
        let compatibility =
            northstar_auth_postgres::users::lock_auth_generation(&pool, user, expected_generation)
                .await
                .unwrap();
        assert_eq!(
            compatibility.is_some(),
            exists,
            "{label}: compatibility entry uses the same generation fence"
        );
        if let Some(tx) = compatibility {
            tx.rollback().await.unwrap();
        }
        let prepared = PreparedCredential::new(
            Uuid::from_u128(0x573_8804),
            connection,
            0,
            CredentialKind::UnboundFast,
        );
        let plan = FastCommitPlan::default();
        let invocation = prepared
            .fast(user, expected_generation, &plan, Some(device), connection)
            .unwrap();
        invocation
            .enter_fast(user, expected_generation, &plan, Some(device), connection)
            .unwrap();
        let observation = prepared.observation();
        let transaction = northstar_auth_postgres::users::lock_auth_generation_observed(
            &pool,
            user,
            expected_generation,
            Some(&invocation),
        )
        .await
        .unwrap();
        assert_eq!(transaction.is_some(), exists, "{label}");
        if let Some(mut tx) = transaction {
            let staged =
                northstar_auth_postgres::authentication::stage_login_epoch_in_transaction_observed(
                    &mut tx,
                    user,
                    Some(device),
                    0,
                    connection,
                    Some(&invocation),
                )
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                observation.snapshot().stage_id,
                Some(staged.operation_id),
                "original operation identity"
            );
            let row: (Uuid, Uuid, Uuid, i64, i64) = sqlx::query_as(
                "SELECT connection_id,user_id,device_id,auth_generation,epoch FROM user_agent_login_epoch_stages WHERE operation_id=$1",
            ).bind(staged.operation_id).fetch_one(&mut *tx).await.unwrap();
            assert_eq!(row, (connection, user, device, 0, staged.epoch));
            let mut observer = pool.acquire().await.unwrap();
            let visible: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM user_agent_login_epoch_stages WHERE operation_id=$1)",
            )
            .bind(staged.operation_id)
            .fetch_one(&mut *observer)
            .await
            .unwrap();
            assert!(!visible, "uncommitted stage is not durable");
            drop(observer);
            tx.rollback().await.unwrap();
        } else {
            let snapshot = observation.snapshot();
            assert_eq!(snapshot.begin, CredentialCall::Ok, "{label}");
            assert_eq!(
                snapshot.eligibility,
                Eligibility::Returned(Some(false)),
                "{label}"
            );
            assert_eq!(
                snapshot.rollback,
                Some((
                    CredentialRollbackSite::GenerationRefused,
                    CredentialCall::Ok
                )),
                "{label}"
            );
            assert!(!snapshot.transaction_returned, "{label}");
        }
    }
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(user)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires the ordinary-role random schema and TEST_DATABASE_URL"]
async fn unbound_credential_receipts_follow_commit_and_preserve_explicit_refusal_sites() {
    let pool = crate::support::operation_mutation_pool().await;
    let user = Uuid::from_u128(0x573_90601);
    let device = Uuid::from_u128(0x573_90602);
    let connection = Uuid::from_u128(0x573_90603);
    let frame = Uuid::from_u128(0x573_90604);
    sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,'observed-fast-receipt','test-only')")
        .bind(user).execute(&pool).await.unwrap();
    let service = AuthenticationService::new(
        PostgresAuthenticationRepository::new(
            pool.clone(),
            Arc::new(Zeroizing::new(vec![43; 32])),
            WorkflowAuthenticationEffects,
        ),
        Arc::new(Zeroizing::new(vec![44; 32])),
        northstar_auth_core::MIN_SCRAM_ITERATIONS,
        false,
    );
    for (label, device, generation, missing_token) in [
        ("commit without device", None, 0, false),
        ("commit with staged device", Some(device), 0, false),
        ("generation refusal", Some(device), 1, false),
        ("FAST slot refusal", Some(device), 0, true),
    ] {
        let prepared = PreparedCredential::new(frame, connection, 0, CredentialKind::UnboundFast);
        let plan = FastCommitPlan {
            token_id: missing_token.then_some(Uuid::from_u128(0x573_90605)),
            ..FastCommitPlan::default()
        };
        let blocker = if device.is_some() && generation == 0 && !missing_token {
            let mut tx = pool.begin().await.unwrap();
            sqlx::query("LOCK TABLE user_agent_login_epoch_sequences IN ACCESS EXCLUSIVE MODE")
                .execute(&mut *tx)
                .await
                .unwrap();
            let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                .fetch_one(&mut *tx)
                .await
                .unwrap();
            Some((tx, pid))
        } else {
            None
        };
        let mut call = Box::pin(service.commit_fast_with_login_epoch_observed(
            user,
            generation,
            &plan,
            device,
            connection,
            Some(&prepared),
        ));
        let result = if let Some((blocker, pid)) = blocker {
            tokio::select! {
                _ = &mut call => panic!("staging bypassed the locked sequence authority"),
                _ = crate::support::blocked_backend(&pool, pid) => {}
            }
            assert!(
                prepared.observation().snapshot().stage_id.is_some(),
                "original stage operation ID is retained before the SQL returns"
            );
            assert_eq!(
                prepared.observation().snapshot().commit,
                CredentialCall::NotEntered
            );
            blocker.rollback().await.unwrap();
            call.await
        } else {
            call.await
        };
        let snapshot = prepared.observation().snapshot();
        assert!(
            snapshot.service_started && snapshot.repository_started,
            "{label}"
        );
        if generation == 0 && !missing_token {
            let AuthenticationResult::Authenticated(receipt) = result else {
                panic!("{label}: credential commit failed");
            };
            assert_eq!(snapshot.commit, CredentialCall::Ok, "{label}");
            assert!(
                snapshot.receipt_constructed && snapshot.return_matches,
                "{label}"
            );
            assert_eq!(
                snapshot.returned,
                Some(CredentialReturned::Authenticated),
                "{label}"
            );
            assert!(
                prepared.transfer(&receipt, frame, connection).is_ok(),
                "{label}: exact committed receipt may transfer"
            );
            assert_eq!(
                receipt.staged_login_epoch().is_some(),
                device.is_some(),
                "{label}"
            );
            if let Some(stage) = receipt.staged_login_epoch() {
                assert_eq!(snapshot.stage_id, Some(stage.operation_id));
                let mut observer = pool.acquire().await.unwrap();
                let durable: (Uuid, Uuid, Uuid, i64) = sqlx::query_as("SELECT connection_id,user_id,device_id,epoch FROM user_agent_login_epoch_stages WHERE operation_id=$1")
                    .bind(stage.operation_id).fetch_one(&mut *observer).await.unwrap();
                assert_eq!(
                    durable,
                    (connection, user, device.unwrap(), stage.epoch),
                    "{label}: receipt is backed by committed state"
                );
            } else {
                assert_eq!(snapshot.stage_id, None);
                assert_eq!(
                    snapshot.preparation[CredentialPreparation::Stage as usize],
                    PreparationResult::Absent
                );
            }
        } else {
            assert!(
                matches!(result, AuthenticationResult::ExpiredCredentials),
                "{label}"
            );
            assert_eq!(snapshot.commit, CredentialCall::NotEntered, "{label}");
            assert!(!snapshot.receipt_constructed, "{label}");
            assert_eq!(
                snapshot.rollback,
                Some((
                    if missing_token {
                        CredentialRollbackSite::FastExpired
                    } else {
                        CredentialRollbackSite::GenerationRefused
                    },
                    CredentialCall::Ok
                )),
                "{label}"
            );
            if let Some(stage_id) = snapshot.stage_id {
                let mut observer = pool.acquire().await.unwrap();
                let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM user_agent_login_epoch_stages WHERE operation_id=$1)")
                    .bind(stage_id).fetch_one(&mut *observer).await.unwrap();
                assert!(
                    !exists,
                    "{label}: refused token rolls back the staged epoch"
                );
            }
        }
    }
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(user)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
}
