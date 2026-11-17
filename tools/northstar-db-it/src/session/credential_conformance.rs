use northstar_auth_application::authentication::{publication::*, FastCommitPlan};
use northstar_session_application::sm::{
    BindingFinalizationOutcome, BindingReservationOutcome, SmResumeFinalizationOutcome,
    SmResumeFinalizationRequest, SmService,
};
use northstar_workflows::{
    sm::{self, SmClaimStatus, SmSessionSnapshot},
    sm_repository::PostgresSmRepository,
};
use std::sync::Arc;
use uuid::Uuid;
use zeroize::Zeroizing;

#[tokio::test]
#[ignore = "requires the ordinary-role random schema and TEST_DATABASE_URL"]
async fn binding_credential_receipts_follow_commit_and_keep_reservation_and_fast_refusals() {
    let pool = crate::support::operation_mutation_pool().await;
    let schema: String = sqlx::query_scalar("SELECT current_schema()")
        .fetch_one(&pool)
        .await
        .unwrap();
    let service = SmService::new(
        PostgresSmRepository::new(pool.clone(), Arc::new(Zeroizing::new(vec![51; 32]))),
        schema,
    )
    .unwrap();
    for (ordinal, label, device, reserved, generation, expired_fast) in [
        (0, "binding without device", false, true, 0, false),
        (1, "binding with stage", true, true, 0, false),
        (2, "binding reservation lost", true, false, 0, false),
        (3, "binding FAST expired", true, true, 0, true),
        (4, "binding generation refused", true, true, 1, false),
    ] {
        let user = Uuid::from_u128(0x573_906100 + ordinal);
        let connection = Uuid::from_u128(0x573_906200 + ordinal);
        let device = device.then_some(Uuid::from_u128(0x573_906300 + ordinal));
        let full = format!("binding-receipt-{ordinal}@example.test/phone");
        sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test-only')")
            .bind(user)
            .bind(format!("binding-receipt-{ordinal}"))
            .execute(&pool)
            .await
            .unwrap();
        if reserved {
            assert_eq!(
                service
                    .reserve_binding(connection, user, 0, &full, 120)
                    .await
                    .unwrap(),
                BindingReservationOutcome::Reserved,
                "{label}"
            );
        }
        let frame = Uuid::from_u128(0x573_906400 + ordinal);
        let prepared = PreparedCredential::new(frame, connection, 0, CredentialKind::Binding);
        let plan = FastCommitPlan {
            token_id: Some(Uuid::from_u128(0x573_906500)),
            ..FastCommitPlan::default()
        };
        let result = service
            .finalize_binding_observed(
                connection,
                user,
                generation,
                &full,
                120,
                device,
                expired_fast.then_some(&plan),
                Some(&prepared),
            )
            .await
            .unwrap();
        let snapshot = prepared.observation().snapshot();
        assert!(
            snapshot.service_started && snapshot.repository_started && snapshot.return_matches,
            "{label}"
        );
        if reserved && generation == 0 && !expired_fast {
            let BindingFinalizationOutcome::Committed { receipt } = result else {
                panic!("{label}: finalization did not commit");
            };
            assert_eq!(snapshot.commit, CredentialCall::Ok, "{label}");
            assert!(snapshot.receipt_constructed, "{label}");
            assert_eq!(
                snapshot.returned,
                Some(CredentialReturned::BindingCommitted),
                "{label}"
            );
            let binding = receipt.binding_publication().unwrap();
            assert_eq!(
                (
                    binding.connection_id,
                    binding.user_id,
                    binding.full_jid.as_str(),
                    binding.lease_seconds
                ),
                (connection, user, full.as_str(), 120)
            );
            assert_eq!(
                receipt.staged_login_epoch().is_some(),
                device.is_some(),
                "{label}"
            );
            assert!(
                prepared.transfer(&receipt, frame, connection).is_ok(),
                "{label}: original receipt can transfer"
            );
        } else {
            if !reserved {
                assert!(
                    matches!(result, BindingFinalizationOutcome::ReservationLost),
                    "{label}"
                );
            } else {
                assert!(
                    matches!(result, BindingFinalizationOutcome::CredentialsExpired),
                    "{label}"
                );
            }
            let site = if generation != 0 {
                CredentialRollbackSite::GenerationRefused
            } else if !reserved {
                CredentialRollbackSite::BindingReservationLost
            } else {
                CredentialRollbackSite::BindingFastExpired
            };
            assert_eq!(
                snapshot.rollback,
                Some((site, CredentialCall::Ok)),
                "{label}"
            );
            assert_eq!(snapshot.commit, CredentialCall::NotEntered, "{label}");
            assert!(!snapshot.receipt_constructed, "{label}");
        }
        let mut observer = pool.acquire().await.unwrap();
        let stages: Vec<(Uuid, Uuid, Uuid, i64)> = sqlx::query_as("SELECT operation_id,connection_id,device_id,auth_generation FROM user_agent_login_epoch_stages WHERE user_id=$1")
            .bind(user).fetch_all(&mut *observer).await.unwrap();
        if let Some(device) = device.filter(|_| reserved && generation == 0 && !expired_fast) {
            assert_eq!(
                stages,
                vec![(snapshot.stage_id.unwrap(), connection, device, 0)],
                "{label}: original stage committed independently"
            );
        } else {
            assert!(stages.is_empty(), "{label}: absent or rolled-back stage");
        }
        drop(observer);
        sqlx::query("DELETE FROM users WHERE id=$1")
            .bind(user)
            .execute(&pool)
            .await
            .unwrap();
    }
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires the ordinary-role random schema and TEST_DATABASE_URL"]
async fn resume_credential_receipts_keep_activation_privacy_and_fast_rollback_sites() {
    let pool = crate::support::operation_mutation_pool().await;
    let schema: String = sqlx::query_scalar("SELECT current_schema()")
        .fetch_one(&pool)
        .await
        .unwrap();
    let service = SmService::new(
        PostgresSmRepository::new(pool.clone(), Arc::new(Zeroizing::new(vec![52; 32]))),
        schema,
    )
    .unwrap();
    for (ordinal, label, device, lost_claim, expired_fast, missing_privacy, generation) in [
        (0, "resume without device", false, false, false, false, 0),
        (1, "resume with stage", true, false, false, false, 0),
        (2, "resume claim lost", true, true, false, false, 0),
        (3, "resume FAST expired", true, false, true, false, 0),
        (4, "resume privacy missing", true, false, false, true, 0),
        (5, "resume generation refused", true, false, false, false, 1),
    ] {
        let user = Uuid::from_u128(0x573_906600 + ordinal);
        let old_connection = Uuid::from_u128(0x573_906700 + ordinal);
        let connection = Uuid::from_u128(0x573_906800 + ordinal);
        let device = device.then_some(Uuid::from_u128(0x573_906900 + ordinal));
        let full = format!("resume-receipt-{ordinal}@example.test/phone");
        let peer_ip = "192.0.2.57".parse().unwrap();
        sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test-only')")
            .bind(user)
            .bind(format!("resume-receipt-{ordinal}"))
            .execute(&pool)
            .await
            .unwrap();
        let state = SmSessionSnapshot {
            inbound_h: 3,
            outbound_h: 4,
            acked_h: 4,
            available: true,
            carbons: false,
            priority: 0,
            blocklist_requested: false,
            roster_requested: true,
            active_privacy_list: None,
            privacy_requested: false,
            peer_ip,
            user_agent_id: device,
            joined_rooms: Vec::new(),
            directed_presence: Vec::new(),
            last_presence: None,
            unacked: Vec::new(),
        };
        let token_hash = [70 + ordinal as u8; 32];
        let session = sm::create_sm_session(
            &pool,
            &token_hash,
            user,
            0,
            &full,
            "phone",
            "example.test",
            old_connection,
            &state,
            300,
            120,
            8,
            64,
        )
        .await
        .unwrap();
        assert!(
            sm::suspend_sm_session(&pool, session, old_connection, &state, 300, 64, 65_536)
                .await
                .unwrap()
        );
        let SmClaimStatus::Claimed(claim) = sm::claim_sm_session_status(
            &pool,
            &token_hash,
            user,
            peer_ip,
            device,
            sm::SmIpPolicy::Exact,
            false,
            120,
        )
        .await
        .unwrap() else {
            panic!("{label}: fixture session was not claimed");
        };
        let frame = Uuid::from_u128(0x573_907000 + ordinal);
        let prepared = PreparedCredential::new(frame, connection, 0, CredentialKind::Resume);
        let plan = FastCommitPlan {
            token_id: Some(Uuid::from_u128(0x573_907100)),
            ..FastCommitPlan::default()
        };
        let result = service
            .finalize_resume_observed(
                SmResumeFinalizationRequest {
                    session_id: session,
                    claim_token: if lost_claim {
                        Uuid::from_u128(0x573_907101)
                    } else {
                        claim.claim_token
                    },
                    connection_id: connection,
                    user_id: user,
                    expected_auth_generation: generation,
                    client_h: 4,
                    acknowledged_count: 0,
                    peer_ip,
                    user_agent_id: device,
                    active_privacy_list: missing_privacy.then_some("missing-list"),
                    ttl_seconds: 300,
                    live_lease_seconds: 120,
                    max_stanzas: 64,
                    max_bytes: 65_536,
                    fast_plan: expired_fast.then_some(&plan),
                },
                Some(&prepared),
            )
            .await
            .unwrap();
        let snapshot = prepared.observation().snapshot();
        assert!(
            snapshot.service_started && snapshot.repository_started && snapshot.return_matches,
            "{label}"
        );
        let committed = !lost_claim && !expired_fast && !missing_privacy && generation == 0;
        if committed {
            let SmResumeFinalizationOutcome::Committed(commit) = result else {
                panic!("{label}: activation did not commit");
            };
            assert_eq!(
                commit.activated.outbound_h, 4,
                "{label}: original outbound counter"
            );
            assert!(commit.activated.unacked.is_empty());
            assert_eq!(snapshot.commit, CredentialCall::Ok, "{label}");
            assert!(snapshot.receipt_constructed, "{label}");
            assert_eq!(
                snapshot.returned,
                Some(CredentialReturned::ResumeCommitted),
                "{label}"
            );
            assert!(commit.receipt.binding_publication().is_none());
            assert_eq!(
                commit.receipt.staged_login_epoch().is_some(),
                device.is_some(),
                "{label}"
            );
            assert!(
                prepared
                    .transfer(&commit.receipt, frame, connection)
                    .is_ok(),
                "{label}: exact committed receipt can transfer"
            );
        } else {
            let site = if generation != 0 {
                assert!(matches!(
                    result,
                    SmResumeFinalizationOutcome::CredentialsExpired
                ));
                CredentialRollbackSite::GenerationRefused
            } else if lost_claim {
                assert!(matches!(result, SmResumeFinalizationOutcome::ClaimLost));
                CredentialRollbackSite::ResumeClaimLost
            } else if expired_fast {
                assert!(matches!(
                    result,
                    SmResumeFinalizationOutcome::CredentialsExpired
                ));
                CredentialRollbackSite::ResumeFastExpired
            } else {
                assert!(matches!(
                    result,
                    SmResumeFinalizationOutcome::PrivacySelectionMissing
                ));
                CredentialRollbackSite::ResumePrivacyMissing
            };
            assert_eq!(
                snapshot.rollback,
                Some((site, CredentialCall::Ok)),
                "{label}"
            );
            assert_eq!(snapshot.commit, CredentialCall::NotEntered, "{label}");
            assert!(!snapshot.receipt_constructed, "{label}");
        }
        let mut observer = pool.acquire().await.unwrap();
        let durable: (Uuid, Option<Uuid>) =
            sqlx::query_as("SELECT connection_id,claim_token FROM sm_resume_sessions WHERE id=$1")
                .bind(session)
                .fetch_one(&mut *observer)
                .await
                .unwrap();
        assert_eq!(
            durable,
            if committed {
                (connection, None)
            } else {
                (old_connection, Some(claim.claim_token))
            },
            "{label}: activation commits or rolls back with its receipt"
        );
        let stages: Vec<(Uuid, Uuid)> = sqlx::query_as(
            "SELECT operation_id,connection_id FROM user_agent_login_epoch_stages WHERE user_id=$1",
        )
        .bind(user)
        .fetch_all(&mut *observer)
        .await
        .unwrap();
        if committed && device.is_some() {
            assert_eq!(
                stages,
                vec![(snapshot.stage_id.unwrap(), connection)],
                "{label}: original stage committed"
            );
        } else {
            assert!(stages.is_empty(), "{label}: no leaked stage");
        }
        drop(observer);
        sqlx::query("DELETE FROM users WHERE id=$1")
            .bind(user)
            .execute(&pool)
            .await
            .unwrap();
    }
    pool.close().await;
}
