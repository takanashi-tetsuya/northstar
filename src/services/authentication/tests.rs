use super::*;
use crate::db;
use crate::db::authentication::stage_login_epoch_in_transaction;
use sqlx::PgPool;
use std::time::Duration;
use tokio::sync::oneshot;

#[derive(Clone, Copy)]
enum CredentialCut {
    Matching,
    NoAck,
    WrongInstance,
    WrongProjection,
    ErrorAfterAck,
    PendingAfterAck,
    CommitError,
    CommitPending,
}
struct CredentialRepository {
    cut: CredentialCut,
}
impl AuthenticationRepository for CredentialRepository {
    async fn scram_credentials(
        &self,
        _username: &str,
        _algorithm: auth::ScramAlgorithm,
    ) -> AuthenticationResult<ScramCredentialSet> {
        panic!("unexpected credential read")
    }
    async fn authenticate_plain(
        &self,
        _username: &str,
        _password: &str,
        _policy: AuthenticationPolicy,
    ) -> AuthenticationResult<AuthenticatedAccount> {
        panic!("unexpected credential read")
    }
    async fn account_by_id(&self, _user_id: Uuid) -> anyhow::Result<Option<LoadedAccount>> {
        panic!("unexpected credential read")
    }
    async fn account_by_username(&self, _username: &str) -> anyhow::Result<Option<LoadedAccount>> {
        panic!("unexpected credential read")
    }
    async fn generation_state(&self, _fence: AuthenticationFence) -> AuthenticationResult<()> {
        panic!("unexpected credential read")
    }
    async fn bind2_archive_boundaries(
        &self,
        _user_id: Uuid,
        _expected_auth_generation: i64,
    ) -> AuthenticationResult<(Option<ArchiveBoundary>, Option<ArchiveBoundary>)> {
        panic!("unexpected credential read")
    }
    async fn authenticate_fast(
        &self,
        _request: FastProofRequest<'_>,
    ) -> AuthenticationResult<FastAuthenticationSuccess> {
        panic!("unexpected credential read")
    }
    async fn commit_fast_with_login_epoch(
        &self,
        _user_id: Uuid,
        _expected_auth_generation: i64,
        _plan: &FastCommitPlan,
        _device_id: Option<Uuid>,
        _connection_id: Uuid,
    ) -> AuthenticationResult<CredentialCommitReceipt> {
        AuthenticationResult::Authenticated(CredentialCommitReceipt::new(None, None, None))
    }
    async fn commit_fast_with_login_epoch_observed(
        &self,
        user_id: Uuid,
        expected_auth_generation: i64,
        plan: &FastCommitPlan,
        device_id: Option<Uuid>,
        connection_id: Uuid,
        invocation: &publication::CredentialInvocation<'_>,
    ) -> AuthenticationResult<CredentialCommitReceipt> {
        use publication::{CredentialInvocation, CredentialPreparation, PreparationResult};
        assert_eq!(
            (user_id, expected_auth_generation, device_id, connection_id),
            (Uuid::from_u128(2), 7, None, Uuid::from_u128(3))
        );
        assert_eq!(plan.issue.as_ref().unwrap().device_id, Uuid::from_u128(9));
        invocation
            .enter_fast(
                user_id,
                expected_auth_generation,
                plan,
                device_id,
                connection_id,
            )
            .unwrap();
        CredentialInvocation::begin(Some(invocation), std::future::ready(Ok::<(), ()>(())))
            .await
            .unwrap();
        CredentialInvocation::eligibility(
            Some(invocation),
            std::future::ready(Ok::<_, ()>(Some(true))),
        )
        .await
        .unwrap();
        invocation.transaction_returned();
        invocation.preparation_entered(CredentialPreparation::Stage);
        invocation.stage_returned(&Ok(None));
        invocation.preparation_entered(CredentialPreparation::Fast);
        invocation.preparation_returned(CredentialPreparation::Fast, PreparationResult::Present);
        if !matches!(self.cut, CredentialCut::NoAck) {
            let result = CredentialInvocation::commit(Some(invocation), async {
                if matches!(self.cut, CredentialCut::CommitPending) {
                    std::future::pending::<()>().await;
                }
                if matches!(self.cut, CredentialCut::CommitError) {
                    Err(std::io::Error::other("synthetic lost COMMIT reply"))
                } else {
                    Ok(())
                }
            })
            .await;
            if let Err(error) = result {
                return AuthenticationResult::BackendFailure(error.into());
            }
        }
        // This fake delay/error is synthetic: production constructs and
        // returns synchronously after the acknowledged COMMIT.
        if matches!(self.cut, CredentialCut::PendingAfterAck) {
            std::future::pending::<()>().await;
        }
        if matches!(self.cut, CredentialCut::ErrorAfterAck) {
            return AuthenticationResult::BackendFailure(anyhow::anyhow!(
                "synthetic post-ack error"
            ));
        }
        let binding =
            matches!(self.cut, CredentialCut::WrongProjection).then(|| BindingPublication {
                connection_id,
                user_id,
                full_jid: "private@example.test/wrong".to_owned(),
                lease_seconds: 77,
            });
        let receipt = CredentialCommitReceipt::new(None, None, binding);
        invocation.constructed(&receipt);
        let receipt = if matches!(self.cut, CredentialCut::WrongInstance) {
            CredentialCommitReceipt::new(None, None, None)
        } else {
            receipt
        };
        AuthenticationResult::Authenticated(receipt)
    }
    async fn publish_credential_commit(
        &self,
        _receipt: &CredentialCommitReceipt,
    ) -> AuthenticationResult<Option<i64>> {
        panic!("unexpected publication")
    }
    async fn publish_credential_commit_observed(
        &self,
        _invocation: &publication::Invocation<'_>,
    ) -> AuthenticationResult<Option<i64>> {
        panic!("unexpected publication")
    }
}
fn credential_service(cut: CredentialCut) -> AuthenticationService<CredentialRepository> {
    AuthenticationService::new(
        CredentialRepository { cut },
        Arc::new(Zeroizing::new(vec![0; 32])),
        auth::MIN_SCRAM_ITERATIONS,
        false,
    )
}
fn credential_plan() -> FastCommitPlan {
    FastCommitPlan {
        token_id: Some(Uuid::from_u128(8)),
        token_was_new: true,
        invalidate: true,
        issue: Some(FastTokenIssue {
            device_id: Uuid::from_u128(9),
            mechanism: "HT-SHA-256-NONE".to_owned(),
            ttl_days: 7,
            strong_reauth_max_days: 30,
            inherited_chain: None,
        }),
    }
}
#[tokio::test]
async fn observed_fast_service_preserves_raw_success_error_pending_and_same_attempt_authority() {
    use publication::{
        CredentialCall, CredentialKind, CredentialReturned, CredentialTerminal, PreparedCredential,
    };
    for cut in [
        CredentialCut::Matching,
        CredentialCut::NoAck,
        CredentialCut::WrongInstance,
        CredentialCut::WrongProjection,
        CredentialCut::ErrorAfterAck,
        CredentialCut::PendingAfterAck,
        CredentialCut::CommitError,
        CredentialCut::CommitPending,
    ] {
        let service = credential_service(cut);
        let prepared = PreparedCredential::new(
            Uuid::from_u128(1),
            Uuid::from_u128(3),
            0,
            CredentialKind::UnboundFast,
        );
        let plan = credential_plan();
        let mut call = Box::pin(service.commit_fast_with_login_epoch_observed(
            Uuid::from_u128(2),
            7,
            &plan,
            None,
            Uuid::from_u128(3),
            Some(&prepared),
        ));
        let result = futures::poll!(&mut call);
        if matches!(
            cut,
            CredentialCut::PendingAfterAck | CredentialCut::CommitPending
        ) {
            assert!(result.is_pending());
            drop(call);
            let snapshot = prepared.observation().snapshot();
            assert_eq!(snapshot.returned, None);
            assert_eq!(snapshot.call_terminal, Some(CredentialTerminal::Cancelled));
            assert_eq!(
                snapshot.commit,
                if matches!(cut, CredentialCut::PendingAfterAck) {
                    CredentialCall::Ok
                } else {
                    CredentialCall::Entered
                }
            );
        } else {
            let std::task::Poll::Ready(result) = result else {
                panic!("finite fake unexpectedly pending")
            };
            drop(call);
            let snapshot = prepared.observation().snapshot();
            assert_eq!(
                matches!(&result, AuthenticationResult::Authenticated(_)),
                matches!(
                    cut,
                    CredentialCut::Matching
                        | CredentialCut::NoAck
                        | CredentialCut::WrongInstance
                        | CredentialCut::WrongProjection
                )
            );
            if let AuthenticationResult::Authenticated(receipt) = result {
                assert_eq!(
                    snapshot.commit,
                    if matches!(cut, CredentialCut::NoAck) {
                        CredentialCall::NotEntered
                    } else {
                        CredentialCall::Ok
                    }
                );
                assert_eq!(snapshot.returned, Some(CredentialReturned::Authenticated));
                assert_eq!(
                    prepared
                        .transfer(&receipt, Uuid::from_u128(1), Uuid::from_u128(3))
                        .is_ok(),
                    matches!(cut, CredentialCut::Matching)
                );
            } else {
                assert!(matches!(result, AuthenticationResult::BackendFailure(_)));
                assert_eq!(snapshot.returned, Some(CredentialReturned::BackendFailure));
                assert_eq!(
                    snapshot.commit,
                    if matches!(cut, CredentialCut::CommitError) {
                        CredentialCall::Err
                    } else {
                        CredentialCall::Ok
                    }
                );
            }
            assert_eq!(snapshot.call_terminal, Some(CredentialTerminal::Returned));
        }
    }
}
#[tokio::test]
async fn explicit_fast_returned_only_compatibility_does_not_create_pre_receipt_facts() {
    let service = credential_service(CredentialCut::NoAck);
    let result = service
        .commit_fast_with_login_epoch_observed(
            Uuid::from_u128(2),
            7,
            &credential_plan(),
            None,
            Uuid::from_u128(3),
            None,
        )
        .await;
    let AuthenticationResult::Authenticated(receipt) = result else {
        panic!("compatibility result changed")
    };
    let observation = publication::Observation::returned_receipt(&receipt, None);
    assert!(observation.credential().is_none());
    assert_eq!(
        observation.snapshot().publication,
        publication::Knowledge::NotStarted
    );
}

#[tokio::test]
async fn dummy_scram_identity_is_independent_from_fast_key_rotation() {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://unused:unused@127.0.0.1/unused")
        .unwrap();
    let make_service = |fast_byte, dummy_byte| {
        AuthenticationService::new(
            crate::db::authentication::PostgresAuthenticationRepository::new(
                pool.clone(),
                Arc::new(Zeroizing::new(vec![fast_byte; 32])),
            ),
            Arc::new(Zeroizing::new(vec![dummy_byte; 32])),
            auth::MIN_SCRAM_ITERATIONS,
            false,
        )
    };
    let before = make_service(0x11, 0xa5)
        .dummy_scram_credentials("missing-account", auth::ScramAlgorithm::Sha256);
    let after_fast_rotation = make_service(0x22, 0xa5)
        .dummy_scram_credentials("missing-account", auth::ScramAlgorithm::Sha256);
    let after_dummy_rotation = make_service(0x22, 0xa6)
        .dummy_scram_credentials("missing-account", auth::ScramAlgorithm::Sha256);
    assert_eq!(before, after_fast_rotation);
    assert_ne!(before, after_dummy_rotation);
}

async fn isolated_pool() -> PgPool {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .acquire_timeout(Duration::from_secs(60))
        .connect(&url)
        .await
        .unwrap();
    let schema: String = sqlx::query_scalar("SELECT current_schema()")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(
        schema.starts_with("northstar_authentication_it_") && schema.len() <= 63,
        "authentication DB test refuses non-isolated schema {schema}"
    );
    eprintln!("isolated_schema={schema}");
    crate::db::migrate(&pool).await.unwrap();
    pool
}

async fn create_account(pool: &PgPool, username: &str, password: &str) -> (Uuid, i64) {
    let mut user = db::create_user(
        pool,
        username,
        password,
        false,
        false,
        auth::MIN_SCRAM_ITERATIONS,
        false,
    )
    .await
    .unwrap();
    let identity = (user.id, user.auth_generation);
    user.password_hash.zeroize();
    user.password_hash.clear();
    identity
}

async fn reserve_test_live_session(
    pool: &PgPool,
    connection_id: Uuid,
    user_id: Uuid,
    auth_generation: i64,
    full_jid: &str,
) {
    let mut tx = db::lock_auth_generation(pool, user_id, auth_generation)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        db::reserve_live_session_in_transaction(
            &mut tx,
            connection_id,
            user_id,
            full_jid,
            120,
            false,
        )
        .await
        .unwrap(),
        db::LiveSessionReservation::Reserved
    );
    tx.commit().await.unwrap();
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL; creates and removes a random isolated schema"]
async fn authentication_service_fences_all_credential_and_inline_state_transitions() {
    let pool = isolated_pool().await;
    let fast_secret = Arc::new(Zeroizing::new(vec![0x5a; 32]));
    let service = AuthenticationService::new(
        crate::db::authentication::PostgresAuthenticationRepository::new(
            pool.clone(),
            Arc::clone(&fast_secret),
        ),
        Arc::new(Zeroizing::new(vec![0xa5; 32])),
        auth::MIN_SCRAM_ITERATIONS,
        false,
    );

    let alice = format!("auth-alice-{}", &Uuid::new_v4().simple().to_string()[..10]);
    let (alice_id, _) = create_account(&pool, &alice, "old correct horse battery").await;
    let prepared_debug = db::prepare_login(
        &pool,
        &alice,
        "old correct horse battery",
        auth::MIN_SCRAM_ITERATIONS,
        false,
    )
    .await
    .unwrap()
    .expect("valid password must prepare a login");
    let prepared_debug_text = format!("{prepared_debug:?}");
    assert!(prepared_debug_text.contains("[REDACTED]"));
    assert!(!prepared_debug_text.contains("$argon2"));
    assert!(!prepared_debug_text.contains("old correct horse battery"));
    drop(prepared_debug);
    let plain_user = match service
        .authenticate_plain(&alice, "old correct horse battery")
        .await
    {
        AuthenticationResult::Authenticated(user) => user,
        _ => panic!("valid PLAIN credentials were rejected"),
    };
    assert_eq!(plain_user.id, alice_id);

    // Compatibility-off accounts never gain a SHA-1 verifier, and the
    // AuthenticationService cannot retrieve one even if the protocol asks.
    type OptionalSha1VerifierColumns = (
        Option<Vec<u8>>,
        Option<i32>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
    );
    let sha1_columns: OptionalSha1VerifierColumns = sqlx::query_as(
        "SELECT scram_sha1_salt,scram_sha1_iterations,
                        scram_sha1_stored_key,scram_sha1_server_key
                   FROM users WHERE id=$1",
    )
    .bind(alice_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(matches!(sha1_columns, (None, None, None, None)));
    assert!(matches!(
        service
            .scram_credentials(&alice, auth::ScramAlgorithm::Sha1)
            .await,
        AuthenticationResult::UnknownCredentials
    ));

    // A completed SCRAM proof remains tied to the UUID/generation whose
    // verifier produced it. Deleting and recreating the same username must
    // not let that proof authenticate the replacement account.
    let old_scram_fence = match service
        .scram_credentials(&alice, auth::ScramAlgorithm::Sha256)
        .await
    {
        AuthenticationResult::Authenticated(credentials) => credentials.fence(),
        _ => panic!("SCRAM-SHA-256 verifier was unavailable"),
    };
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(alice_id)
        .execute(&pool)
        .await
        .unwrap();
    let (replacement_id, _) =
        create_account(&pool, &alice, "replacement correct horse battery").await;
    assert_ne!(replacement_id, old_scram_fence.user_id);
    assert!(matches!(
        service.complete_scram(&alice, Some(old_scram_fence)).await,
        AuthenticationResult::StaleGeneration
    ));

    // Password verification happens outside a database transaction, then
    // apply_prepared_login rechecks UUID/hash/generation under lock. Force
    // a rotation in that window and prove the old password cannot commit.
    let bob = format!("auth-bob-{}", &Uuid::new_v4().simple().to_string()[..10]);
    let (bob_id, _) = create_account(&pool, &bob, "bob old correct horse battery").await;
    let (verified_tx, verified_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let plain_service = service.clone();
    let plain_username = bob.clone();
    let plain_attempt = tokio::spawn(async move {
        plain_service
            .repository
            .authenticate_plain_with_hook(
                &plain_username,
                "bob old correct horse battery",
                AuthenticationPolicy {
                    scram_iterations: auth::MIN_SCRAM_ITERATIONS,
                    scram_sha1_enabled: false,
                },
                move |fence| async move {
                    verified_tx.send(fence).unwrap();
                    release_rx.await.unwrap();
                },
            )
            .await
    });
    let prepared_fence = verified_rx.await.unwrap();
    assert_eq!(prepared_fence.user_id, bob_id);
    db::change_password(
        &pool,
        bob_id,
        "bob new correct horse battery",
        auth::MIN_SCRAM_ITERATIONS,
        false,
    )
    .await
    .unwrap();
    release_tx.send(()).unwrap();
    assert!(matches!(
        plain_attempt.await.unwrap(),
        AuthenticationResult::StaleGeneration
    ));
    let bob_session = match service
        .authenticate_plain(&bob, "bob new correct horse battery")
        .await
    {
        AuthenticationResult::Authenticated(user) => user,
        _ => panic!("rotated PLAIN credential was rejected"),
    };
    assert_eq!(bob_session.id, bob_id);

    // Disabling an account in the same post-verification window is
    // distinguished internally while remaining a generic wire failure.
    let carol = format!("auth-carol-{}", &Uuid::new_v4().simple().to_string()[..10]);
    let (carol_id, _) = create_account(&pool, &carol, "carol correct horse battery").await;
    let (verified_tx, verified_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let disabled_service = service.clone();
    let disabled_username = carol.clone();
    let disabled_attempt = tokio::spawn(async move {
        disabled_service
            .repository
            .authenticate_plain_with_hook(
                &disabled_username,
                "carol correct horse battery",
                AuthenticationPolicy {
                    scram_iterations: auth::MIN_SCRAM_ITERATIONS,
                    scram_sha1_enabled: false,
                },
                move |fence| async move {
                    verified_tx.send(fence).unwrap();
                    release_rx.await.unwrap();
                },
            )
            .await
    });
    verified_rx.await.unwrap();
    sqlx::query("UPDATE users SET is_disabled=TRUE,auth_generation=auth_generation+1 WHERE id=$1")
        .bind(carol_id)
        .execute(&pool)
        .await
        .unwrap();
    release_tx.send(()).unwrap();
    assert!(matches!(
        disabled_attempt.await.unwrap(),
        AuthenticationResult::Disabled
    ));

    // Bind 2 locks the exact generation and reads privacy-filtered MAM
    // boundaries inside that same RR transaction. A concurrent generation
    // update cannot commit in the former check/read gap.
    let bob_generation: i64 = sqlx::query_scalar("SELECT auth_generation FROM users WHERE id=$1")
        .bind(bob_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    let (locked_tx, locked_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let boundary_service = service.clone();
    let boundary_attempt = tokio::spawn(async move {
        boundary_service
            .repository
            .bind2_archive_boundaries_with_hook(bob_id, bob_generation, move |fence| async move {
                locked_tx.send(fence).unwrap();
                release_rx.await.unwrap();
            })
            .await
    });
    locked_rx.await.unwrap();
    let update_pool = pool.clone();
    let mut generation_update = tokio::spawn(async move {
        sqlx::query("UPDATE users SET auth_generation=auth_generation+1 WHERE id=$1")
            .bind(bob_id)
            .execute(&update_pool)
            .await
            .unwrap();
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut generation_update)
            .await
            .is_err()
    );
    release_tx.send(()).unwrap();
    assert!(matches!(
        boundary_attempt.await.unwrap(),
        AuthenticationResult::Authenticated((None, None))
    ));
    generation_update.await.unwrap();

    // FAST account status and one-time proof consumption use one user-row
    // lock and transaction. A later generation update is serialized after
    // proof commit and is caught by the downstream generation fence.
    let dave = format!("auth-dave-{}", &Uuid::new_v4().simple().to_string()[..10]);
    let (dave_id, dave_generation) =
        create_account(&pool, &dave, "dave correct horse battery").await;
    let device_id = Uuid::new_v4();
    let issued = db::issue_fast_token(
        &pool,
        fast_secret.as_slice(),
        dave_id,
        device_id,
        "HT-SHA-256-NONE",
        dave_generation,
        30,
        90,
        None,
    )
    .await
    .unwrap();
    let token = Zeroizing::new(issued.token);
    let proof = Zeroizing::new(auth::fast_proof(&token, false, &[]));
    let (locked_tx, locked_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let fast_service = service.clone();
    let fast_username = dave.clone();
    let fast_attempt = tokio::spawn(async move {
        fast_service
            .repository
            .authenticate_fast_with_hook(
                FastProofRequest {
                    username: &fast_username,
                    device_id,
                    mechanism: "HT-SHA-256-NONE",
                    counter: None,
                    initiator_proof: &proof,
                    channel_binding: &[],
                    invalidate: false,
                    rotate_within_days: 7,
                },
                move |fence| async move {
                    locked_tx.send(fence).unwrap();
                    release_rx.await.unwrap();
                },
            )
            .await
    });
    locked_rx.await.unwrap();
    let update_pool = pool.clone();
    let mut generation_update = tokio::spawn(async move {
        sqlx::query("UPDATE users SET auth_generation=auth_generation+1 WHERE id=$1")
            .bind(dave_id)
            .execute(&update_pool)
            .await
            .unwrap();
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut generation_update)
            .await
            .is_err()
    );
    release_tx.send(()).unwrap();
    let fast_success = match fast_attempt.await.unwrap() {
        AuthenticationResult::Authenticated(success) => success,
        _ => panic!("valid FAST proof was rejected"),
    };
    let (fast_user, responder, _, _, _, authenticated_generation, _, _) = fast_success.into_parts();
    assert_eq!(fast_user.id, dave_id);
    assert_eq!(authenticated_generation, dave_generation);
    assert_eq!(responder.len(), 32);
    generation_update.await.unwrap();
    assert!(matches!(
        service
            .revalidate_generation(dave_id, authenticated_generation)
            .await,
        AuthenticationResult::StaleGeneration
    ));

    // A backend outage is never collapsed into UnknownCredentials.
    pool.close().await;
    assert!(matches!(
        service.authenticate_external(&dave).await,
        AuthenticationResult::BackendFailure(_)
    ));
}

#[test]
fn fast_service_dto_conversions_keep_secrets_move_only() {
    let now = chrono::Utc::now();
    let later = now + chrono::Duration::days(30);
    let device_id = Uuid::new_v4();
    let token_id = Uuid::new_v4();

    let db_issued = db::IssuedFastToken {
        token: Zeroizing::new("secret-fast-token-value".to_string()),
        expires_at: later,
    };
    let round_trip_issued = IssuedFastToken::from(db_issued);
    assert_eq!(round_trip_issued.token.as_str(), "secret-fast-token-value");
    assert_eq!(round_trip_issued.expires_at, later);

    let service_issue = FastTokenIssue {
        device_id,
        mechanism: "HT-SHA-256-NONE".to_string(),
        ttl_days: 30,
        strong_reauth_max_days: 90,
        inherited_chain: Some((now, later)),
    };
    let db_issue = db::FastTokenIssue::from(&service_issue);
    assert_eq!(db_issue.device_id, device_id);
    assert_eq!(db_issue.mechanism, "HT-SHA-256-NONE");
    assert_eq!(db_issue.ttl_days, 30);
    assert_eq!(db_issue.strong_reauth_max_days, 90);
    assert_eq!(db_issue.inherited_chain, Some((now, later)));

    let round_trip_issue = FastTokenIssue::from(db_issue);
    assert_eq!(round_trip_issue, service_issue);

    let service_plan = FastCommitPlan {
        token_id: Some(token_id),
        token_was_new: true,
        invalidate: true,
        issue: Some(service_issue),
    };
    let db_plan = db::FastCommitPlan::from(&service_plan);
    assert_eq!(db_plan.token_id, Some(token_id));
    assert!(db_plan.token_was_new);
    assert!(db_plan.invalidate);
    assert!(db_plan.issue.is_some());

    let round_trip_plan = FastCommitPlan::from(db_plan);
    assert_eq!(round_trip_plan, service_plan);
}

#[test]
fn issued_fast_token_redacts_secret_in_debug_format() {
    let issued = IssuedFastToken {
        token: Zeroizing::new("super-sensitive-token-data-12345".to_string()),
        expires_at: chrono::Utc::now(),
    };
    let debug_str = format!("{issued:?}");
    assert!(debug_str.contains("[REDACTED]"));
    assert!(!debug_str.contains("super-sensitive-token-data-12345"));
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL; creates and removes a random isolated schema"]
async fn bind2_recovers_failed_pooled_transaction_before_preflight() {
    let setup_pool = isolated_pool().await;
    let username = format!("auth-dirty-{}", &Uuid::new_v4().simple().to_string()[..10]);
    let (user_id, generation) =
        create_account(&setup_pool, &username, "dirty connection test password").await;
    let url = std::env::var("TEST_DATABASE_URL").unwrap();
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();

    // Raw BEGIN leaves PostgreSQL in a transaction without advancing
    // SQLx's transaction depth. A late isolation change aborts that
    // backend transaction; the pool's Sync ping does not reset it.
    sqlx::query("BEGIN").execute(&pool).await.unwrap();
    sqlx::query("SELECT pg_backend_pid()")
        .execute(&pool)
        .await
        .unwrap();
    let error = sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .execute(&pool)
        .await
        .unwrap_err();
    assert_eq!(
        error
            .as_database_error()
            .and_then(|database_error| database_error.code())
            .as_deref(),
        Some("25001")
    );

    let repository = crate::db::authentication::PostgresAuthenticationRepository::new(
        pool.clone(),
        Arc::new(Zeroizing::new(vec![0x5a; 32])),
    );
    assert!(matches!(
        repository
            .bind2_archive_boundaries_with_hook(user_id, generation, |_| async {})
            .await,
        AuthenticationResult::Authenticated((None, None))
    ));
    let available_backend_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(available_backend_pid > 0);
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL; creates and removes a random isolated schema"]
async fn bind2_resets_active_pooled_transaction_before_preflight() {
    let setup_pool = isolated_pool().await;
    let username = format!("auth-active-{}", &Uuid::new_v4().simple().to_string()[..10]);
    let (user_id, generation) =
        create_account(&setup_pool, &username, "active connection test password").await;
    let url = std::env::var("TEST_DATABASE_URL").unwrap();
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();

    // SQLx does not track this raw BEGIN. A second BEGIN merely warns and
    // would retain the active READ COMMITTED transaction and snapshot.
    sqlx::query("BEGIN ISOLATION LEVEL READ COMMITTED")
        .execute(&pool)
        .await
        .unwrap();
    let isolation: String = sqlx::query_scalar("SELECT current_setting('transaction_isolation')")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(isolation, "read committed");

    let repository = crate::db::authentication::PostgresAuthenticationRepository::new(
        pool.clone(),
        Arc::new(Zeroizing::new(vec![0x5a; 32])),
    );
    assert!(matches!(
        repository
            .bind2_archive_boundaries_with_hook(user_id, generation, |_| async {})
            .await,
        AuthenticationResult::Authenticated((None, None))
    ));
    let available_backend_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(available_backend_pid > 0);
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL; creates and removes a random isolated schema"]
async fn login_epoch_publication_is_fenced_invisible_and_atomic_with_binding() {
    let pool = isolated_pool().await;
    db::reconcile_deployment_capacity(
        &pool,
        db::DeploymentCapacityConfiguration {
            epoch: 1,
            accounts: 8,
            muc_rooms: 8,
            muc_rooms_per_owner: 4,
            live_sessions: 8,
            sessions_per_account: 8,
            resumable_sessions: 8,
        },
    )
    .await
    .unwrap();
    let username = format!("epoch-{}", &Uuid::new_v4().simple().to_string()[..10]);
    let (user_id, auth_generation) =
        create_account(&pool, &username, "epoch correct horse battery").await;
    let service = AuthenticationService::new(
        crate::db::authentication::PostgresAuthenticationRepository::new(
            pool.clone(),
            Arc::new(Zeroizing::new(vec![0x61; 32])),
        ),
        Arc::new(Zeroizing::new(vec![0xa6; 32])),
        auth::MIN_SCRAM_ITERATIONS,
        false,
    );
    let device_id = Uuid::new_v4();
    let connection_id = Uuid::new_v4();
    let full_jid = format!("{username}@example.test/device");

    let mut tx = db::lock_auth_generation(&pool, user_id, auth_generation)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        db::reserve_live_session_in_transaction(
            &mut tx,
            connection_id,
            user_id,
            &full_jid,
            120,
            false,
        )
        .await
        .unwrap(),
        db::LiveSessionReservation::Reserved
    );
    let staged = stage_login_epoch_in_transaction(
        &mut tx,
        user_id,
        Some(device_id),
        auth_generation,
        connection_id,
    )
    .await
    .unwrap()
    .unwrap();
    tx.commit().await.unwrap();

    // Phase two is durable, but maintenance must still observe no new
    // device epoch before the transport-success continuation runs.
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM user_agent_login_epochs
                  WHERE user_id=$1 AND device_id=$2",
        )
        .bind(user_id)
        .bind(device_id)
        .fetch_one(&pool)
        .await
        .unwrap(),
        0
    );
    let wrong_fence = CredentialCommitReceipt::new(
        None,
        Some(StagedLoginEpoch {
            connection_id: Uuid::new_v4(),
            ..staged
        }),
        None,
    );
    assert!(matches!(
        service.publish_credential_commit(&wrong_fence).await,
        AuthenticationResult::ExpiredCredentials
    ));
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM user_agent_login_epoch_stages
                  WHERE operation_id=$1",
        )
        .bind(staged.operation_id)
        .fetch_one(&pool)
        .await
        .unwrap(),
        1,
        "a mismatched publication fence must not consume the stage"
    );

    let receipt = CredentialCommitReceipt::new(
        None,
        Some(staged),
        Some(BindingPublication {
            connection_id,
            user_id,
            full_jid: full_jid.clone(),
            lease_seconds: 120,
        }),
    );
    assert!(matches!(
        service.publish_credential_commit(&receipt).await,
        AuthenticationResult::Authenticated(Some(1))
    ));
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT epoch FROM user_agent_login_epochs
                  WHERE user_id=$1 AND device_id=$2",
        )
        .bind(user_id)
        .bind(device_id)
        .fetch_one(&pool)
        .await
        .unwrap(),
        1
    );
    assert!(db::release_live_session(&pool, connection_id)
        .await
        .unwrap());

    // Make the stage provisionally eligible with a durable replacement
    // claim whose old SM stream does not exist. Epoch SQL executes first,
    // then binding publication rejects it; the enclosing transaction must
    // leave the published epoch unchanged and retain the stage for TTL
    // cleanup rather than exposing a partial device replacement.
    let failed_connection = Uuid::new_v4();
    let failed_full_jid = format!("{username}@example.test/failure");
    let failed_stage = {
        let mut tx = db::lock_auth_generation(&pool, user_id, auth_generation)
            .await
            .unwrap()
            .unwrap();
        let stage = stage_login_epoch_in_transaction(
            &mut tx,
            user_id,
            Some(device_id),
            auth_generation,
            failed_connection,
        )
        .await
        .unwrap()
        .unwrap();
        sqlx::query(
            "INSERT INTO deployment_session_binding_claims
                 (connection_id,user_id,full_jid,replaced_connection_id,expires_at)
                 VALUES($1,$2,$3,$4,clock_timestamp()+INTERVAL '2 minutes')",
        )
        .bind(failed_connection)
        .bind(user_id)
        .bind(&failed_full_jid)
        .bind(Uuid::new_v4())
        .execute(&mut *tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();
        stage
    };
    let failed_receipt = CredentialCommitReceipt::new(
        None,
        Some(failed_stage),
        Some(BindingPublication {
            connection_id: failed_connection,
            user_id,
            full_jid: failed_full_jid,
            lease_seconds: 120,
        }),
    );
    assert!(matches!(
        service.publish_credential_commit(&failed_receipt).await,
        AuthenticationResult::ExpiredCredentials
    ));
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT epoch FROM user_agent_login_epochs
                  WHERE user_id=$1 AND device_id=$2",
        )
        .bind(user_id)
        .bind(device_id)
        .fetch_one(&pool)
        .await
        .unwrap(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM user_agent_login_epoch_stages
                  WHERE operation_id=$1",
        )
        .bind(failed_stage.operation_id)
        .fetch_one(&pool)
        .await
        .unwrap(),
        1
    );
    sqlx::query(
        "UPDATE user_agent_login_epoch_stages
                SET expires_at=clock_timestamp()-INTERVAL '1 second'
              WHERE operation_id=$1",
    )
    .bind(failed_stage.operation_id)
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(
        db::cleanup_expired_user_agent_login_epoch_stages(&pool, 10)
            .await
            .unwrap(),
        1
    );
    assert!(db::release_live_session(&pool, failed_connection)
        .await
        .unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; creates and removes a random isolated schema"]
async fn publication_lease_lock_blocks_reserve_release_and_fences_expiry_cleanup() {
    let pool = isolated_pool().await;
    db::reconcile_deployment_capacity(
        &pool,
        db::DeploymentCapacityConfiguration {
            epoch: 1,
            accounts: 8,
            muc_rooms: 8,
            muc_rooms_per_owner: 4,
            live_sessions: 8,
            sessions_per_account: 8,
            resumable_sessions: 8,
        },
    )
    .await
    .unwrap();
    let username = format!("lease-lock-{}", &Uuid::new_v4().simple().to_string()[..10]);
    let (user_id, auth_generation) =
        create_account(&pool, &username, "lease lock correct horse").await;
    let full_jid = format!("{username}@example.test/device");
    let first_connection = Uuid::new_v4();
    reserve_test_live_session(&pool, first_connection, user_id, auth_generation, &full_jid).await;

    // The publication-side exact lookup owns both the per-JID advisory
    // barrier and the lease row lock. A concurrent reservation for the
    // same full JID cannot pass the barrier or invert lease/claim order.
    let mut publication = db::lock_auth_generation(&pool, user_id, auth_generation)
        .await
        .unwrap()
        .unwrap();
    assert!(db::publish_binding_live_session_in_transaction(
        &mut publication,
        first_connection,
        user_id,
        &full_jid,
        120,
    )
    .await
    .unwrap());
    let reserve_pool = pool.clone();
    let reserve_jid = full_jid.clone();
    let competing_connection = Uuid::new_v4();
    let (reserve_started_tx, reserve_started_rx) = tokio::sync::oneshot::channel();
    let reserve_task = tokio::spawn(async move {
        let mut tx = reserve_pool.begin().await.unwrap();
        let _ = reserve_started_tx.send(());
        let outcome = db::reserve_live_session_in_transaction(
            &mut tx,
            competing_connection,
            user_id,
            &reserve_jid,
            120,
            false,
        )
        .await;
        tx.rollback().await.unwrap();
        outcome
    });
    reserve_started_rx.await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !reserve_task.is_finished(),
        "same-JID reservation bypassed publication advisory/lease locks"
    );
    publication.commit().await.unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), reserve_task)
            .await
            .expect("same-JID reservation remained deadlocked after publication commit")
            .unwrap()
            .unwrap(),
        db::LiveSessionReservation::Conflict
    );

    // An exact release must likewise wait for the row lock. This is the
    // former EXISTS/delete TOCTOU between authentication publication SQL
    // and commit.
    let mut publication = db::lock_auth_generation(&pool, user_id, auth_generation)
        .await
        .unwrap()
        .unwrap();
    assert!(db::publish_binding_live_session_in_transaction(
        &mut publication,
        first_connection,
        user_id,
        &full_jid,
        120,
    )
    .await
    .unwrap());
    let release_pool = pool.clone();
    let (release_started_tx, release_started_rx) = tokio::sync::oneshot::channel();
    let release_task = tokio::spawn(async move {
        let _ = release_started_tx.send(());
        db::release_live_session(&release_pool, first_connection).await
    });
    release_started_rx.await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !release_task.is_finished(),
        "release deleted a lease locked by authentication publication"
    );
    publication.commit().await.unwrap();
    assert!(tokio::time::timeout(Duration::from_secs(2), release_task)
        .await
        .expect("lease release remained blocked after publication commit")
        .unwrap()
        .unwrap());

    // Expired rows are locked too. Although they cannot authorize an
    // epoch, cleanup cannot delete one between exact revalidation and the
    // caller's rollback/commit decision.
    let expired_connection = Uuid::new_v4();
    reserve_test_live_session(
        &pool,
        expired_connection,
        user_id,
        auth_generation,
        &full_jid,
    )
    .await;
    sqlx::query(
        "UPDATE deployment_session_leases
                SET lease_until=clock_timestamp()-INTERVAL '1 second'
              WHERE connection_id=$1",
    )
    .bind(expired_connection)
    .execute(&pool)
    .await
    .unwrap();
    let mut publication = db::lock_auth_generation(&pool, user_id, auth_generation)
        .await
        .unwrap()
        .unwrap();
    assert!(!db::publish_binding_live_session_in_transaction(
        &mut publication,
        expired_connection,
        user_id,
        &full_jid,
        120,
    )
    .await
    .unwrap());
    let cleanup_pool = pool.clone();
    let (cleanup_started_tx, cleanup_started_rx) = tokio::sync::oneshot::channel();
    let cleanup_task = tokio::spawn(async move {
        let _ = cleanup_started_tx.send(());
        db::try_cleanup_expired_live_session_leases(&cleanup_pool, 10).await
    });
    cleanup_started_rx.await.unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), cleanup_task)
            .await
            .expect("expiry cleanup blocked instead of skipping a publication-locked lease")
            .unwrap()
            .unwrap()
            .expect("an isolated fixture must acquire the reaper role"),
        0,
        "expiry cleanup reported deleting a publication-locked lease"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM deployment_session_leases WHERE connection_id=$1",
        )
        .bind(expired_connection)
        .fetch_one(&pool)
        .await
        .unwrap(),
        1,
        "expiry cleanup removed a lease protected by publication"
    );
    publication.rollback().await.unwrap();
    assert!(
        db::try_cleanup_expired_live_session_leases(&pool, 10)
            .await
            .unwrap()
            .expect("an isolated fixture must acquire the reaper role")
            >= 1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM deployment_session_leases WHERE connection_id=$1",
        )
        .bind(expired_connection)
        .fetch_one(&pool)
        .await
        .unwrap(),
        0
    );
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
}

#[test]
fn configuration_scram_iteration_bounds_match_the_authentication_core() {
    // The configuration crate cannot depend on the auth context, so it keeps its own copies.
    assert_eq!(
        northstar_config::MIN_SCRAM_ITERATIONS,
        auth::MIN_SCRAM_ITERATIONS
    );
    assert_eq!(
        northstar_config::DEFAULT_SCRAM_ITERATIONS,
        auth::DEFAULT_SCRAM_ITERATIONS
    );
    assert_eq!(
        northstar_config::MAX_SCRAM_ITERATIONS,
        auth::MAX_SCRAM_ITERATIONS
    );
}
