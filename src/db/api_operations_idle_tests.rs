// Included inside api_operations::tests so the existing isolated CI suite
// discovers these tests and shares its production migration/enqueue helpers.
#[cfg(test)]
mod idle_regressions {
    use super::*;
    use std::time::Duration;

    async fn pending<'e, E>(executor: E) -> Result<bool>
    where
        E: sqlx::Executor<'e, Database = Postgres>,
    {
        operation_work_pending(executor, Uuid::new_v4(), 60).await
    }

    #[tokio::test]
    async fn invalid_claim_parameters_fail_before_pool_access() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://127.0.0.1:1/unused")
            .unwrap();
        for (worker, seconds, expected) in [
            (Uuid::nil(), 60, "worker id must not be nil"),
            (Uuid::new_v4(), 4, "invalid operation lease"),
            (Uuid::new_v4(), 301, "invalid operation lease"),
        ] {
            let error = operation_work_pending(&pool, worker, seconds)
                .await
                .unwrap_err();
            assert_eq!(error.to_string(), expected);
        }
        pool.close().await;
    }

    #[tokio::test]
    #[ignore = "requires a random isolated TEST_DATABASE_URL PostgreSQL schema"]
    async fn empty_probe_preserves_every_nonterminal_operation_path() {
        let pool = test_pool().await;
        assert!(!pending(&pool).await.unwrap());
        let operation = enqueue_broadcast(&pool, 1).await;
        assert!(
            pending(&pool).await.unwrap(),
            "new work must not be cached away"
        );

        for scenario in [
            "future",
            "revoked",
            "live",
            "cancel",
            "pnr",
            "exhausted",
            "target_pnr",
        ] {
            let mut tx = pool.begin().await.unwrap();
            let expected_status = match scenario {
                "future" => {
                    sqlx::query("UPDATE api_operation_journal SET next_attempt_at=clock_timestamp()+INTERVAL '5 minutes' WHERE id=$1")
                        .bind(operation.id).execute(&mut *tx).await.unwrap();
                    "pending"
                }
                "revoked" => {
                    sqlx::query("UPDATE users SET auth_generation=auth_generation+1 WHERE id=$1")
                        .bind(operation.actor_subject_id)
                        .execute(&mut *tx)
                        .await
                        .unwrap();
                    "failed"
                }
                _ => {
                    let lease = claim_operation_in_tx(&mut tx, Uuid::new_v4(), 30)
                        .await
                        .unwrap()
                        .unwrap();
                    assert_eq!(lease.operation.id, operation.id);
                    match scenario {
                        "live" => {}
                        "cancel" => {
                            assert_eq!(
                                request_operation_cancel_in_tx(
                                    &mut tx,
                                    operation.id,
                                    operation.actor_subject_id,
                                    Uuid::new_v4()
                                )
                                .await
                                .unwrap(),
                                CancelOutcome::Requested
                            );
                        }
                        "pnr" => {
                            assert!(mark_operation_point_of_no_return_in_tx(&mut tx, &lease)
                                .await
                                .unwrap());
                        }
                        "target_pnr" => {
                            enqueue_operation_target_in_tx(
                                &mut tx,
                                &EnqueueOperationTarget {
                                    operation_id: operation.id,
                                    target_key: "idle-probe-target",
                                    ordinal: 0,
                                    payload: &json!({"message":"maintenance"}),
                                    max_attempts: 1,
                                    deadline_seconds: 300,
                                },
                            )
                            .await
                            .unwrap();
                            let target = claim_operation_target_in_tx(
                                &mut tx,
                                operation.id,
                                Uuid::new_v4(),
                                30,
                            )
                            .await
                            .unwrap()
                            .unwrap();
                            assert!(mark_operation_target_point_of_no_return_in_tx(
                                &mut tx, &target
                            )
                            .await
                            .unwrap());
                            sqlx::query("UPDATE api_operation_targets SET lease_expires_at=clock_timestamp()-INTERVAL '1 millisecond' WHERE id=$1")
                                .bind(target.target.id).execute(&mut *tx).await.unwrap();
                        }
                        "exhausted" => {}
                        _ => unreachable!(),
                    }
                    if matches!(scenario, "cancel" | "pnr" | "exhausted") {
                        sqlx::query("UPDATE api_operation_journal SET lease_expires_at=clock_timestamp()-INTERVAL '1 millisecond' WHERE id=$1")
                            .bind(operation.id).execute(&mut *tx).await.unwrap();
                    }
                    match scenario {
                        "live" => "running",
                        "cancel" => "canceled",
                        "pnr" | "target_pnr" => "indeterminate",
                        _ => "failed",
                    }
                }
            };
            assert!(
                pending(&mut *tx).await.unwrap(),
                "{scenario} must reach the original claim"
            );
            let audit_before: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE operation_id=$1")
                    .bind(operation.id)
                    .fetch_one(&mut *tx)
                    .await
                    .unwrap();
            assert!(claim_operation_in_tx(&mut tx, Uuid::new_v4(), 30)
                .await
                .unwrap()
                .is_none());
            let status: String =
                sqlx::query_scalar("SELECT status FROM api_operation_journal WHERE id=$1")
                    .bind(operation.id)
                    .fetch_one(&mut *tx)
                    .await
                    .unwrap();
            assert_eq!(status, expected_status, "{scenario}");
            if !matches!(scenario, "future" | "live") {
                assert!(!pending(&mut *tx).await.unwrap());
                let audit_after: i64 =
                    sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE operation_id=$1")
                        .bind(operation.id)
                        .fetch_one(&mut *tx)
                        .await
                        .unwrap();
                assert!(
                    audit_after > audit_before,
                    "{scenario} must retain its audit transition"
                );
            }
            tx.rollback().await.unwrap();
        }

        let mut cancel = pool.begin().await.unwrap();
        assert_eq!(
            request_operation_cancel_in_tx(
                &mut cancel,
                operation.id,
                operation.actor_subject_id,
                Uuid::new_v4()
            )
            .await
            .unwrap(),
            CancelOutcome::Canceled
        );
        cancel.commit().await.unwrap();
        assert!(
            !pending(&pool).await.unwrap(),
            "terminal journal rows are idle"
        );

        let (actor, idempotency, request, token) = actor_and_reservation(&pool).await;
        let mut tx = pool.begin().await.unwrap();
        let expired = enqueue_operation_in_tx(
            &mut tx,
            &EnqueueOperation {
                request_id: request,
                idempotency_id: idempotency,
                idempotency_lease_token: token,
                actor_id: actor,
                actor_auth_generation: 0,
                authorization_policy: AuthorizationPolicy::ReauthorizeUntilEffect,
                kind: "admin.broadcast",
                target: None,
                payload_version: 1,
                payload: &json!({"message":"expired idle probe"}),
                max_attempts: 4,
                deadline_seconds: 1,
            },
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        tokio::time::sleep(Duration::from_millis(1050)).await;
        assert!(
            pending(&pool).await.unwrap(),
            "expiry work must not be filtered out"
        );
        let mut tx = pool.begin().await.unwrap();
        assert!(claim_operation_in_tx(&mut tx, Uuid::new_v4(), 30)
            .await
            .unwrap()
            .is_none());
        tx.commit().await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, String>("SELECT status FROM api_operation_journal WHERE id=$1")
                .bind(expired.id)
                .fetch_one(&pool)
                .await
                .unwrap(),
            "failed"
        );
        assert!(!pending(&pool).await.unwrap());
        enqueue_broadcast(&pool, 2).await;
        assert!(
            pending(&pool).await.unwrap(),
            "the previous empty result cannot suppress new work"
        );
        pool.close().await;
    }

    async fn grant_only_empty_claim_columns(tx: &mut Transaction<'_, Postgres>) {
        sqlx::query(
            "REVOKE ALL ON api_operation_journal,users,api_operation_targets FROM CURRENT_USER",
        )
        .execute(&mut **tx)
        .await
        .unwrap();
        let full_columns: String = sqlx::query_scalar(
            "SELECT string_agg(pg_catalog.quote_ident(attname),',' ORDER BY attnum)
             FROM pg_catalog.pg_attribute WHERE attrelid='api_operation_journal'::regclass
               AND attnum>0 AND NOT attisdropped",
        )
        .fetch_one(&mut **tx)
        .await
        .unwrap();
        sqlx::query(&format!(
            "GRANT SELECT ({full_columns}) ON api_operation_journal TO CURRENT_USER"
        ))
        .execute(&mut **tx)
        .await
        .unwrap();
        for grant in [
            "GRANT UPDATE (status,worker_id,lease_token,lease_expires_at,attempts,updated_at) ON api_operation_journal TO CURRENT_USER",
            "GRANT SELECT (id,auth_generation,is_admin,is_disabled) ON users TO CURRENT_USER",
            "GRANT SELECT (operation_id,status,lease_expires_at,point_of_no_return_at,deadline_at) ON api_operation_targets TO CURRENT_USER",
        ] {
            sqlx::query(grant).execute(&mut **tx).await.unwrap();
        }
        assert!(!sqlx::query_scalar::<_, bool>("SELECT pg_catalog.has_table_privilege(current_user,'api_operation_journal','SELECT')")
            .fetch_one(&mut **tx).await.unwrap(), "column grants must exercise the fallback");
    }

    #[tokio::test]
    #[ignore = "requires a random isolated TEST_DATABASE_URL PostgreSQL schema"]
    async fn empty_probe_preserves_acl_schema_readonly_and_pool_failures() {
        let pool = test_pool().await;
        assert!(
            !sqlx::query_scalar::<_, bool>(
                "SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname=current_user"
            )
            .fetch_one(&pool)
            .await
            .unwrap(),
            "ACL regressions require an ordinary fixture owner, never a superuser skip"
        );
        let mut tx = pool.begin().await.unwrap();
        grant_only_empty_claim_columns(&mut tx).await;
        assert!(!pending(&mut *tx).await.unwrap());
        assert!(claim_operation_in_tx(&mut tx, Uuid::new_v4(), 60)
            .await
            .unwrap()
            .is_none());
        tx.rollback().await.unwrap();

        let schema: String = sqlx::query_scalar("SELECT current_schema()")
            .fetch_one(&pool)
            .await
            .unwrap();
        for mutation in [
            "REVOKE SELECT (payload) ON api_operation_journal FROM CURRENT_USER".to_owned(),
            "REVOKE SELECT (status) ON api_operation_journal FROM CURRENT_USER".to_owned(),
            "REVOKE UPDATE (updated_at) ON api_operation_journal FROM CURRENT_USER".to_owned(),
            "REVOKE SELECT (auth_generation) ON users FROM CURRENT_USER".to_owned(),
            "REVOKE SELECT (deadline_at) ON api_operation_targets FROM CURRENT_USER".to_owned(),
            format!("REVOKE USAGE ON SCHEMA \"{schema}\" FROM CURRENT_USER"),
            "ALTER TABLE api_operation_journal RENAME TO idle_probe_missing_journal".to_owned(),
            "ALTER TABLE api_operation_targets RENAME TO idle_probe_missing_targets".to_owned(),
            "ALTER TABLE users RENAME TO idle_probe_missing_users".to_owned(),
            "ALTER TABLE api_operation_journal RENAME COLUMN actor_auth_generation TO idle_probe_missing_generation".to_owned(),
            "ALTER TABLE api_operation_targets RENAME COLUMN deadline_at TO idle_probe_missing_deadline".to_owned(),
        ] {
            for use_probe in [false, true] {
                let mut tx = pool.begin().await.unwrap();
                grant_only_empty_claim_columns(&mut tx).await;
                sqlx::query(&mutation).execute(&mut *tx).await.unwrap();
                let result = if use_probe {
                    pending(&mut *tx).await.map(|_| ())
                } else {
                    claim_operation_in_tx(&mut tx, Uuid::new_v4(), 60).await.map(|_| ())
                };
                assert!(result.is_err(), "probe={use_probe} must reject {mutation}");
                tx.rollback().await.unwrap();
                assert!(!pending(&pool).await.unwrap(), "rollback must restore authority");
            }
        }
        for use_probe in [false, true] {
            let mut tx = pool.begin().await.unwrap();
            sqlx::query("SET TRANSACTION READ ONLY")
                .execute(&mut *tx)
                .await
                .unwrap();
            let result = if use_probe {
                pending(&mut *tx).await.map(|_| ())
            } else {
                claim_operation_in_tx(&mut tx, Uuid::new_v4(), 60)
                    .await
                    .map(|_| ())
            };
            assert!(
                result.is_err(),
                "probe={use_probe} cannot hide a read-only database"
            );
            tx.rollback().await.unwrap();
        }

        let limited = test_pool_options()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(1))
            .connect_with((*pool.connect_options()).clone())
            .await
            .unwrap();
        let held = limited.acquire().await.unwrap();
        let error = pending(&limited).await.unwrap_err();
        assert!(matches!(
            error.downcast_ref::<sqlx::Error>(),
            Some(sqlx::Error::PoolTimedOut)
        ));
        drop(held);
        assert!(!pending(&limited).await.unwrap());
        limited.close().await;
        pool.close().await;
    }
}
