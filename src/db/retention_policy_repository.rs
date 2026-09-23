//! Complete authorization, retention policy and response replay transactions.
use crate::{
    db,
    services::{api_mutations::*, retention_policy::*},
};
use sqlx::{PgPool, Postgres, Transaction};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone)]
pub(crate) struct PostgresRetentionPolicyRepository {
    pool: PgPool,
    keyring: Arc<db::ApiControlKeyring>,
}

enum RetentionMutationStart<'a> {
    Ready(Transaction<'a, Postgres>, Uuid, db::IdempotencyLease),
    Finished(ApiMutationOutcome<StoredApiResponse>),
}

fn backend(error: impl Into<anyhow::Error>) -> RetentionPolicyError {
    RetentionPolicyError::Internal(error.into())
}

impl PostgresRetentionPolicyRepository {
    pub(crate) fn new(pool: PgPool, keyring: Arc<db::ApiControlKeyring>) -> Self {
        Self { pool, keyring }
    }

    async fn authorized(
        &self,
        token: &str,
    ) -> Result<(Transaction<'_, Postgres>, Uuid), RetentionPolicyError> {
        let mut tx = self.pool.begin().await.map_err(backend)?;
        // Resolve and hold users -> exact bearer locks through the policy operation.
        let user = db::user_for_token_in_tx(&mut tx, token)
            .await
            .map_err(backend)?
            .ok_or(RetentionPolicyError::Unauthorized)?;
        Ok((tx, user.id))
    }

    async fn start(
        &self,
        admission: &RetentionMutationAdmission<'_>,
    ) -> Result<RetentionMutationStart<'_>, RetentionPolicyError> {
        let (mut tx, user_id) = self.authorized(admission.session_token).await?;
        let rejection =
            match db::acquire_idempotency_in_tx(&self.keyring, &mut tx, &admission.idempotency)
                .await
                .map_err(backend)?
            {
                db::IdempotencyAcquire::Acquired(lease) => {
                    return Ok(RetentionMutationStart::Ready(tx, user_id, lease))
                }
                db::IdempotencyAcquire::Replay(response) => {
                    tx.commit().await.map_err(backend)?;
                    return Ok(RetentionMutationStart::Finished(
                        ApiMutationOutcome::Replay(response),
                    ));
                }
                db::IdempotencyAcquire::FingerprintConflict
                | db::IdempotencyAcquire::RotationConflict => {
                    ApiMutationRejection::IdempotencyConflict
                }
                db::IdempotencyAcquire::ReplayInvalidated => {
                    ApiMutationRejection::ReplayInvalidated
                }
                db::IdempotencyAcquire::Busy {
                    retry_after_seconds,
                } => ApiMutationRejection::Busy {
                    retry_after: retry_after_seconds,
                },
                db::IdempotencyAcquire::CapacityLimited {
                    retry_after_seconds,
                } => ApiMutationRejection::CapacityLimited {
                    retry_after: retry_after_seconds,
                },
                db::IdempotencyAcquire::InProgress {
                    retry_after_seconds,
                } => ApiMutationRejection::InProgress {
                    retry_after: retry_after_seconds,
                },
            };
        tx.rollback().await.map_err(backend)?;
        Ok(RetentionMutationStart::Finished(
            ApiMutationOutcome::Rejected(rejection),
        ))
    }

    async fn finish(
        &self,
        mut tx: Transaction<'_, Postgres>,
        lease: &db::IdempotencyLease,
        response: StoredApiResponse,
    ) -> Result<ApiMutationOutcome<StoredApiResponse>, RetentionPolicyError> {
        if !db::api_mutations::persist_response_in_tx(&self.keyring, &mut tx, lease, &response)
            .await
            .map_err(backend)?
        {
            return Err(backend(anyhow::anyhow!(
                "data-policy idempotency lease changed"
            )));
        }
        tx.commit().await.map_err(backend)?;
        Ok(ApiMutationOutcome::Committed(response))
    }
}

impl RetentionPolicyRepository for PostgresRetentionPolicyRepository {
    async fn user_policy(
        &self,
        session_token: &str,
    ) -> Result<UserRetentionPolicy, RetentionPolicyError> {
        let (mut tx, user_id) = self.authorized(session_token).await?;
        let policy = db::user_retention_policy_in_tx(&mut tx, user_id)
            .await
            .map_err(backend)?;
        tx.commit().await.map_err(backend)?;
        Ok(policy)
    }

    async fn muc_policy(
        &self,
        session_token: &str,
        room_id: Uuid,
    ) -> Result<Option<i32>, RetentionPolicyError> {
        let (mut tx, user_id) = self.authorized(session_token).await?;
        let policy = db::muc_retention_policy_authorized_in_tx(&mut tx, user_id, room_id).await?;
        tx.commit().await.map_err(backend)?;
        Ok(policy)
    }

    async fn set_user_policy(
        &self,
        admission: RetentionMutationAdmission<'_>,
        requested: UserRetentionPolicy,
        limits: RetentionPolicyLimits,
    ) -> Result<ApiMutationOutcome<StoredApiResponse>, RetentionPolicyError> {
        let (mut tx, user_id, lease) = match self.start(&admission).await? {
            RetentionMutationStart::Ready(tx, user_id, lease) => (tx, user_id, lease),
            RetentionMutationStart::Finished(outcome) => return Ok(outcome),
        };
        db::set_user_retention_policy_in_tx(
            &mut tx,
            user_id,
            user_id,
            requested,
            limits,
            lease.request_id,
        )
        .await?;
        let response = StoredApiResponse::json(200, serde_json::json!({"policy":requested}))
            .map_err(backend)?;
        self.finish(tx, &lease, response).await
    }

    async fn set_muc_policy(
        &self,
        admission: RetentionMutationAdmission<'_>,
        room_id: Uuid,
        requested_days: Option<i32>,
        global_days: i64,
    ) -> Result<ApiMutationOutcome<StoredApiResponse>, RetentionPolicyError> {
        let (mut tx, user_id, lease) = match self.start(&admission).await? {
            RetentionMutationStart::Ready(tx, user_id, lease) => (tx, user_id, lease),
            RetentionMutationStart::Finished(outcome) => return Ok(outcome),
        };
        db::set_muc_retention_policy_in_tx(
            &mut tx,
            user_id,
            room_id,
            requested_days,
            global_days,
            lease.request_id,
        )
        .await?;
        let response = StoredApiResponse::json(
            200,
            serde_json::json!({"room_id":room_id,"retention_days":requested_days}),
        )
        .map_err(backend)?;
        self.finish(tx, &lease, response).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn admission<'a>(
        token: &'a str,
        key: &'a str,
        target: &'a [u8],
        muc: bool,
        body: &[u8],
    ) -> RetentionMutationAdmission<'a> {
        RetentionMutationAdmission {
            session_token: token,
            idempotency: IdempotencyRequest {
                request_id: Uuid::new_v4(),
                actor_id: None,
                principal_scope: token.as_bytes(),
                capacity_scope: token.as_bytes(),
                target_scope: target,
                principal_kind: ApiPrincipalKind::User,
                method: "PUT",
                route: if muc {
                    "/api/v1/muc_rooms/{id}/retention"
                } else {
                    "/api/v1/me/retention"
                },
                idempotency_key: key,
                request_fingerprint: api_request_fingerprint("application/json", body),
                ttl_seconds: 3600,
                lease_seconds: 60,
            },
        }
    }

    fn committed(outcome: ApiMutationOutcome<StoredApiResponse>) -> StoredApiResponse {
        match outcome {
            ApiMutationOutcome::Committed(response) => response,
            _ => panic!("a new policy request must commit"),
        }
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL schema"]
    async fn policy_ports_preserve_ceilings_room_ownership_and_response_replay() {
        let pool = crate::db::test_support::operation_mutation_pool().await;
        let owner = Uuid::new_v4();
        let outsider = Uuid::new_v4();
        let admin = Uuid::new_v4();
        for (id, is_admin) in [(owner, false), (outsider, false), (admin, true)] {
            sqlx::query("INSERT INTO users(id,username,password_hash,is_admin) VALUES($1,$2,'test-only',$3)")
                .bind(id).bind(format!("retention_{}", id.simple())).bind(is_admin).execute(&pool).await.unwrap();
        }
        let token = db::create_api_session(&pool, owner, 1).await.unwrap();
        let outsider_token = db::create_api_session(&pool, outsider, 1).await.unwrap();
        let admin_token = db::create_api_session(&pool, admin, 1).await.unwrap();
        let room = Uuid::new_v4();
        let second_room = Uuid::new_v4();
        for id in [room, second_room] {
            sqlx::query(
                "INSERT INTO muc_rooms(id,localpart,owner_id,persistent) VALUES($1,$2,$3,TRUE)",
            )
            .bind(id)
            .bind(format!("retention_{}", id.simple()))
            .bind(owner)
            .execute(&pool)
            .await
            .unwrap();
        }
        let secret = Uuid::new_v4().simple().to_string();
        let keyring = Arc::new(db::ApiControlKeyring::new(secret.as_bytes(), None).unwrap());
        let service = RetentionPolicyService::new(
            PostgresRetentionPolicyRepository::new(pool.clone(), keyring),
            RetentionPolicyLimits {
                personal_mam_days: 365,
                offline_message_days: 30,
                moderation_evidence_days: 365,
            },
            30,
        );
        let policy = UserRetentionPolicy {
            personal_mam_days: Some(7),
            offline_message_days: Some(3),
            moderation_evidence_days: Some(30),
        };
        let body = serde_json::to_vec(&policy).unwrap();
        let first = committed(
            service
                .set_user_policy(
                    admission(&token, "retention-user-policy", b"", false, &body),
                    policy,
                )
                .await
                .unwrap(),
        );
        assert_eq!(first.status, 200);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&first.body).unwrap(),
            serde_json::json!({"policy":policy})
        );
        let replay = service
            .set_user_policy(
                admission(&token, "retention-user-policy", b"", false, &body),
                policy,
            )
            .await
            .unwrap();
        match replay {
            ApiMutationOutcome::Replay(response) => {
                assert_eq!(response.status, first.status);
                assert_eq!(response.headers, first.headers);
                assert_eq!(response.body, first.body);
            }
            _ => panic!("an exact policy retry must replay"),
        }
        assert_eq!(service.user_policy(&token).await.unwrap(), policy);
        assert!(matches!(
            service
                .set_user_policy(
                    admission(&token, "retention-user-extend", b"", false, b"extend"),
                    UserRetentionPolicy {
                        personal_mam_days: Some(14),
                        ..policy
                    },
                )
                .await,
            Err(RetentionPolicyError::Forbidden)
        ));
        let audits: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE actor_id=$1 AND action='data.retention.user.update'")
            .bind(owner).fetch_one(&pool).await.unwrap();
        assert_eq!(
            audits, 1,
            "replay and rejection must not append policy audits"
        );

        assert!(matches!(
            service.muc_policy(&outsider_token, room).await,
            Err(RetentionPolicyError::Forbidden)
        ));
        assert!(matches!(
            service
                .set_muc_policy(
                    admission(
                        &outsider_token,
                        "retention-muc-denied",
                        room.as_bytes(),
                        true,
                        b"7"
                    ),
                    room,
                    Some(7)
                )
                .await,
            Err(RetentionPolicyError::Forbidden)
        ));
        assert!(matches!(
            service.muc_policy(&token, Uuid::new_v4()).await,
            Err(RetentionPolicyError::NotFound)
        ));
        let room_response = committed(
            service
                .set_muc_policy(
                    admission(&token, "retention-muc-policy", room.as_bytes(), true, b"7"),
                    room,
                    Some(7),
                )
                .await
                .unwrap(),
        );
        match service
            .set_muc_policy(
                admission(&token, "retention-muc-policy", room.as_bytes(), true, b"7"),
                room,
                Some(7),
            )
            .await
            .unwrap()
        {
            ApiMutationOutcome::Replay(response) => assert_eq!(response.body, room_response.body),
            _ => panic!("an exact room policy retry must replay"),
        }
        assert!(matches!(
            service
                .set_muc_policy(
                    admission(
                        &token,
                        "retention-muc-policy",
                        second_room.as_bytes(),
                        true,
                        b"7"
                    ),
                    second_room,
                    Some(7),
                )
                .await
                .unwrap(),
            ApiMutationOutcome::Rejected(ApiMutationRejection::IdempotencyConflict)
        ));
        assert_eq!(service.muc_policy(&token, second_room).await.unwrap(), None);
        committed(
            service
                .set_muc_policy(
                    admission(
                        &token,
                        "retention-second-room",
                        second_room.as_bytes(),
                        true,
                        b"7",
                    ),
                    second_room,
                    Some(7),
                )
                .await
                .unwrap(),
        );
        assert_eq!(
            service.muc_policy(&token, second_room).await.unwrap(),
            Some(7)
        );
        assert_eq!(service.muc_policy(&token, room).await.unwrap(), Some(7));
        assert!(matches!(
            service
                .set_muc_policy(
                    admission(
                        &token,
                        "retention-muc-restore",
                        room.as_bytes(),
                        true,
                        b"null"
                    ),
                    room,
                    None
                )
                .await,
            Err(RetentionPolicyError::Forbidden)
        ));
        assert!(matches!(
            service
                .set_muc_policy(
                    admission(
                        &admin_token,
                        "retention-muc-limit",
                        room.as_bytes(),
                        true,
                        b"31"
                    ),
                    room,
                    Some(31)
                )
                .await,
            Err(RetentionPolicyError::Forbidden)
        ));
        committed(
            service
                .set_muc_policy(
                    admission(
                        &admin_token,
                        "retention-muc-restore",
                        room.as_bytes(),
                        true,
                        b"null",
                    ),
                    room,
                    None,
                )
                .await
                .unwrap(),
        );
        assert_eq!(service.muc_policy(&token, room).await.unwrap(), None);

        sqlx::query("DELETE FROM api_sessions WHERE user_id=$1")
            .bind(owner)
            .execute(&pool)
            .await
            .unwrap();
        assert!(matches!(
            service.user_policy(&token).await,
            Err(RetentionPolicyError::Unauthorized)
        ));
        assert!(matches!(
            service.muc_policy(&token, room).await,
            Err(RetentionPolicyError::Unauthorized)
        ));
        pool.close().await;
    }
}
