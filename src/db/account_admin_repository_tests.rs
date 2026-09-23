use super::*;
use crate::services::api_queries::ApiReadAuthority;
use serde_json::Value;
use sqlx::Row;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};

struct Request<'a> {
    actor: &'a Uuid,
    session: &'a str,
    method: &'a str,
    route: &'a str,
    target: &'a [u8],
    key: String,
    request_id: Uuid,
}
impl<'a> Request<'a> {
    fn new(
        actor: &'a Uuid,
        session: &'a str,
        method: &'a str,
        route: &'a str,
        target: &'a [u8],
    ) -> Self {
        Self {
            actor,
            session,
            method,
            route,
            target,
            key: Uuid::new_v4().to_string(),
            request_id: Uuid::new_v4(),
        }
    }
    fn admission(&self) -> AdminMutationAdmission<'_> {
        AdminMutationAdmission {
            authority: ApiReadAuthority {
                user_id: *self.actor,
                auth_generation: 0,
                session_token: self.session,
            },
            idempotency: IdempotencyRequest {
                request_id: self.request_id,
                actor_id: Some(*self.actor),
                principal_scope: self.actor.as_bytes(),
                capacity_scope: self.actor.as_bytes(),
                target_scope: self.target,
                principal_kind: ApiPrincipalKind::Admin,
                method: self.method,
                route: self.route,
                idempotency_key: &self.key,
                request_fingerprint: api_request_fingerprint("application/json", b"fixture"),
                ttl_seconds: 3600,
                lease_seconds: 180,
            },
        }
    }
}
async fn fixture() -> (PgPool, AdminMutationStore, Uuid, String) {
    let pool = db::test_support::operation_mutation_pool().await;
    let actor = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,username,password_hash,is_admin) VALUES($1,$2,'test-only-invalid',TRUE)")
        .bind(actor).bind(format!("account-admin-{}", actor.simple())).execute(&pool).await.unwrap();
    let session = db::create_api_session(&pool, actor, 1).await.unwrap();
    let cluster =
        crate::cluster::ClusterManager::new(None, "accounts.test", None, None, None, None)
            .await
            .unwrap();
    let secret = Uuid::new_v4().simple().to_string();
    let keyring = Arc::new(db::ApiControlKeyring::new(secret.as_bytes(), None).unwrap());
    let store = AdminMutationStore::new(pool.clone(), keyring, cluster.admission());
    (pool, store, actor, session)
}
async fn user(pool: &PgPool, generation: i64) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,username,password_hash,auth_generation) VALUES($1,$2,'test-only-invalid',$3)")
        .bind(id).bind(format!("account-target-{}", id.simple())).bind(generation).execute(pool).await.unwrap();
    id
}
fn committed(outcome: ApiMutationOutcome<StoredApiResponse>) -> StoredApiResponse {
    match outcome {
        ApiMutationOutcome::Committed(response) => response,
        _ => panic!("expected committed response"),
    }
}
fn operation_id(response: &StoredApiResponse) -> Uuid {
    assert_eq!(response.status, 202);
    assert!(response.replay_resource_id.is_none());
    let body: Value = serde_json::from_slice(&response.body).unwrap();
    serde_json::from_value(body["operation_id"].clone()).unwrap()
}
async fn assert_unretained(pool: &PgPool, request_id: Uuid) {
    assert!(!sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM api_idempotency_records WHERE request_id=$1) OR EXISTS(SELECT 1 FROM api_operation_journal WHERE request_id=$1) OR EXISTS(SELECT 1 FROM audit_log WHERE request_id=$1)")
        .bind(request_id).fetch_one(pool).await.unwrap());
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn account_disable_commits_exact_old_generation_and_rolls_back_failed_cleanup_enqueue() {
    let (pool, store, actor, session) = fixture().await;
    let service = AccountAdminService::new(PostgresAccountAdminRepository::new(store.clone()));
    let target_user = user(&pool, 17).await;
    db::create_api_session(&pool, target_user, 1).await.unwrap();
    let request = Request::new(
        &actor,
        &session,
        "PATCH",
        "/api/v1/admin/users/{id}",
        target_user.as_bytes(),
    );
    let patch = UserStatusPatch {
        disabled: Some(true),
        admin: None,
    };
    let response = committed(
        service
            .update_user(request.admission(), target_user, patch)
            .await
            .unwrap(),
    );
    let id = operation_id(&response);
    let row = sqlx::query(
        "SELECT kind,target,authorization_policy,payload FROM api_operation_journal WHERE id=$1",
    )
    .bind(id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row.get::<String, _>("kind"), "admin.user_session_cleanup");
    assert_eq!(
        row.get::<String, _>("target"),
        format!("user:{target_user}:generation:17")
    );
    assert_eq!(
        row.get::<String, _>("authorization_policy"),
        "committed_consequence"
    );
    assert_eq!(
        row.get::<Value, _>("payload"),
        json!({"user_id":target_user,"auth_generation":17})
    );
    let state: (bool, i64) =
        sqlx::query_as("SELECT is_disabled,auth_generation FROM users WHERE id=$1")
            .bind(target_user)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(state, (true, 18));
    assert!(!sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM api_sessions WHERE user_id=$1)"
    )
    .bind(target_user)
    .fetch_one(&pool)
    .await
    .unwrap());
    assert_eq!(
        response.headers.get("location"),
        Some(&format!("/api/v1/admin/operations/{id}"))
    );
    let ApiMutationOutcome::Replay(replay) = service
        .update_user(request.admission(), target_user, patch)
        .await
        .unwrap()
    else {
        panic!("disable must replay")
    };
    assert_eq!(
        (replay.status, replay.headers, replay.body),
        (response.status, response.headers, response.body)
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT auth_generation FROM users WHERE id=$1")
            .bind(target_user)
            .fetch_one(&pool)
            .await
            .unwrap(),
        18
    );

    // An existing active cleanup for this exact generation makes enqueue fail
    // after status mutation; account state and its reservation must roll back.
    let blocked_user = user(&pool, 3).await;
    db::create_api_session(&pool, blocked_user, 1)
        .await
        .unwrap();
    let blocker = Request::new(
        &actor,
        &session,
        "PATCH",
        "/api/v1/admin/users/{id}",
        blocked_user.as_bytes(),
    );
    let admission = blocker.admission();
    let AdminMutationStart::Ready(mut tx, lease) = store.start(&admission).await.unwrap() else {
        panic!("fixture admission")
    };
    let target = format!("user:{blocked_user}:generation:3");
    let (response, _) = enqueue_operation_response_in_tx(
        &mut tx,
        &admission,
        &lease,
        AdminOperationIntent {
            kind: "admin.user_session_cleanup",
            target: Some(&target),
            policy: AuthorizationPolicy::CommittedConsequence,
            payload: &json!({"user_id":blocked_user,"auth_generation":3}),
        },
    )
    .await
    .unwrap();
    store.finish(tx, &lease, response).await.unwrap();
    let blocked = Request::new(
        &actor,
        &session,
        "PATCH",
        "/api/v1/admin/users/{id}",
        blocked_user.as_bytes(),
    );
    assert!(service
        .update_user(blocked.admission(), blocked_user, patch)
        .await
        .is_err());
    let state: (bool, i64) =
        sqlx::query_as("SELECT is_disabled,auth_generation FROM users WHERE id=$1")
            .bind(blocked_user)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(state, (false, 3));
    assert!(sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM api_sessions WHERE user_id=$1)"
    )
    .bind(blocked_user)
    .fetch_one(&pool)
    .await
    .unwrap());
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM audit_log WHERE action='admin.user.update' AND target=$1"
        )
        .bind(blocked_user.to_string())
        .fetch_one(&pool)
        .await
        .unwrap(),
        0
    );
    assert_unretained(&pool, blocked.request_id).await;

    let self_update = Request::new(
        &actor,
        &session,
        "PATCH",
        "/api/v1/admin/users/{id}",
        actor.as_bytes(),
    );
    let ApiMutationOutcome::Rejected(ApiMutationRejection::BadRequest(message)) = service
        .update_user(self_update.admission(), actor, patch)
        .await
        .unwrap()
    else {
        panic!("self disable must be rejected")
    };
    assert_eq!(message, db::UserStatusError::SelfMutation.to_string());
    assert_unretained(&pool, self_update.request_id).await;
}

struct Sessions {
    calls: AtomicUsize,
    live: Mutex<Option<SessionKickSnapshot>>,
}
impl AdminSessionLookup for Arc<Sessions> {
    fn exact_connection(&self, connection_id: Uuid) -> Option<SessionKickSnapshot> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.live
            .lock()
            .unwrap()
            .filter(|entry| entry.connection_id == connection_id)
    }
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn session_kick_snapshots_after_replay_and_retains_missing_session_response() {
    let (pool, store, actor, session) = fixture().await;
    let connection_id = Uuid::new_v4();
    let user_id = user(&pool, 5).await;
    let sessions = Arc::new(Sessions {
        calls: AtomicUsize::new(0),
        live: Mutex::new(Some(SessionKickSnapshot {
            user_id,
            auth_generation: 5,
            connection_id,
        })),
    });
    let service = SessionAdminService::new(
        PostgresSessionAdminRepository::new(store),
        Arc::clone(&sessions),
    );
    let target = format!("connection:{connection_id}");
    let request = Request::new(
        &actor,
        &session,
        "DELETE",
        "/api/v1/admin/sessions/{connection_id}",
        target.as_bytes(),
    );
    let response = committed(
        service
            .kick_session(request.admission(), connection_id)
            .await
            .unwrap(),
    );
    let id = operation_id(&response);
    let row = sqlx::query(
        "SELECT kind,target,authorization_policy,payload FROM api_operation_journal WHERE id=$1",
    )
    .bind(id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row.get::<String, _>("kind"), "admin.session_kick");
    assert_eq!(row.get::<String, _>("target"), target);
    assert_eq!(
        row.get::<String, _>("authorization_policy"),
        "reauthorize_until_effect"
    );
    assert_eq!(
        row.get::<Value, _>("payload"),
        json!({"user_id":user_id,"auth_generation":5,"connection_id":connection_id.to_string()})
    );
    *sessions.live.lock().unwrap() = None;
    let ApiMutationOutcome::Replay(replay) = service
        .kick_session(request.admission(), connection_id)
        .await
        .unwrap()
    else {
        panic!("kick must replay even after disconnect")
    };
    assert_eq!(replay.body, response.body);
    assert_eq!(sessions.calls.load(Ordering::Relaxed), 1);

    let absent = Uuid::new_v4();
    let absent_target = format!("connection:{absent}");
    let missing = Request::new(
        &actor,
        &session,
        "DELETE",
        "/api/v1/admin/sessions/{connection_id}",
        absent_target.as_bytes(),
    );
    let response = committed(
        service
            .kick_session(missing.admission(), absent)
            .await
            .unwrap(),
    );
    assert_eq!(response.status, 400);
    assert_eq!(
        serde_json::from_slice::<Value>(&response.body).unwrap(),
        json!({"error":{"code":"bad_request","message":"session does not exist"}})
    );
    *sessions.live.lock().unwrap() = Some(SessionKickSnapshot {
        user_id,
        auth_generation: 6,
        connection_id: absent,
    });
    let ApiMutationOutcome::Replay(replay) = service
        .kick_session(missing.admission(), absent)
        .await
        .unwrap()
    else {
        panic!("missing result must replay")
    };
    assert_eq!(
        (replay.status, replay.body),
        (response.status, response.body)
    );
    assert_eq!(sessions.calls.load(Ordering::Relaxed), 2);
    assert!(!sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM api_operation_journal WHERE request_id=$1)"
    )
    .bind(missing.request_id)
    .fetch_one(&pool)
    .await
    .unwrap());
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn offline_clear_preserves_transport_owned_queue_and_retries_the_rolled_back_key() {
    let (pool, store, actor, session) = fixture().await;
    let service = AccountAdminService::new(PostgresAccountAdminRepository::new(store));
    let recipient = user(&pool, 0).await;
    // This isolated fixture runs serially; earlier operation tests do not own
    // transports. Preserve the queue's own enqueue and claim checks here.
    assert_eq!(
        db::store_offline(
            &pool,
            recipient,
            "sender@accounts.test",
            "<message><body>retained</body></message>",
            false,
            db::OfflineStorePolicy {
                max_messages: 100,
                max_bytes: 1_000_000,
                ttl_days: 30,
                mam_backed: false
            }
        )
        .await
        .unwrap(),
        db::OfflineStoreOutcome::Stored
    );
    sqlx::query("UPDATE offline_messages SET delivery_claim_id=$1,delivery_claim_expires_at=NOW()+INTERVAL '10 minutes' WHERE recipient_id=$2")
        .bind(Uuid::new_v4()).bind(recipient).execute(&pool).await.unwrap();
    let before = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM offline_messages")
        .fetch_one(&pool)
        .await
        .unwrap();
    let request = Request::new(
        &actor,
        &session,
        "DELETE",
        "/api/v1/admin/offline_messages",
        b"offline_messages",
    );
    let ApiMutationOutcome::Rejected(ApiMutationRejection::Conflict(message)) = service
        .clear_offline_messages(request.admission())
        .await
        .unwrap()
    else {
        panic!("transport-owned rows must block clearing")
    };
    assert_eq!(message, db::OfflineMessagesTransportOwned.to_string());
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM offline_messages")
            .fetch_one(&pool)
            .await
            .unwrap(),
        before
    );
    assert_unretained(&pool, request.request_id).await;
    sqlx::query("UPDATE offline_messages SET delivery_claim_id=NULL,delivery_claim_expires_at=NULL WHERE recipient_id=$1").bind(recipient).execute(&pool).await.unwrap();
    let response = committed(
        service
            .clear_offline_messages(request.admission())
            .await
            .unwrap(),
    );
    assert_eq!(response.status, 200);
    assert_eq!(
        serde_json::from_slice::<Value>(&response.body).unwrap(),
        json!({"cleared":true,"removed":before})
    );
    // A repeated clear must not delete messages accepted after its commit.
    db::store_offline(
        &pool,
        recipient,
        "sender@accounts.test",
        "<message><body>later</body></message>",
        false,
        db::OfflineStorePolicy {
            max_messages: 100,
            max_bytes: 1_000_000,
            ttl_days: 30,
            mam_backed: false,
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        service
            .clear_offline_messages(request.admission())
            .await
            .unwrap(),
        ApiMutationOutcome::Replay(_)
    ));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM offline_messages WHERE recipient_id=$1")
            .bind(recipient)
            .fetch_one(&pool)
            .await
            .unwrap(),
        1
    );
}
