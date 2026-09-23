use super::*;
use crate::services::api_queries::ApiReadAuthority;
use sqlx::Row;
use std::sync::Arc;

struct Request<'a> {
    actor: &'a Uuid,
    session: &'a str,
    method: &'a str,
    route: &'a str,
    target: &'a [u8],
    key: String,
    request_id: Uuid,
}
impl Request<'_> {
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
                request_fingerprint: db::api_request_fingerprint("application/json", b"fixture"),
                ttl_seconds: 3600,
                lease_seconds: 180,
            },
        }
    }
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn administrative_dispatch_preserves_intents_replay_and_atomic_side_records() {
    let pool = db::test_support::operation_mutation_pool().await;
    // The fixture runs these tests serially. Prior cases may retain active
    // singleton controls; their immutable audit history stays in this schema.
    sqlx::query("DELETE FROM api_muc_destroy_intents")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM api_operation_journal")
        .execute(&pool)
        .await
        .unwrap();
    let actor = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,username,password_hash,is_admin) VALUES($1,$2,'test-only-invalid',TRUE)")
        .bind(actor).bind(format!("dispatch-{}", actor.simple())).execute(&pool).await.unwrap();
    let session = db::create_api_session(&pool, actor, 1).await.unwrap();
    let cluster =
        crate::cluster::ClusterManager::new(None, "dispatch.test", None, None, None, None)
            .await
            .unwrap();
    let secret = Uuid::new_v4().simple().to_string();
    let keyring = Arc::new(db::ApiControlKeyring::new(secret.as_bytes(), None).unwrap());
    let service = AdminDispatchService::new(
        PostgresAdminDispatchRepository::new(AdminMutationStore::new(
            pool.clone(),
            keyring,
            cluster.admission(),
        )),
        "dispatch.test".into(),
    );
    let localpart = format!("room-{}", Uuid::new_v4().simple());
    sqlx::query("INSERT INTO muc_rooms(id,localpart) VALUES($1,$2)")
        .bind(Uuid::new_v4())
        .bind(&localpart)
        .execute(&pool)
        .await
        .unwrap();
    let Ok(room) = service.room_target(localpart) else {
        panic!("fixture room must be canonical")
    };
    for (kind, method, route, target, expected_kind, policy) in [
        (
            0,
            "POST",
            "/api/v1/admin/tls/reload",
            &b""[..],
            "admin.tls_reload",
            "reauthorize_until_effect",
        ),
        (
            1,
            "POST",
            "/api/v1/admin/panic_disconnect",
            &b""[..],
            "admin.panic_disconnect",
            "reauthorize_until_effect",
        ),
        (
            2,
            "POST",
            "/api/v1/admin/island_mode",
            &b"island_mode"[..],
            "admin.island_converge",
            "committed_consequence",
        ),
        (
            3,
            "DELETE",
            "/api/v1/admin/muc_rooms/{localpart}",
            room.room_jid().as_bytes(),
            "admin.muc_destroy",
            "committed_consequence",
        ),
        (
            4,
            "POST",
            "/api/v1/admin/broadcast",
            &b""[..],
            "admin.broadcast",
            "reauthorize_until_effect",
        ),
    ] {
        let request = Request {
            actor: &actor,
            session: &session,
            method,
            route,
            target,
            key: Uuid::new_v4().to_string(),
            request_id: Uuid::new_v4(),
        };
        let execute = async || match kind {
            0 => service.reload_tls(request.admission()).await,
            1 => service.panic_disconnect(request.admission()).await,
            2 => service.set_island_mode(request.admission(), true).await,
            3 => service.destroy_room(request.admission(), &room).await,
            _ => {
                service
                    .broadcast(request.admission(), "  Server maintenance tonight.  ")
                    .await
            }
        };
        let ApiMutationOutcome::Committed(response) = execute().await.unwrap() else {
            panic!("first dispatch must commit");
        };
        assert_eq!(response.status, 202);
        assert!(response.replay_resource_id.is_none());
        let body: Value = serde_json::from_slice(&response.body).unwrap();
        let operation_id: Uuid = serde_json::from_value(body["operation_id"].clone()).unwrap();
        assert_eq!(body["status"], "pending");
        assert_eq!(
            response.headers.get("location"),
            Some(&format!("/api/v1/admin/operations/{operation_id}"))
        );
        let ApiMutationOutcome::Replay(replay) = execute().await.unwrap() else {
            panic!("repeat dispatch must replay its original operation");
        };
        assert_eq!(replay.status, response.status);
        assert_eq!(replay.headers, response.headers);
        assert_eq!(replay.body, response.body);
        assert_eq!(replay.request_id, request.request_id);
        let row = sqlx::query("SELECT kind,authorization_policy,payload_version,payload,max_attempts,deadline_at>created_at+INTERVAL '23 hours' AND deadline_at<created_at+INTERVAL '25 hours' AS deadline_ok FROM api_operation_journal WHERE id=$1")
            .bind(operation_id).fetch_one(&pool).await.unwrap();
        assert_eq!(row.get::<String, _>("kind"), expected_kind);
        assert_eq!(row.get::<String, _>("authorization_policy"), policy);
        assert_eq!(row.get::<i16, _>("payload_version"), 1);
        assert_eq!(row.get::<i32, _>("max_attempts"), 8);
        assert!(row.get::<bool, _>("deadline_ok"));
        let payload: Value = row.get("payload");
        if kind == 2 {
            assert_eq!(payload["mode"], "enabled");
            assert_eq!(
                payload["epoch"],
                request.request_id.as_u128().min(i64::MAX as u128) as i64
            );
            assert!(sqlx::query_scalar::<_, bool>(
                "SELECT enabled FROM admin_runtime_settings WHERE key='island_mode'"
            )
            .fetch_one(&pool)
            .await
            .unwrap());
        } else if kind == 3 {
            assert_eq!(payload["room_jid"], room.room_jid());
            assert!(sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM api_muc_destroy_intents WHERE room_jid=$1 AND localpart=$2 AND operation_id=$3)")
                .bind(room.room_jid()).bind(room.localpart()).bind(operation_id).fetch_one(&pool).await.unwrap());
        } else if kind == 4 {
            assert_eq!(payload["message"], "Server maintenance tonight.");
        }
        let requests: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM api_operation_journal WHERE request_id=$1")
                .bind(request.request_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        let audits: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE request_id=$1 AND action='api.operation.transition' AND details->>'phase'='requested'")
            .bind(request.request_id).fetch_one(&pool).await.unwrap();
        assert_eq!((requests, audits), (1, 1));
    }

    let Ok(missing_room) = service.room_target(format!("absent-{}", Uuid::new_v4().simple()))
    else {
        panic!("fixture room must be canonical")
    };
    let missing = Request {
        actor: &actor,
        session: &session,
        method: "DELETE",
        route: "/api/v1/admin/muc_rooms/{localpart}",
        target: missing_room.room_jid().as_bytes(),
        key: Uuid::new_v4().to_string(),
        request_id: Uuid::new_v4(),
    };
    assert!(matches!(
        service
            .destroy_room(missing.admission(), &missing_room)
            .await
            .unwrap(),
        ApiMutationOutcome::Rejected(ApiMutationRejection::BadRequest("room does not exist"))
    ));
    assert!(!sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM api_idempotency_records WHERE request_id=$1) OR EXISTS(SELECT 1 FROM api_operation_journal WHERE request_id=$1)")
        .bind(missing.request_id).fetch_one(&pool).await.unwrap());

    let overlap = Request {
        actor: &actor,
        session: &session,
        method: "POST",
        route: "/api/v1/admin/island_mode",
        target: b"island_mode",
        key: Uuid::new_v4().to_string(),
        request_id: Uuid::new_v4(),
    };
    assert!(service
        .set_island_mode(overlap.admission(), false)
        .await
        .is_err());
    assert!(
        sqlx::query_scalar::<_, bool>(
            "SELECT enabled FROM admin_runtime_settings WHERE key='island_mode'"
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        "a singleton enqueue conflict must roll back its setting update"
    );
    assert!(!sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM audit_log WHERE request_id=$1) OR EXISTS(SELECT 1 FROM api_idempotency_records WHERE request_id=$1)")
        .bind(overlap.request_id).fetch_one(&pool).await.unwrap());
}
