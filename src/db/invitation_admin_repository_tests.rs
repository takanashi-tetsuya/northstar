use super::*;
use crate::services::api_queries::ApiReadAuthority;
use std::sync::Arc;

struct Request<'a> {
    admin: &'a Uuid,
    session: &'a str,
    key: String,
    request_id: Uuid,
}
impl<'a> Request<'a> {
    fn new(admin: &'a Uuid, session: &'a str) -> Self {
        Self {
            admin,
            session,
            key: Uuid::new_v4().to_string(),
            request_id: Uuid::new_v4(),
        }
    }
    fn admission<'b>(&'b self, target: Option<&'b Uuid>) -> AdminMutationAdmission<'b> {
        let (method, route, target_scope, body): (&str, &str, &[u8], &[u8]) = match target {
            Some(id) => (
                "DELETE",
                "/api/v1/admin/invitations/{id}",
                id.as_bytes(),
                b"",
            ),
            None => (
                "POST",
                "/api/v1/admin/invitations",
                b"invitation:create",
                br#"{"label":"  Team access  ","max_uses":2,"expires_in_hours":1}"#,
            ),
        };
        AdminMutationAdmission {
            authority: ApiReadAuthority {
                user_id: *self.admin,
                auth_generation: 0,
                session_token: self.session,
            },
            idempotency: IdempotencyRequest {
                request_id: self.request_id,
                actor_id: Some(*self.admin),
                principal_scope: self.admin.as_bytes(),
                capacity_scope: self.admin.as_bytes(),
                target_scope,
                principal_kind: ApiPrincipalKind::Admin,
                method,
                route,
                idempotency_key: &self.key,
                request_fingerprint: db::api_request_fingerprint("application/json", body),
                ttl_seconds: 24 * 60 * 60,
                lease_seconds: 180,
            },
        }
    }
}

fn input() -> InvitationInput<'static> {
    InvitationInput {
        label: "  Team access  ",
        max_uses: Some(2),
        expires_in_hours: Some(1),
    }
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn invitation_ports_revalidate_secret_replay_and_commit_revoke_outcomes_once() {
    let pool = db::test_support::operation_mutation_pool().await;
    let admin = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,username,password_hash,is_admin) VALUES($1,$2,'test-only-invalid',TRUE)")
        .bind(admin).bind(format!("invitation-{}", admin.simple())).execute(&pool).await.unwrap();
    let session = db::create_api_session(&pool, admin, 1).await.unwrap();
    let cluster =
        crate::cluster::ClusterManager::new(None, "invitation-admin.test", None, None, None, None)
            .await
            .unwrap();
    let secret = Uuid::new_v4().simple().to_string();
    let keyring = Arc::new(db::ApiControlKeyring::new(secret.as_bytes(), None).unwrap());
    let service = InvitationAdminService::new(PostgresInvitationAdminRepository::new(
        AdminMutationStore::new(pool.clone(), keyring, cluster.admission()),
    ));
    let create = Request::new(&admin, &session);
    let ApiMutationOutcome::Committed(response) = service
        .create(create.admission(None), input())
        .await
        .unwrap()
    else {
        panic!("first invitation must commit");
    };
    assert_eq!(response.status, 201);
    let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    let id: Uuid = serde_json::from_value(body["id"].clone()).unwrap();
    let token = body["token"].as_str().unwrap();
    let protected: bool = sqlx::query_scalar(
        "SELECT response.replay_resource_id=invitation.id AND response.expires_at<=invitation.expires_at
            AND invitation.label='Team access' AND invitation.max_uses=2 AND invitation.token_hash=$3
            AND POSITION($4::bytea IN response.response_ciphertext)=0
         FROM api_idempotency_records response JOIN invitation_tokens invitation ON invitation.id=$1
         WHERE response.request_id=$2",
    ).bind(id).bind(create.request_id).bind(crate::auth::token_hash(token)).bind(token.as_bytes())
        .fetch_one(&pool).await.unwrap();
    assert!(
        protected,
        "secret replay must retain the resource binding and expiry ceiling"
    );
    let ApiMutationOutcome::Replay(replay) = service
        .create(create.admission(None), input())
        .await
        .unwrap()
    else {
        panic!("live invitation must replay");
    };
    assert_eq!(replay.body, response.body);
    assert_eq!(replay.headers, response.headers);
    assert_eq!(replay.request_id, create.request_id);

    for (target, expected_status, expected_outcome) in [
        (id, 200, "revoked"),
        (id, 200, "already_revoked"),
        (Uuid::new_v4(), 404, "not_found"),
    ] {
        let request = Request::new(&admin, &session);
        let ApiMutationOutcome::Committed(response) = service
            .revoke(request.admission(Some(&target)), target)
            .await
            .unwrap()
        else {
            panic!("first revocation must commit its result");
        };
        assert_eq!(response.status, expected_status);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        if expected_status == 200 {
            assert_eq!(body["revoked"], true);
            assert_eq!(
                body["already_revoked"],
                expected_outcome == "already_revoked"
            );
        }
        let ApiMutationOutcome::Replay(replay) = service
            .revoke(request.admission(Some(&target)), target)
            .await
            .unwrap()
        else {
            panic!("revocation must replay without another audit");
        };
        assert_eq!(replay.status, response.status);
        assert_eq!(replay.body, response.body);
        let audit: Vec<String> =
            sqlx::query_scalar("SELECT details->>'outcome' FROM audit_log WHERE request_id=$1")
                .bind(request.request_id)
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(audit, vec![expected_outcome]);
    }
    assert!(matches!(
        service
            .create(create.admission(None), input())
            .await
            .unwrap(),
        ApiMutationOutcome::Rejected(ApiMutationRejection::ReplayInvalidated)
    ));
    sqlx::query("UPDATE invitation_tokens SET revoked_at=NULL,use_count=max_uses WHERE id=$1")
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();
    assert!(matches!(
        service
            .create(create.admission(None), input())
            .await
            .unwrap(),
        ApiMutationOutcome::Rejected(ApiMutationRejection::ReplayInvalidated)
    ));
    sqlx::query("UPDATE invitation_tokens SET use_count=0,expires_at=clock_timestamp()-INTERVAL '1 second' WHERE id=$1")
        .bind(id).execute(&pool).await.unwrap();
    assert!(matches!(
        service
            .create(create.admission(None), input())
            .await
            .unwrap(),
        ApiMutationOutcome::Rejected(ApiMutationRejection::ReplayInvalidated)
    ));
    let created: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_log WHERE request_id=$1 AND action='admin.invitation.create'",
    )
    .bind(create.request_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(created, 1);

    for (label, max_uses, expires_in_hours, expected) in [
        ("\0", None, None, "invitation label is invalid"),
        ("team", Some(0), None, "invitation max uses is invalid"),
        (
            "team",
            Some(100_001),
            None,
            "invitation max uses is invalid",
        ),
        ("team", None, Some(0), "invitation expiry is invalid"),
        ("team", None, Some(8761), "invitation expiry is invalid"),
    ] {
        let invalid = Request::new(&admin, &session);
        let outcome = service
            .create(
                invalid.admission(None),
                InvitationInput {
                    label,
                    max_uses,
                    expires_in_hours,
                },
            )
            .await
            .unwrap();
        assert!(
            matches!(outcome, ApiMutationOutcome::Rejected(ApiMutationRejection::BadRequest(message)) if message == expected)
        );
        let retained: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM api_idempotency_records WHERE request_id=$1) OR EXISTS(SELECT 1 FROM audit_log WHERE request_id=$1)")
            .bind(invalid.request_id).fetch_one(&pool).await.unwrap();
        assert!(!retained);
    }
}
