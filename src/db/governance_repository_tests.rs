use super::*;
use crate::api::{cursor::CursorKeyring, governance_cursor::SignedGovernanceCursors};
use std::time::Duration;

type Service = GovernanceService<PostgresGovernanceRepository<SignedGovernanceCursors>>;

struct Request<'a> {
    admin: Uuid,
    session: &'a str,
    key: String,
    request_id: Uuid,
    route: &'static str,
    target: Vec<u8>,
    body: Vec<u8>,
}
impl<'a> Request<'a> {
    fn new(
        admin: Uuid,
        session: &'a str,
        route: &'static str,
        target: &[u8],
        body: serde_json::Value,
    ) -> Self {
        Self {
            admin,
            session,
            key: Uuid::new_v4().to_string(),
            request_id: Uuid::new_v4(),
            route,
            target: target.to_vec(),
            body: serde_json::to_vec(&body).unwrap(),
        }
    }
    fn authority(&self) -> ApiReadAuthority<'_> {
        ApiReadAuthority {
            user_id: self.admin,
            auth_generation: 0,
            session_token: self.session,
        }
    }
    fn admission(&self) -> AdminMutationAdmission<'_> {
        AdminMutationAdmission {
            authority: self.authority(),
            idempotency: IdempotencyRequest {
                request_id: self.request_id,
                actor_id: Some(self.admin),
                principal_scope: self.admin.as_bytes(),
                capacity_scope: self.admin.as_bytes(),
                target_scope: &self.target,
                principal_kind: ApiPrincipalKind::Admin,
                method: "POST",
                route: self.route,
                idempotency_key: &self.key,
                request_fingerprint: db::api_request_fingerprint("application/json", &self.body),
                ttl_seconds: 24 * 60 * 60,
                lease_seconds: 180,
            },
        }
    }
}

fn committed(outcome: ApiMutationOutcome<StoredApiResponse>) -> StoredApiResponse {
    let ApiMutationOutcome::Committed(response) = outcome else {
        panic!("first execution must commit");
    };
    response
}
fn body(response: &StoredApiResponse) -> serde_json::Value {
    serde_json::from_slice(&response.body).unwrap()
}
fn same_replay(
    outcome: ApiMutationOutcome<StoredApiResponse>,
    original: &StoredApiResponse,
    request_id: Uuid,
) {
    let ApiMutationOutcome::Replay(replay) = outcome else {
        panic!("exact retry must replay");
    };
    assert_eq!(replay.status, original.status);
    assert_eq!(replay.headers, original.headers);
    assert_eq!(replay.body, original.body);
    assert_eq!(replay.request_id, request_id);
}
async fn assert_request_absent(pool: &PgPool, request_id: Uuid) {
    let retained: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM api_idempotency_records WHERE request_id=$1)
             OR EXISTS(SELECT 1 FROM audit_log WHERE request_id=$1)",
    )
    .bind(request_id)
    .fetch_one(pool)
    .await
    .unwrap();
    assert!(
        !retained,
        "failed export must roll back replay reservation and audit"
    );
}
async fn create_hold(
    service: &Service,
    request: &Request<'_>,
    targets: &[LegalHoldTarget],
) -> StoredApiResponse {
    committed(
        service
            .create_hold(CreateHoldCommand {
                admission: request.admission(),
                title: "Governance port fixture",
                authority_reference: "fixture-authority",
                reason: "verify export commit boundary",
                targets,
            })
            .await
            .unwrap(),
    )
}
fn hold_command<'a>(
    request: &'a Request<'_>,
    hold_id: Uuid,
    cursor: Option<&'a str>,
    max_rows: i64,
) -> HoldExportCommand<'a> {
    HoldExportCommand {
        admission: request.admission(),
        hold_id,
        max_rows,
        cursor,
    }
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn governance_ports_replay_before_cursor_validation_and_bound_exports_before_commit() {
    let pool = db::test_support::operation_mutation_pool().await;
    let result = tokio::time::timeout(
        Duration::from_secs(45),
        exercise_governance_ports(pool.clone()),
    )
    .await;
    tokio::time::timeout(Duration::from_secs(5), pool.close())
        .await
        .expect("fixture pool did not close");
    result.expect("governance port test exceeded its 45-second deadline");
}

async fn exercise_governance_ports(pool: PgPool) {
    let admin = Uuid::new_v4();
    let user = Uuid::new_v4();
    let large_user = Uuid::new_v4();
    for (id, is_admin) in [(admin, true), (user, false), (large_user, false)] {
        sqlx::query("INSERT INTO users(id,username,password_hash,is_admin) VALUES($1,$2,'test-only-invalid',$3)")
            .bind(id).bind(format!("governance-{}", id.simple())).bind(is_admin)
            .execute(&pool).await.unwrap();
    }
    for (owner, count, payload_len) in [(user, 3, 32), (large_user, 18, 60_000)] {
        let stanza = format!(
            "<message><encrypted xmlns='urn:xmpp:omemo:2'>{}</encrypted></message>",
            "a".repeat(payload_len)
        );
        for _ in 0..count {
            sqlx::query("INSERT INTO message_archive(id,owner_id,peer_jid,peer_full_jid,stanza,encrypted,created_at)
                VALUES($1,$2,'peer@example.test','peer@example.test/device',$3,TRUE,clock_timestamp()-INTERVAL '1 day')")
                .bind(Uuid::new_v4()).bind(owner).bind(&stanza).execute(&pool).await.unwrap();
        }
    }
    let session = db::create_api_session(&pool, admin, 1).await.unwrap();
    let cluster =
        crate::cluster::ClusterManager::new(None, "governance.test", None, None, None, None)
            .await
            .unwrap();
    let secret = Uuid::new_v4().simple().to_string();
    let keyring = Arc::new(db::ApiControlKeyring::new(secret.as_bytes(), None).unwrap());
    let mutations =
        AdminMutationStore::new(pool.clone(), Arc::clone(&keyring), cluster.admission());
    let service_for_cursor_key = |secret: &str| {
        GovernanceService::new(PostgresGovernanceRepository::new(
            pool.clone(),
            mutations.clone(),
            Arc::clone(&keyring),
            SignedGovernanceCursors::new(Arc::new(
                CursorKeyring::new(secret.as_bytes(), None).unwrap(),
            )),
        ))
    };
    let service = service_for_cursor_key(&secret);
    let rotated_secret = Uuid::new_v4().simple().to_string();
    let rotated = service_for_cursor_key(&rotated_secret);

    let targets = [LegalHoldTarget::PersonalArchiveOwner(user)];
    let create = Request::new(
        admin,
        &session,
        "/api/v1/admin/legal-holds",
        b"legal-hold:create",
        serde_json::json!({"title":"Governance port fixture", "authority_reference":"fixture-authority", "reason":"verify export commit boundary", "targets":targets}),
    );
    let created = create_hold(&service, &create, &targets).await;
    assert_eq!(created.status, 201);
    let hold: Uuid = serde_json::from_value(body(&created)["id"].clone()).unwrap();
    same_replay(
        service
            .create_hold(CreateHoldCommand {
                admission: create.admission(),
                title: "Governance port fixture",
                authority_reference: "fixture-authority",
                reason: "verify export commit boundary",
                targets: &targets,
            })
            .await
            .unwrap(),
        &created,
        create.request_id,
    );
    let listed = service
        .list_holds(create.authority(), true, 100, &"ab".repeat(32))
        .await
        .unwrap();
    assert!(listed
        .iter()
        .any(|item| item.id == hold && item.target_count == 1));

    let first = Request::new(
        admin,
        &session,
        "/api/v1/admin/legal-holds/{id}/export",
        hold.as_bytes(),
        serde_json::json!({"max_rows":1}),
    );
    let first_page = committed(
        service
            .export_hold(hold_command(&first, hold, None, 1))
            .await
            .unwrap(),
    );
    let first_body = body(&first_page);
    let cursor = first_body["next_cursor"].as_str().unwrap();
    let export_id: Uuid = serde_json::from_value(first_body["export_id"].clone()).unwrap();
    assert_eq!(first_body["records"].as_array().unwrap().len(), 1);
    let second = Request::new(
        admin,
        &session,
        "/api/v1/admin/legal-holds/{id}/export",
        hold.as_bytes(),
        serde_json::json!({"max_rows":1,"cursor":cursor}),
    );
    let second_page = committed(
        service
            .export_hold(hold_command(&second, hold, Some(cursor), 1))
            .await
            .unwrap(),
    );
    let second_body = body(&second_page);
    assert_eq!(
        second_body["chain_start_sha256"],
        first_body["chain_root_sha256"]
    );
    // Retiring the cursor signing key invalidates fresh continuations but
    // must not prevent an exact replay of already committed response bytes.
    same_replay(
        rotated
            .export_hold(hold_command(&second, hold, Some(cursor), 1))
            .await
            .unwrap(),
        &second_page,
        second.request_id,
    );
    let fresh = Request::new(
        admin,
        &session,
        second.route,
        hold.as_bytes(),
        serde_json::json!({"max_rows":1,"cursor":cursor}),
    );
    let Err(failure) = rotated
        .export_hold(hold_command(&fresh, hold, Some(cursor), 1))
        .await
    else {
        panic!("fresh key must verify cursor");
    };
    assert!(matches!(failure.error, GovernanceError::InvalidCursor));
    assert!(failure.cursor_rejected);
    assert!(!failure.operation_failed);
    assert_request_absent(&pool, fresh.request_id).await;
    let export_audits: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE request_id=$1")
            .bind(second.request_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(export_audits, 1);

    let final_cursor = second_body["next_cursor"].as_str().unwrap();
    let final_request = Request::new(
        admin,
        &session,
        first.route,
        hold.as_bytes(),
        serde_json::json!({"max_rows":1,"cursor":final_cursor}),
    );
    let final_page = committed(
        service
            .export_hold(hold_command(&final_request, hold, Some(final_cursor), 1))
            .await
            .unwrap(),
    );
    assert_eq!(body(&final_page)["complete"], true);
    let completed: bool = sqlx::query_scalar(
        "SELECT completed_at IS NOT NULL FROM governance_export_leases WHERE id=$1",
    )
    .bind(export_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(completed);
    let release = Request::new(
        admin,
        &session,
        "/api/v1/admin/legal-holds/{id}/release",
        hold.as_bytes(),
        serde_json::json!({"reason":"fixture complete"}),
    );
    let released = committed(
        service
            .release_hold(release.admission(), hold, "fixture complete")
            .await
            .unwrap(),
    );
    assert_eq!(body(&released)["active"], false);
    same_replay(
        service
            .release_hold(release.admission(), hold, "fixture complete")
            .await
            .unwrap(),
        &released,
        release.request_id,
    );

    let large_targets = [LegalHoldTarget::PersonalArchiveOwner(large_user)];
    let large_create = Request::new(
        admin,
        &session,
        create.route,
        b"legal-hold:create",
        serde_json::json!({"title":"Governance port fixture", "authority_reference":"fixture-authority", "reason":"verify export commit boundary", "targets":large_targets}),
    );
    let large_created = create_hold(&service, &large_create, &large_targets).await;
    let large_hold: Uuid = serde_json::from_value(body(&large_created)["id"].clone()).unwrap();
    let oversized = Request::new(
        admin,
        &session,
        first.route,
        large_hold.as_bytes(),
        serde_json::json!({"max_rows":100}),
    );
    let Err(failure) = service
        .export_hold(hold_command(&oversized, large_hold, None, 100))
        .await
    else {
        panic!("oversized export must fail before commit");
    };
    assert!(
        matches!(failure.error, GovernanceError::BadRequest(message) if message.contains("reduce max_rows"))
    );
    assert!(failure.operation_failed);
    assert_request_absent(&pool, oversized.request_id).await;
    let retained: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM governance_export_leases WHERE hold_id=$1)",
    )
    .bind(large_hold)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(!retained, "oversized page must not publish an export lease");

    let audit = Request::new(
        admin,
        &session,
        "/api/v1/admin/audit/export",
        b"audit:export",
        serde_json::json!({"max_rows":1}),
    );
    let audit_command = || AuditExportCommand {
        admission: audit.admission(),
        start: None,
        end: None,
        max_rows: 1,
        cursor: None,
    };
    let audit_page = committed(service.export_audit(audit_command()).await.unwrap());
    assert_eq!(body(&audit_page)["entries"].as_array().unwrap().len(), 1);
    assert!(body(&audit_page)["next_cursor"].is_string());
    same_replay(
        rotated.export_audit(audit_command()).await.unwrap(),
        &audit_page,
        audit.request_id,
    );
}
