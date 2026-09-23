use super::*;
use crate::services::api_queries::ApiReadAuthority;
use std::sync::Arc;
use uuid::Uuid;

fn admission<'a>(
    admin: &'a Uuid,
    session: &'a str,
    target: &'a Uuid,
    route: &'a str,
    key: &'a str,
    request_id: Uuid,
    fingerprint: [u8; 32],
) -> AdminMutationAdmission<'a> {
    AdminMutationAdmission {
        authority: ApiReadAuthority {
            user_id: *admin,
            auth_generation: 0,
            session_token: session,
        },
        idempotency: IdempotencyRequest {
            request_id,
            actor_id: Some(*admin),
            principal_scope: admin.as_bytes(),
            capacity_scope: admin.as_bytes(),
            target_scope: target.as_bytes(),
            principal_kind: ApiPrincipalKind::Admin,
            method: "PATCH",
            route,
            idempotency_key: key,
            request_fingerprint: fingerprint,
            ttl_seconds: 3_600,
            lease_seconds: 180,
        },
    }
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn moderation_ports_commit_decisions_and_replay_terminal_errors_once() {
    let pool = crate::db::test_support::operation_mutation_pool().await;
    let admin = Uuid::new_v4();
    let reporter = Uuid::new_v4();
    for (id, is_admin) in [(admin, true), (reporter, false)] {
        sqlx::query(
            "INSERT INTO users(id,username,password_hash,is_admin) VALUES($1,$2,'test-only-invalid',$3)",
        )
        .bind(id)
        .bind(format!("moderation-{}", id.simple()))
        .bind(is_admin)
        .execute(&pool)
        .await
        .unwrap();
    }
    let session = db::create_api_session(&pool, admin, 1).await.unwrap();
    let report = Uuid::new_v4();
    let appeal = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO abuse_reports(id,reporter_id,reported_jid,category) VALUES($1,$2,'peer@example.test','spam')",
    )
    .bind(report)
    .bind(reporter)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO abuse_appeals(id,report_id,appellant_id,reason) VALUES($1,$2,$3,'Please review the original moderation decision.')",
    )
    .bind(appeal)
    .bind(report)
    .bind(reporter)
    .execute(&pool)
    .await
    .unwrap();
    let cluster =
        crate::cluster::ClusterManager::new(None, "report-moderation.test", None, None, None, None)
            .await
            .unwrap();
    let secret = Uuid::new_v4().simple().to_string();
    let keyring = Arc::new(db::ApiControlKeyring::new(secret.as_bytes(), None).unwrap());
    let service = ReportModerationService::new(PostgresReportModerationRepository::new(
        AdminMutationStore::new(pool.clone(), keyring, cluster.admission()),
    ));
    for (is_appeal, target, status, expected_status, expected_outcome) in [
        (false, report, "rejected", 200, "updated"),
        (false, report, "reviewing", 409, "invalid_transition"),
        (false, Uuid::new_v4(), "reviewing", 404, "not_found"),
        (true, appeal, "upheld", 200, "updated"),
        (true, appeal, "reviewing", 409, "invalid_transition"),
        (true, Uuid::new_v4(), "reviewing", 404, "not_found"),
    ] {
        let route = if is_appeal {
            "/api/v1/admin/appeals/{id}"
        } else {
            "/api/v1/admin/reports/{id}"
        };
        let key = Uuid::new_v4().to_string();
        let request_id = Uuid::new_v4();
        let body = serde_json::to_vec(&serde_json::json!({
            "status": status,
            "resolution": "  Reviewed the evidence.  "
        }))
        .unwrap();
        let fingerprint = db::api_request_fingerprint("application/json", &body);
        let command = || {
            admission(
                &admin,
                &session,
                &target,
                route,
                &key,
                request_id,
                fingerprint,
            )
        };
        let execute = async || {
            if is_appeal {
                service
                    .update_appeal(
                        command(),
                        target,
                        status,
                        Some("  Reviewed the evidence.  "),
                    )
                    .await
            } else {
                service
                    .update_report(
                        command(),
                        target,
                        status,
                        Some("  Reviewed the evidence.  "),
                    )
                    .await
            }
        };
        let ApiMutationOutcome::Committed(response) = execute().await.unwrap() else {
            panic!("first moderation decision must commit its response");
        };
        assert_eq!(response.status, expected_status);
        let ApiMutationOutcome::Replay(replay) = execute().await.unwrap() else {
            panic!("moderation response must replay after its audit has committed");
        };
        assert_eq!(replay.request_id, request_id);
        assert_eq!(replay.status, response.status);
        assert_eq!(replay.body, response.body);
        assert_eq!(replay.headers, response.headers);
        let audits: Vec<serde_json::Value> =
            sqlx::query_scalar("SELECT details FROM audit_log WHERE request_id=$1")
                .bind(request_id)
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(audits.len(), 1);
        assert_eq!(audits[0]["outcome"], expected_outcome);
    }
    let report_state: (String, String) =
        sqlx::query_as("SELECT status,resolution FROM abuse_reports WHERE id=$1")
            .bind(report)
            .fetch_one(&pool)
            .await
            .unwrap();
    let appeal_state: (String, String) =
        sqlx::query_as("SELECT status,resolution FROM abuse_appeals WHERE id=$1")
            .bind(appeal)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        report_state,
        ("rejected".into(), "Reviewed the evidence.".into())
    );
    assert_eq!(
        appeal_state,
        ("upheld".into(), "Reviewed the evidence.".into())
    );

    let invalid_request = Uuid::new_v4();
    let invalid_key = Uuid::new_v4().to_string();
    let rejected = service
        .update_report(
            admission(
                &admin,
                &session,
                &report,
                "/api/v1/admin/reports/{id}",
                &invalid_key,
                invalid_request,
                db::api_request_fingerprint("application/json", b"invalid"),
            ),
            report,
            "rejected",
            Some("hidden\0text"),
        )
        .await
        .unwrap();
    assert!(matches!(
        rejected,
        ApiMutationOutcome::Rejected(ApiMutationRejection::BadRequest(_))
    ));
    let retained: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM api_idempotency_records WHERE request_id=$1) OR EXISTS(SELECT 1 FROM audit_log WHERE request_id=$1)",
    )
    .bind(invalid_request)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        !retained,
        "invalid moderation content must fail before admission"
    );
}
