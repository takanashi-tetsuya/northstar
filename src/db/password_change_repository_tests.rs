use northstar_abuse_policy::AbuseAction;
use northstar_abuse_policy::{AbuseConfig, PowIntent};
use northstar_auth_application::password_change::PasswordChangeCommand;
use northstar_auth_application::password_change::PasswordChangeResult;
use northstar_auth_application::password_change::PasswordChangeService;
use northstar_operations_core::api_mutations;
use northstar_operations_core::api_mutations::{
    api_request_fingerprint, ApiPrincipalKind, IdempotencyRequest,
};
use northstar_workflows::password_change_repository::*;
use std::sync::Arc;
use std::{net::IpAddr, time::Duration};
use uuid::Uuid;

async fn run_change(
    service: &PasswordChangeService<PostgresPasswordChangeRepository>,
    token: &str,
    key: &str,
    request_id: Uuid,
    current_password: &str,
    new_password: &str,
) -> PasswordChangeResult {
    let body = serde_json::json!({
        "current_password": current_password,
        "new_password": new_password,
    });
    let bytes = serde_json::to_vec(&body).unwrap();
    let intent = PowIntent::http_json_method(
        AbuseAction::PasswordChange,
        "PATCH",
        "/api/v1/me/password",
        &body,
    );
    service
        .execute(PasswordChangeCommand {
            idempotency: IdempotencyRequest {
                request_id,
                actor_id: None,
                principal_scope: token.as_bytes(),
                capacity_scope: token.as_bytes(),
                target_scope: b"",
                principal_kind: ApiPrincipalKind::User,
                method: "PATCH",
                route: "/api/v1/me/password",
                idempotency_key: key,
                request_fingerprint: api_request_fingerprint("application/json", &bytes),
                ttl_seconds: 3_600,
                lease_seconds: 180,
            },
            presented_session: token,
            current_password,
            new_password,
            proof: None,
            intent: &intent,
            peer_ip: IpAddr::from([192, 0, 2, 50]),
        })
        .await
        .unwrap()
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing at an isolated PostgreSQL database"]
async fn password_change_replays_committed_response_after_bearer_revocation() {
    let url = std::env::var("TEST_DATABASE_URL").expect("set TEST_DATABASE_URL");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(8)
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    let suffix = Uuid::new_v4().simple().to_string();
    let user = northstar_auth_postgres::users::create_user(
        &pool,
        &format!("password{}", &suffix[..10]),
        "password-before-change",
        false,
        true,
        northstar_auth_core::MIN_SCRAM_ITERATIONS,
        false,
    )
    .await
    .unwrap();
    let token = northstar_auth_postgres::users::create_api_session(&pool, user.id, 1)
        .await
        .unwrap();
    let keyring = Arc::new(
        northstar_operations_postgres::api_control::ApiControlKeyring::new(
            b"password-service-test-control-key-00001",
            None,
        )
        .unwrap(),
    );
    let guard = Arc::new(northstar_workflows::abuse_effects::persistent_guard(
        AbuseConfig {
            base_work_factor: 2,
            max_work_factor: 64,
            window: Duration::from_secs(60),
            cooldown_step: Duration::from_secs(60),
            max_wait: Duration::from_secs(900),
            message_free_burst: 6,
            approximate_max_device_seconds: 8,
        },
        pool.clone(),
        Some(b"password-service-test-abuse-key-000001"),
        None,
    ));
    let service = PasswordChangeService::new(
        PostgresPasswordChangeRepository::new(pool.clone(), keyring, guard),
        northstar_auth_core::MIN_SCRAM_ITERATIONS,
        false,
    );
    let key = format!("password-{suffix}");
    let request_id = Uuid::new_v4();
    let changed = run_change(
        &service,
        &token,
        &key,
        request_id,
        "password-before-change",
        "password-after-change",
    )
    .await;
    let PasswordChangeResult::Changed(response, account) = changed else {
        panic!("expected a committed password change");
    };
    assert_eq!(account.user_id, user.id);
    assert_eq!(response.status, 200);
    assert_eq!(response.headers, api_mutations::json_replay_headers());
    assert_eq!(
        response.body,
        br#"{"changed":true,"sessions_revoked":true}"#
    );
    assert!(
        northstar_auth_postgres::users::user_for_token(&pool, &token)
            .await
            .unwrap()
            .is_none()
    );

    let replay = run_change(
        &service,
        &token,
        &key,
        request_id,
        "password-before-change",
        "password-after-change",
    )
    .await;
    let PasswordChangeResult::Replay(replay) = replay else {
        panic!("exact response must replay after the bearer was revoked");
    };
    assert_eq!(replay.request_id, request_id);
    assert_eq!(replay.status, response.status);
    assert_eq!(replay.headers, response.headers);
    assert_eq!(replay.body, response.body);
    let new_key = format!("other-{suffix}");
    let unauthorized = run_change(
        &service,
        &token,
        &new_key,
        Uuid::new_v4(),
        "password-after-change",
        "another-new-password",
    )
    .await;
    assert!(matches!(unauthorized, PasswordChangeResult::Unauthorized));
    pool.close().await;
}
