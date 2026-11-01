use crate::db;
use northstar_operations_application::api_queries::*;
use northstar_workflows::api_queries::*;
use std::time::Duration;
use uuid::Uuid;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires an isolated PostgreSQL schema"]
async fn authorized_projection_holds_account_and_bearer_until_snapshot_finishes() {
    let url = std::env::var("TEST_DATABASE_URL").expect("isolated PostgreSQL URL");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    db::migrate(&pool).await.unwrap();
    let id = Uuid::new_v4();
    let generation: i64 = sqlx::query_scalar(
        "INSERT INTO users(id,username,password_hash,is_admin) VALUES($1,$2,'test-only',TRUE) RETURNING auth_generation",
    ).bind(id).bind(format!("query_{}", id.simple())).fetch_one(&pool).await.unwrap();
    let token = northstar_auth_postgres::users::create_api_session(&pool, id, 1)
        .await
        .unwrap();
    let service = ApiQueryService::new(PostgresApiQueryRepository::new(pool.clone()));
    let actor = || ApiReadAuthority {
        user_id: id,
        auth_generation: generation,
        session_token: &token,
    };
    assert!(service
        .sessions(
            ApiReadAuthority {
                auth_generation: generation + 1,
                ..actor()
            },
            None,
            10,
            || { panic!("a stale generation must not read process state") }
        )
        .await
        .unwrap()
        .is_none());

    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let reader = service.clone();
    let reader_token = token.clone();
    let read = tokio::spawn(async move {
        reader
            .sessions(
                ApiReadAuthority {
                    user_id: id,
                    auth_generation: generation,
                    session_token: &reader_token,
                },
                None,
                10,
                move || {
                    entered_tx.send(()).unwrap();
                    tokio::task::block_in_place(|| {
                        release_rx.recv_timeout(Duration::from_secs(10))
                    })
                    .unwrap();
                    Vec::new()
                },
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(5), entered_rx)
        .await
        .unwrap()
        .unwrap();
    for mutation in [
        "UPDATE users SET is_admin=FALSE WHERE id=$1",
        "DELETE FROM api_sessions WHERE user_id=$1",
    ] {
        let mut tx = pool.begin().await.unwrap();
        sqlx::query("SET LOCAL lock_timeout='250ms'")
            .execute(&mut *tx)
            .await
            .unwrap();
        let error = sqlx::query(mutation)
            .bind(id)
            .execute(&mut *tx)
            .await
            .unwrap_err();
        assert_eq!(
            error
                .as_database_error()
                .and_then(|error| error.code())
                .as_deref(),
            Some("55P03")
        );
        tx.rollback().await.unwrap();
    }
    release_tx.send(()).unwrap();
    let page = read.await.unwrap().unwrap().unwrap();
    assert!(page.rows.is_empty());
    assert!(page.next.is_none());

    sqlx::query("UPDATE users SET is_admin=FALSE WHERE id=$1")
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();
    assert!(service
        .sessions(actor(), None, 10, || panic!(
            "demoted administrator read process state"
        ))
        .await
        .unwrap()
        .is_none());
    assert!(service.users(actor(), None, 10).await.unwrap().is_none());
    assert!(service
        .own_reports(actor(), None, None, 10)
        .await
        .unwrap()
        .is_some());
    sqlx::query("DELETE FROM api_sessions WHERE user_id=$1")
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();
    assert!(service.principal(&token).await.unwrap().is_none());
    assert!(service
        .own_reports(actor(), None, None, 10)
        .await
        .unwrap()
        .is_none());
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
}
