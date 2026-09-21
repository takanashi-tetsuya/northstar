use super::*;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use std::str::FromStr;

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL for a disposable PostgreSQL schema"]
async fn ceremonies_are_single_use_and_key_removal_fences_sessions() {
    let options = PgConnectOptions::from_str(&std::env::var("TEST_DATABASE_URL").unwrap()).unwrap();
    let admin = PgPoolOptions::new()
        .max_connections(2)
        .connect_with(options.clone())
        .await
        .unwrap();
    let schema = format!("northstar_passkeys_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&admin)
        .await
        .unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect_with(options.options([("search_path", schema.as_str())]))
        .await
        .unwrap();
    crate::db::MIGRATOR.run(&pool).await.unwrap();
    let user = Uuid::new_v4();
    let generation: i64 = sqlx::query_scalar(
        "INSERT INTO users(id,username,password_hash)
        VALUES($1,'alice','unused') RETURNING auth_generation",
    )
    .bind(user)
    .fetch_one(&pool)
    .await
    .unwrap();
    let token = crate::db::create_api_session(&pool, user, 1).await.unwrap();
    let session = crate::auth::token_hash(&token);
    let state = serde_json::json!({"fixture":"database lifecycle; signature verification is tested separately"});
    assert!(
        challenge(&pool, user, generation, "register", Some(&[0; 32]), &state)
            .await
            .unwrap()
            .is_none()
    );
    let id = challenge(&pool, user, generation, "register", Some(&session), &state)
        .await
        .unwrap()
        .unwrap();
    assert!(consume(&pool, id, "login", None).await.unwrap().is_none());
    assert!(consume(&pool, id, "register", Some(&[0; 32]))
        .await
        .unwrap()
        .is_none());
    let (left, right) = tokio::join!(
        consume(&pool, id, "register", Some(&session)),
        consume(&pool, id, "register", Some(&session))
    );
    assert_eq!(
        usize::from(left.unwrap().is_some()) + usize::from(right.unwrap().is_some()),
        1
    );
    assert!(consume(&pool, id, "register", Some(&session))
        .await
        .unwrap()
        .is_none());
    let expired = challenge(&pool, user, generation, "login", None, &state)
        .await
        .unwrap()
        .unwrap();
    sqlx::query("UPDATE webauthn_challenges SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1")
        .bind(expired).execute(&pool).await.unwrap();
    assert!(consume(&pool, expired, "login", None)
        .await
        .unwrap()
        .is_none());

    let credential_id = Uuid::new_v4();
    let id = register(
        &pool,
        user,
        generation,
        &session,
        credential_id.as_bytes(),
        &state,
        "Laptop",
    )
    .await
    .unwrap()
    .unwrap();
    assert!(register(
        &pool,
        user,
        generation,
        &session,
        credential_id.as_bytes(),
        &state,
        "Duplicate"
    )
    .await
    .unwrap()
    .is_none());
    let old_revision = credentials(&pool, user).await.unwrap()[0].revision;
    let mut tx = pool.begin().await.unwrap();
    assert!(
        accept(&mut tx, user, generation, id, old_revision, &state, 1)
            .await
            .unwrap()
    );
    tx.commit().await.unwrap();
    let mut tx = pool.begin().await.unwrap();
    assert!(
        !accept(&mut tx, user, generation, id, old_revision, &state, 2)
            .await
            .unwrap()
    );
    let current_revision = credentials(&pool, user).await.unwrap()[0].revision;
    assert!(
        !accept(&mut tx, user, generation, id, current_revision, &state, 1)
            .await
            .unwrap()
    );
    assert!(!accept(
        &mut tx,
        user,
        generation + 1,
        id,
        current_revision,
        &state,
        2
    )
    .await
    .unwrap());
    tx.rollback().await.unwrap();
    let pending = challenge(&pool, user, generation, "login", None, &state)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        remove(&pool, user, generation, &session, id).await.unwrap(),
        Some(generation + 1)
    );
    assert!(credentials(&pool, user).await.unwrap().is_empty());
    assert!(crate::db::user_for_token(&pool, &token)
        .await
        .unwrap()
        .is_none());
    assert!(consume(&pool, pending, "login", None)
        .await
        .unwrap()
        .is_none());
    let mut tx = pool.begin().await.unwrap();
    assert!(
        !accept(&mut tx, user, generation, id, current_revision, &state, 2)
            .await
            .unwrap()
    );
    tx.rollback().await.unwrap();

    pool.close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
}
