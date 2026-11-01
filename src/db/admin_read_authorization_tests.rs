//! Administrative reads hold their authorization fence for the whole read transaction.
use northstar_operations_application::admin_commands::*;
use sqlx::PgPool;
use std::time::Duration;
use uuid::Uuid;

async fn database() -> PgPool {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(8)
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    pool
}

async fn insert_admin(pool: &PgPool, id: Uuid, username: &str) -> AdminActor {
    sqlx::query(
        "INSERT INTO users(id,username,password_hash,is_admin,auth_generation)
         VALUES($1,$2,'test-only',TRUE,0)",
    )
    .bind(id)
    .bind(username)
    .execute(pool)
    .await
    .unwrap();
    AdminActor::new(id, username.to_owned(), 0)
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn admin_read_snapshot_blocks_post_authorization_demotion_until_commit() {
    let pool = database().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let actor_id = Uuid::new_v4();
    let actor = insert_admin(&pool, actor_id, &format!("read-lock-{}", &suffix[..12])).await;
    let repository = crate::db::roster::RootAdminCommandRepository::new(
        pool.clone(),
        pool.clone(),
        crate::db::roster::RootRosterEffects,
    );
    let (authorized_tx, authorized_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let read = tokio::spawn(async move {
        repository
            .authorized_count_with_hook(&actor, || async move {
                authorized_tx.send(()).unwrap();
                release_rx.await.unwrap();
            })
            .await
            .unwrap()
            .expect("fresh administrator must authorize")
    });
    authorized_rx.await.unwrap();

    let mutation_pool = pool.clone();
    let (mutation_started_tx, mutation_started_rx) = tokio::sync::oneshot::channel();
    let mut demotion = tokio::spawn(async move {
        mutation_started_tx.send(()).unwrap();
        sqlx::query("UPDATE users SET is_admin=FALSE WHERE id=$1")
            .bind(actor_id)
            .execute(&mutation_pool)
            .await
            .unwrap()
            .rows_affected()
    });
    mutation_started_rx.await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut demotion)
            .await
            .is_err(),
        "demotion committed while the authorized read still held FOR SHARE"
    );

    release_tx.send(()).unwrap();
    assert!(read.await.unwrap() >= 1);
    assert_eq!(demotion.await.unwrap(), 1);
    assert!(
        !sqlx::query_scalar::<_, bool>("SELECT is_admin FROM users WHERE id=$1")
            .bind(actor_id)
            .fetch_one(&pool)
            .await
            .unwrap()
    );
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn admin_reads_reject_demotion_and_rotation_that_win_the_authorization_race() {
    let pool = database().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let actor_id = Uuid::new_v4();
    let username = format!("read-fence-{}", &suffix[..12]);
    let actor = insert_admin(&pool, actor_id, &username).await;
    let service = AdminCommandService::new(crate::db::roster::RootAdminCommandRepository::new(
        pool.clone(),
        pool.clone(),
        crate::db::roster::RootRosterEffects,
    ));

    let mut blocker = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
        .bind(actor_id)
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
    let demotion_read = {
        let service = service.clone();
        let actor = actor.clone();
        tokio::spawn(async move { service.registered_account_count(&actor).await.unwrap() })
    };
    sqlx::query("UPDATE users SET is_admin=FALSE WHERE id=$1")
        .bind(actor_id)
        .execute(&mut *blocker)
        .await
        .unwrap();
    blocker.commit().await.unwrap();
    assert_eq!(demotion_read.await.unwrap(), None);

    sqlx::query("UPDATE users SET is_admin=TRUE WHERE id=$1")
        .bind(actor_id)
        .execute(&pool)
        .await
        .unwrap();
    let mut blocker = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
        .bind(actor_id)
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
    let rotation_read = {
        let service = service.clone();
        tokio::spawn(async move { service.registered_account_count(&actor).await.unwrap() })
    };
    sqlx::query("UPDATE users SET auth_generation=auth_generation+1 WHERE id=$1")
        .bind(actor_id)
        .execute(&mut *blocker)
        .await
        .unwrap();
    blocker.commit().await.unwrap();
    assert_eq!(rotation_read.await.unwrap(), None);
    pool.close().await;
}
