use northstar_operations_application::operation_muc_destroy::{
    MucDestroyRepository, ValidatedMucDestroy,
};
use northstar_workflows::operation_muc_destroy_repository::PostgresMucDestroyRepository;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing at an isolated PostgreSQL database"]
async fn missing_exact_destroy_intent_rolls_back_without_audit_or_room_mutation() {
    let url = std::env::var("TEST_DATABASE_URL").expect("set TEST_DATABASE_URL");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    let operation_id = Uuid::new_v4();
    let room_jid = "absent-room@conference.example.test";
    let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE operation_id=$1")
        .bind(operation_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    let result = PostgresMucDestroyRepository::new(pool.clone())
        .commit(ValidatedMucDestroy {
            operation_id,
            request_id: Uuid::new_v4(),
            actor_id: Uuid::new_v4(),
            room_jid,
            localpart: "absent-room",
            alternate_jid: None,
            reason: None,
        })
        .await;
    let error = result.err().expect("missing intent must refuse the effect");
    assert!(error
        .to_string()
        .contains("durable MUC destroy intent is absent"));
    let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE operation_id=$1")
        .bind(operation_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(after, before);
    pool.close().await;
}
