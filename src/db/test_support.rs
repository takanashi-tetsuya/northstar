//! Isolated ordinary-role fixtures for repository command tests.
pub(crate) async fn operation_mutation_pool() -> sqlx::PgPool {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let role = std::env::var("TEST_DATABASE_ROLE").ok();
    let expected_schema = std::env::var("TEST_DATABASE_SCHEMA")
        .expect("set TEST_DATABASE_SCHEMA to the isolated mutation fixture schema");
    assert!(expected_schema
        .strip_prefix("northstar_api_operations_it_")
        .is_some_and(
            |suffix| suffix.len() == 32 && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
        ));
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .after_connect(move |connection, _| {
            let role = role.clone();
            let expected_schema = expected_schema.clone();
            Box::pin(async move {
                if let Some(role) = &role {
                    sqlx::query("SELECT pg_catalog.set_config('role',$1,FALSE)")
                        .bind(role)
                        .execute(&mut *connection)
                        .await?;
                }
                let schema: Option<String> = sqlx::query_scalar("SELECT current_schema()")
                    .fetch_one(&mut *connection).await?;
                let (current_role, superuser, bypass_rls): (String, bool, bool) = sqlx::query_as(
                    "SELECT rolname,rolsuper,rolbypassrls FROM pg_catalog.pg_roles WHERE rolname=current_user",
                ).fetch_one(&mut *connection).await?;
                if schema.as_deref() != Some(expected_schema.as_str())
                    || superuser || bypass_rls || role.as_ref().is_some_and(|role| role != &current_role)
                {
                    return Err(sqlx::Error::Protocol(
                        "mutation tests require an ordinary role and their random isolated schema on every connection".into(),
                    ));
                }
                Ok(())
            })
        })
        .connect(&url).await.unwrap();
    crate::db::migrate(&pool).await.unwrap();
    pool
}
