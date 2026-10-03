use anyhow::{Context, Result};
use sqlx::PgConnection;

/// Migration 0114 and later owner-held capabilities require the namespace's
/// actual owner OID to match CURRENT_USER, not merely effective CREATE rights
/// (including the PostgreSQL 15+ pg_database_owner pseudo-role). Check before
/// SQLx changes anything, on the same connection that will apply migrations
/// while the separate database policy lock is held. This is deliberately
/// read-only: bootstrap, migration history and runtime ACL attestation retain
/// their distinct responsibilities.
pub(super) async fn attest_schema_owner(connection: &mut PgConnection) -> Result<()> {
    let (schema, directly_owned): (Option<String>, bool) = sqlx::query_as(
        "SELECT pg_catalog.current_schema()::text,
                EXISTS (
                    SELECT 1
                      FROM pg_catalog.pg_namespace namespace
                      JOIN pg_catalog.pg_roles role ON role.oid=namespace.nspowner
                     WHERE namespace.nspname=pg_catalog.current_schema()
                       AND role.rolname=CURRENT_USER
                )",
    )
    .fetch_one(connection)
    .await
    .context("could not inspect migration schema ownership before applying migrations")?;
    validate_schema_owner(schema.as_deref(), directly_owned)
}

fn validate_schema_owner(schema: Option<&str>, directly_owned: bool) -> Result<()> {
    anyhow::ensure!(
        schema.is_some_and(|schema| schema != "information_schema" && !schema.starts_with("pg_")),
        "database migration preflight failed: select an existing non-system application schema in search_path before running migrations"
    );
    anyhow::ensure!(
        directly_owned,
        "database migration preflight failed: the application schema must be directly owned by the migration login; database ownership or CREATE privilege alone is insufficient (PostgreSQL 15+ normally assigns public to pg_database_owner). For a fresh local database, follow the explicit schema ownership bootstrap in docs/DATABASE_ROLES.md#localhost-owner-only-development-mode; production requires its separate role reconciliation. No migrations were run"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_schema_owner;

    #[test]
    fn migration_schema_preflight_requires_a_non_system_schema() {
        for schema in [
            None,
            Some("pg_catalog"),
            Some("information_schema"),
            Some("pg_toast"),
            Some("pg_temp_1"),
            Some("pg_toast_temp_1"),
        ] {
            let error = validate_schema_owner(schema, true).unwrap_err();
            assert!(error.to_string().contains("non-system application schema"));
        }
    }

    #[test]
    fn migration_schema_preflight_requires_direct_ownership() {
        for schema in [
            "public",
            "northstar_isolated_test",
            "Quoted application schema",
        ] {
            assert!(validate_schema_owner(Some(schema), true).is_ok());
            let error = validate_schema_owner(Some(schema), false).unwrap_err();
            assert!(error.to_string().contains("directly owned"));
            assert!(error.to_string().contains("pg_database_owner"));
            assert!(error.to_string().contains("No migrations were run"));
        }
    }
}
