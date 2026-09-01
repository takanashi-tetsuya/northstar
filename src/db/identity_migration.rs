//! Atomic RFC 7622 identity migration.
//!
//! Every durable JID-bearing subsystem participates in one PostgreSQL
//! transaction.  This is deliberately stricter than running the individual
//! migrations one after another: a collision or malformed identity anywhere
//! rolls the complete A-label-to-U-label transition back.

use anyhow::{Context, Result};
use sqlx::PgPool;

pub async fn canonicalize_all_identity_storage(pool: &PgPool, domain: &str) -> Result<()> {
    let mut transaction = pool
        .begin()
        .await
        .context("could not begin atomic RFC 7622 identity migration")?;

    // A single outer gate makes the transaction boundary explicit even though
    // the subsystem helpers retain their own stable advisory-lock keys.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 7622))")
        .bind("northstar-rfc7622-ulabel-v2")
        .execute(&mut *transaction)
        .await
        .context("could not acquire the atomic RFC 7622 identity migration gate")?;

    super::jid_identity::canonicalize_identity_storage_in_transaction(&mut transaction)
        .await
        .context("PubSub/PEP identity migration failed")?;
    super::authorization_identity::canonicalize_authorization_identity_storage_in_transaction(
        &mut transaction,
    )
    .await
    .context("authorization identity migration failed")?;
    super::push_identity::canonicalize_push_identity_storage_in_transaction(&mut transaction)
        .await
        .context("push identity migration failed")?;
    super::mix_identity::canonicalize_mix_identity_storage_in_transaction(&mut transaction)
        .await
        .context("MIX identity migration failed")?;
    super::profile_identity::canonicalize_profile_identity_storage_in_transaction(&mut transaction)
        .await
        .context("profile PEP identity migration failed")?;
    super::remaining_identity::canonicalize_remaining_identity_storage_in_transaction(
        &mut transaction,
    )
    .await
    .context("remaining durable identity metadata migration failed")?;
    super::session_identity::canonicalize_session_authorization_storage_in_transaction(
        &mut transaction,
        domain,
    )
    .await
    .context("session authorization identity migration failed")?;

    transaction
        .commit()
        .await
        .context("could not commit atomic RFC 7622 identity migration")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::Row;
    use uuid::Uuid;

    const PUBSUB_MARKER: &str = "pubsub-pep-rfc7622-ulabel-v2";
    const REMAINING_MARKER: &str = "remaining-identity-metadata-rfc7622-ulabel-v2";

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL pointing at a disposable random PostgreSQL schema"]
    async fn global_ulabel_migration_rolls_back_every_subsystem_then_retries_idempotently() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to a disposable random PostgreSQL schema");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();

        // Re-run two independently keyed subsystems as one global migration.
        // A late outbox collision must roll back the earlier PubSub rewrite and
        // both marker writes, proving that startup never exposes mixed A/U-label
        // authorization state.
        sqlx::query("DELETE FROM jid_identity_migrations WHERE migration=ANY($1)")
            .bind(vec![PUBSUB_MARKER, REMAINING_MARKER])
            .execute(&pool)
            .await
            .unwrap();
        let node_id = Uuid::new_v4();
        sqlx::query("INSERT INTO pubsub_nodes(id,node,creator_jid) VALUES($1,$2,$3)")
            .bind(node_id)
            .bind(format!("identity-migration-{}", Uuid::new_v4().simple()))
            .bind("Alice@xn--bcher-kva.example")
            .execute(&pool)
            .await
            .unwrap();

        let first_outbox = Uuid::new_v4();
        let second_outbox = Uuid::new_v4();
        let admission_key = vec![0x5a_u8; 32];
        for (id, target) in [
            (first_outbox, "xn--bcher-kva.example"),
            (second_outbox, "bücher.example"),
        ] {
            sqlx::query(
                "INSERT INTO s2s_outbox(id,target_domain,bounce_to,stanza,dedupe_hash,expires_at)
                 VALUES($1,$2,$3,'<message/>',$4,NOW()+INTERVAL '1 hour')",
            )
            .bind(id)
            .bind(target)
            .bind("Bob@xn--bcher-kva.example/Phone")
            .bind(&admission_key)
            .execute(&pool)
            .await
            .unwrap();
        }

        let error = format!(
            "{:#}",
            canonicalize_all_identity_storage(&pool, "example.test")
                .await
                .unwrap_err()
        );
        assert!(error.contains("outbox identity collision"), "{error}");
        assert_eq!(
            sqlx::query_scalar::<_, String>("SELECT creator_jid FROM pubsub_nodes WHERE id=$1",)
                .bind(node_id)
                .fetch_one(&pool)
                .await
                .unwrap(),
            "Alice@xn--bcher-kva.example"
        );
        for marker in [PUBSUB_MARKER, REMAINING_MARKER] {
            assert!(!sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM jid_identity_migrations WHERE migration=$1)",
            )
            .bind(marker)
            .fetch_one(&pool)
            .await
            .unwrap());
        }

        sqlx::query("DELETE FROM s2s_outbox WHERE id=$1")
            .bind(second_outbox)
            .execute(&pool)
            .await
            .unwrap();
        canonicalize_all_identity_storage(&pool, "example.test")
            .await
            .unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, String>("SELECT creator_jid FROM pubsub_nodes WHERE id=$1",)
                .bind(node_id)
                .fetch_one(&pool)
                .await
                .unwrap(),
            "alice@bücher.example"
        );
        let outbox = sqlx::query("SELECT target_domain,bounce_to FROM s2s_outbox WHERE id=$1")
            .bind(first_outbox)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(outbox.get::<String, _>("target_domain"), "bücher.example");
        assert_eq!(
            outbox.get::<Option<String>, _>("bounce_to").as_deref(),
            Some("bob@bücher.example/Phone")
        );

        let markers_before = sqlx::query_as::<_, (String, i64, chrono::DateTime<chrono::Utc>)>(
            "SELECT migration,transformed_rows,completed_at
               FROM jid_identity_migrations
              WHERE migration=ANY($1)
              ORDER BY migration",
        )
        .bind(vec![PUBSUB_MARKER, REMAINING_MARKER])
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(markers_before.len(), 2);
        canonicalize_all_identity_storage(&pool, "example.test")
            .await
            .unwrap();
        let markers_after = sqlx::query_as::<_, (String, i64, chrono::DateTime<chrono::Utc>)>(
            "SELECT migration,transformed_rows,completed_at
               FROM jid_identity_migrations
              WHERE migration=ANY($1)
              ORDER BY migration",
        )
        .bind(vec![PUBSUB_MARKER, REMAINING_MARKER])
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(markers_before, markers_after);
    }
}
