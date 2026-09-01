//! Exact RFC 7622 migration for push service authorization keys.
//!
//! Push delivery attempts reference the subscription's composite primary key.
//! Each rewrite therefore stages a canonical parent, moves its children while
//! the FK remains valid, and only then removes the legacy parent.  All rows are
//! validated and all canonical collisions are rejected before the first write.

use anyhow::{Context, Result};
#[cfg(test)]
use sqlx::PgPool;
use sqlx::{Postgres, Row, Transaction};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

const MIGRATION: &str = "push-keys-rfc7622-ulabel-v2";
const CANONICALIZER_VERSION: i32 = 2;

#[derive(Clone, Debug)]
struct SubscriptionKey {
    user_id: Uuid,
    original_service: String,
    canonical_service: String,
    node: String,
}

#[derive(Clone, Debug)]
struct AttemptKey {
    request_id: Uuid,
    user_id: Uuid,
    original_service: String,
    canonical_service: String,
    node: String,
}

fn canonical_service(table: &str, row_key: &str, value: &str) -> Result<String> {
    crate::jid::canonicalize_bare(value).map_err(|error| {
        error.context(format!(
            "push JID migration rejected invalid service identity in {table} row {row_key}: {value:?}; correct or remove this row and restart"
        ))
    })
}

/// Canonicalize the subscription/delivery parent-child graph exactly once.
#[cfg(test)]
pub async fn canonicalize_push_identity_storage(pool: &PgPool) -> Result<()> {
    let mut transaction = pool.begin().await?;
    canonicalize_push_identity_storage_in_transaction(&mut transaction).await?;
    transaction.commit().await?;
    Ok(())
}

pub(crate) async fn canonicalize_push_identity_storage_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 7622))")
        .bind(MIGRATION)
        .execute(&mut **transaction)
        .await?;

    let completed: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM jid_identity_migrations WHERE migration=$1 AND canonicalizer_version=$2)",
    )
    .bind(MIGRATION)
    .bind(CANONICALIZER_VERSION)
    .fetch_one(&mut **transaction)
    .await?;
    if completed {
        return Ok(());
    }

    sqlx::query("SET LOCAL lock_timeout = '30s'")
        .execute(&mut **transaction)
        .await?;
    sqlx::query(
        "LOCK TABLE push_subscriptions, push_delivery_attempts IN ACCESS EXCLUSIVE MODE",
    )
    .execute(&mut **transaction)
    .await
    .context(
        "timed out after 30 seconds waiting to lock the push identity graph; stop other Northstar nodes using this database, then restart the migration",
    )?;

    let subscriptions = load_subscriptions(transaction).await?;
    ensure_no_parent_collisions(&subscriptions)?;
    let attempts = load_attempts(transaction).await?;
    ensure_children_match_parents(&subscriptions, &attempts)?;

    let mut transformed = 0_i64;
    for subscription in subscriptions
        .iter()
        .filter(|row| row.original_service != row.canonical_service)
    {
        // Keep the FK valid at every statement boundary: stage the canonical
        // parent, re-key all children, then remove the legacy parent.
        let inserted = sqlx::query(
            "INSERT INTO push_subscriptions
               (user_id,service_jid,node,options,updated_at,next_notification_at,
                consecutive_failures,last_success_at)
             SELECT user_id,$2,node,options,updated_at,next_notification_at,
                    consecutive_failures,last_success_at
             FROM push_subscriptions
             WHERE user_id=$1 AND service_jid=$3 AND node=$4",
        )
        .bind(subscription.user_id)
        .bind(&subscription.canonical_service)
        .bind(&subscription.original_service)
        .bind(&subscription.node)
        .execute(&mut **transaction)
        .await?
        .rows_affected();
        anyhow::ensure!(
            inserted == 1,
            "push identity migration lost subscription parent ({}, {:?}, {:?}) while locked",
            subscription.user_id,
            subscription.original_service,
            subscription.node
        );

        let moved_children = sqlx::query(
            "UPDATE push_delivery_attempts SET service_jid=$2
             WHERE user_id=$1 AND service_jid=$3 AND node=$4",
        )
        .bind(subscription.user_id)
        .bind(&subscription.canonical_service)
        .bind(&subscription.original_service)
        .bind(&subscription.node)
        .execute(&mut **transaction)
        .await?
        .rows_affected();

        let deleted = sqlx::query(
            "DELETE FROM push_subscriptions
             WHERE user_id=$1 AND service_jid=$2 AND node=$3",
        )
        .bind(subscription.user_id)
        .bind(&subscription.original_service)
        .bind(&subscription.node)
        .execute(&mut **transaction)
        .await?
        .rows_affected();
        anyhow::ensure!(
            deleted == 1,
            "push identity migration could not retire legacy subscription parent ({}, {:?}, {:?})",
            subscription.user_id,
            subscription.original_service,
            subscription.node
        );
        transformed += 1 + i64::try_from(moved_children)?;
    }

    sqlx::query(
        "INSERT INTO jid_identity_migrations(migration,canonicalizer_version,transformed_rows) VALUES($1,$2,$3)",
    )
    .bind(MIGRATION)
    .bind(CANONICALIZER_VERSION)
    .bind(transformed)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn load_subscriptions(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<Vec<SubscriptionKey>> {
    sqlx::query(
        "SELECT user_id,service_jid,node FROM push_subscriptions ORDER BY user_id,service_jid,node",
    )
    .fetch_all(&mut **transaction)
    .await?
    .into_iter()
    .map(|row| {
        let user_id: Uuid = row.get("user_id");
        let original_service: String = row.get("service_jid");
        let node: String = row.get("node");
        let row_key = format!("{user_id}/{original_service:?}/{node:?}");
        let canonical_service = canonical_service(
            "push_subscriptions.service_jid",
            &row_key,
            &original_service,
        )?;
        Ok(SubscriptionKey {
            user_id,
            original_service,
            canonical_service,
            node,
        })
    })
    .collect()
}

async fn load_attempts(transaction: &mut Transaction<'_, Postgres>) -> Result<Vec<AttemptKey>> {
    sqlx::query(
        "SELECT request_id,user_id,service_jid,node FROM push_delivery_attempts ORDER BY request_id",
    )
    .fetch_all(&mut **transaction)
    .await?
    .into_iter()
    .map(|row| {
        let request_id: Uuid = row.get("request_id");
        let user_id: Uuid = row.get("user_id");
        let original_service: String = row.get("service_jid");
        let node: String = row.get("node");
        let row_key = request_id.to_string();
        let canonical_service = canonical_service(
            "push_delivery_attempts.service_jid",
            &row_key,
            &original_service,
        )?;
        Ok(AttemptKey {
            request_id,
            user_id,
            original_service,
            canonical_service,
            node,
        })
    })
    .collect()
}

fn ensure_no_parent_collisions(rows: &[SubscriptionKey]) -> Result<()> {
    let mut owners = BTreeMap::<(Uuid, &str, &str), &str>::new();
    for row in rows {
        let key = (
            row.user_id,
            row.canonical_service.as_str(),
            row.node.as_str(),
        );
        if let Some(previous) = owners.insert(key, row.original_service.as_str()) {
            anyhow::bail!(
                "push JID migration found a canonical subscription collision for user {} node {:?}: {:?} and {:?} both map to {:?}; resolve the duplicate subscriptions explicitly and restart",
                row.user_id,
                row.node,
                previous,
                row.original_service,
                row.canonical_service
            );
        }
    }
    Ok(())
}

fn ensure_children_match_parents(
    subscriptions: &[SubscriptionKey],
    attempts: &[AttemptKey],
) -> Result<()> {
    let parents = subscriptions
        .iter()
        .map(|row| {
            (
                (
                    row.user_id,
                    row.original_service.as_str(),
                    row.node.as_str(),
                ),
                row.canonical_service.as_str(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut requests = BTreeSet::new();
    for attempt in attempts {
        anyhow::ensure!(
            requests.insert(attempt.request_id),
            "push JID migration found duplicate delivery request {}",
            attempt.request_id
        );
        let key = (
            attempt.user_id,
            attempt.original_service.as_str(),
            attempt.node.as_str(),
        );
        let parent = parents.get(&key).context(format!(
            "push JID migration found orphan delivery attempt {}; restore its subscription parent or remove the attempt and restart",
            attempt.request_id
        ))?;
        anyhow::ensure!(
            *parent == attempt.canonical_service,
            "push JID migration found inconsistent canonical service identity for delivery attempt {}",
            attempt.request_id
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    #[tokio::test]
    #[ignore = "requires a random isolated TEST_DATABASE_URL PostgreSQL schema"]
    async fn postgres_push_graph_is_atomic_fk_safe_and_idempotent() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to a random isolated PostgreSQL schema");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .unwrap();
        db::migrate(&pool).await.unwrap();
        let user = db::create_user(
            &pool,
            &format!("pushid{}", &Uuid::new_v4().simple().to_string()[..12]),
            "test-password-long-enough",
            false,
            false,
            4096,
            false,
        )
        .await
        .unwrap();

        sqlx::query("DELETE FROM jid_identity_migrations WHERE migration=$1")
            .bind(MIGRATION)
            .execute(&pool)
            .await
            .unwrap();
        let request_id = Uuid::new_v4();
        let original = "PuSh@BÜCHER.Example";
        let canonical = crate::jid::canonicalize_bare(original).unwrap();
        sqlx::query(
            "INSERT INTO push_subscriptions(user_id,service_jid,node) VALUES($1,$2,'primary')",
        )
        .bind(user.id)
        .bind(original)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO push_delivery_attempts(request_id,user_id,service_jid,node,expires_at)
             VALUES($1,$2,$3,'primary',NOW()+INTERVAL '5 minutes')",
        )
        .bind(request_id)
        .bind(user.id)
        .bind(original)
        .execute(&pool)
        .await
        .unwrap();

        canonicalize_push_identity_storage(&pool).await.unwrap();
        let parent: String = sqlx::query_scalar(
            "SELECT service_jid FROM push_subscriptions WHERE user_id=$1 AND node='primary'",
        )
        .bind(user.id)
        .fetch_one(&pool)
        .await
        .unwrap();
        let child: String = sqlx::query_scalar(
            "SELECT service_jid FROM push_delivery_attempts WHERE request_id=$1",
        )
        .bind(request_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(parent, canonical);
        assert_eq!(child, canonical);
        let orphans: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM push_delivery_attempts AS attempt
             LEFT JOIN push_subscriptions AS subscription
               USING(user_id,service_jid,node)
             WHERE subscription.user_id IS NULL",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(orphans, 0);
        let transformed: i64 = sqlx::query_scalar(
            "SELECT transformed_rows FROM jid_identity_migrations WHERE migration=$1",
        )
        .bind(MIGRATION)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(transformed, 2);
        canonicalize_push_identity_storage(&pool).await.unwrap();

        assert!(db::enable_push_subscription(
            &pool,
            user.id,
            "push.example.test/Phone",
            "resource-is-not-a-service",
            None,
        )
        .await
        .is_err());

        sqlx::query("DELETE FROM push_delivery_attempts WHERE user_id=$1")
            .bind(user.id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM push_subscriptions WHERE user_id=$1")
            .bind(user.id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM jid_identity_migrations WHERE migration=$1")
            .bind(MIGRATION)
            .execute(&pool)
            .await
            .unwrap();
        for service in ["Case@Example.TEST", "case@example.test"] {
            sqlx::query(
                "INSERT INTO push_subscriptions(user_id,service_jid,node) VALUES($1,$2,'collision')",
            )
            .bind(user.id)
            .bind(service)
            .execute(&pool)
            .await
            .unwrap();
        }
        let error = canonicalize_push_identity_storage(&pool)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("canonical subscription collision"),
            "{error}"
        );
        let unchanged: Vec<String> = sqlx::query_scalar::<_, String>(
            "SELECT service_jid FROM push_subscriptions WHERE user_id=$1 ORDER BY service_jid",
        )
        .bind(user.id)
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(unchanged, vec!["Case@Example.TEST", "case@example.test"]);
        let marker: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM jid_identity_migrations WHERE migration=$1)",
        )
        .bind(MIGRATION)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(!marker);
    }
}
