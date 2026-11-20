//! PEP projections shared by standalone queries and read-only snapshots.

use super::pep::{PepNodeConfig, PepSubscription, PEP_MAX_ITEMS};
use anyhow::Result;
use sqlx::{Executor, PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

pub async fn begin_pep_snapshot(pool: &PgPool) -> Result<Transaction<'_, Postgres>> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *transaction)
        .await?;
    Ok(transaction)
}

pub async fn pep_node<'e>(
    executor: impl Executor<'e, Database = Postgres>,
    owner_id: Uuid,
    node: &str,
) -> Result<Option<PepNodeConfig>> {
    let row = sqlx::query(
        "SELECT access_model, max_items, persist_items, send_last_published_item, deliver_notifications, roster_groups_allowed, access_whitelist FROM pep_nodes WHERE owner_id = $1 AND node = $2",
    )
    .bind(owner_id)
    .bind(node)
    .fetch_optional(executor)
    .await?;
    Ok(row.map(|row| PepNodeConfig {
        access_model: row.get("access_model"),
        max_items: row.get("max_items"),
        persist_items: row.get("persist_items"),
        send_last_published_item: row.get("send_last_published_item"),
        deliver_notifications: row.get("deliver_notifications"),
        roster_groups_allowed: row.get("roster_groups_allowed"),
        access_whitelist: row.get("access_whitelist"),
    }))
}

pub async fn pep_nodes<'e>(
    executor: impl Executor<'e, Database = Postgres>,
    owner_id: Uuid,
) -> Result<Vec<String>> {
    let rows = sqlx::query("SELECT node FROM pep_nodes WHERE owner_id = $1 ORDER BY node")
        .bind(owner_id)
        .fetch_all(executor)
        .await?;
    Ok(rows.iter().map(|row| row.get("node")).collect())
}

pub async fn pep_items<'e>(
    executor: impl Executor<'e, Database = Postgres>,
    owner_id: Uuid,
    node: &str,
    item_id: Option<&str>,
    limit: i64,
) -> Result<Vec<(String, String)>> {
    let rows = sqlx::query("SELECT item_id, payload FROM pep_items WHERE owner_id = $1 AND node = $2 AND ($3::text IS NULL OR item_id = $3) ORDER BY updated_at DESC LIMIT $4")
        .bind(owner_id)
        .bind(node)
        .bind(item_id)
        .bind(limit.clamp(1, i64::from(PEP_MAX_ITEMS)))
        .fetch_all(executor)
        .await?;
    Ok(rows
        .iter()
        .map(|row| (row.get("item_id"), row.get("payload")))
        .collect())
}

pub async fn pep_items_by_ids<'e>(
    executor: impl Executor<'e, Database = Postgres>,
    owner_id: Uuid,
    node: &str,
    item_ids: &[String],
    limit: i64,
) -> Result<Vec<(String, String)>> {
    let rows = sqlx::query(
        "SELECT item_id, payload FROM pep_items WHERE owner_id=$1 AND node=$2 AND item_id=ANY($3) ORDER BY updated_at DESC, item_id DESC LIMIT $4",
    )
    .bind(owner_id)
    .bind(node)
    .bind(item_ids)
    .bind(limit.clamp(1, i64::from(PEP_MAX_ITEMS)))
    .fetch_all(executor)
    .await?;
    Ok(rows
        .iter()
        .map(|row| (row.get("item_id"), row.get("payload")))
        .collect())
}

pub async fn pep_subscribers<'e>(
    executor: impl Executor<'e, Database = Postgres>,
    owner_id: Uuid,
    node: &str,
) -> Result<Vec<PepSubscription>> {
    let rows = sqlx::query("SELECT subscriber_jid, subid FROM pep_subscriptions WHERE owner_id=$1 AND node=$2 AND state='subscribed' ORDER BY subscriber_jid LIMIT 10000")
        .bind(owner_id)
        .bind(node)
        .fetch_all(executor)
        .await?;
    Ok(rows
        .iter()
        .map(|row| PepSubscription {
            jid: row.get("subscriber_jid"),
            subid: row.get("subid"),
        })
        .collect())
}
