//! PEP subscriptions and latest item reads for replay on an existing snapshot.

use super::{PepItem, PepPresenceSubscription};
use anyhow::Result;
use northstar_pubsub_core::PubSubAddress;
use sqlx::{postgres::PgRow, Executor, Postgres, Row};
use uuid::Uuid;

// The same resource match and cap as the existing pool-only replay read.
// Apply the cap before selecting the page or filtering to caps replay owners.
// A macro, not a const, so the composed statements stay static SQL.
macro_rules! available_subscriptions {
    () => {
        "SELECT p.owner_id, u.username, p.node FROM pep_subscriptions p JOIN users u ON u.id=p.owner_id WHERE p.state='subscribed' AND p.subscriber_jid IN ($1,$2) ORDER BY p.owner_id,p.node LIMIT 1000"
    };
}

pub async fn pep_replay_explicit_page<'e>(
    executor: impl Executor<'e, Database = Postgres>,
    requester: &PubSubAddress,
    after: Option<Uuid>,
    limit: i64,
) -> Result<(Vec<PepPresenceSubscription>, bool)> {
    // The lookahead only contributes a count. Return subscription rows for
    // the selected owners, including all their nodes in the capped set.
    let rows = sqlx::query(concat!(
        "WITH subscriptions AS (",
        available_subscriptions!(),
        "),
         owner_window AS (
             SELECT DISTINCT owner_id FROM subscriptions
             WHERE $3::uuid IS NULL OR owner_id > $3
             ORDER BY owner_id LIMIT $4
         ),
         owner_page AS (
             SELECT owner_id, count(*) OVER () > $5 AS has_more
             FROM owner_window ORDER BY owner_id LIMIT $5
         )
         SELECT s.owner_id, s.username, s.node, p.has_more
         FROM subscriptions s JOIN owner_page p ON p.owner_id = s.owner_id
         ORDER BY s.owner_id, s.node"
    ))
    .bind(requester.to_string())
    .bind(requester.bare().to_string())
    .bind(after)
    .bind(limit.saturating_add(1))
    .bind(limit)
    .fetch_all(executor)
    .await?;
    let has_more = rows.first().is_some_and(|row| row.get("has_more"));
    Ok((rows.iter().map(presence_subscription).collect(), has_more))
}

pub async fn pep_replay_caps_subscriptions<'e>(
    executor: impl Executor<'e, Database = Postgres>,
    requester: &PubSubAddress,
    owners: &[Uuid],
) -> Result<Vec<PepPresenceSubscription>> {
    let rows = sqlx::query(concat!(
        "SELECT owner_id, username, node FROM (",
        available_subscriptions!(),
        ") subscriptions
         WHERE owner_id = ANY($3::uuid[])
         ORDER BY owner_id, node"
    ))
    .bind(requester.to_string())
    .bind(requester.bare().to_string())
    .bind(owners)
    .fetch_all(executor)
    .await?;
    Ok(rows.iter().map(presence_subscription).collect())
}

fn presence_subscription(row: &PgRow) -> PepPresenceSubscription {
    PepPresenceSubscription {
        owner_id: row.get("owner_id"),
        owner_username: row.get("username"),
        node: row.get("node"),
    }
}

pub async fn pep_replay_latest_item<'e>(
    executor: impl Executor<'e, Database = Postgres>,
    owner_id: Uuid,
    node: &str,
) -> Result<Option<PepItem>> {
    let row = sqlx::query("SELECT item_id, payload, updated_at FROM pep_items WHERE owner_id=$1 AND node=$2 ORDER BY updated_at DESC, item_id DESC LIMIT $3")
        .bind(owner_id)
        .bind(node)
        .bind(1_i64)
        .fetch_optional(executor)
        .await?;
    Ok(row.map(|row| PepItem {
        item_id: row.get("item_id"),
        payload: row.get("payload"),
        updated_at: row.get("updated_at"),
    }))
}
