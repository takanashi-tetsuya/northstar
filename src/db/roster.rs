use anyhow::Result;
use sqlx::PgPool;
use sqlx::Row;
use uuid::Uuid;

pub async fn roster(
    pool: &PgPool,
    owner_id: Uuid,
) -> Result<Vec<(String, Option<String>, String, Option<String>)>> {
    let rows = sqlx::query("SELECT contact_jid, display_name, subscription, ask FROM roster_items WHERE owner_id = $1 ORDER BY contact_jid")
        .bind(owner_id).fetch_all(pool).await?;
    Ok(rows
        .iter()
        .map(|r| {
            (
                r.get("contact_jid"),
                r.get("display_name"),
                r.get("subscription"),
                r.get("ask"),
            )
        })
        .collect())
}

pub async fn roster_item(
    pool: &PgPool,
    owner_id: Uuid,
    jid: &str,
) -> Result<Option<(String, Option<String>, String, Option<String>)>> {
    let row = sqlx::query(
        "SELECT contact_jid, display_name, subscription, ask FROM roster_items WHERE owner_id = $1 AND contact_jid = $2",
    )
    .bind(owner_id)
    .bind(jid)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|row| {
        (
            row.get("contact_jid"),
            row.get("display_name"),
            row.get("subscription"),
            row.get("ask"),
        )
    }))
}

pub async fn upsert_roster(
    pool: &PgPool,
    owner_id: Uuid,
    jid: &str,
    name: Option<&str>,
) -> Result<()> {
    sqlx::query("INSERT INTO roster_items (owner_id, contact_jid, display_name) VALUES ($1, $2, $3) ON CONFLICT (owner_id, contact_jid) DO UPDATE SET display_name = EXCLUDED.display_name, updated_at = NOW()")
        .bind(owner_id).bind(jid).bind(name).execute(pool).await?;
    Ok(())
}

pub async fn delete_roster(pool: &PgPool, owner_id: Uuid, jid: &str) -> Result<()> {
    sqlx::query("DELETE FROM roster_items WHERE owner_id = $1 AND contact_jid = $2")
        .bind(owner_id)
        .bind(jid)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn update_subscription(
    pool: &PgPool,
    owner_id: Uuid,
    jid: &str,
    subscription: &str,
    ask: Option<&str>,
) -> Result<()> {
    sqlx::query("INSERT INTO roster_items (owner_id, contact_jid, subscription, ask) VALUES ($1, $2, $3, $4) ON CONFLICT (owner_id, contact_jid) DO UPDATE SET subscription = $3, ask = $4, updated_at = NOW()")
        .bind(owner_id).bind(jid).bind(subscription).bind(ask).execute(pool).await?;
    Ok(())
}

pub async fn add_pending_presence_subscription(
    pool: &PgPool,
    requester_id: Uuid,
    recipient_id: Uuid,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO pending_presence_subscriptions (requester_id, recipient_id) VALUES ($1, $2) ON CONFLICT (requester_id, recipient_id) DO UPDATE SET created_at = NOW()",
    )
    .bind(requester_id)
    .bind(recipient_id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn remove_pending_presence_subscription(
    pool: &PgPool,
    requester_id: Uuid,
    recipient_id: Uuid,
) -> Result<()> {
    sqlx::query(
        "DELETE FROM pending_presence_subscriptions WHERE requester_id = $1 AND recipient_id = $2",
    )
    .bind(requester_id)
    .bind(recipient_id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn pending_presence_subscriptions(
    pool: &PgPool,
    recipient_id: Uuid,
) -> Result<Vec<String>> {
    let rows = sqlx::query(
        "SELECT u.username FROM pending_presence_subscriptions p JOIN users u ON u.id = p.requester_id WHERE p.recipient_id = $1 ORDER BY p.created_at",
    )
    .bind(recipient_id)
    .fetch_all(pool)
    .await?;
    Ok(rows.iter().map(|row| row.get("username")).collect())
}

pub async fn add_federated_presence_pending(
    pool: &PgPool,
    recipient_id: Uuid,
    from_jid: &str,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO federated_presence_pending (recipient_id, from_jid) VALUES ($1, $2) ON CONFLICT (recipient_id, from_jid) DO UPDATE SET created_at = NOW()",
    )
    .bind(recipient_id)
    .bind(from_jid)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn remove_federated_presence_pending(
    pool: &PgPool,
    recipient_id: Uuid,
    from_jid: &str,
) -> Result<()> {
    sqlx::query("DELETE FROM federated_presence_pending WHERE recipient_id = $1 AND from_jid = $2")
        .bind(recipient_id)
        .bind(from_jid)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn federated_presence_pending(pool: &PgPool, recipient_id: Uuid) -> Result<Vec<String>> {
    let rows = sqlx::query(
        "SELECT from_jid FROM federated_presence_pending WHERE recipient_id = $1 ORDER BY created_at",
    )
    .bind(recipient_id)
    .fetch_all(pool)
    .await?;
    Ok(rows.iter().map(|row| row.get("from_jid")).collect())
}

pub async fn blocked_jids(pool: &PgPool, owner_id: Uuid) -> Result<Vec<String>> {
    let rows = sqlx::query(
        "SELECT blocked_jid FROM blocked_jids WHERE owner_id = $1 ORDER BY blocked_jid",
    )
    .bind(owner_id)
    .fetch_all(pool)
    .await?;
    Ok(rows.iter().map(|row| row.get("blocked_jid")).collect())
}

pub async fn block_jids(pool: &PgPool, owner_id: Uuid, jids: &[String]) -> Result<()> {
    let mut transaction = pool.begin().await?;
    for jid in jids {
        sqlx::query(
            "INSERT INTO blocked_jids (owner_id, blocked_jid) VALUES ($1, $2) ON CONFLICT DO NOTHING",
        )
        .bind(owner_id)
        .bind(jid)
        .execute(&mut *transaction)
        .await?;
    }
    transaction.commit().await?;
    Ok(())
}

pub async fn unblock_jids(pool: &PgPool, owner_id: Uuid, jids: Option<&[String]>) -> Result<()> {
    if let Some(jids) = jids {
        sqlx::query("DELETE FROM blocked_jids WHERE owner_id = $1 AND blocked_jid = ANY($2)")
            .bind(owner_id)
            .bind(jids)
            .execute(pool)
            .await?;
    } else {
        sqlx::query("DELETE FROM blocked_jids WHERE owner_id = $1")
            .bind(owner_id)
            .execute(pool)
            .await?;
    }
    Ok(())
}

pub async fn is_blocked(pool: &PgPool, owner_id: Uuid, candidate: &str) -> Result<bool> {
    let patterns = blocked_jids(pool, owner_id).await?;
    Ok(patterns
        .iter()
        .any(|pattern| blocked_jid_matches(pattern, candidate)))
}

fn blocked_jid_matches(pattern: &str, candidate: &str) -> bool {
    let pattern = pattern.to_ascii_lowercase();
    let candidate = candidate.to_ascii_lowercase();
    if pattern == candidate {
        return true;
    }
    if pattern.contains('@') && !pattern.contains('/') {
        return crate::state::bare_jid(&candidate) == pattern;
    }
    if !pattern.contains('@') && !pattern.contains('/') {
        return crate::state::jid_domain(&candidate).is_some_and(|domain| domain == pattern)
            || crate::state::bare_jid(&candidate) == pattern;
    }
    false
}
