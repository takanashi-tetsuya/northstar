use anyhow::Result;
use sqlx::PgPool;
use sqlx::Row;
use uuid::Uuid;

pub const PEP_MAX_ITEMS: i32 = 100;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PepNodeConfig {
    pub access_model: String,
    pub max_items: i32,
}

pub async fn pep_node(pool: &PgPool, owner_id: Uuid, node: &str) -> Result<Option<PepNodeConfig>> {
    let row = sqlx::query(
        "SELECT access_model, max_items FROM pep_nodes WHERE owner_id = $1 AND node = $2",
    )
    .bind(owner_id)
    .bind(node)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|row| PepNodeConfig {
        access_model: row.get("access_model"),
        max_items: row.get("max_items"),
    }))
}

#[derive(Debug)]
pub struct PushSubscription {
    pub service_jid: String,
    pub node: String,
    pub options: Option<String>,
}

/// Atomically publishes a batch and applies the node's retention policy.
///
/// `false` means an explicit publish-options precondition did not match the
/// existing node. No item in the batch is written in that case.
pub async fn publish_pep_items(
    pool: &PgPool,
    owner_id: Uuid,
    node: &str,
    requested: PepNodeConfig,
    enforce_preconditions: bool,
    items: &[(&str, &str)],
) -> Result<bool> {
    let mut transaction = pool.begin().await?;
    sqlx::query(
        "INSERT INTO pep_nodes (owner_id, node, access_model, max_items) VALUES ($1, $2, $3, $4) ON CONFLICT (owner_id, node) DO NOTHING",
    )
    .bind(owner_id)
    .bind(node)
    .bind(&requested.access_model)
    .bind(requested.max_items)
    .execute(&mut *transaction)
    .await?;
    let actual = sqlx::query(
        "SELECT access_model, max_items FROM pep_nodes WHERE owner_id = $1 AND node = $2 FOR UPDATE",
    )
    .bind(owner_id)
    .bind(node)
    .fetch_one(&mut *transaction)
    .await?;
    let actual = PepNodeConfig {
        access_model: actual.get("access_model"),
        max_items: actual.get("max_items"),
    };
    if enforce_preconditions && actual != requested {
        transaction.rollback().await?;
        return Ok(false);
    }
    for (item_id, payload) in items {
        sqlx::query("INSERT INTO pep_items (owner_id, node, item_id, payload) VALUES ($1, $2, $3, $4) ON CONFLICT (owner_id, node, item_id) DO UPDATE SET payload = EXCLUDED.payload, updated_at = NOW()")
            .bind(owner_id).bind(node).bind(item_id).bind(payload).execute(&mut *transaction).await?;
    }
    sqlx::query(
        "DELETE FROM pep_items WHERE owner_id = $1 AND node = $2 AND item_id NOT IN (SELECT item_id FROM pep_items WHERE owner_id = $1 AND node = $2 ORDER BY updated_at DESC, item_id DESC LIMIT $3)",
    )
    .bind(owner_id)
    .bind(node)
    .bind(actual.max_items)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(true)
}

pub async fn retract_pep_items(
    pool: &PgPool,
    owner_id: Uuid,
    node: &str,
    item_ids: &[&str],
) -> Result<Option<u64>> {
    let mut transaction = pool.begin().await?;
    let exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM pep_nodes WHERE owner_id = $1 AND node = $2)",
    )
    .bind(owner_id)
    .bind(node)
    .fetch_one(&mut *transaction)
    .await?;
    if !exists {
        transaction.rollback().await?;
        return Ok(None);
    }
    let result = sqlx::query(
        "DELETE FROM pep_items WHERE owner_id = $1 AND node = $2 AND item_id = ANY($3)",
    )
    .bind(owner_id)
    .bind(node)
    .bind(item_ids)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(Some(result.rows_affected()))
}

pub async fn pep_nodes(pool: &PgPool, owner_id: Uuid) -> Result<Vec<String>> {
    let rows = sqlx::query("SELECT node FROM pep_nodes WHERE owner_id = $1 ORDER BY node")
        .bind(owner_id)
        .fetch_all(pool)
        .await?;
    Ok(rows.iter().map(|r| r.get("node")).collect())
}

pub fn default_pep_node_config(node: &str) -> PepNodeConfig {
    match node {
        "urn:xmpp:omemo:2:devices" | "eu.siacs.conversations.axolotl.devicelist" => PepNodeConfig {
            access_model: "open".to_owned(),
            max_items: 1,
        },
        "urn:xmpp:omemo:2:bundles" => PepNodeConfig {
            access_model: "open".to_owned(),
            max_items: PEP_MAX_ITEMS,
        },
        node if node.starts_with("eu.siacs.conversations.axolotl.bundles") => PepNodeConfig {
            access_model: "open".to_owned(),
            max_items: PEP_MAX_ITEMS,
        },
        _ => PepNodeConfig {
            access_model: "presence".to_owned(),
            max_items: 100,
        },
    }
}

pub async fn pep_items(
    pool: &PgPool,
    owner_id: Uuid,
    node: &str,
    item_id: Option<&str>,
    limit: i64,
) -> Result<Vec<(String, String)>> {
    let rows = sqlx::query("SELECT item_id, payload FROM pep_items WHERE owner_id = $1 AND node = $2 AND ($3::text IS NULL OR item_id = $3) ORDER BY updated_at DESC LIMIT $4")
        .bind(owner_id).bind(node).bind(item_id).bind(limit.clamp(1, 100)).fetch_all(pool).await?;
    Ok(rows
        .iter()
        .map(|r| (r.get("item_id"), r.get("payload")))
        .collect())
}

pub async fn set_vcard(pool: &PgPool, user_id: Uuid, payload: &str) -> Result<()> {
    sqlx::query(
        "INSERT INTO vcards (user_id, payload) VALUES ($1, $2) ON CONFLICT (user_id) DO UPDATE SET payload = EXCLUDED.payload, updated_at = NOW()",
    )
    .bind(user_id)
    .bind(payload)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn vcard(pool: &PgPool, user_id: Uuid) -> Result<Option<String>> {
    sqlx::query_scalar("SELECT payload FROM vcards WHERE user_id = $1")
        .bind(user_id)
        .fetch_optional(pool)
        .await
        .map_err(Into::into)
}

pub async fn enable_push(
    pool: &PgPool,
    user_id: Uuid,
    service_jid: &str,
    node: &str,
    options: Option<&str>,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO push_subscriptions (user_id, service_jid, node, options) VALUES ($1, $2, $3, $4) ON CONFLICT (user_id, service_jid, node) DO UPDATE SET options = EXCLUDED.options, updated_at = NOW()",
    )
    .bind(user_id)
    .bind(service_jid)
    .bind(node)
    .bind(options)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn disable_push(
    pool: &PgPool,
    user_id: Uuid,
    service_jid: &str,
    node: Option<&str>,
) -> Result<()> {
    sqlx::query(
        "DELETE FROM push_subscriptions WHERE user_id = $1 AND service_jid = $2 AND ($3::text IS NULL OR node = $3)",
    )
    .bind(user_id)
    .bind(service_jid)
    .bind(node)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn push_subscriptions(pool: &PgPool, user_id: Uuid) -> Result<Vec<PushSubscription>> {
    let rows = sqlx::query(
        "SELECT service_jid, node, options FROM push_subscriptions WHERE user_id = $1 ORDER BY service_jid, node",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .iter()
        .map(|row| PushSubscription {
            service_jid: row.get("service_jid"),
            node: row.get("node"),
            options: row.get("options"),
        })
        .collect())
}
