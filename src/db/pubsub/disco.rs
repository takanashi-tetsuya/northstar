//! PubSub service discovery snapshots for leaf, collection and root nodes.

use super::*;

/// Keep leaf discovery authority and item IDs on one PostgreSQL statement
/// snapshot. A configuration or affiliation change cannot split the access
/// decision from the visible item list.
pub struct LeafDiscoSnapshot {
    pub node_type: String,
    pub access_model: String,
    pub affiliation: Option<String>,
    pub subscribed: bool,
    pub item_ids: Vec<String>,
}

pub async fn leaf_disco_snapshot(
    pool: &PgPool,
    node: &str,
    requester: &str,
) -> Result<Option<LeafDiscoSnapshot>> {
    let requester = crate::jid::canonical_bare_key(requester)?;
    // The SQL gate skips item aggregation for denied requests. The service
    // still applies can_retrieve_pure to these same facts before returning IDs.
    let row = sqlx::query(
        "WITH authority AS MATERIALIZED (
             SELECT n.id,n.node_type,n.access_model,
                (SELECT a.affiliation FROM pubsub_affiliations a
                  WHERE a.node_id=n.id AND a.jid=$2) AS affiliation,
                EXISTS(SELECT 1 FROM pubsub_subscriptions s
                        WHERE s.node_id=n.id
                          AND split_part(s.jid, '/', 1)=$2
                          AND s.state='subscribed'
                          AND (s.expire IS NULL OR s.expire>statement_timestamp())) AS subscribed
               FROM pubsub_nodes n WHERE n.node=$1
         )
         SELECT authority.node_type,authority.access_model,
                authority.affiliation,authority.subscribed,
                CASE WHEN authority.node_type='leaf'
                      AND authority.affiliation IS DISTINCT FROM 'outcast'
                      AND (authority.access_model='open'
                           OR authority.affiliation IN ('owner','publisher','member')
                           OR authority.subscribed)
                     THEN ARRAY(
                    SELECT i.item_id FROM pubsub_items i
                     WHERE i.node_id=authority.id
                     ORDER BY i.created_at DESC,i.id DESC
                ) ELSE ARRAY[]::TEXT[] END AS item_ids
           FROM authority",
    )
    .bind(node)
    .bind(requester)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|row| LeafDiscoSnapshot {
        node_type: row.get("node_type"),
        access_model: row.get("access_model"),
        affiliation: row.get("affiliation"),
        subscribed: row.get("subscribed"),
        item_ids: row.get("item_ids"),
    }))
}

pub struct CollectionDiscoChild {
    pub node: String,
    pub title: Option<String>,
}

pub struct CollectionDiscoSnapshot {
    pub node_type: String,
    pub access_model: String,
    pub affiliation: Option<String>,
    pub subscribed: bool,
    pub children: Vec<CollectionDiscoChild>,
}

/// Read the parent policy and its immediate children from one statement.
/// The SQL gate avoids scanning edges for denied requests; the service checks
/// the same authority facts with can_retrieve_pure before exposing the list.
pub async fn collection_disco_snapshot(
    pool: &PgPool,
    node: &str,
    requester: &str,
) -> Result<Option<CollectionDiscoSnapshot>> {
    let requester = crate::jid::canonical_bare_key(requester)?;
    let rows = sqlx::query(
        "WITH authority AS MATERIALIZED (
             SELECT n.id,n.node_type,n.access_model,
                    (SELECT a.affiliation FROM pubsub_affiliations a
                      WHERE a.node_id=n.id AND a.jid=$2) AS affiliation,
                    EXISTS(SELECT 1 FROM pubsub_subscriptions s
                            WHERE s.node_id=n.id
                              AND split_part(s.jid, '/', 1)=$2
                              AND s.state='subscribed'
                              AND (s.expire IS NULL OR s.expire>statement_timestamp())) AS subscribed
               FROM pubsub_nodes n WHERE n.node=$1
         )
         SELECT authority.node_type,authority.access_model,
                authority.affiliation,authority.subscribed,
                child.node AS child_node,child.title AS child_title
           FROM authority
           LEFT JOIN LATERAL (
               SELECT n.node,n.title
                 FROM pubsub_collection_members e
                 JOIN pubsub_nodes n ON n.id=e.child_node_id
                WHERE e.collection_node_id=authority.id
                  AND authority.node_type='collection'
                  AND authority.affiliation IS DISTINCT FROM 'outcast'
                  AND (authority.access_model='open'
                       OR authority.affiliation IN ('owner','publisher','member')
                       OR authority.subscribed)
                ORDER BY n.node LIMIT 1000
           ) child ON TRUE
          ORDER BY child.node",
    )
    .bind(node)
    .bind(requester)
    .fetch_all(pool)
    .await?;
    let Some(first) = rows.first() else {
        return Ok(None);
    };
    let mut children = Vec::with_capacity(rows.len());
    for row in &rows {
        if let Some(node) = row.get::<Option<String>, _>("child_node") {
            children.push(CollectionDiscoChild {
                node,
                title: row.get("child_title"),
            });
        }
    }
    Ok(Some(CollectionDiscoSnapshot {
        node_type: first.get("node_type"),
        access_model: first.get("access_model"),
        affiliation: first.get("affiliation"),
        subscribed: first.get("subscribed"),
        children,
    }))
}

/// Count, cursor admission, page and index share one authorized statement
/// snapshot. A concurrent node or ACL change cannot split their results.
pub async fn root_disco_page(
    pool: &PgPool,
    requester: &str,
    cursor: Option<&str>,
    backwards: bool,
    limit: i64,
) -> Result<PubSubRootDiscoPage> {
    let requester = crate::jid::canonical_bare_key(requester)?;
    let order = if backwards { "DESC" } else { "ASC" };
    let comparison = if backwards { "<" } else { ">" };
    let sql = format!(
        "WITH visible AS MATERIALIZED (
             SELECT n.node,n.title
               FROM pubsub_nodes n
              WHERE NOT EXISTS (SELECT 1 FROM pubsub_collection_members e WHERE e.child_node_id=n.id)
                AND NOT EXISTS (SELECT 1 FROM pubsub_affiliations denied WHERE denied.node_id=n.id AND denied.jid=$1 AND denied.affiliation='outcast')
                AND (n.access_model='open'
                     OR EXISTS (SELECT 1 FROM pubsub_affiliations allowed WHERE allowed.node_id=n.id AND allowed.jid=$1 AND allowed.affiliation IN ('owner','publisher','member'))
                     OR EXISTS (SELECT 1 FROM pubsub_subscriptions s WHERE s.node_id=n.id AND split_part(s.jid,'/',1)=$1 AND s.state='subscribed' AND (s.expire IS NULL OR s.expire>NOW())))
             UNION ALL SELECT 'serverinfo',NULL::TEXT
         ), ranked AS MATERIALIZED (
             SELECT node,title,ROW_NUMBER() OVER (ORDER BY node)-1 AS ordinal
               FROM visible
         ), summary AS (
             SELECT COUNT(*) AS total,
                    ($2::TEXT IS NULL OR EXISTS(SELECT 1 FROM ranked WHERE node=$2)) AS cursor_exists
               FROM ranked
         )
         SELECT summary.total,summary.cursor_exists,page.node,page.title,page.ordinal
           FROM summary
           LEFT JOIN LATERAL (
               SELECT node,title,ordinal FROM ranked
                WHERE ($2::TEXT IS NULL OR node {comparison} $2)
                ORDER BY node {order} LIMIT $3
           ) page ON TRUE"
    );
    let rows = sqlx::query(&sql)
        .bind(requester)
        .bind(cursor)
        .bind(limit.clamp(0, 1_000))
        .fetch_all(pool)
        .await?;
    let summary = rows
        .first()
        .ok_or_else(|| anyhow::anyhow!("root disco query returned no summary"))?;
    let nodes = rows
        .iter()
        .filter_map(|row| {
            row.get::<Option<String>, _>("node")
                .map(|node| PubSubRootDiscoNode {
                    node,
                    title: row.get("title"),
                    index: row.get("ordinal"),
                })
        })
        .collect();
    Ok(PubSubRootDiscoPage {
        total: summary.get("total"),
        cursor_exists: summary.get("cursor_exists"),
        nodes,
    })
}
