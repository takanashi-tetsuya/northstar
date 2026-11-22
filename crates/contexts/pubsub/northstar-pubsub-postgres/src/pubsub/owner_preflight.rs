use super::affiliation::affiliation_for_bare_jid;
use super::collection::{collection_children_with_executor, collection_parents_with_executor};
use super::node::get_node_with_executor;
use anyhow::Result;
use northstar_pubsub_core::{PubSubBareJid, PubSubNodeName, PubSubOwnerPreflight};
use sqlx::PgPool;

pub async fn owner_preflight(
    pool: &PgPool,
    node: &PubSubNodeName,
    requester: &PubSubBareJid,
    include_graph: bool,
) -> Result<Option<PubSubOwnerPreflight>> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *transaction)
        .await?;
    let result =
        if let Some(node) = get_node_with_executor(&mut *transaction, node.as_str()).await? {
            let requester = requester.to_string();
            let is_owner = affiliation_for_bare_jid(&mut *transaction, node.id, &requester)
                .await?
                .as_deref()
                == Some("owner");
            let (parents, children) = if include_graph {
                let parents = collection_parents_with_executor(&mut *transaction, node.id)
                    .await?
                    .into_iter()
                    .map(|node| node.node)
                    .collect();
                let children = collection_children_with_executor(&mut *transaction, node.id)
                    .await?
                    .into_iter()
                    .map(|node| node.node)
                    .collect();
                (parents, children)
            } else {
                (Vec::new(), Vec::new())
            };
            Some(PubSubOwnerPreflight {
                node,
                is_owner,
                parents,
                children,
            })
        } else {
            None
        };
    transaction.commit().await?;
    Ok(result)
}
