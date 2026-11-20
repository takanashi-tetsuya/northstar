//! Service discovery and node-scoped self lists on read-only snapshots.

use super::{
    affiliation::affiliations_for_jid_on,
    disco::{collection_disco_snapshot_on, leaf_disco_snapshot_on},
    node::{get_node_with_executor, node_metadata_on, node_redirect_with_executor},
    subscription::{node_authorization_facts_on, subscriptions_for_jid_on},
    PgPool, Postgres, Transaction,
};
use anyhow::{Context, Result};
use northstar_pubsub_application::{
    PubSubNodeInfo, PubSubNodeInfoQuery, PubSubNodeItems, PubSubNodeItemsQuery, PubSubSelfList,
    PubSubSelfListQuery,
};
use northstar_pubsub_core::{PubSubAffiliation, PubSubNode, PubSubSubscription};

async fn begin_discovery_read(pool: &PgPool) -> Result<Transaction<'_, Postgres>> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *transaction)
        .await?;
    Ok(transaction)
}

pub async fn node_info(pool: &PgPool, query: &PubSubNodeInfoQuery<'_>) -> Result<PubSubNodeInfo> {
    let mut transaction = begin_discovery_read(pool).await?;
    let result = if let Some(node) = get_node_with_executor(&mut *transaction, query.node).await? {
        let (affiliation, subscribed) =
            node_authorization_facts_on(&mut *transaction, node.id, query.requester).await?;
        if can_retrieve(&node.access_model, affiliation.as_deref(), subscribed)? {
            let metadata = node_metadata_on(&mut *transaction, node.id).await?;
            PubSubNodeInfo::Info {
                node: Box::new(node),
                metadata,
            }
        } else {
            PubSubNodeInfo::Forbidden
        }
    } else {
        PubSubNodeInfo::Missing {
            redirect: node_redirect_with_executor(&mut *transaction, query.node, None).await?,
        }
    };
    transaction.commit().await?;
    Ok(result)
}

pub async fn node_items(
    pool: &PgPool,
    query: &PubSubNodeItemsQuery<'_>,
) -> Result<PubSubNodeItems> {
    let mut transaction = begin_discovery_read(pool).await?;
    let result = if let Some(node) = get_node_with_executor(&mut *transaction, query.node).await? {
        read_node_items(&mut transaction, &node, query.requester).await?
    } else {
        PubSubNodeItems::Missing {
            redirect: node_redirect_with_executor(&mut *transaction, query.node, None).await?,
        }
    };
    transaction.commit().await?;
    Ok(result)
}

async fn read_node_items(
    transaction: &mut Transaction<'_, Postgres>,
    node: &PubSubNode,
    requester: &str,
) -> Result<PubSubNodeItems> {
    match node.node_type.as_str() {
        "leaf" => {
            let snapshot = leaf_disco_snapshot_on(&mut **transaction, &node.node, requester)
                .await?
                .context("leaf disappeared within the discovery snapshot")?;
            if can_retrieve(
                &snapshot.access_model,
                snapshot.affiliation.as_deref(),
                snapshot.subscribed,
            )? {
                Ok(PubSubNodeItems::Leaf(snapshot))
            } else {
                Ok(PubSubNodeItems::Forbidden)
            }
        }
        "collection" => {
            let snapshot = collection_disco_snapshot_on(&mut **transaction, &node.node, requester)
                .await?
                .context("collection disappeared within the discovery snapshot")?;
            if can_retrieve(
                &snapshot.access_model,
                snapshot.affiliation.as_deref(),
                snapshot.subscribed,
            )? {
                Ok(PubSubNodeItems::Collection(snapshot))
            } else {
                Ok(PubSubNodeItems::Forbidden)
            }
        }
        _ => Ok(PubSubNodeItems::UnsupportedKind),
    }
}

pub async fn self_subscriptions(
    pool: &PgPool,
    query: &PubSubSelfListQuery<'_>,
) -> Result<PubSubSelfList<PubSubSubscription>> {
    let Some(name) = query.node else {
        let rows = subscriptions_for_jid_on(pool, query.requester, None).await?;
        return Ok(PubSubSelfList::List(
            rows.into_iter().map(Into::into).collect(),
        ));
    };
    let mut transaction = begin_discovery_read(pool).await?;
    let result = if let Some(node) = get_node_with_executor(&mut *transaction, name).await? {
        // The name is unique in this snapshot. The list SQL joins rows on n.id.
        let rows =
            subscriptions_for_jid_on(&mut *transaction, query.requester, Some(&node.node)).await?;
        PubSubSelfList::List(rows.into_iter().map(Into::into).collect())
    } else {
        PubSubSelfList::Missing {
            redirect: node_redirect_with_executor(&mut *transaction, name, None).await?,
        }
    };
    transaction.commit().await?;
    Ok(result)
}

pub async fn self_affiliations(
    pool: &PgPool,
    query: &PubSubSelfListQuery<'_>,
) -> Result<PubSubSelfList<PubSubAffiliation>> {
    let Some(name) = query.node else {
        let rows = affiliations_for_jid_on(pool, query.requester, None).await?;
        return Ok(PubSubSelfList::List(
            rows.into_iter().map(Into::into).collect(),
        ));
    };
    let mut transaction = begin_discovery_read(pool).await?;
    let result = if let Some(node) = get_node_with_executor(&mut *transaction, name).await? {
        let rows =
            affiliations_for_jid_on(&mut *transaction, query.requester, Some(&node.node)).await?;
        PubSubSelfList::List(rows.into_iter().map(Into::into).collect())
    } else {
        PubSubSelfList::Missing {
            redirect: node_redirect_with_executor(&mut *transaction, name, None).await?,
        }
    };
    transaction.commit().await?;
    Ok(result)
}

fn can_retrieve(access_model: &str, affiliation: Option<&str>, subscribed: bool) -> Result<bool> {
    let affiliation = affiliation
        .map(str::parse::<northstar_xep_0060::Affiliation>)
        .transpose()
        .map_err(|error| anyhow::anyhow!("invalid stored PubSub affiliation: {error}"))?;
    let access_model = access_model
        .parse::<northstar_xep_0060::AccessModel>()
        .map_err(|error| anyhow::anyhow!("invalid stored PubSub access model: {error}"))?;
    Ok(northstar_xep_0060::can_retrieve_pure(
        access_model,
        affiliation,
        subscribed,
    ))
}
