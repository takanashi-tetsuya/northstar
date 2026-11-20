//! Service item and options reads with transaction-local authorization.

use super::{
    affiliation::affiliation_for_bare_jid,
    collection::collection_visible_items_with_executor,
    item::get_items_with_executor,
    node::{get_node_with_executor, node_redirect_with_executor},
    subscription::{get_subscription_with_executor, subscriptions_for_bare_jid},
};
use anyhow::Result;
use northstar_pubsub_application::{
    subscription_options_precheck, PubSubCollectionItemSelection, PubSubItemQuery, PubSubItemRead,
    PubSubOptionsNode, PubSubOptionsQuery, PubSubOptionsRead, PubSubSubscriptionOptionsPrecheck,
};
use northstar_pubsub_core::item_retrieval_access;
use northstar_time::{DateTime, Utc};
use sqlx::{PgConnection, PgPool, Postgres, Transaction};

pub async fn item_read(pool: &PgPool, query: &PubSubItemQuery<'_>) -> Result<PubSubItemRead> {
    let (mut transaction, read_at) = begin_read_snapshot(pool).await?;
    let read = read_items(&mut transaction, query, read_at).await?;
    transaction.commit().await?;
    Ok(read)
}

pub async fn subscription_options_read(
    pool: &PgPool,
    query: &PubSubOptionsQuery<'_>,
) -> Result<PubSubOptionsRead> {
    let (mut transaction, read_at) = begin_read_snapshot(pool).await?;
    let read = read_options(&mut transaction, query, read_at).await?;
    transaction.commit().await?;
    Ok(read)
}

async fn begin_read_snapshot(pool: &PgPool) -> Result<(Transaction<'_, Postgres>, DateTime<Utc>)> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *transaction)
        .await?;
    // Sample the database clock in the statement that establishes the snapshot.
    let read_at = sqlx::query_scalar("SELECT statement_timestamp()")
        .fetch_one(&mut *transaction)
        .await?;
    Ok((transaction, read_at))
}

async fn read_items(
    connection: &mut PgConnection,
    query: &PubSubItemQuery<'_>,
    read_at: DateTime<Utc>,
) -> Result<PubSubItemRead> {
    let Some(node) = get_node_with_executor(&mut *connection, query.node).await? else {
        return Ok(PubSubItemRead::Missing {
            redirect: node_redirect_with_executor(connection, query.node, Some(read_at)).await?,
        });
    };
    let requester = northstar_xmpp_types::jid::canonical_bare_key(query.requester)?;
    let affiliation = affiliation_for_bare_jid(&mut *connection, node.id, &requester).await?;
    let subscriptions = subscriptions_for_bare_jid(
        &mut *connection,
        &requester,
        Some(query.node),
        Some(read_at),
    )
    .await?
    .into_iter()
    .map(Into::into)
    .collect::<Vec<_>>();
    if let Err(denial) = item_retrieval_access(
        &node.access_model,
        affiliation.as_deref(),
        &subscriptions,
        query.echoed_subid,
        read_at,
        northstar_xep_0060::item_retrieval_access,
    ) {
        return Ok(PubSubItemRead::Denied(denial));
    }

    if node.node_type == "collection" {
        return match query.collection {
            PubSubCollectionItemSelection::RsmUnsupported => {
                Ok(PubSubItemRead::CollectionRsmUnsupported)
            }
            PubSubCollectionItemSelection::BadRequest => Ok(PubSubItemRead::BadRequest),
            PubSubCollectionItemSelection::Items {
                max_items,
                max_xml_bytes,
            } => {
                let items = collection_visible_items_with_executor(
                    connection,
                    node.id,
                    &requester,
                    max_items,
                    max_xml_bytes,
                    Some(read_at),
                )
                .await?;
                Ok(PubSubItemRead::Collection {
                    items: items.into_iter().map(Into::into).collect(),
                })
            }
        };
    }
    if !node.persist_items {
        return Ok(PubSubItemRead::NonPersistent);
    }
    let Some(selection) = query.leaf else {
        return Ok(PubSubItemRead::BadRequest);
    };
    let node_limit = i64::from(node.max_items);
    let limit = selection.max_items.unwrap_or(node_limit).min(node_limit);
    let items = get_items_with_executor(connection, node.id, selection.item_ids, limit).await?;
    Ok(PubSubItemRead::Leaf {
        max_items: node.max_items,
        items: items.into_iter().map(Into::into).collect(),
    })
}

async fn read_options(
    connection: &mut PgConnection,
    query: &PubSubOptionsQuery<'_>,
    read_at: DateTime<Utc>,
) -> Result<PubSubOptionsRead> {
    let Some(node) = get_node_with_executor(&mut *connection, query.node).await? else {
        return Ok(PubSubOptionsRead::Missing {
            redirect: node_redirect_with_executor(connection, query.node, Some(read_at)).await?,
        });
    };
    let Some(subscription) =
        get_subscription_with_executor(&mut *connection, node.id, query.subscriber_jid).await?
    else {
        return Ok(PubSubOptionsRead::NotSubscribed);
    };
    let subscription = northstar_pubsub_core::PubSubSubscription::from(subscription);
    Ok(
        match subscription_options_precheck(
            subscription.is_expired_at(read_at),
            &subscription.subid,
            query.echoed_subid,
        ) {
            PubSubSubscriptionOptionsPrecheck::NotSubscribed => PubSubOptionsRead::NotSubscribed,
            PubSubSubscriptionOptionsPrecheck::InvalidSubid => PubSubOptionsRead::InvalidSubid,
            PubSubSubscriptionOptionsPrecheck::Ready => PubSubOptionsRead::Ready {
                node: Box::new(PubSubOptionsNode {
                    id: node.id,
                    node_type: node.node_type,
                    payload_type: node.payload_type,
                }),
                subscription,
            },
        },
    )
}
