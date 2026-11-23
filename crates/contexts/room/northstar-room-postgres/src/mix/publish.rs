//! MIX presence and message storage, node read authorization, event pages and avatars.

use super::*;

mod message;
mod presence;

pub(super) use self::message::matches_locked_publisher_identity;
pub use self::message::{store_mix_message, store_mix_message_inner, store_mix_message_observed};
pub use self::presence::{ensure_mix_presence, store_mix_presence, store_mix_presence_with_policy};
pub(crate) use self::presence::{refresh_probe_presence_liveness, refresh_recovery_presence};

pub async fn authorize_mix_node_read_tx(
    transaction: &mut Transaction<'_, Postgres>,
    channel_id: Uuid,
    actor: &str,
    node: &str,
) -> Result<MixReadOutcome<MixChannel>> {
    anyhow::ensure!(ALL_NODES.contains(&node), "unknown MIX node");
    let actor = canonical_user_bare(actor)?;
    let actor_domain = northstar_xmpp_types::jid::CanonicalJid::parse_bare(&actor)?
        .domainpart()
        .to_owned();
    let row = sqlx::query(
        "SELECT c.*,
                EXISTS(SELECT 1 FROM mix_participants p WHERE p.channel_id=c.id AND p.jid=$2) AS participant,
                EXISTS(SELECT 1 FROM mix_channel_roles r WHERE r.channel_id=c.id AND r.jid=$2) AS privileged,
                EXISTS(SELECT 1 FROM mix_banned b WHERE b.channel_id=c.id AND b.jid_pattern IN ($2,$3)) AS banned,
                EXISTS(SELECT 1 FROM mix_allowed a WHERE a.channel_id=c.id AND a.jid_pattern IN ($2,$3)) AS allowed
           FROM mix_channels c WHERE c.id=$1",
    )
    .bind(channel_id)
    .bind(&actor)
    .bind(actor_domain)
    .fetch_optional(&mut **transaction)
    .await?;
    let Some(row) = row else {
        return Ok(MixReadOutcome::NotFound);
    };
    let channel = channel_from_row(&row);
    let participant: bool = row.get("participant");
    let privileged: bool = row.get("privileged");
    let banned: bool = row.get("banned");
    let allowed: bool = row.get("allowed");
    let discoverable: bool = row.get("discoverable");
    let authorized = if banned && !privileged {
        false
    } else if matches!(node, NODE_CONFIG | NODE_ALLOWED | NODE_BANNED | NODE_JIDMAP) {
        privileged
    } else if node == NODE_INFO {
        participant || privileged || (discoverable && (channel.access_model == "open" || allowed))
    } else {
        participant || privileged
    };
    if authorized {
        Ok(MixReadOutcome::Found(channel))
    } else {
        Ok(MixReadOutcome::Unauthorized)
    }
}

pub async fn authorized_mix_event_page(
    pool: &PgPool,
    channel_id: Uuid,
    actor: &str,
    node: &str,
    before: Option<(DateTime<Utc>, Uuid)>,
    limit: i64,
) -> Result<MixReadOutcome<MixEventPage>> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *transaction)
        .await?;
    match authorize_mix_node_read_tx(&mut transaction, channel_id, actor, node).await? {
        MixReadOutcome::Found(_) => {}
        MixReadOutcome::Unauthorized => {
            transaction.rollback().await?;
            return Ok(MixReadOutcome::Unauthorized);
        }
        MixReadOutcome::NotFound => {
            transaction.rollback().await?;
            return Ok(MixReadOutcome::NotFound);
        }
    }
    let limit = limit.clamp(1, 200);
    let rows = if let Some((created_at, id)) = before {
        sqlx::query(
            "SELECT id,node,item_id,publisher_id,publisher_jid,payload,created_at FROM mix_events WHERE channel_id=$1 AND node=$2 AND (created_at,id)<($3,$4) ORDER BY created_at DESC,id DESC LIMIT $5",
        )
        .bind(channel_id)
        .bind(node)
        .bind(created_at)
        .bind(id)
        .bind(limit + 1)
        .fetch_all(&mut *transaction)
        .await?
    } else {
        sqlx::query(
            "SELECT id,node,item_id,publisher_id,publisher_jid,payload,created_at FROM mix_events WHERE channel_id=$1 AND node=$2 ORDER BY created_at DESC,id DESC LIMIT $3",
        )
        .bind(channel_id)
        .bind(node)
        .bind(limit + 1)
        .fetch_all(&mut *transaction)
        .await?
    };
    let events = rows
        .into_iter()
        .take(limit as usize)
        .map(|row| MixEvent {
            id: row.get("id"),
            item_id: row.get("item_id"),
            payload: row.get("payload"),
            created_at: row.get("created_at"),
        })
        .collect();
    transaction.commit().await?;
    Ok(MixReadOutcome::Found(MixEventPage { events }))
}

#[expect(
    clippy::too_many_arguments,
    reason = "the atomic avatar mutation keeps its authorization, event, renderer, and federation inputs explicit"
)]
pub async fn publish_mix_avatar(
    effects: &impl crate::effects::RoomEffects,
    pool: &PgPool,
    channel_id: Uuid,
    actor: &str,
    node: &str,
    item_id: &str,
    payload: &str,
    payloads: &dyn MixEventPayloadRenderer,
    federated: Option<&FederatedMixMutation>,
) -> Result<bool> {
    anyhow::ensure!(
        matches!(node, NODE_AVATAR_DATA | NODE_AVATAR_METADATA),
        "invalid MIX avatar node"
    );
    let actor = canonical_user_bare(actor)?;
    let (mut transaction, delivery_fence) = begin_mix_delivery_admission(pool).await?;
    guard_federated_mix_mutation_tx(&mut transaction, federated).await?;
    let channel_row = sqlx::query("SELECT * FROM mix_channels WHERE id = $1 FOR UPDATE")
        .bind(channel_id)
        .fetch_optional(&mut *transaction)
        .await?;
    let Some(channel_row) = channel_row else {
        transaction.rollback().await?;
        return Ok(false);
    };
    let authorized: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM mix_channel_roles WHERE channel_id = $1 AND jid = $2 AND role IN ('owner', 'administrator'))",
    )
    .bind(channel_id)
    .bind(&actor)
    .fetch_one(&mut *transaction)
    .await?;
    if !authorized {
        transaction.rollback().await?;
        return Ok(false);
    }
    let channel = channel_from_row(&channel_row);
    if node == NODE_AVATAR_METADATA {
        sqlx::query("DELETE FROM mix_events WHERE channel_id = $1 AND node = $2")
            .bind(channel_id)
            .bind(NODE_AVATAR_METADATA)
            .execute(&mut *transaction)
            .await?;
    }
    let event_id = store_mix_event_tx(&mut transaction, &channel, node, item_id, None, payload)
        .await?
        .context("MIX avatar event unexpectedly conflicted")?;
    if node == NODE_AVATAR_DATA {
        sqlx::query(
            "DELETE FROM mix_events WHERE channel_id = $1 AND node = $2 AND id NOT IN (SELECT id FROM mix_events WHERE channel_id = $1 AND node = $2 ORDER BY created_at DESC, id DESC LIMIT 64)",
        )
        .bind(channel_id)
        .bind(NODE_AVATAR_DATA)
        .execute(&mut *transaction)
        .await?;
    }
    enqueue_mix_node_event_tx(
        &mut transaction,
        &delivery_fence,
        MixNodeProjection {
            channel: &channel,
            node,
            item_id,
            payload: Some(payload),
            retract: false,
            event_id,
            extra_recipients: Vec::new(),
        },
        payloads,
    )
    .await?;
    finalize_federated_mix_mutation_tx(
        effects,
        &mut transaction,
        federated,
        FederatedMixSuccess::PubSubPublish {
            node: node.to_owned(),
            item_id: item_id.to_owned(),
        },
        payloads,
    )
    .await?;
    transaction.commit().await?;
    Ok(true)
}

#[allow(clippy::too_many_arguments)]
pub async fn retract_mix_avatar(
    effects: &impl crate::effects::RoomEffects,
    pool: &PgPool,
    channel_id: Uuid,
    actor: &str,
    node: &str,
    item_id: &str,
    payloads: &dyn MixEventPayloadRenderer,
    federated: Option<&FederatedMixMutation>,
) -> Result<bool> {
    anyhow::ensure!(
        matches!(node, NODE_AVATAR_DATA | NODE_AVATAR_METADATA),
        "invalid MIX avatar node"
    );
    let actor = canonical_user_bare(actor)?;
    let (mut transaction, delivery_fence) = begin_mix_delivery_admission(pool).await?;
    guard_federated_mix_mutation_tx(&mut transaction, federated).await?;
    let channel_row = sqlx::query("SELECT * FROM mix_channels WHERE id = $1 FOR UPDATE")
        .bind(channel_id)
        .fetch_optional(&mut *transaction)
        .await?;
    let Some(channel_row) = channel_row else {
        transaction.rollback().await?;
        return Ok(false);
    };
    let channel = channel_from_row(&channel_row);
    let authorized: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM mix_channel_roles WHERE channel_id = $1 AND jid = $2 AND role IN ('owner', 'administrator'))",
    )
    .bind(channel_id)
    .bind(actor)
    .fetch_one(&mut *transaction)
    .await?;
    if !authorized {
        transaction.rollback().await?;
        return Ok(false);
    }
    let deleted =
        sqlx::query("DELETE FROM mix_events WHERE channel_id = $1 AND node = $2 AND item_id = $3")
            .bind(channel_id)
            .bind(node)
            .bind(item_id)
            .execute(&mut *transaction)
            .await?
            .rows_affected();
    if deleted == 1 {
        enqueue_mix_node_event_tx(
            &mut transaction,
            &delivery_fence,
            MixNodeProjection {
                channel: &channel,
                node,
                item_id,
                payload: None,
                retract: true,
                event_id: Uuid::new_v4(),
                extra_recipients: Vec::new(),
            },
            payloads,
        )
        .await?;
    }
    finalize_federated_mix_mutation_tx(
        effects,
        &mut transaction,
        federated,
        FederatedMixSuccess::PubSubEmpty,
        payloads,
    )
    .await?;
    transaction.commit().await?;
    Ok(true)
}
