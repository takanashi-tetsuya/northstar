use super::*;
use northstar_room_application::mix_service::{CommittedMixChange, HostedMixRefusal};
use northstar_room_core::mix::{MixChannelAddress, MixChannelId};

pub async fn destroy_mix_channel(
    effects: &impl crate::effects::RoomEffects,
    pool: &PgPool,
    channel_id: Uuid,
    actor: &str,
    payloads: &dyn MixEventPayloadRenderer,
    federated: Option<&FederatedMixMutation>,
) -> Result<CommittedMixChange<bool>> {
    let actor = canonical_user_bare(actor)?;
    let (mut transaction, delivery_fence) = begin_mix_delivery_admission(pool).await?;
    guard_federated_mix_mutation_tx(&mut transaction, federated).await?;
    let accounts =
        lock_hosted_pam_accounts_tx(&mut transaction, &MixChannelId::new(channel_id), None, None)
            .await?;
    let channel_row = sqlx::query("SELECT * FROM mix_channels WHERE id=$1 FOR UPDATE")
        .bind(channel_id)
        .fetch_optional(&mut *transaction)
        .await?;
    let Some(channel_row) = channel_row else {
        transaction.rollback().await?;
        return Err(HostedMixRefusal::MissingChannel.into());
    };
    let channel = channel_from_row(&channel_row);
    let channel_jid = channel.jid();
    let authorized: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM mix_channel_roles WHERE channel_id = $1 AND jid = $2 AND role = 'owner')",
    )
    .bind(channel_id)
    .bind(&actor)
    .fetch_one(&mut *transaction)
    .await?;
    if !authorized {
        transaction.rollback().await?;
        return Ok(CommittedMixChange {
            outcome: false,
            roster: Vec::new(),
        });
    }
    let participants = sqlx::query(
        "SELECT channel_id,participant_id,jid,nick,role,joined_at
           FROM mix_participants WHERE channel_id=$1 ORDER BY participant_id",
    )
    .bind(channel_id)
    .fetch_all(&mut *transaction)
    .await?
    .iter()
    .map(participant_from_row)
    .collect::<Vec<_>>();
    // Keep one terminal channel-state event after the authority row is gone.
    // Every current participant is an explicit recipient, independently of
    // its optional node subscriptions, and the normalized outbox stores the
    // channel address rather than depending on the deleted row.
    let info_item_id: String = sqlx::query_scalar(
        "SELECT item_id FROM mix_events
          WHERE channel_id=$1 AND node=$2
          ORDER BY created_at DESC,id DESC LIMIT 1",
    )
    .bind(channel_id)
    .bind(NODE_INFO)
    .fetch_optional(&mut *transaction)
    .await?
    .unwrap_or_else(|| channel_jid.clone());
    enqueue_mix_node_event_tx(
        &mut transaction,
        &delivery_fence,
        MixNodeProjection {
            channel: &channel,
            node: NODE_INFO,
            item_id: &info_item_id,
            payload: None,
            retract: true,
            event_id: Uuid::new_v4(),
            extra_recipients: participants,
        },
        payloads,
    )
    .await?;
    let address = MixChannelAddress::parse(&channel_jid)?;
    let removed = delete_hosted_pam_tx(&mut transaction, &address, None, None).await?;
    let roster = committed_pam_removals_tx(
        effects,
        &mut transaction,
        &address,
        &accounts,
        removed,
        true,
    )
    .await?;
    sqlx::query("DELETE FROM mix_channels WHERE id = $1")
        .bind(channel_id)
        .execute(&mut *transaction)
        .await?;
    finalize_federated_mix_mutation_tx(
        effects,
        &mut transaction,
        federated,
        FederatedMixSuccess::Destroy {
            channel: channel.localpart.clone(),
        },
        payloads,
    )
    .await?;
    transaction.commit().await?;
    Ok(CommittedMixChange {
        outcome: true,
        roster,
    })
}
