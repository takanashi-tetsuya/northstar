use super::*;
use northstar_room_application::mix_service::{
    FederatedMixOutcome, IssueMixInvitation, PreparedMixInvitationToken,
};
use northstar_room_core::mix::MixChannelAddress;

pub(crate) async fn execute_mix_invitation(
    effects: &impl RoomEffects,
    pool: &PgPool,
    command: &IssueMixInvitation,
    token: &PreparedMixInvitationToken,
    payloads: &dyn MixEventPayloadRenderer,
    federated: Option<&FederatedMixMutation>,
) -> Result<bool> {
    store_mix_invitation(
        effects,
        pool,
        InvitationWrite {
            channel_id: &command.channel_id,
            channel: Some(&command.channel),
            inviter: &command.inviter,
            invitee: &command.invitee,
            token: token.secret(),
            token_hash: token.hash(),
            token_id: token.id(),
            lifetime: token.lifetime(),
        },
        payloads,
        federated,
    )
    .await
}

pub(super) struct InvitationWrite<'a> {
    pub(super) channel_id: &'a MixChannelId,
    pub(super) channel: Option<&'a MixChannelAddress>,
    pub(super) inviter: &'a MixRealJid,
    pub(super) invitee: &'a MixRealJid,
    pub(super) token: &'a str,
    pub(super) token_hash: [u8; 32],
    pub(super) token_id: Uuid,
    pub(super) lifetime: northstar_time::Duration,
}

pub(super) async fn store_mix_invitation(
    effects: &impl RoomEffects,
    pool: &PgPool,
    write: InvitationWrite<'_>,
    payloads: &dyn MixEventPayloadRenderer,
    federated: Option<&FederatedMixMutation>,
) -> Result<bool> {
    let mut transaction = pool.begin().await?;
    guard_federated_mix_mutation_tx(&mut transaction, federated).await?;
    let channel = sqlx::query("SELECT * FROM mix_channels WHERE id = $1 FOR UPDATE")
        .bind(write.channel_id.as_uuid())
        .fetch_optional(&mut *transaction)
        .await?
        .as_ref()
        .map(channel_from_row);
    let authorized = if let Some(channel) = &channel {
        anyhow::ensure!(
            write
                .channel
                .is_none_or(|address| address.as_str() == channel.jid()),
            "MIX invitation channel address does not match its incarnation"
        );
        sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM mix_channel_roles WHERE channel_id = $1 AND jid = $2 AND role IN ('owner', 'administrator')) OR (SELECT allow_participant_invites AND EXISTS(SELECT 1 FROM mix_participants WHERE channel_id = $1 AND jid = $2) FROM mix_channels WHERE id = $1)",
        )
        .bind(write.channel_id.as_uuid())
        .bind(write.inviter.as_str())
        .fetch_one(&mut *transaction)
        .await?
    } else {
        false
    };
    let Some(channel) = channel.filter(|_| authorized) else {
        finalize_mix_iq(
            effects,
            &mut transaction,
            federated,
            FederatedMixOutcome::Denied {
                error_type: "auth",
                condition: "forbidden",
            },
            payloads,
        )
        .await?;
        transaction.commit().await?;
        return Ok(false);
    };
    sqlx::query("DELETE FROM mix_invitations WHERE expires_at <= NOW() OR consumed_at IS NOT NULL")
        .execute(&mut *transaction)
        .await?;
    sqlx::query(
        "INSERT INTO mix_invitations (id, channel_id, inviter_jid, invitee_jid, token_hash, expires_at) VALUES ($1, $2, $3, $4, $5, NOW() + $6::interval)",
    )
    .bind(write.token_id)
    .bind(write.channel_id.as_uuid())
    .bind(write.inviter.as_str())
    .bind(write.invitee.as_str())
    .bind(write.token_hash.as_slice())
    .bind(format!("{} seconds", write.lifetime.num_seconds().clamp(60, 86400)))
    .execute(&mut *transaction)
    .await?;
    finalize_federated_mix_mutation_tx(
        effects,
        &mut transaction,
        federated,
        FederatedMixSuccess::Invitation {
            inviter: write.inviter.as_str().to_owned(),
            invitee: write.invitee.as_str().to_owned(),
            channel: channel.jid(),
            token: write.token.to_owned(),
        },
        payloads,
    )
    .await?;
    transaction.commit().await?;
    Ok(true)
}
