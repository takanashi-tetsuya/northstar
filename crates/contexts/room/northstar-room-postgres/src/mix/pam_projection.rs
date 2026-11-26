use super::*;
use northstar_room_application::mix_service::{
    CommittedMixRosterDelta, HostedMixRefusal, MixAccount,
};
use northstar_room_core::mix::{
    MixChannelAddress, MixChannelId, MixLocalParticipantId, MixRealJid,
};

pub(super) async fn lock_pam_accounts_tx(
    transaction: &mut Transaction<'_, Postgres>,
    users: &[Uuid],
) -> Result<BTreeMap<Uuid, (MixAccount, bool)>> {
    Ok(lock_pam_accounts_with_generation_tx(transaction, users)
        .await?
        .into_iter()
        .map(|(id, (account, disabled, _))| (id, (account, disabled)))
        .collect())
}

pub(super) async fn lock_pam_accounts_with_generation_tx(
    transaction: &mut Transaction<'_, Postgres>,
    users: &[Uuid],
) -> Result<BTreeMap<Uuid, (MixAccount, bool, i64)>> {
    if users.is_empty() {
        return Ok(BTreeMap::new());
    }
    let rows = sqlx::query(
        "SELECT id,username,is_disabled,auth_generation FROM northstar_lock_user_rows_update($1)",
    )
    .bind(users)
    .fetch_all(&mut **transaction)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| {
            let account = MixAccount {
                id: row.get("id"),
                username: row.get("username"),
            };
            (
                account.id,
                (account, row.get("is_disabled"), row.get("auth_generation")),
            )
        })
        .collect())
}

pub(super) async fn lock_hosted_pam_accounts_tx(
    transaction: &mut Transaction<'_, Postgres>,
    channel: &MixChannelId,
    actor: Option<&MixRealJid>,
    explicit_user: Option<Uuid>,
) -> Result<BTreeMap<Uuid, (MixAccount, bool)>> {
    let mut users = hosted_pam_candidates_tx(transaction, channel, actor).await?;
    users.extend(explicit_user);
    lock_pam_accounts_tx(transaction, &users).await
}

pub(super) async fn hosted_pam_candidates_tx(
    transaction: &mut Transaction<'_, Postgres>,
    channel: &MixChannelId,
    actor: Option<&MixRealJid>,
) -> Result<Vec<Uuid>> {
    sqlx::query_scalar(
        "SELECT pam.user_id FROM mix_channels channel
           JOIN mix_pam_memberships pam ON pam.channel_jid=channel.localpart || '@' || channel.service_domain
          WHERE channel.id=$1 AND ($2::text IS NULL OR EXISTS (
              SELECT 1 FROM mix_participants participant
               WHERE participant.channel_id=channel.id AND participant.jid=$2
                 AND participant.participant_id::text=pam.participant_id)) ORDER BY pam.user_id",
    )
    .bind(channel.as_uuid())
    .bind(actor.map(MixRealJid::as_str))
    .fetch_all(&mut **transaction)
    .await
    .map_err(Into::into)
}

pub(super) fn pam_account_matches(
    account: &MixAccount,
    disabled: bool,
    actor: &MixRealJid,
) -> bool {
    !disabled
        && actor
            .as_str()
            .split_once('@')
            .is_some_and(|(name, _)| name == account.username)
}

pub(super) fn hosted_pam_users(
    accounts: &BTreeMap<Uuid, (MixAccount, bool)>,
    actor: &MixRealJid,
    explicit_user: Option<Uuid>,
) -> Result<Vec<Uuid>> {
    let username = actor.as_str().split_once('@').map(|(name, _)| name);
    if explicit_user.is_some_and(|id| {
        !accounts
            .get(&id)
            .is_some_and(|(account, disabled)| pam_account_matches(account, *disabled, actor))
    }) || accounts
        .values()
        .any(|(account, disabled)| *disabled && username == Some(account.username.as_str()))
    {
        return Err(HostedMixRefusal::AccountChanged.into());
    }
    Ok(accounts
        .values()
        .filter(|(account, disabled)| pam_account_matches(account, *disabled, actor))
        .map(|(account, _)| account.id)
        .collect())
}

pub(super) async fn hosted_subscription_nodes_tx(
    transaction: &mut Transaction<'_, Postgres>,
    channel: &MixChannelId,
    participant: &MixLocalParticipantId,
) -> Result<Vec<String>> {
    sqlx::query_scalar(
        "SELECT node FROM mix_subscriptions WHERE channel_id = $1 AND participant_id = $2 ORDER BY node",
    )
    .bind(channel.as_uuid())
    .bind(participant.as_uuid())
    .fetch_all(&mut **transaction)
    .await
    .map_err(Into::into)
}

pub(super) async fn mirror_hosted_pam_subscriptions_tx(
    transaction: &mut Transaction<'_, Postgres>,
    channel: &MixChannelAddress,
    participant: &MixLocalParticipantId,
    users: &[Uuid],
    nodes: &[String],
) -> Result<()> {
    if users.is_empty() {
        return Ok(());
    }
    let memberships: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM mix_pam_memberships WHERE channel_jid=$1 AND participant_id=$2
           AND user_id=ANY($3) AND state='joined' ORDER BY id FOR UPDATE",
    )
    .bind(channel.as_str())
    .bind(participant.to_string())
    .bind(users)
    .fetch_all(&mut **transaction)
    .await?;
    if memberships.is_empty() {
        return Ok(());
    }
    sqlx::query(
        "DELETE FROM mix_pam_subscriptions WHERE membership_id=ANY($1) AND NOT (node=ANY($2))",
    )
    .bind(&memberships)
    .bind(nodes)
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "INSERT INTO mix_pam_subscriptions (membership_id,node)
         SELECT membership_id,node FROM unnest($1::uuid[]) AS membership(membership_id)
          CROSS JOIN unnest($2::text[]) AS subscription(node) ON CONFLICT DO NOTHING",
    )
    .bind(&memberships)
    .bind(nodes)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

pub(super) async fn delete_hosted_pam_tx(
    transaction: &mut Transaction<'_, Postgres>,
    channel: &MixChannelAddress,
    participant: Option<&MixLocalParticipantId>,
    users: Option<&[Uuid]>,
) -> Result<Vec<Uuid>> {
    if users.is_some_and(<[Uuid]>::is_empty) {
        return Ok(Vec::new());
    }
    sqlx::query_scalar(
        "DELETE FROM mix_pam_memberships WHERE channel_jid=$1
           AND ($2::text IS NULL OR participant_id=$2)
           AND ($3::uuid[] IS NULL OR user_id=ANY($3)) RETURNING user_id",
    )
    .bind(channel.as_str())
    .bind(participant.map(ToString::to_string))
    .bind(users)
    .fetch_all(&mut **transaction)
    .await
    .map_err(Into::into)
}

pub(super) async fn committed_pam_removals_tx(
    effects: &impl crate::effects::RoomEffects,
    transaction: &mut Transaction<'_, Postgres>,
    channel: &MixChannelAddress,
    accounts: &BTreeMap<Uuid, (MixAccount, bool)>,
    mut removed: Vec<Uuid>,
    ensure_tombstone: bool,
) -> Result<Vec<CommittedMixRosterDelta>> {
    removed.sort_unstable();
    let mut roster = Vec::new();
    for user in removed {
        let (account, _) = accounts
            .get(&user)
            .context("removed MIX-PAM account was not locked")?;
        let change =
            match delete_mix_roster_tx(effects, transaction, user, channel.as_str()).await? {
                None if ensure_tombstone => {
                    Some(record_mix_roster_removal_tx(effects, transaction, user, channel).await?)
                }
                change => change,
            };
        if let Some(change) = change {
            roster.push(CommittedMixRosterDelta::new(account.clone(), change, None));
        }
    }
    Ok(roster)
}

pub(super) async fn record_mix_roster_removal_tx(
    effects: &impl crate::effects::RoomEffects,
    transaction: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    contact: &MixChannelAddress,
) -> Result<northstar_roster_core::RosterChange> {
    let version: i64 = sqlx::query_scalar("SELECT northstar_user_bump_roster_version($1)")
        .bind(user_id)
        .fetch_one(&mut **transaction)
        .await?;
    effects
        .record_roster_change(transaction, user_id, version, contact.as_str(), true)
        .await
}
