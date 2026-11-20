//! Read channel or PAM admission and the selected profile in one database snapshot.

use crate::{accounts::find_enabled_user, effects::RoomEffects, mix};
use anyhow::{Context, Result};
use northstar_room_application::mix_service::{
    MixRelayProfileDenial, MixRelayProfileQuery, MixRelayProfileRequester, MixRelayProfileResult,
};
use northstar_xmpp_types::jid::{prepare_domainpart, CanonicalJid};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use MixRelayProfileDenial::{Forbidden, JidMalformed};
use MixRelayProfileResult::{Denied, RemoteRoute, TargetMissing};

pub(super) async fn read(
    pool: &PgPool,
    effects: &impl RoomEffects,
    query: MixRelayProfileQuery,
) -> Result<MixRelayProfileResult> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *transaction)
        .await?;
    let result = match &query.requester {
        MixRelayProfileRequester::ChannelParticipant {
            actor,
            local_domain,
        } => read_channel_profile(&mut transaction, effects, &query, actor, local_domain).await?,
        MixRelayProfileRequester::FederatedPam {
            authenticated_service,
        } => read_pam_profile(&mut transaction, effects, &query, authenticated_service).await?,
    };
    transaction.commit().await?;
    Ok(result)
}

async fn read_channel_profile(
    transaction: &mut Transaction<'_, Postgres>,
    effects: &impl RoomEffects,
    query: &MixRelayProfileQuery,
    actor: &CanonicalJid,
    local_domain: &str,
) -> Result<MixRelayProfileResult> {
    anyhow::ensure!(
        actor.resourcepart().is_some(),
        "MIX IQ relay requires a full participant JID"
    );
    let channel_localpart = query
        .channel
        .localpart()
        .context("MIX channel lacks a localpart")?;
    let Some(channel) = mix::mix_channel(
        &mut **transaction,
        query.channel.domainpart(),
        channel_localpart,
    )
    .await?
    else {
        return Ok(TargetMissing);
    };
    let Some(requester) =
        mix::mix_participant(&mut **transaction, channel.id, &actor.bare()).await?
    else {
        return Ok(Denied(Forbidden));
    };
    let target_id = query
        .target
        .localpart()
        .and_then(|localpart| localpart.split_once('#'))
        .and_then(|(id, _)| Uuid::parse_str(id).ok());
    let Some(target_id) = target_id else {
        return Ok(Denied(JidMalformed));
    };
    let Some(target) =
        mix::mix_participant_by_id(&mut **transaction, channel.id, target_id).await?
    else {
        return Ok(TargetMissing);
    };
    let preference = mix::mix_participant_preference(&mut **transaction, channel.id, &target.jid)
        .await?
        .unwrap_or_default();
    if preference.vcard != "allow" {
        return Ok(Denied(Forbidden));
    }
    let channel_jid = channel.jid();
    // The channel lookup used canonical JID parts and hosted participant IDs are UUIDs.
    anyhow::ensure!(
        query.target.bare() == format!("{}#{channel_jid}", target.participant_id),
        "MIX encoded target does not belong to this channel"
    );
    let mapped_target = if query.target.resourcepart().is_some() {
        let Some(source) =
            mix::mix_presence_source_jid(&mut **transaction, channel.id, &query.target.to_string())
                .await?
        else {
            return Ok(TargetMissing);
        };
        Some(source)
    } else {
        None
    };

    let local_domain = prepare_domainpart(local_domain).ok();
    let requester_jid = CanonicalJid::parse_bare(&requester.jid)?;
    if let Some(username) = requester_jid
        .localpart()
        .filter(|_| local_domain.as_deref() == Some(requester_jid.domainpart()))
    {
        if let Some(user) = find_enabled_user(&mut **transaction, username).await? {
            if effects
                .relay_is_blocked(transaction, user.id, &channel_jid)
                .await?
                || effects
                    .relay_is_blocked(transaction, user.id, &target.jid)
                    .await?
            {
                return Ok(Denied(Forbidden));
            }
        }
    }
    let target_jid_address = CanonicalJid::parse_bare(&target.jid)?;
    let target_domain = target_jid_address.domainpart();
    if local_domain.as_deref() != Some(target_domain) {
        return Ok(RemoteRoute {
            requester_participant_id: requester.participant_id,
            target_domain: target_domain.to_owned(),
            target_jid: mapped_target.unwrap_or(target.jid),
        });
    }
    let Some(username) = target_jid_address.localpart() else {
        return Ok(Denied(JidMalformed));
    };
    let Some(user) = find_enabled_user(&mut **transaction, username).await? else {
        return Ok(TargetMissing);
    };
    if effects
        .relay_is_blocked(transaction, user.id, &channel_jid)
        .await?
        || effects
            .relay_is_blocked(transaction, user.id, &requester.jid)
            .await?
    {
        return Ok(Denied(Forbidden));
    }
    effects
        .relay_profile_in_transaction(transaction, user.id, &query.kind)
        .await
}

async fn read_pam_profile(
    transaction: &mut Transaction<'_, Postgres>,
    effects: &impl RoomEffects,
    query: &MixRelayProfileQuery,
    authenticated_service: &str,
) -> Result<MixRelayProfileResult> {
    anyhow::ensure!(
        prepare_domainpart(authenticated_service)
            .is_ok_and(|service| service == query.channel.domainpart()),
        "federated MIX IQ source service is not authenticated"
    );
    let Some(username) = query.target.localpart() else {
        return Ok(Denied(JidMalformed));
    };
    let Some(user) = find_enabled_user(&mut **transaction, username).await? else {
        return Ok(TargetMissing);
    };
    let channel_jid = query.channel.bare();
    if !mix::joined_pam_membership(transaction, user.id, &channel_jid).await?
        || effects
            .relay_is_blocked(transaction, user.id, &channel_jid)
            .await?
    {
        return Ok(Denied(Forbidden));
    }
    effects
        .relay_profile_in_transaction(transaction, user.id, &query.kind)
        .await
}
