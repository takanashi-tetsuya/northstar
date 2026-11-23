use super::*;
use northstar_room_core::mix::{MixClock, MixRealJid, SystemMixClock};

#[allow(clippy::too_many_arguments)]
pub async fn create_mix_channel(
    effects: &impl crate::effects::RoomEffects,
    pool: &PgPool,
    service_domain: &str,
    requested_localpart: Option<&str>,
    creator_jid: &str,
    max_channels_per_owner: i64,
    payloads: &dyn MixEventPayloadRenderer,
    federated: Option<&FederatedMixMutation>,
) -> Result<(CreateChannelOutcome, String)> {
    let service_domain = canonical_service_domain(service_domain)?;
    let creator_jid = MixRealJid::parse(creator_jid)?;
    create_mix_channel_at(
        effects,
        pool,
        &service_domain,
        requested_localpart,
        &creator_jid,
        max_channels_per_owner,
        SystemMixClock.now_utc(),
        payloads,
        federated,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn create_mix_channel_at(
    effects: &impl crate::effects::RoomEffects,
    pool: &PgPool,
    service_domain: &str,
    requested_localpart: Option<&str>,
    creator_jid: &MixRealJid,
    max_channels_per_owner: i64,
    item_timestamp: DateTime<Utc>,
    payloads: &dyn MixEventPayloadRenderer,
    federated: Option<&FederatedMixMutation>,
) -> Result<(CreateChannelOutcome, String)> {
    let service_domain = canonical_service_domain(service_domain)?;
    let creator_jid = creator_jid.as_str();
    let item_id = mix_timestamp_item_id(item_timestamp);
    let discoverable = requested_localpart.is_some();
    let localpart = match requested_localpart {
        Some(value) => canonical_channel_localpart(value)?,
        None => Uuid::new_v4().simple().to_string(),
    };
    let mut transaction = pool.begin().await?;
    guard_federated_mix_mutation_tx(&mut transaction, federated).await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(creator_jid)
        .execute(&mut *transaction)
        .await?;
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM mix_channels WHERE creator_jid = $1")
        .bind(creator_jid)
        .fetch_one(&mut *transaction)
        .await?;
    if count >= max_channels_per_owner.max(1) {
        transaction.rollback().await?;
        return Ok((CreateChannelOutcome::QuotaExceeded, localpart));
    }
    let id = Uuid::new_v4();
    let inserted = sqlx::query(
        "INSERT INTO mix_channels (id, service_domain, localpart, creator_jid, discoverable) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (service_domain, localpart) DO NOTHING",
    )
    .bind(id)
    .bind(&service_domain)
    .bind(&localpart)
    .bind(creator_jid)
    .bind(discoverable)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    if inserted == 0 {
        transaction.rollback().await?;
        return Ok((CreateChannelOutcome::Conflict, localpart));
    }
    sqlx::query("INSERT INTO mix_channel_roles (channel_id, jid, role) VALUES ($1, $2, 'owner')")
        .bind(id)
        .bind(creator_jid)
        .execute(&mut *transaction)
        .await?;
    let channel_row = sqlx::query("SELECT * FROM mix_channels WHERE id = $1")
        .bind(id)
        .fetch_one(&mut *transaction)
        .await?;
    let channel = channel_from_row(&channel_row);
    let _ = store_mix_event_tx(
        &mut transaction,
        &channel,
        NODE_INFO,
        &item_id,
        None,
        &payloads.info_payload(&channel),
    )
    .await?;
    let _ = store_mix_event_tx(
        &mut transaction,
        &channel,
        NODE_CONFIG,
        &item_id,
        None,
        &payloads.config_payload(
            &channel,
            creator_jid,
            &BTreeSet::from([creator_jid.to_owned()]),
            &BTreeSet::new(),
        ),
    )
    .await?;
    finalize_federated_mix_mutation_tx(
        effects,
        &mut transaction,
        federated,
        FederatedMixSuccess::Create {
            channel: localpart.clone(),
        },
        payloads,
    )
    .await?;
    transaction.commit().await?;
    Ok((CreateChannelOutcome::Created(id), localpart))
}
