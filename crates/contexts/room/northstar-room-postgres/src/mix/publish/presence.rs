use super::*;
use northstar_room_application::mix_service::{RecoveryEpoch, RecoveryPresenceSource};
use northstar_room_core::mix::MixChannelId;

pub async fn store_mix_presence(
    pool: &PgPool,
    channel_id: Uuid,
    actor_bare: &str,
    actor_full: &str,
    payload: &str,
    unavailable: bool,
    payloads: &dyn MixEventPayloadRenderer,
) -> Result<PresenceOutcome> {
    store_mix_presence_with_policy(
        pool,
        channel_id,
        actor_bare,
        actor_full,
        payload,
        unavailable,
        false,
        payloads,
    )
    .await
}

/// Refresh this resource's liveness, publishing conservative presence only
/// when it has no authoritative presence item.
pub async fn ensure_mix_presence(
    pool: &PgPool,
    channel_id: Uuid,
    actor_bare: &str,
    actor_full: &str,
    payload: &str,
    payloads: &dyn MixEventPayloadRenderer,
) -> Result<PresenceOutcome> {
    store_mix_presence_with_policy(
        pool, channel_id, actor_bare, actor_full, payload, false, true, payloads,
    )
    .await
}

#[expect(
    clippy::too_many_arguments,
    reason = "the MIX presence transaction keeps identity, payload, availability, and replacement policy explicit"
)]
pub async fn store_mix_presence_with_policy(
    pool: &PgPool,
    channel_id: Uuid,
    actor_bare: &str,
    actor_full: &str,
    payload: &str,
    unavailable: bool,
    only_if_absent: bool,
    payloads: &dyn MixEventPayloadRenderer,
) -> Result<PresenceOutcome> {
    let actor_bare = canonical_user_bare(actor_bare)?;
    let actor_full = northstar_xmpp_types::jid::canonicalize(actor_full)?;
    anyhow::ensure!(
        northstar_xmpp_types::jid::canonical_bare_key(&actor_full)? == actor_bare,
        "MIX presence full JID does not belong to participant"
    );
    anyhow::ensure!(payload.len() <= 1_048_576, "MIX presence payload too large");
    let policy = if only_if_absent {
        PresenceWrite::Ensure {
            epoch: None,
            unavailable,
        }
    } else {
        PresenceWrite::Explicit { unavailable }
    };
    write_mix_presence(
        pool,
        channel_id,
        &actor_bare,
        &actor_full,
        payload,
        policy,
        payloads,
    )
    .await
}

pub(crate) async fn refresh_recovery_presence(
    pool: &PgPool,
    epoch: RecoveryEpoch,
    channel: &MixChannelId,
    source: &RecoveryPresenceSource,
    payloads: &dyn MixEventPayloadRenderer,
) -> Result<PresenceOutcome> {
    write_mix_presence(
        pool,
        channel.as_uuid(),
        source.participant().as_str(),
        &source.full().to_string(),
        "",
        PresenceWrite::Ensure {
            epoch: Some(epoch),
            unavailable: false,
        },
        payloads,
    )
    .await
}

pub(crate) async fn refresh_probe_presence_liveness(
    pool: &PgPool,
    channel: &MixChannelId,
    source: &RecoveryPresenceSource,
    payloads: &dyn MixEventPayloadRenderer,
) -> Result<PresenceOutcome> {
    write_mix_presence(
        pool,
        channel.as_uuid(),
        source.participant().as_str(),
        &source.full().to_string(),
        "",
        PresenceWrite::Probe,
        payloads,
    )
    .await
}

#[derive(Clone, Copy)]
enum PresenceWrite {
    Explicit {
        unavailable: bool,
    },
    Ensure {
        epoch: Option<RecoveryEpoch>,
        unavailable: bool,
    },
    Probe,
}

async fn write_mix_presence(
    pool: &PgPool,
    channel_id: Uuid,
    actor_bare: &str,
    actor_full: &str,
    payload: &str,
    policy: PresenceWrite,
    payloads: &dyn MixEventPayloadRenderer,
) -> Result<PresenceOutcome> {
    let (mut transaction, delivery_fence) = if matches!(policy, PresenceWrite::Probe) {
        begin_mix_delivery_fenced_transaction(pool).await?
    } else {
        begin_mix_delivery_admission(pool).await?
    };
    let channel_row = sqlx::query("SELECT * FROM mix_channels WHERE id = $1 FOR UPDATE")
        .bind(channel_id)
        .fetch_optional(&mut *transaction)
        .await?;
    let Some(channel_row) = channel_row else {
        return match policy {
            PresenceWrite::Ensure { epoch: Some(_), .. } | PresenceWrite::Probe => {
                transaction.rollback().await?;
                Ok(PresenceOutcome::Unchanged)
            }
            _ => Err(sqlx::Error::RowNotFound.into()),
        };
    };
    let channel = channel_from_row(&channel_row);
    let participant_row = sqlx::query(
        "SELECT channel_id, participant_id, jid, nick, role, joined_at FROM mix_participants WHERE channel_id = $1 AND jid = $2",
    )
    .bind(channel_id)
    .bind(actor_bare)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(participant_row) = participant_row else {
        transaction.rollback().await?;
        return Ok(PresenceOutcome::NotParticipant);
    };
    let participant = participant_from_row(&participant_row);
    let preference_row = sqlx::query(
        "SELECT jid_visibility, private_messages, vcard, share_presence FROM mix_participant_preferences WHERE channel_id = $1 AND participant_id = $2",
    )
    .bind(channel_id)
    .bind(participant.participant_id)
    .fetch_one(&mut *transaction)
    .await?;
    let preference = MixParticipantPreference {
        jid_visibility: preference_row.get("jid_visibility"),
        private_messages: preference_row.get("private_messages"),
        vcard: preference_row.get("vcard"),
        share_presence: preference_row.get("share_presence"),
    };
    if !preference.share_presence {
        transaction.rollback().await?;
        return Ok(PresenceOutcome::NotSharing);
    }
    if matches!(
        policy,
        PresenceWrite::Ensure {
            unavailable: false,
            ..
        } | PresenceWrite::Probe
    ) {
        let cutoff = match policy {
            PresenceWrite::Ensure { epoch, .. } => epoch.map(|epoch| epoch.cutoff),
            _ => None,
        };
        let existing = sqlx::query(
            "UPDATE mix_events SET created_at = GREATEST(created_at, clock_timestamp(), $5)
              WHERE channel_id = $1 AND node = $2 AND source_full_jid = $3 AND publisher_id = $4",
        )
        .bind(channel_id)
        .bind(NODE_PRESENCE)
        .bind(actor_full)
        .bind(participant.participant_id)
        .bind(cutoff)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if existing != 0 || matches!(policy, PresenceWrite::Probe) {
            transaction.commit().await?;
            return Ok(PresenceOutcome::Unchanged);
        }
    }
    let existing_item: Option<String> = sqlx::query_scalar(
        "SELECT item_id FROM mix_events WHERE channel_id = $1 AND node = $2 AND source_full_jid = $3",
    )
    .bind(channel_id)
    .bind(NODE_PRESENCE)
    .bind(actor_full)
    .fetch_optional(&mut *transaction)
    .await?;
    if !matches!(policy, PresenceWrite::Explicit { .. }) && existing_item.is_some() {
        transaction.commit().await?;
        return Ok(PresenceOutcome::Unchanged);
    }
    let actor = northstar_xmpp_types::jid::CanonicalJid::parse(actor_full)?;
    let public_resource = if participant_jid_visible(&channel, &preference) {
        actor
            .resourcepart()
            .context("MIX presence requires a full JID")?
            .to_owned()
    } else {
        Uuid::new_v4().simple().to_string()
    };
    let item_id = existing_item.unwrap_or(mix_presence_item_id(
        &channel,
        participant.participant_id,
        &public_resource,
    )?);
    if matches!(
        policy,
        PresenceWrite::Explicit { unavailable: true }
            | PresenceWrite::Ensure {
                unavailable: true,
                ..
            }
    ) {
        let deleted = sqlx::query(
            "DELETE FROM mix_events WHERE channel_id = $1 AND node = $2 AND source_full_jid = $3",
        )
        .bind(channel_id)
        .bind(NODE_PRESENCE)
        .bind(actor_full)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if deleted == 0 {
            transaction.commit().await?;
            Ok(PresenceOutcome::Unchanged)
        } else {
            let item = MixPresenceItem {
                item_id: item_id.clone(),
                payload: payload.to_owned(),
                source_full_jid: Some(actor_full.to_owned()),
            };
            enqueue_mix_presence_event_tx(
                &mut transaction,
                &delivery_fence,
                MixPresenceProjection {
                    channel: &channel,
                    participant: &participant,
                    preference: &preference,
                    item: &item,
                    unavailable: true,
                    event_id: Uuid::new_v4(),
                    extra_recipients: Vec::new(),
                },
                payloads,
            )
            .await?;
            transaction.commit().await?;
            Ok(PresenceOutcome::Retracted)
        }
    } else {
        let event_id = store_mix_event_tx(
            &mut transaction,
            &channel,
            NODE_PRESENCE,
            &item_id,
            Some(&participant),
            payload,
        )
        .await?
        .context("MIX presence event unexpectedly conflicted")?;
        sqlx::query(
            "UPDATE mix_events SET source_full_jid = $4, created_at = clock_timestamp()
              WHERE channel_id = $1 AND node = $2 AND item_id = $3",
        )
        .bind(channel_id)
        .bind(NODE_PRESENCE)
        .bind(&item_id)
        .bind(actor_full)
        .execute(&mut *transaction)
        .await?;
        let item = MixPresenceItem {
            item_id: item_id.clone(),
            payload: payload.to_owned(),
            source_full_jid: Some(actor_full.to_owned()),
        };
        enqueue_mix_presence_event_tx(
            &mut transaction,
            &delivery_fence,
            MixPresenceProjection {
                channel: &channel,
                participant: &participant,
                preference: &preference,
                item: &item,
                unavailable: false,
                event_id,
                extra_recipients: Vec::new(),
            },
            payloads,
        )
        .await?;
        transaction.commit().await?;
        Ok(PresenceOutcome::Published)
    }
}
