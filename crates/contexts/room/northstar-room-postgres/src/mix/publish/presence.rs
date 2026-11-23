use super::*;

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

/// Publish a conservative verified-capability presence only when this exact
/// resource has no newer authoritative channel presence. The channel row lock
/// makes the absence check linearizable with explicit client updates.
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
    let (mut transaction, delivery_fence) = begin_mix_delivery_admission(pool).await?;
    let channel_row = sqlx::query("SELECT * FROM mix_channels WHERE id = $1 FOR UPDATE")
        .bind(channel_id)
        .fetch_one(&mut *transaction)
        .await?;
    let channel = channel_from_row(&channel_row);
    let participant_row = sqlx::query(
        "SELECT channel_id, participant_id, jid, nick, role, joined_at FROM mix_participants WHERE channel_id = $1 AND jid = $2",
    )
    .bind(channel_id)
    .bind(&actor_bare)
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
    let existing_item: Option<String> = sqlx::query_scalar(
        "SELECT item_id FROM mix_events WHERE channel_id = $1 AND node = $2 AND source_full_jid = $3",
    )
    .bind(channel_id)
    .bind(NODE_PRESENCE)
    .bind(&actor_full)
    .fetch_optional(&mut *transaction)
    .await?;
    if only_if_absent && existing_item.is_some() {
        transaction.commit().await?;
        return Ok(PresenceOutcome::Unchanged);
    }
    let actor = northstar_xmpp_types::jid::CanonicalJid::parse(&actor_full)?;
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
    if unavailable {
        let deleted = sqlx::query(
            "DELETE FROM mix_events WHERE channel_id = $1 AND node = $2 AND source_full_jid = $3",
        )
        .bind(channel_id)
        .bind(NODE_PRESENCE)
        .bind(&actor_full)
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
                source_full_jid: Some(actor_full.clone()),
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
            "UPDATE mix_events SET source_full_jid = $4 WHERE channel_id = $1 AND node = $2 AND item_id = $3",
        )
        .bind(channel_id)
        .bind(NODE_PRESENCE)
        .bind(&item_id)
        .bind(&actor_full)
        .execute(&mut *transaction)
        .await?;
        let item = MixPresenceItem {
            item_id: item_id.clone(),
            payload: payload.to_owned(),
            source_full_jid: Some(actor_full),
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
