//! MIX participants: lookup, presence recovery and expiry, subscriptions, nicks and leave.

use super::*;

pub async fn mix_participant(
    pool: &PgPool,
    channel_id: Uuid,
    jid: &str,
) -> Result<Option<MixParticipant>> {
    let jid = canonical_user_bare(jid)?;
    let row = sqlx::query(
        "SELECT channel_id, participant_id, jid, nick, role, joined_at FROM mix_participants WHERE channel_id = $1 AND jid = $2",
    )
    .bind(channel_id)
    .bind(jid)
    .fetch_optional(pool)
    .await?;
    Ok(row.as_ref().map(participant_from_row))
}

pub async fn mix_participant_by_id(
    pool: &PgPool,
    channel_id: Uuid,
    participant_id: Uuid,
) -> Result<Option<MixParticipant>> {
    let row = sqlx::query(
        "SELECT channel_id, participant_id, jid, nick, role, joined_at FROM mix_participants WHERE channel_id = $1 AND participant_id = $2",
    )
    .bind(channel_id)
    .bind(participant_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.as_ref().map(participant_from_row))
}

pub async fn mix_presence_source_jid(
    pool: &PgPool,
    channel_id: Uuid,
    item_id: &str,
) -> Result<Option<String>> {
    let item_id = crate::jid::CanonicalJid::parse(item_id)?.to_string();
    sqlx::query_scalar(
        "SELECT source_full_jid FROM mix_events WHERE channel_id = $1 AND node = $2 AND item_id = $3 AND source_full_jid IS NOT NULL",
    )
    .bind(channel_id)
    .bind(NODE_PRESENCE)
    .bind(item_id)
    .fetch_optional(pool)
    .await
    .map_err(Into::into)
}

/// Snapshot every current presence item before process recovery. No row is
/// eagerly deleted by domain: in a clustered deployment another node may
/// still own a local-domain resource. The supervised recovery worker refreshes
/// live local sessions, probes remote actors, then atomically expires and
/// publishes unavailable for only rows older than the returned cutoff.
pub async fn prepare_mix_presence_after_restart(
    pool: &PgPool,
    local_domain: &str,
) -> Result<(DateTime<Utc>, Vec<MixPresenceProbeTarget>)> {
    let _local_domain = crate::jid::prepare_domainpart(local_domain)?;
    let mut transaction = pool.begin().await?;
    let cutoff = Utc::now();
    let rows = sqlx::query(
        "SELECT DISTINCT c.localpart || '@' || c.service_domain AS channel_jid,
                         p.jid AS participant_jid
           FROM mix_events e
           JOIN mix_channels c ON c.id=e.channel_id
           JOIN mix_participants p
             ON p.channel_id=e.channel_id AND p.participant_id=e.publisher_id
          WHERE e.node=$1 ORDER BY channel_jid,participant_jid",
    )
    .bind(NODE_PRESENCE)
    .fetch_all(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok((
        cutoff,
        rows.into_iter()
            .map(|row| MixPresenceProbeTarget {
                channel_jid: row.get("channel_jid"),
                participant_jid: row.get("participant_jid"),
            })
            .collect(),
    ))
}

pub async fn expire_unrefreshed_mix_presence(
    pool: &PgPool,
    cutoff: DateTime<Utc>,
    payloads: &dyn MixEventPayloadRenderer,
) -> Result<Vec<ExpiredMixPresence>> {
    let (mut transaction, delivery_fence) = begin_mix_delivery_admission(pool).await?;
    let rows = sqlx::query(
        "WITH stale AS (SELECT e.id FROM mix_events e WHERE e.node = $1 AND e.created_at < $2 ORDER BY e.created_at, e.id LIMIT 128 FOR UPDATE SKIP LOCKED), deleted AS (DELETE FROM mix_events e USING stale WHERE e.id = stale.id RETURNING e.channel_id, e.publisher_id, e.item_id, e.payload, e.source_full_jid) SELECT d.channel_id, d.publisher_id AS participant_id, p.jid, p.nick, d.item_id, d.payload, d.source_full_jid FROM deleted d JOIN mix_participants p ON p.channel_id = d.channel_id AND p.participant_id = d.publisher_id ORDER BY d.channel_id, d.publisher_id, d.item_id",
    )
    .bind(NODE_PRESENCE)
    .bind(cutoff)
    .fetch_all(&mut *transaction)
    .await?;
    let expired = rows
        .into_iter()
        .map(|row| ExpiredMixPresence {
            channel_id: row.get("channel_id"),
            participant: MixParticipant {
                participant_id: row.get("participant_id"),
                jid: row.get("jid"),
                nick: row.get("nick"),
            },
            item_id: row.get("item_id"),
            payload: row.get("payload"),
            source_full_jid: row.get("source_full_jid"),
        })
        .collect::<Vec<_>>();
    for item in &expired {
        let channel_row = sqlx::query("SELECT * FROM mix_channels WHERE id=$1 FOR SHARE")
            .bind(item.channel_id)
            .fetch_one(&mut *transaction)
            .await?;
        let channel = channel_from_row(&channel_row);
        let preference_row = sqlx::query(
            "SELECT jid_visibility,private_messages,vcard,share_presence
               FROM mix_participant_preferences
              WHERE channel_id=$1 AND participant_id=$2",
        )
        .bind(item.channel_id)
        .bind(item.participant.participant_id)
        .fetch_one(&mut *transaction)
        .await?;
        let preference = MixParticipantPreference {
            jid_visibility: preference_row.get("jid_visibility"),
            private_messages: preference_row.get("private_messages"),
            vcard: preference_row.get("vcard"),
            share_presence: preference_row.get("share_presence"),
        };
        let presence = MixPresenceItem {
            item_id: item.item_id.clone(),
            payload: item.payload.clone(),
            source_full_jid: item.source_full_jid.clone(),
        };
        enqueue_mix_presence_event_tx(
            &mut transaction,
            &delivery_fence,
            MixPresenceProjection {
                channel: &channel,
                participant: &item.participant,
                preference: &preference,
                item: &presence,
                unavailable: true,
                event_id: Uuid::new_v4(),
                extra_recipients: Vec::new(),
            },
            payloads,
        )
        .await?;
    }
    transaction.commit().await?;
    Ok(expired)
}

pub async fn update_mix_subscriptions(
    pool: &PgPool,
    channel_id: Uuid,
    actor: &str,
    subscribe: &[String],
    unsubscribe: &[String],
    payloads: &dyn MixEventPayloadRenderer,
    federated: Option<&FederatedMixMutation>,
) -> Result<Option<UpdateSubscriptionsOutcome>> {
    let actor = canonical_user_bare(actor)?;
    let subscribe = valid_join_nodes(subscribe)?;
    let unsubscribe = valid_join_nodes(unsubscribe)?;
    anyhow::ensure!(
        subscribe.iter().all(|node| !unsubscribe.contains(node)),
        "a MIX node cannot be subscribed and unsubscribed together"
    );
    let (mut transaction, delivery_fence) = begin_mix_delivery_admission(pool).await?;
    guard_federated_mix_mutation_tx(&mut transaction, federated).await?;
    // Serialize subscription changes with message/retraction admission. Those
    // paths lock the channel before persisting an event and selecting its
    // committed audience. Without the same lock here, an unsubscribe could
    // commit after that audience was read but before the message transaction
    // committed, causing a delivery to a participant who had already left the
    // node by commit time. Keep the global lock order channel -> participant,
    // which also matches join/leave and avoids an inversion deadlock.
    let channel_row = sqlx::query("SELECT * FROM mix_channels WHERE id = $1 FOR UPDATE")
        .bind(channel_id)
        .fetch_optional(&mut *transaction)
        .await?;
    let Some(channel_row) = channel_row else {
        transaction.rollback().await?;
        return Ok(None);
    };
    let channel = channel_from_row(&channel_row);
    let participant_row = sqlx::query(
        "SELECT channel_id, participant_id, jid, nick, role, joined_at FROM mix_participants WHERE channel_id = $1 AND jid = $2 FOR UPDATE",
    )
    .bind(channel_id)
    .bind(actor)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(participant_row) = participant_row else {
        transaction.rollback().await?;
        return Ok(None);
    };
    let participant = participant_from_row(&participant_row);
    let participant_id = participant.participant_id;
    let preference_row = sqlx::query(
        "SELECT jid_visibility,private_messages,vcard,share_presence
           FROM mix_participant_preferences
          WHERE channel_id=$1 AND participant_id=$2",
    )
    .bind(channel_id)
    .bind(participant_id)
    .fetch_one(&mut *transaction)
    .await?;
    let preference = MixParticipantPreference {
        jid_visibility: preference_row.get("jid_visibility"),
        private_messages: preference_row.get("private_messages"),
        vcard: preference_row.get("vcard"),
        share_presence: preference_row.get("share_presence"),
    };
    for node in subscribe {
        sqlx::query(
            "INSERT INTO mix_subscriptions (channel_id, participant_id, node) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
        )
        .bind(channel_id)
        .bind(participant_id)
        .bind(node)
        .execute(&mut *transaction)
        .await?;
    }
    for node in &unsubscribe {
        sqlx::query(
            "DELETE FROM mix_subscriptions WHERE channel_id = $1 AND participant_id = $2 AND node = $3",
        )
        .bind(channel_id)
        .bind(participant_id)
        .bind(node)
        .execute(&mut *transaction)
        .await?;
    }
    let removed_presence = if unsubscribe.iter().any(|node| node == NODE_PRESENCE) {
        sqlx::query(
            "DELETE FROM mix_events WHERE channel_id = $1 AND node = $2 AND publisher_id = $3 RETURNING item_id, payload, source_full_jid",
        )
        .bind(channel_id)
        .bind(NODE_PRESENCE)
        .bind(participant_id)
        .fetch_all(&mut *transaction)
        .await?
        .into_iter()
        .map(|row| MixPresenceItem {
            item_id: row.get("item_id"),
            payload: row.get("payload"),
            source_full_jid: row.get("source_full_jid"),
        })
        .collect()
    } else {
        Vec::new()
    };
    let current: Vec<String> = sqlx::query_scalar(
        "SELECT node FROM mix_subscriptions WHERE channel_id = $1 AND participant_id = $2 ORDER BY node",
    )
    .bind(channel_id)
    .bind(participant_id)
    .fetch_all(&mut *transaction)
    .await?;
    for item in &removed_presence {
        enqueue_mix_presence_event_tx(
            &mut transaction,
            &delivery_fence,
            MixPresenceProjection {
                channel: &channel,
                participant: &participant,
                preference: &preference,
                item,
                unavailable: true,
                event_id: Uuid::new_v4(),
                extra_recipients: Vec::new(),
            },
            payloads,
        )
        .await?;
    }
    finalize_federated_mix_mutation_tx(
        &mut transaction,
        federated,
        FederatedMixSuccess::UpdateSubscriptions {
            subscriptions: current.clone(),
        },
        payloads,
    )
    .await?;
    transaction.commit().await?;
    Ok(Some(UpdateSubscriptionsOutcome {
        subscriptions: current,
        participant,
        removed_presence,
    }))
}

pub async fn set_mix_nick(
    pool: &PgPool,
    channel_id: Uuid,
    actor: &str,
    nick: &str,
    payloads: &dyn MixEventPayloadRenderer,
    federated: Option<&FederatedMixMutation>,
) -> Result<Result<MixParticipant, SetNickError>> {
    let actor = canonical_user_bare(actor)?;
    let nick = prepare_mix_nick(nick)?;
    let (mut transaction, delivery_fence) = begin_mix_delivery_admission(pool).await?;
    guard_federated_mix_mutation_tx(&mut transaction, federated).await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("mix-actor:{actor}"))
        .execute(&mut *transaction)
        .await?;
    let channel_row = sqlx::query("SELECT * FROM mix_channels WHERE id = $1 FOR UPDATE")
        .bind(channel_id)
        .fetch_one(&mut *transaction)
        .await?;
    let channel = channel_from_row(&channel_row);
    let collision: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM mix_participants WHERE channel_id = $1 AND nick = $2 AND jid <> $3)",
    )
    .bind(channel_id)
    .bind(&nick)
    .bind(&actor)
    .fetch_one(&mut *transaction)
    .await?;
    if collision {
        transaction.rollback().await?;
        return Ok(Err(SetNickError::Conflict));
    }
    let row = sqlx::query(
        "UPDATE mix_participants SET nick = $3, updated_at = NOW() WHERE channel_id = $1 AND jid = $2 RETURNING channel_id, participant_id, jid, nick, role, joined_at",
    )
    .bind(channel_id)
    .bind(actor)
    .bind(&nick)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(row) = row else {
        transaction.rollback().await?;
        return Ok(Err(SetNickError::NotParticipant));
    };
    let participant = participant_from_row(&row);
    let preference_row = sqlx::query(
        "SELECT jid_visibility,private_messages,vcard,share_presence
           FROM mix_participant_preferences
          WHERE channel_id=$1 AND participant_id=$2",
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
    let payload = payloads.participant_payload(&channel, &participant, &preference);
    let event_id = store_mix_event_tx(
        &mut transaction,
        &channel,
        NODE_PARTICIPANTS,
        &participant.participant_id.to_string(),
        Some(&participant),
        &payload,
    )
    .await?
    .context("MIX participant event unexpectedly conflicted")?;
    enqueue_mix_node_event_tx(
        &mut transaction,
        &delivery_fence,
        MixNodeProjection {
            channel: &channel,
            node: NODE_PARTICIPANTS,
            item_id: &participant.participant_id.to_string(),
            payload: Some(&payload),
            retract: false,
            event_id,
            extra_recipients: Vec::new(),
        },
        payloads,
    )
    .await?;
    sqlx::query(
        "UPDATE mix_pam_memberships SET nick = $3, updated_at = NOW() WHERE channel_jid = $1 AND participant_id = $2",
    )
    .bind(channel.jid())
    .bind(participant.participant_id.to_string())
    .bind(&nick)
    .execute(&mut *transaction)
    .await?;
    finalize_federated_mix_mutation_tx(
        &mut transaction,
        federated,
        FederatedMixSuccess::SetNick { nick: nick.clone() },
        payloads,
    )
    .await?;
    transaction.commit().await?;
    Ok(Ok(participant))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetNickError {
    NotParticipant,
    Conflict,
}

pub async fn leave_mix_channel(
    pool: &PgPool,
    channel_id: Uuid,
    actor: &str,
    pam_user_id: Option<Uuid>,
    payloads: &dyn MixEventPayloadRenderer,
    federated: Option<&FederatedMixMutation>,
) -> Result<Option<LeaveMixOutcome>> {
    let actor = canonical_user_bare(actor)?;
    let (mut transaction, delivery_fence) = begin_mix_delivery_admission(pool).await?;
    guard_federated_mix_mutation_tx(&mut transaction, federated).await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(channel_id.to_string())
        .execute(&mut *transaction)
        .await?;
    let channel_row = sqlx::query("SELECT * FROM mix_channels WHERE id = $1 FOR UPDATE")
        .bind(channel_id)
        .fetch_one(&mut *transaction)
        .await?;
    let channel = channel_from_row(&channel_row);
    if let Some(user_id) = pam_user_id {
        anyhow::ensure!(
            pam_account_matches_actor_tx(&mut transaction, user_id, &actor).await?,
            "MIX-PAM account UUID does not belong to authenticated actor"
        );
    }
    let participant_row = sqlx::query(
        "SELECT channel_id, participant_id, jid, nick, role, joined_at FROM mix_participants WHERE channel_id = $1 AND jid = $2 FOR UPDATE",
    )
    .bind(channel_id)
    .bind(actor)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(participant_row) = participant_row else {
        transaction.rollback().await?;
        return Ok(None);
    };
    let participant = participant_from_row(&participant_row);
    let participant_id = participant.participant_id;
    let preference_row = sqlx::query(
        "SELECT jid_visibility,private_messages,vcard,share_presence
           FROM mix_participant_preferences
          WHERE channel_id=$1 AND participant_id=$2",
    )
    .bind(channel_id)
    .bind(participant_id)
    .fetch_one(&mut *transaction)
    .await?;
    let preference = MixParticipantPreference {
        jid_visibility: preference_row.get("jid_visibility"),
        private_messages: preference_row.get("private_messages"),
        vcard: preference_row.get("vcard"),
        share_presence: preference_row.get("share_presence"),
    };
    let presence_items = sqlx::query(
        "DELETE FROM mix_events WHERE channel_id = $1 AND node = $2 AND publisher_id = $3 RETURNING item_id, payload, source_full_jid",
    )
    .bind(channel_id)
    .bind(NODE_PRESENCE)
    .bind(participant_id)
    .fetch_all(&mut *transaction)
    .await?
    .into_iter()
    .map(|row| MixPresenceItem {
        item_id: row.get("item_id"),
        payload: row.get("payload"),
        source_full_jid: row.get("source_full_jid"),
    })
    .collect::<Vec<_>>();
    sqlx::query("DELETE FROM mix_participants WHERE channel_id = $1 AND participant_id = $2")
        .bind(channel_id)
        .bind(participant_id)
        .execute(&mut *transaction)
        .await?;
    sqlx::query("DELETE FROM mix_events WHERE channel_id = $1 AND node = $2 AND item_id = $3")
        .bind(channel_id)
        .bind(NODE_PARTICIPANTS)
        .bind(participant_id.to_string())
        .execute(&mut *transaction)
        .await?;
    for item in &presence_items {
        enqueue_mix_presence_event_tx(
            &mut transaction,
            &delivery_fence,
            MixPresenceProjection {
                channel: &channel,
                participant: &participant,
                preference: &preference,
                item,
                unavailable: true,
                event_id: Uuid::new_v4(),
                extra_recipients: vec![participant.clone()],
            },
            payloads,
        )
        .await?;
    }
    enqueue_mix_node_event_tx(
        &mut transaction,
        &delivery_fence,
        MixNodeProjection {
            channel: &channel,
            node: NODE_PARTICIPANTS,
            item_id: &participant_id.to_string(),
            payload: None,
            retract: true,
            event_id: Uuid::new_v4(),
            extra_recipients: vec![participant.clone()],
        },
        payloads,
    )
    .await?;
    let mut roster_change = None;
    if let Some(user_id) = pam_user_id {
        sqlx::query("DELETE FROM mix_pam_memberships WHERE user_id = $1 AND channel_jid = $2")
            .bind(user_id)
            .bind(channel.jid())
            .execute(&mut *transaction)
            .await?;
        roster_change = delete_mix_roster_tx(&mut transaction, user_id, &channel.jid()).await?;
    }
    finalize_federated_mix_mutation_tx(
        &mut transaction,
        federated,
        FederatedMixSuccess::Leave,
        payloads,
    )
    .await?;
    transaction.commit().await?;
    Ok(Some(LeaveMixOutcome {
        participant,
        presence_items,
        roster_change,
    }))
}
