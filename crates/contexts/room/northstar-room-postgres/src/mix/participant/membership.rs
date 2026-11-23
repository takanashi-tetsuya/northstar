use super::*;
use northstar_room_application::mix_service::{CommittedMixChange, HostedMixRefusal};
use northstar_room_core::mix::{
    MixChannelAddress, MixChannelId, MixLocalParticipantId, MixRealJid,
};

#[allow(clippy::too_many_arguments)]
pub async fn update_mix_subscriptions(
    effects: &impl crate::effects::RoomEffects,
    pool: &PgPool,
    channel_id: Uuid,
    actor: &str,
    subscribe: &[String],
    unsubscribe: &[String],
    payloads: &dyn MixEventPayloadRenderer,
    federated: Option<&FederatedMixMutation>,
) -> Result<Option<UpdateSubscriptionsOutcome>> {
    let actor = canonical_user_bare(actor)?;
    let actor_jid = MixRealJid::parse(&actor)?;
    let channel_id_typed = MixChannelId::new(channel_id);
    let subscribe = valid_join_nodes(subscribe)?;
    let unsubscribe = valid_join_nodes(unsubscribe)?;
    anyhow::ensure!(
        subscribe.iter().all(|node| !unsubscribe.contains(node)),
        "a MIX node cannot be subscribed and unsubscribed together"
    );
    let (mut transaction, delivery_fence) = begin_mix_delivery_admission(pool).await?;
    guard_federated_mix_mutation_tx(&mut transaction, federated).await?;
    let accounts =
        lock_hosted_pam_accounts_tx(&mut transaction, &channel_id_typed, Some(&actor_jid), None)
            .await?;
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
        return Err(HostedMixRefusal::MissingChannel.into());
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
    let users = hosted_pam_users(&accounts, &actor_jid, None)?;
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
    let participant_uuid = MixLocalParticipantId::new(participant_id);
    let current =
        hosted_subscription_nodes_tx(&mut transaction, &channel_id_typed, &participant_uuid)
            .await?;
    mirror_hosted_pam_subscriptions_tx(
        &mut transaction,
        &MixChannelAddress::parse(&channel.jid())?,
        &participant_uuid,
        &users,
        &current,
    )
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
        effects,
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
    effects: &impl crate::effects::RoomEffects,
    pool: &PgPool,
    channel_id: Uuid,
    actor: &str,
    nick: &str,
    payloads: &dyn MixEventPayloadRenderer,
    federated: Option<&FederatedMixMutation>,
) -> Result<Result<MixParticipant, SetNickError>> {
    let actor = canonical_user_bare(actor)?;
    let actor_jid = MixRealJid::parse(&actor)?;
    let nick = prepare_mix_nick(nick)?;
    let (mut transaction, delivery_fence) = begin_mix_delivery_admission(pool).await?;
    guard_federated_mix_mutation_tx(&mut transaction, federated).await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("mix-actor:{actor}"))
        .execute(&mut *transaction)
        .await?;
    let accounts = lock_hosted_pam_accounts_tx(
        &mut transaction,
        &MixChannelId::new(channel_id),
        Some(&actor_jid),
        None,
    )
    .await?;
    let channel_row = sqlx::query("SELECT * FROM mix_channels WHERE id = $1 FOR UPDATE")
        .bind(channel_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(HostedMixRefusal::MissingChannel)?;
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
    let users = hosted_pam_users(&accounts, &actor_jid, None)?;
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
    if !users.is_empty() {
        sqlx::query(
            "UPDATE mix_pam_memberships SET nick = $3, updated_at = NOW() WHERE channel_jid = $1 AND participant_id = $2 AND user_id=ANY($4)",
        )
        .bind(channel.jid())
        .bind(participant.participant_id.to_string())
        .bind(&nick)
        .bind(&users)
        .execute(&mut *transaction)
        .await?;
    }
    finalize_federated_mix_mutation_tx(
        effects,
        &mut transaction,
        federated,
        FederatedMixSuccess::SetNick { nick: nick.clone() },
        payloads,
    )
    .await?;
    transaction.commit().await?;
    Ok(Ok(participant))
}

pub async fn leave_mix_channel(
    effects: &impl crate::effects::RoomEffects,
    pool: &PgPool,
    channel_id: Uuid,
    actor: &str,
    pam_user_id: Option<Uuid>,
    payloads: &dyn MixEventPayloadRenderer,
    federated: Option<&FederatedMixMutation>,
) -> Result<CommittedMixChange<Option<LeaveMixOutcome>>> {
    let actor = MixRealJid::parse(actor)?;
    let (mut transaction, delivery_fence) = begin_mix_delivery_admission(pool).await?;
    guard_federated_mix_mutation_tx(&mut transaction, federated).await?;
    let accounts = lock_hosted_pam_accounts_tx(
        &mut transaction,
        &MixChannelId::new(channel_id),
        Some(&actor),
        pam_user_id,
    )
    .await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(channel_id.to_string())
        .execute(&mut *transaction)
        .await?;
    let channel_row = sqlx::query("SELECT * FROM mix_channels WHERE id = $1 FOR UPDATE")
        .bind(channel_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(HostedMixRefusal::MissingChannel)?;
    let channel = channel_from_row(&channel_row);
    let channel_address = MixChannelAddress::parse(&channel.jid())?;
    let users = hosted_pam_users(&accounts, &actor, pam_user_id)?;
    let participant_row = sqlx::query(
        "SELECT channel_id, participant_id, jid, nick, role, joined_at FROM mix_participants WHERE channel_id = $1 AND jid = $2 FOR UPDATE",
    )
    .bind(channel_id)
    .bind(actor.as_str())
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(participant_row) = participant_row else {
        if let Some(user_id) = pam_user_id {
            let removed =
                delete_hosted_pam_tx(&mut transaction, &channel_address, None, Some(&[user_id]))
                    .await?;
            let roster = committed_pam_removals_tx(
                effects,
                &mut transaction,
                &channel_address,
                &accounts,
                removed,
                false,
            )
            .await?;
            transaction.commit().await?;
            return Ok(CommittedMixChange {
                outcome: None,
                roster,
            });
        }
        transaction.rollback().await?;
        return Ok(CommittedMixChange {
            outcome: None,
            roster: Vec::new(),
        });
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
    let removed = delete_hosted_pam_tx(
        &mut transaction,
        &channel_address,
        Some(&MixLocalParticipantId::new(participant_id)),
        Some(&users),
    )
    .await?;
    let roster = committed_pam_removals_tx(
        effects,
        &mut transaction,
        &channel_address,
        &accounts,
        removed,
        false,
    )
    .await?;
    let roster_change = roster.first().map(|delta| delta.change.clone());
    finalize_federated_mix_mutation_tx(
        effects,
        &mut transaction,
        federated,
        FederatedMixSuccess::Leave,
        payloads,
    )
    .await?;
    transaction.commit().await?;
    Ok(CommittedMixChange {
        outcome: Some(LeaveMixOutcome {
            participant,
            presence_items,
            roster_change,
        }),
        roster,
    })
}
