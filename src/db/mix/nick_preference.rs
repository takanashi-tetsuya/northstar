//! MIX nick registration and participant preferences.

use super::*;

#[derive(Clone, Debug)]
pub enum RegisterMixNickOutcome {
    Registered { nick: String },
    Conflict,
}

pub async fn register_mix_nick(
    pool: &PgPool,
    service_domain: &str,
    actor: &str,
    nick: &str,
    payloads: &dyn MixEventPayloadRenderer,
    federated: Option<&FederatedMixMutation>,
) -> Result<RegisterMixNickOutcome> {
    let service_domain = canonical_service_domain(service_domain)?;
    let actor = canonical_user_bare(actor)?;
    let nick = prepare_mix_nick(nick)?;
    let (mut transaction, delivery_fence) = begin_mix_delivery_admission(pool).await?;
    guard_federated_mix_mutation_tx(&mut transaction, federated).await?;
    // Registration is an account-wide projection over every participation.
    // Serialize it with join and per-channel nick changes before taking any
    // channel lock, establishing the global actor -> channel lock order.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("mix-actor:{actor}"))
        .execute(&mut *transaction)
        .await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("mix-nick:{service_domain}:{nick}"))
        .execute(&mut *transaction)
        .await?;
    let conflict: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM mix_registered_nicks WHERE service_domain = $1 AND nick = $2 AND jid <> $3)",
    )
    .bind(&service_domain)
    .bind(&nick)
    .bind(&actor)
    .fetch_one(&mut *transaction)
    .await?;
    if conflict {
        transaction.rollback().await?;
        return Ok(RegisterMixNickOutcome::Conflict);
    }
    let channel_ids = sqlx::query_scalar::<_, Uuid>(
        "SELECT c.id
           FROM mix_channels c
          WHERE c.service_domain=$1
            AND EXISTS (
                SELECT 1 FROM mix_participants p
                 WHERE p.channel_id=c.id AND p.jid=$2
            )
          ORDER BY c.id",
    )
    .bind(&service_domain)
    .bind(&actor)
    .fetch_all(&mut *transaction)
    .await?;
    let mut channels = Vec::with_capacity(channel_ids.len());
    for channel_id in channel_ids {
        let row = sqlx::query("SELECT * FROM mix_channels WHERE id=$1 FOR UPDATE")
            .bind(channel_id)
            .fetch_optional(&mut *transaction)
            .await?;
        if let Some(row) = row {
            let channel = channel_from_row(&row);
            let channel_conflict: bool = sqlx::query_scalar(
                "SELECT EXISTS(
                    SELECT 1 FROM mix_participants
                     WHERE channel_id=$1 AND nick=$2 AND jid<>$3
                )",
            )
            .bind(channel.id)
            .bind(&nick)
            .bind(&actor)
            .fetch_one(&mut *transaction)
            .await?;
            if channel_conflict {
                transaction.rollback().await?;
                return Ok(RegisterMixNickOutcome::Conflict);
            }
            channels.push(channel);
        }
    }
    sqlx::query(
        "INSERT INTO mix_registered_nicks (service_domain, jid, nick) VALUES ($1, $2, $3) ON CONFLICT (service_domain, jid) DO UPDATE SET nick = EXCLUDED.nick, updated_at = NOW()",
    )
    .bind(&service_domain)
    .bind(&actor)
    .bind(&nick)
    .execute(&mut *transaction)
    .await?;
    for channel in channels {
        let Some(row) = sqlx::query(
            "UPDATE mix_participants
                SET nick=$3, updated_at=NOW()
              WHERE channel_id=$1 AND jid=$2
          RETURNING channel_id,participant_id,jid,nick,role,joined_at",
        )
        .bind(channel.id)
        .bind(&actor)
        .bind(&nick)
        .fetch_optional(&mut *transaction)
        .await?
        else {
            // A leave which committed before this channel lock won the serial
            // order; it has no remaining projection to update.
            continue;
        };
        let participant = participant_from_row(&row);
        let preference_row = sqlx::query(
            "SELECT jid_visibility,private_messages,vcard,share_presence
               FROM mix_participant_preferences
              WHERE channel_id=$1 AND participant_id=$2",
        )
        .bind(channel.id)
        .bind(participant.participant_id)
        .fetch_one(&mut *transaction)
        .await?;
        let preference = MixParticipantPreference {
            jid_visibility: preference_row.get("jid_visibility"),
            private_messages: preference_row.get("private_messages"),
            vcard: preference_row.get("vcard"),
            share_presence: preference_row.get("share_presence"),
        };
        sqlx::query(
            "UPDATE mix_pam_memberships
                SET nick=$3, updated_at=NOW()
              WHERE channel_jid=$1 AND participant_id=$2",
        )
        .bind(channel.jid())
        .bind(participant.participant_id.to_string())
        .bind(&nick)
        .execute(&mut *transaction)
        .await?;
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
    }
    finalize_federated_mix_mutation_tx(
        &mut transaction,
        federated,
        FederatedMixSuccess::RegisterNick { nick: nick.clone() },
        payloads,
    )
    .await?;
    transaction.commit().await?;
    Ok(RegisterMixNickOutcome::Registered { nick })
}

pub async fn mix_participant_preference(
    pool: &PgPool,
    channel_id: Uuid,
    actor: &str,
) -> Result<Option<MixParticipantPreference>> {
    let actor = canonical_user_bare(actor)?;
    let row = sqlx::query(
        "SELECT pref.jid_visibility, pref.private_messages, pref.vcard, pref.share_presence FROM mix_participant_preferences pref JOIN mix_participants p ON p.channel_id = pref.channel_id AND p.participant_id = pref.participant_id WHERE p.channel_id = $1 AND p.jid = $2",
    )
    .bind(channel_id)
    .bind(actor)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|row| MixParticipantPreference {
        jid_visibility: row.get("jid_visibility"),
        private_messages: row.get("private_messages"),
        vcard: row.get("vcard"),
        share_presence: row.get("share_presence"),
    }))
}

pub(super) fn validate_mix_participant_preference(
    preference: &MixParticipantPreference,
) -> Result<()> {
    anyhow::ensure!(
        matches!(
            preference.jid_visibility.as_str(),
            "default" | "never" | "always" | "prefer not"
        ),
        "invalid MIX JID visibility preference"
    );
    anyhow::ensure!(
        matches!(preference.private_messages.as_str(), "allow" | "block")
            && matches!(preference.vcard.as_str(), "allow" | "block"),
        "invalid MIX participant preference"
    );
    Ok(())
}

pub async fn update_mix_participant_preference(
    pool: &PgPool,
    channel_id: Uuid,
    actor: &str,
    preference: &MixParticipantPreference,
    payloads: &dyn MixEventPayloadRenderer,
    federated: Option<&FederatedMixMutation>,
) -> Result<Option<MixParticipantPreferenceUpdateOutcome>> {
    let actor = canonical_user_bare(actor)?;
    validate_mix_participant_preference(preference)?;
    let (mut transaction, delivery_fence) = begin_mix_delivery_admission(pool).await?;
    guard_federated_mix_mutation_tx(&mut transaction, federated).await?;
    let channel = sqlx::query("SELECT * FROM mix_channels WHERE id = $1 FOR UPDATE")
        .bind(channel_id)
        .fetch_optional(&mut *transaction)
        .await?
        .as_ref()
        .map(channel_from_row);
    let Some(channel) = channel else {
        transaction.rollback().await?;
        return Ok(None);
    };
    // An explicit preference incompatible with a mandatory visibility mode
    // cannot be accepted; this prevents a later response from lying about it.
    if (channel.jid_visibility == "visible" && preference.jid_visibility == "never")
        || (channel.jid_visibility == "hidden" && preference.jid_visibility == "always")
    {
        transaction.rollback().await?;
        return Ok(None);
    }
    let participant_row = sqlx::query(
        "SELECT channel_id, participant_id, jid, nick, role, joined_at FROM mix_participants WHERE channel_id = $1 AND jid = $2 FOR UPDATE",
    )
    .bind(channel_id)
    .bind(&actor)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(participant_row) = participant_row else {
        transaction.rollback().await?;
        return Ok(None);
    };
    let participant = participant_from_row(&participant_row);
    let old_row = sqlx::query(
        "SELECT jid_visibility,private_messages,vcard,share_presence
           FROM mix_participant_preferences
          WHERE channel_id=$1 AND participant_id=$2 FOR UPDATE",
    )
    .bind(channel_id)
    .bind(participant.participant_id)
    .fetch_one(&mut *transaction)
    .await?;
    let old_preference = MixParticipantPreference {
        jid_visibility: old_row.get("jid_visibility"),
        private_messages: old_row.get("private_messages"),
        vcard: old_row.get("vcard"),
        share_presence: old_row.get("share_presence"),
    };
    sqlx::query(
        "INSERT INTO mix_participant_preferences (channel_id, participant_id, jid_visibility, private_messages, vcard, share_presence) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (channel_id, participant_id) DO UPDATE SET jid_visibility = EXCLUDED.jid_visibility, private_messages = EXCLUDED.private_messages, vcard = EXCLUDED.vcard, share_presence = EXCLUDED.share_presence, updated_at = NOW()",
    )
    .bind(channel_id)
    .bind(participant.participant_id)
    .bind(&preference.jid_visibility)
    .bind(&preference.private_messages)
    .bind(&preference.vcard)
    .bind(preference.share_presence)
    .execute(&mut *transaction)
    .await?;
    let old_visible = participant_jid_visible(&channel, &old_preference);
    let new_visible = participant_jid_visible(&channel, preference);
    if old_preference.share_presence != preference.share_presence || old_visible != new_visible {
        let old_presence = sqlx::query(
            "DELETE FROM mix_events
              WHERE channel_id=$1 AND node=$2 AND publisher_id=$3
          RETURNING item_id,payload,source_full_jid",
        )
        .bind(channel_id)
        .bind(NODE_PRESENCE)
        .bind(participant.participant_id)
        .fetch_all(&mut *transaction)
        .await?
        .into_iter()
        .map(|row| MixPresenceItem {
            item_id: row.get("item_id"),
            payload: row.get("payload"),
            source_full_jid: row.get("source_full_jid"),
        })
        .collect::<Vec<_>>();
        for item in old_presence {
            enqueue_mix_presence_event_tx(
                &mut transaction,
                &delivery_fence,
                MixPresenceProjection {
                    channel: &channel,
                    participant: &participant,
                    preference: &old_preference,
                    item: &item,
                    unavailable: true,
                    event_id: Uuid::new_v4(),
                    extra_recipients: Vec::new(),
                },
                payloads,
            )
            .await?;
            if preference.share_presence {
                let Some(source_full_jid) = item.source_full_jid.as_deref() else {
                    // A legacy row without its real publishing resource may
                    // be retracted, but must never be made newly JID-visible.
                    continue;
                };
                let source = crate::jid::CanonicalJid::parse(source_full_jid)?;
                let public_resource = if new_visible {
                    source
                        .resourcepart()
                        .context("MIX presence source lost its resource")?
                        .to_owned()
                } else {
                    Uuid::new_v4().simple().to_string()
                };
                let new_item_id =
                    mix_presence_item_id(&channel, participant.participant_id, &public_resource)?;
                let event_id = store_mix_event_tx(
                    &mut transaction,
                    &channel,
                    NODE_PRESENCE,
                    &new_item_id,
                    Some(&participant),
                    &item.payload,
                )
                .await?
                .context("MIX preference presence event unexpectedly conflicted")?;
                sqlx::query(
                    "UPDATE mix_events SET source_full_jid=$4
                      WHERE channel_id=$1 AND node=$2 AND item_id=$3",
                )
                .bind(channel_id)
                .bind(NODE_PRESENCE)
                .bind(&new_item_id)
                .bind(source_full_jid)
                .execute(&mut *transaction)
                .await?;
                let new_item = MixPresenceItem {
                    item_id: new_item_id,
                    payload: item.payload,
                    source_full_jid: Some(source_full_jid.to_owned()),
                };
                enqueue_mix_presence_event_tx(
                    &mut transaction,
                    &delivery_fence,
                    MixPresenceProjection {
                        channel: &channel,
                        participant: &participant,
                        preference,
                        item: &new_item,
                        unavailable: false,
                        event_id,
                        extra_recipients: Vec::new(),
                    },
                    payloads,
                )
                .await?;
            }
        }
    }
    let rendered = payloads.participant_payload(&channel, &participant, preference);
    let participant_event_id = store_mix_event_tx(
        &mut transaction,
        &channel,
        NODE_PARTICIPANTS,
        &participant.participant_id.to_string(),
        Some(&participant),
        &rendered,
    )
    .await?
    .context("MIX preference participant event unexpectedly conflicted")?;
    enqueue_mix_node_event_tx(
        &mut transaction,
        &delivery_fence,
        MixNodeProjection {
            channel: &channel,
            node: NODE_PARTICIPANTS,
            item_id: &participant.participant_id.to_string(),
            payload: Some(&rendered),
            retract: false,
            event_id: participant_event_id,
            extra_recipients: Vec::new(),
        },
        payloads,
    )
    .await?;
    let mut roster_changes = Vec::new();
    if old_preference.share_presence != preference.share_presence {
        let local_users = sqlx::query_scalar::<_, Uuid>(
            "SELECT user_id FROM mix_pam_memberships
              WHERE channel_jid=$1 AND participant_id=$2 ORDER BY user_id",
        )
        .bind(channel.jid())
        .bind(participant.participant_id.to_string())
        .fetch_all(&mut *transaction)
        .await?;
        for user_id in local_users {
            let change = upsert_mix_roster_tx(
                &mut transaction,
                user_id,
                &channel.jid(),
                channel.name.as_deref(),
                preference.share_presence,
            )
            .await?;
            roster_changes.push((user_id, change));
        }
    }
    finalize_federated_mix_mutation_tx(
        &mut transaction,
        federated,
        FederatedMixSuccess::Preference {
            preference: preference.clone(),
        },
        payloads,
    )
    .await?;
    transaction.commit().await?;
    Ok(Some(MixParticipantPreferenceUpdateOutcome {
        participant,
        roster_changes,
    }))
}
