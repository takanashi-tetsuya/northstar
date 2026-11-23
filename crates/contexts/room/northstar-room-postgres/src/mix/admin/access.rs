use super::super::*;
use northstar_room_application::mix_service::CommittedMixChange;
use northstar_room_core::mix::{MixChannelAddress, MixChannelId, MixLocalParticipantId};

pub async fn authorized_mix_access_entries(
    pool: &PgPool,
    channel_id: Uuid,
    actor: &str,
    banned: bool,
    limit: i64,
) -> Result<MixReadOutcome<Vec<String>>> {
    let node = if banned { NODE_BANNED } else { NODE_ALLOWED };
    let mut transaction = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *transaction)
        .await?;
    match authorize_mix_node_read_tx(&mut transaction, channel_id, actor, node).await? {
        MixReadOutcome::Found(_) => {}
        MixReadOutcome::Unauthorized => {
            transaction.rollback().await?;
            return Ok(MixReadOutcome::Unauthorized);
        }
        MixReadOutcome::NotFound => {
            transaction.rollback().await?;
            return Ok(MixReadOutcome::NotFound);
        }
    }
    let table = if banned { "mix_banned" } else { "mix_allowed" };
    let statement = format!(
        "SELECT jid_pattern FROM {table} WHERE channel_id=$1 ORDER BY jid_pattern LIMIT $2"
    );
    let entries = sqlx::query_scalar(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(channel_id)
        .bind(limit.clamp(1, 500))
        .fetch_all(&mut *transaction)
        .await?;
    transaction.commit().await?;
    Ok(MixReadOutcome::Found(entries))
}

pub async fn set_mix_access_entry(
    effects: &impl crate::effects::RoomEffects,
    pool: &PgPool,
    update: MixAccessEntryUpdate<'_>,
    payloads: &dyn MixEventPayloadRenderer,
    federated: Option<&FederatedMixMutation>,
) -> Result<Option<CommittedMixChange<AccessChangeOutcome>>> {
    let channel_id = update.channel_id;
    let actor = canonical_user_bare(update.actor)?;
    let pattern = canonical_mix_access_pattern(update.pattern)?;
    let banned = update.list == MixAccessList::Banned;
    let (present, reason) = match update.operation {
        MixAccessEntryOperation::Publish { reason } => (true, reason),
        MixAccessEntryOperation::Retract => (false, None),
    };
    anyhow::ensure!(
        reason.is_none_or(|value| value.len() <= 1024),
        "ban reason too large"
    );
    let (mut transaction, delivery_fence) = begin_mix_delivery_admission(pool).await?;
    guard_federated_mix_mutation_tx(&mut transaction, federated).await?;
    let accounts = if banned && present {
        lock_hosted_pam_accounts_tx(&mut transaction, &MixChannelId::new(channel_id), None, None)
            .await?
    } else {
        BTreeMap::new()
    };
    // Serialize against owner/administrator replacement before evaluating the
    // role. Checking first allowed a concurrent config transaction to revoke
    // the actor while this transaction waited for the channel lock, then
    // continue with stale authority.
    let channel_row = sqlx::query("SELECT * FROM mix_channels WHERE id = $1 FOR UPDATE")
        .bind(channel_id)
        .fetch_optional(&mut *transaction)
        .await?;
    let Some(channel_row) = channel_row else {
        transaction.rollback().await?;
        return Ok(None);
    };
    let authorized: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM mix_channel_roles WHERE channel_id = $1 AND jid = $2 AND role IN ('owner', 'administrator'))",
    )
    .bind(channel_id)
    .bind(&actor)
    .fetch_one(&mut *transaction)
    .await?;
    if !authorized {
        transaction.rollback().await?;
        return Ok(None);
    }
    let mut outcome = AccessChangeOutcome::default();
    let channel = channel_from_row(&channel_row);
    let address = MixChannelAddress::parse(&channel.jid())?;
    let mut roster = Vec::new();
    if present {
        let opposite_exists: bool = if banned {
            sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM mix_allowed WHERE channel_id=$1 AND jid_pattern=$2)",
            )
            .bind(channel_id)
            .bind(&pattern)
            .fetch_one(&mut *transaction)
            .await?
        } else {
            sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM mix_banned WHERE channel_id=$1 AND jid_pattern=$2)",
            )
            .bind(channel_id)
            .bind(&pattern)
            .fetch_one(&mut *transaction)
            .await?
        };
        anyhow::ensure!(
            !opposite_exists,
            "a canonical MIX JID pattern cannot be both allowed and banned"
        );
    }
    let node = if banned { NODE_BANNED } else { NODE_ALLOWED };
    let item_id = pattern.clone();
    let access_payload = payloads.access_payload(&pattern);
    let mut access_event_id = None;
    let mut access_retract = false;
    let mut removed_details = Vec::<(
        MixParticipant,
        MixParticipantPreference,
        Vec<MixPresenceItem>,
    )>::new();
    if banned {
        if present {
            sqlx::query(
                "INSERT INTO mix_banned (channel_id, jid_pattern, added_by, reason) VALUES ($1, $2, $3, $4) ON CONFLICT (channel_id, jid_pattern) DO UPDATE SET added_by = EXCLUDED.added_by, reason = EXCLUDED.reason, created_at = NOW()",
            )
            .bind(channel_id)
            .bind(&pattern)
            .bind(&actor)
            .bind(reason)
            .execute(&mut *transaction)
            .await?;
            let domain_pattern = !pattern.contains('@');
            access_event_id = Some(
                store_mix_event_tx(
                    &mut transaction,
                    &channel,
                    node,
                    &item_id,
                    None,
                    &access_payload,
                )
                .await?
                .context("MIX access event unexpectedly conflicted")?,
            );
            let removed = sqlx::query(
                "SELECT p.channel_id,p.participant_id,p.jid,p.nick,p.role,p.joined_at,
                        pref.jid_visibility,pref.private_messages,pref.vcard,pref.share_presence
                   FROM mix_participants p
                   JOIN mix_participant_preferences pref
                     ON pref.channel_id=p.channel_id AND pref.participant_id=p.participant_id
                  WHERE p.channel_id=$1
                    AND (p.jid=$2 OR ($3 AND split_part(p.jid,'@',2)=$2))
                  ORDER BY p.participant_id FOR UPDATE OF p,pref",
            )
            .bind(channel_id)
            .bind(&pattern)
            .bind(domain_pattern)
            .fetch_all(&mut *transaction)
            .await?;
            for row in removed {
                let participant_id: Uuid = row.get("participant_id");
                let participant = participant_from_row(&row);
                let preference = MixParticipantPreference {
                    jid_visibility: row.get("jid_visibility"),
                    private_messages: row.get("private_messages"),
                    vcard: row.get("vcard"),
                    share_presence: row.get("share_presence"),
                };
                sqlx::query(
                    "DELETE FROM mix_participants WHERE channel_id=$1 AND participant_id=$2",
                )
                .bind(channel_id)
                .bind(participant_id)
                .execute(&mut *transaction)
                .await?;
                outcome.removed_participants.push(participant_id);
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
                sqlx::query(
                    "DELETE FROM mix_events WHERE channel_id = $1 AND node = $2 AND item_id = $3",
                )
                .bind(channel_id)
                .bind(NODE_PARTICIPANTS)
                .bind(participant_id.to_string())
                .execute(&mut *transaction)
                .await?;
                let local_users = delete_hosted_pam_tx(
                    &mut transaction,
                    &address,
                    Some(&MixLocalParticipantId::new(participant_id)),
                    None,
                )
                .await?;
                outcome.removed_local_users.extend(&local_users);
                roster.extend(
                    committed_pam_removals_tx(
                        effects,
                        &mut transaction,
                        &address,
                        &accounts,
                        local_users,
                        false,
                    )
                    .await?,
                );
                if !presence_items.is_empty() {
                    outcome
                        .removed_presence
                        .push((participant.clone(), presence_items.clone()));
                }
                removed_details.push((participant, preference, presence_items));
            }
        } else {
            let changed =
                sqlx::query("DELETE FROM mix_banned WHERE channel_id = $1 AND jid_pattern = $2")
                    .bind(channel_id)
                    .bind(&pattern)
                    .execute(&mut *transaction)
                    .await?
                    .rows_affected();
            sqlx::query(
                "DELETE FROM mix_events WHERE channel_id = $1 AND node = $2 AND item_id = $3",
            )
            .bind(channel_id)
            .bind(node)
            .bind(&item_id)
            .execute(&mut *transaction)
            .await?;
            if changed == 1 {
                access_event_id = Some(Uuid::new_v4());
                access_retract = true;
            }
        }
    } else if present {
        sqlx::query(
            "INSERT INTO mix_allowed (channel_id, jid_pattern, added_by) VALUES ($1, $2, $3) ON CONFLICT (channel_id, jid_pattern) DO UPDATE SET added_by = EXCLUDED.added_by, created_at = NOW()",
        )
        .bind(channel_id)
        .bind(&pattern)
        .bind(&actor)
        .execute(&mut *transaction)
        .await?;
        access_event_id = Some(
            store_mix_event_tx(
                &mut transaction,
                &channel,
                node,
                &item_id,
                None,
                &access_payload,
            )
            .await?
            .context("MIX access event unexpectedly conflicted")?,
        );
    } else {
        let changed =
            sqlx::query("DELETE FROM mix_allowed WHERE channel_id = $1 AND jid_pattern = $2")
                .bind(channel_id)
                .bind(&pattern)
                .execute(&mut *transaction)
                .await?
                .rows_affected();
        sqlx::query("DELETE FROM mix_events WHERE channel_id = $1 AND node = $2 AND item_id = $3")
            .bind(channel_id)
            .bind(node)
            .bind(&item_id)
            .execute(&mut *transaction)
            .await?;
        if changed == 1 {
            access_event_id = Some(Uuid::new_v4());
            access_retract = true;
        }
    }
    if let Some(event_id) = access_event_id {
        enqueue_mix_node_event_tx(
            &mut transaction,
            &delivery_fence,
            MixNodeProjection {
                channel: &channel,
                node,
                item_id: &item_id,
                payload: (!access_retract).then_some(access_payload.as_str()),
                retract: access_retract,
                event_id,
                extra_recipients: Vec::new(),
            },
            payloads,
        )
        .await?;
    }
    for (participant, preference, presence_items) in &removed_details {
        for item in presence_items {
            enqueue_mix_presence_event_tx(
                &mut transaction,
                &delivery_fence,
                MixPresenceProjection {
                    channel: &channel,
                    participant,
                    preference,
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
                item_id: &participant.participant_id.to_string(),
                payload: None,
                retract: true,
                event_id: Uuid::new_v4(),
                extra_recipients: vec![participant.clone()],
            },
            payloads,
        )
        .await?;
    }
    finalize_federated_mix_mutation_tx(
        effects,
        &mut transaction,
        federated,
        FederatedMixSuccess::PubSubEmpty,
        payloads,
    )
    .await?;
    transaction.commit().await?;
    outcome.removed_local_users.sort_unstable();
    outcome.removed_local_users.dedup();
    Ok(Some(CommittedMixChange { outcome, roster }))
}
