//! MIX JID maps, invitations, private message recipients and message retraction.

use super::*;

#[cfg(test)]
pub async fn mix_jid_map_entries(
    pool: &PgPool,
    channel_id: Uuid,
    actor: &str,
    limit: i64,
) -> Result<Option<Vec<(String, String)>>> {
    let actor = canonical_user_bare(actor)?;
    let mut transaction = pool.begin().await?;
    let exists = sqlx::query("SELECT id FROM mix_channels WHERE id = $1 FOR SHARE")
        .bind(channel_id)
        .fetch_optional(&mut *transaction)
        .await?;
    if exists.is_none() {
        transaction.rollback().await?;
        return Ok(None);
    }
    let authorized: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM mix_channel_roles WHERE channel_id = $1 AND jid = $2)",
    )
    .bind(channel_id)
    .bind(&actor)
    .fetch_one(&mut *transaction)
    .await?;
    if !authorized {
        transaction.rollback().await?;
        return Ok(None);
    }
    let rows = sqlx::query(
        "SELECT participant_id::text AS participant_id, jid FROM mix_participants WHERE channel_id = $1 ORDER BY participant_id LIMIT $2",
    )
    .bind(channel_id)
    .bind(limit.clamp(1, 500))
    .fetch_all(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(Some(
        rows.into_iter()
            .map(|row| (row.get("participant_id"), row.get("jid")))
            .collect(),
    ))
}

pub async fn authorized_mix_jid_map_entries(
    pool: &PgPool,
    channel_id: Uuid,
    actor: &str,
    limit: i64,
) -> Result<MixReadOutcome<Vec<(String, String)>>> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *transaction)
        .await?;
    match authorize_mix_node_read_tx(&mut transaction, channel_id, actor, NODE_JIDMAP).await? {
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
    let rows = sqlx::query(
        "SELECT participant_id::text AS participant_id,jid FROM mix_participants WHERE channel_id=$1 ORDER BY participant_id LIMIT $2",
    )
    .bind(channel_id)
    .bind(limit.clamp(1, 500))
    .fetch_all(&mut *transaction)
    .await?;
    let entries = rows
        .into_iter()
        .map(|row| (row.get("participant_id"), row.get("jid")))
        .collect();
    transaction.commit().await?;
    Ok(MixReadOutcome::Found(entries))
}

#[expect(
    clippy::too_many_arguments,
    reason = "the atomic invitation mutation keeps its principals, token lifetime, renderer, and federation fence explicit"
)]
pub async fn issue_mix_invitation(
    pool: &PgPool,
    channel_id: Uuid,
    inviter: &str,
    invitee: &str,
    token: &str,
    lifetime: chrono::Duration,
    payloads: &dyn MixEventPayloadRenderer,
    federated: Option<&FederatedMixMutation>,
) -> Result<bool> {
    let inviter = canonical_user_bare(inviter)?;
    let invitee = canonical_user_bare(invitee)?;
    anyhow::ensure!(
        (16..=1024).contains(&token.len()),
        "invalid MIX invitation token"
    );
    let token_hash = Sha256::digest(token.as_bytes()).to_vec();
    let mut transaction = pool.begin().await?;
    guard_federated_mix_mutation_tx(&mut transaction, federated).await?;
    let channel = sqlx::query("SELECT * FROM mix_channels WHERE id = $1 FOR UPDATE")
        .bind(channel_id)
        .fetch_optional(&mut *transaction)
        .await?;
    let Some(channel) = channel else {
        transaction.rollback().await?;
        return Ok(false);
    };
    let channel = channel_from_row(&channel);
    let authorized: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM mix_channel_roles WHERE channel_id = $1 AND jid = $2 AND role IN ('owner', 'administrator')) OR (SELECT allow_participant_invites AND EXISTS(SELECT 1 FROM mix_participants WHERE channel_id = $1 AND jid = $2) FROM mix_channels WHERE id = $1)",
    )
    .bind(channel_id)
    .bind(&inviter)
    .fetch_one(&mut *transaction)
    .await?;
    if !authorized {
        transaction.rollback().await?;
        return Ok(false);
    }
    sqlx::query("DELETE FROM mix_invitations WHERE expires_at <= NOW() OR consumed_at IS NOT NULL")
        .execute(&mut *transaction)
        .await?;
    sqlx::query(
        "INSERT INTO mix_invitations (id, channel_id, inviter_jid, invitee_jid, token_hash, expires_at) VALUES ($1, $2, $3, $4, $5, NOW() + $6::interval)",
    )
    .bind(Uuid::new_v4())
    .bind(channel_id)
    .bind(&inviter)
    .bind(&invitee)
    .bind(token_hash)
    .bind(format!("{} seconds", lifetime.num_seconds().clamp(60, 86400)))
    .execute(&mut *transaction)
    .await?;
    finalize_federated_mix_mutation_tx(
        &mut transaction,
        federated,
        FederatedMixSuccess::Invitation {
            inviter: inviter.clone(),
            invitee: invitee.clone(),
            channel: channel.jid(),
            token: token.to_owned(),
        },
        payloads,
    )
    .await?;
    transaction.commit().await?;
    Ok(true)
}

pub async fn mix_private_message_recipient(
    pool: &PgPool,
    channel_id: Uuid,
    sender: &str,
    recipient_id: Uuid,
) -> Result<Option<(MixParticipant, MixParticipant)>> {
    let sender = canonical_user_bare(sender)?;
    // One MVCC statement binds policy, sender membership, recipient membership
    // and recipient preference to the same snapshot. The previous four-step
    // lookup could deliver after a concurrent leave or policy revocation.
    let row = sqlx::query(
        "SELECT sender.participant_id AS sender_id, sender.jid AS sender_jid,
                sender.nick AS sender_nick, recipient.participant_id AS recipient_id,
                recipient.jid AS recipient_jid, recipient.nick AS recipient_nick
         FROM mix_channels channel
         JOIN mix_participants sender
           ON sender.channel_id = channel.id AND sender.jid = $2
         JOIN mix_participants recipient
           ON recipient.channel_id = channel.id AND recipient.participant_id = $3
         JOIN mix_participant_preferences preference
           ON preference.channel_id = recipient.channel_id
          AND preference.participant_id = recipient.participant_id
         WHERE channel.id = $1 AND channel.allow_private_messages
           AND preference.private_messages = 'allow'",
    )
    .bind(channel_id)
    .bind(sender)
    .bind(recipient_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|row| {
        (
            MixParticipant {
                participant_id: row.get("sender_id"),
                jid: row.get("sender_jid"),
                nick: row.get("sender_nick"),
            },
            MixParticipant {
                participant_id: row.get("recipient_id"),
                jid: row.get("recipient_jid"),
                nick: row.get("recipient_nick"),
            },
        )
    }))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RetractMixMessageOutcome {
    Retracted,
    Existing(MixIntentEvidence),
    NotFound,
    Forbidden,
}

#[derive(Clone, Debug)]
pub struct RetractMixMessageAdmission {
    pub outcome: RetractMixMessageOutcome,
    pub recipients: Vec<MixParticipant>,
}

#[expect(
    clippy::too_many_arguments,
    reason = "the channel-locked retraction transaction keeps replay identity and both durable projections explicit"
)]
pub async fn retract_mix_message(
    pool: &PgPool,
    channel_id: Uuid,
    actor: &str,
    target_id: Uuid,
    retraction_id: Uuid,
    tombstone_payload: &str,
    retraction_payload: &str,
    identity: Option<MixBusinessIdentity<'_>>,
    visible_jid: Option<&str>,
    payloads: &dyn MixEventPayloadRenderer,
) -> Result<RetractMixMessageAdmission> {
    let actor = canonical_user_bare(actor)?;
    let (mut transaction, delivery_fence) = begin_mix_delivery_admission(pool).await?;
    let channel_row = sqlx::query("SELECT * FROM mix_channels WHERE id = $1 FOR UPDATE")
        .bind(channel_id)
        .fetch_optional(&mut *transaction)
        .await?;
    let Some(channel_row) = channel_row else {
        transaction.rollback().await?;
        return Ok(RetractMixMessageAdmission {
            outcome: RetractMixMessageOutcome::NotFound,
            recipients: Vec::new(),
        });
    };
    let channel = channel_from_row(&channel_row);
    if let Some(identity) = identity {
        if let Some(existing) = existing_mix_business_intent_tx(
            &mut transaction,
            channel_id,
            &actor,
            "retraction",
            identity.client_id,
        )
        .await?
        {
            transaction.rollback().await?;
            return Ok(RetractMixMessageAdmission {
                outcome: RetractMixMessageOutcome::Existing(existing),
                recipients: Vec::new(),
            });
        }
    }
    let target = sqlx::query(
        "SELECT publisher_jid FROM mix_events WHERE channel_id = $1 AND node = $2 AND item_id = $3 FOR UPDATE",
    )
    .bind(channel_id)
    .bind(NODE_MESSAGES)
    .bind(target_id.to_string())
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(target) = target else {
        transaction.rollback().await?;
        return Ok(RetractMixMessageAdmission {
            outcome: RetractMixMessageOutcome::NotFound,
            recipients: Vec::new(),
        });
    };
    let publisher: Option<String> = target.get("publisher_jid");
    let role: Option<String> =
        sqlx::query_scalar("SELECT role FROM mix_channel_roles WHERE channel_id = $1 AND jid = $2")
            .bind(channel_id)
            .bind(&actor)
            .fetch_optional(&mut *transaction)
            .await?;
    let own_allowed = channel.allow_user_message_retraction && publisher.as_deref() == Some(&actor);
    let admin_allowed = match channel.administrator_retraction_rights.as_str() {
        "administrators" => role.is_some(),
        "owners" => role.as_deref() == Some("owner"),
        _ => false,
    };
    if !own_allowed && !admin_allowed {
        transaction.rollback().await?;
        return Ok(RetractMixMessageAdmission {
            outcome: RetractMixMessageOutcome::Forbidden,
            recipients: Vec::new(),
        });
    }
    if let Some(identity) = identity {
        if let Some(existing) = admit_mix_business_intent_tx(
            &mut transaction,
            channel_id,
            &actor,
            "retraction",
            identity,
            retraction_id,
            Some(target_id),
        )
        .await?
        {
            transaction.rollback().await?;
            return Ok(RetractMixMessageAdmission {
                outcome: RetractMixMessageOutcome::Existing(existing),
                recipients: Vec::new(),
            });
        }
    }
    sqlx::query(
        "UPDATE mix_events SET payload = $4 WHERE channel_id = $1 AND node = $2 AND item_id = $3",
    )
    .bind(channel_id)
    .bind(NODE_MESSAGES)
    .bind(target_id.to_string())
    .bind(tombstone_payload)
    .execute(&mut *transaction)
    .await?;
    let actor_participant = sqlx::query(
        "SELECT channel_id, participant_id, jid, nick, role, joined_at FROM mix_participants WHERE channel_id = $1 AND jid = $2",
    )
    .bind(channel_id)
    .bind(&actor)
    .fetch_optional(&mut *transaction)
    .await?
    .map(|row| participant_from_row(&row));
    let _ = store_mix_event_tx(
        &mut transaction,
        &channel,
        NODE_MESSAGES,
        &retraction_id.to_string(),
        actor_participant.as_ref(),
        retraction_payload,
    )
    .await?;
    let recipients = mix_subscribers_tx(&mut transaction, channel_id, NODE_MESSAGES).await?;
    let Some(sender) = actor_participant.as_ref() else {
        transaction.rollback().await?;
        return Ok(RetractMixMessageAdmission {
            outcome: RetractMixMessageOutcome::Forbidden,
            recipients: Vec::new(),
        });
    };
    let stanza_template = recipients
        .first()
        .map(|recipient| {
            payloads.retraction_delivery_stanza(
                &channel,
                sender,
                recipient,
                retraction_id,
                target_id,
                visible_jid,
            )
        })
        .transpose()?
        .unwrap_or_default();
    enqueue_mix_deliveries_tx(
        &mut transaction,
        &delivery_fence,
        MixDeliveryProjection {
            channel: &channel,
            event_id: retraction_id,
            recipients: &recipients,
            stanza_template: &stanza_template,
            authoritative_stanza_id: Some(retraction_id),
            archive: true,
            encrypted: false,
        },
    )
    .await?;
    transaction.commit().await?;
    Ok(RetractMixMessageAdmission {
        outcome: RetractMixMessageOutcome::Retracted,
        recipients,
    })
}
