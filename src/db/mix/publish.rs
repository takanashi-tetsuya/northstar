//! MIX presence and message storage, node read authorization, event pages and avatars.

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
pub(super) async fn store_mix_presence_with_policy(
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
    let actor_full = crate::jid::canonicalize(actor_full)?;
    anyhow::ensure!(
        crate::jid::canonical_bare_key(&actor_full)? == actor_bare,
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
    let actor = crate::jid::CanonicalJid::parse(&actor_full)?;
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

#[expect(
    clippy::too_many_arguments,
    reason = "the channel-locked message transaction keeps every replay, archive, audience, and encryption input explicit"
)]
pub async fn store_mix_message(
    pool: &PgPool,
    channel_id: Uuid,
    actor: &str,
    item_id: &str,
    payload: &str,
    identity: Option<MixBusinessIdentity<'_>>,
    delivery_payload: &str,
    visible_jid: Option<&str>,
    encrypted: bool,
    payloads: &dyn MixEventPayloadRenderer,
) -> Result<StoreMixMessageAdmission> {
    store_mix_message_inner(
        pool,
        channel_id,
        actor,
        item_id,
        payload,
        identity,
        delivery_payload,
        visible_jid,
        encrypted,
        payloads,
        None,
    )
    .await
}

pub async fn store_mix_message_observed(
    pool: &PgPool,
    request: &northstar_room_application::mix::StoreRequest,
    identity: Option<MixBusinessIdentity<'_>>,
    payloads: &dyn MixEventPayloadRenderer,
) -> Result<StoreMixMessageAdmission> {
    let command = request.command();
    store_mix_message_inner(
        pool,
        command.channel_id,
        &command.actor,
        &command.item_id.to_string(),
        &command.payload,
        identity,
        &command.delivery_payload,
        command.visible_jid.as_deref(),
        command.encrypted,
        payloads,
        Some(request),
    )
    .await
}

#[expect(
    clippy::too_many_arguments,
    reason = "one shared existing transaction keeps the bound compatibility and observed inputs explicit"
)]
pub(super) async fn store_mix_message_inner(
    pool: &PgPool,
    channel_id: Uuid,
    actor: &str,
    item_id: &str,
    payload: &str,
    identity: Option<MixBusinessIdentity<'_>>,
    delivery_payload: &str,
    visible_jid: Option<&str>,
    encrypted: bool,
    payloads: &dyn MixEventPayloadRenderer,
    observation: Option<&northstar_room_application::mix::StoreRequest>,
) -> Result<StoreMixMessageAdmission> {
    if payload.len() > 1_048_576 {
        return Ok(StoreMixMessageAdmission {
            outcome: StoreEventOutcome::TooLarge,
            recipients: Vec::new(),
        });
    }
    let authoritative_id = Uuid::parse_str(item_id)?;
    anyhow::ensure!(
        authoritative_id.to_string() == item_id,
        "MIX message item id must be a canonical UUID"
    );
    let actor = canonical_user_bare(actor)?;
    let (mut transaction, delivery_fence) = begin_mix_delivery_admission(pool).await?;
    let channel_row = sqlx::query("SELECT * FROM mix_channels WHERE id = $1 FOR UPDATE")
        .bind(channel_id)
        .fetch_one(&mut *transaction)
        .await?;
    let channel = channel_from_row(&channel_row);
    if let Some(identity) = identity {
        if let Some(existing) = existing_mix_business_intent_tx(
            &mut transaction,
            channel_id,
            &actor,
            "message",
            identity.client_id,
        )
        .await?
        {
            if let Some(request) = observation {
                request.observed_existing(foreground_existing(&existing))?;
            }
            transaction.rollback().await?;
            return Ok(StoreMixMessageAdmission {
                outcome: StoreEventOutcome::Existing(existing),
                recipients: Vec::new(),
            });
        }
    }
    let participant_row = sqlx::query(
        "SELECT channel_id, participant_id, jid, nick, role, joined_at FROM mix_participants WHERE channel_id = $1 AND jid = $2",
    )
    .bind(channel_id)
    .bind(&actor)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(participant_row) = participant_row else {
        transaction.rollback().await?;
        return Ok(StoreMixMessageAdmission {
            outcome: StoreEventOutcome::NotParticipant,
            recipients: Vec::new(),
        });
    };
    let participant = participant_from_row(&participant_row);
    if let Some(identity) = identity {
        if let Some(existing) = admit_mix_business_intent_tx(
            &mut transaction,
            channel_id,
            &actor,
            "message",
            identity,
            authoritative_id,
            None,
        )
        .await?
        {
            if let Some(request) = observation {
                request.observed_existing(foreground_existing(&existing))?;
            }
            transaction.rollback().await?;
            return Ok(StoreMixMessageAdmission {
                outcome: StoreEventOutcome::Existing(existing),
                recipients: Vec::new(),
            });
        }
    }
    let stored = store_mix_event_tx(
        &mut transaction,
        &channel,
        NODE_MESSAGES,
        item_id,
        Some(&participant),
        payload,
    )
    .await;
    match stored {
        Ok(Some(storage_id)) => {
            let recipients =
                mix_subscribers_tx(&mut transaction, channel_id, NODE_MESSAGES).await?;
            let stanza_template = recipients
                .first()
                .map(|recipient| {
                    payloads.message_delivery_stanza(
                        &channel,
                        &participant,
                        recipient,
                        authoritative_id,
                        delivery_payload,
                        visible_jid,
                    )
                })
                .transpose()?
                .unwrap_or_default();
            let projection = enqueue_mix_deliveries_tx_with_facts(
                &mut transaction,
                &delivery_fence,
                MixDeliveryProjection {
                    channel: &channel,
                    event_id: authoritative_id,
                    recipients: &recipients,
                    stanza_template: &stanza_template,
                    authoritative_stanza_id: Some(authoritative_id),
                    archive: true,
                    encrypted,
                },
            )
            .await?;
            if let Some(request) = observation {
                northstar_room_application::mix::commit_observed(
                    transaction.commit(),
                    request,
                    northstar_room_core::mix::Stored {
                        authoritative_id,
                        storage_id,
                        channel_id: channel.id,
                        channel_jid: channel.jid(),
                        projection,
                    },
                )
                .await
                .map_err(|error| match error {
                    northstar_room_application::mix::CommitError::Observation(error) => {
                        anyhow::Error::from(error)
                    }
                    northstar_room_application::mix::CommitError::Commit(error) => {
                        anyhow::Error::from(error)
                    }
                })?;
            } else {
                transaction.commit().await?;
            }
            Ok(StoreMixMessageAdmission {
                outcome: StoreEventOutcome::Stored(authoritative_id),
                recipients,
            })
        }
        Ok(None) => {
            transaction.rollback().await?;
            Ok(StoreMixMessageAdmission {
                outcome: StoreEventOutcome::Conflict,
                recipients: Vec::new(),
            })
        }
        Err(error) => Err(error),
    }
}

pub(super) async fn authorize_mix_node_read_tx(
    transaction: &mut Transaction<'_, Postgres>,
    channel_id: Uuid,
    actor: &str,
    node: &str,
) -> Result<MixReadOutcome<MixChannel>> {
    anyhow::ensure!(ALL_NODES.contains(&node), "unknown MIX node");
    let actor = canonical_user_bare(actor)?;
    let actor_domain = crate::jid::CanonicalJid::parse_bare(&actor)?
        .domainpart()
        .to_owned();
    let row = sqlx::query(
        "SELECT c.*,
                EXISTS(SELECT 1 FROM mix_participants p WHERE p.channel_id=c.id AND p.jid=$2) AS participant,
                EXISTS(SELECT 1 FROM mix_channel_roles r WHERE r.channel_id=c.id AND r.jid=$2) AS privileged,
                EXISTS(SELECT 1 FROM mix_banned b WHERE b.channel_id=c.id AND b.jid_pattern IN ($2,$3)) AS banned,
                EXISTS(SELECT 1 FROM mix_allowed a WHERE a.channel_id=c.id AND a.jid_pattern IN ($2,$3)) AS allowed
           FROM mix_channels c WHERE c.id=$1",
    )
    .bind(channel_id)
    .bind(&actor)
    .bind(actor_domain)
    .fetch_optional(&mut **transaction)
    .await?;
    let Some(row) = row else {
        return Ok(MixReadOutcome::NotFound);
    };
    let channel = channel_from_row(&row);
    let participant: bool = row.get("participant");
    let privileged: bool = row.get("privileged");
    let banned: bool = row.get("banned");
    let allowed: bool = row.get("allowed");
    let discoverable: bool = row.get("discoverable");
    let authorized = if banned && !privileged {
        false
    } else if matches!(node, NODE_CONFIG | NODE_ALLOWED | NODE_BANNED | NODE_JIDMAP) {
        privileged
    } else if node == NODE_INFO {
        participant || privileged || (discoverable && (channel.access_model == "open" || allowed))
    } else {
        participant || privileged
    };
    if authorized {
        Ok(MixReadOutcome::Found(channel))
    } else {
        Ok(MixReadOutcome::Unauthorized)
    }
}

pub async fn authorized_mix_event_page(
    pool: &PgPool,
    channel_id: Uuid,
    actor: &str,
    node: &str,
    before: Option<(DateTime<Utc>, Uuid)>,
    limit: i64,
) -> Result<MixReadOutcome<MixEventPage>> {
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
    let limit = limit.clamp(1, 200);
    let rows = if let Some((created_at, id)) = before {
        sqlx::query(
            "SELECT id,node,item_id,publisher_id,publisher_jid,payload,created_at FROM mix_events WHERE channel_id=$1 AND node=$2 AND (created_at,id)<($3,$4) ORDER BY created_at DESC,id DESC LIMIT $5",
        )
        .bind(channel_id)
        .bind(node)
        .bind(created_at)
        .bind(id)
        .bind(limit + 1)
        .fetch_all(&mut *transaction)
        .await?
    } else {
        sqlx::query(
            "SELECT id,node,item_id,publisher_id,publisher_jid,payload,created_at FROM mix_events WHERE channel_id=$1 AND node=$2 ORDER BY created_at DESC,id DESC LIMIT $3",
        )
        .bind(channel_id)
        .bind(node)
        .bind(limit + 1)
        .fetch_all(&mut *transaction)
        .await?
    };
    let events = rows
        .into_iter()
        .take(limit as usize)
        .map(|row| MixEvent {
            id: row.get("id"),
            item_id: row.get("item_id"),
            payload: row.get("payload"),
            created_at: row.get("created_at"),
        })
        .collect();
    transaction.commit().await?;
    Ok(MixReadOutcome::Found(MixEventPage { events }))
}

#[expect(
    clippy::too_many_arguments,
    reason = "the atomic avatar mutation keeps its authorization, event, renderer, and federation inputs explicit"
)]
pub async fn publish_mix_avatar(
    pool: &PgPool,
    channel_id: Uuid,
    actor: &str,
    node: &str,
    item_id: &str,
    payload: &str,
    payloads: &dyn MixEventPayloadRenderer,
    federated: Option<&FederatedMixMutation>,
) -> Result<bool> {
    anyhow::ensure!(
        matches!(node, NODE_AVATAR_DATA | NODE_AVATAR_METADATA),
        "invalid MIX avatar node"
    );
    let actor = canonical_user_bare(actor)?;
    let (mut transaction, delivery_fence) = begin_mix_delivery_admission(pool).await?;
    guard_federated_mix_mutation_tx(&mut transaction, federated).await?;
    let channel_row = sqlx::query("SELECT * FROM mix_channels WHERE id = $1 FOR UPDATE")
        .bind(channel_id)
        .fetch_optional(&mut *transaction)
        .await?;
    let Some(channel_row) = channel_row else {
        transaction.rollback().await?;
        return Ok(false);
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
        return Ok(false);
    }
    let channel = channel_from_row(&channel_row);
    if node == NODE_AVATAR_METADATA {
        sqlx::query("DELETE FROM mix_events WHERE channel_id = $1 AND node = $2")
            .bind(channel_id)
            .bind(NODE_AVATAR_METADATA)
            .execute(&mut *transaction)
            .await?;
    }
    let event_id = store_mix_event_tx(&mut transaction, &channel, node, item_id, None, payload)
        .await?
        .context("MIX avatar event unexpectedly conflicted")?;
    if node == NODE_AVATAR_DATA {
        sqlx::query(
            "DELETE FROM mix_events WHERE channel_id = $1 AND node = $2 AND id NOT IN (SELECT id FROM mix_events WHERE channel_id = $1 AND node = $2 ORDER BY created_at DESC, id DESC LIMIT 64)",
        )
        .bind(channel_id)
        .bind(NODE_AVATAR_DATA)
        .execute(&mut *transaction)
        .await?;
    }
    enqueue_mix_node_event_tx(
        &mut transaction,
        &delivery_fence,
        MixNodeProjection {
            channel: &channel,
            node,
            item_id,
            payload: Some(payload),
            retract: false,
            event_id,
            extra_recipients: Vec::new(),
        },
        payloads,
    )
    .await?;
    finalize_federated_mix_mutation_tx(
        &mut transaction,
        federated,
        FederatedMixSuccess::PubSubPublish {
            node: node.to_owned(),
            item_id: item_id.to_owned(),
        },
        payloads,
    )
    .await?;
    transaction.commit().await?;
    Ok(true)
}

pub async fn retract_mix_avatar(
    pool: &PgPool,
    channel_id: Uuid,
    actor: &str,
    node: &str,
    item_id: &str,
    payloads: &dyn MixEventPayloadRenderer,
    federated: Option<&FederatedMixMutation>,
) -> Result<bool> {
    anyhow::ensure!(
        matches!(node, NODE_AVATAR_DATA | NODE_AVATAR_METADATA),
        "invalid MIX avatar node"
    );
    let actor = canonical_user_bare(actor)?;
    let (mut transaction, delivery_fence) = begin_mix_delivery_admission(pool).await?;
    guard_federated_mix_mutation_tx(&mut transaction, federated).await?;
    let channel_row = sqlx::query("SELECT * FROM mix_channels WHERE id = $1 FOR UPDATE")
        .bind(channel_id)
        .fetch_optional(&mut *transaction)
        .await?;
    let Some(channel_row) = channel_row else {
        transaction.rollback().await?;
        return Ok(false);
    };
    let channel = channel_from_row(&channel_row);
    let authorized: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM mix_channel_roles WHERE channel_id = $1 AND jid = $2 AND role IN ('owner', 'administrator'))",
    )
    .bind(channel_id)
    .bind(actor)
    .fetch_one(&mut *transaction)
    .await?;
    if !authorized {
        transaction.rollback().await?;
        return Ok(false);
    }
    let deleted =
        sqlx::query("DELETE FROM mix_events WHERE channel_id = $1 AND node = $2 AND item_id = $3")
            .bind(channel_id)
            .bind(node)
            .bind(item_id)
            .execute(&mut *transaction)
            .await?
            .rows_affected();
    if deleted == 1 {
        enqueue_mix_node_event_tx(
            &mut transaction,
            &delivery_fence,
            MixNodeProjection {
                channel: &channel,
                node,
                item_id,
                payload: None,
                retract: true,
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
        FederatedMixSuccess::PubSubEmpty,
        payloads,
    )
    .await?;
    transaction.commit().await?;
    Ok(true)
}
