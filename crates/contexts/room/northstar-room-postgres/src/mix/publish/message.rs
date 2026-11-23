use super::*;
use northstar_room_application::mix_service::MixPublisherIdentity;

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
    publisher_identity: &MixPublisherIdentity,
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
        publisher_identity,
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
        request.publisher_identity(),
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
pub async fn store_mix_message_inner(
    pool: &PgPool,
    channel_id: Uuid,
    actor: &str,
    item_id: &str,
    payload: &str,
    identity: Option<MixBusinessIdentity<'_>>,
    delivery_payload: &str,
    publisher_identity: &MixPublisherIdentity,
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
    let Some(participant) = mix_participant(&mut *transaction, channel_id, &actor).await? else {
        transaction.rollback().await?;
        return Ok(StoreMixMessageAdmission {
            outcome: StoreEventOutcome::NotParticipant,
            recipients: Vec::new(),
        });
    };
    if !matches_locked_publisher_identity(
        &mut transaction,
        &channel,
        &participant,
        publisher_identity,
        visible_jid,
    )
    .await?
    {
        transaction.rollback().await?;
        return Ok(StoreMixMessageAdmission {
            outcome: StoreEventOutcome::IdentityPolicyChanged,
            recipients: Vec::new(),
        });
    }
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

// Channel and participant mutations take the channel lock before changing
// these inputs. The renderer's bytes can only be admitted under those facts.
pub(crate) async fn matches_locked_publisher_identity(
    transaction: &mut Transaction<'_, Postgres>,
    channel: &MixChannel,
    participant: &MixParticipant,
    rendered: &MixPublisherIdentity,
    visible_jid: Option<&str>,
) -> Result<bool> {
    if MixPublisherIdentity::from_state(channel, participant) != *rendered {
        return Ok(false);
    }
    let live_jid_visible = if channel.jid_visibility == "maybe" {
        let preference =
            mix_participant_preference(&mut **transaction, channel.id, &participant.jid)
                .await?
                .unwrap_or_default();
        participant_jid_visible(channel, &preference)
    } else {
        rendered.archive_jid_visible
    };
    Ok(visible_jid == live_jid_visible.then_some(participant.jid.as_str()))
}
