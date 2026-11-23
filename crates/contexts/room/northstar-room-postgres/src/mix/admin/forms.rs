use super::super::*;

pub async fn update_mix_info(
    effects: &impl crate::effects::RoomEffects,
    pool: &PgPool,
    channel_id: Uuid,
    actor: &str,
    update: MixInfoUpdate<'_>,
    payloads: &dyn MixEventPayloadRenderer,
    federated: Option<&FederatedMixMutation>,
) -> Result<MixMutationOutcome> {
    let actor = canonical_user_bare(actor)?;
    anyhow::ensure!(
        update.name.is_none_or(|value| value.len() <= 512),
        "MIX name too large"
    );
    anyhow::ensure!(
        update.description.is_none_or(|value| value.len() <= 4096),
        "MIX description too large"
    );
    anyhow::ensure!(update.contacts.len() <= 64, "too many MIX contacts");
    let contacts = update
        .contacts
        .iter()
        .map(|jid| canonical_user_bare(jid))
        .collect::<Result<Vec<_>>>()?;
    anyhow::ensure!(
        contacts.iter().collect::<BTreeSet<_>>().len() == contacts.len(),
        "MIX contacts contain duplicate canonical JIDs"
    );
    let contacts = serde_json::to_value(contacts)?;
    let (mut transaction, delivery_fence) = begin_mix_delivery_admission(pool).await?;
    guard_federated_mix_mutation_tx(&mut transaction, federated).await?;
    let locked = sqlx::query("SELECT * FROM mix_channels WHERE id = $1 FOR UPDATE")
        .bind(channel_id)
        .fetch_optional(&mut *transaction)
        .await?;
    let Some(locked) = locked else {
        transaction.rollback().await?;
        return Ok(MixMutationOutcome::NotFound);
    };
    if locked.get::<i64, _>("revision") != update.expected_revision {
        transaction.rollback().await?;
        return Ok(MixMutationOutcome::Conflict);
    }
    let authorized: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM mix_channel_roles WHERE channel_id = $1 AND jid = $2 AND role IN ('owner', 'administrator'))",
    )
    .bind(channel_id)
    .bind(&actor)
    .fetch_one(&mut *transaction)
    .await?;
    if !authorized {
        transaction.rollback().await?;
        return Ok(MixMutationOutcome::Forbidden);
    }
    let row = sqlx::query(
        "UPDATE mix_channels SET name=$2,description=$3,contacts=$4,
                revision=revision+1,updated_at=NOW()
          WHERE id=$1 AND revision=$5 RETURNING *",
    )
    .bind(channel_id)
    .bind(update.name)
    .bind(update.description)
    .bind(contacts)
    .bind(update.expected_revision)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(row) = row else {
        transaction.rollback().await?;
        return Ok(MixMutationOutcome::Conflict);
    };
    let channel = channel_from_row(&row);
    let payload = payloads.info_payload(&channel);
    let event_id = store_mix_event_tx(
        &mut transaction,
        &channel,
        NODE_INFO,
        update.item_id,
        None,
        &payload,
    )
    .await?
    .context("MIX information event unexpectedly conflicted")?;
    let recipients = mix_node_audience_tx(&mut transaction, channel_id, NODE_INFO).await?;
    let stanza_template = recipients
        .first()
        .map(|recipient| {
            payloads.node_event_stanza(
                &channel,
                recipient,
                NODE_INFO,
                update.item_id,
                Some(&payload),
                false,
            )
        })
        .transpose()?
        .unwrap_or_default();
    enqueue_mix_deliveries_tx(
        &mut transaction,
        &delivery_fence,
        MixDeliveryProjection {
            channel: &channel,
            event_id,
            recipients: &recipients,
            stanza_template: &stanza_template,
            authoritative_stanza_id: None,
            archive: false,
            encrypted: false,
        },
    )
    .await?;
    finalize_federated_mix_mutation_tx(
        effects,
        &mut transaction,
        federated,
        FederatedMixSuccess::PubSubPublish {
            node: NODE_INFO.to_owned(),
            item_id: update.item_id.to_owned(),
        },
        payloads,
    )
    .await?;
    transaction.commit().await?;
    Ok(MixMutationOutcome::Applied(Box::new(
        MixMutationAdmission {
            channel,
            node: NODE_INFO.to_owned(),
            item_id: update.item_id.to_owned(),
            payload,
            recipients,
        },
    )))
}

#[allow(clippy::too_many_arguments)]
pub async fn update_mix_config(
    effects: &impl crate::effects::RoomEffects,
    pool: &PgPool,
    channel_id: Uuid,
    actor: &str,
    update: MixConfigUpdate<'_>,
    roles: MixRoleUpdate<'_>,
    payloads: &dyn MixEventPayloadRenderer,
    federated: Option<&FederatedMixMutation>,
) -> Result<MixMutationOutcome> {
    let actor = canonical_user_bare(actor)?;
    anyhow::ensure!(
        matches!(update.access_model, "open" | "allowlist"),
        "invalid access model"
    );
    anyhow::ensure!(
        matches!(update.jid_visibility, "visible" | "maybe" | "hidden"),
        "invalid JID visibility"
    );
    anyhow::ensure!(
        update.jid_visibility == "visible" || update.nick_required,
        "hidden-JID MIX channels require nicknames for presence identity"
    );
    anyhow::ensure!(
        (2..=5000).contains(&update.max_participants),
        "invalid participant limit"
    );
    anyhow::ensure!(
        (100..=100000).contains(&update.max_events),
        "invalid event limit"
    );
    anyhow::ensure!(
        matches!(
            update.administrator_retraction_rights,
            "nobody" | "administrators" | "owners"
        ),
        "invalid MIX retraction rights"
    );
    let requested_owners = roles
        .owners
        .map(|values| {
            let canonical = values
                .iter()
                .map(|jid| canonical_user_bare(jid))
                .collect::<Result<Vec<_>>>()?;
            let unique = canonical.into_iter().collect::<BTreeSet<_>>();
            anyhow::ensure!(
                unique.len() == values.len(),
                "MIX owner list contains duplicate canonical JIDs"
            );
            Ok(unique)
        })
        .transpose()?;
    if let Some(owners) = &requested_owners {
        anyhow::ensure!(
            !owners.is_empty() && owners.len() <= 64,
            "invalid MIX owner list"
        );
    }
    let requested_administrators = roles
        .administrators
        .map(|values| {
            let canonical = values
                .iter()
                .map(|jid| canonical_user_bare(jid))
                .collect::<Result<Vec<_>>>()?;
            let unique = canonical.into_iter().collect::<BTreeSet<_>>();
            anyhow::ensure!(
                unique.len() == values.len(),
                "MIX administrator list contains duplicate canonical JIDs"
            );
            Ok(unique)
        })
        .transpose()?;
    if let Some(administrators) = &requested_administrators {
        anyhow::ensure!(administrators.len() <= 256, "too many MIX administrators");
    }
    let (mut transaction, delivery_fence) = begin_mix_delivery_admission(pool).await?;
    guard_federated_mix_mutation_tx(&mut transaction, federated).await?;
    let locked = sqlx::query("SELECT * FROM mix_channels WHERE id = $1 FOR UPDATE")
        .bind(channel_id)
        .fetch_optional(&mut *transaction)
        .await?;
    let Some(locked) = locked else {
        transaction.rollback().await?;
        return Ok(MixMutationOutcome::NotFound);
    };
    if locked.get::<i64, _>("revision") != update.expected_revision {
        transaction.rollback().await?;
        return Ok(MixMutationOutcome::Conflict);
    }
    let old_channel = channel_from_row(&locked);
    let actor_is_owner: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM mix_channel_roles WHERE channel_id = $1 AND jid = $2 AND role = 'owner')",
    )
    .bind(channel_id)
    .bind(&actor)
    .fetch_one(&mut *transaction)
    .await?;
    if !actor_is_owner {
        transaction.rollback().await?;
        return Ok(MixMutationOutcome::Forbidden);
    }
    let current_owners = sqlx::query_scalar::<_, String>(
        "SELECT jid FROM mix_channel_roles WHERE channel_id = $1 AND role = 'owner' ORDER BY jid",
    )
    .bind(channel_id)
    .fetch_all(&mut *transaction)
    .await?
    .into_iter()
    .collect::<BTreeSet<_>>();
    let current_administrators = sqlx::query_scalar::<_, String>(
        "SELECT jid FROM mix_channel_roles WHERE channel_id = $1 AND role = 'administrator' ORDER BY jid",
    )
    .bind(channel_id)
    .fetch_all(&mut *transaction)
    .await?
    .into_iter()
    .collect::<BTreeSet<_>>();
    let owners = requested_owners.as_ref().unwrap_or(&current_owners);
    let administrators = requested_administrators
        .as_ref()
        .unwrap_or(&current_administrators);
    anyhow::ensure!(
        owners.is_disjoint(administrators),
        "a MIX JID cannot have two roles"
    );
    let row = sqlx::query(
        "UPDATE mix_channels SET access_model=$3,jid_visibility=$4,nick_required=$5,
                max_participants=$6,max_events=$7,allow_private_messages=$8,
                allow_participant_invites=$9,allow_user_message_retraction=$10,
                administrator_retraction_rights=$11,enforce_registered_nick=$12,
                revision=revision+1,updated_at=NOW()
          WHERE id=$1 AND revision=$13
            AND EXISTS (SELECT 1 FROM mix_channel_roles
                         WHERE channel_id=$1 AND jid=$2 AND role='owner')
        RETURNING *",
    )
    .bind(channel_id)
    .bind(&actor)
    .bind(update.access_model)
    .bind(update.jid_visibility)
    .bind(update.nick_required)
    .bind(update.max_participants)
    .bind(update.max_events)
    .bind(update.allow_private_messages)
    .bind(update.allow_participant_invites)
    .bind(update.allow_user_message_retraction)
    .bind(update.administrator_retraction_rights)
    .bind(update.enforce_registered_nick)
    .bind(update.expected_revision)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(row) = row else {
        transaction.rollback().await?;
        return Ok(MixMutationOutcome::Conflict);
    };
    let channel = channel_from_row(&row);
    if requested_owners.is_some() {
        sqlx::query("DELETE FROM mix_channel_roles WHERE channel_id = $1 AND role = 'owner'")
            .bind(channel_id)
            .execute(&mut *transaction)
            .await?;
        for owner in owners {
            sqlx::query(
                "INSERT INTO mix_channel_roles (channel_id, jid, role) VALUES ($1, $2, 'owner') ON CONFLICT (channel_id, jid) DO UPDATE SET role = 'owner', updated_at = NOW()",
            )
            .bind(channel_id)
            .bind(owner)
            .execute(&mut *transaction)
            .await?;
        }
    }
    if requested_administrators.is_some() {
        sqlx::query(
            "DELETE FROM mix_channel_roles WHERE channel_id = $1 AND role = 'administrator'",
        )
        .bind(channel_id)
        .execute(&mut *transaction)
        .await?;
        for administrator in administrators {
            sqlx::query(
                "INSERT INTO mix_channel_roles (channel_id, jid, role) VALUES ($1, $2, 'administrator') ON CONFLICT (channel_id, jid) DO UPDATE SET role = 'administrator', updated_at = NOW()",
            )
            .bind(channel_id)
            .bind(administrator)
            .execute(&mut *transaction)
            .await?;
        }
    }
    sqlx::query(
        "UPDATE mix_participants p SET role = COALESCE((SELECT r.role FROM mix_channel_roles r WHERE r.channel_id = p.channel_id AND r.jid = p.jid), 'participant'), updated_at = NOW() WHERE p.channel_id = $1",
    )
    .bind(channel_id)
    .execute(&mut *transaction)
    .await?;
    reproject_mix_presence_visibility_tx(
        &mut transaction,
        &delivery_fence,
        &old_channel,
        &channel,
        payloads,
    )
    .await?;
    let payload = payloads.config_payload(&channel, &actor, owners, administrators);
    let event_id = store_mix_event_tx(
        &mut transaction,
        &channel,
        NODE_CONFIG,
        update.item_id,
        None,
        &payload,
    )
    .await?
    .context("MIX configuration event unexpectedly conflicted")?;
    prune_mix_events_tx(&mut transaction, channel_id, update.max_events).await?;
    let recipients = mix_node_audience_tx(&mut transaction, channel_id, NODE_CONFIG).await?;
    let stanza_template = recipients
        .first()
        .map(|recipient| {
            payloads.node_event_stanza(
                &channel,
                recipient,
                NODE_CONFIG,
                update.item_id,
                Some(&payload),
                false,
            )
        })
        .transpose()?
        .unwrap_or_default();
    enqueue_mix_deliveries_tx(
        &mut transaction,
        &delivery_fence,
        MixDeliveryProjection {
            channel: &channel,
            event_id,
            recipients: &recipients,
            stanza_template: &stanza_template,
            authoritative_stanza_id: None,
            archive: false,
            encrypted: false,
        },
    )
    .await?;
    finalize_federated_mix_mutation_tx(
        effects,
        &mut transaction,
        federated,
        FederatedMixSuccess::PubSubPublish {
            node: NODE_CONFIG.to_owned(),
            item_id: update.item_id.to_owned(),
        },
        payloads,
    )
    .await?;
    transaction.commit().await?;
    Ok(MixMutationOutcome::Applied(Box::new(
        MixMutationAdmission {
            channel,
            node: NODE_CONFIG.to_owned(),
            item_id: update.item_id.to_owned(),
            payload,
            recipients,
        },
    )))
}
