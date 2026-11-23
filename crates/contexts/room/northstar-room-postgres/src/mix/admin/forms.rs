use super::super::*;
use northstar_room_application::mix_service::{ConfigPatch, InfoPatch};
use northstar_room_core::mix::{MixChannelId, MixJidVisibility, MixRealJid};

mod config_patch;

const LOCK_FORM_CHANNEL: &str = "SELECT * FROM mix_channels WHERE id = $1 FOR UPDATE";

enum InfoInput<'a> {
    Replacement(MixInfoUpdate<'a>, serde_json::Value),
    Patch(&'a InfoPatch, &'a str),
}

pub async fn update_mix_info(
    effects: &impl crate::effects::RoomEffects,
    pool: &PgPool,
    channel_id: Uuid,
    actor: &str,
    update: MixInfoUpdate<'_>,
    payloads: &dyn MixEventPayloadRenderer,
    federated: Option<&FederatedMixMutation>,
) -> Result<MixMutationOutcome> {
    let actor = MixRealJid::parse(actor)?;
    let contacts = validate_info(update.name, update.description, update.contacts)?;
    apply_info_update(
        effects,
        pool,
        MixChannelId::new(channel_id),
        &actor,
        InfoInput::Replacement(update, contacts),
        payloads,
        federated,
    )
    .await
}

fn validate_info(
    name: Option<&str>,
    description: Option<&str>,
    contacts: &[String],
) -> Result<serde_json::Value> {
    anyhow::ensure!(
        name.is_none_or(|value| value.len() <= 512),
        "MIX name too large"
    );
    anyhow::ensure!(
        description.is_none_or(|value| value.len() <= 4096),
        "MIX description too large"
    );
    anyhow::ensure!(contacts.len() <= 64, "too many MIX contacts");
    let contacts = contacts
        .iter()
        .map(|jid| MixRealJid::parse(jid))
        .collect::<Result<Vec<_>>>()?;
    anyhow::ensure!(
        contacts
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len()
            == contacts.len(),
        "MIX contacts contain duplicate canonical JIDs"
    );
    let contacts =
        serde_json::to_value(contacts.iter().map(MixRealJid::as_str).collect::<Vec<_>>())?;
    Ok(contacts)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn apply_info_patch(
    effects: &impl crate::effects::RoomEffects,
    pool: &PgPool,
    channel_id: MixChannelId,
    actor: &MixRealJid,
    patch: &InfoPatch,
    item_id: &str,
    payloads: &dyn MixEventPayloadRenderer,
    federated: Option<&FederatedMixMutation>,
) -> Result<MixMutationOutcome> {
    apply_info_update(
        effects,
        pool,
        channel_id,
        actor,
        InfoInput::Patch(patch, item_id),
        payloads,
        federated,
    )
    .await
}

async fn apply_info_update(
    effects: &impl crate::effects::RoomEffects,
    pool: &PgPool,
    channel_id: MixChannelId,
    actor: &MixRealJid,
    input: InfoInput<'_>,
    payloads: &dyn MixEventPayloadRenderer,
    federated: Option<&FederatedMixMutation>,
) -> Result<MixMutationOutcome> {
    let channel_id = channel_id.as_uuid();
    let (mut transaction, delivery_fence) = begin_mix_delivery_admission(pool).await?;
    guard_federated_mix_mutation_tx(&mut transaction, federated).await?;
    let locked = sqlx::query(LOCK_FORM_CHANNEL)
        .bind(channel_id)
        .fetch_optional(&mut *transaction)
        .await?;
    let Some(locked) = locked else {
        transaction.rollback().await?;
        return Ok(MixMutationOutcome::NotFound);
    };
    let current = channel_from_row(&locked);
    let (item_id, expected_revision, name, description, contacts) = match input {
        InfoInput::Replacement(update, contacts) => (
            update.item_id,
            update.expected_revision,
            update.name,
            update.description,
            contacts,
        ),
        InfoInput::Patch(patch, item_id) => {
            if let Some(assertion) = patch.visibility {
                anyhow::ensure!(
                    MixJidVisibility::parse(&current.jid_visibility)? == assertion,
                    "unsupported MIX configuration value"
                );
            }
            let name = patch.name.as_deref().or(current.name.as_deref());
            let description = patch
                .description
                .as_deref()
                .or(current.description.as_deref());
            let contacts = patch.contacts.as_deref().unwrap_or(&current.contacts);
            (
                item_id,
                current.revision,
                name,
                description,
                validate_info(name, description, contacts)?,
            )
        }
    };
    if current.revision != expected_revision {
        transaction.rollback().await?;
        return Ok(MixMutationOutcome::Conflict);
    }
    let authorized: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM mix_channel_roles WHERE channel_id = $1 AND jid = $2 AND role IN ('owner', 'administrator'))",
    )
    .bind(channel_id)
    .bind(actor.as_str())
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
    .bind(name)
    .bind(description)
    .bind(contacts)
    .bind(expected_revision)
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
        item_id,
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
                item_id,
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
            item_id: item_id.to_owned(),
        },
        payloads,
    )
    .await?;
    transaction.commit().await?;
    Ok(MixMutationOutcome::Applied(Box::new(
        MixMutationAdmission {
            channel,
            node: NODE_INFO.to_owned(),
            item_id: item_id.to_owned(),
            payload,
            recipients,
        },
    )))
}

struct ValidatedConfig<'a> {
    update: MixConfigUpdate<'a>,
    requested_owners: Option<BTreeSet<String>>,
    requested_administrators: Option<BTreeSet<String>>,
}

enum ConfigInput<'a> {
    Replacement(ValidatedConfig<'a>),
    Patch(&'a ConfigPatch, &'a str),
}

fn validate_config<'a>(
    update: MixConfigUpdate<'a>,
    roles: MixRoleUpdate<'_>,
) -> Result<ValidatedConfig<'a>> {
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
    Ok(ValidatedConfig {
        update,
        requested_owners,
        requested_administrators,
    })
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
    let actor = MixRealJid::parse(actor)?;
    let update = validate_config(update, roles)?;
    apply_config_update(
        effects,
        pool,
        MixChannelId::new(channel_id),
        &actor,
        ConfigInput::Replacement(update),
        payloads,
        federated,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn apply_config_patch(
    effects: &impl crate::effects::RoomEffects,
    pool: &PgPool,
    channel_id: MixChannelId,
    actor: &MixRealJid,
    patch: &ConfigPatch,
    item_id: &str,
    payloads: &dyn MixEventPayloadRenderer,
    federated: Option<&FederatedMixMutation>,
) -> Result<MixMutationOutcome> {
    apply_config_update(
        effects,
        pool,
        channel_id,
        actor,
        ConfigInput::Patch(patch, item_id),
        payloads,
        federated,
    )
    .await
}

async fn apply_config_update(
    effects: &impl crate::effects::RoomEffects,
    pool: &PgPool,
    channel_id: MixChannelId,
    actor: &MixRealJid,
    input: ConfigInput<'_>,
    payloads: &dyn MixEventPayloadRenderer,
    federated: Option<&FederatedMixMutation>,
) -> Result<MixMutationOutcome> {
    let channel_id = channel_id.as_uuid();
    let (mut transaction, delivery_fence) = begin_mix_delivery_admission(pool).await?;
    guard_federated_mix_mutation_tx(&mut transaction, federated).await?;
    let locked = sqlx::query(LOCK_FORM_CHANNEL)
        .bind(channel_id)
        .fetch_optional(&mut *transaction)
        .await?;
    let Some(locked) = locked else {
        transaction.rollback().await?;
        return Ok(MixMutationOutcome::NotFound);
    };
    let old_channel = channel_from_row(&locked);
    if matches!(&input, ConfigInput::Replacement(config) if old_channel.revision != config.update.expected_revision)
    {
        transaction.rollback().await?;
        return Ok(MixMutationOutcome::Conflict);
    }
    let actor_is_owner: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM mix_channel_roles WHERE channel_id = $1 AND jid = $2 AND role = 'owner')",
    )
    .bind(channel_id)
    .bind(actor.as_str())
    .fetch_one(&mut *transaction)
    .await?;
    if !actor_is_owner {
        transaction.rollback().await?;
        return Ok(MixMutationOutcome::Forbidden);
    }
    let ValidatedConfig {
        update,
        requested_owners,
        requested_administrators,
    } = match input {
        ConfigInput::Replacement(config) => config,
        ConfigInput::Patch(patch, item_id) => {
            let (update, roles) = config_patch::resolve_config(patch, item_id, &old_channel)?;
            validate_config(update, roles)?
        }
    };
    if old_channel.revision != update.expected_revision {
        transaction.rollback().await?;
        return Ok(MixMutationOutcome::Conflict);
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
    .bind(actor.as_str())
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
    let payload = payloads.config_payload(&channel, actor.as_str(), owners, administrators);
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
