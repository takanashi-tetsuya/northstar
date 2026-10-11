//! MIX channel administration: information, configuration and access lists.

use super::*;

pub struct MixInfoUpdate<'a> {
    pub item_id: &'a str,
    pub expected_revision: i64,
    pub name: Option<&'a str>,
    pub description: Option<&'a str>,
    pub contacts: &'a [String],
}

pub struct MixConfigUpdate<'a> {
    pub item_id: &'a str,
    pub expected_revision: i64,
    pub access_model: &'a str,
    pub jid_visibility: &'a str,
    pub nick_required: bool,
    pub max_participants: i32,
    pub max_events: i32,
    pub allow_private_messages: bool,
    pub allow_participant_invites: bool,
    pub allow_user_message_retraction: bool,
    pub administrator_retraction_rights: &'a str,
    pub enforce_registered_nick: bool,
}

pub struct MixRoleUpdate<'a> {
    /// `None` preserves the current list; `Some` atomically replaces it.
    pub owners: Option<&'a [String]>,
    pub administrators: Option<&'a [String]>,
}

#[derive(Clone, Debug)]
pub enum MixMutationOutcome {
    Applied(Box<MixMutationAdmission>),
    Conflict,
    Forbidden,
    NotFound,
}

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
    let entries = sqlx::query_scalar(&statement)
        .bind(channel_id)
        .bind(limit.clamp(1, 500))
        .fetch_all(&mut *transaction)
        .await?;
    transaction.commit().await?;
    Ok(MixReadOutcome::Found(entries))
}

pub async fn update_mix_info(
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

pub async fn update_mix_config(
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

pub async fn set_mix_access_entry(
    pool: &PgPool,
    update: MixAccessEntryUpdate<'_>,
    payloads: &dyn MixEventPayloadRenderer,
    federated: Option<&FederatedMixMutation>,
) -> Result<Option<AccessChangeOutcome>> {
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
                let local_users: Vec<Uuid> = sqlx::query_scalar(
                    "SELECT user_id FROM mix_pam_memberships WHERE channel_jid = $1 AND participant_id = $2",
                )
                .bind(channel.jid())
                .bind(participant_id.to_string())
                .fetch_all(&mut *transaction)
                .await?;
                for user_id in local_users {
                    delete_mix_roster_tx(&mut transaction, user_id, &channel.jid()).await?;
                    outcome.removed_local_users.push(user_id);
                }
                sqlx::query(
                    "DELETE FROM mix_pam_memberships WHERE channel_jid = (SELECT localpart || '@' || service_domain FROM mix_channels WHERE id = $1) AND participant_id = $2",
                )
                .bind(channel_id)
                .bind(participant_id.to_string())
                .execute(&mut *transaction)
                .await?;
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
        &mut transaction,
        federated,
        FederatedMixSuccess::PubSubEmpty,
        payloads,
    )
    .await?;
    transaction.commit().await?;
    outcome.removed_local_users.sort_unstable();
    outcome.removed_local_users.dedup();
    Ok(Some(outcome))
}
