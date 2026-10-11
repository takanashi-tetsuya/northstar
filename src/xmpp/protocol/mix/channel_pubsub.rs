//! Channel PubSub node reads, publishes and retractions, with their form validation.

use super::*;

pub(super) async fn pubsub_get(
    state: &Arc<AppState>,
    request: &OwnedIq,
    channel: &MixChannel,
    actor: &str,
    reply_to: &str,
    node: &str,
    max: i64,
) -> Result<String> {
    if !ALL_NODES.contains(&node) {
        return Ok(iq_error_to(
            &request.id,
            &channel.jid(),
            reply_to,
            "auth",
            "forbidden",
        ));
    }
    // XEP-0403 makes presence a channel-managed node. Clients receive its
    // standard presence fan-out and MUST NOT fetch current state directly via
    // PubSub (MAM remains the explicit historical query path).
    if matches!(node, NODE_MESSAGES | NODE_PRESENCE) {
        return Ok(iq_error_to(
            &request.id,
            &channel.jid(),
            reply_to,
            "cancel",
            "feature-not-implemented",
        ));
    }
    if matches!(node, NODE_ALLOWED | NODE_BANNED) {
        let entries = match state
            .mix_service()
            .authorized_mix_access_entries(channel.id, actor, node == NODE_BANNED, max)
            .await?
        {
            MixReadOutcome::Found(entries) => entries,
            MixReadOutcome::Unauthorized | MixReadOutcome::NotFound => {
                return Ok(iq_error_to(
                    &request.id,
                    &channel.jid(),
                    reply_to,
                    "auth",
                    "forbidden",
                ));
            }
        };
        let mut items = XmlElement::new("items").attr("node", node);
        for entry in &entries {
            items.push_child(XmlElement::new("item").attr("id", entry));
        }
        let payload = XmlElement::namespaced("pubsub", PUBSUB_NS)
            .child(items)
            .finish();
        return Ok(iq_result_to(
            &request.id,
            &channel.jid(),
            reply_to,
            &payload,
        ));
    }
    if node == NODE_JIDMAP {
        let entries = match state
            .mix_service()
            .authorized_mix_jid_map_entries(channel.id, actor, max)
            .await?
        {
            MixReadOutcome::Found(entries) => entries,
            MixReadOutcome::Unauthorized | MixReadOutcome::NotFound => {
                return Ok(iq_error_to(
                    &request.id,
                    &channel.jid(),
                    reply_to,
                    "auth",
                    "forbidden",
                ));
            }
        };
        let mut items = XmlElement::new("items").attr("node", NODE_JIDMAP);
        for (participant_id, jid) in &entries {
            items.push_child(
                XmlElement::new("item").attr("id", participant_id).child(
                    XmlElement::namespaced("participant", ANON_NS)
                        .child(XmlElement::new("jid").text(jid.clone())),
                ),
            );
        }
        let payload = XmlElement::namespaced("pubsub", PUBSUB_NS)
            .child(items)
            .finish();
        return Ok(iq_result_to(
            &request.id,
            &channel.jid(),
            reply_to,
            &payload,
        ));
    }
    let effective_max = if matches!(node, NODE_INFO | NODE_CONFIG) {
        1
    } else {
        max
    };
    let page = match state
        .mix_service()
        .authorized_mix_event_page(channel.id, actor, node, None, effective_max)
        .await?
    {
        MixReadOutcome::Found(page) => page,
        MixReadOutcome::Unauthorized | MixReadOutcome::NotFound => {
            return Ok(iq_error_to(
                &request.id,
                &channel.jid(),
                reply_to,
                "auth",
                "forbidden",
            ));
        }
    };
    let mut items = XmlElement::new("items").attr("node", node);
    for event in page.events.iter().rev() {
        items.push_child(
            XmlElement::new("item")
                .attr("id", &event.item_id)
                .validated_fragment(&event.payload)?,
        );
    }
    let payload = XmlElement::namespaced("pubsub", PUBSUB_NS)
        .child(items)
        .finish();
    Ok(iq_result_to(
        &request.id,
        &channel.jid(),
        reply_to,
        &payload,
    ))
}

pub(super) fn field_first<'a>(
    fields: &'a BTreeMap<String, Vec<String>>,
    name: &str,
) -> Option<&'a str> {
    fields
        .get(name)
        .and_then(|values| values.first())
        .map(String::as_str)
}

pub(super) fn field_bool(
    fields: &BTreeMap<String, Vec<String>>,
    name: &str,
    default: bool,
) -> Result<bool> {
    match field_first(fields, name) {
        None => Ok(default),
        Some("1" | "true") => Ok(true),
        Some("0" | "false") => Ok(false),
        Some(_) => anyhow::bail!("invalid MIX boolean field"),
    }
}

pub(super) fn validate_form_fields(
    fields: &BTreeMap<String, Vec<String>>,
    allowed: &[&str],
    multi_value: &[&str],
) -> Result<()> {
    for (name, values) in fields {
        anyhow::ensure!(allowed.contains(&name.as_str()), "unknown MIX form field");
        if !multi_value.contains(&name.as_str()) {
            anyhow::ensure!(values.len() == 1, "invalid MIX form value count");
        }
    }
    Ok(())
}

pub(super) fn validate_fixed_field(
    fields: &BTreeMap<String, Vec<String>>,
    name: &str,
    expected: &str,
) -> Result<()> {
    if let Some(value) = field_first(fields, name) {
        anyhow::ensure!(value == expected, "unsupported MIX configuration value");
    }
    Ok(())
}

pub(super) fn validate_fixed_config(
    fields: &BTreeMap<String, Vec<String>>,
    channel: &MixChannel,
) -> Result<()> {
    for (name, expected) in [
        ("Messages Node Subscription", "participants"),
        ("Presence Node Subscription", "participants"),
        ("Participants Node Subscription", "participants"),
        (
            "Information Node Subscription",
            if channel.access_model == "open" {
                "anyone"
            } else {
                "participants"
            },
        ),
        ("Allowed Node Subscription", "admins"),
        ("Banned Node Subscription", "admins"),
        ("Configuration Node Access", "admins"),
        ("Information Node Update Rights", "admins"),
        ("Avatar Nodes Update Rights", "admins"),
        ("Participants Must Provide Presence", "0"),
        ("Open Presence", "0"),
    ] {
        validate_fixed_field(fields, name, expected)?;
    }
    if let Some(nodes) = fields.get("Nodes Present") {
        let actual = nodes
            .iter()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        let expected = [
            "allowed",
            "banned",
            "information",
            "avatar",
            "jidmap-visible",
            "participants",
            "presence",
        ]
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
        anyhow::ensure!(
            actual.len() == nodes.len() && actual == expected,
            "unsupported MIX node set"
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn pubsub_publish(
    state: &Arc<AppState>,
    request: &OwnedIq,
    channel: &MixChannel,
    actor: &str,
    reply_to: &str,
    node: &str,
    item_count: usize,
    item_ids: &[String],
    fields: &BTreeMap<String, Vec<String>>,
    payloads: &[String],
    federated: Option<&FederatedMixMutation>,
) -> Result<String> {
    anyhow::ensure!(
        payloads.len() == item_count,
        "MIX publish payload count mismatch"
    );
    match node {
        NODE_AVATAR_DATA | NODE_AVATAR_METADATA => {
            anyhow::ensure!(
                item_count == 1 && item_ids.len() == 1 && payloads.len() == 1,
                "MIX avatar publish requires one identified item"
            );
            anyhow::ensure!(fields.is_empty(), "MIX avatar item cannot contain a form");
            let payload_document =
                Document::parse(&payloads[0]).context("malformed MIX avatar payload")?;
            let payload = payload_document.root_element();
            let valid = if node == NODE_AVATAR_DATA {
                super::super::pep::valid_avatar_data(&item_ids[0], payload)
            } else {
                super::super::pep::valid_avatar_metadata(&item_ids[0], payload)
            };
            anyhow::ensure!(valid, "invalid MIX avatar payload");
            if !state
                .mix_service()
                .publish_mix_avatar(
                    channel.id,
                    actor,
                    node,
                    &item_ids[0],
                    &payloads[0],
                    federated,
                )
                .await?
            {
                return Ok(iq_error_to(
                    &request.id,
                    &channel.jid(),
                    reply_to,
                    "auth",
                    "forbidden",
                ));
            }
            let acknowledgement = mix_pubsub_publish_ack(node, &item_ids[0]);
            return Ok(iq_result_to(
                &request.id,
                &channel.jid(),
                reply_to,
                &acknowledgement,
            ));
        }
        NODE_INFO => {
            anyhow::ensure!(item_count == 1, "MIX information publish requires one item");
            validate_form_fields(
                fields,
                &[
                    "FORM_TYPE",
                    "Name",
                    "Description",
                    "Contact",
                    "JID Visibility",
                ],
                &["Contact"],
            )?;
            anyhow::ensure!(
                field_first(fields, "FORM_TYPE") == Some(CORE_NS),
                "invalid MIX information form type"
            );
            let expected_visibility = if channel.jid_visibility == "visible" {
                "jid-mandatory-visible"
            } else if channel.jid_visibility == "maybe" {
                "jid-maybe-visible"
            } else {
                "jid-hidden"
            };
            validate_fixed_field(fields, "JID Visibility", expected_visibility)?;
            let current = state
                .mix_service()
                .mix_channel(&channel.service_domain, &channel.localpart)
                .await?
                .context("MIX channel disappeared")?;
            let name = field_first(fields, "Name").or(current.name.as_deref());
            let description = field_first(fields, "Description").or(current.description.as_deref());
            let contacts = fields.get("Contact").cloned().unwrap_or(current.contacts);
            let item_id = crate::services::mix::mix_timestamp_item_id();
            let mutation = state
                .mix_service()
                .update_mix_info(
                    channel.id,
                    actor,
                    MixInfoUpdate {
                        item_id: item_id.clone(),
                        expected_revision: current.revision,
                        name: name.map(str::to_owned),
                        description: description.map(str::to_owned),
                        contacts: contacts.clone(),
                    },
                    federated,
                )
                .await?;
            let admission = match mutation {
                MixMutationOutcome::Applied(admission) => admission,
                MixMutationOutcome::Conflict => {
                    return Ok(iq_error_to(
                        &request.id,
                        &channel.jid(),
                        reply_to,
                        "cancel",
                        "conflict",
                    ));
                }
                MixMutationOutcome::NotFound => {
                    return Ok(iq_error_to(
                        &request.id,
                        &channel.jid(),
                        reply_to,
                        "cancel",
                        "item-not-found",
                    ));
                }
                MixMutationOutcome::Forbidden => {
                    return Ok(iq_error_to(
                        &request.id,
                        &channel.jid(),
                        reply_to,
                        "auth",
                        "forbidden",
                    ));
                }
            };
            // The exact committed payload and recipient snapshot were placed
            // in the durable MIX outbox by the mutation transaction.
            debug_assert_eq!(admission.channel.id, channel.id);
            debug_assert_eq!(admission.node, NODE_INFO);
            debug_assert!(!admission.payload.is_empty());
            let _committed_recipient_count = admission.recipients.len();
            let acknowledgement = mix_pubsub_publish_ack(&admission.node, &admission.item_id);
            return Ok(iq_result_to(
                &request.id,
                &channel.jid(),
                reply_to,
                &acknowledgement,
            ));
        }
        NODE_CONFIG => {
            anyhow::ensure!(
                item_count == 1,
                "MIX configuration publish requires one item"
            );
            validate_form_fields(
                fields,
                &[
                    "FORM_TYPE",
                    "Last Change Made By",
                    "Owner",
                    "Administrator",
                    "Nodes Present",
                    "Messages Node Subscription",
                    "Presence Node Subscription",
                    "Participants Node Subscription",
                    "Information Node Subscription",
                    "Allowed Node Subscription",
                    "Banned Node Subscription",
                    "Configuration Node Access",
                    "Information Node Update Rights",
                    "Avatar Nodes Update Rights",
                    "JID Visibility",
                    "Mandatory Nicks",
                    "Participants Must Provide Presence",
                    "Open Presence",
                    "User Message Retraction",
                    "Administrator Message Retraction Rights",
                    "Participation Addition by Invitation from Participant",
                    "Private Messages",
                    "Enforce Registered Nick",
                    "access_model",
                    "max_participants",
                    "max_events",
                ],
                &["Owner", "Administrator", "Nodes Present"],
            )?;
            anyhow::ensure!(
                field_first(fields, "FORM_TYPE") == Some(ADMIN_NS),
                "invalid MIX administration form type"
            );
            let role = state.mix_service().mix_role(channel.id, actor).await?;
            if role.as_deref() != Some("owner") {
                return Ok(iq_error_to(
                    &request.id,
                    &channel.jid(),
                    reply_to,
                    "auth",
                    "forbidden",
                ));
            }
            validate_fixed_config(fields, channel)?;
            let access_model = field_first(fields, "access_model").unwrap_or(&channel.access_model);
            let visibility = match field_first(fields, "JID Visibility") {
                Some("jid-hidden") => "hidden",
                Some("jid-maybe-visible") => "maybe",
                Some("jid-mandatory-visible") => "visible",
                Some(_) => anyhow::bail!("unsupported MIX JID visibility mode"),
                None => &channel.jid_visibility,
            };
            let nick_required = field_bool(fields, "Mandatory Nicks", channel.nick_required)?;
            let allow_private_messages =
                field_bool(fields, "Private Messages", channel.allow_private_messages)?;
            let allow_participant_invites = field_bool(
                fields,
                "Participation Addition by Invitation from Participant",
                channel.allow_participant_invites,
            )?;
            let allow_user_message_retraction = field_bool(
                fields,
                "User Message Retraction",
                channel.allow_user_message_retraction,
            )?;
            let administrator_retraction_rights =
                match field_first(fields, "Administrator Message Retraction Rights") {
                    None => channel.administrator_retraction_rights.as_str(),
                    Some("admins") => "administrators",
                    Some(value @ ("nobody" | "owners")) => value,
                    Some(_) => anyhow::bail!("invalid MIX administrator retraction rights"),
                };
            let enforce_registered_nick = field_bool(
                fields,
                "Enforce Registered Nick",
                channel.enforce_registered_nick,
            )?;
            let max_participants = field_first(fields, "max_participants")
                .and_then(|value| value.parse().ok())
                .unwrap_or(channel.max_participants);
            let max_events = field_first(fields, "max_events")
                .and_then(|value| value.parse().ok())
                .unwrap_or(channel.max_events);
            let item_id = crate::services::mix::mix_timestamp_item_id();
            let mutation = state
                .mix_service()
                .update_mix_config(
                    channel.id,
                    actor,
                    MixConfigUpdate {
                        item_id: item_id.clone(),
                        expected_revision: channel.revision,
                        access_model: access_model.to_owned(),
                        jid_visibility: visibility.to_owned(),
                        nick_required,
                        max_participants,
                        max_events,
                        allow_private_messages,
                        allow_participant_invites,
                        allow_user_message_retraction,
                        administrator_retraction_rights: administrator_retraction_rights.to_owned(),
                        enforce_registered_nick,
                    },
                    MixRoleUpdate {
                        owners: fields.get("Owner").cloned(),
                        administrators: fields.get("Administrator").cloned(),
                    },
                    federated,
                )
                .await?;
            let admission = match mutation {
                MixMutationOutcome::Applied(admission) => admission,
                MixMutationOutcome::Conflict => {
                    return Ok(iq_error_to(
                        &request.id,
                        &channel.jid(),
                        reply_to,
                        "cancel",
                        "conflict",
                    ));
                }
                MixMutationOutcome::NotFound => {
                    return Ok(iq_error_to(
                        &request.id,
                        &channel.jid(),
                        reply_to,
                        "cancel",
                        "item-not-found",
                    ));
                }
                MixMutationOutcome::Forbidden => {
                    return Ok(iq_error_to(
                        &request.id,
                        &channel.jid(),
                        reply_to,
                        "auth",
                        "forbidden",
                    ));
                }
            };
            // The exact committed payload and recipient snapshot were placed
            // in the durable MIX outbox by the mutation transaction.
            debug_assert_eq!(admission.channel.id, channel.id);
            debug_assert_eq!(admission.node, NODE_CONFIG);
            debug_assert!(!admission.payload.is_empty());
            let _committed_recipient_count = admission.recipients.len();
            let acknowledgement = mix_pubsub_publish_ack(&admission.node, &admission.item_id);
            return Ok(iq_result_to(
                &request.id,
                &channel.jid(),
                reply_to,
                &acknowledgement,
            ));
        }
        NODE_ALLOWED | NODE_BANNED => {
            anyhow::ensure!(
                item_count == 1 && item_ids.len() == 1,
                "MIX access publish requires one identified item"
            );
            anyhow::ensure!(
                fields.is_empty(),
                "MIX access items do not contain payloads"
            );
            let pattern = crate::services::mix::canonical_mix_access_pattern(&item_ids[0])?;
            let Some(outcome) = state
                .mix_service()
                .set_mix_access_entry(
                    MixAccessEntryUpdate {
                        channel_id: channel.id,
                        actor,
                        pattern: &pattern,
                        list: if node == NODE_BANNED {
                            MixAccessList::Banned
                        } else {
                            MixAccessList::Allowed
                        },
                        operation: MixAccessEntryOperation::Publish { reason: None },
                    },
                    federated,
                )
                .await?
            else {
                return Ok(iq_error_to(
                    &request.id,
                    &channel.jid(),
                    reply_to,
                    "auth",
                    "forbidden",
                ));
            };
            let _ = (&outcome.removed_presence, &outcome.removed_participants);
            for user_id in outcome.removed_local_users {
                if let Some(user) = state.mix_service().find_enabled_user_by_id(user_id).await? {
                    push_mix_roster_update(state, &user, &channel.jid(), true).await?;
                }
            }
        }
        _ => {
            return Ok(iq_error_to(
                &request.id,
                &channel.jid(),
                reply_to,
                "auth",
                "forbidden",
            ));
        }
    }
    Ok(iq_result_to(
        &request.id,
        &channel.jid(),
        reply_to,
        &mix_empty_pubsub(),
    ))
}

pub(super) struct PubSubRetractRequest<'a> {
    pub(super) request: &'a OwnedIq,
    pub(super) channel: &'a MixChannel,
    pub(super) actor: &'a str,
    pub(super) reply_to: &'a str,
    pub(super) node: &'a str,
    pub(super) item_ids: &'a [String],
    pub(super) federated: Option<&'a FederatedMixMutation>,
}

pub(super) async fn pubsub_retract(
    state: &Arc<AppState>,
    operation: PubSubRetractRequest<'_>,
) -> Result<String> {
    let PubSubRetractRequest {
        request,
        channel,
        actor,
        reply_to,
        node,
        item_ids,
        federated,
    } = operation;
    if matches!(node, NODE_AVATAR_DATA | NODE_AVATAR_METADATA) && item_ids.len() == 1 {
        if !state
            .mix_service()
            .retract_mix_avatar(channel.id, actor, node, &item_ids[0], federated)
            .await?
        {
            return Ok(iq_error_to(
                &request.id,
                &channel.jid(),
                reply_to,
                "auth",
                "forbidden",
            ));
        }
        return Ok(iq_result_to(
            &request.id,
            &channel.jid(),
            reply_to,
            &mix_empty_pubsub(),
        ));
    }
    if !matches!(node, NODE_ALLOWED | NODE_BANNED) || item_ids.len() != 1 {
        return Ok(iq_error_to(
            &request.id,
            &channel.jid(),
            reply_to,
            "auth",
            "forbidden",
        ));
    }
    let pattern = crate::services::mix::canonical_mix_access_pattern(&item_ids[0])?;
    let Some(_) = state
        .mix_service()
        .set_mix_access_entry(
            MixAccessEntryUpdate {
                channel_id: channel.id,
                actor,
                pattern: &pattern,
                list: if node == NODE_BANNED {
                    MixAccessList::Banned
                } else {
                    MixAccessList::Allowed
                },
                operation: MixAccessEntryOperation::Retract,
            },
            federated,
        )
        .await?
    else {
        return Ok(iq_error_to(
            &request.id,
            &channel.jid(),
            reply_to,
            "auth",
            "forbidden",
        ));
    };
    Ok(iq_result_to(
        &request.id,
        &channel.jid(),
        reply_to,
        &mix_empty_pubsub(),
    ))
}
