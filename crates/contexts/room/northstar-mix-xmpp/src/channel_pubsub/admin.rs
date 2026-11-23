use super::*;

pub fn field_first<'a>(fields: &'a BTreeMap<String, Vec<String>>, name: &str) -> Option<&'a str> {
    fields
        .get(name)
        .and_then(|values| values.first())
        .map(String::as_str)
}

pub fn field_bool(
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

pub fn validate_form_fields(
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

pub fn validate_fixed_field(
    fields: &BTreeMap<String, Vec<String>>,
    name: &str,
    expected: &str,
) -> Result<()> {
    if let Some(value) = field_first(fields, name) {
        anyhow::ensure!(value == expected, "unsupported MIX configuration value");
    }
    Ok(())
}

pub fn validate_fixed_config(
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

#[allow(clippy::needless_return, clippy::too_many_arguments)]
pub(super) async fn publish_info(
    state: &Arc<impl MixHost>,
    request: &OwnedIq,
    channel: &MixChannel,
    actor: &str,
    reply_to: &str,
    item_count: usize,
    fields: &BTreeMap<String, Vec<String>>,
    federated: Option<&FederatedMixMutation>,
) -> Result<String> {
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
    let item_id = northstar_room_application::mix_service::mix_timestamp_item_id();
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

#[allow(clippy::needless_return, clippy::too_many_arguments)]
pub(super) async fn publish_config(
    state: &Arc<impl MixHost>,
    request: &OwnedIq,
    channel: &MixChannel,
    actor: &str,
    reply_to: &str,
    item_count: usize,
    fields: &BTreeMap<String, Vec<String>>,
    federated: Option<&FederatedMixMutation>,
) -> Result<String> {
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
    let item_id = northstar_room_application::mix_service::mix_timestamp_item_id();
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
