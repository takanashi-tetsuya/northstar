use super::*;
use northstar_room_application::mix_service::{ConfigPatch, InfoPatch};
use northstar_room_core::mix::{MixChannelId, MixJidVisibility, MixRealJid};

pub fn field_first<'a>(fields: &'a BTreeMap<String, Vec<String>>, name: &str) -> Option<&'a str> {
    fields
        .get(name)
        .and_then(|values| values.first())
        .map(String::as_str)
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

#[allow(clippy::too_many_arguments)]
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
    let patch = parse_info_patch(fields)?;
    let mutation = state
        .mix_service()
        .update_info(
            MixChannelId::new(channel.id),
            &MixRealJid::parse(actor)?,
            patch,
            federated,
        )
        .await?;
    Ok(publication_reply(
        &request.id,
        channel,
        reply_to,
        NODE_INFO,
        mutation,
    ))
}

fn parse_info_patch(fields: &BTreeMap<String, Vec<String>>) -> Result<InfoPatch> {
    let visibility = match field_first(fields, "JID Visibility") {
        None => None,
        Some("jid-hidden") => Some(MixJidVisibility::Hidden),
        Some("jid-maybe-visible") => Some(MixJidVisibility::Maybe),
        Some("jid-mandatory-visible") => Some(MixJidVisibility::Visible),
        Some(_) => anyhow::bail!("unsupported MIX configuration value"),
    };
    Ok(InfoPatch {
        name: field_first(fields, "Name").map(str::to_owned),
        description: field_first(fields, "Description").map(str::to_owned),
        contacts: fields.get("Contact").cloned(),
        visibility,
    })
}

#[allow(clippy::too_many_arguments)]
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
    let mutation = state
        .mix_service()
        .update_config(
            MixChannelId::new(channel.id),
            &MixRealJid::parse(actor)?,
            ConfigPatch {
                expected_revision: channel.revision,
                fields: fields.clone(),
            },
            federated,
        )
        .await?;
    Ok(publication_reply(
        &request.id,
        channel,
        reply_to,
        NODE_CONFIG,
        mutation,
    ))
}

fn publication_reply(
    request_id: &str,
    channel: &MixChannel,
    reply_to: &str,
    node: &str,
    mutation: MixMutationOutcome,
) -> String {
    let admission = match mutation {
        MixMutationOutcome::Applied(admission) => admission,
        MixMutationOutcome::Conflict => {
            return iq_error_to(request_id, &channel.jid(), reply_to, "cancel", "conflict");
        }
        MixMutationOutcome::NotFound => {
            return iq_error_to(
                request_id,
                &channel.jid(),
                reply_to,
                "cancel",
                "item-not-found",
            );
        }
        MixMutationOutcome::Forbidden => {
            return iq_error_to(request_id, &channel.jid(), reply_to, "auth", "forbidden");
        }
    };
    // The exact committed payload and recipient snapshot were placed
    // in the durable MIX outbox by the mutation transaction.
    debug_assert_eq!(admission.channel.id, channel.id);
    debug_assert_eq!(admission.node, node);
    debug_assert!(!admission.payload.is_empty());
    let _committed_recipient_count = admission.recipients.len();
    let acknowledgement = mix_pubsub_publish_ack(&admission.node, &admission.item_id);
    iq_result_to(request_id, &channel.jid(), reply_to, &acknowledgement)
}

#[cfg(test)]
mod tests;
