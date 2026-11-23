use super::{ConfigPatch, MixChannel, MixConfigUpdate, MixRoleUpdate, Result};
use northstar_room_core::mix::{
    MixAccessModel, MixAdministratorRetractionRights, MixJidVisibility,
};

pub(super) fn resolve_config<'a>(
    patch: &'a ConfigPatch,
    item_id: &'a str,
    channel: &'a MixChannel,
) -> Result<(MixConfigUpdate<'a>, MixRoleUpdate<'a>)> {
    let fields = &patch.fields;
    let first = |name: &str| {
        fields
            .get(name)
            .and_then(|values| values.first())
            .map(String::as_str)
    };
    let boolean = |name: &str, default| match first(name) {
        None => Ok(default),
        Some("1" | "true") => Ok(true),
        Some("0" | "false") => Ok(false),
        Some(_) => anyhow::bail!("invalid MIX boolean field"),
    };
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
        anyhow::ensure!(
            first(name).is_none_or(|value| value == expected),
            "unsupported MIX configuration value"
        );
    }
    if let Some(nodes) = fields.get("Nodes Present") {
        let expected = [
            "allowed",
            "banned",
            "information",
            "avatar",
            "jidmap-visible",
            "participants",
            "presence",
        ];
        anyhow::ensure!(
            nodes.len() == expected.len()
                && expected
                    .iter()
                    .all(|name| nodes.iter().any(|node| node.as_str() == *name)),
            "unsupported MIX node set"
        );
    }
    let jid_visibility = match first("JID Visibility") {
        Some("jid-hidden") => MixJidVisibility::Hidden,
        Some("jid-maybe-visible") => MixJidVisibility::Maybe,
        Some("jid-mandatory-visible") => MixJidVisibility::Visible,
        Some(_) => anyhow::bail!("unsupported MIX JID visibility mode"),
        None => MixJidVisibility::parse(&channel.jid_visibility)?,
    };
    let nick_required = boolean("Mandatory Nicks", channel.nick_required)?;
    let allow_private_messages = boolean("Private Messages", channel.allow_private_messages)?;
    let allow_participant_invites = boolean(
        "Participation Addition by Invitation from Participant",
        channel.allow_participant_invites,
    )?;
    let allow_user_message_retraction = boolean(
        "User Message Retraction",
        channel.allow_user_message_retraction,
    )?;
    let administrator_retraction_rights = match first("Administrator Message Retraction Rights") {
        None => MixAdministratorRetractionRights::parse(&channel.administrator_retraction_rights)?,
        Some("admins") => MixAdministratorRetractionRights::Administrators,
        Some("nobody") => MixAdministratorRetractionRights::Nobody,
        Some("owners") => MixAdministratorRetractionRights::Owners,
        Some(_) => anyhow::bail!("invalid MIX administrator retraction rights"),
    };
    let enforce_registered_nick =
        boolean("Enforce Registered Nick", channel.enforce_registered_nick)?;
    let access_model =
        MixAccessModel::parse(first("access_model").unwrap_or(&channel.access_model))?;
    Ok((
        MixConfigUpdate {
            item_id,
            expected_revision: patch.expected_revision,
            access_model: access_model.as_str(),
            jid_visibility: jid_visibility.as_str(),
            nick_required,
            max_participants: first("max_participants")
                .and_then(|value| value.parse().ok())
                .unwrap_or(channel.max_participants),
            max_events: first("max_events")
                .and_then(|value| value.parse().ok())
                .unwrap_or(channel.max_events),
            allow_private_messages,
            allow_participant_invites,
            allow_user_message_retraction,
            administrator_retraction_rights: administrator_retraction_rights.as_str(),
            enforce_registered_nick,
        },
        MixRoleUpdate {
            owners: fields.get("Owner").map(Vec::as_slice),
            administrators: fields.get("Administrator").map(Vec::as_slice),
        },
    ))
}

#[cfg(test)]
mod tests;
