//! Defines and implements MIX event, federation result, and PAM payload rendering.

use super::*;

pub(super) fn mix_preference_result_form(preference: &MixParticipantPreference) -> String {
    let value = |variable: &'static str, kind: Option<&'static str>, text: &str| {
        XmlElement::new("field")
            .attr("var", variable)
            .optional_attr("type", kind)
            .child(XmlElement::new("value").text(text))
    };
    XmlElement::namespaced("x", "jabber:x:data")
        .attr("type", "result")
        .child(value("FORM_TYPE", Some("hidden"), "urn:xmpp:mix:anon:0"))
        .child(value("JID Visibility", None, &preference.jid_visibility))
        .child(value(
            "Private Messages",
            None,
            &preference.private_messages,
        ))
        .child(value("vCard", None, &preference.vcard))
        .child(value(
            "Presence",
            None,
            if preference.share_presence {
                "share"
            } else {
                "not share"
            },
        ))
        .finish()
}

pub(super) fn render_federated_mix_iq_result(
    context: &FederatedMixMutation,
    success: &FederatedMixSuccess,
) -> Result<String> {
    let payload = match success {
        FederatedMixSuccess::Create { channel } => {
            XmlElement::namespaced("create", "urn:xmpp:mix:core:1")
                .attr("channel", channel)
                .finish()
        }
        FederatedMixSuccess::Destroy { channel } => {
            XmlElement::namespaced("destroy", "urn:xmpp:mix:core:1")
                .attr("channel", channel)
                .finish()
        }
        FederatedMixSuccess::RegisterNick { nick } => {
            XmlElement::namespaced("register", "urn:xmpp:mix:misc:0")
                .child(XmlElement::new("nick").text(nick))
                .finish()
        }
        FederatedMixSuccess::Join {
            participant,
            subscriptions,
            preference,
            anonymous_profile,
        } => {
            let mut join = XmlElement::namespaced(
                "join",
                if *anonymous_profile {
                    "urn:xmpp:mix:anon:0"
                } else {
                    "urn:xmpp:mix:core:1"
                },
            )
            .attr("id", participant.participant_id);
            for node in subscriptions {
                join.push_child(XmlElement::new("subscribe").attr("node", node));
            }
            if let Some(nick) = participant.nick.as_deref() {
                join.push_child(XmlElement::new("nick").text(nick));
            }
            if let Some(preference) = preference {
                join.push_validated_fragment(&mix_preference_result_form(preference))?;
            }
            join.finish()
        }
        FederatedMixSuccess::Leave => {
            XmlElement::namespaced("leave", "urn:xmpp:mix:core:1").finish()
        }
        FederatedMixSuccess::SetNick { nick } => {
            XmlElement::namespaced("setnick", "urn:xmpp:mix:core:1")
                .child(XmlElement::new("nick").text(nick))
                .finish()
        }
        FederatedMixSuccess::UpdateSubscriptions { subscriptions } => {
            let mut update = XmlElement::namespaced("update-subscription", "urn:xmpp:mix:core:1");
            for node in subscriptions {
                update.push_child(XmlElement::new("subscribe").attr("node", node));
            }
            update.finish()
        }
        FederatedMixSuccess::PubSubPublish { node, item_id } => {
            XmlElement::namespaced("pubsub", "http://jabber.org/protocol/pubsub")
                .child(
                    XmlElement::new("publish")
                        .attr("node", node)
                        .child(XmlElement::new("item").attr("id", item_id)),
                )
                .finish()
        }
        FederatedMixSuccess::PubSubEmpty => {
            XmlElement::namespaced("pubsub", "http://jabber.org/protocol/pubsub").finish()
        }
        FederatedMixSuccess::Preference { preference } => {
            XmlElement::namespaced("user-preference", "urn:xmpp:mix:anon:0")
                .validated_fragment(&mix_preference_result_form(preference))?
                .finish()
        }
        FederatedMixSuccess::Invitation {
            inviter,
            invitee,
            channel,
            token,
        } => XmlElement::namespaced("invite", "urn:xmpp:mix:misc:0")
            .child(
                XmlElement::new("invitation")
                    .child(XmlElement::new("inviter").text(inviter))
                    .child(XmlElement::new("invitee").text(invitee))
                    .child(XmlElement::new("channel").text(channel))
                    .child(XmlElement::new("token").text(token)),
            )
            .finish(),
    };
    Ok(XmlElement::namespaced("iq", "jabber:client")
        .attr("type", "result")
        .attr("from", &context.addressed)
        .attr("to", &context.reply_to)
        .attr("id", &context.request_id)
        .validated_fragment(&payload)?
        .finish())
}

#[derive(Clone)]
pub(crate) struct MixPayloads;

impl MixEventPayloadRenderer for MixPayloads {
    fn info_payload(&self, channel: &MixChannel) -> String {
        render_info_payload(channel)
    }

    fn config_payload(
        &self,
        channel: &MixChannel,
        last_changed_by: &str,
        owners: &BTreeSet<String>,
        administrators: &BTreeSet<String>,
    ) -> String {
        render_config_payload(channel, last_changed_by, owners, administrators)
    }

    fn participant_payload(
        &self,
        channel: &MixChannel,
        participant: &MixParticipant,
        preference: &MixParticipantPreference,
    ) -> String {
        render_participant_payload(channel, participant, preference)
    }

    fn access_payload(&self, pattern: &str) -> String {
        render_access_payload(pattern)
    }

    fn presence_delivery_stanza(&self, delivery: MixPresenceDelivery<'_>) -> Result<String> {
        let MixPresenceDelivery {
            channel,
            participant,
            preference,
            recipient,
            item_id,
            actor_full,
            children,
            unavailable,
        } = delivery;
        let encoded = northstar_xmpp_types::jid::CanonicalJid::parse(item_id)?;
        anyhow::ensure!(
            encoded.resourcepart().is_some(),
            "MIX reflected presence requires an encoded full JID"
        );
        let mut mix = XmlElement::namespaced("mix", "urn:xmpp:mix:presence:0");
        if participant_jid_visible(channel, preference) {
            mix.push_child(XmlElement::new("jid").text(actor_full));
        }
        if let Some(nick) = participant.nick.as_deref() {
            mix.push_child(XmlElement::new("nick").text(nick));
        }
        let mut presence = XmlElement::namespaced("presence", "jabber:client")
            .attr("from", encoded.to_string())
            .attr("to", &recipient.jid)
            .attr("id", Uuid::new_v4())
            .optional_attr("type", unavailable.then_some("unavailable"))
            .child(mix);
        presence.push_validated_fragment(children)?;
        Ok(presence.finish())
    }

    fn node_event_stanza(
        &self,
        channel: &MixChannel,
        recipient: &MixParticipant,
        node: &str,
        item_id: &str,
        payload: Option<&str>,
        retract: bool,
    ) -> Result<String> {
        let mut items = XmlElement::new("items").attr("node", node);
        if retract {
            items.push_child(XmlElement::new("retract").attr("id", item_id));
        } else {
            let mut item = XmlElement::new("item").attr("id", item_id);
            if let Some(payload) = payload {
                item.push_validated_fragment(payload)?;
            }
            items.push_child(item);
        }
        Ok(XmlElement::namespaced("message", "jabber:client")
            .attr("from", channel.jid())
            .attr("to", &recipient.jid)
            .attr("id", Uuid::new_v4())
            .child(
                XmlElement::namespaced("event", "http://jabber.org/protocol/pubsub#event")
                    .child(items),
            )
            .finish())
    }

    fn message_delivery_stanza(
        &self,
        channel: &MixChannel,
        sender: &MixParticipant,
        recipient: &MixParticipant,
        authoritative_id: Uuid,
        payload: &str,
        visible_jid: Option<&str>,
    ) -> Result<String> {
        let participant_address = format!("{}/{}", channel.jid(), sender.participant_id);
        let mut stanza = XmlElement::namespaced("message", "jabber:client")
            .attr("from", &participant_address)
            .attr("to", &recipient.jid)
            .attr("id", authoritative_id)
            .attr("type", "groupchat")
            .validated_fragment(payload)?;
        let mut identity = XmlElement::namespaced("mix", "urn:xmpp:mix:core:1");
        if let Some(nick) = sender.nick.as_deref() {
            identity.push_child(XmlElement::new("nick").text(nick));
        }
        if let Some(jid) = visible_jid {
            identity.push_child(XmlElement::new("jid").text(jid));
        }
        stanza.push_child(identity);
        Ok(crate::services::xml_util::add_stanza_id(
            &stanza.finish(),
            &channel.jid(),
            authoritative_id,
        ))
    }

    fn retraction_delivery_stanza(
        &self,
        channel: &MixChannel,
        sender: &MixParticipant,
        recipient: &MixParticipant,
        authoritative_id: Uuid,
        target_id: Uuid,
        visible_jid: Option<&str>,
    ) -> Result<String> {
        let payload = XmlElement::namespaced("retract", "urn:xmpp:mix:misc:0")
            .attr("id", target_id)
            .finish();
        self.message_delivery_stanza(
            channel,
            sender,
            recipient,
            authoritative_id,
            &payload,
            visible_jid,
        )
    }

    fn federated_iq_result(
        &self,
        context: &FederatedMixMutation,
        success: &FederatedMixSuccess,
    ) -> Result<String> {
        render_federated_mix_iq_result(context, success)
    }

    fn pam_join_result(&self, result: PamJoinResult<'_>) -> Result<String> {
        let PamJoinResult {
            client_request_id,
            actor_bare,
            requester_full_jid,
            channel_jid,
            participant_id,
            subscriptions,
            nick,
        } = result;
        anyhow::ensure!(
            valid_stable_participant_id(participant_id),
            "invalid MIX stable participant id"
        );
        let channel = northstar_xmpp_types::jid::CanonicalJid::parse_bare(channel_jid)?;
        let channel_localpart = channel
            .localpart()
            .ok_or_else(|| anyhow::anyhow!("MIX channel requires a localpart"))?;
        let localpart = format!("{participant_id}#{channel_localpart}");
        let participant_jid = northstar_xmpp_types::jid::CanonicalJid::parse_bare(&format!(
            "{localpart}@{}",
            channel.domainpart()
        ))?;
        anyhow::ensure!(
            participant_jid.localpart() == Some(localpart.as_str()),
            "MIX participant identifier is not a canonical localpart"
        );
        let mut join = XmlElement::namespaced("join", "urn:xmpp:mix:core:1")
            .attr("jid", participant_jid.to_string());
        for node in subscriptions {
            join.push_child(XmlElement::new("subscribe").attr("node", node));
        }
        if let Some(nick) = nick {
            join.push_child(XmlElement::new("nick").text(nick));
        }
        let payload = XmlElement::namespaced("client-join", "urn:xmpp:mix:pam:2")
            .child(join)
            .finish();
        Ok(XmlElement::namespaced("iq", "jabber:client")
            .attr("type", "result")
            .attr("from", actor_bare)
            .attr("to", requester_full_jid)
            .attr("id", client_request_id)
            .validated_fragment(&payload)?
            .finish())
    }

    fn pam_leave_result(
        &self,
        client_request_id: &str,
        actor_bare: &str,
        requester_full_jid: &str,
        channel_jid: &str,
    ) -> Result<String> {
        let payload = XmlElement::namespaced("client-leave", "urn:xmpp:mix:pam:2")
            .attr("channel", channel_jid)
            .child(XmlElement::namespaced("leave", "urn:xmpp:mix:core:1"))
            .finish();
        Ok(XmlElement::namespaced("iq", "jabber:client")
            .attr("type", "result")
            .attr("from", actor_bare)
            .attr("to", requester_full_jid)
            .attr("id", client_request_id)
            .validated_fragment(&payload)?
            .finish())
    }

    fn pam_error_result(
        &self,
        client_request_id: &str,
        actor_bare: &str,
        requester_full_jid: &str,
        error_type: &str,
        condition: &str,
    ) -> Result<String> {
        anyhow::ensure!(
            matches!(
                error_type,
                "auth" | "cancel" | "continue" | "modify" | "wait"
            ),
            "invalid PAM stanza error type"
        );
        let condition =
            XmlElement::dynamic(condition)?.attr("xmlns", "urn:ietf:params:xml:ns:xmpp-stanzas");
        let error = XmlElement::new("error")
            .attr("type", error_type)
            .child(condition);
        Ok(XmlElement::namespaced("iq", "jabber:client")
            .attr("type", "error")
            .attr("from", actor_bare)
            .attr("to", requester_full_jid)
            .attr("id", client_request_id)
            .child(error)
            .finish())
    }
}

pub(super) fn form_field(
    name: &str,
    field_type: Option<&str>,
    values: impl IntoIterator<Item = String>,
) -> XmlElement {
    let mut field = XmlElement::new("field").attr("var", name);
    if let Some(field_type) = field_type {
        field = field.attr("type", field_type);
    }
    for value in values {
        field.push_child(XmlElement::new("value").text(value));
    }
    field
}

pub(super) fn value_field(name: &str, value: impl ToString) -> XmlElement {
    form_field(name, None, [value.to_string()])
}

pub(super) fn render_info_payload(channel: &MixChannel) -> String {
    let mut form = XmlElement::namespaced("x", "jabber:x:data").attr("type", "result");
    form.push_child(form_field(
        "FORM_TYPE",
        Some("hidden"),
        ["urn:xmpp:mix:core:1".to_owned()],
    ));
    if let Some(name) = &channel.name {
        form.push_child(value_field("Name", name));
    }
    if let Some(description) = &channel.description {
        form.push_child(value_field("Description", description));
    }
    if !channel.contacts.is_empty() {
        form.push_child(form_field(
            "Contact",
            None,
            channel.contacts.iter().cloned(),
        ));
    }
    form.push_child(value_field(
        "JID Visibility",
        match channel.jid_visibility.as_str() {
            "visible" => "jid-mandatory-visible",
            "maybe" => "jid-maybe-visible",
            _ => "jid-hidden",
        },
    ));
    form.finish()
}

pub(super) fn render_config_payload(
    channel: &MixChannel,
    last_changed_by: &str,
    owners: &BTreeSet<String>,
    administrators: &BTreeSet<String>,
) -> String {
    let mut form = XmlElement::namespaced("x", "jabber:x:data").attr("type", "result");
    form.push_child(form_field(
        "FORM_TYPE",
        Some("hidden"),
        ["urn:xmpp:mix:admin:0".to_owned()],
    ));
    form.push_child(value_field("Last Change Made By", last_changed_by));
    form.push_child(form_field("Owner", None, owners.iter().cloned()));
    if !administrators.is_empty() {
        form.push_child(form_field(
            "Administrator",
            None,
            administrators.iter().cloned(),
        ));
    }
    form.push_child(form_field(
        "Nodes Present",
        None,
        [
            "participants",
            "presence",
            "information",
            "allowed",
            "banned",
            "jidmap-visible",
            "avatar",
        ]
        .into_iter()
        .map(str::to_owned),
    ));
    for (name, value) in [
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
        (
            "JID Visibility",
            match channel.jid_visibility.as_str() {
                "visible" => "jid-mandatory-visible",
                "maybe" => "jid-maybe-visible",
                _ => "jid-hidden",
            },
        ),
        ("Mandatory Nicks", bool_value(channel.nick_required)),
        ("Participants Must Provide Presence", "0"),
        ("Open Presence", "0"),
        (
            "User Message Retraction",
            bool_value(channel.allow_user_message_retraction),
        ),
        (
            "Administrator Message Retraction Rights",
            if channel.administrator_retraction_rights == "administrators" {
                "admins"
            } else {
                &channel.administrator_retraction_rights
            },
        ),
        (
            "Participation Addition by Invitation from Participant",
            bool_value(channel.allow_participant_invites),
        ),
        (
            "Private Messages",
            bool_value(channel.allow_private_messages),
        ),
        (
            "Enforce Registered Nick",
            bool_value(channel.enforce_registered_nick),
        ),
        ("access_model", &channel.access_model),
    ] {
        form.push_child(value_field(name, value));
    }
    form.push_child(value_field("max_participants", channel.max_participants));
    form.push_child(value_field("max_events", channel.max_events));
    form.finish()
}

pub(super) fn bool_value(value: bool) -> &'static str {
    if value {
        "1"
    } else {
        "0"
    }
}

pub(super) fn render_participant_payload(
    channel: &MixChannel,
    participant: &MixParticipant,
    preference: &MixParticipantPreference,
) -> String {
    let mut element = XmlElement::namespaced("participant", "urn:xmpp:mix:core:1");
    if let Some(nick) = &participant.nick {
        element.push_child(XmlElement::new("nick").text(nick));
    }
    if participant_jid_visible(channel, preference) {
        element.push_child(XmlElement::new("jid").text(&participant.jid));
    }
    element.finish()
}

pub(super) fn render_access_payload(pattern: &str) -> String {
    XmlElement::namespaced("jid", "urn:xmpp:mix:admin:0")
        .text(pattern)
        .finish()
}

#[derive(Clone, Debug)]
pub(crate) enum FederatedMixSuccess {
    Create {
        channel: String,
    },
    Destroy {
        channel: String,
    },
    RegisterNick {
        nick: String,
    },
    Join {
        participant: MixParticipant,
        subscriptions: Vec<String>,
        preference: Option<MixParticipantPreference>,
        anonymous_profile: bool,
    },
    Leave,
    SetNick {
        nick: String,
    },
    UpdateSubscriptions {
        subscriptions: Vec<String>,
    },
    PubSubPublish {
        node: String,
        item_id: String,
    },
    PubSubEmpty,
    Preference {
        preference: MixParticipantPreference,
    },
    Invitation {
        inviter: String,
        invitee: String,
        channel: String,
        token: String,
    },
}

pub(crate) struct MixPresenceDelivery<'a> {
    pub channel: &'a MixChannel,
    pub participant: &'a MixParticipant,
    pub preference: &'a MixParticipantPreference,
    pub recipient: &'a MixParticipant,
    pub item_id: &'a str,
    pub actor_full: &'a str,
    pub children: &'a str,
    pub unavailable: bool,
}

pub(crate) struct PamJoinResult<'a> {
    pub client_request_id: &'a str,
    pub actor_bare: &'a str,
    pub requester_full_jid: &'a str,
    pub channel_jid: &'a str,
    pub participant_id: &'a str,
    pub subscriptions: &'a [String],
    pub nick: Option<&'a str>,
}

pub(crate) trait MixEventPayloadRenderer: Sync {
    fn info_payload(&self, channel: &MixChannel) -> String;
    fn config_payload(
        &self,
        channel: &MixChannel,
        last_changed_by: &str,
        owners: &BTreeSet<String>,
        administrators: &BTreeSet<String>,
    ) -> String;
    fn participant_payload(
        &self,
        channel: &MixChannel,
        participant: &MixParticipant,
        preference: &MixParticipantPreference,
    ) -> String;
    fn access_payload(&self, pattern: &str) -> String;
    fn presence_delivery_stanza(&self, delivery: MixPresenceDelivery<'_>) -> Result<String>;
    fn node_event_stanza(
        &self,
        channel: &MixChannel,
        recipient: &MixParticipant,
        node: &str,
        item_id: &str,
        payload: Option<&str>,
        retract: bool,
    ) -> Result<String>;
    fn message_delivery_stanza(
        &self,
        channel: &MixChannel,
        sender: &MixParticipant,
        recipient: &MixParticipant,
        authoritative_id: Uuid,
        payload: &str,
        visible_jid: Option<&str>,
    ) -> Result<String>;
    fn retraction_delivery_stanza(
        &self,
        channel: &MixChannel,
        sender: &MixParticipant,
        recipient: &MixParticipant,
        authoritative_id: Uuid,
        target_id: Uuid,
        visible_jid: Option<&str>,
    ) -> Result<String>;
    fn federated_iq_result(
        &self,
        context: &FederatedMixMutation,
        success: &FederatedMixSuccess,
    ) -> Result<String>;
    fn pam_join_result(&self, result: PamJoinResult<'_>) -> Result<String>;
    fn pam_leave_result(
        &self,
        client_request_id: &str,
        actor_bare: &str,
        requester_full_jid: &str,
        channel_jid: &str,
    ) -> Result<String>;
    fn pam_error_result(
        &self,
        client_request_id: &str,
        actor_bare: &str,
        requester_full_jid: &str,
        error_type: &str,
        condition: &str,
    ) -> Result<String>;
}
