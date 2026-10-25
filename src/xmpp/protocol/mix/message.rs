//! Channel and private message processing, reflected identity checks and retraction.

use super::*;

pub(super) fn message_children(raw: &str) -> Result<(String, bool)> {
    let document = Document::parse(raw).context("malformed MIX message")?;
    let root = document.root_element();
    anyhow::ensure!(root.tag_name().name() == "message", "not a MIX message");
    anyhow::ensure!(
        root.attribute("type") == Some("groupchat"),
        "MIX messages must be groupchat"
    );
    let encrypted = is_encrypted(root);
    let mut children = String::new();
    for child in root.children().filter(Node::is_element) {
        let namespace = child.tag_name().namespace();
        if (child.tag_name().name() == "mix" && namespace == Some(CORE_NS))
            || child.tag_name().name() == "delay" && namespace == Some("urn:xmpp:delay")
            || child.tag_name().name() == "occupant-id"
                && namespace == Some("urn:xmpp:occupant-id:0")
            || child.tag_name().name() == "stanza-id" && namespace == Some("urn:xmpp:sid:0")
        {
            continue;
        }
        children.push_str(&raw[child.range()]);
    }
    anyhow::ensure!(!children.is_empty(), "empty MIX message");
    Ok((children, encrypted))
}

pub(super) fn private_message_children(raw: &str) -> Result<(String, bool, &'static str)> {
    let document = Document::parse(raw).context("malformed MIX private message")?;
    let root = document.root_element();
    anyhow::ensure!(root.tag_name().name() == "message", "not a MIX message");
    let kind = match root.attribute("type") {
        None | Some("normal") => "normal",
        Some("chat") => "chat",
        _ => anyhow::bail!("unsupported MIX private message type"),
    };
    let encrypted = is_encrypted(root);
    let mut children = String::new();
    for child in root.children().filter(Node::is_element) {
        let namespace = child.tag_name().namespace();
        if (child.tag_name().name() == "mix" && matches!(namespace, Some(CORE_NS | PRESENCE_NS)))
            || child.tag_name().name() == "delay" && namespace == Some("urn:xmpp:delay")
            || child.tag_name().name() == "stanza-id" && namespace == Some("urn:xmpp:sid:0")
        {
            continue;
        }
        children.push_str(&raw[child.range()]);
    }
    anyhow::ensure!(!children.is_empty(), "empty MIX private message");
    Ok((children, encrypted, kind))
}

pub(super) async fn process_private_message(
    state: &Arc<AppState>,
    actor_bare: &str,
    actor_full: &str,
    raw: &str,
    target: &CanonicalJid,
) -> Result<Option<String>> {
    let document = Document::parse(raw).context("malformed MIX private message")?;
    let root = document.root_element();
    let id = root.attribute("id").unwrap_or_default();
    let to = root.attribute("to").unwrap_or_default();
    let (target_id, channel_jid) = match decode_participant_jid(&target.bare()) {
        Ok(value) => value,
        Err(_) => {
            return Ok(Some(message_error(
                id,
                to,
                actor_full,
                "modify",
                "jid-malformed",
            )));
        }
    };
    // A resource-specific private message needs the server-private anonymous
    // resource map. Until an exact mapping exists, fail closed rather than
    // accidentally exposing or addressing the user's real resource.
    if target.resourcepart().is_some() {
        return Ok(Some(message_error(
            id,
            to,
            actor_full,
            "cancel",
            "item-not-found",
        )));
    }
    let channel_address = CanonicalJid::parse_bare(&channel_jid)?;
    let channel_localpart = channel_address
        .localpart()
        .context("encoded MIX target lacks a channel localpart")?;
    let Some(channel) = state
        .mix_service()
        .mix_channel(channel_address.domainpart(), channel_localpart)
        .await?
    else {
        return Ok(Some(message_error(
            id,
            to,
            actor_full,
            "cancel",
            "item-not-found",
        )));
    };
    let recipient_id = match Uuid::parse_str(&target_id) {
        Ok(value) if value.to_string() == target_id => value,
        _ => {
            return Ok(Some(message_error(
                id,
                to,
                actor_full,
                "modify",
                "jid-malformed",
            )));
        }
    };
    let Some((sender, recipient)) = state
        .mix_service()
        .mix_private_message_recipient(channel.id, actor_bare, recipient_id)
        .await?
    else {
        return Ok(Some(message_error(id, to, actor_full, "auth", "forbidden")));
    };
    let (children, encrypted, kind) = private_message_children(raw)?;
    let sender_encoded =
        encoded_participant_jid(&channel.jid(), &sender.participant_id.to_string())?;
    let mut delivery = XmlElement::namespaced("message", "jabber:client")
        .attr("from", sender_encoded)
        .attr("to", &recipient.jid)
        .attr("id", id)
        .attr("type", kind);
    delivery.push_validated_fragment(&children)?;
    // XEP-0404 explicitly forbids the MIX channel from archiving private
    // messages. Participant servers remain free to archive them locally.
    deliver_channel_stanza(
        &state.mix_outbox_context(),
        ChannelStanzaDelivery {
            delivery_id: None,
            mix_source: None,
            channel_jid: &channel.jid(),
            recipient: &recipient,
            stanza: delivery.finish(),
            authoritative_stanza_id: None,
            archive: false,
            encrypted,
            durable: false,
            database_lane: ChannelStanzaDatabaseLane::LiveIngress,
        },
    )
    .await?;
    Ok(None)
}

pub(super) fn validate_reflected_mix_identity(root: Node<'_, '_>) -> Result<()> {
    let identities = root
        .children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().name() == "mix"
                && node.tag_name().namespace() == Some(CORE_NS)
        })
        .collect::<Vec<_>>();
    anyhow::ensure!(
        identities.len() == 1,
        "reflected MIX message requires one authoritative identity"
    );
    let mut nick = None;
    let mut jid = None;
    for child in identities[0].children().filter(Node::is_element) {
        anyhow::ensure!(
            !child.children().any(|node| node.is_element()),
            "invalid reflected MIX identity payload"
        );
        match (child.tag_name().name(), child.tag_name().namespace()) {
            ("nick", Some(CORE_NS)) => {
                anyhow::ensure!(nick.is_none(), "duplicate reflected MIX nick");
                nick = Some(crate::services::mix::prepare_mix_nick(
                    child.text().unwrap_or_default(),
                )?);
            }
            ("jid", Some(CORE_NS)) => {
                anyhow::ensure!(jid.is_none(), "duplicate reflected MIX JID");
                jid = Some(northstar_xmpp_types::jid::canonicalize_bare(
                    child.text().unwrap_or_default(),
                )?);
            }
            _ => anyhow::bail!("unknown reflected MIX identity child"),
        }
    }
    Ok(())
}

pub(super) fn reflected_mix_stanza_id(root: Node<'_, '_>) -> Result<Uuid> {
    let from =
        northstar_xmpp_types::jid::CanonicalJid::parse(root.attribute("from").unwrap_or_default())?;
    anyhow::ensure!(
        from.localpart().is_some() && from.resourcepart().is_some(),
        "reflected MIX message requires a channel participant source"
    );
    let channel = from.bare();
    let stanza_ids = root
        .children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().name() == "stanza-id"
                && node.tag_name().namespace() == Some("urn:xmpp:sid:0")
        })
        .collect::<Vec<_>>();
    anyhow::ensure!(
        stanza_ids.len() == 1,
        "reflected MIX message requires one authoritative stanza-id"
    );
    let stanza_id = stanza_ids[0];
    anyhow::ensure!(
        stanza_id
            .attributes()
            .all(|attribute| matches!(attribute.name(), "id" | "by"))
            && !stanza_id.children().any(|node| node.is_element())
            && stanza_id.text().is_none_or(|text| text.trim().is_empty()),
        "invalid reflected MIX stanza-id shape"
    );
    let by = northstar_xmpp_types::jid::CanonicalJid::parse_bare(
        stanza_id.attribute("by").unwrap_or_default(),
    )?;
    anyhow::ensure!(
        by.to_string() == channel,
        "reflected MIX stanza-id authority does not match the channel"
    );
    let id = stanza_id
        .attribute("id")
        .context("missing MIX stanza-id id")?;
    let id = Uuid::parse_str(id)?;
    anyhow::ensure!(
        id.to_string() == stanza_id.attribute("id").unwrap_or_default(),
        "MIX stanza-id must be a canonical UUID"
    );
    Ok(id)
}

pub(super) fn validate_reflected_mix_presence_identity(root: Node<'_, '_>) -> Result<()> {
    let identities = root
        .children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().name() == "mix"
                && node.tag_name().namespace() == Some(PRESENCE_NS)
        })
        .collect::<Vec<_>>();
    anyhow::ensure!(
        identities.len() == 1,
        "reflected MIX presence requires one authoritative identity"
    );
    let mut nick = None;
    let mut jid = None;
    for child in identities[0].children().filter(Node::is_element) {
        anyhow::ensure!(
            !child.children().any(|node| node.is_element()),
            "invalid reflected MIX presence identity payload"
        );
        match (child.tag_name().name(), child.tag_name().namespace()) {
            ("nick", Some(PRESENCE_NS)) => {
                anyhow::ensure!(nick.is_none(), "duplicate reflected MIX presence nick");
                nick = Some(crate::services::mix::prepare_mix_nick(
                    child.text().unwrap_or_default(),
                )?);
            }
            ("jid", Some(PRESENCE_NS)) => {
                anyhow::ensure!(jid.is_none(), "duplicate reflected MIX presence JID");
                jid = Some(northstar_xmpp_types::jid::canonicalize(
                    child.text().unwrap_or_default(),
                )?);
            }
            _ => anyhow::bail!("unknown reflected MIX presence identity child"),
        }
    }
    Ok(())
}

pub(super) fn mix_retraction_target(root: Node<'_, '_>) -> Result<Option<Uuid>> {
    let retracts = root
        .children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().name() == "retract"
                && node.tag_name().namespace() == Some(MISC_NS)
        })
        .collect::<Vec<_>>();
    if retracts.is_empty() {
        return Ok(None);
    }
    anyhow::ensure!(retracts.len() == 1, "duplicate MIX retraction");
    let retract = retracts[0];
    anyhow::ensure!(
        retract.attributes().len() == 1
            && retract.attribute("id").is_some()
            && !retract.children().any(|node| node.is_element())
            && retract.text().is_none_or(|text| text.trim().is_empty()),
        "invalid MIX retraction"
    );
    anyhow::ensure!(
        root.children()
            .filter(Node::is_element)
            .all(|child| child == retract),
        "MIX retraction cannot carry a body or another payload"
    );
    let target = retract.attribute("id").unwrap_or_default();
    let target = Uuid::parse_str(target).context("invalid MIX retraction MAM id")?;
    anyhow::ensure!(
        target.to_string() == retract.attribute("id").unwrap_or_default(),
        "MIX retraction id must be a canonical UUID"
    );
    Ok(Some(target))
}

pub(super) fn trusted_mix_origin_id(root: Node<'_, '_>) -> Result<Option<String>> {
    let origins = root
        .children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().name() == "origin-id"
                && node.tag_name().namespace() == Some("urn:xmpp:sid:0")
        })
        .collect::<Vec<_>>();
    anyhow::ensure!(origins.len() <= 1, "duplicate MIX origin-id");
    let Some(origin) = origins.first() else {
        return Ok(None);
    };
    anyhow::ensure!(
        origin.attributes().len() == 1
            && origin.attribute("id").is_some()
            && !origin.children().any(|node| node.is_element())
            && origin.text().is_none_or(|text| text.trim().is_empty()),
        "invalid MIX origin-id"
    );
    let id = origin.attribute("id").unwrap_or_default();
    anyhow::ensure!(
        !id.is_empty() && id.len() <= 1_024 && !id.chars().any(char::is_control),
        "invalid MIX origin-id value"
    );
    Ok(Some(id.to_owned()))
}

pub(super) fn mix_replay_semantics(
    operation: &str,
    actor: &str,
    channel: &str,
    target: Option<Uuid>,
    payload: &str,
) -> Vec<u8> {
    let mut commitment =
        Vec::with_capacity(operation.len() + actor.len() + channel.len() + payload.len() + 128);
    let mut append_field = |field: &[u8]| {
        commitment.extend_from_slice(&(field.len() as u64).to_be_bytes());
        commitment.extend_from_slice(field);
    };
    append_field(operation.as_bytes());
    append_field(actor.as_bytes());
    append_field(channel.as_bytes());
    if let Some(target) = target {
        append_field(target.as_bytes());
    } else {
        append_field(&[]);
    }
    append_field(payload.as_bytes());
    commitment
}

pub(super) fn mix_message_identity(nick: Option<&str>, jid: Option<&str>) -> XmlElement {
    let mut identity = XmlElement::namespaced("mix", CORE_NS);
    if let Some(nick) = nick {
        identity.push_child(XmlElement::new("nick").text(nick));
    }
    if let Some(jid) = jid {
        identity.push_child(XmlElement::new("jid").text(jid));
    }
    identity
}

pub(super) struct MixChannelMessage<'a> {
    pub(super) from: &'a str,
    pub(super) to: Option<&'a str>,
    pub(super) id: Uuid,
    pub(super) payload: Option<&'a str>,
    pub(super) nick: Option<&'a str>,
    pub(super) jid: Option<&'a str>,
}

pub(super) fn mix_channel_message(message: MixChannelMessage<'_>) -> Result<String> {
    let mut stanza = XmlElement::namespaced("message", "jabber:client")
        .attr("from", message.from)
        .optional_attr("to", message.to)
        .attr("id", message.id)
        .attr("type", "groupchat");
    if let Some(payload) = message.payload {
        stanza.push_validated_fragment(payload)?;
    }
    stanza.push_child(mix_message_identity(message.nick, message.jid));
    Ok(add_stanza_id(
        &stanza.finish(),
        message.from.split('/').next().unwrap_or(message.from),
        message.id,
    ))
}

pub(super) fn mix_retraction_action(
    from: &str,
    to: Option<&str>,
    id: Uuid,
    target: Uuid,
    nick: Option<&str>,
    jid: Option<&str>,
) -> String {
    let stanza = XmlElement::namespaced("message", "jabber:client")
        .attr("from", from)
        .optional_attr("to", to)
        .attr("id", id)
        .attr("type", "groupchat")
        .child(XmlElement::namespaced("retract", MISC_NS).attr("id", target))
        .child(mix_message_identity(nick, jid));
    add_stanza_id(&stanza.finish(), from.split('/').next().unwrap_or(from), id)
}

pub(super) async fn process_channel_message(
    state: &Arc<AppState>,
    actor_bare: &str,
    actor_full: &str,
    raw: &str,
    observation: Option<&SessionExecutions>,
) -> Result<Option<String>> {
    if let Some(observation) = observation {
        observation.enter(Stage::MixPolicy);
    }
    let document = Document::parse(raw).context("malformed MIX message")?;
    let root = document.root_element();
    let to = root.attribute("to").unwrap_or_default().to_owned();
    let id = root.attribute("id").unwrap_or_default().to_owned();
    let target = CanonicalJid::parse(&to)?;
    let mix_domain = local_mix_domain(state);
    if target.domainpart() != mix_domain {
        return Ok(None);
    }
    if target
        .localpart()
        .is_some_and(|localpart| localpart.contains('#'))
    {
        return process_private_message(state, actor_bare, actor_full, raw, &target).await;
    }
    if target.resourcepart().is_some() {
        return Ok(Some(message_error(
            &id,
            &to,
            actor_full,
            "modify",
            "jid-malformed",
        )));
    }
    let Some(channel_localpart) = target.localpart() else {
        return Ok(Some(message_error(
            &id,
            &to,
            actor_full,
            "modify",
            "jid-malformed",
        )));
    };
    let Some(channel) = state
        .mix_service()
        .mix_channel(&mix_domain, channel_localpart)
        .await?
    else {
        return Ok(Some(message_error(
            &id,
            &to,
            actor_full,
            "cancel",
            "item-not-found",
        )));
    };
    let retraction_target = mix_retraction_target(root)?;
    let retraction_identity = retraction_target.map(|target_id| MixReplayIdentity {
        client_id: id.clone(),
        canonical_semantics: mix_replay_semantics(
            "retraction",
            actor_bare,
            &channel.jid(),
            Some(target_id),
            "",
        ),
    });
    let (message_children, message_encrypted, message_replay_identity) =
        if retraction_target.is_none() {
            let (children, encrypted) = message_children(raw)?;
            let replay = trusted_mix_origin_id(root)?.map(|client_id| MixReplayIdentity {
                client_id,
                canonical_semantics: mix_replay_semantics(
                    "message",
                    actor_bare,
                    &channel.jid(),
                    None,
                    &children,
                ),
            });
            (Some(children), encrypted, replay)
        } else {
            (None, false, None)
        };
    // Only the ordinary frame-owned foreground path gains this owner. A
    // genuinely absent frame retains the explicit compatibility behavior.
    let foreground = if retraction_target.is_none() {
        if let Some(frames) = observation {
            frames.mix_foreground(|| {
                state.mix_service().prepare_mix_foreground(
                    crate::services::mix::foreground::Ingress {
                        channel_id: channel.id,
                        channel_jid: channel.jid(),
                        actor_bare: actor_bare.to_owned(),
                        actor_full: actor_full.to_owned(),
                        children: message_children.as_deref().unwrap_or_default().to_owned(),
                        encrypted: message_encrypted,
                        identity: message_replay_identity.clone(),
                    },
                )
            })?
        } else {
            None
        }
    } else {
        None
    };
    if let (Some(target_id), Some(identity)) = (retraction_target, retraction_identity.as_ref()) {
        match state
            .mix_service()
            .lookup_mix_retraction_replay(channel.id, actor_bare, target_id, identity)
            .await?
        {
            MixBusinessReplay::Replay(_) => return Ok(None),
            MixBusinessReplay::Conflict => {
                return Ok(Some(message_error(
                    &id,
                    &channel.jid(),
                    actor_full,
                    "cancel",
                    "conflict",
                )));
            }
            MixBusinessReplay::Miss => {}
        }
    }
    if let Some(identity) = message_replay_identity.as_ref() {
        let replay = if let Some(owner) = &foreground {
            let request = owner
                .replay_request()?
                .ok_or(crate::services::mix::foreground::Rejected::Input)?;
            state
                .mix_service()
                .lookup_mix_message_replay_observed(&request)
                .await?
        } else {
            state
                .mix_service()
                .lookup_mix_message_replay(channel.id, actor_bare, identity)
                .await?
        };
        match replay {
            MixBusinessReplay::Replay(_) => return Ok(None),
            MixBusinessReplay::Conflict => {
                return Ok(Some(message_error(
                    &id,
                    &channel.jid(),
                    actor_full,
                    "cancel",
                    "conflict",
                )));
            }
            MixBusinessReplay::Miss => {}
        }
    }
    let Some(participant) = state
        .mix_service()
        .mix_participant(channel.id, actor_bare)
        .await?
    else {
        return Ok(Some(message_error(
            &id,
            &channel.jid(),
            actor_full,
            "auth",
            "forbidden",
        )));
    };
    let preference = state
        .mix_service()
        .mix_participant_preference(channel.id, actor_bare)
        .await?
        .unwrap_or_default();
    if let Some(target_id) = retraction_target {
        anyhow::ensure!(
            !id.is_empty() && id.len() <= 1_024 && !id.chars().any(char::is_control),
            "MIX retraction requires a bounded client action id"
        );
        let retraction_id = Uuid::new_v4();
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let archived_actor = if channel.jid_visibility == "visible" {
            actor_bare.to_owned()
        } else {
            encoded_participant_jid(&channel.jid(), &participant.participant_id.to_string())?
        };
        let tombstone = XmlElement::namespaced("message", "jabber:client")
            .attr("from", channel.jid())
            .attr("id", target_id)
            .attr("type", "groupchat")
            .child(
                XmlElement::namespaced("retracted", MISC_NS)
                    .attr("by", archived_actor)
                    .attr("time", now),
            )
            .finish();
        let tombstone = add_stanza_id(&tombstone, &channel.jid(), target_id);
        let archived_jid = (channel.jid_visibility == "visible").then_some(actor_bare);
        let live_jid = crate::services::mix::participant_jid_visible(&channel, &preference)
            .then_some(actor_bare);
        let archived_action = mix_retraction_action(
            &channel.jid(),
            None,
            retraction_id,
            target_id,
            participant.nick.as_deref(),
            archived_jid,
        );
        if let Some(observation) = observation {
            observation.enter(Stage::MixAdmission);
        }
        let admission = state
            .mix_service()
            .retract_mix_message(RetractMixMessageRequest {
                channel_id: channel.id,
                actor: actor_bare,
                target_id,
                retraction_id,
                tombstone_payload: &tombstone,
                retraction_payload: &archived_action,
                identity: retraction_identity,
                visible_jid: live_jid,
            })
            .await?;
        match admission.outcome {
            RetractMixMessageOutcome::NotFound => {
                return Ok(Some(message_error(
                    &id,
                    &channel.jid(),
                    actor_full,
                    "cancel",
                    "item-not-found",
                )));
            }
            RetractMixMessageOutcome::Forbidden => {
                return Ok(Some(message_error(
                    &id,
                    &channel.jid(),
                    actor_full,
                    "auth",
                    "forbidden",
                )));
            }
            RetractMixMessageOutcome::Retracted => {}
            RetractMixMessageOutcome::Replay(_) => return Ok(None),
            RetractMixMessageOutcome::Conflict => {
                return Ok(Some(message_error(
                    &id,
                    &channel.jid(),
                    actor_full,
                    "cancel",
                    "conflict",
                )));
            }
        }
        return Ok(None);
    }
    let children = message_children.expect("non-retraction MIX message has parsed children");
    let archive_id = Uuid::new_v4();
    let archived_jid = (channel.jid_visibility == "visible").then_some(actor_bare);
    let live_jid =
        crate::services::mix::participant_jid_visible(&channel, &preference).then_some(actor_bare);
    let archive = mix_channel_message(MixChannelMessage {
        from: &channel.jid(),
        to: None,
        id: archive_id,
        payload: Some(&children),
        nick: participant.nick.as_deref(),
        jid: archived_jid,
    })?;
    // The durable archive and subscriber snapshot share the channel-locked
    // transaction. This prevents delivery to a participant who concurrently
    // left and prevents a post-join subscriber from missing an archive that
    // linearized after their subscription.
    if let Some(observation) = observation {
        observation.enter(Stage::MixAdmission);
    }
    let admission = if let Some(owner) = &foreground {
        let request = owner.store_request(crate::services::mix::foreground::StoreCommand {
            channel_id: channel.id,
            actor: actor_bare.to_owned(),
            item_id: archive_id,
            payload: archive,
            identity: message_replay_identity,
            delivery_payload: children,
            visible_jid: live_jid.map(str::to_owned),
            encrypted: message_encrypted,
        })?;
        state
            .mix_service()
            .store_mix_message_observed(&request)
            .await?
    } else {
        Arc::new(
            state
                .mix_service()
                .store_mix_message(StoreMixMessageRequest {
                    channel_id: channel.id,
                    actor: actor_bare,
                    item_id: &archive_id.to_string(),
                    payload: &archive,
                    identity: message_replay_identity,
                    delivery_payload: &children,
                    visible_jid: live_jid,
                    encrypted: message_encrypted,
                })
                .await?,
        )
    };
    match admission.outcome {
        StoreEventOutcome::Stored(_) => {}
        StoreEventOutcome::Replay(_) => return Ok(None),
        StoreEventOutcome::NotParticipant => {
            return Ok(Some(message_error(
                &id,
                &channel.jid(),
                actor_full,
                "auth",
                "forbidden",
            )));
        }
        StoreEventOutcome::Conflict => {
            return Ok(Some(message_error(
                &id,
                &channel.jid(),
                actor_full,
                "cancel",
                "conflict",
            )));
        }
        StoreEventOutcome::TooLarge => {
            return Ok(Some(message_error(
                &id,
                &channel.jid(),
                actor_full,
                "modify",
                "policy-violation",
            )));
        }
    }
    Ok(None)
}

pub(super) fn message_error(
    id: &str,
    from: &str,
    to: &str,
    error_type: &str,
    condition: &str,
) -> String {
    let condition = XmlElement::dynamic(condition)
        .unwrap_or_else(|_| XmlElement::new("undefined-condition"))
        .attr("xmlns", "urn:ietf:params:xml:ns:xmpp-stanzas");
    XmlElement::namespaced("message", "jabber:client")
        .attr("type", "error")
        .attr("from", from)
        .attr("to", to)
        .attr("id", id)
        .child(
            XmlElement::new("error")
                .attr("type", error_type)
                .child(condition),
        )
        .finish()
}
