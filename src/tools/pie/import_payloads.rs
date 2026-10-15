//! Parse and validate protocol payloads into portable account data.

use super::*;

pub(super) fn parse_scram(
    node: Node<'_, '_>,
    user: &mut PieUser,
    output: &mut ImportDocument,
) -> Result<()> {
    only_attributes(node, &["mechanism"])?;
    let mechanism = node
        .attribute("mechanism")
        .context("SCRAM credentials missing mechanism")?;
    if mechanism != "SCRAM-SHA-256" {
        unsupported(
            output,
            format!("SCRAM mechanism {mechanism:?} is not supported by Northstar"),
        );
        return Ok(());
    }
    if user.scram.is_some() {
        bail!("duplicate SCRAM-SHA-256 credentials");
    }
    let values = exact_text_children(
        node,
        &["iter-count", "salt", "server-key", "stored-key"],
        SCRAM_NS,
    )?;
    let iteration_text = values
        .get("iter-count")
        .context("SCRAM iter-count missing")?;
    if iteration_text.starts_with('0') || !iteration_text.bytes().all(|b| b.is_ascii_digit()) {
        bail!("invalid SCRAM iter-count syntax");
    }
    let iterations: u32 = iteration_text.parse()?;
    if !(auth::MIN_SCRAM_ITERATIONS..=auth::MAX_SCRAM_ITERATIONS).contains(&iterations) {
        bail!("SCRAM iteration count is outside Northstar's safe bounds");
    }
    let salt = decode_b64(
        values.get("salt").context("SCRAM salt missing")?,
        16,
        1024,
        "SCRAM salt",
    )?;
    let stored_key = decode_b64(
        values
            .get("stored-key")
            .context("SCRAM stored-key missing")?,
        32,
        32,
        "SCRAM stored-key",
    )?;
    let server_key = decode_b64(
        values
            .get("server-key")
            .context("SCRAM server-key missing")?,
        32,
        32,
        "SCRAM server-key",
    )?;
    user.scram = Some(ScramCredential {
        iterations,
        salt,
        stored_key,
        server_key,
    });
    Ok(())
}

pub(super) fn parse_roster(
    node: Node<'_, '_>,
    user: &mut PieUser,
    budget: &mut LoadBudget,
) -> Result<()> {
    only_attributes(node, &[])?;
    for child in element_children(node)? {
        if child.tag_name().namespace() != Some(ROSTER_NS) || child.tag_name().name() != "item" {
            bail!("roster query contains a non-item element");
        }
        item(budget)?;
        only_attributes(child, &["jid", "name", "subscription", "ask", "approved"])?;
        let contact =
            jid::canonicalize_bare(child.attribute("jid").context("roster item missing jid")?)?;
        let subscription = child.attribute("subscription").unwrap_or("none");
        if !matches!(subscription, "none" | "to" | "from" | "both") {
            bail!("invalid roster subscription");
        }
        let ask = child.attribute("ask").map(ToOwned::to_owned);
        if ask.as_deref().is_some_and(|value| value != "subscribe") {
            bail!("invalid roster ask value");
        }
        let approved = match child.attribute("approved") {
            None | Some("false") | Some("0") => false,
            Some("true") | Some("1") => true,
            Some(_) => bail!("invalid roster approved value"),
        };
        let mut groups = Vec::new();
        for group in element_children(child)? {
            if group.tag_name().namespace() != Some(ROSTER_NS)
                || group.tag_name().name() != "group"
                || group.attributes().len() != 0
                || group.children().any(|n| n.is_element())
            {
                bail!("invalid roster group");
            }
            let value = group.text().unwrap_or("").to_owned();
            if value.len() > 1024 {
                bail!("roster group exceeds 1024 bytes");
            }
            groups.push(value);
        }
        groups.sort();
        groups.dedup();
        user.roster.push(RosterItem {
            jid: contact,
            name: child.attribute("name").map(ToOwned::to_owned),
            subscription: subscription.to_owned(),
            ask,
            groups,
            approved,
        });
    }
    Ok(())
}

pub(super) fn parse_offline(
    node: Node<'_, '_>,
    account: &str,
    user: &mut PieUser,
    budget: &mut LoadBudget,
) -> Result<()> {
    only_attributes(node, &[])?;
    for message in element_children(node)? {
        item(budget)?;
        validate_message_node(message)?;
        let raw_recipient = message
            .attribute("to")
            .context("offline message missing to")?;
        let recipient = jid::CanonicalJid::parse(raw_recipient)?;
        if recipient.to_string() != raw_recipient {
            bail!("offline message recipient must already be canonical");
        }
        if recipient.bare() != account {
            bail!("offline message is addressed to another account");
        }
        let target_resource = if message.attribute("type").unwrap_or("normal") == "normal" {
            recipient.resourcepart().map(str::to_owned)
        } else {
            None
        };
        let sender = jid::canonicalize(
            message
                .attribute("from")
                .context("offline message missing from")?,
        )?;
        let stanza = node_to_xml(message);
        bound_xml(&stanza, "offline stanza")?;
        user.offline.push(OfflineMessage {
            sender,
            encrypted: stanza_is_encrypted(message),
            created_at: delay_stamp(message)?,
            stanza,
            target_resource,
        });
    }
    Ok(())
}

pub(super) fn parse_private(
    node: Node<'_, '_>,
    user: &mut PieUser,
    budget: &mut LoadBudget,
) -> Result<()> {
    only_attributes(node, &[])?;
    for child in element_children(node)? {
        item(budget)?;
        let namespace = child
            .tag_name()
            .namespace()
            .context("private XML child must have a namespace")?
            .to_owned();
        if namespace == PRIVATE_NS {
            bail!("private XML child must use its own namespace");
        }
        let xml = node_to_xml(child);
        bound_xml(&xml, "private XML item")?;
        user.private_xml.push(PrivateXml {
            name: child.tag_name().name().to_owned(),
            namespace,
            xml,
        });
    }
    Ok(())
}

pub(super) fn parse_privacy(
    node: Node<'_, '_>,
    user: &mut PieUser,
    budget: &mut LoadBudget,
    output: &mut ImportDocument,
) -> Result<()> {
    only_attributes(node, &[])?;
    let children = element_children(node)?;
    let defaults: Vec<_> = children
        .iter()
        .copied()
        .filter(|child| {
            child.tag_name().namespace() == Some(PRIVACY_NS) && child.tag_name().name() == "default"
        })
        .collect();
    if defaults.len() > 1 {
        bail!("privacy query contains duplicate default selections");
    }
    let selected = defaults
        .first()
        .and_then(|child| child.attribute("name"))
        .map(ToOwned::to_owned);
    for child in children {
        if child.tag_name().namespace() != Some(PRIVACY_NS) {
            bail!("privacy query contains foreign child");
        }
        match child.tag_name().name() {
            "default" => {
                only_attributes(child, &["name"])?;
            }
            "active" => unsupported(
                output,
                "XEP-0016 active privacy-list state is session-specific and was ignored".to_owned(),
            ),
            "list" => {
                only_attributes(child, &["name"])?;
                let name = child
                    .attribute("name")
                    .context("privacy list missing name")?;
                if selected.as_deref().is_some_and(|selected| selected != name)
                    && name != "northstar-blocklist"
                {
                    unsupported(
                        output,
                        format!(
                            "privacy list {name:?} is not the selected Northstar blocklist and was ignored"
                        ),
                    );
                    continue;
                }
                for entry in element_children(child)? {
                    item(budget)?;
                    only_attributes(entry, &["type", "value", "action", "order"])?;
                    if entry.tag_name().name() != "item"
                        || entry.tag_name().namespace() != Some(PRIVACY_NS)
                    {
                        bail!("privacy list contains a non-item element");
                    }
                    let action = entry
                        .attribute("action")
                        .context("privacy item missing action")?;
                    if action == "allow"
                        && entry.attribute("type").is_none()
                        && !entry.children().any(|n| n.is_element())
                    {
                        continue;
                    }
                    if action != "deny"
                        || entry.attribute("type") != Some("jid")
                        || entry.children().any(|n| n.is_element())
                    {
                        unsupported(
                            output,
                            "a privacy-list rule cannot be represented by XEP-0191 and was ignored"
                                .to_owned(),
                        );
                        continue;
                    }
                    user.blocked.push(jid::canonicalize(
                        entry
                            .attribute("value")
                            .context("privacy JID rule missing value")?,
                    )?);
                }
            }
            other => unsupported(output, format!("privacy child {other:?} was ignored")),
        }
    }
    user.blocked.sort();
    user.blocked.dedup();
    Ok(())
}

pub(super) fn parse_pending(
    node: Node<'_, '_>,
    domain: &str,
    user: &mut PieUser,
    budget: &mut LoadBudget,
) -> Result<()> {
    item(budget)?;
    validate_message_like_attributes(node)?;
    if node.attribute("type") != Some("subscribe") {
        bail!("PIE pending presence must have type='subscribe'");
    }
    let from = jid::canonicalize_bare(
        node.attribute("from")
            .context("pending presence missing from")?,
    )?;
    if let Some(to) = node.attribute("to") {
        let expected = format!("{}@{domain}", user.username);
        if jid::canonical_bare_key(to)? != expected {
            bail!("pending presence is addressed to another account");
        }
    }
    let stanza = node_to_xml(node);
    bound_xml(&stanza, "pending presence")?;
    user.pending.push(PendingPresence { from, stanza });
    Ok(())
}

pub(super) fn parse_pep_owner(
    node: Node<'_, '_>,
    user: &mut PieUser,
    budget: &mut LoadBudget,
    output: &mut ImportDocument,
) -> Result<()> {
    only_attributes(node, &[])?;
    let children = element_children(node)?;
    // XEP-0227 does not assign semantic meaning to sibling ordering. Build
    // node configurations before applying subscriptions even when an export
    // places <subscriptions/> first.
    for child in children.iter().copied().filter(|child| {
        child.tag_name().namespace() == Some(PUBSUB_OWNER_NS)
            && child.tag_name().name() == "configure"
    }) {
        match child.tag_name().name() {
            "configure" if child.tag_name().namespace() == Some(PUBSUB_OWNER_NS) => {
                item(budget)?;
                only_attributes(child, &["node"])?;
                let name = bounded_identifier(
                    child
                        .attribute("node")
                        .context("PEP configure missing node")?,
                    1024,
                    "PEP node",
                )?;
                if user.pep_nodes.contains_key(&name) {
                    bail!("duplicate PEP node configuration {name:?}");
                }
                let form = element_children(child)?;
                let [form] = form.as_slice() else {
                    bail!("PEP configure must contain exactly one data form");
                };
                let fields = parse_form(*form)?;
                let mut config = PepNode::default();
                if let Some(value) = first(&fields, "pubsub#access_model") {
                    config.access_model = value.to_owned();
                }
                if !matches!(
                    config.access_model.as_str(),
                    "open" | "presence" | "roster" | "whitelist"
                ) {
                    bail!("unsupported PEP access model");
                }
                if let Some(value) = first(&fields, "pubsub#max_items") {
                    config.max_items = value.parse()?;
                }
                if !(1..=100).contains(&config.max_items) {
                    bail!("PEP max_items exceeds Northstar bounds");
                }
                if let Some(value) = first(&fields, "pubsub#persist_items") {
                    config.persist_items = parse_bool(value)?;
                }
                if let Some(value) = first(&fields, "pubsub#send_last_published_item") {
                    config.send_last = value.to_owned();
                }
                if !matches!(
                    config.send_last.as_str(),
                    "never" | "on_sub" | "on_sub_and_presence"
                ) {
                    bail!("invalid PEP send_last_published_item");
                }
                if let Some(value) = first(&fields, "pubsub#deliver_notifications") {
                    config.deliver_notifications = parse_bool(value)?;
                }
                config.roster_groups_allowed = fields
                    .get("pubsub#roster_groups_allowed")
                    .cloned()
                    .unwrap_or_default();
                config.access_whitelist = fields
                    .get("northstar#access_whitelist")
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .map(|value| jid::canonicalize_bare(&value))
                    .collect::<Result<_>>()?;
                for key in fields.keys() {
                    if !matches!(
                        key.as_str(),
                        "FORM_TYPE"
                            | "pubsub#access_model"
                            | "pubsub#max_items"
                            | "pubsub#persist_items"
                            | "pubsub#send_last_published_item"
                            | "pubsub#deliver_notifications"
                            | "pubsub#roster_groups_allowed"
                            | "northstar#access_whitelist"
                    ) {
                        unsupported(
                            output,
                            format!(
                                "PEP configuration field {key:?} is not persisted by Northstar"
                            ),
                        );
                    }
                }
                user.pep_nodes.insert(name, config);
            }
            _ => unreachable!("configure-only first pass"),
        }
    }
    for child in children.into_iter().filter(|child| {
        !(child.tag_name().namespace() == Some(PUBSUB_OWNER_NS)
            && child.tag_name().name() == "configure")
    }) {
        match child.tag_name().name() {
            "subscriptions" if child.tag_name().namespace() == Some(PUBSUB_OWNER_NS) => {
                only_attributes(child, &["node"])?;
                let name = child
                    .attribute("node")
                    .context("PEP subscriptions missing node")?
                    .to_owned();
                let config = user
                    .pep_nodes
                    .get_mut(&name)
                    .context("PEP subscriptions lack node configuration")?;
                for subscription in element_children(child)? {
                    item(budget)?;
                    only_attributes(subscription, &["jid", "subscription", "subid"])?;
                    let state = subscription
                        .attribute("subscription")
                        .unwrap_or("subscribed");
                    if !matches!(state, "subscribed" | "pending") {
                        unsupported(
                            output,
                            format!("PEP subscription state {state:?} was ignored"),
                        );
                        continue;
                    }
                    let subscriber = jid::canonicalize(
                        subscription
                            .attribute("jid")
                            .context("PEP subscription missing jid")?,
                    )?;
                    let subid = subscription
                        .attribute("subid")
                        .map(ToOwned::to_owned)
                        .unwrap_or_else(|| Uuid::new_v4().to_string());
                    bounded_identifier(&subid, 128, "PEP subid")?;
                    config.subscriptions.push(PepSubscription {
                        jid: subscriber,
                        subid,
                        state: state.to_owned(),
                    });
                }
            }
            "affiliations" if child.tag_name().namespace() == Some(PUBSUB_OWNER_NS) => {
                unsupported(output, "PEP affiliations other than Northstar's implicit owner/access-whitelist model were ignored".to_owned());
            }
            other => unsupported(output, format!("unsupported PEP owner element {other:?}")),
        }
    }
    Ok(())
}

pub(super) fn parse_pep_items(
    node: Node<'_, '_>,
    user: &mut PieUser,
    budget: &mut LoadBudget,
) -> Result<()> {
    only_attributes(node, &[])?;
    for items in element_children(node)? {
        if items.tag_name().namespace() != Some(PUBSUB_NS) || items.tag_name().name() != "items" {
            bail!("PEP pubsub contains non-items child");
        }
        only_attributes(items, &["node"])?;
        let name = items.attribute("node").context("PEP items missing node")?;
        let config = user
            .pep_nodes
            .get_mut(name)
            .context("PEP items have no corresponding node configuration")?;
        for entry in element_children(items)? {
            item(budget)?;
            if entry.tag_name().namespace() != Some(PUBSUB_NS) || entry.tag_name().name() != "item"
            {
                bail!("PEP items contains non-item child");
            }
            only_attributes(entry, &["id", "publisher"])?;
            let id = bounded_identifier(
                entry.attribute("id").context("PEP item missing id")?,
                1024,
                "PEP item id",
            )?;
            let children = element_children(entry)?;
            let [payload] = children.as_slice() else {
                bail!("Northstar PEP item import requires exactly one payload element");
            };
            let payload = node_to_xml(*payload);
            bound_xml(&payload, "PEP payload")?;
            config.items.push(PepItem { id, payload });
        }
        if config.items.len() > config.max_items as usize {
            bail!("PEP node {name:?} contains more items than max_items");
        }
    }
    Ok(())
}

pub(super) fn parse_archive(
    node: Node<'_, '_>,
    username: &str,
    domain: &str,
    user: &mut PieUser,
    budget: &mut LoadBudget,
) -> Result<()> {
    only_attributes(node, &[])?;
    let account = format!("{username}@{domain}");
    let mut previous = None;
    for result in element_children(node)? {
        item(budget)?;
        if result.tag_name().namespace() != Some("urn:xmpp:mam:2")
            || result.tag_name().name() != "result"
        {
            bail!("PIE MAM archive contains a non-result element");
        }
        only_attributes(result, &["id", "queryid"])?;
        let result_id = bounded_identifier(
            result.attribute("id").context("MAM result missing id")?,
            1024,
            "MAM result id",
        )?;
        let forwarded = element_children(result)?;
        let [forwarded] = forwarded.as_slice() else {
            bail!("MAM result must contain exactly one forwarded element");
        };
        if forwarded.tag_name().namespace() != Some("urn:xmpp:forward:0")
            || forwarded.tag_name().name() != "forwarded"
        {
            bail!("MAM result child is not forwarded");
        }
        let children = element_children(*forwarded)?;
        let delay = children
            .iter()
            .find(|child| {
                child.tag_name().namespace() == Some("urn:xmpp:delay")
                    && child.tag_name().name() == "delay"
            })
            .context("MAM forwarded element missing delay")?;
        only_attributes(*delay, &["stamp", "from"])?;
        let created_at = DateTime::parse_from_rfc3339(
            delay
                .attribute("stamp")
                .context("MAM delay missing stamp")?,
        )?
        .with_timezone(&Utc);
        if previous.is_some_and(|previous| created_at < previous) {
            bail!("MAM results are not in chronological order");
        }
        previous = Some(created_at);
        let message = children
            .iter()
            .find(|child| {
                child.tag_name().namespace() == Some(CLIENT_NS)
                    && child.tag_name().name() == "message"
            })
            .context("MAM forwarded element missing jabber:client message")?;
        validate_message_node(*message)?;
        let from_full = message
            .attribute("from")
            .map(jid::canonicalize)
            .transpose()?;
        let to_full = message.attribute("to").map(jid::canonicalize).transpose()?;
        let from_bare = from_full
            .as_deref()
            .map(jid::canonical_bare_key)
            .transpose()?;
        let to_bare = to_full
            .as_deref()
            .map(jid::canonical_bare_key)
            .transpose()?;
        let peer_full_jid = if from_bare.as_deref() == Some(&account) {
            to_full.context("outgoing MAM message missing to")?
        } else if to_bare.as_deref() == Some(&account) {
            from_full.context("incoming MAM message missing from")?
        } else {
            bail!("MAM message does not belong to imported account");
        };
        let peer_jid = jid::canonical_bare_key(&peer_full_jid)?;
        let stanza = node_to_xml(*message);
        bound_xml(&stanza, "MAM stanza")?;
        user.archive.push(ArchiveItem {
            result_id,
            peer_jid,
            peer_full_jid,
            encrypted: stanza_is_encrypted(*message),
            stanza,
            created_at,
        });
    }
    Ok(())
}
