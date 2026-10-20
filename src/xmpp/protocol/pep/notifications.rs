//! Render PEP notifications and prepare or deliver live and last-item events.

use super::*;

pub(super) fn pep_subscription_element(
    node: &str,
    jid: &str,
    state: &str,
    subid: &str,
) -> XmlElement {
    XmlElement::new("subscription")
        .attr("node", node)
        .attr("jid", jid)
        .attr("subscription", state)
        .attr("subid", subid)
}

pub(super) fn pep_event_message(
    from: &str,
    to: &str,
    message_id: impl ToString,
    event: &str,
    reply_to: Option<&str>,
) -> Result<String> {
    let mut event_wrapper = XmlElement::namespaced("event", NS_PUBSUB_EVENT);
    event_wrapper.push_validated_fragment(event)?;
    let mut message = XmlElement::namespaced("message", "jabber:client")
        .attr("from", from)
        .attr("to", to)
        .attr("type", "headline")
        .attr("id", message_id)
        .child(event_wrapper);
    if let Some(publisher) = reply_to {
        message.push_child(
            XmlElement::namespaced("addresses", "http://jabber.org/protocol/address").child(
                XmlElement::new("address")
                    .attr("type", "replyto")
                    .attr("jid", publisher),
            ),
        );
    }
    Ok(message.finish())
}

impl ProtocolSession {
    /// Render a generic PEP event from the service's transaction-owned
    /// authorization snapshot. Runtime caps/resources are soft routing hints:
    /// they may narrow or expand a bare authorized principal to its resources,
    /// but can never add another principal.
    pub(crate) fn prepare_pep_audience_messages(
        state: &crate::state::AppState,
        publisher_full_jid: Option<&str>,
        node: &str,
        event: &str,
        audience: &PepAudienceSnapshot,
    ) -> Result<Vec<(String, String)>> {
        let event_for = |recipient: &str, reply_to_publisher: bool| -> Result<String> {
            pep_event_message(
                &audience.owner_bare_jid,
                recipient,
                uuid::Uuid::new_v4(),
                event,
                reply_to_publisher.then_some(publisher_full_jid).flatten(),
            )
        };
        let mut delivered = HashSet::new();
        let mut plan = Vec::new();
        for (full_jid, target) in state.session_entries_for(&audience.owner_bare_jid) {
            if target.available.load(std::sync::atomic::Ordering::Relaxed)
                && super::super::caps::wants_pep_node(state, &full_jid, node)
                && delivered.insert(full_jid.clone())
            {
                plan.push((full_jid.clone(), event_for(&full_jid, false)?));
            }
        }
        for contact in &audience.roster_jids {
            let contact_jid = crate::jid::CanonicalJid::parse_bare(contact)?;
            let contact_bare = contact_jid.to_string();
            if contact_jid.domainpart() == state.local_domain() {
                for (full_jid, target) in state.session_entries_for(&contact_bare) {
                    if target.available.load(std::sync::atomic::Ordering::Relaxed)
                        && super::super::caps::wants_pep_node(state, &full_jid, node)
                        && delivered.insert(full_jid.clone())
                    {
                        plan.push((full_jid.clone(), event_for(&full_jid, true)?));
                    }
                }
            } else {
                for full_jid in
                    super::super::caps::interested_resources_for_bare(state, &contact_bare, node)
                {
                    if delivered.insert(full_jid.clone()) {
                        plan.push((full_jid.clone(), event_for(&full_jid, true)?));
                    }
                }
            }
        }
        for subscription_jid in &audience.explicit_jids {
            let parsed = crate::jid::CanonicalJid::parse(subscription_jid)?;
            if parsed.resourcepart().is_some() {
                if delivered.insert(subscription_jid.clone()) {
                    plan.push((
                        subscription_jid.clone(),
                        event_for(subscription_jid, false)?,
                    ));
                }
                continue;
            }
            let subscription_bare = parsed.bare();
            let interested_resources =
                super::super::caps::interested_resources_for_bare(state, &subscription_bare, node);
            if interested_resources.is_empty() {
                if delivered.insert(subscription_jid.clone()) {
                    plan.push((
                        subscription_jid.clone(),
                        event_for(subscription_jid, false)?,
                    ));
                }
            } else {
                for resource in interested_resources {
                    if delivered.insert(resource.clone()) {
                        plan.push((resource.clone(), event_for(&resource, false)?));
                    }
                }
            }
        }
        Ok(plan)
    }

    /// Render a profile event from a transaction-owned authorization snapshot.
    /// Session and caps state only narrows delivery to useful resources; it
    /// cannot add a roster contact or explicit subscriber absent from the
    /// durable snapshot.
    pub(crate) fn prepare_profile_audience_messages(
        state: &crate::state::AppState,
        publisher_full_jid: Option<&str>,
        node: &str,
        event: &str,
        audience: &ProfileAudienceSnapshot,
    ) -> Result<Vec<(String, String)>> {
        let event_for = |recipient: &str, reply_to_publisher: bool| -> Result<String> {
            pep_event_message(
                &audience.owner_bare_jid,
                recipient,
                uuid::Uuid::new_v4(),
                event,
                reply_to_publisher.then_some(publisher_full_jid).flatten(),
            )
        };
        let mut delivered = HashSet::new();
        let mut plan = Vec::new();
        for (full_jid, target) in state.session_entries_for(&audience.owner_bare_jid) {
            if target.available.load(std::sync::atomic::Ordering::Relaxed)
                && super::super::caps::wants_pep_node(state, &full_jid, node)
                && delivered.insert(full_jid.clone())
            {
                plan.push((full_jid.clone(), event_for(&full_jid, false)?));
            }
        }
        for contact in &audience.roster_jids {
            let contact_jid = crate::jid::CanonicalJid::parse_bare(contact)?;
            let contact_bare = contact_jid.to_string();
            if contact_jid.domainpart() == state.local_domain() {
                for (full_jid, target) in state.session_entries_for(&contact_bare) {
                    if target.available.load(std::sync::atomic::Ordering::Relaxed)
                        && super::super::caps::wants_pep_node(state, &full_jid, node)
                        && delivered.insert(full_jid.clone())
                    {
                        plan.push((full_jid.clone(), event_for(&full_jid, true)?));
                    }
                }
            } else {
                for full_jid in
                    super::super::caps::interested_resources_for_bare(state, &contact_bare, node)
                {
                    if delivered.insert(full_jid.clone()) {
                        plan.push((full_jid.clone(), event_for(&full_jid, true)?));
                    }
                }
            }
        }
        for subscription_jid in &audience.explicit_jids {
            let parsed = crate::jid::CanonicalJid::parse(subscription_jid)?;
            if parsed.resourcepart().is_some() {
                if delivered.insert(subscription_jid.clone()) {
                    plan.push((
                        subscription_jid.clone(),
                        event_for(subscription_jid, false)?,
                    ));
                }
                continue;
            }
            let subscription_bare = parsed.bare();
            let interested_resources =
                super::super::caps::interested_resources_for_bare(state, &subscription_bare, node);
            if interested_resources.is_empty() {
                if delivered.insert(subscription_jid.clone()) {
                    plan.push((
                        subscription_jid.clone(),
                        event_for(subscription_jid, false)?,
                    ));
                }
            } else {
                for resource in interested_resources {
                    if delivered.insert(resource.clone()) {
                        plan.push((resource.clone(), event_for(&resource, false)?));
                    }
                }
            }
        }
        Ok(plan)
    }
}

pub(super) fn render_pep_direct_state_messages(
    snapshot: &PepDirectStateSnapshot,
) -> Result<Vec<(String, String)>> {
    snapshot
        .transitions
        .iter()
        .map(|transition| {
            let (recipient, event) = match transition {
                PepDirectStateTransition::Subscription {
                    recipient_jid,
                    subid,
                    state,
                } => (
                    recipient_jid,
                    pep_subscription_element(&snapshot.node, recipient_jid, state, subid).finish(),
                ),
                PepDirectStateTransition::Affiliation {
                    recipient_jid,
                    affiliation,
                } => (
                    recipient_jid,
                    XmlElement::new("affiliation")
                        .attr("node", &snapshot.node)
                        .attr("jid", recipient_jid)
                        .attr("affiliation", affiliation)
                        .finish(),
                ),
            };
            Ok((
                recipient.clone(),
                pep_event_message(
                    &snapshot.owner_bare_jid,
                    recipient,
                    uuid::Uuid::new_v4(),
                    &event,
                    None,
                )?,
            ))
        })
        .collect()
}

pub(crate) async fn send_pep_last_item(
    context: &PepLastItemsContext,
    owner: &crate::services::pubsub::PubSubAccount,
    node: &str,
    recipient: &str,
    on_presence: bool,
    expected_local_epoch: Option<northstar_session_core::LocalCapsEpoch>,
) -> Result<()> {
    send_pep_last_item_for_owner(
        context,
        owner.id,
        &owner.username,
        node,
        recipient,
        on_presence,
        expected_local_epoch,
    )
    .await
}

pub(crate) fn prepare_pep_last_item_outbox(
    snapshot: &PepSubscribeSnapshot,
) -> Result<Vec<PubSubOutboxInsert>> {
    let Some(item) = snapshot.last_item.as_ref() else {
        return Ok(Vec::new());
    };
    let payload = published_event_item(&snapshot.node, &item.item_id, &item.payload)?;
    let message_id = uuid::Uuid::new_v4();
    let mut items = XmlElement::new("items").attr("node", &snapshot.node);
    items.push_validated_fragment(&payload)?;
    let message = XmlElement::namespaced("message", "jabber:client")
        .attr("from", &snapshot.owner_bare_jid)
        .attr("to", &snapshot.subscriber_jid)
        .attr("type", "headline")
        .attr("id", message_id)
        .child(XmlElement::namespaced("event", NS_PUBSUB_EVENT).child(items))
        .child(
            XmlElement::namespaced("delay", "urn:xmpp:delay")
                .attr("stamp", item.updated_at.to_rfc3339()),
        )
        .finish();
    Ok(vec![PubSubOutboxInsert::new_pep_stanza(
        message_id,
        snapshot.owner_id,
        &snapshot.owner_bare_jid,
        None,
        snapshot.subscriber_jid.clone(),
        snapshot.subscriber_account_id,
        PepOutboxEventKind::LastItem,
        PepOutboxAuthorizationMode::CausalAudience,
        message,
        &snapshot.node,
        &snapshot.local_domain,
        chrono::Utc::now(),
    )?])
}

pub(super) async fn send_pep_last_item_for_owner(
    context: &PepLastItemsContext,
    owner_id: uuid::Uuid,
    owner_username: &str,
    node: &str,
    recipient: &str,
    on_presence: bool,
    expected_local_epoch: Option<northstar_session_core::LocalCapsEpoch>,
) -> Result<()> {
    let Some(config) = context.pubsub_service().pep_node(owner_id, node).await? else {
        return Ok(());
    };
    if config.send_last_published_item == "never"
        || on_presence && config.send_last_published_item != "on_sub_and_presence"
        || !config.deliver_notifications
    {
        return Ok(());
    }
    let Some(item) = context
        .pubsub_service()
        .pep_items_with_timestamp(owner_id, node, 1)
        .await?
        .into_iter()
        .next()
    else {
        return Ok(());
    };
    let owner_jid = canonical_account_jid(owner_username, context.local_domain())?;
    let payload = published_event_item(node, &item.item_id, &item.payload)?;
    let mut items = XmlElement::new("items").attr("node", node);
    items.push_validated_fragment(&payload)?;
    let message = XmlElement::namespaced("message", "jabber:client")
        .attr("from", &owner_jid)
        .attr("to", recipient)
        .attr("type", "headline")
        .attr("id", uuid::Uuid::new_v4())
        .child(XmlElement::namespaced("event", NS_PUBSUB_EVENT).child(items))
        .child(
            XmlElement::namespaced("delay", "urn:xmpp:delay")
                .attr("stamp", item.updated_at.to_rfc3339()),
        )
        .finish();
    context
        .route_message(&owner_jid, recipient, message, expected_local_epoch)
        .await
}

/// Delivers XEP-0060 send-last events for durable explicit subscriptions.
/// Unlike XEP-0163 automatic subscriptions, explicit subscriptions do not
/// depend on an XEP-0115 `node+notify` feature advertisement.
pub(crate) async fn deliver_explicit_pep_last_items_for_resource(
    context: &PepLastItemsContext,
    full_jid: &str,
    expected_local_epoch: Option<northstar_session_core::LocalCapsEpoch>,
) -> Result<()> {
    let full_jid = crate::jid::canonical_session_key(full_jid)?;
    for subscription in context
        .pubsub_service()
        .pep_subscriptions_for_available_resource(&full_jid)
        .await?
    {
        if pep_access_allowed_for_owner(
            context.pubsub_service(),
            subscription.owner_id,
            &subscription.owner_username,
            context.local_domain(),
            &subscription.node,
            &full_jid,
        )
        .await?
        {
            send_pep_last_item_for_owner(
                context,
                subscription.owner_id,
                &subscription.owner_username,
                &subscription.node,
                &full_jid,
                true,
                expected_local_epoch,
            )
            .await?;
        }
    }
    Ok(())
}

pub(crate) async fn deliver_pep_last_items_for_resource(
    context: &PepLastItemsContext,
    full_jid: &str,
    expected_local_epoch: northstar_session_core::LocalCapsEpoch,
) -> Result<()> {
    let wanted = context.pep_notify_nodes(full_jid);
    if wanted.is_empty() {
        return Ok(());
    }
    let full = crate::jid::CanonicalJid::parse(full_jid)?;
    let bare = full.bare();
    let Some(username) = full.localpart() else {
        return Ok(());
    };
    let Some(subscriber) = context.pubsub_service().find_enabled_user(username).await? else {
        return Ok(());
    };
    let explicit = context
        .pubsub_service()
        .pep_subscriptions_for_available_resource(full_jid)
        .await?
        .into_iter()
        .map(|subscription| (subscription.owner_id, subscription.node))
        .collect::<HashSet<_>>();
    for node in &wanted {
        if !explicit.contains(&(subscriber.id, node.clone()))
            && context
                .pubsub_service()
                .pep_node(subscriber.id, node)
                .await?
                .is_some()
        {
            send_pep_last_item(
                context,
                &subscriber,
                node,
                full_jid,
                true,
                Some(expected_local_epoch),
            )
            .await?;
        }
    }
    for (contact, _, subscription, _) in context.pubsub_service().roster(subscriber.id).await? {
        if !matches!(subscription.as_str(), "to" | "both") {
            continue;
        }
        let Ok(contact_jid) = crate::jid::CanonicalJid::parse_bare(&contact) else {
            continue;
        };
        if contact_jid.domainpart() != context.local_domain() {
            continue;
        }
        let Some(contact_name) = contact_jid.localpart() else {
            continue;
        };
        let Some(owner) = context
            .pubsub_service()
            .find_enabled_user(contact_name)
            .await?
        else {
            continue;
        };
        if context.pubsub_service().is_blocked(owner.id, &bare).await? {
            continue;
        }
        for node in &wanted {
            if !explicit.contains(&(owner.id, node.clone()))
                && pep_access_allowed(
                    context.pubsub_service(),
                    &owner,
                    context.local_domain(),
                    node,
                    &bare,
                )
                .await?
            {
                send_pep_last_item(
                    context,
                    &owner,
                    node,
                    full_jid,
                    true,
                    Some(expected_local_epoch),
                )
                .await?;
            }
        }
    }
    Ok(())
}

pub(crate) async fn deliver_pep_last_items_for_federated_resource(
    context: &PepLastItemsContext,
    full_jid: &str,
) -> Result<()> {
    let wanted = context.pep_notify_nodes(full_jid);
    if wanted.is_empty() {
        return Ok(());
    }
    let remote = crate::jid::CanonicalJid::parse(full_jid)?;
    if remote.resourcepart().is_none() || remote.domainpart() == context.local_domain() {
        return Ok(());
    }
    let bare = remote.bare();
    let explicit = context
        .pubsub_service()
        .pep_subscriptions_for_available_resource(full_jid)
        .await?
        .into_iter()
        .map(|subscription| (subscription.owner_id, subscription.node))
        .collect::<HashSet<_>>();
    for username in context
        .pubsub_service()
        .pep_owner_usernames_for_presence_subscriber(&bare)
        .await?
    {
        let Some(owner) = context
            .pubsub_service()
            .find_enabled_user(&username)
            .await?
        else {
            continue;
        };
        if context.pubsub_service().is_blocked(owner.id, &bare).await? {
            continue;
        }
        for node in &wanted {
            if !explicit.contains(&(owner.id, node.clone()))
                && pep_access_allowed(
                    context.pubsub_service(),
                    &owner,
                    context.local_domain(),
                    node,
                    full_jid,
                )
                .await?
            {
                send_pep_last_item(context, &owner, node, full_jid, true, None).await?;
            }
        }
    }
    Ok(())
}

/// Removes only an `<item>` root's inherited PubSub namespace before the
/// item is embedded below `pubsub#event`. Nested payload namespace
/// declarations are deliberately preserved.
pub(super) fn strip_pubsub_item_root_namespaces(payload: &str) -> Result<String> {
    let root = XmlElement::new("root");
    let prefix_len = root.open().len();
    let wrapped = root.validated_fragment(payload)?.finish();
    let document = roxmltree::Document::parse(&wrapped)?;
    let single = format!(" xmlns='{NS_PUBSUB}'");
    let double = format!(" xmlns=\"{NS_PUBSUB}\"");
    let mut openings = document
        .root_element()
        .children()
        .filter(|child| child.is_element() && child.tag_name().name() == "item")
        .filter_map(|item| {
            let range = item.range();
            let start = range.start.checked_sub(prefix_len)?;
            let end = payload[start..].find('>').map(|end| start + end)?;
            Some((start, end))
        })
        .collect::<Vec<_>>();
    let mut output = payload.to_owned();
    openings.sort_unstable_by_key(|(start, _)| std::cmp::Reverse(*start));
    for (start, end) in openings {
        let opening = output[start..=end].to_owned();
        let cleaned = opening.replace(&single, "").replace(&double, "");
        output.replace_range(start..=end, &cleaned);
    }
    Ok(output)
}

pub(super) fn published_event_items(node: &str, items: &[(String, String)]) -> Result<String> {
    let mut container = XmlElement::new("northstar-items");
    for (item_id, payload) in items {
        container.push_validated_fragment(&published_event_item(node, item_id, payload)?)?;
    }
    Ok(container.finish_children())
}

pub(crate) fn profile_item_event(node: &str, payload: &str) -> Result<String> {
    let payload = strip_pubsub_item_root_namespaces(payload)?;
    let mut event = XmlElement::new("items").attr("node", node);
    event.push_validated_fragment(&payload)?;
    Ok(event.finish())
}

pub(super) fn published_event_item(node: &str, item_id: &str, payload: &str) -> Result<String> {
    if node == VCARD4 {
        Ok(XmlElement::new("item").attr("id", item_id).finish())
    } else {
        strip_pubsub_item_root_namespaces(payload)
    }
}
