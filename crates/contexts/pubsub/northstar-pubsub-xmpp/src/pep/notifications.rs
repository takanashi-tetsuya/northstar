//! Render PEP notifications and prepare or deliver live and last-item events.

use super::*;
use northstar_pubsub_application::DEFAULT_PEP_REPLAY_LIMIT;
use northstar_pubsub_core::{PepReplayMode, PreparedEventContext, PubSubAddress};
use northstar_time::{DateTime, Utc};

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

/// Render a generic PEP event from the service's transaction-owned
/// authorization snapshot. Runtime caps/resources are soft routing hints:
/// they may narrow or expand a bare authorized principal to its resources,
/// but can never add another principal.
pub fn pep_audience_messages(
    routing: &(impl PepAudienceRouting + ?Sized),
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
    for full_jid in routing.pep_available_resources_wanting(&audience.owner_bare_jid, node) {
        if delivered.insert(full_jid.clone()) {
            plan.push((full_jid.clone(), event_for(&full_jid, false)?));
        }
    }
    for contact in &audience.roster_jids {
        let contact_jid = northstar_xmpp_types::jid::CanonicalJid::parse_bare(contact)?;
        let contact_bare = contact_jid.to_string();
        if contact_jid.domainpart() == routing.pep_routing_local_domain() {
            for full_jid in routing.pep_available_resources_wanting(&contact_bare, node) {
                if delivered.insert(full_jid.clone()) {
                    plan.push((full_jid.clone(), event_for(&full_jid, true)?));
                }
            }
        } else {
            for full_jid in routing.pep_interested_resources(&contact_bare, node) {
                if delivered.insert(full_jid.clone()) {
                    plan.push((full_jid.clone(), event_for(&full_jid, true)?));
                }
            }
        }
    }
    for subscription_jid in &audience.explicit_jids {
        let parsed = northstar_xmpp_types::jid::CanonicalJid::parse(subscription_jid)?;
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
        let interested_resources = routing.pep_interested_resources(&subscription_bare, node);
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
pub fn profile_audience_messages(
    routing: &(impl PepAudienceRouting + ?Sized),
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
    for full_jid in routing.pep_available_resources_wanting(&audience.owner_bare_jid, node) {
        if delivered.insert(full_jid.clone()) {
            plan.push((full_jid.clone(), event_for(&full_jid, false)?));
        }
    }
    for contact in &audience.roster_jids {
        let contact_jid = northstar_xmpp_types::jid::CanonicalJid::parse_bare(contact)?;
        let contact_bare = contact_jid.to_string();
        if contact_jid.domainpart() == routing.pep_routing_local_domain() {
            for full_jid in routing.pep_available_resources_wanting(&contact_bare, node) {
                if delivered.insert(full_jid.clone()) {
                    plan.push((full_jid.clone(), event_for(&full_jid, true)?));
                }
            }
        } else {
            for full_jid in routing.pep_interested_resources(&contact_bare, node) {
                if delivered.insert(full_jid.clone()) {
                    plan.push((full_jid.clone(), event_for(&full_jid, true)?));
                }
            }
        }
    }
    for subscription_jid in &audience.explicit_jids {
        let parsed = northstar_xmpp_types::jid::CanonicalJid::parse(subscription_jid)?;
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
        let interested_resources = routing.pep_interested_resources(&subscription_bare, node);
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

/// Delivers the last published item on `node` for `owner` to `recipient`.
pub async fn send_pep_last_item<C: PepLastItemDelivery>(
    context: &C,
    owner: &PubSubAccount,
    node: &str,
    recipient: &str,
    on_presence: bool,
    expected_local_epoch: Option<C::CapsEpoch>,
) -> Result<()> {
    let query = PepReplayQuery {
        requester: PubSubAddress::parse(recipient)?,
        mode: PepReplayMode::AfterSubscribe {
            owner: owner.clone(),
            node: node.to_owned(),
            on_presence,
        },
        local_domain: context.last_item_local_domain().to_owned(),
        after: None,
        limit: 1,
    };
    deliver_pep_replay(context, query, recipient, expected_local_epoch).await
}

/// Prepares the send-last outbox entries for a PEP subscription.
pub fn prepare_pep_last_item_outbox(
    snapshot: &PepSubscribeSnapshot,
    context: PreparedEventContext,
) -> Result<Vec<PubSubOutboxInsert>> {
    let Some(item) = snapshot.last_item.as_ref() else {
        return Ok(Vec::new());
    };
    let message = pep_last_item_message(
        &snapshot.owner_bare_jid,
        &snapshot.subscriber_jid,
        &snapshot.node,
        &item.item_id,
        &item.payload,
        item.updated_at,
        context.id,
    )?;
    Ok(vec![PubSubOutboxInsert::new_pep_stanza(
        context.id,
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
        context.at,
    )?])
}

fn pep_last_item_message(
    owner: &str,
    recipient: &str,
    node: &str,
    item_id: &str,
    payload: &str,
    updated_at: DateTime<Utc>,
    message_id: uuid::Uuid,
) -> Result<String> {
    let payload = published_event_item(node, item_id, payload)?;
    let items = XmlElement::new("items")
        .attr("node", node)
        .validated_fragment(&payload)?;
    Ok(XmlElement::namespaced("message", "jabber:client")
        .attr("from", owner)
        .attr("to", recipient)
        .attr("type", "headline")
        .attr("id", message_id)
        .child(XmlElement::namespaced("event", NS_PUBSUB_EVENT).child(items))
        .child(
            XmlElement::namespaced("delay", "urn:xmpp:delay")
                .attr("stamp", updated_at.to_rfc3339()),
        )
        .finish())
}

/// Delivers XEP-0060 send-last events for durable explicit subscriptions.
/// Unlike XEP-0163 automatic subscriptions, explicit subscriptions do not
/// depend on an XEP-0115 `node+notify` feature advertisement.
pub async fn deliver_explicit_pep_last_items_for_resource<C: PepLastItemDelivery>(
    context: &C,
    full_jid: &str,
    expected_local_epoch: Option<C::CapsEpoch>,
) -> Result<()> {
    let requester = PubSubAddress::parse(full_jid)?;
    anyhow::ensure!(
        requester.has_resource(),
        "session JID must contain a resourcepart"
    );
    let recipient = requester.to_string();
    deliver_pep_replay(
        context,
        presence_query(context, requester, PepReplayMode::Explicit),
        &recipient,
        expected_local_epoch,
    )
    .await
}

/// Delivers PEP send-last items for a local resource based on its entity capabilities.
pub async fn deliver_pep_last_items_for_resource<C: PepLastItemDelivery>(
    context: &C,
    full_jid: &str,
    expected_local_epoch: C::CapsEpoch,
) -> Result<()> {
    let wanted = context.last_item_notify_nodes(full_jid);
    if wanted.is_empty() {
        return Ok(());
    }
    let query = presence_query(
        context,
        PubSubAddress::parse(full_jid)?,
        PepReplayMode::LocalCaps { wanted },
    );
    deliver_pep_replay(context, query, full_jid, Some(expected_local_epoch)).await
}

/// Delivers PEP send-last items for a federated resource based on its entity capabilities.
pub async fn deliver_pep_last_items_for_federated_resource<C: PepLastItemDelivery>(
    context: &C,
    full_jid: &str,
) -> Result<()> {
    let wanted = context.last_item_notify_nodes(full_jid);
    if wanted.is_empty() {
        return Ok(());
    }
    let query = presence_query(
        context,
        PubSubAddress::parse(full_jid)?,
        PepReplayMode::FederatedCaps { wanted },
    );
    deliver_pep_replay(context, query, full_jid, None).await
}

fn presence_query<C: PepLastItemDelivery>(
    context: &C,
    requester: PubSubAddress,
    mode: PepReplayMode,
) -> PepReplayQuery {
    PepReplayQuery {
        requester,
        mode,
        local_domain: context.last_item_local_domain().to_owned(),
        after: None,
        limit: DEFAULT_PEP_REPLAY_LIMIT,
    }
}

async fn deliver_pep_replay<C: PepLastItemDelivery>(
    context: &C,
    mut query: PepReplayQuery,
    recipient: &str,
    expected_local_epoch: Option<C::CapsEpoch>,
) -> Result<()> {
    loop {
        let page = context.last_item_replay_page(&query).await?;
        for entry in page.entries {
            let owner = canonical_account_jid(&entry.owner_username, &query.local_domain)?;
            let message = pep_last_item_message(
                &owner,
                recipient,
                &entry.node,
                &entry.item_id,
                &entry.payload,
                entry.updated_at,
                context.last_item_time_sources().new_uuid(),
            )?;
            context
                .last_item_route(&owner, recipient, message, expected_local_epoch)
                .await?;
        }
        let Some(next) = page.next else {
            return Ok(());
        };
        query.after = Some(next);
    }
}

pub(super) fn published_event_items(node: &str, items: &[(String, String)]) -> Result<String> {
    let mut container = XmlElement::new("northstar-items");
    for (item_id, payload) in items {
        container.push_validated_fragment(&published_event_item(node, item_id, payload)?)?;
    }
    Ok(container.finish_children())
}

pub(super) fn published_event_item(node: &str, item_id: &str, payload: &str) -> Result<String> {
    if node == VCARD4 {
        Ok(XmlElement::new("item").attr("id", item_id).finish())
    } else {
        strip_pubsub_item_root_namespaces(payload)
    }
}
