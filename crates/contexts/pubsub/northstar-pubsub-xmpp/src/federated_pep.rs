//! PEP requests of remote entities (S2S inbound `<iq/>`) addressed to the bare JID of a local account.

use anyhow::{Context, Result};
use northstar_federation_core::wire::{s2s_iq_error, s2s_iq_result};
use northstar_pubsub_application::{PepItemQuery, PepItemRead, PepItemSelection};
use northstar_pubsub_core::PepSubscribeSnapshot;
use roxmltree::Node;

use crate::pep::parse_pep_item_selection;
use crate::pubsub::PubSubHost;

/// Answers a federated PEP items request: `<pubsub><items node='...'/></pubsub>` of type `get`.
pub async fn federated_pep_items<H: PubSubHost>(
    host: &H,
    owner_name: Option<&str>,
    full_target: bool,
    child: Node<'_, '_>,
    id: &str,
    to: &str,
    from: &str,
) -> Result<String> {
    if full_target || child.children().filter(|node| node.is_element()).count() != 1 {
        return Ok(s2s_iq_error(id, to, from, "bad-request"));
    }
    let Some(items) = child
        .children()
        .find(|node| node.is_element() && node.tag_name().name() == "items")
    else {
        return Ok(s2s_iq_error(id, to, from, "bad-request"));
    };
    if items
        .attributes()
        .any(|attribute| !matches!(attribute.name(), "node" | "max_items" | "subid"))
    {
        return Ok(s2s_iq_error(id, to, from, "bad-request"));
    }
    let Some(node) = items.attribute("node").filter(|node| {
        !node.is_empty() && node.len() <= 1_024 && !node.chars().any(char::is_control)
    }) else {
        return Ok(s2s_iq_error(id, to, from, "bad-request"));
    };
    let Some(owner_name) = owner_name else {
        return Ok(s2s_iq_error(id, to, from, "item-not-found"));
    };
    let query = PepItemQuery {
        owner_username: owner_name,
        requester_jid: from,
        node,
        selection: parse_pep_item_selection(items, None),
    };
    let read = host
        .pubsub_application_service()
        .pep_items_read(&query)
        .await?;
    federated_pep_item_reply(id, to, from, node, query.selection.as_ref(), read)
}

fn federated_pep_item_reply(
    id: &str,
    to: &str,
    from: &str,
    node: &str,
    selection: Option<&PepItemSelection>,
    read: PepItemRead,
) -> Result<String> {
    let stored = match read {
        PepItemRead::OwnerMissing | PepItemRead::NodeMissing => {
            return Ok(s2s_iq_error(id, to, from, "item-not-found"));
        }
        PepItemRead::Denied(_) => return Ok(s2s_iq_error(id, to, from, "not-authorized")),
        PepItemRead::Items { items, .. } => items,
    };
    let Some(selection) = selection else {
        return Ok(s2s_iq_error(id, to, from, "bad-request"));
    };
    if stored.is_empty() && !selection.item_ids.is_empty() {
        return Ok(s2s_iq_error(id, to, from, "item-not-found"));
    }
    let mut item_list = northstar_xml_builder::XmlElement::new("items").attr("node", node);
    for (_, item) in stored {
        item_list = item_list
            .validated_fragment(&item)
            .context("stored PEP item is not valid XML")?;
    }
    let payload = northstar_xml_builder::XmlElement::new("pubsub")
        .attr("xmlns", "http://jabber.org/protocol/pubsub")
        .child(item_list)
        .finish();
    Ok(s2s_iq_result(id, to, from, &payload))
}

/// Answers a federated PEP subscribe or unsubscribe request: `<pubsub><subscribe/></pubsub>` or
/// `<pubsub><unsubscribe/></pubsub>` of type `set`.
pub async fn federated_pep_subscription<H: PubSubHost>(
    host: &H,
    owner_name: Option<&str>,
    full_target: bool,
    child: Node<'_, '_>,
    id: &str,
    to: &str,
    from: &str,
) -> Result<String> {
    if full_target {
        return Ok(s2s_iq_error(id, to, from, "jid-malformed"));
    }
    let Some(owner_name) = owner_name else {
        return Ok(s2s_iq_error(id, to, from, "item-not-found"));
    };
    let Some(owner) = host
        .pubsub_application_service()
        .find_enabled_user(owner_name)
        .await?
    else {
        return Ok(s2s_iq_error(id, to, from, "item-not-found"));
    };
    let operations = child
        .children()
        .filter(|node| node.is_element())
        .collect::<Vec<_>>();
    if operations.len() != 1 {
        return Ok(s2s_iq_error(id, to, from, "bad-request"));
    }
    let operation = operations[0];
    if operation.tag_name().namespace() != Some("http://jabber.org/protocol/pubsub")
        || !matches!(operation.tag_name().name(), "subscribe" | "unsubscribe")
    {
        return Ok(s2s_iq_error(id, to, from, "feature-not-implemented"));
    }
    let Some(node) = operation.attribute("node").filter(|node| {
        !node.is_empty() && node.len() <= 1_024 && !node.chars().any(char::is_control)
    }) else {
        return Ok(s2s_iq_error(id, to, from, "bad-request"));
    };
    let Some(requested) = operation.attribute("jid") else {
        return Ok(s2s_iq_error(id, to, from, "bad-request"));
    };
    let Ok(requested) = northstar_xmpp_types::jid::canonicalize(requested) else {
        return Ok(s2s_iq_error(id, to, from, "jid-malformed"));
    };
    if operation.tag_name().name() == "subscribe" {
        let service = host.pubsub_application_service();
        let time = service.time_sources();
        let requested_subid = time.new_uuid().to_string();
        let context = time.prepare_event();
        let outcome = match service
            .subscribe_pep_node(
                northstar_pubsub_application::PepSubscribeCommand::from(
                    northstar_pubsub_core::PepSubscribeWrite {
                        owner: &owner,
                        actor: northstar_pubsub_core::PepSubscriptionActor {
                            jid: from,
                            local_account: None,
                        },
                        node,
                        subscriber_jid: &requested,
                        max_subscriptions: 1_000,
                        requested_subid: &requested_subid,
                    },
                ),
                &move |snapshot: &PepSubscribeSnapshot| {
                    crate::pep::prepare_pep_last_item_outbox(snapshot, context)
                },
            )
            .await
        {
            Ok(outcome) => outcome,
            Err(error) if northstar_pubsub_application::is_pubsub_mutation_busy(&error) => {
                return Ok(crate::pubsub::pubsub_s2s_iq_error(
                    id,
                    to,
                    from,
                    &crate::pubsub::PubSubReply::Error("resource-constraint"),
                ));
            }
            Err(error) => return Err(error),
        };
        let subscription = match outcome.outcome {
            northstar_pubsub_core::PepSubscribeOutcome::Subscribed(subscription) => subscription,
            northstar_pubsub_core::PepSubscribeOutcome::NotFound => {
                return Ok(s2s_iq_error(id, to, from, "item-not-found"));
            }
            northstar_pubsub_core::PepSubscribeOutcome::Forbidden => {
                return Ok(s2s_iq_error(id, to, from, "forbidden"));
            }
            northstar_pubsub_core::PepSubscribeOutcome::NotAuthorized(_) => {
                return Ok(s2s_iq_error(id, to, from, "not-authorized"));
            }
            northstar_pubsub_core::PepSubscribeOutcome::LimitExceeded => {
                return Ok(s2s_iq_error(id, to, from, "policy-violation"));
            }
        };
        let payload = northstar_xml_builder::XmlElement::new("pubsub")
            .attr("xmlns", "http://jabber.org/protocol/pubsub")
            .child(
                northstar_xml_builder::XmlElement::new("subscription")
                    .attr("node", node)
                    .attr("jid", &requested)
                    .attr("subscription", "subscribed")
                    .attr("subid", &subscription.subid),
            )
            .finish();
        Ok(s2s_iq_result(id, to, from, &payload))
    } else {
        let outcome = match host
            .pubsub_application_service()
            .unsubscribe_pep_node(northstar_pubsub_application::PepUnsubscribeCommand::from(
                northstar_pubsub_core::PepUnsubscribeWrite {
                    owner: &owner,
                    actor: northstar_pubsub_core::PepSubscriptionActor {
                        jid: from,
                        local_account: None,
                    },
                    node,
                    subscriber_jid: &requested,
                    subid: operation.attribute("subid"),
                },
            ))
            .await
        {
            Ok(outcome) => outcome,
            Err(error) if northstar_pubsub_application::is_pubsub_mutation_busy(&error) => {
                return Ok(crate::pubsub::pubsub_s2s_iq_error(
                    id,
                    to,
                    from,
                    &crate::pubsub::PubSubReply::Error("resource-constraint"),
                ));
            }
            Err(error) => return Err(error),
        };
        match outcome.outcome {
            northstar_pubsub_core::PepUnsubscribeOutcome::Unsubscribed(_) => {}
            northstar_pubsub_core::PepUnsubscribeOutcome::NotFound => {
                return Ok(s2s_iq_error(id, to, from, "item-not-found"));
            }
            northstar_pubsub_core::PepUnsubscribeOutcome::Forbidden => {
                return Ok(s2s_iq_error(id, to, from, "forbidden"));
            }
            northstar_pubsub_core::PepUnsubscribeOutcome::InvalidSubid => {
                return Ok(s2s_iq_error(id, to, from, "unexpected-request"));
            }
        }
        Ok(s2s_iq_result(id, to, from, ""))
    }
}

#[cfg(test)]
mod tests;
