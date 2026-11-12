//! PEP requests of remote entities (S2S inbound `<iq/>`) addressed to the bare JID of a local account.

use anyhow::{Context, Result};
use northstar_federation_core::wire::{s2s_iq_error, s2s_iq_result};
use roxmltree::Node;

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
    let Some(owner) = host
        .pubsub_application_service()
        .find_enabled_user(owner_name)
        .await?
    else {
        return Ok(s2s_iq_error(id, to, from, "item-not-found"));
    };
    if host
        .pubsub_application_service()
        .pep_node(owner.id, node)
        .await?
        .is_none()
    {
        return Ok(s2s_iq_error(id, to, from, "item-not-found"));
    }
    if !crate::pep::pep_access_allowed(
        host.pubsub_application_service(),
        &owner,
        host.pubsub_local_domain(),
        node,
        from,
    )
    .await?
    {
        return Ok(s2s_iq_error(id, to, from, "not-authorized"));
    }
    let requested = items
        .children()
        .filter(|node| node.is_element())
        .map(|item| {
            (item.tag_name().namespace() == Some("http://jabber.org/protocol/pubsub")
                && item.tag_name().name() == "item"
                && item.attributes().len() == 1
                && item.attribute("id").is_some_and(|item_id| {
                    !item_id.is_empty()
                        && item_id.len() <= 1_024
                        && !item_id.chars().any(char::is_control)
                })
                && !item.children().any(|child| child.is_element()))
            .then(|| item.attribute("id").unwrap_or_default())
        })
        .collect::<Option<Vec<_>>>();
    let Some(requested) =
        requested.filter(|items| items.len() <= northstar_pubsub_core::PEP_MAX_ITEMS as usize)
    else {
        return Ok(s2s_iq_error(id, to, from, "bad-request"));
    };
    let max_items = match items.attribute("max_items") {
        Some(value) => match value.parse::<i64>() {
            Ok(value) if value > 0 => value.min(northstar_pubsub_core::PEP_MAX_ITEMS as i64),
            _ => return Ok(s2s_iq_error(id, to, from, "bad-request")),
        },
        None => northstar_pubsub_core::PEP_MAX_ITEMS as i64,
    };
    let stored = if requested.is_empty() {
        host.pubsub_application_service()
            .pep_items(owner.id, node, None, max_items)
            .await?
    } else {
        host.pubsub_application_service()
            .pep_items_by_ids(owner.id, node, &requested, max_items)
            .await?
    };
    if stored.is_empty() && !requested.is_empty() {
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
        let requested_subid = uuid::Uuid::new_v4().to_string();
        let outcome = match host
            .pubsub_application_service()
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
                &crate::pep::prepare_pep_last_item_outbox,
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
#[path = "federated_pep_tests.rs"]
mod tests;
