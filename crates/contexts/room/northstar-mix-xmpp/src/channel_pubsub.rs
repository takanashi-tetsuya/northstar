//! Channel PubSub node reads, publishes and retractions, with their form validation.

use super::*;

mod access;
mod admin;

pub use self::admin::{field_first, validate_form_fields};

pub async fn pubsub_get(
    state: &Arc<impl MixHost>,
    request: &OwnedIq,
    channel: &MixChannel,
    actor: &str,
    reply_to: &str,
    node: &str,
    max: i64,
) -> Result<String> {
    if !ALL_NODES.contains(&node) {
        return Ok(iq_error_to(
            &request.id,
            &channel.jid(),
            reply_to,
            "auth",
            "forbidden",
        ));
    }
    // XEP-0403 makes presence a channel-managed node. Clients receive its
    // standard presence fan-out and MUST NOT fetch current state directly via
    // PubSub (MAM remains the explicit historical query path).
    if matches!(node, NODE_MESSAGES | NODE_PRESENCE) {
        return Ok(iq_error_to(
            &request.id,
            &channel.jid(),
            reply_to,
            "cancel",
            "feature-not-implemented",
        ));
    }
    if matches!(node, NODE_ALLOWED | NODE_BANNED) {
        return access::get(state, request, channel, actor, reply_to, node, max).await;
    }
    if node == NODE_JIDMAP {
        let entries = match state
            .mix_service()
            .authorized_mix_jid_map_entries(channel.id, actor, max)
            .await?
        {
            MixReadOutcome::Found(entries) => entries,
            MixReadOutcome::Unauthorized | MixReadOutcome::NotFound => {
                return Ok(iq_error_to(
                    &request.id,
                    &channel.jid(),
                    reply_to,
                    "auth",
                    "forbidden",
                ));
            }
        };
        let mut items = XmlElement::new("items").attr("node", NODE_JIDMAP);
        for (participant_id, jid) in &entries {
            items.push_child(
                XmlElement::new("item").attr("id", participant_id).child(
                    XmlElement::namespaced("participant", ANON_NS)
                        .child(XmlElement::new("jid").text(jid.clone())),
                ),
            );
        }
        let payload = XmlElement::namespaced("pubsub", PUBSUB_NS)
            .child(items)
            .finish();
        return Ok(iq_result_to(
            &request.id,
            &channel.jid(),
            reply_to,
            &payload,
        ));
    }
    let effective_max = if matches!(node, NODE_INFO | NODE_CONFIG) {
        1
    } else {
        max
    };
    let page = match state
        .mix_service()
        .authorized_mix_event_page(channel.id, actor, node, None, effective_max)
        .await?
    {
        MixReadOutcome::Found(page) => page,
        MixReadOutcome::Unauthorized | MixReadOutcome::NotFound => {
            return Ok(iq_error_to(
                &request.id,
                &channel.jid(),
                reply_to,
                "auth",
                "forbidden",
            ));
        }
    };
    let mut items = XmlElement::new("items").attr("node", node);
    for event in page.events.iter().rev() {
        items.push_child(
            XmlElement::new("item")
                .attr("id", &event.item_id)
                .validated_fragment(&event.payload)?,
        );
    }
    let payload = XmlElement::namespaced("pubsub", PUBSUB_NS)
        .child(items)
        .finish();
    Ok(iq_result_to(
        &request.id,
        &channel.jid(),
        reply_to,
        &payload,
    ))
}

#[allow(clippy::too_many_arguments)]
pub async fn pubsub_publish(
    state: &Arc<impl MixHost>,
    request: &OwnedIq,
    channel: &MixChannel,
    actor: &str,
    reply_to: &str,
    node: &str,
    item_count: usize,
    item_ids: &[String],
    fields: &BTreeMap<String, Vec<String>>,
    payloads: &[String],
    federated: Option<&FederatedMixMutation>,
) -> Result<String> {
    anyhow::ensure!(
        payloads.len() == item_count,
        "MIX publish payload count mismatch"
    );
    match node {
        NODE_AVATAR_DATA | NODE_AVATAR_METADATA => {
            anyhow::ensure!(
                item_count == 1 && item_ids.len() == 1 && payloads.len() == 1,
                "MIX avatar publish requires one identified item"
            );
            anyhow::ensure!(fields.is_empty(), "MIX avatar item cannot contain a form");
            let payload_document =
                Document::parse(&payloads[0]).context("malformed MIX avatar payload")?;
            let payload = payload_document.root_element();
            let valid = if node == NODE_AVATAR_DATA {
                northstar_xmpp_avatar::valid_avatar_data(&item_ids[0], payload)
            } else {
                northstar_xmpp_avatar::valid_avatar_metadata(&item_ids[0], payload)
            };
            anyhow::ensure!(valid, "invalid MIX avatar payload");
            if !state
                .mix_service()
                .publish_mix_avatar(
                    channel.id,
                    actor,
                    node,
                    &item_ids[0],
                    &payloads[0],
                    federated,
                )
                .await?
            {
                return Ok(iq_error_to(
                    &request.id,
                    &channel.jid(),
                    reply_to,
                    "auth",
                    "forbidden",
                ));
            }
            let acknowledgement = mix_pubsub_publish_ack(node, &item_ids[0]);
            Ok(iq_result_to(
                &request.id,
                &channel.jid(),
                reply_to,
                &acknowledgement,
            ))
        }
        NODE_INFO => {
            return admin::publish_info(
                state, request, channel, actor, reply_to, item_count, fields, federated,
            )
            .await;
        }
        NODE_CONFIG => {
            return admin::publish_config(
                state, request, channel, actor, reply_to, item_count, fields, federated,
            )
            .await;
        }
        NODE_ALLOWED | NODE_BANNED => {
            access::publish(
                state, request, channel, actor, reply_to, node, item_count, item_ids, fields,
                federated,
            )
            .await
        }
        _ => Ok(iq_error_to(
            &request.id,
            &channel.jid(),
            reply_to,
            "auth",
            "forbidden",
        )),
    }
}

pub struct PubSubRetractRequest<'a> {
    pub request: &'a OwnedIq,
    pub channel: &'a MixChannel,
    pub actor: &'a str,
    pub reply_to: &'a str,
    pub node: &'a str,
    pub item_ids: &'a [String],
    pub federated: Option<&'a FederatedMixMutation>,
}

pub async fn pubsub_retract(
    state: &Arc<impl MixHost>,
    operation: PubSubRetractRequest<'_>,
) -> Result<String> {
    let PubSubRetractRequest {
        request,
        channel,
        actor,
        reply_to,
        node,
        item_ids,
        federated,
    } = operation;
    if matches!(node, NODE_AVATAR_DATA | NODE_AVATAR_METADATA) && item_ids.len() == 1 {
        if !state
            .mix_service()
            .retract_mix_avatar(channel.id, actor, node, &item_ids[0], federated)
            .await?
        {
            return Ok(iq_error_to(
                &request.id,
                &channel.jid(),
                reply_to,
                "auth",
                "forbidden",
            ));
        }
        return Ok(iq_result_to(
            &request.id,
            &channel.jid(),
            reply_to,
            &mix_empty_pubsub(),
        ));
    }
    if !matches!(node, NODE_ALLOWED | NODE_BANNED) || item_ids.len() != 1 {
        return Ok(iq_error_to(
            &request.id,
            &channel.jid(),
            reply_to,
            "auth",
            "forbidden",
        ));
    }
    access::retract(
        state, request, channel, actor, reply_to, node, item_ids, federated,
    )
    .await
}
