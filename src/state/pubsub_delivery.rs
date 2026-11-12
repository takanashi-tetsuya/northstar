//! The node's PubSub deliveries outside a client request: due digests, the event outbox and the last-item replay on available presence.

use super::pubsub_digest_worker::PubSubDigestWorkerContext;
use super::AppState;
use anyhow::Result;
use northstar_pubsub_application::service::subscription_event_children;
use northstar_xml_builder::XmlElement;
use std::{sync::Arc, time::Duration};

pub(crate) async fn deliver_due_pubsub_digests(
    context: &PubSubDigestWorkerContext,
) -> Result<usize> {
    let digests = context.claim_due().await?;
    let count = digests.len();
    for digest in digests {
        let show_values = if let Some(snapshot) = digest.show_values.clone() {
            Some(snapshot)
        } else {
            context
                .current_show_values(digest.subscription_node_id, &digest.subscriber_jid)
                .await?
        };
        if let Some(show_values) = show_values {
            let mut batches = Vec::<(Vec<uuid::Uuid>, String)>::new();
            let mut batch_ids = Vec::new();
            let mut batch_xml = String::new();
            for (id, event) in digest.ids.into_iter().zip(digest.event_xml) {
                if !batch_xml.is_empty()
                    && batch_xml.len().saturating_add(event.len())
                        > northstar_xep_0060::MAX_PUBLISH_XML_BYTES
                {
                    batches.push((
                        std::mem::take(&mut batch_ids),
                        std::mem::take(&mut batch_xml),
                    ));
                }
                batch_ids.push(id);
                batch_xml.push_str(&event);
            }
            if !batch_ids.is_empty() {
                batches.push((batch_ids, batch_xml));
            }
            for index in 0..batches.len() {
                let (ids, children) = &batches[index];
                if let Err(error) = context
                    .notification()
                    .route_children(
                        &digest.subscriber_jid,
                        children,
                        Some(&show_values),
                        uuid::Uuid::new_v4(),
                    )
                    .await
                {
                    let pending_ids = batches[index..]
                        .iter()
                        .flat_map(|(ids, _)| ids.iter().copied())
                        .collect::<Vec<_>>();
                    context.release(&pending_ids).await?;
                    return Err(error);
                }
                context.acknowledge(ids).await?;
            }
        } else {
            context.acknowledge(&digest.ids).await?;
        }
    }
    Ok(count)
}

pub(crate) fn start_pubsub_digest_delivery(
    state: Arc<AppState>,
    cancel: tokio_util::sync::CancellationToken,
) {
    let registry = Arc::clone(state.worker_registry());
    let context = Arc::new(state.pubsub_digest_worker_context());
    registry.supervise(
        "pubsub-digest-delivery",
        northstar_runtime::workers::WorkerCriticality::Restartable,
        northstar_runtime::workers::WorkerMode::Continuous,
        Some(Duration::from_secs(5)),
        cancel,
        move |heartbeat| {
            let context = Arc::clone(&context);
            async move {
                let mut interval = tokio::time::interval(Duration::from_secs(1));
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    interval.tick().await;
                    if let Err(error) = deliver_due_pubsub_digests(&context).await {
                        heartbeat.error(&error);
                        tracing::error!(
                            ?error,
                            "failed to deliver durable PubSub notification digest"
                        );
                    } else {
                        heartbeat.ok();
                    }
                }
            }
        },
    );
}

pub(crate) fn start_pubsub_event_outbox_delivery(
    state: Arc<AppState>,
    cancel: tokio_util::sync::CancellationToken,
) {
    let registry = Arc::clone(state.worker_registry());
    let context = Arc::new(state.pubsub_event_outbox_worker_context());
    registry.supervise(
        "pubsub-event-outbox-delivery",
        northstar_runtime::workers::WorkerCriticality::Restartable,
        northstar_runtime::workers::WorkerMode::Continuous,
        Some(Duration::from_secs(30)),
        cancel.clone(),
        move |heartbeat| {
            let context = Arc::clone(&context);
            let cancel = cancel.clone();
            async move {
                let mut maintenance_ticks = 0_u32;
                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => return Ok(()),
                        _ = tokio::time::sleep(Duration::from_millis(250)) => {}
                    }
                    let claimed = context.claim().await?;
                    for item in claimed {
                        let _delivery_timer = context.start_delivery_timer();
                        if !context.renew(&item).await? {
                            tracing::warn!(
                                delivery_id = %item.delivery_id,
                                event_id = %item.event_id,
                                ordering_key = %item.ordering_key,
                                event_sequence = item.event_sequence,
                                target_domain = %item.target_domain,
                                attempt_count = item.attempt_count,
                                expires_at = %item.expires_at,
                                "PubSub event outbox claim lost before routing"
                            );
                            continue;
                        }
                        // Keep routing strictly inside the renewed 30-second
                        // lease.  An unresponsive remote/domain route must be
                        // retried with the same immutable event instead of
                        // completing after another worker has taken over.
                        let result = match tokio::time::timeout(
                            Duration::from_secs(20),
                            context.deliver(&item),
                        )
                        .await
                        {
                            Ok(result) => result,
                            Err(_) => Err(anyhow::anyhow!(
                                "PubSub outbox route exceeded its bounded delivery window"
                            )),
                        };
                        match result {
                            Ok(()) => {
                                if !context.acknowledge(&item).await? {
                                    tracing::warn!(
                                        delivery_id = %item.delivery_id,
                                        "PubSub event outbox acknowledgement lost its lease"
                                    );
                                }
                            }
                            Err(error) if !item.payload_binding_valid() => {
                                context
                                    .dead_letter_integrity(&item, &error.to_string())
                                    .await?;
                            }
                            Err(error) => {
                                context.retry(&item, &error.to_string()).await?;
                            }
                        }
                    }
                    maintenance_ticks = maintenance_ticks.saturating_add(1);
                    if maintenance_ticks >= 20 {
                        maintenance_ticks = 0;
                        context.maintain().await?;
                    }
                    heartbeat.ok();
                }
            }
        },
    );
}

pub(crate) async fn deliver_last_items_on_presence(
    state: Arc<AppState>,
    outbound: northstar_stream::outbound::OutboundSender,
    recipient_id: uuid::Uuid,
    active_privacy_list: Option<String>,
    connection_id: uuid::Uuid,
    recipient: String,
    show: &'static str,
) -> Result<()> {
    let requester_bare = northstar_xmpp_types::jid::canonical_bare_key(&recipient)?;
    let service = northstar_pubsub_xmpp::pubsub::pubsub_domain(state.as_ref());
    if state
        .pubsub_service()
        .presence_delivery_denied(
            recipient_id,
            active_privacy_list.as_deref(),
            connection_id,
            &service,
        )
        .await?
    {
        return Ok(());
    }
    let mut cursor: Option<(String, String)> = None;
    loop {
        let page = state
            .pubsub_service()
            .subscriptions_addressing_jid_page(
                &recipient,
                cursor
                    .as_ref()
                    .map(|(node, jid)| (node.as_str(), jid.as_str())),
                100,
            )
            .await?;
        if page.is_empty() {
            break;
        }
        let page_len = page.len();
        for subscription in page {
            cursor = Some((subscription.node.clone(), subscription.jid.clone()));
            if subscription.state != "subscribed"
                || !subscription.deliver
                || !subscription.show_values.iter().any(|value| value == show)
            {
                continue;
            }
            let Some(node) = state.pubsub_service().get_node(&subscription.node).await? else {
                continue;
            };
            if node.send_last_published_item != "on_sub_and_presence"
                || !state
                    .pubsub_service()
                    .can_retrieve_node(&node, &requester_bare)
                    .await?
            {
                continue;
            }
            let Some(item) = state
                .pubsub_service()
                .get_items(node.id, &[], 1)
                .await?
                .into_iter()
                .next()
            else {
                continue;
            };
            let mut event = XmlElement::new("items").attr("node", &node.node);
            if node.deliver_payloads {
                event.push_validated_fragment(&northstar_pubsub_xmpp::pubsub::event_item_xml(
                    &item.xml_payload,
                ))?;
            } else {
                event.push_child(XmlElement::new("item").attr("id", &item.item_id));
            }
            let event = event.finish();
            let children =
                subscription_event_children(&subscription, &event, None, Some(item.created_at))?;
            if subscription.digest
                && state
                    .pubsub_service()
                    .enqueue_pubsub_digest(
                        node.id,
                        &subscription.jid,
                        &children,
                        subscription.digest_frequency,
                    )
                    .await?
            {
                continue;
            }
            let message = XmlElement::namespaced("message", "jabber:client")
                .attr("type", "headline")
                .attr("id", uuid::Uuid::new_v4())
                .attr("from", &service)
                .attr("to", &recipient)
                .validated_fragment(&children)?
                .finish();
            if outbound.send(message).await.is_err() {
                return Ok(());
            }
        }
        if page_len < 100 {
            break;
        }
    }
    Ok(())
}
