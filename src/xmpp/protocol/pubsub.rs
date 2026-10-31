use super::{Action, ProtocolSession};
use crate::services::xml_util::{iq_error_from, iq_result_from};
use crate::state::{pubsub_digest_worker::PubSubDigestWorkerContext, AppState};
use crate::xmpp::xml_builder::XmlElement;
use anyhow::Result;
use northstar_pubsub_application::{service::subscription_event_children, PubSubService};
use northstar_pubsub_core::PubSubNode;
use roxmltree::Node;
use std::{sync::Arc, time::Duration};

pub(crate) use northstar_pubsub_xmpp::pubsub::{error_condition, pubsub_s2s_iq_error, PubSubReply};

pub(crate) fn service_disco_payload(state: &AppState) -> String {
    northstar_pubsub_xmpp::pubsub::service_disco_payload(state)
}

pub(crate) async fn federated_disco_info(
    state: &AppState,
    requester: &str,
    requested_node: Option<&str>,
) -> Result<PubSubReply> {
    northstar_pubsub_xmpp::pubsub::federated_disco_info(state, requester, requested_node).await
}

pub(crate) async fn federated_disco_items(
    state: &AppState,
    requester: &str,
    request: Node<'_, '_>,
) -> Result<PubSubReply> {
    northstar_pubsub_xmpp::pubsub::federated_disco_items(state, requester, request).await
}

pub(crate) async fn handle_request(
    state: &AppState,
    requester: &str,
    kind: &str,
    child: Node<'_, '_>,
) -> Result<PubSubReply> {
    northstar_pubsub_xmpp::pubsub::handle_request(state, requester, kind, child).await
}

pub(crate) async fn handle_authorization_response(
    state: &AppState,
    requester: &str,
    message: Node<'_, '_>,
) -> Result<()> {
    northstar_pubsub_xmpp::pubsub::handle_authorization_response(state, requester, message).await
}

pub(crate) async fn node_metadata_form(state: &AppState, node: &PubSubNode) -> Result<String> {
    northstar_pubsub_xmpp::pubsub::node_metadata_form(state, node).await
}

impl ProtocolSession {
    pub(crate) fn pubsub_domain(&self) -> String {
        northstar_pubsub_xmpp::pubsub::pubsub_domain(self.state.as_ref())
    }

    pub(crate) async fn pubsub_iq_get(&self, id: &str, child: Node<'_, '_>) -> Result<Action> {
        self.pubsub_request(id, "get", child).await
    }

    pub(crate) async fn pubsub_iq_set(
        &self,
        id: &str,
        child: Node<'_, '_>,
        _to: &str,
    ) -> Result<Action> {
        self.pubsub_request(id, "set", child).await
    }

    pub(crate) async fn pubsub_owner_get(&self, id: &str, child: Node<'_, '_>) -> Result<Action> {
        self.pubsub_request(id, "get", child).await
    }

    pub(crate) async fn pubsub_owner_set(&self, id: &str, child: Node<'_, '_>) -> Result<Action> {
        self.pubsub_request(id, "set", child).await
    }

    async fn pubsub_request(&self, id: &str, kind: &str, child: Node<'_, '_>) -> Result<Action> {
        let service = self.pubsub_domain();
        let Some(full_jid) = self.full_jid.as_deref() else {
            return Ok(Action::Send(iq_error_from(id, &service, "not-authorized")));
        };
        let reply = match handle_request(&self.state, full_jid, kind, child).await {
            Ok(reply) => reply,
            Err(error) if northstar_pubsub_application::is_pubsub_mutation_busy(&error) => {
                PubSubReply::Error("resource-constraint")
            }
            Err(error) => return Err(error),
        };
        Ok(match reply {
            PubSubReply::Result(payload) => Action::Send(iq_result_from(id, &service, &payload)),
            reply @ (PubSubReply::Error(_) | PubSubReply::ExtendedError(_)) => Action::Send(
                northstar_pubsub_xmpp::pubsub::pubsub_iq_error(id, &service, &reply),
            ),
        })
    }

    pub(crate) async fn pubsub_authorization_response(&self, root: Node<'_, '_>) -> Result<bool> {
        let Some(to) = root.attribute("to") else {
            return Ok(false);
        };
        if northstar_xmpp_types::jid::canonicalize_bare(to)
            .ok()
            .as_deref()
            != northstar_xmpp_types::jid::canonicalize_bare(&self.pubsub_domain())
                .ok()
                .as_deref()
        {
            return Ok(false);
        }
        let Some(requester) = self.full_jid.as_deref() else {
            return Ok(true);
        };
        handle_authorization_response(&self.state, requester, root).await?;
        Ok(true)
    }

    /// XEP-0060 `send_last_published_item=on_sub_and_presence` delivery.
    /// Presence addressed to the service is consumed by the service and is
    /// never routed to a similarly named local account.
    pub(crate) async fn pubsub_presence(&mut self, kind: &str, from: &str) -> Result<Action> {
        if kind != "available" {
            return Ok(Action::None);
        }
        let requester_full = northstar_xmpp_types::jid::canonicalize(from)?;
        let requester_id = self
            .authenticated
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("PubSub presence requires an authenticated account"))?
            .id;
        let active_privacy_list = self
            .privacy_active
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let connection_id = self.connection_id;
        let state = self.state.clone();
        let outbound = self.outbound.clone();
        let show = match self.show.load(std::sync::atomic::Ordering::Relaxed) {
            2 => "away",
            3 => "chat",
            4 => "dnd",
            5 => "xa",
            _ => "online",
        };
        self.defer_after_transport("pubsub-last-item-replay", async move {
            if let Err(error) = deliver_last_items_on_presence(
                state,
                outbound,
                requester_id,
                active_privacy_list,
                connection_id,
                requester_full,
                show,
            )
            .await
            {
                tracing::error!(
                    ?error,
                    "failed PubSub last-item replay on available presence"
                );
            }
        })?;
        Ok(Action::None)
    }
}

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

async fn deliver_last_items_on_presence(
    state: Arc<AppState>,
    outbound: crate::xmpp::outbound::OutboundSender,
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

impl northstar_pubsub_xmpp::pubsub::PubSubHost for AppState {
    fn pubsub_local_domain(&self) -> &str {
        self.local_domain()
    }

    fn pubsub_server_name(&self) -> &str {
        self.server_name()
    }

    fn pubsub_node_owner_limits(&self) -> northstar_pubsub_xmpp::pubsub::PubSubOwnerLimits {
        let limits = self.pubsub_owner_limits();
        northstar_pubsub_xmpp::pubsub::PubSubOwnerLimits {
            max_nodes: limits.max_nodes,
            max_storage_bytes: limits.max_storage_bytes,
        }
    }

    fn pubsub_application_service(
        &self,
    ) -> &PubSubService<impl northstar_pubsub_xmpp::PubSubRepositories> {
        self.pubsub_service()
    }
}
