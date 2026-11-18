//! The node's PubSub deliveries outside a client request: due digests, the event outbox and the last-item replay on available presence.

use anyhow::Result;
use northstar_pubsub_application::service::subscription_event_children;
use northstar_pubsub_application::{PubSubOutboxRepository, PubSubService};
use northstar_pubsub_core::{
    ClaimedPubSubOutboxDelivery, DuePubSubDigest, PepOutboxAuthorizationOutcome,
    PubSubOutboxDeliveryKind,
};
use northstar_telemetry::metrics::{DurationHistogram, DurationTimer};
use northstar_xml_builder::XmlElement;
use std::future::Future;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::Duration;
use uuid::Uuid;

/// The stanza routes a PubSub delivery outside a client request uses; the
/// composition root binds them to its local, cluster and federation routes.
pub trait PubSubDeliveryRoutes: Send + Sync + 'static {
    /// The PubSub service's JID.
    fn service_domain(&self) -> String;
    fn route_children(
        &self,
        recipient: &str,
        children: &str,
        show_values: Option<&[String]>,
        message_id: Uuid,
    ) -> impl Future<Output = Result<()>> + Send;
    fn route_service_message(
        &self,
        service: &str,
        recipient: &str,
        message: String,
    ) -> impl Future<Output = Result<()>> + Send;
    /// Routes one authorized PEP stanza from its owner's bare JID.
    fn route_pep_message(
        &self,
        sender_bare_jid: &str,
        recipient: &str,
        message: String,
    ) -> impl Future<Output = Result<()>> + Send;
}

/// PubSub outbox worker timing and last-successful-maintenance gauges.
pub struct PubSubOutboxTelemetry<'a> {
    pending_rows: &'a AtomicU64,
    pending_bytes: &'a AtomicU64,
    dead_letter_rows: &'a AtomicU64,
}

impl<'a> PubSubOutboxTelemetry<'a> {
    pub fn new(
        pending_rows: &'a AtomicU64,
        pending_bytes: &'a AtomicU64,
        dead_letter_rows: &'a AtomicU64,
    ) -> Self {
        Self {
            pending_rows,
            pending_bytes,
            dead_letter_rows,
        }
    }

    pub fn publish_snapshot(&self, pending_rows: i64, pending_bytes: i64, dead_letter_rows: i64) {
        let nonnegative = |value: i64| u64::try_from(value.max(0)).unwrap_or(u64::MAX);
        self.pending_rows
            .store(nonnegative(pending_rows), Ordering::Relaxed);
        self.pending_bytes
            .store(nonnegative(pending_bytes), Ordering::Relaxed);
        self.dead_letter_rows
            .store(nonnegative(dead_letter_rows), Ordering::Relaxed);
    }
}

/// Durable digest claims and their policy-checked delivery endpoint.
pub struct PubSubDigestWorkerContext<R, N> {
    service: PubSubService<R>,
    notification: N,
}

impl<R: PubSubOutboxRepository, N: PubSubDeliveryRoutes> PubSubDigestWorkerContext<R, N> {
    pub fn new(service: PubSubService<R>, notification: N) -> Self {
        Self {
            service,
            notification,
        }
    }

    pub fn notification(&self) -> &N {
        &self.notification
    }

    pub async fn claim_due(&self) -> Result<Vec<DuePubSubDigest>> {
        self.service.claim_due_pubsub_digests(1_000).await
    }

    pub async fn current_show_values(
        &self,
        node_id: Uuid,
        subscriber_jid: &str,
    ) -> Result<Option<Vec<String>>> {
        let subscription = self
            .service
            .outbox_get_subscription(node_id, subscriber_jid)
            .await?;
        let now = northstar_time::Utc::now();
        Ok(subscription
            .filter(|subscription| subscription.deliver && subscription.is_active_at(now))
            .map(|subscription| subscription.show_values))
    }

    pub async fn release(&self, ids: &[Uuid]) -> Result<()> {
        self.service.release_pubsub_digests(ids).await
    }

    pub async fn acknowledge(&self, ids: &[Uuid]) -> Result<()> {
        self.service.acknowledge_pubsub_digests(ids).await
    }
}

/// Durable PubSub event delivery and its exact routing and metrics capabilities.
pub struct PubSubEventOutboxWorkerContext<R, N> {
    service: PubSubService<R>,
    notification: N,
    delivery_duration: Arc<DurationHistogram>,
    pending_rows: Arc<AtomicU64>,
    pending_bytes: Arc<AtomicU64>,
    dead_letter_rows: Arc<AtomicU64>,
}

impl<R: PubSubOutboxRepository, N: PubSubDeliveryRoutes> PubSubEventOutboxWorkerContext<R, N> {
    pub fn new(
        service: PubSubService<R>,
        notification: N,
        delivery_duration: Arc<DurationHistogram>,
        pending_rows: Arc<AtomicU64>,
        pending_bytes: Arc<AtomicU64>,
        dead_letter_rows: Arc<AtomicU64>,
    ) -> Self {
        Self {
            service,
            notification,
            delivery_duration,
            pending_rows,
            pending_bytes,
            dead_letter_rows,
        }
    }

    pub fn start_delivery_timer(&self) -> DurationTimer<'_> {
        self.delivery_duration.start_timer()
    }

    pub async fn claim(&self) -> Result<Vec<ClaimedPubSubOutboxDelivery>> {
        self.service.claim_pubsub_outbox(256).await
    }

    pub async fn renew(&self, item: &ClaimedPubSubOutboxDelivery) -> Result<bool> {
        self.service
            .renew_pubsub_outbox_lease(item.delivery_id, item.lease_token)
            .await
    }

    pub async fn acknowledge(&self, item: &ClaimedPubSubOutboxDelivery) -> Result<bool> {
        self.service
            .acknowledge_pubsub_outbox(item.delivery_id, item.lease_token)
            .await
    }

    pub async fn dead_letter_integrity(
        &self,
        item: &ClaimedPubSubOutboxDelivery,
        error: &str,
    ) -> Result<()> {
        self.service
            .dead_letter_pubsub_outbox(
                item.delivery_id,
                item.lease_token,
                "payload-integrity",
                error,
            )
            .await?;
        Ok(())
    }

    pub async fn retry(&self, item: &ClaimedPubSubOutboxDelivery, error: &str) -> Result<()> {
        self.service.retry_pubsub_outbox(item, error).await?;
        Ok(())
    }

    pub async fn maintain(&self) -> Result<()> {
        self.service.expire_pubsub_outbox(1_000).await?;
        self.service.cleanup_pubsub_dead_letters(1_000).await?;
        self.service
            .cleanup_idle_pubsub_event_streams(1_000)
            .await?;
        let snapshot = self.service.pubsub_outbox_snapshot().await?;
        PubSubOutboxTelemetry::new(
            &self.pending_rows,
            &self.pending_bytes,
            &self.dead_letter_rows,
        )
        .publish_snapshot(
            snapshot.pending_rows,
            snapshot.pending_bytes,
            snapshot.dead_letter_rows,
        );
        Ok(())
    }

    pub async fn deliver(&self, item: &ClaimedPubSubOutboxDelivery) -> Result<()> {
        if !item.payload_binding_valid() {
            anyhow::bail!("PubSub outbox payload digest mismatch");
        }
        match item.delivery_kind {
            PubSubOutboxDeliveryKind::PubSubChildren => {
                self.notification
                    .route_children(
                        &item.recipient_jid,
                        &item.payload_xml,
                        item.show_values.as_deref(),
                        item.event_id,
                    )
                    .await
            }
            PubSubOutboxDeliveryKind::PubSubDigest => {
                self.service
                    .enqueue_pubsub_digest_snapshot(
                        item.delivery_id,
                        item.subscription_node_id.ok_or_else(|| {
                            anyhow::anyhow!("digest outbox row lacks subscription node")
                        })?,
                        &item.recipient_jid,
                        &item.payload_xml,
                        item.digest_frequency_ms
                            .ok_or_else(|| anyhow::anyhow!("digest outbox row lacks frequency"))?,
                        item.show_values.as_deref().unwrap_or(&[]),
                    )
                    .await
            }
            PubSubOutboxDeliveryKind::PubSubDirect => {
                self.notification
                    .route_service_message(
                        &self.notification.service_domain(),
                        &item.recipient_jid,
                        item.payload_xml.clone(),
                    )
                    .await
            }
            PubSubOutboxDeliveryKind::PepStanza => {
                match self.service.authorize_pep_outbox_delivery(item).await? {
                    PepOutboxAuthorizationOutcome::Deliver => {}
                    PepOutboxAuthorizationOutcome::Drop(reason) => {
                        tracing::warn!(
                            delivery_id = %item.delivery_id,
                            event_id = %item.event_id,
                            ?reason,
                            "ACK-dropping PEP outbox delivery after live authorization denial"
                        );
                        return Ok(());
                    }
                }
                let Some(subject) = item.pep_subject.as_ref() else {
                    // Authorization already fail-closes and counts every missing
                    // subject before it can return Deliver.
                    tracing::error!(
                        delivery_id = %item.delivery_id,
                        "ACK-dropping PEP outbox delivery without a structured subject"
                    );
                    return Ok(());
                };
                self.notification
                    .route_pep_message(
                        &subject.sender_bare_jid,
                        &item.recipient_jid,
                        item.payload_xml.clone(),
                    )
                    .await
            }
        }
    }
}

pub async fn deliver_due_pubsub_digests<R, N>(
    context: &PubSubDigestWorkerContext<R, N>,
) -> Result<usize>
where
    R: PubSubOutboxRepository,
    N: PubSubDeliveryRoutes,
{
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

pub fn start_pubsub_digest_delivery<R, N>(
    context: Arc<PubSubDigestWorkerContext<R, N>>,
    registry: Arc<northstar_runtime::workers::WorkerRegistry>,
    cancel: tokio_util::sync::CancellationToken,
) where
    R: PubSubOutboxRepository + 'static,
    N: PubSubDeliveryRoutes,
{
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

pub fn start_pubsub_event_outbox_delivery<R, N>(
    context: Arc<PubSubEventOutboxWorkerContext<R, N>>,
    registry: Arc<northstar_runtime::workers::WorkerRegistry>,
    cancel: tokio_util::sync::CancellationToken,
) where
    R: PubSubOutboxRepository + 'static,
    N: PubSubDeliveryRoutes,
{
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

#[allow(clippy::too_many_arguments)]
pub async fn deliver_last_items_on_presence<R>(
    pubsub: &PubSubService<R>,
    service: String,
    outbound: northstar_stream::outbound::OutboundSender,
    recipient_id: uuid::Uuid,
    active_privacy_list: Option<String>,
    connection_id: uuid::Uuid,
    recipient: String,
    show: &'static str,
) -> Result<()>
where
    R: crate::PubSubRepositories + PubSubOutboxRepository,
{
    let requester_bare = northstar_xmpp_types::jid::canonical_bare_key(&recipient)?;
    if pubsub
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
        let page = pubsub
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
            let Some(node) = pubsub.get_node(&subscription.node).await? else {
                continue;
            };
            if node.send_last_published_item != "on_sub_and_presence"
                || !pubsub.can_retrieve_node(&node, &requester_bare).await?
            {
                continue;
            }
            let Some(item) = pubsub.get_items(node.id, &[], 1).await?.into_iter().next() else {
                continue;
            };
            let mut event = XmlElement::new("items").attr("node", &node.node);
            if node.deliver_payloads {
                event.push_validated_fragment(&crate::pubsub::event_item_xml(&item.xml_payload))?;
            } else {
                event.push_child(XmlElement::new("item").attr("id", &item.item_id));
            }
            let event = event.finish();
            let children =
                subscription_event_children(&subscription, &event, None, Some(item.created_at))?;
            if subscription.digest
                && pubsub
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

#[cfg(test)]
mod tests {
    use super::PubSubOutboxTelemetry;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn pubsub_snapshot_clamps_negative_database_counts() {
        let pending_rows = AtomicU64::new(7);
        let pending_bytes = AtomicU64::new(11);
        let dead_letters = AtomicU64::new(13);
        let telemetry = PubSubOutboxTelemetry::new(&pending_rows, &pending_bytes, &dead_letters);

        telemetry.publish_snapshot(-1, i64::MAX, -3);
        assert_eq!(pending_rows.load(Ordering::Relaxed), 0);
        assert_eq!(pending_bytes.load(Ordering::Relaxed), i64::MAX as u64);
        assert_eq!(dead_letters.load(Ordering::Relaxed), 0);
    }
}
