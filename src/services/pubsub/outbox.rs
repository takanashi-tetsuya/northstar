//! Durable outbox authorization, lifecycle and digest operations, plus transactional notification rendering.

use super::*;

impl<R: PubSubOutboxRepository> PubSubService<R> {
    pub(crate) async fn outbox_get_subscription(
        &self,
        node_id: Uuid,
        jid: &str,
    ) -> Result<Option<PubSubSubscription>> {
        let _database_turn = self.durable_outbox_database_turn().await;

        self.repository.outbox_get_subscription(node_id, jid).await
    }
}

impl<R: PubSubOutboxRepository> PubSubService<R> {
    pub(crate) async fn local_account_blocks_pubsub(
        &self,
        username: &str,
        service: &str,
    ) -> Result<bool> {
        self.repository
            .local_account_blocks_pubsub(username, service)
            .await
    }
    pub(crate) async fn presence_delivery_denied(
        &self,
        recipient_id: Uuid,
        active_privacy_list: Option<&str>,
        connection_id: Uuid,
        service: &str,
    ) -> Result<bool> {
        self.repository
            .presence_delivery_denied(recipient_id, active_privacy_list, connection_id, service)
            .await
    }
    pub(crate) async fn authorize_pep_outbox_delivery(
        &self,
        item: &ClaimedPubSubOutboxDelivery,
    ) -> Result<PepOutboxAuthorizationOutcome> {
        let _database_turn = self.durable_outbox_database_turn().await;

        self.repository.authorize_pep_outbox_delivery(item).await
    }
    pub(crate) async fn claim_pubsub_outbox(
        &self,
        limit: i64,
    ) -> Result<Vec<ClaimedPubSubOutboxDelivery>> {
        let _database_turn = self.durable_outbox_database_turn().await;

        self.repository.claim_pubsub_outbox(limit).await
    }
    pub(crate) async fn acknowledge_pubsub_outbox(
        &self,
        delivery_id: Uuid,
        lease_token: Uuid,
    ) -> Result<bool> {
        let _database_turn = self.durable_outbox_database_turn().await;

        self.repository
            .acknowledge_pubsub_outbox(delivery_id, lease_token)
            .await
    }
    pub(crate) async fn renew_pubsub_outbox_lease(
        &self,
        delivery_id: Uuid,
        lease_token: Uuid,
    ) -> Result<bool> {
        let _database_turn = self.durable_outbox_database_turn().await;

        self.repository
            .renew_pubsub_outbox_lease(delivery_id, lease_token)
            .await
    }
    pub(crate) async fn retry_pubsub_outbox(
        &self,
        item: &ClaimedPubSubOutboxDelivery,
        error: &str,
    ) -> Result<PubSubOutboxFailureDisposition> {
        let _database_turn = self.durable_outbox_database_turn().await;

        self.repository.retry_pubsub_outbox(item, error).await
    }
    pub(crate) async fn dead_letter_pubsub_outbox(
        &self,
        delivery_id: Uuid,
        lease_token: Uuid,
        reason: &str,
        error: &str,
    ) -> Result<PubSubOutboxFailureDisposition> {
        let _database_turn = self.durable_outbox_database_turn().await;

        self.repository
            .dead_letter_pubsub_outbox(delivery_id, lease_token, reason, error)
            .await
    }
    pub(crate) async fn expire_pubsub_outbox(&self, limit: i64) -> Result<u64> {
        let _database_turn = self.durable_outbox_database_turn().await;

        self.repository.expire_pubsub_outbox(limit).await
    }
    pub(crate) async fn cleanup_pubsub_dead_letters(&self, limit: i64) -> Result<u64> {
        let _database_turn = self.durable_outbox_database_turn().await;

        self.repository.cleanup_pubsub_dead_letters(limit).await
    }
    pub(crate) async fn cleanup_idle_pubsub_event_streams(&self, limit: i64) -> Result<u64> {
        let _database_turn = self.durable_outbox_database_turn().await;

        self.repository
            .cleanup_idle_pubsub_event_streams(limit)
            .await
    }
    pub(crate) async fn pubsub_outbox_snapshot(&self) -> Result<PubSubOutboxSnapshot> {
        let _database_turn = self.durable_outbox_database_turn().await;

        self.repository.pubsub_outbox_snapshot().await
    }
    pub(crate) async fn enqueue_pubsub_digest_snapshot(
        &self,
        source_delivery_id: Uuid,
        node_id: Uuid,
        subscriber_jid: &str,
        event_xml: &str,
        frequency_ms: i32,
        show_values: &[String],
    ) -> Result<()> {
        let _database_turn = self.durable_outbox_database_turn().await;

        self.repository
            .enqueue_pubsub_digest_snapshot(
                source_delivery_id,
                node_id,
                subscriber_jid,
                event_xml,
                frequency_ms,
                show_values,
            )
            .await
    }
    pub(crate) async fn enqueue_pubsub_digest(
        &self,
        node_id: Uuid,
        subscriber_jid: &str,
        event_xml: &str,
        frequency_ms: i32,
    ) -> Result<bool> {
        let node_key = node_id.to_string();
        let _permit = self
            .admit_mutation(&[subscriber_jid, &node_key], false)
            .await?;
        self.repository
            .enqueue_pubsub_digest(node_id, subscriber_jid, event_xml, frequency_ms)
            .await
    }
    pub(crate) async fn claim_due_pubsub_digests(
        &self,
        limit: i64,
    ) -> Result<Vec<DuePubSubDigest>> {
        let _database_turn = self.durable_outbox_database_turn().await;

        self.repository.claim_due_pubsub_digests(limit).await
    }
    pub(crate) async fn release_pubsub_digests(&self, ids: &[Uuid]) -> Result<()> {
        let _database_turn = self.durable_outbox_database_turn().await;

        self.repository.release_pubsub_digests(ids).await
    }
    pub(crate) async fn acknowledge_pubsub_digests(&self, ids: &[Uuid]) -> Result<()> {
        let _database_turn = self.durable_outbox_database_turn().await;

        self.repository.acknowledge_pubsub_digests(ids).await
    }
}

pub(super) fn subscription_delivery_kind(
    subscription: &PubSubSubscription,
    subscription_node_id: Uuid,
) -> (PubSubOutboxDeliveryKind, Option<(Uuid, i32)>) {
    if subscription.digest {
        (
            PubSubOutboxDeliveryKind::PubSubDigest,
            Some((subscription_node_id, subscription.digest_frequency)),
        )
    } else {
        (PubSubOutboxDeliveryKind::PubSubChildren, None)
    }
}

impl PubSubEventRenderer {
    pub(crate) fn render_transactional_node_event(
        &self,
        node: &PubSubNode,
        audience: &[PubSubNotificationDelivery],
        direct_recipients: &[String],
        event: &str,
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<PubSubOutboxInsert>> {
        let ordering_key = format!("pubsub:{}", node.id);
        let mut outbox = Vec::with_capacity(audience.len() + direct_recipients.len());
        for delivery in audience {
            let children = subscription_event_children(
                &delivery.subscription,
                event,
                delivery.collection.as_deref(),
                None,
            )?;
            let (kind, digest) =
                subscription_delivery_kind(&delivery.subscription, delivery.subscription_node_id);
            outbox.push(PubSubOutboxInsert::new(
                event_id,
                ordering_key.clone(),
                PubSubOutboxSource::PubSub,
                kind,
                delivery.subscription.jid.clone(),
                children,
                Some(delivery.subscription.show_values.clone()),
                digest,
                &node.node,
                None,
                created_at,
            )?);
        }
        for recipient in direct_recipients {
            let mut wrapper = XmlElement::namespaced("event", NS_PUBSUB_EVENT);
            wrapper.push_validated_fragment(event)?;
            let message = XmlElement::namespaced("message", "jabber:client")
                .attr("type", "headline")
                .attr("id", event_id)
                .attr("from", &self.service_jid)
                .attr("to", recipient)
                .child(wrapper)
                .finish();
            outbox.push(PubSubOutboxInsert::new(
                event_id,
                ordering_key.clone(),
                PubSubOutboxSource::PubSub,
                PubSubOutboxDeliveryKind::PubSubDirect,
                recipient.clone(),
                message,
                None,
                None,
                &node.node,
                None,
                created_at,
            )?);
        }
        Ok(outbox)
    }
}

impl PubSubEventRenderer {
    pub(crate) fn render_create(
        &self,
        node: &PubSubNode,
        audience: &[PubSubNotificationDelivery],
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<PubSubOutboxInsert>> {
        let event = XmlElement::new("create").attr("node", &node.node).finish();
        self.render_transactional_node_event(node, audience, &[], &event, event_id, created_at)
    }

    pub(crate) fn render_items(
        &self,
        node: &PubSubNode,
        items: &[(String, String)],
        audience: &[PubSubNotificationDelivery],
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<PubSubOutboxInsert>> {
        let mut event = XmlElement::new("items").attr("node", &node.node);
        for (item_id, payload) in items {
            if node.deliver_payloads {
                event.push_validated_fragment(payload)?;
            } else {
                event.push_child(XmlElement::new("item").attr("id", item_id));
            }
        }
        self.render_transactional_node_event(
            node,
            audience,
            &[],
            &event.finish(),
            event_id,
            created_at,
        )
    }

    pub(crate) fn render_purge(
        &self,
        node: &PubSubNode,
        audience: &[PubSubNotificationDelivery],
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<PubSubOutboxInsert>> {
        let event = XmlElement::new("purge").attr("node", &node.node).finish();
        self.render_transactional_node_event(node, audience, &[], &event, event_id, created_at)
    }

    pub(crate) fn render_retract(
        &self,
        node: &PubSubNode,
        item_ids: &[String],
        audience: &[PubSubNotificationDelivery],
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<PubSubOutboxInsert>> {
        let mut items = XmlElement::new("items").attr("node", &node.node);
        for item_id in item_ids {
            items.push_child(XmlElement::new("retract").attr("id", item_id));
        }
        self.render_transactional_node_event(
            node,
            audience,
            &[],
            &items.finish(),
            event_id,
            created_at,
        )
    }

    pub(crate) fn render_delete(
        &self,
        node: &PubSubNode,
        redirect: Option<&str>,
        audience: &[PubSubNotificationDelivery],
        nonactive_recipients: &[String],
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<PubSubOutboxInsert>> {
        if !node.notify_delete {
            return Ok(Vec::new());
        }
        let mut delete = XmlElement::new("delete").attr("node", &node.node);
        if let Some(uri) = redirect {
            delete.push_child(XmlElement::new("redirect").attr("uri", uri));
        }
        self.render_transactional_node_event(
            node,
            audience,
            nonactive_recipients,
            &delete.finish(),
            event_id,
            created_at,
        )
    }

    pub(crate) fn render_configuration(
        &self,
        node: &PubSubNode,
        config: &PubSubNodeConfig,
        audience: &[PubSubNotificationDelivery],
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<PubSubOutboxInsert>> {
        let form = pubsub_node_config_form(config, "result");
        let mut event = XmlElement::new("configuration").attr("node", &node.node);
        event.push_validated_fragment(&form)?;
        self.render_transactional_node_event(
            node,
            audience,
            &[],
            &event.finish(),
            event_id,
            created_at,
        )
    }

    pub(crate) fn render_collection_edge(
        &self,
        source: &PubSubNode,
        action: &str,
        target_node: &str,
        audience: &[PubSubNotificationDelivery],
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<PubSubOutboxInsert>> {
        anyhow::ensure!(matches!(action, "associate" | "dissociate"));
        let action = XmlElement::dynamic(action)
            .map_err(|error| anyhow::anyhow!("invalid collection action QName: {error}"))?
            .attr("node", target_node);
        let event = XmlElement::new("collection")
            .attr("node", &source.node)
            .child(action)
            .finish();
        self.render_transactional_node_event(source, audience, &[], &event, event_id, created_at)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn render_subscription_transition(
        &self,
        node: &PubSubNode,
        subscription: &PubSubSubscription,
        notify_recipients: &[String],
        authorization_recipients: &[String],
        last_item: Option<&PubSubItem>,
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<PubSubOutboxInsert>> {
        let transition = XmlElement::new("subscription")
            .attr("node", &node.node)
            .attr("jid", &subscription.jid)
            .attr("subscription", &subscription.state)
            .attr("subid", &subscription.subid)
            .finish();
        let mut outbox = self.render_transactional_node_event(
            node,
            &[],
            notify_recipients,
            &transition,
            event_id,
            created_at,
        )?;

        if !authorization_recipients.is_empty() {
            let authorization_event_id = Uuid::new_v4();
            let form = XmlElement::namespaced("x", NS_DATA)
                .attr("type", "form")
                .child(data_form_field(
                    "FORM_TYPE",
                    Some("hidden"),
                    SUBSCRIBE_AUTH_FORM,
                ))
                .child(data_form_field("pubsub#node", None, &node.node))
                .child(data_form_field(
                    "pubsub#subscriber_jid",
                    None,
                    &subscription.jid,
                ))
                .child(data_form_field("pubsub#subid", None, &subscription.subid))
                .child(data_form_field("pubsub#allow", Some("boolean"), "false"))
                .finish();
            for recipient in authorization_recipients {
                let mut message = XmlElement::namespaced("message", "jabber:client")
                    .attr("id", Uuid::new_v4())
                    .attr("from", &self.service_jid)
                    .attr("to", recipient);
                message.push_validated_fragment(&form)?;
                outbox.push(PubSubOutboxInsert::new(
                    authorization_event_id,
                    format!("pubsub:{}", node.id),
                    PubSubOutboxSource::PubSub,
                    PubSubOutboxDeliveryKind::PubSubDirect,
                    recipient.clone(),
                    message.finish(),
                    None,
                    None,
                    &node.node,
                    None,
                    created_at,
                )?);
            }
        }

        if let Some(item) = last_item {
            let last_item_event_id = Uuid::new_v4();
            let mut event = XmlElement::new("items").attr("node", &node.node);
            if node.deliver_payloads {
                event.push_validated_fragment(&item.xml_payload)?;
            } else {
                event.push_child(XmlElement::new("item").attr("id", &item.item_id));
            }
            let children = subscription_event_children(
                subscription,
                &event.finish(),
                None,
                Some(item.created_at),
            )?;
            let (kind, digest) = subscription_delivery_kind(subscription, node.id);
            outbox.push(PubSubOutboxInsert::new(
                last_item_event_id,
                format!("pubsub:{}", node.id),
                PubSubOutboxSource::PubSub,
                kind,
                subscription.jid.clone(),
                children,
                Some(subscription.show_values.clone()),
                digest,
                &node.node,
                None,
                created_at,
            )?);
        }
        Ok(outbox)
    }

    pub(crate) fn render_affiliation_transition(
        &self,
        node: &PubSubNode,
        jid: &str,
        affiliation: &str,
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<PubSubOutboxInsert>> {
        let event = XmlElement::new("affiliation")
            .attr("node", &node.node)
            .attr("jid", jid)
            .attr("affiliation", affiliation)
            .finish();
        self.render_transactional_node_event(
            node,
            &[],
            &[jid.to_owned()],
            &event,
            event_id,
            created_at,
        )
    }
}

pub(super) fn data_form_field(var: &str, field_type: Option<&str>, value: &str) -> XmlElement {
    let mut field = XmlElement::new("field").attr("var", var);
    if let Some(field_type) = field_type {
        field = field.attr("type", field_type);
    }
    field.child(XmlElement::new("value").text(value.to_owned()))
}
