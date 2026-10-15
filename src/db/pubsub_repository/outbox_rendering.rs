//! PubSub mutation outbox rendering for the event renderer and the PostgreSQL-backed PubSub service.

use super::*;

impl db::PubSubMutationOutboxRenderer for PubSubEventRenderer {
    fn render_create(
        &self,
        node: &db::PubSubNode,
        audience: &[db::PubSubNotificationDelivery],
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<db::PubSubOutboxInsert>> {
        PubSubEventRenderer::render_create(
            self,
            node,
            &audience
                .iter()
                .map(|delivery| PubSubNotificationDelivery {
                    subscription_node_id: delivery.subscription_node_id,
                    subscription: delivery.subscription.clone().into(),
                    collection: delivery.collection.clone(),
                })
                .collect::<Vec<_>>(),
            event_id,
            created_at,
        )
    }
    fn render_items(
        &self,
        node: &db::PubSubNode,
        items: &[(String, String)],
        audience: &[db::PubSubNotificationDelivery],
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<db::PubSubOutboxInsert>> {
        PubSubEventRenderer::render_items(
            self,
            node,
            items,
            &audience
                .iter()
                .map(|delivery| PubSubNotificationDelivery {
                    subscription_node_id: delivery.subscription_node_id,
                    subscription: delivery.subscription.clone().into(),
                    collection: delivery.collection.clone(),
                })
                .collect::<Vec<_>>(),
            event_id,
            created_at,
        )
    }
    fn render_purge(
        &self,
        node: &db::PubSubNode,
        audience: &[db::PubSubNotificationDelivery],
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<db::PubSubOutboxInsert>> {
        PubSubEventRenderer::render_purge(
            self,
            node,
            &audience
                .iter()
                .map(|delivery| PubSubNotificationDelivery {
                    subscription_node_id: delivery.subscription_node_id,
                    subscription: delivery.subscription.clone().into(),
                    collection: delivery.collection.clone(),
                })
                .collect::<Vec<_>>(),
            event_id,
            created_at,
        )
    }
    fn render_retract(
        &self,
        node: &db::PubSubNode,
        item_ids: &[String],
        audience: &[db::PubSubNotificationDelivery],
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<db::PubSubOutboxInsert>> {
        PubSubEventRenderer::render_retract(
            self,
            node,
            item_ids,
            &audience
                .iter()
                .map(|delivery| PubSubNotificationDelivery {
                    subscription_node_id: delivery.subscription_node_id,
                    subscription: delivery.subscription.clone().into(),
                    collection: delivery.collection.clone(),
                })
                .collect::<Vec<_>>(),
            event_id,
            created_at,
        )
    }
    fn render_delete(
        &self,
        node: &db::PubSubNode,
        redirect: Option<&str>,
        audience: &[db::PubSubNotificationDelivery],
        nonactive_recipients: &[String],
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<db::PubSubOutboxInsert>> {
        PubSubEventRenderer::render_delete(
            self,
            node,
            redirect,
            &audience
                .iter()
                .map(|delivery| PubSubNotificationDelivery {
                    subscription_node_id: delivery.subscription_node_id,
                    subscription: delivery.subscription.clone().into(),
                    collection: delivery.collection.clone(),
                })
                .collect::<Vec<_>>(),
            nonactive_recipients,
            event_id,
            created_at,
        )
    }
    fn render_configuration(
        &self,
        node: &db::PubSubNode,
        config: &db::PubSubNodeConfig,
        audience: &[db::PubSubNotificationDelivery],
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<db::PubSubOutboxInsert>> {
        PubSubEventRenderer::render_configuration(
            self,
            node,
            config,
            &audience
                .iter()
                .map(|delivery| PubSubNotificationDelivery {
                    subscription_node_id: delivery.subscription_node_id,
                    subscription: delivery.subscription.clone().into(),
                    collection: delivery.collection.clone(),
                })
                .collect::<Vec<_>>(),
            event_id,
            created_at,
        )
    }
    fn render_collection_edge(
        &self,
        source: &db::PubSubNode,
        action: &str,
        target_node: &str,
        audience: &[db::PubSubNotificationDelivery],
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<db::PubSubOutboxInsert>> {
        PubSubEventRenderer::render_collection_edge(
            self,
            source,
            action,
            target_node,
            &audience
                .iter()
                .map(|delivery| PubSubNotificationDelivery {
                    subscription_node_id: delivery.subscription_node_id,
                    subscription: delivery.subscription.clone().into(),
                    collection: delivery.collection.clone(),
                })
                .collect::<Vec<_>>(),
            event_id,
            created_at,
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn render_subscription_transition(
        &self,
        node: &db::PubSubNode,
        subscription: &db::PubSubSubscription,
        notify_recipients: &[String],
        authorization_recipients: &[String],
        last_item: Option<&db::PubSubItem>,
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<db::PubSubOutboxInsert>> {
        PubSubEventRenderer::render_subscription_transition(
            self,
            node,
            &subscription.clone().into(),
            notify_recipients,
            authorization_recipients,
            last_item.cloned().map(Into::into).as_ref(),
            event_id,
            created_at,
        )
    }
    fn render_affiliation_transition(
        &self,
        node: &db::PubSubNode,
        jid: &str,
        affiliation: &str,
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<db::PubSubOutboxInsert>> {
        PubSubEventRenderer::render_affiliation_transition(
            self,
            node,
            jid,
            affiliation,
            event_id,
            created_at,
        )
    }
}
#[cfg(test)]
impl db::PubSubMutationOutboxRenderer for PubSubService<PostgresPubSubRepository> {
    fn render_create(
        &self,
        node: &db::PubSubNode,
        audience: &[db::PubSubNotificationDelivery],
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<db::PubSubOutboxInsert>> {
        db::PubSubMutationOutboxRenderer::render_create(
            &self.repository_for_tests().renderer,
            node,
            audience,
            event_id,
            created_at,
        )
    }
    fn render_items(
        &self,
        node: &db::PubSubNode,
        items: &[(String, String)],
        audience: &[db::PubSubNotificationDelivery],
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<db::PubSubOutboxInsert>> {
        db::PubSubMutationOutboxRenderer::render_items(
            &self.repository_for_tests().renderer,
            node,
            items,
            audience,
            event_id,
            created_at,
        )
    }
    fn render_purge(
        &self,
        node: &db::PubSubNode,
        audience: &[db::PubSubNotificationDelivery],
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<db::PubSubOutboxInsert>> {
        db::PubSubMutationOutboxRenderer::render_purge(
            &self.repository_for_tests().renderer,
            node,
            audience,
            event_id,
            created_at,
        )
    }
    fn render_retract(
        &self,
        node: &db::PubSubNode,
        item_ids: &[String],
        audience: &[db::PubSubNotificationDelivery],
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<db::PubSubOutboxInsert>> {
        db::PubSubMutationOutboxRenderer::render_retract(
            &self.repository_for_tests().renderer,
            node,
            item_ids,
            audience,
            event_id,
            created_at,
        )
    }
    fn render_delete(
        &self,
        node: &db::PubSubNode,
        redirect: Option<&str>,
        audience: &[db::PubSubNotificationDelivery],
        nonactive_recipients: &[String],
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<db::PubSubOutboxInsert>> {
        db::PubSubMutationOutboxRenderer::render_delete(
            &self.repository_for_tests().renderer,
            node,
            redirect,
            audience,
            nonactive_recipients,
            event_id,
            created_at,
        )
    }
    fn render_configuration(
        &self,
        node: &db::PubSubNode,
        config: &db::PubSubNodeConfig,
        audience: &[db::PubSubNotificationDelivery],
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<db::PubSubOutboxInsert>> {
        db::PubSubMutationOutboxRenderer::render_configuration(
            &self.repository_for_tests().renderer,
            node,
            config,
            audience,
            event_id,
            created_at,
        )
    }
    fn render_collection_edge(
        &self,
        source: &db::PubSubNode,
        action: &str,
        target_node: &str,
        audience: &[db::PubSubNotificationDelivery],
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<db::PubSubOutboxInsert>> {
        db::PubSubMutationOutboxRenderer::render_collection_edge(
            &self.repository_for_tests().renderer,
            source,
            action,
            target_node,
            audience,
            event_id,
            created_at,
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn render_subscription_transition(
        &self,
        node: &db::PubSubNode,
        subscription: &db::PubSubSubscription,
        notify_recipients: &[String],
        authorization_recipients: &[String],
        last_item: Option<&db::PubSubItem>,
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<db::PubSubOutboxInsert>> {
        db::PubSubMutationOutboxRenderer::render_subscription_transition(
            &self.repository_for_tests().renderer,
            node,
            subscription,
            notify_recipients,
            authorization_recipients,
            last_item,
            event_id,
            created_at,
        )
    }
    fn render_affiliation_transition(
        &self,
        node: &db::PubSubNode,
        jid: &str,
        affiliation: &str,
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<db::PubSubOutboxInsert>> {
        db::PubSubMutationOutboxRenderer::render_affiliation_transition(
            &self.repository_for_tests().renderer,
            node,
            jid,
            affiliation,
            event_id,
            created_at,
        )
    }
}
