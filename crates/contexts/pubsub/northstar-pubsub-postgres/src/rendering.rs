//! PubSub mutation outbox rendering by the application event renderer.

use anyhow::Result;
use northstar_pubsub_application::service::PubSubEventRenderer;
use northstar_pubsub_core::PubSubNotificationDelivery;
use uuid::Uuid;

impl crate::PubSubMutationOutboxRenderer for PubSubEventRenderer {
    fn render_create(
        &self,
        node: &crate::PubSubNode,
        audience: &[crate::PubSubNotificationDelivery],
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<crate::PubSubOutboxInsert>> {
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
        node: &crate::PubSubNode,
        items: &[(String, String)],
        audience: &[crate::PubSubNotificationDelivery],
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<crate::PubSubOutboxInsert>> {
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
        node: &crate::PubSubNode,
        audience: &[crate::PubSubNotificationDelivery],
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<crate::PubSubOutboxInsert>> {
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
        node: &crate::PubSubNode,
        item_ids: &[String],
        audience: &[crate::PubSubNotificationDelivery],
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<crate::PubSubOutboxInsert>> {
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
        node: &crate::PubSubNode,
        redirect: Option<&str>,
        audience: &[crate::PubSubNotificationDelivery],
        nonactive_recipients: &[String],
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<crate::PubSubOutboxInsert>> {
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
        node: &crate::PubSubNode,
        config: &crate::PubSubNodeConfig,
        audience: &[crate::PubSubNotificationDelivery],
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<crate::PubSubOutboxInsert>> {
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
        source: &crate::PubSubNode,
        action: &str,
        target_node: &str,
        audience: &[crate::PubSubNotificationDelivery],
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<crate::PubSubOutboxInsert>> {
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
        node: &crate::PubSubNode,
        subscription: &crate::PubSubSubscription,
        notify_recipients: &[String],
        authorization_recipients: &[String],
        last_item: Option<&crate::PubSubItem>,
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<crate::PubSubOutboxInsert>> {
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
        node: &crate::PubSubNode,
        jid: &str,
        affiliation: &str,
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<crate::PubSubOutboxInsert>> {
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
