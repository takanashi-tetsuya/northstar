//! Renderers for PubSub mutation outbox deliveries.

use anyhow::Result;
use northstar_time::{DateTime, Utc};
use uuid::Uuid;

use super::{
    PubSubItem, PubSubNode, PubSubNodeConfig, PubSubNotificationDelivery, PubSubSubscription,
};

/// Application-layer XML renderer invoked only after the repository has
/// locked the source node, every ancestor collection and their subscription
/// authority. The returned rows are inserted before the mutation commits.
pub trait PubSubMutationOutboxRenderer: Sync {
    fn render_create(
        &self,
        node: &PubSubNode,
        audience: &[PubSubNotificationDelivery],
        event_id: Uuid,
        created_at: DateTime<Utc>,
    ) -> Result<Vec<super::super::PubSubOutboxInsert>> {
        let _ = (node, audience, event_id, created_at);
        Ok(Vec::new())
    }

    fn render_items(
        &self,
        node: &PubSubNode,
        items: &[(String, String)],
        audience: &[PubSubNotificationDelivery],
        event_id: Uuid,
        created_at: DateTime<Utc>,
    ) -> Result<Vec<super::super::PubSubOutboxInsert>> {
        let _ = (node, items, audience, event_id, created_at);
        Ok(Vec::new())
    }

    fn render_purge(
        &self,
        node: &PubSubNode,
        audience: &[PubSubNotificationDelivery],
        event_id: Uuid,
        created_at: DateTime<Utc>,
    ) -> Result<Vec<super::super::PubSubOutboxInsert>> {
        let _ = (node, audience, event_id, created_at);
        Ok(Vec::new())
    }

    fn render_retract(
        &self,
        node: &PubSubNode,
        item_ids: &[String],
        audience: &[PubSubNotificationDelivery],
        event_id: Uuid,
        created_at: DateTime<Utc>,
    ) -> Result<Vec<super::super::PubSubOutboxInsert>> {
        let _ = (node, item_ids, audience, event_id, created_at);
        Ok(Vec::new())
    }

    fn render_delete(
        &self,
        node: &PubSubNode,
        redirect: Option<&str>,
        audience: &[PubSubNotificationDelivery],
        nonactive_recipients: &[String],
        event_id: Uuid,
        created_at: DateTime<Utc>,
    ) -> Result<Vec<super::super::PubSubOutboxInsert>> {
        let _ = (
            node,
            redirect,
            audience,
            nonactive_recipients,
            event_id,
            created_at,
        );
        Ok(Vec::new())
    }

    fn render_configuration(
        &self,
        node: &PubSubNode,
        config: &PubSubNodeConfig,
        audience: &[PubSubNotificationDelivery],
        event_id: Uuid,
        created_at: DateTime<Utc>,
    ) -> Result<Vec<super::super::PubSubOutboxInsert>> {
        let _ = (node, config, audience, event_id, created_at);
        Ok(Vec::new())
    }

    fn render_collection_edge(
        &self,
        source: &PubSubNode,
        action: &str,
        target_node: &str,
        audience: &[PubSubNotificationDelivery],
        event_id: Uuid,
        created_at: DateTime<Utc>,
    ) -> Result<Vec<super::super::PubSubOutboxInsert>> {
        let _ = (source, action, target_node, audience, event_id, created_at);
        Ok(Vec::new())
    }

    /// Render one authoritative subscription transition. `notify_recipients`
    /// and `authorization_recipients` are derived under the node lock; the
    /// protocol layer never supplies either list. `last_item` is read in the
    /// same transaction after the new subscription state is visible.
    #[allow(clippy::too_many_arguments)]
    fn render_subscription_transition(
        &self,
        node: &PubSubNode,
        subscription: &PubSubSubscription,
        notify_recipients: &[String],
        authorization_recipients: &[String],
        last_item: Option<&PubSubItem>,
        event_id: Uuid,
        created_at: DateTime<Utc>,
    ) -> Result<Vec<super::super::PubSubOutboxInsert>> {
        let _ = (
            node,
            subscription,
            notify_recipients,
            authorization_recipients,
            last_item,
            event_id,
            created_at,
        );
        Ok(Vec::new())
    }

    fn render_affiliation_transition(
        &self,
        node: &PubSubNode,
        jid: &str,
        affiliation: &str,
        event_id: Uuid,
        created_at: DateTime<Utc>,
    ) -> Result<Vec<super::super::PubSubOutboxInsert>> {
        let _ = (node, jid, affiliation, event_id, created_at);
        Ok(Vec::new())
    }
}

#[cfg(any(test, feature = "test-support"))]
pub struct NoopMutationOutboxRenderer;

#[cfg(any(test, feature = "test-support"))]
impl PubSubMutationOutboxRenderer for NoopMutationOutboxRenderer {}

#[cfg(any(test, feature = "test-support"))]
pub(super) struct FixedMutationOutboxRenderer<'a>(
    pub(super) &'a [super::super::PubSubOutboxInsert],
);

#[cfg(any(test, feature = "test-support"))]
impl PubSubMutationOutboxRenderer for FixedMutationOutboxRenderer<'_> {
    fn render_create(
        &self,
        _: &PubSubNode,
        _: &[PubSubNotificationDelivery],
        _: Uuid,
        _: DateTime<Utc>,
    ) -> Result<Vec<super::super::PubSubOutboxInsert>> {
        Ok(self.0.to_vec())
    }

    fn render_items(
        &self,
        _: &PubSubNode,
        _: &[(String, String)],
        _: &[PubSubNotificationDelivery],
        _: Uuid,
        _: DateTime<Utc>,
    ) -> Result<Vec<super::super::PubSubOutboxInsert>> {
        Ok(self.0.to_vec())
    }

    fn render_purge(
        &self,
        _: &PubSubNode,
        _: &[PubSubNotificationDelivery],
        _: Uuid,
        _: DateTime<Utc>,
    ) -> Result<Vec<super::super::PubSubOutboxInsert>> {
        Ok(self.0.to_vec())
    }

    fn render_retract(
        &self,
        _: &PubSubNode,
        _: &[String],
        _: &[PubSubNotificationDelivery],
        _: Uuid,
        _: DateTime<Utc>,
    ) -> Result<Vec<super::super::PubSubOutboxInsert>> {
        Ok(self.0.to_vec())
    }

    fn render_delete(
        &self,
        _: &PubSubNode,
        _: Option<&str>,
        _: &[PubSubNotificationDelivery],
        _: &[String],
        _: Uuid,
        _: DateTime<Utc>,
    ) -> Result<Vec<super::super::PubSubOutboxInsert>> {
        Ok(self.0.to_vec())
    }

    fn render_configuration(
        &self,
        _: &PubSubNode,
        _: &PubSubNodeConfig,
        _: &[PubSubNotificationDelivery],
        _: Uuid,
        _: DateTime<Utc>,
    ) -> Result<Vec<super::super::PubSubOutboxInsert>> {
        Ok(self.0.to_vec())
    }

    fn render_collection_edge(
        &self,
        _: &PubSubNode,
        _: &str,
        _: &str,
        _: &[PubSubNotificationDelivery],
        _: Uuid,
        _: DateTime<Utc>,
    ) -> Result<Vec<super::super::PubSubOutboxInsert>> {
        Ok(self.0.to_vec())
    }

    fn render_subscription_transition(
        &self,
        _: &PubSubNode,
        _: &PubSubSubscription,
        _: &[String],
        _: &[String],
        _: Option<&PubSubItem>,
        _: Uuid,
        _: DateTime<Utc>,
    ) -> Result<Vec<super::super::PubSubOutboxInsert>> {
        Ok(self.0.to_vec())
    }

    fn render_affiliation_transition(
        &self,
        _: &PubSubNode,
        _: &str,
        _: &str,
        _: Uuid,
        _: DateTime<Utc>,
    ) -> Result<Vec<super::super::PubSubOutboxInsert>> {
        Ok(self.0.to_vec())
    }
}
