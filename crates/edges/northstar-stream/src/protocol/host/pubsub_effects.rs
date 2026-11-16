use crate::protocol::{ProtocolSession, SessionHost};
use anyhow::Result;
use roxmltree::Node;
use std::sync::Arc;

/// PubSub authorization responses and last-item replay.
pub trait SessionPubSubEffectsHost: Send + Sync + 'static {
    /// True when the message was a PubSub authorization form and needs no further handling. A form dropped
    /// because mutation capacity is exhausted counts as handled.
    fn dispatch_pubsub_authorization_response(
        session: &ProtocolSession<Self>,
        root: Node<'_, '_>,
    ) -> impl std::future::Future<Output = Result<bool>> + Send
    where
        Self: SessionHost;
    /// Replays the last published PubSub items to a resource that became available (XEP-0060
    /// `send_last_published_item=on_sub_and_presence`).
    #[allow(clippy::too_many_arguments)]
    fn replay_pubsub_last_items(
        self: Arc<Self>,
        outbound: crate::outbound::OutboundSender,
        recipient_id: uuid::Uuid,
        active_privacy_list: Option<String>,
        connection_id: uuid::Uuid,
        recipient: String,
        show: &'static str,
    ) -> impl std::future::Future<Output = Result<()>> + Send + 'static;
}
