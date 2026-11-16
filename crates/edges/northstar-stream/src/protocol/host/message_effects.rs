/// Push notifications, carbon preferences, and federation delivery.
pub trait SessionMessageEffectsHost: Send + Sync + 'static {
    /// The repository behind [`SessionMessageEffectsHost::push_service`].
    type PushStore: northstar_message_application::push::PushRepository + 'static;
    /// See `ServerNode::push_service`.
    fn push_service(&self) -> &northstar_message_application::push::PushService<Self::PushStore>;
    /// A carbon preference is session-local and must be visible to fan-out
    /// before its IQ result is sent to the same connection.
    fn set_local_carbons_for_connection(
        &self,
        key: &str,
        connection_id: uuid::Uuid,
        enabled: bool,
    ) -> bool;
    /// The durable federation outbox and direct route.
    type S2sOutbox: northstar_federation_core::FederationRoute;
    /// See `ServerNode::federation_outbox`.
    fn federation_outbox(&self) -> &Self::S2sOutbox;
}
