use northstar_session_core::LocalCapsEpoch;
use std::sync::Arc;

/// Capability observations, verification state, and effect dispatch.
pub trait SessionCapsHost: crate::caps_effects::CapsEventSource + 'static {
    /// See `ServerNode::caps_by_jid`.
    fn caps_by_jid(&self) -> &northstar_protocol_runtime::caps::CapsResourceIndex;
    /// See `ServerNode::caps_cache`.
    fn federated_caps_gates(&self) -> &northstar_protocol_runtime::caps::FederatedCapsGateIndex;
    fn caps_cache(&self) -> &northstar_protocol_runtime::caps::CapsCacheIndex;
    /// See `ServerNode::caps_effect_dispatcher`.
    fn caps_effect_dispatcher(
        &self,
    ) -> &Arc<northstar_protocol_runtime::caps::CapsEffectDispatcher>;
    /// See `LocalSessionTable::local_caps_epoch_is_current`.
    fn local_caps_epoch_is_current(
        &self,
        full_jid: &str,
        epoch: LocalCapsEpoch,
        expected_gate: Option<&Arc<tokio::sync::Mutex<()>>>,
    ) -> bool;
    /// See `LocalSessionTable::local_caps_observer_connection_is_current`.
    fn local_caps_observer_connection_is_current(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
        expected_gate: &Arc<tokio::sync::Mutex<()>>,
    ) -> bool;
    /// See `ServerNode::pending_caps`.
    fn pending_caps(&self) -> &northstar_protocol_runtime::caps::PendingCapsIndex;
}
