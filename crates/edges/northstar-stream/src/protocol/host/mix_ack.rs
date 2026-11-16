/// The MIX service used by protocol sessions.
pub trait SessionMixAckHost: Send + Sync + 'static {
    /// The repository behind [`SessionMixAckHost::mix_service`].
    type MixStore: northstar_room_application::mix_service::MixRepository + 'static;
    /// See `ServerNode::mix_service`.
    fn mix_service(&self) -> &northstar_room_application::mix_service::MixService<Self::MixStore>;
}
