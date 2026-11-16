use crate::protocol::dispatch::route::ClientIqRoute;
use crate::protocol::{ProtocolSession, SessionHost};
use crate::transport::Action;
use crate::IqRouter;
use anyhow::Result;
use roxmltree::Node;

/// Stanza dispatch and client IQ routes.
pub trait SessionDispatchHost: Send + Sync + 'static {
    /// Handles a client `<message/>` (the message, MUC and MIX contexts).
    fn dispatch_message(
        session: &ProtocolSession<Self>,
        root: Node<'_, '_>,
        raw: &str,
        client_raw: &str,
    ) -> impl std::future::Future<Output = Result<Action>> + Send
    where
        Self: SessionHost;
    /// Hands a groupchat `<message/>` to the room context.
    fn dispatch_muc_message(
        session: &ProtocolSession<Self>,
        root: Node<'_, '_>,
        raw: &str,
    ) -> impl std::future::Future<Output = Result<Action>> + Send
    where
        Self: SessionHost;
    /// Hands a `<message/>` to the MIX context, or `None` when it addresses no MIX channel.
    fn dispatch_mix_message(
        session: &ProtocolSession<Self>,
        root: Node<'_, '_>,
        raw: &str,
    ) -> impl std::future::Future<Output = Result<Option<Action>>> + Send
    where
        Self: SessionHost;
    /// Handles a client `<presence/>` (the roster and room contexts).
    fn dispatch_presence(
        session: &mut ProtocolSession<Self>,
        root: Node<'_, '_>,
        raw: &str,
    ) -> impl std::future::Future<Output = Result<Action>> + Send
    where
        Self: SessionHost;
    /// Answers an IQ addressed to a MIX channel, or `None` when the IQ is not one.
    fn dispatch_mix_iq(
        session: &ProtocolSession<Self>,
        raw: &str,
    ) -> impl std::future::Future<Output = Result<Option<Action>>> + Send
    where
        Self: SessionHost;
    /// The IQ routes the client dispatch hands requests to.
    fn iq_routes() -> &'static IqRouter<ClientIqRoute<Self>>
    where
        Self: SessionHost;
}
