//! What a client transport needs from the node that runs it: admission against the connection
//! limits, the connection actors that own each connection's task, and the protocol session it
//! carries. The node implements this once; TCP, direct TLS, WebSocket and BOSH stay generic over
//! it, so they never name the node's state.

use crate::outbound::OutboundSender;
use crate::session::StreamSession;
use crate::transport::{ClientTransport, StreamLimits};
use northstar_runtime::connection_actors::ConnectionActorRegistry;
use std::{net::IpAddr, sync::Arc};

pub trait TransportHost: Send + Sync + 'static {
    /// The protocol session a transport carries. Its futures borrow it across awaits, so a
    /// connection task can only be spawned when it is `Sync` as well.
    type Session: StreamSession + Sync + 'static;

    /// Holds one admitted client connection against the node's limits until it is dropped.
    type ConnectionGuard: Send + 'static;

    /// The served domain.
    fn local_domain(&self) -> &str;

    /// Admits a client connection from `ip`, or refuses it at the configured capacity.
    fn acquire_client_connection(self: &Arc<Self>, ip: IpAddr) -> Option<Self::ConnectionGuard>;

    /// The registry that owns and drains connection tasks.
    fn connection_actors(&self) -> &ConnectionActorRegistry;

    /// Opens the protocol session for a new connection. `secure_transport` is true when the
    /// transport is already protected below the stream, as a WebSocket behind HTTPS is.
    fn open_session(
        self: Arc<Self>,
        outbound: OutboundSender,
        secure_transport: bool,
        transport: ClientTransport,
        stream_limits: Option<StreamLimits>,
        peer_ip: IpAddr,
    ) -> Self::Session;
}
