//! The node's capabilities as the client transports see them.

use crate::node::{ClientSession, ServerNode};
use axum::http::HeaderMap;
use northstar_c2s::host::C2sHost;
use northstar_c2s::websocket_upgrade::WebSocketHost;
use northstar_runtime::connection_actors::ConnectionActorRegistry;
use northstar_stream::host::TransportHost;
use northstar_stream::outbound::OutboundSender;
use northstar_stream::protocol::ProtocolSession;
use northstar_stream::transport::{ClientTransport, StreamLimits};
use northstar_telemetry::metrics::C2sBackpressureTelemetry;
use std::{net::IpAddr, sync::Arc};

impl TransportHost for ServerNode {
    type Session = ClientSession;
    type ConnectionGuard = northstar_stream::client_admission::ClientConnectionGuard;

    fn local_domain(&self) -> &str {
        &self.config.domain
    }

    fn acquire_client_connection(self: &Arc<Self>, ip: IpAddr) -> Option<Self::ConnectionGuard> {
        self.session.live().client_admission().acquire(ip)
    }

    fn connection_actors(&self) -> &ConnectionActorRegistry {
        ServerNode::connection_actors(self)
    }

    fn open_session(
        self: Arc<Self>,
        outbound: OutboundSender,
        secure_transport: bool,
        transport: ClientTransport,
        stream_limits: Option<StreamLimits>,
        peer_ip: IpAddr,
    ) -> ClientSession {
        ProtocolSession::new(
            self,
            outbound,
            secure_transport,
            transport,
            stream_limits,
            peer_ip,
        )
    }
}

impl ServerNode {
    pub(crate) fn connection_actors(
        &self,
    ) -> &northstar_runtime::connection_actors::ConnectionActorRegistry {
        self.session.live().connection_actors()
    }
}

impl C2sHost for ServerNode {
    fn tls_context(&self) -> &northstar_security::tls::TlsContext {
        &self.tls_context
    }

    fn record_c2s_tcp_connection(&self) {
        self.metrics.record_c2s_tcp_connection();
    }

    fn record_c2s_websocket_connection(&self) {
        self.metrics.record_c2s_websocket_connection();
    }

    fn sm_live_lease_seconds(&self) -> u64 {
        self.config.sm_live_lease_seconds
    }

    fn c2s_backpressure_telemetry(&self) -> C2sBackpressureTelemetry {
        self.metrics.c2s_backpressure_telemetry()
    }
}

impl WebSocketHost for ServerNode {
    fn public_url(&self) -> &str {
        &self.public_discovery_context.policy().public_url
    }

    fn trusted_proxy_ips(&self) -> &[IpAddr] {
        &self.public_discovery_context.policy().trusted_proxy_ips
    }

    fn websocket_allowed_origins(&self) -> &[String] {
        &self
            .public_discovery_context
            .policy()
            .websocket_allowed_origins
    }

    fn client_ip(&self, peer_ip: IpAddr, headers: &HeaderMap) -> IpAddr {
        northstar_http::client_ip(peer_ip, headers, &self.http_transport_policy())
    }
}
