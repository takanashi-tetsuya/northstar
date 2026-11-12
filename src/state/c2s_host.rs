//! The node's capabilities as the client transports see them.

use super::admission_guards::ClientConnectionGuard;
use super::AppState;
use crate::xmpp::protocol::ClientSession;
use crate::xmpp::protocol::ProtocolSession;
use axum::http::HeaderMap;
use northstar_c2s::host::C2sHost;
use northstar_c2s::websocket_upgrade::WebSocketHost;
use northstar_runtime::connection_actors::ConnectionActorRegistry;
use northstar_stream::host::TransportHost;
use northstar_stream::outbound::OutboundSender;
use northstar_stream::transport::{ClientTransport, StreamLimits};
use northstar_telemetry::metrics::C2sBackpressureTelemetry;
use std::{net::IpAddr, sync::Arc};

impl TransportHost for AppState {
    type Session = ClientSession;
    type ConnectionGuard = ClientConnectionGuard;

    fn local_domain(&self) -> &str {
        AppState::local_domain(self)
    }

    fn acquire_client_connection(self: &Arc<Self>, ip: IpAddr) -> Option<ClientConnectionGuard> {
        AppState::acquire_client_connection(self, ip)
    }

    fn connection_actors(&self) -> &ConnectionActorRegistry {
        AppState::connection_actors(self)
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

impl C2sHost for AppState {
    fn tls_context(&self) -> &northstar_security::tls::TlsContext {
        AppState::tls_context(self)
    }

    fn record_c2s_tcp_connection(&self) {
        AppState::record_c2s_tcp_connection(self);
    }

    fn record_c2s_websocket_connection(&self) {
        AppState::record_c2s_websocket_connection(self);
    }

    fn sm_live_lease_seconds(&self) -> u64 {
        self.sm_session_policy().live_lease_seconds
    }

    fn c2s_backpressure_telemetry(&self) -> C2sBackpressureTelemetry {
        AppState::c2s_backpressure_telemetry(self)
    }
}

impl WebSocketHost for AppState {
    fn public_url(&self) -> &str {
        &self.public_discovery_context().policy().public_url
    }

    fn trusted_proxy_ips(&self) -> &[IpAddr] {
        &self.public_discovery_context().policy().trusted_proxy_ips
    }

    fn websocket_allowed_origins(&self) -> &[String] {
        &self
            .public_discovery_context()
            .policy()
            .websocket_allowed_origins
    }

    fn client_ip(&self, peer_ip: IpAddr, headers: &HeaderMap) -> IpAddr {
        northstar_http::client_ip(peer_ip, headers, &self.http_transport_policy())
    }
}
