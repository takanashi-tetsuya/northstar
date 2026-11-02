//! The node's capabilities as the client transports see them.

use super::admission_guards::ClientConnectionGuard;
use super::AppState;
use crate::xmpp::protocol::ProtocolSession;
use northstar_c2s::host::C2sHost;
use northstar_runtime::connection_actors::ConnectionActorRegistry;
use northstar_stream::host::TransportHost;
use northstar_stream::outbound::OutboundSender;
use northstar_stream::transport::{ClientTransport, StreamLimits};
use northstar_telemetry::metrics::C2sBackpressureTelemetry;
use std::{net::IpAddr, sync::Arc};

impl TransportHost for AppState {
    type Session = ProtocolSession;
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
    ) -> ProtocolSession {
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
