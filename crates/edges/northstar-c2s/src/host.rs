//! What the native client transports (TCP, direct TLS and WebSocket) need from the node beyond
//! every transport's [`TransportHost`]: the TLS material, the connection metrics and the cadence
//! of the stream management lease watch. A native write also needs the session's
//! [`DirectWritePort`].

use super::direct_delivery::DirectWritePort;
use northstar_stream::host::TransportHost;
use northstar_telemetry::metrics::C2sBackpressureTelemetry;

pub trait C2sHost: TransportHost<Session: DirectWritePort> {
    /// The current client TLS configuration; each connection takes one snapshot of it.
    fn tls_context(&self) -> &northstar_security::tls::TlsContext;

    fn record_c2s_tcp_connection(&self);

    fn record_c2s_websocket_connection(&self);

    /// How long a live stream management session holds its lease.
    fn sm_live_lease_seconds(&self) -> u64;

    fn c2s_backpressure_telemetry(&self) -> C2sBackpressureTelemetry;
}
