//! The values a transport hands a protocol session, or reads back from it: which transport carries the
//! stream, the limits it enforces, the TLS evidence it observed and the session's exit signals.

use tokio_util::sync::CancellationToken;

/// What a protocol session asks its transport to do with one processed frame.
pub enum Action {
    Send(String),
    SendMany(Vec<String>),
    /// Ordered outbound items deferred by CSI. Unlike ordinary protocol
    /// replies these may carry a durable-delivery fence which the transport
    /// must complete only at its negotiated recovery boundary (SM h, BOSH
    /// response ack, or the explicit non-SM socket-write fallback).
    SendManyItems(Vec<crate::outbound::OutboundItem>),
    /// The first frame is the terminal authentication success. Publish the
    /// staged login epoch and already-committed route only after that frame
    /// reaches the transport.
    SendManyThenActivate(crate::auth_publication::AuthReplies),
    /// Send each terminal payload in order and then close the XML stream.
    /// Unlike ordinary outbound stanzas these frames are not added to an SM
    /// resume queue: the operation producing them has already revoked the
    /// authenticated session and resumption must be impossible.
    SendManyAndClose(Vec<String>),
    Resume(crate::resume::ResumePayload),
    StartTls,
    CloseWith(String),
    Close,
    None,
}

/// The transport carrying a client stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientTransport {
    Tcp,
    WebSocket,
    Bosh,
}

/// Limits the owning transport can actually enforce on a native XML stream.
/// HTTP binding leaves this absent because its request and inactivity limits
/// are negotiated independently by XEP-0124.
#[derive(Clone, Copy, Debug)]
pub struct StreamLimits {
    pub max_bytes: usize,
    pub negotiation_idle: std::time::Duration,
    pub authenticated_idle: std::time::Duration,
}

impl StreamLimits {
    pub fn idle_timeout(self, authenticated: bool) -> std::time::Duration {
        if authenticated {
            self.authenticated_idle
        } else {
            self.negotiation_idle
        }
    }
}

/// What a TLS transport observed about its peer when the handshake completed.
pub struct TlsSessionEvidence {
    pub channel_bindings: Option<northstar_auth_core::ChannelBindings>,
    pub client_certificate_identities: Vec<String>,
    pub client_certificate_chain: Vec<tokio_rustls::rustls::pki_types::CertificateDer<'static>>,
    pub generation: u64,
}

/// Read-only transport observation of the two independent session exit
/// signals. The transport owns process shutdown separately; only protocol and
/// application authority may cancel a session or its outbound queue.
#[derive(Clone)]
pub struct SessionTerminationSignals {
    policy_revoke: CancellationToken,
    backpressure: CancellationToken,
}

impl SessionTerminationSignals {
    /// Observes the session's policy revocation and its outbound backpressure disconnect.
    pub fn new(policy_revoke: CancellationToken, backpressure: CancellationToken) -> Self {
        Self {
            policy_revoke,
            backpressure,
        }
    }

    pub async fn revoked(&self) {
        self.policy_revoke.cancelled().await;
    }

    pub async fn backpressured(&self) {
        self.backpressure.cancelled().await;
    }

    pub fn is_revoked(&self) -> bool {
        self.policy_revoke.is_cancelled()
    }

    pub fn is_backpressured(&self) -> bool {
        self.backpressure.is_cancelled()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn termination_signals_keep_revocation_and_backpressure_distinct() {
        let policy_revoke = tokio_util::sync::CancellationToken::new();
        let backpressure = tokio_util::sync::CancellationToken::new();
        let signals = SessionTerminationSignals::new(policy_revoke.clone(), backpressure.clone());
        assert!(!signals.is_revoked());
        assert!(!signals.is_backpressured());

        backpressure.cancel();
        signals.backpressured().await;
        assert!(signals.is_backpressured());
        assert!(!signals.is_revoked());

        policy_revoke.cancel();
        signals.revoked().await;
        assert!(signals.is_revoked());
        assert!(signals.is_backpressured());
    }
}
