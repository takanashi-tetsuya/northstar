pub(crate) mod dane;
pub mod dialback;
pub mod dns;
pub mod inbound;
pub(crate) mod lab_dnssec;
pub mod outbound;
mod registry;
mod resume;
mod sm;
pub(crate) mod telemetry;
pub mod tls;
pub mod util;

pub(crate) use dialback::*;
pub(crate) use dns::*;
pub use inbound::*;
pub(crate) use outbound::*;
pub(crate) use registry::*;
pub(crate) use tls::*;
pub(crate) use util::*;

use tokio::sync::mpsc;

#[derive(Clone)]
pub(crate) struct OutboundS2sSession {
    sender: mpsc::Sender<FederationEnvelope>,
    authenticated: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl OutboundS2sSession {
    pub(crate) fn new(sender: mpsc::Sender<FederationEnvelope>) -> Self {
        Self {
            sender,
            authenticated: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    pub(crate) fn authenticated_flag(&self) -> std::sync::Arc<std::sync::atomic::AtomicBool> {
        std::sync::Arc::clone(&self.authenticated)
    }

    pub(crate) fn is_authenticated(&self) -> bool {
        self.authenticated
            .load(std::sync::atomic::Ordering::Acquire)
    }
}

#[derive(Clone)]
pub(crate) struct BidiS2sSession {
    connection_id: uuid::Uuid,
    /// The receiving domain named by the authenticated XML stream. Reverse
    /// traffic must be hosted by this domain; TLS/SASL for one stream never
    /// grants a generic relay capability.
    local_domain: String,
    sender: mpsc::Sender<FederationEnvelope>,
    disconnect: tokio_util::sync::CancellationToken,
}

impl BidiS2sSession {
    pub(crate) fn new(
        connection_id: uuid::Uuid,
        local_domain: String,
        sender: mpsc::Sender<FederationEnvelope>,
        disconnect: tokio_util::sync::CancellationToken,
    ) -> Self {
        Self {
            connection_id,
            local_domain,
            sender,
            disconnect,
        }
    }
}

pub use northstar_federation_application::{FederationDeliveryMode, FederationEnvelope};

/// Application service backing the private federation outbox capability.
pub(crate) type FederationRouter = crate::services::federation_outbox::FederationOutboxService<
    crate::db::federation_outbox_repository::PostgresFederationOutboxRepository,
>;

pub const IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

pub(crate) fn bidi_connection_key(local_domain: &str, remote_domain: &str) -> Option<String> {
    let local_domain = crate::jid::prepare_domainpart(local_domain).ok()?;
    let remote_domain = crate::jid::prepare_domainpart(remote_domain).ok()?;
    Some(format!("{local_domain}\0{remote_domain}"))
}

#[cfg(test)]
mod tests {
    use super::{bidi_connection_key, FederationEnvelope};

    #[test]
    fn bidi_routes_are_scoped_to_an_exact_canonical_domain_pair() {
        assert_eq!(
            bidi_connection_key("Conference.Example.", "REMOTE.example"),
            Some("conference.example\0remote.example".to_owned())
        );
        assert_ne!(
            bidi_connection_key("example", "remote.example"),
            bidi_connection_key("conference.example", "remote.example")
        );
        assert!(bidi_connection_key("alice@example", "remote.example").is_none());
    }

    #[tokio::test]
    async fn volatile_envelopes_have_no_outbox_fence_and_ack_only_after_write() {
        let (mut envelope, completion) = FederationEnvelope::volatile(
            "remote.example".to_owned(),
            "<message from='alice@example' to='bob@remote.example'/>".to_owned(),
            tokio::time::Instant::now() + std::time::Duration::from_secs(1),
        );
        assert!(!envelope.is_durable());
        assert!(envelope.outbox_id.is_nil());
        assert!(envelope.lock_token.is_nil());
        envelope.complete_volatile_delivery();
        assert!(completion.await.is_ok());

        let (dropped, completion) = FederationEnvelope::volatile(
            "remote.example".to_owned(),
            "<message from='alice@example' to='bob@remote.example'/>".to_owned(),
            tokio::time::Instant::now() + std::time::Duration::from_secs(1),
        );
        drop(dropped);
        assert!(completion.await.is_err());
    }
}
