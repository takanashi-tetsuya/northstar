pub(crate) mod dane;
pub mod dialback;
pub mod dns;
pub mod inbound;
pub mod outbound;
mod registry;
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
}

impl BidiS2sSession {
    pub(crate) fn new(
        connection_id: uuid::Uuid,
        local_domain: String,
        sender: mpsc::Sender<FederationEnvelope>,
    ) -> Self {
        Self {
            connection_id,
            local_domain,
            sender,
        }
    }
}

pub use northstar_federation_application::{FederationDeliveryMode, FederationEnvelope};

#[derive(Clone)]
pub struct FederationRouter {
    pool: sqlx::PgPool,
    wake: mpsc::Sender<()>,
    ttl_seconds: u64,
    max_rows: i64,
    max_bytes: i64,
    max_per_domain: i64,
    components: crate::components::ComponentRegistry,
    component_domains: std::sync::Arc<std::collections::HashSet<String>>,
}

impl FederationRouter {
    pub fn channel(
        pool: sqlx::PgPool,
        config: &crate::config::Config,
        components: crate::components::ComponentRegistry,
    ) -> (Self, mpsc::Receiver<()>) {
        // This channel is only an edge-triggered wake-up. PostgreSQL is the
        // source of truth, so dropping/coalescing a wake-up never loses data.
        let (wake, rx) = mpsc::channel(1);
        (
            Self {
                pool,
                wake,
                ttl_seconds: config.s2s_outbox_ttl_seconds,
                max_rows: config.s2s_outbox_max_rows,
                max_bytes: config.s2s_outbox_max_bytes,
                max_per_domain: config.s2s_outbox_max_per_domain,
                components,
                component_domains: std::sync::Arc::new(
                    config
                        .components
                        .iter()
                        .flat_map(|credential| credential.allowed_domains.iter().cloned())
                        .collect(),
                ),
            },
            rx,
        )
    }

    pub async fn send(
        &self,
        target_domain: &str,
        stanza: String,
        bounce_to: Option<String>,
    ) -> bool {
        match crate::db::enqueue_s2s_outbox(
            &self.pool,
            target_domain,
            &stanza,
            bounce_to.as_deref(),
            self.ttl_seconds,
            self.max_rows,
            self.max_bytes,
            self.max_per_domain,
        )
        .await
        {
            Ok(_) => {
                // Component delivery is durable too.  A connected component
                // only receives an edge-triggered wake-up and then claims its
                // own domain's rows from PostgreSQL.  This lets the node that
                // owns the socket perform delivery without another cluster
                // node leasing the row first.
                let component = self
                    .components
                    .wake_route(&self.component_domains, target_domain);
                if component == crate::components::ComponentRoute::NotConfigured {
                    let _ = self.wake.try_send(());
                }
                true
            }
            Err(error) => {
                tracing::warn!(%target_domain, ?error, "federation stanza was not persisted");
                false
            }
        }
    }

    /// Policy used by protocol operations which combine their own durable
    /// state transition with federation admission in one PostgreSQL
    /// transaction.
    pub(crate) fn outbox_policy(&self) -> crate::db::S2sOutboxPolicy {
        crate::db::S2sOutboxPolicy {
            ttl_seconds: self.ttl_seconds,
            max_rows: self.max_rows,
            max_bytes: self.max_bytes,
            max_per_domain: self.max_per_domain,
        }
    }

    /// Wake the best-effort dispatcher after a caller-owned transaction has
    /// committed an outbox row. PostgreSQL remains the source of truth, so a
    /// coalesced wake-up is harmless and the periodic poll still recovers it.
    pub(crate) fn wake_outbox(&self) {
        let _ = self.wake.try_send(());
    }
}

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
