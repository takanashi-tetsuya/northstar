use crate::{
    platform::config::{ComponentConnectionMode, ComponentCredential},
    platform::metrics::{DurationHistogram, DurationTimer},
    s2s,
    state::AppState,
    xmpp::xml_builder::XmlElement,
};
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use dashmap::{mapref::entry::Entry, DashMap};
use rand::{rngs::OsRng, RngCore};
use roxmltree::{Document, Node};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    future::Future,
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{lookup_host, TcpListener, TcpStream},
    sync::{mpsc, OwnedSemaphorePermit},
    task::JoinSet,
    time::Instant,
};
use tokio_rustls::TlsAcceptor;
use uuid::Uuid;
use zeroize::Zeroize;
#[cfg(test)]
use zeroize::Zeroizing;

mod connections;
mod session;
mod wire;

#[cfg(test)]
use self::connections::component_connect_address_allowed;
use self::connections::{component_connection, outbound_component_connection};
use self::session::{cleanup_component_muc, drive_component};
#[cfg(test)]
use self::session::{
    component_lease_renewal_period, invalid_component_stanza, write_component_outbox_with_renewal,
    ComponentOutboxWriteError,
};
#[cfg(test)]
use self::wire::decode_hex_20;
use self::wire::{
    client_to_component, component_frame_stream_error, component_iq_error,
    component_read_error_condition, component_stanza_error, component_stream_attribute,
    component_to_client, is_component_stream_error, is_element, is_empty_element,
    is_inherited_empty_element, modern_plain_shape_is_valid, read_handshake_frame,
    read_handshake_frame_after_open, stream_id, stream_namespace, validate_legacy_connect_opening,
    validate_modern_opening, verified_secret, verify_legacy_handshake, verify_modern_plain,
    write_component_stream_open, write_legacy_connect_open, write_legacy_stream_open,
};

const COMPONENT_ACCEPT_NS: &str = "jabber:component:accept";
const COMPONENT_CONNECT_NS: &str = "jabber:component:connect";
const COMPONENT_BIND_NS: &str = "urn:xmpp:component:0";
const SASL_NS: &str = "urn:ietf:params:xml:ns:xmpp-sasl";
const STREAMS_NS: &str = "http://etherx.jabber.org/streams";
// Claim exactly one durable row at a time. A component socket can spend up to
// the S2S write timeout on every stanza, so pre-claiming a large batch lets the
// leases of later rows expire before their first write begins.
const COMPONENT_OUTBOX_CLAIM_BATCH: i64 = 1;
// Bound one poll/wake turn so an always-busy outbox cannot starve frames sent
// by the component. Claims remain just-in-time within this drain budget.
const COMPONENT_OUTBOX_DRAIN_LIMIT: usize = 32;

/// The five metric cells needed by component transport tasks.
pub(crate) struct ComponentTelemetry<'a> {
    connections_active: &'a AtomicU64,
    delivery_duration: &'a DurationHistogram,
    failures: &'a AtomicU64,
    deliveries: &'a AtomicU64,
    outbox_lease_lost: &'a AtomicU64,
}

impl<'a> ComponentTelemetry<'a> {
    pub(crate) fn new(
        connections_active: &'a AtomicU64,
        delivery_duration: &'a DurationHistogram,
        failures: &'a AtomicU64,
        deliveries: &'a AtomicU64,
        outbox_lease_lost: &'a AtomicU64,
    ) -> Self {
        Self {
            connections_active,
            delivery_duration,
            failures,
            deliveries,
            outbox_lease_lost,
        }
    }

    fn active_connection(&self) -> ActiveComponentConnection<'a> {
        ActiveComponentConnection::new(self.connections_active)
    }

    fn outbox_delivery_timer(&self) -> DurationTimer<'a> {
        self.delivery_duration.start_timer()
    }

    fn connection_failed(&self) {
        self.failures.fetch_add(1, Ordering::Relaxed);
    }

    fn outbox_written(&self) {
        self.deliveries.fetch_add(1, Ordering::Relaxed);
    }

    fn outbox_lease_lost(&self) {
        self.outbox_lease_lost.fetch_add(1, Ordering::Relaxed);
    }
}

struct ActiveComponentConnection<'a>(&'a AtomicU64);

impl<'a> ActiveComponentConnection<'a> {
    fn new(counter: &'a AtomicU64) -> Self {
        counter.fetch_add(1, Ordering::Relaxed);
        Self(counter)
    }
}

impl Drop for ActiveComponentConnection<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

fn same_component_domain(left: &str, right: &str) -> bool {
    matches!(
        (
            crate::jid::prepare_domainpart(left),
            crate::jid::prepare_domainpart(right)
        ),
        (Ok(left), Ok(right)) if left == right
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComponentProtocol {
    Legacy0114Accept,
    Legacy0114Connect,
    Modern0225,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ComponentRelayGrant {
    LocalOnly,
    FederationRelay,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ComponentRouteTarget {
    LocalService,
    ConfiguredComponent,
    Federation,
    Denied,
}

impl ComponentProtocol {
    fn relay_grant(self) -> ComponentRelayGrant {
        match self {
            Self::Legacy0114Connect => ComponentRelayGrant::LocalOnly,
            Self::Legacy0114Accept | Self::Modern0225 => ComponentRelayGrant::FederationRelay,
        }
    }
}

fn component_route_target(
    local_domain: &str,
    target: &str,
    configured_component: bool,
    relay_grant: ComponentRelayGrant,
) -> ComponentRouteTarget {
    if northstar_federation_core::classify_hosted_domain(local_domain, target).is_some() {
        ComponentRouteTarget::LocalService
    } else if configured_component {
        ComponentRouteTarget::ConfiguredComponent
    } else if relay_grant == ComponentRelayGrant::FederationRelay {
        ComponentRouteTarget::Federation
    } else {
        ComponentRouteTarget::Denied
    }
}

#[derive(Clone)]
struct ComponentSession {
    connection_id: Uuid,
    /// Edge-triggered wake-up only. PostgreSQL is the source of truth for
    /// server-to-component delivery; the bounded channel never owns a stanza.
    sender: mpsc::Sender<()>,
}

/// Concurrent ownership index for authenticated external-component domains.
///
/// The backing map stays private so callers cannot bypass the atomic vacant
/// registration and owner-fenced removal rules. Clones share the same index;
/// this is required by the component listeners and the federation router.
#[derive(Clone, Default)]
pub(crate) struct ComponentRegistry {
    sessions: Arc<DashMap<String, ComponentSession>>,
}

impl ComponentRegistry {
    fn new() -> Self {
        Self::default()
    }

    /// Atomically claim a component domain for one authenticated connection.
    fn register_domain(
        &self,
        domain: &str,
        connection_id: Uuid,
        sender: mpsc::Sender<()>,
    ) -> Result<()> {
        match self.sessions.entry(domain.to_owned()) {
            Entry::Vacant(entry) => {
                entry.insert(ComponentSession {
                    connection_id,
                    sender,
                });
                Ok(())
            }
            Entry::Occupied(_) => anyhow::bail!("component hostname is already bound"),
        }
    }

    fn contains_connected_domain(&self, domain: &str) -> bool {
        self.sessions.contains_key(domain)
    }

    /// Wake the currently authenticated owner while retaining the map guard.
    /// Holding the guard through `try_send` preserves the former ownership
    /// snapshot: an owner-fenced unbind cannot replace the session midway
    /// through this decision.
    pub(crate) fn wake_route(
        &self,
        configured_domains: &HashSet<String>,
        target: &str,
    ) -> ComponentRoute {
        let Some(domain) = target_domain(target) else {
            return ComponentRoute::NotConfigured;
        };
        if !configured_domains.contains(&domain) {
            return ComponentRoute::NotConfigured;
        }
        let Some(session) = self.sessions.get(&domain) else {
            return ComponentRoute::Unavailable;
        };
        if session.sender.try_send(()).is_ok() {
            ComponentRoute::Delivered
        } else {
            ComponentRoute::Unavailable
        }
    }

    fn connection_owns_domain(&self, domain: &str, connection_id: Uuid) -> bool {
        self.sessions
            .get(domain)
            .is_some_and(|session| session.connection_id == connection_id)
    }

    /// Remove a domain only if the same authenticated connection still owns
    /// it. A newly registered incarnation can never be removed by stale
    /// cleanup from its predecessor.
    fn remove_domain_if_owner(&self, domain: &str, connection_id: Uuid) -> bool {
        self.sessions
            .remove_if(domain, |_, session| session.connection_id == connection_id)
            .is_some()
    }

    /// Drop every domain owned by a closing multi-domain connection while
    /// preserving domains already transferred to another incarnation.
    fn remove_connection(&self, connection_id: Uuid) {
        self.sessions
            .retain(|_, session| session.connection_id != connection_id);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ComponentRoute {
    NotConfigured,
    Delivered,
    Unavailable,
}

pub(crate) fn registry() -> ComponentRegistry {
    ComponentRegistry::new()
}

pub fn target_domain(jid: &str) -> Option<String> {
    crate::jid::CanonicalJid::parse(jid)
        .ok()
        .map(|jid| jid.domainpart().to_owned())
}

async fn wait_for_component_shutdown(cancel: &tokio_util::sync::CancellationToken) {
    cancel.cancelled().await;
}

pub async fn serve(
    state: Arc<AppState>,
    cancel: tokio_util::sync::CancellationToken,
    listener: Option<TcpListener>,
) -> Result<()> {
    // This task participates in main's listener select. A disabled or empty
    // component configuration is an idle listener state, not a successful
    // listener termination: returning here would make main shut down every
    // otherwise healthy service.
    let policy = state.component_runtime_policy();
    if !policy.enabled || policy.max_connections == 0 || !state.has_component_credentials() {
        // A zero actor budget is an explicit hard-disable: do not bind the
        // inbound listener and do not start any connect-mode supervisor.
        wait_for_component_shutdown(&cancel).await;
        return Ok(());
    }
    let mut supervisors = JoinSet::new();
    for credential in state.component_connect_credentials() {
        for domain in credential.allowed_domains.clone() {
            let state = Arc::clone(&state);
            let cancel = cancel.clone();
            let credential = credential.clone();
            supervisors.spawn(outbound_component_supervisor(
                state, credential, domain, cancel,
            ));
        }
    }
    let accepts_connections = state.accepts_component_connections();
    if !accepts_connections {
        let result = if supervisors.is_empty() {
            wait_for_component_shutdown(&cancel).await;
            Ok(())
        } else {
            tokio::select! {
                _ = cancel.cancelled() => Ok(()),
                joined = supervisors.join_next() => {
                    component_supervisor_completion(joined, cancel.is_cancelled())
                }
            }
        };
        supervisors.abort_all();
        while supervisors.join_next().await.is_some() {}
        return result;
    }

    let listener = listener.context("external component listener was not activated")?;
    let address = listener
        .local_addr()
        .context("could not inspect external component listener")?;
    tracing::info!(%address, "XMPP external component listener ready");
    let result = loop {
        let (stream, peer) = tokio::select! {
            _ = cancel.cancelled() => break Ok(()),
            joined = supervisors.join_next(), if !supervisors.is_empty() => {
                match component_supervisor_completion(joined, cancel.is_cancelled()) {
                    Ok(()) => continue,
                    Err(error) => break Err(error),
                }
            }
            accepted = listener.accept() => accepted?,
        };
        let Ok(connection_permit) = state.try_acquire_component_connection() else {
            state.component_telemetry().connection_failed();
            tracing::debug!(%peer, "rejected component connection at the configured capacity limit");
            continue;
        };
        let state = Arc::clone(&state);
        let actors = state.connection_actors().clone();
        let connection_cancel = actors.shutdown_token().child_token();
        let actor = component_accept_actor(
            stream,
            peer,
            Arc::clone(&state),
            connection_permit,
            connection_cancel,
        );
        let result = actors.try_spawn(
            crate::platform::connection_actors::ConnectionActorKind::ComponentAccept,
            Some(peer.to_string()),
            actor,
        );
        if let Err(error) = result {
            tracing::debug!(%peer, ?error, "rejected component accept actor admission");
        }
    };
    supervisors.abort_all();
    while supervisors.join_next().await.is_some() {}
    result
}

fn component_supervisor_completion(
    joined: Option<std::result::Result<Result<()>, tokio::task::JoinError>>,
    cancelled: bool,
) -> Result<()> {
    if cancelled {
        return Ok(());
    }
    match joined {
        Some(Ok(Ok(()))) => anyhow::bail!("connect-mode component supervisor exited unexpectedly"),
        Some(Ok(Err(error))) => Err(error.context("connect-mode component supervisor failed")),
        Some(Err(error)) => Err(anyhow::Error::from(error)
            .context("connect-mode component supervisor panicked or was cancelled")),
        None => anyhow::bail!("all connect-mode component supervisors exited unexpectedly"),
    }
}

async fn outbound_component_supervisor(
    state: Arc<AppState>,
    credential: ComponentCredential,
    domain: String,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<()> {
    let mut consecutive_failures = 0_u32;
    loop {
        let connection_permit = tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            permit = state.acquire_component_connection() => {
                permit.context("component connection semaphore closed unexpectedly")?
            }
        };
        let actors = state.connection_actors().clone();
        let connection_cancel = actors.shutdown_token().child_token();
        let actor_state = Arc::clone(&state);
        let actor_credential = credential.clone();
        let actor_domain = domain.clone();
        let (result_tx, result_rx) = tokio::sync::oneshot::channel();
        let actor = component_connect_actor(
            actor_state,
            actor_credential,
            actor_domain,
            connection_permit,
            connection_cancel,
            result_tx,
        );
        actors
            .try_spawn(
                crate::platform::connection_actors::ConnectionActorKind::ComponentConnect,
                Some(domain.clone()),
                actor,
            )
            .map_err(|error| anyhow::anyhow!("component actor admission failed: {error}"))?;
        let result = tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            result = result_rx => result.context("component actor exited without a result")?,
        };
        match result {
            Ok(()) => {
                consecutive_failures = 0;
                tracing::info!(%domain, "outbound XEP-0114 component disconnected; reconnecting");
            }
            Err(error) => {
                consecutive_failures = consecutive_failures.saturating_add(1);
                state.component_telemetry().connection_failed();
                tracing::warn!(
                    %domain,
                    attempt = consecutive_failures,
                    ?error,
                    "outbound XEP-0114 component connection failed"
                );
            }
        }
        let exponent = consecutive_failures.clamp(1, 6) - 1;
        let base_millis = 1_000_u64 << exponent;
        let jitter_millis = OsRng.next_u64() % (base_millis / 2 + 1);
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            _ = tokio::time::sleep(Duration::from_millis(base_millis + jitter_millis)) => {}
        }
    }
}

async fn component_accept_actor(
    stream: TcpStream,
    peer: SocketAddr,
    state: Arc<AppState>,
    connection_permit: OwnedSemaphorePermit,
    connection_cancel: tokio_util::sync::CancellationToken,
) {
    if let Err(error) = component_connection(
        stream,
        peer,
        Arc::clone(&state),
        connection_permit,
        connection_cancel,
    )
    .await
    {
        state.component_telemetry().connection_failed();
        tracing::debug!(%peer, ?error, "external component connection closed");
    }
}

async fn component_connect_actor(
    state: Arc<AppState>,
    credential: ComponentCredential,
    domain: String,
    connection_permit: OwnedSemaphorePermit,
    connection_cancel: tokio_util::sync::CancellationToken,
    result_tx: tokio::sync::oneshot::Sender<Result<()>>,
) {
    let result = outbound_component_connection(
        state,
        credential,
        domain,
        connection_permit,
        connection_cancel,
    )
    .await;
    let _ = result_tx.send(result);
}

#[cfg(test)]
mod tests;
