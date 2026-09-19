use crate::{
    config::{ComponentConnectionMode, ComponentCredential},
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
    if !state.config.components_enabled
        || state.config.max_component_connections == 0
        || !state.has_component_credentials()
    {
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
            state
                .metrics
                .component_failures_total
                .fetch_add(1, Ordering::Relaxed);
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
            crate::connection_actors::ConnectionActorKind::ComponentAccept,
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
                crate::connection_actors::ConnectionActorKind::ComponentConnect,
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
                state
                    .metrics
                    .component_failures_total
                    .fetch_add(1, Ordering::Relaxed);
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
        state
            .metrics
            .component_failures_total
            .fetch_add(1, Ordering::Relaxed);
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

async fn outbound_component_connection(
    state: Arc<AppState>,
    credential: ComponentCredential,
    domain: String,
    _permit: OwnedSemaphorePermit,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<()> {
    anyhow::ensure!(
        credential.connection == ComponentConnectionMode::Connect && credential.legacy_0114,
        "invalid outbound component profile"
    );
    let handshake_timeout = Duration::from_secs(state.config.component_handshake_timeout_seconds);
    let mut stream = connect_component_endpoint(Arc::clone(&state), credential.clone()).await?;
    stream.set_nodelay(true)?;
    write_legacy_connect_open(&mut stream, &domain).await?;
    let mut input = s2s::S2sInputState::default();
    let opening = read_handshake_frame(handshake_timeout, &mut stream, &mut input).await?;
    let receiving_stream_id = validate_legacy_connect_opening(&opening, &domain)?;
    let secret = verified_secret(&credential)?;
    let mut digest = Sha1::new();
    digest.update(receiving_stream_id.as_bytes());
    digest.update(secret.as_bytes());
    let proof = digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    s2s::write_xml(
        &mut stream,
        &crate::xmpp::xml_builder::XmlElement::new("handshake")
            .attr("xmlns", COMPONENT_CONNECT_NS)
            .text(proof)
            .finish(),
    )
    .await?;
    let acknowledgement = read_handshake_frame(handshake_timeout, &mut stream, &mut input).await?;
    if !is_inherited_empty_element(&acknowledgement, "handshake", COMPONENT_CONNECT_NS) {
        anyhow::bail!("outbound XEP-0114 component rejected the handshake");
    }

    let connection_id = Uuid::new_v4();
    let (sender, receiver) = mpsc::channel(state.config.component_queue_capacity);
    state
        .component_registry()
        .register_domain(&domain, connection_id, sender.clone())?;
    tracing::info!(%domain, "outbound XEP-0114 component authenticated");
    let _active_connection =
        ActiveComponentConnection::new(&state.metrics.component_connections_active);
    let result = drive_component(
        stream,
        Arc::clone(&state),
        credential.clone(),
        connection_id,
        ComponentProtocol::Legacy0114Connect,
        sender,
        HashSet::from([domain.clone()]),
        receiver,
        input,
        cancel,
    )
    .await;
    state.component_registry().remove_connection(connection_id);
    crate::xmpp::protocol::caps::federated_caps_connection_closed(&state, connection_id).await;
    cleanup_component_muc(
        Arc::clone(&state),
        credential.allowed_domains.clone(),
        connection_id,
    )
    .await;
    result
}

async fn connect_component_endpoint(
    state: Arc<AppState>,
    credential: ComponentCredential,
) -> Result<TcpStream> {
    let endpoint = credential
        .connect_endpoint
        .as_ref()
        .context("connect-mode component omitted its endpoint")?;
    let dns_host = match endpoint.host.parse::<IpAddr>() {
        Ok(address) => address.to_string(),
        Err(_) => crate::jid::domain_to_ascii(&endpoint.host)
            .context("component endpoint cannot be represented as a DNS host")?,
    };
    let deadline =
        Instant::now() + Duration::from_secs(state.config.component_handshake_timeout_seconds);
    let resolved =
        tokio::time::timeout_at(deadline, lookup_host((dns_host.as_str(), endpoint.port)))
            .await
            .context("component endpoint DNS resolution timed out")?
            .context("component endpoint DNS resolution failed")?;
    let mut addresses = Vec::new();
    for address in resolved.take(32) {
        if !component_connect_address_allowed(address.ip(), credential.allow_public_connect) {
            continue;
        }
        if !addresses.contains(&address) {
            addresses.push(address);
        }
    }
    anyhow::ensure!(
        !addresses.is_empty(),
        "component endpoint resolved only to addresses forbidden by its SSRF policy"
    );
    let mut last_error = None;
    for address in addresses {
        match tokio::time::timeout_at(deadline, TcpStream::connect(address)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(error)) => last_error = Some(anyhow::Error::from(error)),
            Err(error) => last_error = Some(anyhow::Error::from(error)),
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("component endpoint was unreachable")))
}

fn component_connect_address_allowed(address: IpAddr, allow_public: bool) -> bool {
    let safe_destination = match address {
        IpAddr::V4(address) => {
            !address.is_unspecified()
                && !address.is_multicast()
                && !address.is_broadcast()
                && !address.is_link_local()
        }
        IpAddr::V6(address) => {
            !address.is_unspecified() && !address.is_multicast() && !address.is_unicast_link_local()
        }
    };
    if !safe_destination {
        return false;
    }
    if allow_public {
        return true;
    }
    match address {
        IpAddr::V4(address) => address.is_loopback() || address.is_private(),
        IpAddr::V6(address) => address.is_loopback() || (address.segments()[0] & 0xfe00) == 0xfc00,
    }
}

async fn component_connection(
    mut stream: TcpStream,
    peer: SocketAddr,
    state: Arc<AppState>,
    _permit: OwnedSemaphorePermit,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<()> {
    stream.set_nodelay(true)?;
    let handshake_timeout = Duration::from_secs(state.config.component_handshake_timeout_seconds);
    let mut input = s2s::S2sInputState::default();
    let opening = match read_handshake_frame(handshake_timeout, &mut stream, &mut input).await {
        Ok(opening) => opening,
        Err(error) => {
            if let Some(condition) = component_read_error_condition(&error) {
                write_legacy_stream_open(&mut stream, &state.config.domain, &stream_id()).await?;
                s2s::send_stream_error(&mut stream, condition).await?;
            }
            return Err(error);
        }
    };
    let namespace = match stream_namespace(&opening) {
        Ok(namespace) => namespace,
        Err(condition) => {
            write_legacy_stream_open(&mut stream, &state.config.domain, &stream_id()).await?;
            s2s::send_stream_error(&mut stream, condition).await?;
            anyhow::bail!("component sent an invalid initial stream: {condition}");
        }
    };
    if namespace == COMPONENT_ACCEPT_NS {
        return legacy_connection(stream, state, opening, input, cancel).await;
    }
    if namespace == "jabber:client" {
        return modern_connection(stream, state, opening, input, cancel).await;
    }
    write_legacy_stream_open(&mut stream, &state.config.domain, &stream_id()).await?;
    s2s::send_stream_error(&mut stream, "invalid-namespace").await?;
    anyhow::bail!("component used an unsupported stream namespace from {peer}")
}

async fn legacy_connection(
    mut stream: TcpStream,
    state: Arc<AppState>,
    opening: String,
    mut input: s2s::S2sInputState,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<()> {
    let handshake_timeout = Duration::from_secs(state.config.component_handshake_timeout_seconds);
    let component_domain =
        match component_stream_attribute(&opening, "to", COMPONENT_ACCEPT_NS, false)
            .and_then(|domain| crate::jid::prepare_domainpart(&domain).ok())
        {
            Some(domain) => domain,
            None => {
                write_legacy_stream_open(&mut stream, &state.config.domain, &stream_id()).await?;
                s2s::send_stream_error(&mut stream, "improper-addressing").await?;
                anyhow::bail!("XEP-0114 component stream omitted a valid domain-only to address");
            }
        };
    let credential = state
        .component_authentication_credential(&component_domain)
        .filter(|credential| {
            credential.connection == ComponentConnectionMode::Accept && credential.legacy_0114
        });
    let Some(credential) = credential else {
        write_legacy_stream_open(&mut stream, &component_domain, &stream_id()).await?;
        s2s::send_stream_error(&mut stream, "host-unknown").await?;
        anyhow::bail!("unknown or disabled XEP-0114 component domain");
    };
    if state
        .component_registry()
        .contains_connected_domain(&component_domain)
    {
        write_legacy_stream_open(&mut stream, &component_domain, &stream_id()).await?;
        s2s::send_stream_error(&mut stream, "conflict").await?;
        anyhow::bail!("component domain is already connected");
    }

    let receiving_stream_id = stream_id();
    write_legacy_stream_open(&mut stream, &component_domain, &receiving_stream_id).await?;
    let handshake =
        read_handshake_frame_after_open(handshake_timeout, &mut stream, &mut input).await?;
    if Document::parse(&handshake).is_err() {
        s2s::send_stream_error(&mut stream, "not-well-formed").await?;
        anyhow::bail!("XEP-0114 component sent malformed handshake XML");
    }
    let verified = match verify_legacy_handshake(&credential, &receiving_stream_id, &handshake) {
        Ok(verified) => verified,
        Err(error) => {
            tracing::error!(domain = %component_domain, ?error, "could not read XEP-0114 component credential");
            s2s::send_stream_error(&mut stream, "internal-server-error").await?;
            return Err(error);
        }
    };
    if !verified {
        s2s::send_stream_error(&mut stream, "not-authorized").await?;
        anyhow::bail!("XEP-0114 component authentication failed");
    }

    let connection_id = Uuid::new_v4();
    let (sender, receiver) = mpsc::channel(state.config.component_queue_capacity);
    if state
        .component_registry()
        .register_domain(&component_domain, connection_id, sender.clone())
        .is_err()
    {
        s2s::send_stream_error(&mut stream, "conflict").await?;
        anyhow::bail!("component domain became occupied during authentication");
    }
    if let Err(error) = s2s::write_xml(&mut stream, &XmlElement::new("handshake").finish()).await {
        state.component_registry().remove_connection(connection_id);
        return Err(error);
    }
    tracing::info!(domain = %component_domain, "XEP-0114 external component authenticated");
    let _active_connection =
        ActiveComponentConnection::new(&state.metrics.component_connections_active);
    let mut bound = HashSet::new();
    bound.insert(component_domain);
    let result = drive_component(
        stream,
        Arc::clone(&state),
        credential.clone(),
        connection_id,
        ComponentProtocol::Legacy0114Accept,
        sender,
        bound,
        receiver,
        input,
        cancel,
    )
    .await;
    state.component_registry().remove_connection(connection_id);
    crate::xmpp::protocol::caps::federated_caps_connection_closed(&state, connection_id).await;
    cleanup_component_muc(
        Arc::clone(&state),
        credential.allowed_domains.clone(),
        connection_id,
    )
    .await;
    result
}

async fn modern_connection(
    mut stream: TcpStream,
    state: Arc<AppState>,
    opening: String,
    mut input: s2s::S2sInputState,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<()> {
    let handshake_timeout = Duration::from_secs(state.config.component_handshake_timeout_seconds);
    if component_stream_attribute(&opening, "version", "jabber:client", false).as_deref()
        != Some("1.0")
    {
        write_component_stream_open(&mut stream, &state.config.domain, "", &stream_id()).await?;
        s2s::send_stream_error(&mut stream, "unsupported-version").await?;
        anyhow::bail!("XEP-0225 component did not open a version 1.0 stream");
    }
    let asserted_domain = match component_stream_attribute(&opening, "from", "jabber:client", true)
        .and_then(|domain| crate::jid::prepare_domainpart(&domain).ok())
    {
        Some(domain) => domain,
        None => {
            write_component_stream_open(&mut stream, &state.config.domain, "", &stream_id())
                .await?;
            s2s::send_stream_error(&mut stream, "invalid-from").await?;
            anyhow::bail!("XEP-0225 component stream omitted a valid domain-only from address");
        }
    };
    let target = match component_stream_attribute(&opening, "to", "jabber:client", true)
        .and_then(|domain| crate::jid::prepare_domainpart(&domain).ok())
    {
        Some(domain) => domain,
        None => {
            write_component_stream_open(
                &mut stream,
                &state.config.domain,
                &asserted_domain,
                &stream_id(),
            )
            .await?;
            s2s::send_stream_error(&mut stream, "improper-addressing").await?;
            anyhow::bail!("XEP-0225 component stream omitted a valid domain-only to address");
        }
    };
    let credential = state
        .component_authentication_credential(&asserted_domain)
        .filter(|credential| {
            same_component_domain(&credential.primary_domain, &asserted_domain)
                && credential.connection == ComponentConnectionMode::Accept
                && credential.modern_0225
        });
    if !same_component_domain(&target, &state.config.domain) || credential.is_none() {
        write_component_stream_open(
            &mut stream,
            &state.config.domain,
            &asserted_domain,
            &stream_id(),
        )
        .await?;
        s2s::send_stream_error(&mut stream, "host-unknown").await?;
        anyhow::bail!("unknown or disabled XEP-0225 component identity");
    }
    let credential = credential.expect("checked above");

    write_component_stream_open(
        &mut stream,
        &state.config.domain,
        &asserted_domain,
        &stream_id(),
    )
    .await?;
    s2s::write_xml(
        &mut stream,
        &XmlElement::new("stream:features")
            .child(
                XmlElement::namespaced("starttls", "urn:ietf:params:xml:ns:xmpp-tls")
                    .child(XmlElement::new("required")),
            )
            .finish(),
    )
    .await?;
    let starttls =
        read_handshake_frame_after_open(handshake_timeout, &mut stream, &mut input).await?;
    if !is_empty_element(&starttls, "starttls", "urn:ietf:params:xml:ns:xmpp-tls") {
        s2s::send_stream_error(&mut stream, "policy-violation").await?;
        anyhow::bail!("XEP-0225 component did not negotiate mandatory STARTTLS");
    }
    s2s::write_xml(
        &mut stream,
        &XmlElement::namespaced("proceed", "urn:ietf:params:xml:ns:xmpp-tls").finish(),
    )
    .await?;
    let material = state.tls.current();
    let acceptor = TlsAcceptor::from(material.c2s_starttls.clone());
    let mut secure = tokio::time::timeout(
        Duration::from_secs(state.config.component_handshake_timeout_seconds),
        acceptor.accept(stream),
    )
    .await
    .context("component TLS handshake timed out")?
    .context("component TLS handshake failed")?;
    input.reset_entity();

    let opening =
        read_handshake_frame_after_open(handshake_timeout, &mut secure, &mut input).await?;
    if let Err(condition) = validate_modern_opening(&state, &credential, &opening) {
        s2s::send_stream_error(&mut secure, condition).await?;
        anyhow::bail!("component stream identity changed during XEP-0225 negotiation: {condition}");
    }
    write_component_stream_open(
        &mut secure,
        &state.config.domain,
        &credential.primary_domain,
        &stream_id(),
    )
    .await?;
    s2s::write_xml(
        &mut secure,
        &XmlElement::new("stream:features")
            .child(
                XmlElement::namespaced("mechanisms", "urn:ietf:params:xml:ns:xmpp-sasl")
                    .child(XmlElement::new("mechanism").text("PLAIN")),
            )
            .finish(),
    )
    .await?;
    let mut authenticated = false;
    for _ in 0..3 {
        let authentication =
            read_handshake_frame_after_open(handshake_timeout, &mut secure, &mut input).await?;
        let failure = if is_empty_element(&authentication, "abort", SASL_NS) {
            Some("aborted")
        } else if !is_element(&authentication, "auth", SASL_NS) {
            Some("malformed-request")
        } else if Document::parse(&authentication)
            .ok()
            .and_then(|document| {
                document
                    .root_element()
                    .attribute("mechanism")
                    .map(str::to_owned)
            })
            .as_deref()
            != Some("PLAIN")
        {
            Some("invalid-mechanism")
        } else if !modern_plain_shape_is_valid(&authentication) {
            Some("malformed-request")
        } else {
            match verify_modern_plain(&credential, &authentication) {
                Ok(true) => {
                    authenticated = true;
                    None
                }
                Ok(false) => Some("not-authorized"),
                Err(error) => {
                    tracing::error!(
                        domain = %credential.primary_domain,
                        ?error,
                        "could not read XEP-0225 component credential"
                    );
                    Some("temporary-auth-failure")
                }
            }
        };
        let Some(failure) = failure else {
            break;
        };
        let condition = match failure {
            "invalid-mechanism" => "invalid-mechanism",
            "malformed-request" => "malformed-request",
            "not-authorized" => "not-authorized",
            _ => "temporary-auth-failure",
        };
        s2s::write_xml(
            &mut secure,
            &crate::xmpp::xml_builder::XmlElement::new("failure")
                .attr("xmlns", "urn:ietf:params:xml:ns:xmpp-sasl")
                .child(crate::xmpp::xml_builder::XmlElement::new(condition))
                .finish(),
        )
        .await?;
    }
    if !authenticated {
        s2s::send_stream_error(&mut secure, "policy-violation").await?;
        anyhow::bail!("XEP-0225 SASL authentication attempt limit exceeded");
    }
    s2s::write_xml(
        &mut secure,
        &XmlElement::namespaced("success", "urn:ietf:params:xml:ns:xmpp-sasl").finish(),
    )
    .await?;
    input.reset_entity();

    let opening =
        read_handshake_frame_after_open(handshake_timeout, &mut secure, &mut input).await?;
    if let Err(condition) = validate_modern_opening(&state, &credential, &opening) {
        s2s::send_stream_error(&mut secure, condition).await?;
        anyhow::bail!("component stream identity changed during XEP-0225 negotiation: {condition}");
    }
    write_component_stream_open(
        &mut secure,
        &state.config.domain,
        &credential.primary_domain,
        &stream_id(),
    )
    .await?;
    s2s::write_xml(
        &mut secure,
        &XmlElement::new("stream:features")
            .child(
                XmlElement::namespaced("bind", "urn:xmpp:component:0")
                    .child(XmlElement::new("required")),
            )
            .finish(),
    )
    .await?;

    let connection_id = Uuid::new_v4();
    let (sender, receiver) = mpsc::channel(state.config.component_queue_capacity);
    tracing::info!(domain = %credential.primary_domain, "XEP-0225 component authenticated; hostname binding required");
    let _active_connection =
        ActiveComponentConnection::new(&state.metrics.component_connections_active);
    let result = drive_component(
        secure,
        Arc::clone(&state),
        credential.clone(),
        connection_id,
        ComponentProtocol::Modern0225,
        sender,
        HashSet::new(),
        receiver,
        input,
        cancel,
    )
    .await;
    state.component_registry().remove_connection(connection_id);
    crate::xmpp::protocol::caps::federated_caps_connection_closed(&state, connection_id).await;
    cleanup_component_muc(
        Arc::clone(&state),
        credential.allowed_domains.clone(),
        connection_id,
    )
    .await;
    result
}

#[allow(clippy::too_many_arguments)]
async fn drive_component<S>(
    mut io: S,
    state: Arc<AppState>,
    credential: ComponentCredential,
    connection_id: Uuid,
    protocol: ComponentProtocol,
    session_sender: mpsc::Sender<()>,
    mut bound_domains: HashSet<String>,
    mut outgoing: mpsc::Receiver<()>,
    mut input: s2s::S2sInputState,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut durable_poll = tokio::time::interval(Duration::from_millis(250));
    durable_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let initial_binding_deadline = tokio::time::sleep(Duration::from_secs(
        state.config.component_handshake_timeout_seconds,
    ));
    tokio::pin!(initial_binding_deadline);
    let mut initial_binding_complete = protocol != ComponentProtocol::Modern0225;
    let cancellation = cancel.clone().cancelled_owned();
    tokio::pin!(cancellation);
    loop {
        tokio::select! {
            frame = s2s::read_entity_frame(&mut io, &mut input) => {
                let frame = match frame {
                    Ok(frame) => frame,
                    Err(error) => {
                        if let Some(condition) = component_read_error_condition(&error) {
                            let _ = s2s::send_stream_error(&mut io, condition).await;
                        }
                        return Err(error);
                    }
                };
                if frame.starts_with("</stream:stream") {
                    s2s::write_xml(&mut io, &XmlElement::new("stream:stream").close()).await?;
                    return Ok(());
                }
                if protocol == ComponentProtocol::Modern0225 {
                    if let Some(reply) = handle_hostname_binding(
                        Arc::clone(&state),
                        credential.clone(),
                        connection_id,
                        session_sender.clone(),
                        &mut bound_domains,
                        frame.clone(),
                    )
                    .await?
                    {
                        s2s::write_xml(&mut io, &reply).await?;
                        initial_binding_complete |= !bound_domains.is_empty();
                        continue;
                    }
                }
                if is_component_stream_error(&frame) {
                    anyhow::bail!("external component reported a stream error");
                }
                if let Some(condition) = component_frame_stream_error(&frame) {
                    s2s::send_stream_error(&mut io, condition).await?;
                    anyhow::bail!("component sent a fatal {condition} frame");
                }
                let canonical = component_to_client(&frame, protocol);
                let reply = route_component_stanza(
                    Arc::clone(&state),
                    connection_id,
                    bound_domains.clone(),
                    canonical,
                ).await?;
                if let Some(reply) = reply {
                    s2s::write_xml(&mut io, &client_to_component(&reply, protocol)).await?;
                }
            }
            wake = outgoing.recv() => {
                let Some(()) = wake else { return Ok(()) };
                deliver_component_outbox(
                    &mut io,
                    Arc::clone(&state),
                    protocol,
                    bound_domains.clone(),
                    cancel.clone(),
                )
                .await?;
            }
            _ = durable_poll.tick() => {
                deliver_component_outbox(
                    &mut io,
                    Arc::clone(&state),
                    protocol,
                    bound_domains.clone(),
                    cancel.clone(),
                )
                .await?;
            }
            _ = &mut initial_binding_deadline, if !initial_binding_complete => {
                s2s::send_stream_error(&mut io, "policy-violation").await?;
                anyhow::bail!("XEP-0225 component did not bind a hostname before the deadline");
            }
            _ = &mut cancellation => {
                let _ = s2s::write_xml(&mut io, &XmlElement::new("stream:stream").close()).await;
                return Ok(());
            }
        }
    }
}

async fn deliver_component_outbox<S: AsyncWrite + Unpin + Send>(
    io: &mut S,
    state: Arc<AppState>,
    protocol: ComponentProtocol,
    bound_domains: HashSet<String>,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<()> {
    if bound_domains.is_empty() {
        return Ok(());
    }
    let domains = bound_domains.iter().cloned().collect::<Vec<_>>();
    let drain_limit = state
        .config
        .component_queue_capacity
        .min(COMPONENT_OUTBOX_DRAIN_LIMIT);
    for _ in 0..drain_limit {
        // Claim only when this socket is ready to start the row. A batch claim
        // would start every lease at once while writes remain serial.
        let items = crate::db::claim_due_s2s_outbox_for_domains(
            &state.pool,
            COMPONENT_OUTBOX_CLAIM_BATCH,
            state.config.s2s_outbox_lease_seconds,
            &domains,
        )
        .await?;
        let Some(item) = items.into_iter().next() else {
            break;
        };
        let _delivery_timer = state.metrics.outbox_delivery_duration_seconds.start_timer();
        let envelope = s2s::FederationEnvelope::from(item);
        let serialized = client_to_component(&envelope.stanza, protocol);
        match write_component_outbox_with_lease(
            io,
            Arc::clone(&state),
            envelope.outbox_id,
            envelope.lock_token,
            serialized,
            cancel.clone(),
        )
        .await
        {
            Ok(()) => {}
            Err(ComponentOutboxWriteError::Socket(error)) => {
                s2s::fail_envelope(&state, &envelope, &error, false).await;
                return Err(error);
            }
            Err(ComponentOutboxWriteError::Lease(error)) => {
                // Do not mutate a row after fencing was lost or its renewal
                // became uncertain. Closing this stream lets the durable row
                // be reclaimed after its last confirmed lease expires.
                return Err(error);
            }
        }

        state
            .metrics
            .component_deliveries_total
            .fetch_add(1, Ordering::Relaxed);
        let completion_budget =
            component_lease_renewal_period(state.config.s2s_outbox_lease_seconds);
        let completed = tokio::time::timeout(
            completion_budget,
            crate::db::complete_s2s_outbox(&state.pool, envelope.outbox_id, envelope.lock_token),
        )
        .await
        .context("component outbox completion timed out before the renewed lease boundary")??;
        if !completed {
            state
                .metrics
                .s2s_outbox_lease_lost_total
                .fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                outbox_id = %envelope.outbox_id,
                domain = %envelope.target_domain,
                "component stanza was written after its outbox lease was lost; delivery may be duplicated"
            );
            anyhow::bail!(
                "component outbox lease was lost before delivery completion for {}",
                envelope.outbox_id
            );
        }
    }
    Ok(())
}

#[derive(Debug)]
enum ComponentOutboxWriteError {
    Socket(anyhow::Error),
    Lease(anyhow::Error),
}

fn component_lease_renewal_period(lease_seconds: u64) -> Duration {
    Duration::from_secs((lease_seconds / 3).max(1))
}

async fn write_component_outbox_with_lease<S: AsyncWrite + Unpin + Send>(
    io: &mut S,
    state: Arc<AppState>,
    outbox_id: Uuid,
    lock_token: Uuid,
    serialized: String,
    cancel: tokio_util::sync::CancellationToken,
) -> std::result::Result<(), ComponentOutboxWriteError> {
    let renewal_period = component_lease_renewal_period(state.config.s2s_outbox_lease_seconds);
    let renewal_timeout = renewal_period.min(Duration::from_secs(5));
    let pool = state.pool.clone();
    let lease_seconds = state.config.s2s_outbox_lease_seconds;
    let result = write_component_outbox_with_renewal(
        io,
        serialized,
        renewal_period,
        renewal_timeout,
        cancel,
        move || {
            let pool = pool.clone();
            async move {
                crate::db::renew_s2s_outbox_lease(&pool, outbox_id, lock_token, lease_seconds).await
            }
        },
    )
    .await;
    match result {
        Err(ComponentOutboxWriteError::Lease(error)) => {
            state
                .metrics
                .s2s_outbox_lease_lost_total
                .fetch_add(1, Ordering::Relaxed);
            Err(ComponentOutboxWriteError::Lease(error.context(format!(
                "component outbox lease became unsafe while writing {}",
                outbox_id
            ))))
        }
        other => other,
    }
}

async fn write_component_outbox_with_renewal<S, Renew, RenewalFuture>(
    io: &mut S,
    serialized: String,
    renewal_period: Duration,
    renewal_timeout: Duration,
    cancel: tokio_util::sync::CancellationToken,
    mut renew: Renew,
) -> std::result::Result<(), ComponentOutboxWriteError>
where
    S: AsyncWrite + Unpin + Send,
    Renew: FnMut() -> RenewalFuture + Send,
    RenewalFuture: Future<Output = Result<bool>> + Send,
{
    let write = s2s::write_xml(io, &serialized);
    tokio::pin!(write);
    let renewal = tokio::time::sleep(renewal_period);
    tokio::pin!(renewal);
    let cancellation = cancel.cancelled_owned();
    tokio::pin!(cancellation);

    loop {
        tokio::select! {
            // Prefer observing a completed write over a simultaneous renewal
            // tick, avoiding a false lease-loss report after the last byte.
            biased;
            result = &mut write => {
                return result
                    .context("failed to write durable external-component envelope")
                    .map_err(ComponentOutboxWriteError::Socket);
            }
            _ = &mut cancellation => {
                return Err(ComponentOutboxWriteError::Lease(anyhow::anyhow!(
                    "component shutdown interrupted an outbox socket write"
                )));
            }
            _ = &mut renewal => {
                let renewal_result = tokio::select! {
                    biased;
                    result = &mut write => {
                        return result
                            .context("failed to write durable external-component envelope")
                            .map_err(ComponentOutboxWriteError::Socket);
                    }
                    _ = &mut cancellation => {
                        return Err(ComponentOutboxWriteError::Lease(anyhow::anyhow!(
                            "component shutdown interrupted an outbox lease renewal"
                        )));
                    }
                    result = tokio::time::timeout(renewal_timeout, renew()) => result,
                };
                match renewal_result {
                    Ok(Ok(true)) => {
                        renewal.as_mut().reset(Instant::now() + renewal_period);
                    }
                    Ok(Ok(false)) => {
                        return Err(ComponentOutboxWriteError::Lease(anyhow::anyhow!(
                            "component outbox lease was lost during socket write"
                        )));
                    }
                    Ok(Err(error)) => {
                        return Err(ComponentOutboxWriteError::Lease(
                            error.context("could not renew component outbox lease during socket write")
                        ));
                    }
                    Err(_) => {
                        return Err(ComponentOutboxWriteError::Lease(anyhow::anyhow!(
                            "component outbox lease renewal exceeded its database deadline"
                        )));
                    }
                }
            }
        }
    }
}

async fn handle_hostname_binding(
    state: Arc<AppState>,
    credential: ComponentCredential,
    connection_id: Uuid,
    session_sender: mpsc::Sender<()>,
    bound_domains: &mut HashSet<String>,
    raw: String,
) -> Result<Option<String>> {
    let document = match Document::parse(&raw) {
        Ok(document) => document,
        Err(_) => return Ok(None),
    };
    let root = document.root_element();
    if root.tag_name().name() != "iq"
        || !matches!(root.tag_name().namespace(), None | Some("jabber:client"))
        || root.attribute("type") != Some("set")
    {
        return Ok(None);
    }
    let element_children = root
        .children()
        .filter(roxmltree::Node::is_element)
        .collect::<Vec<_>>();
    if element_children.len() != 1 {
        let id = root.attribute("id").unwrap_or_default();
        return Ok(Some(component_iq_error(id, "bad-request")));
    }
    let command = element_children[0];
    if !matches!(command.tag_name().name(), "bind" | "unbind")
        || command.tag_name().namespace() != Some(COMPONENT_BIND_NS)
    {
        return Ok(None);
    }
    let id = root.attribute("id").unwrap_or_default().to_owned();
    if id.is_empty() || id.len() > 128 {
        return Ok(Some(component_iq_error(&id, "bad-request")));
    }
    let hostname_children = command
        .children()
        .filter(roxmltree::Node::is_element)
        .collect::<Vec<_>>();
    if hostname_children.len() != 1
        || hostname_children[0].tag_name().name() != "hostname"
        || hostname_children[0].tag_name().namespace() != Some(COMPONENT_BIND_NS)
        || hostname_children[0]
            .children()
            .any(|node| node.is_element())
    {
        return Ok(Some(component_iq_error(&id, "bad-request")));
    }
    let Some(hostname) = hostname_children[0].text() else {
        return Ok(Some(component_iq_error(&id, "bad-request")));
    };
    if hostname.contains('/') {
        // XEP-0225 permits an application-specific domain/resource form, but
        // defines no interoperable routing semantics for it.
        return Ok(Some(component_iq_error(&id, "not-allowed")));
    }
    let hostname = match crate::jid::prepare_domainpart(hostname) {
        Ok(hostname) => hostname,
        Err(_) => return Ok(Some(component_iq_error(&id, "bad-request"))),
    };
    if !credential.allowed_domains.contains(&hostname) {
        return Ok(Some(component_iq_error(&id, "not-allowed")));
    }
    if command.tag_name().name() == "bind" {
        if bound_domains.contains(&hostname) {
            return Ok(Some(component_iq_error(&id, "conflict")));
        }
        if state
            .component_registry()
            .register_domain(&hostname, connection_id, session_sender.clone())
            .is_err()
        {
            return Ok(Some(component_iq_error(&id, "conflict")));
        }
        bound_domains.insert(hostname.clone());
        return Ok(Some(
            crate::xmpp::xml_builder::XmlElement::new("iq")
                .attr("xmlns", "jabber:client")
                .attr("type", "result")
                .attr("id", &id)
                .child(
                    crate::xmpp::xml_builder::XmlElement::new("bind")
                        .attr("xmlns", COMPONENT_BIND_NS)
                        .child(
                            crate::xmpp::xml_builder::XmlElement::new("hostname")
                                .text(hostname.clone()),
                        ),
                )
                .finish(),
        ));
    }

    let owned = state
        .component_registry()
        .connection_owns_domain(&hostname, connection_id);
    if !owned {
        return Ok(Some(component_iq_error(&id, "not-allowed")));
    }
    // Everything derived from the stanza parser is now owned (`id` and
    // `hostname`); release the document before the asynchronous MUC cleanup.
    drop(document);
    if let Err(error) = crate::xmpp::protocol::federated_muc::federated_muc_connection_closed(
        &state,
        &hostname,
        connection_id,
    )
    .await
    {
        tracing::warn!(
            component_domain = %hostname,
            %connection_id,
            ?error,
            "failed to clean up MUC occupants after component hostname unbind"
        );
        return Ok(Some(component_iq_error(&id, "internal-server-error")));
    }
    state
        .component_registry()
        .remove_domain_if_owner(&hostname, connection_id);
    bound_domains.remove(&hostname);
    Ok(Some(
        crate::xmpp::xml_builder::XmlElement::new("iq")
            .attr("xmlns", "jabber:client")
            .attr("type", "result")
            .attr("id", &id)
            .finish(),
    ))
}

async fn route_component_stanza(
    state: Arc<AppState>,
    connection_id: Uuid,
    bound_domains: HashSet<String>,
    raw: String,
) -> Result<Option<String>> {
    let document = Document::parse(&raw).context("component sent invalid XML")?;
    let root = document.root_element();
    if !matches!(root.tag_name().name(), "message" | "presence" | "iq") {
        anyhow::bail!("component sent an unsupported top-level stanza");
    }
    if root.tag_name().namespace() != Some("jabber:client") {
        return Ok(component_stanza_error(root, "bad-request"));
    }
    if let Some(condition) = invalid_component_stanza(root) {
        return Ok(component_stanza_error(root, condition));
    }
    let from = root.attribute("from").unwrap_or_default();
    let to = root.attribute("to").unwrap_or_default();
    let Some(from_domain) = target_domain(from) else {
        return Ok(component_stanza_error(root, "jid-malformed"));
    };
    if to.is_empty() || target_domain(to).is_none() {
        return Ok(component_stanza_error(root, "jid-malformed"));
    }
    if !bound_domains.contains(&from_domain) {
        return Ok(component_stanza_error(root, "not-authorized"));
    }

    let target = target_domain(to).expect("checked above");
    let hosted_locally = [
        state.config.domain.clone(),
        format!("pubsub.{}", state.config.domain),
        format!("conference.{}", state.config.domain),
        format!("mix.{}", state.config.domain),
        format!("upload.{}", state.config.domain),
    ]
    .iter()
    .any(|hosted| same_component_domain(&target, hosted));
    if hosted_locally {
        let server_raw = s2s::stanza_namespace(&raw, "jabber:client", "jabber:server");
        // Do not retain a parser node or frame-local `&str` across the
        // application await.  The owned bridge also gives the actor registry
        // a concrete `Send + 'static` future boundary.
        drop(document);
        return s2s::route_inbound_component_owned(
            Arc::clone(&state),
            from_domain,
            connection_id,
            server_raw,
        )
        .await
        .map(|reply| {
            reply.map(|reply| s2s::stanza_namespace(&reply, "jabber:server", "jabber:client"))
        });
    }

    if state.config.component_domain_configured(&target) {
        let error = component_stanza_error(root, "service-unavailable");
        let federation = state.federation.clone();
        let from = from.to_owned();
        drop(document);
        return match federation.send(&target, raw, Some(from)).await {
            true => Ok(None),
            false => Ok(error),
        };
    }
    if state.island_mode_enabled() {
        return Ok(component_stanza_error(root, "remote-server-not-found"));
    }
    if !state.federation_domain_allowed(&target) {
        return Ok(component_stanza_error(root, "remote-server-not-found"));
    }
    let timeout_error = component_stanza_error(root, "remote-server-timeout");
    let federation = state.federation.clone();
    let from = from.to_owned();
    drop(document);
    if federation.send(&target, raw, Some(from)).await {
        Ok(None)
    } else {
        Ok(timeout_error)
    }
}

fn invalid_component_stanza(root: Node<'_, '_>) -> Option<&'static str> {
    match root.tag_name().name() {
        "message" => {
            if root.attribute("type").is_some_and(|kind| {
                !matches!(kind, "normal" | "chat" | "groupchat" | "headline" | "error")
            }) {
                return Some("bad-request");
            }
        }
        "presence" => {
            if root.attribute("type").is_some_and(|kind| {
                !matches!(
                    kind,
                    "unavailable"
                        | "subscribe"
                        | "subscribed"
                        | "unsubscribe"
                        | "unsubscribed"
                        | "probe"
                        | "error"
                )
            }) {
                return Some("bad-request");
            }
        }
        "iq" => {
            let Some(kind) = root.attribute("type") else {
                return Some("bad-request");
            };
            if !matches!(kind, "get" | "set" | "result" | "error")
                || root.attribute("id").is_none_or(str::is_empty)
            {
                return Some("bad-request");
            }
            let payloads = root
                .children()
                .filter(|node| node.is_element() && node.tag_name().name() != "error")
                .count();
            if matches!(kind, "get" | "set") && payloads != 1 {
                return Some("bad-request");
            }
            if matches!(kind, "result" | "error") && payloads > 1 {
                return Some("bad-request");
            }
        }
        _ => return Some("unsupported-stanza-type"),
    }
    None
}

async fn cleanup_component_muc(state: Arc<AppState>, domains: Vec<String>, connection_id: Uuid) {
    for domain in domains {
        if let Err(error) = crate::xmpp::protocol::federated_muc::federated_muc_connection_closed(
            &state,
            &domain,
            connection_id,
        )
        .await
        {
            tracing::warn!(
                component_domain = %domain,
                %connection_id,
                ?error,
                "failed to clean up MUC occupants after component disconnect"
            );
        }
    }
}

fn verify_legacy_handshake(
    credential: &ComponentCredential,
    stream_id: &str,
    raw: &str,
) -> Result<bool> {
    let document = Document::parse(raw).context("invalid XEP-0114 handshake")?;
    let root = document.root_element();
    if root.tag_name().name() != "handshake"
        || !matches!(
            root.tag_name().namespace(),
            None | Some(COMPONENT_ACCEPT_NS)
        )
        || root.attributes().len() != 0
        || root.children().any(|node| node.is_element())
    {
        return Ok(false);
    }
    let supplied = decode_hex_20(root.text().unwrap_or_default().trim());
    let Some(supplied) = supplied else {
        return Ok(false);
    };
    let secret = verified_secret(credential)?;
    let mut digest = Sha1::new();
    digest.update(stream_id.as_bytes());
    digest.update(secret.as_bytes());
    let expected: [u8; 20] = digest.finalize().into();
    Ok(bool::from(expected.ct_eq(&supplied)))
}

fn verify_modern_plain(credential: &ComponentCredential, raw: &str) -> Result<bool> {
    if !modern_plain_shape_is_valid(raw) {
        return Ok(false);
    }
    let document = Document::parse(raw).context("invalid component SASL stanza")?;
    let root = document.root_element();
    let encoded = root.text().unwrap_or_default();
    if encoded.len() > 8192 {
        return Ok(false);
    }
    let mut decoded = match STANDARD.decode(encoded.trim()) {
        Ok(decoded) => decoded,
        Err(_) => return Ok(false),
    };
    let fields = decoded.split(|byte| *byte == 0).collect::<Vec<_>>();
    if fields.len() != 3 {
        decoded.zeroize();
        return Ok(false);
    }
    let authzid = std::str::from_utf8(fields[0]).unwrap_or_default();
    let authcid = std::str::from_utf8(fields[1]).unwrap_or_default();
    let identity_matches = same_component_domain(authcid, &credential.primary_domain)
        && (authzid.is_empty() || same_component_domain(authzid, &credential.primary_domain));
    let candidate: [u8; 32] = Sha256::digest(fields[2]).into();
    let password_matches = bool::from(candidate.ct_eq(&credential.secret_sha256));
    decoded.zeroize();
    Ok(identity_matches & password_matches)
}

fn modern_plain_shape_is_valid(raw: &str) -> bool {
    Document::parse(raw).is_ok_and(|document| {
        let root = document.root_element();
        root.tag_name().name() == "auth"
            && root.tag_name().namespace() == Some(SASL_NS)
            && root.attribute("mechanism") == Some("PLAIN")
            && root.attributes().len() == 1
            && !root.children().any(|child| child.is_element())
    })
}

fn component_frame_stream_error(raw: &str) -> Option<&'static str> {
    let Ok(document) = Document::parse(raw) else {
        return Some("not-well-formed");
    };
    if matches!(
        document.root_element().tag_name().name(),
        "message" | "presence" | "iq"
    ) {
        None
    } else {
        Some("unsupported-stanza-type")
    }
}

fn is_component_stream_error(raw: &str) -> bool {
    Document::parse(raw).is_ok_and(|document| {
        let root = document.root_element();
        root.tag_name().name() == "error" && root.tag_name().namespace() == Some(STREAMS_NS)
    })
}

fn verified_secret(credential: &ComponentCredential) -> Result<&str> {
    let secret = credential
        .secret_value
        .as_ref()
        .context("component credential secret was not loaded during startup")?;
    let digest: [u8; 32] = Sha256::digest(secret.as_bytes()).into();
    if !bool::from(digest.ct_eq(&credential.secret_sha256)) {
        anyhow::bail!("in-memory component secret fingerprint mismatch");
    }
    Ok(secret.as_str())
}

fn validate_modern_opening(
    state: &AppState,
    credential: &ComponentCredential,
    opening: &str,
) -> std::result::Result<(), &'static str> {
    match stream_namespace(opening) {
        Ok(namespace) if namespace == "jabber:client" => {}
        Ok(_) => return Err("invalid-namespace"),
        Err(condition) => return Err(condition),
    }
    if component_stream_attribute(opening, "version", "jabber:client", false).as_deref()
        != Some("1.0")
    {
        return Err("unsupported-version");
    }
    if component_stream_attribute(opening, "from", "jabber:client", true)
        .is_none_or(|domain| !same_component_domain(&domain, &credential.primary_domain))
    {
        return Err("invalid-from");
    }
    if component_stream_attribute(opening, "to", "jabber:client", true)
        .is_none_or(|domain| !same_component_domain(&domain, &state.config.domain))
    {
        return Err("host-unknown");
    }
    Ok(())
}

async fn read_handshake_frame<S: AsyncRead + Unpin + Send>(
    timeout: Duration,
    stream: &mut S,
    input: &mut s2s::S2sInputState,
) -> Result<String> {
    tokio::time::timeout(timeout, s2s::read_entity_frame(stream, input))
        .await
        .context("component handshake timed out")?
}

async fn read_handshake_frame_after_open<S: AsyncRead + AsyncWrite + Unpin + Send>(
    timeout: Duration,
    stream: &mut S,
    input: &mut s2s::S2sInputState,
) -> Result<String> {
    match read_handshake_frame(timeout, stream, input).await {
        Ok(frame) => Ok(frame),
        Err(error) => {
            if let Some(condition) = component_read_error_condition(&error) {
                let _ = s2s::send_stream_error(stream, condition).await;
            }
            Err(error)
        }
    }
}

fn component_read_error_condition(error: &anyhow::Error) -> Option<&'static str> {
    if error
        .downcast_ref::<tokio::time::error::Elapsed>()
        .is_some()
    {
        Some("connection-timeout")
    } else {
        s2s::s2s_read_stream_error_condition(error)
    }
}

fn stream_namespace(opening: &str) -> std::result::Result<String, &'static str> {
    let complete = format!("{opening}{}", XmlElement::new("stream:stream").close());
    let document = Document::parse(&complete).map_err(|_| "not-well-formed")?;
    let root = document.root_element();
    if root.tag_name().name() != "stream" || root.tag_name().namespace() != Some(STREAMS_NS) {
        return Err("invalid-namespace");
    }
    if root.children().any(|child| child.is_element()) {
        return Err("not-well-formed");
    }
    root.lookup_namespace_uri(None)
        .map(str::to_owned)
        .ok_or("invalid-namespace")
}

/// Parse an external-component stream opening without weakening the stricter
/// `jabber:server` parser used by S2S. XEP-0114 uses
/// `jabber:component:accept` and predates versioned streams, while the
/// Deferred XEP-0225 profile uses a version 1.0 `jabber:client` stream.
fn component_stream_attribute(
    xml: &str,
    name: &str,
    default_namespace: &str,
    require_version_1: bool,
) -> Option<String> {
    if !matches!(name, "from" | "to" | "id" | "version") {
        return None;
    }
    let complete = format!("{xml}{}", XmlElement::new("stream:stream").close());
    let document = Document::parse(&complete).ok()?;
    let root = document.root_element();
    if root.tag_name().name() != "stream"
        || root.tag_name().namespace() != Some(STREAMS_NS)
        || root.lookup_namespace_uri(None) != Some(default_namespace)
        || (require_version_1 && root.attribute("version") != Some("1.0"))
        || root.children().any(|child| child.is_element())
    {
        return None;
    }
    let value = root.attribute(name)?;
    if value.is_empty() || value.len() > 1_024 || value.chars().any(char::is_control) {
        return None;
    }
    Some(value.to_owned())
}

fn validate_legacy_connect_opening(opening: &str, component: &str) -> Result<String> {
    let complete = format!("{opening}{}", XmlElement::new("stream:stream").close());
    let document = Document::parse(&complete)
        .context("outbound XEP-0114 component returned malformed stream XML")?;
    let root = document.root_element();
    anyhow::ensure!(
        root.tag_name().name() == "stream"
            && root.tag_name().namespace() == Some(STREAMS_NS)
            && root.lookup_namespace_uri(None) == Some(COMPONENT_CONNECT_NS)
            && !root.children().any(|child| child.is_element()),
        "outbound XEP-0114 component returned an invalid stream namespace"
    );
    let to = root
        .attribute("to")
        .context("outbound XEP-0114 component stream omitted to")?;
    anyhow::ensure!(
        same_component_domain(to, component),
        "outbound XEP-0114 component stream addressed a different domain"
    );
    if let Some(from) = root.attribute("from") {
        anyhow::ensure!(
            same_component_domain(from, component),
            "outbound XEP-0114 component asserted a different domain"
        );
    }
    let id = root
        .attribute("id")
        .filter(|id| !id.is_empty() && id.len() <= 1_024 && !id.chars().any(char::is_control))
        .context("outbound XEP-0114 component stream omitted a valid id")?;
    Ok(id.to_owned())
}

fn is_element(raw: &str, name: &str, namespace: &str) -> bool {
    Document::parse(raw).is_ok_and(|document| {
        let root = document.root_element();
        root.tag_name().name() == name && root.tag_name().namespace() == Some(namespace)
    })
}

fn is_empty_element(raw: &str, name: &str, namespace: &str) -> bool {
    Document::parse(raw).is_ok_and(|document| {
        let root = document.root_element();
        root.tag_name().name() == name
            && root.tag_name().namespace() == Some(namespace)
            && root.attributes().len() == 0
            && !root.children().any(|child| {
                child.is_element() || child.text().is_some_and(|text| !text.trim().is_empty())
            })
    })
}

fn is_inherited_empty_element(raw: &str, name: &str, stream_namespace: &str) -> bool {
    Document::parse(raw).is_ok_and(|document| {
        let root = document.root_element();
        root.tag_name().name() == name
            && root
                .tag_name()
                .namespace()
                .is_none_or(|namespace| namespace == stream_namespace)
            && root.attributes().len() == 0
            && !root.children().any(|child| {
                child.is_element() || child.text().is_some_and(|text| !text.trim().is_empty())
            })
    })
}

fn component_to_client(raw: &str, protocol: ComponentProtocol) -> String {
    match protocol {
        ComponentProtocol::Legacy0114Accept => {
            s2s::stanza_namespace(raw, COMPONENT_ACCEPT_NS, "jabber:client")
        }
        ComponentProtocol::Legacy0114Connect => {
            s2s::stanza_namespace(raw, COMPONENT_CONNECT_NS, "jabber:client")
        }
        ComponentProtocol::Modern0225 => {
            s2s::stanza_namespace(raw, "jabber:client", "jabber:client")
        }
    }
}

fn client_to_component(raw: &str, protocol: ComponentProtocol) -> String {
    match protocol {
        ComponentProtocol::Legacy0114Accept => {
            s2s::stanza_namespace(raw, "jabber:client", COMPONENT_ACCEPT_NS)
        }
        ComponentProtocol::Legacy0114Connect => {
            s2s::stanza_namespace(raw, "jabber:client", COMPONENT_CONNECT_NS)
        }
        ComponentProtocol::Modern0225 => {
            s2s::stanza_namespace(raw, "jabber:client", "jabber:client")
        }
    }
}

fn component_iq_error(id: &str, condition: &str) -> String {
    let (error_type, condition) = match condition {
        "bad-request" => ("modify", "bad-request"),
        "internal-server-error" => ("wait", "internal-server-error"),
        "resource-constraint" => ("wait", "resource-constraint"),
        "conflict" => ("cancel", "conflict"),
        "not-allowed" => ("cancel", "not-allowed"),
        _ => ("cancel", "service-unavailable"),
    };
    crate::xmpp::xml_builder::XmlElement::new("iq")
        .attr("xmlns", "jabber:client")
        .attr("type", "error")
        .attr("id", id)
        .child(
            crate::xmpp::xml_builder::XmlElement::new("error")
                .attr("type", error_type)
                .child(
                    crate::xmpp::xml_builder::XmlElement::new(condition)
                        .attr("xmlns", "urn:ietf:params:xml:ns:xmpp-stanzas"),
                ),
        )
        .finish()
}

fn component_stanza_error(root: Node<'_, '_>, condition: &str) -> Option<String> {
    if root.attribute("type") == Some("error") {
        return None;
    }
    let (error_type, condition) = match condition {
        "bad-request" => ("modify", "bad-request"),
        "jid-malformed" => ("modify", "jid-malformed"),
        "not-authorized" => ("auth", "not-authorized"),
        "remote-server-not-found" => ("cancel", "remote-server-not-found"),
        "remote-server-timeout" => ("wait", "remote-server-timeout"),
        "resource-constraint" => ("wait", "resource-constraint"),
        "service-unavailable" => ("cancel", "service-unavailable"),
        _ => ("cancel", "undefined-condition"),
    };
    Some(crate::xmpp::xml_util::reflected_stanza_error(
        root,
        &crate::xmpp::xml_builder::XmlElement::new("error")
            .attr(
                "xmlns",
                root.tag_name().namespace().unwrap_or("jabber:client"),
            )
            .attr("type", error_type)
            .child(
                crate::xmpp::xml_builder::XmlElement::new(condition)
                    .attr("xmlns", "urn:ietf:params:xml:ns:xmpp-stanzas"),
            )
            .finish(),
    ))
}

async fn write_legacy_stream_open<S: AsyncWrite + Unpin + Send>(
    stream: &mut S,
    component: &str,
    id: &str,
) -> Result<()> {
    s2s::write_xml(
        stream,
        &crate::xmpp::xml_builder::XmlElement::new("stream:stream")
            .attr("xmlns", COMPONENT_ACCEPT_NS)
            .attr("xmlns:stream", STREAMS_NS)
            .attr("from", component)
            .attr("id", id)
            .open(),
    )
    .await
}

async fn write_legacy_connect_open<S: AsyncWrite + Unpin + Send>(
    stream: &mut S,
    component: &str,
) -> Result<()> {
    // XEP-0114 footnote 4 assigns the component name to `from` when the server
    // initiates jabber:component:connect. The receiver returns that identity in
    // `to`; an optional response `from` is accepted only when it is identical.
    s2s::write_xml(
        stream,
        &crate::xmpp::xml_builder::XmlElement::new("stream:stream")
            .attr("xmlns", COMPONENT_CONNECT_NS)
            .attr("xmlns:stream", STREAMS_NS)
            .attr("from", component)
            .open(),
    )
    .await
}

async fn write_component_stream_open<S: AsyncWrite + Unpin + Send>(
    stream: &mut S,
    from: &str,
    to: &str,
    id: &str,
) -> Result<()> {
    s2s::write_xml(
        stream,
        &crate::xmpp::xml_builder::XmlElement::new("stream:stream")
            .attr("xmlns", "jabber:client")
            .attr("xmlns:stream", STREAMS_NS)
            .attr("from", from)
            .optional_attr("to", (!to.is_empty()).then_some(to))
            .attr("id", id)
            .attr("version", "1.0")
            .open(),
    )
    .await
}

fn stream_id() -> String {
    Uuid::new_v4().simple().to_string()
}

fn decode_hex_20(value: &str) -> Option<[u8; 20]> {
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let mut decoded = [0_u8; 20];
    for (index, slot) in decoded.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        pin::Pin,
        sync::atomic::{AtomicBool, AtomicUsize},
        task::{Context as TaskContext, Poll},
    };

    struct RenewalGatedWriter {
        writable: Arc<AtomicBool>,
        bytes: Vec<u8>,
    }

    impl AsyncWrite for RenewalGatedWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _context: &mut TaskContext<'_>,
            buffer: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            if !self.writable.load(Ordering::Acquire) {
                return Poll::Pending;
            }
            self.bytes.extend_from_slice(buffer);
            Poll::Ready(Ok(buffer.len()))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _context: &mut TaskContext<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _context: &mut TaskContext<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn unconfigured_component_task_stays_alive_until_cancelled() {
        let cancel = tokio_util::sync::CancellationToken::new();
        let task_cancel = cancel.clone();
        let mut task = tokio::spawn(async move {
            wait_for_component_shutdown(&task_cancel).await;
        });

        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut task)
                .await
                .is_err(),
            "an unconfigured component task must not terminate main"
        );
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("component shutdown wait timed out")
            .expect("component shutdown task panicked");
    }

    #[tokio::test]
    async fn connect_supervisor_failures_and_panics_are_never_silent() {
        let mut failed = JoinSet::new();
        failed.spawn(async {
            Err::<(), anyhow::Error>(anyhow::anyhow!("injected supervisor failure"))
        });
        let error = component_supervisor_completion(failed.join_next().await, false)
            .expect_err("supervisor error must terminate the component service");
        assert!(format!("{error:#}").contains("injected supervisor failure"));

        let joined: std::result::Result<Result<()>, tokio::task::JoinError> =
            tokio::spawn(async { panic!("injected supervisor panic") })
                .await
                .map(|()| Ok(()));
        let error = component_supervisor_completion(Some(joined), false)
            .expect_err("supervisor panic must terminate the component service");
        assert!(format!("{error:#}").contains("panicked or was cancelled"));

        assert!(component_supervisor_completion(Some(Ok(Ok(()))), true).is_ok());
        assert!(component_supervisor_completion(Some(Ok(Ok(()))), false).is_err());
    }

    #[tokio::test]
    async fn component_socket_write_is_fenced_by_lease_renewal() {
        let writable = Arc::new(AtomicBool::new(false));
        let renewals = Arc::new(AtomicUsize::new(0));
        let mut writer = RenewalGatedWriter {
            writable: Arc::clone(&writable),
            bytes: Vec::new(),
        };
        let writable_after_renewal = Arc::clone(&writable);
        let renewal_count = Arc::clone(&renewals);
        let cancel = tokio_util::sync::CancellationToken::new();
        tokio::time::timeout(
            Duration::from_secs(1),
            write_component_outbox_with_renewal(
                &mut writer,
                "<message/>".to_owned(),
                Duration::from_millis(1),
                Duration::from_millis(100),
                cancel.clone(),
                move || {
                    writable_after_renewal.store(true, Ordering::Release);
                    renewal_count.fetch_add(1, Ordering::Relaxed);
                    std::future::ready(Ok(true))
                },
            ),
        )
        .await
        .expect("lease-fenced component write timed out")
        .expect("renewed component write failed");
        assert_eq!(renewals.load(Ordering::Relaxed), 1);
        assert_eq!(writer.bytes, b"<message/>");

        let mut blocked = RenewalGatedWriter {
            writable: Arc::new(AtomicBool::new(false)),
            bytes: Vec::new(),
        };
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            write_component_outbox_with_renewal(
                &mut blocked,
                "<message/>".to_owned(),
                Duration::from_millis(1),
                Duration::from_millis(100),
                cancel,
                || std::future::ready(Ok(false)),
            ),
        )
        .await
        .expect("lease-loss component write timed out");
        assert!(matches!(result, Err(ComponentOutboxWriteError::Lease(_))));
        assert!(blocked.bytes.is_empty());
    }

    #[test]
    fn component_outbox_claims_are_just_in_time_and_bounded() {
        assert_eq!(COMPONENT_OUTBOX_CLAIM_BATCH, 1);
        const { assert!(COMPONENT_OUTBOX_DRAIN_LIMIT <= 32) };
        assert_eq!(component_lease_renewal_period(30), Duration::from_secs(10));
        assert_eq!(component_lease_renewal_period(1), Duration::from_secs(1));
    }

    fn credential(secret: &str, secret_file: std::path::PathBuf) -> ComponentCredential {
        ComponentCredential {
            primary_domain: "gateway.example".to_owned(),
            allowed_domains: vec!["gateway.example".to_owned()],
            secret_value: Some(Arc::new(Zeroizing::new(secret.to_owned()))),
            secret_file: Some(secret_file),
            secret_sha256: Sha256::digest(secret.as_bytes()).into(),
            legacy_0114: true,
            modern_0225: true,
            connection: ComponentConnectionMode::Accept,
            connect_endpoint: None,
            allow_public_connect: false,
        }
    }

    #[test]
    fn active_component_connection_counter_is_drop_safe() {
        let counter = AtomicU64::new(0);
        {
            let _connection = ActiveComponentConnection::new(&counter);
            assert_eq!(counter.load(Ordering::Relaxed), 1);
        }
        assert_eq!(counter.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn component_target_uses_prepared_jid_domain() {
        assert_eq!(
            target_domain("romeo@Chat.Example/resource").as_deref(),
            Some("chat.example")
        );
        assert_eq!(
            target_domain("romeo@BÜCHER.example/Resource").as_deref(),
            Some("bücher.example")
        );
        assert!(target_domain("bad jid").is_none());
        assert!(target_domain("romeo@example..test/resource").is_none());
        assert!(target_domain("romeo@example.test/bad\u{0007}resource").is_none());
    }

    #[test]
    fn component_wake_is_bounded_and_requires_configuration() {
        let registry = registry();
        let connection_id = Uuid::new_v4();
        let (sender, mut receiver) = mpsc::channel(1);
        registry
            .register_domain("gateway.example", connection_id, sender)
            .expect("register component");
        let configured = HashSet::from(["gateway.example".to_owned()]);
        assert_eq!(
            registry.wake_route(&configured, "alice@gateway.example"),
            ComponentRoute::Delivered
        );
        assert_eq!(
            registry.wake_route(&configured, "alice@gateway.example"),
            ComponentRoute::Unavailable
        );
        assert_eq!(receiver.try_recv(), Ok(()));
        assert_eq!(
            registry.wake_route(&HashSet::new(), "alice@gateway.example"),
            ComponentRoute::NotConfigured
        );
        drop(receiver);
        assert_eq!(
            registry.wake_route(&configured, "alice@gateway.example"),
            ComponentRoute::Unavailable
        );
    }

    #[test]
    fn legacy_hex_decoder_is_strict() {
        assert_eq!(decode_hex_20(&"a5".repeat(20)), Some([0xa5; 20]));
        assert!(decode_hex_20(&"a5".repeat(19)).is_none());
        assert!(decode_hex_20(&format!("{}zz", "a5".repeat(19))).is_none());
        assert!(decode_hex_20(&"A5".repeat(20)).is_none());
    }

    #[test]
    fn component_stream_attributes_accept_only_the_protocol_namespace_and_version() {
        let legacy = format!(
            "<stream:stream xmlns='{COMPONENT_ACCEPT_NS}' xmlns:stream='{STREAMS_NS}' to='gateway.example'>"
        );
        let formatted = format!(
            "<stream:stream\n  xmlns='{COMPONENT_ACCEPT_NS}'\n  xmlns:stream='{STREAMS_NS}'\n  to='gateway.example'>"
        );
        assert_eq!(stream_namespace(&formatted).unwrap(), COMPONENT_ACCEPT_NS);
        assert_eq!(
            component_stream_attribute(&legacy, "to", COMPONENT_ACCEPT_NS, false).as_deref(),
            Some("gateway.example")
        );

        let modern = format!(
            "<stream:stream xmlns='jabber:client' xmlns:stream='{STREAMS_NS}' from='gateway.example' to='example' version='1.0'>"
        );
        assert_eq!(
            component_stream_attribute(&modern, "from", "jabber:client", true).as_deref(),
            Some("gateway.example")
        );
        assert!(component_stream_attribute(&legacy, "to", "jabber:client", true).is_none());
        assert!(component_stream_attribute(
            &modern.replace(" version='1.0'", ""),
            "from",
            "jabber:client",
            true,
        )
        .is_none());
    }

    #[test]
    fn starttls_and_sasl_abort_controls_are_empty_and_namespaced() {
        assert!(is_empty_element(
            "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>",
            "starttls",
            "urn:ietf:params:xml:ns:xmpp-tls"
        ));
        assert!(!is_empty_element(
            "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><extra/></starttls>",
            "starttls",
            "urn:ietf:params:xml:ns:xmpp-tls"
        ));
        assert!(is_empty_element(
            "<abort xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>",
            "abort",
            SASL_NS
        ));
    }

    #[test]
    fn namespace_conversion_does_not_leave_client_namespace_on_legacy_stream() {
        let stanza = "<message xmlns='jabber:client' from='a.test' to='b.test'/>";
        assert!(
            client_to_component(stanza, ComponentProtocol::Legacy0114Accept)
                .contains("xmlns='jabber:component:accept'")
        );
        assert!(
            client_to_component(stanza, ComponentProtocol::Legacy0114Connect)
                .contains("xmlns='jabber:component:connect'")
        );
    }

    #[test]
    fn connect_endpoint_ssrf_policy_requires_explicit_public_opt_in() {
        for private in [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.0.1",
            "::1",
            "fd00::1",
        ] {
            assert!(component_connect_address_allowed(
                private.parse().unwrap(),
                false
            ));
        }
        for forbidden in ["0.0.0.0", "224.0.0.1", "::", "ff02::1", "169.254.169.254"] {
            assert!(!component_connect_address_allowed(
                forbidden.parse().unwrap(),
                false
            ));
        }
        assert!(component_connect_address_allowed(
            "203.0.113.1".parse().unwrap(),
            true
        ));
        for forbidden_even_when_public in
            ["0.0.0.0", "255.255.255.255", "169.254.169.254", "fe80::1"]
        {
            assert!(!component_connect_address_allowed(
                forbidden_even_when_public.parse().unwrap(),
                true
            ));
        }
    }

    #[test]
    fn connect_handshake_ack_may_inherit_only_the_connect_namespace() {
        assert!(is_inherited_empty_element(
            "<handshake/>",
            "handshake",
            COMPONENT_CONNECT_NS
        ));
        assert!(is_inherited_empty_element(
            "<handshake xmlns='jabber:component:connect'/>",
            "handshake",
            COMPONENT_CONNECT_NS
        ));
        assert!(!is_inherited_empty_element(
            "<handshake xmlns='jabber:component:accept'/>",
            "handshake",
            COMPONENT_CONNECT_NS
        ));
        assert!(!is_inherited_empty_element(
            "<handshake><extra/></handshake>",
            "handshake",
            COMPONENT_CONNECT_NS
        ));
    }

    #[test]
    fn connect_responder_stream_is_strictly_addressed_to_the_component() {
        let valid = format!(
            "<stream:stream xmlns='{COMPONENT_CONNECT_NS}' xmlns:stream='{STREAMS_NS}' to='gateway.example' id='stream-id'>"
        );
        assert_eq!(
            validate_legacy_connect_opening(&valid, "gateway.example").unwrap(),
            "stream-id"
        );
        let equivalent = valid.replace(
            "to='gateway.example'",
            "to='GATEWAY.EXAMPLE' from='gateway.example'",
        );
        assert_eq!(
            validate_legacy_connect_opening(&equivalent, "gateway.example").unwrap(),
            "stream-id"
        );
        for invalid in [
            valid.replace("to='gateway.example' ", ""),
            valid.replace("to='gateway.example'", "to='forged.example'"),
            valid.replace(
                "to='gateway.example'",
                "to='gateway.example' from='forged.example'",
            ),
            valid.replace(COMPONENT_CONNECT_NS, COMPONENT_ACCEPT_NS),
            valid.replace(" id='stream-id'", ""),
        ] {
            assert!(
                validate_legacy_connect_opening(&invalid, "gateway.example").is_err(),
                "accepted invalid connect responder opening: {invalid}"
            );
        }
    }

    #[test]
    fn legacy_handshake_uses_stream_id_plus_mounted_secret() {
        let secret = "this-is-a-32-byte-or-longer-component-secret";
        let path = std::env::temp_dir().join(format!(
            "northstar-component-secret-{}",
            Uuid::new_v4().simple()
        ));
        std::fs::write(&path, format!("{secret}\n")).expect("write test secret");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mut permissions = std::fs::metadata(&path)
                .expect("read test secret metadata")
                .permissions();
            permissions.set_mode(0o600);
            std::fs::set_permissions(&path, permissions).expect("restrict test secret permissions");
        }
        let credential = credential(secret, path.clone());
        let stream_id = "0123456789abcdef";
        let mut digest = Sha1::new();
        digest.update(stream_id.as_bytes());
        digest.update(secret.as_bytes());
        let response = digest
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert!(verify_legacy_handshake(
            &credential,
            stream_id,
            &format!("<handshake xmlns='{COMPONENT_ACCEPT_NS}'>{response}</handshake>")
        )
        .expect("verify handshake"));
        assert!(!verify_legacy_handshake(
            &credential,
            stream_id,
            &format!(
                "<handshake xmlns='{COMPONENT_ACCEPT_NS}'>{}</handshake>",
                "00".repeat(20)
            )
        )
        .expect("reject handshake"));
        assert!(!verify_legacy_handshake(
            &credential,
            stream_id,
            &format!("<handshake xmlns='urn:example:forged'>{response}</handshake>")
        )
        .expect("reject forged namespace"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn modern_plain_binds_authentication_to_primary_domain() {
        let secret = "this-is-a-32-byte-or-longer-component-secret";
        let credential = credential(secret, std::path::PathBuf::new());
        let valid = STANDARD.encode(format!("\0gateway.example\0{secret}"));
        assert!(verify_modern_plain(
            &credential,
            &format!("<auth xmlns='{SASL_NS}' mechanism='PLAIN'>{valid}</auth>")
        )
        .expect("verify SASL PLAIN"));
        let forged = STANDARD.encode(format!("\0other.example\0{secret}"));
        assert!(!verify_modern_plain(
            &credential,
            &format!("<auth xmlns='{SASL_NS}' mechanism='PLAIN'>{forged}</auth>")
        )
        .expect("reject forged identity"));
        assert!(!verify_modern_plain(
            &credential,
            &format!("<auth xmlns='{SASL_NS}' mechanism='PLAIN' forged='true'>{valid}</auth>")
        )
        .expect("reject extra SASL attribute"));
        assert!(!verify_modern_plain(
            &credential,
            &format!("<auth xmlns='{SASL_NS}' mechanism='PLAIN'>{valid}<extra/></auth>")
        )
        .expect("reject SASL child element"));
    }

    #[test]
    fn component_stanza_shape_is_strict_before_remote_routing() {
        for valid in [
            "<message xmlns='jabber:client' from='a.example' to='b.example'/>",
            "<presence xmlns='jabber:client' from='a.example' to='b.example' type='probe'/>",
            "<iq xmlns='jabber:client' from='a.example' to='b.example' type='get' id='i'><ping xmlns='urn:xmpp:ping'/></iq>",
        ] {
            let document = Document::parse(valid).unwrap();
            assert_eq!(invalid_component_stanza(document.root_element()), None);
        }
        for invalid in [
            "<message xmlns='jabber:client' from='a.example' to='b.example' type='invalid'/>",
            "<presence xmlns='jabber:client' from='a.example' to='b.example' type='available'/>",
            "<iq xmlns='jabber:client' from='a.example' to='b.example' type='get' id='i'/>",
            "<iq xmlns='jabber:client' from='a.example' to='b.example' type='set' id='i'><a/><b/></iq>",
            "<iq xmlns='jabber:client' from='a.example' to='b.example' type='result'/>",
        ] {
            let document = Document::parse(invalid).unwrap();
            assert_eq!(
                invalid_component_stanza(document.root_element()),
                Some("bad-request"),
                "accepted {invalid}"
            );
        }
    }

    #[test]
    fn fatal_component_frames_are_classified_as_stream_errors() {
        assert_eq!(
            component_frame_stream_error("<message xmlns='jabber:client'/>"),
            None
        );
        assert_eq!(
            component_frame_stream_error("<handshake xmlns='jabber:component:accept'/>"),
            Some("unsupported-stanza-type")
        );
        assert_eq!(
            component_frame_stream_error("<message><broken></message>"),
            Some("not-well-formed")
        );
        assert!(is_component_stream_error(
            "<stream:error xmlns:stream='http://etherx.jabber.org/streams'><policy-violation xmlns='urn:ietf:params:xml:ns:xmpp-streams'/></stream:error>"
        ));
    }

    #[test]
    fn component_error_stanzas_never_create_error_loops() {
        let document = Document::parse(
            "<message xmlns='jabber:client' from='a.example' to='b.example' type='error'><error type='cancel'/></message>",
        )
        .unwrap();
        assert_eq!(
            component_stanza_error(document.root_element(), "not-authorized"),
            None
        );
    }

    #[test]
    fn rejected_remote_component_route_uses_the_standard_condition() {
        let document = Document::parse(
            "<message xmlns='jabber:client' id='relay' from='gateway.example' to='user@denied.example'><body>blocked</body></message>",
        )
        .unwrap();
        let error = component_stanza_error(document.root_element(), "remote-server-not-found")
            .expect("ordinary stanza must be reflected as an error");
        assert!(error
            .contains("<remote-server-not-found xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>"));
        assert!(!error.contains("undefined-condition"));
    }

    #[test]
    fn unregistering_one_connection_never_removes_another_incarnation() {
        let registry = registry();
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        let (sender, _receiver) = mpsc::channel(1);
        registry
            .register_domain("gateway.example", second, sender)
            .unwrap();
        registry.remove_connection(first);
        assert!(registry.connection_owns_domain("gateway.example", second));
    }
}
