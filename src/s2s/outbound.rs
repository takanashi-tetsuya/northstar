use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use futures::{stream::FuturesUnordered, FutureExt, StreamExt};
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, Ordering};
use subtle::ConstantTimeEq;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::TlsConnector;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const IO_TIMEOUT: Duration = Duration::from_secs(15);
const VOLATILE_DELIVERY_TIMEOUT: Duration = Duration::from_secs(16);
const HAPPY_EYEBALLS_DELAY: Duration = Duration::from_millis(250);
const HAPPY_EYEBALLS_MAX_IN_FLIGHT: usize = 4;

pub(crate) type SecureS2sConnection = (
    tokio_rustls::client::TlsStream<TcpStream>,
    String,
    String,
    S2sInputState,
    Vec<tokio_rustls::rustls::pki_types::CertificateDer<'static>>,
    u64,
);

fn happy_eyeballs_delay(candidate_index: usize) -> Duration {
    HAPPY_EYEBALLS_DELAY.saturating_mul(candidate_index.min(u32::MAX as usize) as u32)
}

use crate::{
    db,
    jid::{prepare_domainpart, CanonicalJid},
    state::AppState,
    xmpp::xml_builder::XmlElement,
};
use anyhow::{Context, Result};
use roxmltree::Document;
use std::{future::Future, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};

use super::*;

use tokio::sync::mpsc;

#[derive(Debug)]
struct PeerStanzaLimitExceeded {
    serialized_bytes: usize,
    peer_max_bytes: usize,
}

#[derive(Debug)]
enum DialbackAuthorizationFailure {
    Invalid,
    Error(String),
}

fn same_s2s_domain(left: &str, right: &str) -> bool {
    matches!(
        (prepare_domainpart(left), prepare_domainpart(right)),
        (Ok(left), Ok(right)) if left == right
    )
}

impl std::fmt::Display for PeerStanzaLimitExceeded {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "serialized federation stanza is {} bytes, exceeding the peer-advertised XEP-0478 max-bytes of {}",
            self.serialized_bytes, self.peer_max_bytes
        )
    }
}

impl std::error::Error for PeerStanzaLimitExceeded {}

impl DialbackAuthorizationFailure {
    fn bounce_condition(&self) -> &'static str {
        match self {
            Self::Invalid => "internal-server-error",
            Self::Error(_) => "remote-server-timeout",
        }
    }
}

impl std::fmt::Display for DialbackAuthorizationFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid => formatter.write_str("authoritative server rejected XEP-0220 dialback"),
            Self::Error(condition) => write!(
                formatter,
                "authoritative server returned XEP-0220 dialback error {condition}"
            ),
        }
    }
}

impl std::error::Error for DialbackAuthorizationFailure {}

pub(crate) fn is_peer_stanza_limit_error(error: &anyhow::Error) -> bool {
    error.downcast_ref::<PeerStanzaLimitExceeded>().is_some()
}

fn is_dialback_authorization_error(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<DialbackAuthorizationFailure>()
        .is_some()
}

fn outbound_cancellation_message(server_shutting_down: bool, phase: &str) -> String {
    if server_shutting_down {
        format!("outbound S2S connection closed during server shutdown{phase}")
    } else {
        format!("outbound S2S certificate was explicitly revoked{phase}")
    }
}

fn outbound_cancellation_error(state: &AppState, phase: &str) -> anyhow::Error {
    anyhow::anyhow!(outbound_cancellation_message(
        state.connection_actors().shutdown_token().is_cancelled(),
        phase,
    ))
}

pub(crate) fn get_or_create_outbound(
    state: &Arc<AppState>,
    source_domain: &str,
    target_domain: &str,
) -> Option<mpsc::Sender<FederationEnvelope>> {
    let source_domain = prepare_domainpart(source_domain).ok()?;
    let target_domain = prepare_domainpart(target_domain).ok()?;
    let connection_key = format!("{source_domain}\0{target_domain}");
    if let Some(sender) = state
        .s2s_connection_registry()
        .live_outbound_sender(&connection_key)
    {
        return Some(sender);
    }
    let connection_permit = state.try_acquire_s2s_connection().ok()?;
    let (tx, rx) = mpsc::channel(256);
    let connection_id = uuid::Uuid::new_v4();
    let actors = state.connection_actors().clone();
    let disconnect = actors.shutdown_token().child_token();
    let session = OutboundS2sSession::new(tx.clone());
    let authenticated = session.authenticated_flag();
    match state
        .s2s_connection_registry()
        .register_outbound(connection_key.clone(), session)
    {
        OutboundRegistration::Existing(sender) => return Some(sender),
        OutboundRegistration::Inserted => {}
    }
    let state_clone = Arc::clone(state);
    let domain_clone = target_domain.clone();
    let source_clone = source_domain.clone();
    let connection_key_clone = connection_key.clone();
    let worker_sender = tx.clone();
    let actor = async move {
        let _connection_permit = connection_permit;
        let result = AssertUnwindSafe(run_outbound_connection(
            Arc::clone(&state_clone),
            source_clone,
            domain_clone.clone(),
            rx,
            Arc::clone(&authenticated),
            connection_id,
            disconnect,
        ))
        .catch_unwind()
        .await;
        match &result {
            Ok(Err(error))
                if state_clone
                    .connection_actors()
                    .shutdown_token()
                    .is_cancelled() =>
            {
                // The actor's cancellation token is a child of the global
                // connection-registry token, so an orderly process shutdown
                // reaches the same select branches as a live CRL revocation.
                // Shutdown is expected lifecycle, not a federation failure.
                tracing::debug!(
                    domain = %domain_clone,
                    ?error,
                    "federation outbound connection closed during server shutdown"
                );
            }
            Ok(Err(error)) => {
                state_clone
                    .metrics
                    .federation_failures_total
                    .fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    domain = %domain_clone,
                    ?error,
                    "federation outbound connection failed or closed"
                );
            }
            Err(_) => {
                state_clone
                    .metrics
                    .federation_failures_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            Ok(Ok(())) => {}
        }
        authenticated.store(false, Ordering::Release);
        state_clone
            .s2s_connection_registry()
            .remove_outbound_if_sender(&connection_key_clone, &worker_sender);
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    };
    if let Err(error) = actors.try_spawn(
        crate::connection_actors::ConnectionActorKind::S2sOutbound,
        Some(target_domain.clone()),
        actor,
    ) {
        state
            .s2s_connection_registry()
            .remove_outbound_if_sender(&connection_key, &tx);
        tracing::debug!(domain = %target_domain, ?error, "rejected outbound S2S actor admission");
        return None;
    }
    Some(tx)
}

/// Deliver a stanza only through an already authenticated S2S stream.
///
/// This path deliberately has no PostgreSQL outbox projection and never
/// creates a new connection. It is used for XEP-0334 `no-store` messages:
/// callers receive `false` when no live route accepts the stanza, when the
/// bounded queue is saturated, or when the socket write does not complete.
pub(crate) async fn send_volatile_on_authenticated_route(
    state: &AppState,
    source_domain: &str,
    target_domain: &str,
    stanza: String,
) -> bool {
    let Ok(source_domain) = prepare_domainpart(source_domain) else {
        return false;
    };
    let Ok(target_domain) = prepare_domainpart(target_domain) else {
        return false;
    };
    if state.island_mode_enabled() || !state.federation_domain_allowed(&target_domain) {
        return false;
    }
    let target_entity_allowed = Document::parse(&stanza).ok().is_some_and(|document| {
        document
            .root_element()
            .attribute("to")
            .is_some_and(|target| state.federation_entity_allowed(target))
    });
    if !target_entity_allowed {
        return false;
    }
    // Reserve one extra second for the write task to publish its completion
    // after its stricter socket deadline. This removes the race where the C2S
    // caller could be told failure at the same instant the peer received it.
    let deadline = tokio::time::Instant::now() + IO_TIMEOUT;
    let (envelope, completion) =
        FederationEnvelope::volatile(target_domain.clone(), stanza, deadline);
    if !bidi_envelope_authorized(&envelope, &source_domain) {
        return false;
    }
    let mut envelope = Some(envelope);
    let mut accepted = false;

    if let Some(route_key) = bidi_connection_key(&source_domain, &target_domain) {
        if let Some(route) = state
            .s2s_connection_registry()
            .bidirectional_route(&route_key)
        {
            let candidate = envelope.take().expect("volatile envelope is present");
            match route.sender.try_send(candidate) {
                Ok(()) => accepted = true,
                Err(error) => envelope = Some(error.into_inner()),
            }
        }
    }

    if !accepted {
        let connection_key = format!("{source_domain}\0{target_domain}");
        if let Some(sender) = state
            .s2s_connection_registry()
            .authenticated_outbound_sender(&connection_key)
        {
            let candidate = envelope.take().expect("volatile envelope is present");
            match sender.try_send(candidate) {
                Ok(()) => accepted = true,
                Err(error) => drop(error.into_inner()),
            }
        }
    }

    if !accepted {
        return false;
    }
    matches!(
        tokio::time::timeout(VOLATILE_DELIVERY_TIMEOUT, completion).await,
        Ok(Ok(()))
    )
}

async fn run_outbound_connection(
    state: Arc<AppState>,
    source_domain: String,
    target_domain: String,
    mut rx: mpsc::Receiver<FederationEnvelope>,
    authenticated: Arc<AtomicBool>,
    connection_id: uuid::Uuid,
    disconnect: tokio_util::sync::CancellationToken,
) -> Result<()> {
    let Some(mut first) = rx.recv().await else {
        return Ok(());
    };
    if !first.is_durable() {
        anyhow::bail!(
            "an unauthenticated federation connection cannot be opened by volatile delivery"
        );
    }
    let mut first_delivered = false;
    let lease_valid = Arc::new(AtomicBool::new(true));
    let lease_cancel = tokio_util::sync::CancellationToken::new();
    let lease_task = tokio::spawn(renew_first_envelope_lease(
        Arc::clone(&state),
        first.outbox_id,
        first.lock_token,
        Arc::clone(&lease_valid),
        lease_cancel.clone(),
        disconnect.clone(),
    ));
    let initial = InitialDelivery {
        envelope: &mut first,
        delivered: &mut first_delivered,
        lease_valid: &lease_valid,
        lease_cancel: &lease_cancel,
    };
    let result = connect_and_multiplex(
        &state,
        &source_domain,
        &target_domain,
        &mut rx,
        initial,
        &authenticated,
        connection_id,
        disconnect,
    )
    .await;
    lease_cancel.cancel();
    let mut lease_task = lease_task;
    match tokio::time::timeout(Duration::from_secs(1), &mut lease_task).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            tracing::error!(?error, "S2S outbox lease-renewal task panicked");
        }
        Err(_) => {
            tracing::error!("S2S outbox lease-renewal task ignored cancellation; aborting");
            lease_task.abort();
            match tokio::time::timeout(Duration::from_secs(1), &mut lease_task).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) if error.is_cancelled() => {}
                Ok(Err(error)) => {
                    tracing::error!(?error, "aborted S2S lease-renewal task panicked");
                }
                Err(_) => {
                    tracing::error!("aborted S2S lease-renewal task could not be reaped");
                }
            }
        }
    }
    if let Err(error) = &result {
        // Island mode is an operational pause, not a permanent destination
        // denial. Durable rows must return to the retryable outbox so they can
        // resume after the kill switch is lifted.
        let permanent = !state.federation_domain_allowed(&target_domain)
            || is_peer_stanza_limit_error(error)
            || is_dialback_authorization_error(error);
        if !first_delivered {
            fail_envelope(&state, &first, error, permanent).await;
        }
        while let Ok(envelope) = rx.try_recv() {
            fail_envelope(&state, &envelope, error, permanent).await;
        }
    }
    result
}

async fn renew_first_envelope_lease(
    state: Arc<AppState>,
    outbox_id: uuid::Uuid,
    lock_token: uuid::Uuid,
    lease_valid: Arc<AtomicBool>,
    cancel: tokio_util::sync::CancellationToken,
    disconnect: tokio_util::sync::CancellationToken,
) {
    let interval_seconds = (state.config.s2s_outbox_lease_seconds / 3).max(1);
    let database_deadline = Duration::from_secs(interval_seconds.min(5));
    let mut interval = tokio::time::interval(Duration::from_secs(interval_seconds));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // The claim itself established the first lease; do not issue an
    // immediate redundant write on interval's initial ready tick.
    interval.tick().await;
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return,
            _ = disconnect.cancelled() => return,
            _ = interval.tick() => {
                let renewal = db::renew_s2s_outbox_lease(
                    &state.pool,
                    outbox_id,
                    lock_token,
                    state.config.s2s_outbox_lease_seconds,
                );
                tokio::pin!(renewal);
                let result = tokio::select! {
                    biased;
                    _ = cancel.cancelled() => return,
                    _ = disconnect.cancelled() => return,
                    result = tokio::time::timeout(database_deadline, &mut renewal) => result,
                };
                match result {
                    Ok(Ok(true)) => {}
                    Ok(Ok(false)) => {
                        lease_valid.store(false, Ordering::Release);
                        tracing::warn!(%outbox_id, "federation outbox lease was lost during connection setup");
                        return;
                    }
                    Ok(Err(error)) => {
                        lease_valid.store(false, Ordering::Release);
                        tracing::error!(%outbox_id, ?error, "could not renew federation outbox lease during connection setup");
                        return;
                    }
                    Err(_) => {
                        lease_valid.store(false, Ordering::Release);
                        tracing::error!(%outbox_id, ?database_deadline, "federation outbox lease renewal exceeded its database deadline");
                        return;
                    }
                }
            }
        }
    }
}

struct InitialDelivery<'a> {
    envelope: &'a mut FederationEnvelope,
    delivered: &'a mut bool,
    lease_valid: &'a AtomicBool,
    lease_cancel: &'a tokio_util::sync::CancellationToken,
}

#[allow(clippy::too_many_arguments)]
async fn connect_and_multiplex(
    state: &Arc<AppState>,
    source_domain: &str,
    target_domain: &str,
    rx: &mut mpsc::Receiver<FederationEnvelope>,
    initial: InitialDelivery<'_>,
    authenticated: &AtomicBool,
    connection_id: uuid::Uuid,
    disconnect: tokio_util::sync::CancellationToken,
) -> Result<()> {
    let result = AssertUnwindSafe(connect_and_multiplex_inner(
        state,
        source_domain,
        target_domain,
        connection_id,
        rx,
        initial,
        authenticated,
        disconnect,
    ))
    .catch_unwind()
    .await;
    let cleanup = AssertUnwindSafe(
        crate::xmpp::protocol::federated_muc::federated_muc_connection_closed(
            state,
            target_domain,
            connection_id,
        ),
    )
    .catch_unwind()
    .await;
    match result {
        Ok(result) => match cleanup {
            Ok(Ok(())) => result,
            Ok(Err(error)) => {
                tracing::warn!(
                    peer_domain = %target_domain,
                    %connection_id,
                    ?error,
                    "failed to clean up federated MUC occupants after outbound S2S disconnect"
                );
                result
            }
            Err(panic) => std::panic::resume_unwind(panic),
        },
        Err(panic) => {
            match cleanup {
                Ok(Ok(())) => {}
                Ok(Err(error)) => tracing::warn!(
                    peer_domain = %target_domain,
                    %connection_id,
                    ?error,
                    "failed to clean up federated MUC occupants after outbound S2S actor panic"
                ),
                Err(_) => tracing::error!(
                    peer_domain = %target_domain,
                    %connection_id,
                    "federated MUC cleanup also panicked while unwinding an outbound S2S actor panic"
                ),
            }
            std::panic::resume_unwind(panic)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn connect_and_multiplex_inner(
    state: &Arc<AppState>,
    source_domain: &str,
    target_domain: &str,
    connection_id: uuid::Uuid,
    rx: &mut mpsc::Receiver<FederationEnvelope>,
    initial: InitialDelivery<'_>,
    authenticated: &AtomicBool,
    disconnect: tokio_util::sync::CancellationToken,
) -> Result<()> {
    if state.island_mode_enabled() || !state.federation_domain_allowed(target_domain) {
        anyhow::bail!("target domain is denied by federation policy");
    }
    let (mut secure, mut opening, mut features, mut input, peer_certificates, tls_generation) =
        connect_secure_stream_from(state, source_domain, target_domain).await?;
    let mut peer_limits = advertised_stream_limits(&features).unwrap_or_default();
    let external = state.config.s2s_sasl_external_enabled && sasl_external_advertised(&features);
    let bidi_enabled;
    if external {
        bidi_enabled = request_bidi_if_advertised(&mut secure, &features).await?;
        let authorization = STANDARD.encode(source_domain.as_bytes());
        write_xml(
            &mut secure,
            &crate::xmpp::xml_builder::XmlElement::new("auth")
                .attr("xmlns", "urn:ietf:params:xml:ns:xmpp-sasl")
                .attr("mechanism", "EXTERNAL")
                .text(authorization)
                .finish(),
        )
        .await?;
        let success = timed_read_frame(&mut secure, &mut input).await?;
        if valid_empty_negotiation_element(&success, "success", "urn:ietf:params:xml:ns:xmpp-sasl")
        {
            input.reset_entity();
            write_xml(&mut secure, &client_open(source_domain, target_domain)).await?;
            opening = timed_read_frame(&mut secure, &mut input).await?;
            features = timed_read_frame(&mut secure, &mut input).await?;
            peer_limits = advertised_stream_limits(&features).unwrap_or_default();
            validate_stream_identity(source_domain, target_domain, &opening)?;
        } else {
            // Once a PKIX-authenticated peer advertises EXTERNAL, falling
            // back to Dialback after rejection would permit an active
            // downgrade. Dialback remains available only when EXTERNAL was
            // not advertised in the first place.
            anyhow::bail!("remote server rejected SASL EXTERNAL");
        }
    } else {
        bidi_enabled = request_bidi_if_advertised(&mut secure, &features).await?;
        authenticate_dialback_outbound(
            state,
            source_domain,
            target_domain,
            &mut secure,
            &opening,
            &features,
            &mut input,
        )
        .await?;
    }

    let _certificate_session = if external {
        Some(state.tls.register_certificate_session(
            connection_id,
            crate::tls::CertificateSessionKind::OutboundS2s,
            peer_certificates,
            tls_generation,
            disconnect.clone(),
        )?)
    } else {
        None
    };
    if disconnect.is_cancelled() {
        return Err(outbound_cancellation_error(state, " before delivery"));
    }

    // Only this post-authentication state may accept an ephemeral stanza.
    // The worker clears the flag before removing its route entry.
    authenticated.store(true, Ordering::Release);

    let keepalive_period = keepalive_interval_for_peer(peer_limits);
    let mut keepalive_interval = tokio::time::interval_at(
        tokio::time::Instant::now() + keepalive_period,
        keepalive_period,
    );
    keepalive_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut incoming_idle_deadline = tokio::time::Instant::now() + S2S_AUTHENTICATED_IDLE_TIMEOUT;

    if !initial.lease_valid.load(Ordering::Acquire) {
        anyhow::bail!("federation outbox lease was lost before first delivery");
    }
    tokio::select! {
        biased;
        _ = disconnect.cancelled() => {
            return Err(outbound_cancellation_error(state, " before first delivery"));
        }
        result = deliver_envelope(state, &mut secure, initial.envelope, peer_limits.max_bytes) => {
            result?;
        }
    }
    keepalive_interval.reset_after(keepalive_period);
    *initial.delivered = true;
    initial.lease_cancel.cancel();

    loop {
        tokio::select! {
            _ = disconnect.cancelled() => {
                let _ = send_stream_error(&mut secure, "not-authorized").await;
                return Err(outbound_cancellation_error(state, ""));
            }
            _ = keepalive_interval.tick() => {
                if let Err(e) = write_xml(&mut secure, " ").await {
                    anyhow::bail!("keepalive failed: {}", e);
                }
            }
            envelope = rx.recv() => {
                let Some(mut envelope) = envelope else { break };
                if let Err(error) = deliver_envelope(state, &mut secure, &mut envelope, peer_limits.max_bytes).await {
                    let permanent = is_peer_stanza_limit_error(&error);
                    fail_envelope(state, &envelope, &error, permanent).await;
                    if permanent {
                        continue;
                    }
                    return Err(error);
                }
                keepalive_interval.reset_after(keepalive_period);
            }
            frame = read_frame_until_idle_deadline(
                &mut secure,
                &mut input,
                S2S_AUTHENTICATED_IDLE_TIMEOUT,
                &mut incoming_idle_deadline,
            ) => {
                let frame = match frame {
                    Ok(Some(frame)) => frame,
                    Ok(None) => {
                        tracing::debug!(peer_domain = target_domain, "closed idle authenticated outbound S2S stream");
                        break;
                    }
                    Err(error) => {
                        if let Some(condition) = s2s_read_stream_error_condition(&error) {
                            let _ = send_stream_error(&mut secure, condition).await;
                        }
                        return Err(error);
                    }
                };
                if frame.starts_with("</stream:stream") {
                    break;
                }
                if let Some(condition) = peer_stream_error_condition(&frame) {
                    anyhow::bail!("remote S2S stream error: {condition}");
                }
                if !bidi_enabled {
                    send_stream_error(&mut secure, "unexpected-request").await?;
                    anyhow::bail!("remote sent a stanza on a unidirectional S2S connection");
                }
                match route_inbound_for_connection(
                    state,
                    target_domain,
                    source_domain,
                    connection_id,
                    &frame,
                )
                .await?
                {
                    InboundFederationRoute::Reply(Some(reply)) => {
                        if let Some(reply) = super::inbound::reply_within_peer_limit(
                            &reply,
                            &frame,
                            peer_limits.max_bytes,
                        )? {
                            write_xml(&mut secure, &reply).await?;
                            keepalive_interval.reset_after(keepalive_period);
                        }
                    }
                    InboundFederationRoute::Reply(None) => {}
                    InboundFederationRoute::StreamError(condition) => {
                        send_stream_error(&mut secure, condition).await?;
                        anyhow::bail!("remote S2S stanza violated stream addressing: {condition}");
                    }
                }
            }
        }
    }

    write_xml(&mut secure, &XmlElement::new("stream:stream").close()).await?;
    secure.shutdown().await?;
    Ok(())
}

pub(crate) async fn deliver_envelope<S: AsyncWrite + Unpin>(
    state: &AppState,
    secure: &mut S,
    envelope: &mut FederationEnvelope,
    peer_max_bytes: Option<usize>,
) -> Result<()> {
    let _delivery_timer = envelope
        .is_durable()
        .then(|| state.metrics.outbox_delivery_duration_seconds.start_timer());
    let serialized = serialize_for_peer(&envelope.stanza, peer_max_bytes)?;
    // Route admission can race an administrator enabling island mode. Hold
    // the shared side of the policy gate only for the socket-write boundary;
    // the exclusive transition waits for an in-flight write and prevents any
    // already-cloned sender or queued envelope from writing afterwards.
    let delivery_permit = state
        .federation_delivery_permit()
        .await
        .context("federation delivery is disabled by island mode")?;
    if let Some(write_budget) = envelope.volatile_write_budget() {
        if write_budget.is_zero() {
            // The originating C2S request has already timed out or gone
            // away. Dropping the volatile envelope preserves no-store and
            // avoids a late write after the sender was told delivery failed.
            return Ok(());
        }
        tokio::time::timeout(write_budget, write_xml(secure, &serialized))
            .await
            .context("volatile federation delivery deadline elapsed")??;
    } else {
        write_xml(secure, &serialized)
            .await
            .context("failed to write federation envelope")?;
    }
    drop(delivery_permit);
    if envelope.is_durable() {
        if !db::complete_s2s_outbox(&state.pool, envelope.outbox_id, envelope.lock_token).await? {
            state
                .metrics
                .s2s_outbox_lease_lost_total
                .fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                outbox_id = %envelope.outbox_id,
                domain = %envelope.target_domain,
                "federation stanza was written after its outbox lease was lost; delivery may be duplicated"
            );
        }
    } else {
        envelope.complete_volatile_delivery();
    }
    state
        .metrics
        .federation_outbound_deliveries_total
        .fetch_add(1, Ordering::Relaxed);
    Ok(())
}

pub(crate) fn serialize_for_peer(stanza: &str, peer_max_bytes: Option<usize>) -> Result<String> {
    let serialized = server_namespace(stanza);
    if let Some(peer_max_bytes) = peer_max_bytes {
        if serialized.len() > peer_max_bytes {
            return Err(PeerStanzaLimitExceeded {
                serialized_bytes: serialized.len(),
                peer_max_bytes,
            }
            .into());
        }
    }
    Ok(serialized)
}

pub(crate) async fn fail_envelope(
    state: &AppState,
    envelope: &FederationEnvelope,
    error: &anyhow::Error,
    permanent: bool,
) {
    if !envelope.is_durable() {
        return;
    }
    let bounce_condition = error
        .downcast_ref::<DialbackAuthorizationFailure>()
        .map(DialbackAuthorizationFailure::bounce_condition)
        .unwrap_or_else(|| {
            if is_peer_stanza_limit_error(error) {
                "policy-violation"
            } else {
                "remote-server-not-found"
            }
        });
    let item = db::S2sOutboxItem {
        id: envelope.outbox_id,
        target_domain: envelope.target_domain.clone(),
        bounce_to: envelope.bounce_to.clone(),
        stanza: envelope.stanza.clone(),
        attempt_count: envelope.attempt_count,
        lock_token: envelope.lock_token,
    };
    match db::fail_s2s_outbox(
        &state.pool,
        &item,
        &format!("{error:#}"),
        state.config.s2s_outbox_retry_base_seconds,
        state.config.s2s_outbox_retry_max_seconds,
        state.config.s2s_outbox_max_attempts,
        permanent,
    )
    .await
    {
        Ok(db::S2sFailureDisposition::Dropped) => {
            state
                .metrics
                .s2s_outbox_permanent_failures_total
                .fetch_add(1, Ordering::Relaxed);
            bounce_delivery_failure_with_condition(state, envelope, bounce_condition);
        }
        Ok(db::S2sFailureDisposition::Expired) => {
            state
                .metrics
                .s2s_outbox_expired_total
                .fetch_add(1, Ordering::Relaxed);
            bounce_delivery_failure_with_condition(state, envelope, bounce_condition);
        }
        Ok(db::S2sFailureDisposition::RetryScheduled) => {
            state
                .metrics
                .s2s_outbox_retries_total
                .fetch_add(1, Ordering::Relaxed);
        }
        Ok(db::S2sFailureDisposition::LeaseLost) => {
            state
                .metrics
                .s2s_outbox_lease_lost_total
                .fetch_add(1, Ordering::Relaxed);
        }
        Err(database_error) => tracing::error!(
            outbox_id = %envelope.outbox_id,
            ?database_error,
            "failed to update federation outbox retry state"
        ),
    }
}

pub(crate) async fn connect_secure_stream_from(
    state: &AppState,
    source_domain: &str,
    target_domain: &str,
) -> Result<SecureS2sConnection> {
    let source_domain =
        prepare_domainpart(source_domain).context("invalid local federation domain")?;
    let target_domain =
        prepare_domainpart(target_domain).context("invalid remote federation domain")?;
    if state.island_mode_enabled() || !state.federation_domain_allowed(&target_domain) {
        anyhow::bail!("target domain is denied by federation policy");
    }
    let endpoints = resolve_federation_endpoints(state, &target_domain).await?;
    let mut last_error = None;
    let mut group_start = 0;
    while group_start < endpoints.len() {
        let first = &endpoints[group_start];
        let mut group_end = group_start + 1;
        while group_end < endpoints.len()
            && endpoints[group_end].selection_group == first.selection_group
            && endpoints[group_end].direct_tls == first.direct_tls
        {
            group_end += 1;
        }
        match connect_secure_endpoint_group(
            state,
            &source_domain,
            &target_domain,
            &endpoints[group_start..group_end],
        )
        .await
        {
            Ok(connection) => return Ok(connection),
            Err(error) => {
                tracing::debug!(%target_domain, selection_group = first.selection_group, direct_tls = first.direct_tls, ?error, "federation endpoint group failed");
                last_error = Some(error);
            }
        }
        group_start = group_end;
    }
    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("DNS returned no federation endpoints")))
}

async fn connect_secure_endpoint_group(
    state: &AppState,
    source_domain: &str,
    target_domain: &str,
    endpoints: &[FederationEndpoint],
) -> Result<SecureS2sConnection> {
    race_happy_eyeballs(endpoints, |endpoint| {
        async move {
            let _global_permit =
                tokio::time::timeout(CONNECT_TIMEOUT, state.acquire_s2s_connection_attempt())
                    .await
                    .context("global S2S connection-attempt limiter timed out")?
                    .context("global S2S connection-attempt limiter closed")?;
            // Revalidate immediately before connect so resolver/cache changes
            // cannot bypass the DNS-rebinding and private-network boundary.
            validate_endpoint(state, endpoint.address)?;
            connect_secure_endpoint(state, source_domain, target_domain, &endpoint).await
        }
    })
    .await
}

async fn race_happy_eyeballs<T, Attempt, AttemptFuture>(
    endpoints: &[FederationEndpoint],
    attempt: Attempt,
) -> Result<T>
where
    Attempt: Fn(FederationEndpoint) -> AttemptFuture + Clone,
    AttemptFuture: Future<Output = Result<T>>,
{
    let per_worker_permits = Arc::new(tokio::sync::Semaphore::new(HAPPY_EYEBALLS_MAX_IN_FLIGHT));
    let mut attempts = FuturesUnordered::new();
    for (index, endpoint) in happy_eyeballs_endpoint_order(endpoints)
        .into_iter()
        .enumerate()
    {
        let per_worker_permits = Arc::clone(&per_worker_permits);
        let attempt = attempt.clone();
        attempts.push(async move {
            if index != 0 {
                tokio::time::sleep(happy_eyeballs_delay(index)).await;
            }
            let _worker_permit = per_worker_permits
                .acquire_owned()
                .await
                .context("Happy Eyeballs connection limiter closed")?;
            let result = attempt(endpoint.clone()).await;
            Ok::<_, anyhow::Error>((endpoint, result))
        });
    }
    let mut last_error = None;
    while let Some(attempt) = attempts.next().await {
        let (endpoint, result) = attempt?;
        match result {
            Ok(connection) => return Ok(connection),
            Err(error) => {
                tracing::debug!(address = %endpoint.address, direct_tls = endpoint.direct_tls, ?error, "federation Happy Eyeballs candidate failed");
                last_error = Some(error);
            }
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("empty federation endpoint group")))
}

fn happy_eyeballs_endpoint_order(endpoints: &[FederationEndpoint]) -> Vec<FederationEndpoint> {
    let mut v4 = endpoints
        .iter()
        .filter(|endpoint| endpoint.address.is_ipv4())
        .cloned()
        .collect::<Vec<_>>()
        .into_iter();
    let mut v6 = endpoints
        .iter()
        .filter(|endpoint| endpoint.address.is_ipv6())
        .cloned()
        .collect::<Vec<_>>()
        .into_iter();
    let prefer_v6 = endpoints
        .first()
        .is_none_or(|endpoint| endpoint.address.is_ipv6());
    let mut ordered = Vec::with_capacity(endpoints.len());
    loop {
        let (first, second) = if prefer_v6 {
            (v6.next(), v4.next())
        } else {
            (v4.next(), v6.next())
        };
        if first.is_none() && second.is_none() {
            break;
        }
        ordered.extend(first);
        ordered.extend(second);
    }
    ordered
}

async fn connect_secure_endpoint(
    state: &AppState,
    source_domain: &str,
    target_domain: &str,
    endpoint: &FederationEndpoint,
) -> Result<SecureS2sConnection> {
    let dane_policy = if state.config.federation_dane_mode == crate::s2s::dane::DaneMode::Off {
        None
    } else {
        let resolver = state
            .s2s_dnssec_resolver()
            .context("DANE is enabled but the validating DNSSEC resolver is unavailable")?;
        crate::s2s::dane::lookup_dane_policy(
            resolver,
            state.config.federation_dane_mode,
            endpoint
                .dane_srv_binding
                .as_ref()
                .map_or(endpoint.tls_server_name.as_str(), |binding| {
                    binding.target()
                }),
            endpoint.address.port(),
            endpoint.address.ip(),
            endpoint.dane_srv_binding.as_ref(),
        )
        .await?
    };
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(endpoint.address))
        .await
        .context("S2S TCP connection timed out")??;
    stream.set_nodelay(true)?;
    let mut stream = stream;
    let mut input = S2sInputState::default();
    let server_name = ServerName::try_from(endpoint.tls_server_name.clone())
        .context("invalid federation TLS SNI domain")?;
    let (secure, tls_generation) = if endpoint.direct_tls {
        let (config, tls_generation) =
            s2s_client_config(state, true, &endpoint.public_key_pins, dane_policy.as_ref())?;
        let connector = TlsConnector::from(config);
        let secure = tokio::time::timeout(IO_TIMEOUT, connector.connect(server_name, stream))
            .await
            .context("outbound S2S Direct TLS handshake timed out")??;
        (secure, tls_generation)
    } else {
        write_xml(&mut stream, &client_open(source_domain, target_domain)).await?;
        let _ = timed_read_frame(&mut stream, &mut input).await?;
        let features = timed_read_frame(&mut stream, &mut input).await?;
        if !stream_feature_advertised(&features, "starttls", "urn:ietf:params:xml:ns:xmpp-tls") {
            anyhow::bail!("remote server did not advertise STARTTLS");
        }
        write_xml(
            &mut stream,
            &XmlElement::namespaced("starttls", "urn:ietf:params:xml:ns:xmpp-tls").finish(),
        )
        .await?;
        let proceed = timed_read_frame(&mut stream, &mut input).await?;
        if !valid_empty_negotiation_element(&proceed, "proceed", "urn:ietf:params:xml:ns:xmpp-tls")
        {
            anyhow::bail!("remote server rejected STARTTLS");
        }
        let (config, tls_generation) = s2s_client_config(
            state,
            false,
            &endpoint.public_key_pins,
            dane_policy.as_ref(),
        )?;
        let connector = TlsConnector::from(config);
        let secure = tokio::time::timeout(IO_TIMEOUT, connector.connect(server_name, stream))
            .await
            .context("outbound S2S TLS handshake timed out")??;
        (secure, tls_generation)
    };
    if endpoint.direct_tls
        && secure
            .get_ref()
            .1
            .alpn_protocol()
            .is_some_and(|protocol| protocol != b"xmpp-server")
    {
        anyhow::bail!("remote S2S endpoint selected an invalid ALPN protocol");
    }
    let mut secure = secure;
    let peer_certificates = secure
        .get_ref()
        .1
        .peer_certificates()
        .context("remote S2S endpoint did not present a certificate")?
        .to_vec();
    let end_entity = peer_certificates
        .first()
        .context("remote S2S endpoint presented an empty certificate chain")?;
    let dane_matches = dane_policy
        .as_ref()
        .map(|policy| policy.matching_credentials(&peer_certificates))
        .transpose()?
        .unwrap_or_default();
    let dane_ee_authorized = dane_matches.contains(&crate::s2s::dane::DaneMatch::DaneEndEntity);
    let identity =
        verify_peer_xmpp_identity(end_entity, target_domain)?.or(if endpoint.delegated_identity {
            verify_peer_xmpp_identity(end_entity, &endpoint.tls_server_name)?
        } else {
            None
        });
    let presented_pin = peer_public_key_pin(end_entity)?;
    let pin_authorized = endpoint
        .public_key_pins
        .iter()
        .any(|expected| bool::from(expected.ct_eq(&presented_pin)));
    if identity.is_none() && !dane_ee_authorized && !(dane_policy.is_none() && pin_authorized) {
        anyhow::bail!(
            "remote S2S certificate identifies neither the XMPP domain nor its authenticated delegation"
        );
    }
    tracing::debug!(
        peer_domain = %target_domain,
        identity = ?identity,
        pin_authorized,
        dane = ?dane_matches,
        "authenticated outbound S2S certificate identity"
    );
    input.reset_entity();
    write_xml(&mut secure, &client_open(source_domain, target_domain)).await?;
    let opening = timed_read_frame(&mut secure, &mut input).await?;
    validate_stream_identity(source_domain, target_domain, &opening)?;
    let features = timed_read_frame(&mut secure, &mut input).await?;
    Ok((
        secure,
        opening,
        features,
        input,
        peer_certificates,
        tls_generation,
    ))
}

fn validate_stream_identity(source_domain: &str, target_domain: &str, opening: &str) -> Result<()> {
    if stream_attribute(opening, "from")
        .is_none_or(|domain| !same_s2s_domain(&domain, target_domain))
        || stream_attribute(opening, "to")
            .is_none_or(|domain| !same_s2s_domain(&domain, source_domain))
    {
        anyhow::bail!("remote S2S stream returned an invalid identity");
    }
    Ok(())
}

fn parseable_stream_features(feature_xml: &str) -> std::borrow::Cow<'_, str> {
    // Parser-only normalization: an extracted stream child inherits the
    // `stream` prefix from its opening stream. Restore that binding solely so
    // the already received frame can be parsed; this string is never emitted.
    const FEATURES_QNAME: &str = "stream:features";
    let opening_prefix = format!("<{FEATURES_QNAME}");
    if feature_xml.starts_with(&opening_prefix) && !feature_xml.contains("xmlns:stream=") {
        let parseable_prefix = format!(
            "{opening_prefix} xmlns:stream='{}'",
            "http://etherx.jabber.org/streams"
        );
        std::borrow::Cow::Owned(feature_xml.replacen(&opening_prefix, &parseable_prefix, 1))
    } else {
        std::borrow::Cow::Borrowed(feature_xml)
    }
}

fn stream_feature_advertised(feature_xml: &str, name: &str, namespace: &str) -> bool {
    let parseable = parseable_stream_features(feature_xml);
    Document::parse(parseable.as_ref()).is_ok_and(|document| {
        let root = document.root_element();
        root.tag_name().name() == "features"
            && root.tag_name().namespace() == Some("http://etherx.jabber.org/streams")
            && root.children().any(|child| {
                child.is_element()
                    && child.tag_name().name() == name
                    && child.tag_name().namespace() == Some(namespace)
            })
    })
}

fn sasl_external_advertised(feature_xml: &str) -> bool {
    let parseable = parseable_stream_features(feature_xml);
    Document::parse(parseable.as_ref()).is_ok_and(|document| {
        let root = document.root_element();
        root.tag_name().name() == "features"
            && root.tag_name().namespace() == Some("http://etherx.jabber.org/streams")
            && root.children().any(|mechanisms| {
                mechanisms.is_element()
                    && mechanisms.tag_name().name() == "mechanisms"
                    && mechanisms.tag_name().namespace() == Some("urn:ietf:params:xml:ns:xmpp-sasl")
                    && mechanisms.children().any(|mechanism| {
                        mechanism.is_element()
                            && mechanism.tag_name().name() == "mechanism"
                            && mechanism.tag_name().namespace()
                                == Some("urn:ietf:params:xml:ns:xmpp-sasl")
                            && mechanism.text() == Some("EXTERNAL")
                    })
            })
    })
}

fn valid_empty_negotiation_element(raw: &str, name: &str, namespace: &str) -> bool {
    Document::parse(raw).is_ok_and(|document| {
        let root = document.root_element();
        root.tag_name().name() == name
            && root.tag_name().namespace() == Some(namespace)
            && root.attributes().len() == 0
            && !root.children().any(|child| child.is_element())
            && root.text().is_none_or(|text| text.trim().is_empty())
    })
}

async fn authenticate_dialback_outbound(
    state: &AppState,
    source_domain: &str,
    target_domain: &str,
    secure: &mut tokio_rustls::client::TlsStream<TcpStream>,
    opening: &str,
    features: &str,
    input: &mut S2sInputState,
) -> Result<()> {
    if !state.config.dialback_enabled || !advertised(features) {
        anyhow::bail!("remote server offers neither usable SASL EXTERNAL nor XEP-0220 dialback");
    }
    let id = stream_attribute(opening, "id").context("dialback stream omitted its id")?;
    if id.is_empty() || id.len() > 1_024 {
        anyhow::bail!("dialback stream id is invalid");
    }
    let value = state.derive_dialback_key(target_domain, source_domain, &id);
    write_xml(
        secure,
        &result_request(source_domain, target_domain, &value),
    )
    .await?;
    let response = timed_read_frame(secure, input).await?;
    match parse_result_response(&response, target_domain, source_domain)? {
        DialbackOutcome::Valid => Ok(()),
        DialbackOutcome::Invalid => Err(DialbackAuthorizationFailure::Invalid.into()),
        DialbackOutcome::Error(condition) => {
            Err(DialbackAuthorizationFailure::Error(condition).into())
        }
    }
}

async fn request_bidi_if_advertised<S: AsyncWrite + Unpin>(
    stream: &mut S,
    features: &str,
) -> Result<bool> {
    if !bidi_advertised(features) {
        return Ok(false);
    }
    let request = crate::xmpp::xml_builder::XmlElement::new("bidi")
        .attr("xmlns", "urn:xmpp:bidi")
        .validated_fragment(&stream_limits_feature())?
        .finish();
    write_xml(stream, &request).await?;
    Ok(true)
}

pub(crate) async fn dispatch_due_outbox(state: &Arc<AppState>) -> Result<()> {
    for expired in db::expire_s2s_outbox(&state.pool, state.config.s2s_outbox_claim_batch).await? {
        state
            .metrics
            .s2s_outbox_expired_total
            .fetch_add(1, Ordering::Relaxed);
        tracing::warn!(
            outbox_id = %expired.id,
            domain = %expired.target_domain,
            attempts = expired.attempt_count,
            queued_at = %expired.created_at,
            "federation stanza expired before delivery"
        );
        let envelope = FederationEnvelope {
            outbox_id: expired.id,
            lock_token: uuid::Uuid::nil(),
            attempt_count: expired.attempt_count,
            target_domain: expired.target_domain,
            bounce_to: expired.bounce_to,
            stanza: expired.stanza,
            delivery_mode: FederationDeliveryMode::DurableOutbox,
            volatile_completion: None,
            volatile_deadline: None,
        };
        bounce_delivery_failure(state, &envelope);
    }

    if state.island_mode_enabled() {
        return Ok(());
    }
    let component_domains = state.configured_component_domains();
    let items = db::claim_due_s2s_outbox_excluding_domains(
        &state.pool,
        state.config.s2s_outbox_claim_batch,
        state.config.s2s_outbox_lease_seconds,
        &component_domains,
    )
    .await?;
    for item in items {
        let mut envelope = FederationEnvelope::from(item);
        let target_entity = Document::parse(&envelope.stanza)
            .ok()
            .and_then(|document| document.root_element().attribute("to").map(str::to_owned));
        if state.island_mode_enabled()
            || !state.federation_domain_allowed(&envelope.target_domain)
            || !target_entity
                .as_deref()
                .is_some_and(|target| state.federation_entity_allowed(target))
        {
            fail_envelope(
                state,
                &envelope,
                &anyhow::anyhow!("target domain is denied by federation policy"),
                true,
            )
            .await;
            continue;
        }
        let source_domain = envelope_source_domain(state, &envelope);
        if let Some(route_key) = bidi_connection_key(&source_domain, &envelope.target_domain) {
            if let Some(route) = state
                .s2s_connection_registry()
                .bidirectional_route(&route_key)
            {
                if bidi_envelope_authorized(&envelope, &route.local_domain) {
                    match route.sender.try_send(envelope) {
                        Ok(()) => continue,
                        Err(error) => envelope = error.into_inner(),
                    }
                }
            }
        }
        let Some(sender) = get_or_create_outbound(state, &source_domain, &envelope.target_domain)
        else {
            fail_envelope(
                state,
                &envelope,
                &anyhow::anyhow!("federation connection capacity is exhausted"),
                false,
            )
            .await;
            continue;
        };
        if let Err(error) = sender.try_send(envelope) {
            let envelope = error.into_inner();
            fail_envelope(
                state,
                &envelope,
                &anyhow::anyhow!("local federation worker queue is saturated"),
                false,
            )
            .await;
        }
    }
    Ok(())
}

fn envelope_source_domain(state: &AppState, envelope: &FederationEnvelope) -> String {
    let parsed = Document::parse(&envelope.stanza).ok();
    let source = parsed
        .as_ref()
        .and_then(|document| document.root_element().attribute("from"))
        .and_then(|from| CanonicalJid::parse(from).ok())
        .map(|jid| jid.domainpart().to_owned());
    source
        .filter(|domain| {
            state.config.component_domain_configured(domain)
                || same_s2s_domain(domain, &state.config.domain)
                || same_s2s_domain(domain, &format!("pubsub.{}", state.config.domain))
                || same_s2s_domain(domain, &format!("conference.{}", state.config.domain))
                || same_s2s_domain(domain, &format!("mix.{}", state.config.domain))
        })
        .unwrap_or_else(|| state.config.domain.clone())
}

fn bidi_envelope_authorized(envelope: &FederationEnvelope, local_stream_domain: &str) -> bool {
    let Ok(document) = Document::parse(&envelope.stanza) else {
        return false;
    };
    let root = document.root_element();
    let from = root
        .attribute("from")
        .and_then(|jid| CanonicalJid::parse(jid).ok())
        .map(|jid| jid.domainpart().to_owned());
    let to = root
        .attribute("to")
        .and_then(|jid| CanonicalJid::parse(jid).ok())
        .map(|jid| jid.domainpart().to_owned());
    let source_authorized = from
        .as_deref()
        .is_some_and(|domain| same_s2s_domain(domain, local_stream_domain));
    source_authorized
        && to
            .as_deref()
            .is_some_and(|domain| same_s2s_domain(domain, &envelope.target_domain))
}

pub(crate) fn bounce_delivery_failure(state: &AppState, envelope: &FederationEnvelope) {
    bounce_delivery_failure_with_condition(state, envelope, "remote-server-not-found");
}

fn bounce_delivery_failure_with_condition(
    state: &AppState,
    envelope: &FederationEnvelope,
    condition: &str,
) {
    let Some(origin) = &envelope.bounce_to else {
        return;
    };
    let Some(error) = delivery_failure_stanza(&envelope.stanza, condition) else {
        return;
    };
    for session in state.sessions_for(origin) {
        let _ = session.sender.try_send(error.clone());
    }
}

fn delivery_failure_stanza(stanza: &str, condition: &str) -> Option<String> {
    // Restrict element names to the conditions emitted by this outbox. This
    // keeps the generic reflector from ever receiving an attacker-controlled
    // XML name if a future caller passes through a remote diagnostic string.
    if !matches!(
        condition,
        "internal-server-error"
            | "policy-violation"
            | "remote-server-not-found"
            | "remote-server-timeout"
    ) {
        return None;
    }
    let client_stanza = client_namespace(stanza);
    let document = Document::parse(&client_stanza).ok()?;
    let root = document.root_element();
    if root.attribute("type") == Some("error") {
        // RFC 6120 section 8.3.1 forbids responding to a stanza error with
        // another stanza error.
        return None;
    }
    Some(crate::xmpp::xml_util::stanza_error(
        root,
        crate::xmpp::xml_util::stanza_error_type(condition),
        condition,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outbound_cancellation_distinguishes_shutdown_from_certificate_revocation() {
        assert_eq!(
            outbound_cancellation_message(true, " before delivery"),
            "outbound S2S connection closed during server shutdown before delivery"
        );
        assert_eq!(
            outbound_cancellation_message(false, " before delivery"),
            "outbound S2S certificate was explicitly revoked before delivery"
        );
    }

    #[test]
    fn happy_eyeballs_staggers_candidates_deterministically() {
        assert_eq!(happy_eyeballs_delay(0), Duration::ZERO);
        assert_eq!(happy_eyeballs_delay(1), Duration::from_millis(250));
        assert_eq!(happy_eyeballs_delay(4), Duration::from_secs(1));
        assert_eq!(HAPPY_EYEBALLS_MAX_IN_FLIGHT, 4);
    }

    #[test]
    fn happy_eyeballs_alternates_families_and_preserves_family_order() {
        let endpoint = |address: &str| FederationEndpoint {
            address: address.parse().unwrap(),
            direct_tls: true,
            tls_server_name: "remote.test".to_owned(),
            delegated_identity: false,
            public_key_pins: Vec::new(),
            selection_group: 0,
            dane_srv_binding: None,
        };
        let ordered = happy_eyeballs_endpoint_order(&[
            endpoint("[2001:4860:4860::8888]:5269"),
            endpoint("[2001:4860:4860::8844]:5269"),
            endpoint("8.8.8.8:5269"),
            endpoint("8.8.4.4:5269"),
        ]);
        assert_eq!(
            ordered
                .iter()
                .map(|endpoint| endpoint.address)
                .collect::<Vec<_>>(),
            vec![
                "[2001:4860:4860::8888]:5269".parse().unwrap(),
                "8.8.8.8:5269".parse().unwrap(),
                "[2001:4860:4860::8844]:5269".parse().unwrap(),
                "8.8.4.4:5269".parse().unwrap(),
            ]
        );
    }

    #[tokio::test]
    async fn happy_eyeballs_live_fallback_reaches_ipv4_after_ipv6_failure() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let endpoint = |address| FederationEndpoint {
            address,
            direct_tls: true,
            tls_server_name: "remote.test".to_owned(),
            delegated_identity: false,
            public_key_pins: Vec::new(),
            selection_group: 0,
            dane_srv_binding: None,
        };
        let endpoints = [
            endpoint(format!("[::1]:{port}").parse().unwrap()),
            endpoint(format!("127.0.0.1:{port}").parse().unwrap()),
        ];
        let connect = race_happy_eyeballs(&endpoints, |endpoint| async move {
            tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(endpoint.address))
                .await
                .context("live Happy Eyeballs attempt timed out")?
                .context("live Happy Eyeballs attempt failed")
        });
        let (connected, accepted) = tokio::join!(connect, listener.accept());
        let connected = connected.unwrap();
        let (_, accepted_peer) = accepted.unwrap();
        assert!(connected.peer_addr().unwrap().is_ipv4());
        assert!(accepted_peer.is_ipv4());
    }

    #[test]
    fn stream_identity_uses_idna_and_rejects_non_domain_identities() {
        assert!(validate_stream_identity(
            "example.test",
            "B\u{fc}CHER.Example.",
            "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:server' version='1.0' from='xn--bcher-kva.example' to='EXAMPLE.TEST'>"
        )
        .is_ok());
        assert!(validate_stream_identity(
            "example.test",
            "remote.test",
            "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:server' version='1.0' from='alice@remote.test' to='example.test'>"
        )
        .is_err());
        assert!(validate_stream_identity(
            "example.test",
            "remote..test",
            "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:server' version='1.0' from='remote..test' to='example.test'>"
        )
        .is_err());
    }

    #[test]
    fn peer_stream_limit_is_applied_after_server_namespace_serialization() {
        let stanza = "<message xmlns='jabber:client'><body>hello</body></message>";
        let serialized = serialize_for_peer(stanza, None).unwrap();
        assert!(serialized.contains("xmlns='jabber:server'"));
        assert!(serialize_for_peer(stanza, Some(serialized.len())).is_ok());
        let error = serialize_for_peer(stanza, Some(serialized.len() - 1)).unwrap_err();
        assert!(is_peer_stanza_limit_error(&error));
    }

    #[test]
    fn dialback_authorization_failures_use_xep_0220_bounce_conditions() {
        let invalid = anyhow::Error::new(DialbackAuthorizationFailure::Invalid);
        let timeout = anyhow::Error::new(DialbackAuthorizationFailure::Error(
            "remote-server-not-found".to_owned(),
        ));
        assert!(is_dialback_authorization_error(&invalid));
        assert!(is_dialback_authorization_error(&timeout));
        assert_eq!(
            invalid
                .downcast_ref::<DialbackAuthorizationFailure>()
                .unwrap()
                .bounce_condition(),
            "internal-server-error"
        );
        assert_eq!(
            timeout
                .downcast_ref::<DialbackAuthorizationFailure>()
                .unwrap()
                .bounce_condition(),
            "remote-server-timeout"
        );
    }

    #[test]
    fn federation_failure_bounces_reflect_the_original_stanza_without_error_loops() {
        let original = "<message xmlns='jabber:server' from='alice@local.test/Phone' to='bob@remote.test' type='chat' id='m1'><body>still here</body><x xmlns='urn:example:extension'/></message>";
        for (condition, error_type) in [
            ("internal-server-error", "wait"),
            ("remote-server-timeout", "wait"),
            ("remote-server-not-found", "cancel"),
            ("policy-violation", "modify"),
        ] {
            let bounced = delivery_failure_stanza(original, condition).unwrap();
            let document = Document::parse(&bounced).unwrap();
            let root = document.root_element();
            assert_eq!(root.tag_name().namespace(), Some("jabber:client"));
            assert_eq!(root.attribute("type"), Some("error"));
            assert_eq!(root.attribute("id"), Some("m1"));
            assert_eq!(root.attribute("from"), Some("bob@remote.test"));
            assert_eq!(root.attribute("to"), Some("alice@local.test/Phone"));
            assert!(root.children().any(|child| {
                child.is_element()
                    && child.tag_name().name() == "body"
                    && child.text() == Some("still here")
            }));
            assert!(root.children().any(|child| {
                child.is_element()
                    && child.tag_name().name() == "x"
                    && child.tag_name().namespace() == Some("urn:example:extension")
            }));
            let error = root
                .children()
                .find(|child| {
                    child.is_element()
                        && child.tag_name().name() == "error"
                        && child.tag_name().namespace() == Some("jabber:client")
                })
                .unwrap();
            assert_eq!(error.attribute("type"), Some(error_type));
            assert!(error.children().any(|child| {
                child.is_element()
                    && child.tag_name().name() == condition
                    && child.tag_name().namespace() == Some("urn:ietf:params:xml:ns:xmpp-stanzas")
            }));
        }

        let error = "<message xmlns='jabber:client' from='alice@local.test' to='bob@remote.test' type='error' id='e1'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></message>";
        assert!(delivery_failure_stanza(error, "remote-server-not-found").is_none());
        assert!(delivery_failure_stanza(original, "invented-condition").is_none());
    }

    #[test]
    fn negotiation_features_require_exact_elements_and_namespaces() {
        let features = "<stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>EXTERNAL</mechanism></mechanisms></stream:features>";
        assert!(stream_feature_advertised(
            features,
            "starttls",
            "urn:ietf:params:xml:ns:xmpp-tls"
        ));
        assert!(sasl_external_advertised(features));
        assert!(!sasl_external_advertised(
            "<stream:features><feature var='EXTERNAL'/></stream:features>"
        ));
        assert!(!stream_feature_advertised(
            "<stream:features><feature var='urn:ietf:params:xml:ns:xmpp-tls'/></stream:features>",
            "starttls",
            "urn:ietf:params:xml:ns:xmpp-tls"
        ));

        assert!(valid_empty_negotiation_element(
            "<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>",
            "proceed",
            "urn:ietf:params:xml:ns:xmpp-tls"
        ));
        assert!(!valid_empty_negotiation_element(
            "<proceed-bogus xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>",
            "proceed",
            "urn:ietf:params:xml:ns:xmpp-tls"
        ));
    }
}
