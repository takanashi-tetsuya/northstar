use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use futures::{stream::FuturesUnordered, FutureExt, StreamExt};
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, Ordering};
use subtle::ConstantTimeEq;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::TlsConnector;

mod connection;
mod dialback_verify;
mod transport;

use self::connection::run_outbound_connection;
pub(crate) use self::dialback_verify::verify_remote;
use self::transport::{
    authenticate_transport, connect_secure_endpoint_group, AuthenticatedTransport,
};
#[cfg(test)]
use self::transport::{
    happy_eyeballs_delay, happy_eyeballs_endpoint_order, race_happy_eyeballs,
    sasl_external_advertised, stream_feature_advertised, valid_empty_negotiation_element,
    validate_stream_identity,
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const IO_TIMEOUT: Duration = Duration::from_secs(15);
const VOLATILE_DELIVERY_TIMEOUT: Duration = Duration::from_secs(16);
// One shared budget for all recovery observations and conditional writes.
const AUTHENTICATED_ROUTE_RECOVERY_DEADLINE: Duration = Duration::from_secs(5);
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

use crate::{
    state::{
        s2s_outbox_dispatch::{S2sOutboxDispatchContext, S2sOutboxFailureEffects},
        AppState,
    },
    xmpp::xml_builder::XmlElement,
};
use anyhow::{Context, Result};
use northstar_xmpp_types::jid::{prepare_domainpart, CanonicalJid};
use roxmltree::Document;
use std::{future::Future, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};

use super::*;
#[cfg(test)]
use crate::db;

use crate::services::s2s_outbox_dispatch::{OutboxFailureDisposition, S2sOutboxDispatchService};
type DispatchService = S2sOutboxDispatchService<
    crate::db::s2s_outbox_dispatch_repository::PostgresS2sOutboxDispatchRepository,
>;

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
                    .s2s_outbound_disposition_telemetry()
                    .connection_failed();
                tracing::warn!(
                    domain = %domain_clone,
                    ?error,
                    "federation outbound connection failed or closed"
                );
            }
            Err(_) => {
                state_clone
                    .s2s_outbound_disposition_telemetry()
                    .connection_failed();
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
        northstar_runtime::connection_actors::ConnectionActorKind::S2sOutbound,
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
    send_volatile_with_context(
        &state.s2s_outbox_dispatch_context(),
        source_domain,
        target_domain,
        stanza,
    )
    .await
}

async fn send_volatile_with_context(
    context: &S2sOutboxDispatchContext,
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
    if context.island_mode_enabled() || !context.federation_domain_allowed(&target_domain) {
        return false;
    }
    let target_entity_allowed = Document::parse(&stanza).ok().is_some_and(|document| {
        document
            .root_element()
            .attribute("to")
            .is_some_and(|target| context.federation_entity_allowed(target))
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
        if let Some(route) = context.bidirectional_route(&route_key) {
            let candidate = envelope.take().expect("volatile envelope is present");
            match route.sender.try_send(candidate) {
                Ok(()) => accepted = true,
                Err(error) => envelope = Some(error.into_inner()),
            }
        }
    }

    if !accepted {
        let connection_key = format!("{source_domain}\0{target_domain}");
        if let Some(sender) = context
            .registry()
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

pub(crate) async fn deliver_managed_envelope<S: AsyncWrite + Unpin>(
    state: &AppState,
    secure: &mut S,
    envelope: &mut FederationEnvelope,
    peer_max_bytes: Option<usize>,
    sm: &mut super::sm::StreamManagement,
) -> Result<()> {
    deliver_envelope_inner(state, secure, envelope, peer_max_bytes, Some(sm)).await
}

async fn deliver_envelope_inner<S: AsyncWrite + Unpin>(
    state: &AppState,
    secure: &mut S,
    envelope: &mut FederationEnvelope,
    peer_max_bytes: Option<usize>,
    mut sm: Option<&mut super::sm::StreamManagement>,
) -> Result<()> {
    let _delivery_timer = envelope
        .is_durable()
        .then(|| state.s2s_outbox_delivery_telemetry().start_timer());
    let serialized = serialize_for_peer(&envelope.stanza, peer_max_bytes)?;
    let managed = sm.as_ref().is_some_and(|sm| sm.is_enabled());
    if envelope
        .volatile_write_budget()
        .is_some_and(|budget| budget.is_zero())
    {
        return Ok(());
    }
    if managed && envelope.is_durable() {
        let renewed = tokio::time::timeout(
            Duration::from_secs(5),
            state
                .s2s_outbox_dispatch_service()
                .renew(envelope.outbox_id, envelope.lock_token),
        )
        .await
        .context("S2S outbox lease renewal timed out")??;
        anyhow::ensure!(renewed, "S2S outbox lease was lost before managed delivery");
    }
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
        if let Some(sm) = sm.as_mut() {
            sm.track(Some(envelope), &serialized)?;
        }
        tokio::time::timeout(write_budget, write_xml(secure, &serialized))
            .await
            .context("volatile federation delivery deadline elapsed")??;
    } else {
        if let Some(sm) = sm.as_mut() {
            sm.track(Some(envelope), &serialized)?;
        }
        write_xml(secure, &serialized)
            .await
            .context("failed to write federation envelope")?;
    }
    drop(delivery_permit);
    if let Some(sm) = sm {
        sm.request(secure).await?;
    }
    if envelope.is_durable() && !managed {
        if !state
            .s2s_outbox_dispatch_service()
            .complete(envelope.outbox_id, envelope.lock_token)
            .await?
        {
            state.s2s_outbound_disposition_telemetry().lease_lost();
            tracing::warn!(
                outbox_id = %envelope.outbox_id,
                domain = %envelope.target_domain,
                "federation stanza was written after its outbox lease was lost; delivery may be duplicated"
            );
        }
    } else if !envelope.is_durable() {
        envelope.complete_volatile_delivery();
    }
    state.s2s_outbound_disposition_telemetry().delivered();
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
    fail_envelope_with(
        &state.s2s_outbox_failure_effects(),
        envelope,
        error,
        permanent,
    )
    .await;
}

async fn fail_envelope_with(
    effects: &S2sOutboxFailureEffects,
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
    let item = northstar_federation_core::S2sOutboxItem {
        id: envelope.outbox_id,
        target_domain: envelope.target_domain.clone(),
        bounce_to: envelope.bounce_to.clone(),
        stanza: envelope.stanza.clone(),
        attempt_count: envelope.attempt_count,
        lock_token: envelope.lock_token,
    };
    match effects
        .service()
        .fail(&item, &format!("{error:#}"), permanent)
        .await
    {
        Ok(OutboxFailureDisposition::Dropped) => {
            effects.telemetry().permanent_failure();
            effects.bounce(envelope, bounce_condition);
        }
        Ok(OutboxFailureDisposition::Expired) => {
            effects.telemetry().expired();
            effects.bounce(envelope, bounce_condition);
        }
        Ok(OutboxFailureDisposition::RetryScheduled) => {
            effects.telemetry().retry();
        }
        Ok(OutboxFailureDisposition::LeaseLost) => {
            effects.telemetry().lease_lost();
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
    let endpoints =
        resolve_federation_endpoints(state.federation_dns_context(), &target_domain).await?;
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

/// A newly authenticated bidirectional stream may recover one matching FIFO
/// head from an obsolete connection-failure backoff. The registry consumes the
/// hint before a mutating query is polled; an unknown database result therefore
/// falls back to normal durable retry instead of replaying the acceleration.
async fn recover_authenticated_route_heads(
    service: &DispatchService,
    registry: &S2sConnectionRegistry,
    excluded_domains: &[String],
    domain_allowed: impl Fn(&str) -> bool,
    limit: usize,
) -> Result<usize> {
    let deadline = tokio::time::Instant::now() + AUTHENTICATED_ROUTE_RECOVERY_DEADLINE;
    let mut recovered = 0;
    for route in registry.pending_bidi_recoveries(limit) {
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        if !registry.bidi_recovery_is_current(&route) {
            continue;
        }
        if excluded_domains.contains(&route.remote_domain) || !domain_allowed(&route.remote_domain)
        {
            registry.observe_bidi_recovery(&route, None);
            continue;
        }
        let head = tokio::select! {
            biased;
            _ = route.disconnect.cancelled() => {
                registry.observe_bidi_recovery(&route, None);
                continue;
            }
            result = tokio::time::timeout_at(
                deadline,
                service.route_head(&route.remote_domain),
            ) => result.context("authenticated S2S recovery observation exceeded its turn deadline")??,
        };
        let observation = head.as_ref().map(|head| BidiRecoveryHead {
            id: head.id,
            attempt_count: head.attempt_count,
            leased: head.claim_in_flight,
            due: head.retry_due,
            direction_matches: same_s2s_domain(&head.target_domain, &route.remote_domain)
                && bidi_stanza_authorized(&head.stanza, &route.local_domain, &route.remote_domain),
        });
        if !matches!(
            registry.observe_bidi_recovery(&route, observation),
            BidiRecoveryAction::RetryHead
        ) {
            continue;
        }
        let Some(head) = head else {
            continue;
        };
        // Observation consumed this connection's one opportunity synchronously.
        // Recheck its exact owner after the read; never hold a registry guard
        // across PostgreSQL or let a revoked/replaced stream schedule new work.
        if !registry.bidi_recovery_is_current(&route) {
            continue;
        }
        let changed = tokio::select! {
            biased;
            _ = route.disconnect.cancelled() => false,
            result = tokio::time::timeout_at(
                deadline,
                service.wake_route_head(head.id, &route.remote_domain, head.attempt_count),
            ) => result.context("authenticated S2S recovery write exceeded its turn deadline")??,
        };
        recovered += usize::from(changed);
    }
    Ok(recovered)
}

pub(crate) async fn dispatch_due_outbox(
    context: &S2sOutboxDispatchContext,
    actor_state: &Arc<AppState>,
) -> Result<()> {
    for expired in context.service().expire().await? {
        context.failure().telemetry().expired();
        tracing::warn!(
            outbox_id = %expired.id,
            domain = %expired.target_domain,
            attempts = expired.attempt_count,
            queued_at = %expired.created_at,
            "federation stanza expired before delivery"
        );
        let envelope = FederationEnvelope::new(
            expired.id,
            uuid::Uuid::nil(),
            expired.attempt_count,
            expired.target_domain,
            expired.bounce_to,
            expired.stanza,
            FederationDeliveryMode::DurableOutbox,
        );
        context
            .failure()
            .bounce(&envelope, "remote-server-not-found");
    }

    if context.island_mode_enabled() {
        return Ok(());
    }
    let component_domains = context.component_domains();
    if let Err(error) = recover_authenticated_route_heads(
        context.service(),
        context.registry(),
        component_domains,
        |domain| context.federation_domain_allowed(domain),
        context.service().recovery_batch_limit()?,
    )
    .await
    {
        // Recovery is a bounded optimization. Its failure must not suppress
        // ordinary due work, lease expiry or the established retry policy.
        tracing::warn!(?error, "authenticated S2S route recovery could not finish");
    }
    let items = context
        .service()
        .claim_excluding_domains(component_domains)
        .await?;
    for item in items {
        let mut envelope = FederationEnvelope::from(item);
        let target_entity = Document::parse(&envelope.stanza)
            .ok()
            .and_then(|document| document.root_element().attribute("to").map(str::to_owned));
        if context.island_mode_enabled()
            || !context.federation_domain_allowed(&envelope.target_domain)
            || !target_entity
                .as_deref()
                .is_some_and(|target| context.federation_entity_allowed(target))
        {
            fail_envelope_with(
                context.failure(),
                &envelope,
                &anyhow::anyhow!("target domain is denied by federation policy"),
                true,
            )
            .await;
            continue;
        }
        let source_domain = envelope_source_domain(context, &envelope);
        if let Some(route_key) = bidi_connection_key(&source_domain, &envelope.target_domain) {
            if let Some(route) = context.bidirectional_route(&route_key) {
                if bidi_envelope_authorized(&envelope, &route.local_domain) {
                    match route.sender.try_send(envelope) {
                        Ok(()) => continue,
                        Err(error) => envelope = error.into_inner(),
                    }
                }
            }
        }
        // A new connection still enters the existing S2S actor runtime. Its
        // broad transport dependencies are separate from outbox claim authority.
        let Some(sender) =
            get_or_create_outbound(actor_state, &source_domain, &envelope.target_domain)
        else {
            fail_envelope_with(
                context.failure(),
                &envelope,
                &anyhow::anyhow!("federation connection capacity is exhausted"),
                false,
            )
            .await;
            continue;
        };
        if let Err(error) = sender.try_send(envelope) {
            let envelope = error.into_inner();
            fail_envelope_with(
                context.failure(),
                &envelope,
                &anyhow::anyhow!("local federation worker queue is saturated"),
                false,
            )
            .await;
        }
    }
    Ok(())
}

fn envelope_source_domain(
    context: &S2sOutboxDispatchContext,
    envelope: &FederationEnvelope,
) -> String {
    let parsed = Document::parse(&envelope.stanza).ok();
    let source = parsed
        .as_ref()
        .and_then(|document| document.root_element().attribute("from"))
        .and_then(|from| CanonicalJid::parse(from).ok())
        .map(|jid| jid.domainpart().to_owned());
    source
        .filter(|domain| {
            context.component_domain_configured(domain)
                || same_s2s_domain(domain, context.local_domain())
                || same_s2s_domain(domain, &format!("pubsub.{}", context.local_domain()))
                || same_s2s_domain(domain, &format!("conference.{}", context.local_domain()))
                || same_s2s_domain(domain, &format!("mix.{}", context.local_domain()))
        })
        .unwrap_or_else(|| context.local_domain().to_owned())
}

fn bidi_envelope_authorized(envelope: &FederationEnvelope, local_stream_domain: &str) -> bool {
    bidi_stanza_authorized(
        &envelope.stanza,
        local_stream_domain,
        &envelope.target_domain,
    )
}

fn bidi_stanza_authorized(stanza: &str, local_stream_domain: &str, target_domain: &str) -> bool {
    let Ok(document) = Document::parse(stanza) else {
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
            .is_some_and(|domain| same_s2s_domain(domain, target_domain))
}

pub(crate) fn delivery_failure_stanza(stanza: &str, condition: &str) -> Option<String> {
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
    Some(crate::services::xml_util::stanza_error(
        root,
        crate::services::xml_util::stanza_error_type(condition),
        condition,
    ))
}

#[cfg(test)]
mod tests;
