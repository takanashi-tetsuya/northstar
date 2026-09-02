pub(crate) mod framing;
pub(crate) mod protocol;
pub(crate) mod sm_counter;
pub(crate) mod stanza_validation;
pub(crate) mod xml_builder;
pub(crate) mod xml_util;

use crate::state::AppState;
use crate::transport_parsing::{
    take_websocket_frame, websocket_close_has_content,
    websocket_has_invalid_stream_header_namespace, WEBSOCKET_FRAMING_NS,
};
use anyhow::{Context, Result};
use axum::extract::ws::{Message, WebSocket};
use framing::XmlEntityFramer;
use futures::FutureExt;
use protocol::{Action, ProtocolSession};
use std::{
    future::Future,
    net::SocketAddr,
    panic::AssertUnwindSafe,
    sync::{atomic::Ordering, Arc},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
};
use tokio_rustls::TlsAcceptor;

pub(crate) const MAX_XMPP_FRAME_BYTES: usize = 1024 * 1024;
const XMPP_WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const C2S_BACKEND_OPERATION_TIMEOUT: Duration = Duration::from_secs(5);
const WEBSOCKET_TERMINAL_WRITE_TIMEOUT: Duration = Duration::from_secs(2);
pub(crate) const C2S_NEGOTIATION_IDLE_TIMEOUT: Duration = Duration::from_secs(15);
pub(crate) const C2S_AUTHENTICATED_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Debug)]
struct PeerIdleTracker {
    authenticated: bool,
    deadline: tokio::time::Instant,
}

impl PeerIdleTracker {
    fn new(authenticated: bool, now: tokio::time::Instant) -> Self {
        Self {
            authenticated,
            deadline: now + c2s_idle_timeout(authenticated),
        }
    }

    fn synchronize_authentication(&mut self, authenticated: bool, now: tokio::time::Instant) {
        if self.authenticated != authenticated {
            self.authenticated = authenticated;
            self.deadline = now + c2s_idle_timeout(authenticated);
        }
    }

    fn note_peer_traffic(&mut self, authenticated: bool, now: tokio::time::Instant) {
        self.authenticated = authenticated;
        self.deadline = now + c2s_idle_timeout(authenticated);
    }
}

fn c2s_idle_timeout(authenticated: bool) -> Duration {
    if authenticated {
        C2S_AUTHENTICATED_IDLE_TIMEOUT
    } else {
        C2S_NEGOTIATION_IDLE_TIMEOUT
    }
}

pub async fn serve_tcp(
    state: Arc<AppState>,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<()> {
    let listener = TcpListener::bind(state.config.xmpp_bind)
        .await
        .with_context(|| format!("could not bind XMPP listener to {}", state.config.xmpp_bind))?;
    tracing::info!(address = %state.config.xmpp_bind, "XMPP TCP listener ready");
    loop {
        let (stream, peer) = tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            accepted = listener.accept() => accepted?,
        };
        let state = state.clone();
        let Some(connection_guard) = state.acquire_client_connection(peer.ip()) else {
            tracing::debug!(%peer, "rejected XMPP connection at the configured capacity limit");
            continue;
        };
        let actors = state.connection_actors().clone();
        let actor_shutdown = actors.shutdown_token().child_token();
        let peer_label = peer.to_string();
        let result = actors.try_spawn(
            crate::connection_actors::ConnectionActorKind::C2sTcp,
            Some(peer_label),
            async move {
                let _connection_guard = connection_guard;
                state
                    .metrics
                    .tcp_connections_total
                    .fetch_add(1, Ordering::Relaxed);
                let material = state.tls.current();
                let tls = TlsAcceptor::from(material.c2s_starttls.clone());
                if let Err(error) = tcp_connection(
                    stream,
                    peer,
                    state,
                    tls,
                    material.tls_server_end_point.clone(),
                    material.generation,
                    actor_shutdown,
                )
                .await
                {
                    tracing::debug!(%peer, ?error, "XMPP connection closed with error");
                }
            },
        );
        if let Err(error) = result {
            tracing::debug!(%peer, ?error, "rejected XMPP connection actor admission");
        }
    }
}

pub async fn serve_xmpps_tcp(
    state: Arc<AppState>,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<()> {
    let listener = TcpListener::bind(state.config.xmpps_bind)
        .await
        .with_context(|| {
            format!(
                "could not bind XMPPS listener to {}",
                state.config.xmpps_bind
            )
        })?;
    tracing::info!(address = %state.config.xmpps_bind, "XMPPS Direct TLS listener ready");
    loop {
        let (stream, peer) = tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            accepted = listener.accept() => accepted?,
        };
        let state = state.clone();
        let Some(connection_guard) = state.acquire_client_connection(peer.ip()) else {
            tracing::debug!(%peer, "rejected XMPPS connection at the configured capacity limit");
            continue;
        };
        let actors = state.connection_actors().clone();
        let actor_shutdown = actors.shutdown_token().child_token();
        let peer_label = peer.to_string();
        let result = actors.try_spawn(
            crate::connection_actors::ConnectionActorKind::C2sDirectTls,
            Some(peer_label),
            async move {
                let _connection_guard = connection_guard;
                state
                    .metrics
                    .tcp_connections_total
                    .fetch_add(1, Ordering::Relaxed);
                let material = state.tls.current();
                let tls = TlsAcceptor::from(material.c2s_direct.clone());
                if let Err(error) = xmpps_tcp_connection(
                    stream,
                    peer,
                    state,
                    tls,
                    material.tls_server_end_point.clone(),
                    material.generation,
                    actor_shutdown,
                )
                .await
                {
                    tracing::debug!(%peer, ?error, "XMPPS connection closed with error");
                }
            },
        );
        if let Err(error) = result {
            tracing::debug!(%peer, ?error, "rejected XMPPS connection actor admission");
        }
    }
}

async fn xmpps_tcp_connection(
    stream: TcpStream,
    peer: SocketAddr,
    state: Arc<AppState>,
    tls: TlsAcceptor,
    tls_server_end_point: Option<Vec<u8>>,
    tls_generation: u64,
    actor_shutdown: tokio_util::sync::CancellationToken,
) -> Result<()> {
    stream.set_nodelay(true)?;
    let secure = tokio::select! {
        _ = actor_shutdown.cancelled() => return Ok(()),
        result = tokio::time::timeout(Duration::from_secs(15), tls.accept(stream)) => {
            result.context("Direct TLS handshake timed out")?.context("Direct TLS handshake failed")?
        }
    };
    if !crate::tls::direct_tls_sni_matches(secure.get_ref().1.server_name(), &state.config.domain) {
        anyhow::bail!("client Direct TLS SNI does not match the XMPP domain");
    }
    if secure
        .get_ref()
        .1
        .alpn_protocol()
        .is_some_and(|protocol| protocol != b"xmpp-client")
    {
        anyhow::bail!("client selected an invalid ALPN protocol");
    }
    let (tx, mut rx) = mpsc::channel(512);
    let mut session = ProtocolSession::new(
        state.clone(),
        crate::outbound::OutboundSender::new(tx),
        false,
        protocol::ClientTransport::Tcp,
        peer.ip(),
    );
    session.secure_transport = true;
    session.channel_bindings = channel_bindings(&secure, tls_server_end_point)?;
    session.client_certificate_identities = secure
        .get_ref()
        .1
        .peer_certificates()
        .map(|certificates| {
            crate::tls::c2s_client_xmpp_identities(certificates, &state.config.domain)
        })
        .transpose()?
        .unwrap_or_default();
    session.client_certificate_chain = secure
        .get_ref()
        .1
        .peer_certificates()
        .map(<[_]>::to_vec)
        .unwrap_or_default();
    session.tls_generation = tls_generation;
    tracing::debug!(%peer, "XMPPS connection established");
    let transport = AssertUnwindSafe(drive_io(secure, &mut session, &mut rx, &actor_shutdown))
        .catch_unwind()
        .await;
    finish_protocol_session(&mut session, transport)
        .await
        .map(|_| ())
}

async fn tcp_connection(
    stream: TcpStream,
    peer: SocketAddr,
    state: Arc<AppState>,
    tls: TlsAcceptor,
    tls_server_end_point: Option<Vec<u8>>,
    tls_generation: u64,
    actor_shutdown: tokio_util::sync::CancellationToken,
) -> Result<()> {
    stream.set_nodelay(true)?;
    let (tx, mut rx) = mpsc::channel(512);
    let mut session = ProtocolSession::new(
        state.clone(),
        crate::outbound::OutboundSender::new(tx),
        false,
        protocol::ClientTransport::Tcp,
        peer.ip(),
    );
    let transport = AssertUnwindSafe(async {
        let outcome = drive_io(stream, &mut session, &mut rx, &actor_shutdown).await?;
        let DriveOutcome::Upgrade(mut plain) = outcome else {
            return Ok(());
        };
        // STARTTLS is a transport transition, not a session exit. Keep this
        // exact ProtocolSession alive through the handshake and finalize it
        // only after the upgraded transport (or the handshake itself) ends.
        send(
            &mut plain,
            "<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>",
        )
        .await?;
        let secure = tokio::select! {
            _ = actor_shutdown.cancelled() => return Ok(()),
            result = tokio::time::timeout(Duration::from_secs(15), tls.accept(plain)) => {
                result.context("STARTTLS handshake timed out")?.context("TLS handshake failed")?
            }
        };
        session.secure_transport = true;
        session.channel_bindings = channel_bindings(&secure, tls_server_end_point)?;
        session.client_certificate_identities = secure
            .get_ref()
            .1
            .peer_certificates()
            .map(|certificates| {
                crate::tls::c2s_client_xmpp_identities(certificates, &state.config.domain)
            })
            .transpose()?
            .unwrap_or_default();
        session.client_certificate_chain = secure
            .get_ref()
            .1
            .peer_certificates()
            .map(<[_]>::to_vec)
            .unwrap_or_default();
        session.tls_generation = tls_generation;
        tracing::debug!(%peer, "XMPP connection upgraded to TLS");
        let _ = drive_io(secure, &mut session, &mut rx, &actor_shutdown).await?;
        Ok(())
    })
    .catch_unwind()
    .await;
    finish_protocol_session(&mut session, transport).await
}

fn channel_bindings(
    secure: &tokio_rustls::server::TlsStream<TcpStream>,
    tls_server_end_point: Option<Vec<u8>>,
) -> Result<Option<crate::auth::ChannelBindings>> {
    let tls_exporter = secure
        .get_ref()
        .1
        .export_keying_material([0_u8; 32], b"EXPORTER-Channel-Binding", Some(&[]))
        .map(|value| value.to_vec())
        .map_err(|error| {
            tracing::debug!(?error, "TLS exporter channel binding is unavailable");
            error
        })
        .ok();
    crate::auth::ChannelBindings::from_available(tls_server_end_point, tls_exporter)
}

enum DriveOutcome<S> {
    Upgrade(S),
    Done,
}

struct BackpressureDisconnectMetric {
    state: Arc<AppState>,
    disconnect: tokio_util::sync::CancellationToken,
}

async fn finish_protocol_session<T>(
    session: &mut ProtocolSession,
    transport: std::thread::Result<T>,
) -> T {
    let finalized = AssertUnwindSafe(session.finalize()).catch_unwind().await;
    match transport {
        Ok(value) => match finalized {
            Ok(_) => value,
            Err(panic) => std::panic::resume_unwind(panic),
        },
        Err(panic) => {
            match finalized {
                Ok(_) => {}
                Err(_) => tracing::error!(
                    peer_ip = %session.peer_ip,
                    "XMPP session finalizer also panicked while unwinding a transport panic"
                ),
            }
            std::panic::resume_unwind(panic)
        }
    }
}

impl Drop for BackpressureDisconnectMetric {
    fn drop(&mut self) {
        if self.disconnect.is_cancelled() {
            self.state
                .metrics
                .c2s_backpressure_disconnects_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
}

async fn drive_io<S>(
    mut io: S,
    session: &mut ProtocolSession,
    rx: &mut mpsc::Receiver<crate::outbound::OutboundItem>,
    actor_shutdown: &tokio_util::sync::CancellationToken,
) -> Result<DriveOutcome<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let disconnect = session.disconnect.clone();
    let backpressure_disconnect = session.outbound.backpressure_disconnect();
    let _backpressure_metric = BackpressureDisconnectMetric {
        state: Arc::clone(&session.state),
        disconnect: backpressure_disconnect.clone(),
    };
    let mut buffer = String::new();
    let mut framer = XmlEntityFramer::default();
    let mut pending_utf8 = Vec::new();
    let mut bytes = [0u8; 8192];
    let mut peer_idle =
        PeerIdleTracker::new(session.authenticated.is_some(), tokio::time::Instant::now());
    let mut authentication_watch = tokio::time::interval(Duration::from_secs(1));
    let mut sm_lease_watch = tokio::time::interval(Duration::from_secs(
        (session.state.config.sm_live_lease_seconds / 3).max(1),
    ));
    sm_lease_watch.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        peer_idle.synchronize_authentication(
            session.authenticated.is_some(),
            tokio::time::Instant::now(),
        );
        let resource_bind_deadline = session
            .resource_bind_deadline()
            .unwrap_or_else(|| std::time::Instant::now() + Duration::from_secs(86_400));
        tokio::select! {
            _ = actor_shutdown.cancelled() => {
                // Process shutdown is a transport loss, not a policy revoke;
                // keep an already-negotiated SM stream eligible for resume.
                return Ok(DriveOutcome::Done);
            }
            _ = backpressure_disconnect.cancelled() => {
                tracing::warn!(peer_ip = %session.peer_ip, "closed slow XMPP client after an ordered outbound delivery could not be queued; recoverable messages remain available for replay and committed state will resynchronize after reconnect");
                return Ok(DriveOutcome::Done);
            }
            _ = disconnect.cancelled() => {
                session.sm_resume_allowed = false;
                return Ok(DriveOutcome::Done);
            }
            _ = tokio::time::sleep_until(peer_idle.deadline) => {
                session.sm_resume_allowed = false;
                tracing::debug!(peer_ip = %session.peer_ip, authenticated = session.authenticated.is_some(), "closed byte-idle XMPP connection at the advertised XEP-0478 limit");
                let opening = !session.stream_opened;
                let domain = session.state.config.domain.clone();
                let _ = tcp_fatal_error(
                    &mut io,
                    &domain,
                    opening,
                    &crate::xmpp::xml_util::stream_error("policy-violation"),
                ).await;
                return Ok(DriveOutcome::Done);
            }
            _ = authentication_watch.tick(), if session.authenticated.is_none() => {
                if session.connected_at.elapsed()
                    >= Duration::from_secs(session.state.config.unauthenticated_timeout_seconds)
                {
                    tracing::debug!(peer_ip = %session.peer_ip, "closed unauthenticated XMPP connection after deadline");
                    return Ok(DriveOutcome::Done);
                }
            }
            _ = sm_lease_watch.tick(), if session.sm_db_id.is_some() => {
                if let Err(error) = session.checkpoint_sm().await {
                    tcp_internal_backend_error(
                        &mut io,
                        session,
                        !session.stream_opened,
                        "checkpoint XEP-0198 state",
                        &error,
                    ).await;
                    return Ok(DriveOutcome::Done);
                }
            }
            _ = tokio::time::sleep_until(resource_bind_deadline.into()), if session.resource_bind_deadline().is_some() => {
                session.sm_resume_allowed = false;
                let domain = session.state.config.domain.clone();
                let _ = tcp_fatal_error(
                    &mut io,
                    &domain,
                    !session.stream_opened,
                    &crate::xmpp::xml_util::stream_error("policy-violation"),
                ).await;
                return Ok(DriveOutcome::Done);
            }
            read = io.read(&mut bytes) => {
                let count = read?;
                if count == 0 {
                    if !pending_utf8.is_empty() { anyhow::bail!("XMPP stream ended inside a UTF-8 character"); }
                    return Ok(DriveOutcome::Done);
                }
                peer_idle.note_peer_traffic(
                    session.authenticated.is_some(),
                    tokio::time::Instant::now(),
                );
                pending_utf8.extend_from_slice(&bytes[..count]);
                if let Err(error) = append_utf8(&mut pending_utf8, &mut buffer) {
                    tracing::debug!(?error, peer_ip = %session.peer_ip, "invalid UTF-8 in XMPP stream");
                    session.sm_resume_allowed = false;
                    let opening = !session.stream_opened;
                    tcp_fatal_error(
                        &mut io,
                        &session.state.config.domain,
                        opening,
                        &crate::xmpp::xml_util::stream_error("unsupported-encoding"),
                    )
                    .await?;
                    return Ok(DriveOutcome::Done);
                }
                loop {
                    // XEP-0388 deliberately forbids the otherwise legal XMPP
                    // whitespace keepalive while a SASL2 exchange is active.
                    // `take_frame` normally consumes leading XML whitespace, so
                    // enforce this at the transport boundary before framing can
                    // discard it (including between coalesced TCP frames).
                    if session.sasl2_state.is_some() && starts_with_xml_whitespace(&buffer) {
                        tracing::debug!(peer_ip = %session.peer_ip, "closed connection after whitespace during SASL2 negotiation");
                        return Ok(DriveOutcome::Done);
                    }
                    let frame = match framer.take_frame(&mut buffer) {
                        Ok(Some(frame)) => {
                            if frame.len() > MAX_XMPP_FRAME_BYTES {
                                tracing::debug!(peer_ip = %session.peer_ip, "XMPP frame exceeded 1 MiB");
                                session.sm_resume_allowed = false;
                                let opening = !session.stream_opened;
                                tcp_fatal_error(
                                    &mut io,
                                    &session.state.config.domain,
                                    opening,
                                    &crate::xmpp::xml_util::stream_error("policy-violation"),
                                )
                                .await?;
                                return Ok(DriveOutcome::Done);
                            }
                            frame
                        }
                        Ok(None) => {
                            // Bound only the incomplete top-level element.
                            // Several coalesced, individually valid stanzas
                            // must not be rejected as one oversized stanza.
                            if buffer.len() + pending_utf8.len() > MAX_XMPP_FRAME_BYTES {
                                tracing::debug!(peer_ip = %session.peer_ip, "incomplete XMPP frame exceeded 1 MiB");
                                session.sm_resume_allowed = false;
                                let opening = !session.stream_opened;
                                tcp_fatal_error(
                                    &mut io,
                                    &session.state.config.domain,
                                    opening,
                                    &crate::xmpp::xml_util::stream_error("policy-violation"),
                                )
                                .await?;
                                return Ok(DriveOutcome::Done);
                            }
                            break;
                        }
                        Err(error) => {
                            tracing::debug!(?error, peer_ip = %session.peer_ip, "invalid XMPP framing");
                            session.sm_resume_allowed = false;
                            let condition = framing::stream_error_condition(&error);
                            let opening = !session.stream_opened;
                            tcp_fatal_error(
                                &mut io,
                                &session.state.config.domain,
                                opening,
                                &crate::xmpp::xml_util::stream_error(condition),
                            )
                            .await?;
                            return Ok(DriveOutcome::Done);
                        }
                    };
                    let opening = !session.stream_opened;
                    let stream_was_open = session.stream_opened;
                    let action = match tokio::time::timeout(
                        C2S_BACKEND_OPERATION_TIMEOUT,
                        session.handle(&frame),
                    ).await {
                        Ok(Ok(action)) => action,
                        Ok(Err(error)) => {
                            tracing::error!(?error, peer_ip = %session.peer_ip, "XMPP protocol/backend failure");
                            session.sm_resume_allowed = false;
                            tcp_fatal_error(
                                &mut io,
                                &session.state.config.domain,
                                opening,
                                &crate::xmpp::xml_util::stream_error("internal-server-error"),
                            )
                            .await?;
                            return Ok(DriveOutcome::Done);
                        }
                        Err(_) => {
                            session.sm_resume_allowed = false;
                            let error = anyhow::anyhow!("XMPP protocol/backend operation timed out");
                            tcp_internal_backend_error(
                                &mut io,
                                session,
                                opening,
                                "process inbound stanza",
                                &error,
                            ).await;
                            return Ok(DriveOutcome::Done);
                        }
                    };
                    let xml_entity_restarted = stream_was_open && !session.stream_opened;
                    match action {
                        Action::Send(reply) => {
                            if !tcp_record_and_send(&mut io, session, &reply, opening).await? {
                                return Ok(DriveOutcome::Done);
                            }
                        },
                        Action::SendMany(replies) => {
                            for reply in replies {
                                if !tcp_record_and_send(&mut io, session, &reply, opening).await? {
                                    return Ok(DriveOutcome::Done);
                                }
                            }
                        }
                        Action::SendManyItems(items) => {
                            for item in items {
                                if !tcp_record_and_send_item(
                                    &mut io,
                                    session,
                                    &item,
                                    opening,
                                )
                                .await?
                                {
                                    return Ok(DriveOutcome::Done);
                                }
                            }
                        }
                        Action::SendManyThenActivate(replies) => {
                            for (index, reply) in replies.into_iter().enumerate() {
                                if !tcp_record_and_send(&mut io, session, &reply, opening).await? {
                                    return Ok(DriveOutcome::Done);
                                }
                                if index == 0
                                    && !session.publish_committed_authentication_and_route().await
                                {
                                    return Ok(DriveOutcome::Done);
                                }
                            }
                        }
                        Action::SendManyAndClose(replies) => {
                            session.sm_resume_allowed = false;
                            for reply in replies {
                                send(&mut io, &reply).await?;
                            }
                            send(&mut io, "</stream:stream>").await?;
                            return Ok(DriveOutcome::Done);
                        }
                        Action::Resume(payload) => {
                            let crate::xmpp::protocol::ResumeTransportParts {
                                control,
                                post_control,
                                replay,
                                activate_route,
                                transient_capacity: _resume_transport_capacity,
                            } = payload.into_transport_parts();
                            if !tcp_record_and_send(&mut io, session, &control, opening).await? {
                                return Ok(DriveOutcome::Done);
                            }
                            if activate_route
                                && !session.publish_committed_authentication_and_route().await
                            {
                                return Ok(DriveOutcome::Done);
                            }
                            for nonza in post_control {
                                if !tcp_record_and_send(&mut io, session, &nonza, opening).await? {
                                    return Ok(DriveOutcome::Done);
                                }
                            }
                            for stanza in replay {
                                send(&mut io, &stanza).await?;
                                session.record_replayed();
                            }
                        }
                        Action::StartTls => return Ok(DriveOutcome::Upgrade(io)),
                        Action::CloseWith(reply) => {
                            session.sm_resume_allowed = false;
                            tcp_fatal_error(
                                &mut io,
                                &session.state.config.domain,
                                opening,
                                &reply,
                            )
                            .await?;
                            return Ok(DriveOutcome::Done);
                        }
                        Action::Close => {
                            send(&mut io, "</stream:stream>").await?;
                            return Ok(DriveOutcome::Done);
                        }
                        Action::None => {}
                    }
                    if xml_entity_restarted {
                        // A successful legacy SASL exchange closes the first
                        // XML stream but keeps the transport. RFC 6120 then
                        // starts a fresh XML entity, which is the only point
                        // at which another XML declaration becomes legal.
                        framer.reset_entity();
                    }
                    // Any worker that writes to this session's bounded outbound
                    // channel starts only after the action/control frame above
                    // has reached the transport, avoiding a self-channel stall.
                    session.start_post_action_tasks();
                }
            }
            outgoing = rx.recv() => {
                let Some(outgoing) = outgoing else { return Ok(DriveOutcome::Done); };
                let outgoing = session.csi_filter_outbound(outgoing);
                if let Some(outgoing) = outgoing {
                    if !tcp_record_and_send_item(
                        &mut io,
                        session,
                        &outgoing,
                        !session.stream_opened,
                    ).await? {
                        return Ok(DriveOutcome::Done);
                    }
                }
            }
        }
    }
}

fn append_utf8(pending: &mut Vec<u8>, output: &mut String) -> Result<()> {
    match std::str::from_utf8(pending) {
        Ok(text) => {
            output.push_str(text);
            pending.clear();
            Ok(())
        }
        Err(error) if error.error_len().is_none() => {
            let valid = error.valid_up_to();
            output
                .push_str(std::str::from_utf8(&pending[..valid]).context("invalid UTF-8 prefix")?);
            pending.drain(..valid);
            Ok(())
        }
        Err(_) => anyhow::bail!("XMPP stream is not valid UTF-8"),
    }
}

fn starts_with_xml_whitespace(value: &str) -> bool {
    value
        .as_bytes()
        .first()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
}

fn websocket_server_open(domain: &str) -> String {
    xml_builder::XmlElement::new("open")
        .attr("xmlns", WEBSOCKET_FRAMING_NS)
        .attr("from", domain)
        .attr("id", crate::xmpp::xml_util::stream_id())
        .attr("version", "1.0")
        .attr("xml:lang", "en")
        .finish()
}

fn websocket_close() -> String {
    xml_builder::XmlElement::new("close")
        .attr("xmlns", WEBSOCKET_FRAMING_NS)
        .finish()
}

struct WebSocketSendCancellation<'a> {
    actor_shutdown: &'a tokio_util::sync::CancellationToken,
    disconnect: &'a tokio_util::sync::CancellationToken,
    backpressure_disconnect: &'a tokio_util::sync::CancellationToken,
}

async fn websocket_send_live(
    socket: &mut WebSocket,
    message: Message,
    cancellation: &WebSocketSendCancellation<'_>,
) -> bool {
    tokio::select! {
        biased;
        _ = cancellation.actor_shutdown.cancelled() => false,
        _ = cancellation.disconnect.cancelled() => false,
        _ = cancellation.backpressure_disconnect.cancelled() => false,
        result = tokio::time::timeout(XMPP_WRITE_TIMEOUT, socket.send(message)) => {
            matches!(result, Ok(Ok(())))
        }
    }
}

async fn websocket_send_terminal(socket: &mut WebSocket, message: Message) -> bool {
    bounded_websocket_terminal_write(socket.send(message)).await
}

async fn bounded_websocket_terminal_write<F, T, E>(write: F) -> bool
where
    F: Future<Output = std::result::Result<T, E>>,
{
    matches!(
        tokio::time::timeout(WEBSOCKET_TERMINAL_WRITE_TIMEOUT, write).await,
        Ok(Ok(_))
    )
}

#[derive(Default)]
struct WebSocketTerminalSequence {
    started: bool,
}

impl WebSocketTerminalSequence {
    fn begin(&mut self) -> bool {
        if self.started {
            false
        } else {
            self.started = true;
            true
        }
    }

    fn has_started(&self) -> bool {
        self.started
    }
}

fn needs_shutdown_terminal_sequence(
    actor_shutdown: bool,
    session_disconnect: bool,
    terminal: &WebSocketTerminalSequence,
) -> bool {
    (actor_shutdown || session_disconnect) && !terminal.has_started()
}

async fn websocket_fatal_error(
    socket: &mut WebSocket,
    domain: &str,
    opening: bool,
    error: String,
    terminal: &mut WebSocketTerminalSequence,
) {
    if !terminal.begin() {
        return;
    }
    // RFC 7395 section 3.5 requires a server opening frame before an error
    // raised while the peer's opening frame is being processed.
    if opening
        && !websocket_send_terminal(socket, Message::Text(websocket_server_open(domain).into()))
            .await
    {
        return;
    }
    if !websocket_send_terminal(socket, Message::Text(error.into())).await {
        return;
    }
    if !websocket_send_terminal(socket, Message::Text(websocket_close().into())).await {
        return;
    }
    // Sending the XMPP <close/> is not the WebSocket closing handshake.
    let _ = websocket_send_terminal(socket, Message::Close(None)).await;
}

async fn websocket_orderly_close(
    socket: &mut WebSocket,
    stream_opened: bool,
    terminal: &mut WebSocketTerminalSequence,
) {
    websocket_send_many_and_close(socket, Vec::new(), stream_opened, terminal).await;
}

async fn websocket_send_many_and_close(
    socket: &mut WebSocket,
    replies: Vec<String>,
    stream_opened: bool,
    terminal: &mut WebSocketTerminalSequence,
) {
    if !terminal.begin() {
        return;
    }

    // An explicit terminal action owns its complete ordered output sequence.
    // Account deletion and password replacement deliberately disconnect every
    // resource before returning this action, so live-send cancellation must
    // not overtake the final IQ response. Each write remains independently
    // bounded by WEBSOCKET_TERMINAL_WRITE_TIMEOUT.
    for message in websocket_terminal_messages(replies, stream_opened) {
        if !websocket_send_terminal(socket, message).await {
            return;
        }
    }
}

fn websocket_terminal_messages(replies: Vec<String>, stream_opened: bool) -> Vec<Message> {
    let mut messages = Vec::with_capacity(replies.len() + usize::from(stream_opened) + 1);
    messages.extend(replies.into_iter().map(|reply| Message::Text(reply.into())));
    if stream_opened {
        messages.push(Message::Text(websocket_close().into()));
    }
    messages.push(Message::Close(None));
    messages
}

async fn send<S: AsyncWrite + Unpin>(io: &mut S, stanza: &str) -> Result<()> {
    tokio::time::timeout(XMPP_WRITE_TIMEOUT, async {
        io.write_all(stanza.as_bytes()).await?;
        io.flush().await
    })
    .await
    .context("XMPP write timed out")??;
    Ok(())
}

fn tcp_server_open(domain: &str) -> String {
    crate::xmpp::xml_builder::XmlElement::new("stream:stream")
        .attr("from", domain)
        .attr("id", crate::xmpp::xml_util::stream_id())
        .attr("version", "1.0")
        .attr("xml:lang", "en")
        .attr("xmlns", "jabber:client")
        .attr("xmlns:stream", "http://etherx.jabber.org/streams")
        .open()
}

async fn tcp_fatal_error<S: AsyncWrite + Unpin>(
    io: &mut S,
    domain: &str,
    opening: bool,
    error: &str,
) -> Result<()> {
    // RFC 6120 section 4.9.1.2 requires an opening response before a stream
    // error raised while processing the initiating stream header.
    if opening {
        send(io, &tcp_server_open(domain)).await?;
    }
    send(io, error).await?;
    send(io, "</stream:stream>").await
}

async fn tcp_record_and_send<S: AsyncWrite + Unpin>(
    io: &mut S,
    session: &mut ProtocolSession,
    stanza: &str,
    opening: bool,
) -> Result<bool> {
    if let Err(error) = session.record_outbound(stanza).await {
        tcp_internal_backend_error(io, session, opening, "record outbound stanza", &error).await;
        return Ok(false);
    }
    send(io, stanza).await?;
    Ok(true)
}

async fn tcp_record_and_send_item<S: AsyncWrite + Unpin>(
    io: &mut S,
    session: &mut ProtocolSession,
    item: &crate::outbound::OutboundItem,
    opening: bool,
) -> Result<bool> {
    let managed_by_sm = match session.record_outbound_item(item).await {
        Ok(managed) => managed,
        Err(error) => {
            tcp_internal_backend_error(io, session, opening, "record outbound stanza", &error)
                .await;
            return Ok(false);
        }
    };
    let socket_delivery = if let Some(delivery) = item.durable_delivery.filter(|_| !managed_by_sm) {
        match tokio::time::timeout(
            C2S_BACKEND_OPERATION_TIMEOUT,
            session.state.replay_service().fence_socket_write(delivery),
        )
        .await
        {
            Ok(Ok(delivery)) => Some(delivery),
            Ok(Err(error)) => {
                tcp_internal_backend_error(
                    io,
                    session,
                    opening,
                    "fence durable socket write",
                    &error,
                )
                .await;
                return Ok(false);
            }
            Err(_) => {
                tcp_internal_backend_error(
                    io,
                    session,
                    opening,
                    "fence durable socket write timed out",
                    &anyhow::anyhow!("C2S backend operation timed out"),
                )
                .await;
                return Ok(false);
            }
        }
    } else {
        None
    };
    send(io, &item.stanza).await?;
    if !managed_by_sm {
        item.confirm_transport_ownership();
    }
    if let Some(delivery) = socket_delivery {
        match tokio::time::timeout(
            C2S_BACKEND_OPERATION_TIMEOUT,
            session
                .state
                .replay_service()
                .acknowledge_socket_write(delivery),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::warn!(?error, message_id = %delivery.message_id, "C2S transport write succeeded but durable delivery acknowledgement failed")
            }
            Err(_) => {
                tracing::warn!(message_id = %delivery.message_id, "C2S transport write succeeded but durable delivery acknowledgement timed out")
            }
        }
    }
    Ok(true)
}

async fn tcp_internal_backend_error<S: AsyncWrite + Unpin>(
    io: &mut S,
    session: &mut ProtocolSession,
    opening: bool,
    operation: &'static str,
    error: &anyhow::Error,
) {
    tracing::error!(?error, operation, peer_ip = %session.peer_ip, "XMPP transport/backend failure");
    session.sm_resume_allowed = false;
    let domain = session.state.config.domain.clone();
    // The original backend error is authoritative; a broken or stalled peer
    // must not keep the task alive while the terminal response is attempted.
    let _ = tcp_fatal_error(
        io,
        &domain,
        opening,
        &crate::xmpp::xml_util::stream_error("internal-server-error"),
    )
    .await;
}

pub async fn websocket_connection(
    mut socket: WebSocket,
    state: Arc<AppState>,
    peer_ip: std::net::IpAddr,
    actor_shutdown: tokio_util::sync::CancellationToken,
) {
    state
        .metrics
        .websocket_connections_total
        .fetch_add(1, Ordering::Relaxed);
    let (tx, mut rx) = mpsc::channel(512);
    let mut session = ProtocolSession::new(
        state,
        crate::outbound::OutboundSender::new(tx),
        true,
        protocol::ClientTransport::WebSocket,
        peer_ip,
    );
    let mut framer = XmlEntityFramer::default();
    let disconnect = session.disconnect.clone();
    let backpressure_disconnect = session.outbound.backpressure_disconnect();
    let send_cancellation = WebSocketSendCancellation {
        actor_shutdown: &actor_shutdown,
        disconnect: &disconnect,
        backpressure_disconnect: &backpressure_disconnect,
    };
    let _backpressure_metric = BackpressureDisconnectMetric {
        state: Arc::clone(&session.state),
        disconnect: backpressure_disconnect.clone(),
    };
    let mut authentication_watch = tokio::time::interval(Duration::from_secs(1));
    let mut sm_lease_watch = tokio::time::interval(Duration::from_secs(
        (session.state.config.sm_live_lease_seconds / 3).max(1),
    ));
    sm_lease_watch.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut peer_idle =
        PeerIdleTracker::new(session.authenticated.is_some(), tokio::time::Instant::now());
    let mut terminal_sequence = WebSocketTerminalSequence::default();
    let transport = AssertUnwindSafe(async {
        loop {
        peer_idle.synchronize_authentication(
            session.authenticated.is_some(),
            tokio::time::Instant::now(),
        );
        let resource_bind_deadline = session
            .resource_bind_deadline()
            .unwrap_or_else(|| std::time::Instant::now() + Duration::from_secs(86_400));
        tokio::select! {
            _ = actor_shutdown.cancelled() => {
                let opened = session.stream_opened;
                websocket_orderly_close(
                    &mut socket,
                    opened,
                    &mut terminal_sequence,
                ).await;
                break;
            }
            _ = backpressure_disconnect.cancelled() => {
                tracing::warn!(%peer_ip, "closed slow WebSocket XMPP client after an ordered outbound delivery could not be queued; recoverable messages remain available for replay and committed state will resynchronize after reconnect");
                break;
            }
            _ = disconnect.cancelled() => {
                session.sm_resume_allowed = false;
                let opened = session.stream_opened;
                websocket_orderly_close(&mut socket, opened, &mut terminal_sequence).await;
                break;
            }
            _ = tokio::time::sleep_until(peer_idle.deadline) => {
                session.sm_resume_allowed = false;
                tracing::debug!(%peer_ip, authenticated = session.authenticated.is_some(), "closed byte-idle WebSocket XMPP connection at the advertised XEP-0478 limit");
                let opening = !session.stream_opened;
                let domain = session.state.config.domain.clone();
                websocket_fatal_error(
                    &mut socket,
                    &domain,
                    opening,
                    crate::xmpp::xml_util::stream_error("policy-violation"),
                    &mut terminal_sequence,
                ).await;
                break;
            }
            _ = authentication_watch.tick(), if session.authenticated.is_none() => {
                if session.connected_at.elapsed()
                    >= Duration::from_secs(session.state.config.unauthenticated_timeout_seconds)
                {
                    tracing::debug!(%peer_ip, "closed unauthenticated WebSocket after deadline");
                    session.sm_resume_allowed = false;
                    let opening = !session.stream_opened;
                    let domain = session.state.config.domain.clone();
                    websocket_fatal_error(
                        &mut socket,
                        &domain,
                        opening,
                        crate::xmpp::xml_util::stream_error("policy-violation"),
                        &mut terminal_sequence,
                    ).await;
                    break;
                }
            }
            _ = sm_lease_watch.tick(), if session.sm_db_id.is_some() => {
                if session.checkpoint_sm().await.is_err() {
                    session.sm_resume_allowed = false;
                    let opening = !session.stream_opened;
                    let domain = session.state.config.domain.clone();
                    websocket_fatal_error(
                        &mut socket,
                        &domain,
                        opening,
                        crate::xmpp::xml_util::stream_error("internal-server-error"),
                        &mut terminal_sequence,
                    ).await;
                    break;
                }
            }
            _ = tokio::time::sleep_until(resource_bind_deadline.into()), if session.resource_bind_deadline().is_some() => {
                session.sm_resume_allowed = false;
                let opening = !session.stream_opened;
                let domain = session.state.config.domain.clone();
                websocket_fatal_error(
                    &mut socket,
                    &domain,
                    opening,
                    crate::xmpp::xml_util::stream_error("policy-violation"),
                    &mut terminal_sequence,
                ).await;
                break;
            }
            incoming = socket.recv() => {
                if matches!(&incoming, Some(Ok(_))) {
                    peer_idle.note_peer_traffic(
                        session.authenticated.is_some(),
                        tokio::time::Instant::now(),
                    );
                }
                match incoming {
                    Some(Ok(Message::Text(text))) => {
                        let frame = match take_websocket_frame(
                            text.as_str(),
                            &mut framer,
                            MAX_XMPP_FRAME_BYTES,
                        ) {
                            Ok(frame) => frame,
                            Err(error) => {
                                tracing::debug!(?error, "invalid WebSocket XMPP framing");
                                session.sm_resume_allowed = false;
                                let condition = framing::stream_error_condition(&error);
                                let opening = !session.stream_opened;
                                let domain = session.state.config.domain.clone();
                                websocket_fatal_error(
                                    &mut socket,
                                    &domain,
                                    opening,
                                    crate::xmpp::xml_util::stream_error(condition),
                                    &mut terminal_sequence,
                                ).await;
                                break;
                            }
                        };
                        if websocket_has_invalid_stream_header_namespace(&frame) {
                            session.sm_resume_allowed = false;
                            let opening = !session.stream_opened;
                            let domain = session.state.config.domain.clone();
                            websocket_fatal_error(
                                &mut socket,
                                &domain,
                                opening,
                                crate::xmpp::xml_util::stream_error("invalid-namespace"),
                                &mut terminal_sequence,
                            ).await;
                            break;
                        }
                        if websocket_close_has_content(&frame) {
                            session.sm_resume_allowed = false;
                            let opening = !session.stream_opened;
                            let domain = session.state.config.domain.clone();
                            websocket_fatal_error(
                                &mut socket,
                                &domain,
                                opening,
                                crate::xmpp::xml_util::stream_error("not-well-formed"),
                                &mut terminal_sequence,
                            ).await;
                            break;
                        }
                        let opening = !session.stream_opened;
                        let stream_was_opened = session.stream_opened;
                        let action = tokio::time::timeout(
                            C2S_BACKEND_OPERATION_TIMEOUT,
                            session.handle(&frame),
                        ).await.map_err(|_| anyhow::anyhow!("XMPP protocol/backend operation timed out"))
                            .and_then(|result| result);
                        if stream_was_opened
                            && !session.stream_opened
                            && session.authenticated.is_some()
                        {
                            framer.reset_entity();
                        }
                        match action {
                            Ok(Action::Send(reply)) => {
                                if session.record_outbound(&reply).await.is_err() {
                                    session.sm_resume_allowed = false;
                                    let domain = session.state.config.domain.clone();
                                    websocket_fatal_error(
                                        &mut socket,
                                        &domain,
                                        opening,
                                        crate::xmpp::xml_util::stream_error("internal-server-error"),
                                        &mut terminal_sequence,
                                    ).await;
                                    break;
                                }
                                if !websocket_send_live(
                                    &mut socket,
                                    Message::Text(reply.into()),
                                    &send_cancellation,
                                )
                                .await
                                {
                                    // A broken transport remains eligible for XEP-0198 resume.
                                    break;
                                }
                            }
                            Ok(Action::SendMany(replies)) => {
                                let mut failed = false;
                                for reply in replies {
                                    if session.record_outbound(&reply).await.is_err() {
                                        session.sm_resume_allowed = false;
                                        let domain = session.state.config.domain.clone();
                                        websocket_fatal_error(
                                            &mut socket,
                                            &domain,
                                            opening,
                                            crate::xmpp::xml_util::stream_error("internal-server-error"),
                                            &mut terminal_sequence,
                                        ).await;
                                        failed = true;
                                        break;
                                    }
                                    if !websocket_send_live(
                                        &mut socket,
                                        Message::Text(reply.into()),
                                        &send_cancellation,
                                    )
                                    .await
                                    {
                                        failed = true;
                                        break;
                                    }
                                }
                                if failed {
                                    break;
                                }
                            }
                            Ok(Action::SendManyItems(items)) => {
                                let mut failed = false;
                                for item in items {
                                    if !websocket_record_and_send_item(
                                        &mut socket,
                                        &mut session,
                                        item,
                                        opening,
                                        &mut terminal_sequence,
                                        &send_cancellation,
                                    )
                                    .await
                                    {
                                        failed = true;
                                        break;
                                    }
                                }
                                if failed {
                                    break;
                                }
                            }
                            Ok(Action::SendManyThenActivate(replies)) => {
                                let mut failed = false;
                                for (index, reply) in replies.into_iter().enumerate() {
                                    if session.record_outbound(&reply).await.is_err() {
                                        session.sm_resume_allowed = false;
                                        failed = true;
                                        break;
                                    }
                                    if !websocket_send_live(
                                        &mut socket,
                                        Message::Text(reply.into()),
                                        &send_cancellation,
                                    )
                                    .await
                                    {
                                        failed = true;
                                        break;
                                    }
                                    if index == 0
                                        && !session
                                            .publish_committed_authentication_and_route()
                                            .await
                                    {
                                        failed = true;
                                        break;
                                    }
                                }
                                if failed {
                                    break;
                                }
                            }
                            Ok(Action::SendManyAndClose(replies)) => {
                                session.sm_resume_allowed = false;
                                websocket_send_many_and_close(
                                    &mut socket,
                                    replies,
                                    true,
                                    &mut terminal_sequence,
                                )
                                .await;
                                break;
                            }
                            Ok(Action::Resume(payload)) => {
                                let crate::xmpp::protocol::ResumeTransportParts {
                                    control,
                                    post_control,
                                    replay,
                                    activate_route,
                                    transient_capacity: _resume_transport_capacity,
                                } = payload.into_transport_parts();
                                if session.record_outbound(&control).await.is_err() {
                                    session.sm_resume_allowed = false;
                                    let domain = session.state.config.domain.clone();
                                    websocket_fatal_error(
                                        &mut socket,
                                        &domain,
                                        opening,
                                        crate::xmpp::xml_util::stream_error("internal-server-error"),
                                        &mut terminal_sequence,
                                    ).await;
                                    break;
                                }
                                if !websocket_send_live(
                                    &mut socket,
                                    Message::Text(control.into()),
                                    &send_cancellation,
                                )
                                .await
                                {
                                    break;
                                }
                                if activate_route
                                    && !session
                                        .publish_committed_authentication_and_route()
                                        .await
                                {
                                    break;
                                }
                                let mut failed = false;
                                for nonza in post_control {
                                    if session.record_outbound(&nonza).await.is_err() {
                                        session.sm_resume_allowed = false;
                                        failed = true;
                                        break;
                                    }
                                    if !websocket_send_live(
                                        &mut socket,
                                        Message::Text(nonza.into()),
                                        &send_cancellation,
                                    )
                                    .await
                                    {
                                        failed = true;
                                        break;
                                    }
                                }
                                if failed {
                                    break;
                                }
                                for stanza in replay {
                                    if !websocket_send_live(
                                        &mut socket,
                                        Message::Text(stanza.into()),
                                        &send_cancellation,
                                    )
                                    .await
                                    {
                                        failed = true;
                                        break;
                                    }
                                    session.record_replayed();
                                }
                                if failed {
                                    break;
                                }
                            }
                            Ok(Action::Close) => {
                                session.sm_resume_allowed = false;
                                websocket_orderly_close(
                                    &mut socket,
                                    true,
                                    &mut terminal_sequence,
                                ).await;
                                break;
                            }
                            Ok(Action::CloseWith(reply)) => {
                                session.sm_resume_allowed = false;
                                let domain = session.state.config.domain.clone();
                                websocket_fatal_error(
                                    &mut socket,
                                    &domain,
                                    opening,
                                    reply,
                                    &mut terminal_sequence,
                                ).await;
                                break;
                            }
                            Ok(Action::None) => {}
                            Ok(Action::StartTls) => {
                                if !websocket_send_live(
                                    &mut socket,
                                    Message::Text("<failure xmlns='urn:ietf:params:xml:ns:xmpp-tls'><unexpected-request/></failure>".into()),
                                        &send_cancellation,
                                ).await {
                                    break;
                                }
                            }
                            Err(error) => {
                                tracing::debug!(?error, "invalid WebSocket XMPP stanza");
                                session.sm_resume_allowed = false;
                                let domain = session.state.config.domain.clone();
                                websocket_fatal_error(
                                    &mut socket,
                                    &domain,
                                    opening,
                                    crate::xmpp::xml_util::stream_error("internal-server-error"),
                                    &mut terminal_sequence,
                                ).await;
                                break;
                            }
                        }
                        session.start_post_action_tasks();
                    },
                    Some(Ok(Message::Ping(value))) => {
                        if !websocket_send_live(
                            &mut socket,
                            Message::Pong(value),
                                    &send_cancellation,
                        ).await {
                            break;
                        }
                    }
                    Some(Ok(Message::Close(frame))) => {
                        // A WebSocket-only close is an implicit XMPP close.
                        // Preserve the resumable stream lease if XEP-0198 was
                        // negotiated, and complete the WebSocket handshake.
                        if terminal_sequence.begin() {
                            let _ = websocket_send_terminal(
                                &mut socket,
                                Message::Close(frame),
                            ).await;
                        }
                        break;
                    }
                    None | Some(Err(_)) => break,
                    Some(Ok(Message::Binary(payload))) => {
                        tracing::debug!(
                            payload_bytes = payload.len(),
                            "rejected binary WebSocket XMPP message before XML processing"
                        );
                        session.sm_resume_allowed = false;
                        let opening = !session.stream_opened;
                        let domain = session.state.config.domain.clone();
                        websocket_fatal_error(
                            &mut socket,
                            &domain,
                            opening,
                            crate::xmpp::xml_util::stream_error("unsupported-stanza-type"),
                            &mut terminal_sequence,
                        ).await;
                        break;
                    }
                    _ => {}
                }
            }
            outgoing = rx.recv() => {
                let Some(outgoing) = outgoing else { break; };
                let outgoing = session.csi_filter_outbound(outgoing);
                if let Some(outgoing) = outgoing {
                    let opening = !session.stream_opened;
                    if !websocket_record_and_send_item(
                        &mut socket,
                        &mut session,
                        outgoing,
                        opening,
                        &mut terminal_sequence,
                        &send_cancellation,
                    )
                    .await
                    {
                        break;
                    }
                }
            }
        }
    }
    })
    .catch_unwind()
    .await;
    // A session-policy disconnect can win while a socket write is pending.
    // Preserve resumability for transport/backpressure failures, but never for
    // an explicit administrative or certificate-driven session revocation.
    if disconnect.is_cancelled() {
        session.sm_resume_allowed = false;
    }
    if needs_shutdown_terminal_sequence(
        actor_shutdown.is_cancelled(),
        disconnect.is_cancelled(),
        &terminal_sequence,
    ) {
        let opened = session.stream_opened;
        websocket_orderly_close(&mut socket, opened, &mut terminal_sequence).await;
    }
    finish_protocol_session(&mut session, transport).await;
}

async fn websocket_record_and_send_item(
    socket: &mut WebSocket,
    session: &mut ProtocolSession,
    item: crate::outbound::OutboundItem,
    opening: bool,
    terminal: &mut WebSocketTerminalSequence,
    cancellation: &WebSocketSendCancellation<'_>,
) -> bool {
    let managed_by_sm = match session.record_outbound_item(&item).await {
        Ok(managed) => managed,
        Err(_) => {
            session.sm_resume_allowed = false;
            let domain = session.state.config.domain.clone();
            websocket_fatal_error(
                socket,
                &domain,
                opening,
                crate::xmpp::xml_util::stream_error("internal-server-error"),
                terminal,
            )
            .await;
            return false;
        }
    };
    let socket_delivery = if let Some(delivery) = item.durable_delivery.filter(|_| !managed_by_sm) {
        match tokio::time::timeout(
            C2S_BACKEND_OPERATION_TIMEOUT,
            session.state.replay_service().fence_socket_write(delivery),
        )
        .await
        {
            Ok(Ok(delivery)) => Some(delivery),
            Ok(Err(error)) => {
                tracing::error!(?error, message_id = %delivery.message_id, "failed to fence durable WebSocket write");
                session.sm_resume_allowed = false;
                let domain = session.state.config.domain.clone();
                websocket_fatal_error(
                    socket,
                    &domain,
                    opening,
                    crate::xmpp::xml_util::stream_error("internal-server-error"),
                    terminal,
                )
                .await;
                return false;
            }
            Err(_) => {
                tracing::error!(message_id = %delivery.message_id, "timed out fencing durable WebSocket write");
                session.sm_resume_allowed = false;
                let domain = session.state.config.domain.clone();
                websocket_fatal_error(
                    socket,
                    &domain,
                    opening,
                    crate::xmpp::xml_util::stream_error("internal-server-error"),
                    terminal,
                )
                .await;
                return false;
            }
        }
    } else {
        None
    };
    if !websocket_send_live(
        socket,
        Message::Text(item.stanza.clone().into()),
        cancellation,
    )
    .await
    {
        return false;
    }
    if !managed_by_sm {
        item.confirm_transport_ownership();
    }
    if let Some(delivery) = socket_delivery {
        match tokio::time::timeout(
            C2S_BACKEND_OPERATION_TIMEOUT,
            session
                .state
                .replay_service()
                .acknowledge_socket_write(delivery),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::warn!(?error, message_id = %delivery.message_id, "WebSocket write succeeded but durable delivery acknowledgement failed")
            }
            Err(_) => {
                tracing::warn!(message_id = %delivery.message_id, "WebSocket write succeeded but durable delivery acknowledgement timed out")
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn websocket_terminal_write_runs_after_session_disconnect_is_latched() {
        let disconnect = tokio_util::sync::CancellationToken::new();
        disconnect.cancel();
        let mut write_polled = false;

        assert!(
            bounded_websocket_terminal_write(async {
                assert!(disconnect.is_cancelled());
                write_polled = true;
                Ok::<(), ()>(())
            })
            .await
        );
        assert!(write_polled);
    }

    #[test]
    fn websocket_shutdown_finishes_exactly_one_terminal_sequence() {
        let mut terminal = WebSocketTerminalSequence::default();
        assert!(needs_shutdown_terminal_sequence(false, true, &terminal));
        assert!(terminal.begin());
        assert!(!needs_shutdown_terminal_sequence(true, true, &terminal));
        assert!(!terminal.begin());
    }

    #[test]
    fn websocket_terminal_action_orders_replies_before_both_close_frames() {
        let messages = websocket_terminal_messages(
            vec!["<iq id='account-remove' type='result'/>".to_owned()],
            true,
        );
        assert_eq!(messages.len(), 3);
        assert!(matches!(
            &messages[0],
            Message::Text(reply) if reply.contains("account-remove")
        ));
        assert!(matches!(
            &messages[1],
            Message::Text(close) if close.as_str() == websocket_close()
        ));
        assert!(matches!(&messages[2], Message::Close(None)));
    }

    #[test]
    fn peer_idle_deadline_changes_only_for_peer_traffic_or_authentication() {
        let started = tokio::time::Instant::now();
        let mut tracker = PeerIdleTracker::new(false, started);
        assert_eq!(tracker.deadline, started + C2S_NEGOTIATION_IDLE_TIMEOUT);

        // Local queue/timer selection does not call either mutating method.
        // Merely re-entering the loop with the same auth state must preserve
        // the original absolute deadline.
        let local_event = started + Duration::from_secs(5);
        tracker.synchronize_authentication(false, local_event);
        assert_eq!(tracker.deadline, started + C2S_NEGOTIATION_IDLE_TIMEOUT);

        tracker.note_peer_traffic(false, local_event);
        assert_eq!(tracker.deadline, local_event + C2S_NEGOTIATION_IDLE_TIMEOUT);

        let authenticated_at = started + Duration::from_secs(7);
        tracker.synchronize_authentication(true, authenticated_at);
        assert_eq!(
            tracker.deadline,
            authenticated_at + C2S_AUTHENTICATED_IDLE_TIMEOUT
        );
    }

    #[test]
    fn accepts_utf8_split_between_network_reads() {
        let encoded = "消息".as_bytes();
        let mut pending = encoded[..2].to_vec();
        let mut output = String::new();
        append_utf8(&mut pending, &mut output).unwrap();
        assert!(output.is_empty());
        pending.extend_from_slice(&encoded[2..]);
        append_utf8(&mut pending, &mut output).unwrap();
        assert_eq!(output, "消息");
    }

    #[test]
    fn websocket_frames_must_start_with_markup() {
        assert!(crate::transport_parsing::websocket_frame_starts_with_markup("<response/>"));
        assert!(
            crate::transport_parsing::websocket_frame_starts_with_markup(
                "<?xml version='1.0'?><response/>"
            )
        );
        for invalid in ["", " <response/>", "\n<response/>", "x<response/>"] {
            assert!(
                !crate::transport_parsing::websocket_frame_starts_with_markup(invalid),
                "{invalid:?}"
            );
        }
    }

    #[test]
    fn websocket_accepts_a_strict_utf8_xml_declaration() {
        let mut framer = XmlEntityFramer::default();
        assert_eq!(
            take_websocket_frame("<?xml version='1.0' encoding='UTF-8'?><open xmlns='urn:ietf:params:xml:ns:xmpp-framing'/>", &mut framer, MAX_XMPP_FRAME_BYTES).unwrap(),
            "<open xmlns='urn:ietf:params:xml:ns:xmpp-framing'/>"
        );
        assert!(take_websocket_frame(
            "<?xml version='1.0'?><message xmlns='jabber:client'/>",
            &mut framer,
            MAX_XMPP_FRAME_BYTES,
        )
        .is_err());
    }

    #[test]
    fn websocket_message_contains_exactly_one_frame_and_no_stream_whitespace() {
        let mut framer = XmlEntityFramer::default();
        assert_eq!(
            take_websocket_frame(
                "<message xmlns='jabber:client'/>",
                &mut framer,
                MAX_XMPP_FRAME_BYTES
            )
            .unwrap(),
            "<message xmlns='jabber:client'/>"
        );
        for invalid in [
            "",
            " <message xmlns='jabber:client'/>",
            "<message xmlns='jabber:client'/> ",
            "<message xmlns='jabber:client'/><presence xmlns='jabber:client'/>",
            "<message xmlns='jabber:client'>",
        ] {
            assert!(
                take_websocket_frame(
                    invalid,
                    &mut XmlEntityFramer::default(),
                    MAX_XMPP_FRAME_BYTES
                )
                .is_err(),
                "{invalid:?}"
            );
        }
    }

    #[test]
    fn websocket_frame_honors_the_advertised_one_mib_octet_limit() {
        let oversized = format!(
            "<message xmlns='jabber:client'><body>{}</body></message>",
            "x".repeat(MAX_XMPP_FRAME_BYTES)
        );
        assert!(take_websocket_frame(
            &oversized,
            &mut XmlEntityFramer::default(),
            MAX_XMPP_FRAME_BYTES
        )
        .is_err());
    }

    #[test]
    fn websocket_stream_headers_require_the_framing_namespace() {
        let server_open = websocket_server_open("example.test");
        let document = roxmltree::Document::parse(&server_open).unwrap();
        let root = document.root_element();
        assert_eq!(root.tag_name().namespace(), Some(WEBSOCKET_FRAMING_NS));
        assert_eq!(root.attribute("from"), Some("example.test"));
        assert_eq!(root.attribute("version"), Some("1.0"));
        assert_eq!(
            root.attribute(("http://www.w3.org/XML/1998/namespace", "lang")),
            Some("en")
        );
        assert!(!websocket_has_invalid_stream_header_namespace(
            "<open xmlns='urn:ietf:params:xml:ns:xmpp-framing'/>"
        ));
        assert!(!websocket_has_invalid_stream_header_namespace(
            "<message xmlns='jabber:client'/>"
        ));
        assert!(websocket_has_invalid_stream_header_namespace(
            "<open xmlns='jabber:client'/>"
        ));
        assert!(websocket_has_invalid_stream_header_namespace("<close/>"));
        assert!(!websocket_close_has_content(
            "<close xmlns='urn:ietf:params:xml:ns:xmpp-framing'/>"
        ));
        assert!(websocket_close_has_content(
            "<close xmlns='urn:ietf:params:xml:ns:xmpp-framing'> </close>"
        ));
        assert!(websocket_close_has_content(
            "<close xmlns='urn:ietf:params:xml:ns:xmpp-framing'><x/></close>"
        ));
    }

    #[tokio::test]
    async fn tcp_initial_header_failure_opens_errors_and_closes_the_stream() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        tcp_fatal_error(
            &mut server,
            "example.test",
            true,
            &crate::xmpp::xml_util::stream_error("invalid-namespace"),
        )
        .await
        .unwrap();
        drop(server);
        let mut received = String::new();
        client.read_to_string(&mut received).await.unwrap();
        assert!(received.starts_with("<stream:stream from='example.test'"));
        assert!(received.contains("<invalid-namespace"));
        assert!(received.ends_with("</stream:stream>"));
    }

    #[tokio::test]
    async fn tcp_backend_failure_is_a_terminal_internal_server_error_on_wire() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        tcp_fatal_error(
            &mut server,
            "example.test",
            false,
            &crate::xmpp::xml_util::stream_error("internal-server-error"),
        )
        .await
        .unwrap();
        drop(server);
        let mut received = String::new();
        client.read_to_string(&mut received).await.unwrap();
        assert!(received.contains("<internal-server-error"));
        assert!(received.ends_with("</stream:stream>"));
    }

    #[tokio::test]
    async fn tcp_terminal_write_failure_returns_instead_of_hanging() {
        let (client, mut server) = tokio::io::duplex(1);
        drop(client);
        let result = tokio::time::timeout(
            Duration::from_millis(250),
            tcp_fatal_error(
                &mut server,
                "example.test",
                false,
                &crate::xmpp::xml_util::stream_error("internal-server-error"),
            ),
        )
        .await;
        assert!(result.is_ok(), "terminal write exceeded the test bound");
        assert!(result.unwrap().is_err());
    }
}
