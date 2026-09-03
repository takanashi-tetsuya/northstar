use crate::{
    db,
    jid::{prepare_domainpart, CanonicalJid},
    services::{
        messaging::{
            DurableAdmissionOutcome, IdentityAuthority, LocalDelivery, MessageIdentity,
            MessagePostCommit, PersonalMessageDestination, ValidatedPersonalMessage,
        },
        retractions::{
            ArchiveWrite, DeliveryProjection, OwnerProjection, RetractionCommand, RetractionOutcome,
        },
    },
    state::AppState,
    xmpp::xml_builder::XmlElement,
    xmpp::xml_util::*,
};
use anyhow::{Context, Result};
use futures::FutureExt;
use roxmltree::Document;
use std::borrow::Cow;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
    sync::mpsc,
};
use tokio_rustls::TlsAcceptor;

fn hosted_s2s_domain(state: &AppState, target: &str) -> bool {
    let Ok(target) = prepare_domainpart(target) else {
        return false;
    };
    [
        state.config.domain.clone(),
        format!("pubsub.{}", state.config.domain),
        format!("conference.{}", state.config.domain),
        format!("mix.{}", state.config.domain),
    ]
    .into_iter()
    .filter_map(|domain| prepare_domainpart(&domain).ok())
    .any(|domain| domain == target)
}

fn locally_hosted_identity_domain(configured_domain: &str, candidate: &str) -> bool {
    [
        configured_domain.to_owned(),
        format!("pubsub.{configured_domain}"),
        format!("conference.{configured_domain}"),
        format!("mix.{configured_domain}"),
        format!("upload.{configured_domain}"),
    ]
    .iter()
    .any(|hosted| same_s2s_domain(candidate, hosted))
}

fn authenticated_s2s_sender(asserted: &str, authenticated_domain: &str) -> bool {
    let (Ok(asserted), Ok(authenticated_domain)) = (
        CanonicalJid::parse(asserted),
        prepare_domainpart(authenticated_domain),
    ) else {
        return false;
    };
    asserted.domainpart() == authenticated_domain
}

fn same_s2s_domain(left: &str, right: &str) -> bool {
    matches!(
        (prepare_domainpart(left), prepare_domainpart(right)),
        (Ok(left), Ok(right)) if left == right
    )
}

fn valid_starttls_request(raw: &str) -> bool {
    let Ok(document) = Document::parse(raw) else {
        return false;
    };
    let root = document.root_element();
    root.tag_name().name() == "starttls"
        && root.tag_name().namespace() == Some("urn:ietf:params:xml:ns:xmpp-tls")
        && root.attributes().len() == 0
        && !root.children().any(|child| child.is_element())
        && root.text().is_none_or(|text| text.trim().is_empty())
}

fn element_then_stream_close(element: XmlElement) -> String {
    let mut xml = element.finish();
    xml.push_str(&XmlElement::new("stream:stream").close());
    xml
}

fn sasl_failure_then_stream_close(condition: &'static str) -> String {
    element_then_stream_close(
        XmlElement::namespaced("failure", "urn:ietf:params:xml:ns:xmpp-sasl")
            .child(XmlElement::new(condition)),
    )
}

fn is_certificate_downgrade(element_name: &str, certificate_requires_external: bool) -> bool {
    certificate_requires_external && element_name == "result"
}

fn restore_inherited_dialback_namespace(raw: &str) -> Cow<'_, str> {
    let trimmed = raw.trim_start();
    let Some(name) = ["result", "verify"]
        .into_iter()
        .find(|name| trimmed.starts_with(&format!("<db:{name}")))
    else {
        return Cow::Borrowed(raw);
    };
    let opening_end = trimmed.find('>').unwrap_or(trimmed.len());
    if trimmed[..opening_end].contains("xmlns:db=") {
        return Cow::Borrowed(raw);
    }
    Cow::Owned(raw.replacen(
        &format!("<db:{name}"),
        &format!("<db:{name} xmlns:db='{DIALBACK_NS}'"),
        1,
    ))
}

fn pre_tls_features(state: &AppState) -> String {
    let mut features = crate::xmpp::xml_builder::XmlElement::new("stream:features").child(
        crate::xmpp::xml_builder::XmlElement::new("starttls")
            .attr("xmlns", "urn:ietf:params:xml:ns:xmpp-tls")
            .child(crate::xmpp::xml_builder::XmlElement::new("required")),
    );
    if state.config.federation_enabled {
        features = features.child(
            crate::xmpp::xml_builder::XmlElement::new("bidi")
                .attr("xmlns", "urn:xmpp:features:bidi"),
        );
    }
    features
        .validated_fragment(&negotiation_stream_limits_feature())
        .expect("server-generated stream limits must be valid XML")
        .finish()
}

use super::*;

async fn wait_for_federation_shutdown(cancel: &tokio_util::sync::CancellationToken) {
    cancel.cancelled().await;
}

async fn read_s2s_opening<S: AsyncRead + AsyncWrite + Unpin + Send>(
    stream: &mut S,
    local_domain: &str,
    input: &mut S2sInputState,
) -> Result<Option<S2sStreamOpening>> {
    let frame = match timed_read_frame(stream, input).await {
        Ok(frame) => frame,
        Err(error) => {
            if let Some(condition) = s2s_read_stream_error_condition(&error) {
                let _ = send_initial_stream_error(stream, local_domain, None, condition).await;
            }
            return Err(error);
        }
    };
    match parse_s2s_stream_opening(&frame) {
        Ok(opening) => Ok(Some(opening)),
        Err(condition) => {
            let remote_domain = stream_opening_remote_domain(&frame);
            send_initial_stream_error(stream, local_domain, remote_domain.as_deref(), condition)
                .await?;
            Ok(None)
        }
    }
}

async fn read_s2s_negotiation_frame<S: AsyncRead + AsyncWrite + Unpin + Send>(
    stream: &mut S,
    input: &mut S2sInputState,
) -> Result<String> {
    match timed_read_frame(stream, input).await {
        Ok(frame) => Ok(frame),
        Err(error) => {
            if let Some(condition) = s2s_read_stream_error_condition(&error) {
                let _ = send_stream_error(stream, condition).await;
            }
            Err(error)
        }
    }
}

pub async fn serve_s2s_tls(
    state: Arc<AppState>,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<()> {
    if !state.config.federation_enabled {
        wait_for_federation_shutdown(&cancel).await;
        return Ok(());
    }
    let listener = TcpListener::bind(state.config.s2s_tls_bind)
        .await
        .with_context(|| {
            format!(
                "could not bind S2S Direct TLS listener to {}",
                state.config.s2s_tls_bind
            )
        })?;
    tracing::info!(address = %state.config.s2s_tls_bind, "XMPP S2S Direct TLS listener ready");
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            accepted = listener.accept() => {
                let (stream, peer) = accepted?;
                let Ok(connection_permit) = state.try_acquire_s2s_connection() else {
                    tracing::debug!(%peer, "rejected XMPPS federation connection at the configured capacity limit");
                    continue;
                };
                let (tls_config, tls_generation) = s2s_server_config(&state, true)?;
                let acceptor = TlsAcceptor::from(tls_config);
                let state = Arc::clone(&state);
                let actors = state.connection_actors().clone();
                let actor_shutdown = actors.shutdown_token().child_token();
                let actor = inbound_xmpps_actor(
                    stream,
                    peer,
                    Arc::clone(&state),
                    acceptor,
                    tls_generation,
                    connection_permit,
                    actor_shutdown,
                );
                let result = actors.try_spawn(
                    crate::connection_actors::ConnectionActorKind::S2sInboundDirectTls,
                    Some(peer.to_string()),
                    actor,
                );
                if let Err(error) = result {
                    tracing::debug!(%peer, ?error, "rejected inbound XMPPS actor admission");
                }
            }
        }
    }
}

pub async fn serve(
    state: Arc<AppState>,
    mut outbound_wake: mpsc::Receiver<()>,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<()> {
    if !state.config.federation_enabled {
        tracing::warn!("server-to-server federation is disabled by policy");
        // This task is selected by main as a long-lived listener. Closing the
        // optional outbox wake channel is not a server shutdown signal.
        wait_for_federation_shutdown(&cancel).await;
        return Ok(());
    }
    let listener = TcpListener::bind(state.config.s2s_bind)
        .await
        .with_context(|| format!("could not bind S2S listener to {}", state.config.s2s_bind))?;
    tracing::info!(address = %state.config.s2s_bind, "XMPP S2S listener ready");
    let mut outbox_poll = tokio::time::interval(std::time::Duration::from_secs(1));
    outbox_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut outbound_wake_open = true;
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            accepted = listener.accept() => {
                let (stream, peer) = accepted?;
                let Ok(connection_permit) = state.try_acquire_s2s_connection() else {
                    tracing::debug!(%peer, "rejected federation connection at the configured capacity limit");
                    continue;
                };
                let (tls_config, tls_generation) = s2s_server_config(&state, false)?;
                let acceptor = TlsAcceptor::from(tls_config);
                let state = Arc::clone(&state);
                let actors = state.connection_actors().clone();
                let actor_shutdown = actors.shutdown_token().child_token();
                let actor = inbound_starttls_actor(
                    stream,
                    peer,
                    Arc::clone(&state),
                    acceptor,
                    tls_generation,
                    connection_permit,
                    actor_shutdown,
                );
                let result = actors.try_spawn(
                    crate::connection_actors::ConnectionActorKind::S2sInboundStartTls,
                    Some(peer.to_string()),
                    actor,
                );
                if let Err(error) = result {
                    tracing::debug!(%peer, ?error, "rejected inbound S2S actor admission");
                }
            }
            _ = outbox_poll.tick() => {
                if let Err(error) = dispatch_due_outbox(&state).await {
                    tracing::error!(?error, "failed to dispatch the durable federation outbox");
                }
            }
            wake = outbound_wake.recv(), if outbound_wake_open => {
                if wake.is_some() {
                    if let Err(error) = dispatch_due_outbox(&state).await {
                        tracing::error!(?error, "failed to dispatch the durable federation outbox after wake-up");
                    }
                } else {
                    // The periodic outbox poll and inbound listener remain
                    // valid after every sender of the optimization hint has
                    // gone away.
                    outbound_wake_open = false;
                }
            }
        }
    }
}

async fn inbound_xmpps_actor(
    stream: TcpStream,
    peer: std::net::SocketAddr,
    state: Arc<AppState>,
    acceptor: TlsAcceptor,
    tls_generation: u64,
    connection_permit: tokio::sync::OwnedSemaphorePermit,
    actor_shutdown: tokio_util::sync::CancellationToken,
) {
    let _connection_permit = connection_permit;
    state
        .metrics
        .federation_inbound_connections_total
        .fetch_add(1, Ordering::Relaxed);
    state
        .metrics
        .federation_inbound_active
        .fetch_add(1, Ordering::Relaxed);
    let connection = AssertUnwindSafe(inbound_xmpps_connection(
        stream,
        Arc::clone(&state),
        acceptor,
        tls_generation,
    ))
    .catch_unwind();
    tokio::pin!(connection);
    let shutdown = actor_shutdown.cancelled_owned();
    tokio::pin!(shutdown);
    let result = tokio::select! {
        _ = &mut shutdown => Ok(Ok(())),
        result = &mut connection => result,
    };
    if let Ok(Err(error)) = &result {
        tracing::debug!(%peer, ?error, "inbound XMPPS federation stream closed");
    }
    state
        .metrics
        .federation_inbound_active
        .fetch_sub(1, Ordering::Relaxed);
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

async fn inbound_starttls_actor(
    stream: TcpStream,
    peer: std::net::SocketAddr,
    state: Arc<AppState>,
    acceptor: TlsAcceptor,
    tls_generation: u64,
    connection_permit: tokio::sync::OwnedSemaphorePermit,
    actor_shutdown: tokio_util::sync::CancellationToken,
) {
    let _connection_permit = connection_permit;
    state
        .metrics
        .federation_inbound_connections_total
        .fetch_add(1, Ordering::Relaxed);
    state
        .metrics
        .federation_inbound_active
        .fetch_add(1, Ordering::Relaxed);
    let connection = AssertUnwindSafe(inbound_connection(
        stream,
        Arc::clone(&state),
        acceptor,
        tls_generation,
    ))
    .catch_unwind();
    tokio::pin!(connection);
    let shutdown = actor_shutdown.cancelled_owned();
    tokio::pin!(shutdown);
    let result = tokio::select! {
        _ = &mut shutdown => Ok(Ok(())),
        result = &mut connection => result,
    };
    if let Ok(Err(error)) = &result {
        tracing::debug!(%peer, ?error, "inbound federation stream closed");
    }
    state
        .metrics
        .federation_inbound_active
        .fetch_sub(1, Ordering::Relaxed);
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

pub(crate) async fn inbound_xmpps_connection(
    stream: TcpStream,
    state: Arc<AppState>,
    acceptor: TlsAcceptor,
    tls_generation: u64,
) -> Result<()> {
    stream.set_nodelay(true)?;
    let mut secure = tokio::time::timeout(IO_TIMEOUT, acceptor.accept(stream))
        .await
        .context("inbound XMPPS S2S TLS handshake timed out")??;
    if secure
        .get_ref()
        .1
        .alpn_protocol()
        .is_some_and(|protocol| protocol != b"xmpp-server")
    {
        anyhow::bail!("remote S2S endpoint selected an invalid ALPN protocol");
    }
    let direct_tls_sni = secure.get_ref().1.server_name().map(str::to_owned);
    let peer_certificates = secure
        .get_ref()
        .1
        .peer_certificates()
        .map(|certificates| certificates.to_vec())
        .unwrap_or_default();

    let mut input = S2sInputState::default();

    let Some(opening) = read_s2s_opening(&mut secure, &state.config.domain, &mut input).await?
    else {
        return Ok(());
    };
    let asserted_domain = opening.from;
    let target = opening.to;
    if locally_hosted_identity_domain(&state.config.domain, &asserted_domain) {
        send_initial_stream_error(
            &mut secure,
            &state.config.domain,
            Some(&asserted_domain),
            "invalid-from",
        )
        .await?;
        anyhow::bail!("inbound S2S stream asserted a locally hosted source domain");
    }
    if !crate::tls::direct_tls_sni_matches(direct_tls_sni.as_deref(), &target) {
        send_initial_stream_error(
            &mut secure,
            &state.config.domain,
            Some(&asserted_domain),
            "host-unknown",
        )
        .await?;
        anyhow::bail!("inbound S2S Direct TLS SNI does not match the stream target domain");
    }
    if !hosted_s2s_domain(&state, &target)
        || state.island_mode_enabled()
        || !state.federation_domain_allowed(&asserted_domain)
    {
        send_initial_stream_error(
            &mut secure,
            &state.config.domain,
            Some(&asserted_domain),
            "host-unknown",
        )
        .await?;
        anyhow::bail!("federation domain rejected by policy");
    }

    let receiving_stream_id = stream_id().to_string();
    write_xml(
        &mut secure,
        &server_open(&target, &asserted_domain, &receiving_stream_id),
    )
    .await?;
    let Some(authentication) = authenticate_secure_inbound(
        &mut secure,
        Arc::clone(&state),
        asserted_domain.clone(),
        target.clone(),
        receiving_stream_id.clone(),
        peer_certificates.clone(),
        &mut input,
    )
    .await?
    else {
        return Ok(());
    };
    tracing::info!(peer_domain = %asserted_domain, "S2S inbound XMPPS federation authenticated");
    drive_authenticated_inbound(
        secure,
        state,
        authentication.domain,
        target,
        authentication.bidi_enabled,
        authentication.peer_limits,
        input,
        authentication.via_external,
        peer_certificates,
        tls_generation,
    )
    .await
}

pub(crate) async fn inbound_connection(
    mut stream: TcpStream,
    state: Arc<AppState>,
    acceptor: TlsAcceptor,
    tls_generation: u64,
) -> Result<()> {
    stream.set_nodelay(true)?;
    let mut input = S2sInputState::default();
    let Some(opening) = read_s2s_opening(&mut stream, &state.config.domain, &mut input).await?
    else {
        return Ok(());
    };
    let claimed_domain = opening.from;
    let target = opening.to;
    if locally_hosted_identity_domain(&state.config.domain, &claimed_domain) {
        send_initial_stream_error(
            &mut stream,
            &state.config.domain,
            Some(&claimed_domain),
            "invalid-from",
        )
        .await?;
        anyhow::bail!("pre-TLS S2S stream asserted a locally hosted source domain");
    }
    if !hosted_s2s_domain(&state, &target)
        || state.island_mode_enabled()
        || claimed_domain.is_empty()
    {
        send_initial_stream_error(
            &mut stream,
            &state.config.domain,
            Some(&claimed_domain),
            "host-unknown",
        )
        .await?;
        anyhow::bail!("federation domain rejected by policy");
    }
    write_xml(
        &mut stream,
        &server_open(&target, &claimed_domain, &stream_id().to_string()),
    )
    .await?;
    write_xml(&mut stream, &pre_tls_features(&state)).await?;
    let starttls = read_s2s_negotiation_frame(&mut stream, &mut input).await?;
    if !valid_starttls_request(&starttls) {
        write_xml(
            &mut stream,
            &element_then_stream_close(XmlElement::namespaced(
                "failure",
                "urn:ietf:params:xml:ns:xmpp-tls",
            )),
        )
        .await?;
        anyhow::bail!("remote server did not negotiate STARTTLS");
    }
    write_xml(
        &mut stream,
        &XmlElement::namespaced("proceed", "urn:ietf:params:xml:ns:xmpp-tls").finish(),
    )
    .await?;
    let mut secure = tokio::time::timeout(IO_TIMEOUT, acceptor.accept(stream))
        .await
        .context("inbound S2S TLS handshake timed out")??;
    let peer_certificates = secure
        .get_ref()
        .1
        .peer_certificates()
        .map(|certificates| certificates.to_vec())
        .unwrap_or_default();
    // RFC 6120 requires every piece of information received above TCP before
    // TLS to be discarded.  This includes an incomplete UTF-8 prefix and the
    // pre-TLS asserted domain; only the fresh encrypted stream is authoritative.
    input.reset_entity();
    let Some(opening) = read_s2s_opening(&mut secure, &state.config.domain, &mut input).await?
    else {
        return Ok(());
    };
    let asserted_domain = opening.from;
    let target = opening.to;
    if locally_hosted_identity_domain(&state.config.domain, &asserted_domain) {
        send_initial_stream_error(
            &mut secure,
            &state.config.domain,
            Some(&asserted_domain),
            "invalid-from",
        )
        .await?;
        anyhow::bail!("post-TLS S2S stream asserted a locally hosted source domain");
    }
    if asserted_domain.is_empty()
        || !hosted_s2s_domain(&state, &target)
        || state.island_mode_enabled()
        || !state.federation_domain_allowed(&asserted_domain)
    {
        send_initial_stream_error(
            &mut secure,
            &state.config.domain,
            Some(&asserted_domain),
            "host-unknown",
        )
        .await?;
        anyhow::bail!("post-TLS federation domain rejected by policy");
    }
    let receiving_stream_id = stream_id().to_string();
    write_xml(
        &mut secure,
        &server_open(&target, &asserted_domain, &receiving_stream_id),
    )
    .await?;
    let Some(authentication) = authenticate_secure_inbound(
        &mut secure,
        Arc::clone(&state),
        asserted_domain.clone(),
        target.clone(),
        receiving_stream_id.clone(),
        peer_certificates.clone(),
        &mut input,
    )
    .await?
    else {
        return Ok(());
    };

    drive_authenticated_inbound(
        secure,
        state,
        authentication.domain,
        target,
        authentication.bidi_enabled,
        authentication.peer_limits,
        input,
        authentication.via_external,
        peer_certificates,
        tls_generation,
    )
    .await
}

struct InboundAuthentication {
    domain: String,
    bidi_enabled: bool,
    peer_limits: AdvertisedStreamLimits,
    via_external: bool,
}

#[allow(clippy::too_many_arguments)]
async fn authenticate_secure_inbound(
    secure: &mut tokio_rustls::server::TlsStream<TcpStream>,
    state: Arc<AppState>,
    asserted_domain: String,
    target: String,
    receiving_stream_id: String,
    peer_certificates: Vec<tokio_rustls::rustls::pki_types::CertificateDer<'static>>,
    input: &mut S2sInputState,
) -> Result<Option<InboundAuthentication>> {
    let certificate_identity = if state.config.s2s_sasl_external_enabled {
        match verify_peer_domain(&state, &peer_certificates, &asserted_domain) {
            Ok(identity) => identity,
            Err(error) => {
                tracing::warn!(
                    peer_domain = asserted_domain,
                    ?error,
                    "could not validate the inbound S2S certificate"
                );
                None
            }
        }
    } else {
        None
    };
    write_xml(secure, &features(&state, certificate_identity.is_some())).await?;
    let mut authentication = read_s2s_negotiation_frame(secure, input).await?;
    let bidi_request = parse_bidi_request(&authentication);
    if bidi_request.is_some() {
        authentication = read_s2s_negotiation_frame(secure, input).await?;
    }
    // The `db` prefix is normally declared once on `<stream:stream>`. Frames
    // are parsed independently after incremental framing, so restore that
    // inherited namespace only when the dialback root did not redeclare it.
    // Explicit conflicting bindings remain untouched and fail authorization.
    let parseable_authentication = restore_inherited_dialback_namespace(&authentication);
    let document =
        Document::parse(&parseable_authentication).context("invalid S2S authentication stanza")?;
    let element = document.root_element();
    // `roxmltree::Node` and every `&str` obtained from it are frame-local
    // borrows.  Materialize the complete authentication request before the
    // first socket/database await so the connection actor's future remains
    // `Send + 'static` independently of the parser's lifetimes.
    let element_name = element.tag_name().name().to_owned();
    let element_namespace = element.tag_name().namespace().map(str::to_owned);
    let external_shape_valid = valid_external_auth_shape(element);
    let mechanism = element.attribute("mechanism").map(str::to_owned);
    let encoded_authorization = element.text().unwrap_or_default().to_owned();
    let response_type = element.attribute("type").map(str::to_owned);
    let request_from = element.attribute("from").map(str::to_owned);
    let request_to = element.attribute("to").map(str::to_owned);
    let request_id = element.attribute("id").map(str::to_owned);
    let supplied_key = element.text().unwrap_or_default().trim().to_owned();
    drop(document);
    drop(parseable_authentication);

    if element_name == "auth"
        && element_namespace.as_deref() == Some("urn:ietf:params:xml:ns:xmpp-sasl")
    {
        if !external_shape_valid {
            write_xml(secure, &sasl_failure_then_stream_close("malformed-request")).await?;
            anyhow::bail!("remote server sent a malformed SASL authentication request");
        }
        if !state.config.s2s_sasl_external_enabled || mechanism.as_deref() != Some("EXTERNAL") {
            write_xml(secure, &sasl_failure_then_stream_close("invalid-mechanism")).await?;
            anyhow::bail!("remote server selected a disabled or invalid SASL mechanism");
        }
        if encoded_authorization.len() > 2_048 {
            write_xml(secure, &sasl_failure_then_stream_close("invalid-authzid")).await?;
            anyhow::bail!("SASL EXTERNAL authorization identity exceeds its size limit");
        }
        let authorization = match decode_external(&encoded_authorization) {
            Ok(authorization) => authorization,
            Err(error) => {
                write_xml(
                    secure,
                    &sasl_failure_then_stream_close("incorrect-encoding"),
                )
                .await?;
                return Err(error).context("invalid SASL EXTERNAL response encoding");
            }
        };
        let authenticated_domain = match prepare_domainpart(if authorization.is_empty() {
            &asserted_domain
        } else {
            &authorization
        }) {
            Ok(domain) => domain,
            Err(error) => {
                write_xml(secure, &sasl_failure_then_stream_close("invalid-authzid")).await?;
                return Err(error).context("SASL EXTERNAL authorization identity is not a domain");
            }
        };
        let certificate_identity = if same_s2s_domain(&authenticated_domain, &asserted_domain) {
            certificate_identity
        } else {
            None
        };
        let Some(certificate_identity) = certificate_identity else {
            write_xml(secure, &sasl_failure_then_stream_close("not-authorized")).await?;
            anyhow::bail!("S2S certificate does not authorize the asserted domain");
        };
        tracing::debug!(
            peer_domain = %authenticated_domain,
            identity = ?certificate_identity,
            "authenticated inbound S2S certificate identity"
        );
        write_xml(
            secure,
            &XmlElement::namespaced("success", "urn:ietf:params:xml:ns:xmpp-sasl").finish(),
        )
        .await?;
        input.reset_entity();
        let Some(opening) = read_s2s_opening(secure, &target, input).await? else {
            return Ok(None);
        };
        if !same_s2s_domain(&opening.from, &authenticated_domain) {
            send_initial_stream_error(secure, &target, Some(&authenticated_domain), "invalid-from")
                .await?;
            anyhow::bail!("post-SASL S2S stream asserted a different source domain");
        }
        if !same_s2s_domain(&opening.to, &target) {
            send_initial_stream_error(secure, &target, Some(&authenticated_domain), "host-unknown")
                .await?;
            anyhow::bail!("post-SASL S2S stream asserted a different target domain");
        }
        write_xml(
            secure,
            &server_open(&target, &authenticated_domain, &stream_id().to_string()),
        )
        .await?;
        let features = crate::xmpp::xml_builder::XmlElement::new("stream:features")
            .validated_fragment(&stream_limits_feature())?
            .finish();
        write_xml(secure, &features).await?;
        return Ok(Some(InboundAuthentication {
            domain: authenticated_domain,
            bidi_enabled: bidi_request.is_some(),
            peer_limits: bidi_request.map_or_else(AdvertisedStreamLimits::default, |request| {
                request.peer_limits
            }),
            via_external: true,
        }));
    }

    if !state.config.dialback_enabled || element_namespace.as_deref() != Some(DIALBACK_NS) {
        send_stream_error(secure, "not-authorized").await?;
        anyhow::bail!("remote server did not select an offered S2S authentication mechanism");
    }
    let certificate_requires_external = certificate_identity.is_some();
    if response_type.is_some() {
        // Verification/result responses are valid only on connections for
        // which this server has emitted the matching request. XEP-0220 warns
        // that accepting an unsolicited response permits identity spoofing;
        // ignore it without turning a non-fatal Dialback error into a stream
        // error.
        tracing::warn!(
            peer_domain = asserted_domain,
            "ignored an unsolicited dialback response on an inbound stream"
        );
        return Ok(None);
    }
    let from_matches = request_from
        .as_deref()
        .is_some_and(|value| same_s2s_domain(value, &asserted_domain));
    let to_matches = request_to
        .as_deref()
        .is_some_and(|value| same_s2s_domain(value, &target));
    if !from_matches || !to_matches {
        send_stream_error(secure, "invalid-from").await?;
        anyhow::bail!("dialback stanza identity does not match the XML stream");
    }
    match element_name.as_str() {
        "verify" => {
            let id = request_id.as_deref().unwrap_or_default();
            if id.is_empty() || id.len() > 1_024 {
                write_xml(
                    secure,
                    &verify_error(&target, &asserted_domain, id, "bad-request"),
                )
                .await?;
                return Ok(None);
            }
            let valid = valid_key(&supplied_key)
                && matches_key(
                    &state.derive_dialback_key(&asserted_domain, &target, id),
                    &supplied_key,
                );
            write_xml(
                secure,
                &verify_response(&target, &asserted_domain, id, valid),
            )
            .await?;
            Ok(None)
        }
        "result" => {
            // A db:result authenticates the initiating content stream, so a
            // peer whose certificate already qualifies for our advertised
            // SASL EXTERNAL mechanism must not downgrade. A db:verify below
            // is different: it is the mandatory authoritative callback for a
            // separate Dialback exchange and must remain usable even when the
            // callback connection itself presents a valid certificate.
            if is_certificate_downgrade("result", certificate_requires_external) {
                send_stream_error(secure, "not-authorized").await?;
                anyhow::bail!(
                    "peer presented a valid XMPP certificate but attempted to downgrade to Dialback"
                );
            }
            if !valid_key(&supplied_key) {
                write_xml(secure, &result_response(&target, &asserted_domain, false)).await?;
                return Ok(None);
            }
            let verification = verify_remote_owned(
                Arc::clone(&state),
                asserted_domain.clone(),
                target.clone(),
                receiving_stream_id.clone(),
                supplied_key.clone(),
            )
            .await;
            match verification {
                Ok(DialbackOutcome::Valid) => {
                    write_xml(secure, &result_response(&target, &asserted_domain, true)).await?;
                    Ok(Some(InboundAuthentication {
                        domain: prepare_domainpart(&asserted_domain)
                            .context("dialback asserted an invalid originating domain")?,
                        bidi_enabled: bidi_request.is_some(),
                        peer_limits: bidi_request
                            .map_or_else(AdvertisedStreamLimits::default, |request| {
                                request.peer_limits
                            }),
                        via_external: false,
                    }))
                }
                Ok(DialbackOutcome::Invalid) => {
                    write_xml(secure, &result_response(&target, &asserted_domain, false)).await?;
                    Ok(None)
                }
                Ok(DialbackOutcome::Error(condition)) => {
                    tracing::warn!(
                        peer_domain = asserted_domain,
                        authoritative_condition = %condition,
                        "authoritative server returned a dialback verification error"
                    );
                    write_xml(
                        secure,
                        &result_error(&target, &asserted_domain, "remote-server-not-found"),
                    )
                    .await?;
                    Ok(None)
                }
                Err(error) => {
                    tracing::warn!(
                        peer_domain = asserted_domain,
                        ?error,
                        "dialback callback verification failed"
                    );
                    write_xml(
                        secure,
                        &result_error(&target, &asserted_domain, "remote-server-not-found"),
                    )
                    .await?;
                    Ok(None)
                }
            }
        }
        _ => {
            send_stream_error(secure, "not-authorized").await?;
            anyhow::bail!("unsupported dialback element")
        }
    }
}

async fn verify_remote_owned(
    state: Arc<AppState>,
    originating_domain: String,
    receiving_domain: String,
    stream_id: String,
    supplied_key: String,
) -> Result<DialbackOutcome> {
    verify_remote(
        state,
        &originating_domain,
        &receiving_domain,
        &stream_id,
        &supplied_key,
    )
    .await
}

fn valid_external_auth_shape(element: roxmltree::Node<'_, '_>) -> bool {
    element.tag_name().name() == "auth"
        && element.tag_name().namespace() == Some("urn:ietf:params:xml:ns:xmpp-sasl")
        && element.attributes().len() == 1
        && element.attribute("mechanism").is_some()
        && element
            .attributes()
            .all(|attribute| attribute.name() == "mechanism" && attribute.namespace().is_none())
        && element
            .children()
            .all(|child| child.is_text() && child.text().is_some())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BidiRequest {
    peer_limits: AdvertisedStreamLimits,
}

fn parse_bidi_request(raw: &str) -> Option<BidiRequest> {
    let document = Document::parse(raw).ok()?;
    let root = document.root_element();
    if root.tag_name().name() != "bidi"
        || root.tag_name().namespace() != Some("urn:xmpp:bidi")
        || root.attributes().len() != 0
        || root.children().any(|child| {
            child.is_text() && child.text().is_some_and(|text| !text.trim().is_empty())
        })
    {
        return None;
    }
    let mut children = root.children().filter(|child| child.is_element());
    let peer_limits = match children.next() {
        None => AdvertisedStreamLimits::default(),
        Some(limits)
            if limits.tag_name().name() == "limits"
                && limits.tag_name().namespace() == Some(STREAM_LIMITS_NS)
                && children.next().is_none() =>
        {
            parse_stream_limits_element(limits)?
        }
        Some(_) => return None,
    };
    Some(BidiRequest { peer_limits })
}

#[allow(clippy::too_many_arguments)]
async fn drive_authenticated_inbound(
    secure: tokio_rustls::server::TlsStream<TcpStream>,
    state: Arc<AppState>,
    authenticated_domain: String,
    local_domain: String,
    bidi_enabled: bool,
    peer_limits: AdvertisedStreamLimits,
    input: S2sInputState,
    via_external: bool,
    peer_certificates: Vec<tokio_rustls::rustls::pki_types::CertificateDer<'static>>,
    tls_generation: u64,
) -> Result<()> {
    let connection_id = uuid::Uuid::new_v4();
    let disconnect = tokio_util::sync::CancellationToken::new();
    let certificate_session = if via_external {
        Some(state.tls.register_certificate_session(
            connection_id,
            crate::tls::CertificateSessionKind::InboundS2s,
            peer_certificates,
            tls_generation,
            disconnect.clone(),
        )?)
    } else {
        None
    };
    if disconnect.is_cancelled() {
        anyhow::bail!("inbound S2S certificate was explicitly revoked before route activation");
    }
    let (sender, receiver) = mpsc::channel(256);
    let domain = prepare_domainpart(&authenticated_domain)
        .context("authenticated S2S domain became invalid")?;
    let local_domain =
        prepare_domainpart(&local_domain).context("local S2S stream domain became invalid")?;
    let route_key = bidi_connection_key(&local_domain, &domain)
        .context("bidirectional S2S route domains became invalid")?;
    // When another stream already owns the route, retain this stream's sender
    // until its authenticated loop exits. This preserves the prior
    // conditionally-moved sender lifetime and prevents its receiver from being
    // closed merely because the registry rejected publication.
    let mut unregistered_bidi_session = None;
    let registered = if bidi_enabled {
        match state
            .s2s_connection_registry()
            .register_bidirectional_if_vacant(
                route_key.clone(),
                BidiS2sSession::new(connection_id, local_domain.clone(), sender),
            ) {
            Ok(()) => {
                tracing::debug!(peer_domain = %domain, %local_domain, "XEP-0288 bidirectional S2S stream enabled");
                true
            }
            Err(session) => {
                unregistered_bidi_session = Some(session);
                tracing::debug!(peer_domain = %domain, %local_domain, "kept the existing bidirectional S2S route");
                false
            }
        }
    } else {
        // The unregistered sender remains alive across the authenticated loop,
        // exactly as before the registry boundary.
        unregistered_bidi_session = Some(BidiS2sSession::new(
            connection_id,
            local_domain.clone(),
            sender,
        ));
        false
    };
    let result = AssertUnwindSafe(drive_authenticated_inbound_inner(
        secure,
        Arc::clone(&state),
        authenticated_domain.clone(),
        local_domain.clone(),
        connection_id,
        registered,
        peer_limits,
        receiver,
        input,
        disconnect,
    ))
    .catch_unwind()
    .await;
    // Socket ownership ended with the authenticated loop. Unregister before
    // potentially slow MUC/route reconciliation so a concurrent TLS reload
    // cannot report a drain for a connection which is already closed.
    drop(certificate_session);
    if registered {
        state
            .s2s_connection_registry()
            .remove_bidirectional_if_connection(&route_key, connection_id);
    }
    crate::xmpp::protocol::caps::federated_caps_connection_closed(&state, connection_id).await;
    let cleanup = AssertUnwindSafe(
        crate::xmpp::protocol::federated_muc::federated_muc_connection_closed(
            &state,
            &authenticated_domain,
            connection_id,
        ),
    )
    .catch_unwind()
    .await;
    drop(unregistered_bidi_session);
    match result {
        Ok(result) => match cleanup {
            Ok(Ok(())) => result,
            Ok(Err(error)) => {
                tracing::warn!(
                    peer_domain = %authenticated_domain,
                    %connection_id,
                    ?error,
                    "failed to clean up federated MUC occupants after S2S disconnect"
                );
                result
            }
            Err(panic) => std::panic::resume_unwind(panic),
        },
        Err(panic) => {
            match cleanup {
                Ok(Ok(())) => {}
                Ok(Err(error)) => tracing::warn!(
                    peer_domain = %authenticated_domain,
                    %connection_id,
                    ?error,
                    "failed to clean up federated MUC occupants after S2S actor panic"
                ),
                Err(_) => tracing::error!(
                    peer_domain = %authenticated_domain,
                    %connection_id,
                    "federated MUC cleanup also panicked while unwinding an S2S actor panic"
                ),
            }
            std::panic::resume_unwind(panic)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn drive_authenticated_inbound_inner(
    mut secure: tokio_rustls::server::TlsStream<TcpStream>,
    state: Arc<AppState>,
    authenticated_domain: String,
    local_domain: String,
    connection_id: uuid::Uuid,
    bidi_enabled: bool,
    peer_limits: AdvertisedStreamLimits,
    mut outgoing: mpsc::Receiver<FederationEnvelope>,
    mut input: S2sInputState,
    disconnect: tokio_util::sync::CancellationToken,
) -> Result<()> {
    let mut incoming_idle_deadline = tokio::time::Instant::now() + S2S_AUTHENTICATED_IDLE_TIMEOUT;
    let peer_keepalive_period = keepalive_interval_for_peer(peer_limits);
    let mut peer_keepalive = tokio::time::interval_at(
        tokio::time::Instant::now() + peer_keepalive_period,
        peer_keepalive_period,
    );
    peer_keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let disconnect_signal = disconnect.cancelled_owned();
    tokio::pin!(disconnect_signal);
    loop {
        tokio::select! {
            _ = &mut disconnect_signal => {
                let _ = send_stream_error(&mut secure, "not-authorized").await;
                anyhow::bail!("inbound S2S certificate was explicitly revoked");
            }
            frame = read_frame_until_idle_deadline(
                &mut secure,
                &mut input,
                S2S_AUTHENTICATED_IDLE_TIMEOUT,
                &mut incoming_idle_deadline,
            ) => {
                let frame = match frame {
                    Ok(Some(frame)) => frame,
                    Err(error) => {
                        if let Some(condition) = s2s_read_stream_error_condition(&error) {
                            let _ = send_stream_error(&mut secure, condition).await;
                        }
                        return Err(error);
                    }
                    Ok(None) => {
                        tracing::debug!(peer_domain = authenticated_domain, "closed idle authenticated S2S stream");
                        write_xml(&mut secure, &XmlElement::new("stream:stream").close()).await?;
                        return Ok(());
                    }
                };
                if frame.starts_with("</stream:stream") {
                    write_xml(&mut secure, &XmlElement::new("stream:stream").close()).await?;
                    return Ok(());
                }
                match route_inbound_for_connection_owned(
                    Arc::clone(&state),
                    authenticated_domain.clone(),
                    local_domain.clone(),
                    connection_id,
                    frame.clone(),
                )
                .await?
                {
                    InboundFederationRoute::Reply(Some(reply)) => {
                        if let Some(reply) = reply_within_peer_limit(
                            &reply,
                            &frame,
                            peer_limits.max_bytes,
                        )? {
                            write_xml(&mut secure, &reply).await?;
                            if peer_limits.idle_seconds.is_some() {
                                peer_keepalive.reset_after(peer_keepalive_period);
                            }
                        }
                    }
                    InboundFederationRoute::Reply(None) => {}
                    InboundFederationRoute::StreamError(condition) => {
                        send_stream_error(&mut secure, condition).await?;
                        anyhow::bail!("remote S2S stanza violated stream addressing: {condition}");
                    }
                }
            }
            envelope = outgoing.recv(), if bidi_enabled => {
                let Some(mut envelope) = envelope else { return Ok(()) };
                if let Err(error) = deliver_envelope(&state, &mut secure, &mut envelope, peer_limits.max_bytes).await {
                    let permanent = is_peer_stanza_limit_error(&error);
                    fail_envelope(&state, &envelope, &error, permanent).await;
                    if permanent {
                        continue;
                    }
                    return Err(error);
                }
                if peer_limits.idle_seconds.is_some() {
                    peer_keepalive.reset_after(peer_keepalive_period);
                }
            }
            _ = peer_keepalive.tick(), if bidi_enabled && peer_limits.idle_seconds.is_some() => {
                write_xml(&mut secure, " ").await?;
            }
        }
    }
}

/// Serialize a response under the peer-advertised XEP-0478 byte limit. When
/// the intended response is too large, prefer the specification's compact
/// `policy-violation` stanza error. A peer can advertise a limit so small
/// that even the error cannot fit (including zero); in that case emitting no
/// stanza is the only way to honor the advertised receive limit.
pub(crate) fn reply_within_peer_limit(
    reply: &str,
    request: &str,
    peer_max_bytes: Option<usize>,
) -> Result<Option<String>> {
    match super::outbound::serialize_for_peer(reply, peer_max_bytes) {
        Ok(reply) => Ok(Some(reply)),
        Err(error) if super::outbound::is_peer_stanza_limit_error(&error) => {
            let error_reply = Document::parse(request).ok().and_then(|document| {
                let root = document.root_element();
                (root.attribute("type") != Some("error")
                    && matches!(root.tag_name().name(), "iq" | "message" | "presence"))
                .then(|| s2s_stanza_error(root, "modify", "policy-violation"))
            });
            let Some(error_reply) = error_reply else {
                return Ok(None);
            };
            match super::outbound::serialize_for_peer(&error_reply, peer_max_bytes) {
                Ok(error_reply) => Ok(Some(error_reply)),
                Err(error) if super::outbound::is_peer_stanza_limit_error(&error) => Ok(None),
                Err(error) => Err(error),
            }
        }
        Err(error) => Err(error),
    }
}

pub(crate) async fn route_inbound_component(
    state: &Arc<AppState>,
    authenticated_domain: &str,
    connection_id: uuid::Uuid,
    raw: &str,
) -> Result<Option<String>> {
    if !valid_inbound_wire_namespace(raw) {
        return Ok(None);
    }
    let client_raw = client_namespace(raw);
    if let MixDispatch::Handled(reply) =
        route_inbound_mix(state, authenticated_domain, &client_raw, false).await?
    {
        return Ok(reply);
    }
    route_inbound_scoped(
        state,
        authenticated_domain,
        InboundRouteAuthority::Component { connection_id },
        raw,
    )
    .await
}

/// Owned actor boundary for external-component routing.  Component sockets
/// are supervised as `Send + 'static` actors; keeping the state and both XML
/// identities owned here prevents parser/frame borrows from leaking into that
/// task's opaque future while preserving the same authorization path below.
pub(crate) async fn route_inbound_component_owned(
    state: Arc<AppState>,
    authenticated_domain: String,
    connection_id: uuid::Uuid,
    raw: String,
) -> Result<Option<String>> {
    route_inbound_component(&state, &authenticated_domain, connection_id, &raw).await
}

pub(crate) async fn route_inbound_for_connection(
    state: &Arc<AppState>,
    authenticated_domain: &str,
    local_domain: &str,
    connection_id: uuid::Uuid,
    raw: &str,
) -> Result<InboundFederationRoute> {
    if state.island_mode_enabled() {
        return Ok(InboundFederationRoute::Reply(None));
    }
    if invalid_inbound_core_namespace(raw) {
        return Ok(InboundFederationRoute::StreamError("invalid-namespace"));
    }
    if !valid_inbound_wire_namespace(raw) {
        return Ok(InboundFederationRoute::Reply(None));
    }
    if let Some(condition) = s2s_stream_address_error(raw, authenticated_domain, local_domain) {
        return Ok(InboundFederationRoute::StreamError(condition));
    }
    let client_raw = client_namespace(raw);
    if let MixDispatch::Handled(reply) =
        route_inbound_mix(state, authenticated_domain, &client_raw, true).await?
    {
        return Ok(InboundFederationRoute::Reply(reply));
    }
    Ok(InboundFederationRoute::Reply(
        route_inbound_scoped(
            state,
            authenticated_domain,
            InboundRouteAuthority::Federation { connection_id },
            raw,
        )
        .await?,
    ))
}

async fn route_inbound_for_connection_owned(
    state: Arc<AppState>,
    authenticated_domain: String,
    local_domain: String,
    connection_id: uuid::Uuid,
    raw: String,
) -> Result<InboundFederationRoute> {
    route_inbound_for_connection(
        &state,
        &authenticated_domain,
        &local_domain,
        connection_id,
        &raw,
    )
    .await
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum InboundFederationRoute {
    Reply(Option<String>),
    StreamError(&'static str),
}

/// Enforce the hop-by-hop S2S address authorization rules before any stanza
/// reaches an application handler. RFC 6120 sections 8.1.1.2 and 8.1.2.2
/// require these failures to terminate the stream, rather than being reflected
/// as ordinary stanza errors.
fn s2s_stream_address_error(
    raw: &str,
    authenticated_domain: &str,
    local_domain: &str,
) -> Option<&'static str> {
    let document = Document::parse(raw).ok()?;
    let root = document.root_element();
    let from = root
        .attribute("from")
        .and_then(|value| CanonicalJid::parse(value).ok());
    let to = root
        .attribute("to")
        .and_then(|value| CanonicalJid::parse(value).ok());
    let (Some(from), Some(to)) = (from, to) else {
        return Some("improper-addressing");
    };
    if !same_s2s_domain(from.domainpart(), authenticated_domain) {
        return Some("invalid-from");
    }
    if !same_s2s_domain(to.domainpart(), local_domain) {
        return Some("host-unknown");
    }
    None
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InboundRouteAuthority {
    Federation { connection_id: uuid::Uuid },
    Component { connection_id: uuid::Uuid },
}

enum MixDispatch {
    NotMix,
    Handled(Option<String>),
}

async fn route_inbound_mix(
    state: &Arc<AppState>,
    authenticated_domain: &str,
    client_raw: &str,
    enforce_federation_policy: bool,
) -> Result<MixDispatch> {
    let document = Document::parse(client_raw).context("invalid federated stanza")?;
    let root = document.root_element();
    match validate_inbound_core_stanza(root) {
        InboundCoreValidation::Valid => {}
        InboundCoreValidation::Drop => return Ok(MixDispatch::Handled(None)),
        InboundCoreValidation::Error(condition) => {
            return Ok(MixDispatch::Handled(Some(s2s_stanza_error(
                root, "modify", condition,
            ))));
        }
    }
    let from = root.attribute("from").unwrap_or_default();
    let to = root.attribute("to").unwrap_or_default();
    if enforce_federation_policy && !state.federation_entity_allowed(from) {
        return Ok(MixDispatch::Handled(Some(s2s_stanza_error(
            root,
            "auth",
            "not-authorized",
        ))));
    }
    let target_is_mix = CanonicalJid::parse(to).is_ok_and(|jid| {
        same_s2s_domain(jid.domainpart(), &format!("mix.{}", state.config.domain))
    });
    let source_is_mix = prepare_domainpart(authenticated_domain).is_ok_and(|domain| {
        domain.strip_prefix("mix.").is_some()
            && CanonicalJid::parse(from).is_ok_and(|jid| same_s2s_domain(jid.domainpart(), &domain))
    });
    if !target_is_mix && !source_is_mix {
        return Ok(MixDispatch::NotMix);
    }
    if !authenticated_s2s_sender(from, authenticated_domain) {
        return Ok(MixDispatch::Handled(Some(s2s_stanza_error(
            root,
            "auth",
            "not-authorized",
        ))));
    }
    let stanza_name = root.tag_name().name().to_owned();
    let unsupported_error = s2s_stanza_error(root, "cancel", "unsupported-stanza-type");
    drop(document);
    let consumed = match stanza_name.as_str() {
        "iq" => {
            federated_mix_iq_owned(
                Arc::clone(state),
                authenticated_domain.to_owned(),
                client_raw.to_owned(),
            )
            .await?
        }
        "message" => {
            federated_mix_message_owned(
                Arc::clone(state),
                authenticated_domain.to_owned(),
                client_raw.to_owned(),
            )
            .await?
        }
        "presence" => {
            federated_mix_presence_owned(
                Arc::clone(state),
                authenticated_domain.to_owned(),
                client_raw.to_owned(),
            )
            .await?
        }
        _ => false,
    };
    Ok(MixDispatch::Handled(
        (!consumed).then_some(unsupported_error),
    ))
}

async fn federated_mix_iq_owned(
    state: Arc<AppState>,
    authenticated_domain: String,
    raw: String,
) -> Result<bool> {
    crate::xmpp::protocol::mix::federated_mix_iq(state, &authenticated_domain, raw).await
}

async fn federated_mix_message_owned(
    state: Arc<AppState>,
    authenticated_domain: String,
    raw: String,
) -> Result<bool> {
    crate::xmpp::protocol::mix::federated_mix_message(state, &authenticated_domain, raw).await
}

async fn federated_mix_presence_owned(
    state: Arc<AppState>,
    authenticated_domain: String,
    raw: String,
) -> Result<bool> {
    crate::xmpp::protocol::mix::federated_mix_presence(state, &authenticated_domain, raw).await
}

async fn route_inbound_scoped(
    state: &AppState,
    authenticated_domain: &str,
    authority: InboundRouteAuthority,
    raw: &str,
) -> Result<Option<String>> {
    if matches!(authority, InboundRouteAuthority::Federation { .. }) && state.island_mode_enabled()
    {
        return Ok(None);
    }
    if !valid_inbound_wire_namespace(raw) {
        return Ok(None);
    }
    let client_raw = client_namespace(raw);
    let document = Document::parse(&client_raw).context("invalid federated stanza")?;
    let root = document.root_element();
    match validate_inbound_core_stanza(root) {
        InboundCoreValidation::Valid => {}
        InboundCoreValidation::Drop => return Ok(None),
        InboundCoreValidation::Error(condition) => {
            return Ok(Some(s2s_stanza_error(root, "modify", condition)));
        }
    }
    let raw_from = root.attribute("from").unwrap_or_default();
    let raw_to = root.attribute("to").unwrap_or_default();
    let (Ok(from_jid), Ok(to_jid)) = (CanonicalJid::parse(raw_from), CanonicalJid::parse(raw_to))
    else {
        return Ok(Some(s2s_stanza_error(root, "modify", "jid-malformed")));
    };
    let from = from_jid.to_string();
    let to = to_jid.to_string();
    if matches!(authority, InboundRouteAuthority::Federation { .. })
        && !state.federation_entity_allowed(&from)
    {
        return Ok(Some(s2s_stanza_error(root, "auth", "not-authorized")));
    }
    let from_is_authenticated = authenticated_s2s_sender(&from, authenticated_domain);
    let to_domain = to_jid.domainpart();
    if matches!(authority, InboundRouteAuthority::Component { .. })
        && (!from_is_authenticated || !component_local_target(state, to_domain))
    {
        return Ok(Some(s2s_stanza_error(root, "auth", "not-authorized")));
    }
    let to_is_muc_service =
        same_s2s_domain(to_domain, &format!("conference.{}", state.config.domain));
    if to_is_muc_service {
        if !from_is_authenticated {
            return Ok(Some(s2s_stanza_error(root, "auth", "not-authorized")));
        }
        let connection_id = match authority {
            InboundRouteAuthority::Federation { connection_id }
            | InboundRouteAuthority::Component { connection_id } => connection_id,
        };
        return match root.tag_name().name() {
            "presence" => {
                crate::xmpp::protocol::federated_muc::federated_muc_presence(
                    state,
                    authenticated_domain,
                    connection_id,
                    root,
                    &client_raw,
                )
                .await
            }
            "message" => {
                crate::xmpp::protocol::federated_muc::federated_muc_message(
                    state,
                    authenticated_domain,
                    connection_id,
                    root,
                    &client_raw,
                )
                .await
            }
            "iq" => {
                crate::xmpp::protocol::federated_muc::federated_muc_iq(
                    state,
                    authenticated_domain,
                    connection_id,
                    root,
                    &client_raw,
                )
                .await
            }
            _ => Ok(Some(s2s_stanza_error(
                root,
                "cancel",
                "unsupported-stanza-type",
            ))),
        };
    }
    let to_is_upload_service = to_jid.localpart().is_none()
        && to_jid.resourcepart().is_none()
        && same_s2s_domain(to_domain, &format!("upload.{}", state.config.domain));
    if matches!(authority, InboundRouteAuthority::Component { .. }) && to_is_upload_service {
        // Upload reservations are owned and quota-accounted by a local user
        // row. An external component domain is authenticated, but is not a
        // local user and must never be converted into one implicitly.
        return Ok(Some(s2s_stanza_error(root, "auth", "not-authorized")));
    }
    if from_is_authenticated && state.config.component_domain_configured(to_domain) {
        return if state
            .federation
            .send(to_domain, client_raw.clone(), None)
            .await
        {
            Ok(None)
        } else {
            Ok(Some(s2s_stanza_error(
                root,
                "cancel",
                "service-unavailable",
            )))
        };
    }
    let to_is_local_domain = same_s2s_domain(to_domain, &state.config.domain);
    let to_is_pubsub_service = matches!(root.tag_name().name(), "iq" | "message")
        && to_jid.localpart().is_none()
        && same_s2s_domain(to_domain, &format!("pubsub.{}", state.config.domain));
    if !from_is_authenticated || (!to_is_local_domain && !to_is_pubsub_service) {
        return Ok(Some(s2s_stanza_error(root, "auth", "not-authorized")));
    }
    let connection_id = match authority {
        InboundRouteAuthority::Federation { connection_id }
        | InboundRouteAuthority::Component { connection_id } => connection_id,
    };
    match root.tag_name().name() {
        "message" if to_is_pubsub_service => {
            crate::xmpp::protocol::pubsub::handle_authorization_response(state, &from, root)
                .await?;
            Ok(None)
        }
        "message" => {
            route_inbound_message(state, root, &client_raw, &from, &to, authenticated_domain).await
        }
        "iq" => route_inbound_iq(state, root, &client_raw, &from, &to).await,
        "presence" => {
            route_inbound_presence(state, root, &client_raw, &from, &to, connection_id).await
        }
        _ => Ok(Some(s2s_stanza_error(
            root,
            "cancel",
            "unsupported-stanza-type",
        ))),
    }
}

fn component_local_target(state: &AppState, domain: &str) -> bool {
    locally_hosted_identity_domain(&state.config.domain, domain)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InboundCoreValidation {
    Valid,
    /// Unknown/wrong-namespace top-level elements and malformed error stanzas
    /// are ignored. Reflecting them would either create an error loop or emit
    /// another non-stanza element on an authenticated stream.
    Drop,
    Error(&'static str),
}

fn valid_inbound_wire_namespace(raw: &str) -> bool {
    Document::parse(raw).is_ok_and(|document| {
        let root = document.root_element();
        matches!(root.tag_name().name(), "iq" | "message" | "presence")
            // A child which inherited the stream's `jabber:server` default
            // namespace appears unqualified when parsed as a standalone
            // frame. An explicit client namespace on an S2S stream is never
            // accepted and must not be normalized into a valid stanza.
            && matches!(root.tag_name().namespace(), None | Some("jabber:server"))
    })
}

fn invalid_inbound_core_namespace(raw: &str) -> bool {
    Document::parse(raw).is_ok_and(|document| {
        let root = document.root_element();
        matches!(root.tag_name().name(), "iq" | "message" | "presence")
            && !matches!(root.tag_name().namespace(), None | Some("jabber:server"))
    })
}

fn validate_inbound_core_stanza(root: roxmltree::Node<'_, '_>) -> InboundCoreValidation {
    if root.tag_name().namespace() != Some("jabber:client")
        || !matches!(root.tag_name().name(), "iq" | "message" | "presence")
    {
        return InboundCoreValidation::Drop;
    }
    if root
        .attribute("from")
        .and_then(|value| CanonicalJid::parse(value).ok())
        .is_none()
    {
        // There is no trustworthy return address for a stanza error.
        return InboundCoreValidation::Drop;
    }
    if root
        .attribute("to")
        .and_then(|value| CanonicalJid::parse(value).ok())
        .is_none()
    {
        return if root.attribute("type") == Some("error") {
            InboundCoreValidation::Drop
        } else {
            InboundCoreValidation::Error("jid-malformed")
        };
    }
    if root.tag_name().name() == "iq" && root.attribute("id").is_none() {
        // An IQ error cannot be correlated without the request ID.
        return InboundCoreValidation::Drop;
    }
    match crate::xmpp::stanza_validation::validate_client_stanza(root) {
        Ok(()) => InboundCoreValidation::Valid,
        Err(_) if root.attribute("type") == Some("error") => InboundCoreValidation::Drop,
        Err(condition) => InboundCoreValidation::Error(condition),
    }
}

pub(crate) async fn route_inbound_presence(
    state: &AppState,
    root: roxmltree::Node<'_, '_>,
    raw: &str,
    from: &str,
    to: &str,
    connection_id: uuid::Uuid,
) -> Result<Option<String>> {
    let Ok(to_jid) = CanonicalJid::parse(to) else {
        return Ok(Some(s2s_stanza_error(root, "modify", "jid-malformed")));
    };
    let Some(recipient_name) = to_jid.localpart() else {
        return Ok(Some(s2s_stanza_error(root, "modify", "jid-malformed")));
    };
    let Some(recipient) = db::find_enabled_user(&state.pool, recipient_name).await? else {
        return Ok(None);
    };
    let recipient_bare = format!("{}@{}", recipient.username, state.config.domain);
    let kind = root.attribute("type").unwrap_or("available");
    // Multiple authenticated streams for one remote domain can concurrently
    // carry presence for the same full JID. Choose one server-side order and
    // retain it through capability side effects and final local/cluster
    // routing; otherwise an older available could be delivered after a newer
    // unavailable even if the caps cache itself had already been cleaned.
    let federated_presence_epoch = if matches!(kind, "available" | "unavailable") {
        match crate::jid::canonical_session_key(from) {
            Ok(full_jid) => Some(state.federated_caps_gates().lock(&full_jid).await),
            Err(_) => None,
        }
    } else {
        None
    };
    if kind == "probe" {
        return route_inbound_presence_probe(state, root, from, &to_jid, &recipient).await;
    }
    let subscription_kind = matches!(
        kind,
        "subscribe" | "subscribed" | "unsubscribe" | "unsubscribed"
    );
    if !subscription_kind
        && db::is_blocked_for_account(&state.pool, recipient.id, &recipient_bare, from).await?
    {
        return Ok(None);
    }
    if subscription_kind
        && to_jid.resourcepart().is_some()
        && kind != "subscribe"
        && state.sessions_for(&to_jid.to_string()).is_empty()
        && state
            .cluster
            .lookup_nodes(&to_jid.to_string())
            .await
            .map_or(true, |nodes| nodes.is_empty())
    {
        return Ok(None);
    }
    let subscription_from = subscription_kind
        .then(|| CanonicalJid::parse(from))
        .transpose()
        .context("validated federated sender became malformed")?
        .map(|jid| jid.bare());
    let recipient_bare = format!("{}@{}", recipient.username, state.config.domain);
    let canonical_subscription = subscription_from
        .as_deref()
        .map(|contact| canonical_subscription_stanza(raw, contact, to));
    if let Some(resource_epoch) = federated_presence_epoch.as_ref() {
        match crate::xmpp::protocol::caps::observe_federated_caps(
            state,
            root,
            from,
            connection_id,
            resource_epoch,
        )
        .await
        {
            crate::xmpp::protocol::caps::FederatedCapsObservationResult::Accepted => {}
            crate::xmpp::protocol::caps::FederatedCapsObservationResult::StaleOwner => {
                return Ok(None);
            }
            crate::xmpp::protocol::caps::FederatedCapsObservationResult::Saturated => {
                return Ok(Some(s2s_stanza_error(root, "wait", "resource-constraint")));
            }
        }
    }
    if subscription_kind {
        let contact = subscription_from.as_deref().expect("guarded above");
        let persisted = canonical_subscription.as_deref().expect("guarded above");
        let transition = match state
            .presence_service()
            .transition_inbound(recipient.id, &state.config.domain, contact, kind, persisted)
            .await?
        {
            crate::services::presence::PresenceMutation::Transition(transition) => transition,
            crate::services::presence::PresenceMutation::PolicyDenied(_)
            | crate::services::presence::PresenceMutation::Missing
            | crate::services::presence::PresenceMutation::Unauthorized => {
                // The exact local UUID disappeared/was disabled, or its
                // account-wide inbound policy denied the authenticated remote
                // stanza. Inbound federation intentionally has no C2S
                // generation authority of its own.
                return Ok(None);
            }
        };
        let recipient = transition.recipient.clone();
        let recipient_bare = format!("{}@{}", recipient.username, state.config.domain);

        // Subscription notifications precede the corresponding roster push
        // (RFC 6121 sections 3.2/3.3). Incoming subscribe requests are sent to
        // available resources; the other state notifications go only to
        // resources that requested the roster.
        if transition.effect == crate::services::presence::InboundRemotePresenceEffect::Forward {
            let mut targets = state.session_entries_for(&recipient_bare);
            if kind == "subscribe" {
                targets.retain(|(_, target)| {
                    target.user_id == recipient.id
                        && target.auth_generation == recipient.auth_generation
                        && target.available.load(Ordering::Acquire)
                });
            } else {
                targets.retain(|(_, target)| {
                    target.user_id == recipient.id
                        && target.auth_generation == recipient.auth_generation
                        && target.available.load(Ordering::Acquire)
                        && target.roster_requested.load(Ordering::Acquire)
                });
            }
            for (target_jid, target) in targets {
                if state
                    .privacy_allows_session(&target, from, db::PrivacyStanzaKind::PresenceIn)
                    .await?
                {
                    let _ = target.sender.try_send(set_to(persisted, &target_jid));
                }
            }
        }

        if let Some(reply_kind) = transition.auto_reply {
            let response = presence_probe_status_response(
                &recipient_bare,
                contact,
                reply_kind,
                root.attribute("id"),
            );
            let remote_domain = CanonicalJid::parse(contact)
                .expect("canonical federated contact")
                .domainpart()
                .to_owned();
            if !state.federation.send(&remote_domain, response, None).await {
                return Ok(Some(s2s_stanza_error(root, "wait", "resource-constraint")));
            }
            if reply_kind == "subscribed" {
                send_current_presence_to_remote(state, &recipient_bare, contact).await;
            }
        }

        if transition.send_unavailable {
            send_unavailable_presence_to_remote(state, &recipient_bare, contact).await;
        }

        if let Some(change) = transition.change.as_ref() {
            if let Err(error) = crate::xmpp::protocol::roster::deliver_roster_change(
                state,
                recipient.id,
                &recipient.username,
                change,
                None,
            )
            .await
            {
                state
                    .metrics
                    .post_accept_side_effect_failures_total
                    .fetch_add(1, Ordering::Relaxed);
                tracing::warn!(?error, recipient_id = %recipient.id, contact = %contact, %kind, "federated roster transition was committed but roster push failed");
            }
        }
        if kind == "subscribe"
            && transition.effect == crate::services::presence::InboundRemotePresenceEffect::Forward
            && state.sessions_for(&recipient_bare).is_empty()
        {
            if let Err(error) =
                crate::xmpp::protocol::misc::send_push_notification(state, recipient.id).await
            {
                state
                    .metrics
                    .post_accept_side_effect_failures_total
                    .fetch_add(1, Ordering::Relaxed);
                tracing::warn!(?error, recipient_id = %recipient.id, contact = %contact, "federated subscription was committed but push notification failed");
            }
        }
        return Ok(None);
    }
    let (delivery_target, delivery) = canonical_subscription.map_or_else(
        || (to, raw.to_owned()),
        |stanza| (recipient_bare.as_str(), stanza),
    );
    let mut targets = state.session_entries_for(delivery_target);
    if CanonicalJid::parse(delivery_target).is_ok_and(|jid| jid.resourcepart().is_none()) {
        targets.retain(|(_, target)| target.available.load(Ordering::Relaxed));
    }
    for (_, target) in targets {
        if state
            .privacy_allows_session(&target, from, db::PrivacyStanzaKind::PresenceIn)
            .await?
        {
            let _ = target.sender.try_send(delivery.clone());
        }
    }
    Ok(None)
}

async fn send_unavailable_presence_to_remote(state: &AppState, owner: &str, contact: &str) {
    let remote_domain = CanonicalJid::parse(contact)
        .expect("canonical federated contact")
        .domainpart()
        .to_owned();
    let mut resources = state.session_entries_for(owner);
    resources.retain(|(_, session)| session.available.load(Ordering::Acquire));
    for (full_jid, session) in resources {
        match state
            .privacy_allows_session(&session, contact, db::PrivacyStanzaKind::PresenceOut)
            .await
        {
            Ok(true) => {}
            Ok(false) => continue,
            Err(error) => {
                tracing::warn!(?error, %full_jid, %contact, "privacy policy lookup failed for outbound unavailable presence");
                continue;
            }
        }
        let stanza = crate::xmpp::xml_builder::XmlElement::new("presence")
            .attr("xmlns", "jabber:client")
            .attr("from", &full_jid)
            .attr("to", contact)
            .attr("type", "unavailable")
            .finish();
        if !state.federation.send(&remote_domain, stanza, None).await {
            state
                .metrics
                .post_accept_side_effect_failures_total
                .fetch_add(1, Ordering::Relaxed);
            tracing::warn!(owner = %owner, contact = %contact, "failed to admit required federated unavailable presence after subscription removal");
        }
    }
}

async fn send_current_presence_to_remote(state: &AppState, owner: &str, contact: &str) {
    let remote_domain = CanonicalJid::parse(contact)
        .expect("canonical federated contact")
        .domainpart()
        .to_owned();
    let mut resources = state.session_entries_for(owner);
    resources.retain(|(_, session)| session.available.load(Ordering::Acquire));
    for (full_jid, session) in resources {
        match state
            .privacy_allows_session(&session, contact, db::PrivacyStanzaKind::PresenceOut)
            .await
        {
            Ok(true) => {}
            Ok(false) => continue,
            Err(error) => {
                tracing::warn!(?error, %full_jid, %contact, "privacy policy lookup failed for outbound current presence");
                continue;
            }
        }
        let stanza = session
            .last_presence
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
            .map(|presence| set_to(&presence, contact))
            .unwrap_or_else(|| {
                crate::xmpp::xml_builder::XmlElement::new("presence")
                    .attr("xmlns", "jabber:client")
                    .attr("from", &full_jid)
                    .attr("to", contact)
                    .finish()
            });
        if !state.federation.send(&remote_domain, stanza, None).await {
            state
                .metrics
                .post_accept_side_effect_failures_total
                .fetch_add(1, Ordering::Relaxed);
            tracing::warn!(owner = %owner, contact = %contact, "failed to admit current presence after federated subscription approval");
        }
    }
}

async fn route_inbound_presence_probe(
    state: &AppState,
    root: roxmltree::Node<'_, '_>,
    requester: &str,
    target_jid: &CanonicalJid,
    recipient: &db::EnabledUser,
) -> Result<Option<String>> {
    let requester_bare = crate::jid::canonical_bare_key(requester)?;
    let recipient_bare = format!("{}@{}", recipient.username, state.config.domain);
    let roster_authorized = db::roster_item(&state.pool, recipient.id, &requester_bare)
        .await?
        .is_some_and(|item| matches!(item.2.as_str(), "from" | "both"));
    let directed_authorized = target_jid.resourcepart().is_some()
        && state
            .session_entries_for(&target_jid.to_string())
            .into_iter()
            .any(|(_, session)| {
                session.directed_presence.iter().any(|authorized| {
                    crate::xmpp::protocol::presence::directed_recipient_matches(
                        authorized.key(),
                        requester,
                    )
                })
            });
    if !roster_authorized && !directed_authorized {
        return Ok(Some(presence_probe_status_response(
            &recipient_bare,
            requester,
            "unsubscribed",
            root.attribute("id"),
        )));
    }

    let owner = if target_jid.resourcepart().is_some() {
        target_jid.to_string()
    } else {
        recipient_bare.clone()
    };
    let mut available = state.session_entries_for(&owner);
    available.retain(|(_, session)| session.available.load(Ordering::Relaxed));
    let mut privacy_allowed = Vec::with_capacity(available.len());
    for entry in available {
        if state
            .privacy_allows_session(&entry.1, requester, db::PrivacyStanzaKind::PresenceIn)
            .await?
            && state
                .privacy_allows_session(&entry.1, requester, db::PrivacyStanzaKind::PresenceOut)
                .await?
        {
            privacy_allowed.push(entry);
        }
    }
    let available = privacy_allowed;
    if available.is_empty() {
        return Ok(Some(presence_probe_status_response(
            &recipient_bare,
            requester,
            "unavailable",
            root.attribute("id"),
        )));
    }

    let requester_domain = CanonicalJid::parse(requester)
        .expect("validated federated probe sender")
        .domainpart()
        .to_owned();
    let full_target = target_jid.resourcepart().is_some();
    for (full_jid, session) in available {
        let last_presence = session
            .last_presence
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let response = if full_target {
            // RFC 6121 section 4.3.2: a full-JID probe must expose only the
            // fact that this exact resource is available, never show/status,
            // priority, caps, OMEMO or another presence extension.
            let original_id = last_presence.as_deref().and_then(|presence| {
                let document = Document::parse(presence).ok()?;
                document
                    .root_element()
                    .attribute("id")
                    .filter(|id| {
                        !id.is_empty() && id.len() <= 1_024 && !id.chars().any(char::is_control)
                    })
                    .map(str::to_owned)
            });
            crate::xmpp::xml_builder::XmlElement::new("presence")
                .attr("xmlns", "jabber:server")
                .attr("from", &full_jid)
                .attr("to", requester)
                .optional_attr("id", original_id.as_deref())
                .finish()
        } else {
            last_presence
                .map(|presence| set_to(&presence, requester))
                .unwrap_or_else(|| {
                    crate::xmpp::xml_builder::XmlElement::new("presence")
                        .attr("xmlns", "jabber:server")
                        .attr("from", &full_jid)
                        .attr("to", requester)
                        .finish()
                })
        };
        // RFC 6121 section 4.3.2.1 preserves each available resource's
        // original presence id.  The probe id is mirrored only for
        // unavailable/unsubscribed/error responses above.
        if !state
            .federation
            .send(&requester_domain, response, None)
            .await
        {
            return Ok(Some(s2s_stanza_error(root, "wait", "resource-constraint")));
        }
    }
    Ok(None)
}

fn presence_probe_status_response(from: &str, to: &str, kind: &str, id: Option<&str>) -> String {
    let kind = match kind {
        "unavailable" => "unavailable",
        "unsubscribed" => "unsubscribed",
        _ => "error",
    };
    crate::xmpp::xml_builder::XmlElement::new("presence")
        .attr("xmlns", "jabber:server")
        .attr("from", from)
        .attr("to", to)
        .attr("type", kind)
        .optional_attr("id", id)
        .finish()
}

fn canonical_subscription_stanza(raw: &str, from: &str, to: &str) -> String {
    crate::xmpp::xml_util::set_client_namespace(&set_to(&set_from(raw, from), to))
}

fn is_xep0357_notification_publish(pubsub: roxmltree::Node<'_, '_>) -> bool {
    pubsub.children().any(|operation| {
        operation.is_element()
            && operation.tag_name().name() == "publish"
            && operation.tag_name().namespace() == Some("http://jabber.org/protocol/pubsub")
            && operation.children().any(|item| {
                item.is_element()
                    && item.tag_name().name() == "item"
                    && item.tag_name().namespace() == Some("http://jabber.org/protocol/pubsub")
                    && item.children().any(|payload| {
                        payload.is_element()
                            && payload.tag_name().name() == "notification"
                            && payload.tag_name().namespace() == Some("urn:xmpp:push:0")
                    })
            })
    })
}

fn bare_account_iq_may_route_to_service_resource(
    target: &CanonicalJid,
    payload: roxmltree::Node<'_, '_>,
) -> bool {
    target.localpart().is_some()
        && target.resourcepart().is_none()
        && is_xep0357_notification_publish(payload)
}

pub(crate) async fn route_inbound_iq(
    state: &AppState,
    root: roxmltree::Node<'_, '_>,
    raw: &str,
    from: &str,
    to: &str,
) -> Result<Option<String>> {
    let kind = root.attribute("type").unwrap_or("get");
    let Ok(to_jid) = CanonicalJid::parse(to) else {
        return Ok(Some(s2s_stanza_error(root, "modify", "jid-malformed")));
    };
    let recipient_name = to_jid.localpart();
    let recipient = match recipient_name {
        Some(username) => db::find_enabled_user(&state.pool, username).await?,
        None => None,
    };
    if let Some(recipient) = recipient.as_ref() {
        let recipient_bare = format!("{}@{}", recipient.username, state.config.domain);
        if db::is_blocked_for_account(&state.pool, recipient.id, &recipient_bare, from).await? {
            return if matches!(kind, "get" | "set") {
                Ok(Some(s2s_iq_error(
                    root.attribute("id").unwrap_or_default(),
                    to,
                    from,
                    "service-unavailable",
                )))
            } else {
                Ok(None)
            };
        }
    }
    if matches!(kind, "result" | "error") {
        let id = root.attribute("id").unwrap_or_default();
        if crate::xmpp::protocol::caps::handle_federated_caps_response(state, id, kind, root, raw)
            .await
        {
            return Ok(None);
        }
        if crate::xmpp::protocol::misc::handle_push_delivery_response(state, id, kind, from).await?
        {
            return Ok(None);
        }
        // Never broadcast an uncorrelated response to every resource of an
        // account. IQ responses belong to an exact originating resource.
        if to_jid.resourcepart().is_none() {
            return Ok(None);
        }
        let mut delivered = false;
        for target in state.sessions_for(to) {
            if state
                .privacy_allows_session(&target, from, db::PrivacyStanzaKind::Iq)
                .await?
                && target.sender.try_send(raw.to_owned()).is_ok()
            {
                delivered = true;
                break;
            }
        }
        if !delivered {
            if let Ok(nodes) = state.cluster.lookup_nodes(to).await {
                for node_id in nodes {
                    if node_id != state.cluster.node_id
                        && state
                            .cluster
                            .send_to_node(&node_id, to, raw, false, None)
                            .await
                            .unwrap_or(false)
                    {
                        break;
                    }
                }
            }
        }
        return Ok(None);
    }

    if to_jid.localpart().is_some() && recipient.is_none() {
        // RFC 6121 section 8.5.1 is evaluated before any server-side IQ
        // extension handler. A ping, vCard or other payload must not turn a
        // nonexistent local account into an oracle that appears to exist.
        return Ok(Some(s2s_iq_error(
            root.attribute("id").unwrap_or_default(),
            to,
            from,
            "service-unavailable",
        )));
    }

    if to_jid.resourcepart().is_some() {
        let Some(recipient) = recipient.as_ref() else {
            return Ok(Some(s2s_iq_error(
                root.attribute("id").unwrap_or_default(),
                to,
                from,
                "service-unavailable",
            )));
        };
        // RFC 6121 section 8.5.3.1 applies the presence-leak gate to every
        // IQ get/set addressed to a matching full JID.  This includes Jingle
        // and unknown extension IQs; capability discovery is not special.
        if matches!(kind, "get" | "set") {
            let requester_bare = crate::jid::canonical_bare_key(from)?;
            let subscribed = db::roster_item(&state.pool, recipient.id, &requester_bare)
                .await?
                .is_some_and(|item| matches!(item.2.as_str(), "from" | "both"));
            let directed = state
                .session_entries_for(to)
                .into_iter()
                .any(|(_, session)| {
                    session.directed_presence.iter().any(|authorized| {
                        crate::xmpp::protocol::presence::directed_recipient_matches(
                            authorized.key(),
                            from,
                        )
                    })
                });
            if !subscribed && !directed {
                return Ok(Some(s2s_iq_error(
                    root.attribute("id").unwrap_or_default(),
                    to,
                    from,
                    "service-unavailable",
                )));
            }
        }
        // RFC 6121 section 8.5.3.2.3 requires service-unavailable before a
        // server-side handler (including the XEP-0115 cache) can answer for
        // an exact resource which is not connected on any cluster node.
        let local_resource_matches = !state.session_entries_for(to).is_empty();
        let remote_resource_matches = state.cluster.lookup_nodes(to).await.is_ok_and(|nodes| {
            nodes
                .iter()
                .any(|node_id| node_id != &state.cluster.node_id)
        });
        if !local_resource_matches && !remote_resource_matches {
            return Ok(Some(s2s_iq_error(
                root.attribute("id").unwrap_or_default(),
                to,
                from,
                "service-unavailable",
            )));
        }
        let targets = state.sessions_for(to);
        if !targets.is_empty() {
            let mut allowed = false;
            for target in &targets {
                if state
                    .privacy_allows_session(target, from, db::PrivacyStanzaKind::Iq)
                    .await?
                {
                    allowed = true;
                    break;
                }
            }
            if !allowed {
                return if matches!(kind, "get" | "set") {
                    Ok(Some(s2s_iq_error(
                        root.attribute("id").unwrap_or_default(),
                        to,
                        from,
                        "service-unavailable",
                    )))
                } else {
                    Ok(None)
                };
            }
        }
    }
    let id = root.attribute("id").unwrap_or_default();
    let Some(child) = root.children().find(|node| node.is_element()) else {
        return Ok(Some(s2s_iq_error(id, to, from, "bad-request")));
    };
    if kind == "set"
        && child.tag_name().name() == "jingle"
        && child.tag_name().namespace() == Some(crate::xmpp::protocol::jingle::JINGLE_NS)
    {
        if let Err(condition) = crate::xmpp::protocol::jingle::validate_jingle_iq(root, child, None)
        {
            return Ok(Some(s2s_iq_error(id, to, from, condition)));
        }
    }
    if kind == "get"
        && to.contains('/')
        && child.tag_name().name() == "query"
        && child.tag_name().namespace() == Some("http://jabber.org/protocol/disco#info")
    {
        if let Some(result) =
            crate::xmpp::protocol::caps::cached_disco_result(state, id, to, child.attribute("node"))
        {
            return Ok(Some(crate::xmpp::xml_util::set_to(&result, from)));
        }
    }
    if to_jid.localpart().is_none()
        && same_s2s_domain(
            to_jid.domainpart(),
            &format!("pubsub.{}", state.config.domain),
        )
    {
        let reply =
            match crate::xmpp::protocol::pubsub::handle_request(state, from, kind, child).await {
                Ok(reply) => reply,
                Err(error) if crate::services::pubsub::is_pubsub_mutation_busy(&error) => {
                    crate::xmpp::protocol::pubsub::PubSubReply::Error("resource-constraint")
                }
                Err(error) => return Err(error),
            };
        return Ok(Some(match reply {
            crate::xmpp::protocol::pubsub::PubSubReply::Result(payload) => {
                s2s_iq_result(id, to, from, &payload)
            }
            reply @ (crate::xmpp::protocol::pubsub::PubSubReply::Error(_)
            | crate::xmpp::protocol::pubsub::PubSubReply::ExtendedError(_)) => {
                crate::xmpp::protocol::pubsub::pubsub_s2s_iq_error(id, to, from, &reply)
            }
        }));
    }
    let namespace = child.tag_name().namespace().unwrap_or_default();
    match (child.tag_name().name(), namespace, kind) {
        ("ping", northstar_xep_0199::NAMESPACE, "get")
            if state.config.xmpp_extensions.route_enabled(
                northstar_xep_core::StanzaKind::IqGet,
                northstar_xep_0199::NAMESPACE,
                "ping",
            ) =>
        {
            if northstar_xep_0199::parse_ping_element(child).is_err() {
                Ok(Some(s2s_iq_error(id, to, from, "bad-request")))
            } else {
                Ok(Some(s2s_iq_result(
                    id,
                    to,
                    from,
                    northstar_xep_0199::build_response(),
                )))
            }
        }
        ("ping", northstar_xep_0199::NAMESPACE, "get") => {
            Ok(Some(s2s_iq_error(id, to, from, "service-unavailable")))
        }
        ("vCard", "vcard-temp", "get") => {
            let Some(owner_name) = recipient_name else {
                return Ok(Some(s2s_iq_error(id, to, from, "item-not-found")));
            };
            let Some(owner) = db::find_enabled_user(&state.pool, owner_name).await? else {
                return Ok(Some(s2s_iq_error(id, to, from, "item-not-found")));
            };
            let record = db::get_vcard(&state.pool, owner.id).await?;
            let payload = record
                .payload_vcard_temp
                .unwrap_or_else(|| XmlElement::namespaced("vCard", "vcard-temp").finish());
            Ok(Some(s2s_iq_result(id, to, from, &payload)))
        }
        ("pubsub", "http://jabber.org/protocol/pubsub", "get") => {
            if to_jid.resourcepart().is_some()
                || child.children().filter(|node| node.is_element()).count() != 1
            {
                return Ok(Some(s2s_iq_error(id, to, from, "bad-request")));
            }
            let Some(items) = child
                .children()
                .find(|node| node.is_element() && node.tag_name().name() == "items")
            else {
                return Ok(Some(s2s_iq_error(id, to, from, "bad-request")));
            };
            if items
                .attributes()
                .any(|attribute| !matches!(attribute.name(), "node" | "max_items" | "subid"))
            {
                return Ok(Some(s2s_iq_error(id, to, from, "bad-request")));
            }
            let Some(node) = items.attribute("node").filter(|node| {
                !node.is_empty() && node.len() <= 1_024 && !node.chars().any(char::is_control)
            }) else {
                return Ok(Some(s2s_iq_error(id, to, from, "bad-request")));
            };
            let Some(owner_name) = recipient_name else {
                return Ok(Some(s2s_iq_error(id, to, from, "item-not-found")));
            };
            let Some(owner) = state.pubsub_service().find_enabled_user(owner_name).await? else {
                return Ok(Some(s2s_iq_error(id, to, from, "item-not-found")));
            };
            if db::pep_node(&state.pool, owner.id, node).await?.is_none() {
                return Ok(Some(s2s_iq_error(id, to, from, "item-not-found")));
            }
            if !crate::xmpp::protocol::pep::pep_access_allowed(
                state.pubsub_service(),
                &owner,
                &state.config.domain,
                node,
                from,
            )
            .await?
            {
                return Ok(Some(s2s_iq_error(id, to, from, "not-authorized")));
            }
            let requested = items
                .children()
                .filter(|node| node.is_element())
                .map(|item| {
                    (item.tag_name().namespace() == Some("http://jabber.org/protocol/pubsub")
                        && item.tag_name().name() == "item"
                        && item.attributes().len() == 1
                        && item.attribute("id").is_some_and(|item_id| {
                            !item_id.is_empty()
                                && item_id.len() <= 1_024
                                && !item_id.chars().any(char::is_control)
                        })
                        && !item.children().any(|child| child.is_element()))
                    .then(|| item.attribute("id").unwrap_or_default())
                })
                .collect::<Option<Vec<_>>>();
            let Some(requested) =
                requested.filter(|items| items.len() <= db::PEP_MAX_ITEMS as usize)
            else {
                return Ok(Some(s2s_iq_error(id, to, from, "bad-request")));
            };
            let max_items = match items.attribute("max_items") {
                Some(value) => match value.parse::<i64>() {
                    Ok(value) if value > 0 => value.min(db::PEP_MAX_ITEMS as i64),
                    _ => return Ok(Some(s2s_iq_error(id, to, from, "bad-request"))),
                },
                None => db::PEP_MAX_ITEMS as i64,
            };
            let stored = if requested.is_empty() {
                db::pep_items(&state.pool, owner.id, node, None, max_items).await?
            } else {
                db::pep_items_by_ids(&state.pool, owner.id, node, &requested, max_items).await?
            };
            if stored.is_empty() && !requested.is_empty() {
                return Ok(Some(s2s_iq_error(id, to, from, "item-not-found")));
            }
            let mut item_list =
                crate::xmpp::xml_builder::XmlElement::new("items").attr("node", node);
            for (_, item) in stored {
                item_list = item_list
                    .validated_fragment(&item)
                    .context("stored PEP item is not valid XML")?;
            }
            let payload = crate::xmpp::xml_builder::XmlElement::new("pubsub")
                .attr("xmlns", "http://jabber.org/protocol/pubsub")
                .child(item_list)
                .finish();
            Ok(Some(s2s_iq_result(id, to, from, &payload)))
        }
        ("pubsub", "http://jabber.org/protocol/pubsub", "set")
            if !is_xep0357_notification_publish(child) =>
        {
            if to_jid.resourcepart().is_some() {
                return Ok(Some(s2s_iq_error(id, to, from, "jid-malformed")));
            }
            let Some(owner_name) = recipient_name else {
                return Ok(Some(s2s_iq_error(id, to, from, "item-not-found")));
            };
            let Some(owner) = state.pubsub_service().find_enabled_user(owner_name).await? else {
                return Ok(Some(s2s_iq_error(id, to, from, "item-not-found")));
            };
            let operations = child
                .children()
                .filter(|node| node.is_element())
                .collect::<Vec<_>>();
            if operations.len() != 1 {
                return Ok(Some(s2s_iq_error(id, to, from, "bad-request")));
            }
            let operation = operations[0];
            if operation.tag_name().namespace() != Some("http://jabber.org/protocol/pubsub")
                || !matches!(operation.tag_name().name(), "subscribe" | "unsubscribe")
            {
                return Ok(Some(s2s_iq_error(id, to, from, "feature-not-implemented")));
            }
            let Some(node) = operation.attribute("node").filter(|node| {
                !node.is_empty() && node.len() <= 1_024 && !node.chars().any(char::is_control)
            }) else {
                return Ok(Some(s2s_iq_error(id, to, from, "bad-request")));
            };
            let Some(requested) = operation.attribute("jid") else {
                return Ok(Some(s2s_iq_error(id, to, from, "bad-request")));
            };
            let Ok(requested) = crate::jid::canonicalize(requested) else {
                return Ok(Some(s2s_iq_error(id, to, from, "jid-malformed")));
            };
            if operation.tag_name().name() == "subscribe" {
                let requested_subid = uuid::Uuid::new_v4().to_string();
                let outcome = match state
                    .pubsub_service()
                    .subscribe_pep_node(
                        northstar_pubsub_application::PepSubscribeCommand::from(
                            crate::services::pubsub::PepSubscribeWrite {
                                owner: &owner,
                                actor: crate::services::pubsub::PepSubscriptionActor {
                                    jid: from,
                                    local_account: None,
                                },
                                node,
                                subscriber_jid: &requested,
                                max_subscriptions: 1_000,
                                requested_subid: &requested_subid,
                            },
                        ),
                        &crate::xmpp::protocol::pep::prepare_pep_last_item_outbox,
                    )
                    .await
                {
                    Ok(outcome) => outcome,
                    Err(error) if crate::services::pubsub::is_pubsub_mutation_busy(&error) => {
                        return Ok(Some(crate::xmpp::protocol::pubsub::pubsub_s2s_iq_error(
                            id,
                            to,
                            from,
                            &crate::xmpp::protocol::pubsub::PubSubReply::Error(
                                "resource-constraint",
                            ),
                        )));
                    }
                    Err(error) => return Err(error),
                };
                let subscription = match outcome.outcome {
                    crate::services::pubsub::PepSubscribeOutcome::Subscribed(subscription) => {
                        subscription
                    }
                    crate::services::pubsub::PepSubscribeOutcome::NotFound => {
                        return Ok(Some(s2s_iq_error(id, to, from, "item-not-found")));
                    }
                    crate::services::pubsub::PepSubscribeOutcome::Forbidden => {
                        return Ok(Some(s2s_iq_error(id, to, from, "forbidden")));
                    }
                    crate::services::pubsub::PepSubscribeOutcome::NotAuthorized(_) => {
                        return Ok(Some(s2s_iq_error(id, to, from, "not-authorized")));
                    }
                    crate::services::pubsub::PepSubscribeOutcome::LimitExceeded => {
                        return Ok(Some(s2s_iq_error(id, to, from, "policy-violation")));
                    }
                };
                let payload = crate::xmpp::xml_builder::XmlElement::new("pubsub")
                    .attr("xmlns", "http://jabber.org/protocol/pubsub")
                    .child(
                        crate::xmpp::xml_builder::XmlElement::new("subscription")
                            .attr("node", node)
                            .attr("jid", &requested)
                            .attr("subscription", "subscribed")
                            .attr("subid", &subscription.subid),
                    )
                    .finish();
                Ok(Some(s2s_iq_result(id, to, from, &payload)))
            } else {
                let outcome = match state
                    .pubsub_service()
                    .unsubscribe_pep_node(
                        northstar_pubsub_application::PepUnsubscribeCommand::from(
                            crate::services::pubsub::PepUnsubscribeWrite {
                                owner: &owner,
                                actor: crate::services::pubsub::PepSubscriptionActor {
                                    jid: from,
                                    local_account: None,
                                },
                                node,
                                subscriber_jid: &requested,
                                subid: operation.attribute("subid"),
                            },
                        ),
                    )
                    .await
                {
                    Ok(outcome) => outcome,
                    Err(error) if crate::services::pubsub::is_pubsub_mutation_busy(&error) => {
                        return Ok(Some(crate::xmpp::protocol::pubsub::pubsub_s2s_iq_error(
                            id,
                            to,
                            from,
                            &crate::xmpp::protocol::pubsub::PubSubReply::Error(
                                "resource-constraint",
                            ),
                        )));
                    }
                    Err(error) => return Err(error),
                };
                match outcome.outcome {
                    crate::services::pubsub::PepUnsubscribeOutcome::Unsubscribed(_) => {}
                    crate::services::pubsub::PepUnsubscribeOutcome::NotFound => {
                        return Ok(Some(s2s_iq_error(id, to, from, "item-not-found")));
                    }
                    crate::services::pubsub::PepUnsubscribeOutcome::Forbidden => {
                        return Ok(Some(s2s_iq_error(id, to, from, "forbidden")));
                    }
                    crate::services::pubsub::PepUnsubscribeOutcome::InvalidSubid => {
                        return Ok(Some(s2s_iq_error(id, to, from, "unexpected-request")));
                    }
                }
                Ok(Some(s2s_iq_result(id, to, from, "")))
            }
        }
        ("query", "http://jabber.org/protocol/disco#info", "get") => {
            if to_jid.localpart().is_none()
                && same_s2s_domain(
                    to_jid.domainpart(),
                    &format!("pubsub.{}", state.config.domain),
                )
            {
                let reply = crate::xmpp::protocol::pubsub::federated_disco_info(
                    state,
                    from,
                    child.attribute("node"),
                )
                .await?;
                return Ok(Some(match reply {
                    crate::xmpp::protocol::pubsub::PubSubReply::Result(payload) => {
                        s2s_iq_result(id, to, from, &payload)
                    }
                    reply @ (crate::xmpp::protocol::pubsub::PubSubReply::Error(_)
                    | crate::xmpp::protocol::pubsub::PubSubReply::ExtendedError(_)) => {
                        crate::xmpp::protocol::pubsub::pubsub_s2s_iq_error(id, to, from, &reply)
                    }
                }));
            }
            if let Some(owner_name) = recipient_name {
                let Some(owner) = state.pubsub_service().find_enabled_user(owner_name).await?
                else {
                    return Ok(Some(s2s_iq_error(id, to, from, "item-not-found")));
                };
                let Some(payload) = crate::xmpp::protocol::pep::federated_pep_disco_info(
                    state,
                    &owner,
                    from,
                    child.attribute("node"),
                )
                .await?
                else {
                    return Ok(Some(s2s_iq_error(id, to, from, "item-not-found")));
                };
                return Ok(Some(s2s_iq_result(id, to, from, &payload)));
            }
            let mut payload =
                XmlElement::namespaced("query", "http://jabber.org/protocol/disco#info").child(
                    XmlElement::new("identity")
                        .attr("category", "server")
                        .attr("type", "im")
                        .attr("name", "Northstar XMPP Server"),
                );
            for feature in [
                "http://jabber.org/protocol/disco#info",
                "vcard-temp",
                "urn:xmpp:push:0",
                "urn:xmpp:sid:0",
            ] {
                payload.push_child(XmlElement::new("feature").attr("var", feature));
            }
            if state
                .config
                .xmpp_extensions
                .enabled(northstar_xep_0199::XEP_ID)
            {
                payload.push_child(
                    XmlElement::new("feature").attr("var", northstar_xep_0199::NAMESPACE),
                );
            }
            Ok(Some(s2s_iq_result(id, to, from, &payload.finish())))
        }
        ("query", "http://jabber.org/protocol/disco#items", "get")
            if to_jid.localpart().is_none()
                && same_s2s_domain(
                    to_jid.domainpart(),
                    &format!("pubsub.{}", state.config.domain),
                ) =>
        {
            let reply =
                crate::xmpp::protocol::pubsub::federated_disco_items(state, from, child).await?;
            Ok(Some(match reply {
                crate::xmpp::protocol::pubsub::PubSubReply::Result(payload) => {
                    s2s_iq_result(id, to, from, &payload)
                }
                reply @ (crate::xmpp::protocol::pubsub::PubSubReply::Error(_)
                | crate::xmpp::protocol::pubsub::PubSubReply::ExtendedError(_)) => {
                    crate::xmpp::protocol::pubsub::pubsub_s2s_iq_error(id, to, from, &reply)
                }
            }))
        }
        ("query", "http://jabber.org/protocol/disco#items", "get")
            if recipient_name.is_some() && to_jid.resourcepart().is_none() =>
        {
            let owner_name = recipient_name.expect("guarded above");
            let Some(owner) = state.pubsub_service().find_enabled_user(owner_name).await? else {
                return Ok(Some(s2s_iq_error(id, to, from, "item-not-found")));
            };
            let Some(payload) = crate::xmpp::protocol::pep::federated_pep_disco_items(
                state,
                &owner,
                from,
                child.attribute("node"),
            )
            .await?
            else {
                return Ok(Some(s2s_iq_error(id, to, from, "item-not-found")));
            };
            Ok(Some(s2s_iq_result(id, to, from, &payload)))
        }
        _ => {
            let bare_target = to_jid.resourcepart().is_none();
            // RFC 6121 sections 8.5.2.1.3 and 8.5.2.2.3 require the server
            // to answer an IQ addressed to a bare account and MUST NOT route
            // it to account resources.  The sole compatibility extension is
            // the strict XEP-0357 notification payload: a configured Push
            // Service may be represented by a bare account JID and processes
            // the IQ through one deterministic service resource.  Domain-only
            // Push Service JIDs are handled as server services above.
            if bare_target && !bare_account_iq_may_route_to_service_resource(&to_jid, child) {
                return Ok(Some(s2s_iq_error(id, to, from, "service-unavailable")));
            }
            // Never spray the narrow service-resource exception across
            // resources: highest priority wins and the canonical full JID is
            // a deterministic tie-breaker.
            let mut targets = state.session_entries_for(to);
            if bare_target {
                targets.retain(|(_, target)| {
                    target.available.load(Ordering::Acquire)
                        && target.priority.load(Ordering::Acquire) >= 0
                });
                targets.sort_by(|(left_jid, left), (right_jid, right)| {
                    right
                        .priority
                        .load(Ordering::Acquire)
                        .cmp(&left.priority.load(Ordering::Acquire))
                        .then_with(|| left_jid.cmp(right_jid))
                });
            }
            let mut delivered = false;
            for (_, target) in targets {
                if state
                    .privacy_allows_session(&target, from, db::PrivacyStanzaKind::Iq)
                    .await?
                    && target.sender.try_send(raw.to_owned()).is_ok()
                {
                    delivered = true;
                    if bare_target {
                        break;
                    }
                }
            }
            if !delivered {
                if let Ok(nodes) = state.cluster.lookup_nodes(to).await {
                    for node_id in nodes {
                        if node_id == state.cluster.node_id {
                            continue;
                        }
                        let accepted = if bare_target {
                            state
                                .cluster
                                .send_to_node_primary(&node_id, to, raw)
                                .await
                                .is_ok_and(|receipt| receipt.delivered)
                        } else {
                            state
                                .cluster
                                .send_to_node(&node_id, to, raw, false, None)
                                .await
                                .unwrap_or(false)
                        };
                        if accepted {
                            delivered = true;
                            if bare_target {
                                break;
                            }
                        }
                    }
                }
            }
            if !delivered {
                return Ok(Some(s2s_iq_error(id, to, from, "service-unavailable")));
            }
            Ok(None)
        }
    }
}

pub(crate) async fn route_inbound_message(
    state: &AppState,
    root: roxmltree::Node<'_, '_>,
    raw: &str,
    from: &str,
    to: &str,
    authenticated_domain: &str,
) -> Result<Option<String>> {
    if let Err(condition) = validate_routed_message(root, &state.config.xmpp_extensions) {
        return Ok(inbound_message_error(
            root,
            stanza_error_type(condition),
            condition,
        ));
    }
    let personal_retraction_command =
        match crate::xmpp::protocol::retractions::personal_retraction_command(root) {
            Ok(command) => command,
            Err(()) => return Ok(inbound_message_error(root, "modify", "bad-request")),
        };
    let personal_retraction = personal_retraction_command.is_some();
    let from_jid = match CanonicalJid::parse(from) {
        Ok(from) => from,
        Err(_) => return Ok(inbound_message_error(root, "modify", "jid-malformed")),
    };
    let canonical_from = from_jid.to_string();
    let Ok(to_jid) = CanonicalJid::parse(to) else {
        return Ok(inbound_message_error(root, "modify", "jid-malformed"));
    };
    if crate::xmpp::protocol::misc::handle_push_disable(state, root, from, to).await? {
        return Ok(None);
    }
    let Some(recipient_name) = to_jid.localpart() else {
        return Ok(inbound_message_error(root, "modify", "jid-malformed"));
    };
    let Some(recipient) = db::find_enabled_user(&state.pool, recipient_name).await? else {
        return Ok(
            if crate::xmpp::protocol::messaging::missing_user_message_should_error(
                root.attribute("type").unwrap_or("normal"),
            ) {
                inbound_message_error(root, "cancel", "service-unavailable")
            } else {
                None
            },
        );
    };
    let recipient_bare = format!("{}@{}", recipient.username, state.config.domain);
    if db::is_blocked_for_account(&state.pool, recipient.id, &recipient_bare, from).await? {
        return Ok(inbound_message_error(root, "cancel", "service-unavailable"));
    }
    let message_type = root.attribute("type").unwrap_or("normal");
    if personal_retraction && !matches!(message_type, "normal" | "chat") {
        return Ok(inbound_message_error(root, "modify", "bad-request"));
    }
    let bare_target = to_jid.resourcepart().is_none();
    if bare_target {
        match crate::xmpp::protocol::messaging::bare_message_route(message_type) {
            crate::xmpp::protocol::messaging::BareMessageRoute::Reject => {
                return Ok(inbound_message_error(root, "cancel", "service-unavailable"));
            }
            crate::xmpp::protocol::messaging::BareMessageRoute::Ignore => return Ok(None),
            crate::xmpp::protocol::messaging::BareMessageRoute::Primary
            | crate::xmpp::protocol::messaging::BareMessageRoute::All => {}
        }
    }
    // Resolve local per-resource privacy policy before any archive or delivery
    // admission.  A resource's active list replaces the account default; if
    // there is no online route, the durable default governs offline storage.
    let mut privacy_candidates = state.session_entries_for(to);
    if bare_target {
        privacy_candidates.retain(|(_, session)| {
            session.available.load(Ordering::Relaxed)
                && session.priority.load(Ordering::Relaxed) >= 0
        });
    }
    let unfiltered_privacy_candidates = privacy_candidates.len();
    let mut privacy_allowed = false;
    for (_, target) in &privacy_candidates {
        if state
            .privacy_allows_session(target, from, db::PrivacyStanzaKind::Message)
            .await?
        {
            privacy_allowed = true;
            break;
        }
    }
    if unfiltered_privacy_candidates > 0 && !privacy_allowed {
        return Ok(inbound_message_error(root, "cancel", "service-unavailable"));
    }
    let remote_route_exists = state
        .cluster
        .lookup_nodes(to)
        .await
        .is_ok_and(|nodes| nodes.into_iter().any(|node| node != state.cluster.node_id));
    if unfiltered_privacy_candidates == 0
        && !remote_route_exists
        && db::privacy_denies(
            &state.pool,
            recipient.id,
            None,
            from,
            db::PrivacyStanzaKind::Message,
        )
        .await?
    {
        return Ok(inbound_message_error(root, "cancel", "service-unavailable"));
    }
    // Deterministic full-resource failure is still a truthful stanza error
    // before admission. After the durable transaction commits, the same
    // condition can only be a routing race and must be recovered from the
    // resource-affine outbox without returning an error.
    if !bare_target && unfiltered_privacy_candidates == 0 && !remote_route_exists {
        match crate::xmpp::protocol::messaging::full_no_match_route(message_type) {
            crate::xmpp::protocol::messaging::FullNoMatchRoute::Ignore => return Ok(None),
            crate::xmpp::protocol::messaging::FullNoMatchRoute::Reject => {
                return Ok(inbound_message_error(root, "cancel", "service-unavailable"));
            }
            crate::xmpp::protocol::messaging::FullNoMatchRoute::FallbackChat => {}
        }
    }
    let stable_id = uuid::Uuid::new_v4();
    let recipient_by = format!("{}@{}", recipient.username, state.config.domain);
    let authoritative_raw = strip_stanza_ids_by_domain(
        &strip_untrusted_direct_delays(raw, Some(authenticated_domain)),
        &state.config.domain,
    );
    let annotated = add_stanza_id(&authoritative_raw, &recipient_by, stable_id);
    let encrypted = is_encrypted(root);
    let durable_content_allowed = encrypted || !state.config.require_encrypted_archive;
    let persistence_allowed = personal_retraction || offline_storage_permitted(root);
    let archive = if encrypted {
        if let Some(command) = personal_retraction_command.as_ref() {
            crate::xmpp::protocol::retractions::encrypted_retraction_archive(
                &annotated,
                &command.target_id,
            )
        } else {
            encrypted_archive_stanza(&annotated)
        }
    } else {
        annotated.clone()
    };
    // MAM policy lookup is read-only and must finish before any delivery
    // queue or offline transaction accepts the stanza. Once accepted, later
    // archive/retraction failures are log-only to prevent duplicate retries.
    let archive_allowed = personal_retraction
        || (mam_storage_eligible(root)
            && (encrypted || !state.config.require_encrypted_archive)
            && db::archive_allowed(&state.pool, recipient.id, &canonical_from).await?);
    let mut history_committed = false;
    let mut durable_c2s_delivery = None;
    let direct_delivery_mode = crate::xmpp::protocol::messaging::direct_delivery_mode(root);
    if !personal_retraction
        && matches!(message_type, "normal" | "chat")
        && crate::xmpp::protocol::messaging::durable_direct_delivery_allowed(
            direct_delivery_mode,
            durable_content_allowed,
        )
    {
        if !persistence_allowed {
            // DirectDeliveryMode::Durable is defined by this condition. Keep
            // this assertion close to the admission boundary so future policy
            // changes cannot accidentally create a non-recoverable write.
            anyhow::bail!("durable inbound message lost its persistence projection");
        }
        let writes = archive_allowed
            .then_some(ArchiveWrite {
                id: stable_id,
                owner_id: recipient.id,
                peer_jid: &canonical_from,
                stanza: &archive,
                encrypted,
                stanza_id: root.attribute("id"),
            })
            .into_iter()
            .collect::<Vec<_>>();
        let identity_parts = authoritative_remote_stanza_identity(root, authenticated_domain);
        let identity =
            identity_parts
                .as_ref()
                .map(
                    |(actor_scope_raw, actor_scope, identity_value)| MessageIdentity {
                        authority: IdentityAuthority::AuthenticatedRemoteStanza,
                        actor_scope_raw,
                        actor_scope,
                        target_scope: &recipient_bare,
                        value: identity_value,
                        payload: &authoritative_raw,
                    },
                );
        let delayed = add_delay_from(&annotated, chrono::Utc::now(), Some(&state.config.domain));
        let delivery = ValidatedPersonalMessage {
            local_actor_id: None,
            identity,
            archives: &writes,
            destination: PersonalMessageDestination::Local(LocalDelivery {
                delivery_id: stable_id,
                recipient_id: recipient.id,
                recipient_bare_jid: &recipient_bare,
                sender_jid: &canonical_from,
                stanza: &delayed,
                encrypted,
                mam_backed: archive_allowed,
            }),
        };
        match state
            .message_service()
            .admit_personal_message(&delivery)
            .await
        {
            Ok(DurableAdmissionOutcome::Stored { post_commit, .. }) => {
                history_committed = archive_allowed;
                let MessagePostCommit::RouteLocalDelivery { delivery_id, .. } = post_commit else {
                    anyhow::bail!("local federation ingress returned a non-local commit plan");
                };
                durable_c2s_delivery = Some(delivery_id);
            }
            Ok(DurableAdmissionOutcome::Replay) => return Ok(None),
            Ok(DurableAdmissionOutcome::AccountUnavailable) => return Ok(None),
            Err(error) => {
                tracing::warn!(?error, %authenticated_domain, "inbound message history/C2S admission failed atomically");
                return Ok(inbound_message_error(root, "wait", "resource-constraint"));
            }
        }
    }
    let mut targets = state.session_entries_for(to);
    if bare_target {
        targets.retain(|(_, session)| {
            session.available.load(Ordering::Relaxed)
                && session.priority.load(Ordering::Relaxed) >= 0
        });
        if message_type != "headline" {
            targets.sort_by(|(left_jid, left), (right_jid, right)| {
                right
                    .priority
                    .load(Ordering::Relaxed)
                    .cmp(&left.priority.load(Ordering::Relaxed))
                    .then_with(|| left_jid.cmp(right_jid))
            });
        }
    }
    let mut allowed_targets = Vec::with_capacity(targets.len());
    for target in targets {
        if state
            .privacy_allows_session(&target.1, from, db::PrivacyStanzaKind::Message)
            .await?
        {
            allowed_targets.push(target);
        }
    }
    let targets = allowed_targets;
    let deliver_all = bare_target
        && crate::xmpp::protocol::messaging::bare_message_route(message_type)
            == crate::xmpp::protocol::messaging::BareMessageRoute::All;
    if let Some(command) = personal_retraction_command.as_ref() {
        // A full-JID route that is deterministically invalid must be rejected
        // before creating a durable projection. Chat fallback remains valid;
        // a bare target may recover through the offline outbox.
        if !bare_target && targets.is_empty() && !remote_route_exists {
            match crate::xmpp::protocol::messaging::full_no_match_route(message_type) {
                crate::xmpp::protocol::messaging::FullNoMatchRoute::Ignore => return Ok(None),
                crate::xmpp::protocol::messaging::FullNoMatchRoute::Reject => {
                    return Ok(inbound_message_error(root, "cancel", "service-unavailable"));
                }
                crate::xmpp::protocol::messaging::FullNoMatchRoute::FallbackChat => {}
            }
        }
        let writes = archive_allowed
            .then_some(ArchiveWrite {
                id: stable_id,
                owner_id: recipient.id,
                peer_jid: &canonical_from,
                stanza: &archive,
                encrypted,
                stanza_id: root.attribute("id"),
            })
            .into_iter()
            .collect::<Vec<_>>();
        let delayed = add_delay_from(&annotated, chrono::Utc::now(), Some(&state.config.domain));
        let delivery = DeliveryProjection {
            id: stable_id,
            recipient_id: recipient.id,
            local_actor_id: None,
            sender_jid: &canonical_from,
            stanza: &delayed,
            encrypted,
            max_messages: state.config.offline_max_messages_per_account,
            max_bytes: state.config.offline_max_bytes_per_account,
            ttl_days: state.config.offline_message_ttl_days,
            mam_backed: archive_allowed,
        };
        match state
            .retraction_service()
            .apply_with_delivery(
                &[OwnerProjection {
                    owner_id: recipient.id,
                    peer_jid: &canonical_from,
                }],
                &canonical_from,
                &RetractionCommand {
                    target_id: &command.target_id,
                    action_id: &command.action_id,
                    semantic_payload: &command.semantic_payload,
                },
                &writes,
                Some(&delivery),
                None,
            )
            .await
        {
            Ok(RetractionOutcome::Applied { .. }) => {
                history_committed = true;
                durable_c2s_delivery = Some(stable_id);
            }
            Ok(RetractionOutcome::Replay) => return Ok(None),
            Ok(RetractionOutcome::Conflict) => {
                return Ok(inbound_message_error(root, "cancel", "conflict"));
            }
            Ok(RetractionOutcome::Forbidden) => {
                return Ok(inbound_message_error(root, "auth", "forbidden"));
            }
            Ok(RetractionOutcome::AccountUnavailable) => return Ok(None),
            Ok(RetractionOutcome::CapacityExceeded) => {
                return Ok(inbound_message_error(root, "wait", "resource-constraint"));
            }
            Err(error) => {
                tracing::warn!(?error, %authenticated_domain, "inbound retraction admission failed atomically before delivery");
                return Ok(inbound_message_error(root, "wait", "resource-constraint"));
            }
        }
    }
    let mut delivered_key = None;
    let live_delivery = durable_c2s_delivery.map(|message_id| crate::outbound::DurableDelivery {
        recipient_id: recipient.id,
        message_id,
        claim_id: None,
    });
    for (key, target) in &targets {
        let accepted = if let Some(delivery) = live_delivery {
            target
                .sender
                .try_send_durable(annotated.clone(), delivery)
                .is_ok()
        } else {
            target.sender.try_send(annotated.clone()).is_ok()
        };
        if accepted {
            let counter = if live_delivery.is_some() {
                &state.metrics.online_queue_durable_acceptances_total
            } else {
                &state.metrics.online_queue_volatile_acceptances_total
            };
            counter.fetch_add(1, Ordering::Relaxed);
            if delivered_key.is_none() {
                delivered_key = Some(key.clone());
            }
            if !deliver_all {
                break;
            }
        }
    }
    let mut delivered = delivered_key.is_some();

    if deliver_all {
        if let Ok(nodes) = state.cluster.lookup_nodes(to).await {
            for node_id in nodes {
                if node_id == state.cluster.node_id {
                    continue;
                }
                let accepted = if let Some(delivery) = live_delivery {
                    state
                        .cluster
                        .send_to_node_available_durable(&node_id, to, &annotated, delivery)
                        .await
                        .unwrap_or(false)
                } else {
                    state
                        .cluster
                        .send_to_node_available(&node_id, to, &annotated)
                        .await
                        .unwrap_or(false)
                };
                if accepted {
                    delivered = true;
                }
            }
        }
    } else if !delivered {
        if let Ok(nodes) = state.cluster.lookup_nodes(to).await {
            for node_id in nodes {
                if node_id != state.cluster.node_id {
                    let receipt = if let Some(delivery) = live_delivery {
                        state
                            .cluster
                            .send_to_node_primary_durable(&node_id, to, &annotated, delivery)
                            .await
                            .unwrap_or_default()
                    } else {
                        state
                            .cluster
                            .send_to_node_primary(&node_id, to, &annotated)
                            .await
                            .unwrap_or_default()
                    };
                    if crate::xmpp::protocol::messaging::accepted_cluster_message_delivery(
                        state, &node_id, to, &receipt,
                    ) {
                        delivered = true;
                        delivered_key = receipt.accepted_full_jid;
                        break;
                    }
                }
            }
        }
    }

    if !delivered && !bare_target {
        let allow_bare_fallback = match crate::xmpp::protocol::messaging::full_no_match_route(
            message_type,
        ) {
            crate::xmpp::protocol::messaging::FullNoMatchRoute::Ignore => return Ok(None),
            crate::xmpp::protocol::messaging::FullNoMatchRoute::Reject
                if crate::xmpp::protocol::messaging::durable_full_no_match_recovers(
                    message_type,
                    live_delivery.is_some(),
                ) =>
            {
                state
                    .metrics
                    .post_accept_side_effect_failures_total
                    .fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    recipient_id = %recipient.id,
                    target = %to,
                    "exact full-JID S2S route disappeared after durable admission; resource-affine row remains replayable"
                );
                false
            }
            crate::xmpp::protocol::messaging::FullNoMatchRoute::Reject => {
                return Ok(inbound_message_error(root, "cancel", "service-unavailable"));
            }
            crate::xmpp::protocol::messaging::FullNoMatchRoute::FallbackChat => true,
        };

        if allow_bare_fallback {
            let mut fallback_targets = state.session_entries_for(&recipient_by);
            fallback_targets.retain(|(_, session)| {
                session.available.load(Ordering::Relaxed)
                    && session.priority.load(Ordering::Relaxed) >= 0
            });
            fallback_targets.sort_by(|(left_jid, left), (right_jid, right)| {
                right
                    .priority
                    .load(Ordering::Relaxed)
                    .cmp(&left.priority.load(Ordering::Relaxed))
                    .then_with(|| left_jid.cmp(right_jid))
            });
            let mut allowed_fallback = Vec::with_capacity(fallback_targets.len());
            for target in fallback_targets {
                match state
                    .privacy_allows_session(&target.1, from, db::PrivacyStanzaKind::Message)
                    .await
                {
                    Ok(true) => allowed_fallback.push(target),
                    Ok(false) => {}
                    Err(error) if live_delivery.is_some() => {
                        state
                            .metrics
                            .post_accept_side_effect_failures_total
                            .fetch_add(1, Ordering::Relaxed);
                        tracing::warn!(
                            ?error,
                            target = %target.0,
                            recipient_id = %recipient.id,
                            "privacy policy failed closed during post-admission S2S full-JID fallback"
                        );
                    }
                    Err(error) => return Err(error),
                }
            }
            for (key, target) in allowed_fallback {
                let accepted = if let Some(delivery) = live_delivery {
                    target
                        .sender
                        .try_send_durable(annotated.clone(), delivery)
                        .is_ok()
                } else {
                    target.sender.try_send(annotated.clone()).is_ok()
                };
                if accepted {
                    let counter = if live_delivery.is_some() {
                        &state.metrics.online_queue_durable_acceptances_total
                    } else {
                        &state.metrics.online_queue_volatile_acceptances_total
                    };
                    counter.fetch_add(1, Ordering::Relaxed);
                    delivered_key = Some(key);
                    delivered = true;
                    break;
                }
            }
            if !delivered {
                if let Ok(nodes) = state.cluster.lookup_nodes(&recipient_by).await {
                    for node_id in nodes {
                        if node_id == state.cluster.node_id {
                            continue;
                        }
                        let receipt = if let Some(delivery) = live_delivery {
                            state
                                .cluster
                                .send_to_node_primary_durable(
                                    &node_id,
                                    &recipient_by,
                                    &annotated,
                                    delivery,
                                )
                                .await
                                .unwrap_or_default()
                        } else {
                            state
                                .cluster
                                .send_to_node_primary(&node_id, &recipient_by, &annotated)
                                .await
                                .unwrap_or_default()
                        };
                        if crate::xmpp::protocol::messaging::accepted_cluster_message_delivery(
                            state,
                            &node_id,
                            &recipient_by,
                            &receipt,
                        ) {
                            delivered = true;
                            delivered_key = receipt.accepted_full_jid;
                            break;
                        }
                    }
                }
            }
        }
    }

    if !delivered && message_type == "headline" {
        return Ok(None);
    }

    if delivered {
        if !history_committed {
            finalize_accepted_inbound_history(
                &state.pool,
                root,
                AcceptedInboundHistory {
                    metrics: &state.metrics,
                    recipient_id: recipient.id,
                    canonical_from: &canonical_from,
                    stable_id,
                    archive_allowed,
                    archive: &archive,
                    encrypted,
                    route: "s2s-online",
                },
            )
            .await;
        }
        let remote_muc_private_message =
            is_remote_muc_private_message(root, from, authenticated_domain);
        if should_carbon(root) && !remote_muc_private_message {
            if let Some(delivered_key) = delivered_key.as_deref() {
                crate::xmpp::protocol::messaging::send_received_carbons_for_state(
                    state,
                    &recipient_by,
                    Some(delivered_key),
                    &annotated,
                )
                .await;
            }
        }
        state
            .metrics
            .messages_routed_total
            .fetch_add(1, Ordering::Relaxed);
        return Ok(None);
    }
    if durable_c2s_delivery.is_some() {
        if let Err(error) =
            crate::xmpp::protocol::misc::send_push_notification(state, recipient.id).await
        {
            state
                .metrics
                .post_accept_side_effect_failures_total
                .fetch_add(1, Ordering::Relaxed);
            tracing::warn!(?error, %stable_id, recipient_id = %recipient.id, "durable inbound C2S message was accepted but push notification failed");
        }
        return Ok(None);
    }
    if direct_delivery_mode
        == crate::xmpp::protocol::messaging::DirectDeliveryMode::VolatileExplicitNoStore
    {
        return Ok(inbound_message_error(root, "wait", "service-unavailable"));
    }
    if !persistence_allowed {
        return Ok(None);
    }
    if persistence_allowed
        && matches!(
            root.attribute("type").unwrap_or("normal"),
            "normal" | "chat"
        )
        && durable_content_allowed
    {
        let delayed = add_delay_from(&archive, chrono::Utc::now(), Some(&state.config.domain));
        let offline_outcome = db::store_offline_for_recipient(
            &state.pool,
            recipient.id,
            &recipient_by,
            from,
            &delayed,
            encrypted,
            db::OfflineStorePolicy {
                max_messages: state.config.offline_max_messages_per_account,
                max_bytes: state.config.offline_max_bytes_per_account,
                ttl_days: state.config.offline_message_ttl_days,
                mam_backed: archive_allowed,
            },
        )
        .await?;
        if offline_outcome == db::OfflineStoreOutcome::RecipientUnavailable {
            return Ok(None);
        }
        if offline_outcome == db::OfflineStoreOutcome::QuotaExceeded {
            if history_committed {
                if let Err(error) =
                    crate::xmpp::protocol::misc::send_push_notification(state, recipient.id).await
                {
                    state
                        .metrics
                        .post_accept_side_effect_failures_total
                        .fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(?error, %stable_id, recipient_id = %recipient.id, "MAM-backed inbound message was accepted but offline quota and push delivery both failed");
                }
                return Ok(None);
            }
            return Ok(inbound_message_error(root, "wait", "resource-constraint"));
        }
        if !history_committed {
            finalize_accepted_inbound_history(
                &state.pool,
                root,
                AcceptedInboundHistory {
                    metrics: &state.metrics,
                    recipient_id: recipient.id,
                    canonical_from: &canonical_from,
                    stable_id,
                    archive_allowed,
                    archive: &archive,
                    encrypted,
                    route: "s2s-offline",
                },
            )
            .await;
        }
        if let Err(error) =
            crate::xmpp::protocol::misc::send_push_notification(state, recipient.id).await
        {
            state
                .metrics
                .post_accept_side_effect_failures_total
                .fetch_add(1, Ordering::Relaxed);
            tracing::warn!(?error, %stable_id, recipient_id = %recipient.id, "inbound offline message was accepted but push notification failed");
        }
        return Ok(None);
    }
    Ok(inbound_message_error(root, "wait", "recipient-unavailable"))
}

/// Complete ordinary best-effort history after a legacy online/offline route.
/// Personal retractions are deliberately excluded: their authorization,
/// tombstones, action MAM, and delivery outbox commit before fanout.
struct AcceptedInboundHistory<'a> {
    metrics: &'a crate::metrics::Metrics,
    recipient_id: uuid::Uuid,
    canonical_from: &'a str,
    stable_id: uuid::Uuid,
    archive_allowed: bool,
    archive: &'a str,
    encrypted: bool,
    route: &'static str,
}

async fn finalize_accepted_inbound_history(
    pool: &sqlx::PgPool,
    root: roxmltree::Node<'_, '_>,
    history: AcceptedInboundHistory<'_>,
) {
    let AcceptedInboundHistory {
        metrics,
        recipient_id,
        canonical_from,
        stable_id,
        archive_allowed,
        archive,
        encrypted,
        route,
    } = history;
    let writes = archive_allowed
        .then_some(ArchiveWrite {
            id: stable_id,
            owner_id: recipient_id,
            peer_jid: canonical_from,
            stanza: archive,
            encrypted,
            stanza_id: root.attribute("id"),
        })
        .into_iter()
        .collect::<Vec<_>>();
    debug_assert!(
        crate::xmpp::protocol::retractions::personal_retraction_command(root)
            .ok()
            .flatten()
            .is_none(),
        "personal retraction reached post-delivery history finalization"
    );
    let history_result = if writes.is_empty() {
        Ok(())
    } else {
        let writes = writes
            .iter()
            .map(|write| db::PersonalArchiveWrite {
                id: write.id,
                owner_id: write.owner_id,
                peer_jid: write.peer_jid,
                stanza: write.stanza,
                encrypted: write.encrypted,
                stanza_id: write.stanza_id,
            })
            .collect::<Vec<_>>();
        db::admit_personal_history(pool, None, &writes)
            .await
            .map(|_| ())
    };
    if let Err(error) = history_result {
        metrics
            .post_accept_side_effect_failures_total
            .fetch_add(1, Ordering::Relaxed);
        tracing::warn!(?error, %stable_id, %route, %recipient_id, "accepted inbound message history transaction failed");
    }
}

/// Select a single XEP-0359 identity asserted by the exact domain
/// authenticated on this S2S stream. IDs by an unrelated domain are ordinary
/// forwarded payload and can never suppress delivery. Multiple assertions by
/// the same authority are treated as ambiguous and simply disable dedupe.
fn authoritative_remote_stanza_identity(
    root: roxmltree::Node<'_, '_>,
    authenticated_domain: &str,
) -> Option<(String, String, String)> {
    let authenticated_domain = prepare_domainpart(authenticated_domain).ok()?;
    let mut candidates = root.children().filter_map(|node| {
        if !node.is_element()
            || node.tag_name().name() != "stanza-id"
            || node.tag_name().namespace() != Some("urn:xmpp:sid:0")
        {
            return None;
        }
        let raw_by = node.attribute("by")?;
        let by = CanonicalJid::parse(raw_by).ok()?;
        let identity = node.attribute("id")?;
        if identity.is_empty() || identity.len() > 1_024 || identity.chars().any(char::is_control) {
            return None;
        }
        (by.domainpart() == authenticated_domain)
            .then(|| (raw_by.to_owned(), by.to_string(), identity.to_owned()))
    });
    let candidate = candidates.next()?;
    candidates.next().is_none().then_some(candidate)
}

/// RFC 6120 §8.3.1 forbids replying to an error stanza with another stanza
/// error.  Keep the guard next to the S2S message pipeline so every early
/// validation, privacy and routing rejection shares the same behavior.
fn inbound_message_error(
    root: roxmltree::Node<'_, '_>,
    error_type: &str,
    condition: &str,
) -> Option<String> {
    (root.attribute("type") != Some("error")).then(|| s2s_stanza_error(root, error_type, condition))
}

#[cfg(test)]
fn offline_quota_error(root: roxmltree::Node<'_, '_>) -> String {
    s2s_stanza_error(root, "wait", "resource-constraint")
}

#[cfg(test)]
fn recipient_unavailable_error(root: roxmltree::Node<'_, '_>) -> String {
    s2s_stanza_error(root, "wait", "recipient-unavailable")
}

fn is_remote_muc_private_message(
    root: roxmltree::Node<'_, '_>,
    from: &str,
    authenticated_domain: &str,
) -> bool {
    prepare_domainpart(authenticated_domain).is_ok_and(|domain| {
        domain.strip_prefix("conference.").is_some()
            && CanonicalJid::parse(from).is_ok_and(|jid| {
                jid.resourcepart().is_some() && same_s2s_domain(jid.domainpart(), &domain)
            })
    }) && matches!(
        root.attribute("type").unwrap_or("normal"),
        "chat" | "normal"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::retractions::RetractionService;

    #[test]
    fn local_service_domains_cannot_be_asserted_by_an_inbound_federation_stream() {
        for domain in [
            "example.test",
            "PUBSUB.Example.Test.",
            "conference.example.test",
            "mix.example.test",
            "upload.example.test",
        ] {
            assert!(locally_hosted_identity_domain("example.test", domain));
        }
        assert!(!locally_hosted_identity_domain(
            "example.test",
            "remote.example.test"
        ));
    }

    #[tokio::test]
    async fn disabled_federation_task_waits_for_cancel() {
        let cancel = tokio_util::sync::CancellationToken::new();
        let task_cancel = cancel.clone();
        let mut task = tokio::spawn(async move {
            wait_for_federation_shutdown(&task_cancel).await;
        });

        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), &mut task)
                .await
                .is_err(),
            "disabled federation must not terminate the whole server"
        );
        cancel.cancel();
        tokio::time::timeout(std::time::Duration::from_secs(1), task)
            .await
            .expect("disabled federation shutdown wait timed out")
            .expect("disabled federation shutdown task panicked");
    }

    #[test]
    fn push_notification_publish_routes_to_service_instead_of_pep() {
        let push = Document::parse(
            "<pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='device'><item><notification xmlns='urn:xmpp:push:0'/></item></publish><publish-options/></pubsub>",
        )
        .unwrap();
        assert!(is_xep0357_notification_publish(push.root_element()));

        let pep = Document::parse(
            "<pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='urn:test'><item><value xmlns='urn:test'>payload</value></item></publish></pubsub>",
        )
        .unwrap();
        assert!(!is_xep0357_notification_publish(pep.root_element()));

        // RFC 6121 §§8.5.2.1.3 and 8.5.2.2.3 say that an IQ addressed to a
        // bare account is answered by the server and MUST NOT be delivered to
        // account resources.  Northstar's explicit, narrow service extension
        // is limited to the XEP-0357 notification shape; generic PubSub or an
        // arbitrary IQ cannot use this compatibility route.
        let service_account = CanonicalJid::parse_bare("push@example.test").unwrap();
        assert!(bare_account_iq_may_route_to_service_resource(
            &service_account,
            push.root_element()
        ));
        assert!(!bare_account_iq_may_route_to_service_resource(
            &service_account,
            pep.root_element()
        ));
        let domain_service = CanonicalJid::parse("push.example.test").unwrap();
        assert!(!bare_account_iq_may_route_to_service_resource(
            &domain_service,
            push.root_element()
        ));
        let full_resource = CanonicalJid::parse("push@example.test/worker").unwrap();
        assert!(!bare_account_iq_may_route_to_service_resource(
            &full_resource,
            push.root_element()
        ));
    }

    #[test]
    fn authoritative_dialback_callbacks_are_not_misclassified_as_downgrades() {
        assert!(is_certificate_downgrade("result", true));
        assert!(!is_certificate_downgrade("verify", true));
        assert!(!is_certificate_downgrade("result", false));
    }

    #[test]
    fn remote_history_identity_is_bound_to_the_authenticated_domain() {
        let document = Document::parse(
            "<message><stanza-id xmlns='urn:xmpp:sid:0' by='Alice@REMOTE.test' id='trusted'/><stanza-id xmlns='urn:xmpp:sid:0' by='mallory.test' id='ignored'/></message>",
        )
        .unwrap();
        assert_eq!(
            authoritative_remote_stanza_identity(document.root_element(), "remote.TEST"),
            Some((
                "Alice@REMOTE.test".to_owned(),
                "alice@remote.test".to_owned(),
                "trusted".to_owned()
            ))
        );
        assert!(
            authoritative_remote_stanza_identity(document.root_element(), "unrelated.test")
                .is_none()
        );

        let ambiguous = Document::parse(
            "<message><stanza-id xmlns='urn:xmpp:sid:0' by='alice@remote.test' id='a'/><stanza-id xmlns='urn:xmpp:sid:0' by='remote.test' id='b'/></message>",
        )
        .unwrap();
        assert!(
            authoritative_remote_stanza_identity(ambiguous.root_element(), "remote.test").is_none()
        );
    }

    #[test]
    fn s2s_sender_authentication_uses_idna_and_rejects_malformed_jids() {
        assert!(authenticated_s2s_sender(
            "Alice@B\u{fc}cher.Example/Phone",
            "bücher.example"
        ));
        assert!(authenticated_s2s_sender(
            "mix.bücher.example",
            "MIX.B\u{fc}CHER.example."
        ));
        assert!(!authenticated_s2s_sender(
            "alice@example.test/\u{0007}",
            "example.test"
        ));
        assert!(!authenticated_s2s_sender(
            "alice@evil.test/Phone",
            "example.test"
        ));
    }

    #[test]
    fn rfc6120_s2s_address_violations_are_fatal_stream_errors() {
        let valid = "<message from='alice@remote.test/phone' to='bob@local.test'/>";
        assert_eq!(
            s2s_stream_address_error(valid, "remote.test", "local.test"),
            None
        );
        for (stanza, expected) in [
            (
                "<message to='bob@local.test'/>",
                Some("improper-addressing"),
            ),
            (
                "<message from='alice@remote.test'/>",
                Some("improper-addressing"),
            ),
            (
                "<message from='not a jid' to='bob@local.test'/>",
                Some("improper-addressing"),
            ),
            (
                "<message from='alice@remote.test' to='not a jid'/>",
                Some("improper-addressing"),
            ),
            (
                "<message from='mallory@evil.test' to='bob@local.test'/>",
                Some("invalid-from"),
            ),
            (
                "<message from='alice@remote.test' to='bob@elsewhere.test'/>",
                Some("host-unknown"),
            ),
        ] {
            assert_eq!(
                s2s_stream_address_error(stanza, "REMOTE.test", "LOCAL.test"),
                expected,
                "wrong stream result for {stanza}"
            );
        }
    }

    #[test]
    fn inbound_federation_uses_the_same_strict_core_stanza_grammar() {
        assert!(valid_inbound_wire_namespace(
            "<message from='a@remote.test' to='b@local.test'/>"
        ));
        assert!(valid_inbound_wire_namespace(
            "<message xmlns='jabber:server' from='a@remote.test' to='b@local.test'/>"
        ));
        assert!(!valid_inbound_wire_namespace(
            "<message xmlns='jabber:client' from='a@remote.test' to='b@local.test'/>"
        ));
        assert!(!valid_inbound_wire_namespace(
            "<message xmlns='urn:wrong' from='a@remote.test' to='b@local.test'/>"
        ));
        for valid in [
            "<message xmlns='jabber:client' from='a@remote.test' to='b@local.test' type='chat'><body>ok</body></message>",
            "<presence xmlns='jabber:client' from='a@remote.test' to='b@local.test' type='subscribe'/>",
            "<iq xmlns='jabber:client' from='a@remote.test' to='b@local.test' type='get' id='q1'><ping xmlns='urn:xmpp:ping'/></iq>",
        ] {
            let document = Document::parse(valid).unwrap();
            assert_eq!(
                validate_inbound_core_stanza(document.root_element()),
                InboundCoreValidation::Valid,
                "rejected {valid}"
            );
        }

        for (invalid, expected) in [
            (
                "<message xmlns='jabber:client' from='a@remote.test' to='b@local.test' type='invented'/>",
                InboundCoreValidation::Error("bad-request"),
            ),
            (
                "<presence xmlns='jabber:client' from='a@remote.test' to='b@local.test'><priority>128</priority></presence>",
                InboundCoreValidation::Error("bad-request"),
            ),
        ] {
            let document = Document::parse(invalid).unwrap();
            assert_eq!(
                validate_inbound_core_stanza(document.root_element()),
                expected,
                "accepted {invalid}"
            );
        }

        for dropped in [
            "<message xmlns='urn:wrong' type='chat'/>",
            "<feature xmlns='jabber:client'/>",
            "<iq xmlns='jabber:client' type='error' id='e'><error/></iq>",
            "<iq xmlns='jabber:client' from='a@remote.test' to='b@local.test' type='get'><ping xmlns='urn:xmpp:ping'/></iq>",
            "<message xmlns='jabber:client' from='bad domain' to='b@local.test' type='chat'/>",
        ] {
            let document = Document::parse(dropped).unwrap();
            assert_eq!(
                validate_inbound_core_stanza(document.root_element()),
                InboundCoreValidation::Drop,
                "reflected {dropped}"
            );
        }
    }

    #[test]
    fn probe_status_responses_preserve_correlation_and_escape_addresses() {
        let response = presence_probe_status_response(
            "alice@local.test",
            "bob&carol@remote.test",
            "unavailable",
            Some("probe'1"),
        );
        assert_eq!(
            response,
            "<presence xmlns='jabber:server' from='alice@local.test' to='bob&amp;carol@remote.test' type='unavailable' id='probe&apos;1'/>"
        );
    }

    #[test]
    fn bidi_replies_honor_the_peer_limit_and_use_policy_violation_when_possible() {
        let request = "<iq xmlns='jabber:server' type='get' id='q1' from='remote.test' to='local.test'><ping xmlns='urn:xmpp:ping'/></iq>";
        let oversized = format!(
            "<iq xmlns='jabber:server' type='result' id='q1' from='local.test' to='remote.test'><value>{}</value></iq>",
            "x".repeat(2_048)
        );
        let error = s2s_stanza_error(
            Document::parse(request).unwrap().root_element(),
            "modify",
            "policy-violation",
        );
        let error_bytes = super::super::outbound::serialize_for_peer(&error, None)
            .unwrap()
            .len();

        let bounded = reply_within_peer_limit(&oversized, request, Some(error_bytes))
            .unwrap()
            .expect("the compact policy error fits exactly");
        assert!(bounded.contains("<policy-violation"));
        assert!(bounded.contains("id='q1'"));
        assert!(
            reply_within_peer_limit(&oversized, request, Some(error_bytes - 1))
                .unwrap()
                .is_none()
        );
        assert!(reply_within_peer_limit(&oversized, request, Some(0))
            .unwrap()
            .is_none());
    }

    #[test]
    fn bidi_request_requires_the_negotiation_namespace() {
        assert_eq!(
            parse_bidi_request("<bidi xmlns='urn:xmpp:bidi'/>"),
            Some(BidiRequest {
                peer_limits: AdvertisedStreamLimits::default()
            })
        );
        assert_eq!(
            parse_bidi_request("<bidi xmlns='urn:xmpp:bidi'><limits xmlns='urn:xmpp:stream-limits:0'><max-bytes>8192</max-bytes><idle-seconds>12</idle-seconds></limits></bidi>"),
            Some(BidiRequest {
                peer_limits: AdvertisedStreamLimits {
                    max_bytes: Some(8192),
                    idle_seconds: Some(12),
                }
            })
        );
        for invalid in [
            "<bidi xmlns='urn:xmpp:features:bidi'/>",
            "<bidi/>",
            "<message xmlns='jabber:server'/>",
            "<bidi xmlns='urn:xmpp:bidi' extra='true'/>",
            "<bidi xmlns='urn:xmpp:bidi'>text</bidi>",
            "<bidi xmlns='urn:xmpp:bidi'><unknown/></bidi>",
            "<bidi xmlns='urn:xmpp:bidi'><limits xmlns='urn:xmpp:stream-limits:0'/><limits xmlns='urn:xmpp:stream-limits:0'/></bidi>",
            "<bidi xmlns='urn:xmpp:bidi'><limits xmlns='urn:xmpp:stream-limits:0'><idle-seconds>12</idle-seconds><max-bytes>8192</max-bytes></limits></bidi>",
        ] {
            assert!(parse_bidi_request(invalid).is_none(), "accepted {invalid}");
        }
    }

    #[test]
    fn starttls_requires_the_exact_empty_negotiation_element() {
        assert!(valid_starttls_request(
            "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"
        ));
        for invalid in [
            "<starttls/>",
            "<starttls-bogus xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>",
            "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls' extra='1'/>",
            "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls>",
        ] {
            assert!(!valid_starttls_request(invalid), "accepted {invalid}");
        }
    }

    #[test]
    fn dialback_frames_inherit_only_the_stream_declared_prefix() {
        let inherited = restore_inherited_dialback_namespace(
            "<db:result from='remote.test' to='local.test'>00</db:result>",
        );
        let document = Document::parse(&inherited).unwrap();
        assert_eq!(
            document.root_element().tag_name().namespace(),
            Some(DIALBACK_NS)
        );

        let conflicting =
            "<db:result xmlns:db='urn:wrong' from='remote.test' to='local.test'>00</db:result>";
        assert!(matches!(
            restore_inherited_dialback_namespace(conflicting),
            Cow::Borrowed(_)
        ));
        let document = Document::parse(conflicting).unwrap();
        assert_ne!(
            document.root_element().tag_name().namespace(),
            Some(DIALBACK_NS)
        );
    }

    #[test]
    fn external_authentication_rejects_ambiguous_xml_and_base64() {
        let valid = Document::parse(
            "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='EXTERNAL'>=</auth>",
        )
        .unwrap();
        assert!(valid_external_auth_shape(valid.root_element()));
        assert_eq!(decode_external("=").unwrap(), "");
        assert_eq!(decode_external("").unwrap(), "");

        for invalid in [
            "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='EXTERNAL' extra='1'>=</auth>",
            "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='EXTERNAL'><response/></auth>",
            "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='EXTERNAL'><!--split-->ZXhhbXBsZS50ZXN0</auth>",
        ] {
            let document = Document::parse(invalid).unwrap();
            assert!(!valid_external_auth_shape(document.root_element()), "accepted {invalid}");
        }
        assert!(decode_external(" ZXhhbXBsZS50ZXN0").is_err());
        assert!(decode_external("ZXhhbXBsZS50ZXN0\n").is_err());
        assert!(decode_external("=AAA").is_err());
    }

    #[test]
    fn message_delivery_errors_use_rfc6120_type_condition_pairs() {
        let request = Document::parse(
            "<message xmlns='jabber:server' from='alice@remote.test/a' to='bob@local.test'><body>hello</body></message>",
        )
        .unwrap();
        for (serialized, condition) in [
            (
                offline_quota_error(request.root_element()),
                "resource-constraint",
            ),
            (
                recipient_unavailable_error(request.root_element()),
                "recipient-unavailable",
            ),
        ] {
            let response = Document::parse(&serialized).unwrap();
            let error = response
                .root_element()
                .children()
                .find(|child| {
                    child.is_element()
                        && child.tag_name().name() == "error"
                        && child.tag_name().namespace() == Some("jabber:server")
                })
                .unwrap();
            assert_eq!(error.attribute("type"), Some("wait"));
            assert!(error.children().any(|child| {
                child.is_element()
                    && child.tag_name().name() == condition
                    && child.tag_name().namespace() == Some("urn:ietf:params:xml:ns:xmpp-stanzas")
            }));
        }
    }

    #[test]
    fn message_errors_never_generate_error_loops() {
        let ordinary = Document::parse(
            "<message xmlns='jabber:server' from='alice@remote.test/a' to='bob@local.test'><body>hello</body></message>",
        )
        .unwrap();
        assert!(
            inbound_message_error(ordinary.root_element(), "cancel", "service-unavailable")
                .is_some()
        );

        let error = Document::parse(
            "<message xmlns='jabber:server' type='error' from='alice@remote.test/a' to='missing@local.test'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></message>",
        )
        .unwrap();
        assert!(
            inbound_message_error(error.root_element(), "cancel", "service-unavailable").is_none()
        );
    }

    #[tokio::test(flavor = "current_thread")]
    #[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
    async fn message_acceptance_boundary_prevents_mam_retraction_and_offline_ghosts() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let admin = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .unwrap();
        let schema = format!("message_acceptance_test_{}", uuid::Uuid::new_v4().simple());
        eprintln!("isolated_schema={schema}");
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&admin)
            .await
            .unwrap();
        let connection_schema = schema.clone();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .after_connect(move |connection, _| {
                let statement = format!("SET search_path TO {connection_schema}");
                Box::pin(async move {
                    sqlx::query(&statement).execute(connection).await?;
                    Ok(())
                })
            })
            .connect(&url)
            .await
            .unwrap();
        sqlx::query(
            "CREATE TABLE users(id UUID PRIMARY KEY, username TEXT NOT NULL, \
             is_disabled BOOLEAN NOT NULL DEFAULT FALSE)",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "CREATE TABLE federated_presence_pending( \
             recipient_id UUID NOT NULL, from_jid TEXT NOT NULL, stanza TEXT, \
             created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), PRIMARY KEY(recipient_id, from_jid))",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "CREATE TABLE offline_messages( \
             id UUID PRIMARY KEY, recipient_id UUID NOT NULL, sender_jid TEXT NOT NULL, \
             stanza TEXT NOT NULL, target_resource VARCHAR(1023), encrypted BOOLEAN NOT NULL, mam_backed BOOLEAN NOT NULL DEFAULT FALSE, \
             created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "CREATE TABLE message_archive( \
             id UUID PRIMARY KEY, owner_id UUID NOT NULL, peer_jid TEXT NOT NULL, \
             peer_full_jid TEXT NOT NULL, stanza TEXT NOT NULL, encrypted BOOLEAN NOT NULL, \
             stanza_id VARCHAR(128), created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "CREATE TABLE s2s_outbox( \
             id UUID PRIMARY KEY, target_domain TEXT NOT NULL, bounce_to TEXT, stanza TEXT NOT NULL, \
             dedupe_hash BYTEA NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), \
             expires_at TIMESTAMPTZ NOT NULL, next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), \
             attempt_count INTEGER NOT NULL DEFAULT 0, locked_until TIMESTAMPTZ, lock_token UUID, \
             last_error TEXT, enqueue_sequence BIGINT GENERATED BY DEFAULT AS IDENTITY, \
             UNIQUE(target_domain, dedupe_hash))",
        )
        .execute(&pool)
        .await
        .unwrap();

        let recipient_id = uuid::Uuid::new_v4();
        let sender_id = uuid::Uuid::new_v4();
        sqlx::query("INSERT INTO users(id, username) VALUES($1, 'bob'), ($2, 'alice')")
            .bind(recipient_id)
            .bind(sender_id)
            .execute(&pool)
            .await
            .unwrap();
        let persisted_subscribe = "<presence xmlns='jabber:client' from='alice@remote.test' to='bob@local.test' type='subscribe'><status>hello</status></presence>";
        db::add_federated_presence_pending_with_stanza(
            &pool,
            recipient_id,
            "alice@remote.test",
            Some(persisted_subscribe),
        )
        .await
        .unwrap();
        let oversized_subscription = "x".repeat(65_537);
        assert!(db::add_federated_presence_pending_with_stanza(
            &pool,
            recipient_id,
            "mallory@remote.test",
            Some(&oversized_subscription),
        )
        .await
        .is_err());
        let pending_rows: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM federated_presence_pending")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(pending_rows, 1);
        let retained_subscription: String = sqlx::query_scalar(
            "SELECT stanza FROM federated_presence_pending WHERE recipient_id=$1 AND from_jid='alice@remote.test'",
        )
        .bind(recipient_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(retained_subscription, persisted_subscribe);
        db::archive_message(
            &pool,
            uuid::Uuid::new_v4(),
            recipient_id,
            "alice@remote.test/Phone",
            "<message from='alice@remote.test/Phone' to='bob@local.test' id='remote-original'><body>recipient original</body></message>",
            false,
            Some("remote-original"),
        )
        .await
        .unwrap();
        db::archive_message(
            &pool,
            uuid::Uuid::new_v4(),
            sender_id,
            "carol@remote.test/Laptop",
            "<message from='alice@local.test/Phone' to='carol@remote.test/Laptop' id='outbound-original'><body>sender original</body></message>",
            false,
            Some("outbound-original"),
        )
        .await
        .unwrap();

        use crate::xmpp::protocol::messaging::{undelivered_disposition, UndeliveredDisposition};
        assert_eq!(
            undelivered_disposition("headline", true, true),
            UndeliveredDisposition::Drop
        );
        assert_eq!(
            undelivered_disposition("chat", false, true),
            UndeliveredDisposition::Drop
        );
        assert_eq!(
            undelivered_disposition("normal", true, false),
            UndeliveredDisposition::RejectWait
        );
        assert_eq!(
            undelivered_disposition("groupchat", true, true),
            UndeliveredDisposition::RejectCancel
        );

        sqlx::query("INSERT INTO offline_messages(id, recipient_id, sender_jid, stanza, encrypted) VALUES($1, $2, 'seed@remote.test', '<message/>', FALSE)")
            .bind(uuid::Uuid::new_v4())
            .bind(recipient_id)
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            db::store_offline(
                &pool,
                recipient_id,
                "alice@remote.test/Phone",
                "<message><retract xmlns='urn:xmpp:message-retract:1' id='remote-original'/></message>",
                false,
                db::OfflineStorePolicy {
                    max_messages: 1,
                    max_bytes: 1_000_000,
                    ttl_days: 30,
                    mam_backed: false,
                },
            )
            .await
            .unwrap(),
            db::OfflineStoreOutcome::QuotaExceeded
        );
        assert!(db::enqueue_s2s_outbox(
            &pool,
            "remote.test",
            "<message from='alice@local.test' to='carol@remote.test'/>",
            Some("alice@local.test/Phone"),
            300,
            0,
            1_000_000,
            100,
        )
        .await
        .is_err());
        let rejected_archive_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM message_archive")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(rejected_archive_count, 2);
        let recipient_original: String = sqlx::query_scalar(
            "SELECT stanza FROM message_archive WHERE owner_id=$1 AND stanza_id='remote-original'",
        )
        .bind(recipient_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(recipient_original.contains("recipient original"));
        let sender_original: String = sqlx::query_scalar(
            "SELECT stanza FROM message_archive WHERE owner_id=$1 AND stanza_id='outbound-original'",
        )
        .bind(sender_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(sender_original.contains("sender original"));
        let rejected_offline_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM offline_messages")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(rejected_offline_count, 1);

        let online_retraction = Document::parse(
            "<message id='online-retraction'><retract xmlns='urn:xmpp:message-retract:1' id='remote-original'/></message>",
        )
        .unwrap();
        let online_stable_id = uuid::Uuid::new_v4();
        let retraction_service = RetractionService::new(
            pool.clone(),
            crate::abuse::test_personal_retraction_content_keyring(),
            "local.test",
        );
        let online_action = "<message from='alice@remote.test/Phone' to='bob@local.test' id='online-retraction'><retract xmlns='urn:xmpp:message-retract:1' id='remote-original'/></message>";
        let online_command = crate::xmpp::protocol::retractions::personal_retraction_command(
            online_retraction.root_element(),
        )
        .unwrap()
        .unwrap();
        let online_writes = [ArchiveWrite {
            id: online_stable_id,
            owner_id: recipient_id,
            peer_jid: "alice@remote.test/Phone",
            stanza: online_action,
            encrypted: false,
            stanza_id: Some("online-retraction"),
        }];
        let online_delivery = DeliveryProjection {
            id: online_stable_id,
            recipient_id,
            local_actor_id: None,
            sender_jid: "alice@remote.test/Phone",
            stanza: online_action,
            encrypted: false,
            max_messages: 100,
            max_bytes: 1_000_000,
            ttl_days: 30,
            mam_backed: true,
        };
        assert_eq!(
            retraction_service
                .apply_with_delivery(
                    &[OwnerProjection {
                        owner_id: recipient_id,
                        peer_jid: "alice@remote.test/Phone",
                    }],
                    "alice@remote.test/Phone",
                    &RetractionCommand {
                        target_id: &online_command.target_id,
                        action_id: &online_command.action_id,
                        semantic_payload: &online_command.semantic_payload,
                    },
                    &online_writes,
                    Some(&online_delivery),
                    None,
                )
                .await
                .unwrap(),
            RetractionOutcome::Applied { tombstones: 1 }
        );
        let tombstone: String = sqlx::query_scalar(
            "SELECT stanza FROM message_archive WHERE owner_id=$1 AND stanza_id='remote-original'",
        )
        .bind(recipient_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(tombstone.contains("urn:xmpp:message-retract:1"));
        assert!(!tombstone.contains("recipient original"));

        db::archive_message(
            &pool,
            uuid::Uuid::new_v4(),
            recipient_id,
            "alice@remote.test/Phone",
            "<message from='alice@remote.test/Phone' to='bob@local.test' id='offline-original'><body>offline original</body></message>",
            false,
            Some("offline-original"),
        )
        .await
        .unwrap();
        sqlx::query("DELETE FROM offline_messages")
            .execute(&pool)
            .await
            .unwrap();
        let offline_retraction_xml = "<message id='offline-retraction'><retract xmlns='urn:xmpp:message-retract:1' id='offline-original'/></message>";
        let offline_retraction = Document::parse(offline_retraction_xml).unwrap();
        let offline_command = crate::xmpp::protocol::retractions::personal_retraction_command(
            offline_retraction.root_element(),
        )
        .unwrap()
        .unwrap();
        let offline_delivery_id = uuid::Uuid::new_v4();
        let offline_writes = [ArchiveWrite {
            id: uuid::Uuid::new_v4(),
            owner_id: recipient_id,
            peer_jid: "alice@remote.test/Phone",
            stanza: offline_retraction_xml,
            encrypted: false,
            stanza_id: Some("offline-retraction"),
        }];
        let offline_delivery = DeliveryProjection {
            id: offline_delivery_id,
            recipient_id,
            local_actor_id: None,
            sender_jid: "alice@remote.test/Phone",
            stanza: offline_retraction_xml,
            encrypted: false,
            max_messages: 100,
            max_bytes: 1_000_000,
            ttl_days: 30,
            mam_backed: true,
        };
        assert_eq!(
            retraction_service
                .apply_with_delivery(
                    &[OwnerProjection {
                        owner_id: recipient_id,
                        peer_jid: "alice@remote.test/Phone",
                    }],
                    "alice@remote.test/Phone",
                    &RetractionCommand {
                        target_id: &offline_command.target_id,
                        action_id: &offline_command.action_id,
                        semantic_payload: &offline_command.semantic_payload,
                    },
                    &offline_writes,
                    Some(&offline_delivery),
                    None,
                )
                .await
                .unwrap(),
            RetractionOutcome::Applied { tombstones: 1 }
        );
        let offline_tombstone: String = sqlx::query_scalar(
            "SELECT stanza FROM message_archive WHERE owner_id=$1 AND stanza_id='offline-original'",
        )
        .bind(recipient_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(offline_tombstone.contains("urn:xmpp:message-retract:1"));
        let accepted_offline_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM offline_messages")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(accepted_offline_count, 1);

        db::enqueue_s2s_outbox(
            &pool,
            "remote.test",
            "<message from='alice@local.test' to='carol@remote.test'><retract xmlns='urn:xmpp:message-retract:1' id='outbound-original'/></message>",
            Some("alice@local.test/Phone"),
            300,
            100,
            1_000_000,
            100,
        )
        .await
        .unwrap();
        let outbound_retraction = Document::parse(
            "<message id='outbound-retraction'><retract xmlns='urn:xmpp:message-retract:1' id='outbound-original'/></message>",
        )
        .unwrap();
        let outbound_action = "<message from='alice@local.test/Phone' to='carol@remote.test/Laptop' id='outbound-retraction'><retract xmlns='urn:xmpp:message-retract:1' id='outbound-original'/></message>";
        let outbound_action_write = [ArchiveWrite {
            id: uuid::Uuid::new_v4(),
            owner_id: sender_id,
            peer_jid: "carol@remote.test/Laptop",
            stanza: outbound_action,
            encrypted: false,
            stanza_id: Some("outbound-retraction"),
        }];
        let outbound_command = crate::xmpp::protocol::retractions::personal_retraction_command(
            outbound_retraction.root_element(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            retraction_service
                .apply(
                    &[OwnerProjection {
                        owner_id: sender_id,
                        peer_jid: "carol@remote.test/Laptop",
                    }],
                    "alice@local.test/Phone",
                    &RetractionCommand {
                        target_id: &outbound_command.target_id,
                        action_id: &outbound_command.action_id,
                        semantic_payload: &outbound_command.semantic_payload,
                    },
                    &outbound_action_write,
                    None,
                )
                .await
                .unwrap(),
            RetractionOutcome::Applied { tombstones: 1 }
        );
        let rollback_original_id = uuid::Uuid::new_v4();
        db::archive_message(
            &pool,
            rollback_original_id,
            sender_id,
            "carol@remote.test/Laptop",
            "<message from='alice@local.test/Phone' to='carol@remote.test/Laptop' id='rollback-original'><body>must survive rollback</body></message>",
            false,
            Some("rollback-original"),
        )
        .await
        .unwrap();
        let rollback_retraction = Document::parse(
            "<message id='rollback-action'><retract xmlns='urn:xmpp:message-retract:1' id='rollback-original'/></message>",
        )
        .unwrap();
        let conflicting_action = [ArchiveWrite {
            id: rollback_original_id,
            owner_id: sender_id,
            peer_jid: "carol@remote.test/Laptop",
            stanza: "<message id='rollback-action'/>",
            encrypted: false,
            stanza_id: Some("rollback-action"),
        }];
        let rollback_command = crate::xmpp::protocol::retractions::personal_retraction_command(
            rollback_retraction.root_element(),
        )
        .unwrap()
        .unwrap();
        assert!(retraction_service
            .apply(
                &[OwnerProjection {
                    owner_id: sender_id,
                    peer_jid: "carol@remote.test/Laptop",
                }],
                "alice@local.test/Phone",
                &RetractionCommand {
                    target_id: &rollback_command.target_id,
                    action_id: &rollback_command.action_id,
                    semantic_payload: &rollback_command.semantic_payload,
                },
                &conflicting_action,
                None,
            )
            .await
            .is_err());
        let rollback_original: String =
            sqlx::query_scalar("SELECT stanza FROM message_archive WHERE id=$1 AND owner_id=$2")
                .bind(rollback_original_id)
                .bind(sender_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(rollback_original.contains("must survive rollback"));
        let outbound_tombstone: String = sqlx::query_scalar(
            "SELECT stanza FROM message_archive WHERE owner_id=$1 AND stanza_id='outbound-original'",
        )
        .bind(sender_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(outbound_tombstone.contains("urn:xmpp:message-retract:1"));
        let outbox_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM s2s_outbox")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(outbox_count, 1);

        pool.close().await;
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&admin)
            .await
            .unwrap();
        admin.close().await;
    }

    #[test]
    fn persisted_federated_subscription_keeps_extensions_and_uses_bare_jids() {
        let raw = "<presence xmlns='jabber:server' type='subscribe' from='Alice@Remote.Test/Phone' to='Bob@Local.Test/Desktop'><status xml:lang='en'>Please add me</status><nick xmlns='http://jabber.org/protocol/nick'>Alice</nick></presence>";
        let persisted = canonical_subscription_stanza(raw, "alice@remote.test", "bob@local.test");
        let document = Document::parse(&persisted).unwrap();
        let root = document.root_element();
        assert_eq!(root.attribute("from"), Some("alice@remote.test"));
        assert_eq!(root.attribute("to"), Some("bob@local.test"));
        assert_eq!(root.tag_name().namespace(), Some("jabber:client"));
        assert!(!persisted.contains("jabber:server"));
        assert!(root.children().any(|child| {
            child.is_element()
                && child.tag_name().name() == "status"
                && child.text() == Some("Please add me")
        }));
        assert!(root.children().any(|child| {
            child.is_element()
                && child.tag_name().name() == "nick"
                && child.tag_name().namespace() == Some("http://jabber.org/protocol/nick")
                && child.text() == Some("Alice")
        }));
    }

    #[test]
    fn authenticated_sender_cannot_escape_the_peer_domain() {
        assert!(authenticated_s2s_sender(
            "alice@remote.example/phone",
            "remote.example"
        ));
        assert!(!authenticated_s2s_sender(
            "pubsub.remote.example",
            "remote.example"
        ));
        assert!(authenticated_s2s_sender(
            "pubsub.remote.example",
            "pubsub.remote.example"
        ));
        assert!(!authenticated_s2s_sender(
            "room@conference.remote.example/Alice",
            "remote.example"
        ));
        assert!(authenticated_s2s_sender(
            "room@conference.remote.example/Alice",
            "conference.remote.example"
        ));
        assert!(!authenticated_s2s_sender(
            "alice@evil.example/phone",
            "remote.example"
        ));
        assert!(!authenticated_s2s_sender(
            "alice@conference.remote.example.evil/phone",
            "remote.example"
        ));
    }

    #[test]
    fn federated_pep_subscription_branch_has_no_split_authority_reads() {
        let source = include_str!("inbound.rs");
        let branch = source
            .split_once("if !is_xep0357_notification_publish(child) =>")
            .expect("federated PEP set branch must remain identifiable")
            .1
            .split_once("(\"query\", \"http://jabber.org/protocol/disco#info\", \"get\")")
            .expect("federated PEP set branch must end before disco handling")
            .0;
        for forbidden in [
            "db::pep_node(",
            "pep_access_allowed(",
            "subscribe_pep_node_with_outbox(",
            "db::unsubscribe_pep_node(",
        ] {
            assert!(
                !branch.contains(forbidden),
                "federated PEP policy escaped the service transaction: {forbidden}"
            );
        }
        assert!(branch.contains(".subscribe_pep_node("));
        assert!(branch.contains(".unsubscribe_pep_node("));
        assert!(branch.contains("PepSubscriptionActor"));
    }

    #[test]
    fn remote_muc_private_messages_are_not_carbon_copied() {
        let private = Document::parse(
            "<message xmlns='jabber:client' type='chat' from='room@conference.remote.example/nick' to='alice@example.test/phone'><body>private</body></message>",
        )
        .unwrap();
        assert!(is_remote_muc_private_message(
            private.root_element(),
            "room@conference.remote.example/nick",
            "conference.remote.example"
        ));
        let direct = Document::parse(
            "<message xmlns='jabber:client' type='chat' from='bob@remote.example/phone' to='alice@example.test/phone'><body>direct</body></message>",
        )
        .unwrap();
        assert!(!is_remote_muc_private_message(
            direct.root_element(),
            "bob@remote.example/phone",
            "remote.example"
        ));
    }
}
