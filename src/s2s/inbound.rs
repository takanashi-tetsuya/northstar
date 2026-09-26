use crate::{
    db,
    jid::{prepare_domainpart, CanonicalJid},
    services::{
        messaging::{
            DurableAdmissionOutcome, IdentityAuthority, LocalDelivery, LocalRecipientDecision,
            MessageIdentity, MessagePostCommit, OfflineAdmissionOutcome, OfflineMessageAdmission,
            PersonalMessageDestination, ValidatedPersonalMessage,
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
        state.local_domain().to_owned(),
        format!("pubsub.{}", state.local_domain()),
        format!("conference.{}", state.local_domain()),
        format!("mix.{}", state.local_domain()),
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
    if state.s2s_federation_enabled() {
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
            tracing::debug!(?error, "could not read initial S2S stream opening");
            if let Some(condition) = s2s_read_stream_error_condition(&error) {
                let _ = send_initial_stream_error(stream, local_domain, None, condition).await;
            }
            return Err(error);
        }
    };
    match parse_s2s_stream_opening(&frame) {
        Ok(opening) => Ok(Some(opening)),
        Err(condition) => {
            tracing::debug!(%condition, "rejected initial S2S stream opening");
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
    listener: Option<TcpListener>,
) -> Result<()> {
    if !state.s2s_federation_enabled() {
        wait_for_federation_shutdown(&cancel).await;
        return Ok(());
    }
    let listener = listener.context("S2S Direct TLS listener was not activated")?;
    let address = listener
        .local_addr()
        .context("could not inspect S2S Direct TLS listener")?;
    tracing::info!(%address, "XMPP S2S Direct TLS listener ready");
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
    listener: Option<TcpListener>,
) -> Result<()> {
    if !state.s2s_federation_enabled() {
        tracing::warn!("server-to-server federation is disabled by policy");
        // This task is selected by main as a long-lived listener. Closing the
        // optional outbox wake channel is not a server shutdown signal.
        wait_for_federation_shutdown(&cancel).await;
        return Ok(());
    }
    let listener = listener.context("S2S listener was not activated")?;
    let address = listener
        .local_addr()
        .context("could not inspect S2S listener")?;
    tracing::info!(%address, "XMPP S2S listener ready");
    let mut outbox_poll = tokio::time::interval(std::time::Duration::from_secs(1));
    outbox_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut outbound_wake_open = true;
    let outbox_dispatch = state.s2s_outbox_dispatch_context();
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
                if let Err(error) = dispatch_due_outbox(&outbox_dispatch, &state).await {
                    tracing::error!(?error, "failed to dispatch the durable federation outbox");
                }
            }
            wake = outbound_wake.recv(), if outbound_wake_open => {
                if wake.is_some() {
                    if let Err(error) = dispatch_due_outbox(&outbox_dispatch, &state).await {
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
    state.s2s_inbound_connection_telemetry().started();
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
    state.s2s_inbound_connection_telemetry().finished();
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
    state.s2s_inbound_connection_telemetry().started();
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
    state.s2s_inbound_connection_telemetry().finished();
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

    let Some(opening) = read_s2s_opening(&mut secure, state.local_domain(), &mut input).await?
    else {
        return Ok(());
    };
    let asserted_domain = opening.from;
    let target = opening.to;
    if locally_hosted_identity_domain(state.local_domain(), &asserted_domain) {
        send_initial_stream_error(
            &mut secure,
            state.local_domain(),
            Some(&asserted_domain),
            "invalid-from",
        )
        .await?;
        anyhow::bail!("inbound S2S stream asserted a locally hosted source domain");
    }
    if !crate::tls::direct_tls_sni_matches(direct_tls_sni.as_deref(), &target) {
        send_initial_stream_error(
            &mut secure,
            state.local_domain(),
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
            state.local_domain(),
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
    let Some(opening) = read_s2s_opening(&mut stream, state.local_domain(), &mut input).await?
    else {
        return Ok(());
    };
    let claimed_domain = opening.from;
    let target = opening.to;
    if locally_hosted_identity_domain(state.local_domain(), &claimed_domain) {
        send_initial_stream_error(
            &mut stream,
            state.local_domain(),
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
            state.local_domain(),
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
    let Some(opening) = read_s2s_opening(&mut secure, state.local_domain(), &mut input).await?
    else {
        return Ok(());
    };
    let asserted_domain = opening.from;
    let target = opening.to;
    if locally_hosted_identity_domain(state.local_domain(), &asserted_domain) {
        send_initial_stream_error(
            &mut secure,
            state.local_domain(),
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
            state.local_domain(),
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
    let certificate_identity = if state.s2s_sasl_external_enabled() {
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
        if !state.s2s_sasl_external_enabled() || mechanism.as_deref() != Some("EXTERNAL") {
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
            .validated_fragment(&super::sm::feature())?
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

    if !state.s2s_dialback_enabled() || element_namespace.as_deref() != Some(DIALBACK_NS) {
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
        Some(state.tls_context().register_certificate_session(
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
    let scope = super::resume::Scope {
        local: local_domain.clone(),
        remote: domain,
        external: via_external,
        bidi: bidi_enabled,
    };
    let transport = super::resume::Transport {
        stream: secure,
        input,
        limits: peer_limits,
        disconnect,
        _certificate: certificate_session,
    };
    let result = AssertUnwindSafe(drive_authenticated_inbound_inner(
        transport,
        Arc::clone(&state),
        scope,
        connection_id,
        sender,
        receiver,
    ))
    .catch_unwind()
    .await;
    state
        .s2s_connection_registry()
        .remove_bidirectional_if_connection(&route_key, connection_id);
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

fn publish_inbound_route(
    state: &AppState,
    scope: &super::resume::Scope,
    connection_id: uuid::Uuid,
    sender: &mpsc::Sender<FederationEnvelope>,
    disconnect: &tokio_util::sync::CancellationToken,
) -> bool {
    if !scope.bidi {
        return false;
    }
    let key = bidi_connection_key(&scope.local, &scope.remote).expect("prepared stream domains");
    let registered = state
        .s2s_connection_registry()
        .register_bidirectional_if_vacant(
            key,
            BidiS2sSession::new(
                connection_id,
                scope.local.clone(),
                sender.clone(),
                disconnect.clone(),
            ),
        )
        .is_ok();
    if registered {
        state.federation_outbox().wake_outbox();
    }
    registered
}

fn initial_bidi_route_admissible(
    sm_enabled: bool,
    application_stanza_seen: bool,
    negotiation_deadline_elapsed: bool,
    suspended_owner_exists: bool,
) -> bool {
    sm_enabled
        || application_stanza_seen
        || (negotiation_deadline_elapsed && !suspended_owner_exists)
}

async fn reject_resume(
    mut request: super::resume::Request,
    condition: &'static str,
    reason: &'static str,
) {
    // Keep this diagnostic independent of the resume ID, peer counter and
    // stanza contents: fixture logs are retained after a failed stress run.
    tracing::debug!(condition, reason, "rejected inbound S2S resumption");
    let _ = super::sm::failed(&mut request.transport.stream, condition).await;
    let _ = request.result.send(Err(Box::new(request.transport)));
}

async fn accept_resume(
    state: &AppState,
    sm: &mut super::sm::StreamManagement,
    registration: &mut super::resume::Registration,
    scope: &super::resume::Scope,
    mut request: super::resume::Request,
) -> Result<Option<super::resume::Transport>> {
    if request.result.is_closed() {
        return Ok(None);
    }
    if registration.expired() {
        reject_resume(request, "item-not-found", "resume-window-expired").await;
        return Ok(None);
    }
    if request.epoch != registration.epoch || request.transport.disconnect.is_cancelled() {
        reject_resume(
            request,
            "unexpected-request",
            "owner-generation-or-certificate-changed",
        )
        .await;
        return Ok(None);
    }
    if let Err(error) = sm.validate_resume(request.h, request.transport.limits.max_bytes) {
        let reason = match error.to_string().as_str() {
            "S2S peer acknowledged unsent stanzas" => "invalid-handled-count",
            "S2S replay is unavailable" => "unreplayable-pending-stanza",
            "S2S replay exceeds peer limit" => "replay-exceeds-peer-limit",
            _ => "unknown-validation-error",
        };
        reject_resume(request, "policy-violation", reason).await;
        return Ok(None);
    }
    anyhow::ensure!(
        !state.island_mode_enabled() && state.federation_domain_allowed(&scope.remote),
        "federation disabled during resumption"
    );
    sm.renew(state).await?;
    if registration.expired() {
        reject_resume(
            request,
            "item-not-found",
            "resume-window-expired-after-renewal",
        )
        .await;
        return Ok(None);
    }
    sm.acknowledge(state, request.h).await?;
    registration.advance();
    if request.result.send(Ok(())).is_err() {
        anyhow::bail!("S2S resume requester disappeared");
    }
    write_xml(
        &mut request.transport.stream,
        &XmlElement::new("resumed")
            .attr("xmlns", super::sm::NS)
            .attr("previd", &registration.id)
            .attr("h", sm.received().to_string())
            .finish(),
    )
    .await?;
    sm.replay(state, &mut request.transport.stream).await?;
    Ok(Some(request.transport))
}

async fn drive_authenticated_inbound_inner(
    transport: super::resume::Transport,
    state: Arc<AppState>,
    scope: super::resume::Scope,
    connection_id: uuid::Uuid,
    sender: mpsc::Sender<FederationEnvelope>,
    mut outgoing: mpsc::Receiver<FederationEnvelope>,
) -> Result<()> {
    let route_key =
        bidi_connection_key(&scope.local, &scope.remote).expect("prepared stream domains");
    let mut transport = Some(transport);
    let mut sm = super::sm::StreamManagement::with_budget(
        state
            .s2s_connection_registry()
            .resumption
            .replay_bytes
            .clone(),
    );
    let (resume_sender, mut resumes) = mpsc::channel::<super::resume::Request>(1);
    let mut registration: Option<super::resume::Registration> = None;
    let mut used = false;
    let mut suspended_until = None;
    let mut resume_window = super::resume::WINDOW;
    let result = async {
    loop {
        if state.island_mode_enabled() || !state.federation_domain_allowed(&scope.remote) {
            anyhow::bail!("S2S stream is denied by federation policy");
        }
        if transport.is_none() {
            let deadline = suspended_until.context("missing S2S resume deadline")?;
            loop {
                tokio::select! {
                    _ = tokio::time::sleep_until(deadline) => anyhow::bail!("S2S resume window expired"),
                    request = resumes.recv() => {
                        let request = request.context("S2S resume owner closed")?;
                        if let Some(resumed) = tokio::time::timeout_at(deadline, accept_resume(&state, &mut sm, registration.as_mut().expect("registered resume owner"), &scope, request)).await.context("S2S resume window expired")?? {
                            transport = Some(resumed);
                            suspended_until = None;
                            break;
                        }
                    }
                }
            }
        }
        let current = transport.as_mut().expect("active S2S transport");
        if current.disconnect.is_cancelled() { anyhow::bail!("inbound S2S certificate was explicitly revoked"); }
        // A newly authenticated stream may still send <resume/>. Publishing
        // its BIDI route now could deliver an outbox stanza before <resumed/>,
        // which makes the peer reject an otherwise valid resumption. Wait for
        // the first SM command or application stanza before routing on it.
        let mut registered = if initial_bidi_route_admissible(sm.is_enabled(), used, false, false) {
            publish_inbound_route(&state, &scope, connection_id, &sender, &current.disconnect)
        } else {
            false
        };
        let mut initial_negotiation_complete = sm.is_enabled() || used;
        let mut initial_negotiation_deadline = tokio::time::Instant::now() + super::IO_TIMEOUT;
        let peer_limits = current.limits;
        let mut incoming_idle_deadline = tokio::time::Instant::now() + S2S_AUTHENTICATED_IDLE_TIMEOUT;
        let keepalive_period = keepalive_interval_for_peer(peer_limits);
        let mut keepalive = tokio::time::interval_at(tokio::time::Instant::now() + keepalive_period, keepalive_period);
        keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // A successful handoff restarts this loop with a freshly authenticated transport.
        let mut restart = false;
        let active_result: Result<Option<super::resume::Request>> = async {
        loop {
            let current = transport.as_mut().expect("active S2S transport");
            tokio::select! {
                biased;
                _ = current.disconnect.cancelled() => {
                    let _ = send_stream_error(&mut current.stream, "not-authorized").await;
                    anyhow::bail!("inbound S2S certificate was explicitly revoked");
                }
                _ = tokio::time::sleep_until(initial_negotiation_deadline), if !initial_negotiation_complete => {
                    // A peer may use BIDI without SM or sending a stanza of
                    // its own. Admit its route after the negotiation window,
                    // but preserve a suspended owner's full resume window.
                    if initial_bidi_route_admissible(
                        sm.is_enabled(),
                        used,
                        true,
                        state.s2s_connection_registry().resumption.has_suspended_scope(&scope),
                    ) {
                        initial_negotiation_complete = true;
                        registered = publish_inbound_route(&state, &scope, connection_id, &sender, &current.disconnect);
                    } else {
                        initial_negotiation_deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
                    }
                }
                _ = tokio::time::sleep_until(sm.deadline()), if sm.is_enabled() => anyhow::bail!("S2S acknowledgement timed out"),
                request = resumes.recv(), if registration.is_some() => return Ok(request),
                frame = read_frame_until_idle_deadline(&mut current.stream, &mut current.input,
                    S2S_AUTHENTICATED_IDLE_TIMEOUT, &mut incoming_idle_deadline) => {
                    let frame = match frame {
                        Ok(Some(frame)) => frame,
                        Ok(None) => { let _ = write_xml(&mut current.stream, &XmlElement::new("stream:stream").close()).await; return Ok(None); }
                        Err(error) => {
                            if let Some(condition) = s2s_read_stream_error_condition(&error) { let _ = send_stream_error(&mut current.stream, condition).await; }
                            return Err(error);
                        }
                    };
                    if frame.starts_with("</stream:stream") {
                        let _ = write_xml(&mut current.stream, &XmlElement::new("stream:stream").close()).await;
                        return Ok(None);
                    }
                    match super::sm::parse_control(&frame)? {
                        Some(super::sm::Control::Resume { id, h }) if !sm.is_enabled() && !used => {
                            let Some((epoch, owner)) = state.s2s_connection_registry().resumption.lookup(&id, &scope) else {
                                tracing::debug!(condition = "item-not-found", reason = "no-matching-resume-owner", "rejected inbound S2S resumption");
                                super::sm::failed(&mut current.stream, "item-not-found").await?;
                                continue;
                            };
                            state.s2s_connection_registry().remove_bidirectional_if_connection(&route_key, connection_id);
                            while let Ok(envelope) = outgoing.try_recv() {
                                fail_envelope(&state, &envelope, &anyhow::anyhow!("S2S route moved to resumed stream"), false).await;
                            }
                            let (reply, response) = tokio::sync::oneshot::channel();
                            let request = super::resume::Request { transport: transport.take().expect("active transport"), h, epoch, result: reply };
                            owner.try_send(request).map_err(|_| anyhow::anyhow!("S2S resume owner is busy or gone"))?;
                            match tokio::time::timeout(std::time::Duration::from_secs(15), response).await.context("S2S resume handoff timed out")?? {
                                Ok(()) => return Ok(None),
                                Err(returned) => { transport = Some(*returned); restart = true; return Ok(None); }
                            }
                        }
                        Some(super::sm::Control::Enable { resume, max }) if !sm.is_enabled() => {
                            sm.enable();
                            let mut enabled = XmlElement::new("enabled").attr("xmlns", super::sm::NS);
                            if resume && max != Some(0) {
                                resume_window = std::time::Duration::from_secs(u64::from(max.unwrap_or(60).min(60)));
                                registration = state.s2s_connection_registry().resumption.register(scope.clone(), resume_sender.clone());
                                if let Some(owner) = &registration {
                                    enabled = enabled.attr("resume", "true").attr("id", &owner.id).attr("max", resume_window.as_secs().to_string());
                                }
                            }
                            write_xml(&mut current.stream, &enabled.finish()).await?;
                            initial_negotiation_complete = true;
                            registered = publish_inbound_route(&state, &scope, connection_id, &sender, &current.disconnect);
                            continue;
                        }
                        _ => {}
                    }
                    if sm.control(&state, &mut current.stream, &frame, false).await? { continue; }
                    used = true;
                    if !initial_negotiation_complete {
                        initial_negotiation_complete = true;
                        registered = publish_inbound_route(&state, &scope, connection_id, &sender, &current.disconnect);
                    }
                    let routed = route_inbound_for_connection_owned(Arc::clone(&state), scope.remote.clone(), scope.local.clone(), connection_id, frame.clone()).await?;
                    sm.handled(&frame);
                    match routed {
                        InboundFederationRoute::Reply(Some(reply)) => {
                            if let Some(reply) = reply_within_peer_limit(&reply, &frame, peer_limits.max_bytes)? {
                                sm.track(None, &reply)?;
                                write_xml(&mut current.stream, &reply).await?;
                                sm.request(&mut current.stream).await?;
                                keepalive.reset_after(keepalive_period);
                            }
                        }
                        InboundFederationRoute::Reply(None) => {}
                        InboundFederationRoute::StreamError(condition) => {
                            send_stream_error(&mut current.stream, condition).await?;
                            anyhow::bail!("remote S2S stanza violated stream addressing: {condition}");
                        }
                    }
                }
                envelope = outgoing.recv(), if registered => {
                    let Some(mut envelope) = envelope else { return Ok(None); };
                    used = true;
                    if let Err(error) = deliver_managed_envelope(&state, &mut current.stream, &mut envelope, peer_limits.max_bytes, &mut sm).await {
                        let permanent = is_peer_stanza_limit_error(&error);
                        if !sm.owns(&envelope) { fail_envelope(&state, &envelope, &error, permanent).await; }
                        if permanent { continue; }
                        return Err(error);
                    }
                    keepalive.reset_after(keepalive_period);
                }
                _ = keepalive.tick(), if scope.bidi && peer_limits.idle_seconds.is_some() => write_xml(&mut current.stream, " ").await?,
            }
        }
        }.await;
        state.s2s_connection_registry().remove_bidirectional_if_connection(&route_key, connection_id);
        match active_result {
            Ok(Some(request)) => {
                if let Some(resumed) = accept_resume(&state, &mut sm, registration.as_mut().expect("registered resume owner"), &scope, request).await? {
                    if let Some(mut old) = transport.take() {
                        // Dropping the previous socket fences its writer before this loop resumes.
                        let _ = tokio::time::timeout(std::time::Duration::from_millis(100), send_stream_error(&mut old.stream, "conflict")).await;
                    }
                    transport = Some(resumed);
                }
            }
            Ok(None) if restart => continue,
            Ok(None) => return Ok(()),
            Err(error) => {
                if registration.is_none() || !super::util::transport_lost(&error)
                    || transport.as_ref().is_some_and(|current| current.disconnect.is_cancelled()) { return Err(error); }
                let deadline = tokio::time::Instant::now() + resume_window;
                registration.as_mut().expect("registered resume owner").suspend(deadline);
                sm.renew(&state).await?;
                transport.take();
                suspended_until = Some(deadline);
            }
        }
    }
    }.await;
    drop(registration);
    sm.retry_unacknowledged(&state).await;
    while let Ok(envelope) = outgoing.try_recv() {
        fail_envelope(
            &state,
            &envelope,
            &anyhow::anyhow!("S2S connection closed"),
            false,
        )
        .await;
    }
    result
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
        same_s2s_domain(jid.domainpart(), &format!("mix.{}", state.local_domain()))
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
        same_s2s_domain(to_domain, &format!("conference.{}", state.local_domain()));
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
        && same_s2s_domain(to_domain, &format!("upload.{}", state.local_domain()));
    if matches!(authority, InboundRouteAuthority::Component { .. }) && to_is_upload_service {
        // Upload reservations are owned and quota-accounted by a local user
        // row. An external component domain is authenticated, but is not a
        // local user and must never be converted into one implicitly.
        return Ok(Some(s2s_stanza_error(root, "auth", "not-authorized")));
    }
    if from_is_authenticated && state.s2s_component_domain_configured(to_domain) {
        return if state
            .federation_outbox()
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
    let to_is_local_domain = same_s2s_domain(to_domain, state.local_domain());
    let to_is_pubsub_service = matches!(root.tag_name().name(), "iq" | "message")
        && to_jid.localpart().is_none()
        && same_s2s_domain(to_domain, &format!("pubsub.{}", state.local_domain()));
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
    locally_hosted_identity_domain(state.local_domain(), domain)
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
    let Some(recipient) = state
        .presence_service()
        .find_enabled_user(recipient_name)
        .await?
    else {
        return Ok(None);
    };
    let recipient_bare = format!("{}@{}", recipient.username, state.local_domain());
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
        && state
            .presence_service()
            .is_blocked_for_account(recipient.id, &recipient_bare, from)
            .await?
    {
        return Ok(None);
    }
    if subscription_kind
        && to_jid.resourcepart().is_some()
        && kind != "subscribe"
        && state.sessions_for(&to_jid.to_string()).is_empty()
        && !state
            .s2s_subscription_target_route_exists(&to_jid.to_string())
            .await
    {
        return Ok(None);
    }
    let subscription_from = subscription_kind
        .then(|| CanonicalJid::parse(from))
        .transpose()
        .context("validated federated sender became malformed")?
        .map(|jid| jid.bare());
    let recipient_bare = format!("{}@{}", recipient.username, state.local_domain());
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
            .transition_inbound(recipient.id, state.local_domain(), contact, kind, persisted)
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
        let recipient_bare = format!("{}@{}", recipient.username, state.local_domain());

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
            if !state
                .federation_outbox()
                .send(&remote_domain, response, None)
                .await
            {
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
                state.s2s_inbound_delivery_telemetry().post_accept_failed();
                tracing::warn!(?error, recipient_id = %recipient.id, contact = %contact, %kind, "federated roster transition was committed but roster push failed");
            }
        }
        if kind == "subscribe"
            && transition.effect == crate::services::presence::InboundRemotePresenceEffect::Forward
            && state.sessions_for(&recipient_bare).is_empty()
        {
            if let Err(error) = state.dispatch_push_notification(recipient.id).await {
                state.s2s_inbound_delivery_telemetry().post_accept_failed();
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
        if !state
            .federation_outbox()
            .send(&remote_domain, stanza, None)
            .await
        {
            state.s2s_inbound_delivery_telemetry().post_accept_failed();
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
        if !state
            .federation_outbox()
            .send(&remote_domain, stanza, None)
            .await
        {
            state.s2s_inbound_delivery_telemetry().post_accept_failed();
            tracing::warn!(owner = %owner, contact = %contact, "failed to admit current presence after federated subscription approval");
        }
    }
}

async fn route_inbound_presence_probe(
    state: &AppState,
    root: roxmltree::Node<'_, '_>,
    requester: &str,
    target_jid: &CanonicalJid,
    recipient: &crate::services::presence::PresenceAccount,
) -> Result<Option<String>> {
    let requester_bare = crate::jid::canonical_bare_key(requester)?;
    let recipient_bare = format!("{}@{}", recipient.username, state.local_domain());
    let roster_authorized = state
        .s2s_roster_authorization_service()
        .allows_presence(recipient.id, &requester_bare)
        .await?;
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
            .federation_outbox()
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
        Some(username) => state.presence_service().find_enabled_user(username).await?,
        None => None,
    };
    if let Some(recipient) = recipient.as_ref() {
        let recipient_bare = format!("{}@{}", recipient.username, state.local_domain());
        if state
            .presence_service()
            .is_blocked_for_account(recipient.id, &recipient_bare, from)
            .await?
        {
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
            state
                .route_s2s_iq_response_to_remote_resource(to, raw)
                .await;
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
            let subscribed = state
                .s2s_roster_authorization_service()
                .allows_presence(recipient.id, &requester_bare)
                .await?;
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
        let remote_resource_matches = state.s2s_remote_recipient_route_exists(to).await;
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
            &format!("pubsub.{}", state.local_domain()),
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
        ("ping", northstar_xep_0199::NAMESPACE, "get") if state.s2s_ping_route_enabled() => {
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
            let payload = match state.profile_service().public_vcard(owner_name).await? {
                crate::services::profile::PublicVCard::MissingAccount => {
                    return Ok(Some(s2s_iq_error(id, to, from, "item-not-found")));
                }
                crate::services::profile::PublicVCard::Profile(Some(payload)) => payload,
                crate::services::profile::PublicVCard::Profile(None) => {
                    XmlElement::namespaced("vCard", "vcard-temp").finish()
                }
            };
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
            if state
                .pubsub_service()
                .pep_node(owner.id, node)
                .await?
                .is_none()
            {
                return Ok(Some(s2s_iq_error(id, to, from, "item-not-found")));
            }
            if !crate::xmpp::protocol::pep::pep_access_allowed(
                state.pubsub_service(),
                &owner,
                state.local_domain(),
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
                state
                    .pubsub_service()
                    .pep_items(owner.id, node, None, max_items)
                    .await?
            } else {
                state
                    .pubsub_service()
                    .pep_items_by_ids(owner.id, node, &requested, max_items)
                    .await?
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
                    &format!("pubsub.{}", state.local_domain()),
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
            if state.xmpp_extension_enabled(northstar_xep_0199::XEP_ID) {
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
                    &format!("pubsub.{}", state.local_domain()),
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
                delivered = state
                    .route_s2s_iq_request_remote(to, raw, bare_target)
                    .await;
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
    if let Err(condition) = state.validate_routed_message(root) {
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
    let recipient = match state
        .message_service()
        .resolve_local_recipient(recipient_name, state.local_domain(), from)
        .await?
    {
        LocalRecipientDecision::Missing => {
            return Ok(
                if crate::xmpp::protocol::messaging::missing_user_message_should_error(
                    root.attribute("type").unwrap_or("normal"),
                ) {
                    inbound_message_error(root, "cancel", "service-unavailable")
                } else {
                    None
                },
            );
        }
        LocalRecipientDecision::Blocked => {
            return Ok(inbound_message_error(root, "cancel", "service-unavailable"));
        }
        LocalRecipientDecision::Deliver(recipient) => recipient,
    };
    let recipient_bare = format!("{}@{}", recipient.username, state.local_domain());
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
    let remote_route_exists = state.s2s_remote_recipient_route_exists(to).await;
    if unfiltered_privacy_candidates == 0
        && !remote_route_exists
        && state
            .message_service()
            .default_recipient_privacy_denies(recipient.id, from)
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
    let recipient_by = format!("{}@{}", recipient.username, state.local_domain());
    let authoritative_raw = strip_stanza_ids_by_domain(
        &strip_untrusted_direct_delays(raw, Some(authenticated_domain)),
        state.local_domain(),
    );
    let annotated = add_stanza_id(&authoritative_raw, &recipient_by, stable_id);
    let encrypted = is_encrypted(root);
    let durable_content_allowed = encrypted || !state.archive_requires_encryption();
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
    let archive_allowed = state
        .message_service()
        .archive_enabled(
            recipient.id,
            &canonical_from,
            mam_storage_eligible(root),
            encrypted,
            personal_retraction,
        )
        .await?;
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
        let delayed = add_delay_from(&annotated, chrono::Utc::now(), Some(state.local_domain()));
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
        let delayed = add_delay_from(&annotated, chrono::Utc::now(), Some(state.local_domain()));
        let limits = state.offline_delivery_limits();
        let delivery = DeliveryProjection {
            id: stable_id,
            recipient_id: recipient.id,
            local_actor_id: None,
            sender_jid: &canonical_from,
            stanza: &delayed,
            encrypted,
            max_messages: limits.max_messages,
            max_bytes: limits.max_bytes,
            ttl_days: limits.ttl_days,
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
            state
                .s2s_online_queue_telemetry()
                .accepted(live_delivery.is_some());
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
        delivered |= state
            .route_s2s_message_to_available_remote_resources(to, &annotated, live_delivery)
            .await;
    } else if !delivered {
        let remote = state
            .route_s2s_message_to_remote_primary(to, &annotated, live_delivery)
            .await;
        if remote.delivered {
            delivered = true;
            delivered_key = remote.accepted_full_jid;
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
                state.s2s_inbound_delivery_telemetry().post_accept_failed();
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
                        state.s2s_inbound_delivery_telemetry().post_accept_failed();
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
                    state
                        .s2s_online_queue_telemetry()
                        .accepted(live_delivery.is_some());
                    delivered_key = Some(key);
                    delivered = true;
                    break;
                }
            }
            if !delivered {
                let remote = state
                    .route_s2s_message_to_remote_primary(&recipient_by, &annotated, live_delivery)
                    .await;
                if remote.delivered {
                    delivered = true;
                    delivered_key = remote.accepted_full_jid;
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
                state,
                root,
                AcceptedInboundHistory {
                    telemetry: state.s2s_accepted_history_telemetry(),
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
                crate::services::message_carbons::send_received_carbons(
                    state,
                    &recipient_by,
                    Some(delivered_key),
                    &annotated,
                )
                .await;
            }
        }
        state.s2s_inbound_delivery_telemetry().routed();
        return Ok(None);
    }
    if durable_c2s_delivery.is_some() {
        if let Err(error) = state.dispatch_push_notification(recipient.id).await {
            state.s2s_inbound_delivery_telemetry().post_accept_failed();
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
        let delayed = add_delay_from(&archive, chrono::Utc::now(), Some(state.local_domain()));
        let offline_outcome = state
            .message_service()
            .store_offline(OfflineMessageAdmission {
                recipient_id: recipient.id,
                recipient_bare_jid: &recipient_by,
                sender_jid: from,
                stanza: &delayed,
                encrypted,
                mam_backed: archive_allowed,
                identity: None,
            })
            .await?;
        if offline_outcome == OfflineAdmissionOutcome::RecipientUnavailable {
            return Ok(None);
        }
        if offline_outcome == OfflineAdmissionOutcome::QuotaExceeded {
            if history_committed {
                if let Err(error) = state.dispatch_push_notification(recipient.id).await {
                    state.s2s_inbound_delivery_telemetry().post_accept_failed();
                    tracing::warn!(?error, %stable_id, recipient_id = %recipient.id, "MAM-backed inbound message was accepted but offline quota and push delivery both failed");
                }
                return Ok(None);
            }
            return Ok(inbound_message_error(root, "wait", "resource-constraint"));
        }
        if !history_committed {
            finalize_accepted_inbound_history(
                state,
                root,
                AcceptedInboundHistory {
                    telemetry: state.s2s_accepted_history_telemetry(),
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
        if let Err(error) = state.dispatch_push_notification(recipient.id).await {
            state.s2s_inbound_delivery_telemetry().post_accept_failed();
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
    telemetry: super::telemetry::AcceptedHistoryTelemetry<'a>,
    recipient_id: uuid::Uuid,
    canonical_from: &'a str,
    stable_id: uuid::Uuid,
    archive_allowed: bool,
    archive: &'a str,
    encrypted: bool,
    route: &'static str,
}

async fn finalize_accepted_inbound_history(
    state: &AppState,
    root: roxmltree::Node<'_, '_>,
    history: AcceptedInboundHistory<'_>,
) {
    let AcceptedInboundHistory {
        telemetry,
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
    let history_result = state.message_service().admit_history(&writes).await;
    if let Err(error) = history_result {
        telemetry.failed();
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
#[path = "inbound_tests.rs"]
mod tests;
