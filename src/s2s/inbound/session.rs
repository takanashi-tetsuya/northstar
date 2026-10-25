//! Run inbound listeners and connection actors with authenticated stream management and resumption.

use super::*;

pub(super) async fn wait_for_federation_shutdown(cancel: &tokio_util::sync::CancellationToken) {
    cancel.cancelled().await;
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
                let (tls_config, tls_generation) = s2s_server_config(state.tls_context(), true)?;
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
                    northstar_runtime::connection_actors::ConnectionActorKind::S2sInboundDirectTls,
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
                let (tls_config, tls_generation) = s2s_server_config(state.tls_context(), false)?;
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
                    northstar_runtime::connection_actors::ConnectionActorKind::S2sInboundStartTls,
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

pub(super) async fn inbound_xmpps_actor(
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

pub(super) async fn inbound_starttls_actor(
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

#[allow(clippy::too_many_arguments)]
pub(super) async fn drive_authenticated_inbound(
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
            crate::security::tls::CertificateSessionKind::InboundS2s,
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
    let scope = super::super::resume::Scope {
        local: local_domain.clone(),
        remote: domain,
        external: via_external,
        bidi: bidi_enabled,
    };
    let transport = super::super::resume::Transport {
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

pub(super) fn publish_inbound_route(
    state: &AppState,
    scope: &super::super::resume::Scope,
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

pub(super) fn initial_bidi_route_admissible(
    sm_enabled: bool,
    application_stanza_seen: bool,
    negotiation_deadline_elapsed: bool,
    suspended_owner_exists: bool,
) -> bool {
    sm_enabled
        || application_stanza_seen
        || (negotiation_deadline_elapsed && !suspended_owner_exists)
}

pub(super) async fn reject_resume(
    mut request: super::super::resume::Request,
    condition: &'static str,
    reason: &'static str,
) {
    // Keep this diagnostic independent of the resume ID, peer counter and
    // stanza contents: fixture logs are retained after a failed stress run.
    tracing::debug!(condition, reason, "rejected inbound S2S resumption");
    let _ = super::super::sm::failed(&mut request.transport.stream, condition).await;
    let _ = request.result.send(Err(Box::new(request.transport)));
}

pub(super) async fn accept_resume(
    state: &AppState,
    sm: &mut super::super::sm::StreamManagement,
    registration: &mut super::super::resume::Registration,
    scope: &super::super::resume::Scope,
    mut request: super::super::resume::Request,
) -> Result<Option<super::super::resume::Transport>> {
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
            .attr("xmlns", super::super::sm::NS)
            .attr("previd", &registration.id)
            .attr("h", sm.received().to_string())
            .finish(),
    )
    .await?;
    sm.replay(state, &mut request.transport.stream).await?;
    Ok(Some(request.transport))
}

pub(super) async fn drive_authenticated_inbound_inner(
    transport: super::super::resume::Transport,
    state: Arc<AppState>,
    scope: super::super::resume::Scope,
    connection_id: uuid::Uuid,
    sender: mpsc::Sender<FederationEnvelope>,
    mut outgoing: mpsc::Receiver<FederationEnvelope>,
) -> Result<()> {
    let route_key =
        bidi_connection_key(&scope.local, &scope.remote).expect("prepared stream domains");
    let mut transport = Some(transport);
    let mut sm = super::super::sm::StreamManagement::with_budget(
        state
            .s2s_connection_registry()
            .resumption
            .replay_bytes
            .clone(),
    );
    let (resume_sender, mut resumes) = mpsc::channel::<super::super::resume::Request>(1);
    let mut registration: Option<super::super::resume::Registration> = None;
    let mut used = false;
    let mut suspended_until = None;
    let mut resume_window = super::super::resume::WINDOW;
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
        let mut initial_negotiation_deadline = tokio::time::Instant::now() + super::super::IO_TIMEOUT;
        let peer_limits = current.limits;
        let mut incoming_idle_deadline = tokio::time::Instant::now() + S2S_AUTHENTICATED_IDLE_TIMEOUT;
        let keepalive_period = keepalive_interval_for_peer(peer_limits);
        let mut keepalive = tokio::time::interval_at(tokio::time::Instant::now() + keepalive_period, keepalive_period);
        keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // A successful handoff restarts this loop with a freshly authenticated transport.
        let mut restart = false;
        let active_result: Result<Option<super::super::resume::Request>> = async {
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
                    match super::super::sm::parse_control(&frame)? {
                        Some(super::super::sm::Control::Resume { id, h }) if !sm.is_enabled() && !used => {
                            let Some((epoch, owner)) = state.s2s_connection_registry().resumption.lookup(&id, &scope) else {
                                tracing::debug!(condition = "item-not-found", reason = "no-matching-resume-owner", "rejected inbound S2S resumption");
                                super::super::sm::failed(&mut current.stream, "item-not-found").await?;
                                continue;
                            };
                            state.s2s_connection_registry().remove_bidirectional_if_connection(&route_key, connection_id);
                            while let Ok(envelope) = outgoing.try_recv() {
                                fail_envelope(&state, &envelope, &anyhow::anyhow!("S2S route moved to resumed stream"), false).await;
                            }
                            let (reply, response) = tokio::sync::oneshot::channel();
                            let request = super::super::resume::Request { transport: transport.take().expect("active transport"), h, epoch, result: reply };
                            owner.try_send(request).map_err(|_| anyhow::anyhow!("S2S resume owner is busy or gone"))?;
                            match tokio::time::timeout(std::time::Duration::from_secs(15), response).await.context("S2S resume handoff timed out")?? {
                                Ok(()) => return Ok(None),
                                Err(returned) => { transport = Some(*returned); restart = true; return Ok(None); }
                            }
                        }
                        Some(super::super::sm::Control::Enable { resume, max }) if !sm.is_enabled() => {
                            sm.enable();
                            let mut enabled = XmlElement::new("enabled").attr("xmlns", super::super::sm::NS);
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
                if registration.is_none() || !super::super::util::transport_lost(&error)
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
    match super::super::outbound::serialize_for_peer(reply, peer_max_bytes) {
        Ok(reply) => Ok(Some(reply)),
        Err(error) if super::super::outbound::is_peer_stanza_limit_error(&error) => {
            let error_reply = Document::parse(request).ok().and_then(|document| {
                let root = document.root_element();
                (root.attribute("type") != Some("error")
                    && matches!(root.tag_name().name(), "iq" | "message" | "presence"))
                .then(|| s2s_stanza_error(root, "modify", "policy-violation"))
            });
            let Some(error_reply) = error_reply else {
                return Ok(None);
            };
            match super::super::outbound::serialize_for_peer(&error_reply, peer_max_bytes) {
                Ok(error_reply) => Ok(Some(error_reply)),
                Err(error) if super::super::outbound::is_peer_stanza_limit_error(&error) => {
                    Ok(None)
                }
                Err(error) => Err(error),
            }
        }
        Err(error) => Err(error),
    }
}
