//! Manage outbound connection lifecycle, initial delivery leases, multiplexing, cleanup and stream resumption.

use super::*;

pub(super) async fn run_outbound_connection(
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
        state.s2s_outbox_dispatch_service().clone(),
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

pub(super) async fn renew_first_envelope_lease(
    service: DispatchService,
    outbox_id: uuid::Uuid,
    lock_token: uuid::Uuid,
    lease_valid: Arc<AtomicBool>,
    cancel: tokio_util::sync::CancellationToken,
    disconnect: tokio_util::sync::CancellationToken,
) {
    let interval_seconds = (service.lease_seconds() / 3).max(1);
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
                let renewal = service.renew(outbox_id, lock_token);
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

pub(super) struct InitialDelivery<'a> {
    pub(super) envelope: &'a mut FederationEnvelope,
    pub(super) delivered: &'a mut bool,
    pub(super) lease_valid: &'a AtomicBool,
    pub(super) lease_cancel: &'a tokio_util::sync::CancellationToken,
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn connect_and_multiplex(
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
    crate::xmpp::protocol::caps::federated_caps_connection_closed(state, connection_id).await;
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
pub(super) async fn connect_and_multiplex_inner(
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
    let AuthenticatedTransport {
        stream: mut secure,
        mut input,
        features,
        limits: mut peer_limits,
        external,
        bidi: bidi_enabled,
        certificate: mut certificate_session,
    } = authenticate_transport(state, source_domain, target_domain, &disconnect).await?;

    let mut sm = super::super::sm::StreamManagement::with_budget(
        state
            .s2s_connection_registry()
            .resumption
            .replay_bytes
            .clone(),
    );
    let mut resume = None;
    if super::super::sm::advertised(&features) {
        sm.enable();
        write_xml(
            &mut secure,
            &XmlElement::new("enable")
                .attr("xmlns", super::super::sm::NS)
                .attr("resume", "true")
                .attr("max", "60")
                .finish(),
        )
        .await?;
        tokio::time::timeout(IO_TIMEOUT, async {
            loop {
                let response = timed_read_frame(&mut secure, &mut input).await?;
                if super::super::sm::accepted(&response) {
                    resume = super::super::sm::enabled_resume(&response)?;
                    return Ok::<_, anyhow::Error>(());
                }
                // A BIDI route can emit stanzas before it reads our enable.
                // Incoming counting starts at enabled; our outgoing count
                // has already started at enable, including any reply here.
                anyhow::ensure!(
                    bidi_enabled && super::super::sm::is_stanza(&response),
                    "remote rejected S2S stream management"
                );
                match route_inbound_for_connection(
                    state,
                    target_domain,
                    source_domain,
                    connection_id,
                    &response,
                )
                .await?
                {
                    InboundFederationRoute::Reply(Some(reply)) => {
                        if let Some(reply) = super::super::inbound::reply_within_peer_limit(
                            &reply,
                            &response,
                            peer_limits.max_bytes,
                        )? {
                            sm.track(None, &reply)?;
                            write_xml(&mut secure, &reply).await?;
                            sm.request(&mut secure).await?;
                        }
                    }
                    InboundFederationRoute::Reply(None) => {}
                    InboundFederationRoute::StreamError(condition) => {
                        send_stream_error(&mut secure, condition).await?;
                        anyhow::bail!("invalid S2S stanza during SM negotiation");
                    }
                }
            }
        })
        .await
        .context("S2S stream management negotiation timed out")??;
    }

    // Only this post-authentication state may accept an ephemeral stanza.
    // The worker clears the flag before removing its route entry.
    authenticated.store(true, Ordering::Release);

    let mut keepalive_period = keepalive_interval_for_peer(peer_limits);
    let mut keepalive_interval = tokio::time::interval_at(
        tokio::time::Instant::now() + keepalive_period,
        keepalive_period,
    );
    keepalive_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut incoming_idle_deadline = tokio::time::Instant::now() + S2S_AUTHENTICATED_IDLE_TIMEOUT;

    let result = async {
    let mut first = true;
    loop {
    let active_result: Result<()> = async {
    if first {
        if !initial.lease_valid.load(Ordering::Acquire) {
            anyhow::bail!("federation outbox lease was lost before first delivery");
        }
        let delivery = tokio::select! {
            biased;
            _ = disconnect.cancelled() => return Err(outbound_cancellation_error(state, " before first delivery")),
            result = deliver_managed_envelope(state, &mut secure, initial.envelope, peer_limits.max_bytes, &mut sm) => result,
        };
        if delivery.is_ok() || sm.owns(initial.envelope) {
            *initial.delivered = true;
            initial.lease_cancel.cancel();
            first = false;
        }
        delivery?;
        keepalive_interval.reset_after(keepalive_period);
    }

    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(sm.deadline()), if sm.is_enabled() => {
                anyhow::bail!("S2S acknowledgement timed out");
            }
            _ = disconnect.cancelled() => {
                let _ = send_stream_error(&mut secure, "not-authorized").await;
                return Err(outbound_cancellation_error(state, ""));
            }
            _ = keepalive_interval.tick() => {
                if let Err(e) = write_xml(&mut secure, " ").await {
                    return Err(e.context("S2S keepalive failed"));
                }
            }
            envelope = rx.recv() => {
                let Some(mut envelope) = envelope else { break };
                if let Err(error) = deliver_managed_envelope(state, &mut secure, &mut envelope, peer_limits.max_bytes, &mut sm).await {
                    let permanent = is_peer_stanza_limit_error(&error);
                    if !sm.owns(&envelope) { fail_envelope(state, &envelope, &error, permanent).await; }
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
                if sm.control(state, &mut secure, &frame, false).await? {
                    continue;
                }
                if !bidi_enabled {
                    send_stream_error(&mut secure, "unexpected-request").await?;
                    anyhow::bail!("remote sent a stanza on a unidirectional S2S connection");
                }
                let routed = route_inbound_for_connection(
                    state, target_domain, source_domain, connection_id, &frame,
                ).await?;
                sm.handled(&frame);
                match routed {
                    InboundFederationRoute::Reply(Some(reply)) => {
                        if let Some(reply) = super::super::inbound::reply_within_peer_limit(
                            &reply,
                            &frame,
                            peer_limits.max_bytes,
                        )? {
                            sm.track(None, &reply)?;
                            write_xml(&mut secure, &reply).await?;
                            sm.request(&mut secure).await?;
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

    // A deliberate XML close ends the logical stream even if the footer write fails.
    let _ = write_xml(&mut secure, &XmlElement::new("stream:stream").close()).await;
    let _ = secure.shutdown().await;
    Ok(())
    }.await;
    authenticated.store(false, Ordering::Release);
    let error = match active_result { Ok(()) => return Ok(()), Err(error) => error };
    let Some((id, window)) = &resume else { return Err(error); };
    if first || !super::super::util::transport_lost(&error) || disconnect.is_cancelled() { return Err(error); }
    sm.renew(state).await?;
    drop(secure);
    drop(certificate_session);
    let deadline = tokio::time::Instant::now() + *window;
    let reconnected = tokio::time::timeout_at(deadline, async {
        let mut backoff = Duration::from_millis(100);
        loop {
            let attempt = async {
                let mut next = authenticate_transport(state, source_domain, target_domain, &disconnect).await?;
                anyhow::ensure!(next.external == external && next.bidi == bidi_enabled && super::super::sm::advertised(&next.features),
                    "S2S resume authentication or stream features changed");
                write_xml(&mut next.stream, &XmlElement::new("resume").attr("xmlns", super::super::sm::NS)
                    .attr("previd", id).attr("h", sm.received().to_string()).finish()).await?;
                let response = timed_read_frame(&mut next.stream, &mut next.input).await?;
                let h = super::super::sm::resumed(&response, id)?;
                sm.validate_resume(h, next.limits.max_bytes)?;
                sm.renew(state).await?;
                sm.acknowledge(state, h).await?;
                sm.replay(state, &mut next.stream).await?;
                Ok::<_, anyhow::Error>(next)
            }.await;
            match attempt {
                Ok(next) => return Ok(next),
                Err(error) if super::super::util::transport_lost(&error) => {
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(2));
                }
                Err(error) => return Err(error),
            }
        }
    });
    let next = tokio::select! {
        biased;
        _ = disconnect.cancelled() => return Err(outbound_cancellation_error(state, " during resumption")),
        result = reconnected => result.context("S2S resume window expired")??,
    };
    secure = next.stream;
    input = next.input;
    peer_limits = next.limits;
    certificate_session = next.certificate;
    tracing::info!(peer_domain = target_domain, %connection_id, "resumed outbound S2S stream");
    authenticated.store(true, Ordering::Release);
    incoming_idle_deadline = tokio::time::Instant::now() + S2S_AUTHENTICATED_IDLE_TIMEOUT;
    keepalive_period = keepalive_interval_for_peer(peer_limits);
    keepalive_interval = tokio::time::interval_at(tokio::time::Instant::now() + keepalive_period, keepalive_period);
    keepalive_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    }
    }.await;
    authenticated.store(false, Ordering::Release);
    sm.retry_unacknowledged(state).await;
    result
}
