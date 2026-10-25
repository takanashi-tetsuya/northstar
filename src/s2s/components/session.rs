//! Drive authenticated component sessions, durable outbox delivery, hostname binding, routing and cleanup.

use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) async fn drive_component<S>(
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
    let initial_binding_deadline =
        tokio::time::sleep(state.component_runtime_policy().handshake_timeout);
    tokio::pin!(initial_binding_deadline);
    let mut initial_binding_complete = protocol != ComponentProtocol::Modern0225;
    let relay_grant = protocol.relay_grant();
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
                    relay_grant,
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

pub(super) async fn deliver_component_outbox<S: AsyncWrite + Unpin + Send>(
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
        .component_runtime_policy()
        .queue_capacity
        .min(COMPONENT_OUTBOX_DRAIN_LIMIT);
    for _ in 0..drain_limit {
        // Claim only when this socket is ready to start the row. A batch claim
        // would start every lease at once while writes remain serial.
        let items = state
            .s2s_outbox_dispatch_service()
            .claim_for_domains(COMPONENT_OUTBOX_CLAIM_BATCH, &domains)
            .await?;
        let Some(item) = items.into_iter().next() else {
            break;
        };
        let _delivery_timer = state.component_telemetry().outbox_delivery_timer();
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

        state.component_telemetry().outbox_written();
        let completion_budget =
            component_lease_renewal_period(state.s2s_outbox_dispatch_service().lease_seconds());
        let completed = tokio::time::timeout(
            completion_budget,
            state
                .s2s_outbox_dispatch_service()
                .complete(envelope.outbox_id, envelope.lock_token),
        )
        .await
        .context("component outbox completion timed out before the renewed lease boundary")??;
        if !completed {
            state.component_telemetry().outbox_lease_lost();
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
pub(super) enum ComponentOutboxWriteError {
    Socket(anyhow::Error),
    Lease(anyhow::Error),
}

pub(super) fn component_lease_renewal_period(lease_seconds: u64) -> Duration {
    Duration::from_secs((lease_seconds / 3).max(1))
}

pub(super) async fn write_component_outbox_with_lease<S: AsyncWrite + Unpin + Send>(
    io: &mut S,
    state: Arc<AppState>,
    outbox_id: Uuid,
    lock_token: Uuid,
    serialized: String,
    cancel: tokio_util::sync::CancellationToken,
) -> std::result::Result<(), ComponentOutboxWriteError> {
    let renewal_period =
        component_lease_renewal_period(state.s2s_outbox_dispatch_service().lease_seconds());
    let renewal_timeout = renewal_period.min(Duration::from_secs(5));
    let dispatch: crate::services::s2s_outbox_dispatch::S2sOutboxDispatchService<_> =
        state.s2s_outbox_dispatch_service().clone();
    let result = write_component_outbox_with_renewal(
        io,
        serialized,
        renewal_period,
        renewal_timeout,
        cancel,
        move || {
            let dispatch = dispatch.clone();
            async move { dispatch.renew(outbox_id, lock_token).await }
        },
    )
    .await;
    match result {
        Err(ComponentOutboxWriteError::Lease(error)) => {
            state.component_telemetry().outbox_lease_lost();
            Err(ComponentOutboxWriteError::Lease(error.context(format!(
                "component outbox lease became unsafe while writing {}",
                outbox_id
            ))))
        }
        other => other,
    }
}

pub(super) async fn write_component_outbox_with_renewal<S, Renew, RenewalFuture>(
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

pub(super) async fn handle_hostname_binding(
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
    let hostname = match northstar_xmpp_types::jid::prepare_domainpart(hostname) {
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

pub(super) async fn route_component_stanza(
    state: Arc<AppState>,
    connection_id: Uuid,
    relay_grant: ComponentRelayGrant,
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
    let route_target = component_route_target(
        state.local_domain(),
        &target,
        state.xmpp_component_domain_configured(&target),
        relay_grant,
    );
    if route_target == ComponentRouteTarget::Denied {
        return Ok(component_stanza_error(root, "remote-server-not-found"));
    }
    if route_target == ComponentRouteTarget::LocalService {
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

    if route_target == ComponentRouteTarget::ConfiguredComponent {
        let error = component_stanza_error(root, "service-unavailable");
        let federation = state.federation_outbox().clone();
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
    let federation = state.federation_outbox().clone();
    let from = from.to_owned();
    drop(document);
    if federation.send(&target, raw, Some(from)).await {
        Ok(None)
    } else {
        Ok(timeout_error)
    }
}

pub(super) fn invalid_component_stanza(root: Node<'_, '_>) -> Option<&'static str> {
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

pub(super) async fn cleanup_component_muc(
    state: Arc<AppState>,
    domains: Vec<String>,
    connection_id: Uuid,
) {
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
