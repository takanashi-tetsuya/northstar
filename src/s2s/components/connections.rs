//! Establish inbound and outbound component connections and negotiate legacy and modern authentication.

use super::*;

pub(super) async fn outbound_component_connection(
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
    let handshake_timeout = state.component_runtime_policy().handshake_timeout;
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
    let (sender, receiver) = mpsc::channel(state.component_runtime_policy().queue_capacity);
    state
        .component_registry()
        .register_domain(&domain, connection_id, sender.clone())?;
    tracing::info!(%domain, "outbound XEP-0114 component authenticated");
    let _active_connection = state.component_telemetry().active_connection();
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

pub(super) async fn connect_component_endpoint(
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
    let deadline = Instant::now() + state.component_runtime_policy().handshake_timeout;
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

pub(super) fn component_connect_address_allowed(address: IpAddr, allow_public: bool) -> bool {
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

pub(super) async fn component_connection(
    mut stream: TcpStream,
    peer: SocketAddr,
    state: Arc<AppState>,
    _permit: OwnedSemaphorePermit,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<()> {
    stream.set_nodelay(true)?;
    let handshake_timeout = state.component_runtime_policy().handshake_timeout;
    let mut input = s2s::S2sInputState::default();
    let opening = match read_handshake_frame(handshake_timeout, &mut stream, &mut input).await {
        Ok(opening) => opening,
        Err(error) => {
            if let Some(condition) = component_read_error_condition(&error) {
                write_legacy_stream_open(&mut stream, state.local_domain(), &stream_id()).await?;
                s2s::send_stream_error(&mut stream, condition).await?;
            }
            return Err(error);
        }
    };
    let namespace = match stream_namespace(&opening) {
        Ok(namespace) => namespace,
        Err(condition) => {
            write_legacy_stream_open(&mut stream, state.local_domain(), &stream_id()).await?;
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
    write_legacy_stream_open(&mut stream, state.local_domain(), &stream_id()).await?;
    s2s::send_stream_error(&mut stream, "invalid-namespace").await?;
    anyhow::bail!("component used an unsupported stream namespace from {peer}")
}

pub(super) async fn legacy_connection(
    mut stream: TcpStream,
    state: Arc<AppState>,
    opening: String,
    mut input: s2s::S2sInputState,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<()> {
    let handshake_timeout = state.component_runtime_policy().handshake_timeout;
    let component_domain =
        match component_stream_attribute(&opening, "to", COMPONENT_ACCEPT_NS, false)
            .and_then(|domain| crate::jid::prepare_domainpart(&domain).ok())
        {
            Some(domain) => domain,
            None => {
                write_legacy_stream_open(&mut stream, state.local_domain(), &stream_id()).await?;
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
    let (sender, receiver) = mpsc::channel(state.component_runtime_policy().queue_capacity);
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
    let _active_connection = state.component_telemetry().active_connection();
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

pub(super) async fn modern_connection(
    mut stream: TcpStream,
    state: Arc<AppState>,
    opening: String,
    mut input: s2s::S2sInputState,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<()> {
    let handshake_timeout = state.component_runtime_policy().handshake_timeout;
    if component_stream_attribute(&opening, "version", "jabber:client", false).as_deref()
        != Some("1.0")
    {
        write_component_stream_open(&mut stream, state.local_domain(), "", &stream_id()).await?;
        s2s::send_stream_error(&mut stream, "unsupported-version").await?;
        anyhow::bail!("XEP-0225 component did not open a version 1.0 stream");
    }
    let asserted_domain = match component_stream_attribute(&opening, "from", "jabber:client", true)
        .and_then(|domain| crate::jid::prepare_domainpart(&domain).ok())
    {
        Some(domain) => domain,
        None => {
            write_component_stream_open(&mut stream, state.local_domain(), "", &stream_id())
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
                state.local_domain(),
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
    if !same_component_domain(&target, state.local_domain()) || credential.is_none() {
        write_component_stream_open(
            &mut stream,
            state.local_domain(),
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
        state.local_domain(),
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
    let material = state.tls_context().c2s_snapshot(false);
    let acceptor = TlsAcceptor::from(material.server_config.clone());
    let mut secure = tokio::time::timeout(
        state.component_runtime_policy().handshake_timeout,
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
        state.local_domain(),
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
        state.local_domain(),
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
    let (sender, receiver) = mpsc::channel(state.component_runtime_policy().queue_capacity);
    tracing::info!(domain = %credential.primary_domain, "XEP-0225 component authenticated; hostname binding required");
    let _active_connection = state.component_telemetry().active_connection();
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
