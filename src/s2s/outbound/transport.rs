//! Select secure endpoints and negotiate TLS, stream identity, SASL EXTERNAL, dialback and bidirectional transport.

use super::*;

pub(super) fn happy_eyeballs_delay(candidate_index: usize) -> Duration {
    HAPPY_EYEBALLS_DELAY.saturating_mul(candidate_index.min(u32::MAX as usize) as u32)
}

pub(super) struct AuthenticatedTransport {
    pub(super) stream: tokio_rustls::client::TlsStream<TcpStream>,
    pub(super) input: S2sInputState,
    pub(super) features: String,
    pub(super) limits: AdvertisedStreamLimits,
    pub(super) external: bool,
    pub(super) bidi: bool,
    pub(super) certificate: Option<crate::security::tls::CertificateSessionGuard>,
}

pub(super) async fn authenticate_transport(
    state: &Arc<AppState>,
    source_domain: &str,
    target_domain: &str,
    disconnect: &tokio_util::sync::CancellationToken,
) -> Result<AuthenticatedTransport> {
    anyhow::ensure!(
        !state.island_mode_enabled() && state.federation_domain_allowed(target_domain),
        "target domain is denied by federation policy"
    );
    let (mut secure, mut opening, mut features, mut input, peer_certificates, tls_generation) =
        connect_secure_stream_from(state, source_domain, target_domain).await?;
    let mut peer_limits = advertised_stream_limits(&features).unwrap_or_default();
    let external = state.s2s_sasl_external_enabled() && sasl_external_advertised(&features);
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

    let certificate_session = if external {
        Some(state.tls_context().register_certificate_session(
            uuid::Uuid::new_v4(),
            crate::security::tls::CertificateSessionKind::OutboundS2s,
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

    Ok(AuthenticatedTransport {
        stream: secure,
        input,
        features,
        limits: peer_limits,
        external,
        bidi: bidi_enabled,
        certificate: certificate_session,
    })
}

pub(super) async fn connect_secure_endpoint_group(
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

pub(super) async fn race_happy_eyeballs<T, Attempt, AttemptFuture>(
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

pub(super) fn happy_eyeballs_endpoint_order(
    endpoints: &[FederationEndpoint],
) -> Vec<FederationEndpoint> {
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

pub(super) async fn connect_secure_endpoint(
    state: &AppState,
    source_domain: &str,
    target_domain: &str,
    endpoint: &FederationEndpoint,
) -> Result<SecureS2sConnection> {
    let dane_mode = state.s2s_dane_mode();
    let dane_policy = if dane_mode == crate::s2s::dane::DaneMode::Off {
        None
    } else {
        let resolver = state
            .s2s_dnssec_resolver()
            .context("DANE is enabled but the validating DNSSEC resolver is unavailable")?;
        crate::s2s::dane::lookup_dane_policy(
            resolver,
            dane_mode,
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

pub(super) fn validate_stream_identity(
    source_domain: &str,
    target_domain: &str,
    opening: &str,
) -> Result<()> {
    if stream_attribute(opening, "from")
        .is_none_or(|domain| !same_s2s_domain(&domain, target_domain))
        || stream_attribute(opening, "to")
            .is_none_or(|domain| !same_s2s_domain(&domain, source_domain))
    {
        anyhow::bail!("remote S2S stream returned an invalid identity");
    }
    Ok(())
}

pub(super) fn parseable_stream_features(feature_xml: &str) -> std::borrow::Cow<'_, str> {
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

pub(super) fn stream_feature_advertised(feature_xml: &str, name: &str, namespace: &str) -> bool {
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

pub(super) fn sasl_external_advertised(feature_xml: &str) -> bool {
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

pub(super) fn valid_empty_negotiation_element(raw: &str, name: &str, namespace: &str) -> bool {
    Document::parse(raw).is_ok_and(|document| {
        let root = document.root_element();
        root.tag_name().name() == name
            && root.tag_name().namespace() == Some(namespace)
            && root.attributes().len() == 0
            && !root.children().any(|child| child.is_element())
            && root.text().is_none_or(|text| text.trim().is_empty())
    })
}

pub(super) async fn authenticate_dialback_outbound(
    state: &AppState,
    source_domain: &str,
    target_domain: &str,
    secure: &mut tokio_rustls::client::TlsStream<TcpStream>,
    opening: &str,
    features: &str,
    input: &mut S2sInputState,
) -> Result<()> {
    if !state.s2s_dialback_enabled() || !advertised(features) {
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

pub(super) async fn request_bidi_if_advertised<S: AsyncWrite + Unpin>(
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
