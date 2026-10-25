//! Establish inbound secure connections and validate stream identities and peer authentication.

use super::*;

pub(super) fn hosted_s2s_domain(local_domain: &str, target: &str) -> bool {
    northstar_federation_core::classify_hosted_domain(local_domain, target)
        .is_some_and(northstar_federation_core::HostedDomain::accepts_s2s_stream_target)
}

pub(super) fn locally_hosted_identity_domain(configured_domain: &str, candidate: &str) -> bool {
    northstar_federation_core::classify_hosted_domain(configured_domain, candidate).is_some()
}

pub(super) fn authenticated_s2s_sender(asserted: &str, authenticated_domain: &str) -> bool {
    let (Ok(asserted), Ok(authenticated_domain)) = (
        CanonicalJid::parse(asserted),
        prepare_domainpart(authenticated_domain),
    ) else {
        return false;
    };
    asserted.domainpart() == authenticated_domain
}

pub(super) fn same_s2s_domain(left: &str, right: &str) -> bool {
    matches!(
        (prepare_domainpart(left), prepare_domainpart(right)),
        (Ok(left), Ok(right)) if left == right
    )
}

pub(super) fn valid_starttls_request(raw: &str) -> bool {
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

pub(super) fn element_then_stream_close(element: XmlElement) -> String {
    let mut xml = element.finish();
    xml.push_str(&XmlElement::new("stream:stream").close());
    xml
}

pub(super) fn sasl_failure_then_stream_close(condition: &'static str) -> String {
    element_then_stream_close(
        XmlElement::namespaced("failure", "urn:ietf:params:xml:ns:xmpp-sasl")
            .child(XmlElement::new(condition)),
    )
}

pub(super) fn is_certificate_downgrade(
    element_name: &str,
    certificate_requires_external: bool,
) -> bool {
    certificate_requires_external && element_name == "result"
}

pub(super) fn restore_inherited_dialback_namespace(raw: &str) -> Cow<'_, str> {
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

pub(super) fn pre_tls_features(state: &AppState) -> String {
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

pub(super) async fn read_s2s_opening<S: AsyncRead + AsyncWrite + Unpin + Send>(
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

pub(super) async fn read_s2s_negotiation_frame<S: AsyncRead + AsyncWrite + Unpin + Send>(
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
    if !northstar_security::tls::direct_tls_sni_matches(direct_tls_sni.as_deref(), &target) {
        send_initial_stream_error(
            &mut secure,
            state.local_domain(),
            Some(&asserted_domain),
            "host-unknown",
        )
        .await?;
        anyhow::bail!("inbound S2S Direct TLS SNI does not match the stream target domain");
    }
    if !hosted_s2s_domain(state.local_domain(), &target)
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
    if !hosted_s2s_domain(state.local_domain(), &target)
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
        || !hosted_s2s_domain(state.local_domain(), &target)
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

pub(super) struct InboundAuthentication {
    pub(super) domain: String,
    pub(super) bidi_enabled: bool,
    pub(super) peer_limits: AdvertisedStreamLimits,
    pub(super) via_external: bool,
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn authenticate_secure_inbound(
    secure: &mut tokio_rustls::server::TlsStream<TcpStream>,
    state: Arc<AppState>,
    asserted_domain: String,
    target: String,
    receiving_stream_id: String,
    peer_certificates: Vec<tokio_rustls::rustls::pki_types::CertificateDer<'static>>,
    input: &mut S2sInputState,
) -> Result<Option<InboundAuthentication>> {
    let certificate_identity = if state.s2s_sasl_external_enabled() {
        match verify_peer_domain(state.tls_context(), &peer_certificates, &asserted_domain) {
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
    write_xml(
        secure,
        &features(state.s2s_feature_policy(), certificate_identity.is_some()),
    )
    .await?;
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
            .validated_fragment(&super::super::sm::feature())?
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

pub(super) async fn verify_remote_owned(
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

pub(super) fn valid_external_auth_shape(element: roxmltree::Node<'_, '_>) -> bool {
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
pub(super) struct BidiRequest {
    pub(super) peer_limits: AdvertisedStreamLimits,
}

pub(super) fn parse_bidi_request(raw: &str) -> Option<BidiRequest> {
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
