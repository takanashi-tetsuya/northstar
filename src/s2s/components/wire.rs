//! Verify credentials and provide component wire parsing, validation, namespace conversion and XML rendering helpers.

use super::*;

pub(super) fn verify_legacy_handshake(
    credential: &ComponentCredential,
    stream_id: &str,
    raw: &str,
) -> Result<bool> {
    let document = Document::parse(raw).context("invalid XEP-0114 handshake")?;
    let root = document.root_element();
    if root.tag_name().name() != "handshake"
        || !matches!(
            root.tag_name().namespace(),
            None | Some(COMPONENT_ACCEPT_NS)
        )
        || root.attributes().len() != 0
        || root.children().any(|node| node.is_element())
    {
        return Ok(false);
    }
    let supplied = decode_hex_20(root.text().unwrap_or_default().trim());
    let Some(supplied) = supplied else {
        return Ok(false);
    };
    let secret = verified_secret(credential)?;
    let mut digest = Sha1::new();
    digest.update(stream_id.as_bytes());
    digest.update(secret.as_bytes());
    let expected: [u8; 20] = digest.finalize().into();
    Ok(bool::from(expected.ct_eq(&supplied)))
}

pub(super) fn verify_modern_plain(credential: &ComponentCredential, raw: &str) -> Result<bool> {
    if !modern_plain_shape_is_valid(raw) {
        return Ok(false);
    }
    let document = Document::parse(raw).context("invalid component SASL stanza")?;
    let root = document.root_element();
    let encoded = root.text().unwrap_or_default();
    if encoded.len() > 8192 {
        return Ok(false);
    }
    let mut decoded = match STANDARD.decode(encoded.trim()) {
        Ok(decoded) => decoded,
        Err(_) => return Ok(false),
    };
    let fields = decoded.split(|byte| *byte == 0).collect::<Vec<_>>();
    if fields.len() != 3 {
        decoded.zeroize();
        return Ok(false);
    }
    let authzid = std::str::from_utf8(fields[0]).unwrap_or_default();
    let authcid = std::str::from_utf8(fields[1]).unwrap_or_default();
    let identity_matches = same_component_domain(authcid, &credential.primary_domain)
        && (authzid.is_empty() || same_component_domain(authzid, &credential.primary_domain));
    let candidate: [u8; 32] = Sha256::digest(fields[2]).into();
    let password_matches = bool::from(candidate.ct_eq(&credential.secret_sha256));
    decoded.zeroize();
    Ok(identity_matches & password_matches)
}

pub(super) fn modern_plain_shape_is_valid(raw: &str) -> bool {
    Document::parse(raw).is_ok_and(|document| {
        let root = document.root_element();
        root.tag_name().name() == "auth"
            && root.tag_name().namespace() == Some(SASL_NS)
            && root.attribute("mechanism") == Some("PLAIN")
            && root.attributes().len() == 1
            && !root.children().any(|child| child.is_element())
    })
}

pub(super) fn component_frame_stream_error(raw: &str) -> Option<&'static str> {
    let Ok(document) = Document::parse(raw) else {
        return Some("not-well-formed");
    };
    if matches!(
        document.root_element().tag_name().name(),
        "message" | "presence" | "iq"
    ) {
        None
    } else {
        Some("unsupported-stanza-type")
    }
}

pub(super) fn is_component_stream_error(raw: &str) -> bool {
    Document::parse(raw).is_ok_and(|document| {
        let root = document.root_element();
        root.tag_name().name() == "error" && root.tag_name().namespace() == Some(STREAMS_NS)
    })
}

pub(super) fn verified_secret(credential: &ComponentCredential) -> Result<&str> {
    let secret = credential
        .secret_value
        .as_ref()
        .context("component credential secret was not loaded during startup")?;
    let digest: [u8; 32] = Sha256::digest(secret.as_bytes()).into();
    if !bool::from(digest.ct_eq(&credential.secret_sha256)) {
        anyhow::bail!("in-memory component secret fingerprint mismatch");
    }
    Ok(secret.as_str())
}

pub(super) fn validate_modern_opening(
    state: &AppState,
    credential: &ComponentCredential,
    opening: &str,
) -> std::result::Result<(), &'static str> {
    match stream_namespace(opening) {
        Ok(namespace) if namespace == "jabber:client" => {}
        Ok(_) => return Err("invalid-namespace"),
        Err(condition) => return Err(condition),
    }
    if component_stream_attribute(opening, "version", "jabber:client", false).as_deref()
        != Some("1.0")
    {
        return Err("unsupported-version");
    }
    if component_stream_attribute(opening, "from", "jabber:client", true)
        .is_none_or(|domain| !same_component_domain(&domain, &credential.primary_domain))
    {
        return Err("invalid-from");
    }
    if component_stream_attribute(opening, "to", "jabber:client", true)
        .is_none_or(|domain| !same_component_domain(&domain, state.local_domain()))
    {
        return Err("host-unknown");
    }
    Ok(())
}

pub(super) async fn read_handshake_frame<S: AsyncRead + Unpin + Send>(
    timeout: Duration,
    stream: &mut S,
    input: &mut s2s::S2sInputState,
) -> Result<String> {
    tokio::time::timeout(timeout, s2s::read_entity_frame(stream, input))
        .await
        .context("component handshake timed out")?
}

pub(super) async fn read_handshake_frame_after_open<S: AsyncRead + AsyncWrite + Unpin + Send>(
    timeout: Duration,
    stream: &mut S,
    input: &mut s2s::S2sInputState,
) -> Result<String> {
    match read_handshake_frame(timeout, stream, input).await {
        Ok(frame) => Ok(frame),
        Err(error) => {
            if let Some(condition) = component_read_error_condition(&error) {
                let _ = s2s::send_stream_error(stream, condition).await;
            }
            Err(error)
        }
    }
}

pub(super) fn component_read_error_condition(error: &anyhow::Error) -> Option<&'static str> {
    if error
        .downcast_ref::<tokio::time::error::Elapsed>()
        .is_some()
    {
        Some("connection-timeout")
    } else {
        s2s::s2s_read_stream_error_condition(error)
    }
}

pub(super) fn stream_namespace(opening: &str) -> std::result::Result<String, &'static str> {
    let complete = format!("{opening}{}", XmlElement::new("stream:stream").close());
    let document = Document::parse(&complete).map_err(|_| "not-well-formed")?;
    let root = document.root_element();
    if root.tag_name().name() != "stream" || root.tag_name().namespace() != Some(STREAMS_NS) {
        return Err("invalid-namespace");
    }
    if root.children().any(|child| child.is_element()) {
        return Err("not-well-formed");
    }
    root.lookup_namespace_uri(None)
        .map(str::to_owned)
        .ok_or("invalid-namespace")
}

/// Parse an external-component stream opening without weakening the stricter
/// `jabber:server` parser used by S2S. XEP-0114 uses
/// `jabber:component:accept` and predates versioned streams, while the
/// Deferred XEP-0225 profile uses a version 1.0 `jabber:client` stream.
pub(super) fn component_stream_attribute(
    xml: &str,
    name: &str,
    default_namespace: &str,
    require_version_1: bool,
) -> Option<String> {
    if !matches!(name, "from" | "to" | "id" | "version") {
        return None;
    }
    let complete = format!("{xml}{}", XmlElement::new("stream:stream").close());
    let document = Document::parse(&complete).ok()?;
    let root = document.root_element();
    if root.tag_name().name() != "stream"
        || root.tag_name().namespace() != Some(STREAMS_NS)
        || root.lookup_namespace_uri(None) != Some(default_namespace)
        || (require_version_1 && root.attribute("version") != Some("1.0"))
        || root.children().any(|child| child.is_element())
    {
        return None;
    }
    let value = root.attribute(name)?;
    if value.is_empty() || value.len() > 1_024 || value.chars().any(char::is_control) {
        return None;
    }
    Some(value.to_owned())
}

pub(super) fn validate_legacy_connect_opening(opening: &str, component: &str) -> Result<String> {
    let complete = format!("{opening}{}", XmlElement::new("stream:stream").close());
    let document = Document::parse(&complete)
        .context("outbound XEP-0114 component returned malformed stream XML")?;
    let root = document.root_element();
    anyhow::ensure!(
        root.tag_name().name() == "stream"
            && root.tag_name().namespace() == Some(STREAMS_NS)
            && root.lookup_namespace_uri(None) == Some(COMPONENT_CONNECT_NS)
            && !root.children().any(|child| child.is_element()),
        "outbound XEP-0114 component returned an invalid stream namespace"
    );
    let to = root
        .attribute("to")
        .context("outbound XEP-0114 component stream omitted to")?;
    anyhow::ensure!(
        same_component_domain(to, component),
        "outbound XEP-0114 component stream addressed a different domain"
    );
    if let Some(from) = root.attribute("from") {
        anyhow::ensure!(
            same_component_domain(from, component),
            "outbound XEP-0114 component asserted a different domain"
        );
    }
    let id = root
        .attribute("id")
        .filter(|id| !id.is_empty() && id.len() <= 1_024 && !id.chars().any(char::is_control))
        .context("outbound XEP-0114 component stream omitted a valid id")?;
    Ok(id.to_owned())
}

pub(super) fn is_element(raw: &str, name: &str, namespace: &str) -> bool {
    Document::parse(raw).is_ok_and(|document| {
        let root = document.root_element();
        root.tag_name().name() == name && root.tag_name().namespace() == Some(namespace)
    })
}

pub(super) fn is_empty_element(raw: &str, name: &str, namespace: &str) -> bool {
    Document::parse(raw).is_ok_and(|document| {
        let root = document.root_element();
        root.tag_name().name() == name
            && root.tag_name().namespace() == Some(namespace)
            && root.attributes().len() == 0
            && !root.children().any(|child| {
                child.is_element() || child.text().is_some_and(|text| !text.trim().is_empty())
            })
    })
}

pub(super) fn is_inherited_empty_element(raw: &str, name: &str, stream_namespace: &str) -> bool {
    Document::parse(raw).is_ok_and(|document| {
        let root = document.root_element();
        root.tag_name().name() == name
            && root
                .tag_name()
                .namespace()
                .is_none_or(|namespace| namespace == stream_namespace)
            && root.attributes().len() == 0
            && !root.children().any(|child| {
                child.is_element() || child.text().is_some_and(|text| !text.trim().is_empty())
            })
    })
}

pub(super) fn component_to_client(raw: &str, protocol: ComponentProtocol) -> String {
    match protocol {
        ComponentProtocol::Legacy0114Accept => {
            s2s::stanza_namespace(raw, COMPONENT_ACCEPT_NS, "jabber:client")
        }
        ComponentProtocol::Legacy0114Connect => {
            s2s::stanza_namespace(raw, COMPONENT_CONNECT_NS, "jabber:client")
        }
        ComponentProtocol::Modern0225 => {
            s2s::stanza_namespace(raw, "jabber:client", "jabber:client")
        }
    }
}

pub(super) fn client_to_component(raw: &str, protocol: ComponentProtocol) -> String {
    match protocol {
        ComponentProtocol::Legacy0114Accept => {
            s2s::stanza_namespace(raw, "jabber:client", COMPONENT_ACCEPT_NS)
        }
        ComponentProtocol::Legacy0114Connect => {
            s2s::stanza_namespace(raw, "jabber:client", COMPONENT_CONNECT_NS)
        }
        ComponentProtocol::Modern0225 => {
            s2s::stanza_namespace(raw, "jabber:client", "jabber:client")
        }
    }
}

pub(super) fn component_iq_error(id: &str, condition: &str) -> String {
    let (error_type, condition) = match condition {
        "bad-request" => ("modify", "bad-request"),
        "internal-server-error" => ("wait", "internal-server-error"),
        "resource-constraint" => ("wait", "resource-constraint"),
        "conflict" => ("cancel", "conflict"),
        "not-allowed" => ("cancel", "not-allowed"),
        _ => ("cancel", "service-unavailable"),
    };
    crate::xmpp::xml_builder::XmlElement::new("iq")
        .attr("xmlns", "jabber:client")
        .attr("type", "error")
        .attr("id", id)
        .child(
            crate::xmpp::xml_builder::XmlElement::new("error")
                .attr("type", error_type)
                .child(
                    crate::xmpp::xml_builder::XmlElement::new(condition)
                        .attr("xmlns", "urn:ietf:params:xml:ns:xmpp-stanzas"),
                ),
        )
        .finish()
}

pub(super) fn component_stanza_error(root: Node<'_, '_>, condition: &str) -> Option<String> {
    if root.attribute("type") == Some("error") {
        return None;
    }
    let (error_type, condition) = match condition {
        "bad-request" => ("modify", "bad-request"),
        "jid-malformed" => ("modify", "jid-malformed"),
        "not-authorized" => ("auth", "not-authorized"),
        "remote-server-not-found" => ("cancel", "remote-server-not-found"),
        "remote-server-timeout" => ("wait", "remote-server-timeout"),
        "resource-constraint" => ("wait", "resource-constraint"),
        "service-unavailable" => ("cancel", "service-unavailable"),
        _ => ("cancel", "undefined-condition"),
    };
    Some(crate::services::xml_util::reflected_stanza_error(
        root,
        &crate::xmpp::xml_builder::XmlElement::new("error")
            .attr(
                "xmlns",
                root.tag_name().namespace().unwrap_or("jabber:client"),
            )
            .attr("type", error_type)
            .child(
                crate::xmpp::xml_builder::XmlElement::new(condition)
                    .attr("xmlns", "urn:ietf:params:xml:ns:xmpp-stanzas"),
            )
            .finish(),
    ))
}

pub(super) async fn write_legacy_stream_open<S: AsyncWrite + Unpin + Send>(
    stream: &mut S,
    component: &str,
    id: &str,
) -> Result<()> {
    s2s::write_xml(
        stream,
        &crate::xmpp::xml_builder::XmlElement::new("stream:stream")
            .attr("xmlns", COMPONENT_ACCEPT_NS)
            .attr("xmlns:stream", STREAMS_NS)
            .attr("from", component)
            .attr("id", id)
            .open(),
    )
    .await
}

pub(super) async fn write_legacy_connect_open<S: AsyncWrite + Unpin + Send>(
    stream: &mut S,
    component: &str,
) -> Result<()> {
    // XEP-0114 footnote 4 assigns the component name to `from` when the server
    // initiates jabber:component:connect. The receiver returns that identity in
    // `to`; an optional response `from` is accepted only when it is identical.
    s2s::write_xml(
        stream,
        &crate::xmpp::xml_builder::XmlElement::new("stream:stream")
            .attr("xmlns", COMPONENT_CONNECT_NS)
            .attr("xmlns:stream", STREAMS_NS)
            .attr("from", component)
            .open(),
    )
    .await
}

pub(super) async fn write_component_stream_open<S: AsyncWrite + Unpin + Send>(
    stream: &mut S,
    from: &str,
    to: &str,
    id: &str,
) -> Result<()> {
    s2s::write_xml(
        stream,
        &crate::xmpp::xml_builder::XmlElement::new("stream:stream")
            .attr("xmlns", "jabber:client")
            .attr("xmlns:stream", STREAMS_NS)
            .attr("from", from)
            .optional_attr("to", (!to.is_empty()).then_some(to))
            .attr("id", id)
            .attr("version", "1.0")
            .open(),
    )
    .await
}

pub(super) fn stream_id() -> String {
    Uuid::new_v4().simple().to_string()
}

pub(super) fn decode_hex_20(value: &str) -> Option<[u8; 20]> {
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let mut decoded = [0_u8; 20];
    for (index, slot) in decoded.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(decoded)
}
