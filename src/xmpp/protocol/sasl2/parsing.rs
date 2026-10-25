//! Validate and parse SASL payloads, inline requests, and stream openings, including stream capture and errors.

use super::*;

pub(super) fn attr_is(node: Node<'_, '_>, allowed: &[&str]) -> bool {
    node.attributes().all(|attr| {
        attr.namespace().is_none() && allowed.iter().any(|allowed| *allowed == attr.name())
    })
}

pub(super) fn structural_text_is_empty(node: Node<'_, '_>) -> bool {
    node.children()
        .filter(|child| child.is_text())
        .all(|child| child.text().unwrap_or_default().trim().is_empty())
}

pub(super) fn direct_text(node: Node<'_, '_>) -> String {
    node.children()
        .filter(|child| child.is_text())
        .filter_map(|child| child.text())
        .collect()
}

pub(in crate::xmpp::protocol) fn normalize_base64_payload(
    payload: Zeroizing<String>,
) -> std::result::Result<Zeroizing<String>, &'static str> {
    use base64::Engine;
    if payload.chars().any(char::is_whitespace) {
        return Err("incorrect-encoding");
    }
    // RFC 6120 uses a single '=' to distinguish an explicit zero-length SASL
    // response from the absence of an initial response.
    if payload.as_str() == "=" {
        return Ok(Zeroizing::new(String::new()));
    }
    base64::engine::general_purpose::STANDARD
        .decode(payload.as_bytes())
        .map_err(|_| "incorrect-encoding")?;
    Ok(payload)
}

pub(super) fn normalize_sasl2_base64_payload(
    payload: String,
) -> std::result::Result<String, &'static str> {
    use base64::Engine;
    if payload.chars().any(char::is_whitespace) {
        return Err("incorrect-encoding");
    }
    // Unlike RFC 6120 legacy SASL, XEP-0388 does not assign a special
    // zero-length meaning to a single '='. An empty SASL2 element already
    // represents a zero-length response, while '=' is invalid Base64.
    base64::engine::general_purpose::STANDARD
        .decode(&payload)
        .map_err(|_| "incorrect-encoding")?;
    Ok(payload)
}

pub(super) fn singleton_text(
    node: Node<'_, '_>,
    max: usize,
) -> std::result::Result<String, &'static str> {
    if node.children().any(|child| child.is_element()) || !attr_is(node, &[]) {
        return Err("malformed-request");
    }
    let text = direct_text(node);
    if text.len() > max || text.chars().any(char::is_control) {
        return Err("malformed-request");
    }
    Ok(text)
}

pub(super) fn parse_user_agent(
    node: Node<'_, '_>,
) -> std::result::Result<Option<Uuid>, &'static str> {
    if !attr_is(node, &["id"]) || !structural_text_is_empty(node) {
        return Err("malformed-request");
    }
    let id = match node.attribute("id") {
        Some(value) => Some(
            Uuid::parse_str(value)
                .ok()
                .filter(|id| id.get_version_num() == 4 && id.get_variant() == Variant::RFC4122)
                .ok_or("malformed-request")?,
        ),
        None => None,
    };
    let mut software = false;
    let mut device = false;
    for child in node.children().filter(|child| child.is_element()) {
        if child.tag_name().namespace() != Some(SASL2_NS) {
            return Err("malformed-request");
        }
        match child.tag_name().name() {
            // XEP-0388 defines software before device. Enforcing the schema
            // order closes ambiguous parser behaviour between implementations.
            "software" if !software && !device => {
                singleton_text(child, 256)?;
                software = true;
            }
            "device" if !device => {
                singleton_text(child, 256)?;
                device = true;
            }
            _ => return Err("malformed-request"),
        }
    }
    Ok(id)
}

pub(super) fn parse_bind(node: Node<'_, '_>) -> std::result::Result<Bind2Request, &'static str> {
    if !attr_is(node, &[]) || !structural_text_is_empty(node) {
        return Err("malformed-request");
    }
    let mut request = Bind2Request::default();
    let mut inline_feature_seen = false;
    for child in node.children().filter(|child| child.is_element()) {
        match (child.tag_name().name(), child.tag_name().namespace()) {
            ("tag", Some(BIND2_NS)) if request.tag.is_none() && !inline_feature_seen => {
                let tag = singleton_text(child, 512)?;
                if tag.is_empty() {
                    return Err("malformed-request");
                }
                request.tag = Some(tag);
            }
            ("enable", Some("urn:xmpp:carbons:2")) if !request.carbons => {
                inline_feature_seen = true;
                if !attr_is(child, &[])
                    || child.children().any(|node| node.is_element())
                    || !structural_text_is_empty(child)
                {
                    return Err("malformed-request");
                }
                request.carbons = true;
            }
            ("enable", Some("urn:xmpp:sm:3")) if request.sm.is_none() => {
                inline_feature_seen = true;
                if !attr_is(child, &["resume", "max"])
                    || child.children().any(|node| node.is_element())
                    || !structural_text_is_empty(child)
                {
                    return Err("malformed-request");
                }
                let resume = match child.attribute("resume") {
                    None | Some("false") | Some("0") => false,
                    Some("true") | Some("1") => true,
                    _ => return Err("malformed-request"),
                };
                let max = child
                    .attribute("max")
                    .map(|value| {
                        value
                            .parse::<u64>()
                            .ok()
                            .filter(|value| *value > 0)
                            .ok_or("malformed-request")
                    })
                    .transpose()?;
                request.sm = Some(SmInlineRequest { resume, max });
            }
            ("active", Some("urn:xmpp:csi:0")) if request.csi_active.is_none() => {
                inline_feature_seen = true;
                if !attr_is(child, &[])
                    || child.children().any(|node| node.is_element())
                    || !structural_text_is_empty(child)
                {
                    return Err("malformed-request");
                }
                request.csi_active = Some(true);
            }
            ("inactive", Some("urn:xmpp:csi:0")) if request.csi_active.is_none() => {
                inline_feature_seen = true;
                if !attr_is(child, &[])
                    || child.children().any(|node| node.is_element())
                    || !structural_text_is_empty(child)
                {
                    return Err("malformed-request");
                }
                request.csi_active = Some(false);
            }
            _ => return Err("malformed-request"),
        }
    }
    Ok(request)
}

pub(crate) fn parse_authenticate(
    root: Node<'_, '_>,
) -> std::result::Result<Sasl2Request, &'static str> {
    if root.tag_name().name() != "authenticate"
        || root.tag_name().namespace() != Some(SASL2_NS)
        || !attr_is(root, &["mechanism"])
        || !structural_text_is_empty(root)
    {
        return Err("malformed-request");
    }
    let mechanism = root
        .attribute("mechanism")
        .filter(|value| !value.is_empty() && value.len() <= 64)
        .ok_or("malformed-request")?
        .to_owned();
    let mut initial_response = None;
    let mut user_agent_id = None;
    let mut user_agent_seen = false;
    let mut bind = None;
    let mut request_token = None;
    let mut fast = None;
    let mut resume = None;
    // XEP-0388's schema is ordered: initial-response?, user-agent?, then
    // extension elements. Once an extension has appeared, base SASL2
    // children may not be smuggled after it.
    let mut extension_seen = false;
    for child in root.children().filter(|child| child.is_element()) {
        match (child.tag_name().name(), child.tag_name().namespace()) {
            ("initial-response", Some(SASL2_NS))
                if initial_response.is_none() && !user_agent_seen && !extension_seen =>
            {
                let payload = normalize_sasl2_base64_payload(singleton_text(child, 64 * 1024)?)?;
                initial_response = Some(Zeroizing::new(payload));
            }
            ("user-agent", Some(SASL2_NS)) if !user_agent_seen && !extension_seen => {
                user_agent_id = Some(parse_user_agent(child)?);
                user_agent_seen = true;
            }
            ("bind", Some(BIND2_NS)) if bind.is_none() => {
                extension_seen = true;
                bind = Some(parse_bind(child)?);
            }
            ("request-token", Some(FAST_NS)) if request_token.is_none() => {
                extension_seen = true;
                if !attr_is(child, &["mechanism"])
                    || child.children().any(|node| node.is_element())
                    || !structural_text_is_empty(child)
                {
                    return Err("malformed-request");
                }
                request_token = Some(
                    child
                        .attribute("mechanism")
                        .filter(|mechanism| auth::is_fast_mechanism(mechanism))
                        .ok_or("invalid-mechanism")?
                        .to_owned(),
                );
            }
            ("fast", Some(FAST_NS)) if fast.is_none() => {
                extension_seen = true;
                if !attr_is(child, &["count", "invalidate"])
                    || child.children().any(|node| node.is_element())
                    || !structural_text_is_empty(child)
                {
                    return Err("malformed-request");
                }
                let count = child
                    .attribute("count")
                    .map(|value| {
                        value
                            .parse::<i64>()
                            .ok()
                            .filter(|count| *count > 0)
                            .ok_or("malformed-request")
                    })
                    .transpose()?;
                let invalidate = match child.attribute("invalidate") {
                    None | Some("false") | Some("0") => false,
                    Some("true") | Some("1") => true,
                    _ => return Err("malformed-request"),
                };
                fast = Some(FastRequest { count, invalidate });
            }
            ("resume", Some("urn:xmpp:sm:3")) if resume.is_none() => {
                extension_seen = true;
                if !attr_is(child, &["previd", "h"])
                    || child.children().any(|node| node.is_element())
                    || !structural_text_is_empty(child)
                {
                    return Err("malformed-request");
                }
                let previd = child
                    .attribute("previd")
                    .filter(|value| {
                        use base64::Engine;
                        base64::engine::general_purpose::URL_SAFE_NO_PAD
                            .decode(value)
                            .is_ok_and(|decoded| decoded.len() == 32)
                    })
                    .ok_or("malformed-request")?
                    .to_owned();
                let h = child
                    .attribute("h")
                    .and_then(|value| value.parse::<u32>().ok())
                    .ok_or("malformed-request")?;
                resume = Some(SmResumeRequest {
                    previd: Zeroizing::new(previd),
                    h,
                });
            }
            _ => return Err("malformed-request"),
        }
    }
    Ok(Sasl2Request {
        mechanism,
        initial_response,
        user_agent_id: user_agent_id.flatten(),
        bind,
        request_token,
        fast,
        resume,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StreamOpenError {
    NotWellFormed,
    BadNamespacePrefix,
    InvalidNamespace,
    UnsupportedVersion,
    ImproperAddressing,
    HostUnknown,
    InvalidFrom,
    BadFormat,
}

impl StreamOpenError {
    pub(crate) fn condition(self) -> &'static str {
        match self {
            Self::NotWellFormed => "not-well-formed",
            Self::BadNamespacePrefix => "bad-namespace-prefix",
            Self::InvalidNamespace => "invalid-namespace",
            Self::UnsupportedVersion => "unsupported-version",
            Self::ImproperAddressing => "improper-addressing",
            Self::HostUnknown => "host-unknown",
            Self::InvalidFrom => "invalid-from",
            Self::BadFormat => "bad-format",
        }
    }
}

pub(super) fn supported_stream_version(version: &str) -> bool {
    let Some((major, minor)) = version.split_once('.') else {
        return false;
    };
    if major.is_empty()
        || minor.is_empty()
        || !major.bytes().all(|byte| byte.is_ascii_digit())
        || !minor.bytes().all(|byte| byte.is_ascii_digit())
    {
        return false;
    }
    major.trim_start_matches('0') == "1"
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ParsedStreamOpen {
    pub(super) from: Option<String>,
    pub(super) language: Option<String>,
}

pub(super) fn lexical_opening_qname(xml: &str) -> Option<&str> {
    let remainder = xml.strip_prefix('<')?;
    if remainder.starts_with('/') || remainder.starts_with('?') || remainder.starts_with('!') {
        return None;
    }
    let end = remainder
        .find(|character: char| character.is_ascii_whitespace() || matches!(character, '>' | '/'))
        .unwrap_or(remainder.len());
    (end != 0).then_some(&remainder[..end])
}

pub(crate) fn is_tcp_stream_opening(xml: &str) -> bool {
    lexical_opening_qname(xml)
        .is_some_and(|qname| qname.rsplit_once(':').map_or(qname, |(_, local)| local) == "stream")
}

pub(super) fn parse_stream_open(
    xml: &str,
    websocket: bool,
    expected_domain: &str,
) -> std::result::Result<ParsedStreamOpen, StreamOpenError> {
    let tcp_stream = is_tcp_stream_opening(xml);
    if tcp_stream == websocket {
        return Err(StreamOpenError::InvalidNamespace);
    }
    let complete;
    let input = if tcp_stream {
        if lexical_opening_qname(xml) != Some("stream:stream") {
            return Err(StreamOpenError::BadNamespacePrefix);
        }
        complete = complete_inbound_stream_opening_for_parser(xml);
        complete.as_str()
    } else {
        xml
    };
    let document = Document::parse(input).map_err(|_| StreamOpenError::NotWellFormed)?;
    let root = document.root_element();
    let valid_open = if tcp_stream {
        root.tag_name().name() == "stream"
            && root.tag_name().namespace() == Some("http://etherx.jabber.org/streams")
            && root.lookup_namespace_uri(None) == Some("jabber:client")
    } else {
        root.tag_name().name() == "open"
            && root.tag_name().namespace() == Some("urn:ietf:params:xml:ns:xmpp-framing")
    };
    if !valid_open {
        return Err(StreamOpenError::InvalidNamespace);
    }
    // An absent version is a pre-RFC-6120 (0.9) stream.  Northstar does not
    // implement the legacy protocol, so respond with a normal server opening
    // plus <unsupported-version/> instead of trying to negotiate SASL/TLS.
    let version = root.attribute("version").unwrap_or("0.9");
    if !supported_stream_version(version) {
        return Err(StreamOpenError::UnsupportedVersion);
    }
    if root
        .children()
        .any(|child| child.is_element() || child.text().is_some_and(|text| !text.trim().is_empty()))
        || root.attributes().any(|attribute| {
            let allowed = match attribute.namespace() {
                None => matches!(attribute.name(), "to" | "from" | "version"),
                Some("http://www.w3.org/XML/1998/namespace") => attribute.name() == "lang",
                // RFC 6120 extension attributes must be namespace-qualified.
                Some(_) => true,
            };
            !allowed
                || attribute.value().len() > 1_024
                || attribute.value().chars().any(char::is_control)
        })
        || root
            .attribute(("http://www.w3.org/XML/1998/namespace", "lang"))
            .is_some_and(|language| !valid_language_tag(language))
    {
        return Err(StreamOpenError::BadFormat);
    }
    let Some(to) = root.attribute("to") else {
        return Err(StreamOpenError::ImproperAddressing);
    };
    if northstar_xmpp_types::jid::prepare_domainpart(to)
        .ok()
        .as_deref()
        != Some(expected_domain)
    {
        return Err(StreamOpenError::HostUnknown);
    }
    let from = match root.attribute("from") {
        None => None,
        Some(value) => {
            let jid = northstar_xmpp_types::jid::CanonicalJid::parse_bare(value)
                .map_err(|_| StreamOpenError::InvalidFrom)?;
            if jid.domainpart() != expected_domain {
                return Err(StreamOpenError::InvalidFrom);
            }
            Some(
                jid.localpart()
                    .ok_or(StreamOpenError::InvalidFrom)?
                    .to_owned(),
            )
        }
    };
    Ok(ParsedStreamOpen {
        from,
        language: root
            .attribute(("http://www.w3.org/XML/1998/namespace", "lang"))
            .map(str::to_owned),
    })
}

impl ProtocolSession {
    pub(crate) fn capture_stream_from(
        &mut self,
        xml: &str,
    ) -> std::result::Result<(), StreamOpenError> {
        let parsed = parse_stream_open(
            xml,
            self.uses_websocket_framing(),
            self.state.local_domain(),
        )?;
        if let (Some(authenticated), Some(stream_from)) =
            (self.authenticated.as_ref(), parsed.from.as_deref())
        {
            if authenticated.username != stream_from {
                return Err(StreamOpenError::InvalidFrom);
            }
        }
        self.negotiation.open(parsed.from, parsed.language);
        Ok(())
    }
}
