use crate::auth;
use crate::xmpp::xml_builder::XmlElement;
use crate::xmpp::xml_util::valid_language_tag;
use anyhow::{Context, Result};
use roxmltree::{Document, Node};
use uuid::{Uuid, Variant};
use zeroize::Zeroizing;

use super::{Action, ProtocolSession};

pub(crate) const SASL2_NS: &str = "urn:xmpp:sasl:2";
pub(crate) const BIND2_NS: &str = "urn:xmpp:bind:0";
pub(crate) const FAST_NS: &str = "urn:xmpp:fast:0";

#[derive(Clone, Debug, Default)]
pub(crate) struct Bind2Request {
    pub tag: Option<String>,
    pub carbons: bool,
    pub sm: Option<SmInlineRequest>,
    pub csi_active: Option<bool>,
}

#[derive(Clone, Debug)]
pub(crate) struct SmInlineRequest {
    pub resume: bool,
    pub max: Option<u64>,
}

#[derive(Clone, Debug)]
pub(crate) struct FastRequest {
    /// XEP-0484 requires a monotonically increasing count only for TLS 0-RTT.
    /// Northstar does not advertise or accept early data, so ordinary FAST
    /// clients may omit it. A supplied value is still enforced atomically.
    pub count: Option<i64>,
    pub invalidate: bool,
}

pub(crate) struct SmResumeRequest {
    pub previd: Zeroizing<String>,
    pub h: u32,
}

pub(crate) struct Sasl2Request {
    pub mechanism: String,
    pub initial_response: Option<Zeroizing<String>>,
    pub user_agent_id: Option<Uuid>,
    pub bind: Option<Bind2Request>,
    pub request_token: Option<String>,
    pub fast: Option<FastRequest>,
    pub resume: Option<SmResumeRequest>,
}

pub(crate) struct Sasl2Context {
    pub request: Sasl2Request,
    pub fast_should_rotate: bool,
    pub awaiting_initial_response: bool,
    pub fast_token_id: Option<Uuid>,
    pub fast_token_was_new: bool,
    pub fast_invalidate: bool,
    pub authenticated_generation: Option<i64>,
    pub inherited_fast_chain:
        Option<(chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>)>,
}

impl std::fmt::Debug for SmResumeRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SmResumeRequest")
            .field("previd", &"[REDACTED]")
            .field("h", &self.h)
            .finish()
    }
}

impl std::fmt::Debug for Sasl2Request {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Sasl2Request")
            .field("mechanism", &self.mechanism)
            .field(
                "initial_response",
                &self.initial_response.as_ref().map(|_| "[REDACTED]"),
            )
            .field("user_agent_id", &self.user_agent_id)
            .field("bind", &self.bind)
            .field("request_token", &self.request_token)
            .field("fast", &self.fast)
            .field("resume", &self.resume)
            .finish()
    }
}

impl std::fmt::Debug for Sasl2Context {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Sasl2Context")
            .field("request", &self.request)
            .field("fast_should_rotate", &self.fast_should_rotate)
            .field("awaiting_initial_response", &self.awaiting_initial_response)
            .field("fast_token_id", &self.fast_token_id.map(|_| "[REDACTED]"))
            .field("fast_token_was_new", &self.fast_token_was_new)
            .field("fast_invalidate", &self.fast_invalidate)
            .field("authenticated_generation", &self.authenticated_generation)
            .field("inherited_fast_chain", &self.inherited_fast_chain)
            .finish()
    }
}

fn attr_is(node: Node<'_, '_>, allowed: &[&str]) -> bool {
    node.attributes().all(|attr| {
        attr.namespace().is_none() && allowed.iter().any(|allowed| *allowed == attr.name())
    })
}

fn structural_text_is_empty(node: Node<'_, '_>) -> bool {
    node.children()
        .filter(|child| child.is_text())
        .all(|child| child.text().unwrap_or_default().trim().is_empty())
}

fn direct_text(node: Node<'_, '_>) -> String {
    node.children()
        .filter(|child| child.is_text())
        .filter_map(|child| child.text())
        .collect()
}

pub(super) fn normalize_base64_payload(
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

fn normalize_sasl2_base64_payload(payload: String) -> std::result::Result<String, &'static str> {
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

fn singleton_text(node: Node<'_, '_>, max: usize) -> std::result::Result<String, &'static str> {
    if node.children().any(|child| child.is_element()) || !attr_is(node, &[]) {
        return Err("malformed-request");
    }
    let text = direct_text(node);
    if text.len() > max || text.chars().any(char::is_control) {
        return Err("malformed-request");
    }
    Ok(text)
}

fn parse_user_agent(node: Node<'_, '_>) -> std::result::Result<Option<Uuid>, &'static str> {
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

fn parse_bind(node: Node<'_, '_>) -> std::result::Result<Bind2Request, &'static str> {
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

pub(crate) fn failure_xml(condition: &str, text: Option<&str>) -> String {
    let condition = XmlElement::dynamic(condition)
        .expect("SASL error condition must be a valid QName")
        .attr("xmlns", "urn:ietf:params:xml:ns:xmpp-sasl");
    let mut failure = XmlElement::namespaced("failure", SASL2_NS).child(condition);
    if let Some(text) = text {
        failure.push_child(XmlElement::new("text").text(text.to_owned()));
    }
    failure.finish()
}

fn fast_token_xml(issued: &crate::services::authentication::IssuedFastToken) -> String {
    XmlElement::namespaced("token", FAST_NS)
        .attr(
            "expiry",
            issued
                .expires_at
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        )
        .attr("token", issued.token.as_str())
        .finish()
}

pub(crate) fn authentication_feature_xml(session: &ProtocolSession) -> String {
    let mut mechanism_names = Vec::with_capacity(6);
    if !session.client_certificate_identities.is_empty() {
        mechanism_names.push("EXTERNAL");
    }
    if session.channel_bindings.is_some() {
        mechanism_names.push("SCRAM-SHA-256-PLUS");
    }
    mechanism_names.push("SCRAM-SHA-256");
    if session.state.config.scram_sha1_enabled {
        if session.channel_bindings.is_some() {
            mechanism_names.push("SCRAM-SHA-1-PLUS");
        }
        mechanism_names.push("SCRAM-SHA-1");
    }
    mechanism_names.push("PLAIN");

    let mut fast_mechanism_names = Vec::with_capacity(3);
    if session.state.config.fast_token_enabled {
        if let Some(bindings) = session.channel_bindings.as_ref() {
            if bindings.get("tls-server-end-point").is_some() {
                fast_mechanism_names.push("HT-SHA-256-ENDP");
            }
            if bindings.get("tls-exporter").is_some() {
                fast_mechanism_names.push("HT-SHA-256-EXPR");
            }
        }
        fast_mechanism_names.push("HT-SHA-256-NONE");
    }

    let mut authentication = XmlElement::namespaced("authentication", SASL2_NS);
    for mechanism in mechanism_names {
        authentication.push_child(XmlElement::new("mechanism").text(mechanism));
    }
    let mut inline = XmlElement::new("inline")
        .child(XmlElement::namespaced("sm", "urn:xmpp:sm:3"))
        .child(
            XmlElement::namespaced("bind", BIND2_NS).child(
                XmlElement::new("inline")
                    .child(XmlElement::new("feature").attr("var", "urn:xmpp:carbons:2"))
                    .child(XmlElement::new("feature").attr("var", "urn:xmpp:csi:0"))
                    .child(XmlElement::new("feature").attr("var", "urn:xmpp:sm:3")),
            ),
        );
    if session.state.config.fast_token_enabled {
        let mut fast = XmlElement::namespaced("fast", FAST_NS);
        for mechanism in fast_mechanism_names {
            fast.push_child(XmlElement::new("mechanism").text(mechanism));
        }
        inline.push_child(fast);
    }
    authentication.child(inline).finish()
}

fn sasl2_success_xml(
    additional_data: Option<&[u8]>,
    authorization_identifier: &str,
    extension_fragments: &[&str],
) -> Result<String> {
    use base64::Engine;

    let mut success = XmlElement::namespaced("success", SASL2_NS);
    if let Some(data) = additional_data.filter(|data| !data.is_empty()) {
        success.push_child(
            XmlElement::new("additional-data")
                .text(base64::engine::general_purpose::STANDARD.encode(data)),
        );
    }
    success.push_child(
        XmlElement::new("authorization-identifier").text(authorization_identifier.to_owned()),
    );
    for fragment in extension_fragments
        .iter()
        .copied()
        .filter(|fragment| !fragment.is_empty())
    {
        success.push_validated_fragment(fragment)?;
    }
    Ok(success.finish())
}

fn inline_resume_envelope_reservation_bytes(
    additional_data: Option<&[u8]>,
    authorization_identifier: &str,
    resumed_control: &str,
    token_xml: &str,
    features: &String,
) -> Option<usize> {
    // XML text escaping expands one UTF-8 byte by at most six bytes. Standard
    // Base64 is exactly four bytes per three-byte block. The fixed allowance
    // covers element names/namespaces and String growth; multiplying the
    // serialized upper bound by four also dominates allocator capacity
    // rounding before the actual capacity is verified by ResumePayload.
    let encoded = match additional_data.filter(|data| !data.is_empty()) {
        Some(data) => data.len().checked_add(2)?.checked_div(3)?.checked_mul(4)?,
        None => 0,
    };
    let serialized_upper = 4_096usize
        .checked_add(authorization_identifier.len().checked_mul(6)?)?
        .checked_add(encoded)?
        .checked_add(resumed_control.len())?
        .checked_add(token_xml.len())?;
    serialized_upper
        .checked_mul(4)?
        .checked_add(std::mem::size_of::<String>())?
        .checked_add(features.capacity())
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

fn supported_stream_version(version: &str) -> bool {
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
struct ParsedStreamOpen {
    from: Option<String>,
    language: Option<String>,
}

fn lexical_opening_qname(xml: &str) -> Option<&str> {
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

/// roxmltree requires a complete document. TCP XMPP supplies only the inbound
/// opening tag at this point, so synthesize a closing tag exclusively for the
/// local parser input. This string is never written to any transport.
fn complete_inbound_stream_opening_for_parser(xml: &str) -> String {
    let closing = "</stream:stream>";
    let mut parser_input = String::with_capacity(xml.len() + closing.len());
    parser_input.push_str(xml);
    parser_input.push_str(closing);
    parser_input
}

fn parse_stream_open(
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
    if crate::jid::prepare_domainpart(to).ok().as_deref() != Some(expected_domain) {
        return Err(StreamOpenError::HostUnknown);
    }
    let from = match root.attribute("from") {
        None => None,
        Some(value) => {
            let jid = crate::jid::CanonicalJid::parse_bare(value)
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
        let parsed = parse_stream_open(xml, self.websocket, &self.state.config.domain)?;
        if let (Some(authenticated), Some(stream_from)) =
            (self.authenticated.as_ref(), parsed.from.as_deref())
        {
            if authenticated.username != stream_from {
                return Err(StreamOpenError::InvalidFrom);
            }
        }
        self.stream_from = parsed.from;
        self.stream_language = parsed.language;
        self.stream_opened = true;
        Ok(())
    }

    pub(crate) async fn authenticate2(&mut self, root: Node<'_, '_>) -> Result<Action> {
        let metrics_state = self.state.clone();
        let _authentication_timer = metrics_state
            .metrics
            .authentication_duration_seconds
            .start_timer();
        if !self.secure_transport {
            return Ok(Action::Send(failure_xml("encryption-required", None)));
        }
        if self.authenticated.is_some() {
            return Ok(Action::Send(crate::xmpp::xml_util::stream_error(
                "not-authorized",
            )));
        }
        if self.sasl_state.is_some() || self.sasl2_state.is_some() {
            return Ok(Action::Send(failure_xml("malformed-request", None)));
        }
        self.sasl_scram_fence = None;
        let mut request = match parse_authenticate(root) {
            Ok(request) => request,
            Err(condition) => return Ok(Action::Send(failure_xml(condition, None))),
        };
        if request.request_token.is_some() && request.user_agent_id.is_none() {
            return Ok(Action::Send(failure_xml("malformed-request", None)));
        }
        if request
            .request_token
            .as_deref()
            .is_some_and(|mechanism| !self.fast_mechanism_available(mechanism))
        {
            return Ok(Action::Send(failure_xml("invalid-mechanism", None)));
        }
        if auth::is_fast_mechanism(&request.mechanism) {
            if !self.fast_mechanism_available(&request.mechanism) {
                return Ok(Action::Send(failure_xml("invalid-mechanism", None)));
            }
            if request
                .request_token
                .as_ref()
                .is_some_and(|mechanism| mechanism != &request.mechanism)
            {
                return Ok(Action::Send(failure_xml("invalid-mechanism", None)));
            }
            return self.authenticate_fast(request).await;
        }
        if request.fast.is_some() {
            return Ok(Action::Send(failure_xml("malformed-request", None)));
        }

        let mut mechanism: Box<dyn auth::SaslMechanism> = match request.mechanism.as_str() {
            "EXTERNAL" if !self.client_certificate_identities.is_empty() => Box::new(
                auth::ExternalMechanism::new(self.client_certificate_identities.clone()),
            ),
            "PLAIN" => Box::new(auth::PlainMechanism::new(self.state.config.domain.clone())),
            "SCRAM-SHA-256" => {
                if self.channel_bindings.is_some() {
                    Box::new(
                        auth::ScramSha256Mechanism::new_with_channel_binding_support(
                            self.state.config.domain.clone(),
                        ),
                    )
                } else {
                    Box::new(auth::ScramSha256Mechanism::new(
                        self.state.config.domain.clone(),
                    ))
                }
            }
            "SCRAM-SHA-256-PLUS" => {
                let Some(bindings) = self.channel_bindings.clone() else {
                    return Ok(Action::Send(failure_xml("invalid-mechanism", None)));
                };
                Box::new(auth::ScramSha256Mechanism::new_plus(
                    self.state.config.domain.clone(),
                    bindings,
                ))
            }
            "SCRAM-SHA-1" if self.state.config.scram_sha1_enabled => {
                if self.channel_bindings.is_some() {
                    Box::new(
                        auth::ScramSha256Mechanism::new_sha1_with_channel_binding_support(
                            self.state.config.domain.clone(),
                        ),
                    )
                } else {
                    Box::new(auth::ScramSha256Mechanism::new_sha1(
                        self.state.config.domain.clone(),
                    ))
                }
            }
            "SCRAM-SHA-1-PLUS" if self.state.config.scram_sha1_enabled => {
                let Some(bindings) = self.channel_bindings.clone() else {
                    return Ok(Action::Send(failure_xml("invalid-mechanism", None)));
                };
                Box::new(auth::ScramSha256Mechanism::new_sha1_plus(
                    self.state.config.domain.clone(),
                    bindings,
                ))
            }
            _ => return Ok(Action::Send(failure_xml("invalid-mechanism", None))),
        };
        let awaiting_initial_response = request.initial_response.is_none();
        let initial_response = request.initial_response.take();
        let step = initial_response
            .as_deref()
            .map(|payload| mechanism.initial_response(payload))
            .unwrap_or_else(|| auth::SaslStep::Challenge(String::new()));
        self.sasl2_state = Some(Sasl2Context {
            request,
            fast_should_rotate: false,
            awaiting_initial_response,
            fast_token_id: None,
            fast_token_was_new: false,
            fast_invalidate: false,
            authenticated_generation: None,
            inherited_fast_chain: None,
        });
        self.process_sasl_step(mechanism, step).await
    }

    async fn authenticate_fast(&mut self, mut request: Sasl2Request) -> Result<Action> {
        use base64::Engine;
        let Some(fast) = request.fast.clone() else {
            return Ok(Action::Send(failure_xml("malformed-request", None)));
        };
        let Some(user_agent_id) = request.user_agent_id else {
            return Ok(Action::Send(failure_xml("malformed-request", None)));
        };
        let Some(stream_username) = self.stream_from.as_deref() else {
            return Ok(Action::Send(failure_xml("not-authorized", None)));
        };
        let Some(initial_response) = request.initial_response.as_deref() else {
            return Ok(Action::Send(failure_xml("malformed-request", None)));
        };
        let decoded = match base64::engine::general_purpose::STANDARD.decode(initial_response) {
            Ok(decoded) => Zeroizing::new(decoded),
            Err(_) => return Ok(Action::Send(failure_xml("incorrect-encoding", None))),
        };
        let Some(separator) = decoded.iter().position(|byte| *byte == 0) else {
            return Ok(Action::Send(failure_xml("malformed-request", None)));
        };
        if decoded[separator + 1..].len() != 32 {
            return Ok(Action::Send(failure_xml("malformed-request", None)));
        }
        let authcid = match std::str::from_utf8(&decoded[..separator])
            .ok()
            .and_then(|value| auth::normalize_username(value).ok())
        {
            Some(authcid) if authcid == stream_username => authcid,
            _ => return Ok(Action::Send(failure_xml("not-authorized", None))),
        };
        match self.sasl_login_is_limited(&authcid).await {
            Ok(true) => return Ok(self.sasl_rate_limit_failure()),
            Ok(false) => {}
            Err(error) => {
                return Ok(self.authentication_backend_failure(
                    &request.mechanism,
                    &authcid,
                    "load FAST login abuse state",
                    &error,
                ));
            }
        }
        let channel_binding: &[u8] = match request.mechanism.as_str() {
            "HT-SHA-256-NONE" => &[],
            mechanism => match self
                .channel_bindings
                .as_ref()
                .and_then(|bindings| bindings.for_fast_mechanism(mechanism))
            {
                Some(binding) => binding,
                None => return Ok(Action::Send(failure_xml("invalid-mechanism", None))),
            },
        };
        let verified = self
            .state
            .authentication_service()
            .authenticate_fast(crate::services::authentication::FastProofRequest {
                username: &authcid,
                device_id: user_agent_id,
                mechanism: &request.mechanism,
                counter: fast.count,
                initiator_proof: &decoded[separator + 1..],
                channel_binding,
                invalidate: fast.invalidate,
                rotate_within_days: self.state.config.fast_token_rotation_days,
            })
            .await;
        let (
            user,
            responder,
            should_rotate,
            fast_token_id,
            fast_token_was_new,
            authenticated_generation,
            strong_auth_at,
            chain_expires_at,
        ) = match verified {
            crate::services::authentication::AuthenticationResult::Authenticated(verified) => {
                verified.into_parts()
            }
            crate::services::authentication::AuthenticationResult::UnknownCredentials
            | crate::services::authentication::AuthenticationResult::Disabled
            | crate::services::authentication::AuthenticationResult::ReplayedCredentials => {
                if let Err(error) = self.record_sasl_failure(Some(&authcid)).await {
                    return Ok(self.authentication_backend_failure(
                        &request.mechanism,
                        &authcid,
                        "record invalid FAST login",
                        &error,
                    ));
                }
                return Ok(Action::Send(failure_xml("not-authorized", None)));
            }
            crate::services::authentication::AuthenticationResult::StaleGeneration
            | crate::services::authentication::AuthenticationResult::ExpiredCredentials => {
                return Ok(Action::Send(failure_xml("credentials-expired", None)));
            }
            crate::services::authentication::AuthenticationResult::BackendFailure(error) => {
                return Ok(self.authentication_backend_failure(
                    &request.mechanism,
                    &authcid,
                    "verify FAST token",
                    &error,
                ));
            }
            crate::services::authentication::AuthenticationResult::IntegrityFailure => {
                self.state
                    .metrics
                    .fast_credential_integrity_failures_total
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                tracing::error!(
                    device_id = %user_agent_id,
                    mechanism = %request.mechanism,
                    "FAST credential derivation integrity failure"
                );
                return Ok(Action::Send(failure_xml("temporary-auth-failure", None)));
            }
        };
        request.initial_response = None;
        self.sasl2_state = Some(Sasl2Context {
            request,
            fast_should_rotate: should_rotate,
            awaiting_initial_response: false,
            fast_token_id: Some(fast_token_id),
            fast_token_was_new,
            fast_invalidate: fast.invalidate,
            authenticated_generation: Some(authenticated_generation),
            inherited_fast_chain: Some((strong_auth_at, chain_expires_at)),
        });
        self.complete_sasl2(user, Some(responder), false).await
    }

    pub(crate) async fn sasl2_response(&mut self, root: Node<'_, '_>) -> Result<Action> {
        let metrics_state = self.state.clone();
        let _authentication_timer = metrics_state
            .metrics
            .authentication_duration_seconds
            .start_timer();
        if root.tag_name().namespace() != Some(SASL2_NS)
            || root.tag_name().name() != "response"
            || !attr_is(root, &[])
            || root.children().any(|child| child.is_element())
        {
            return Ok(self.fail_sasl2_exchange("malformed-request"));
        }
        if self.sasl2_state.is_none() {
            return Ok(self.fail_sasl2_exchange("not-authorized"));
        }
        let payload = direct_text(root);
        if payload.len() > 64 * 1024 {
            return Ok(self.fail_sasl2_exchange("malformed-request"));
        }
        let payload = match normalize_sasl2_base64_payload(payload) {
            Ok(payload) => Zeroizing::new(payload),
            Err(condition) => return Ok(self.fail_sasl2_exchange(condition)),
        };
        let Some(mut mechanism) = self.sasl_state.take() else {
            return Ok(self.fail_sasl2_exchange("not-authorized"));
        };
        let awaiting_initial = self
            .sasl2_state
            .as_mut()
            .map(|context| std::mem::take(&mut context.awaiting_initial_response))
            .unwrap_or(false);
        let step = if awaiting_initial {
            mechanism.initial_response(&payload)
        } else {
            mechanism.response(&payload)
        };
        self.process_sasl_step(mechanism, step).await
    }

    pub(crate) fn sasl2_abort(&mut self, root: Node<'_, '_>) -> Action {
        let metrics_state = self.state.clone();
        let _authentication_timer = metrics_state
            .metrics
            .authentication_duration_seconds
            .start_timer();
        if root.tag_name().namespace() != Some(SASL2_NS)
            || !attr_is(root, &[])
            || !structural_text_is_empty(root)
        {
            return self.fail_sasl2_exchange("malformed-request");
        }
        if self.sasl2_state.is_none() {
            return self.fail_sasl2_exchange("not-authorized");
        }
        let mut text_seen = false;
        for child in root.children().filter(|child| child.is_element()) {
            if child.tag_name().namespace() == Some(SASL2_NS) && child.tag_name().name() == "text" {
                if text_seen || singleton_text(child, 1024).is_err() {
                    return self.fail_sasl2_exchange("malformed-request");
                }
                text_seen = true;
            }
            // Unknown extension elements are deliberately ignored: abort is
            // extensible and has no state-changing inline operations.
        }
        self.sasl_state = None;
        self.sasl_scram_fence = None;
        self.sasl2_state = None;
        Action::Send(failure_xml("aborted", None))
    }

    fn fail_sasl2_exchange(&mut self, condition: &str) -> Action {
        self.sasl_state = None;
        self.sasl_scram_fence = None;
        self.sasl2_state = None;
        Action::Send(failure_xml(condition, None))
    }

    pub(crate) async fn complete_sasl2(
        &mut self,
        user: crate::services::authentication::AuthenticatedAccount,
        sasl_data: Option<Zeroizing<Vec<u8>>>,
        authenticated_with_external: bool,
    ) -> Result<Action> {
        let Some(context) = self.sasl2_state.take() else {
            return Ok(Action::Send(failure_xml("temporary-auth-failure", None)));
        };
        let expected_auth_generation = context
            .authenticated_generation
            .unwrap_or(user.auth_generation);
        if expected_auth_generation != user.auth_generation {
            self.sasl_state = None;
            return Ok(Action::Send(failure_xml("credentials-expired", None)));
        }
        match self
            .state
            .authentication_service()
            .revalidate_generation(user.id, expected_auth_generation)
            .await
        {
            crate::services::authentication::AuthenticationResult::Authenticated(()) => {}
            crate::services::authentication::AuthenticationResult::Disabled
            | crate::services::authentication::AuthenticationResult::StaleGeneration
            | crate::services::authentication::AuthenticationResult::ExpiredCredentials
            | crate::services::authentication::AuthenticationResult::ReplayedCredentials => {
                self.sasl_state = None;
                return Ok(Action::Send(failure_xml("credentials-expired", None)));
            }
            crate::services::authentication::AuthenticationResult::UnknownCredentials => {
                self.sasl_state = None;
                return Ok(Action::Send(failure_xml("not-authorized", None)));
            }
            crate::services::authentication::AuthenticationResult::IntegrityFailure => {
                self.state
                    .metrics
                    .fast_credential_integrity_failures_total
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                tracing::error!(user_id = %user.id, "credential integrity failure during SASL2 revalidation");
                self.sasl_state = None;
                return Ok(Action::Send(failure_xml("temporary-auth-failure", None)));
            }
            crate::services::authentication::AuthenticationResult::BackendFailure(error) => {
                self.state
                    .metrics
                    .authentication_backend_failures_total
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                tracing::error!(?error, user_id = %user.id, "could not revalidate SASL2 credentials");
                self.sasl_state = None;
                return Ok(Action::Send(failure_xml("temporary-auth-failure", None)));
            }
        }
        self.user_agent_id = context.request.user_agent_id;
        if self
            .stream_from
            .as_ref()
            .is_some_and(|from| from != &user.username)
        {
            self.sasl_state = None;
            self.user_agent_id = None;
            return Ok(Action::Send(failure_xml("not-authorized", None)));
        }
        let bind_plan = if let Some(bind) = context.request.bind.clone() {
            let tag = match bind.tag.as_deref() {
                Some(tag) if !tag.is_empty() => match crate::jid::prepare_resourcepart(tag) {
                    Ok(tag) => Some(tag),
                    Err(_) => {
                        self.user_agent_id = None;
                        return Ok(Action::Send(failure_xml("malformed-request", None)));
                    }
                },
                _ => None,
            };
            let generated = Uuid::new_v4().simple().to_string();
            let resource = tag
                .map(|tag| format!("{tag}/{generated}"))
                .unwrap_or(generated);
            let boundaries = match self
                .state
                .authentication_service()
                .bind2_archive_boundaries(user.id, expected_auth_generation)
                .await
            {
                crate::services::authentication::AuthenticationResult::Authenticated(
                    boundaries,
                ) => boundaries,
                crate::services::authentication::AuthenticationResult::Disabled
                | crate::services::authentication::AuthenticationResult::StaleGeneration
                | crate::services::authentication::AuthenticationResult::ExpiredCredentials
                | crate::services::authentication::AuthenticationResult::ReplayedCredentials => {
                    self.sasl_state = None;
                    self.user_agent_id = None;
                    return Ok(Action::Send(failure_xml("credentials-expired", None)));
                }
                crate::services::authentication::AuthenticationResult::UnknownCredentials => {
                    self.sasl_state = None;
                    self.user_agent_id = None;
                    return Ok(Action::Send(failure_xml("not-authorized", None)));
                }
                crate::services::authentication::AuthenticationResult::IntegrityFailure => {
                    self.state
                        .metrics
                        .fast_credential_integrity_failures_total
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    tracing::error!(user_id = %user.id, "credential integrity failure during Bind2 preflight");
                    self.sasl_state = None;
                    self.user_agent_id = None;
                    return Ok(Action::Send(failure_xml("temporary-auth-failure", None)));
                }
                crate::services::authentication::AuthenticationResult::BackendFailure(error) => {
                    self.state
                        .metrics
                        .authentication_backend_failures_total
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    tracing::error!(?error, "could not preflight Bind 2 MAM metadata");
                    self.sasl_state = None;
                    self.user_agent_id = None;
                    return Ok(Action::Send(failure_xml("temporary-auth-failure", None)));
                }
            };
            Some((bind, resource, boundaries))
        } else {
            None
        };
        let fast_plan = self.sasl2_fast_commit_plan(&context);
        let mut unbound_state_committed = false;
        let mut token_xml = if bind_plan.is_none() && context.request.resume.is_none() {
            match self
                .commit_sasl2_unbound_state(&fast_plan, &user, expected_auth_generation)
                .await?
            {
                Ok((token_xml, receipt)) => {
                    unbound_state_committed = true;
                    self.pending_credential_commit = Some(receipt);
                    token_xml
                }
                Err(condition) => {
                    self.sasl_state = None;
                    self.user_agent_id = None;
                    return Ok(Action::Send(failure_xml(condition, None)));
                }
            }
        } else {
            String::new()
        };
        // Keep the guard provisional until the entire SASL2 outcome (including
        // inline resume/bind) is known.  It is already present in the live CRL
        // registry before either inline operation begins, but automatically
        // unregisters if a later fallible step turns the exchange into a SASL
        // failure.  A subsequent password/FAST retry can therefore never
        // inherit an EXTERNAL-only drain registration.
        let mut certificate_session =
            if authenticated_with_external && self._certificate_session.is_none() {
                Some(self.external_certificate_session()?)
            } else {
                None
            };
        if self.disconnect.is_cancelled() {
            self.sasl_state = None;
            self.user_agent_id = None;
            return Ok(Action::Close);
        }
        self.authenticated = Some(user.clone());
        self.authenticated_at = Some(std::time::Instant::now());
        let mut resume_xml = String::new();
        if let Some(resume) = context.request.resume.as_ref() {
            match self
                .resume_values_with_fast(&resume.previd, resume.h, Some(&fast_plan), true)
                .await
            {
                Ok((Action::Resume(mut payload), issued)) => {
                    if let Some(issued) = issued {
                        token_xml = fast_token_xml(&issued);
                    }
                    let authorization_identifier = self
                        .full_jid
                        .as_deref()
                        .unwrap_or_else(|| {
                            self.authenticated = None;
                            ""
                        })
                        .to_owned();
                    if authorization_identifier.is_empty() {
                        self.sasl_state = None;
                        return Ok(Action::Send(failure_xml("temporary-auth-failure", None)));
                    }
                    let features = self.features();
                    let envelope_reservation = inline_resume_envelope_reservation_bytes(
                        sasl_data.as_ref().map(|data| data.as_slice()),
                        &authorization_identifier,
                        payload.control(),
                        &token_xml,
                        &features,
                    )
                    .context("SASL2 inline resume envelope allocation overflow")?;
                    let envelope_capacity = self
                        .state
                        .sm_memory_governor()
                        .try_reserve_transient(envelope_reservation)
                        .context("SASL2 inline resume transport memory capacity reached")?;
                    let success = sasl2_success_xml(
                        sasl_data.as_ref().map(|data| data.as_slice()),
                        &authorization_identifier,
                        &[payload.control(), &token_xml],
                    )?;
                    let post_control = vec![features];
                    payload.replace_envelope(
                        success,
                        post_control,
                        envelope_reservation,
                        envelope_capacity,
                    )?;
                    if self.disconnect.is_cancelled() {
                        self.sm_resume_allowed = false;
                        self.sasl_state = None;
                        return Ok(Action::Close);
                    }
                    if let Some(guard) = certificate_session.take() {
                        self._certificate_session = Some(guard);
                    }
                    self.sasl_state = None;
                    // XEP-0388 requires fresh stream features immediately
                    // after every SASL2 success, including an inline SM
                    // resumption which skips Bind2. Reframing preserves the
                    // original replay reservation and adds the envelope lease.
                    payload.activate_route = true;
                    return Ok(Action::Resume(payload));
                }
                Ok((Action::Send(failed), _)) => resume_xml = failed,
                Ok((Action::Close, _)) if self.pending_credential_commit.is_some() => {
                    self.sasl_state = None;
                    return Ok(Action::Close);
                }
                Ok(_) => resume_xml = crate::xmpp::xml_util::sm_failed("undefined-condition"),
                Err(error) if self.pending_credential_commit.is_some() => {
                    // The SM/FAST transaction has already committed. A
                    // compensation or post-commit staging failure cannot be
                    // converted into an ordinary inline-resume failure and
                    // must never fall through to the unbound FAST commit.
                    tracing::error!(
                        ?error,
                        user_id = %user.id,
                        "inline SM resumption failed after credential commit; closing"
                    );
                    self.sm_resume_allowed = false;
                    self.sasl_state = None;
                    return Ok(Action::Close);
                }
                Err(error) => {
                    tracing::error!(?error, user_id = %user.id, "inline SM resumption backend failed");
                    resume_xml = crate::xmpp::xml_util::sm_failed("internal-server-error");
                }
            }
        }
        if bind_plan.is_none() && !unbound_state_committed {
            token_xml = match self
                .commit_sasl2_unbound_state(&fast_plan, &user, expected_auth_generation)
                .await?
            {
                Ok((token_xml, receipt)) => {
                    self.pending_credential_commit = Some(receipt);
                    token_xml
                }
                Err(condition) => {
                    self.authenticated = None;
                    self.sasl_state = None;
                    self.user_agent_id = None;
                    return Ok(Action::Send(failure_xml(condition, None)));
                }
            };
        }
        if bind_plan.is_some() {
            self.user_agent_epoch = None;
        }
        let mut bound_inner = String::new();
        let mut bound_xml = String::new();
        let authorization_identifier = if let Some((bind, resource, boundaries)) = bind_plan {
            let jid = match self
                .bind_resource_sasl2_internal(&user, resource, Some(&fast_plan), self.user_agent_id)
                .await
            {
                Ok(Ok((jid, issued))) => {
                    if let Some(issued) = issued {
                        token_xml = fast_token_xml(&issued);
                    }
                    jid
                }
                Ok(Err(super::misc::ResourceBindingFailure::CommittedRouteLost))
                    if self.pending_credential_commit.is_some() =>
                {
                    self.sasl_state = None;
                    return Ok(Action::Close);
                }
                Ok(Err(failure)) => {
                    tracing::warn!(
                        user_id = %user.id,
                        ?failure,
                        "Bind2 resource publication was rejected before credential commit"
                    );
                    self.authenticated = None;
                    self.sasl_state = None;
                    self.user_agent_id = None;
                    return Ok(Action::Send(failure_xml(failure.sasl_condition(), None)));
                }
                Err(error) => {
                    tracing::error!(?error, user_id = %user.id, "Bind 2 resource registration failed");
                    self.authenticated = None;
                    self.sasl_state = None;
                    self.user_agent_id = None;
                    return Ok(Action::Send(failure_xml("temporary-auth-failure", None)));
                }
            };
            let (archive_start, archive_end) = boundaries;
            if archive_start.is_some() || archive_end.is_some() {
                let mut metadata = XmlElement::namespaced("metadata", "urn:xmpp:mam:2");
                if let Some(boundary) = archive_start {
                    metadata.push_child(
                        XmlElement::new("start").attr("id", boundary.id).attr(
                            "timestamp",
                            boundary
                                .created_at
                                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                        ),
                    );
                }
                if let Some(boundary) = archive_end {
                    metadata.push_child(
                        XmlElement::new("end").attr("id", boundary.id).attr(
                            "timestamp",
                            boundary
                                .created_at
                                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                        ),
                    );
                }
                bound_inner.push_str(&metadata.finish());
            }
            if bind.carbons {
                self.carbons
                    .store(true, std::sync::atomic::Ordering::Release);
            }
            if let Some(active) = bind.csi_active {
                self.csi_active = active;
            }
            if let Some(sm) = bind.sm {
                match self.enable_sm_inline(sm.resume, sm.max).await {
                    Ok(enabled) => bound_inner.push_str(&enabled),
                    Err(condition) => bound_inner.push_str(
                        &XmlElement::namespaced("failed", "urn:xmpp:sm:3")
                            .child(
                                XmlElement::dynamic(condition)
                                    .expect("SM failure condition must be a valid QName")
                                    .attr("xmlns", "urn:ietf:params:xml:ns:xmpp-stanzas"),
                            )
                            .finish(),
                    ),
                }
            }
            self.bind2_mam_catchup = true;
            // This queue only duplicates MAM for Bind 2. Defer its deletion
            // until the resource is successfully active, and never convert a
            // post-acceptance cleanup outage into a false SASL failure.
            let replay_state = self.state.clone();
            let user_id = user.id;
            let outbound = self.outbound.clone();
            let replay_full_jid = jid.clone();
            self.defer_after_transport("bind2-offline-replay", async move {
                super::replay::replay_bind2_offline(
                    replay_state,
                    outbound,
                    user_id,
                    replay_full_jid,
                )
                .await;
            })?;
            bound_xml = XmlElement::namespaced("bound", BIND2_NS)
                .validated_fragment(&bound_inner)?
                .finish();
            jid
        } else {
            format!("{}@{}", user.username, self.state.config.domain)
        };

        let success = sasl2_success_xml(
            sasl_data.as_ref().map(|data| data.as_slice()),
            &authorization_identifier,
            &[&resume_xml, &bound_xml, &token_xml],
        )?;
        if self.disconnect.is_cancelled() {
            self.sm_resume_allowed = false;
            self.sasl_state = None;
            return Ok(Action::Close);
        }
        if let Some(guard) = certificate_session.take() {
            self._certificate_session = Some(guard);
        }
        self.sasl_state = None;
        // The local/cluster route was reserved before the PostgreSQL commit,
        // but stanza delivery stays gated until the SASL2 success outcome is
        // fully constructed and no remaining inline operation can fail it.
        if self.registered_key.is_some() || self.pending_credential_commit.is_some() {
            Ok(Action::SendManyThenActivate(vec![success, self.features()]))
        } else {
            Ok(Action::SendMany(vec![success, self.features()]))
        }
    }

    /// Commit FAST rotation/invalidation and any mandatory replacement token
    /// before Bind 2 publishes a routable resource. The proof counter is
    /// consumed during verification; every other credential side effect is
    /// staged here while authentication is still externally invisible.
    fn sasl2_fast_commit_plan(
        &self,
        context: &Sasl2Context,
    ) -> crate::services::authentication::FastCommitPlan {
        let mechanism = if context.fast_should_rotate {
            context
                .request
                .request_token
                .as_deref()
                .or(Some(context.request.mechanism.as_str()))
        } else {
            context.request.request_token.as_deref()
        };
        let issue = mechanism
            .filter(|mechanism| self.fast_mechanism_available(mechanism))
            .zip(context.request.user_agent_id)
            .map(
                |(mechanism, device_id)| crate::services::authentication::FastTokenIssue {
                    device_id,
                    mechanism: mechanism.to_owned(),
                    ttl_days: self.state.config.fast_token_ttl_days,
                    strong_reauth_max_days: self.state.config.fast_strong_reauth_max_days,
                    inherited_chain: context.inherited_fast_chain,
                },
            );
        crate::services::authentication::FastCommitPlan {
            token_id: context.fast_token_id,
            token_was_new: context.fast_token_was_new,
            invalidate: context.fast_invalidate,
            issue,
        }
    }

    async fn commit_sasl2_unbound_state(
        &self,
        plan: &crate::services::authentication::FastCommitPlan,
        user: &crate::services::authentication::AuthenticatedAccount,
        expected_auth_generation: i64,
    ) -> Result<
        std::result::Result<
            (
                String,
                crate::services::authentication::CredentialCommitReceipt,
            ),
            &'static str,
        >,
    > {
        match self
            .state
            .authentication_service()
            .commit_fast_with_login_epoch(
                user.id,
                expected_auth_generation,
                plan,
                // Without Bind2 there is no live installation session yet.
                // Allocate its replacement epoch later, in the RFC resource-bind
                // transaction, so a client that authenticates but never binds
                // cannot evict an established device session.
                None,
                self.connection_id,
            )
            .await
        {
            crate::services::authentication::AuthenticationResult::Authenticated(mut receipt) => {
                let token_xml = receipt
                    .take_issued_fast()
                    .as_ref()
                    .map(fast_token_xml)
                    .unwrap_or_default();
                Ok(Ok((token_xml, receipt)))
            }
            crate::services::authentication::AuthenticationResult::Disabled
            | crate::services::authentication::AuthenticationResult::StaleGeneration
            | crate::services::authentication::AuthenticationResult::ExpiredCredentials
            | crate::services::authentication::AuthenticationResult::ReplayedCredentials => {
                Ok(Err("credentials-expired"))
            }
            crate::services::authentication::AuthenticationResult::UnknownCredentials => {
                Ok(Err("not-authorized"))
            }
            crate::services::authentication::AuthenticationResult::IntegrityFailure => {
                self.state
                    .metrics
                    .fast_credential_integrity_failures_total
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                tracing::error!(
                    user_id = %user.id,
                    "SASL2 credential commit integrity failure"
                );
                Ok(Err("temporary-auth-failure"))
            }
            crate::services::authentication::AuthenticationResult::BackendFailure(error) => {
                self.state
                    .metrics
                    .authentication_backend_failures_total
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                tracing::error!(?error, "atomic SASL2 credential/session commit failed");
                Ok(Err("temporary-auth-failure"))
            }
        }
    }

    fn fast_mechanism_available(&self, mechanism: &str) -> bool {
        if !self.state.config.fast_token_enabled {
            return false;
        }
        match mechanism {
            "HT-SHA-256-NONE" => true,
            mechanism => self
                .channel_bindings
                .as_ref()
                .and_then(|bindings| bindings.for_fast_mechanism(mechanism))
                .is_some(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(xml: &str) -> std::result::Result<Sasl2Request, &'static str> {
        let document = Document::parse(xml).unwrap();
        parse_authenticate(document.root_element())
    }

    const DEVICE: &str = "67e55044-10b1-426f-9247-bb680e5fe0c8";

    #[test]
    fn request_and_context_debug_redact_all_bearer_material() {
        use base64::Engine;

        let initial =
            base64::engine::general_purpose::STANDARD.encode(b"\0alice\0secret-password-material");
        let previd = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x91_u8; 32]);
        let xml = format!(
            "<authenticate xmlns='{SASL2_NS}' mechanism='PLAIN'>\
               <initial-response>{initial}</initial-response>\
               <resume xmlns='urn:xmpp:sm:3' previd='{previd}' h='0'/>\
             </authenticate>"
        );
        let request = parse(&xml).unwrap();
        let request_debug = format!("{request:?}");
        assert!(request_debug.contains("[REDACTED]"));
        assert!(!request_debug.contains(&initial));
        assert!(!request_debug.contains(&previd));

        let token_id = Uuid::new_v4();
        let context = Sasl2Context {
            request,
            fast_should_rotate: false,
            awaiting_initial_response: false,
            fast_token_id: Some(token_id),
            fast_token_was_new: false,
            fast_invalidate: false,
            authenticated_generation: Some(7),
            inherited_fast_chain: None,
        };
        let context_debug = format!("{context:?}");
        assert!(!context_debug.contains(&initial));
        assert!(!context_debug.contains(&previd));
        assert!(!context_debug.contains(&token_id.to_string()));
    }

    #[test]
    fn validates_tcp_and_websocket_stream_openings() {
        let tcp = "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='EXAMPLE.test.' from='A\u{30a}LICE@example.test' version='1.0' xml:lang='en-US'>";
        assert_eq!(
            parse_stream_open(tcp, false, "example.test").unwrap(),
            ParsedStreamOpen {
                from: Some("\u{e5}lice".to_owned()),
                language: Some("en-US".to_owned()),
            }
        );
        let websocket =
            "<open xmlns='urn:ietf:params:xml:ns:xmpp-framing' to='example.test' version='1.0'/>";
        assert_eq!(
            parse_stream_open(websocket, true, "example.test").unwrap(),
            ParsedStreamOpen {
                from: None,
                language: None,
            }
        );
        assert!(parse_stream_open(tcp, true, "example.test").is_err());
        assert!(parse_stream_open(websocket, false, "example.test").is_err());
    }

    #[test]
    fn stream_versions_are_numeric_and_minor_versions_are_forward_compatible() {
        for version in ["1.0", "1.1", "1.01", "0001.00042"] {
            let opening = format!(
                "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='example.test' version='{version}'>"
            );
            assert!(
                parse_stream_open(&opening, false, "example.test").is_ok(),
                "rejected {version}"
            );
        }
        for version in ["2.0", "0.9", "1", "1.", ".1", "1.x", "1.0.1"] {
            let opening = format!(
                "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='example.test' version='{version}'>"
            );
            assert_eq!(
                parse_stream_open(&opening, false, "example.test"),
                Err(StreamOpenError::UnsupportedVersion),
                "accepted {version}"
            );
        }
    }

    #[test]
    fn stream_open_failures_keep_the_rfc_condition() {
        let bad_prefix = "<s:stream xmlns:s='http://etherx.jabber.org/streams' xmlns='jabber:client' to='example.test' version='1.0'>";
        assert_eq!(
            parse_stream_open(bad_prefix, false, "example.test"),
            Err(StreamOpenError::BadNamespacePrefix)
        );
        let missing_to = "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' version='1.0'>";
        assert_eq!(
            parse_stream_open(missing_to, false, "example.test"),
            Err(StreamOpenError::ImproperAddressing)
        );
        let unknown_host = "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='other.test' version='1.0'>";
        assert_eq!(
            parse_stream_open(unknown_host, false, "example.test"),
            Err(StreamOpenError::HostUnknown)
        );
        let invalid_from = "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='example.test' from='alice@example.test/Phone' version='1.0'>";
        assert_eq!(
            parse_stream_open(invalid_from, false, "example.test"),
            Err(StreamOpenError::InvalidFrom)
        );
        let empty_from = "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='example.test' from='' version='1.0'>";
        assert_eq!(
            parse_stream_open(empty_from, false, "example.test"),
            Err(StreamOpenError::InvalidFrom)
        );
        let invalid_namespace = "<stream:stream xmlns:stream='urn:wrong' xmlns='jabber:client' to='example.test' version='1.0'>";
        assert_eq!(
            parse_stream_open(invalid_namespace, false, "example.test"),
            Err(StreamOpenError::InvalidNamespace)
        );
    }

    #[test]
    fn rejects_incomplete_or_smuggled_stream_openings() {
        for opening in [
            "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='example.test'>",
            "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:server' to='example.test' version='1.0'>",
            "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' version='1.0'>",
            "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='other.test' version='1.0'>",
            "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='example.test' version='1.0' id='client-controlled'>",
            "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='example.test' from='alice@example.test/device' version='1.0'>",
            "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='example.test' version='1.0'><auth/>",
        ] {
            assert!(
                parse_stream_open(opening, false, "example.test").is_err(),
                "accepted {opening}"
            );
        }
        for opening in [
            "<open xmlns='urn:ietf:params:xml:ns:xmpp-framing' to='example.test'/>",
            "<open xmlns='urn:evil' to='example.test' version='1.0'/>",
            "<open xmlns='urn:ietf:params:xml:ns:xmpp-framing' to='example.test' version='1.0' restart='true'/>",
            "<open xmlns='urn:ietf:params:xml:ns:xmpp-framing' to='example.test' version='1.0'><auth/></open>",
        ] {
            assert!(
                parse_stream_open(opening, true, "example.test").is_err(),
                "accepted {opening}"
            );
        }
    }

    #[test]
    fn parses_password_auth_with_inline_bind() {
        let xml = format!(
            "<authenticate xmlns='{SASL2_NS}' mechanism='SCRAM-SHA-256'><initial-response>biwsbj11LHI9eA==</initial-response><user-agent id='{DEVICE}'><software>Test</software></user-agent><bind xmlns='{BIND2_NS}'><tag>Phone</tag><enable xmlns='urn:xmpp:carbons:2'/><enable xmlns='urn:xmpp:sm:3' resume='true'/><inactive xmlns='urn:xmpp:csi:0'/></bind><request-token xmlns='{FAST_NS}' mechanism='HT-SHA-256-ENDP'/></authenticate>"
        );
        let request = parse(&xml).unwrap();
        assert_eq!(request.bind.unwrap().tag.as_deref(), Some("Phone"));
        assert_eq!(request.request_token.as_deref(), Some("HT-SHA-256-ENDP"));
    }

    #[test]
    fn parses_strict_inline_sm_resume() {
        use base64::Engine;
        let previd = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7_u8; 32]);
        let request = parse(&format!(
            "<authenticate xmlns='{SASL2_NS}' mechanism='SCRAM-SHA-256'><resume xmlns='urn:xmpp:sm:3' previd='{previd}' h='4294967295'/><bind xmlns='{BIND2_NS}'/></authenticate>"
        ))
        .unwrap();
        let resume = request.resume.unwrap();
        assert_eq!(resume.previd.as_str(), previd);
        assert_eq!(resume.h, u32::MAX);

        for invalid in [
            "<resume xmlns='urn:xmpp:sm:3' previd='short' h='0'/>".to_owned(),
            format!("<resume xmlns='urn:xmpp:sm:3' previd='{previd}' h='4294967296'/>"),
            format!("<resume xmlns='urn:xmpp:sm:3' previd='{previd}' h='0' extra='x'/>"),
        ] {
            let xml = format!(
                "<authenticate xmlns='{SASL2_NS}' mechanism='SCRAM-SHA-256'>{invalid}</authenticate>"
            );
            assert_eq!(parse(&xml).unwrap_err(), "malformed-request");
        }
    }

    #[test]
    fn user_agent_and_initial_response_are_optional_for_sasl2() {
        let request = parse(&format!(
            "<authenticate xmlns='{SASL2_NS}' mechanism='SCRAM-SHA-256'/>"
        ))
        .unwrap();
        assert!(request.user_agent_id.is_none());
        assert!(request.initial_response.is_none());
    }

    #[test]
    fn sasl2_rejects_legacy_explicit_empty_but_accepts_an_empty_element() {
        let malformed = format!(
            "<authenticate xmlns='{SASL2_NS}' mechanism='PLAIN'><initial-response>***</initial-response></authenticate>"
        );
        assert_eq!(parse(&malformed).unwrap_err(), "incorrect-encoding");
        let legacy_explicit_empty = format!(
            "<authenticate xmlns='{SASL2_NS}' mechanism='PLAIN'><initial-response>=</initial-response></authenticate>"
        );
        assert_eq!(
            parse(&legacy_explicit_empty).unwrap_err(),
            "incorrect-encoding"
        );
        let empty_element = format!(
            "<authenticate xmlns='{SASL2_NS}' mechanism='PLAIN'><initial-response/></authenticate>"
        );
        assert_eq!(
            parse(&empty_element)
                .unwrap()
                .initial_response
                .as_ref()
                .map(|value| value.as_str()),
            Some("")
        );
    }

    #[test]
    fn rejects_out_of_order_sasl2_user_agent_and_bind2_children() {
        for xml in [
            format!(
                "<authenticate xmlns='{SASL2_NS}' mechanism='PLAIN'><user-agent id='{DEVICE}'/><initial-response>AA==</initial-response></authenticate>"
            ),
            format!(
                "<authenticate xmlns='{SASL2_NS}' mechanism='PLAIN'><bind xmlns='{BIND2_NS}'/><user-agent id='{DEVICE}'/></authenticate>"
            ),
            format!(
                "<authenticate xmlns='{SASL2_NS}' mechanism='PLAIN'><user-agent id='{DEVICE}'><device>Phone</device><software>Client</software></user-agent></authenticate>"
            ),
            format!(
                "<authenticate xmlns='{SASL2_NS}' mechanism='PLAIN'><bind xmlns='{BIND2_NS}'><enable xmlns='urn:xmpp:carbons:2'/><tag>late</tag></bind></authenticate>"
            ),
            format!(
                "<authenticate xmlns='{SASL2_NS}' mechanism='PLAIN'><bind xmlns='{BIND2_NS}'><tag/></bind></authenticate>"
            ),
        ] {
            assert_eq!(parse(&xml).unwrap_err(), "malformed-request", "{xml}");
        }
    }

    #[test]
    fn rejects_duplicate_and_wrong_namespace_children() {
        let duplicate = format!(
            "<authenticate xmlns='{SASL2_NS}' mechanism='PLAIN'><user-agent id='{DEVICE}'/><user-agent id='{DEVICE}'/></authenticate>"
        );
        assert_eq!(parse(&duplicate).unwrap_err(), "malformed-request");
        let wrong_ns = format!(
            "<authenticate xmlns='{SASL2_NS}' mechanism='PLAIN'><initial-response xmlns='urn:evil'>AA==</initial-response><user-agent id='{DEVICE}'/></authenticate>"
        );
        assert_eq!(parse(&wrong_ns).unwrap_err(), "malformed-request");
    }

    #[test]
    fn rejects_non_v4_device_ids_and_invalid_replay_counts() {
        let nil = format!(
            "<authenticate xmlns='{SASL2_NS}' mechanism='HT-SHA-256-NONE'><user-agent id='00000000-0000-0000-0000-000000000000'/><fast xmlns='{FAST_NS}' count='0'/></authenticate>"
        );
        assert_eq!(parse(&nil).unwrap_err(), "malformed-request");
        let non_rfc_variant = format!(
            "<authenticate xmlns='{SASL2_NS}' mechanism='HT-SHA-256-NONE'><user-agent id='550e8400-e29b-41d4-c716-446655440000'/></authenticate>"
        );
        assert_eq!(parse(&non_rfc_variant).unwrap_err(), "malformed-request");
        let negative = format!(
            "<authenticate xmlns='{SASL2_NS}' mechanism='HT-SHA-256-NONE'><user-agent id='{DEVICE}'/><fast xmlns='{FAST_NS}' count='-1'/></authenticate>"
        );
        assert_eq!(parse(&negative).unwrap_err(), "malformed-request");

        let ordinary_non_early_data = format!(
            "<authenticate xmlns='{SASL2_NS}' mechanism='HT-SHA-256-NONE'><initial-response>AA==</initial-response><user-agent id='{DEVICE}'/><fast xmlns='{FAST_NS}'/></authenticate>"
        );
        assert_eq!(
            parse(&ordinary_non_early_data).unwrap().fast.unwrap().count,
            None
        );
    }

    #[test]
    fn rejects_channel_binding_downgrade_at_request_boundary() {
        let unsupported = format!(
            "<authenticate xmlns='{SASL2_NS}' mechanism='PLAIN'><user-agent id='{DEVICE}'/><bind xmlns='{BIND2_NS}'/><request-token xmlns='{FAST_NS}' mechanism='HT-SHA-512-NONE'/></authenticate>"
        );
        assert_eq!(parse(&unsupported).unwrap_err(), "invalid-mechanism");
    }

    #[test]
    fn rejects_text_smuggling_in_empty_extension_elements() {
        let xml = format!(
            "<authenticate xmlns='{SASL2_NS}' mechanism='PLAIN'><initial-response>AA==</initial-response><user-agent id='{DEVICE}'/><bind xmlns='{BIND2_NS}'><enable xmlns='urn:xmpp:carbons:2'>junk</enable></bind></authenticate>"
        );
        assert_eq!(parse(&xml).unwrap_err(), "malformed-request");
        let fast = format!(
            "<authenticate xmlns='{SASL2_NS}' mechanism='HT-SHA-256-NONE'><initial-response>AA==</initial-response><user-agent id='{DEVICE}'/><fast xmlns='{FAST_NS}' count='1'>junk</fast></authenticate>"
        );
        assert_eq!(parse(&fast).unwrap_err(), "malformed-request");
    }

    #[test]
    fn sasl2_failure_keeps_text_in_the_sasl2_namespace() {
        let hostile = "denied </text><success xmlns='urn:evil'/>&\r🙂";
        let xml = failure_xml("not-authorized", Some(hostile));
        let document = Document::parse(&xml).unwrap();
        let text = document
            .root_element()
            .children()
            .find(|child| child.tag_name().name() == "text")
            .unwrap();
        assert_eq!(text.tag_name().namespace(), Some(SASL2_NS));
        assert_eq!(text.text(), Some(hostile));
        assert_eq!(
            document
                .descendants()
                .filter(|node| node.is_element() && node.tag_name().name() == "success")
                .count(),
            0
        );
    }

    #[test]
    fn sasl2_success_validates_fragments_and_escapes_authorization_identifier() {
        let hostile = "alice<&'@example.test/🙂";
        let success = sasl2_success_xml(
            Some(b"server-final"),
            hostile,
            &["<resumed xmlns='urn:xmpp:sm:3' h='7'/>"],
        )
        .unwrap();
        let document = Document::parse(&success).unwrap();
        assert_eq!(
            document
                .descendants()
                .find(|node| {
                    node.is_element() && node.tag_name().name() == "authorization-identifier"
                })
                .and_then(|node| node.text()),
            Some(hostile)
        );
        assert!(document.descendants().any(|node| {
            node.is_element()
                && node.tag_name().name() == "resumed"
                && node.tag_name().namespace() == Some("urn:xmpp:sm:3")
        }));
        assert!(sasl2_success_xml(None, hostile, &["<broken></fragment>"]).is_err());
    }

    #[test]
    fn fast_token_xml_formats_valid_rfc3339_response() {
        let now = chrono::Utc::now();
        let token = crate::services::authentication::IssuedFastToken {
            token: Zeroizing::new("fast-token-payload-abc".to_string()),
            expires_at: now,
        };
        let xml = fast_token_xml(&token);
        assert!(xml.starts_with("<token xmlns='urn:xmpp:fast:0'"));
        assert!(xml.contains("token='fast-token-payload-abc'"));
        let expected_expiry = now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        assert!(xml.contains(&format!("expiry='{expected_expiry}'")));
    }
}
