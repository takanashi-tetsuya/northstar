//! Validate and parse SASL payloads and inline requests.

use super::*;

pub fn attr_is(node: Node<'_, '_>, allowed: &[&str]) -> bool {
    node.attributes().all(|attr| {
        attr.namespace().is_none() && allowed.iter().any(|allowed| *allowed == attr.name())
    })
}

pub fn structural_text_is_empty(node: Node<'_, '_>) -> bool {
    node.children()
        .filter(|child| child.is_text())
        .all(|child| child.text().unwrap_or_default().trim().is_empty())
}

pub fn direct_text(node: Node<'_, '_>) -> String {
    node.children()
        .filter(|child| child.is_text())
        .filter_map(|child| child.text())
        .collect()
}

pub fn normalize_base64_payload(
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

pub fn normalize_sasl2_base64_payload(
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

pub fn singleton_text(node: Node<'_, '_>, max: usize) -> std::result::Result<String, &'static str> {
    if node.children().any(|child| child.is_element()) || !attr_is(node, &[]) {
        return Err("malformed-request");
    }
    let text = direct_text(node);
    if text.len() > max || text.chars().any(char::is_control) {
        return Err("malformed-request");
    }
    Ok(text)
}

pub fn parse_user_agent(node: Node<'_, '_>) -> std::result::Result<Option<Uuid>, &'static str> {
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

pub fn parse_bind(node: Node<'_, '_>) -> std::result::Result<Bind2Request, &'static str> {
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

pub fn parse_authenticate(root: Node<'_, '_>) -> std::result::Result<Sasl2Request, &'static str> {
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

pub fn legacy_sasl_auth(root: Node<'_, '_>) -> Option<(String, Option<Zeroizing<String>>)> {
    if root.tag_name().name() != "auth"
        || root.tag_name().namespace() != Some("urn:ietf:params:xml:ns:xmpp-sasl")
        || root
            .attributes()
            .any(|attribute| attribute.namespace().is_some() || attribute.name() != "mechanism")
        || root.children().any(|child| child.is_element())
    {
        return None;
    }
    let mechanism = root.attribute("mechanism")?;
    let text_nodes = root
        .children()
        .filter(|child| child.is_text())
        .filter_map(|child| child.text())
        .collect::<Vec<_>>();
    let payload = (!text_nodes.is_empty()).then(|| Zeroizing::new(text_nodes.concat()));
    if mechanism.is_empty()
        || mechanism.len() > 128
        || payload
            .as_ref()
            .is_some_and(|payload| payload.len() > 65_536)
    {
        return None;
    }
    Some((mechanism.to_owned(), payload))
}

pub fn legacy_sasl_payload(root: Node<'_, '_>) -> Option<Zeroizing<String>> {
    if root.attributes().len() != 0 || root.children().any(|child| child.is_element()) {
        return None;
    }
    let payload = root
        .children()
        .filter(|child| child.is_text())
        .filter_map(|child| child.text())
        .collect::<String>();
    (payload.len() <= 65_536).then(|| Zeroizing::new(payload))
}
