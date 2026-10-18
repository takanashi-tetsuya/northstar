//! Parse and validate BOSH requests and apply request sequencing, timing and negotiation rules.

use super::*;

pub(super) fn secure_proxy_request(
    peer_ip: IpAddr,
    headers: &HeaderMap,
    trusted: &[IpAddr],
) -> bool {
    if !trusted.contains(&peer_ip) {
        return false;
    }
    let mut values = headers.get_all("x-forwarded-proto").iter();
    matches!((values.next(), values.next()), (Some(value), None) if value
        .to_str()
        .ok()
        .is_some_and(|value| !value.contains(',') && value.trim().eq_ignore_ascii_case("https")))
}

pub(super) fn supported_request_headers(headers: &HeaderMap) -> bool {
    let mut content_types = headers.get_all(header::CONTENT_TYPE).iter();
    let content_type_ok = match (content_types.next(), content_types.next()) {
        (None, None) => true,
        // XEP-0124 section 14.2 explicitly tells connection managers to
        // ignore the request Content-Type. Browsers and older BOSH clients
        // legitimately use text/plain or form media types. The bounded body
        // is still parsed as one strict XML document below.
        (Some(value), None) => value.to_str().is_ok_and(|value| value.len() <= 256),
        _ => false,
    };
    let mut content_encodings = headers.get_all(header::CONTENT_ENCODING).iter();
    let content_encoding_ok = match (content_encodings.next(), content_encodings.next()) {
        (None, None) => true,
        (Some(value), None) => value
            .to_str()
            .ok()
            .is_some_and(|value| value.eq_ignore_ascii_case("identity")),
        _ => false,
    };
    content_type_ok && content_encoding_ok
}

pub(super) fn classify_rid(next_rid: u64, rid: u64) -> RidDisposition {
    if rid < next_rid {
        RidDisposition::Old
    } else if rid == next_rid {
        RidDisposition::Expected
    } else if rid == next_rid.saturating_add(1) {
        RidDisposition::BufferedOneAhead
    } else {
        RidDisposition::OutsideWindow
    }
}

pub(super) fn valid_client_response_ack(
    acknowledgements_announced: bool,
    highest_responded: u64,
    request_rid: u64,
    ack: Option<u64>,
) -> bool {
    ack.is_none_or(|ack| {
        acknowledgements_announced && ack < request_rid && ack <= highest_responded
    })
}

pub(super) fn advance_bosh_key_sequence(
    expected_key: &mut Option<String>,
    key: Option<&str>,
    newkey: Option<&str>,
) -> bool {
    match expected_key.as_deref() {
        None => key.is_none() && newkey.is_none(),
        Some(expected) => {
            let Some(key) = key else {
                return false;
            };
            let digest = Sha1::digest(key.as_bytes());
            let mut actual = String::with_capacity(40);
            for byte in digest {
                use std::fmt::Write as _;
                let _ = write!(&mut actual, "{byte:02x}");
            }
            if !bool::from(actual.as_bytes().ct_eq(expected.as_bytes())) {
                return false;
            }
            *expected_key = Some(newkey.unwrap_or(key).to_owned());
            true
        }
    }
}

pub(super) fn replace_duplicate_responders(
    pending: &mut PendingRequest,
    request: &BoshRequest,
    newest: oneshot::Sender<BoshHttpResponse>,
    content_type: &str,
) -> bool {
    if pending.request.fingerprint != request.fingerprint {
        let _ = newest.send(terminal_response_with_content("bad-request", content_type));
        return false;
    }
    let recoverable = BoshHttpResponse {
        body: Bytes::from(
            bosh_body_element(None, false, None)
                .attr("type", "error")
                .finish(),
        ),
        content_type: content_type.to_owned(),
    };
    for previous in std::mem::take(&mut pending.responders) {
        let _ = previous.send(recoverable.clone());
    }
    pending.responders.push(newest);
    true
}

pub(super) fn inactivity_deadline(
    last_response: Instant,
    inactivity: Duration,
    request_held: bool,
) -> Option<Instant> {
    (!request_held).then_some(last_response + inactivity)
}

pub(super) fn take_expired_buffered(
    buffered: &mut BTreeMap<u64, PendingRequest>,
    wait: Duration,
    now: Instant,
) -> Vec<PendingRequest> {
    let expired = buffered
        .iter()
        .filter_map(|(rid, pending)| (pending.request.received_at + wait <= now).then_some(*rid))
        .collect::<Vec<_>>();
    expired
        .into_iter()
        .filter_map(|rid| buffered.remove(&rid))
        .collect()
}

pub(super) fn within_polling_interval(
    previous: Instant,
    current: Instant,
    polling: Duration,
) -> bool {
    current
        .checked_duration_since(previous)
        .is_some_and(|elapsed| elapsed < polling)
}

pub(super) fn too_frequent_held_empty_request(
    previous: &BoshRequest,
    current: &BoshRequest,
    polling: Duration,
) -> bool {
    current.payloads.is_empty()
        && current.pause.is_none()
        && !current.terminate
        && within_polling_interval(previous.received_at, current.received_at, polling)
}

pub(super) fn highest_contiguous_buffered_rid(
    next_rid: u64,
    highest_received: u64,
    buffered: &BTreeMap<u64, PendingRequest>,
) -> Option<u64> {
    if highest_received < next_rid || !buffered.contains_key(&next_rid) {
        return None;
    }
    let mut contiguous = next_rid;
    while contiguous < highest_received {
        let Some(candidate) = contiguous.checked_add(1) else {
            break;
        };
        if !buffered.contains_key(&candidate) {
            break;
        }
        contiguous = candidate;
    }
    Some(contiguous)
}

pub(super) fn parse_body(raw: &str, max_stanzas: usize) -> Result<BoshRequest, &'static str> {
    let frame = parse_bosh_frame(
        raw,
        max_stanzas,
        crate::xmpp::MAX_XMPP_FRAME_BYTES,
        HTTP_BIND_NS,
    )?;
    let document = Document::parse(&frame).map_err(|_| "bad-request")?;
    let root = document.root_element();

    let sid = attr(root, "sid").map(str::to_owned);
    let creation = sid.is_none();
    for attribute in root.attributes() {
        let allowed = match attribute.namespace() {
            None => {
                let common = matches!(attribute.name(), "rid" | "sid" | "ack");
                common
                    || (creation
                        && matches!(
                            attribute.name(),
                            "to" | "from"
                                | "wait"
                                | "hold"
                                | "ver"
                                | "route"
                                | "content"
                                | "newkey"
                        ))
                    || (!creation
                        && matches!(
                            attribute.name(),
                            "to" | "from" | "pause" | "type" | "key" | "newkey"
                        ))
            }
            Some(XBOSH_NS) => {
                (creation && attribute.name() == "version")
                    || (!creation && attribute.name() == "restart")
            }
            Some(XML_NS) => attribute.name() == "lang",
            _ => false,
        };
        if !allowed {
            return Err("bad-request");
        }
    }

    let rid = positive_number(attr(root, "rid").ok_or("bad-request")?)?;
    if creation && rid >= MAX_RID {
        return Err("bad-request");
    }
    let ack = attr(root, "ack").map(positive_number).transpose()?;
    let key = attr(root, "key").map(bosh_key).transpose()?;
    let newkey = attr(root, "newkey").map(bosh_key).transpose()?;
    let wait = attr(root, "wait").map(nonnegative_number).transpose()?;
    let hold = attr(root, "hold")
        .map(nonnegative_number)
        .transpose()?
        .map(u8::try_from)
        .transpose()
        .map_err(|_| "bad-request")?;
    let pause = attr(root, "pause").map(nonnegative_number).transpose()?;
    let terminate = match attr(root, "type") {
        None => false,
        Some("terminate") => true,
        Some(_) => return Err("bad-request"),
    };
    let restart = match root.attribute((XBOSH_NS, "restart")) {
        None | Some("0" | "false") => false,
        Some("1" | "true") => true,
        Some(_) => return Err("bad-request"),
    };
    let xmpp_version = root.attribute((XBOSH_NS, "version")).map(str::to_owned);
    let content = attr(root, "content")
        .map(validate_content_type)
        .transpose()?;
    if attr(root, "route").is_some_and(|route| route.chars().any(char::is_control)) {
        return Err("bad-request");
    }

    let payloads = root
        .children()
        .filter(|child| child.is_element())
        .map(|child| {
            frame
                .get(child.range())
                .map(str::to_owned)
                .ok_or("bad-request")
        })
        .collect::<Result<Vec<_>, _>>()?;
    if attr(root, "ver").is_some_and(|version| parse_bosh_version(version).is_none()) {
        return Err("bad-request");
    }
    let fingerprint = Sha256::digest(raw.as_bytes()).into();
    Ok(BoshRequest {
        rid,
        sid,
        to: attr(root, "to").map(str::to_owned),
        from: attr(root, "from").map(str::to_owned),
        wait,
        hold,
        ver: attr(root, "ver").map(str::to_owned),
        content,
        ack,
        key,
        newkey,
        pause,
        terminate,
        restart,
        xmpp_version,
        language: root.attribute((XML_NS, "lang")).map(str::to_owned),
        payloads,
        fingerprint,
        received_at: Instant::now(),
    })
}

pub(super) fn bosh_key(value: &str) -> Result<String, &'static str> {
    (value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| value.to_ascii_lowercase())
        .ok_or("bad-request")
}

pub(super) fn attr<'a>(root: roxmltree::Node<'a, 'a>, name: &str) -> Option<&'a str> {
    root.attribute(name)
}

pub(super) fn positive_number(value: &str) -> Result<u64, &'static str> {
    let parsed = nonnegative_number(value)?;
    (parsed > 0 && parsed <= MAX_RID)
        .then_some(parsed)
        .ok_or("bad-request")
}

pub(super) fn nonnegative_number(value: &str) -> Result<u64, &'static str> {
    if value.is_empty()
        || value.len() > 16
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err("bad-request");
    }
    value.parse().map_err(|_| "bad-request")
}

pub(super) fn validate_content_type(value: &str) -> Result<String, &'static str> {
    let mut parts = value.split(';');
    let essence = parts.next().unwrap_or_default().trim();
    let valid_parameters = parts.all(|parameter| {
        matches!(
            parameter.trim().to_ascii_lowercase().as_str(),
            "charset=utf-8" | "charset=\"utf-8\""
        )
    });
    if value.is_empty()
        || value.len() > 128
        || value.chars().any(char::is_control)
        || HeaderValue::from_str(value).is_err()
        || !valid_parameters
        || !matches!(
            essence.to_ascii_lowercase().as_str(),
            "text/xml" | "application/xml" | "application/xmpp+xml"
        )
    {
        return Err("bad-request");
    }
    Ok(value.to_owned())
}

pub(super) fn negotiated_bosh_version(client: Option<&str>) -> String {
    let Some(client) = client else {
        return "1.11".to_owned();
    };
    let Some((major, minor)) = parse_bosh_version(client) else {
        return "1.11".to_owned();
    };
    if major < 1 || (major == 1 && minor < 11) {
        format!("{major}.{minor}")
    } else {
        "1.11".to_owned()
    }
}

pub(super) fn negotiated_wait(client: Option<u64>, maximum: u64) -> u64 {
    client.unwrap_or(maximum).min(maximum)
}

pub(super) fn negotiated_hold(client: Option<u8>, wait: u64) -> u8 {
    if wait == 0 {
        0
    } else {
        client.unwrap_or(1).min(1)
    }
}

pub(super) fn parse_bosh_version(value: &str) -> Option<(u16, u16)> {
    let (major, minor) = value.split_once('.')?;
    if major.is_empty()
        || minor.is_empty()
        || major.len() > 5
        || minor.len() > 5
        || !major.bytes().all(|byte| byte.is_ascii_digit())
        || !minor.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    Some((major.parse().ok()?, minor.parse().ok()?))
}

pub(super) fn capture_bosh_stream(
    protocol: &mut ProtocolSession,
    to: Option<&str>,
    from: Option<&str>,
    language: Option<&str>,
) -> Result<(), ()> {
    let opening = XmlElement::new("stream:stream")
        .attr("xmlns:stream", "http://etherx.jabber.org/streams")
        .attr("xmlns", "jabber:client")
        .optional_attr("to", to)
        .optional_attr("from", from)
        .optional_attr("xml:lang", language)
        .attr("version", "1.0")
        .open();
    protocol.capture_stream_from(&opening).map_err(|_| ())
}

pub(super) fn bosh_request_shape_error(
    request: &BoshRequest,
    stream_opened: bool,
) -> Option<&'static str> {
    if (request.to.is_some() || request.from.is_some()) && !request.restart {
        return Some("bad-request");
    }
    if request.pause.is_some()
        && (request.terminate || request.restart || !request.payloads.is_empty())
    {
        return Some("bad-request");
    }
    if request.restart && (request.terminate || stream_opened) {
        return Some("bad-request");
    }
    None
}

/// XEP-0206 restart requests are allowed to repeat the `to` attribute. Use
/// the configured canonical domain for the synthetic stream opening after
/// validating the supplied value, so a valid legacy restart cannot be
/// rejected merely because its XML spelling differs in case or IDNA form.
pub(super) fn validated_bosh_restart_target(
    requested: Option<&str>,
    configured_domain: &str,
) -> Result<String, &'static str> {
    match requested {
        Some(value)
            if crate::jid::prepare_domainpart(value).ok().as_deref() == Some(configured_domain) =>
        {
            Ok(configured_domain.to_owned())
        }
        Some(_) => Err("improper-addressing"),
        None => Ok(configured_domain.to_owned()),
    }
}
