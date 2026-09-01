use super::*;
use crate::jid::prepare_domainpart;
use crate::state::AppState;
use anyhow::{Context, Result};
use hmac::{Hmac, Mac};
use roxmltree::Document;
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};

pub(crate) const DIALBACK_NS: &str = "jabber:server:dialback";
pub(crate) const STREAM_LIMITS_NS: &str = "urn:xmpp:stream-limits:0";

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct AdvertisedStreamLimits {
    pub max_bytes: Option<usize>,
    pub idle_seconds: Option<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum DialbackOutcome {
    Valid,
    Invalid,
    Error(String),
}

fn same_dialback_domain(left: &str, right: &str) -> bool {
    matches!(
        (prepare_domainpart(left), prepare_domainpart(right)),
        (Ok(left), Ok(right)) if left == right
    )
}

pub(crate) fn stream_limits_feature() -> String {
    stream_limits_feature_for_idle(S2S_AUTHENTICATED_IDLE_TIMEOUT)
}

pub(crate) fn negotiation_stream_limits_feature() -> String {
    stream_limits_feature_for_idle(IO_TIMEOUT)
}

fn stream_limits_feature_for_idle(idle_timeout: Duration) -> String {
    crate::xmpp::xml_builder::XmlElement::new("limits")
        .attr("xmlns", STREAM_LIMITS_NS)
        .child(
            crate::xmpp::xml_builder::XmlElement::new("max-bytes")
                .text(S2S_MAX_STANZA_BYTES.to_string()),
        )
        .child(
            crate::xmpp::xml_builder::XmlElement::new("idle-seconds")
                .text(idle_timeout.as_secs().to_string()),
        )
        .finish()
}

pub(crate) fn features(state: &AppState, external_available: bool) -> String {
    // RFC 6120 section 6.3.4 ties an EXTERNAL offer to a certificate which
    // can actually authorize the asserted peer identity.  Advertising it to
    // every TLS peer makes a legitimate Dialback-only peer select a
    // mechanism that this server must then reject.
    let mut features = crate::xmpp::xml_builder::XmlElement::new("stream:features");
    if state.config.s2s_sasl_external_enabled && external_available {
        features = features.child(
            crate::xmpp::xml_builder::XmlElement::new("mechanisms")
                .attr("xmlns", "urn:ietf:params:xml:ns:xmpp-sasl")
                .child(crate::xmpp::xml_builder::XmlElement::new("mechanism").text("EXTERNAL")),
        );
    }
    if state.config.dialback_enabled {
        features = features.child(
            crate::xmpp::xml_builder::XmlElement::new("dialback")
                .attr("xmlns", "urn:xmpp:features:dialback")
                .child(crate::xmpp::xml_builder::XmlElement::new("errors")),
        );
    }
    if state.config.federation_enabled {
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

pub(crate) fn parse_stream_limits_element(
    limits: roxmltree::Node<'_, '_>,
) -> Option<AdvertisedStreamLimits> {
    if limits.tag_name().name() != "limits"
        || limits.tag_name().namespace() != Some(STREAM_LIMITS_NS)
        || limits.attributes().len() != 0
        || limits.children().any(|child| {
            child.is_text() && child.text().is_some_and(|text| !text.trim().is_empty())
        })
    {
        return None;
    }

    let mut parsed = AdvertisedStreamLimits::default();
    let mut saw_idle = false;
    for child in limits.children().filter(|child| child.is_element()) {
        if child.tag_name().namespace() != Some(STREAM_LIMITS_NS)
            || child.attributes().len() != 0
            || child.children().any(|nested| !nested.is_text())
        {
            return None;
        }
        let value = child.text()?.trim().parse::<u32>().ok()?;
        match child.tag_name().name() {
            "max-bytes" if parsed.max_bytes.is_none() && !saw_idle => {
                parsed.max_bytes = usize::try_from(value).ok();
                parsed.max_bytes?;
            }
            "idle-seconds" if parsed.idle_seconds.is_none() => {
                parsed.idle_seconds = Some(value);
                saw_idle = true;
            }
            _ => return None,
        }
    }
    Some(parsed)
}

/// Returns the peer's advertised limits only when the XEP-0478 element is
/// structurally unambiguous. Invalid or absent limits are ignored for
/// compatibility; our own inbound hard limits remain enforced independently.
pub(crate) fn advertised_stream_limits(feature_xml: &str) -> Option<AdvertisedStreamLimits> {
    let repaired;
    let parseable =
        if feature_xml.starts_with("<stream:features") && !feature_xml.contains("xmlns:stream=") {
            repaired = feature_xml.replacen(
                "<stream:features",
                "<stream:features xmlns:stream='http://etherx.jabber.org/streams'",
                1,
            );
            repaired.as_str()
        } else {
            feature_xml
        };
    let document = Document::parse(parseable).ok()?;
    let root = document.root_element();
    let limits = if root.tag_name().name() == "limits"
        && root.tag_name().namespace() == Some(STREAM_LIMITS_NS)
    {
        root
    } else {
        let mut candidates = root.children().filter(|child| {
            child.is_element()
                && child.tag_name().name() == "limits"
                && child.tag_name().namespace() == Some(STREAM_LIMITS_NS)
        });
        let limits = candidates.next()?;
        if candidates.next().is_some() {
            return None;
        }
        limits
    };
    parse_stream_limits_element(limits)
}

pub(crate) fn keepalive_interval_for_peer(limits: AdvertisedStreamLimits) -> Duration {
    let peer_half = limits
        .idle_seconds
        .map(|seconds| Duration::from_secs(u64::from(seconds).max(2) / 2))
        .unwrap_or(Duration::from_secs(45));
    peer_half.min(Duration::from_secs(45))
}

pub(crate) fn bidi_advertised(feature_xml: &str) -> bool {
    let repaired;
    let parseable =
        if feature_xml.starts_with("<stream:features") && !feature_xml.contains("xmlns:stream=") {
            repaired = feature_xml.replacen(
                "<stream:features",
                "<stream:features xmlns:stream='http://etherx.jabber.org/streams'",
                1,
            );
            repaired.as_str()
        } else {
            feature_xml
        };
    Document::parse(parseable).is_ok_and(|document| {
        let root = document.root_element();
        root.tag_name().name() == "features"
            && root.tag_name().namespace() == Some("http://etherx.jabber.org/streams")
            && root.children().any(|child| {
                child.is_element()
                    && child.tag_name().name() == "bidi"
                    && child.tag_name().namespace() == Some("urn:xmpp:features:bidi")
            })
    })
}

pub(crate) fn advertised(feature_xml: &str) -> bool {
    let repaired;
    let parseable =
        if feature_xml.starts_with("<stream:features") && !feature_xml.contains("xmlns:stream=") {
            repaired = feature_xml.replacen(
                "<stream:features",
                "<stream:features xmlns:stream='http://etherx.jabber.org/streams'",
                1,
            );
            repaired.as_str()
        } else {
            feature_xml
        };
    Document::parse(parseable).is_ok_and(|document| {
        let root = document.root_element();
        root.tag_name().name() == "features"
            && root.tag_name().namespace() == Some("http://etherx.jabber.org/streams")
            && root.children().any(|child| {
                child.is_element()
                    && child.tag_name().name() == "dialback"
                    && child.tag_name().namespace() == Some("urn:xmpp:features:dialback")
            })
    })
}

/// XEP-0185 generation for XEP-0220: HMAC-SHA256(SHA256(secret),
/// receiving-domain SP originating-domain SP stream-id).
pub(crate) fn key(
    secret: &[u8],
    receiving_domain: &str,
    originating_domain: &str,
    stream_id: &str,
) -> String {
    // XEP-0185 deliberately uses the lowercase hexadecimal representation of
    // SHA256(secret) as the HMAC key, not the 32 raw digest octets.  Using the
    // raw bytes produces a plausible-looking but non-interoperable key.
    let derived = hex(&Sha256::digest(secret));
    let mut mac =
        Hmac::<Sha256>::new_from_slice(derived.as_bytes()).expect("SHA-256 accepts any key length");
    mac.update(receiving_domain.as_bytes());
    mac.update(b" ");
    mac.update(originating_domain.as_bytes());
    mac.update(b" ");
    mac.update(stream_id.as_bytes());
    hex(&mac.finalize().into_bytes())
}

pub(crate) fn valid_key(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub(crate) fn matches_key(expected: &str, supplied: &str) -> bool {
    let (Some(expected), Some(supplied)) = (decode_hex(expected), decode_hex(supplied)) else {
        return false;
    };
    let Ok(mut supplied_mac) = Hmac::<Sha256>::new_from_slice(b"northstar-dialback-compare") else {
        return false;
    };
    supplied_mac.update(&supplied);
    let supplied_tag = supplied_mac.finalize().into_bytes();
    let Ok(mut expected_mac) = Hmac::<Sha256>::new_from_slice(b"northstar-dialback-compare") else {
        return false;
    };
    expected_mac.update(&expected);
    expected_mac.verify_slice(&supplied_tag).is_ok()
}

pub(crate) fn result_request(from: &str, to: &str, value: &str) -> String {
    crate::xmpp::xml_builder::XmlElement::new("db:result")
        .attr("xmlns:db", DIALBACK_NS)
        .attr("from", from)
        .attr("to", to)
        .text(value)
        .finish()
}

pub(crate) fn result_response(from: &str, to: &str, valid: bool) -> String {
    crate::xmpp::xml_builder::XmlElement::new("db:result")
        .attr("xmlns:db", DIALBACK_NS)
        .attr("from", from)
        .attr("to", to)
        .attr("type", if valid { "valid" } else { "invalid" })
        .finish()
}

pub(crate) fn result_error(from: &str, to: &str, condition: &'static str) -> String {
    dialback_error_element("result", from, to, None, condition)
}

pub(crate) fn verify_request(from: &str, to: &str, id: &str, value: &str) -> String {
    crate::xmpp::xml_builder::XmlElement::new("db:verify")
        .attr("xmlns:db", DIALBACK_NS)
        .attr("from", from)
        .attr("to", to)
        .attr("id", id)
        .text(value)
        .finish()
}

pub(crate) fn verify_response(from: &str, to: &str, id: &str, valid: bool) -> String {
    crate::xmpp::xml_builder::XmlElement::new("db:verify")
        .attr("xmlns:db", DIALBACK_NS)
        .attr("from", from)
        .attr("to", to)
        .attr("id", id)
        .attr("type", if valid { "valid" } else { "invalid" })
        .finish()
}

pub(crate) fn verify_error(from: &str, to: &str, id: &str, condition: &'static str) -> String {
    dialback_error_element("verify", from, to, Some(id), condition)
}

fn dialback_error_element(
    name: &'static str,
    from: &str,
    to: &str,
    id: Option<&str>,
    condition: &'static str,
) -> String {
    debug_assert!(matches!(name, "result" | "verify"));
    debug_assert!(is_stanza_error_condition(condition));
    crate::xmpp::xml_builder::XmlElement::new(match name {
        "result" => "db:result",
        _ => "db:verify",
    })
    .attr("xmlns:db", DIALBACK_NS)
    .attr("from", from)
    .attr("to", to)
    .optional_attr("id", id)
    .attr("type", "error")
    .child(
        crate::xmpp::xml_builder::XmlElement::new("error")
            .attr("xmlns", "jabber:server")
            .attr("type", stanza_error_type(condition))
            .child(
                crate::xmpp::xml_builder::XmlElement::new(condition)
                    .attr("xmlns", "urn:ietf:params:xml:ns:xmpp-stanzas"),
            ),
    )
    .finish()
}

pub(crate) fn parse_result_response(
    raw: &str,
    expected_from: &str,
    expected_to: &str,
) -> Result<DialbackOutcome> {
    parse_dialback_response(raw, "result", expected_from, expected_to, None)
}

fn parse_verify_response(
    raw: &str,
    expected_from: &str,
    expected_to: &str,
    expected_id: &str,
) -> Result<DialbackOutcome> {
    parse_dialback_response(raw, "verify", expected_from, expected_to, Some(expected_id))
}

fn parse_dialback_response(
    raw: &str,
    expected_name: &str,
    expected_from: &str,
    expected_to: &str,
    expected_id: Option<&str>,
) -> Result<DialbackOutcome> {
    let document = Document::parse(raw).context("invalid authoritative dialback response")?;
    let root = document.root_element();
    if root.tag_name().name() != expected_name
        || root.tag_name().namespace() != Some(DIALBACK_NS)
        || root
            .attribute("from")
            .is_none_or(|domain| !same_dialback_domain(domain, expected_from))
        || root
            .attribute("to")
            .is_none_or(|domain| !same_dialback_domain(domain, expected_to))
        || expected_id.is_some_and(|id| root.attribute("id") != Some(id))
    {
        anyhow::bail!("unsolicited or mismatched authoritative dialback response");
    }
    match root.attribute("type") {
        Some("valid") => Ok(DialbackOutcome::Valid),
        Some("invalid") => Ok(DialbackOutcome::Invalid),
        Some("error") => Ok(DialbackOutcome::Error(parse_error_condition(root)?)),
        _ => anyhow::bail!("authoritative dialback response omitted a valid result type"),
    }
}

fn parse_error_condition(root: roxmltree::Node<'_, '_>) -> Result<String> {
    let mut errors = root.children().filter(|child| {
        child.is_element()
            && child.tag_name().name() == "error"
            // The stream's `jabber:server` default namespace is not present
            // in the standalone frame handed to roxmltree, so namespace-less
            // `error` is equivalent here to an inherited jabber:server node.
            && matches!(child.tag_name().namespace(), None | Some("jabber:server"))
    });
    let error = errors
        .next()
        .context("dialback error response omitted its stanza error")?;
    if errors.next().is_some() {
        anyhow::bail!("dialback response contained multiple stanza errors");
    }
    let mut conditions = error.children().filter(|child| {
        child.is_element()
            && child.tag_name().namespace() == Some("urn:ietf:params:xml:ns:xmpp-stanzas")
            && child.tag_name().name() != "text"
    });
    let condition = conditions
        .next()
        .map(|condition| condition.tag_name().name())
        .filter(|condition| is_stanza_error_condition(condition))
        .context("dialback response contained no recognized stanza error condition")?;
    if conditions.next().is_some() {
        anyhow::bail!("dialback response contained multiple stanza error conditions");
    }
    Ok(condition.to_owned())
}

fn is_stanza_error_condition(condition: &str) -> bool {
    matches!(
        condition,
        "bad-request"
            | "conflict"
            | "feature-not-implemented"
            | "forbidden"
            | "gone"
            | "internal-server-error"
            | "item-not-found"
            | "jid-malformed"
            | "not-acceptable"
            | "not-allowed"
            | "not-authorized"
            | "policy-violation"
            | "recipient-unavailable"
            | "redirect"
            | "registration-required"
            | "remote-server-not-found"
            | "remote-server-timeout"
            | "resource-constraint"
            | "service-unavailable"
            | "subscription-required"
            | "undefined-condition"
            | "unexpected-request"
    )
}

fn stanza_error_type(condition: &str) -> &'static str {
    match condition {
        "forbidden" | "not-authorized" => "auth",
        "bad-request" | "jid-malformed" | "not-acceptable" => "modify",
        "internal-server-error" | "remote-server-timeout" | "resource-constraint" => "wait",
        _ => "cancel",
    }
}

pub(crate) async fn verify_remote(
    state: Arc<AppState>,
    originating_domain: &str,
    receiving_domain: &str,
    stream_id: &str,
    supplied_key: &str,
) -> Result<DialbackOutcome> {
    if !valid_key(supplied_key) {
        return Ok(DialbackOutcome::Invalid);
    }
    let originating_domain =
        prepare_domainpart(originating_domain).context("invalid dialback originating domain")?;
    let receiving_domain =
        prepare_domainpart(receiving_domain).context("invalid dialback receiving domain")?;
    let permit = state
        .try_acquire_dialback_verification()
        .context("too many concurrent dialback verification requests")?;
    let _connection_permit = state
        .try_acquire_s2s_connection()
        .context("S2S connection capacity is exhausted during dialback verification")?;
    let (mut stream, opening, _features, mut input, _peer_certificates, _tls_generation) =
        crate::s2s::outbound::connect_secure_stream_from(
            &state,
            &receiving_domain,
            &originating_domain,
        )
        .await?;
    if stream_attribute(&opening, "from")
        .is_none_or(|domain| !same_dialback_domain(&domain, &originating_domain))
        || stream_attribute(&opening, "to")
            .is_none_or(|domain| !same_dialback_domain(&domain, &receiving_domain))
    {
        anyhow::bail!("authoritative dialback endpoint returned an invalid stream identity");
    }
    write_xml(
        &mut stream,
        &verify_request(
            &receiving_domain,
            &originating_domain,
            stream_id,
            supplied_key,
        ),
    )
    .await?;
    let response = timed_read_frame(&mut stream, &mut input).await?;
    drop(permit);
    parse_verify_response(&response, &originating_domain, &receiving_domain, stream_id)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16)?;
            let low = (pair[1] as char).to_digit(16)?;
            Some(((high << 4) | low) as u8)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xep_0185_key_is_stable_and_compared_in_constant_time() {
        let first = key(
            b"correct horse battery staple",
            "example.org",
            "example.net",
            "abc",
        );
        let second = key(
            b"correct horse battery staple",
            "example.org",
            "example.net",
            "abc",
        );
        assert_eq!(first.len(), 64);
        assert!(matches_key(&first, &second));
        assert!(!matches_key(&first, &"0".repeat(64)));
        assert!(!valid_key("not-a-key"));

        // Published XEP-0185 section 3 test vector.
        assert_eq!(
            key(
                b"s3cr3tf0rd14lb4ck",
                "xmpp.example.com",
                "example.org",
                "D60000229F",
            ),
            "37c69b1cf07a3f67c04a5ef5902fa5114f2c76fe4a2686482ba5b89323075643"
        );
    }

    #[test]
    fn bidi_feature_detection_requires_the_exact_namespace() {
        assert!(bidi_advertised(
            "<stream:features><bidi xmlns='urn:xmpp:features:bidi'/></stream:features>"
        ));
        assert!(!bidi_advertised(
            "<stream:features><bidi xmlns='urn:xmpp:bidi'/></stream:features>"
        ));
        assert!(!bidi_advertised(
            "<stream:features><feature var='urn:xmpp:features:bidi'/></stream:features>"
        ));
        assert!(!bidi_advertised(
            "<message xmlns='jabber:server'><bidi xmlns='urn:xmpp:features:bidi'/></message>"
        ));
        assert!(!bidi_advertised("<stream:features/>"));
    }

    #[test]
    fn dialback_feature_detection_does_not_trust_substrings() {
        assert!(advertised(
            "<stream:features><dialback xmlns='urn:xmpp:features:dialback'><errors/></dialback></stream:features>"
        ));
        for invalid in [
            "<stream:features><feature var='urn:xmpp:features:dialback'/></stream:features>",
            "<stream:features><dialback xmlns='urn:wrong'>urn:xmpp:features:dialback</dialback></stream:features>",
            "<message xmlns='jabber:server'><dialback xmlns='urn:xmpp:features:dialback'/></message>",
        ] {
            assert!(!advertised(invalid), "accepted {invalid}");
        }
    }

    #[test]
    fn stream_limit_advertisement_matches_the_enforced_frame_limit() {
        let feature = stream_limits_feature();
        assert_eq!(
            advertised_stream_limits(&feature),
            Some(AdvertisedStreamLimits {
                max_bytes: Some(S2S_MAX_STANZA_BYTES),
                idle_seconds: Some(300),
            })
        );
        assert_eq!(
            advertised_stream_limits(&negotiation_stream_limits_feature()),
            Some(AdvertisedStreamLimits {
                max_bytes: Some(S2S_MAX_STANZA_BYTES),
                idle_seconds: Some(IO_TIMEOUT.as_secs() as u32),
            })
        );
        assert_eq!(
            advertised_stream_limits(
                "<stream:features><limits xmlns='urn:xmpp:stream-limits:0'><max-bytes>4096</max-bytes><idle-seconds>20</idle-seconds></limits></stream:features>"
            ),
            Some(AdvertisedStreamLimits {
                max_bytes: Some(4096),
                idle_seconds: Some(20),
            })
        );
        assert_eq!(
            advertised_stream_limits(
                "<stream:features><limits xmlns='urn:xmpp:stream-limits:0'><max-bytes>0</max-bytes></limits></stream:features>"
            ),
            Some(AdvertisedStreamLimits {
                max_bytes: Some(0),
                idle_seconds: None,
            })
        );
        for invalid in [
            "<stream:features><limits xmlns='urn:example:wrong'><max-bytes>1</max-bytes></limits></stream:features>",
            "<stream:features><limits xmlns='urn:xmpp:stream-limits:0'><idle-seconds>10</idle-seconds><max-bytes>1</max-bytes></limits></stream:features>",
            "<stream:features><limits xmlns='urn:xmpp:stream-limits:0'><max-bytes>1</max-bytes><max-bytes>2</max-bytes></limits></stream:features>",
            "<stream:features><limits xmlns='urn:xmpp:stream-limits:0'><unknown>1</unknown></limits></stream:features>",
            "<stream:features><limits xmlns='urn:xmpp:stream-limits:0'/><limits xmlns='urn:xmpp:stream-limits:0'/></stream:features>",
        ] {
            assert_eq!(advertised_stream_limits(invalid), None, "accepted {invalid}");
        }
        assert_eq!(
            keepalive_interval_for_peer(AdvertisedStreamLimits {
                max_bytes: None,
                idle_seconds: Some(20),
            }),
            Duration::from_secs(10)
        );
    }

    #[test]
    fn graceful_dialback_responses_are_correlated_and_parsed() {
        assert_eq!(
            parse_result_response(
                "<db:result xmlns:db='jabber:server:dialback' from='remote.test' to='local.test' type='valid'/>",
                "REMOTE.test.",
                "LOCAL.test"
            )
            .unwrap(),
            DialbackOutcome::Valid
        );
        assert_eq!(
            parse_result_response(
                "<db:result xmlns:db='jabber:server:dialback' from='remote.test' to='local.test' type='invalid'/>",
                "remote.test",
                "local.test"
            )
            .unwrap(),
            DialbackOutcome::Invalid
        );
        let error = result_error("remote.test", "local.test", "remote-server-timeout");
        assert_eq!(
            parse_result_response(&error, "remote.test", "local.test").unwrap(),
            DialbackOutcome::Error("remote-server-timeout".to_owned())
        );
        assert!(parse_result_response(&error, "attacker.test", "local.test").is_err());

        let verification = verify_error(
            "remote.test",
            "local.test",
            "CaseSensitive-ID",
            "item-not-found",
        );
        assert_eq!(
            parse_verify_response(
                &verification,
                "remote.test",
                "local.test",
                "CaseSensitive-ID"
            )
            .unwrap(),
            DialbackOutcome::Error("item-not-found".to_owned())
        );
        assert!(parse_verify_response(
            &verification,
            "remote.test",
            "local.test",
            "casesensitive-id"
        )
        .is_err());
    }

    #[test]
    fn graceful_dialback_error_parser_rejects_ambiguous_conditions() {
        for malformed in [
            "<db:result xmlns:db='jabber:server:dialback' from='remote.test' to='local.test' type='error'/>",
            "<db:result xmlns:db='jabber:server:dialback' from='remote.test' to='local.test' type='error'><error xmlns='jabber:server' type='cancel'><invented xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></db:result>",
            "<db:result xmlns:db='jabber:server:dialback' from='remote.test' to='local.test' type='error'><error xmlns='jabber:server' type='cancel'><item-not-found xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><remote-server-timeout xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></db:result>",
        ] {
            assert!(parse_result_response(malformed, "remote.test", "local.test").is_err());
        }
    }
}
