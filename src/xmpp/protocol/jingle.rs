use roxmltree::Node;
use std::collections::HashSet;

pub(crate) const JINGLE_NS: &str = "urn:xmpp:jingle:1";
pub(crate) const JMI_NS: &str = "urn:xmpp:jingle-message:0";
const RTP_INFO_NS: &str = "urn:xmpp:jingle:apps:rtp:info:1";

const MAX_CONTENTS: usize = 16;
const MAX_JMI_DESCRIPTIONS: usize = 8;
const MAX_TOKEN_BYTES: usize = 1024;

const ACTIONS: &[&str] = &[
    "content-accept",
    "content-add",
    "content-modify",
    "content-reject",
    "content-remove",
    "description-info",
    "security-info",
    "session-accept",
    "session-info",
    "session-initiate",
    "session-terminate",
    "transport-accept",
    "transport-info",
    "transport-reject",
    "transport-replace",
];

fn valid_bounded_string(value: Option<&str>) -> bool {
    value.is_some_and(|value| {
        !value.trim().is_empty()
            && value.len() <= MAX_TOKEN_BYTES
            && !value.chars().any(char::is_control)
    })
}

// XEP-0166 declares the session identifier as xs:NMTOKEN.  This deliberately
// differs from the free-form content/proposal identifiers: whitespace is not
// legal in an NMTOKEN, while ':' is.
fn valid_nmtoken(value: Option<&str>) -> bool {
    value.is_some_and(|value| {
        !value.is_empty()
            && value.len() <= MAX_TOKEN_BYTES
            && value
                .chars()
                .all(|character| xml_name_char(character, true))
    })
}

// XML 1.0 (Fifth Edition), productions [4] NameStartChar and [4a]
// NameChar.  `xs:NMTOKEN` accepts any non-empty sequence of NameChar, while
// `xs:NCName` uses the same grammar with ':' excluded.  Using Unicode's broad
// alphabetic/numeric predicates here is both under- and over-inclusive (for
// example, combining marks and U+00B7 are legal NameChar values).
fn xml_name_start_char(character: char, allow_colon: bool) -> bool {
    (allow_colon && character == ':')
        || character == '_'
        || character.is_ascii_alphabetic()
        || matches!(character,
            '\u{00C0}'..='\u{00D6}'
            | '\u{00D8}'..='\u{00F6}'
            | '\u{00F8}'..='\u{02FF}'
            | '\u{0370}'..='\u{037D}'
            | '\u{037F}'..='\u{1FFF}'
            | '\u{200C}'..='\u{200D}'
            | '\u{2070}'..='\u{218F}'
            | '\u{2C00}'..='\u{2FEF}'
            | '\u{3001}'..='\u{D7FF}'
            | '\u{F900}'..='\u{FDCF}'
            | '\u{FDF0}'..='\u{FFFD}'
            | '\u{10000}'..='\u{EFFFF}'
        )
}

fn xml_name_char(character: char, allow_colon: bool) -> bool {
    xml_name_start_char(character, allow_colon)
        || character.is_ascii_digit()
        || matches!(character, '-' | '.' | '\u{00B7}' | '\u{0300}'..='\u{036F}' | '\u{203F}'..='\u{2040}')
}

fn valid_ice_foundation(value: Option<&str>) -> bool {
    value.is_some_and(|value| {
        !value.is_empty()
            && value.len() <= 32
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/'))
    })
}

fn valid_ncname(value: Option<&str>) -> bool {
    value.is_some_and(|value| {
        let mut characters = value.chars();
        let Some(first) = characters.next() else {
            return false;
        };
        value.len() <= MAX_TOKEN_BYTES
            && xml_name_start_char(first, false)
            && characters.all(|character| xml_name_char(character, false))
    })
}

fn full_jid(value: &str) -> Option<String> {
    let canonical = crate::jid::canonicalize(value).ok()?;
    crate::jid::CanonicalJid::parse(&canonical)
        .ok()?
        .resourcepart()?;
    Some(canonical)
}

fn extension_namespace(node: Node<'_, '_>) -> bool {
    node.tag_name()
        .namespace()
        .is_some_and(|namespace| namespace != JINGLE_NS)
}

fn has_non_whitespace_text(node: Node<'_, '_>) -> bool {
    node.children()
        .any(|child| child.is_text() && child.text().is_some_and(|text| !text.trim().is_empty()))
}

fn validate_rtp_description(description: Node<'_, '_>) -> Result<(), &'static str> {
    if !valid_ncname(description.attribute("media"))
        || description.attributes().any(|attribute| {
            attribute.namespace().is_none() && !matches!(attribute.name(), "media" | "ssrc")
        })
        || description
            .attribute("ssrc")
            .is_some_and(|ssrc| ssrc.parse::<u32>().is_err())
        || has_non_whitespace_text(description)
    {
        return Err("bad-request");
    }
    let payloads = description
        .children()
        .filter(|child| {
            child.is_element()
                && child.tag_name().name() == "payload-type"
                && child.tag_name().namespace() == description.tag_name().namespace()
        })
        .collect::<Vec<_>>();
    if payloads.len() > 128 {
        return Err("bad-request");
    }
    let mut payload_ids = HashSet::new();
    for payload in payloads {
        let Some(id) = payload
            .attribute("id")
            .and_then(|id| id.parse::<u8>().ok())
            .filter(|id| *id <= 127)
        else {
            return Err("bad-request");
        };
        if !payload_ids.insert(id)
            || payload.attributes().any(|attribute| {
                attribute.namespace().is_none()
                    && !matches!(
                        attribute.name(),
                        "channels" | "clockrate" | "id" | "maxptime" | "name" | "ptime"
                    )
            })
            || payload.attribute("name").is_some_and(|name| {
                name.is_empty() || name.len() > 128 || name.chars().any(char::is_control)
            })
            || (id >= 96 && payload.attribute("name").is_none())
            || has_non_whitespace_text(payload)
            || payload
                .attribute("channels")
                .is_some_and(|value| value.parse::<u8>().ok().is_none_or(|value| value == 0))
            || ["clockrate", "maxptime", "ptime"].iter().any(|name| {
                payload
                    .attribute(*name)
                    .is_some_and(|value| value.parse::<u32>().ok().is_none_or(|value| value == 0))
            })
        {
            return Err("bad-request");
        }
        for child in payload.children().filter(|child| child.is_element()) {
            if child.tag_name().namespace() == description.tag_name().namespace()
                && child.tag_name().name() == "parameter"
            {
                if child.attributes().any(|attribute| {
                    attribute.namespace().is_none() && !matches!(attribute.name(), "name" | "value")
                }) || child.attribute("name").is_none_or(|name| {
                    name.is_empty() || name.len() > 128 || name.chars().any(char::is_control)
                }) || child
                    .attribute("value")
                    .is_none_or(|value| value.len() > 512 || value.chars().any(char::is_control))
                    || child.children().any(|nested| nested.is_element())
                    || child.text().is_some_and(|text| !text.trim().is_empty())
                {
                    return Err("bad-request");
                }
            } else if child.tag_name().namespace() == description.tag_name().namespace() {
                return Err("feature-not-implemented");
            }
        }
    }

    let mut bandwidths = 0usize;
    let mut encryptions = 0usize;
    let mut rtcp_muxes = 0usize;
    for child in description.children().filter(|child| child.is_element()) {
        if child.tag_name().namespace() != description.tag_name().namespace()
            || child.tag_name().name() == "payload-type"
        {
            continue;
        }
        match child.tag_name().name() {
            "bandwidth" => {
                bandwidths += 1;
                if child
                    .attributes()
                    .any(|attribute| attribute.name() != "type")
                    || !valid_ncname(child.attribute("type"))
                    || child
                        .text()
                        .map(str::trim)
                        .and_then(|value| value.parse::<u64>().ok())
                        .is_none()
                    || child.children().any(|nested| nested.is_element())
                {
                    return Err("bad-request");
                }
            }
            "rtcp-mux" => {
                rtcp_muxes += 1;
                if child.attributes().len() != 0
                    || child.children().any(|nested| nested.is_element())
                    || child.text().is_some_and(|text| !text.trim().is_empty())
                {
                    return Err("bad-request");
                }
            }
            "encryption" => {
                encryptions += 1;
                if child
                    .attributes()
                    .any(|attribute| attribute.name() != "required")
                    || child
                        .attribute("required")
                        .is_some_and(|value| !matches!(value, "true" | "false" | "0" | "1"))
                    || has_non_whitespace_text(child)
                {
                    return Err("bad-request");
                }
                let cryptos = child
                    .children()
                    .filter(|nested| nested.is_element())
                    .collect::<Vec<_>>();
                if cryptos.is_empty()
                    || cryptos.len() > 32
                    || cryptos.iter().any(|crypto| {
                        crypto.tag_name().namespace() != description.tag_name().namespace()
                            || crypto.tag_name().name() != "crypto"
                            || crypto.attributes().any(|attribute| {
                                !matches!(
                                    attribute.name(),
                                    "crypto-suite" | "key-params" | "session-params" | "tag"
                                )
                            })
                            || ["crypto-suite", "key-params", "tag"].iter().any(|name| {
                                crypto.attribute(*name).is_none_or(|value| {
                                    value.is_empty()
                                        || value.len() > 1024
                                        || value.chars().any(char::is_control)
                                })
                            })
                            || crypto
                                .attribute("tag")
                                .and_then(|value| value.parse::<u32>().ok())
                                .is_none()
                            || crypto.attribute("session-params").is_some_and(|value| {
                                value.len() > 1024 || value.chars().any(char::is_control)
                            })
                            || crypto.children().any(|nested| nested.is_element())
                            || has_non_whitespace_text(*crypto)
                    })
                {
                    return Err("bad-request");
                }
            }
            _ => return Err("feature-not-implemented"),
        }
    }
    if bandwidths > 1 || encryptions > 1 || rtcp_muxes > 1 {
        return Err("bad-request");
    }
    Ok(())
}

fn validate_dtls_fingerprint(fingerprint: Node<'_, '_>) -> Result<(), &'static str> {
    let hash = fingerprint.attribute("hash").unwrap_or_default();
    let expected_octets = match hash {
        "sha-256" => 32,
        "sha-384" => 48,
        "sha-512" => 64,
        _ => return Err("not-acceptable"),
    };
    if fingerprint.attributes().any(|attribute| {
        attribute.namespace().is_none() && !matches!(attribute.name(), "hash" | "setup")
    }) || fingerprint
        .attribute("setup")
        .is_none_or(|setup| !matches!(setup, "active" | "passive" | "actpass"))
        || fingerprint.children().any(|child| child.is_element())
    {
        return Err("bad-request");
    }
    let octets = fingerprint
        .text()
        .unwrap_or_default()
        .trim()
        .split(':')
        .collect::<Vec<_>>();
    if octets.len() != expected_octets
        || octets
            .iter()
            .any(|octet| octet.len() != 2 || !octet.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        return Err("bad-request");
    }
    Ok(())
}

fn validate_rtp_session_info(info: Node<'_, '_>) -> Result<(), &'static str> {
    if info.tag_name().namespace() != Some(RTP_INFO_NS)
        || info.children().any(|child| child.is_element())
        || has_non_whitespace_text(info)
    {
        return Err("bad-request");
    }
    match info.tag_name().name() {
        "active" | "hold" | "ringing" | "unhold" => {
            if info.attributes().len() != 0 {
                return Err("bad-request");
            }
        }
        "mute" | "unmute" => {
            if info
                .attribute("creator")
                .is_none_or(|creator| !matches!(creator, "initiator" | "responder"))
                || info.attributes().any(|attribute| {
                    attribute.namespace().is_none()
                        && !matches!(attribute.name(), "creator" | "name")
                })
                || info.attribute("name").is_some_and(|name| {
                    name.len() > MAX_TOKEN_BYTES || name.chars().any(char::is_control)
                })
            {
                return Err("bad-request");
            }
        }
        _ => return Err("feature-not-implemented"),
    }
    Ok(())
}

fn validate_ice_transport(transport: Node<'_, '_>) -> Result<(), &'static str> {
    if has_non_whitespace_text(transport)
        || transport.attributes().any(|attribute| {
            !matches!(attribute.name(), "pwd" | "ufrag")
                || attribute.value().len() > 512
                || attribute.value().chars().any(char::is_control)
        })
    {
        return Err("bad-request");
    }
    let elements = transport
        .children()
        .filter(|child| child.is_element())
        .collect::<Vec<_>>();
    let candidates = transport
        .children()
        .filter(|child| {
            child.is_element()
                && child.tag_name().name() == "candidate"
                && child.tag_name().namespace() == transport.tag_name().namespace()
        })
        .collect::<Vec<_>>();
    if candidates.len() > 256 {
        return Err("resource-constraint");
    }
    if !candidates.is_empty()
        && ["pwd", "ufrag"].iter().any(|name| {
            transport
                .attribute(*name)
                .is_none_or(|value| value.is_empty() || value.chars().any(char::is_whitespace))
        })
    {
        return Err("bad-request");
    }
    let mut candidate_ids = HashSet::new();
    for candidate in candidates {
        if candidate.attributes().any(|attribute| {
            !matches!(
                attribute.name(),
                "component"
                    | "foundation"
                    | "generation"
                    | "id"
                    | "ip"
                    | "network"
                    | "port"
                    | "priority"
                    | "protocol"
                    | "rel-addr"
                    | "rel-port"
                    | "type"
            )
        }) || candidate.children().any(|child| child.is_element())
            || candidate.text().is_some_and(|text| !text.trim().is_empty())
            || !valid_ncname(candidate.attribute("id"))
            || !valid_ice_foundation(candidate.attribute("foundation"))
            || candidate
                .attribute("component")
                .and_then(|value| value.parse::<u8>().ok())
                .is_none_or(|value| value == 0)
            || candidate
                .attribute("generation")
                .and_then(|value| value.parse::<u8>().ok())
                .is_none()
            || candidate
                .attribute("port")
                .and_then(|value| value.parse::<u16>().ok())
                .is_none_or(|value| value == 0)
            || candidate
                .attribute("priority")
                .and_then(|value| value.parse::<u32>().ok())
                .is_none_or(|value| value == 0)
            || candidate
                .attribute("ip")
                .and_then(|value| value.parse::<std::net::IpAddr>().ok())
                .is_none()
            || candidate.attribute("protocol") != Some("udp")
            || candidate
                .attribute("type")
                .is_none_or(|kind| !matches!(kind, "host" | "prflx" | "srflx" | "relay"))
            || candidate
                .attribute("network")
                .is_some_and(|value| value.parse::<u8>().is_err())
            || candidate
                .attribute("rel-addr")
                .is_some_and(|value| value.parse::<std::net::IpAddr>().is_err())
            || candidate
                .attribute("rel-port")
                .is_some_and(|value| value.parse::<u16>().ok().is_none_or(|port| port == 0))
            || candidate.attribute("rel-addr").is_some()
                != candidate.attribute("rel-port").is_some()
        {
            return Err("bad-request");
        }
        if !candidate_ids.insert(candidate.attribute("id").unwrap_or_default()) {
            return Err("bad-request");
        }
    }
    let remote_candidates = elements
        .iter()
        .filter(|node| {
            node.tag_name().name() == "remote-candidate"
                && node.tag_name().namespace() == transport.tag_name().namespace()
        })
        .collect::<Vec<_>>();
    if remote_candidates.len() > 1
        || (!remote_candidates.is_empty()
            && elements.iter().any(|node| {
                node.tag_name().name() == "candidate"
                    && node.tag_name().namespace() == transport.tag_name().namespace()
            }))
        || remote_candidates.iter().any(|candidate| {
            candidate
                .attributes()
                .any(|attribute| !matches!(attribute.name(), "component" | "ip" | "port"))
                || candidate
                    .attribute("component")
                    .and_then(|value| value.parse::<u8>().ok())
                    .is_none_or(|value| value == 0)
                || candidate
                    .attribute("ip")
                    .and_then(|value| value.parse::<std::net::IpAddr>().ok())
                    .is_none()
                || candidate
                    .attribute("port")
                    .and_then(|value| value.parse::<u16>().ok())
                    .is_none_or(|value| value == 0)
                || candidate.children().any(|child| child.is_element())
                || candidate.text().is_some_and(|text| !text.trim().is_empty())
        })
    {
        return Err("bad-request");
    }
    let fingerprints = transport
        .children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().name() == "fingerprint"
                && node.tag_name().namespace() == Some("urn:xmpp:jingle:apps:dtls:0")
        })
        .collect::<Vec<_>>();
    if fingerprints.len() > 1 {
        return Err("bad-request");
    }
    for fingerprint in &fingerprints {
        validate_dtls_fingerprint(*fingerprint)?;
    }
    let sctp_maps = transport
        .children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().name() == "sctpmap"
                && node.tag_name().namespace() == Some("urn:xmpp:jingle:transports:dtls-sctp:1")
        })
        .collect::<Vec<_>>();
    if sctp_maps.len() > 1
        || sctp_maps.iter().any(|map| {
            map.attributes()
                .any(|attribute| !matches!(attribute.name(), "number" | "protocol" | "streams"))
                || map
                    .attribute("streams")
                    .is_some_and(|value| value.parse::<u32>().ok().is_none_or(|value| value == 0))
                || map.children().any(|child| child.is_element())
                || map.text().is_some_and(|text| !text.trim().is_empty())
                || map
                    .attribute("number")
                    .and_then(|value| value.parse::<u16>().ok())
                    .is_none_or(|value| value == 0)
                || map.attribute("protocol") != Some("webrtc-datachannel")
        })
    {
        return Err("bad-request");
    }
    let channels = transport
        .children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().name() == "channel"
                && node.tag_name().namespace()
                    == Some("urn:xmpp:jingle:transports:webrtc-datachannel:0")
        })
        .collect::<Vec<_>>();
    if channels.len() > 256 {
        return Err("resource-constraint");
    }
    if (!sctp_maps.is_empty() && fingerprints.len() != 1)
        || (!channels.is_empty() && sctp_maps.len() != 1)
        || channels.iter().any(|channel| {
            channel.attributes().any(|attribute| {
                !matches!(
                    attribute.name(),
                    "id" | "maxPacketLifeTime"
                        | "maxRetransmits"
                        | "negotiated"
                        | "ordered"
                        | "protocol"
                )
            }) || ["id", "maxPacketLifeTime", "maxRetransmits"]
                .iter()
                .any(|name| {
                    channel
                        .attribute(*name)
                        .is_some_and(|value| value.parse::<u16>().is_err())
                })
                || ["negotiated", "ordered"].iter().any(|name| {
                    channel
                        .attribute(*name)
                        .is_some_and(|value| !matches!(value, "true" | "false" | "0" | "1"))
                })
                || channel
                    .attribute("protocol")
                    .is_some_and(|value| value.len() > 256 || value.chars().any(char::is_control))
                || (channel.attribute("maxPacketLifeTime").is_some()
                    && channel.attribute("maxRetransmits").is_some())
                || channel.children().any(|child| child.is_element())
                || channel.text().is_some_and(|text| !text.trim().is_empty())
        })
    {
        return Err("bad-request");
    }
    let mut channel_ids = HashSet::new();
    if channels
        .iter()
        .filter_map(|channel| channel.attribute("id"))
        .any(|id| !channel_ids.insert(id))
    {
        return Err("bad-request");
    }
    let known = elements.iter().filter(|node| {
        matches!(
            (node.tag_name().namespace(), node.tag_name().name()),
            (
                Some("urn:xmpp:jingle:transports:ice-udp:1"),
                "candidate" | "remote-candidate"
            ) | (Some("urn:xmpp:jingle:apps:dtls:0"), "fingerprint")
                | (Some("urn:xmpp:jingle:transports:dtls-sctp:1"), "sctpmap")
                | (
                    Some("urn:xmpp:jingle:transports:webrtc-datachannel:0"),
                    "channel"
                )
        )
    });
    if known.count() != elements.len() {
        return Err("feature-not-implemented");
    }
    Ok(())
}

fn validate_content(content: Node<'_, '_>, action: &str) -> Result<(), &'static str> {
    if content.tag_name().name() != "content"
        || content.tag_name().namespace() != Some(JINGLE_NS)
        || content
            .attribute("creator")
            .is_none_or(|creator| !matches!(creator, "initiator" | "responder"))
        || !valid_bounded_string(content.attribute("name"))
        || content
            .attribute("senders")
            .is_some_and(|senders| !matches!(senders, "both" | "initiator" | "none" | "responder"))
        || content
            .attribute("disposition")
            .is_some_and(|disposition| !valid_ncname(Some(disposition)))
        || has_non_whitespace_text(content)
        || content.attributes().any(|attribute| {
            !matches!(
                attribute.name(),
                "creator" | "disposition" | "name" | "senders"
            )
        })
    {
        return Err("bad-request");
    }
    let descriptions = content
        .children()
        .filter(|child| child.is_element() && child.tag_name().name() == "description")
        .collect::<Vec<_>>();
    let transports = content
        .children()
        .filter(|child| child.is_element() && child.tag_name().name() == "transport")
        .collect::<Vec<_>>();
    let securities = content
        .children()
        .filter(|child| child.is_element() && child.tag_name().name() == "security")
        .collect::<Vec<_>>();
    let extensions = content
        .children()
        .filter(|child| child.is_element())
        .count();
    if descriptions.len() > 1
        || transports.len() > 1
        || securities.len() > 1
        || descriptions.len() + transports.len() + securities.len() != extensions
    {
        return Err("bad-request");
    }
    for description in &descriptions {
        if !extension_namespace(*description) {
            return Err("bad-request");
        }
        if description.tag_name().namespace() == Some("urn:xmpp:jingle:apps:rtp:1") {
            validate_rtp_description(*description)?;
        }
    }
    for transport in &transports {
        if !extension_namespace(*transport) {
            return Err("bad-request");
        }
        if transport.tag_name().namespace() == Some("urn:xmpp:jingle:transports:ice-udp:1") {
            validate_ice_transport(*transport)?;
        }
    }
    if securities
        .iter()
        .any(|security| !extension_namespace(*security))
    {
        return Err("bad-request");
    }
    match action {
        "session-initiate" | "session-accept" | "content-add" => {
            if descriptions.len() != 1 || transports.len() != 1 {
                return Err("bad-request");
            }
        }
        "description-info" if descriptions.len() != 1 => return Err("bad-request"),
        "transport-info" | "transport-replace" | "transport-accept" if transports.len() != 1 => {
            return Err("bad-request");
        }
        "security-info" if securities.len() != 1 => return Err("bad-request"),
        "content-modify" if content.attribute("senders").is_none() => {
            return Err("bad-request");
        }
        _ => {}
    }
    Ok(())
}

fn validate_reason(reason: Node<'_, '_>) -> Result<(), &'static str> {
    if reason.tag_name().name() != "reason" || reason.tag_name().namespace() != Some(JINGLE_NS) {
        return Err("bad-request");
    }
    let children = reason
        .children()
        .filter(|child| child.is_element())
        .collect::<Vec<_>>();
    let text = children
        .iter()
        .filter(|child| {
            child.tag_name().name() == "text" && child.tag_name().namespace() == Some(JINGLE_NS)
        })
        .collect::<Vec<_>>();
    let conditions = children
        .iter()
        .filter(|child| {
            child.tag_name().namespace() == Some(JINGLE_NS) && child.tag_name().name() != "text"
        })
        .collect::<Vec<_>>();
    let details = children
        .iter()
        .filter(|child| child.tag_name().namespace() != Some(JINGLE_NS))
        .collect::<Vec<_>>();
    if text.len() > 1
        || text.first().is_some_and(|text| {
            text.text().is_some_and(|value| value.len() > 1024)
                || text.attributes().len() != 0
                || text.children().any(|nested| nested.is_element())
        })
        || conditions.len() != 1
        || details.len() > 1
        || details
            .first()
            .is_some_and(|detail| detail.tag_name().namespace().is_none())
        || has_non_whitespace_text(reason)
    {
        return Err("bad-request");
    }
    let condition = conditions[0];
    let mut expected_index = 1;
    if children.get(expected_index).is_some_and(|child| {
        child.tag_name().name() == "text" && child.tag_name().namespace() == Some(JINGLE_NS)
    }) {
        expected_index += 1;
    }
    if children
        .get(expected_index)
        .is_some_and(|child| child.tag_name().namespace() != Some(JINGLE_NS))
    {
        expected_index += 1;
    }
    if children.first() != Some(condition) || expected_index != children.len() {
        return Err("bad-request");
    }
    if !matches!(
        condition.tag_name().name(),
        "alternative-session"
            | "busy"
            | "cancel"
            | "connectivity-error"
            | "decline"
            | "expired"
            | "failed-application"
            | "failed-transport"
            | "general-error"
            | "gone"
            | "incompatible-parameters"
            | "media-error"
            | "security-error"
            | "success"
            | "timeout"
            | "unsupported-applications"
            | "unsupported-transports"
    ) || condition.attributes().len() != 0
    {
        return Err("bad-request");
    }
    if condition.tag_name().name() == "alternative-session" {
        let sids = condition
            .children()
            .filter(|child| child.is_element())
            .collect::<Vec<_>>();
        if sids.len() > 1
            || sids.first().is_some_and(|sid| {
                sid.tag_name().name() != "sid"
                    || sid.tag_name().namespace() != Some(JINGLE_NS)
                    || !valid_nmtoken(sid.text())
                    || sid.attributes().len() != 0
                    || sid.children().any(|nested| nested.is_element())
            })
        {
            return Err("bad-request");
        }
    } else if condition.children().any(|child| child.is_element())
        || condition
            .text()
            .is_some_and(|value| !value.trim().is_empty())
    {
        return Err("bad-request");
    }
    Ok(())
}

/// Validate server-visible XEP-0166 signalling without acting as a Jingle
/// endpoint. The raw IQ remains client asserted and is routed unchanged apart
/// from the ordinary authenticated `from` rewrite.
pub(crate) fn validate_jingle_iq(
    root: Node<'_, '_>,
    jingle: Node<'_, '_>,
    authenticated_from: Option<&str>,
) -> Result<(), &'static str> {
    if root.attribute("type") != Some("set")
        || jingle.tag_name().name() != "jingle"
        || jingle.tag_name().namespace() != Some(JINGLE_NS)
    {
        return Err("bad-request");
    }
    let from = root
        .attribute("from")
        .or(authenticated_from)
        .and_then(full_jid);
    let to = root.attribute("to").and_then(full_jid);
    let (Some(from), Some(to)) = (from, to) else {
        return Err("bad-request");
    };
    let Some(action) = jingle
        .attribute("action")
        .filter(|action| ACTIONS.contains(action))
    else {
        return Err("bad-request");
    };
    if !valid_nmtoken(jingle.attribute("sid"))
        || has_non_whitespace_text(jingle)
        || jingle.attributes().any(|attribute| {
            !matches!(
                attribute.name(),
                "action" | "initiator" | "responder" | "sid"
            )
        })
    {
        return Err("bad-request");
    }
    let initiator = match jingle.attribute("initiator") {
        Some(value) => Some(full_jid(value).ok_or("jid-malformed")?),
        None => None,
    };
    let responder = match jingle.attribute("responder") {
        Some(value) => Some(full_jid(value).ok_or("jid-malformed")?),
        None => None,
    };
    // XEP-0166 explicitly permits call managers, relays and transfer
    // controllers to name an initiator/responder different from the IQ
    // sender. The receiving endpoint, which has the session state and trust
    // policy, decides whether to honor that delegation; a routing server must
    // not reject it merely because the JIDs differ.
    let _ = (from, to, initiator, responder);
    let contents = jingle
        .children()
        .filter(|child| child.is_element() && child.tag_name().name() == "content")
        .collect::<Vec<_>>();
    let reasons = jingle
        .children()
        .filter(|child| {
            child.is_element()
                && child.tag_name().name() == "reason"
                && child.tag_name().namespace() == Some(JINGLE_NS)
        })
        .collect::<Vec<_>>();
    let non_contents = jingle
        .children()
        .filter(|child| {
            child.is_element()
                && child.tag_name().name() != "content"
                && !(child.tag_name().name() == "reason"
                    && child.tag_name().namespace() == Some(JINGLE_NS))
        })
        .collect::<Vec<_>>();
    if contents.len() > MAX_CONTENTS {
        return Err("resource-constraint");
    }
    if reasons.len() > 1 {
        return Err("bad-request");
    }
    if let Some(reason) = reasons.first() {
        validate_reason(*reason)?;
    }
    if matches!(action, "session-info" | "session-terminate") {
        if !contents.is_empty() {
            return Err("bad-request");
        }
    } else if contents.is_empty() || !non_contents.is_empty() {
        return Err("bad-request");
    }
    if action == "session-terminate" && !non_contents.is_empty() {
        return Err("bad-request");
    }
    if action == "session-info"
        && (non_contents.len() > 16
            || non_contents
                .iter()
                .any(|payload| !extension_namespace(*payload)))
    {
        return Err("bad-request");
    }
    if action == "session-info" {
        for payload in &non_contents {
            if payload.tag_name().namespace() == Some(RTP_INFO_NS) {
                validate_rtp_session_info(*payload)?;
            }
        }
    }
    let mut names = HashSet::new();
    let mut has_session_disposition = false;
    for content in contents {
        validate_content(content, action)?;
        let key = (
            content.attribute("creator").unwrap_or_default(),
            content.attribute("name").unwrap_or_default(),
        );
        if !names.insert(key) {
            return Err("bad-request");
        }
        if content.attribute("disposition").unwrap_or("session") == "session" {
            has_session_disposition = true;
        }
    }
    if action == "session-initiate" && !has_session_disposition {
        return Err("bad-request");
    }
    Ok(())
}

fn validate_jmi_reason_children(
    action: Node<'_, '_>,
    allow_tie_break: bool,
) -> Result<(), &'static str> {
    let elements = action
        .children()
        .filter(|child| child.is_element())
        .collect::<Vec<_>>();
    if elements.len() > usize::from(allow_tie_break) + 1 {
        return Err("bad-request");
    }
    let reasons = elements
        .iter()
        .filter(|child| {
            child.tag_name().name() == "reason" && child.tag_name().namespace() == Some(JINGLE_NS)
        })
        .collect::<Vec<_>>();
    if reasons.len() > 1 {
        return Err("bad-request");
    }
    if let Some(reason) = reasons.first() {
        validate_reason(**reason)?;
    }
    if elements.iter().any(|child| {
        !(child.tag_name().name() == "reason" && child.tag_name().namespace() == Some(JINGLE_NS))
            && !(allow_tie_break
                && child.tag_name().name() == "tie-break"
                && child.tag_name().namespace() == Some(JMI_NS)
                && !child.children().any(|nested| nested.is_element()))
    }) {
        return Err("bad-request");
    }
    if elements.len() == 2
        && !(elements[0].tag_name().name() == "reason"
            && elements[0].tag_name().namespace() == Some(JINGLE_NS)
            && elements[1].tag_name().name() == "tie-break"
            && elements[1].tag_name().namespace() == Some(JMI_NS))
    {
        return Err("bad-request");
    }
    Ok(())
}

/// Validate visible XEP-0353 payloads. Encrypted JMI has no server-visible
/// action child and therefore continues through the normal encrypted-message
/// path without inspection.
pub(crate) fn validate_jmi_message(root: Node<'_, '_>) -> Result<(), &'static str> {
    // RFC 6120 error stanzas carry an unmodified copy of the original
    // payload.  A JMI action in that copy is not a new call action and MUST
    // not be rejected merely because the outer message type is `error`.
    if root.attribute("type") == Some("error") {
        return Ok(());
    }
    let actions = root
        .children()
        .filter(|child| child.is_element() && child.tag_name().namespace() == Some(JMI_NS))
        .collect::<Vec<_>>();
    if actions.is_empty() {
        return Ok(());
    }
    if actions.len() != 1
        || root.attribute("type") != Some("chat")
        || !root.children().any(|child| {
            child.is_element()
                && child.tag_name().name() == "store"
                && child.tag_name().namespace() == Some("urn:xmpp:hints")
        })
    {
        return Err("bad-request");
    }
    let action = actions[0];
    if !matches!(
        action.tag_name().name(),
        "propose" | "proceed" | "retract" | "reject" | "finish" | "ringing"
    ) || !valid_bounded_string(action.attribute("id"))
        || action
            .attributes()
            .any(|attribute| attribute.name() != "id")
        || has_non_whitespace_text(action)
    {
        return Err("bad-request");
    }
    match action.tag_name().name() {
        "propose" => {
            let descriptions = action
                .children()
                .filter(|child| child.is_element())
                .collect::<Vec<_>>();
            if descriptions.is_empty() || descriptions.len() > MAX_JMI_DESCRIPTIONS {
                return Err("bad-request");
            }
            for description in descriptions {
                if description.tag_name().name() != "description"
                    || !extension_namespace(description)
                    || has_non_whitespace_text(description)
                {
                    return Err("bad-request");
                }
                if description.tag_name().namespace() == Some("urn:xmpp:jingle:apps:rtp:1") {
                    validate_rtp_description(description)?;
                }
            }
        }
        "proceed" | "ringing" => {
            if action.children().any(|child| child.is_element()) {
                return Err("bad-request");
            }
        }
        "retract" => validate_jmi_reason_children(action, true)?,
        "reject" => validate_jmi_reason_children(action, true)?,
        "finish" => {
            let migrated = action
                .children()
                .filter(|child| {
                    child.is_element()
                        && child.tag_name().name() == "migrated"
                        && child.tag_name().namespace() == Some(JMI_NS)
                })
                .collect::<Vec<_>>();
            if migrated.len() > 1
                || migrated.first().is_some_and(|migrated| {
                    !valid_bounded_string(migrated.attribute("to"))
                        || migrated
                            .attributes()
                            .any(|attribute| attribute.name() != "to")
                        || migrated.children().any(|child| child.is_element())
                })
            {
                return Err("bad-request");
            }
            let other = action
                .children()
                .filter(|child| child.is_element() && child.tag_name().name() != "migrated")
                .collect::<Vec<_>>();
            if other.len() > 1 {
                return Err("bad-request");
            }
            if let Some(reason) = other.first() {
                validate_reason(*reason)?;
            }
            let elements = action
                .children()
                .filter(|child| child.is_element())
                .collect::<Vec<_>>();
            if elements.len() == 2
                && !(elements[0].tag_name().name() == "reason"
                    && elements[0].tag_name().namespace() == Some(JINGLE_NS)
                    && elements[1].tag_name().name() == "migrated"
                    && elements[1].tag_name().namespace() == Some(JMI_NS))
            {
                return Err("bad-request");
            }
        }
        _ => unreachable!(),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use roxmltree::Document;

    fn validate_iq(xml: &str) -> Result<(), &'static str> {
        let document = Document::parse(xml).unwrap();
        let root = document.root_element();
        validate_jingle_iq(
            root,
            root.children().find(|child| child.is_element()).unwrap(),
            None,
        )
    }

    #[test]
    fn accepts_webrtc_rtp_ice_dtls_negotiation() {
        let fingerprint = (0..32).map(|_| "AA").collect::<Vec<_>>().join(":");
        let xml = format!(
            "<iq xmlns='jabber:client' type='set' id='call' from='alice@example.test/Phone' to='bob@example.test/Laptop'><jingle xmlns='{JINGLE_NS}' action='session-initiate' initiator='alice@example.test/Phone' sid='call-1'><content creator='initiator' name='audio'><description xmlns='urn:xmpp:jingle:apps:rtp:1' media='audio'><payload-type id='111' name='opus'/></description><transport xmlns='urn:xmpp:jingle:transports:ice-udp:1' pwd='secret' ufrag='ufrag'><fingerprint xmlns='urn:xmpp:jingle:apps:dtls:0' hash='sha-256' setup='actpass'>{fingerprint}</fingerprint><candidate component='1' foundation='1' generation='0' id='candidate-1' ip='192.0.2.2' port='50000' priority='2130706431' protocol='udp' type='host'/><sctpmap xmlns='urn:xmpp:jingle:transports:dtls-sctp:1' number='5000' protocol='webrtc-datachannel' streams='16'/></transport></content></jingle></iq>"
        );
        assert_eq!(validate_iq(&xml), Ok(()));
    }

    #[test]
    fn rejects_unknown_action_bare_target_and_malformed_known_transport() {
        for xml in [
            "<iq type='set' id='1' from='alice@example.test/a' to='bob@example.test/b'><jingle xmlns='urn:xmpp:jingle:1' action='invented' sid='s'/></iq>",
            "<iq type='set' id='1' from='alice@example.test/a' to='bob@example.test'><jingle xmlns='urn:xmpp:jingle:1' action='session-info' sid='s'/></iq>",
            "<iq type='set' id='1' from='alice@example.test/a' to='bob@example.test/b'><jingle xmlns='urn:xmpp:jingle:1' action='session-initiate' sid='s'><content creator='initiator' name='a'><description xmlns='urn:xmpp:jingle:apps:rtp:1' media='audio'/><transport xmlns='urn:xmpp:jingle:transports:ice-udp:1'><invented xmlns='urn:example:unknown'/></transport></content></jingle></iq>",
            "<iq type='set' id='1' from='alice@example.test/a' to='bob@example.test/b'><jingle xmlns='urn:xmpp:jingle:1' action='session-initiate' sid='s'><content creator='initiator' name='a'><description xmlns='urn:xmpp:jingle:apps:rtp:1' media='audio'/><transport xmlns='urn:xmpp:jingle:transports:ice-udp:1'><fingerprint xmlns='urn:xmpp:jingle:apps:dtls:0'/><fingerprint xmlns='urn:xmpp:jingle:apps:dtls:0'/></transport></content></jingle></iq>",
        ] {
            assert!(validate_iq(xml).is_err(), "{xml}");
        }
    }

    #[test]
    fn routes_delegated_and_extension_defined_jingle_payloads() {
        for xml in [
            "<iq type='set' id='1' from='manager@example.test/a' to='bob@example.test/b'><jingle xmlns='urn:xmpp:jingle:1' action='session-initiate' initiator='alice@example.test/phone' sid='s'><content creator='initiator' name='file'><description xmlns='urn:xmpp:jingle:apps:file-transfer:5'><file><name>hello.txt</name><size>5</size></file></description><transport xmlns='urn:xmpp:jingle:transports:s5b:1' sid='stream'/><security xmlns='urn:xmpp:jingle:security:xtls:0'><method name='x509'/></security></content></jingle></iq>",
            "<iq type='set' id='2' from='bob@example.test/b' to='alice@example.test/phone'><jingle xmlns='urn:xmpp:jingle:1' action='session-info' sid='s'><received xmlns='urn:xmpp:jingle:apps:file-transfer:5' creator='initiator' name='file'/></jingle></iq>",
            "<iq type='set' id='3' from='bob@example.test/b' to='alice@example.test/phone'><jingle xmlns='urn:xmpp:jingle:1' action='session-info' sid='s'><checksum xmlns='urn:xmpp:jingle:apps:file-transfer:5' creator='initiator' name='file'><file><hash xmlns='urn:xmpp:hashes:2' algo='sha-256'>AA==</hash></file></checksum></jingle></iq>",
        ] {
            assert_eq!(validate_iq(xml), Ok(()), "{xml}");
        }
    }

    #[test]
    fn termination_reason_is_optional_but_strict_when_present() {
        let without_reason = "<iq type='set' id='1' from='alice@example.test/a' to='bob@example.test/b'><jingle xmlns='urn:xmpp:jingle:1' action='session-terminate' sid='s'/></iq>";
        assert_eq!(validate_iq(without_reason), Ok(()));
        for xml in [
            "<iq type='set' id='1' from='alice@example.test/a' to='bob@example.test/b'><jingle xmlns='urn:xmpp:jingle:1' action='session-terminate' sid='s'><reason><invented/></reason></jingle></iq>",
            "<iq type='set' id='1' from='alice@example.test/a' to='bob@example.test/b'><jingle xmlns='urn:xmpp:jingle:1' action='session-terminate' sid='s'><reason><success/><busy/></reason></jingle></iq>",
        ] {
            assert_eq!(validate_iq(xml), Err("bad-request"), "{xml}");
        }
    }

    #[test]
    fn session_ids_are_nmtokens_and_content_modify_requires_senders() {
        let valid = "<iq type='set' id='1' from='alice@example.test/a' to='bob@example.test/b'><jingle xmlns='urn:xmpp:jingle:1' action='content-modify' sid='session:one'><content creator='initiator' name='audio stream' senders='none'/></jingle></iq>";
        assert_eq!(validate_iq(valid), Ok(()));
        let valid_unicode = "<iq type='set' id='1' from='alice@example.test/a' to='bob@example.test/b'><jingle xmlns='urn:xmpp:jingle:1' action='session-info' sid='session·é'><active xmlns='urn:xmpp:jingle:apps:rtp:info:1'/></jingle></iq>";
        assert_eq!(validate_iq(valid_unicode), Ok(()));
        // XEP-0166 recommends, but does not require, a replacement SID for
        // alternative-session (the schema uses minOccurs='0').
        let valid_alternative_without_sid = "<iq type='set' id='1' from='alice@example.test/a' to='bob@example.test/b'><jingle xmlns='urn:xmpp:jingle:1' action='session-terminate' sid='s'><reason><alternative-session/></reason></jingle></iq>";
        assert_eq!(validate_iq(valid_alternative_without_sid), Ok(()));

        for xml in [
            "<iq type='set' id='1' from='alice@example.test/a' to='bob@example.test/b'><jingle xmlns='urn:xmpp:jingle:1' action='content-modify' sid='session:one'><content creator='initiator' name='audio stream'/></jingle></iq>",
            "<iq type='set' id='1' from='alice@example.test/a' to='bob@example.test/b'><jingle xmlns='urn:xmpp:jingle:1' action='content-modify' sid='not a token'><content creator='initiator' name='audio stream' senders='both'/></jingle></iq>",
            "<iq type='set' id='1' from='alice@example.test/a' to='bob@example.test/b'><jingle xmlns='urn:xmpp:jingle:1' action='content-modify' sid='s'><content creator='initiator' name='audio stream' disposition='early session' senders='both'/></jingle></iq>",
            "<iq type='set' id='1' from='alice@example.test/a' to='bob@example.test/b'><jingle xmlns='urn:xmpp:jingle:1' action='session-terminate' sid='s'><reason><alternative-session><sid>not a token</sid></alternative-session></reason></jingle></iq>",
        ] {
            assert_eq!(validate_iq(xml), Err("bad-request"), "{xml}");
        }
    }

    #[test]
    fn reason_is_valid_on_any_action_and_allows_one_application_detail() {
        let valid = "<iq type='set' id='1' from='alice@example.test/a' to='bob@example.test/b'><jingle xmlns='urn:xmpp:jingle:1' action='transport-info' sid='s'><content creator='initiator' name='audio'><transport xmlns='urn:xmpp:jingle:transports:ice-udp:1'/></content><reason><connectivity-error/><text>no candidate pair</text><ice-failure xmlns='urn:example:ice-detail'/></reason></jingle></iq>";
        assert_eq!(validate_iq(valid), Ok(()));

        for xml in [
            "<iq type='set' id='1' from='alice@example.test/a' to='bob@example.test/b'><jingle xmlns='urn:xmpp:jingle:1' action='session-terminate' sid='s'><reason><success/><one xmlns='urn:one'/><two xmlns='urn:two'/></reason></jingle></iq>",
            "<iq type='set' id='1' from='alice@example.test/a' to='bob@example.test/b'><jingle xmlns='urn:xmpp:jingle:1' action='session-terminate' sid='s'><reason><invented/></reason></jingle></iq>",
            "<iq type='set' id='1' from='alice@example.test/a' to='bob@example.test/b'><jingle xmlns='urn:xmpp:jingle:1' action='session-terminate' sid='s'><reason><success/><detail xmlns='urn:example:detail'/><text>out of order</text></reason></jingle></iq>",
        ] {
            assert_eq!(validate_iq(xml), Err("bad-request"), "{xml}");
        }
    }

    #[test]
    fn ice_candidates_require_credentials_and_schema_safe_identifiers() {
        let content = |transport: &str| {
            format!(
                "<iq type='set' id='1' from='alice@example.test/a' to='bob@example.test/b'><jingle xmlns='{JINGLE_NS}' action='session-initiate' sid='s'><content creator='initiator' name='audio'><description xmlns='urn:xmpp:jingle:apps:rtp:1' media='audio'/>{transport}</content></jingle></iq>"
            )
        };
        let candidate = "<candidate component='1' foundation='1' generation='0' id='candidate-1' ip='127.0.0.1' port='50000' priority='1' protocol='udp' type='host'/>";
        assert_eq!(
            validate_iq(&content(&format!(
                "<transport xmlns='urn:xmpp:jingle:transports:ice-udp:1'>{candidate}</transport>"
            ))),
            Err("bad-request")
        );
        // Candidate addresses are opaque end-to-end signalling.  Loopback,
        // private and link-local candidates are valid ICE host candidates;
        // the server validates their syntax but never connects to them.
        assert_eq!(
            validate_iq(&content(&format!(
                "<transport xmlns='urn:xmpp:jingle:transports:ice-udp:1' pwd='p' ufrag='u'>{candidate}</transport>"
            ))),
            Ok(())
        );
        let unicode_id = "<candidate component='1' foundation='1' generation='0' id='é́' ip='192.0.2.1' port='50000' priority='1' protocol='udp' type='host'/>";
        assert_eq!(
            validate_iq(&content(&format!(
                "<transport xmlns='urn:xmpp:jingle:transports:ice-udp:1' pwd='p' ufrag='u'>{unicode_id}</transport>"
            ))),
            Ok(())
        );
        for transport in [
            "<transport xmlns='urn:xmpp:jingle:transports:ice-udp:1' pwd='p' ufrag='u'><candidate component='1' foundation='1' generation='0' id='bad:id' ip='192.0.2.1' port='50000' priority='1' protocol='udp' type='host'/></transport>",
            "<transport xmlns='urn:xmpp:jingle:transports:ice-udp:1' pwd='p' ufrag='u'><candidate component='1' foundation='1' generation='0' id='same' ip='192.0.2.1' port='50000' priority='1' protocol='udp' type='host'/><candidate component='2' foundation='2' generation='0' id='same' ip='192.0.2.1' port='50001' priority='2' protocol='udp' type='host'/></transport>",
            "<transport xmlns='urn:xmpp:jingle:transports:ice-udp:1'><remote-candidate component='1' ip='192.0.2.1' port='50000'>hidden</remote-candidate></transport>",
        ] {
            assert_eq!(
                validate_iq(&content(transport)),
                Err("bad-request"),
                "{transport}"
            );
        }
    }

    #[test]
    fn rtp_payloads_are_bounded_unique_and_extension_safe() {
        let description = |payload: &str| {
            format!(
                "<iq type='set' id='1' from='alice@example.test/a' to='bob@example.test/b'><jingle xmlns='{JINGLE_NS}' action='session-initiate' sid='s'><content creator='initiator' name='media'><description xmlns='urn:xmpp:jingle:apps:rtp:1' media='screen'>{payload}</description><transport xmlns='urn:xmpp:jingle:transports:ice-udp:1'/></content></jingle></iq>"
            )
        };
        assert_eq!(
            validate_iq(&description(
                "<payload-type id='0'/><extension xmlns='urn:example:rtp-extension'/>"
            )),
            Ok(())
        );
        for (payload, condition) in [
            ("<payload-type id='96'/>", "bad-request"),
            (
                "<payload-type id='111' name='opus'/><payload-type id='111' name='duplicate'/>",
                "bad-request",
            ),
            (
                "<payload-type id='111' name='opus' channels='0'/>",
                "bad-request",
            ),
            (
                "<payload-type id='111' name='opus'><parameter value='missing-name'/></payload-type>",
                "bad-request",
            ),
            (
                "<payload-type id='111' name='opus'><parameter name='missing-value'/></payload-type>",
                "bad-request",
            ),
            ("<encryption required='true'/>", "bad-request"),
            ("<invented/>", "feature-not-implemented"),
        ] {
            assert_eq!(
                validate_iq(&description(payload)),
                Err(condition),
                "{payload}"
            );
        }
    }

    #[test]
    fn rtp_session_info_matches_the_current_schema() {
        for xml in [
            "<iq type='set' id='1' from='alice@example.test/a' to='bob@example.test/b'><jingle xmlns='urn:xmpp:jingle:1' action='session-info' sid='s'><active xmlns='urn:xmpp:jingle:apps:rtp:info:1'/></jingle></iq>",
            "<iq type='set' id='1' from='alice@example.test/a' to='bob@example.test/b'><jingle xmlns='urn:xmpp:jingle:1' action='session-info' sid='s'><mute xmlns='urn:xmpp:jingle:apps:rtp:info:1' creator='responder'/></jingle></iq>",
            "<iq type='set' id='1' from='alice@example.test/a' to='bob@example.test/b'><jingle xmlns='urn:xmpp:jingle:1' action='session-info' sid='s'><unmute xmlns='urn:xmpp:jingle:apps:rtp:info:1' creator='initiator' name='audio'/></jingle></iq>",
        ] {
            assert_eq!(validate_iq(xml), Ok(()), "{xml}");
        }
        for (xml, condition) in [
            (
                "<iq type='set' id='1' from='alice@example.test/a' to='bob@example.test/b'><jingle xmlns='urn:xmpp:jingle:1' action='session-info' sid='s'><active xmlns='urn:xmpp:jingle:apps:rtp:info:1' name='audio'/></jingle></iq>",
                "bad-request",
            ),
            (
                "<iq type='set' id='1' from='alice@example.test/a' to='bob@example.test/b'><jingle xmlns='urn:xmpp:jingle:1' action='session-info' sid='s'><mute xmlns='urn:xmpp:jingle:apps:rtp:info:1'/></jingle></iq>",
                "bad-request",
            ),
            (
                "<iq type='set' id='1' from='alice@example.test/a' to='bob@example.test/b'><jingle xmlns='urn:xmpp:jingle:1' action='session-info' sid='s'><invented xmlns='urn:xmpp:jingle:apps:rtp:info:1'/></jingle></iq>",
                "feature-not-implemented",
            ),
        ] {
            assert_eq!(validate_iq(xml), Err(condition), "{xml}");
        }
    }

    #[test]
    fn dtls_and_data_channel_shapes_reject_ambiguous_inputs() {
        let fingerprint = (0..32).map(|_| "AA").collect::<Vec<_>>().join(":");
        let content = |transport_children: &str| {
            format!(
                "<iq type='set' id='1' from='alice@example.test/a' to='bob@example.test/b'><jingle xmlns='{JINGLE_NS}' action='session-initiate' sid='s'><content creator='initiator' name='data'><description xmlns='urn:example:data'/><transport xmlns='urn:xmpp:jingle:transports:ice-udp:1'>{transport_children}</transport></content></jingle></iq>"
            )
        };
        for children in [
            format!("<fingerprint xmlns='urn:xmpp:jingle:apps:dtls:0' hash='sha-256' setup='actpass' invented='1'>{fingerprint}</fingerprint>"),
            format!("<fingerprint xmlns='urn:xmpp:jingle:apps:dtls:0' hash='sha-256' setup='actpass'>{fingerprint}<nested/></fingerprint>"),
            "<sctpmap xmlns='urn:xmpp:jingle:transports:dtls-sctp:1' port='5000' protocol='webrtc-datachannel'/>".to_owned(),
            "<sctpmap xmlns='urn:xmpp:jingle:transports:dtls-sctp:1' number='5000' protocol='webrtc-datachannel'/>".to_owned(),
            "<sctpmap xmlns='urn:xmpp:jingle:transports:dtls-sctp:1' number='5000' protocol='webrtc-datachannel'/><channel xmlns='urn:xmpp:jingle:transports:webrtc-datachannel:0' id='1' maxPacketLifeTime='10' maxRetransmits='1'/>".to_owned(),
            format!("<fingerprint xmlns='urn:xmpp:jingle:apps:dtls:0' hash='sha-256' setup='actpass'>{fingerprint}</fingerprint><sctpmap xmlns='urn:xmpp:jingle:transports:dtls-sctp:1' number='5000' protocol='webrtc-datachannel'/><channel xmlns='urn:xmpp:jingle:transports:webrtc-datachannel:0' id='1'/><channel xmlns='urn:xmpp:jingle:transports:webrtc-datachannel:0' id='1'/>")
        ] {
            assert_eq!(validate_iq(&content(&children)), Err("bad-request"), "{children}");
        }
    }

    #[test]
    fn jmi_requires_chat_store_one_action_and_supported_descriptions() {
        let valid = Document::parse(
            "<message type='chat' from='alice@example.test/a' to='bob@example.test'><propose xmlns='urn:xmpp:jingle-message:0' id='call-1'><description xmlns='urn:xmpp:jingle:apps:rtp:1' media='audio'/></propose><store xmlns='urn:xmpp:hints'/></message>",
        )
        .unwrap();
        assert_eq!(validate_jmi_message(valid.root_element()), Ok(()));
        for xml in [
            "<message type='normal'><ringing xmlns='urn:xmpp:jingle-message:0' id='call-1'/><store xmlns='urn:xmpp:hints'/></message>",
            "<message type='chat'><ringing xmlns='urn:xmpp:jingle-message:0' id='call-1'/></message>",
            "<message type='chat'><ringing xmlns='urn:xmpp:jingle-message:0' id='call-1'/><reject xmlns='urn:xmpp:jingle-message:0' id='call-1'/><store xmlns='urn:xmpp:hints'/></message>",
        ] {
            let document = Document::parse(xml).unwrap();
            assert!(
                validate_jmi_message(document.root_element()).is_err(),
                "{xml}"
            );
        }
        let extension = Document::parse(
            "<message type='chat'><propose xmlns='urn:xmpp:jingle-message:0' id='call-1'><description xmlns='urn:example:future-app'/></propose><store xmlns='urn:xmpp:hints'/></message>",
        )
        .unwrap();
        assert_eq!(validate_jmi_message(extension.root_element()), Ok(()));
    }

    #[test]
    fn jmi_accepts_tie_break_retract_and_session_id_migration() {
        for xml in [
            "<message type='chat'><retract xmlns='urn:xmpp:jingle-message:0' id='old'><reason xmlns='urn:xmpp:jingle:1'><expired/></reason><tie-break/></retract><store xmlns='urn:xmpp:hints'/></message>",
            "<message type='chat'><finish xmlns='urn:xmpp:jingle-message:0' id='old'><reason xmlns='urn:xmpp:jingle:1'><expired/></reason><migrated to='new-session-id'/></finish><store xmlns='urn:xmpp:hints'/></message>",
        ] {
            let document = Document::parse(xml).unwrap();
            assert_eq!(
                validate_jmi_message(document.root_element()),
                Ok(()),
                "{xml}"
            );
        }
        for xml in [
            "<message type='chat'><reject xmlns='urn:xmpp:jingle-message:0' id='old'><tie-break/><reason xmlns='urn:xmpp:jingle:1'><expired/></reason></reject><store xmlns='urn:xmpp:hints'/></message>",
            "<message type='chat'><finish xmlns='urn:xmpp:jingle-message:0' id='old'><migrated to='new'/><reason xmlns='urn:xmpp:jingle:1'><expired/></reason></finish><store xmlns='urn:xmpp:hints'/></message>",
        ] {
            let document = Document::parse(xml).unwrap();
            assert_eq!(
                validate_jmi_message(document.root_element()),
                Err("bad-request"),
                "{xml}"
            );
        }
    }

    #[test]
    fn encrypted_signalling_envelopes_remain_opaque() {
        let document = Document::parse(
            "<message type='chat'><encrypted xmlns='urn:xmpp:omemo:2'><payload><propose xmlns='urn:xmpp:jingle-message:0' id='opaque'/></payload></encrypted></message>",
        )
        .unwrap();
        assert_eq!(validate_jmi_message(document.root_element()), Ok(()));

        let error = Document::parse(
            "<message type='error'><propose xmlns='urn:xmpp:jingle-message:0' id='call'><description xmlns='urn:xmpp:jingle:apps:rtp:1' media='audio'/></propose><store xmlns='urn:xmpp:hints'/><error xmlns='jabber:client' type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></message>",
        )
        .unwrap();
        assert_eq!(validate_jmi_message(error.root_element()), Ok(()));
    }
}
