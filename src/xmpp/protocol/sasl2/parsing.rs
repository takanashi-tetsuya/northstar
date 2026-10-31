//! Validate and parse stream openings, including stream capture and errors.

use super::*;

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
