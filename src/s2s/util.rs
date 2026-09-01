use crate::xmpp::framing::XmlEntityFramer;
use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;

/// The hard stanza-size boundary enforced by every S2S reader.  Keep the
/// XEP-0478 advertisement and the actual framing limit tied to one constant.
pub(crate) const S2S_MAX_STANZA_BYTES: usize = 1024 * 1024;
pub(crate) const S2S_AUTHENTICATED_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Incremental input state for one S2S XML entity.
///
/// The declaration-placement state must outlive an individual socket read and
/// an individual stanza. Otherwise a peer can send a second XML declaration
/// after the first frame has been drained and have it mistaken for the start
/// of a new entity. The same state also preserves coalesced frames which were
/// read together with stream features or an authentication response.
#[derive(Debug, Default)]
pub(crate) struct S2sInputState {
    buffer: String,
    pending_utf8: Vec<u8>,
    framer: XmlEntityFramer,
}

impl S2sInputState {
    /// Start a genuinely new XML entity after TLS or successful legacy SASL.
    /// Bytes from the previous negotiation entity cannot be reinterpreted in
    /// the new security context.
    pub(crate) fn reset_entity(&mut self) {
        self.buffer.clear();
        self.pending_utf8.clear();
        self.framer.reset_entity();
    }
}

#[derive(Debug, thiserror::Error)]
enum S2sReadError {
    #[error("S2S stream ended unexpectedly")]
    Ended,
    #[error("S2S stream is not UTF-8")]
    InvalidUtf8,
    #[error("S2S frame exceeds the configured byte limit")]
    FrameTooLarge,
    #[error("S2S negotiation frame exceeded its total deadline")]
    NegotiationTimedOut,
}

pub(crate) fn s2s_read_stream_error_condition(error: &anyhow::Error) -> Option<&'static str> {
    match error.downcast_ref::<S2sReadError>() {
        Some(S2sReadError::Ended) => None,
        Some(S2sReadError::FrameTooLarge) => Some("policy-violation"),
        Some(S2sReadError::InvalidUtf8) => Some("unsupported-encoding"),
        Some(S2sReadError::NegotiationTimedOut) => Some("connection-timeout"),
        None if error.downcast_ref::<std::io::Error>().is_some() => None,
        None => Some(crate::xmpp::framing::stream_error_condition(error)),
    }
}

pub(crate) async fn timed_read_frame<S: AsyncRead + Unpin>(
    stream: &mut S,
    input: &mut S2sInputState,
) -> Result<String> {
    // Negotiation has a fixed wall-clock budget. Reusing the established-
    // stream idle reader here used to refresh this deadline after every byte,
    // allowing a slow peer to occupy one of the global S2S connection permits
    // indefinitely by dripping an incomplete stream header or SASL frame.
    let deadline = tokio::time::Instant::now() + IO_TIMEOUT;
    match read_frame_until_deadline(stream, input, deadline).await? {
        Some(frame) => Ok(frame),
        None => Err(S2sReadError::NegotiationTimedOut.into()),
    }
}

async fn read_frame_until_deadline<S: AsyncRead + Unpin>(
    stream: &mut S,
    input: &mut S2sInputState,
    deadline: tokio::time::Instant,
) -> Result<Option<String>> {
    let mut bytes = [0u8; 8192];
    loop {
        if let Some(frame) = input.framer.take_frame(&mut input.buffer)? {
            return Ok(Some(frame));
        }
        let count = match tokio::time::timeout_at(deadline, stream.read(&mut bytes)).await {
            Ok(read) => read?,
            Err(_) => return Ok(None),
        };
        if count == 0 {
            return Err(S2sReadError::Ended.into());
        }
        append_s2s_input(&mut input.buffer, &mut input.pending_utf8, &bytes[..count])?;
    }
}

pub(crate) async fn read_entity_frame<S: AsyncRead + Unpin>(
    stream: &mut S,
    input: &mut S2sInputState,
) -> Result<String> {
    let mut bytes = [0u8; 8192];
    loop {
        if let Some(frame) = input.framer.take_frame(&mut input.buffer)? {
            return Ok(frame);
        }
        let count = stream.read(&mut bytes).await?;
        if count == 0 {
            return Err(S2sReadError::Ended.into());
        }
        append_s2s_input(&mut input.buffer, &mut input.pending_utf8, &bytes[..count])?;
    }
}

/// Read one complete frame while treating every received byte, including XML
/// whitespace keepalives and a fragmented stanza, as stream activity.  This
/// matches XEP-0478's `idle-seconds` definition instead of timing the total
/// wall-clock duration required to assemble a stanza.
#[cfg(test)]
pub(crate) async fn read_frame_until_idle<S: AsyncRead + Unpin>(
    stream: &mut S,
    input: &mut S2sInputState,
    idle_timeout: Duration,
) -> Result<Option<String>> {
    let mut idle_deadline = tokio::time::Instant::now() + idle_timeout;
    read_frame_until_idle_deadline(stream, input, idle_timeout, &mut idle_deadline).await
}

/// Cancellation-safe XEP-0478 reader for use in `select!` loops. The caller
/// owns the deadline, so a local write/queue event that cancels this future
/// cannot accidentally grant the peer a fresh idle window. Only bytes read
/// from the peer advance the deadline.
pub(crate) async fn read_frame_until_idle_deadline<S: AsyncRead + Unpin>(
    stream: &mut S,
    input: &mut S2sInputState,
    idle_timeout: Duration,
    idle_deadline: &mut tokio::time::Instant,
) -> Result<Option<String>> {
    let mut bytes = [0u8; 8192];
    loop {
        if let Some(frame) = input.framer.take_frame(&mut input.buffer)? {
            return Ok(Some(frame));
        }
        let count = match tokio::time::timeout_at(*idle_deadline, stream.read(&mut bytes)).await {
            Ok(read) => read?,
            Err(_) => return Ok(None),
        };
        if count == 0 {
            return Err(S2sReadError::Ended.into());
        }
        *idle_deadline = tokio::time::Instant::now() + idle_timeout;
        append_s2s_input(&mut input.buffer, &mut input.pending_utf8, &bytes[..count])?;
    }
}

fn append_s2s_input(buffer: &mut String, pending_utf8: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    pending_utf8.extend_from_slice(bytes);
    match std::str::from_utf8(pending_utf8) {
        Ok(text) => {
            buffer.push_str(text);
            pending_utf8.clear();
        }
        Err(error) if error.error_len().is_none() => {
            let valid = error.valid_up_to();
            buffer.push_str(
                std::str::from_utf8(&pending_utf8[..valid]).context("invalid S2S UTF-8 prefix")?,
            );
            pending_utf8.drain(..valid);
        }
        Err(_) => return Err(S2sReadError::InvalidUtf8.into()),
    }
    if buffer.len() + pending_utf8.len() > S2S_MAX_STANZA_BYTES {
        return Err(S2sReadError::FrameTooLarge.into());
    }
    Ok(())
}

pub(crate) async fn write_xml<S: AsyncWrite + Unpin>(stream: &mut S, xml: &str) -> Result<()> {
    tokio::time::timeout(IO_TIMEOUT, async {
        stream.write_all(xml.as_bytes()).await?;
        stream.flush().await
    })
    .await
    .context("S2S write timed out")??;
    Ok(())
}

pub(crate) async fn send_stream_error<S: AsyncWrite + Unpin>(
    stream: &mut S,
    condition: &str,
) -> Result<()> {
    let condition = stream_error_element(condition);
    let error = crate::xmpp::xml_builder::XmlElement::new("stream:error")
        .child(
            crate::xmpp::xml_builder::XmlElement::new(condition)
                .attr("xmlns", "urn:ietf:params:xml:ns:xmpp-streams"),
        )
        .finish();
    write_xml(stream, &(error + "</stream:stream>")).await
}

fn stream_error_element(condition: &str) -> &'static str {
    match condition {
        "bad-format" => "bad-format",
        "bad-namespace-prefix" => "bad-namespace-prefix",
        "conflict" => "conflict",
        "connection-timeout" => "connection-timeout",
        "host-gone" => "host-gone",
        "host-unknown" => "host-unknown",
        "improper-addressing" => "improper-addressing",
        "internal-server-error" => "internal-server-error",
        "invalid-from" => "invalid-from",
        "invalid-namespace" => "invalid-namespace",
        "invalid-xml" => "invalid-xml",
        "not-authorized" => "not-authorized",
        "not-well-formed" => "not-well-formed",
        "policy-violation" => "policy-violation",
        "remote-connection-failed" => "remote-connection-failed",
        "reset" => "reset",
        "resource-constraint" => "resource-constraint",
        "restricted-xml" => "restricted-xml",
        "see-other-host" => "see-other-host",
        "system-shutdown" => "system-shutdown",
        "undefined-condition" => "undefined-condition",
        "unsupported-encoding" => "unsupported-encoding",
        "unsupported-feature" => "unsupported-feature",
        "unsupported-stanza-type" => "unsupported-stanza-type",
        "unsupported-version" => "unsupported-version",
        _ => "undefined-condition",
    }
}

pub(crate) fn peer_stream_error_condition(raw: &str) -> Option<String> {
    let trimmed = raw.trim_start();
    if !trimmed.starts_with("<stream:error") {
        return None;
    }
    let parseable = if trimmed.contains("xmlns:stream=") {
        trimmed.to_owned()
    } else {
        trimmed.replacen(
            "<stream:error",
            "<stream:error xmlns:stream='http://etherx.jabber.org/streams'",
            1,
        )
    };
    let document = roxmltree::Document::parse(&parseable).ok()?;
    let root = document.root_element();
    if root.tag_name().name() != "error"
        || root.tag_name().namespace() != Some("http://etherx.jabber.org/streams")
    {
        return None;
    }
    root.children()
        .find(|child| {
            child.is_element()
                && child.tag_name().namespace() == Some("urn:ietf:params:xml:ns:xmpp-streams")
        })
        .map(|child| child.tag_name().name().to_owned())
        .or_else(|| Some("undefined-condition".to_owned()))
}

pub(crate) fn stream_attribute(xml: &str, name: &str) -> Option<String> {
    if !matches!(name, "from" | "to" | "id" | "version") {
        return None;
    }
    let complete = format!("{xml}</stream:stream>");
    let document = roxmltree::Document::parse(&complete).ok()?;
    let root = document.root_element();
    if root.tag_name().name() != "stream"
        || root.tag_name().namespace() != Some("http://etherx.jabber.org/streams")
        || root.lookup_namespace_uri(None) != Some("jabber:server")
        || !root
            .attribute("version")
            .is_some_and(supported_stream_version)
        || root.children().any(|child| {
            child.is_element() || child.text().is_some_and(|text| !text.trim().is_empty())
        })
        || root
            .attributes()
            .any(|attribute| match attribute.namespace() {
                None => !matches!(attribute.name(), "from" | "to" | "id" | "version"),
                Some("http://www.w3.org/XML/1998/namespace") => {
                    attribute.name() != "lang"
                        || !crate::xmpp::xml_util::valid_language_tag(attribute.value())
                }
                Some(_) => false,
            })
    {
        return None;
    }
    let value = root.attribute(name)?;
    if value.is_empty() || value.len() > 1_024 || value.chars().any(char::is_control) {
        return None;
    }
    match name {
        "from" | "to" => crate::jid::prepare_domainpart(value).ok(),
        // Stream IDs are opaque and case-sensitive. The previous textual
        // scanner lowercased every attribute, breaking Dialback correlation
        // against peers that use uppercase or mixed-case IDs.
        _ => Some(value.to_owned()),
    }
}

fn supported_stream_version(version: &str) -> bool {
    let Some((major, minor)) = version.split_once('.') else {
        return false;
    };
    !major.is_empty()
        && !minor.is_empty()
        && major.bytes().all(|byte| byte.is_ascii_digit())
        && minor.bytes().all(|byte| byte.is_ascii_digit())
        && major.trim_start_matches('0') == "1"
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct S2sStreamOpening {
    pub from: String,
    pub to: String,
    pub id: Option<String>,
}

pub(crate) fn parse_s2s_stream_opening(
    xml: &str,
) -> std::result::Result<S2sStreamOpening, &'static str> {
    let qname = xml
        .strip_prefix('<')
        .and_then(|remainder| {
            let end = remainder
                .find(|character: char| {
                    character.is_ascii_whitespace() || matches!(character, '>' | '/')
                })
                .unwrap_or(remainder.len());
            (end != 0).then_some(&remainder[..end])
        })
        .ok_or("not-well-formed")?;
    if qname.rsplit_once(':').map_or(qname, |(_, local)| local) == "stream"
        && qname != "stream:stream"
    {
        return Err("bad-namespace-prefix");
    }
    let complete = format!("{xml}</stream:stream>");
    let document = roxmltree::Document::parse(&complete).map_err(|_| "not-well-formed")?;
    let root = document.root_element();
    if root.tag_name().name() != "stream"
        || root.tag_name().namespace() != Some("http://etherx.jabber.org/streams")
        || root.lookup_namespace_uri(None) != Some("jabber:server")
    {
        return Err("invalid-namespace");
    }
    if !root
        .attribute("version")
        .is_some_and(supported_stream_version)
    {
        return Err("unsupported-version");
    }
    if root
        .children()
        .any(|child| child.is_element() || child.text().is_some_and(|text| !text.trim().is_empty()))
    {
        return Err("not-well-formed");
    }
    for attribute in root.attributes() {
        let allowed = match attribute.namespace() {
            None => matches!(attribute.name(), "from" | "to" | "id" | "version"),
            Some("http://www.w3.org/XML/1998/namespace") => {
                attribute.name() == "lang"
                    && crate::xmpp::xml_util::valid_language_tag(attribute.value())
            }
            // RFC 6120 permits stream-header extension attributes only when
            // they are namespace-qualified, preventing collisions with core
            // attributes added by later protocol versions.
            Some(_) => true,
        };
        if !allowed {
            return Err("bad-format");
        }
    }
    let parse_domain = |name| {
        root.attribute(name)
            .filter(|value| {
                !value.is_empty() && value.len() <= 1_024 && !value.chars().any(char::is_control)
            })
            .and_then(|value| crate::jid::prepare_domainpart(value).ok())
            .ok_or("improper-addressing")
    };
    let from = parse_domain("from")?;
    let to = parse_domain("to")?;
    let id = root
        .attribute("id")
        .map(|value| {
            if value.is_empty() || value.len() > 1_024 || value.chars().any(char::is_control) {
                Err("invalid-id")
            } else {
                Ok(value.to_owned())
            }
        })
        .transpose()?;
    Ok(S2sStreamOpening { from, to, id })
}

/// Recover only a syntactically safe initiating domain for the `to` attribute
/// of an initial stream-error response.  RFC 6120 requires that response to be
/// a complete receiving-stream header even when another opening attribute (for
/// example the stream namespace or version) is invalid.
pub(crate) fn stream_opening_remote_domain(xml: &str) -> Option<String> {
    let complete = format!("{xml}</stream:stream>");
    let document = roxmltree::Document::parse(&complete).ok()?;
    let root = document.root_element();
    if root.tag_name().name() != "stream" || root.children().any(|child| child.is_element()) {
        return None;
    }
    root.attribute("from")
        .filter(|value| {
            !value.is_empty() && value.len() <= 1_024 && !value.chars().any(char::is_control)
        })
        .and_then(|value| crate::jid::prepare_domainpart(value).ok())
}

pub(crate) async fn send_initial_stream_error<S: AsyncWrite + Unpin>(
    stream: &mut S,
    local_domain: &str,
    remote_domain: Option<&str>,
    condition: &str,
) -> Result<()> {
    write_xml(
        stream,
        &crate::xmpp::xml_builder::XmlElement::new("stream:stream")
            .attr("xmlns", "jabber:server")
            .attr("xmlns:stream", "http://etherx.jabber.org/streams")
            .attr("from", local_domain)
            .optional_attr("to", remote_domain)
            .attr("id", uuid::Uuid::new_v4())
            .attr("version", "1.0")
            .attr("xml:lang", "en")
            .open(),
    )
    .await?;
    send_stream_error(stream, condition).await
}

pub(crate) fn client_open(from: &str, to: &str) -> String {
    crate::xmpp::xml_builder::XmlElement::new("stream:stream")
        .attr("xmlns", "jabber:server")
        .attr("xmlns:stream", "http://etherx.jabber.org/streams")
        .attr("xmlns:db", "jabber:server:dialback")
        .attr("from", from)
        .attr("to", to)
        .attr("version", "1.0")
        .attr("xml:lang", "en")
        .open()
}

pub(crate) fn server_open(from: &str, to: &str, id: &str) -> String {
    crate::xmpp::xml_builder::XmlElement::new("stream:stream")
        .attr("xmlns", "jabber:server")
        .attr("xmlns:stream", "http://etherx.jabber.org/streams")
        .attr("xmlns:db", "jabber:server:dialback")
        .attr("from", from)
        .attr("to", to)
        .attr("id", id)
        .attr("version", "1.0")
        .attr("xml:lang", "en")
        .open()
}

pub(crate) fn client_namespace(raw: &str) -> String {
    stanza_namespace(raw, "jabber:server", "jabber:client")
}

pub(crate) fn server_namespace(raw: &str) -> String {
    stanza_namespace(raw, "jabber:client", "jabber:server")
}

#[cfg(test)]
mod stream_open_tests {
    use super::{
        client_open, parse_s2s_stream_opening, peer_stream_error_condition, read_entity_frame,
        read_frame_until_deadline, read_frame_until_idle, read_frame_until_idle_deadline,
        s2s_read_stream_error_condition, server_open, stream_attribute,
        stream_opening_remote_domain, supported_stream_version, S2sInputState, S2sReadError,
    };
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;

    #[test]
    fn s2s_streams_advertise_the_dialback_prefix() {
        assert!(client_open("a.example", "b.example").contains("xmlns:db='jabber:server:dialback'"));
        assert!(server_open("b.example", "a.example", "id")
            .contains("xmlns:db='jabber:server:dialback'"));
    }

    #[test]
    fn parses_stream_attributes_as_xml_and_preserves_opaque_ids() {
        let opening = "<stream:stream\n xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:server'\n from = 'EXAMPLE.test.' to=\"B\u{fc}CHER.example\" id = 'AbC-123' version='1.0'>";
        assert_eq!(
            stream_attribute(opening, "from").as_deref(),
            Some("example.test")
        );
        assert_eq!(
            stream_attribute(opening, "to").as_deref(),
            Some("bücher.example")
        );
        assert_eq!(stream_attribute(opening, "id").as_deref(), Some("AbC-123"));
        assert_eq!(stream_attribute(opening, "version").as_deref(), Some("1.0"));
    }

    #[test]
    fn rejects_substring_spoofing_wrong_namespaces_and_duplicate_attributes() {
        for opening in [
            "<stream:stream xmlns:stream='urn:wrong' data-from='evil.test' to='local.test'>",
            "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:server' version='1.0' from='a.test' from='b.test' to='local.test'>",
            "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:server' version='1.0' from='bad domain' to='local.test'>",
            "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' version='1.0' from='a.test' to='local.test'>",
            "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:server' version='0.9' from='a.test' to='local.test'>",
        ] {
            assert!(stream_attribute(opening, "from").is_none(), "accepted {opening}");
        }
    }

    #[test]
    fn validates_complete_s2s_stream_opening_semantics() {
        let opening = parse_s2s_stream_opening(
            "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:server' from='REMOTE.test.' to='B\u{fc}cher.example' id='Opaque-ID' version='1.0'>",
        )
        .unwrap();
        assert_eq!(opening.from, "remote.test");
        assert_eq!(opening.to, "bücher.example");
        assert_eq!(opening.id.as_deref(), Some("Opaque-ID"));
        for (invalid, condition) in [
            (
                "<s:stream xmlns:s='http://etherx.jabber.org/streams' xmlns='jabber:server' from='a.test' to='b.test' version='1.0'>",
                "bad-namespace-prefix",
            ),
            (
                "<stream:stream xmlns:stream='urn:wrong' xmlns='jabber:server' from='a.test' to='b.test' version='1.0'>",
                "invalid-namespace",
            ),
            (
                "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' from='a.test' to='b.test' version='1.0'>",
                "invalid-namespace",
            ),
            (
                "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:server' from='a.test' to='b.test' version='0.9'>",
                "unsupported-version",
            ),
            (
                "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:server' to='b.test' version='1.0'>",
                "improper-addressing",
            ),
        ] {
            assert_eq!(parse_s2s_stream_opening(invalid), Err(condition));
        }
    }

    #[test]
    fn s2s_stream_versions_accept_supported_one_x_minors_only() {
        for version in ["1.0", "1.1", "1.999"] {
            assert!(supported_stream_version(version), "rejected {version}");
        }
        for version in ["", "1", "1.", ".0", "0.9", "2.0", "1.x", "1.0.1"] {
            assert!(!supported_stream_version(version), "accepted {version}");
        }
        let opening = parse_s2s_stream_opening(
            "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:server' from='remote.test' to='local.test' version='1.7' xml:lang='en-US' ext:trace='ok' xmlns:ext='urn:example:trace'>",
        )
        .unwrap();
        assert_eq!(opening.from, "remote.test");
    }

    #[test]
    fn s2s_stream_opening_rejects_unknown_core_attributes_and_bad_language() {
        for invalid in [
            "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:server' from='remote.test' to='local.test' version='1.0' bogus='x'>",
            "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:server' from='remote.test' to='local.test' version='1.0' xml:lang='en--US'>",
        ] {
            assert_eq!(parse_s2s_stream_opening(invalid), Err("bad-format"));
        }
    }

    #[test]
    fn recovers_only_a_safe_domain_for_initial_error_addressing() {
        assert_eq!(
            stream_opening_remote_domain(
                "<stream:stream xmlns='jabber:server' xmlns:stream='urn:wrong' from='REMOTE.example' to='local.example' version='99'>"
            ),
            Some("remote.example".to_owned())
        );
        assert_eq!(
            stream_opening_remote_domain(
                "<stream:stream xmlns='jabber:server' xmlns:stream='urn:wrong' from='user@remote.example' to='local.example'>"
            ),
            None
        );
    }

    #[test]
    fn extracts_peer_stream_errors_without_requiring_repeated_prefix_binding() {
        assert_eq!(
            peer_stream_error_condition(
                "<stream:error><policy-violation xmlns='urn:ietf:params:xml:ns:xmpp-streams'/></stream:error>"
            )
            .as_deref(),
            Some("policy-violation")
        );
        assert!(peer_stream_error_condition("<message/>").is_none());
    }

    #[test]
    fn maps_framing_failures_to_stream_errors_without_answering_eof() {
        assert_eq!(
            s2s_read_stream_error_condition(&anyhow::Error::new(S2sReadError::FrameTooLarge)),
            Some("policy-violation")
        );
        assert_eq!(
            s2s_read_stream_error_condition(&anyhow::Error::new(S2sReadError::InvalidUtf8)),
            Some("unsupported-encoding")
        );
        assert_eq!(
            s2s_read_stream_error_condition(&anyhow::Error::new(S2sReadError::NegotiationTimedOut)),
            Some("connection-timeout")
        );
        assert_eq!(
            s2s_read_stream_error_condition(&anyhow::Error::new(S2sReadError::Ended)),
            None
        );
    }

    #[tokio::test]
    async fn idle_deadline_resets_on_whitespace_and_fragmented_xml_traffic() {
        let (mut writer, mut reader) = tokio::io::duplex(256);
        let mut input = S2sInputState::default();
        let read = read_frame_until_idle(&mut reader, &mut input, Duration::from_millis(100));
        let write = async {
            tokio::time::sleep(Duration::from_millis(60)).await;
            writer.write_all(b" \n<message").await.unwrap();
            tokio::time::sleep(Duration::from_millis(60)).await;
            writer.write_all(b"/>").await.unwrap();
        };
        let (frame, ()) = tokio::join!(read, write);
        assert_eq!(frame.unwrap().as_deref(), Some("<message/>"));
    }

    #[tokio::test]
    async fn negotiation_deadline_is_not_extended_by_slow_drip_traffic() {
        let (mut writer, mut reader) = tokio::io::duplex(256);
        let mut input = S2sInputState::default();
        let deadline = tokio::time::Instant::now() + Duration::from_millis(100);
        let read = read_frame_until_deadline(&mut reader, &mut input, deadline);
        let write = async {
            tokio::time::sleep(Duration::from_millis(60)).await;
            writer.write_all(b"<message").await.unwrap();
            // This arrives within an idle window measured from the first
            // bytes, but outside the fixed negotiation budget.
            tokio::time::sleep(Duration::from_millis(60)).await;
            writer.write_all(b"/>").await.unwrap();
        };
        let (frame, ()) = tokio::join!(read, write);
        assert!(frame.unwrap().is_none());
    }

    #[tokio::test]
    async fn idle_deadline_expires_when_no_bytes_arrive() {
        let (_writer, mut reader) = tokio::io::duplex(64);
        let mut input = S2sInputState::default();
        let frame = read_frame_until_idle(&mut reader, &mut input, Duration::from_millis(10))
            .await
            .unwrap();
        assert!(frame.is_none());
    }

    #[tokio::test]
    async fn caller_cancellation_does_not_refresh_the_peer_idle_deadline() {
        let (_writer, mut reader) = tokio::io::duplex(64);
        let mut input = S2sInputState::default();
        let idle = Duration::from_millis(100);
        let started = tokio::time::Instant::now();
        let mut deadline = started + idle;

        let cancelled = tokio::time::timeout(
            Duration::from_millis(30),
            read_frame_until_idle_deadline(&mut reader, &mut input, idle, &mut deadline),
        )
        .await;
        assert!(cancelled.is_err());
        tokio::time::sleep(Duration::from_millis(30)).await;
        let frame = read_frame_until_idle_deadline(&mut reader, &mut input, idle, &mut deadline)
            .await
            .unwrap();
        assert!(frame.is_none());
        assert!(started.elapsed() < Duration::from_millis(150));
    }

    #[tokio::test]
    async fn entity_state_preserves_coalesced_frames_and_rejects_late_declarations() {
        let (mut writer, mut reader) = tokio::io::duplex(512);
        writer
            .write_all(
                b"<?xml version='1.0'?><stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:server'><stream:features/><?xml version='1.0'?><message/>",
            )
            .await
            .unwrap();
        let mut input = S2sInputState::default();
        assert!(read_entity_frame(&mut reader, &mut input)
            .await
            .unwrap()
            .starts_with("<stream:stream"));
        assert_eq!(
            read_entity_frame(&mut reader, &mut input).await.unwrap(),
            "<stream:features/>"
        );
        let error = read_entity_frame(&mut reader, &mut input)
            .await
            .unwrap_err();
        assert_eq!(
            crate::xmpp::framing::stream_error_condition(&error),
            "not-well-formed"
        );
    }

    #[tokio::test]
    async fn explicit_entity_reset_allows_a_new_declaration_after_sasl() {
        let (mut first_writer, mut first_reader) = tokio::io::duplex(128);
        first_writer
            .write_all(b"<?xml version='1.0'?><success/>")
            .await
            .unwrap();
        let mut input = S2sInputState::default();
        assert_eq!(
            read_entity_frame(&mut first_reader, &mut input)
                .await
                .unwrap(),
            "<success/>"
        );

        input.reset_entity();
        let (mut second_writer, mut second_reader) = tokio::io::duplex(128);
        second_writer
            .write_all(b"<?xml version='1.0'?><stream:stream>")
            .await
            .unwrap();
        assert_eq!(
            read_entity_frame(&mut second_reader, &mut input)
                .await
                .unwrap(),
            "<stream:stream>"
        );
    }
}

pub(crate) fn stanza_namespace(raw: &str, source: &str, target: &str) -> String {
    let Ok(document) = roxmltree::Document::parse(raw) else {
        return raw.to_owned();
    };
    let root = document.root_element();
    let namespace = root.lookup_namespace_uri(None);
    if namespace != Some(source) && namespace.is_some() {
        return raw.to_owned();
    }

    let Some((name_end, default_namespace)) = root_opening_namespace(raw) else {
        return raw.to_owned();
    };
    if namespace == Some(source) {
        let Some((value_start, value_end)) = default_namespace else {
            return raw.to_owned();
        };
        let mut namespaced = raw.to_owned();
        namespaced.replace_range(value_start..value_end, target);
        return namespaced;
    }

    let mut namespaced = raw.to_owned();
    namespaced.insert_str(name_end, &format!(" xmlns='{target}'"));
    namespaced
}

/// Return the end of the root element name and the byte range of its default
/// namespace value. XML has already been validated by `roxmltree`; this small
/// lexical pass exists only so conversion preserves the stanza byte-for-byte
/// apart from the root namespace declaration.
fn root_opening_namespace(raw: &str) -> Option<(usize, Option<(usize, usize)>)> {
    let bytes = raw.as_bytes();
    let mut cursor = raw.len() - raw.trim_start().len();
    if bytes.get(cursor) != Some(&b'<') {
        return None;
    }
    cursor += 1;
    if matches!(bytes.get(cursor), Some(b'!' | b'?' | b'/')) {
        return None;
    }

    while let Some(byte) = bytes.get(cursor) {
        if byte.is_ascii_whitespace() || matches!(byte, b'>' | b'/') {
            break;
        }
        cursor += 1;
    }
    let name_end = cursor;

    loop {
        while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
            cursor += 1;
        }
        if matches!(bytes.get(cursor), None | Some(b'>' | b'/')) {
            return Some((name_end, None));
        }

        let attribute_start = cursor;
        while let Some(byte) = bytes.get(cursor) {
            if byte.is_ascii_whitespace() || matches!(byte, b'=' | b'>' | b'/') {
                break;
            }
            cursor += 1;
        }
        let attribute_name = raw.get(attribute_start..cursor)?;
        while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
            cursor += 1;
        }
        if bytes.get(cursor) != Some(&b'=') {
            return None;
        }
        cursor += 1;
        while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
            cursor += 1;
        }
        let quote = *bytes.get(cursor)?;
        if quote != b'\'' && quote != b'"' {
            return None;
        }
        cursor += 1;
        let value_start = cursor;
        while bytes.get(cursor).copied() != Some(quote) {
            cursor += 1;
            if cursor >= bytes.len() {
                return None;
            }
        }
        let value_end = cursor;
        cursor += 1;
        if attribute_name == "xmlns" {
            return Some((name_end, Some((value_start, value_end))));
        }
    }
}

#[cfg(test)]
mod stanza_namespace_tests {
    use super::{client_namespace, s2s_stanza_error, server_namespace};
    use roxmltree::Document;

    #[test]
    fn only_converts_the_root_default_namespace() {
        let stanza = "<message xmlns = \"jabber:server\" note=\"xmlns='jabber:server'\"><forwarded xmlns='urn:xmpp:forward:0'><message xmlns='jabber:server'><body>xmlns='jabber:server'</body></message></forwarded></message>";
        assert_eq!(
            client_namespace(stanza),
            "<message xmlns = \"jabber:client\" note=\"xmlns='jabber:server'\"><forwarded xmlns='urn:xmpp:forward:0'><message xmlns='jabber:server'><body>xmlns='jabber:server'</body></message></forwarded></message>"
        );
    }

    #[test]
    fn adds_only_a_missing_root_namespace_and_preserves_other_namespaces() {
        assert_eq!(
            server_namespace("<presence><show>away</show></presence>"),
            "<presence xmlns='jabber:server'><show>away</show></presence>"
        );
        assert_eq!(
            server_namespace("<query xmlns='jabber:iq:roster'/>"),
            "<query xmlns='jabber:iq:roster'/>"
        );
    }

    #[test]
    fn malformed_xml_is_not_rewritten() {
        let malformed = "<message xmlns='jabber:server'><body>";
        assert_eq!(client_namespace(malformed), malformed);
    }

    #[test]
    fn federation_errors_swap_addresses_and_preserve_original_payload() {
        let document = Document::parse(
            "<message xmlns='jabber:server' from='alice@remote.test/a' to='bob@local.test'><body>hello</body></message>",
        )
        .unwrap();
        let error = s2s_stanza_error(document.root_element(), "cancel", "service-unavailable");
        let document = Document::parse(&error).unwrap();
        let root = document.root_element();
        assert_eq!(root.attribute("from"), Some("bob@local.test"));
        assert_eq!(root.attribute("to"), Some("alice@remote.test/a"));
        assert!(root.children().any(|child| {
            child.is_element() && child.tag_name().name() == "body" && child.text() == Some("hello")
        }));
        assert!(root.children().any(|child| {
            child.is_element()
                && child.tag_name().name() == "error"
                && child.tag_name().namespace() == Some("jabber:server")
        }));
    }
}

pub(crate) fn decode_external(value: &str) -> Result<String> {
    if value.is_empty() || value == "=" {
        return Ok(String::new());
    }
    String::from_utf8(STANDARD.decode(value)?).context("SASL EXTERNAL identity is not UTF-8")
}

pub(crate) fn s2s_stanza_error(
    root: roxmltree::Node<'_, '_>,
    error_type: &str,
    condition: &str,
) -> String {
    let error_type = match error_type {
        "auth" => "auth",
        "cancel" => "cancel",
        "continue" => "continue",
        "modify" => "modify",
        "wait" => "wait",
        _ => "cancel",
    };
    let condition = stanza_error_element(condition);
    crate::xmpp::xml_util::reflected_stanza_error(
        root,
        &crate::xmpp::xml_builder::XmlElement::new("error")
            .attr("xmlns", "jabber:server")
            .attr("type", error_type)
            .child(
                crate::xmpp::xml_builder::XmlElement::new(condition)
                    .attr("xmlns", "urn:ietf:params:xml:ns:xmpp-stanzas"),
            )
            .finish(),
    )
}

pub(crate) fn s2s_iq_result(id: &str, from: &str, to: &str, payload: &str) -> String {
    crate::xmpp::xml_builder::XmlElement::new("iq")
        .attr("xmlns", "jabber:server")
        .attr("type", "result")
        .attr("id", id)
        .attr("from", from)
        .attr("to", to)
        .validated_fragment(payload)
        .expect("server-generated S2S IQ payload must be valid XML")
        .finish()
}

pub(crate) fn s2s_iq_error(id: &str, from: &str, to: &str, condition: &str) -> String {
    let condition = stanza_error_element(condition);
    crate::xmpp::xml_builder::XmlElement::new("iq")
        .attr("xmlns", "jabber:server")
        .attr("type", "error")
        .attr("id", id)
        .attr("from", from)
        .attr("to", to)
        .child(
            crate::xmpp::xml_builder::XmlElement::new("error")
                .attr("type", "cancel")
                .child(
                    crate::xmpp::xml_builder::XmlElement::new(condition)
                        .attr("xmlns", "urn:ietf:params:xml:ns:xmpp-stanzas"),
                ),
        )
        .finish()
}

fn stanza_error_element(condition: &str) -> &'static str {
    match condition {
        "bad-request" => "bad-request",
        "conflict" => "conflict",
        "feature-not-implemented" => "feature-not-implemented",
        "forbidden" => "forbidden",
        "gone" => "gone",
        "internal-server-error" => "internal-server-error",
        "item-not-found" => "item-not-found",
        "jid-malformed" => "jid-malformed",
        "not-acceptable" => "not-acceptable",
        "not-allowed" => "not-allowed",
        "not-authorized" => "not-authorized",
        "policy-violation" => "policy-violation",
        "recipient-unavailable" => "recipient-unavailable",
        "redirect" => "redirect",
        "registration-required" => "registration-required",
        "remote-server-not-found" => "remote-server-not-found",
        "remote-server-timeout" => "remote-server-timeout",
        "resource-constraint" => "resource-constraint",
        "service-unavailable" => "service-unavailable",
        "subscription-required" => "subscription-required",
        "undefined-condition" => "undefined-condition",
        "unexpected-request" => "unexpected-request",
        _ => "undefined-condition",
    }
}
