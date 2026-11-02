use crate::xmpp::framing::XmlEntityFramer;
use anyhow::{Context, Result};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use northstar_federation_core::wire::stream_error_element;

// A peer can write at the advertised boundary while TLS or socket readiness
// needs another scheduler turn. Do not extend the activity clock; only allow
// one bounded final read before declaring the stream idle.
const S2S_IDLE_READ_GRACE: Duration = Duration::from_secs(1);

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
        let read_deadline = *idle_deadline + (idle_timeout / 10).min(S2S_IDLE_READ_GRACE);
        if tokio::time::Instant::now() >= read_deadline {
            return Ok(None);
        }
        let count = match tokio::time::timeout_at(read_deadline, stream.read(&mut bytes)).await {
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
    if buffer.len() + pending_utf8.len() > MAX_S2S_STANZA_BYTES {
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

pub(crate) fn transport_lost(error: &anyhow::Error) -> bool {
    matches!(
        error.downcast_ref::<S2sReadError>(),
        Some(S2sReadError::Ended)
    ) || error.downcast_ref::<std::io::Error>().is_some_and(|error| {
        matches!(
            error.kind(),
            std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::ConnectionRefused
                | std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::UnexpectedEof
                | std::io::ErrorKind::NotConnected
                | std::io::ErrorKind::TimedOut
        )
    })
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

#[cfg(test)]
mod stream_open_tests {
    use super::{
        read_entity_frame, read_frame_until_deadline, read_frame_until_idle,
        read_frame_until_idle_deadline, s2s_read_stream_error_condition, S2sInputState,
        S2sReadError,
    };
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;

    struct PendingOnce<S> {
        stream: S,
        first_poll: bool,
    }

    impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for PendingOnce<S> {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            let this = self.get_mut();
            if this.first_poll {
                this.first_poll = false;
                cx.waker().wake_by_ref();
                return std::task::Poll::Pending;
            }
            std::pin::Pin::new(&mut this.stream).poll_read(cx, buf)
        }
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
    async fn queued_frame_survives_a_pending_read_at_the_idle_boundary() {
        let (mut writer, reader) = tokio::io::duplex(64);
        let mut reader = PendingOnce {
            stream: reader,
            first_poll: true,
        };
        let mut input = S2sInputState::default();
        let idle = Duration::from_secs(10);
        let mut deadline = tokio::time::Instant::now() + Duration::from_millis(10);
        writer.write_all(b"<message id='boundary'/>").await.unwrap();
        tokio::time::sleep(Duration::from_millis(15)).await;
        assert!(tokio::time::Instant::now() > deadline);

        let frame = read_frame_until_idle_deadline(&mut reader, &mut input, idle, &mut deadline)
            .await
            .unwrap();
        assert_eq!(frame.as_deref(), Some("<message id='boundary'/>"));
    }

    #[tokio::test]
    async fn expired_idle_grace_does_not_admit_a_late_frame() {
        let (mut writer, mut reader) = tokio::io::duplex(64);
        let mut input = S2sInputState::default();
        let idle = Duration::from_secs(10);
        let mut deadline = tokio::time::Instant::now() - Duration::from_secs(2);
        writer.write_all(b"<message id='late'/>").await.unwrap();

        let frame = read_frame_until_idle_deadline(&mut reader, &mut input, idle, &mut deadline)
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
