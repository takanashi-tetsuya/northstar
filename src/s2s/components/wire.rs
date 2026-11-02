//! Verify credentials and provide component wire parsing, validation, namespace conversion and XML rendering helpers.

use super::*;

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
