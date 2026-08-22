use crate::{state::attr_escape, xmpp::framing::take_frame};
use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;

pub(crate) async fn timed_read_frame<S: AsyncRead + Unpin>(
    stream: &mut S,
    buffer: &mut String,
) -> Result<String> {
    tokio::time::timeout(IO_TIMEOUT, read_frame(stream, buffer))
        .await
        .context("S2S read timed out")?
}

pub(crate) async fn read_frame<S: AsyncRead + Unpin>(
    stream: &mut S,
    buffer: &mut String,
) -> Result<String> {
    let mut bytes = [0u8; 8192];
    let mut pending_utf8 = Vec::new();
    loop {
        if let Some(frame) = take_frame(buffer) {
            return Ok(frame);
        }
        let count = stream.read(&mut bytes).await?;
        if count == 0 {
            anyhow::bail!("S2S stream ended unexpectedly");
        }
        pending_utf8.extend_from_slice(&bytes[..count]);
        match std::str::from_utf8(&pending_utf8) {
            Ok(text) => {
                buffer.push_str(text);
                pending_utf8.clear();
            }
            Err(error) if error.error_len().is_none() => {
                let valid = error.valid_up_to();
                buffer.push_str(
                    std::str::from_utf8(&pending_utf8[..valid])
                        .context("invalid S2S UTF-8 prefix")?,
                );
                pending_utf8.drain(..valid);
            }
            Err(_) => anyhow::bail!("S2S stream is not UTF-8"),
        }
        if buffer.len() + pending_utf8.len() > 1024 * 1024 {
            anyhow::bail!("S2S frame exceeds 1 MiB");
        }
    }
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
    write_xml(
        stream,
        &format!(
            "<stream:error><{} xmlns='urn:ietf:params:xml:ns:xmpp-streams'/></stream:error></stream:stream>",
            condition
        ),
    )
    .await
}

pub(crate) fn stream_attribute(xml: &str, name: &str) -> Option<String> {
    for quote in ['\'', '"'] {
        let needle = format!(" {name}={quote}");
        if let Some(start) = xml.find(&needle) {
            let value = &xml[start + needle.len()..];
            if let Some(end) = value.find(quote) {
                return Some(value[..end].trim_end_matches('.').to_ascii_lowercase());
            }
        }
    }
    None
}

pub(crate) fn client_open(from: &str, to: &str) -> String {
    format!(
        "<stream:stream xmlns='jabber:server' xmlns:stream='http://etherx.jabber.org/streams' from='{}' to='{}' version='1.0'>",
        attr_escape(from),
        attr_escape(to)
    )
}

pub(crate) fn server_open(from: &str, to: &str, id: &str) -> String {
    format!(
        "<stream:stream xmlns='jabber:server' xmlns:stream='http://etherx.jabber.org/streams' from='{}' to='{}' id='{}' version='1.0'>",
        attr_escape(from),
        attr_escape(to),
        attr_escape(id)
    )
}

pub(crate) fn client_namespace(raw: &str) -> String {
    stanza_namespace(raw, "jabber:server", "jabber:client")
}

pub(crate) fn server_namespace(raw: &str) -> String {
    stanza_namespace(raw, "jabber:client", "jabber:server")
}

pub(crate) fn stanza_namespace(raw: &str, source: &str, target: &str) -> String {
    let single = format!("xmlns='{source}'");
    if raw.contains(&single) {
        return raw.replacen(&single, &format!("xmlns='{target}'"), 1);
    }
    let double = format!("xmlns=\"{source}\"");
    if raw.contains(&double) {
        return raw.replacen(&double, &format!("xmlns='{target}'"), 1);
    }
    let Some(name_end) = raw.find(|character: char| character.is_whitespace() || character == '>')
    else {
        return raw.to_owned();
    };
    let mut namespaced = raw.to_owned();
    namespaced.insert_str(name_end, &format!(" xmlns='{target}'"));
    namespaced
}

pub(crate) fn decode_external(value: &str) -> Result<String> {
    let value = value.trim();
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
    format!(
        "<{0} xmlns='jabber:server' type='error' id='{1}' from='{2}' to='{3}'><error type='{4}'><{5} xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></{0}>",
        root.tag_name().name(),
        attr_escape(root.attribute("id").unwrap_or_default()),
        attr_escape(root.attribute("to").unwrap_or_default()),
        attr_escape(root.attribute("from").unwrap_or_default()),
        attr_escape(error_type),
        condition
    )
}

pub(crate) fn s2s_iq_result(id: &str, from: &str, to: &str, payload: &str) -> String {
    format!(
        "<iq xmlns='jabber:server' type='result' id='{}' from='{}' to='{}'>{}</iq>",
        attr_escape(id),
        attr_escape(from),
        attr_escape(to),
        payload
    )
}

pub(crate) fn s2s_iq_error(id: &str, from: &str, to: &str, condition: &str) -> String {
    format!(
        "<iq xmlns='jabber:server' type='error' id='{}' from='{}' to='{}'><error type='cancel'><{} xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>",
        attr_escape(id),
        attr_escape(from),
        attr_escape(to),
        condition
    )
}
