pub(crate) mod framing;
pub(crate) mod protocol;
pub(crate) mod xml_util;

use crate::state::AppState;
use anyhow::{Context, Result};
use axum::extract::ws::{Message, WebSocket};
use framing::take_frame;
use protocol::{Action, ProtocolSession};
use std::{
    net::SocketAddr,
    sync::{atomic::Ordering, Arc},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
};
use tokio_rustls::TlsAcceptor;

pub async fn serve_tcp(
    state: Arc<AppState>,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<()> {
    let listener = TcpListener::bind(state.config.xmpp_bind)
        .await
        .with_context(|| format!("could not bind XMPP listener to {}", state.config.xmpp_bind))?;
    tracing::info!(address = %state.config.xmpp_bind, "XMPP TCP listener ready");
    loop {
        let (stream, peer) = tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            accepted = listener.accept() => accepted?,
        };
        let state = state.clone();
        tokio::spawn(async move {
            state
                .metrics
                .tcp_connections_total
                .fetch_add(1, Ordering::Relaxed);
            let tls = TlsAcceptor::from(state.tls.current());
            if let Err(error) = tcp_connection(stream, peer, state, tls).await {
                tracing::debug!(%peer, ?error, "XMPP connection closed with error");
            }
        });
    }
}

async fn tcp_connection(
    stream: TcpStream,
    peer: SocketAddr,
    state: Arc<AppState>,
    tls: TlsAcceptor,
) -> Result<()> {
    stream.set_nodelay(true)?;
    let (tx, mut rx) = mpsc::channel(512);
    let mut session = ProtocolSession::new(state.clone(), tx, false, false, peer.ip());
    let outcome = drive_io(stream, &mut session, &mut rx).await?;
    let DriveOutcome::Upgrade(mut plain) = outcome else {
        return Ok(());
    };
    plain
        .write_all(b"<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
        .await?;
    plain.flush().await?;
    let secure = tls.accept(plain).await.context("TLS handshake failed")?;
    session.tls = true;
    tracing::debug!(%peer, "XMPP connection upgraded to TLS");
    let _ = drive_io(secure, &mut session, &mut rx).await?;
    Ok(())
}

enum DriveOutcome<S> {
    Upgrade(S),
    Done,
}

async fn drive_io<S>(
    mut io: S,
    session: &mut ProtocolSession,
    rx: &mut mpsc::Receiver<String>,
) -> Result<DriveOutcome<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buffer = String::new();
    let mut pending_utf8 = Vec::new();
    let mut bytes = [0u8; 8192];
    loop {
        tokio::select! {
            read = io.read(&mut bytes) => {
                let count = read?;
                if count == 0 {
                    if !pending_utf8.is_empty() { anyhow::bail!("XMPP stream ended inside a UTF-8 character"); }
                    return Ok(DriveOutcome::Done);
                }
                pending_utf8.extend_from_slice(&bytes[..count]);
                append_utf8(&mut pending_utf8, &mut buffer)?;
                if buffer.len() + pending_utf8.len() > 1024 * 1024 { anyhow::bail!("XMPP frame exceeds 1 MiB"); }
                while let Some(frame) = take_frame(&mut buffer)? {
                    match session.handle(&frame).await? {
                        Action::Send(reply) => { send(&mut io, &reply).await?; session.record_outbound(&reply); },
                        Action::SendMany(replies) => {
                            for reply in replies {
                                send(&mut io, &reply).await?;
                                session.record_outbound(&reply);
                            }
                        }
                        Action::Resume { control, replay } => {
                            send(&mut io, &control).await?;
                            session.record_outbound(&control);
                            for stanza in replay {
                                send(&mut io, &stanza).await?;
                                session.record_replayed();
                            }
                        }
                        Action::StartTls => return Ok(DriveOutcome::Upgrade(io)),
                        Action::Close => {
                            send(&mut io, "</stream:stream>").await?;
                            return Ok(DriveOutcome::Done);
                        }
                        Action::None => {}
                    }
                }
            }
            outgoing = rx.recv() => {
                let Some(outgoing) = outgoing else { return Ok(DriveOutcome::Done); };
                send(&mut io, &outgoing).await?;
                session.record_outbound(&outgoing);
            }
        }
    }
}

fn append_utf8(pending: &mut Vec<u8>, output: &mut String) -> Result<()> {
    match std::str::from_utf8(pending) {
        Ok(text) => {
            output.push_str(text);
            pending.clear();
            Ok(())
        }
        Err(error) if error.error_len().is_none() => {
            let valid = error.valid_up_to();
            output
                .push_str(std::str::from_utf8(&pending[..valid]).context("invalid UTF-8 prefix")?);
            pending.drain(..valid);
            Ok(())
        }
        Err(_) => anyhow::bail!("XMPP stream is not valid UTF-8"),
    }
}

async fn send<S: AsyncWrite + Unpin>(io: &mut S, stanza: &str) -> Result<()> {
    io.write_all(stanza.as_bytes()).await?;
    io.flush().await?;
    Ok(())
}

pub async fn websocket_connection(
    mut socket: WebSocket,
    state: Arc<AppState>,
    peer_ip: std::net::IpAddr,
) {
    state
        .metrics
        .websocket_connections_total
        .fetch_add(1, Ordering::Relaxed);
    let (tx, mut rx) = mpsc::channel(512);
    let mut session = ProtocolSession::new(state, tx, true, true, peer_ip);
    loop {
        tokio::select! {
            incoming = socket.recv() => {
                match incoming {
                    Some(Ok(Message::Text(text))) => {
                        let mut payload = text.to_string();
                        let frame = match take_frame(&mut payload) {
                            Ok(Some(frame)) if payload.trim().is_empty() => frame,
                            Ok(_) => {
                                tracing::debug!("WebSocket payload did not contain exactly one complete XMPP frame");
                                break;
                            }
                            Err(error) => {
                                tracing::debug!(?error, "invalid WebSocket XMPP framing");
                                break;
                            }
                        };
                        match session.handle(&frame).await {
                        Ok(Action::Send(reply)) => { if socket.send(Message::Text(reply.clone().into())).await.is_err() { break; } session.record_outbound(&reply); },
                        Ok(Action::SendMany(replies)) => {
                            for reply in replies {
                                if socket.send(Message::Text(reply.clone().into())).await.is_err() { return; }
                                session.record_outbound(&reply);
                            }
                        }
                        Ok(Action::Resume { control, replay }) => {
                            if socket.send(Message::Text(control.clone().into())).await.is_err() { return; }
                            session.record_outbound(&control);
                            for stanza in replay {
                                if socket.send(Message::Text(stanza.into())).await.is_err() { return; }
                                session.record_replayed();
                            }
                        }
                        Ok(Action::Close) => {
                            let _ = socket.send(Message::Text("<close xmlns='urn:ietf:params:xml:ns:xmpp-framing'/>".into())).await;
                            break;
                        }
                        Ok(Action::None) => {}
                        Ok(Action::StartTls) => { let _ = socket.send(Message::Text("<failure xmlns='urn:ietf:params:xml:ns:xmpp-tls'><unexpected-request/></failure>".into())).await; }
                        Err(error) => { tracing::debug!(?error, "invalid WebSocket XMPP stanza"); break; }
                    }
                    },
                    Some(Ok(Message::Ping(value))) => { if socket.send(Message::Pong(value)).await.is_err() { break; } }
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                    _ => {}
                }
            }
            outgoing = rx.recv() => {
                let Some(outgoing) = outgoing else { break; };
                if socket.send(Message::Text(outgoing.clone().into())).await.is_err() { break; }
                session.record_outbound(&outgoing);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_utf8_split_between_network_reads() {
        let encoded = "消息".as_bytes();
        let mut pending = encoded[..2].to_vec();
        let mut output = String::new();
        append_utf8(&mut pending, &mut output).unwrap();
        assert!(output.is_empty());
        pending.extend_from_slice(&encoded[2..]);
        append_utf8(&mut pending, &mut output).unwrap();
        assert_eq!(output, "消息");
    }
}
