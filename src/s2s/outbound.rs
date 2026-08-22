use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use std::sync::atomic::Ordering;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::TlsConnector;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const IO_TIMEOUT: Duration = Duration::from_secs(15);

use crate::state::{attr_escape, AppState};
use anyhow::{Context, Result};
use roxmltree::Document;
use std::{sync::Arc, time::Duration};
use tokio::{io::AsyncWriteExt, net::TcpStream};

use super::*;

use tokio::sync::mpsc;

pub(crate) fn get_or_create_outbound(
    state: &Arc<AppState>,
    target_domain: &str,
) -> mpsc::Sender<FederationEnvelope> {
    if let Some(sender) = state.s2s_outbound_connections.get(target_domain) {
        if !sender.is_closed() {
            return sender.clone();
        }
    }
    let (tx, rx) = mpsc::channel(100);
    state
        .s2s_outbound_connections
        .insert(target_domain.to_owned(), tx.clone());
    let state_clone = Arc::clone(state);
    let domain_clone = target_domain.to_owned();
    tokio::spawn(async move {
        if let Err(error) =
            run_outbound_connection(Arc::clone(&state_clone), domain_clone.clone(), rx).await
        {
            state_clone
                .metrics
                .federation_failures_total
                .fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                domain = %domain_clone,
                ?error,
                "federation outbound connection failed or closed"
            );
        }
        state_clone.s2s_outbound_connections.remove(&domain_clone);
    });
    tx
}

async fn run_outbound_connection(
    state: Arc<AppState>,
    target_domain: String,
    mut rx: mpsc::Receiver<FederationEnvelope>,
) -> Result<()> {
    if !state.config.federation_domain_allowed(&target_domain) {
        anyhow::bail!("target domain is denied by federation policy");
    }
    let endpoint = resolve_federation_endpoint(&state, &target_domain).await?;
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(endpoint))
        .await
        .context("S2S TCP connection timed out")??;
    stream.set_nodelay(true)?;
    let mut stream = stream;
    let mut buffer = String::new();
    write_xml(
        &mut stream,
        &client_open(&state.config.domain, &target_domain),
    )
    .await?;
    let _ = timed_read_frame(&mut stream, &mut buffer).await?;
    let features = timed_read_frame(&mut stream, &mut buffer).await?;
    if !features.contains("urn:ietf:params:xml:ns:xmpp-tls") {
        anyhow::bail!("remote server did not advertise STARTTLS");
    }
    write_xml(
        &mut stream,
        "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>",
    )
    .await?;
    let proceed = timed_read_frame(&mut stream, &mut buffer).await?;
    if !proceed.starts_with("<proceed") {
        anyhow::bail!("remote server rejected STARTTLS");
    }
    let connector = TlsConnector::from(s2s_client_config(&state)?);
    let server_name =
        ServerName::try_from(target_domain.clone()).context("invalid remote federation domain")?;
    let mut secure = tokio::time::timeout(IO_TIMEOUT, connector.connect(server_name, stream))
        .await
        .context("outbound S2S TLS handshake timed out")??;
    buffer.clear();
    write_xml(
        &mut secure,
        &client_open(&state.config.domain, &target_domain),
    )
    .await?;
    let _ = timed_read_frame(&mut secure, &mut buffer).await?;
    let features = timed_read_frame(&mut secure, &mut buffer).await?;
    if !features.contains("<mechanism>EXTERNAL</mechanism>") {
        anyhow::bail!("remote server does not support SASL EXTERNAL");
    }
    let authorization = STANDARD.encode(state.config.domain.as_bytes());
    write_xml(
        &mut secure,
        &format!(
            "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='EXTERNAL'>{authorization}</auth>"
        ),
    )
    .await?;
    let success = timed_read_frame(&mut secure, &mut buffer).await?;
    if !success.starts_with("<success") {
        anyhow::bail!("remote server rejected SASL EXTERNAL");
    }
    buffer.clear();
    write_xml(
        &mut secure,
        &client_open(&state.config.domain, &target_domain),
    )
    .await?;
    let _ = timed_read_frame(&mut secure, &mut buffer).await?;
    let _ = timed_read_frame(&mut secure, &mut buffer).await?;

    // Connection established! Enter the multiplexing loop.
    loop {
        tokio::select! {
            envelope = rx.recv() => {
                let Some(envelope) = envelope else {
                    // Receiver dropped, meaning channel was removed or no more senders.
                    break;
                };
                write_xml(&mut secure, &server_namespace(&envelope.stanza)).await?;
                state
                    .metrics
                    .federation_outbound_deliveries_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            frame = timed_read_frame(&mut secure, &mut buffer) => {
                let frame = frame?;
                if frame.starts_with("</stream:stream") {
                    break;
                }
                if route_inbound(&state, &target_domain, &frame).await?.is_some() {
                    // unexpected reply while routing federated IQ response
                    tracing::debug!(domain = %target_domain, "unexpected reply while routing federated IQ response");
                }
            }
        }
    }

    write_xml(&mut secure, "</stream:stream>").await?;
    secure.shutdown().await?;

    // Bounce any pending envelopes left in the channel
    while let Ok(envelope) = rx.try_recv() {
        bounce_delivery_failure(&state, &envelope);
    }

    Ok(())
}

pub(crate) fn bounce_delivery_failure(state: &AppState, envelope: &FederationEnvelope) {
    let Some(origin) = &envelope.bounce_to else {
        return;
    };
    let id = Document::parse(&envelope.stanza)
        .ok()
        .and_then(|document| {
            document
                .root_element()
                .attribute("id")
                .map(ToOwned::to_owned)
        })
        .unwrap_or_default();
    let error = format!(
        "<message xmlns='jabber:client' type='error' id='{}'><error type='cancel'><remote-server-not-found xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></message>",
        attr_escape(&id)
    );
    for session in state.sessions_for(origin) {
        let _ = session.sender.try_send(error.clone());
    }
}
