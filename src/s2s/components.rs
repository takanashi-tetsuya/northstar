use crate::s2s;
use anyhow::{Context, Result};
use northstar_config::{ComponentConnectionMode, ComponentCredential};
use northstar_federation_application::components::*;
use northstar_s2s::host::ComponentHost;
use rand::{rngs::OsRng, RngCore};
use roxmltree::Document;
use sha1::Sha1;
use sha2::Digest;
use std::{
    collections::HashSet,
    future::Future,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{lookup_host, TcpListener, TcpStream},
    sync::{mpsc, OwnedSemaphorePermit},
    task::JoinSet,
    time::Instant,
};
use tokio_rustls::TlsAcceptor;
use uuid::Uuid;

mod connections;
mod session;
mod wire;

#[cfg(test)]
use self::connections::component_connect_address_allowed;
use self::connections::{component_connection, outbound_component_connection};
use self::session::{cleanup_component_muc, drive_component};
#[cfg(test)]
use self::session::{
    component_lease_renewal_period, write_component_outbox_with_renewal, ComponentOutboxWriteError,
};
use self::wire::{
    component_read_error_condition, read_handshake_frame, read_handshake_frame_after_open,
    write_component_stream_open, write_legacy_connect_open, write_legacy_stream_open,
};

// Claim exactly one durable row at a time. A component socket can spend up to
// the S2S write timeout on every stanza, so pre-claiming a large batch lets the
// leases of later rows expire before their first write begins.
const COMPONENT_OUTBOX_CLAIM_BATCH: i64 = 1;
// Bound one poll/wake turn so an always-busy outbox cannot starve frames sent
// by the component. Claims remain just-in-time within this drain budget.
const COMPONENT_OUTBOX_DRAIN_LIMIT: usize = 32;

async fn wait_for_component_shutdown(cancel: &tokio_util::sync::CancellationToken) {
    cancel.cancelled().await;
}

pub async fn serve<H: ComponentHost>(
    state: Arc<H>,
    cancel: tokio_util::sync::CancellationToken,
    listener: Option<TcpListener>,
) -> Result<()> {
    // This task participates in main's listener select. A disabled or empty
    // component configuration is an idle listener state, not a successful
    // listener termination: returning here would make main shut down every
    // otherwise healthy service.
    let policy = state.component_runtime_policy();
    if !policy.enabled || policy.max_connections == 0 || !state.has_component_credentials() {
        // A zero actor budget is an explicit hard-disable: do not bind the
        // inbound listener and do not start any connect-mode supervisor.
        wait_for_component_shutdown(&cancel).await;
        return Ok(());
    }
    let mut supervisors = JoinSet::new();
    for credential in state.component_connect_credentials() {
        for domain in credential.allowed_domains.clone() {
            let state = Arc::clone(&state);
            let cancel = cancel.clone();
            let credential = credential.clone();
            supervisors.spawn(outbound_component_supervisor(
                state, credential, domain, cancel,
            ));
        }
    }
    let accepts_connections = state.accepts_component_connections();
    if !accepts_connections {
        let result = if supervisors.is_empty() {
            wait_for_component_shutdown(&cancel).await;
            Ok(())
        } else {
            tokio::select! {
                _ = cancel.cancelled() => Ok(()),
                joined = supervisors.join_next() => {
                    component_supervisor_completion(joined, cancel.is_cancelled())
                }
            }
        };
        supervisors.abort_all();
        while supervisors.join_next().await.is_some() {}
        return result;
    }

    let listener = listener.context("external component listener was not activated")?;
    let address = listener
        .local_addr()
        .context("could not inspect external component listener")?;
    tracing::info!(%address, "XMPP external component listener ready");
    let result = loop {
        let (stream, peer) = tokio::select! {
            _ = cancel.cancelled() => break Ok(()),
            joined = supervisors.join_next(), if !supervisors.is_empty() => {
                match component_supervisor_completion(joined, cancel.is_cancelled()) {
                    Ok(()) => continue,
                    Err(error) => break Err(error),
                }
            }
            accepted = listener.accept() => accepted?,
        };
        let Ok(connection_permit) = state.try_acquire_component_connection() else {
            state.component_telemetry().connection_failed();
            tracing::debug!(%peer, "rejected component connection at the configured capacity limit");
            continue;
        };
        let state = Arc::clone(&state);
        let actors = state.connection_actors().clone();
        let connection_cancel = actors.shutdown_token().child_token();
        let actor = component_accept_actor(
            stream,
            peer,
            Arc::clone(&state),
            connection_permit,
            connection_cancel,
        );
        let result = actors.try_spawn(
            northstar_runtime::connection_actors::ConnectionActorKind::ComponentAccept,
            Some(peer.to_string()),
            actor,
        );
        if let Err(error) = result {
            tracing::debug!(%peer, ?error, "rejected component accept actor admission");
        }
    };
    supervisors.abort_all();
    while supervisors.join_next().await.is_some() {}
    result
}

fn component_supervisor_completion(
    joined: Option<std::result::Result<Result<()>, tokio::task::JoinError>>,
    cancelled: bool,
) -> Result<()> {
    if cancelled {
        return Ok(());
    }
    match joined {
        Some(Ok(Ok(()))) => anyhow::bail!("connect-mode component supervisor exited unexpectedly"),
        Some(Ok(Err(error))) => Err(error.context("connect-mode component supervisor failed")),
        Some(Err(error)) => Err(anyhow::Error::from(error)
            .context("connect-mode component supervisor panicked or was cancelled")),
        None => anyhow::bail!("all connect-mode component supervisors exited unexpectedly"),
    }
}

async fn outbound_component_supervisor<H: ComponentHost>(
    state: Arc<H>,
    credential: ComponentCredential,
    domain: String,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<()> {
    let mut consecutive_failures = 0_u32;
    loop {
        let connection_permit = tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            permit = state.acquire_component_connection() => {
                permit.context("component connection semaphore closed unexpectedly")?
            }
        };
        let actors = state.connection_actors().clone();
        let connection_cancel = actors.shutdown_token().child_token();
        let actor_state = Arc::clone(&state);
        let actor_credential = credential.clone();
        let actor_domain = domain.clone();
        let (result_tx, result_rx) = tokio::sync::oneshot::channel();
        let actor = component_connect_actor(
            actor_state,
            actor_credential,
            actor_domain,
            connection_permit,
            connection_cancel,
            result_tx,
        );
        actors
            .try_spawn(
                northstar_runtime::connection_actors::ConnectionActorKind::ComponentConnect,
                Some(domain.clone()),
                actor,
            )
            .map_err(|error| anyhow::anyhow!("component actor admission failed: {error}"))?;
        let result = tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            result = result_rx => result.context("component actor exited without a result")?,
        };
        match result {
            Ok(()) => {
                consecutive_failures = 0;
                tracing::info!(%domain, "outbound XEP-0114 component disconnected; reconnecting");
            }
            Err(error) => {
                consecutive_failures = consecutive_failures.saturating_add(1);
                state.component_telemetry().connection_failed();
                tracing::warn!(
                    %domain,
                    attempt = consecutive_failures,
                    ?error,
                    "outbound XEP-0114 component connection failed"
                );
            }
        }
        let exponent = consecutive_failures.clamp(1, 6) - 1;
        let base_millis = 1_000_u64 << exponent;
        let jitter_millis = OsRng.next_u64() % (base_millis / 2 + 1);
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            _ = tokio::time::sleep(Duration::from_millis(base_millis + jitter_millis)) => {}
        }
    }
}

async fn component_accept_actor<H: ComponentHost>(
    stream: TcpStream,
    peer: SocketAddr,
    state: Arc<H>,
    connection_permit: OwnedSemaphorePermit,
    connection_cancel: tokio_util::sync::CancellationToken,
) {
    if let Err(error) = component_connection(
        stream,
        peer,
        Arc::clone(&state),
        connection_permit,
        connection_cancel,
    )
    .await
    {
        state.component_telemetry().connection_failed();
        tracing::debug!(%peer, ?error, "external component connection closed");
    }
}

async fn component_connect_actor<H: ComponentHost>(
    state: Arc<H>,
    credential: ComponentCredential,
    domain: String,
    connection_permit: OwnedSemaphorePermit,
    connection_cancel: tokio_util::sync::CancellationToken,
    result_tx: tokio::sync::oneshot::Sender<Result<()>>,
) {
    let result = outbound_component_connection(
        state,
        credential,
        domain,
        connection_permit,
        connection_cancel,
    )
    .await;
    let _ = result_tx.send(result);
}

#[cfg(test)]
mod tests;
