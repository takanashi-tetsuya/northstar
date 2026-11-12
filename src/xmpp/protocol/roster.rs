use super::{Action, ProtocolSession, SessionHost};
use anyhow::Result;
use northstar_roster_application::{RosterFlushBatch, RosterSyncGate, RosterSyncPermit};
use northstar_roster_xmpp::roster::RosterGetOutcome;
use northstar_roster_xmpp::{PostAcceptFailureTelemetry, RosterSessionHost};
use roxmltree::Node;
use std::sync::Arc;
use std::time::Duration;

/// The session handlers of roster.rs.
pub(crate) trait RosterHandlers {
    async fn roster_get(
        &mut self,
        id: &str,
        iq: Node<'_, '_>,
        query: Node<'_, '_>,
    ) -> Result<Action>;

    async fn roster_set(&self, id: &str, iq: Node<'_, '_>, query: Node<'_, '_>) -> Result<Action>;
}

impl<H: SessionHost + RosterSessionHost> RosterHandlers for ProtocolSession<H> {
    async fn roster_get(
        &mut self,
        id: &str,
        iq: Node<'_, '_>,
        query: Node<'_, '_>,
    ) -> Result<Action> {
        Ok(
            match northstar_roster_xmpp::roster::roster_get(&*self, id, iq, query).await? {
                RosterGetOutcome::Reply(response) => Action::Send(response),
                RosterGetOutcome::Synchronize {
                    response,
                    permit,
                    snapshot_version,
                    initial_delta,
                    target,
                } => {
                    let failure_telemetry = self.host().post_accept_failure_telemetry();
                    let outbound = self.outbound.clone();
                    let gate = Arc::clone(&self.roster_sync);
                    let disconnect = self.disconnect.clone();
                    self.defer_after_transport("roster-initial-sync", async move {
                        flush_roster_sync(RosterSyncFlush {
                            failure_telemetry,
                            outbound,
                            gate,
                            disconnect,
                            permit,
                            snapshot_version,
                            initial_delta,
                            target,
                        })
                        .await;
                    })?;
                    Action::Send(response)
                }
            },
        )
    }

    async fn roster_set(&self, id: &str, iq: Node<'_, '_>, query: Node<'_, '_>) -> Result<Action> {
        northstar_roster_xmpp::roster::roster_set(self, id, iq, query)
            .await
            .map(Action::Send)
    }
}

struct RosterSyncFlush {
    failure_telemetry: PostAcceptFailureTelemetry,
    outbound: northstar_stream::outbound::OutboundSender,
    gate: Arc<RosterSyncGate>,
    disconnect: tokio_util::sync::CancellationToken,
    permit: RosterSyncPermit,
    snapshot_version: i64,
    initial_delta: Vec<String>,
    target: String,
}

async fn flush_roster_sync(request: RosterSyncFlush) {
    let RosterSyncFlush {
        failure_telemetry,
        outbound,
        gate,
        disconnect,
        permit,
        snapshot_version,
        initial_delta,
        target,
    } = request;
    async fn enqueue(
        outbound: &northstar_stream::outbound::OutboundSender,
        stanza: String,
    ) -> bool {
        matches!(
            tokio::time::timeout(Duration::from_secs(5), outbound.send(stanza)).await,
            Ok(Ok(()))
        )
    }

    for stanza in initial_delta {
        if !enqueue(&outbound, stanza).await {
            gate.fail(permit);
            outbound.disconnect_backpressured_transport();
            disconnect.cancel();
            failure_telemetry.record_failure();
            tracing::warn!(%target, "roster delta could not enter the transport; forcing a full resync");
            return;
        }
    }

    let mut batch = gate.start_flush(permit, snapshot_version);
    loop {
        match batch {
            RosterFlushBatch::Batch(pushes) => {
                for (version, stanza) in pushes {
                    if !enqueue(&outbound, stanza).await {
                        gate.fail(permit);
                        outbound.disconnect_backpressured_transport();
                        disconnect.cancel();
                        failure_telemetry.record_failure();
                        tracing::warn!(%target, version, "buffered roster push could not enter the transport; forcing a full resync");
                        return;
                    }
                }
                batch = gate.next_flush_batch(permit);
            }
            RosterFlushBatch::Complete => return,
            RosterFlushBatch::Failed | RosterFlushBatch::Superseded => {
                outbound.disconnect_backpressured_transport();
                disconnect.cancel();
                failure_telemetry.record_failure();
                tracing::warn!(%target, "roster synchronization fence failed; forcing a full resync");
                return;
            }
        }
    }
}
