// From src/xmpp/protocol/roster.rs.
use crate::PostAcceptFailureTelemetry;
use northstar_roster_application::{RosterFlushBatch, RosterSyncGate, RosterSyncPermit};
use std::sync::Arc;
use std::time::Duration;

pub(super) struct RosterSyncFlush {
    pub(super) failure_telemetry: PostAcceptFailureTelemetry,
    pub(super) outbound: northstar_stream::outbound::OutboundSender,
    pub(super) gate: Arc<RosterSyncGate>,
    pub(super) disconnect: tokio_util::sync::CancellationToken,
    pub(super) permit: RosterSyncPermit,
    pub(super) snapshot_version: i64,
    pub(super) initial_delta: Vec<String>,
    pub(super) target: String,
}

pub(super) async fn flush_roster_sync(request: RosterSyncFlush) {
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
