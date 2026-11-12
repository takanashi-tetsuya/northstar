use super::{Action, ProtocolSession, SessionHost};
use anyhow::Result;
use northstar_roster_application::{
    BeginRosterSyncError, RosterFlushBatch, RosterRepository, RosterService, RosterSyncGate,
    RosterSyncPermit, S2sOutboxPolicy,
};
use northstar_roster_core::{LocalRosterContact, PresenceAccount, RosterChange};
use northstar_roster_xmpp::roster::RosterGetOutcome;
use northstar_roster_xmpp::{PostAcceptFailureTelemetry, RosterSessionHost};
use roxmltree::Node;
use std::sync::Arc;
use std::time::Duration;

impl<H: SessionHost + RosterSessionHost> ProtocolSession<H> {
    pub(crate) async fn roster_get(
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
                    let failure_telemetry = self.host.post_accept_failure_telemetry();
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

    pub(crate) async fn roster_set(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        query: Node<'_, '_>,
    ) -> Result<Action> {
        northstar_roster_xmpp::roster::roster_set(self, id, iq, query)
            .await
            .map(Action::Send)
    }
}

impl<H: SessionHost + RosterSessionHost> northstar_roster_xmpp::roster::RosterSession
    for ProtocolSession<H>
{
    fn roster_service(&self) -> &RosterService<impl RosterRepository<Error = anyhow::Error>> {
        self.host.roster_service()
    }

    fn roster_full_jid(&self) -> Option<&str> {
        self.full_jid.as_deref()
    }

    fn roster_begin_sync(
        &self,
        annotations_requested: bool,
    ) -> std::result::Result<RosterSyncPermit, BeginRosterSyncError> {
        self.roster_sync.begin(
            &self.roster_requested,
            &self.mix_roster_annotations,
            annotations_requested,
        )
    }

    fn roster_fail_sync(&self, permit: RosterSyncPermit) {
        self.roster_sync.fail(permit);
    }

    fn roster_disconnect(&self) {
        self.disconnect.cancel();
    }

    fn roster_is_hosted_domain(&self, domain: &str) -> bool {
        domain == self.host.muc_domain()
            || domain == self.host.upload_domain()
            || domain == self.host.pubsub_domain()
    }

    fn roster_outbox_policy(&self) -> S2sOutboxPolicy {
        self.host.roster_outbox_policy()
    }

    fn roster_wake_outbox(&self) {
        self.host.roster_wake_outbox();
    }

    async fn roster_deliver_removal_presence(
        &self,
        owner: &PresenceAccount,
        recipient: &LocalRosterContact,
        target_bare: &str,
        stanza: &str,
    ) {
        self.host
            .deliver_roster_removal_presence(owner, recipient, target_bare, stanza)
            .await;
    }

    async fn roster_push_change(
        &self,
        owner_id: uuid::Uuid,
        owner: &str,
        change: &RosterChange,
    ) -> Result<()> {
        self.host
            .deliver_committed_roster_change(owner_id, owner, change, None)
            .await
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
