use crate::roster::{roster_change_item_element, roster_push_xml};
use crate::{PostAcceptFailureTelemetry, RosterJournalReader, RosterSessionHost, SessionIdentity};
use anyhow::Result;
use northstar_roster_application::SystemRosterEvents;
use northstar_roster_core::{
    RosterActor, RosterEventSource as _, RosterFlushBatch, RosterGap, RosterReadSnapshot,
    RosterSyncGate, RosterSyncPermit,
};
use northstar_stream::outbound::OutboundSender;
use northstar_stream::protocol::{ProtocolSession, SessionHost};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

pub(super) struct RosterSyncDrain<H> {
    host: Weak<H>,
    gate: Weak<RosterSyncGate>,
    outbound: OutboundSender,
    disconnect: CancellationToken,
    failure_telemetry: PostAcceptFailureTelemetry,
    actor: RosterActor,
    mix_annotations: Arc<AtomicBool>,
}

pub(super) fn prepare_roster_sync<H: SessionHost + RosterSessionHost>(
    session: &ProtocolSession<H>,
    permit: RosterSyncPermit,
    target: String,
) -> Result<Arc<RosterSyncDrain<H>>> {
    let Some(actor) = session
        .roster_actor()
        .filter(|actor| actor.full_jid == target)
    else {
        session.roster_sync.fail(permit);
        session.disconnect.cancel();
        anyhow::bail!("roster synchronization requires the bound actor");
    };
    let drain = Arc::new(RosterSyncDrain {
        host: Arc::downgrade(session.host()),
        gate: Arc::downgrade(&session.roster_sync),
        outbound: session.outbound.clone(),
        disconnect: session.disconnect.clone(),
        failure_telemetry: session.host().post_accept_failure_telemetry(),
        actor,
        mix_annotations: Arc::clone(&session.mix_roster_annotations),
    });
    let repair = Arc::clone(&drain);
    session
        .roster_sync
        .set_repair_scheduler(permit, move |permit| {
            let repair = Arc::clone(&repair);
            tokio::spawn(async move {
                if let Some(gate) = repair.gate.upgrade() {
                    repair
                        .drain(&gate, permit, gate.next_flush_batch(permit))
                        .await;
                }
            });
        });
    Ok(drain)
}

impl<H: SessionHost + RosterSessionHost> RosterSyncDrain<H> {
    pub(super) async fn flush_roster_sync(
        &self,
        permit: RosterSyncPermit,
        snapshot_version: i64,
        initial_delta: Vec<String>,
    ) {
        let Some(gate) = self.gate.upgrade() else {
            return;
        };
        for stanza in initial_delta {
            if !self.enqueue(stanza).await {
                self.resync(&gate, permit);
                return;
            }
        }
        self.drain(&gate, permit, gate.start_flush(permit, snapshot_version))
            .await;
    }

    async fn drain(
        &self,
        gate: &RosterSyncGate,
        permit: RosterSyncPermit,
        mut batch: RosterFlushBatch,
    ) {
        loop {
            let pushes = match batch {
                RosterFlushBatch::Batch(pushes) => pushes,
                RosterFlushBatch::Repair(gap) => {
                    let proof = self.read_repair(gap).await;
                    let Some(pushes) = gate.repair_batch(permit, gap, proof) else {
                        self.resync(gate, permit);
                        return;
                    };
                    pushes
                }
                RosterFlushBatch::Complete
                | RosterFlushBatch::Failed
                | RosterFlushBatch::Superseded => return,
            };
            for (version, stanza) in pushes {
                if !self.enqueue(stanza).await || !gate.accept_flushed(permit, version) {
                    self.resync(gate, permit);
                    return;
                }
            }
            batch = gate.next_flush_batch(permit);
        }
    }

    async fn read_repair(&self, gap: RosterGap) -> Option<Vec<(i64, String)>> {
        gap.bounded_count()?;
        let host = self.host.upgrade()?;
        let owner = (self.actor.account_id, self.actor.auth_generation);
        let annotations = self.mix_annotations.load(Ordering::Acquire);
        let RosterReadSnapshot {
            changes,
            mix_participants,
            ..
        } = match RosterJournalReader::read_roster_gap(host.as_ref(), owner, gap, annotations).await
        {
            Ok(snapshot) => snapshot?,
            Err(error) => {
                tracing::warn!(?error, "could not read roster push gap");
                return None;
            }
        };
        Some(
            changes?
                .into_iter()
                .map(|change| {
                    let participant = mix_participants
                        .get(&change.contact_jid)
                        .map(String::as_str);
                    let item = roster_change_item_element(&change, participant);
                    // Gap repair runs detached from the session borrow, so
                    // it draws stanza IDs from the system event source.
                    let stanza = roster_push_xml(
                        self.actor.bare_jid(),
                        &self.actor.full_jid,
                        change.version,
                        item,
                        SystemRosterEvents.new_protocol_id(),
                    );
                    (change.version, stanza)
                })
                .collect(),
        )
    }

    async fn enqueue(&self, stanza: String) -> bool {
        let is_current = || {
            !self.disconnect.is_cancelled()
                && self.host.upgrade().is_some_and(|host| {
                    host.session_entries_for(&self.actor.full_jid)
                        .into_iter()
                        .any(|(_, current)| {
                            current.user_id == self.actor.account_id
                                && current.auth_generation == self.actor.auth_generation
                                && current.connection_id == self.actor.connection_id
                                && !current.disconnect.is_cancelled()
                                && current.roster_requested.load(Ordering::Acquire)
                        })
                })
        };
        matches!(
            tokio::time::timeout(
                Duration::from_secs(5),
                self.outbound
                    .send_if_current(stanza, is_current, std::future::ready(true)),
            )
            .await,
            Ok(Ok(true))
        )
    }

    fn resync(&self, gate: &RosterSyncGate, permit: RosterSyncPermit) {
        if gate.fail(permit) {
            self.outbound.disconnect_backpressured_transport();
            self.disconnect.cancel();
            self.failure_telemetry.record_failure();
            tracing::warn!(target = %self.actor.full_jid, "roster synchronization could not prove or deliver an ordered delta; forcing a full resync");
        }
    }
}
