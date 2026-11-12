//! Local MUC occupant records, their endpoints and suspended SM endpoint buffers.

use crate::outbound::OutboundSender;
use northstar_room_core::occupancy;
use std::collections::VecDeque;

pub type MucOccupant = occupancy::MucOccupant<OutboundSender, SuspendedMucEndpoint>;
pub type MucOccupantEndpoint = occupancy::MucOccupantEndpoint<OutboundSender, SuspendedMucEndpoint>;

pub struct SuspendedMucEndpoint {
    pub sm_session_id: uuid::Uuid,
    /// The synchronous route fence is present for the complete lifetime of an
    /// SM-associated resource, including while it is live.  A delivery holds
    /// this mutex through `try_send`, while disconnect changes Live to
    /// Transitioning under the same mutex.  Consequently no sender can observe
    /// the old transport after suspension has begun.
    pub route: std::sync::Mutex<SuspendedMucRoute>,
    pub buffer: tokio::sync::Mutex<SuspendedMucBuffer>,
    pub changed: tokio::sync::Notify,
    /// Shared actual-byte lease for the durable stream plus its process-local
    /// MUC suffix. Clones across room occupants reference one reservation.
    pub sm_capacity:
        std::sync::Mutex<Option<northstar_session_application::sm_capacity::SmCapacityLease>>,
}

#[derive(Clone)]
pub enum SuspendedMucRoute {
    Live(crate::outbound::OutboundSender),
    /// A short synchronous hand-off. Deliveries wait rather than falling back
    /// to a stale occupant-local sender.
    Transitioning,
    Suspended,
}

pub struct SuspendedMucBuffer {
    pub phase: SuspendedMucPhase,
    /// True only when the exact snapshot used by a committed-or-ambiguous SM
    /// transaction already contains this buffer's suffix. Keeping ownership
    /// separate from the delivery phase preserves it across Sealed->Waiting
    /// resume races without making an error state writable.
    pub snapshot_owned: bool,
    /// Already-sequenced SM traffic consumes the same stanza and byte budget
    /// as this volatile suffix.  Charging it here prevents a disconnect with
    /// a nearly-full unacked queue from opening a second independent queue.
    pub base_stanzas: usize,
    pub base_bytes: usize,
    pub bytes: usize,
    pub stanzas: VecDeque<SuspendedMucStanza>,
}

#[derive(Clone)]
pub struct SuspendedMucStanza {
    pub source_id: uuid::Uuid,
    pub xml: String,
}

#[derive(Clone, Debug)]
pub enum SuspendedMucPhase {
    /// The route mutex owns the live sender; the suspended queue is empty.
    Dormant,
    /// Short synchronous hand-off from the old live route to the durable SM
    /// row.  Volatile admission is bounded by the complete SM budget.
    Collecting,
    /// PostgreSQL owns subsequent delivery and the process-local suffix is
    /// empty.
    Durable,
    /// Resume has fenced durable appends but has not yet received the current
    /// queue size from PostgreSQL. New delivery waits for the exact base.
    Waiting,
    /// One exact resume claim is collecting the final globally-ordered suffix.
    Resuming,
    /// A process-restart restore reserved the nickname but must reject traffic
    /// until its PostgreSQL CAS and SM checkpoint have both committed.
    Reserved,
    /// The suffix has been snapshotted for an atomic SM checkpoint.  No new
    /// traffic is acknowledged while the checkpoint is in flight.
    Committing,
    /// PostgreSQL owns the complete replay queue. The buffer is empty, but the
    /// route stays suspended until `<resumed/>` and replay reach the socket.
    CheckpointOwned,
    /// Fail-closed terminal/intermediate state.  Retained traffic remains
    /// available for durable promotion, but new volatile traffic is rejected.
    Sealed,
}

impl SuspendedMucBuffer {
    pub fn enqueue_volatile(
        &mut self,
        stanza: String,
        max_stanzas: usize,
        max_bytes: usize,
    ) -> bool {
        if !matches!(
            &self.phase,
            SuspendedMucPhase::Collecting | SuspendedMucPhase::Resuming
        ) {
            return false;
        }
        let Some(next_bytes) = self.bytes.checked_add(stanza.len()) else {
            return false;
        };
        let Some(total_stanzas) = self.base_stanzas.checked_add(self.stanzas.len() + 1) else {
            return false;
        };
        let Some(total_bytes) = self.base_bytes.checked_add(next_bytes) else {
            return false;
        };
        if total_stanzas > max_stanzas || total_bytes > max_bytes {
            return false;
        }
        self.bytes = next_bytes;
        self.stanzas.push_back(SuspendedMucStanza {
            source_id: uuid::Uuid::new_v4(),
            xml: stanza,
        });
        true
    }

    /// Remove only a stanza whose next owner has already accepted it.  Using
    /// the actual front length (rather than clearing/saturating the counter)
    /// keeps the byte bound exact after a first or mid-drain failure.
    pub fn commit_front(&mut self) {
        let stanza = self
            .stanzas
            .pop_front()
            .expect("a suspended MUC drain can commit only its current front");
        self.bytes = self
            .bytes
            .checked_sub(stanza.xml.len())
            .expect("suspended MUC byte accounting must match its queue");
    }
}

impl SuspendedMucEndpoint {
    pub fn try_send_live_write_notification(
        &self,
        stanza: String,
        receipt: tokio::sync::mpsc::UnboundedSender<()>,
    ) -> anyhow::Result<bool> {
        let route = self
            .route
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let SuspendedMucRoute::Live(sender) = &*route else {
            // A write-only completion cannot transfer into durable or volatile
            // SM storage, nor cross a concurrent Live-to-Transitioning fence.
            return Ok(false);
        };
        match sender.try_send_with_transport_write_receipt(stanza, receipt) {
            Ok(()) => Ok(true),
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => Ok(false),
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                anyhow::bail!("live SM shutdown recipient queue is full")
            }
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn new(sm_session_id: uuid::Uuid) -> Self {
        Self::new_collecting(sm_session_id, 0, 0)
    }

    pub fn new_live(sm_session_id: uuid::Uuid, sender: crate::outbound::OutboundSender) -> Self {
        Self {
            sm_session_id,
            route: std::sync::Mutex::new(SuspendedMucRoute::Live(sender)),
            buffer: tokio::sync::Mutex::new(SuspendedMucBuffer {
                phase: SuspendedMucPhase::Dormant,
                snapshot_owned: false,
                base_stanzas: 0,
                base_bytes: 0,
                bytes: 0,
                stanzas: VecDeque::new(),
            }),
            changed: tokio::sync::Notify::new(),
            sm_capacity: std::sync::Mutex::new(None),
        }
    }

    pub fn new_collecting(
        sm_session_id: uuid::Uuid,
        base_stanzas: usize,
        base_bytes: usize,
    ) -> Self {
        Self {
            sm_session_id,
            route: std::sync::Mutex::new(SuspendedMucRoute::Suspended),
            buffer: tokio::sync::Mutex::new(SuspendedMucBuffer {
                phase: SuspendedMucPhase::Collecting,
                snapshot_owned: false,
                base_stanzas,
                base_bytes,
                bytes: 0,
                stanzas: VecDeque::new(),
            }),
            changed: tokio::sync::Notify::new(),
            sm_capacity: std::sync::Mutex::new(None),
        }
    }

    pub fn new_reserved(sm_session_id: uuid::Uuid, base_stanzas: usize, base_bytes: usize) -> Self {
        Self {
            sm_session_id,
            route: std::sync::Mutex::new(SuspendedMucRoute::Suspended),
            buffer: tokio::sync::Mutex::new(SuspendedMucBuffer {
                phase: SuspendedMucPhase::Reserved,
                snapshot_owned: false,
                base_stanzas,
                base_bytes,
                bytes: 0,
                stanzas: VecDeque::new(),
            }),
            changed: tokio::sync::Notify::new(),
            sm_capacity: std::sync::Mutex::new(None),
        }
    }

    pub fn new_durable(sm_session_id: uuid::Uuid) -> Self {
        Self {
            sm_session_id,
            route: std::sync::Mutex::new(SuspendedMucRoute::Suspended),
            buffer: tokio::sync::Mutex::new(SuspendedMucBuffer {
                phase: SuspendedMucPhase::Durable,
                snapshot_owned: false,
                base_stanzas: 0,
                base_bytes: 0,
                bytes: 0,
                stanzas: VecDeque::new(),
            }),
            changed: tokio::sync::Notify::new(),
            sm_capacity: std::sync::Mutex::new(None),
        }
    }
}

pub struct RestoreLocalMucOccupantsRequest<'a> {
    pub user: &'a northstar_auth_application::authentication::AuthenticatedAccount,
    pub full_jid: &'a str,
    pub connection_id: uuid::Uuid,
    pub sm_session_id: uuid::Uuid,
    pub memberships: &'a [northstar_session_application::sm::SmMucMembership],
    pub base_stanzas: usize,
    pub base_bytes: usize,
}

/// The local MUC occupancies a resumed stream restored, as the session reads them before it commits or aborts the
/// restore through its host.
pub trait RestoredMucOccupancy: Send + Sync + 'static {
    /// The memberships that could not be proven valid.
    fn failures(&self) -> &[northstar_session_application::sm::SmMucMembership];
    /// The volatile suspension FIFO in order; the stream emits it after `<resumed/>` and the durable unacked replay.
    fn replay_suffix(&self) -> &[String];
    /// The memberships the restore reattaches.
    fn planned_memberships(&self) -> Vec<northstar_session_application::sm::SmMucMembership>;
    /// The joined-room entries of the planned memberships.
    fn planned_joined_rooms(&self) -> Vec<(String, northstar_session_core::JoinedMucMembership)>;
}

/// The memberships a committed MUC restore reattached and the ones it lost.
pub struct CommittedLocalMucResume {
    pub joined_rooms: Vec<(String, northstar_session_core::JoinedMucMembership)>,
    pub failures: Vec<northstar_session_application::sm::SmMucMembership>,
}
