//! Local MUC occupant records, their endpoints and suspended SM endpoint buffers.

use crate::services::muc::{LocalMucOccupantIdentity, SerializableMucOccupant};
use std::{collections::VecDeque, sync::Arc};

#[derive(Clone)]
pub struct MucOccupant {
    pub full_jid: String,
    pub room_jid: String,
    pub nick: String,
    pub endpoint: MucOccupantEndpoint,
    pub affiliation: String,
    pub role: String,
    pub room_non_anonymous: bool,
    pub occupant_id: String,
    /// Per-occupancy ABA guard used for atomic nickname changes in Redis.
    /// This value is internal and is never exposed in XMPP stanzas.
    pub cluster_epoch: uuid::Uuid,
    /// Exact transport incarnation which owns this occupancy.  A resumed SM
    /// stream updates this value while preserving the occupancy epoch; a
    /// recreated post-crash occupancy receives a fresh epoch.
    pub connection_id: uuid::Uuid,
    /// Durable stream epoch owning this local occupant, when XEP-0198
    /// resumption is enabled.
    pub sm_session_id: Option<uuid::Uuid>,
    pub payload: String,
}

impl<'a> From<&'a MucOccupant> for LocalMucOccupantIdentity<'a> {
    fn from(occupant: &'a MucOccupant) -> Self {
        Self {
            room_jid: &occupant.room_jid,
            nick: &occupant.nick,
            full_jid: &occupant.full_jid,
            connection_id: occupant.connection_id,
            cluster_epoch: occupant.cluster_epoch,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LocalMucNicknameMove {
    Published,
    AlreadyPublished,
    DeferredToReconciliation,
    OldMissing,
    CollisionRestored,
    CollisionRestoreFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LocalMucJoinPublication {
    Published,
    AlreadyPublished,
    Occupied,
}

impl From<&MucOccupant> for SerializableMucOccupant {
    fn from(occ: &MucOccupant) -> Self {
        Self {
            full_jid: occ.full_jid.clone(),
            room_jid: occ.room_jid.clone(),
            nick: occ.nick.clone(),
            affiliation: occ.affiliation.clone(),
            role: occ.role.clone(),
            room_non_anonymous: occ.room_non_anonymous,
            occupant_id: occ.occupant_id.clone(),
            cluster_epoch: occ.cluster_epoch,
            connection_id: occ.connection_id,
            federated_domain: match &occ.endpoint {
                MucOccupantEndpoint::Local(_) | MucOccupantEndpoint::Suspended(_) => None,
                MucOccupantEndpoint::Federated {
                    authenticated_domain,
                    ..
                } => Some(authenticated_domain.clone()),
            },
            sm_session_id: occ.sm_session_id,
            payload: occ.payload.clone(),
        }
    }
}

pub(crate) fn muc_departure_identity_matches(
    occupant: &MucOccupant,
    full_jid: &str,
    connection_id: uuid::Uuid,
    cluster_epoch: uuid::Uuid,
) -> bool {
    !connection_id.is_nil()
        && !cluster_epoch.is_nil()
        && occupant.full_jid == full_jid
        && occupant.connection_id == connection_id
        && occupant.cluster_epoch == cluster_epoch
}

#[derive(Clone)]
pub enum MucOccupantEndpoint {
    Local(crate::xmpp::outbound::OutboundSender),
    /// A local occupant whose transport disappeared while a durable XEP-0198
    /// resume window is open.  Traffic is bounded and moved into PostgreSQL;
    /// it is never sent into the dead transport channel.
    Suspended(Arc<SuspendedMucEndpoint>),
    Federated {
        authenticated_domain: String,
        connection_id: uuid::Uuid,
    },
}

pub struct SuspendedMucEndpoint {
    pub sm_session_id: uuid::Uuid,
    /// The synchronous route fence is present for the complete lifetime of an
    /// SM-associated resource, including while it is live.  A delivery holds
    /// this mutex through `try_send`, while disconnect changes Live to
    /// Transitioning under the same mutex.  Consequently no sender can observe
    /// the old transport after suspension has begun.
    pub(crate) route: std::sync::Mutex<SuspendedMucRoute>,
    pub(crate) buffer: tokio::sync::Mutex<SuspendedMucBuffer>,
    pub(crate) changed: tokio::sync::Notify,
    /// Shared actual-byte lease for the durable stream plus its process-local
    /// MUC suffix. Clones across room occupants reference one reservation.
    pub(crate) sm_capacity: std::sync::Mutex<Option<crate::services::sm_capacity::SmCapacityLease>>,
}

#[derive(Clone)]
pub(crate) enum SuspendedMucRoute {
    Live(crate::xmpp::outbound::OutboundSender),
    /// A short synchronous hand-off. Deliveries wait rather than falling back
    /// to a stale occupant-local sender.
    Transitioning,
    Suspended,
}

pub(crate) struct SuspendedMucBuffer {
    pub(crate) phase: SuspendedMucPhase,
    /// True only when the exact snapshot used by a committed-or-ambiguous SM
    /// transaction already contains this buffer's suffix. Keeping ownership
    /// separate from the delivery phase preserves it across Sealed->Waiting
    /// resume races without making an error state writable.
    pub(crate) snapshot_owned: bool,
    /// Already-sequenced SM traffic consumes the same stanza and byte budget
    /// as this volatile suffix.  Charging it here prevents a disconnect with
    /// a nearly-full unacked queue from opening a second independent queue.
    pub(crate) base_stanzas: usize,
    pub(crate) base_bytes: usize,
    pub(crate) bytes: usize,
    pub(crate) stanzas: VecDeque<SuspendedMucStanza>,
}

#[derive(Clone)]
pub(crate) struct SuspendedMucStanza {
    pub(crate) source_id: uuid::Uuid,
    pub(crate) xml: String,
}

#[derive(Clone, Debug)]
pub(crate) enum SuspendedMucPhase {
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
    pub(crate) fn enqueue_volatile(
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
    pub(crate) fn commit_front(&mut self) {
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
    pub(crate) fn try_send_live_write_notification(
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

    #[cfg(test)]
    pub fn new(sm_session_id: uuid::Uuid) -> Self {
        Self::new_collecting(sm_session_id, 0, 0)
    }

    pub(crate) fn new_live(
        sm_session_id: uuid::Uuid,
        sender: crate::xmpp::outbound::OutboundSender,
    ) -> Self {
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

    pub(crate) fn new_collecting(
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

    pub(crate) fn new_reserved(
        sm_session_id: uuid::Uuid,
        base_stanzas: usize,
        base_bytes: usize,
    ) -> Self {
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

    pub(crate) fn new_durable(sm_session_id: uuid::Uuid) -> Self {
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

pub(crate) struct RestoreLocalMucOccupantsRequest<'a> {
    pub(crate) user: &'a crate::services::authentication::AuthenticatedAccount,
    pub(crate) full_jid: &'a str,
    pub(crate) connection_id: uuid::Uuid,
    pub(crate) sm_session_id: uuid::Uuid,
    pub(crate) memberships: &'a [crate::services::sm::SmMucMembership],
    pub(crate) base_stanzas: usize,
    pub(crate) base_bytes: usize,
}
