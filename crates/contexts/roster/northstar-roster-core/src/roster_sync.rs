//! The in-memory ordering fence of one resource's initial roster
//! synchronization. Committed pushes are buffered until the roster result
//! owns the transport, then flushed in version order.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;

/// Upper limit on buffered committed pushes during a single initial roster sync.
pub const MAX_BUFFERED_ROSTER_CHANGES: usize = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RosterSyncPermit {
    pub generation: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub enum BeginRosterSyncError {
    AlreadySynchronizing,
    Failed,
}

#[derive(Debug, Eq, PartialEq)]
pub enum RosterPushDisposition {
    NotInterested,
    Deliver(String),
    Buffered,
    Overflow,
}

#[derive(Debug, Eq, PartialEq)]
pub enum RosterFlushBatch {
    Batch(Vec<(i64, String)>),
    Complete,
    Superseded,
    Failed,
}

#[derive(Debug)]
pub enum RosterSyncState {
    Idle,
    Synchronizing {
        generation: u64,
        buffered: BTreeMap<i64, String>,
    },
    Flushing {
        generation: u64,
        buffered: BTreeMap<i64, String>,
    },
    Failed,
}

/// In-memory ordering fence shared by `ProtocolSession` and its published
/// `OnlineSession`. Database snapshots remain short; only already-rendered
/// committed pushes are buffered while the IQ result enters the transport.
#[derive(Debug)]
pub struct RosterSyncGate {
    generation: AtomicU64,
    state: Mutex<RosterSyncState>,
}

impl Default for RosterSyncGate {
    fn default() -> Self {
        Self {
            generation: AtomicU64::new(0),
            state: Mutex::new(RosterSyncState::Idle),
        }
    }
}

impl RosterSyncGate {
    pub fn begin(
        &self,
        roster_requested: &AtomicBool,
        mix_annotations: &AtomicBool,
        annotations_requested: bool,
    ) -> std::result::Result<RosterSyncPermit, BeginRosterSyncError> {
        self.begin_with_hook(
            roster_requested,
            mix_annotations,
            annotations_requested,
            || {},
        )
    }

    pub fn begin_with_hook<F>(
        &self,
        roster_requested: &AtomicBool,
        mix_annotations: &AtomicBool,
        annotations_requested: bool,
        after_gate_entry: F,
    ) -> std::result::Result<RosterSyncPermit, BeginRosterSyncError>
    where
        F: FnOnce(),
    {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match *state {
            RosterSyncState::Idle => {}
            RosterSyncState::Failed => return Err(BeginRosterSyncError::Failed),
            RosterSyncState::Synchronizing { .. } | RosterSyncState::Flushing { .. } => {
                return Err(BeginRosterSyncError::AlreadySynchronizing);
            }
        }
        let generation = self.generation.fetch_add(1, Ordering::Relaxed) + 1;
        *state = RosterSyncState::Synchronizing {
            generation,
            buffered: BTreeMap::new(),
        };
        after_gate_entry();
        mix_annotations.store(annotations_requested, Ordering::Release);
        roster_requested.store(true, Ordering::Release);
        Ok(RosterSyncPermit { generation })
    }

    pub fn route(
        &self,
        roster_requested: &AtomicBool,
        mix_annotations: &AtomicBool,
        version: i64,
        plain_stanza: String,
        annotated_stanza: Option<String>,
    ) -> RosterPushDisposition {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !roster_requested.load(Ordering::Acquire) {
            return RosterPushDisposition::NotInterested;
        }
        let stanza = if mix_annotations.load(Ordering::Acquire) {
            annotated_stanza.unwrap_or(plain_stanza)
        } else {
            plain_stanza
        };
        match &mut *state {
            RosterSyncState::Idle => RosterPushDisposition::Deliver(stanza),
            RosterSyncState::Synchronizing { buffered, .. }
            | RosterSyncState::Flushing { buffered, .. } => {
                if buffered.contains_key(&version) {
                    return RosterPushDisposition::Buffered;
                }
                if buffered.len() >= MAX_BUFFERED_ROSTER_CHANGES {
                    *state = RosterSyncState::Failed;
                    return RosterPushDisposition::Overflow;
                }
                buffered.insert(version, stanza);
                RosterPushDisposition::Buffered
            }
            RosterSyncState::Failed => RosterPushDisposition::Overflow,
        }
    }

    pub fn start_flush(&self, permit: RosterSyncPermit, snapshot_version: i64) -> RosterFlushBatch {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let prior = std::mem::replace(&mut *state, RosterSyncState::Failed);
        let (generation, mut buffered) = match prior {
            RosterSyncState::Synchronizing {
                generation,
                buffered,
            } if generation == permit.generation => (generation, buffered),
            RosterSyncState::Failed => return RosterFlushBatch::Failed,
            prior => {
                *state = prior;
                return RosterFlushBatch::Superseded;
            }
        };
        buffered.retain(|version, _| *version > snapshot_version);
        *state = RosterSyncState::Flushing {
            generation,
            buffered,
        };
        self.next_batch_locked(&mut state, permit)
    }

    pub fn next_flush_batch(&self, permit: RosterSyncPermit) -> RosterFlushBatch {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.next_batch_locked(&mut state, permit)
    }

    fn next_batch_locked(
        &self,
        state: &mut RosterSyncState,
        permit: RosterSyncPermit,
    ) -> RosterFlushBatch {
        match state {
            RosterSyncState::Flushing {
                generation,
                buffered,
            } if *generation == permit.generation => {
                if buffered.is_empty() {
                    *state = RosterSyncState::Idle;
                    RosterFlushBatch::Complete
                } else {
                    RosterFlushBatch::Batch(std::mem::take(buffered).into_iter().collect())
                }
            }
            RosterSyncState::Failed => RosterFlushBatch::Failed,
            _ => RosterFlushBatch::Superseded,
        }
    }

    pub fn fail(&self, permit: RosterSyncPermit) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let matches = match &*state {
            RosterSyncState::Synchronizing { generation, .. }
            | RosterSyncState::Flushing { generation, .. } => *generation == permit.generation,
            RosterSyncState::Idle | RosterSyncState::Failed => false,
        };
        if matches {
            *state = RosterSyncState::Failed;
        }
    }
}

#[cfg(test)]
mod tests;
