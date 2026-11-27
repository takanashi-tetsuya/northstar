//! The in-memory ordering fence of one resource's initial roster
//! synchronization. Committed pushes are buffered until the roster result
//! owns the transport, then flushed in version order.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use crate::RosterVersion;

/// Upper limit on buffered committed pushes during a single initial roster sync.
pub const MAX_BUFFERED_ROSTER_CHANGES: usize = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RosterSyncPermit {
    pub generation: u64,
    cursor: Option<RosterVersion>,
}

impl RosterSyncPermit {
    pub fn requested_version(self, requested: Option<i64>) -> Option<i64> {
        requested.filter(|version| self.cursor.is_none_or(|cursor| *version >= cursor.0))
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum BeginRosterSyncError {
    AlreadySynchronizing,
    Failed,
}

#[derive(Debug, Eq, PartialEq)]
pub enum RosterPushDisposition {
    NotInterested,
    Delivered,
    Covered,
    Buffered,
    Resync,
    Failed,
}

#[derive(Debug, Eq, PartialEq)]
pub enum RosterFlushBatch {
    Batch(Vec<(i64, String)>),
    Repair(RosterGap),
    Complete,
    Superseded,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RosterGap {
    pub after: RosterVersion,
    pub through: RosterVersion,
}

impl RosterGap {
    pub fn bounded_count(self) -> Option<usize> {
        let count = usize::try_from(self.through.0.checked_sub(self.after.0)?).ok()?;
        (self.after.0 >= 0 && (1..=MAX_BUFFERED_ROSTER_CHANGES).contains(&count)).then_some(count)
    }
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
pub struct RosterSyncGate(Mutex<SyncInner>);

type ScheduleRepair = Arc<dyn Fn(RosterSyncPermit) + Send + Sync>;

struct SyncInner {
    generation: u64,
    state: RosterSyncState,
    cursor: Option<RosterVersion>,
    in_flight_through: Option<i64>,
    schedule_repair: Option<ScheduleRepair>,
}

impl std::fmt::Debug for RosterSyncGate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RosterSyncGate")
            .finish_non_exhaustive()
    }
}

impl Default for RosterSyncGate {
    fn default() -> Self {
        Self(Mutex::new(SyncInner {
            generation: 0,
            state: RosterSyncState::Idle,
            cursor: None,
            in_flight_through: None,
            schedule_repair: None,
        }))
    }
}

impl RosterSyncGate {
    fn lock(&self) -> MutexGuard<'_, SyncInner> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn set_repair_scheduler(
        &self,
        permit: RosterSyncPermit,
        schedule: impl Fn(RosterSyncPermit) + Send + Sync + 'static,
    ) {
        let mut inner = self.lock();
        if matches!(inner.state, RosterSyncState::Synchronizing { generation, .. } if generation == permit.generation)
        {
            inner.schedule_repair = Some(Arc::new(schedule));
        }
    }

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
        let mut inner = self.lock();
        match inner.state {
            RosterSyncState::Idle => {}
            RosterSyncState::Failed => return Err(BeginRosterSyncError::Failed),
            RosterSyncState::Synchronizing { .. } | RosterSyncState::Flushing { .. } => {
                return Err(BeginRosterSyncError::AlreadySynchronizing);
            }
        }
        inner.generation += 1;
        let generation = inner.generation;
        inner.state = RosterSyncState::Synchronizing {
            generation,
            buffered: BTreeMap::new(),
        };
        after_gate_entry();
        mix_annotations.store(annotations_requested, Ordering::Release);
        roster_requested.store(true, Ordering::Release);
        Ok(RosterSyncPermit {
            generation,
            cursor: inner.cursor,
        })
    }

    pub fn route(
        &self,
        roster_requested: &AtomicBool,
        mix_annotations: &AtomicBool,
        version: i64,
        plain_stanza: String,
        annotated_stanza: Option<String>,
        enqueue: impl FnOnce(String) -> bool,
    ) -> RosterPushDisposition {
        let mut guard = self.lock();
        let inner = &mut *guard;
        if !roster_requested.load(Ordering::Acquire) {
            return RosterPushDisposition::NotInterested;
        }
        if matches!(inner.state, RosterSyncState::Failed) {
            return RosterPushDisposition::Failed;
        }
        if inner.cursor.is_some_and(|cursor| version <= cursor.0) {
            return RosterPushDisposition::Covered;
        }
        if inner
            .in_flight_through
            .is_some_and(|through| version <= through)
        {
            return RosterPushDisposition::Buffered;
        }
        let stanza = if mix_annotations.load(Ordering::Acquire) {
            annotated_stanza.unwrap_or(plain_stanza)
        } else {
            plain_stanza
        };
        match &mut inner.state {
            RosterSyncState::Idle => {
                if inner.cursor.and_then(|cursor| cursor.0.checked_add(1)) == Some(version) {
                    if enqueue(stanza) {
                        inner.cursor = Some(RosterVersion(version));
                        return RosterPushDisposition::Delivered;
                    }
                } else if let Some((after, schedule)) =
                    inner.cursor.zip(inner.schedule_repair.clone())
                {
                    inner.generation += 1;
                    let generation = inner.generation;
                    inner.state = RosterSyncState::Flushing {
                        generation,
                        buffered: BTreeMap::from([(version, stanza)]),
                    };
                    drop(guard);
                    schedule(RosterSyncPermit {
                        generation,
                        cursor: Some(after),
                    });
                    return RosterPushDisposition::Buffered;
                }
                inner.state = RosterSyncState::Failed;
                RosterPushDisposition::Resync
            }
            RosterSyncState::Synchronizing { buffered, .. }
            | RosterSyncState::Flushing { buffered, .. } => {
                if buffered.contains_key(&version) {
                    return RosterPushDisposition::Buffered;
                }
                if buffered.len() >= MAX_BUFFERED_ROSTER_CHANGES {
                    inner.state = RosterSyncState::Failed;
                    return RosterPushDisposition::Resync;
                }
                buffered.insert(version, stanza);
                RosterPushDisposition::Buffered
            }
            RosterSyncState::Failed => RosterPushDisposition::Failed,
        }
    }

    pub fn start_flush(&self, permit: RosterSyncPermit, snapshot_version: i64) -> RosterFlushBatch {
        let mut inner = self.lock();
        let prior = std::mem::replace(&mut inner.state, RosterSyncState::Failed);
        let (generation, mut buffered) = match prior {
            RosterSyncState::Synchronizing {
                generation,
                buffered,
            } if generation == permit.generation => (generation, buffered),
            RosterSyncState::Failed => return RosterFlushBatch::Failed,
            prior => {
                inner.state = prior;
                return RosterFlushBatch::Superseded;
            }
        };
        let snapshot = RosterVersion(snapshot_version);
        buffered.retain(|version, _| *version > snapshot.0);
        inner.cursor = Some(snapshot);
        inner.state = RosterSyncState::Flushing {
            generation,
            buffered,
        };
        Self::next_batch_locked(&mut inner, permit)
    }

    pub fn next_flush_batch(&self, permit: RosterSyncPermit) -> RosterFlushBatch {
        Self::next_batch_locked(&mut self.lock(), permit)
    }

    fn next_batch_locked(inner: &mut SyncInner, permit: RosterSyncPermit) -> RosterFlushBatch {
        if inner.in_flight_through.is_some() && !matches!(inner.state, RosterSyncState::Failed) {
            return RosterFlushBatch::Superseded;
        }
        match &mut inner.state {
            RosterSyncState::Flushing {
                generation,
                buffered,
            } if *generation == permit.generation => {
                let cursor = inner.cursor.expect("flushing has a roster cursor");
                let Some((&first, _)) = buffered.first_key_value() else {
                    inner.state = RosterSyncState::Idle;
                    return RosterFlushBatch::Complete;
                };
                if cursor.0.checked_add(1) != Some(first) {
                    return RosterFlushBatch::Repair(RosterGap {
                        after: cursor,
                        through: RosterVersion(first),
                    });
                }
                let mut batch = Vec::new();
                let mut previous = cursor.0;
                while buffered
                    .first_key_value()
                    .is_some_and(|(version, _)| previous.checked_add(1) == Some(*version))
                {
                    let entry = buffered.pop_first().expect("next buffered version");
                    previous = entry.0;
                    batch.push(entry);
                }
                inner.in_flight_through = Some(previous);
                RosterFlushBatch::Batch(batch)
            }
            RosterSyncState::Failed => RosterFlushBatch::Failed,
            _ => RosterFlushBatch::Superseded,
        }
    }

    pub fn accept_flushed(&self, permit: RosterSyncPermit, version: i64) -> bool {
        let mut inner = self.lock();
        if !matches!(inner.state, RosterSyncState::Flushing { generation, .. } if generation == permit.generation)
            || inner.cursor.and_then(|cursor| cursor.0.checked_add(1)) != Some(version)
            || inner
                .in_flight_through
                .is_none_or(|through| version > through)
        {
            return false;
        }
        inner.cursor = Some(RosterVersion(version));
        if inner.in_flight_through == Some(version) {
            inner.in_flight_through = None;
        }
        true
    }

    pub fn repair_batch(
        &self,
        permit: RosterSyncPermit,
        gap: RosterGap,
        proof: Option<Vec<(i64, String)>>,
    ) -> Option<Vec<(i64, String)>> {
        let mut inner = self.lock();
        if inner.cursor != Some(gap.after) || inner.in_flight_through.is_some() {
            return None;
        }
        let RosterSyncState::Flushing {
            generation,
            buffered,
        } = &mut inner.state
        else {
            return None;
        };
        if *generation != permit.generation {
            return None;
        }
        let mut proof = proof.filter(|rows| {
            gap.bounded_count() == Some(rows.len())
                && rows
                    .iter()
                    .zip(gap.after.0 + 1..=gap.through.0)
                    .all(|((version, _), expected)| *version == expected)
        })?;
        for (version, stanza) in &mut proof {
            if let Some(original) = buffered.remove(version) {
                *stanza = original;
            }
        }
        inner.in_flight_through = Some(gap.through.0);
        Some(proof)
    }

    pub fn fail(&self, permit: RosterSyncPermit) -> bool {
        let mut inner = self.lock();
        let matches = match &inner.state {
            RosterSyncState::Synchronizing { generation, .. }
            | RosterSyncState::Flushing { generation, .. } => *generation == permit.generation,
            RosterSyncState::Idle | RosterSyncState::Failed => false,
        };
        if matches {
            inner.state = RosterSyncState::Failed;
        }
        matches
    }
}

#[cfg(test)]
mod ordered_tests;
#[cfg(test)]
mod tests;
