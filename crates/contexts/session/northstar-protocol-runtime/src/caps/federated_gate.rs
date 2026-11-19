use dashmap::DashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::sync::OwnedMutexGuard;

pub struct FederatedCapsGateSlot {
    pub gate: Arc<tokio::sync::Mutex<()>>,
    pub participants: std::sync::atomic::AtomicUsize,
}

pub struct FederatedCapsParticipant<'a> {
    pub index: &'a FederatedCapsGateIndex,
    pub full_jid: String,
    pub slot: Arc<FederatedCapsGateSlot>,
}

pub struct FederatedCapsGuard<'a> {
    pub participant: Option<FederatedCapsParticipant<'a>>,
    pub guard: Option<OwnedMutexGuard<()>>,
}

impl FederatedCapsGuard<'_> {
    pub fn resource(&self) -> &str {
        &self
            .participant
            .as_ref()
            .expect("live federated caps guard owns a participant")
            .full_jid
    }
}

impl Drop for FederatedCapsParticipant<'_> {
    fn drop(&mut self) {
        let previous = self.slot.participants.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0, "federated caps participant underflow");
        if previous == 1 {
            self.index.entries.remove_if(&self.full_jid, |_, current| {
                Arc::ptr_eq(current, &self.slot)
                    && current.participants.load(Ordering::Acquire) == 0
            });
        }
    }
}

impl Drop for FederatedCapsGuard<'_> {
    fn drop(&mut self) {
        self.guard.take();
        self.participant.take();
    }
}

pub struct FederatedCapsGateIndex {
    pub entries: DashMap<String, Arc<FederatedCapsGateSlot>>,
}

impl Default for FederatedCapsGateIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl FederatedCapsGateIndex {
    pub fn new() -> Self {
        Self {
            entries: DashMap::new(),
        }
    }

    pub async fn lock(&self, full_jid: &str) -> FederatedCapsGuard<'_> {
        let full_jid = full_jid.to_owned();
        let slot = match self.entries.entry(full_jid.clone()) {
            dashmap::mapref::entry::Entry::Occupied(entry) => {
                entry.get().participants.fetch_add(1, Ordering::AcqRel);
                Arc::clone(entry.get())
            }
            dashmap::mapref::entry::Entry::Vacant(entry) => {
                let slot = Arc::new(FederatedCapsGateSlot {
                    gate: Arc::new(tokio::sync::Mutex::new(())),
                    participants: std::sync::atomic::AtomicUsize::new(1),
                });
                Arc::clone(&entry.insert(slot))
            }
        };
        let participant = FederatedCapsParticipant {
            index: self,
            full_jid,
            slot: Arc::clone(&slot),
        };
        let guard = Arc::clone(&slot.gate).lock_owned().await;
        FederatedCapsGuard {
            participant: Some(participant),
            guard: Some(guard),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn participants(&self, full_jid: &str) -> usize {
        self.entries
            .get(full_jid)
            .map_or(0, |slot| slot.participants.load(Ordering::Acquire))
    }
}
