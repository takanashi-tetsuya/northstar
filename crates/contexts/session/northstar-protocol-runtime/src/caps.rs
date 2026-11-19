#![forbid(unsafe_code)]

use northstar_session_core::LocalCapsEpoch;
use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{Notify, Semaphore};

mod cache_index;
mod federated_gate;
mod pending_index;
mod resource_index;

pub use cache_index::{CachedCaps, CapsCacheAdmission, CapsCacheIndex};
pub use federated_gate::{
    FederatedCapsGateIndex, FederatedCapsGateSlot, FederatedCapsGuard, FederatedCapsParticipant,
};
pub use pending_index::PendingCapsIndex;
pub use resource_index::{caps_retry_delay, CapsResourceAdmission, CapsResourceIndex};

pub const CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);
pub const PENDING_TTL: Duration = Duration::from_secs(30);
pub const MAX_CAPS_CACHE_ENTRIES: usize = 4_096;
pub const MAX_CAPS_CACHE_RAW_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_CAPS_CACHE_SUMMARY_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_CAPS_OBSERVATION_SUMMARY_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_CAPS_EFFECT_CONCURRENCY: usize = 16;
pub const MAX_FEDERATED_CAPS_RESOURCES: usize = 8_192;
pub const MAX_FEDERATED_CAPS_RESOURCES_PER_DOMAIN: usize = 2_048;
pub const MAX_CAPS_EFFECT_HINTS: usize = MAX_FEDERATED_CAPS_RESOURCES + 2_048;
pub const CAPS_EFFECT_DRAIN_GRACE: Duration = Duration::from_secs(5);
pub const CAPS_EFFECT_RETRY_BASE: Duration = Duration::from_millis(250);
pub const CAPS_EFFECT_RETRY_MAX: Duration = Duration::from_secs(30);

pub const EFFECT_EXPLICIT_PEP_LAST_ITEMS: u8 = 1 << 0;
pub const EFFECT_AUTOMATIC_PEP_LAST_ITEMS: u8 = 1 << 1;
pub const EFFECT_VERIFIED_MIX_PRESENCE: u8 = 1 << 2;
pub const EFFECT_DISCO_QUERY: u8 = 1 << 3;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CapsEffects(pub u8);

impl CapsEffects {
    pub const EXPLICIT_PEP_LAST_ITEMS: Self = Self(1 << 0);
    pub const AUTOMATIC_PEP_LAST_ITEMS: Self = Self(1 << 1);
    pub const VERIFIED_MIX_PRESENCE: Self = Self(1 << 2);
    pub const DISCO_QUERY: Self = Self(1 << 3);

    pub fn contains(self, effect: Self) -> bool {
        self.0 & effect.0 != 0
    }

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl std::ops::BitOr for CapsEffects {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for CapsEffects {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CapsKey {
    pub algorithm: String,
    pub node: String,
    pub version: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapsObservationOwner {
    Local(LocalCapsEpoch),
    Federated {
        connection_id: uuid::Uuid,
        observation_id: uuid::Uuid,
    },
}

impl CapsObservationOwner {
    pub fn is_local(self) -> bool {
        matches!(self, Self::Local(_))
    }

    pub fn federated_connection(self) -> Option<uuid::Uuid> {
        match self {
            Self::Federated { connection_id, .. } => Some(connection_id),
            Self::Local(_) => None,
        }
    }
}

#[derive(Debug)]
pub struct VerifiedCapsSummary {
    pub mix_core: bool,
    pub mix_pam: bool,
    pub notify_storage: String,
    pub notify_ranges: Vec<(u32, u32)>,
}

impl VerifiedCapsSummary {
    pub fn new(
        mix_core: bool,
        mix_pam: bool,
        notify_storage: String,
        notify_ranges: Vec<(u32, u32)>,
    ) -> Self {
        Self {
            mix_core,
            mix_pam,
            notify_storage,
            notify_ranges,
        }
    }

    pub fn has_feature(&self, feature: &str) -> bool {
        match feature {
            "urn:xmpp:mix:core:1" => self.mix_core,
            "urn:xmpp:mix:pam:2" => self.mix_pam,
            _ => false,
        }
    }

    pub fn wants_node(&self, node: &str) -> bool {
        self.notify_nodes().any(|wanted| wanted == node)
    }

    pub fn notify_nodes(&self) -> impl Iterator<Item = &str> {
        self.notify_ranges
            .iter()
            .map(|&(start, end)| &self.notify_storage[start as usize..end as usize])
    }

    pub fn resident_charge(&self) -> usize {
        std::mem::size_of::<Self>()
            .saturating_add(2 * std::mem::size_of::<usize>())
            .saturating_add(
                self.notify_ranges
                    .capacity()
                    .saturating_mul(std::mem::size_of::<(u32, u32)>()),
            )
            .saturating_add(self.notify_storage.capacity())
    }
}

#[derive(Clone, Debug)]
pub enum CapsVerification {
    NoAdvertisement,
    NeedsDisco,
    Querying { id: String },
    Verified(Arc<VerifiedCapsSummary>),
    Invalid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapsVerificationCommit {
    Applied,
    Stale,
    ResourceLimited,
}

#[derive(Clone, Debug)]
pub struct CapsObservation {
    pub owner: CapsObservationOwner,
    pub key: Option<CapsKey>,
    pub verification: CapsVerification,
    pub pending_effects: u8,
    pub running_effects: u8,
    pub retry_at: Instant,
    pub consecutive_failures: u32,
    pub touched_at: Instant,
    pub federated_domain: Option<String>,
    pub summary_bytes: usize,
}

#[derive(Clone)]
pub struct CapsObservationSnapshot {
    pub owner: CapsObservationOwner,
    pub key: Option<CapsKey>,
    pub summary: Option<Arc<VerifiedCapsSummary>>,
}

impl CapsObservationSnapshot {
    pub fn local_epoch(&self) -> Option<LocalCapsEpoch> {
        match self.owner {
            CapsObservationOwner::Local(epoch) => Some(epoch),
            CapsObservationOwner::Federated { .. } => None,
        }
    }

    pub fn into_notify_nodes(self) -> Vec<String> {
        self.summary.map_or_else(Vec::new, |summary| {
            summary.notify_nodes().map(str::to_owned).collect()
        })
    }
}

pub fn remove_local_caps_epoch(
    pending: &PendingCapsIndex,
    observations: &CapsResourceIndex,
    full_jid: &str,
    epoch: LocalCapsEpoch,
) {
    pending.remove_local_epoch(full_jid, epoch);
    observations.remove_local_epoch(full_jid, epoch);
}

#[derive(Clone, Debug)]
pub struct PendingCaps {
    pub full_jid: String,
    pub key: CapsKey,
    pub owner: CapsObservationOwner,
    pub expires_at: Instant,
}

#[derive(Debug)]
pub struct CapsEffectJob {
    pub full_jid: String,
    pub owner: CapsObservationOwner,
    pub key: Option<CapsKey>,
    pub effects: CapsEffects,
    pub queued_at: Instant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FederatedCapsObservationResult {
    Accepted,
    StaleOwner,
    Saturated,
}

pub struct CapsEffectQueue {
    pub accepting: bool,
    pub local_ready: VecDeque<String>,
    pub federated_ready: VecDeque<String>,
    pub local_queued: HashSet<String>,
    pub federated_queued: HashSet<String>,
    pub prefer_local: bool,
    pub rescan_required: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapsEffectAdmission {
    Queued,
    Coalesced,
    Saturated,
    Closed,
}

pub struct CapsEffectDispatcher {
    pub queue: Mutex<CapsEffectQueue>,
    pub wake: Notify,
    pub execution_slots: Arc<Semaphore>,
    pub capacity: usize,
}

impl CapsEffectDispatcher {
    pub fn new() -> Arc<Self> {
        Self::with_limits(MAX_CAPS_EFFECT_HINTS, MAX_CAPS_EFFECT_CONCURRENCY)
    }

    pub fn with_limits(capacity: usize, concurrency: usize) -> Arc<Self> {
        assert!(capacity > 0, "caps effect capacity must be positive");
        assert!(concurrency > 0, "caps effect concurrency must be positive");
        Arc::new(Self {
            queue: Mutex::new(CapsEffectQueue {
                accepting: true,
                local_ready: VecDeque::new(),
                federated_ready: VecDeque::new(),
                local_queued: HashSet::new(),
                federated_queued: HashSet::new(),
                prefer_local: true,
                rescan_required: false,
            }),
            wake: Notify::new(),
            execution_slots: Arc::new(Semaphore::new(concurrency)),
            capacity,
        })
    }

    pub fn enqueue_hint(&self, full_jid: String, local: bool) -> CapsEffectAdmission {
        let mut queue = self
            .queue
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !queue.accepting {
            return CapsEffectAdmission::Closed;
        }
        let already_queued = if local {
            queue.local_queued.contains(&full_jid)
        } else {
            queue.federated_queued.contains(&full_jid)
        };
        if already_queued {
            return CapsEffectAdmission::Coalesced;
        }
        let class_len = if local {
            queue.local_ready.len()
        } else {
            queue.federated_ready.len()
        };
        if class_len >= self.capacity {
            let notify = !queue.rescan_required;
            queue.rescan_required = true;
            drop(queue);
            if notify {
                self.wake.notify_one();
            }
            return CapsEffectAdmission::Saturated;
        }
        if local {
            queue.local_queued.insert(full_jid.clone());
            queue.local_ready.push_back(full_jid);
        } else {
            queue.federated_queued.insert(full_jid.clone());
            queue.federated_ready.push_back(full_jid);
        }
        drop(queue);
        self.wake.notify_one();
        CapsEffectAdmission::Queued
    }

    pub fn take_hint(&self) -> Option<String> {
        let mut queue = self
            .queue
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let take_local = match (
            queue.local_ready.is_empty(),
            queue.federated_ready.is_empty(),
        ) {
            (true, true) => return None,
            (false, true) => true,
            (true, false) => false,
            (false, false) => queue.prefer_local,
        };
        let full_jid = if take_local {
            queue.prefer_local = false;
            let full_jid = queue.local_ready.pop_front().expect("checked non-empty");
            queue.local_queued.remove(&full_jid);
            full_jid
        } else {
            queue.prefer_local = true;
            let full_jid = queue
                .federated_ready
                .pop_front()
                .expect("checked non-empty");
            queue.federated_queued.remove(&full_jid);
            full_jid
        };
        let wake_rescan = queue.rescan_required;
        drop(queue);
        if wake_rescan {
            self.wake.notify_one();
        }
        Some(full_jid)
    }

    pub fn next(&self) -> Option<(String, bool)> {
        let mut queue = self
            .queue
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let candidate = if queue.prefer_local {
            queue
                .local_ready
                .pop_front()
                .map(|jid| (jid, true))
                .or_else(|| queue.federated_ready.pop_front().map(|jid| (jid, false)))
        } else {
            queue
                .federated_ready
                .pop_front()
                .map(|jid| (jid, false))
                .or_else(|| queue.local_ready.pop_front().map(|jid| (jid, true)))
        };
        if let Some((jid, local)) = candidate {
            if local {
                queue.local_queued.remove(&jid);
            } else {
                queue.federated_queued.remove(&jid);
            }
            queue.prefer_local = !queue.prefer_local;
            Some((jid, local))
        } else {
            None
        }
    }

    pub fn request_rescan(&self) {
        let mut queue = self
            .queue
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        queue.rescan_required = true;
        drop(queue);
        self.wake.notify_one();
    }

    pub fn begin_rescan(&self) -> bool {
        let mut queue = self
            .queue
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        std::mem::replace(&mut queue.rescan_required, false)
    }

    pub fn finish_rescan(&self) {
        let mut queue = self
            .queue
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        queue.rescan_required = false;
    }

    pub fn cancel_local(&self, full_jid: &str, _connection_id: uuid::Uuid) {
        let mut queue = self
            .queue
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if queue.local_queued.remove(full_jid) {
            queue.local_ready.retain(|candidate| candidate != full_jid);
        }
    }

    pub fn close(&self) {
        let mut queue = self
            .queue
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        queue.accepting = false;
        queue.local_ready.clear();
        queue.federated_ready.clear();
        queue.local_queued.clear();
        queue.federated_queued.clear();
        drop(queue);
        self.wake.notify_waiters();
    }

    pub fn wake(&self) -> &Notify {
        &self.wake
    }

    pub fn execution_slots(&self) -> &Arc<Semaphore> {
        &self.execution_slots
    }
}

#[cfg(test)]
mod tests;
