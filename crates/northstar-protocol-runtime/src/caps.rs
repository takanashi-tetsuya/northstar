#![forbid(unsafe_code)]

use dashmap::DashMap;
use northstar_session_core::LocalCapsEpoch;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{Notify, OwnedMutexGuard, Semaphore};

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

#[derive(Clone)]
pub struct CachedCaps {
    pub query: Option<String>,
    pub summary: Arc<VerifiedCapsSummary>,
    pub expires_at: Instant,
    pub touched_at: Instant,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FederatedCapsObservationResult {
    Accepted,
    StaleOwner,
    Saturated,
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

pub struct PendingCapsIndex {
    pub entries: DashMap<String, PendingCaps>,
    pub admission: Mutex<()>,
}

impl Default for PendingCapsIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl PendingCapsIndex {
    pub fn new() -> Self {
        Self {
            entries: DashMap::new(),
            admission: Mutex::new(()),
        }
    }

    pub fn insert(
        &self,
        id: String,
        full_jid: String,
        key: CapsKey,
        owner: CapsObservationOwner,
        expires_at: Instant,
    ) -> bool {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if self.entries.contains_key(&id) {
            return false;
        }
        self.entries
            .retain(|_, pending| pending.full_jid != full_jid || pending.owner != owner);
        if self.entries.iter().any(|pending| pending.key == key) {
            return false;
        }
        self.entries.insert(
            id,
            PendingCaps {
                full_jid,
                key,
                owner,
                expires_at,
            },
        );
        true
    }

    pub fn take(&self, id: &str) -> Option<PendingCaps> {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.entries.remove(id).map(|(_, pending)| pending)
    }

    pub fn federated_resource(&self, id: &str) -> Option<String> {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.entries
            .get(id)
            .filter(|pending| matches!(pending.owner, CapsObservationOwner::Federated { .. }))
            .map(|pending| pending.full_jid.clone())
    }

    pub fn remove(&self, id: &str) {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.entries.remove(id);
    }

    pub fn remove_resource(&self, full_jid: &str) {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.entries
            .retain(|_, pending| pending.full_jid != full_jid);
    }

    pub fn remove_local_resource(&self, full_jid: &str, connection_id: uuid::Uuid) {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.entries.retain(|_, pending| {
            pending.full_jid != full_jid
                || !matches!(pending.owner, CapsObservationOwner::Local(epoch) if epoch.connection_id == connection_id)
        });
    }

    pub fn remove_local_epoch(&self, full_jid: &str, epoch: LocalCapsEpoch) {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.entries.retain(|_, pending| {
            pending.full_jid != full_jid || pending.owner != CapsObservationOwner::Local(epoch)
        });
    }

    pub fn remove_federated_connection(&self, connection_id: uuid::Uuid) {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.entries.retain(|_, pending| {
            !matches!(pending.owner, CapsObservationOwner::Federated { connection_id: owner, .. } if owner == connection_id)
        });
    }

    pub fn remove_federated_resource_if_connection(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
    ) {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.entries.retain(|_, pending| {
            pending.full_jid != full_jid
                || pending.owner.federated_connection() != Some(connection_id)
        });
    }

    pub fn take_expired(&self, now: Instant) -> Vec<(String, PendingCaps)> {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let expired = self
            .entries
            .iter()
            .filter(|entry| entry.expires_at <= now)
            .map(|entry| entry.key().clone())
            .collect::<Vec<_>>();
        expired
            .into_iter()
            .filter_map(|id| self.entries.remove(&id).map(|(_, pending)| (id, pending)))
            .collect()
    }

    pub fn next_expiration(&self) -> Option<Instant> {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.entries.iter().map(|pending| pending.expires_at).min()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[derive(Default)]
pub struct CapsCacheAdmission {
    pub raw_bytes: usize,
    pub summary_bytes: usize,
}

pub struct CapsCacheIndex {
    pub entries: DashMap<CapsKey, CachedCaps>,
    pub admission: Mutex<CapsCacheAdmission>,
    pub max_entries: usize,
    pub max_raw_bytes: usize,
    pub max_summary_bytes: usize,
    pub ttl: Duration,
}

impl Default for CapsCacheIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl CapsCacheIndex {
    pub fn new() -> Self {
        Self::with_limits(MAX_CAPS_CACHE_ENTRIES, CACHE_TTL)
    }

    pub fn with_limits(max_entries: usize, ttl: Duration) -> Self {
        Self::with_budgets(
            max_entries,
            MAX_CAPS_CACHE_RAW_BYTES,
            MAX_CAPS_CACHE_SUMMARY_BYTES,
            ttl,
        )
    }

    pub fn with_budgets(
        max_entries: usize,
        max_raw_bytes: usize,
        max_summary_bytes: usize,
        ttl: Duration,
    ) -> Self {
        assert!(max_entries > 0, "caps cache capacity must be positive");
        assert!(max_raw_bytes > 0, "caps raw cache budget must be positive");
        assert!(
            max_summary_bytes > 0,
            "caps semantic cache budget must be positive"
        );
        Self {
            entries: DashMap::new(),
            admission: Mutex::new(CapsCacheAdmission::default()),
            max_entries,
            max_raw_bytes,
            max_summary_bytes,
            ttl,
        }
    }

    pub fn query(&self, key: &CapsKey, now: Instant) -> Option<Arc<VerifiedCapsSummary>> {
        let mut admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut cached = self.entries.get_mut(key)?;
        if cached.expires_at <= now {
            drop(cached);
            if let Some((_, expired)) = self.entries.remove(key) {
                release_cache_admission(&mut admission, &expired);
            }
            return None;
        }
        cached.touched_at = now;
        Some(Arc::clone(&cached.summary))
    }

    pub fn raw_query(&self, key: &CapsKey, now: Instant) -> Option<String> {
        let mut admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut cached = self.entries.get_mut(key)?;
        if cached.expires_at <= now {
            drop(cached);
            if let Some((_, expired)) = self.entries.remove(key) {
                release_cache_admission(&mut admission, &expired);
            }
            return None;
        }
        cached.touched_at = now;
        cached.query.clone()
    }

    pub fn insert(
        &self,
        key: CapsKey,
        query: String,
        summary: Arc<VerifiedCapsSummary>,
        now: Instant,
    ) {
        let mut admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some((_, previous)) = self.entries.remove(&key) {
            release_cache_admission(&mut admission, &previous);
        } else if self.entries.len() >= self.max_entries {
            if let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|entry| entry.touched_at)
                .map(|entry| entry.key().clone())
            {
                if let Some((_, evicted)) = self.entries.remove(&oldest) {
                    release_cache_admission(&mut admission, &evicted);
                }
            }
        }
        let summary_bytes = summary.resident_charge();
        if summary_bytes > self.max_summary_bytes
            || admission.summary_bytes.saturating_add(summary_bytes) > self.max_summary_bytes
        {
            return;
        }
        let raw_bytes = query.len();
        if raw_bytes <= self.max_raw_bytes
            && admission.raw_bytes.saturating_add(raw_bytes) > self.max_raw_bytes
        {
            if let Some(oldest_raw) = self
                .entries
                .iter()
                .filter(|entry| entry.query.is_some())
                .min_by_key(|entry| entry.touched_at)
                .map(|entry| entry.key().clone())
            {
                if let Some(mut cached) = self.entries.get_mut(&oldest_raw) {
                    if let Some(raw) = cached.query.take() {
                        admission.raw_bytes = admission
                            .raw_bytes
                            .checked_sub(raw.len())
                            .expect("caps raw cache byte counter underflow");
                    }
                }
            }
        }
        let query = if raw_bytes <= self.max_raw_bytes
            && admission.raw_bytes.saturating_add(raw_bytes) <= self.max_raw_bytes
        {
            admission.raw_bytes += raw_bytes;
            Some(query)
        } else {
            None
        };
        admission.summary_bytes += summary_bytes;
        self.entries.insert(
            key,
            CachedCaps {
                query,
                summary,
                expires_at: now + self.ttl,
                touched_at: now,
            },
        );
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn charged_bytes(&self) -> (usize, usize) {
        let admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        (admission.raw_bytes, admission.summary_bytes)
    }

    pub fn sweep(&self, now: Instant) {
        let mut admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let expired = self
            .entries
            .iter()
            .filter(|entry| entry.expires_at <= now)
            .map(|entry| entry.key().clone())
            .collect::<Vec<_>>();
        for key in expired {
            if let Some((_, cached)) = self.entries.remove(&key) {
                release_cache_admission(&mut admission, &cached);
            }
        }
    }
}

fn release_cache_admission(admission: &mut CapsCacheAdmission, cached: &CachedCaps) {
    if let Some(raw) = cached.query.as_ref() {
        admission.raw_bytes = admission
            .raw_bytes
            .checked_sub(raw.len())
            .expect("caps cache raw counter underflow");
    }
    admission.summary_bytes = admission
        .summary_bytes
        .checked_sub(cached.summary.resident_charge())
        .expect("caps cache semantic counter underflow");
}

#[derive(Default)]
pub struct CapsResourceAdmission {
    pub federated: usize,
    pub federated_per_domain: HashMap<String, usize>,
    pub summary_bytes: usize,
}

pub struct CapsResourceIndex {
    pub entries: DashMap<String, CapsObservation>,
    pub admission: Mutex<CapsResourceAdmission>,
    pub max_federated: usize,
    pub max_federated_per_domain: usize,
    pub max_summary_bytes: usize,
}

impl Default for CapsResourceIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl CapsResourceIndex {
    pub fn new() -> Self {
        Self::with_limits(
            MAX_FEDERATED_CAPS_RESOURCES,
            MAX_FEDERATED_CAPS_RESOURCES_PER_DOMAIN,
        )
    }

    pub fn with_limits(max_federated: usize, max_federated_per_domain: usize) -> Self {
        Self::with_budgets(
            max_federated,
            max_federated_per_domain,
            MAX_CAPS_OBSERVATION_SUMMARY_BYTES,
        )
    }

    pub fn with_budgets(
        max_federated: usize,
        max_federated_per_domain: usize,
        max_summary_bytes: usize,
    ) -> Self {
        assert!(
            max_federated > 0,
            "federated caps capacity must be positive"
        );
        assert!(
            max_federated_per_domain > 0 && max_federated_per_domain <= max_federated,
            "federated caps per-domain capacity must fit the global capacity"
        );
        assert!(
            max_summary_bytes > 0,
            "caps observation summary budget must be positive"
        );
        Self {
            entries: DashMap::new(),
            admission: Mutex::new(CapsResourceAdmission::default()),
            max_federated,
            max_federated_per_domain,
            max_summary_bytes,
        }
    }

    pub fn observe_local(
        &self,
        full_jid: String,
        epoch: LocalCapsEpoch,
        key: Option<CapsKey>,
        cached: Option<Arc<VerifiedCapsSummary>>,
        now: Instant,
    ) {
        let mut admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let (previous_summary_bytes, previous_summary) =
            self.entries.get(&full_jid).map_or((0, None), |entry| {
                let summary = (entry.key.as_ref() == key.as_ref())
                    .then(|| match &entry.verification {
                        CapsVerification::Verified(summary) => Some(Arc::clone(summary)),
                        _ => None,
                    })
                    .flatten();
                (entry.summary_bytes, summary)
            });
        let cached = admit_observation_summary(
            &admission,
            previous_summary_bytes,
            cached.or(previous_summary),
            self.max_summary_bytes,
        );
        let summary_bytes = cached
            .as_deref()
            .map_or(0, VerifiedCapsSummary::resident_charge);
        if let Some(previous) = self.entries.insert(
            full_jid,
            new_caps_observation(CapsObservationOwner::Local(epoch), key, cached, None, now),
        ) {
            release_observation_admission(&mut admission, &previous);
        }
        admission.summary_bytes += summary_bytes;
    }

    pub fn observe_federated(
        &self,
        full_jid: String,
        connection_id: uuid::Uuid,
        domain: String,
        key: Option<CapsKey>,
        cached: Option<Arc<VerifiedCapsSummary>>,
        now: Instant,
    ) -> Option<CapsObservationOwner> {
        let mut admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let previous_domain = self
            .entries
            .get(&full_jid)
            .and_then(|entry| entry.federated_domain.clone());
        let adds_federated = previous_domain.is_none();
        let changes_domain = previous_domain
            .as_deref()
            .is_some_and(|previous| previous != domain);
        let domain_count = admission
            .federated_per_domain
            .get(&domain)
            .copied()
            .unwrap_or(0);
        if (adds_federated && admission.federated >= self.max_federated)
            || ((adds_federated || changes_domain) && domain_count >= self.max_federated_per_domain)
        {
            return None;
        }
        let (previous_summary_bytes, previous_summary) =
            self.entries.get(&full_jid).map_or((0, None), |entry| {
                let summary = (entry.key.as_ref() == key.as_ref())
                    .then(|| match &entry.verification {
                        CapsVerification::Verified(summary) => Some(Arc::clone(summary)),
                        _ => None,
                    })
                    .flatten();
                (entry.summary_bytes, summary)
            });
        let cached = admit_observation_summary(
            &admission,
            previous_summary_bytes,
            cached.or(previous_summary),
            self.max_summary_bytes,
        );
        let summary_bytes = cached
            .as_deref()
            .map_or(0, VerifiedCapsSummary::resident_charge);
        let owner = CapsObservationOwner::Federated {
            connection_id,
            observation_id: uuid::Uuid::new_v4(),
        };
        let previous = self.entries.insert(
            full_jid,
            new_caps_observation(owner, key, cached, Some(domain.clone()), now),
        );
        if let Some(previous) = previous.as_ref() {
            release_observation_admission(&mut admission, previous);
        }
        admission.summary_bytes += summary_bytes;
        admission.federated += 1;
        *admission.federated_per_domain.entry(domain).or_default() += 1;
        Some(owner)
    }

    pub fn owner(&self, full_jid: &str) -> Option<CapsObservationOwner> {
        self.entries.get(full_jid).map(|entry| entry.owner)
    }

    pub fn summary(&self, full_jid: &str) -> Option<Arc<VerifiedCapsSummary>> {
        let mut entry = self.entries.get_mut(full_jid)?;
        entry.touched_at = Instant::now();
        match &entry.verification {
            CapsVerification::Verified(summary) => Some(Arc::clone(summary)),
            _ => None,
        }
    }

    pub fn snapshot(&self, full_jid: &str) -> Option<CapsObservationSnapshot> {
        let mut entry = self.entries.get_mut(full_jid)?;
        entry.touched_at = Instant::now();
        Some(CapsObservationSnapshot {
            owner: entry.owner,
            key: entry.key.clone(),
            summary: match &entry.verification {
                CapsVerification::Verified(summary) => Some(Arc::clone(summary)),
                _ => None,
            },
        })
    }

    pub fn interested_resources_for_bare(&self, bare: &str, node: &str) -> Vec<String> {
        self.entries
            .iter()
            .filter_map(|entry| {
                let matches_bare = northstar_xmpp_types::canonical_bare_key(entry.key())
                    .is_ok_and(|candidate| candidate == bare);
                let interested = matches!(&entry.verification,
                    CapsVerification::Verified(summary) if summary.wants_node(node));
                (matches_bare && interested).then(|| entry.key().clone())
            })
            .collect()
    }

    pub fn current_owner(&self, full_jid: &str, owner: CapsObservationOwner) -> bool {
        self.entries
            .get(full_jid)
            .is_some_and(|entry| entry.owner == owner)
    }

    pub fn begin_query(
        &self,
        full_jid: &str,
        owner: CapsObservationOwner,
        key: &CapsKey,
        id: String,
    ) -> bool {
        let Some(mut entry) = self.entries.get_mut(full_jid) else {
            return false;
        };
        if entry.owner != owner || entry.key.as_ref() != Some(key) {
            return false;
        }
        if !matches!(entry.verification, CapsVerification::NeedsDisco) {
            return false;
        }
        entry.verification = CapsVerification::Querying { id };
        true
    }

    pub fn mark_query_failed(&self, full_jid: &str, owner: CapsObservationOwner, id: &str) {
        let Some(mut entry) = self.entries.get_mut(full_jid) else {
            return;
        };
        if entry.owner == owner
            && matches!(&entry.verification, CapsVerification::Querying { id: current, .. } if current == id)
        {
            entry.verification = CapsVerification::NeedsDisco;
        }
    }

    pub fn mark_verified(
        &self,
        full_jid: &str,
        owner: CapsObservationOwner,
        key: &CapsKey,
        id: &str,
        summary: Arc<VerifiedCapsSummary>,
    ) -> CapsVerificationCommit {
        let mut admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(mut entry) = self.entries.get_mut(full_jid) else {
            return CapsVerificationCommit::Stale;
        };
        if entry.owner != owner
            || entry.key.as_ref() != Some(key)
            || !matches!(&entry.verification, CapsVerification::Querying { id: current, .. } if current == id)
        {
            return CapsVerificationCommit::Stale;
        }
        if !try_install_verified_summary(
            &mut admission,
            &mut entry,
            summary,
            self.max_summary_bytes,
        ) {
            entry.verification = CapsVerification::NeedsDisco;
            entry.pending_effects |= EFFECT_DISCO_QUERY;
            entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
            entry.retry_at = Instant::now() + caps_retry_delay(entry.consecutive_failures);
            return CapsVerificationCommit::ResourceLimited;
        }
        entry.pending_effects &= !EFFECT_DISCO_QUERY;
        entry.retry_at = Instant::now();
        entry.consecutive_failures = 0;
        CapsVerificationCommit::Applied
    }

    pub fn mark_cached_verified(
        &self,
        full_jid: &str,
        owner: CapsObservationOwner,
        key: &CapsKey,
        summary: Arc<VerifiedCapsSummary>,
    ) -> CapsVerificationCommit {
        let mut admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(mut entry) = self.entries.get_mut(full_jid) else {
            return CapsVerificationCommit::Stale;
        };
        if entry.owner != owner
            || entry.key.as_ref() != Some(key)
            || !matches!(entry.verification, CapsVerification::NeedsDisco)
        {
            return CapsVerificationCommit::Stale;
        }
        if !try_install_verified_summary(
            &mut admission,
            &mut entry,
            summary,
            self.max_summary_bytes,
        ) {
            return CapsVerificationCommit::ResourceLimited;
        }
        entry.pending_effects &= !EFFECT_DISCO_QUERY;
        entry.retry_at = Instant::now();
        entry.consecutive_failures = 0;
        CapsVerificationCommit::Applied
    }

    pub fn mark_invalid(
        &self,
        full_jid: &str,
        owner: CapsObservationOwner,
        key: &CapsKey,
        id: &str,
    ) {
        let Some(mut entry) = self.entries.get_mut(full_jid) else {
            return;
        };
        if entry.owner == owner
            && entry.key.as_ref() == Some(key)
            && matches!(&entry.verification, CapsVerification::Querying { id: current, .. } if current == id)
        {
            entry.verification = CapsVerification::Invalid;
            entry.pending_effects &= !EFFECT_DISCO_QUERY;
        }
    }

    pub fn rearm_expired(&self, id: &str, pending: &PendingCaps, now: Instant) -> bool {
        let Some(mut entry) = self.entries.get_mut(&pending.full_jid) else {
            return false;
        };
        if entry.owner != pending.owner || entry.key.as_ref() != Some(&pending.key) {
            return false;
        }
        if !matches!(&entry.verification, CapsVerification::Querying { id: current, .. } if current == id)
        {
            return false;
        }
        entry.verification = CapsVerification::NeedsDisco;
        entry.pending_effects |= EFFECT_DISCO_QUERY;
        entry.retry_at = now;
        true
    }

    pub fn claim_effects(&self, full_jid: &str, now: Instant) -> Option<CapsEffectJob> {
        let mut entry = self.entries.get_mut(full_jid)?;
        if entry.pending_effects == 0 || entry.running_effects != 0 || entry.retry_at > now {
            return None;
        }
        let effects = CapsEffects(entry.pending_effects);
        entry.pending_effects = 0;
        entry.running_effects = effects.0;
        Some(CapsEffectJob {
            full_jid: full_jid.to_owned(),
            owner: entry.owner,
            key: entry.key.clone(),
            effects,
            queued_at: entry.touched_at.min(now),
        })
    }

    pub fn complete_effects(&self, job: &CapsEffectJob, failed: CapsEffects, now: Instant) -> bool {
        let Some(mut entry) = self.entries.get_mut(&job.full_jid) else {
            return false;
        };
        if entry.owner != job.owner {
            return false;
        }
        entry.running_effects &= !job.effects.0;
        if !failed.is_empty() {
            entry.pending_effects |= failed.0;
            entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
            entry.retry_at = now + caps_retry_delay(entry.consecutive_failures);
        } else {
            entry.consecutive_failures = 0;
            entry.retry_at = now;
        }
        entry.pending_effects != 0 && entry.running_effects == 0 && entry.retry_at <= now
    }

    pub fn recover_interrupted(&self, now: Instant) {
        for mut entry in self.entries.iter_mut() {
            if entry.running_effects != 0 {
                entry.pending_effects |= entry.running_effects;
                entry.running_effects = 0;
                entry.retry_at = now;
            }
        }
    }

    pub fn ready_observations(&self, now: Instant) -> Vec<(String, bool)> {
        self.entries
            .iter()
            .filter(|entry| {
                entry.pending_effects != 0 && entry.running_effects == 0 && entry.retry_at <= now
            })
            .map(|entry| (entry.key().clone(), entry.owner.is_local()))
            .collect()
    }

    pub fn next_retry_deadline(&self, now: Instant) -> Option<Instant> {
        self.entries
            .iter()
            .filter(|entry| {
                entry.pending_effects != 0 && entry.running_effects == 0 && entry.retry_at > now
            })
            .map(|entry| entry.retry_at)
            .min()
    }

    pub fn federated_resources_for_connection(&self, connection_id: uuid::Uuid) -> Vec<String> {
        self.entries
            .iter()
            .filter(|entry| entry.owner.federated_connection() == Some(connection_id))
            .map(|entry| entry.key().clone())
            .collect()
    }

    pub fn remove_federated_resource_if_connection(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
    ) -> bool {
        let mut admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let removed = self.entries.remove_if(full_jid, |_, observation| {
            observation.owner.federated_connection() == Some(connection_id)
        });
        if let Some((_, observation)) = removed {
            release_observation_admission(&mut admission, &observation);
            true
        } else {
            false
        }
    }

    pub fn remove_local_resource(&self, full_jid: &str, connection_id: uuid::Uuid) {
        let mut admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let removed = self.entries.remove_if(full_jid, |_, observation| {
            matches!(observation.owner, CapsObservationOwner::Local(epoch) if epoch.connection_id == connection_id)
        });
        if let Some((_, observation)) = removed {
            release_observation_admission(&mut admission, &observation);
        }
    }

    pub fn remove_local_epoch(&self, full_jid: &str, epoch: LocalCapsEpoch) {
        let mut admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let removed = self.entries.remove_if(full_jid, |_, observation| {
            observation.owner == CapsObservationOwner::Local(epoch)
        });
        if let Some((_, observation)) = removed {
            release_observation_admission(&mut admission, &observation);
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn federated_counts(&self, domain: &str) -> (usize, usize) {
        let admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        (
            admission.federated,
            admission
                .federated_per_domain
                .get(domain)
                .copied()
                .unwrap_or(0),
        )
    }

    pub fn summary_bytes(&self) -> usize {
        self.admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .summary_bytes
    }
}

fn release_observation_admission(
    admission: &mut CapsResourceAdmission,
    observation: &CapsObservation,
) {
    admission.summary_bytes = admission
        .summary_bytes
        .checked_sub(observation.summary_bytes)
        .expect("caps observation summary counter underflow");
    let Some(domain) = observation.federated_domain.as_deref() else {
        return;
    };
    admission.federated = admission
        .federated
        .checked_sub(1)
        .expect("federated caps admission counter underflow");
    let remove_domain = {
        let count = admission
            .federated_per_domain
            .get_mut(domain)
            .expect("federated caps domain counter missing");
        *count = count
            .checked_sub(1)
            .expect("federated caps domain counter underflow");
        *count == 0
    };
    if remove_domain {
        admission.federated_per_domain.remove(domain);
    }
}

fn admit_observation_summary(
    admission: &CapsResourceAdmission,
    replaced_summary_bytes: usize,
    summary: Option<Arc<VerifiedCapsSummary>>,
    max_summary_bytes: usize,
) -> Option<Arc<VerifiedCapsSummary>> {
    let summary = summary?;
    let charge = summary.resident_charge();
    let bytes_after_replacement = admission
        .summary_bytes
        .checked_sub(replaced_summary_bytes)
        .expect("caps replacement summary counter underflow")
        .saturating_add(charge);
    (charge <= max_summary_bytes && bytes_after_replacement <= max_summary_bytes).then_some(summary)
}

fn try_install_verified_summary(
    admission: &mut CapsResourceAdmission,
    entry: &mut CapsObservation,
    summary: Arc<VerifiedCapsSummary>,
    max_summary_bytes: usize,
) -> bool {
    let charge = summary.resident_charge();
    let bytes_after_install = admission
        .summary_bytes
        .checked_sub(entry.summary_bytes)
        .expect("caps observation summary counter underflow")
        .saturating_add(charge);
    if charge > max_summary_bytes || bytes_after_install > max_summary_bytes {
        return false;
    }
    let mut effects = EFFECT_AUTOMATIC_PEP_LAST_ITEMS;
    if entry.owner.is_local()
        && (summary.has_feature("urn:xmpp:mix:core:1") || summary.has_feature("urn:xmpp:mix:pam:2"))
    {
        effects |= EFFECT_VERIFIED_MIX_PRESENCE;
    }
    admission.summary_bytes = bytes_after_install;
    entry.summary_bytes = charge;
    entry.verification = CapsVerification::Verified(summary);
    entry.pending_effects |= effects;
    true
}

fn new_caps_observation(
    owner: CapsObservationOwner,
    key: Option<CapsKey>,
    cached: Option<Arc<VerifiedCapsSummary>>,
    federated_domain: Option<String>,
    now: Instant,
) -> CapsObservation {
    let (verification, mut pending_effects) = match (key.as_ref(), cached) {
        (None, _) => (
            CapsVerification::NoAdvertisement,
            EFFECT_EXPLICIT_PEP_LAST_ITEMS,
        ),
        (Some(_), Some(summary)) => {
            let mut effects = EFFECT_EXPLICIT_PEP_LAST_ITEMS | EFFECT_AUTOMATIC_PEP_LAST_ITEMS;
            if owner.is_local()
                && (summary.has_feature("urn:xmpp:mix:core:1")
                    || summary.has_feature("urn:xmpp:mix:pam:2"))
            {
                effects |= EFFECT_VERIFIED_MIX_PRESENCE;
            }
            (CapsVerification::Verified(summary), effects)
        }
        (Some(_), None) => (
            CapsVerification::NeedsDisco,
            EFFECT_EXPLICIT_PEP_LAST_ITEMS | EFFECT_DISCO_QUERY,
        ),
    };
    if !owner.is_local() {
        pending_effects &= !EFFECT_VERIFIED_MIX_PRESENCE;
    }
    let summary_bytes = match &verification {
        CapsVerification::Verified(summary) => summary.resident_charge(),
        _ => 0,
    };
    CapsObservation {
        owner,
        key,
        verification,
        pending_effects,
        running_effects: 0,
        retry_at: now,
        consecutive_failures: 0,
        touched_at: now,
        federated_domain,
        summary_bytes,
    }
}

pub fn caps_retry_delay(failures: u32) -> Duration {
    let shift = failures.saturating_sub(1).min(7);
    CAPS_EFFECT_RETRY_BASE
        .saturating_mul(1_u32 << shift)
        .min(CAPS_EFFECT_RETRY_MAX)
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
