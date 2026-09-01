use super::ProtocolSession;
use crate::state::{AppState, CapsKey, LocalCapsEpoch};
use crate::xmpp::xml_builder::XmlElement;
use crate::xmpp::xml_util::{iq_result_from, stream_id};
use base64::{engine::general_purpose::STANDARD, Engine};
use dashmap::DashMap;
use futures::{stream::FuturesUnordered, StreamExt};
use roxmltree::Node;
use sha1::{Digest, Sha1};
use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{Notify, Semaphore};
use tokio_util::sync::CancellationToken;

const CAPS_NS: &str = "http://jabber.org/protocol/caps";
const DISCO_INFO_NS: &str = "http://jabber.org/protocol/disco#info";
const CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);
const PENDING_TTL: Duration = Duration::from_secs(30);
const MAX_CAPS_CACHE_ENTRIES: usize = 4_096;
/// Raw disco XML is optional responder material, not semantic authority.  Its
/// separately-accounted budget prevents the entry bound from multiplying the
/// 64-KiB parser limit into hundreds of MiB.
const MAX_CAPS_CACHE_RAW_BYTES: usize = 16 * 1024 * 1024;
/// Cached semantic knowledge accelerates same-key observations, while current
/// observations retain their own Arc. Both stores have independent, exact
/// charged-byte bounds so eviction/backpressure cannot change an observation
/// into a negative capability answer.
const MAX_CAPS_CACHE_SUMMARY_BYTES: usize = 16 * 1024 * 1024;
const MAX_CAPS_OBSERVATION_SUMMARY_BYTES: usize = 64 * 1024 * 1024;
const MAX_DISCO_PAYLOAD_BYTES: usize = 64 * 1024;
const MAX_DISCO_CHILDREN: usize = 512;
const MAX_CAPS_EFFECT_CONCURRENCY: usize = 16;
/// This bounds only duplicate wake hints.  The observation table owns every
/// effect bit, and the worker reconstructs hints from that table after a drop,
/// restart, or saturation event.
const MAX_CAPS_EFFECT_HINTS: usize = MAX_FEDERATED_CAPS_RESOURCES + 2_048;
const CAPS_EFFECT_DRAIN_GRACE: Duration = Duration::from_secs(5);
const MAX_FEDERATED_CAPS_RESOURCES: usize = 8_192;
const MAX_FEDERATED_CAPS_RESOURCES_PER_DOMAIN: usize = 2_048;
const CAPS_EFFECT_RETRY_BASE: Duration = Duration::from_millis(250);
const CAPS_EFFECT_RETRY_MAX: Duration = Duration::from_secs(30);

const EFFECT_EXPLICIT_PEP_LAST_ITEMS: u8 = 1 << 0;
const EFFECT_AUTOMATIC_PEP_LAST_ITEMS: u8 = 1 << 1;
const EFFECT_VERIFIED_MIX_PRESENCE: u8 = 1 << 2;
const EFFECT_DISCO_QUERY: u8 = 1 << 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CapsObservationOwner {
    Local(LocalCapsEpoch),
    Federated {
        connection_id: uuid::Uuid,
        /// Unique even when one authenticated stream advertises the same
        /// full JID and capability key repeatedly.  A connection UUID alone
        /// cannot fence that same-stream ABA.
        observation_id: uuid::Uuid,
    },
}

impl CapsObservationOwner {
    fn is_local(self) -> bool {
        matches!(self, Self::Local(_))
    }

    fn federated_connection(self) -> Option<uuid::Uuid> {
        match self {
            Self::Federated { connection_id, .. } => Some(connection_id),
            Self::Local(_) => None,
        }
    }
}

/// A verified, bounded semantic projection of one disco#info result. Current
/// resources retain this Arc independently of the optional raw-document LRU,
/// so cache eviction can never turn `Unknown` into `NotInterested`.
#[derive(Debug)]
struct VerifiedCapsSummary {
    mix_core: bool,
    mix_pam: bool,
    /// All notify nodes share one bounded allocation; ranges preserve every
    /// advertised node without multiplying allocator overhead by up to 512
    /// children per observation.
    notify_storage: String,
    notify_ranges: Vec<(u32, u32)>,
}

impl VerifiedCapsSummary {
    fn has_feature(&self, feature: &str) -> bool {
        match feature {
            "urn:xmpp:mix:core:1" => self.mix_core,
            "urn:xmpp:mix:pam:2" => self.mix_pam,
            _ => false,
        }
    }

    fn wants_node(&self, node: &str) -> bool {
        self.notify_nodes().any(|wanted| wanted == node)
    }

    fn notify_nodes(&self) -> impl Iterator<Item = &str> {
        self.notify_ranges
            .iter()
            .map(|&(start, end)| &self.notify_storage[start as usize..end as usize])
    }

    /// Conservative resident charge for the Arc allocation, Vec allocation,
    /// and every owned notify-node buffer. Charging a shared Arc once per
    /// observation deliberately over-counts, which makes the global bound
    /// safe without coupling correctness to cache residency or Arc lifetime.
    fn resident_charge(&self) -> usize {
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
enum CapsVerification {
    NoAdvertisement,
    NeedsDisco,
    Querying { id: String },
    Verified(Arc<VerifiedCapsSummary>),
    Invalid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CapsVerificationCommit {
    Applied,
    Stale,
    ResourceLimited,
}

#[derive(Clone, Debug)]
struct CapsObservation {
    owner: CapsObservationOwner,
    key: Option<CapsKey>,
    verification: CapsVerification,
    pending_effects: u8,
    running_effects: u8,
    retry_at: Instant,
    consecutive_failures: u32,
    touched_at: Instant,
    federated_domain: Option<String>,
    summary_bytes: usize,
}

#[derive(Clone)]
struct CapsObservationSnapshot {
    owner: CapsObservationOwner,
    key: Option<CapsKey>,
    summary: Option<Arc<VerifiedCapsSummary>>,
}

#[derive(Clone)]
struct CachedCaps {
    /// Optional responder payload. Current observations never retain this
    /// potentially 64-KiB string; eviction may only turn disco proxying into
    /// a cache miss.
    query: Option<String>,
    summary: Arc<VerifiedCapsSummary>,
    expires_at: Instant,
    touched_at: Instant,
}

#[derive(Clone, Debug)]
struct PendingCaps {
    full_jid: String,
    key: CapsKey,
    owner: CapsObservationOwner,
    expires_at: Instant,
}

#[derive(Debug)]
struct CapsEffectJob {
    full_jid: String,
    owner: CapsObservationOwner,
    key: Option<CapsKey>,
    effects: CapsEffects,
    queued_at: Instant,
}

/// Authoritative state for every accepted available resource. Local entries
/// are bounded by the existing C2S connection semaphore and removed by the
/// exact session incarnation. Federated entries are admitted before presence
/// routing under explicit global/per-domain budgets and are owned by the
/// authenticated S2S connection incarnation; overload is reported as
/// resource-constraint instead of accepting a semantically incomplete route.
pub(crate) struct CapsResourceIndex {
    entries: DashMap<String, CapsObservation>,
    admission: Mutex<CapsResourceAdmission>,
    max_federated: usize,
    max_federated_per_domain: usize,
    max_summary_bytes: usize,
}

#[derive(Default)]
struct CapsResourceAdmission {
    federated: usize,
    federated_per_domain: HashMap<String, usize>,
    summary_bytes: usize,
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

/// IQ IDs are a derived correlation index, never a second admission authority.
/// There is at most one Querying correlation per accepted observation; actual
/// work concurrency is bounded by the fair effect dispatcher.
pub(crate) struct PendingCapsIndex {
    entries: DashMap<String, PendingCaps>,
    admission: Mutex<()>,
}

/// Per-federated-resource ordering authority for XEP-0115 observations.
///
/// A remote full JID can be observed concurrently on more than one authenticated
/// S2S stream. XMPP preserves order within one stream, but it provides no
/// cross-stream ordering primitive, so Northstar chooses one here. Available,
/// unavailable, disco responses and their final PEP side effects all cross the
/// same gate. This makes gate acquisition the single linearization point: an
/// old available observation cannot resume after a later unavailable and
/// recreate a resource mapping or enqueue PEP delivery.
///
/// Each entry has an explicit participant count incremented while holding the
/// DashMap entry lock. A participant exists before awaiting the mutex, so task
/// cancellation and successful guard release run the same RAII cleanup. The
/// final participant compare-removes its exact Arc. Consequently arbitrary
/// remote resource names do not create a TTL cache, an abort leak, or another
/// attacker-controlled capacity budget.
pub(crate) struct FederatedCapsGateIndex {
    entries: DashMap<String, Arc<FederatedCapsGateSlot>>,
}

struct FederatedCapsGateSlot {
    gate: Arc<tokio::sync::Mutex<()>>,
    participants: std::sync::atomic::AtomicUsize,
}

struct FederatedCapsParticipant<'a> {
    index: &'a FederatedCapsGateIndex,
    full_jid: String,
    slot: Arc<FederatedCapsGateSlot>,
}

pub(crate) struct FederatedCapsGuard<'a> {
    participant: Option<FederatedCapsParticipant<'a>>,
    guard: Option<tokio::sync::OwnedMutexGuard<()>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FederatedCapsObservationResult {
    Accepted,
    StaleOwner,
    Saturated,
}

impl FederatedCapsGuard<'_> {
    pub(crate) fn resource(&self) -> &str {
        &self
            .participant
            .as_ref()
            .expect("live federated caps guard owns a participant")
            .full_jid
    }
}

impl FederatedCapsGateIndex {
    pub(crate) fn new() -> Self {
        Self {
            entries: DashMap::new(),
        }
    }

    pub(crate) async fn lock(&self, full_jid: &str) -> FederatedCapsGuard<'_> {
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

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }

    #[cfg(test)]
    fn participants(&self, full_jid: &str) -> usize {
        self.entries
            .get(full_jid)
            .map_or(0, |slot| slot.participants.load(Ordering::Acquire))
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
        // Unlock before decrementing the participant count. A concurrent
        // acquirer either joins this exact slot under the map entry lock or
        // creates a new slot only after no old operation can enter it.
        self.guard.take();
        self.participant.take();
    }
}

impl PendingCapsIndex {
    pub(crate) fn new() -> Self {
        Self {
            entries: DashMap::new(),
            admission: Mutex::new(()),
        }
    }

    fn insert(
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
        // The first live correlation owns verification for this semantic key.
        // Followers keep their observation disco bit and retry after the
        // leader populates the knowledge cache (or its correlation expires),
        // preventing same-key fan-out from becoming one IQ per resource.
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

    fn take(&self, id: &str) -> Option<PendingCaps> {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.entries.remove(id).map(|(_, pending)| pending)
    }

    fn federated_resource(&self, id: &str) -> Option<String> {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.entries
            .get(id)
            .filter(|pending| matches!(pending.owner, CapsObservationOwner::Federated { .. }))
            .map(|pending| pending.full_jid.clone())
    }

    fn remove(&self, id: &str) {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.entries.remove(id);
    }

    pub(crate) fn remove_resource(&self, full_jid: &str) {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.entries
            .retain(|_, pending| pending.full_jid != full_jid);
    }

    pub(crate) fn remove_local_resource(&self, full_jid: &str, connection_id: uuid::Uuid) {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.entries.retain(|_, pending| {
            pending.full_jid != full_jid
                || !matches!(pending.owner, CapsObservationOwner::Local(epoch) if epoch.connection_id == connection_id)
        });
    }

    fn remove_local_epoch(&self, full_jid: &str, epoch: LocalCapsEpoch) {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.entries.retain(|_, pending| {
            pending.full_jid != full_jid || pending.owner != CapsObservationOwner::Local(epoch)
        });
    }

    fn remove_federated_connection(&self, connection_id: uuid::Uuid) {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.entries.retain(|_, pending| {
            !matches!(pending.owner, CapsObservationOwner::Federated { connection_id: owner, .. } if owner == connection_id)
        });
    }

    fn remove_federated_resource_if_connection(&self, full_jid: &str, connection_id: uuid::Uuid) {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.entries.retain(|_, pending| {
            pending.full_jid != full_jid
                || pending.owner.federated_connection() != Some(connection_id)
        });
    }

    fn take_expired(&self, now: Instant) -> Vec<(String, PendingCaps)> {
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

    fn next_expiration(&self) -> Option<Instant> {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.entries.iter().map(|pending| pending.expires_at).min()
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }
}

/// Optional raw/summary deduplication cache. Observation-owned Arcs are the
/// semantic authority; this cache may evict or expire any entry without
/// changing current PEP/MIX interest.
pub(crate) struct CapsCacheIndex {
    entries: DashMap<CapsKey, CachedCaps>,
    admission: Mutex<CapsCacheAdmission>,
    max_entries: usize,
    max_raw_bytes: usize,
    max_summary_bytes: usize,
    ttl: Duration,
}

#[derive(Default)]
struct CapsCacheAdmission {
    raw_bytes: usize,
    summary_bytes: usize,
}

impl CapsCacheIndex {
    pub(crate) fn new() -> Self {
        Self::with_limits(MAX_CAPS_CACHE_ENTRIES, CACHE_TTL)
    }

    fn with_limits(max_entries: usize, ttl: Duration) -> Self {
        Self::with_budgets(
            max_entries,
            MAX_CAPS_CACHE_RAW_BYTES,
            MAX_CAPS_CACHE_SUMMARY_BYTES,
            ttl,
        )
    }

    fn with_budgets(
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

    fn query(&self, key: &CapsKey, now: Instant) -> Option<Arc<VerifiedCapsSummary>> {
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

    fn raw_query(&self, key: &CapsKey, now: Instant) -> Option<String> {
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

    fn insert(&self, key: CapsKey, query: String, summary: Arc<VerifiedCapsSummary>, now: Instant) {
        let mut admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some((_, previous)) = self.entries.remove(&key) {
            release_cache_admission(&mut admission, &previous);
        } else if self.entries.len() >= self.max_entries {
            // One insert needs at most one entry eviction. A linear minimum
            // selection avoids sorting the whole attacker-influenced cache on
            // every distinct verified key.
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
            // The cache is optional. Do not evict several small entries for a
            // single large one (an O(n^2) churn vector); current observations
            // still retain authoritative summaries independently.
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
            // Preserve semantic same-key knowledge even when the optional raw
            // responder cache has no byte room.
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
        debug_assert!(self.entries.len() <= self.max_entries);
    }

    pub(crate) fn sweep(&self, now: Instant) {
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

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }

    #[cfg(test)]
    fn charged_bytes(&self) -> (usize, usize) {
        let admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        (admission.raw_bytes, admission.summary_bytes)
    }
}

fn release_cache_admission(admission: &mut CapsCacheAdmission, cached: &CachedCaps) {
    admission.raw_bytes = admission
        .raw_bytes
        .checked_sub(cached.query.as_ref().map_or(0, String::len))
        .expect("caps raw cache byte counter underflow");
    admission.summary_bytes = admission
        .summary_bytes
        .checked_sub(cached.summary.resident_charge())
        .expect("caps semantic cache byte counter underflow");
}

impl CapsResourceIndex {
    pub(crate) fn new() -> Self {
        Self::with_limits(
            MAX_FEDERATED_CAPS_RESOURCES,
            MAX_FEDERATED_CAPS_RESOURCES_PER_DOMAIN,
        )
    }

    fn with_limits(max_federated: usize, max_federated_per_domain: usize) -> Self {
        Self::with_budgets(
            max_federated,
            max_federated_per_domain,
            MAX_CAPS_OBSERVATION_SUMMARY_BYTES,
        )
    }

    fn with_budgets(
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

    fn observe_local(
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

    fn observe_federated(
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
        *admission
            .federated_per_domain
            .entry(domain.clone())
            .or_default() += 1;
        Some(owner)
    }

    fn owner(&self, full_jid: &str) -> Option<CapsObservationOwner> {
        self.entries.get(full_jid).map(|entry| entry.owner)
    }

    #[cfg(test)]
    fn summary(&self, full_jid: &str) -> Option<Arc<VerifiedCapsSummary>> {
        let mut entry = self.entries.get_mut(full_jid)?;
        entry.touched_at = Instant::now();
        match &entry.verification {
            CapsVerification::Verified(summary) => Some(Arc::clone(summary)),
            _ => None,
        }
    }

    fn snapshot(&self, full_jid: &str) -> Option<CapsObservationSnapshot> {
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

    fn interested_resources_for_bare(&self, bare: &str, node: &str) -> Vec<String> {
        self.entries
            .iter()
            .filter_map(|entry| {
                let matches_bare = crate::jid::canonical_bare_key(entry.key())
                    .is_ok_and(|candidate| candidate == bare);
                let interested = matches!(&entry.verification,
                    CapsVerification::Verified(summary) if summary.wants_node(node));
                (matches_bare && interested).then(|| entry.key().clone())
            })
            .collect()
    }

    fn current_owner(&self, full_jid: &str, owner: CapsObservationOwner) -> bool {
        self.entries
            .get(full_jid)
            .is_some_and(|entry| entry.owner == owner)
    }

    fn begin_query(
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

    fn mark_query_failed(&self, full_jid: &str, owner: CapsObservationOwner, id: &str) {
        let Some(mut entry) = self.entries.get_mut(full_jid) else {
            return;
        };
        if entry.owner == owner
            && matches!(&entry.verification, CapsVerification::Querying { id: current, .. } if current == id)
        {
            entry.verification = CapsVerification::NeedsDisco;
        }
    }

    fn mark_verified(
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
            // Resource exhaustion is neither a malformed result nor negative
            // interest. Keep verification work authoritative and retry it at
            // an event-driven deadline after memory can be released.
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

    fn mark_cached_verified(
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

    fn mark_invalid(&self, full_jid: &str, owner: CapsObservationOwner, key: &CapsKey, id: &str) {
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

    fn rearm_expired(&self, id: &str, pending: &PendingCaps, now: Instant) -> bool {
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

    fn claim_effects(&self, full_jid: &str, now: Instant) -> Option<CapsEffectJob> {
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

    fn complete_effects(&self, job: &CapsEffectJob, failed: CapsEffects, now: Instant) -> bool {
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

    fn recover_interrupted(&self, now: Instant) {
        for mut entry in self.entries.iter_mut() {
            if entry.running_effects != 0 {
                entry.pending_effects |= entry.running_effects;
                entry.running_effects = 0;
                entry.retry_at = now;
            }
        }
    }

    fn ready_observations(&self, now: Instant) -> Vec<(String, bool)> {
        self.entries
            .iter()
            .filter(|entry| {
                entry.pending_effects != 0 && entry.running_effects == 0 && entry.retry_at <= now
            })
            .map(|entry| (entry.key().clone(), entry.owner.is_local()))
            .collect()
    }

    fn next_retry_deadline(&self, now: Instant) -> Option<Instant> {
        self.entries
            .iter()
            .filter(|entry| {
                entry.pending_effects != 0 && entry.running_effects == 0 && entry.retry_at > now
            })
            .map(|entry| entry.retry_at)
            .min()
    }

    fn federated_resources_for_connection(&self, connection_id: uuid::Uuid) -> Vec<String> {
        self.entries
            .iter()
            .filter(|entry| entry.owner.federated_connection() == Some(connection_id))
            .map(|entry| entry.key().clone())
            .collect()
    }

    fn remove_federated_resource_if_connection(
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

    pub(crate) fn remove_local_resource(&self, full_jid: &str, connection_id: uuid::Uuid) {
        let mut admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some((_, observation)) = self.entries.remove_if(full_jid, |_, observation| {
            matches!(observation.owner, CapsObservationOwner::Local(epoch) if epoch.connection_id == connection_id)
        }) {
            release_observation_admission(&mut admission, &observation);
        }
    }

    fn remove_local_epoch(&self, full_jid: &str, epoch: LocalCapsEpoch) {
        let mut admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some((_, observation)) = self.entries.remove_if(full_jid, |_, observation| {
            observation.owner == CapsObservationOwner::Local(epoch)
        }) {
            release_observation_admission(&mut admission, &observation);
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }

    #[cfg(test)]
    fn federated_counts(&self, domain: &str) -> (usize, usize) {
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

    #[cfg(test)]
    fn summary_bytes(&self) -> usize {
        self.admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .summary_bytes
    }
}

fn try_install_verified_summary(
    admission: &mut CapsResourceAdmission,
    observation: &mut CapsObservation,
    summary: Arc<VerifiedCapsSummary>,
    max_summary_bytes: usize,
) -> bool {
    debug_assert_eq!(observation.summary_bytes, 0);
    let charge = summary.resident_charge();
    if charge > max_summary_bytes
        || admission.summary_bytes.saturating_add(charge) > max_summary_bytes
    {
        return false;
    }
    let mut effects = EFFECT_AUTOMATIC_PEP_LAST_ITEMS;
    if observation.owner.is_local()
        && (summary.has_feature("urn:xmpp:mix:core:1") || summary.has_feature("urn:xmpp:mix:pam:2"))
    {
        effects |= EFFECT_VERIFIED_MIX_PRESENCE;
    }
    observation.verification = CapsVerification::Verified(summary);
    observation.pending_effects |= effects;
    observation.summary_bytes = charge;
    admission.summary_bytes += charge;
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

fn caps_retry_delay(failures: u32) -> Duration {
    let shift = failures.saturating_sub(1).min(7);
    CAPS_EFFECT_RETRY_BASE
        .saturating_mul(1_u32 << shift)
        .min(CAPS_EFFECT_RETRY_MAX)
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct CapsEffects(u8);

impl CapsEffects {
    const EXPLICIT_PEP_LAST_ITEMS: Self = Self(1 << 0);
    const AUTOMATIC_PEP_LAST_ITEMS: Self = Self(1 << 1);
    const VERIFIED_MIX_PRESENCE: Self = Self(1 << 2);
    const DISCO_QUERY: Self = Self(1 << 3);

    fn contains(self, effect: Self) -> bool {
        self.0 & effect.0 != 0
    }

    fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl std::ops::BitOr for CapsEffects {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

#[derive(Debug)]
struct CapsEffectQueue {
    accepting: bool,
    local_ready: VecDeque<String>,
    federated_ready: VecDeque<String>,
    local_queued: HashSet<String>,
    federated_queued: HashSet<String>,
    prefer_local: bool,
    rescan_required: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CapsEffectAdmission {
    Queued,
    Coalesced,
    Saturated,
    Closed,
}

/// Bounded wake-hint queue for the authoritative observation table.  A hint
/// can be coalesced, saturated, lost on restart, or become stale without
/// changing semantics: saturation requests an event-driven reconstruction from
/// `CapsResourceIndex`, while restart recovery performs one initial rebuild.
pub(crate) struct CapsEffectDispatcher {
    queue: Mutex<CapsEffectQueue>,
    wake: Notify,
    execution_slots: Arc<Semaphore>,
    capacity: usize,
}

impl CapsEffectDispatcher {
    pub(crate) fn new() -> Arc<Self> {
        Self::with_limits(MAX_CAPS_EFFECT_HINTS, MAX_CAPS_EFFECT_CONCURRENCY)
    }

    fn with_limits(capacity: usize, concurrency: usize) -> Arc<Self> {
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

    fn hint(
        &self,
        full_jid: String,
        local: bool,
        metrics: &crate::metrics::Metrics,
    ) -> CapsEffectAdmission {
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
            metrics
                .caps_effect_coalesced_total
                .fetch_add(1, Ordering::Relaxed);
            return CapsEffectAdmission::Coalesced;
        }
        let class_len = if local {
            queue.local_ready.len()
        } else {
            queue.federated_ready.len()
        };
        if class_len >= self.capacity {
            metrics
                .caps_effect_queue_saturated_total
                .fetch_add(1, Ordering::Relaxed);
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

    fn take_hint(&self) -> Option<String> {
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

    fn request_rescan(&self) {
        let notify = {
            let mut queue = self
                .queue
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let notify = !queue.rescan_required;
            queue.rescan_required = true;
            notify
        };
        if notify {
            self.wake.notify_one();
        }
    }

    fn begin_rescan(&self) -> bool {
        let mut queue = self
            .queue
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !queue.rescan_required {
            return false;
        }
        queue.rescan_required = false;
        true
    }

    /// Lifecycle removal needs no correctness mutation here: the exact
    /// observation is compare-removed from `CapsResourceIndex`, and any hint
    /// which remains becomes a harmless failed lookup.
    pub(crate) fn cancel_local(&self, full_jid: &str, connection_id: uuid::Uuid) {
        let _ = (full_jid, connection_id);
    }

    fn close(&self) {
        self.queue
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .accepting = false;
        self.wake.notify_waiters();
    }
}

struct CapsEffectRunGuard(Arc<AppState>);

impl Drop for CapsEffectRunGuard {
    fn drop(&mut self) {
        self.0.caps_by_jid().recover_interrupted(Instant::now());
        self.0.caps_effect_dispatcher().request_rescan();
    }
}

type CapsEffectFuture =
    Pin<Box<dyn Future<Output = (CapsEffectJob, CapsEffects)> + Send + 'static>>;

pub(super) fn local_caps_epoch_is_current(
    state: &AppState,
    full_jid: &str,
    epoch: LocalCapsEpoch,
) -> bool {
    state.sessions.get(full_jid).is_some_and(|session| {
        local_caps_route_epoch_matches(
            session.connection_id,
            session.caps_observation_generation.load(Ordering::Acquire),
            session.routable.load(Ordering::Acquire),
            session.disconnect.is_cancelled(),
            session.lifecycle.load(Ordering::Acquire),
            true,
            epoch,
        )
    })
}

pub(super) fn local_caps_route_epoch_matches(
    current_connection_id: uuid::Uuid,
    current_generation: u64,
    routable: bool,
    cancelled: bool,
    lifecycle: u8,
    same_gate: bool,
    expected: LocalCapsEpoch,
) -> bool {
    current_connection_id == expected.connection_id
        && current_generation == expected.generation
        && routable
        && !cancelled
        && lifecycle == 0
        && same_gate
}

/// Cleanup-side route removal is synchronous and deliberately cannot await
/// the async MIX gate. This fence closes the complementary interleaving: if
/// route removal happened after the handler's initial check but before one of
/// its index/queue insertions, Drop compare-removes only that exact epoch.
struct LocalCapsObservationFence<'a> {
    state: &'a AppState,
    full_jid: &'a str,
    epoch: LocalCapsEpoch,
}

impl Drop for LocalCapsObservationFence<'_> {
    fn drop(&mut self) {
        if local_caps_epoch_is_current(self.state, self.full_jid, self.epoch) {
            return;
        }
        self.state
            .pending_caps()
            .remove_local_epoch(self.full_jid, self.epoch);
        self.state
            .caps_by_jid()
            .remove_local_epoch(self.full_jid, self.epoch);
    }
}

fn hint_caps_effects(state: &AppState, full_jid: String) {
    let local = state
        .caps_by_jid()
        .owner(&full_jid)
        .is_some_and(CapsObservationOwner::is_local);
    match state
        .caps_effect_dispatcher()
        .hint(full_jid, local, &state.metrics)
    {
        CapsEffectAdmission::Queued | CapsEffectAdmission::Coalesced => {}
        CapsEffectAdmission::Saturated => {
            tracing::debug!("caps wake-hint queue saturated; observation remains pending");
        }
        CapsEffectAdmission::Closed => {
            tracing::debug!("caps wake hint ignored during service shutdown; observation retained");
        }
    }
}

fn allocate_local_caps_epoch(
    connection_id: uuid::Uuid,
    generation: &std::sync::atomic::AtomicU64,
) -> LocalCapsEpoch {
    LocalCapsEpoch {
        connection_id,
        generation: generation.fetch_add(1, Ordering::AcqRel).wrapping_add(1),
    }
}

fn caps_owner_is_current(state: &AppState, job: &CapsEffectJob) -> bool {
    state.caps_by_jid().current_owner(&job.full_jid, job.owner)
        && match job.owner {
            CapsObservationOwner::Local(epoch) => {
                local_caps_epoch_is_current(state, &job.full_jid, epoch)
            }
            CapsObservationOwner::Federated { .. } => true,
        }
}

async fn send_caps_disco_query(state: &AppState, job: &CapsEffectJob) -> anyhow::Result<()> {
    let key = job
        .key
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("caps disco work has no advertised key"))?;
    // Re-check verified knowledge at dispatch time. Observations can be
    // admitted together before the first response arrives; the pending index
    // single-flights that first request, and followers resolve from this same
    // Arc on their event-driven retry instead of emitting duplicate IQs.
    if let Some(summary) = state.caps_cache().query(key, Instant::now()) {
        return match state.caps_by_jid().mark_cached_verified(
            &job.full_jid,
            job.owner,
            key,
            summary,
        ) {
            CapsVerificationCommit::Applied => Ok(()),
            CapsVerificationCommit::Stale => {
                anyhow::bail!("caps observation no longer needs cached verification")
            }
            CapsVerificationCommit::ResourceLimited => {
                anyhow::bail!("caps semantic memory budget is exhausted")
            }
        };
    }
    let id = format!("caps-{}", stream_id());
    let expires_at = Instant::now() + PENDING_TTL;
    if !state
        .caps_by_jid()
        .begin_query(&job.full_jid, job.owner, key, id.clone())
    {
        anyhow::bail!("caps observation no longer needs this disco query");
    }
    if !state.pending_caps().insert(
        id.clone(),
        job.full_jid.clone(),
        key.clone(),
        job.owner,
        expires_at,
    ) {
        state
            .caps_by_jid()
            .mark_query_failed(&job.full_jid, job.owner, &id);
        anyhow::bail!("caps IQ correlation ID or semantic key is already in flight");
    }
    let query = caps_disco_request(
        &state.config.domain,
        &job.full_jid,
        &id,
        &key.node,
        &key.version,
    );
    let sent = match job.owner {
        CapsObservationOwner::Local(epoch) => {
            let sender = state.sessions.get(&job.full_jid).and_then(|session| {
                local_caps_route_epoch_matches(
                    session.connection_id,
                    session.caps_observation_generation.load(Ordering::Acquire),
                    session.routable.load(Ordering::Acquire),
                    session.disconnect.is_cancelled(),
                    session.lifecycle.load(Ordering::Acquire),
                    true,
                    epoch,
                )
                .then(|| session.sender.clone())
            });
            match sender {
                Some(sender) => match sender.try_send(query) {
                    Ok(()) => true,
                    Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                        // This sender belongs to the exact epoch validated above.
                        // Queue saturation is a transport failure, never a
                        // successful disco dispatch.
                        sender.disconnect_backpressured_transport();
                        false
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => false,
                },
                None => false,
            }
        }
        CapsObservationOwner::Federated { .. } => {
            let domain = crate::jid::CanonicalJid::parse(&job.full_jid)?
                .domainpart()
                .to_owned();
            state
                .federation
                .send(&domain, query, Some(state.config.domain.clone()))
                .await
        }
    };
    if sent {
        Ok(())
    } else {
        state.pending_caps().remove(&id);
        state
            .caps_by_jid()
            .mark_query_failed(&job.full_jid, job.owner, &id);
        anyhow::bail!("caps disco query was not accepted by its exact transport")
    }
}

async fn execute_caps_effects_inner(state: &Arc<AppState>, job: &CapsEffectJob) -> CapsEffects {
    if !caps_owner_is_current(state, job) {
        return CapsEffects::default();
    }
    let mut failed = CapsEffects::default();
    if job.effects.contains(CapsEffects::DISCO_QUERY) {
        if let Err(error) = send_caps_disco_query(state, job).await {
            failed.0 |= CapsEffects::DISCO_QUERY.0;
            tracing::warn!(?error, resource = %job.full_jid, "failed to dispatch capability disco query");
        }
    }
    if job.effects.contains(CapsEffects::EXPLICIT_PEP_LAST_ITEMS) {
        let local_epoch = match job.owner {
            CapsObservationOwner::Local(epoch) => Some(epoch),
            CapsObservationOwner::Federated { .. } => None,
        };
        if let Err(error) = super::pep::deliver_explicit_pep_last_items_for_resource(
            state,
            &job.full_jid,
            local_epoch,
        )
        .await
        {
            failed.0 |= CapsEffects::EXPLICIT_PEP_LAST_ITEMS.0;
            tracing::warn!(?error, resource = %job.full_jid, "failed to deliver explicit PEP last items");
        }
    }
    if job.effects.contains(CapsEffects::AUTOMATIC_PEP_LAST_ITEMS) {
        let result = match job.owner {
            CapsObservationOwner::Local(epoch) => {
                super::pep::deliver_pep_last_items_for_resource(state, &job.full_jid, epoch).await
            }
            CapsObservationOwner::Federated { .. } => {
                super::pep::deliver_pep_last_items_for_federated_resource(state, &job.full_jid)
                    .await
            }
        };
        if let Err(error) = result {
            failed.0 |= CapsEffects::AUTOMATIC_PEP_LAST_ITEMS.0;
            tracing::warn!(?error, resource = %job.full_jid, "failed to deliver capability-selected PEP last items");
        }
    }
    if job.effects.contains(CapsEffects::VERIFIED_MIX_PRESENCE) {
        let result = match job.owner {
            CapsObservationOwner::Local(epoch) => {
                super::mix::publish_verified_mix_presence(
                    state,
                    &job.full_jid,
                    epoch.connection_id,
                    epoch.generation,
                )
                .await
            }
            CapsObservationOwner::Federated { .. } => Ok(()),
        };
        if let Err(error) = result {
            failed.0 |= CapsEffects::VERIFIED_MIX_PRESENCE.0;
            tracing::warn!(?error, resource = %job.full_jid, "failed to publish verified MIX presence");
        }
    }
    failed
}

async fn execute_caps_effects(state: Arc<AppState>, job: &CapsEffectJob) -> CapsEffects {
    match job.owner {
        CapsObservationOwner::Local(_) => execute_caps_effects_inner(&state, job).await,
        CapsObservationOwner::Federated { .. } => {
            let _resource_epoch = state.federated_caps_gates().lock(&job.full_jid).await;
            execute_caps_effects_inner(&state, job).await
        }
    }
}

async fn run_caps_effect_dispatcher(
    state: Arc<AppState>,
    cancel: CancellationToken,
    heartbeat: crate::workers::WorkerHeartbeat,
) -> anyhow::Result<()> {
    let dispatcher = Arc::clone(state.caps_effect_dispatcher());
    state.caps_by_jid().recover_interrupted(Instant::now());
    // A restart performs one authoritative reconstruction. Thereafter new
    // work, saturation, completions and exact retry/expiry deadlines are the
    // only wake sources; correctness does not depend on fixed polling.
    dispatcher.request_rescan();
    let _recovery = CapsEffectRunGuard(Arc::clone(&state));
    let mut running = FuturesUnordered::<CapsEffectFuture>::new();
    let mut draining = false;
    let mut liveness = tokio::time::interval(Duration::from_secs(15));
    liveness.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        if cancel.is_cancelled() && !draining {
            draining = true;
            dispatcher.close();
        }

        loop {
            let Ok(permit) = Arc::clone(&dispatcher.execution_slots).try_acquire_owned() else {
                break;
            };
            let Some(full_jid) = dispatcher.take_hint() else {
                drop(permit);
                break;
            };
            let Some(job) = state.caps_by_jid().claim_effects(&full_jid, Instant::now()) else {
                drop(permit);
                continue;
            };
            let effect_state = Arc::clone(&state);
            running.push(Box::pin(async move {
                let _permit = permit;
                let failed = execute_caps_effects(effect_state, &job).await;
                (job, failed)
            }));
        }

        if !draining
            && dispatcher.execution_slots.available_permits() > 0
            && dispatcher.begin_rescan()
        {
            let now = Instant::now();
            for (full_jid, local) in state.caps_by_jid().ready_observations(now) {
                let _ = dispatcher.hint(full_jid, local, &state.metrics);
            }
            // Schedule reconstructed hints before sleeping. If a class filled,
            // `hint` left rescan_required set; freeing a slot wakes the next
            // reconstruction without a lost-notify window.
            continue;
        }

        if draining && running.is_empty() {
            heartbeat.ok();
            return Ok(());
        }

        let now = Instant::now();
        let next_deadline = if draining {
            None
        } else {
            match (
                state.caps_by_jid().next_retry_deadline(now),
                state.pending_caps().next_expiration(),
            ) {
                (Some(left), Some(right)) => Some(left.min(right)),
                (Some(deadline), None) | (None, Some(deadline)) => Some(deadline),
                (None, None) => None,
            }
        };
        let deadline_wait = async move {
            match next_deadline {
                Some(deadline) => tokio::time::sleep_until(deadline.into()).await,
                None => futures::future::pending::<()>().await,
            }
        };
        tokio::pin!(deadline_wait);

        tokio::select! {
            _ = cancel.cancelled(), if !draining => {
                draining = true;
                dispatcher.close();
            }
            Some((job, failed)) = running.next(), if !running.is_empty() => {
                if matches!(job.owner, CapsObservationOwner::Local(epoch) if !local_caps_epoch_is_current(&state, &job.full_jid, epoch)) {
                    if let CapsObservationOwner::Local(epoch) = job.owner {
                        state.pending_caps().remove_local_epoch(&job.full_jid, epoch);
                        state.caps_by_jid().remove_local_epoch(&job.full_jid, epoch);
                    }
                } else if state.caps_by_jid().complete_effects(&job, failed, Instant::now()) {
                    let _ = dispatcher.hint(
                        job.full_jid.clone(),
                        job.owner.is_local(),
                        &state.metrics,
                    );
                }
                state.metrics.caps_effect_latency_seconds.observe(job.queued_at.elapsed());
                let failures = failed.0.count_ones() as u64;
                if failures == 0 {
                    heartbeat.ok();
                } else {
                    state.metrics.caps_effect_failures_total.fetch_add(
                        failures,
                        Ordering::Relaxed,
                    );
                    heartbeat.error(format!("{failures} caps side effects failed"));
                }
            }
            _ = dispatcher.wake.notified() => {}
            _ = &mut deadline_wait, if !draining => {
                let now = Instant::now();
                for (id, pending) in state.pending_caps().take_expired(now) {
                    if state.caps_by_jid().rearm_expired(&id, &pending, now) {
                        let _ = dispatcher.hint(
                            pending.full_jid,
                            pending.owner.is_local(),
                            &state.metrics,
                        );
                    }
                }
                dispatcher.request_rescan();
            }
            _ = liveness.tick() => {
                state.caps_cache().sweep(Instant::now());
                heartbeat.pulse();
            }
        }
    }
}

pub(crate) fn start_caps_effect_dispatcher(state: Arc<AppState>, cancel: CancellationToken) {
    let worker_registry = Arc::clone(state.worker_registry());
    worker_registry.supervise_draining(
        "caps-side-effects",
        crate::workers::WorkerCriticality::Restartable,
        crate::workers::WorkerMode::Continuous,
        Some(Duration::from_secs(60)),
        CAPS_EFFECT_DRAIN_GRACE,
        cancel.clone(),
        move |heartbeat| {
            let state = Arc::clone(&state);
            let cancel = cancel.clone();
            async move { run_caps_effect_dispatcher(state, cancel, heartbeat).await }
        },
    );
}

impl ProtocolSession {
    /// Rebind a persisted XEP-0115 advertisement to a newly activated
    /// XEP-0198 transport incarnation.
    ///
    /// The staged resume route is deliberately invisible when this method is
    /// armed. Publication consumes the value exactly once, crosses the same
    /// resource gate used by presence/cleanup, revalidates the new route, and
    /// then runs the ordinary observation pipeline. The pipeline allocates a
    /// fresh `(connection_id,generation)` epoch and sends any disco query to
    /// the replacement transport.
    pub(crate) async fn rebind_resumed_caps_observation(&mut self) {
        let Some(raw_presence) = self.resumed_caps_presence.take() else {
            return;
        };
        let Some(full_jid) = self.registered_key.clone() else {
            return;
        };
        let Ok(document) = roxmltree::Document::parse(&raw_presence) else {
            tracing::warn!(
                connection_id = %self.connection_id,
                "discarded malformed persisted presence while rebinding entity capabilities"
            );
            return;
        };
        let presence = document.root_element();
        if presence.tag_name().name() != "presence"
            || presence
                .attribute("type")
                .is_some_and(|kind| kind != "available")
        {
            return;
        }

        let _resource_epoch = Arc::clone(&self.mix_presence_gate).lock_owned().await;
        let route_is_current = self.state.sessions.get(&full_jid).is_some_and(|session| {
            session.connection_id == self.connection_id
                && Arc::ptr_eq(&session.mix_presence_gate, &self.mix_presence_gate)
                && session.routable.load(Ordering::Acquire)
                && !session.disconnect.is_cancelled()
                && session.lifecycle.load(Ordering::Acquire) == 0
        });
        if route_is_current {
            self.commit_caps_observation(presence, &full_jid);
        }
    }

    pub(crate) fn advertised_mix_capability(
        &self,
        presence: Node<'_, '_>,
        full_jid: &str,
    ) -> super::mix::MixSessionCapability {
        let Ok(full_jid) = crate::jid::canonical_session_key(full_jid) else {
            return super::mix::MixSessionCapability::Unknown;
        };
        let Some(key) = observed_caps_key(presence, &full_jid) else {
            return super::mix::MixSessionCapability::Unknown;
        };
        let summary = self
            .state
            .caps_by_jid()
            .snapshot(&full_jid)
            .filter(|observation| observation.key.as_ref() == Some(&key))
            .and_then(|observation| observation.summary)
            .or_else(|| self.state.caps_cache().query(&key, Instant::now()));
        let Some(summary) = summary else {
            return super::mix::MixSessionCapability::Unknown;
        };
        if summary.has_feature("urn:xmpp:mix:core:1") || summary.has_feature("urn:xmpp:mix:pam:2") {
            super::mix::MixSessionCapability::Supported
        } else {
            super::mix::MixSessionCapability::Unsupported
        }
    }

    /// Commit the latest caps observation only after the surrounding presence
    /// handler has durably applied the matching MIX projection and updated
    /// availability while holding `mix_presence_gate`.
    pub(crate) fn commit_caps_observation(&self, presence: Node<'_, '_>, full_jid: &str) {
        let Ok(full_jid) = crate::jid::canonical_session_key(full_jid) else {
            return;
        };
        let connection_is_current = self.state.sessions.get(&full_jid).is_some_and(|session| {
            session.connection_id == self.connection_id
                && Arc::ptr_eq(&session.mix_presence_gate, &self.mix_presence_gate)
                && session.routable.load(Ordering::Acquire)
                && !session.disconnect.is_cancelled()
                && session.lifecycle.load(Ordering::Acquire) == 0
        });
        if !connection_is_current {
            return;
        }
        let epoch =
            allocate_local_caps_epoch(self.connection_id, &self.caps_observation_generation);
        let _observation_fence = LocalCapsObservationFence {
            state: &self.state,
            full_jid: &full_jid,
            epoch,
        };
        // Every presence is a latest-wins observation, including an available
        // stanza without `<c/>`. Retire only this connection's older state so
        // a late old actor cannot cancel a replacement's pending work.
        self.state
            .pending_caps()
            .remove_local_resource(&full_jid, self.connection_id);
        if presence
            .attribute("type")
            .is_some_and(|kind| kind != "available")
        {
            self.state
                .caps_by_jid()
                .remove_local_resource(&full_jid, self.connection_id);
            return;
        }
        let now = Instant::now();
        let key = observed_caps_key(presence, &full_jid);
        let cached = key
            .as_ref()
            .and_then(|key| self.state.caps_cache().query(key, now));
        self.state
            .caps_by_jid()
            .observe_local(full_jid.clone(), epoch, key, cached, now);
        hint_caps_effects(&self.state, full_jid.clone());
    }

    pub(crate) async fn handle_caps_response(
        &self,
        id: &str,
        kind: &str,
        root: Node<'_, '_>,
        raw: &str,
    ) -> bool {
        let Some(pending) = self.state.pending_caps().take(id) else {
            return false;
        };
        let CapsObservationOwner::Local(epoch) = pending.owner else {
            // A C2S actor can never authorize a federated correlation. Put it
            // back only if it is still live; the S2S response path will own it.
            let _ = self.state.pending_caps().insert(
                id.to_owned(),
                pending.full_jid,
                pending.key,
                pending.owner,
                pending.expires_at,
            );
            return false;
        };
        let _epoch_guard = Arc::clone(&self.mix_presence_gate).lock_owned().await;
        if epoch.connection_id != self.connection_id
            || !local_caps_epoch_is_current(&self.state, &pending.full_jid, epoch)
        {
            return true;
        }
        let _observation_fence = LocalCapsObservationFence {
            state: &self.state,
            full_jid: &pending.full_jid,
            epoch,
        };
        // RFC 6120 §8.1.2.1 permits a client to omit `from`; in that case the
        // receiving server supplies the authenticated full JID.  An explicit
        // value is still untrusted input and may authorize this correlation
        // only when it is the authenticated full JID.  The federated handler
        // below deliberately keeps requiring an explicit, authenticated S2S
        // sender instead of using this C2S rule.
        let response_from =
            effective_c2s_caps_sender(self.full_jid.as_deref(), root.attribute("from"));
        if pending.expires_at <= Instant::now()
            || response_from.as_deref() != Some(pending.full_jid.as_str())
        {
            tracing::debug!(
                authenticated = ?self.full_jid,
                explicit_from = ?root.attribute("from"),
                effective_from = ?response_from,
                expected_from = %pending.full_jid,
                stanza_type = %kind,
                expired = pending.expires_at <= Instant::now(),
                "rearming entity capabilities after an invalid response envelope"
            );
            if self
                .state
                .caps_by_jid()
                .rearm_expired(id, &pending, Instant::now())
            {
                hint_caps_effects(&self.state, pending.full_jid.clone());
            }
            return true;
        }
        if kind != "result" {
            self.state.caps_by_jid().mark_invalid(
                &pending.full_jid,
                pending.owner,
                &pending.key,
                id,
            );
            return true;
        }
        let Some(query) = root.children().find(|node| {
            node.is_element()
                && node.tag_name().name() == "query"
                && node.tag_name().namespace() == Some(DISCO_INFO_NS)
        }) else {
            self.state.caps_by_jid().mark_invalid(
                &pending.full_jid,
                pending.owner,
                &pending.key,
                id,
            );
            return true;
        };
        let expected_node = format!("{}#{}", pending.key.node, pending.key.version);
        if query.attribute("node") != Some(expected_node.as_str()) {
            tracing::debug!(jid = %pending.full_jid, "discarded entity capabilities with a mismatched node");
            self.state.caps_by_jid().mark_invalid(
                &pending.full_jid,
                pending.owner,
                &pending.key,
                id,
            );
            return true;
        }
        let range = query.range();
        let Some(payload) = raw.get(range) else {
            return true;
        };
        if payload.len() > MAX_DISCO_PAYLOAD_BYTES {
            self.state.caps_by_jid().mark_invalid(
                &pending.full_jid,
                pending.owner,
                &pending.key,
                id,
            );
            return true;
        }
        let Ok(verification) = verification_string(query) else {
            tracing::debug!(jid = %pending.full_jid, "discarded malformed entity capabilities");
            self.state.caps_by_jid().mark_invalid(
                &pending.full_jid,
                pending.owner,
                &pending.key,
                id,
            );
            return true;
        };
        if pending.key.algorithm == "sha-1" {
            let computed = STANDARD.encode(Sha1::digest(verification.as_bytes()));
            if computed != pending.key.version {
                tracing::warn!(jid = %pending.full_jid, "discarded entity capabilities whose hash did not verify");
                self.state.caps_by_jid().mark_invalid(
                    &pending.full_jid,
                    pending.owner,
                    &pending.key,
                    id,
                );
                return true;
            }
        }
        let Ok(summary) = verified_caps_summary(query, payload) else {
            self.state.caps_by_jid().mark_invalid(
                &pending.full_jid,
                pending.owner,
                &pending.key,
                id,
            );
            return true;
        };
        let summary = Arc::new(summary);
        self.state.caps_cache().insert(
            pending.key.clone(),
            payload.to_owned(),
            Arc::clone(&summary),
            Instant::now(),
        );
        let full_jid = pending.full_jid.clone();
        tracing::debug!(
            jid = %full_jid,
            node = %pending.key.node,
            version = %pending.key.version,
            "cached verified entity capabilities"
        );
        match self.state.caps_by_jid().mark_verified(
            &full_jid,
            pending.owner,
            &pending.key,
            id,
            summary,
        ) {
            CapsVerificationCommit::Applied => hint_caps_effects(&self.state, full_jid),
            CapsVerificationCommit::ResourceLimited => {
                self.state
                    .metrics
                    .caps_effect_failures_total
                    .fetch_add(1, Ordering::Relaxed);
                tracing::warn!(jid = %full_jid, "caps semantic memory budget exhausted; verification remains pending");
                hint_caps_effects(&self.state, full_jid);
            }
            CapsVerificationCommit::Stale => {}
        }
        true
    }
}

fn observed_caps_key(presence: Node<'_, '_>, full_jid: &str) -> Option<CapsKey> {
    let caps = presence.children().find(|node| {
        node.is_element()
            && node.tag_name().name() == "c"
            && node.tag_name().namespace() == Some(CAPS_NS)
    })?;
    let (algorithm, node, version) = (
        caps.attribute("hash")?,
        caps.attribute("node")?,
        caps.attribute("ver")?,
    );
    // SHA-1 is the mandatory verification algorithm. Unsupported algorithms
    // are namespaced by this exact full JID before entering the bounded cache,
    // so an unverified claim cannot be shared with or collide with another
    // resource's capability mapping.
    if node.is_empty()
        || node.len() > 2_048
        || version.is_empty()
        || version.len() > 256
        || algorithm.is_empty()
        || algorithm.len() > 64
        || node.chars().any(char::is_control)
        || version.chars().any(char::is_control)
        || algorithm.chars().any(char::is_control)
    {
        return None;
    }
    Some(CapsKey {
        algorithm: scoped_algorithm(algorithm, full_jid),
        node: node.to_owned(),
        version: version.to_owned(),
    })
}

fn effective_c2s_caps_sender(
    authenticated_full_jid: Option<&str>,
    explicit_from: Option<&str>,
) -> Option<String> {
    let authenticated = crate::jid::canonical_session_key(authenticated_full_jid?).ok()?;
    match explicit_from {
        None => Some(authenticated),
        Some(from) => {
            let claimed = crate::jid::canonical_session_key(from).ok()?;
            (claimed == authenticated).then_some(authenticated)
        }
    }
}

fn current_caps_observation(state: &AppState, target: &str) -> Option<CapsObservationSnapshot> {
    let snapshot = state.caps_by_jid().snapshot(target)?;
    if let CapsObservationOwner::Local(epoch) = snapshot.owner {
        if !local_caps_epoch_is_current(state, target, epoch) {
            state.pending_caps().remove_local_epoch(target, epoch);
            state.caps_by_jid().remove_local_epoch(target, epoch);
            return None;
        }
    }
    Some(snapshot)
}

/// Observes an authenticated federated resource's XEP-0115 advertisement.
/// Remote claims are never trusted directly: the advertised disco payload is
/// requested over the already-authenticated S2S route and hash-verified before
/// it can influence PEP fan-out.
pub(crate) async fn observe_federated_caps(
    state: &AppState,
    presence: Node<'_, '_>,
    full_jid: &str,
    connection_id: uuid::Uuid,
    resource_epoch: &FederatedCapsGuard<'_>,
) -> FederatedCapsObservationResult {
    let Ok(full_jid) = crate::jid::canonical_session_key(full_jid) else {
        return FederatedCapsObservationResult::StaleOwner;
    };
    if resource_epoch.resource() != full_jid {
        debug_assert_eq!(resource_epoch.resource(), full_jid);
        return FederatedCapsObservationResult::StaleOwner;
    }
    if presence
        .attribute("type")
        .is_some_and(|kind| kind != "available")
    {
        if state
            .caps_by_jid()
            .owner(&full_jid)
            .is_some_and(|owner| owner.federated_connection() != Some(connection_id))
        {
            return FederatedCapsObservationResult::StaleOwner;
        }
        state
            .caps_by_jid()
            .remove_federated_resource_if_connection(&full_jid, connection_id);
        state
            .pending_caps()
            .remove_federated_resource_if_connection(&full_jid, connection_id);
        return FederatedCapsObservationResult::Accepted;
    }
    let domain = crate::jid::CanonicalJid::parse(&full_jid)
        .expect("canonical full JID was parsed above")
        .domainpart()
        .to_owned();
    let now = Instant::now();
    let key = observed_caps_key(presence, &full_jid);
    let cached = key
        .as_ref()
        .and_then(|key| state.caps_cache().query(key, now));
    state.pending_caps().remove_resource(&full_jid);
    if state
        .caps_by_jid()
        .observe_federated(full_jid.clone(), connection_id, domain, key, cached, now)
        .is_none()
    {
        return FederatedCapsObservationResult::Saturated;
    }
    hint_caps_effects(state, full_jid);
    FederatedCapsObservationResult::Accepted
}

/// Retires every observation owned by one authenticated federation/component
/// transport. Each resource crosses the same gate as presence, responses and
/// effects, while the compare-remove still checks the exact connection so a
/// newer stream's same-full-JID observation survives teardown ABA.
pub(crate) async fn federated_caps_connection_closed(state: &AppState, connection_id: uuid::Uuid) {
    loop {
        let resources = state
            .caps_by_jid()
            .federated_resources_for_connection(connection_id);
        if resources.is_empty() {
            break;
        }
        for resource in resources {
            let _resource_epoch = state.federated_caps_gates().lock(&resource).await;
            state
                .caps_by_jid()
                .remove_federated_resource_if_connection(&resource, connection_id);
        }
    }
    state
        .pending_caps()
        .remove_federated_connection(connection_id);
}

fn caps_disco_request(domain: &str, full_jid: &str, id: &str, node: &str, version: &str) -> String {
    XmlElement::namespaced("iq", "jabber:client")
        .attr("type", "get")
        .attr("from", domain)
        .attr("to", full_jid)
        .attr("id", id)
        .child(
            XmlElement::namespaced("query", DISCO_INFO_NS)
                .attr("node", format!("{node}#{version}")),
        )
        .finish()
}

/// Consumes a disco result generated by `observe_federated_caps`. Returns
/// false for unrelated IQs so normal S2S routing remains untouched.
pub(crate) async fn handle_federated_caps_response(
    state: &AppState,
    id: &str,
    kind: &str,
    root: Node<'_, '_>,
    raw: &str,
) -> bool {
    // Peek only the routing key, then acquire the same authority as presence.
    // Consume the pending entry after the gate is held: an unavailable which
    // linearized first removes it, while a response which linearized first
    // completes before that unavailable can commit its removal.
    let Some(resource) = state.pending_caps().federated_resource(id) else {
        return false;
    };
    let _resource_epoch = state.federated_caps_gates().lock(&resource).await;
    let Some(pending) = state.pending_caps().take(id) else {
        return true;
    };
    debug_assert_eq!(pending.full_jid, resource);
    if !matches!(pending.owner, CapsObservationOwner::Federated { .. }) {
        let _ = state.pending_caps().insert(
            id.to_owned(),
            pending.full_jid,
            pending.key,
            pending.owner,
            pending.expires_at,
        );
        return false;
    }
    if !state
        .caps_by_jid()
        .current_owner(&pending.full_jid, pending.owner)
    {
        return true;
    }
    let response_from = root
        .attribute("from")
        .and_then(|jid| crate::jid::canonical_session_key(jid).ok());
    if pending.expires_at <= Instant::now()
        || response_from.as_deref() != Some(pending.full_jid.as_str())
    {
        if state
            .caps_by_jid()
            .rearm_expired(id, &pending, Instant::now())
        {
            hint_caps_effects(state, pending.full_jid.clone());
        }
        return true;
    }
    if kind != "result" {
        state
            .caps_by_jid()
            .mark_invalid(&pending.full_jid, pending.owner, &pending.key, id);
        return true;
    }
    let Some(query) = root.children().find(|node| {
        node.is_element()
            && node.tag_name().name() == "query"
            && node.tag_name().namespace() == Some(DISCO_INFO_NS)
    }) else {
        state
            .caps_by_jid()
            .mark_invalid(&pending.full_jid, pending.owner, &pending.key, id);
        return true;
    };
    let expected_node = format!("{}#{}", pending.key.node, pending.key.version);
    let range = query.range();
    let Some(payload) = raw.get(range) else {
        state
            .caps_by_jid()
            .mark_invalid(&pending.full_jid, pending.owner, &pending.key, id);
        return true;
    };
    if query.attribute("node") != Some(expected_node.as_str())
        || payload.len() > MAX_DISCO_PAYLOAD_BYTES
    {
        state
            .caps_by_jid()
            .mark_invalid(&pending.full_jid, pending.owner, &pending.key, id);
        return true;
    }
    let Ok(verification) = verification_string(query) else {
        state
            .caps_by_jid()
            .mark_invalid(&pending.full_jid, pending.owner, &pending.key, id);
        return true;
    };
    if pending.key.algorithm == "sha-1"
        && STANDARD.encode(Sha1::digest(verification.as_bytes())) != pending.key.version
    {
        tracing::warn!(jid = %pending.full_jid, "discarded federated entity capabilities whose hash did not verify");
        state
            .caps_by_jid()
            .mark_invalid(&pending.full_jid, pending.owner, &pending.key, id);
        return true;
    }
    let Ok(summary) = verified_caps_summary(query, payload) else {
        state
            .caps_by_jid()
            .mark_invalid(&pending.full_jid, pending.owner, &pending.key, id);
        return true;
    };
    let summary = Arc::new(summary);
    state.caps_cache().insert(
        pending.key.clone(),
        payload.to_owned(),
        Arc::clone(&summary),
        Instant::now(),
    );
    let resource = pending.full_jid;
    match state
        .caps_by_jid()
        .mark_verified(&resource, pending.owner, &pending.key, id, summary)
    {
        CapsVerificationCommit::Applied => hint_caps_effects(state, resource),
        CapsVerificationCommit::ResourceLimited => {
            state
                .metrics
                .caps_effect_failures_total
                .fetch_add(1, Ordering::Relaxed);
            tracing::warn!(%resource, "caps semantic memory budget exhausted; verification remains pending");
            hint_caps_effects(state, resource);
        }
        CapsVerificationCommit::Stale => {}
    }
    true
}

pub(crate) fn cached_disco_result(
    state: &AppState,
    id: &str,
    target: &str,
    requested_node: Option<&str>,
) -> Option<String> {
    let target = crate::jid::canonical_session_key(target).ok()?;
    let observation = current_caps_observation(state, &target)?;
    let key = observation.key?;
    if observation.summary.is_none() {
        tracing::debug!(%target, "entity capability cache lookup has no resource mapping");
        return None;
    }
    let expected_node = format!("{}#{}", key.node, key.version);
    if requested_node != Some(expected_node.as_str()) {
        tracing::debug!(
            %target,
            requested_node = ?requested_node,
            %expected_node,
            "entity capability cache lookup used a mismatched node"
        );
        return None;
    }
    let Some(query) = state.caps_cache().raw_query(&key, Instant::now()) else {
        tracing::debug!(%target, node = %key.node, version = %key.version, "entity capability cache lookup missed verified content");
        return None;
    };
    Some(iq_result_from(id, &target, &query))
}

pub(crate) fn pep_notify_nodes(state: &AppState, target: &str) -> Vec<String> {
    let Ok(target) = crate::jid::canonical_session_key(target) else {
        return Vec::new();
    };
    current_caps_observation(state, &target)
        .and_then(|observation| observation.summary)
        .map_or_else(Vec::new, |summary| {
            summary.notify_nodes().map(str::to_owned).collect()
        })
}

/// MIX/PEP consumers share the strict top-level feature parser used at caps
/// verification time. Text, identities and nested data-form elements cannot
/// impersonate a disco feature. Successful use refreshes both LRU layers.
pub(crate) fn verified_caps_has_any_feature(
    state: &AppState,
    target: &str,
    features: &[&str],
) -> Option<bool> {
    let Ok(target) = crate::jid::canonical_session_key(target) else {
        return None;
    };
    current_caps_observation(state, &target)
        .and_then(|observation| observation.summary)
        .map(|summary| features.iter().any(|feature| summary.has_feature(feature)))
}

fn scoped_algorithm(algorithm: &str, full_jid: &str) -> String {
    if algorithm == "sha-1" {
        algorithm.to_owned()
    } else {
        // The separator cannot occur in a prepared JID or accepted algorithm,
        // and the prefix prevents collision with a registered hash name.
        format!("jid-scoped\u{1f}{full_jid}\u{1f}{algorithm}")
    }
}

pub(crate) fn wants_pep_node(state: &AppState, target: &str, node: &str) -> bool {
    let Ok(target) = crate::jid::canonical_session_key(target) else {
        return false;
    };
    current_caps_observation(state, &target)
        .and_then(|observation| observation.summary)
        .is_some_and(|summary| summary.wants_node(node))
}

pub(crate) fn interested_resources_for_bare(
    state: &AppState,
    bare: &str,
    node: &str,
) -> Vec<String> {
    state
        .caps_by_jid()
        .interested_resources_for_bare(bare, node)
}

fn verified_caps_summary(query: Node<'_, '_>, raw_query: &str) -> Result<VerifiedCapsSummary, ()> {
    if raw_query.len() > MAX_DISCO_PAYLOAD_BYTES
        || query.tag_name().name() != "query"
        || query.tag_name().namespace() != Some(DISCO_INFO_NS)
    {
        return Err(());
    }
    let mut features = HashSet::new();
    let mut mix_core = false;
    let mut mix_pam = false;
    let mut notify_storage = String::new();
    let mut notify_ranges = Vec::new();
    for (index, child) in query.children().filter(Node::is_element).enumerate() {
        if index >= MAX_DISCO_CHILDREN {
            return Err(());
        }
        if child.tag_name().name() != "feature"
            || child.tag_name().namespace() != Some(DISCO_INFO_NS)
        {
            continue;
        }
        let feature = child.attribute("var").ok_or(())?.to_owned();
        if !features.insert(feature.clone()) {
            return Err(());
        }
        mix_core |= feature == "urn:xmpp:mix:core:1";
        mix_pam |= feature == "urn:xmpp:mix:pam:2";
        if let Some(node) = feature.strip_suffix("+notify") {
            if !node.is_empty() {
                // No secondary item limit is applied here. The complete list
                // is already bounded by the 64-KiB payload and 512 top-level
                // child parser limits enforced above.
                let start = u32::try_from(notify_storage.len()).map_err(|_| ())?;
                notify_storage.push_str(node);
                let end = u32::try_from(notify_storage.len()).map_err(|_| ())?;
                notify_ranges.push((start, end));
            }
        }
    }
    Ok(VerifiedCapsSummary {
        mix_core,
        mix_pam,
        notify_storage,
        notify_ranges,
    })
}

fn verification_string(query: Node<'_, '_>) -> Result<String, ()> {
    let mut identities = Vec::new();
    let mut features = Vec::new();
    let mut forms = Vec::new();
    for (index, child) in query.children().filter(Node::is_element).enumerate() {
        if index >= MAX_DISCO_CHILDREN {
            return Err(());
        }
        match (child.tag_name().name(), child.tag_name().namespace()) {
            ("identity", Some(DISCO_INFO_NS)) => {
                let category = child.attribute("category").ok_or(())?;
                let kind = child.attribute("type").ok_or(())?;
                identities.push(format!(
                    "{category}/{kind}/{}/{}",
                    child
                        .attribute(("http://www.w3.org/XML/1998/namespace", "lang"))
                        .unwrap_or_default(),
                    child.attribute("name").unwrap_or_default()
                ));
            }
            ("feature", Some(DISCO_INFO_NS)) => {
                features.push(child.attribute("var").ok_or(())?.to_owned());
            }
            ("x", Some("jabber:x:data")) if child.attribute("type") == Some("result") => {
                if let Some(form) = canonical_form(child)? {
                    forms.push(form);
                }
            }
            _ => {}
        }
    }
    if has_duplicates(&identities)
        || has_duplicates(&features)
        || has_duplicates_by(&forms, |form| form.0.as_str())
    {
        return Err(());
    }
    identities.sort_unstable();
    features.sort_unstable();
    forms.sort_unstable();
    let mut output = String::new();
    for identity in identities {
        output.push_str(&identity);
        output.push('<');
    }
    for feature in features {
        output.push_str(&feature);
        output.push('<');
    }
    for (_, form) in forms {
        output.push_str(&form);
    }
    if output.len() > MAX_DISCO_PAYLOAD_BYTES {
        return Err(());
    }
    Ok(output)
}

fn canonical_form(form: Node<'_, '_>) -> Result<Option<(String, String)>, ()> {
    let form_type_fields = form
        .children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().name() == "field"
                && node.tag_name().namespace() == Some("jabber:x:data")
                && node.attribute("var") == Some("FORM_TYPE")
        })
        .collect::<Vec<_>>();
    if form_type_fields.len() > 1 {
        return Err(());
    }
    let Some(form_type_field) = form_type_fields.first().copied() else {
        return Ok(None);
    };
    if form_type_field.attribute("type") != Some("hidden") {
        return Ok(None);
    }
    let form_type_values = form_type_field
        .children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().name() == "value"
                && node.tag_name().namespace() == Some("jabber:x:data")
        })
        .map(|node| node.text().unwrap_or_default().to_owned())
        .take(MAX_DISCO_CHILDREN + 1)
        .collect::<Vec<_>>();
    if form_type_values.is_empty() || form_type_values.len() > MAX_DISCO_CHILDREN {
        return Ok(None);
    }
    if form_type_values
        .iter()
        .any(|value| value != &form_type_values[0])
    {
        return Err(());
    }

    let mut form_type = None;
    let mut fields = Vec::new();
    let mut seen = HashSet::new();
    for (index, field) in form
        .children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().name() == "field"
                && node.tag_name().namespace() == Some("jabber:x:data")
        })
        .enumerate()
    {
        if index >= MAX_DISCO_CHILDREN {
            return Err(());
        }
        let variable = field.attribute("var").ok_or(())?;
        if !seen.insert(variable.to_owned()) {
            return Err(());
        }
        let mut values = field
            .children()
            .filter(|node| {
                node.is_element()
                    && node.tag_name().name() == "value"
                    && node.tag_name().namespace() == Some("jabber:x:data")
            })
            .map(|node| node.text().unwrap_or_default().to_owned())
            .take(MAX_DISCO_CHILDREN + 1)
            .collect::<Vec<_>>();
        if values.len() > MAX_DISCO_CHILDREN {
            return Err(());
        }
        values.sort_unstable();
        if variable == "FORM_TYPE" {
            form_type = values.pop();
        } else {
            fields.push((variable.to_owned(), values));
        }
    }
    let form_type = form_type.ok_or(())?;
    fields.sort_by(|left, right| left.0.cmp(&right.0));
    let mut output = format!("{form_type}<");
    for (variable, values) in fields {
        output.push_str(&variable);
        output.push('<');
        for value in values {
            output.push_str(&value);
            output.push('<');
        }
    }
    Ok(Some((form_type, output)))
}

fn has_duplicates(values: &[String]) -> bool {
    let mut seen = HashSet::new();
    values.iter().any(|value| !seen.insert(value))
}

fn has_duplicates_by<'a, T>(values: &'a [T], key: impl Fn(&'a T) -> &'a str) -> bool {
    let mut seen = HashSet::new();
    values.iter().any(|value| !seen.insert(key(value)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use roxmltree::Document;

    fn key(seed: u16) -> CapsKey {
        CapsKey {
            algorithm: "sha-1".to_owned(),
            node: format!("node-{seed}"),
            version: format!("version-{seed}"),
        }
    }

    fn summary(feature: &str) -> Arc<VerifiedCapsSummary> {
        Arc::new(VerifiedCapsSummary {
            mix_core: feature == "urn:xmpp:mix:core:1",
            mix_pam: feature == "urn:xmpp:mix:pam:2",
            notify_storage: feature.to_owned(),
            notify_ranges: vec![(0, u32::try_from(feature.len()).unwrap())],
        })
    }

    fn federated_owner(
        connection_id: uuid::Uuid,
        observation_id: uuid::Uuid,
    ) -> CapsObservationOwner {
        CapsObservationOwner::Federated {
            connection_id,
            observation_id,
        }
    }

    #[tokio::test]
    async fn federated_gate_serializes_and_self_cleans_after_waiters_leave() {
        let index = Arc::new(FederatedCapsGateIndex::new());
        let resource = "alice@remote.test/Phone";
        let first = index.lock(resource).await;
        let waiter_index = Arc::clone(&index);
        let waiter = tokio::spawn(async move {
            let _guard = waiter_index.lock(resource).await;
        });
        for _ in 0..100 {
            if index.participants(resource) == 2 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(index.participants(resource), 2);
        drop(first);
        waiter.await.unwrap();
        assert_eq!(index.len(), 0);
    }

    #[test]
    fn verified_summary_keeps_every_notify_feature_within_parser_bounds() {
        let features = (0..200)
            .map(|index| format!("<feature var='urn:test:{index}+notify'/>"))
            .collect::<String>();
        let xml = format!("<query xmlns='{DISCO_INFO_NS}'>{features}</query>");
        assert!(xml.len() < MAX_DISCO_PAYLOAD_BYTES);
        let document = Document::parse(&xml).unwrap();
        let query = document.root_element();
        verification_string(query).expect("bounded payload verifies");
        let summary = verified_caps_summary(query, &xml).expect("bounded summary parses");
        assert_eq!(summary.notify_ranges.len(), 200);
        assert!(summary.wants_node("urn:test:199"));
    }

    #[test]
    fn raw_cache_eviction_does_not_change_observation_interest() {
        let now = Instant::now();
        let cache = CapsCacheIndex::with_limits(1, Duration::from_secs(60));
        let observations = CapsResourceIndex::with_limits(4, 4);
        let first_key = key(1);
        let first_summary = summary("urn:test:first");
        cache.insert(
            first_key.clone(),
            "<query first='true'/>".to_owned(),
            Arc::clone(&first_summary),
            now,
        );
        assert_eq!(cache.len(), 1);
        observations.observe_local(
            "alice@example.test/Phone".to_owned(),
            LocalCapsEpoch {
                connection_id: uuid::Uuid::nil(),
                generation: 1,
            },
            Some(first_key.clone()),
            Some(first_summary),
            now,
        );
        cache.insert(
            key(2),
            "<query second='true'/>".to_owned(),
            summary("urn:test:second"),
            now + Duration::from_millis(1),
        );
        assert!(cache
            .raw_query(&first_key, now + Duration::from_millis(2))
            .is_none());
        assert!(observations
            .summary("alice@example.test/Phone")
            .is_some_and(|summary| summary.wants_node("urn:test:first")));
        observations.observe_local(
            "alice@example.test/Phone".to_owned(),
            LocalCapsEpoch {
                connection_id: uuid::Uuid::nil(),
                generation: 2,
            },
            Some(first_key),
            None,
            now + Duration::from_millis(3),
        );
        assert!(observations
            .summary("alice@example.test/Phone")
            .is_some_and(|summary| summary.wants_node("urn:test:first")));
    }

    #[test]
    fn raw_cache_has_an_exact_byte_budget_and_evicts_only_responder_xml() {
        let now = Instant::now();
        let cache = CapsCacheIndex::with_budgets(4, 24, 64 * 1024, Duration::from_secs(60));
        let first_key = key(10);
        let second_key = key(11);
        cache.insert(
            first_key.clone(),
            "1234567890123456".to_owned(),
            summary("urn:test:first"),
            now,
        );
        cache.insert(
            second_key.clone(),
            "abcdefghijklmnop".to_owned(),
            summary("urn:test:second"),
            now + Duration::from_millis(1),
        );
        let (raw_bytes, semantic_bytes) = cache.charged_bytes();
        assert!(raw_bytes <= 24);
        assert!(semantic_bytes <= 64 * 1024);
        assert!(cache
            .raw_query(&first_key, now + Duration::from_millis(2))
            .is_none());
        assert!(cache
            .query(&first_key, now + Duration::from_millis(2))
            .is_some());
        assert!(cache
            .raw_query(&second_key, now + Duration::from_millis(2))
            .is_some());
    }

    #[test]
    fn summary_budget_preserves_pending_verification_and_releases_exactly() {
        let now = Instant::now();
        let verified = summary("urn:test:large+notify");
        let charge = verified.resident_charge();
        let index = CapsResourceIndex::with_budgets(4, 4, charge);
        let first = "alice@example.test/One";
        let second = "alice@example.test/Two";
        index.observe_local(
            first.to_owned(),
            LocalCapsEpoch {
                connection_id: uuid::Uuid::new_v4(),
                generation: 1,
            },
            Some(key(20)),
            Some(Arc::clone(&verified)),
            now,
        );
        index.observe_local(
            second.to_owned(),
            LocalCapsEpoch {
                connection_id: uuid::Uuid::new_v4(),
                generation: 1,
            },
            Some(key(21)),
            Some(Arc::clone(&verified)),
            now,
        );
        assert_eq!(index.summary_bytes(), charge);
        assert!(index.summary(first).is_some());
        assert!(index.summary(second).is_none());
        assert!(index
            .ready_observations(now)
            .iter()
            .any(|(resource, _)| resource == second));

        let first_connection = match index.owner(first).unwrap() {
            CapsObservationOwner::Local(epoch) => epoch.connection_id,
            CapsObservationOwner::Federated { .. } => unreachable!(),
        };
        index.remove_local_resource(first, first_connection);
        assert_eq!(index.summary_bytes(), 0);
        index.observe_local(
            second.to_owned(),
            LocalCapsEpoch {
                connection_id: uuid::Uuid::new_v4(),
                generation: 2,
            },
            Some(key(21)),
            Some(verified),
            now,
        );
        assert!(index.summary(second).is_some());
        assert_eq!(index.summary_bytes(), charge);
    }

    #[test]
    fn local_replacement_never_exposes_an_absent_observation() {
        let index = Arc::new(CapsResourceIndex::with_limits(4, 4));
        let resource = "alice@example.test/Phone";
        let connection_id = uuid::Uuid::new_v4();
        index.observe_local(
            resource.to_owned(),
            LocalCapsEpoch {
                connection_id,
                generation: 1,
            },
            None,
            None,
            Instant::now(),
        );
        let start = Arc::new(std::sync::Barrier::new(2));
        let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let reader_index = Arc::clone(&index);
        let reader_start = Arc::clone(&start);
        let reader_done = Arc::clone(&done);
        let reader = std::thread::spawn(move || {
            reader_start.wait();
            loop {
                assert!(reader_index.snapshot(resource).is_some());
                if reader_done.load(Ordering::Acquire) {
                    break;
                }
            }
        });
        start.wait();
        for generation in 2..=2_000 {
            index.observe_local(
                resource.to_owned(),
                LocalCapsEpoch {
                    connection_id,
                    generation,
                },
                None,
                None,
                Instant::now(),
            );
        }
        done.store(true, Ordering::Release);
        reader.join().unwrap();
        assert!(index.snapshot(resource).is_some());
    }

    #[test]
    fn same_connection_federated_readvertisement_is_aba_fenced() {
        let index = CapsResourceIndex::with_limits(4, 4);
        let connection_id = uuid::Uuid::new_v4();
        let resource = "alice@remote.test/Phone";
        let first = index
            .observe_federated(
                resource.to_owned(),
                connection_id,
                "remote.test".to_owned(),
                None,
                None,
                Instant::now(),
            )
            .unwrap();
        let old_job = index.claim_effects(resource, Instant::now()).unwrap();
        let second = index
            .observe_federated(
                resource.to_owned(),
                connection_id,
                "remote.test".to_owned(),
                None,
                None,
                Instant::now(),
            )
            .unwrap();
        assert_ne!(first, second);
        assert!(!index.complete_effects(&old_job, CapsEffects::default(), Instant::now()));
        assert_eq!(index.owner(resource), Some(second));
        assert_eq!(
            index.claim_effects(resource, Instant::now()).unwrap().owner,
            second
        );
    }

    #[test]
    fn failed_effect_bits_are_rearmed_until_success() {
        let index = CapsResourceIndex::with_limits(4, 4);
        let resource = "alice@remote.test/Phone";
        index
            .observe_federated(
                resource.to_owned(),
                uuid::Uuid::new_v4(),
                "remote.test".to_owned(),
                None,
                None,
                Instant::now(),
            )
            .unwrap();
        let job = index.claim_effects(resource, Instant::now()).unwrap();
        index.complete_effects(&job, job.effects, Instant::now());
        let retry = index
            .claim_effects(resource, Instant::now() + CAPS_EFFECT_RETRY_MAX)
            .expect("failed work remains authoritative");
        assert_eq!(retry.owner, job.owner);
        assert_eq!(retry.effects, job.effects);
    }

    #[test]
    fn saturated_ready_queue_is_reconstructible_from_observations() {
        let metrics = crate::metrics::Metrics::default();
        let dispatcher = CapsEffectDispatcher::with_limits(1, 1);
        let index = CapsResourceIndex::with_limits(4, 4);
        for (resource, seed) in [("a@remote.test/One", 1_u16), ("b@remote.test/Two", 2_u16)] {
            index
                .observe_federated(
                    resource.to_owned(),
                    uuid::Uuid::new_v4(),
                    "remote.test".to_owned(),
                    Some(key(seed)),
                    None,
                    Instant::now(),
                )
                .unwrap();
        }
        let local_resource = "local@example.test/Phone";
        index.observe_local(
            local_resource.to_owned(),
            LocalCapsEpoch {
                connection_id: uuid::Uuid::new_v4(),
                generation: 1,
            },
            None,
            None,
            Instant::now(),
        );
        assert_eq!(
            dispatcher.hint("a@remote.test/One".to_owned(), false, &metrics),
            CapsEffectAdmission::Queued
        );
        assert_eq!(
            dispatcher.hint("b@remote.test/Two".to_owned(), false, &metrics),
            CapsEffectAdmission::Saturated
        );
        assert!(
            dispatcher.begin_rescan(),
            "saturation requests reconstruction"
        );
        assert_eq!(
            dispatcher.hint(local_resource.to_owned(), true, &metrics),
            CapsEffectAdmission::Queued,
            "federated saturation has an independent local hint budget"
        );
        assert_eq!(dispatcher.take_hint().as_deref(), Some(local_resource));
        assert!(index
            .claim_effects(local_resource, Instant::now())
            .is_some_and(|job| job.owner.is_local()));
        assert_eq!(dispatcher.take_hint().as_deref(), Some("a@remote.test/One"));
        let ready = index.ready_observations(Instant::now());
        assert!(ready.iter().any(|(jid, _)| jid == "b@remote.test/Two"));
        assert_eq!(
            dispatcher.hint("b@remote.test/Two".to_owned(), false, &metrics),
            CapsEffectAdmission::Queued
        );
    }

    #[test]
    fn federated_admission_counters_are_exact_across_replace_and_teardown() {
        let index = CapsResourceIndex::with_limits(2, 1);
        let first_connection = uuid::Uuid::new_v4();
        let second_connection = uuid::Uuid::new_v4();
        let resource = "alice@remote.test/Phone";
        index
            .observe_federated(
                resource.to_owned(),
                first_connection,
                "remote.test".to_owned(),
                None,
                None,
                Instant::now(),
            )
            .unwrap();
        assert_eq!(index.federated_counts("remote.test"), (1, 1));
        index
            .observe_federated(
                resource.to_owned(),
                second_connection,
                "remote.test".to_owned(),
                None,
                None,
                Instant::now(),
            )
            .unwrap();
        assert_eq!(index.federated_counts("remote.test"), (1, 1));
        assert!(!index.remove_federated_resource_if_connection(resource, first_connection));
        assert_eq!(index.federated_counts("remote.test"), (1, 1));
        assert!(index.remove_federated_resource_if_connection(resource, second_connection));
        assert_eq!(index.federated_counts("remote.test"), (0, 0));
        assert_eq!(index.len(), 0);
    }

    #[test]
    fn distinct_federated_observation_ids_are_part_of_pending_authority() {
        let connection_id = uuid::Uuid::new_v4();
        let first = federated_owner(connection_id, uuid::Uuid::new_v4());
        let second = federated_owner(connection_id, uuid::Uuid::new_v4());
        assert_ne!(first, second);
        assert_eq!(first.federated_connection(), second.federated_connection());

        let pending = PendingCapsIndex::new();
        assert!(pending.insert(
            "one".to_owned(),
            "alice@remote.test/Phone".to_owned(),
            key(1),
            first,
            Instant::now() + Duration::from_secs(1),
        ));
        assert!(pending.insert(
            "two".to_owned(),
            "alice@remote.test/Phone".to_owned(),
            key(2),
            second,
            Instant::now() + Duration::from_secs(1),
        ));
        assert_eq!(pending.len(), 2);
        assert_eq!(pending.take("one").unwrap().owner, first);
        assert_eq!(pending.take("two").unwrap().owner, second);
    }

    #[test]
    fn pending_caps_single_flights_one_query_per_semantic_key() {
        let pending = PendingCapsIndex::new();
        let shared_key = key(30);
        let first = federated_owner(uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
        let second = federated_owner(uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
        assert!(pending.insert(
            "leader".to_owned(),
            "one@remote.test/Phone".to_owned(),
            shared_key.clone(),
            first,
            Instant::now() + Duration::from_secs(30),
        ));
        assert!(!pending.insert(
            "follower".to_owned(),
            "two@remote.test/Phone".to_owned(),
            shared_key,
            second,
            Instant::now() + Duration::from_secs(30),
        ));
        assert_eq!(pending.len(), 1);
    }
}
