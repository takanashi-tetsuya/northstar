use super::ProtocolSession;
use crate::state::{AppState, CachedCaps, CapsKey, CapsResource, PendingCaps};
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
const MAX_PENDING_CAPS: usize = 1_024;
const MAX_DISCO_PAYLOAD_BYTES: usize = 64 * 1024;
const MAX_DISCO_CHILDREN: usize = 512;
const MAX_CAPS_EFFECT_JIDS: usize = 2_048;
const MAX_CAPS_EFFECT_CONCURRENCY: usize = 16;
const CAPS_EFFECT_DRAIN_GRACE: Duration = Duration::from_secs(5);
/// Federated resources never observe a local transport teardown, so the
/// resource-to-advertisement map polices its own size with a hard entry bound
/// plus LRU/TTL eviction instead of growing with remote presence churn.
const MAX_CAPS_RESOURCES: usize = 8_192;
const CAPS_RESOURCE_TTL: Duration = Duration::from_secs(60 * 60);

/// Process-global resource-to-capability index.  DashMap supplies cheap
/// concurrent reads, while the admission mutex makes the compound
/// TTL/LRU/capacity decision linearizable. The narrow iterator keeps existing
/// PEP audience scans allocation-free without exposing mutation primitives.
pub(crate) struct CapsResourceIndex {
    entries: DashMap<String, CapsResource>,
    admission: Mutex<()>,
    max_entries: usize,
    ttl: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PendingCapsAdmission {
    Admitted,
    Duplicate,
    Full,
}

/// Linearizable correlation admission shared by C2S and S2S. The map itself
/// remains concurrent for cheap response lookup, while every compound
/// expire/deduplicate/cap/insert operation passes through one narrow mutex.
pub(crate) struct PendingCapsIndex {
    entries: DashMap<String, PendingCaps>,
    admission: Mutex<()>,
    max_entries: usize,
}

impl PendingCapsIndex {
    pub(crate) fn new() -> Self {
        Self::with_limit(MAX_PENDING_CAPS)
    }

    fn with_limit(max_entries: usize) -> Self {
        assert!(max_entries > 0, "pending caps capacity must be positive");
        Self {
            entries: DashMap::new(),
            admission: Mutex::new(()),
            max_entries,
        }
    }

    fn admit(
        &self,
        id: String,
        full_jid: String,
        key: CapsKey,
        now: Instant,
    ) -> PendingCapsAdmission {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.entries.retain(|_, pending| pending.expires_at > now);
        if self.entries.iter().any(|pending| {
            pending.full_jid == full_jid && pending.key == key && pending.expires_at > now
        }) {
            return PendingCapsAdmission::Duplicate;
        }
        self.entries
            .retain(|_, pending| pending.full_jid != full_jid);
        if self.entries.len() >= self.max_entries {
            return PendingCapsAdmission::Full;
        }
        self.entries.insert(
            id,
            PendingCaps {
                full_jid,
                key,
                expires_at: now + PENDING_TTL,
            },
        );
        debug_assert!(self.entries.len() <= self.max_entries);
        PendingCapsAdmission::Admitted
    }

    fn take(&self, id: &str) -> Option<PendingCaps> {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.entries.remove(id).map(|(_, pending)| pending)
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

    pub(crate) fn sweep(&self, now: Instant) {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.entries.retain(|_, pending| pending.expires_at > now);
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }
}

/// Verified XEP-0115 payloads have one process-global TTL/LRU budget. Reads
/// touch recency, and insertion evicts only unpinned keys. This makes C2S and
/// S2S verification share a genuine hard cap rather than two racy len checks.
pub(crate) struct CapsCacheIndex {
    entries: DashMap<CapsKey, CachedCaps>,
    admission: Mutex<()>,
    max_entries: usize,
    ttl: Duration,
}

impl CapsCacheIndex {
    pub(crate) fn new() -> Self {
        Self::with_limits(MAX_CAPS_CACHE_ENTRIES, CACHE_TTL)
    }

    fn with_limits(max_entries: usize, ttl: Duration) -> Self {
        assert!(max_entries > 0, "caps cache capacity must be positive");
        Self {
            entries: DashMap::new(),
            admission: Mutex::new(()),
            max_entries,
            ttl,
        }
    }

    fn query(&self, key: &CapsKey, now: Instant) -> Option<String> {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut cached = self.entries.get_mut(key)?;
        if cached.expires_at <= now {
            drop(cached);
            self.entries.remove(key);
            return None;
        }
        cached.touched_at = now;
        Some(cached.query.clone())
    }

    fn contains_fresh(&self, key: &CapsKey, now: Instant) -> bool {
        self.query(key, now).is_some()
    }

    fn insert(
        &self,
        key: CapsKey,
        query: String,
        now: Instant,
        pinned: impl Fn(&CapsKey) -> bool,
    ) -> bool {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.entries.retain(|_, cached| cached.expires_at > now);
        if !self.entries.contains_key(&key) && self.entries.len() >= self.max_entries {
            let mut candidates = self
                .entries
                .iter()
                .filter(|entry| !pinned(entry.key()))
                .map(|entry| (entry.touched_at, entry.key().clone()))
                .collect::<Vec<_>>();
            candidates.sort_unstable_by_key(|(touched_at, _)| *touched_at);
            let needed = self
                .entries
                .len()
                .saturating_add(1)
                .saturating_sub(self.max_entries);
            for (_, candidate) in candidates.into_iter().take(needed.max(1)) {
                self.entries.remove(&candidate);
            }
        }
        if !self.entries.contains_key(&key) && self.entries.len() >= self.max_entries {
            return false;
        }
        self.entries.insert(
            key,
            CachedCaps {
                query,
                expires_at: now + self.ttl,
                touched_at: now,
            },
        );
        debug_assert!(self.entries.len() <= self.max_entries);
        true
    }

    pub(crate) fn sweep(&self, now: Instant) {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.entries.retain(|_, cached| cached.expires_at > now);
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }

    #[cfg(test)]
    fn contains_key(&self, key: &CapsKey) -> bool {
        self.entries.contains_key(key)
    }
}

impl CapsResourceIndex {
    pub(crate) fn new() -> Self {
        Self::with_limits(MAX_CAPS_RESOURCES, CAPS_RESOURCE_TTL)
    }

    fn with_limits(max_entries: usize, ttl: Duration) -> Self {
        assert!(max_entries > 0, "caps resource capacity must be positive");
        Self {
            entries: DashMap::new(),
            admission: Mutex::new(()),
            max_entries,
            ttl,
        }
    }

    fn admit(
        &self,
        full_jid: String,
        key: CapsKey,
        now: Instant,
        pinned: impl Fn(&str) -> bool,
    ) -> bool {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.entries.retain(|jid, resource| {
            pinned(jid)
                || now
                    .checked_duration_since(resource.touched_at)
                    .is_none_or(|age| age < self.ttl)
        });

        if self.entries.contains_key(&full_jid) {
            self.entries.insert(
                full_jid,
                CapsResource {
                    key,
                    touched_at: now,
                },
            );
            return true;
        }

        if self.entries.len() >= self.max_entries {
            let keep =
                (self.max_entries - self.max_entries / 8).min(self.max_entries.saturating_sub(1));
            let mut candidates = self
                .entries
                .iter()
                .filter(|entry| !pinned(entry.key()))
                .map(|entry| (entry.value().touched_at, entry.key().clone()))
                .collect::<Vec<_>>();
            candidates.sort_unstable_by_key(|(touched_at, _)| *touched_at);
            let removable = self.entries.len().saturating_sub(keep);
            for (_, jid) in candidates.into_iter().take(removable) {
                self.entries.remove(&jid);
            }
        }
        if self.entries.len() >= self.max_entries {
            return false;
        }
        self.entries.insert(
            full_jid,
            CapsResource {
                key,
                touched_at: now,
            },
        );
        debug_assert!(self.entries.len() <= self.max_entries);
        true
    }

    fn touch(&self, target: &str, now: Instant, pinned: impl Fn(&str) -> bool) -> Option<CapsKey> {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut resource = self.entries.get_mut(target)?;
        let expired = now
            .checked_duration_since(resource.touched_at)
            .is_some_and(|age| age >= self.ttl);
        if expired && !pinned(target) {
            drop(resource);
            self.entries.remove(target);
            return None;
        }
        resource.touched_at = now;
        Some(resource.key.clone())
    }

    fn sweep(&self, now: Instant, pinned: impl Fn(&str) -> bool) {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.entries.retain(|jid, resource| {
            pinned(jid)
                || now
                    .checked_duration_since(resource.touched_at)
                    .is_none_or(|age| age < self.ttl)
        });
    }

    pub(crate) fn remove_resource(&self, full_jid: &str) {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.entries.remove(full_jid);
    }

    pub(crate) fn iter(&self) -> dashmap::iter::Iter<'_, String, CapsResource> {
        self.entries.iter()
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }

    #[cfg(test)]
    fn contains_key(&self, full_jid: &str) -> bool {
        self.entries.contains_key(full_jid)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct CapsEffects(u8);

impl CapsEffects {
    const EXPLICIT_PEP_LAST_ITEMS: Self = Self(1 << 0);
    const AUTOMATIC_PEP_LAST_ITEMS: Self = Self(1 << 1);
    const VERIFIED_MIX_PRESENCE: Self = Self(1 << 2);

    fn contains(self, effect: Self) -> bool {
        self.0 & effect.0 != 0
    }

    fn is_empty(self) -> bool {
        self.0 == 0
    }

    fn merge(&mut self, effects: Self) {
        self.0 |= effects.0;
    }
}

impl std::ops::BitOr for CapsEffects {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

#[derive(Debug)]
struct CapsEffectEntry {
    pending: CapsEffects,
    running: CapsEffects,
    pending_since: Option<Instant>,
    running_since: Option<Instant>,
    queued: bool,
}

#[derive(Debug)]
struct CapsEffectJob {
    full_jid: String,
    effects: CapsEffects,
    queued_at: Instant,
}

#[derive(Debug)]
struct CapsEffectQueue {
    accepting: bool,
    entries: HashMap<String, CapsEffectEntry>,
    ready: VecDeque<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CapsEffectAdmission {
    Queued,
    Coalesced,
    Saturated,
    Closed,
}

/// Process-global XEP-0115 follow-up boundary. Capacity is charged per unique
/// full JID rather than per presence stanza, so one authenticated resource can
/// refresh its latest requested effects without creating tasks or database
/// waiters. A running JID remains in the map and can have at most one merged
/// follow-up, which makes the single-flight property explicit.
pub(crate) struct CapsEffectDispatcher {
    queue: Mutex<CapsEffectQueue>,
    wake: Notify,
    execution_slots: Arc<Semaphore>,
    capacity: usize,
}

impl CapsEffectDispatcher {
    pub(crate) fn new() -> Arc<Self> {
        Self::with_limits(MAX_CAPS_EFFECT_JIDS, MAX_CAPS_EFFECT_CONCURRENCY)
    }

    fn with_limits(capacity: usize, concurrency: usize) -> Arc<Self> {
        assert!(capacity > 0, "caps effect capacity must be positive");
        assert!(concurrency > 0, "caps effect concurrency must be positive");
        Arc::new(Self {
            queue: Mutex::new(CapsEffectQueue {
                accepting: true,
                entries: HashMap::new(),
                ready: VecDeque::new(),
            }),
            wake: Notify::new(),
            execution_slots: Arc::new(Semaphore::new(concurrency)),
            capacity,
        })
    }

    fn enqueue(
        &self,
        full_jid: String,
        effects: CapsEffects,
        metrics: &crate::metrics::Metrics,
    ) -> CapsEffectAdmission {
        self.enqueue_inner(full_jid, effects, false, metrics)
    }

    fn enqueue_latest(
        &self,
        full_jid: String,
        effects: CapsEffects,
        metrics: &crate::metrics::Metrics,
    ) -> CapsEffectAdmission {
        self.enqueue_inner(full_jid, effects, true, metrics)
    }

    fn enqueue_inner(
        &self,
        full_jid: String,
        effects: CapsEffects,
        replace_pending: bool,
        metrics: &crate::metrics::Metrics,
    ) -> CapsEffectAdmission {
        if effects.is_empty() {
            return CapsEffectAdmission::Coalesced;
        }
        let now = Instant::now();
        let mut queue = self
            .queue
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !queue.accepting {
            return CapsEffectAdmission::Closed;
        }
        if let Some(entry) = queue.entries.get_mut(&full_jid) {
            if replace_pending {
                entry.pending = effects;
                entry.pending_since = Some(now);
            } else {
                entry.pending.merge(effects);
                entry.pending_since.get_or_insert(now);
            }
            let should_queue = !entry.queued && entry.running.is_empty();
            if should_queue {
                entry.queued = true;
                queue.ready.push_back(full_jid);
                self.wake.notify_one();
            }
            metrics
                .caps_effect_coalesced_total
                .fetch_add(1, Ordering::Relaxed);
            return CapsEffectAdmission::Coalesced;
        }
        if queue.entries.len() >= self.capacity {
            metrics
                .caps_effect_queue_saturated_total
                .fetch_add(1, Ordering::Relaxed);
            return CapsEffectAdmission::Saturated;
        }
        queue.entries.insert(
            full_jid.clone(),
            CapsEffectEntry {
                pending: effects,
                running: CapsEffects::default(),
                pending_since: Some(now),
                running_since: None,
                queued: true,
            },
        );
        queue.ready.push_back(full_jid);
        drop(queue);
        self.wake.notify_one();
        CapsEffectAdmission::Queued
    }

    fn take_ready(&self) -> Option<CapsEffectJob> {
        let mut queue = self
            .queue
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        while let Some(full_jid) = queue.ready.pop_front() {
            let Some(entry) = queue.entries.get_mut(&full_jid) else {
                continue;
            };
            if !entry.queued || !entry.running.is_empty() || entry.pending.is_empty() {
                continue;
            }
            entry.queued = false;
            let effects = std::mem::take(&mut entry.pending);
            entry.running = effects;
            entry.running_since = entry.pending_since.take();
            return Some(CapsEffectJob {
                full_jid,
                effects: entry.running,
                queued_at: entry.running_since.unwrap_or_else(Instant::now),
            });
        }
        None
    }

    fn complete(&self, full_jid: &str) {
        let mut queue = self
            .queue
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut requeue = false;
        let mut remove = false;
        if let Some(entry) = queue.entries.get_mut(full_jid) {
            entry.running = CapsEffects::default();
            entry.running_since = None;
            if entry.pending.is_empty() {
                remove = true;
            } else if !entry.queued {
                entry.queued = true;
                requeue = true;
            }
        }
        if remove {
            queue.entries.remove(full_jid);
        } else if requeue {
            queue.ready.push_back(full_jid.to_owned());
        }
        drop(queue);
        self.wake.notify_one();
    }

    pub(crate) fn cancel(&self, full_jid: &str) {
        let mut queue = self
            .queue
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let remove = if let Some(entry) = queue.entries.get_mut(full_jid) {
            entry.pending = CapsEffects::default();
            entry.pending_since = None;
            entry.queued = false;
            entry.running.is_empty()
        } else {
            false
        };
        queue.ready.retain(|queued| queued != full_jid);
        if remove {
            queue.entries.remove(full_jid);
        }
    }

    fn close(&self) {
        self.queue
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .accepting = false;
        self.wake.notify_waiters();
    }

    fn is_drained(&self) -> bool {
        self.queue
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entries
            .is_empty()
    }

    fn recover_interrupted(&self) {
        let mut queue = self
            .queue
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut requeue = Vec::new();
        for (full_jid, entry) in &mut queue.entries {
            if !entry.running.is_empty() {
                let interrupted = entry.running;
                entry.pending.merge(interrupted);
                entry.pending_since = match (entry.pending_since, entry.running_since) {
                    (Some(pending), Some(running)) => Some(pending.min(running)),
                    (pending, running) => pending.or(running),
                };
                entry.running = CapsEffects::default();
                entry.running_since = None;
            }
            if !entry.pending.is_empty() && !entry.queued {
                entry.queued = true;
                requeue.push(full_jid.clone());
            }
        }
        queue.ready.extend(requeue);
        drop(queue);
        self.wake.notify_waiters();
    }

    #[cfg(test)]
    fn queued_jids(&self) -> usize {
        self.queue
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entries
            .len()
    }

    #[cfg(test)]
    fn ready_entries(&self) -> usize {
        self.queue
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .ready
            .len()
    }
}

struct CapsEffectRunGuard(Arc<CapsEffectDispatcher>);

impl Drop for CapsEffectRunGuard {
    fn drop(&mut self) {
        self.0.recover_interrupted();
    }
}

type CapsEffectFuture = Pin<Box<dyn Future<Output = (CapsEffectJob, usize)> + Send + 'static>>;

fn enqueue_caps_effects(state: &AppState, full_jid: String, effects: CapsEffects) {
    match state
        .caps_effect_dispatcher()
        .enqueue(full_jid, effects, &state.metrics)
    {
        CapsEffectAdmission::Queued | CapsEffectAdmission::Coalesced => {}
        CapsEffectAdmission::Saturated => {
            tracing::debug!("caps side-effect queue saturated; skipped best-effort delivery");
        }
        CapsEffectAdmission::Closed => {
            tracing::debug!("caps side effect ignored during service shutdown");
        }
    }
}

fn enqueue_latest_caps_effects(state: &AppState, full_jid: String, effects: CapsEffects) {
    match state
        .caps_effect_dispatcher()
        .enqueue_latest(full_jid, effects, &state.metrics)
    {
        CapsEffectAdmission::Queued | CapsEffectAdmission::Coalesced => {}
        CapsEffectAdmission::Saturated => {
            tracing::debug!(
                "caps side-effect queue saturated; skipped latest best-effort delivery"
            );
        }
        CapsEffectAdmission::Closed => {
            tracing::debug!("caps side effect ignored during service shutdown");
        }
    }
}

async fn execute_caps_effects(state: Arc<AppState>, job: &CapsEffectJob) -> usize {
    let mut failures = 0;
    if job.effects.contains(CapsEffects::EXPLICIT_PEP_LAST_ITEMS) {
        if let Err(error) =
            super::pep::deliver_explicit_pep_last_items_for_resource(&state, &job.full_jid).await
        {
            failures += 1;
            tracing::warn!(?error, resource = %job.full_jid, "failed to deliver explicit PEP last items");
        }
    }
    if job.effects.contains(CapsEffects::AUTOMATIC_PEP_LAST_ITEMS) {
        if let Err(error) =
            super::pep::deliver_pep_last_items_for_resource(&state, &job.full_jid).await
        {
            failures += 1;
            tracing::warn!(?error, resource = %job.full_jid, "failed to deliver capability-selected PEP last items");
        }
    }
    if job.effects.contains(CapsEffects::VERIFIED_MIX_PRESENCE) {
        if let Err(error) = super::mix::publish_verified_mix_presence(&state, &job.full_jid).await {
            failures += 1;
            tracing::warn!(?error, resource = %job.full_jid, "failed to publish verified MIX presence");
        }
    }
    failures
}

async fn run_caps_effect_dispatcher(
    state: Arc<AppState>,
    cancel: CancellationToken,
    heartbeat: crate::workers::WorkerHeartbeat,
) -> anyhow::Result<()> {
    let dispatcher = Arc::clone(state.caps_effect_dispatcher());
    let _recovery = CapsEffectRunGuard(Arc::clone(&dispatcher));
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
            let Some(job) = dispatcher.take_ready() else {
                drop(permit);
                break;
            };
            let effect_state = Arc::clone(&state);
            running.push(Box::pin(async move {
                let _permit = permit;
                let failures = execute_caps_effects(effect_state, &job).await;
                (job, failures)
            }));
        }

        if draining && running.is_empty() && dispatcher.is_drained() {
            heartbeat.ok();
            return Ok(());
        }

        tokio::select! {
            _ = cancel.cancelled(), if !draining => {
                draining = true;
                dispatcher.close();
            }
            Some((job, failures)) = running.next(), if !running.is_empty() => {
                dispatcher.complete(&job.full_jid);
                state.metrics.caps_effect_latency_seconds.observe(job.queued_at.elapsed());
                if failures == 0 {
                    heartbeat.ok();
                } else {
                    state.metrics.caps_effect_failures_total.fetch_add(
                        failures as u64,
                        Ordering::Relaxed,
                    );
                    heartbeat.error(format!("{failures} caps side effects failed"));
                }
            }
            _ = dispatcher.wake.notified() => {}
            _ = liveness.tick() => {
                sweep_caps_resources(&state);
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
    pub(crate) fn observe_caps(&self, presence: Node<'_, '_>, full_jid: &str) {
        let Ok(full_jid) = crate::jid::canonical_session_key(full_jid) else {
            return;
        };
        if presence
            .attribute("type")
            .is_some_and(|kind| kind != "available")
        {
            self.state.caps_by_jid().remove_resource(&full_jid);
            self.state.caps_effect_dispatcher().cancel(&full_jid);
            return;
        }
        enqueue_latest_caps_effects(
            &self.state,
            full_jid.clone(),
            CapsEffects::EXPLICIT_PEP_LAST_ITEMS,
        );
        let Some(caps) = presence.children().find(|node| {
            node.is_element()
                && node.tag_name().name() == "c"
                && node.tag_name().namespace() == Some(CAPS_NS)
        }) else {
            self.state.caps_by_jid().remove_resource(&full_jid);
            return;
        };
        let (Some(algorithm), Some(node), Some(version)) = (
            caps.attribute("hash"),
            caps.attribute("node"),
            caps.attribute("ver"),
        ) else {
            return;
        };
        // SHA-1 is the mandatory verification algorithm.  XEP-0115 still
        // requires a disco lookup for an unsupported algorithm, but that
        // result may only be associated with this exact JID and must never be
        // placed in the global node/ver cache.  Scoping the internal key by
        // full JID provides that isolation without trusting the advertised
        // hash.
        if node.is_empty()
            || node.len() > 2_048
            || version.is_empty()
            || version.len() > 256
            || algorithm.is_empty()
            || algorithm.len() > 64
            || node.chars().any(|character| character.is_control())
            || version.chars().any(|character| character.is_control())
            || algorithm.chars().any(|character| character.is_control())
        {
            return;
        }
        let key = CapsKey {
            algorithm: scoped_algorithm(algorithm, &full_jid),
            node: node.to_owned(),
            version: version.to_owned(),
        };
        admit_caps_resource(&self.state, full_jid.clone(), key.clone());
        if self.state.caps_cache().contains_fresh(&key, Instant::now()) {
            enqueue_caps_effects(&self.state, full_jid, CapsEffects::AUTOMATIC_PEP_LAST_ITEMS);
            return;
        }
        let id = format!("caps-{}", stream_id());
        match self
            .state
            .pending_caps()
            .admit(id.clone(), full_jid.clone(), key, Instant::now())
        {
            PendingCapsAdmission::Admitted => {}
            PendingCapsAdmission::Duplicate => return,
            PendingCapsAdmission::Full => {
                tracing::debug!(%full_jid, "skipped entity capability lookup at the pending-query limit");
                return;
            }
        }
        let query = caps_disco_request(&self.state.config.domain, &full_jid, &id, node, version);
        if self.outbound.try_send(query).is_err() {
            self.state.pending_caps().remove(&id);
        }
    }

    pub(crate) fn handle_caps_response(
        &self,
        id: &str,
        kind: &str,
        root: Node<'_, '_>,
        raw: &str,
    ) -> bool {
        let Some(pending) = self.state.pending_caps().take(id) else {
            return false;
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
            || kind != "result"
        {
            tracing::debug!(
                authenticated = ?self.full_jid,
                explicit_from = ?root.attribute("from"),
                effective_from = ?response_from,
                expected_from = %pending.full_jid,
                stanza_type = %kind,
                expired = pending.expires_at <= Instant::now(),
                "discarded entity capabilities with an invalid response envelope"
            );
            return true;
        }
        let Some(query) = root.children().find(|node| {
            node.is_element()
                && node.tag_name().name() == "query"
                && node.tag_name().namespace() == Some(DISCO_INFO_NS)
        }) else {
            return true;
        };
        let expected_node = format!("{}#{}", pending.key.node, pending.key.version);
        if query.attribute("node") != Some(expected_node.as_str()) {
            tracing::debug!(jid = %pending.full_jid, "discarded entity capabilities with a mismatched node");
            return true;
        }
        let range = query.range();
        let Some(payload) = raw.get(range) else {
            return true;
        };
        if payload.len() > MAX_DISCO_PAYLOAD_BYTES {
            return true;
        }
        if pending.key.algorithm == "sha-1" {
            let Ok(verification) = verification_string(query) else {
                tracing::debug!(jid = %pending.full_jid, "discarded malformed entity capabilities");
                return true;
            };
            let computed = STANDARD.encode(Sha1::digest(verification.as_bytes()));
            if computed != pending.key.version {
                tracing::warn!(jid = %pending.full_jid, "discarded entity capabilities whose hash did not verify");
                return true;
            }
        }
        if !self.state.caps_cache().insert(
            pending.key.clone(),
            payload.to_owned(),
            Instant::now(),
            |key| caps_key_is_pinned(&self.state, key),
        ) {
            tracing::debug!(jid = %pending.full_jid, "discarded verified entity capabilities at the cache limit");
            return true;
        }
        let mix_capable = disco_has_feature(query, "urn:xmpp:mix:core:1")
            || disco_has_feature(query, "urn:xmpp:mix:pam:2");
        let full_jid = pending.full_jid.clone();
        tracing::debug!(
            jid = %full_jid,
            node = %pending.key.node,
            version = %pending.key.version,
            "cached verified entity capabilities"
        );
        let mut effects = CapsEffects::AUTOMATIC_PEP_LAST_ITEMS;
        if mix_capable {
            effects.merge(CapsEffects::VERIFIED_MIX_PRESENCE);
        }
        enqueue_caps_effects(&self.state, full_jid, effects);
        true
    }
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

/// Admit one resource's capability mapping under a hard per-process entry
/// bound with LRU eviction and a freshness TTL. The map's own policing is the
/// only defense: a remote resource which disappears without an unavailable
/// presence has no other removal path.
fn admit_caps_resource(state: &AppState, full_jid: String, key: CapsKey) {
    let admitted = state
        .caps_by_jid()
        .admit(full_jid.clone(), key, Instant::now(), |candidate| {
            local_caps_resource_is_pinned(state, candidate)
        });
    if !admitted {
        tracing::debug!(%full_jid, "skipped entity capability mapping at the pinned resource limit");
    }
}

fn sweep_caps_resources(state: &AppState) {
    state.caps_by_jid().sweep(Instant::now(), |candidate| {
        local_caps_resource_is_pinned(state, candidate)
    });
}

/// LRU refresh for one resource mapping; returns its verified capability key.
pub(crate) fn touch_caps_resource(state: &AppState, target: &str) -> Option<CapsKey> {
    state
        .caps_by_jid()
        .touch(target, Instant::now(), |candidate| {
            local_caps_resource_is_pinned(state, candidate)
        })
}

fn local_caps_resource_is_pinned(state: &AppState, target: &str) -> bool {
    state.sessions.get(target).is_some_and(|session| {
        session.routable.load(Ordering::Acquire)
            && !session.disconnect.is_cancelled()
            && session.lifecycle.load(Ordering::Acquire) == 0
    })
}

/// Observes an authenticated federated resource's XEP-0115 advertisement.
/// Remote claims are never trusted directly: the advertised disco payload is
/// requested over the already-authenticated S2S route and hash-verified before
/// it can influence PEP fan-out.
pub(crate) async fn observe_federated_caps(
    state: &AppState,
    presence: Node<'_, '_>,
    full_jid: &str,
) {
    let Ok(full_jid) = crate::jid::canonical_session_key(full_jid) else {
        return;
    };
    if presence
        .attribute("type")
        .is_some_and(|kind| kind != "available")
    {
        state.caps_by_jid().remove_resource(&full_jid);
        return;
    }
    if let Err(error) =
        super::pep::deliver_explicit_pep_last_items_for_resource(state, &full_jid).await
    {
        tracing::warn!(?error, resource = %full_jid, "failed to deliver explicit federated PEP last items");
    }
    let Some(caps) = presence.children().find(|node| {
        node.is_element()
            && node.tag_name().name() == "c"
            && node.tag_name().namespace() == Some(CAPS_NS)
    }) else {
        state.caps_by_jid().remove_resource(&full_jid);
        return;
    };
    let (Some(algorithm), Some(node), Some(version)) = (
        caps.attribute("hash"),
        caps.attribute("node"),
        caps.attribute("ver"),
    ) else {
        return;
    };
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
        return;
    }
    let key = CapsKey {
        algorithm: scoped_algorithm(algorithm, &full_jid),
        node: node.to_owned(),
        version: version.to_owned(),
    };
    admit_caps_resource(state, full_jid.clone(), key.clone());
    if state.caps_cache().contains_fresh(&key, Instant::now()) {
        if let Err(error) =
            super::pep::deliver_pep_last_items_for_federated_resource(state, &full_jid).await
        {
            tracing::warn!(?error, resource = %full_jid, "failed to deliver cached federated PEP last items");
        }
        return;
    }
    let id = format!("caps-{}", stream_id());
    match state
        .pending_caps()
        .admit(id.clone(), full_jid.clone(), key, Instant::now())
    {
        PendingCapsAdmission::Admitted => {}
        PendingCapsAdmission::Duplicate | PendingCapsAdmission::Full => return,
    }
    let query = caps_disco_request(&state.config.domain, &full_jid, &id, node, version);
    let domain = match crate::jid::CanonicalJid::parse(&full_jid) {
        Ok(jid) => jid.domainpart().to_owned(),
        Err(_) => {
            state.pending_caps().remove(&id);
            return;
        }
    };
    if !state
        .federation
        .send(&domain, query, Some(state.config.domain.clone()))
        .await
    {
        state.pending_caps().remove(&id);
    }
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
    let Some(pending) = state.pending_caps().take(id) else {
        return false;
    };
    let response_from = root
        .attribute("from")
        .and_then(|jid| crate::jid::canonical_session_key(jid).ok());
    if pending.expires_at <= Instant::now()
        || response_from.as_deref() != Some(pending.full_jid.as_str())
        || kind != "result"
    {
        return true;
    }
    let Some(query) = root.children().find(|node| {
        node.is_element()
            && node.tag_name().name() == "query"
            && node.tag_name().namespace() == Some(DISCO_INFO_NS)
    }) else {
        return true;
    };
    let expected_node = format!("{}#{}", pending.key.node, pending.key.version);
    let range = query.range();
    let Some(payload) = raw.get(range) else {
        return true;
    };
    if query.attribute("node") != Some(expected_node.as_str())
        || payload.len() > MAX_DISCO_PAYLOAD_BYTES
    {
        return true;
    }
    if pending.key.algorithm == "sha-1" {
        let Ok(verification) = verification_string(query) else {
            return true;
        };
        if STANDARD.encode(Sha1::digest(verification.as_bytes())) != pending.key.version {
            tracing::warn!(jid = %pending.full_jid, "discarded federated entity capabilities whose hash did not verify");
            return true;
        }
    }
    if !state.caps_cache().insert(
        pending.key.clone(),
        payload.to_owned(),
        Instant::now(),
        |key| caps_key_is_pinned(state, key),
    ) {
        return true;
    }
    let resource = pending.full_jid;
    if let Err(error) =
        super::pep::deliver_pep_last_items_for_federated_resource(state, &resource).await
    {
        tracing::warn!(?error, %resource, "failed to deliver verified federated PEP last items");
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
    let Some(key) = touch_caps_resource(state, &target) else {
        tracing::debug!(%target, "entity capability cache lookup has no resource mapping");
        return None;
    };
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
    let Some(query) = state.caps_cache().query(&key, Instant::now()) else {
        tracing::debug!(%target, node = %key.node, version = %key.version, "entity capability cache lookup missed verified content");
        return None;
    };
    Some(iq_result_from(id, &target, &query))
}

pub(crate) fn pep_notify_nodes(state: &AppState, target: &str) -> Vec<String> {
    let Ok(target) = crate::jid::canonical_session_key(target) else {
        return Vec::new();
    };
    let Some(key) = touch_caps_resource(state, &target) else {
        return Vec::new();
    };
    let Some(query) = state.caps_cache().query(&key, Instant::now()) else {
        return Vec::new();
    };
    notify_nodes_from_query(&query)
}

/// MIX/PEP consumers share the strict top-level feature parser used at caps
/// verification time. Text, identities and nested data-form elements cannot
/// impersonate a disco feature. Successful use refreshes both LRU layers.
pub(crate) fn cached_caps_has_feature(state: &AppState, target: &str, feature: &str) -> bool {
    let Ok(target) = crate::jid::canonical_session_key(target) else {
        return false;
    };
    let Some(key) = touch_caps_resource(state, &target) else {
        return false;
    };
    let Some(query) = state.caps_cache().query(&key, Instant::now()) else {
        return false;
    };
    let Ok(document) = roxmltree::Document::parse(&query) else {
        return false;
    };
    let root = document.root_element();
    root.tag_name().name() == "query"
        && root.tag_name().namespace() == Some(DISCO_INFO_NS)
        && disco_has_feature(root, feature)
}

fn notify_nodes_from_query(query: &str) -> Vec<String> {
    let Ok(document) = roxmltree::Document::parse(query) else {
        return Vec::new();
    };
    let root = document.root_element();
    if root.tag_name().name() != "query" || root.tag_name().namespace() != Some(DISCO_INFO_NS) {
        return Vec::new();
    }
    root.children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().name() == "feature"
                && node.tag_name().namespace() == Some(DISCO_INFO_NS)
        })
        .filter_map(|node| node.attribute("var"))
        .filter_map(|feature| feature.strip_suffix("+notify"))
        .filter(|node| !node.is_empty() && node.len() <= 1_024)
        .take(128)
        .map(ToOwned::to_owned)
        .collect()
}

fn disco_has_feature(query: Node<'_, '_>, feature: &str) -> bool {
    query.children().any(|node| {
        node.is_element()
            && node.tag_name().name() == "feature"
            && node.tag_name().namespace() == Some(DISCO_INFO_NS)
            && node.attribute("var") == Some(feature)
    })
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

fn caps_key_is_pinned(state: &AppState, key: &CapsKey) -> bool {
    state
        .caps_by_jid()
        .iter()
        .any(|resource| &resource.value().key == key && state.sessions.contains_key(resource.key()))
}

pub(crate) fn wants_pep_node(state: &AppState, target: &str, node: &str) -> bool {
    pep_notify_nodes(state, target)
        .iter()
        .any(|wanted| wanted == node)
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

    #[test]
    fn high_frequency_same_jid_is_coalesced_into_one_job() {
        let metrics = crate::metrics::Metrics::default();
        let dispatcher = CapsEffectDispatcher::with_limits(4, 2);
        assert_eq!(
            dispatcher.enqueue_latest(
                "alice@example.test/Phone".to_owned(),
                CapsEffects::EXPLICIT_PEP_LAST_ITEMS,
                &metrics,
            ),
            CapsEffectAdmission::Queued
        );
        for _ in 0..10_000 {
            assert_eq!(
                dispatcher.enqueue(
                    "alice@example.test/Phone".to_owned(),
                    CapsEffects::AUTOMATIC_PEP_LAST_ITEMS,
                    &metrics,
                ),
                CapsEffectAdmission::Coalesced
            );
        }
        assert_eq!(dispatcher.queued_jids(), 1);
        assert_eq!(
            metrics.caps_effect_coalesced_total.load(Ordering::Relaxed),
            10_000
        );
        let job = dispatcher.take_ready().expect("one merged job");
        assert!(job.effects.contains(CapsEffects::EXPLICIT_PEP_LAST_ITEMS));
        assert!(job.effects.contains(CapsEffects::AUTOMATIC_PEP_LAST_ITEMS));
        assert!(dispatcher.take_ready().is_none());
    }

    #[test]
    fn cached_caps_effect_merges_with_the_available_presence_effect() {
        let metrics = crate::metrics::Metrics::default();
        let dispatcher = CapsEffectDispatcher::with_limits(2, 1);
        dispatcher.enqueue_latest(
            "alice@example.test/Phone".to_owned(),
            CapsEffects::EXPLICIT_PEP_LAST_ITEMS,
            &metrics,
        );
        dispatcher.enqueue(
            "alice@example.test/Phone".to_owned(),
            CapsEffects::AUTOMATIC_PEP_LAST_ITEMS,
            &metrics,
        );
        let job = dispatcher.take_ready().expect("cached capability job");
        assert_eq!(
            job.effects,
            CapsEffects::EXPLICIT_PEP_LAST_ITEMS | CapsEffects::AUTOMATIC_PEP_LAST_ITEMS
        );
    }

    #[test]
    fn new_presence_replaces_pending_stale_capability_effects() {
        let metrics = crate::metrics::Metrics::default();
        let dispatcher = CapsEffectDispatcher::with_limits(2, 1);
        dispatcher.enqueue(
            "alice@example.test/Phone".to_owned(),
            CapsEffects::AUTOMATIC_PEP_LAST_ITEMS | CapsEffects::VERIFIED_MIX_PRESENCE,
            &metrics,
        );
        dispatcher.enqueue_latest(
            "alice@example.test/Phone".to_owned(),
            CapsEffects::EXPLICIT_PEP_LAST_ITEMS,
            &metrics,
        );
        assert_eq!(
            dispatcher
                .take_ready()
                .expect("latest presence job")
                .effects,
            CapsEffects::EXPLICIT_PEP_LAST_ITEMS
        );
    }

    #[test]
    fn running_jid_has_only_one_coalesced_follow_up() {
        let metrics = crate::metrics::Metrics::default();
        let dispatcher = CapsEffectDispatcher::with_limits(2, 1);
        dispatcher.enqueue_latest(
            "alice@example.test/Phone".to_owned(),
            CapsEffects::EXPLICIT_PEP_LAST_ITEMS,
            &metrics,
        );
        let first = dispatcher.take_ready().expect("first job");
        for _ in 0..100 {
            dispatcher.enqueue(
                first.full_jid.clone(),
                CapsEffects::AUTOMATIC_PEP_LAST_ITEMS,
                &metrics,
            );
        }
        assert!(dispatcher.take_ready().is_none());
        dispatcher.complete(&first.full_jid);
        let follow_up = dispatcher.take_ready().expect("one follow-up");
        assert_eq!(follow_up.effects, CapsEffects::AUTOMATIC_PEP_LAST_ITEMS);
        assert!(dispatcher.take_ready().is_none());
    }

    #[test]
    fn unique_jid_capacity_and_global_execution_limit_are_bounded() {
        let metrics = crate::metrics::Metrics::default();
        let dispatcher = CapsEffectDispatcher::with_limits(2, 1);
        for jid in ["a@example.test/One", "b@example.test/Two"] {
            assert_eq!(
                dispatcher.enqueue(
                    jid.to_owned(),
                    CapsEffects::EXPLICIT_PEP_LAST_ITEMS,
                    &metrics,
                ),
                CapsEffectAdmission::Queued
            );
        }
        assert_eq!(
            dispatcher.enqueue(
                "c@example.test/Three".to_owned(),
                CapsEffects::EXPLICIT_PEP_LAST_ITEMS,
                &metrics,
            ),
            CapsEffectAdmission::Saturated
        );
        assert_eq!(dispatcher.queued_jids(), 2);
        assert_eq!(
            metrics
                .caps_effect_queue_saturated_total
                .load(Ordering::Relaxed),
            1
        );
        let permit = Arc::clone(&dispatcher.execution_slots)
            .try_acquire_owned()
            .expect("one global slot");
        assert!(Arc::clone(&dispatcher.execution_slots)
            .try_acquire_owned()
            .is_err());
        drop(permit);
    }

    #[test]
    fn closed_queue_rejects_new_work_and_drains_admitted_work() {
        let metrics = crate::metrics::Metrics::default();
        let dispatcher = CapsEffectDispatcher::with_limits(2, 1);
        dispatcher.enqueue(
            "alice@example.test/Phone".to_owned(),
            CapsEffects::EXPLICIT_PEP_LAST_ITEMS,
            &metrics,
        );
        dispatcher.close();
        assert_eq!(
            dispatcher.enqueue(
                "bob@example.test/Laptop".to_owned(),
                CapsEffects::EXPLICIT_PEP_LAST_ITEMS,
                &metrics,
            ),
            CapsEffectAdmission::Closed
        );
        let admitted = dispatcher.take_ready().expect("pre-close work remains");
        dispatcher.complete(&admitted.full_jid);
        assert!(dispatcher.is_drained());
    }

    #[test]
    fn repeated_unavailable_transitions_do_not_accumulate_stale_queue_keys() {
        let metrics = crate::metrics::Metrics::default();
        let dispatcher = CapsEffectDispatcher::with_limits(2, 1);
        let jid = "alice@example.test/Phone";
        for _ in 0..10_000 {
            dispatcher.enqueue_latest(
                jid.to_owned(),
                CapsEffects::EXPLICIT_PEP_LAST_ITEMS,
                &metrics,
            );
            dispatcher.cancel(jid);
        }
        assert_eq!(dispatcher.queued_jids(), 0);
        assert_eq!(dispatcher.ready_entries(), 0);
    }

    #[test]
    fn interrupted_running_work_is_requeued_without_duplication() {
        let metrics = crate::metrics::Metrics::default();
        let dispatcher = CapsEffectDispatcher::with_limits(2, 1);
        dispatcher.enqueue(
            "alice@example.test/Phone".to_owned(),
            CapsEffects::EXPLICIT_PEP_LAST_ITEMS,
            &metrics,
        );
        let running = dispatcher.take_ready().expect("running job");
        dispatcher.enqueue(
            running.full_jid.clone(),
            CapsEffects::AUTOMATIC_PEP_LAST_ITEMS,
            &metrics,
        );
        dispatcher.recover_interrupted();
        let recovered = dispatcher.take_ready().expect("recovered job");
        assert_eq!(
            recovered.effects,
            CapsEffects::EXPLICIT_PEP_LAST_ITEMS | CapsEffects::AUTOMATIC_PEP_LAST_ITEMS
        );
        assert!(dispatcher.take_ready().is_none());
    }

    #[test]
    fn outbound_caps_query_round_trips_untrusted_runtime_values() {
        let domain = "例.example'\"<&>";
        let full_jid = "ユーザー@example.test/Phone' /><evil/>";
        let id = "caps-'\"<&>🙂";
        let node = "urn:example:'\"<&>日本語";
        let version = "v&<\"'🙂";
        let xml = caps_disco_request(domain, full_jid, id, node, version);
        let document = Document::parse(&xml).unwrap();
        let iq = document.root_element();
        assert_eq!(iq.tag_name().namespace(), Some("jabber:client"));
        assert_eq!(iq.attribute("from"), Some(domain));
        assert_eq!(iq.attribute("to"), Some(full_jid));
        assert_eq!(iq.attribute("id"), Some(id));
        let query = iq.children().find(Node::is_element).unwrap();
        assert_eq!(query.tag_name().namespace(), Some(DISCO_INFO_NS));
        assert_eq!(
            query.attribute("node"),
            Some(format!("{node}#{version}").as_str())
        );
        assert_eq!(query.children().filter(Node::is_element).count(), 0);
    }

    #[test]
    fn verification_is_sorted_and_rejects_poisoned_results() {
        let xml = "<query xmlns='http://jabber.org/protocol/disco#info'><identity category='client' type='pc' name='Northstar'/><feature var='z'/><feature var='a'/></query>";
        let document = Document::parse(xml).unwrap();
        assert_eq!(
            verification_string(document.root_element()).unwrap(),
            "client/pc//Northstar<a<z<"
        );
        let poisoned = "<query xmlns='http://jabber.org/protocol/disco#info'><feature var='a'/><feature var='a'/></query>";
        let document = Document::parse(poisoned).unwrap();
        assert!(verification_string(document.root_element()).is_err());
    }

    #[test]
    fn pep_notify_interest_accepts_only_top_level_disco_features() {
        let query = "<query xmlns='http://jabber.org/protocol/disco#info'><feature var='urn:example:one+notify'/><x xmlns='jabber:x:data'><feature xmlns='http://jabber.org/protocol/disco#info' var='urn:example:poison+notify'/></x><feature var='+notify'/><feature var='urn:example:plain'/></query>";
        assert_eq!(notify_nodes_from_query(query), ["urn:example:one"]);
        assert!(notify_nodes_from_query("<query xmlns='urn:wrong'><feature xmlns='http://jabber.org/protocol/disco#info' var='urn:example:one+notify'/></query>").is_empty());
    }

    #[test]
    fn unsupported_hashes_are_scoped_to_the_exact_jid() {
        assert_eq!(scoped_algorithm("sha-1", "a@example.test/one"), "sha-1");
        assert_ne!(
            scoped_algorithm("sha-256", "a@example.test/one"),
            scoped_algorithm("sha-256", "a@example.test/two")
        );
    }

    #[test]
    fn omitted_c2s_caps_sender_uses_authenticated_full_jid() {
        assert_eq!(
            effective_c2s_caps_sender(Some("Bob@EXAMPLE.test/Phone"), None).as_deref(),
            Some("bob@example.test/Phone")
        );
        assert_eq!(
            effective_c2s_caps_sender(
                Some("bob@example.test/Phone"),
                Some("bob@example.test/Phone")
            )
            .as_deref(),
            Some("bob@example.test/Phone")
        );
    }

    #[test]
    fn spoofed_c2s_caps_sender_is_rejected_before_cache_admission() {
        // `handle_caps_response` returns before parsing or inserting the
        // advertised payload when this authorization gate returns `None`, so
        // a forged sender cannot poison the verified capabilities cache.
        assert!(effective_c2s_caps_sender(
            Some("bob@example.test/Phone"),
            Some("mallory@example.test/Phone")
        )
        .is_none());
        assert!(
            effective_c2s_caps_sender(Some("bob@example.test/Phone"), Some("not a jid")).is_none()
        );
    }

    #[test]
    fn invalid_extended_forms_are_ignored_but_poisoning_is_rejected() {
        let ignored = Document::parse(
            "<query xmlns='http://jabber.org/protocol/disco#info'><feature var='a'/><x xmlns='jabber:x:data' type='result'><field var='FORM_TYPE'><value>ignored</value></field></x></query>",
        )
        .unwrap();
        assert_eq!(verification_string(ignored.root_element()).unwrap(), "a<");

        let poisoned = Document::parse(
            "<query xmlns='http://jabber.org/protocol/disco#info'><x xmlns='jabber:x:data' type='result'><field var='FORM_TYPE' type='hidden'><value>one</value><value>two</value></field></x></query>",
        )
        .unwrap();
        assert!(verification_string(poisoned.root_element()).is_err());
    }

    #[test]
    fn capability_checks_ignore_nested_and_textual_feature_names() {
        let document = Document::parse(
            "<query xmlns='http://jabber.org/protocol/disco#info'><identity category='client' type='pc' name='urn:xmpp:mix:core:1'/><x xmlns='jabber:x:data'><feature xmlns='http://jabber.org/protocol/disco#info' var='urn:xmpp:mix:core:1'/></x></query>",
        )
        .unwrap();
        assert!(!disco_has_feature(
            document.root_element(),
            "urn:xmpp:mix:core:1"
        ));
    }

    #[test]
    fn caps_resource_admission_is_bounded_and_evicts_the_oldest_resources() {
        let max_entries = 16;
        let ttl = Duration::from_secs(3_600);
        let index = CapsResourceIndex::with_limits(max_entries, ttl);
        let base = Instant::now();
        for seed in 0_u8..max_entries as u8 {
            assert!(index.admit(
                format!("jid-{seed}"),
                resource_key(seed),
                base - Duration::from_secs((max_entries - usize::from(seed)) as u64),
                |_| false,
            ));
        }
        // Refreshing jid-0 makes it the most recently used resource even
        // though its advertisement was observed first.
        assert!(index.touch("jid-0", base, |_| false).is_some());
        assert!(index.admit("jid-new".to_owned(), resource_key(200), base, |_| false,));
        assert!(index.len() <= max_entries);
        assert!(index.contains_key("jid-new"));
        assert!(index.contains_key("jid-0"));
        assert!(index.contains_key("jid-3"));
        // The two oldest untouched resources made room for the admission.
        assert!(!index.contains_key("jid-1"));
        assert!(!index.contains_key("jid-2"));
    }

    #[test]
    fn caps_resource_sweep_keeps_only_fresh_resources() {
        let ttl = Duration::from_secs(3_600);
        let index = CapsResourceIndex::with_limits(16, ttl);
        let base = Instant::now();
        assert!(index.admit(
            "stale@example.test/Phone".to_owned(),
            resource_key(1),
            base - ttl - Duration::from_secs(1),
            |_| false,
        ));
        assert!(index.admit(
            "fresh@example.test/Phone".to_owned(),
            resource_key(2),
            base,
            |_| false,
        ));
        index.sweep(base, |_| false);
        assert!(!index.contains_key("stale@example.test/Phone"));
        assert!(index.contains_key("fresh@example.test/Phone"));
    }

    #[test]
    fn caps_resource_re_admission_refreshes_without_growth() {
        let ttl = Duration::from_secs(3_600);
        let index = CapsResourceIndex::with_limits(16, ttl);
        let base = Instant::now();
        let jid = "alice@example.test/Phone";
        assert!(index.admit(jid.to_owned(), resource_key(1), base - ttl, |_| false));
        assert_eq!(index.len(), 1);
        assert!(index.admit(jid.to_owned(), resource_key(1), base, |_| false));
        assert_eq!(index.len(), 1);
        assert_eq!(
            index.touch(jid, base, |_| false).map(|key| key.node),
            Some("node-1".to_owned())
        );
    }

    #[test]
    fn caps_resource_hard_cap_is_linearizable_under_concurrent_admission() {
        let max_entries = 8;
        let workers = 64;
        let index = Arc::new(CapsResourceIndex::with_limits(
            max_entries,
            Duration::from_secs(3_600),
        ));
        let barrier = Arc::new(std::sync::Barrier::new(workers));
        let mut threads = Vec::new();
        for seed in 0..workers {
            let index = Arc::clone(&index);
            let barrier = Arc::clone(&barrier);
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                index.admit(
                    format!("remote-{seed}@example.test/Device"),
                    resource_key(seed as u8),
                    Instant::now(),
                    |_| false,
                )
            }));
        }
        for thread in threads {
            let _ = thread.join().expect("caps admission worker panicked");
        }
        assert!(index.len() <= max_entries);
    }

    #[test]
    fn pending_caps_hard_cap_is_linearizable_for_c2s_and_s2s_callers() {
        let limit = 8;
        let workers = 64;
        let index = Arc::new(PendingCapsIndex::with_limit(limit));
        let barrier = Arc::new(std::sync::Barrier::new(workers));
        let mut threads = Vec::new();
        for seed in 0..workers {
            let index = Arc::clone(&index);
            let barrier = Arc::clone(&barrier);
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                index.admit(
                    format!("id-{seed}"),
                    format!("remote-{seed}@example.test/Device"),
                    resource_key(seed as u8),
                    Instant::now(),
                )
            }));
        }
        let admitted = threads
            .into_iter()
            .map(|thread| {
                thread.join().expect("pending caps worker panicked")
                    == PendingCapsAdmission::Admitted
            })
            .filter(|admitted| *admitted)
            .count();
        assert_eq!(admitted, limit);
        assert_eq!(index.len(), limit);
    }

    #[test]
    fn verified_caps_cache_is_concurrently_bounded_and_lru_pinned() {
        let limit = 8;
        let workers = 64;
        let cache = Arc::new(CapsCacheIndex::with_limits(
            limit,
            Duration::from_secs(3_600),
        ));
        let barrier = Arc::new(std::sync::Barrier::new(workers));
        let mut threads = Vec::new();
        for seed in 0..workers {
            let cache = Arc::clone(&cache);
            let barrier = Arc::clone(&barrier);
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                cache.insert(
                    resource_key(seed as u8),
                    format!("<query seed='{seed}'/>"),
                    Instant::now(),
                    |_| false,
                )
            }));
        }
        for thread in threads {
            let _ = thread.join().expect("caps cache worker panicked");
        }
        assert!(cache.len() <= limit);

        let cache = CapsCacheIndex::with_limits(2, Duration::from_secs(60));
        let now = Instant::now();
        let old = resource_key(1);
        let touched = resource_key(2);
        let incoming = resource_key(3);
        assert!(cache.insert(old.clone(), "old".to_owned(), now, |_| false));
        assert!(cache.insert(
            touched.clone(),
            "touch".to_owned(),
            now + Duration::from_millis(1),
            |_| false,
        ));
        assert_eq!(
            cache.query(&touched, now + Duration::from_millis(2)),
            Some("touch".to_owned())
        );
        assert!(cache.insert(
            incoming.clone(),
            "new".to_owned(),
            now + Duration::from_millis(3),
            |candidate| candidate == &touched,
        ));
        assert!(!cache.contains_key(&old));
        assert!(cache.contains_key(&touched));
        assert!(cache.contains_key(&incoming));
    }

    #[test]
    fn pinned_local_resources_are_neither_expired_nor_evicted() {
        let ttl = Duration::from_secs(60);
        let index = CapsResourceIndex::with_limits(2, ttl);
        let now = Instant::now();
        for seed in 0_u8..2 {
            assert!(index.admit(
                format!("local-{seed}@example.test/Device"),
                resource_key(seed),
                now - ttl - Duration::from_secs(1),
                |_| true,
            ));
        }
        assert!(index
            .touch("local-0@example.test/Device", now, |_| true)
            .is_some());
        assert!(!index.admit(
            "remote@example.test/Device".to_owned(),
            resource_key(9),
            now,
            |candidate| candidate.starts_with("local-"),
        ));
        index.sweep(now, |candidate| candidate.starts_with("local-"));
        assert_eq!(index.len(), 2);
    }

    fn resource_key(seed: u8) -> CapsKey {
        CapsKey {
            algorithm: "sha-1".to_owned(),
            node: format!("node-{seed}"),
            version: format!("ver-{seed}"),
        }
    }
}
