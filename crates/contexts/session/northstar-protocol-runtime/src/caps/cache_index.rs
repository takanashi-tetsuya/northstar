use super::{
    CapsKey, VerifiedCapsSummary, CACHE_TTL, MAX_CAPS_CACHE_ENTRIES, MAX_CAPS_CACHE_RAW_BYTES,
    MAX_CAPS_CACHE_SUMMARY_BYTES,
};
use dashmap::DashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct CachedCaps {
    pub query: Option<String>,
    pub summary: Arc<VerifiedCapsSummary>,
    pub expires_at: Instant,
    pub touched_at: Instant,
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
