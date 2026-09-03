#![forbid(unsafe_code)]

use dashmap::DashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const MIX_IQ_RELAY_LIMIT: usize = 1_024;
pub const MIX_IQ_RELAY_TTL: Duration = Duration::from_secs(30);

#[derive(Clone, Debug)]
pub enum MixIqRelayStage {
    /// A local client sent an IQ through a remote channel.  The remote MIX
    /// service must return exactly the encoded participant and requester that
    /// were registered here before the client id is restored.
    Participant {
        requester_full_jid: String,
        original_id: String,
        expected_from: String,
        channel_jid: String,
    },
    /// A locally hosted channel relayed a whitelisted read to a remote
    /// participant.  Responses are accepted only from the exact real target
    /// and are rewritten back to the encoded channel identity.
    Channel {
        requester_full_jid: String,
        requester_encoded_jid: String,
        original_id: String,
        target_real_jid: String,
        target_encoded_jid: String,
        channel_jid: String,
    },
}

#[derive(Clone, Debug)]
pub struct PendingMixIqRelay {
    pub stage: MixIqRelayStage,
    pub expires_at: Instant,
}

/// One linearizable correlation budget for every MIX IQ relay. Expiry is
/// drained by a single supervised worker; admission never creates one timer
/// task per untrusted request.
pub struct MixIqRelayIndex {
    entries: DashMap<String, PendingMixIqRelay>,
    admission: Mutex<()>,
    max_entries: usize,
    ttl: Duration,
}

impl Default for MixIqRelayIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl MixIqRelayIndex {
    pub fn new() -> Self {
        Self::with_limits(MIX_IQ_RELAY_LIMIT, MIX_IQ_RELAY_TTL)
    }

    pub fn with_limits(max_entries: usize, ttl: Duration) -> Self {
        assert!(max_entries > 0, "MIX relay capacity must be positive");
        Self {
            entries: DashMap::new(),
            admission: Mutex::new(()),
            max_entries,
            ttl,
        }
    }

    pub fn admit(&self, id: String, stage: MixIqRelayStage, now: Instant) -> bool {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if self.entries.contains_key(&id) || self.entries.len() >= self.max_entries {
            return false;
        }
        self.entries.insert(
            id,
            PendingMixIqRelay {
                stage,
                expires_at: now + self.ttl,
            },
        );
        debug_assert!(self.entries.len() <= self.max_entries);
        true
    }

    pub fn get(&self, id: &str) -> Option<PendingMixIqRelay> {
        self.entries.get(id).map(|pending| pending.value().clone())
    }

    pub fn remove(&self, id: &str) -> Option<PendingMixIqRelay> {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.entries.remove(id).map(|(_, pending)| pending)
    }

    pub fn take_expired(&self, now: Instant) -> Vec<PendingMixIqRelay> {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let expired = self
            .entries
            .iter()
            .filter(|pending| pending.expires_at <= now)
            .map(|pending| pending.key().clone())
            .collect::<Vec<_>>();
        expired
            .into_iter()
            .filter_map(|id| self.entries.remove(&id).map(|(_, pending)| pending))
            .collect()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}
