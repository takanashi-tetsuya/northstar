//! The MIX IQ relay correlation index: one linearizable budget of pending relays.

use dashmap::DashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

mod authority;
mod clock;

pub use authority::{RelayPamIncarnation, RelayReturnAuthority, RelayReturnRoute};
pub use clock::{MixRelayMonotonic, SystemMixRelayMonotonic};

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
    pub return_authority: Option<RelayReturnAuthority>,
    token: Arc<()>,
}

pub enum ResponseTake {
    MissingOrReplaced,
    Response(PendingMixIqRelay),
    Expired(PendingMixIqRelay),
}

/// One linearizable correlation budget for every MIX IQ relay. Expiry is
/// drained by a single supervised worker; admission never creates one timer
/// task per untrusted request.
pub struct MixIqRelayIndex {
    entries: DashMap<String, PendingMixIqRelay>,
    admission: Mutex<()>,
    max_entries: usize,
    ttl: Duration,
    clock: Arc<dyn MixRelayMonotonic>,
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
        Self::with_clock(max_entries, ttl, Arc::new(SystemMixRelayMonotonic))
    }

    pub fn with_clock(
        max_entries: usize,
        ttl: Duration,
        clock: Arc<dyn MixRelayMonotonic>,
    ) -> Self {
        assert!(max_entries > 0, "MIX relay capacity must be positive");
        Self {
            entries: DashMap::new(),
            admission: Mutex::new(()),
            max_entries,
            ttl,
            clock,
        }
    }

    pub fn admit(&self, id: String, stage: MixIqRelayStage, now: Instant) -> bool {
        self.insert(id, stage, None, now)
    }

    pub fn now(&self) -> Instant {
        self.clock.now()
    }

    pub fn admit_with_authority(
        &self,
        id: String,
        stage: MixIqRelayStage,
        authority: RelayReturnAuthority,
    ) -> bool {
        self.insert(id, stage, Some(authority), self.now())
    }

    fn insert(
        &self,
        id: String,
        stage: MixIqRelayStage,
        return_authority: Option<RelayReturnAuthority>,
        now: Instant,
    ) -> bool {
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
                return_authority,
                token: Arc::new(()),
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

    pub fn take_response(
        &self,
        id: &str,
        expected: &PendingMixIqRelay,
        now: Instant,
    ) -> ResponseTake {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let removed = self.entries.remove_if(id, |_, pending| {
            Arc::ptr_eq(&pending.token, &expected.token)
        });
        match removed {
            Some((_, pending)) if pending.expires_at <= now => ResponseTake::Expired(pending),
            Some((_, pending)) => ResponseTake::Response(pending),
            None => ResponseTake::MissingOrReplaced,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod concurrency_tests;
#[cfg(test)]
mod return_tests;
