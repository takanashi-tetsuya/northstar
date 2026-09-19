//! Bounded, expiry-aware replay protection for one-time assertions/tokens.

use crate::assertion::AssertionError;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::Mutex;

pub struct BoundedReplayCache {
    capacity: usize,
    entries: Mutex<HashMap<String, DateTime<Utc>>>,
}

impl BoundedReplayCache {
    pub fn new(capacity: usize) -> Result<Self, AssertionError> {
        if capacity == 0 {
            return Err(AssertionError::ReplayCapacity);
        }
        Ok(Self {
            capacity,
            entries: Mutex::new(HashMap::new()),
        })
    }

    pub fn claim(
        &self,
        jti: impl Into<String>,
        expires_at: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<(), AssertionError> {
        let jti = jti.into();
        if jti.trim().is_empty() || expires_at <= now {
            return Err(AssertionError::ExpiredOrNotYetValid);
        }
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| AssertionError::ReplayCapacity)?;
        entries.retain(|_, expiry| *expiry > now);
        if entries.contains_key(&jti) {
            return Err(AssertionError::Replay);
        }
        if entries.len() >= self.capacity {
            return Err(AssertionError::ReplayCapacity);
        }
        entries.insert(jti, expires_at);
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.entries.lock().map(|v| v.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_rejects_replay_and_enforces_capacity_with_expiry() {
        let cache = BoundedReplayCache::new(1).unwrap();
        let now = Utc::now();
        cache
            .claim("one", now + chrono::Duration::seconds(10), now)
            .unwrap();
        assert_eq!(
            cache.claim("one", now + chrono::Duration::seconds(10), now),
            Err(AssertionError::Replay)
        );
        assert_eq!(
            cache.claim("two", now + chrono::Duration::seconds(10), now),
            Err(AssertionError::ReplayCapacity)
        );
        cache
            .claim(
                "two",
                now + chrono::Duration::seconds(20),
                now + chrono::Duration::seconds(11),
            )
            .unwrap();
        assert_eq!(cache.len(), 1);
    }
}
