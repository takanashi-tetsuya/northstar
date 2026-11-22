//! Injected PubSub clocks and UUID sources, and the event context prepared from them.

use northstar_time::{DateTime, Utc};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use uuid::Uuid;

/// A thread-safe source of UTC instants for PubSub.
pub trait PubSubClock: Send + Sync {
    /// Return the instant supplied by this clock.
    fn now(&self) -> DateTime<Utc>;
}

/// A thread-safe source of UUIDs for PubSub.
pub trait PubSubIdSource: Send + Sync {
    /// Draw the next UUID from this source.
    fn new_uuid(&self) -> Uuid;
}

/// A PubSub clock that reads the system time in UTC.
#[derive(Default, Clone, Copy, Debug)]
pub struct SystemPubSubClock;

impl PubSubClock for SystemPubSubClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

/// A PubSub ID source that generates random version 4 UUIDs.
#[derive(Default, Clone, Copy, Debug)]
pub struct RandomPubSubIds;

impl PubSubIdSource for RandomPubSubIds {
    fn new_uuid(&self) -> Uuid {
        Uuid::new_v4()
    }
}

/// A PubSub clock that always returns the supplied instant.
#[derive(Clone, Copy, Debug)]
pub struct FixedPubSubClock(
    /// The UTC instant returned on every read.
    pub DateTime<Utc>,
);

impl PubSubClock for FixedPubSubClock {
    fn now(&self) -> DateTime<Utc> {
        self.0
    }
}

/// A deterministic PubSub ID source that encodes a counter starting at one.
#[derive(Debug)]
pub struct SequentialPubSubIds(AtomicU64);

impl Default for SequentialPubSubIds {
    fn default() -> Self {
        Self(AtomicU64::new(1))
    }
}

impl PubSubIdSource for SequentialPubSubIds {
    fn new_uuid(&self) -> Uuid {
        let next = self.0.fetch_add(1, Ordering::Relaxed);
        Uuid::from_u128(u128::from(next))
    }
}

/// The instant and UUID captured for an event before its transaction starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PreparedEventContext {
    /// The instant read from the clock.
    pub at: DateTime<Utc>,
    /// The UUID drawn from the ID source.
    pub id: Uuid,
}

impl PreparedEventContext {
    /// Read the clock once and draw one UUID for the event.
    pub fn prepare(clock: &dyn PubSubClock, ids: &dyn PubSubIdSource) -> Self {
        Self {
            at: clock.now(),
            id: ids.new_uuid(),
        }
    }
}

/// A clock and UUID source shared across clones of this value.
#[derive(Clone)]
pub struct PubSubTimeSources {
    clock: Arc<dyn PubSubClock>,
    ids: Arc<dyn PubSubIdSource>,
}

impl PubSubTimeSources {
    /// Use the supplied clock and UUID source.
    pub fn new(clock: Arc<dyn PubSubClock>, ids: Arc<dyn PubSubIdSource>) -> Self {
        Self { clock, ids }
    }

    /// Read the configured clock.
    pub fn now(&self) -> DateTime<Utc> {
        self.clock.now()
    }

    /// Draw one UUID from the configured source.
    pub fn new_uuid(&self) -> Uuid {
        self.ids.new_uuid()
    }

    /// Capture an instant and UUID from the configured sources for an event.
    pub fn prepare_event(&self) -> PreparedEventContext {
        PreparedEventContext::prepare(self.clock.as_ref(), self.ids.as_ref())
    }
}

impl Default for PubSubTimeSources {
    fn default() -> Self {
        Self::new(Arc::new(SystemPubSubClock), Arc::new(RandomPubSubIds))
    }
}

impl fmt::Debug for PubSubTimeSources {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PubSubTimeSources")
    }
}

#[cfg(test)]
mod tests;
