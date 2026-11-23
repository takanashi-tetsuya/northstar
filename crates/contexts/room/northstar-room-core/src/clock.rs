//! Injected MUC clocks and UUID sources, and the facts prepared from them.

use northstar_time::{DateTime, Utc};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use uuid::Uuid;

/// A thread-safe source of UTC instants for MUC.
pub trait MucClock: Send + Sync {
    /// Return the instant supplied by this clock.
    fn now(&self) -> DateTime<Utc>;
}

/// A thread-safe source of UUIDs for MUC.
pub trait MucIdSource: Send + Sync {
    /// Draw the next UUID from this source.
    fn new_uuid(&self) -> Uuid;
}

/// A MUC clock that reads the system time in UTC.
#[derive(Default, Clone, Copy, Debug)]
pub struct SystemMucClock;

impl MucClock for SystemMucClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

/// A MUC ID source that generates random version 4 UUIDs.
#[derive(Default, Clone, Copy, Debug)]
pub struct RandomMucIds;

impl MucIdSource for RandomMucIds {
    fn new_uuid(&self) -> Uuid {
        Uuid::new_v4()
    }
}

/// A MUC clock that always returns the supplied instant.
#[derive(Clone, Copy, Debug)]
pub struct FixedMucClock(
    /// The UTC instant returned on every read.
    pub DateTime<Utc>,
);

impl MucClock for FixedMucClock {
    fn now(&self) -> DateTime<Utc> {
        self.0
    }
}

/// A deterministic MUC ID source that encodes a counter starting at one.
#[derive(Debug)]
pub struct SequentialMucIds(AtomicU64);

impl Default for SequentialMucIds {
    fn default() -> Self {
        Self(AtomicU64::new(1))
    }
}

impl MucIdSource for SequentialMucIds {
    fn new_uuid(&self) -> Uuid {
        let next = self.0.fetch_add(1, Ordering::Relaxed);
        Uuid::from_u128(u128::from(next))
    }
}

/// The instant and UUID captured for a command before its transaction starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MucRequestFacts {
    /// The instant read from the clock.
    pub at: DateTime<Utc>,
    /// The UUID drawn from the ID source.
    pub id: Uuid,
}

impl MucRequestFacts {
    /// Read the clock once and draw one UUID for the command.
    pub fn prepare(clock: &dyn MucClock, ids: &dyn MucIdSource) -> Self {
        Self {
            at: clock.now(),
            id: ids.new_uuid(),
        }
    }
}

/// A clock and UUID source shared across clones of this value.
#[derive(Clone)]
pub struct MucTimeSources {
    clock: Arc<dyn MucClock>,
    ids: Arc<dyn MucIdSource>,
}

impl MucTimeSources {
    /// Use the supplied clock and UUID source.
    pub fn new(clock: Arc<dyn MucClock>, ids: Arc<dyn MucIdSource>) -> Self {
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

    /// Capture an instant and UUID from the configured sources for a command.
    pub fn prepare_request(&self) -> MucRequestFacts {
        MucRequestFacts::prepare(self.clock.as_ref(), self.ids.as_ref())
    }
}

impl Default for MucTimeSources {
    fn default() -> Self {
        Self::new(Arc::new(SystemMucClock), Arc::new(RandomMucIds))
    }
}

impl fmt::Debug for MucTimeSources {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MucTimeSources")
    }
}

#[cfg(test)]
mod tests;
