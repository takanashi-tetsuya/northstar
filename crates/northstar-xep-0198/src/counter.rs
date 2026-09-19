#![forbid(unsafe_code)]

//! Typed 32-bit handled counters with RFC 6120 / XEP-0198 modular wraparound arithmetic.
//!
//! XEP-0198 defines handled stanza counters as unsigned 32-bit integers modulo 2^32.
//! Sequence numbers increment by 1 for each handled stanza (message, presence, iq).
//! Stream management control elements (<enable/>, <r/>, <a/>, etc.) do NOT advance
//! the handled counter.

use std::fmt;
use std::ops::Deref;

use crate::error::AckError;

/// A typed 32-bit handled stanza sequence counter.
///
/// In XEP-0198, counters are strictly 32-bit unsigned integers modulo 2^32.
/// Comparisons and delta calculations account for unsigned overflow/wraparound.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(transparent)]
pub struct SmCounter(pub u32);

impl SmCounter {
    /// Creates a new counter with the given raw `u32` value.
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Zero-valued counter (initial state before any stanzas are handled).
    pub const ZERO: Self = Self(0);

    /// Gets the underlying raw `u32` value.
    pub const fn get(self) -> u32 {
        self.0
    }

    /// Increments the counter by 1 modulo 2^32.
    #[must_use]
    pub const fn increment(self) -> Self {
        Self(self.0.wrapping_add(1))
    }

    /// Adds `rhs` to the counter modulo 2^32.
    #[must_use]
    pub const fn wrapping_add(self, rhs: u32) -> Self {
        Self(self.0.wrapping_add(rhs))
    }

    /// Subtracts `rhs` from the counter modulo 2^32.
    #[must_use]
    pub const fn wrapping_sub(self, rhs: u32) -> Self {
        Self(self.0.wrapping_sub(rhs))
    }

    /// Advances the counter by 1 in place (modulo 2^32).
    pub fn advance(&mut self) {
        self.0 = self.0.wrapping_add(1);
    }

    /// Advances the counter by `n` in place (modulo 2^32).
    pub fn advance_by(&mut self, n: u32) {
        self.0 = self.0.wrapping_add(n);
    }

    /// Computes the forward distance from `self` to `target` modulo 2^32.
    pub const fn forward_distance_to(self, target: Self) -> u32 {
        target.0.wrapping_sub(self.0)
    }

    /// Validates an incoming acknowledgement counter against the last acknowledged count
    /// and the number of currently outstanding unacknowledged stanzas in the queue.
    ///
    /// Returns:
    /// - `Ok(delta)`: the number of newly acknowledged stanzas to pop from the unacked queue
    ///   (0 represents an idempotent duplicate acknowledgement).
    /// - `Err(AckError)`: the acknowledgement is ahead of sent count or stale.
    pub fn validate_ack(
        last_acked: Self,
        received: Self,
        outstanding: usize,
        outbound_sent: Self,
    ) -> Result<usize, AckError> {
        let delta = received.0.wrapping_sub(last_acked.0) as usize;
        if delta <= outstanding {
            Ok(delta)
        } else {
            Err(AckError::HandledCountTooHigh {
                received: received.0,
                sent: outbound_sent.0,
                outstanding,
            })
        }
    }
}

impl From<u32> for SmCounter {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<SmCounter> for u32 {
    fn from(counter: SmCounter) -> Self {
        counter.0
    }
}

impl Deref for SmCounter {
    type Target = u32;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for SmCounter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

/// Computes the number of newly acknowledged stanzas for an XEP-0198 `h`.
///
/// XEP-0198 counters are modulo 2^32. Because the unacknowledged FIFO is
/// strictly bounded far below 2^31, any forward delta larger than `outstanding` is
/// either an acknowledgement ahead of the server's sent count or a stale
/// acknowledgement from before a wrap. In either case it is invalid.
pub fn acknowledgement_delta(previous: u32, received: u32, outstanding: usize) -> Option<usize> {
    let delta = received.wrapping_sub(previous) as usize;
    (delta <= outstanding).then_some(delta)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_basic_operations() {
        let mut c = SmCounter::new(0);
        assert_eq!(c.get(), 0);
        assert_eq!(*c, 0);

        c.advance();
        assert_eq!(c.get(), 1);

        c.advance_by(5);
        assert_eq!(c.get(), 6);

        let c2 = c.increment();
        assert_eq!(c2.get(), 7);
        assert_eq!(c.get(), 6);

        assert_eq!(c.wrapping_add(10).get(), 16);
        assert_eq!(c.wrapping_sub(2).get(), 4);
    }

    #[test]
    fn counter_wraparound_arithmetic() {
        let max = SmCounter::new(u32::MAX);
        assert_eq!(max.increment().get(), 0);
        assert_eq!(max.wrapping_add(2).get(), 1);

        let zero = SmCounter::new(0);
        assert_eq!(zero.wrapping_sub(1).get(), u32::MAX);

        assert_eq!(max.forward_distance_to(SmCounter::new(2)), 3);
        assert_eq!(
            SmCounter::new(10).forward_distance_to(SmCounter::new(20)),
            10
        );
    }

    #[test]
    fn counter_display_and_conversions() {
        let c = SmCounter::new(42);
        assert_eq!(format!("{c}"), "42");
        let raw: u32 = c.into();
        assert_eq!(raw, 42);
        let from_raw: SmCounter = 42_u32.into();
        assert_eq!(from_raw, c);
    }

    #[test]
    fn acknowledgement_delta_accepts_duplicate_and_valid_progress() {
        assert_eq!(acknowledgement_delta(42, 42, 0), Some(0));
        assert_eq!(acknowledgement_delta(42, 42, 8), Some(0));
        assert_eq!(acknowledgement_delta(10, 12, 2), Some(2));
        assert_eq!(acknowledgement_delta(10, 15, 10), Some(5));
    }

    #[test]
    fn acknowledgement_delta_handles_wraparound() {
        assert_eq!(acknowledgement_delta(u32::MAX - 1, 1, 3), Some(3));
        assert_eq!(acknowledgement_delta(u32::MAX, 0, 1), Some(1));
        assert_eq!(acknowledgement_delta(u32::MAX, 5, 10), Some(6));
        assert_eq!(acknowledgement_delta(u32::MAX, 1, 1), None);
    }

    #[test]
    fn acknowledgement_delta_rejects_ahead_and_stale() {
        assert_eq!(acknowledgement_delta(10, 13, 2), None);
        assert_eq!(acknowledgement_delta(10, 9, 512), None);
        assert_eq!(acknowledgement_delta(10, 11, 0), None);
    }

    #[test]
    fn validate_ack_error_reporting() {
        let last_acked = SmCounter::new(10);
        let sent = SmCounter::new(12);

        // Valid progress of 2
        assert_eq!(
            SmCounter::validate_ack(last_acked, SmCounter::new(12), 2, sent),
            Ok(2)
        );

        // Duplicate ack (progress of 0)
        assert_eq!(
            SmCounter::validate_ack(last_acked, SmCounter::new(10), 2, sent),
            Ok(0)
        );

        // Ahead / impossible ack (received 13 when only 12 sent)
        assert_eq!(
            SmCounter::validate_ack(last_acked, SmCounter::new(13), 2, sent),
            Err(AckError::HandledCountTooHigh {
                received: 13,
                sent: 12,
                outstanding: 2,
            })
        );
    }
}
