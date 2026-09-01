//! Small, dependency-free XEP-0198 counter rules.
//!
//! Keeping this arithmetic outside the session/database implementation lets
//! protocol code, unit tests, and fuzz targets exercise one authoritative
//! definition without pulling the full XMPP session stack into a fuzz binary.

/// Returns the number of newly acknowledged stanzas for an XEP-0198 `h`.
///
/// XEP-0198 counters are modulo 2^32. Because the unacknowledged FIFO is
/// strictly bounded far below 2^31, any delta larger than `outstanding` is
/// either an acknowledgement ahead of the server's sent count or a stale
/// acknowledgement from before a wrap. In either case it is invalid.
pub(crate) fn acknowledgement_delta(
    previous: u32,
    received: u32,
    outstanding: usize,
) -> Option<usize> {
    let delta = received.wrapping_sub(previous) as usize;
    (delta <= outstanding).then_some(delta)
}

#[cfg(test)]
mod tests {
    use super::acknowledgement_delta;

    #[test]
    fn accepts_duplicate_acknowledgements_with_or_without_outstanding_work() {
        assert_eq!(acknowledgement_delta(42, 42, 0), Some(0));
        assert_eq!(acknowledgement_delta(42, 42, 8), Some(0));
    }

    #[test]
    fn accepts_only_the_bounded_forward_window_across_u32_wrap() {
        assert_eq!(acknowledgement_delta(u32::MAX - 1, 1, 3), Some(3));
        assert_eq!(acknowledgement_delta(u32::MAX, 0, 1), Some(1));
        assert_eq!(acknowledgement_delta(u32::MAX, 1, 1), None);
    }

    #[test]
    fn rejects_ahead_and_stale_acknowledgements() {
        assert_eq!(acknowledgement_delta(10, 13, 2), None);
        assert_eq!(acknowledgement_delta(10, 9, 512), None);
        assert_eq!(acknowledgement_delta(10, 11, 0), None);
    }
}
