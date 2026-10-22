#![forbid(unsafe_code)]

//! Pure outbound unacknowledged stanza queue accounting.
//!
//! Stores sent stanzas pending acknowledgement from the remote entity, enforcing
//! maximum stanza count and byte memory bounds. Provides replay slices upon resumption
//! and ordered FIFO removal upon acknowledgement.

use std::collections::VecDeque;

use crate::counter::SmCounter;
use crate::error::QueueError;

/// One unacknowledged stanza entry in the outbound queue.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UnackedEntry<T = String> {
    /// The caller-owned stanza payload (e.g. XML text or structured stanza).
    pub payload: T,
    /// The logical byte size of the stanza entry for capacity accounting.
    pub byte_size: usize,
    /// The outbound sequence counter assigned to this stanza.
    pub sequence: SmCounter,
}

impl<T> UnackedEntry<T> {
    /// Creates a new unacknowledged stanza entry.
    pub const fn new(payload: T, byte_size: usize, sequence: SmCounter) -> Self {
        Self {
            payload,
            byte_size,
            sequence,
        }
    }
}

/// A capacity-bounded FIFO queue of unacknowledged outbound stanzas.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UnackedQueue<T = String> {
    entries: VecDeque<UnackedEntry<T>>,
    max_stanzas: usize,
    max_bytes: usize,
    current_bytes: usize,
}

impl<T> UnackedQueue<T> {
    /// Creates a new unacknowledged queue with the given limits.
    pub fn new(max_stanzas: usize, max_bytes: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            max_stanzas,
            max_bytes,
            current_bytes: 0,
        }
    }

    /// Number of stanzas currently in the unacknowledged queue.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the unacknowledged queue is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Total accounted byte size of all stanzas currently in the queue.
    pub fn total_bytes(&self) -> usize {
        self.current_bytes
    }

    /// Configured maximum stanza limit.
    pub fn max_stanzas(&self) -> usize {
        self.max_stanzas
    }

    /// Configured maximum byte size limit.
    pub fn max_bytes(&self) -> usize {
        self.max_bytes
    }

    /// Read-only slice/reference to the queued entries.
    pub fn entries(&self) -> &VecDeque<UnackedEntry<T>> {
        &self.entries
    }

    /// Appends a new sent stanza to the back of the queue.
    ///
    /// Returns `Err(QueueError)` if appending would exceed `max_stanzas` or `max_bytes`.
    pub fn push_back(
        &mut self,
        payload: T,
        byte_size: usize,
        sequence: SmCounter,
    ) -> Result<(), QueueError> {
        if self.entries.len() >= self.max_stanzas {
            return Err(QueueError::MaxStanzasExceeded {
                current: self.entries.len(),
                max: self.max_stanzas,
            });
        }
        let new_bytes = self
            .current_bytes
            .checked_add(byte_size)
            .ok_or(QueueError::ByteSizeOverflow)?;
        if new_bytes > self.max_bytes {
            return Err(QueueError::MaxBytesExceeded {
                current: new_bytes,
                max: self.max_bytes,
            });
        }

        self.current_bytes = new_bytes;
        self.entries
            .push_back(UnackedEntry::new(payload, byte_size, sequence));
        Ok(())
    }

    /// Acknowledges and removes `count` stanzas from the front of the queue in FIFO order.
    ///
    /// Returns the removed entries. If `count >= len()`, all entries are removed.
    pub fn acknowledge(&mut self, count: usize) -> Vec<UnackedEntry<T>> {
        let to_remove = count.min(self.entries.len());
        let mut acknowledged = Vec::with_capacity(to_remove);
        for _ in 0..to_remove {
            if let Some(entry) = self.entries.pop_front() {
                self.current_bytes = self.current_bytes.saturating_sub(entry.byte_size);
                acknowledged.push(entry);
            }
        }
        acknowledged
    }

    /// Iterator over references to the queued stanza payloads for replay upon resumption.
    pub fn replay_payloads(&self) -> impl Iterator<Item = &T> {
        self.entries.iter().map(|entry| &entry.payload)
    }

    /// Clears the queue, releasing all entries and resetting byte accounting to 0.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.current_bytes = 0;
    }
}

impl<T: Clone> UnackedQueue<T> {
    /// Pure helper to stage an append suffix (e.g. for MUC synthetic notifications or recovery stanzas)
    /// without taking destructive ownership of the active queue.
    ///
    /// Validates that `self.len() + suffix.len() <= max_stanzas` and total bytes `<= max_bytes`.
    /// Returns `(staged_queue, new_outbound_sequence)`.
    pub fn stage_suffix(
        &self,
        suffix: Vec<(T, usize)>,
        mut start_sequence: SmCounter,
    ) -> Result<(Self, SmCounter), QueueError> {
        let total_stanzas = self
            .entries
            .len()
            .checked_add(suffix.len())
            .ok_or(QueueError::ByteSizeOverflow)?;
        if total_stanzas > self.max_stanzas {
            return Err(QueueError::MaxStanzasExceeded {
                current: total_stanzas,
                max: self.max_stanzas,
            });
        }

        let suffix_bytes = suffix
            .iter()
            .try_fold(0usize, |acc, (_, size)| acc.checked_add(*size))
            .ok_or(QueueError::ByteSizeOverflow)?;
        let total_bytes = self
            .current_bytes
            .checked_add(suffix_bytes)
            .ok_or(QueueError::ByteSizeOverflow)?;
        if total_bytes > self.max_bytes {
            return Err(QueueError::MaxBytesExceeded {
                current: total_bytes,
                max: self.max_bytes,
            });
        }

        let mut staged = self.clone();
        for (payload, byte_size) in suffix {
            start_sequence.advance();
            staged.push_back(payload, byte_size, start_sequence)?;
        }

        Ok((staged, start_sequence))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unacked_queue_push_and_acknowledge() {
        let mut queue = UnackedQueue::new(10, 1000);
        assert!(queue.is_empty());
        assert_eq!(queue.len(), 0);
        assert_eq!(queue.total_bytes(), 0);

        queue
            .push_back("<msg-1/>".to_string(), 8, SmCounter::new(1))
            .unwrap();
        queue
            .push_back("<msg-2/>".to_string(), 8, SmCounter::new(2))
            .unwrap();
        queue
            .push_back("<msg-3/>".to_string(), 8, SmCounter::new(3))
            .unwrap();

        assert_eq!(queue.len(), 3);
        assert_eq!(queue.total_bytes(), 24);

        // Acknowledge first 2 stanzas
        let acked = queue.acknowledge(2);
        assert_eq!(acked.len(), 2);
        assert_eq!(acked[0].payload, "<msg-1/>");
        assert_eq!(acked[0].sequence.get(), 1);
        assert_eq!(acked[1].payload, "<msg-2/>");
        assert_eq!(acked[1].sequence.get(), 2);

        assert_eq!(queue.len(), 1);
        assert_eq!(queue.total_bytes(), 8);
        assert_eq!(queue.entries()[0].payload, "<msg-3/>");

        // Idempotent/zero ack
        let acked_zero = queue.acknowledge(0);
        assert!(acked_zero.is_empty());
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn unacked_queue_capacity_limits() {
        let mut queue = UnackedQueue::new(2, 20);

        queue
            .push_back("12345678".to_string(), 8, SmCounter::new(1))
            .unwrap();
        queue
            .push_back("12345678".to_string(), 8, SmCounter::new(2))
            .unwrap();

        // Exceeds stanza limit
        assert!(matches!(
            queue.push_back("x".to_string(), 1, SmCounter::new(3)),
            Err(QueueError::MaxStanzasExceeded { current: 2, max: 2 })
        ));

        // Reopen stanza capacity by acking 1
        queue.acknowledge(1);
        assert_eq!(queue.len(), 1);
        assert_eq!(queue.total_bytes(), 8);

        // Exceeds byte limit (8 + 15 = 23 > 20)
        assert!(matches!(
            queue.push_back("123456789012345".to_string(), 15, SmCounter::new(3)),
            Err(QueueError::MaxBytesExceeded {
                current: 23,
                max: 20
            })
        ));
    }

    #[test]
    fn stage_suffix_accounting() {
        let mut queue = UnackedQueue::new(5, 50);
        queue
            .push_back("<m1/>".to_string(), 5, SmCounter::new(1))
            .unwrap();
        queue
            .push_back("<m2/>".to_string(), 5, SmCounter::new(2))
            .unwrap();

        let suffix = vec![("<m3/>".to_string(), 5), ("<m4/>".to_string(), 5)];

        let (staged, new_h) = queue.stage_suffix(suffix, SmCounter::new(2)).unwrap();
        assert_eq!(staged.len(), 4);
        assert_eq!(staged.total_bytes(), 20);
        assert_eq!(new_h.get(), 4);
        let payloads: Vec<&String> = staged.replay_payloads().collect();
        assert_eq!(payloads, vec!["<m1/>", "<m2/>", "<m3/>", "<m4/>"]);

        // Original queue remains untouched
        assert_eq!(queue.len(), 2);
    }
}
