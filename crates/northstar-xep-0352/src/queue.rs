#![forbid(unsafe_code)]

//! Generic bounded deferred queue with coalescing and explicit overflow decisions.

use crate::policy::{CoalescingKey, CsiPolicyConfig, OverflowPolicy};
use std::collections::VecDeque;

/// A single entry stored within the deferred queue.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DeferredEntry<T> {
    /// Caller-owned payload (e.g., XML string or `OutboundItem`).
    pub payload: T,
    /// Coalescing key string if this item is eligible for replacement.
    pub key: Option<String>,
    /// Byte size contribution of this entry.
    pub byte_size: usize,
    /// Monotonically increasing sequence number for deterministic FIFO tracking.
    pub sequence: u64,
}

/// Explicit outcome of attempting to enqueue an item into the deferred queue.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EnqueueResult<T> {
    /// Item was successfully enqueued.
    Enqueued {
        /// If this item replaced a previously queued item with the same coalescing key,
        /// the replaced item is returned here (no silent loss).
        replaced_previous: Option<T>,
    },
    /// Item caused the queue capacity to overflow; the explicit overflow policy decision is returned.
    Overflow {
        /// Explicit overflow action and affected items.
        decision: OverflowDecision<T>,
    },
    /// Item was discarded by policy (e.g. typing notifications when discard is enabled).
    Discarded {
        /// The discarded item.
        discarded_item: T,
    },
}

impl<T> EnqueueResult<T> {
    /// Returns `true` if the item was successfully enqueued.
    pub const fn is_enqueued(&self) -> bool {
        matches!(self, Self::Enqueued { .. })
    }

    /// Returns `true` if the item resulted in an overflow decision.
    pub const fn is_overflow(&self) -> bool {
        matches!(self, Self::Overflow { .. })
    }

    /// Returns `true` if the item was discarded.
    pub const fn is_discarded(&self) -> bool {
        matches!(self, Self::Discarded { .. })
    }
}

/// Explicit decision and displaced items when queue bounds are exceeded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OverflowDecision<T> {
    /// Stream should be disconnected due to queue overflow.
    Disconnect {
        /// The unhandled item that triggered overflow.
        unhandled_item: T,
        /// Total number of items in queue at time of overflow.
        queued_count: usize,
        /// Total bytes in queue at time of overflow.
        queued_bytes: usize,
    },
    /// The incoming item was rejected and not added to the queue.
    Reject {
        /// The rejected item.
        rejected_item: T,
    },
    /// The incoming item should be routed to persistent/adapter storage.
    Persist {
        /// The item to persist.
        item_to_persist: T,
    },
    /// Oldest items were evicted to make room for the new item.
    EvictedOldest {
        /// The items evicted from the front of the queue (must be audited or persisted by adapter).
        evicted: Vec<T>,
        /// The newly enqueued item's replaced predecessor, if it coalesced.
        replaced_previous: Option<T>,
    },
}

/// Generic bounded FIFO queue with soft-signal coalescing.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DeferredQueue<T> {
    entries: VecDeque<DeferredEntry<T>>,
    total_bytes: usize,
    config: CsiPolicyConfig,
    next_sequence: u64,
}

impl<T> Default for DeferredQueue<T> {
    fn default() -> Self {
        Self::new(CsiPolicyConfig::default())
    }
}

impl<T> DeferredQueue<T> {
    /// Creates a new deferred queue with the provided policy configuration.
    pub fn new(config: CsiPolicyConfig) -> Self {
        Self {
            entries: VecDeque::new(),
            total_bytes: 0,
            config,
            next_sequence: 0,
        }
    }

    /// Creates a new deferred queue with explicit count and byte bounds.
    pub fn with_bounds(max_stanzas: usize, max_bytes: usize) -> Self {
        let config = CsiPolicyConfig {
            max_deferred_stanzas: max_stanzas,
            max_deferred_bytes: max_bytes,
            ..CsiPolicyConfig::default()
        };
        Self::new(config)
    }

    /// Returns the number of items currently in the queue.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the total bytes of all items currently in the queue.
    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    /// Reference to the active policy configuration.
    pub fn config(&self) -> &CsiPolicyConfig {
        &self.config
    }

    /// Mutable reference to the active policy configuration.
    pub fn config_mut(&mut self) -> &mut CsiPolicyConfig {
        &mut self.config
    }

    /// Clears the queue and resets byte counter.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.total_bytes = 0;
    }

    /// Read-only iterator over queued entries.
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.entries.iter().map(|entry| &entry.payload)
    }

    /// Read-only access to inner entry queue.
    pub fn entries(&self) -> &VecDeque<DeferredEntry<T>> {
        &self.entries
    }

    /// Enqueue a caller-owned item with optional coalescing key and byte size.
    pub fn enqueue(
        &mut self,
        payload: T,
        byte_size: usize,
        key: Option<CoalescingKey>,
    ) -> EnqueueResult<T> {
        let key_str = key.map(|k| k.as_key_string());

        // Check if an existing entry with the same coalescing key can be updated in-place
        if let Some(ref k) = key_str {
            if let Some(pos) = self
                .entries
                .iter()
                .position(|e| e.key.as_deref() == Some(k))
            {
                let old_size = self.entries[pos].byte_size;
                let new_total_bytes = self
                    .total_bytes
                    .saturating_sub(old_size)
                    .saturating_add(byte_size);

                if new_total_bytes <= self.config.max_deferred_bytes {
                    let sequence = self.entries[pos].sequence;
                    let old_entry = std::mem::replace(
                        &mut self.entries[pos],
                        DeferredEntry {
                            payload,
                            key: Some(k.clone()),
                            byte_size,
                            sequence,
                        },
                    );
                    self.total_bytes = new_total_bytes;
                    return EnqueueResult::Enqueued {
                        replaced_previous: Some(old_entry.payload),
                    };
                }

                // Replacing this item would exceed max_deferred_bytes
                return match self.config.overflow_policy {
                    OverflowPolicy::Disconnect => EnqueueResult::Overflow {
                        decision: OverflowDecision::Disconnect {
                            unhandled_item: payload,
                            queued_count: self.entries.len(),
                            queued_bytes: self.total_bytes,
                        },
                    },
                    OverflowPolicy::Reject => EnqueueResult::Overflow {
                        decision: OverflowDecision::Reject {
                            rejected_item: payload,
                        },
                    },
                    OverflowPolicy::Persist => EnqueueResult::Overflow {
                        decision: OverflowDecision::Persist {
                            item_to_persist: payload,
                        },
                    },
                    OverflowPolicy::DropOldest => {
                        let mut evicted = Vec::new();
                        let mut current_bytes = new_total_bytes;

                        // Remove from front until under byte limit
                        while current_bytes > self.config.max_deferred_bytes
                            && !self.entries.is_empty()
                        {
                            if let Some(removed) = self.entries.pop_front() {
                                current_bytes = current_bytes.saturating_sub(removed.byte_size);
                                evicted.push(removed.payload);
                            }
                        }

                        // Now find the target key again or append if it was popped
                        let replaced_previous = if let Some(new_pos) = self
                            .entries
                            .iter()
                            .position(|e| e.key.as_deref() == Some(k))
                        {
                            let sequence = self.entries[new_pos].sequence;
                            let old_entry = std::mem::replace(
                                &mut self.entries[new_pos],
                                DeferredEntry {
                                    payload,
                                    key: Some(k.clone()),
                                    byte_size,
                                    sequence,
                                },
                            );
                            Some(old_entry.payload)
                        } else {
                            let seq = self.next_sequence;
                            self.next_sequence = self.next_sequence.saturating_add(1);
                            self.entries.push_back(DeferredEntry {
                                payload,
                                key: Some(k.clone()),
                                byte_size,
                                sequence: seq,
                            });
                            None
                        };

                        self.total_bytes = current_bytes;
                        EnqueueResult::Overflow {
                            decision: OverflowDecision::EvictedOldest {
                                evicted,
                                replaced_previous,
                            },
                        }
                    }
                };
            }
        }

        // New item insertion check
        let would_exceed_count = self.entries.len() >= self.config.max_deferred_stanzas;
        let would_exceed_bytes =
            self.total_bytes.saturating_add(byte_size) > self.config.max_deferred_bytes;

        if !would_exceed_count && !would_exceed_bytes {
            let seq = self.next_sequence;
            self.next_sequence = self.next_sequence.saturating_add(1);
            self.total_bytes = self.total_bytes.saturating_add(byte_size);
            self.entries.push_back(DeferredEntry {
                payload,
                key: key_str,
                byte_size,
                sequence: seq,
            });
            return EnqueueResult::Enqueued {
                replaced_previous: None,
            };
        }

        // Handle overflow for new item
        match self.config.overflow_policy {
            OverflowPolicy::Disconnect => EnqueueResult::Overflow {
                decision: OverflowDecision::Disconnect {
                    unhandled_item: payload,
                    queued_count: self.entries.len(),
                    queued_bytes: self.total_bytes,
                },
            },
            OverflowPolicy::Reject => EnqueueResult::Overflow {
                decision: OverflowDecision::Reject {
                    rejected_item: payload,
                },
            },
            OverflowPolicy::Persist => EnqueueResult::Overflow {
                decision: OverflowDecision::Persist {
                    item_to_persist: payload,
                },
            },
            OverflowPolicy::DropOldest => {
                let mut evicted = Vec::new();
                while (self.entries.len() >= self.config.max_deferred_stanzas
                    || self.total_bytes.saturating_add(byte_size) > self.config.max_deferred_bytes)
                    && !self.entries.is_empty()
                {
                    if let Some(removed) = self.entries.pop_front() {
                        self.total_bytes = self.total_bytes.saturating_sub(removed.byte_size);
                        evicted.push(removed.payload);
                    }
                }

                let seq = self.next_sequence;
                self.next_sequence = self.next_sequence.saturating_add(1);
                self.total_bytes = self.total_bytes.saturating_add(byte_size);
                self.entries.push_back(DeferredEntry {
                    payload,
                    key: key_str,
                    byte_size,
                    sequence: seq,
                });

                EnqueueResult::Overflow {
                    decision: OverflowDecision::EvictedOldest {
                        evicted,
                        replaced_previous: None,
                    },
                }
            }
        }
    }

    /// Drains all queued payloads in deterministic FIFO order and resets byte counter.
    pub fn drain_all(&mut self) -> Vec<T> {
        self.total_bytes = 0;
        self.entries.drain(..).map(|e| e.payload).collect()
    }

    /// Drains all entries (including metadata and sequence numbers) in deterministic FIFO order.
    pub fn drain_entries(&mut self) -> Vec<DeferredEntry<T>> {
        self.total_bytes = 0;
        self.entries.drain(..).collect()
    }
}
