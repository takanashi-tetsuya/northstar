//! Recipient, stream-management, MIX handoff and BOSH evidence and the evidence sequence.

use super::*;

#[derive(Serialize)]
#[serde(tag = "kind")]
pub(crate) enum RecipientEvidence {
    None,
    Native {
        native: Box<NativeEvidence>,
    },
    Sm {
        native_writes: Vec<NativeEvidence>,
        sm_turns: Vec<SmEvidence>,
        fifo_after: Vec<Slot>,
        outbound_h: u32,
        acked_h: u32,
        mix_handoffs: Vec<MixHandoff>,
    },
    Bosh {
        bosh: Box<BoshEvidence>,
        sm_turns: Vec<SmEvidence>,
        sm_fifo_after: Vec<Slot>,
        sm_outbound_h: Option<u32>,
        sm_acked_h: Option<u32>,
    },
    NativeReplacement {
        old: Box<NativeEvidence>,
        replacement: Box<NativeEvidence>,
        row_events: Vec<RowEvent>,
        row_after: Option<Source>,
        replacement_dequeued: Dequeue,
    },
}

#[derive(Clone, Serialize)]
#[serde(tag = "kind")]
pub(crate) enum RowEvent {
    Replace {
        seq: u32,
        recipient_id: Id,
        message_id: Id,
        before_claim_id: Id,
        after_claim_id: Id,
    },
    AuthorityRead {
        seq: u32,
        source: Source,
        current_claim_id: Option<Id>,
        matches: bool,
    },
    Delete {
        seq: u32,
        source: Source,
    },
}

#[derive(Clone, Serialize)]
pub(crate) struct DriverPoll {
    pub(crate) seq: u32,
    pub(crate) result: &'static str,
}

#[derive(Clone, Serialize)]
#[serde(tag = "kind")]
pub(crate) enum SmPurpose {
    Record,
    Checkpoint,
    Acknowledge { h: u32 },
}
#[derive(Clone, Serialize)]
pub(crate) struct SmScope {
    pub(crate) purpose: SmPurpose,
    pub(crate) session_id: Option<Id>,
    pub(crate) connection_id: Id,
    pub(crate) inbound_h: u32,
    pub(crate) outbound_h: u32,
    pub(crate) acked_h: u32,
    pub(crate) queued: u32,
}
#[derive(Clone, Serialize)]
pub(crate) struct SmBinding {
    pub(crate) session_id: Option<Id>,
    pub(crate) connection_id: Id,
    pub(crate) inbound_h: u32,
    pub(crate) outbound_h: u32,
    pub(crate) acked_h: u32,
    pub(crate) whole: Vec<Option<Source>>,
    pub(crate) acknowledged: Vec<Option<Source>>,
    pub(crate) remaining: Vec<Option<Source>>,
}
#[derive(Clone, Serialize)]
#[serde(tag = "kind")]
pub(crate) enum SmHDecision {
    NotRequested,
    Invalid,
    Prefix { count: u32 },
}
#[derive(Clone, Serialize)]
#[serde(tag = "kind")]
pub(crate) enum SmFact {
    Checkpoint {
        rotations: Vec<Rotation>,
        settled: Vec<Source>,
    },
    UnpersistedAck {
        deleted: Vec<Source>,
        absent_unclaimed: Vec<Source>,
    },
}
#[derive(Clone, Serialize)]
#[serde(tag = "kind")]
pub(crate) enum SmKnowledge {
    NotRequested,
    NoCommitRequested,
    NoPersistence,
    RollbackCallEntered,
    RollbackKnown,
    CommitCallEntered { fact: SmFact },
    ReceiptKnown { fact: SmFact },
}
#[derive(Clone, Serialize)]
pub(crate) struct SmState {
    pub(crate) scope: SmScope,
    pub(crate) binding: Option<SmBinding>,
    pub(crate) h_decision: SmHDecision,
    pub(crate) knowledge: SmKnowledge,
    pub(crate) appended: bool,
    pub(crate) restored: bool,
    pub(crate) ownership_applied: bool,
    pub(crate) acknowledged_h_applied: Option<u32>,
    pub(crate) notification_attempted: bool,
    pub(crate) capacity_completed: Option<bool>,
    pub(crate) returned_updated: Option<bool>,
    pub(crate) returned_error: bool,
    pub(crate) record_managed_by_sm: Option<bool>,
    pub(crate) terminal: Option<&'static str>,
}
#[derive(Clone, Serialize)]
pub(crate) struct SmPrefix {
    pub(crate) seq: u32,
    pub(crate) state: SmState,
}
#[derive(Serialize)]
pub(crate) struct SmEvidence {
    #[serde(flatten)]
    pub(crate) state: SmState,
    pub(crate) prefixes: Vec<SmPrefix>,
    pub(crate) polls: Vec<DriverPoll>,
}
#[derive(Clone, Serialize)]
#[serde(tag = "kind")]
pub(crate) enum MixHandoffResult {
    SmPersisted { session_id: Id },
    BoshPersisted { session_id: Id },
    SocketFenced { connection_id: Id },
    Empty,
    Closed,
}
#[derive(Clone, Serialize)]
pub(crate) struct MixHandoff {
    pub(crate) seq: u32,
    pub(crate) delivery_id: Id,
    pub(crate) result: MixHandoffResult,
}

#[derive(Clone, Serialize)]
pub(crate) struct BoshScope {
    pub(crate) session_id: Id,
    pub(crate) ttl_seconds: u64,
    pub(crate) kind: &'static str,
}
#[derive(Clone, Serialize)]
#[serde(tag = "kind")]
pub(crate) enum BoshTransferKnowledge {
    NoCommitRequested,
    CommitCallEntered { source: Source },
    ReceiptKnown { source: Source },
}
#[derive(Clone, Serialize)]
pub(crate) struct BoshTransferSnapshot {
    pub(crate) source: Source,
    pub(crate) knowledge: BoshTransferKnowledge,
    pub(crate) returned_source: Option<Source>,
    pub(crate) return_matches_receipt: bool,
    pub(crate) local_entered: bool,
    pub(crate) source_applied: bool,
    pub(crate) notification_attempted: bool,
    pub(crate) queue_accepted: Option<bool>,
}
#[derive(Clone, Serialize)]
#[serde(tag = "kind")]
pub(crate) enum BoshBindKnowledge {
    NotRequired,
    NoCommitRequested,
    CommitCallEntered { membership: Membership },
    ReceiptKnown { membership: Membership },
}
#[derive(Clone, Serialize)]
pub(crate) struct BoshBindAttempt {
    pub(crate) selected_end: Option<u32>,
    pub(crate) selected_len: u32,
    pub(crate) sources: Option<Vec<Source>>,
    pub(crate) knowledge: BoshBindKnowledge,
    pub(crate) returned: Option<Membership>,
    pub(crate) return_matches: bool,
    pub(crate) superseded_message: Option<Id>,
    pub(crate) restored: bool,
    pub(crate) restore_matches: bool,
    pub(crate) removed_indices: Vec<u32>,
}
#[derive(Clone, Serialize)]
pub(crate) struct BoshResponseSnapshot {
    pub(crate) rid: u64,
    pub(crate) kind: &'static str,
    pub(crate) lineage: Vec<Option<Source>>,
    pub(crate) removed: Vec<bool>,
    pub(crate) attempts: Vec<BoshBindAttempt>,
    pub(crate) construction_restored: u32,
    pub(crate) exposure_entered: bool,
    pub(crate) responder_calls: u32,
    pub(crate) accepted_responders: u32,
    pub(crate) refused_responders: u32,
    pub(crate) control_calls: u32,
    pub(crate) control_accepted: u32,
    pub(crate) control_refused: u32,
    pub(crate) empty_cache_evictions: u32,
    pub(crate) bookkeeping: bool,
    pub(crate) cached: bool,
}
#[derive(Clone, Serialize)]
pub(crate) struct BoshExpected {
    pub(crate) rid: u64,
    pub(crate) membership: Membership,
}
#[derive(Clone, Serialize)]
pub(crate) struct BoshRenewSnapshot {
    pub(crate) expected: Option<BoshExpected>,
    pub(crate) knowledge: &'static str,
    pub(crate) returned: bool,
    pub(crate) return_matches: bool,
    pub(crate) ack_issued: bool,
    pub(crate) replay_calls: u32,
    pub(crate) replay_accepted: u32,
    pub(crate) replay_refused: u32,
    pub(crate) replay_bookkeeping: bool,
}
#[derive(Clone, Serialize)]
pub(crate) struct BoshAckSnapshot {
    pub(crate) rid: u64,
    pub(crate) knowledge: &'static str,
    pub(crate) deleted: Option<Vec<DeletedSource>>,
    pub(crate) returned: bool,
    pub(crate) return_matches: bool,
    pub(crate) cache_evictions: u32,
    pub(crate) receipt_calls: u32,
    pub(crate) receipts_sent: u32,
    pub(crate) receipts_refused: u32,
}
#[derive(Clone, Serialize)]
pub(crate) struct BoshState {
    pub(crate) scope: BoshScope,
    pub(crate) transfers: Vec<BoshTransferSnapshot>,
    pub(crate) responses: Vec<BoshResponseSnapshot>,
    pub(crate) renewals: Vec<BoshRenewSnapshot>,
    pub(crate) acknowledgements: Vec<BoshAckSnapshot>,
    pub(crate) terminal: Option<&'static str>,
    pub(crate) keep_running: Option<bool>,
}
#[derive(Clone, Serialize)]
#[serde(tag = "kind")]
pub(crate) enum BoshAssociation {
    Outbound {
        item_index: u32,
        item: Slot,
    },
    Request {
        phase: &'static str,
        rid: u64,
        ack: Option<u64>,
        sid: Option<String>,
        fingerprint_hex: String,
    },
}
#[derive(Clone, Serialize)]
pub(crate) struct BoshPrefix {
    pub(crate) seq: u32,
    pub(crate) state: BoshState,
}
#[derive(Clone, Serialize)]
pub(crate) struct BoshOwnerEvidence {
    pub(crate) owner_index: u32,
    pub(crate) association: BoshAssociation,
    #[serde(flatten)]
    pub(crate) state: BoshState,
    pub(crate) prefixes: Vec<BoshPrefix>,
    pub(crate) polls: Vec<DriverPoll>,
}
#[derive(Clone, Serialize)]
pub(crate) struct BoshTransferCall {
    pub(crate) seq: u32,
    pub(crate) owner_index: u32,
    pub(crate) source: Source,
    pub(crate) returned_source: Option<Source>,
}
#[derive(Clone, Serialize)]
pub(crate) struct BoshBindCall {
    pub(crate) seq: u32,
    pub(crate) owner_index: u32,
    pub(crate) rid: u64,
    pub(crate) sources: Vec<Source>,
    pub(crate) returned_membership: Option<Membership>,
}
#[derive(Clone, Serialize)]
pub(crate) struct BoshRenewCall {
    pub(crate) seq: u32,
    pub(crate) owner_index: u32,
    pub(crate) expected: Option<BoshExpected>,
    pub(crate) returned: Option<bool>,
}
#[derive(Clone, Serialize)]
pub(crate) struct BoshAckCall {
    pub(crate) seq: u32,
    pub(crate) owner_index: u32,
    pub(crate) rid: u64,
    pub(crate) returned: Option<bool>,
}
#[derive(Clone, Serialize)]
#[serde(tag = "kind")]
pub(crate) enum BoshResponseResult {
    Received { body_hex: String },
    Empty,
    Closed,
}
#[derive(Clone, Serialize)]
pub(crate) struct BoshResponseReceiver {
    pub(crate) seq: u32,
    pub(crate) owner_index: u32,
    pub(crate) rid: u64,
    pub(crate) phase: &'static str,
    pub(crate) receiver_index: u32,
    pub(crate) result: BoshResponseResult,
}
#[derive(Clone, Serialize)]
pub(crate) struct BoshCacheEntry {
    pub(crate) rid: u64,
    pub(crate) fingerprint_hex: String,
    pub(crate) membership: Membership,
    pub(crate) body_hex: String,
    pub(crate) response_bytes: u32,
    pub(crate) replays: u32,
    pub(crate) transport_receipt_count: u32,
}
#[derive(Clone, Serialize)]
pub(crate) struct BoshCacheHistory {
    pub(crate) seq: u32,
    pub(crate) entries: Vec<BoshCacheEntry>,
}
#[derive(Clone, Serialize)]
pub(crate) struct BoshTransportReceipt {
    pub(crate) seq: u32,
    pub(crate) item_index: u32,
    pub(crate) result: &'static str,
}
#[derive(Default, Serialize)]
pub(crate) struct BoshEvidence {
    pub(crate) owners: Vec<BoshOwnerEvidence>,
    pub(crate) transfer_calls: Vec<BoshTransferCall>,
    pub(crate) bind_calls: Vec<BoshBindCall>,
    pub(crate) renew_calls: Vec<BoshRenewCall>,
    pub(crate) ack_calls: Vec<BoshAckCall>,
    pub(crate) response_receivers: Vec<BoshResponseReceiver>,
    pub(crate) cache_history: Vec<BoshCacheHistory>,
    pub(crate) fifo_after: Vec<Slot>,
    pub(crate) output_bytes: u32,
    pub(crate) highest_responded: u64,
    pub(crate) mix_handoffs: Vec<MixHandoff>,
    pub(crate) transport_receipts: Vec<BoshTransportReceipt>,
}

/// One bounded observation counter across the case. It records call order;
/// it neither advances futures nor supplies permissions or domain verdicts.
#[derive(Default)]
pub(crate) struct Sequence {
    pub(super) observations: u32,
    pub(super) polls: u32,
}
impl Sequence {
    pub(crate) fn next(&mut self) -> u32 {
        assert!(
            (self.observations as usize) < MAX_FACTS,
            "direct observation cap exceeded"
        );
        self.observations += 1;
        self.observations
    }
    pub(crate) fn polled<T>(&mut self, actual: &std::task::Poll<T>) -> DriverPoll {
        assert!(self.polls < 64, "direct driver poll cap exceeded");
        self.polls += 1;
        DriverPoll {
            seq: self.next(),
            result: if actual.is_ready() {
                "Ready"
            } else {
                "Pending"
            },
        }
    }
}
