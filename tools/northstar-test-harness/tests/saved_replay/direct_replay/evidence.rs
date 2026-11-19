//! Evidence envelope and admission, direct, original and native delivery evidence.

use super::*;

// These wire types describe actual observations, never expected verdicts. In
// particular, writer/flush facts and the owner's permission remain independent.
#[derive(Serialize)]
pub(crate) struct Envelope {
    pub(crate) schema: &'static str,
    pub(crate) entry: &'static str,
    pub(crate) input_sha256: String,
    pub(crate) rejection: Option<RejectedInput>,
    pub(crate) execution: Option<Execution>,
    pub(crate) originals: Vec<OriginalEvidence>,
    pub(crate) recipient: Option<RecipientEvidence>,
}
#[derive(Serialize)]
pub(crate) struct RejectedInput {
    pub(crate) class: &'static str,
    pub(crate) reason: Rejection,
}
#[derive(Clone, Copy, Serialize)]
pub(crate) enum Execution {
    Complete,
    Cancelled,
}
impl Envelope {
    pub(crate) fn rejected(input: &[u8], reason: Rejection) -> Self {
        Self {
            schema: EVIDENCE_SCHEMA,
            entry: ENTRY,
            input_sha256: digest(input),
            rejection: Some(RejectedInput {
                class: "InvalidScenario",
                reason,
            }),
            execution: None,
            originals: vec![],
            recipient: None,
        }
    }
}
pub(crate) fn emit(envelope: &Envelope) -> anyhow::Result<()> {
    let payload = serde_json::to_vec(envelope)?;
    anyhow::ensure!(
        payload.len() <= MAX_FRAME,
        "direct evidence frame cap exceeded"
    );
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "\x1eNORTHSTAR_DIRECT_CASE_V1 {}", payload.len())?;
    stdout.write_all(&payload)?;
    stdout.write_all(b"\n\x1eEND\n")?;
    stdout.flush()?;
    Ok(())
}
#[derive(Clone, Serialize)]
pub(crate) struct Correlation {
    pub(crate) operation_id: Id,
    pub(crate) effect: u64,
    pub(crate) generation: u64,
    pub(crate) attempt: u64,
}
impl From<northstar_abuse_policy::admission_execution::Correlation> for Correlation {
    fn from(value: northstar_abuse_policy::admission_execution::Correlation) -> Self {
        Self {
            operation_id: Id(value.operation),
            effect: value.effect,
            generation: value.generation,
            attempt: u64::from(value.attempt),
        }
    }
}
#[derive(Clone, Serialize)]
pub(crate) struct FenceEvidence {
    pub(crate) admission_key_hex: String,
    pub(crate) payload_mac_hex: String,
    pub(crate) lease_token: Id,
}
impl From<&northstar_abuse_policy::admission_transaction::AdmissionFence> for FenceEvidence {
    fn from(value: &northstar_abuse_policy::admission_transaction::AdmissionFence) -> Self {
        Self {
            admission_key_hex: hex(&value.admission_key),
            payload_mac_hex: hex(&value.payload_mac),
            lease_token: Id(value.lease_token),
        }
    }
}
#[derive(Clone, Serialize)]
#[serde(tag = "kind")]
pub(crate) enum AdmissionFact {
    Reserved {
        fence: FenceEvidence,
    },
    Finalized {
        fence: FenceEvidence,
        result: &'static str,
    },
}
#[derive(Clone, Serialize)]
pub(crate) struct AdmissionCommit {
    pub(crate) correlation: Correlation,
    pub(crate) scope: &'static str,
    pub(crate) fact: AdmissionFact,
}
#[derive(Clone, Serialize)]
#[serde(tag = "kind")]
pub(crate) enum AdmissionKnowledge {
    NoCommitRequested,
    CommitCallEntered { prepared: AdmissionCommit },
    ReceiptKnown { receipt: AdmissionCommit },
}
#[derive(Clone, Serialize)]
#[serde(tag = "kind")]
pub(crate) enum AdmissionReturned {
    Proceed { fence: FenceEvidence },
    AcceptPending,
    Error,
}
#[derive(Clone, Serialize)]
pub(crate) struct AdmissionEvidence {
    pub(crate) correlation: Correlation,
    pub(crate) started: bool,
    pub(crate) knowledge: AdmissionKnowledge,
    pub(crate) returned: Option<AdmissionReturned>,
}
#[derive(Clone, Serialize)]
pub(crate) struct DirectPrepared {
    pub(crate) correlation: Correlation,
    pub(crate) transaction: Transaction,
    pub(crate) admitted_mode: Mode,
}
#[derive(Clone, Serialize)]
pub(crate) struct DirectReceipt {
    pub(crate) prepared: DirectPrepared,
}
#[derive(Clone, Serialize)]
#[serde(tag = "kind")]
pub(crate) enum DirectKnowledge {
    NoCommitRequested,
    CommitCallEntered { prepared: DirectPrepared },
    ReceiptKnown { receipt: DirectReceipt },
}
#[derive(Clone, Serialize)]
#[serde(tag = "kind")]
pub(crate) enum CommitResult {
    Stored {
        archive_written: bool,
        recipient_id: Id,
        delivery_id: Id,
    },
    Replay,
    AccountUnavailable,
}
#[derive(Clone, Serialize)]
pub(crate) struct DirectReturned {
    pub(crate) commit: CommitResult,
    pub(crate) mode: Mode,
    pub(crate) live_claim_id: Option<Id>,
}
#[derive(Clone, Serialize)]
pub(crate) struct DirectEvidence {
    pub(crate) correlation: Correlation,
    pub(crate) started: bool,
    pub(crate) knowledge: DirectKnowledge,
    pub(crate) returned: Option<DirectReturned>,
    pub(crate) preserved_transaction: Option<Transaction>,
    pub(crate) application_error: bool,
}
#[derive(Clone, Serialize)]
pub(crate) struct ArchiveEvidence {
    pub(crate) archive_id: Id,
    pub(crate) owner_id: Id,
    pub(crate) peer_jid: String,
    pub(crate) stanza_id: Option<String>,
    pub(crate) encrypted: bool,
    pub(crate) xml: String,
}
#[derive(Clone, Serialize)]
pub(crate) struct Projection {
    pub(crate) message_type: String,
    pub(crate) origin_id: Option<String>,
    pub(crate) rated: bool,
    pub(crate) normalized_payload: Option<String>,
    pub(crate) live_xml: String,
    pub(crate) stored_xml: String,
    pub(crate) archives: Vec<ArchiveEvidence>,
}
#[derive(Clone, Serialize)]
pub(crate) struct IdentityEvidence {
    pub(crate) authority: &'static str,
    pub(crate) actor_scope_raw: String,
    pub(crate) actor_scope: String,
    pub(crate) target_scope: String,
    pub(crate) value: String,
    pub(crate) payload: String,
}
#[derive(Clone, Serialize)]
pub(crate) struct PreparedEvidence {
    pub(crate) actor_id: Id,
    pub(crate) recipient_id: Id,
    pub(crate) delivery_id: Id,
    pub(crate) eligibility: &'static str,
    pub(crate) encrypted: bool,
    pub(crate) mam_backed: bool,
    pub(crate) archive_ids: Vec<Id>,
    pub(crate) identity: Option<IdentityEvidence>,
}
#[derive(Clone, Serialize)]
pub(crate) struct Continuation {
    pub(crate) kind: &'static str,
    pub(crate) error_type: Option<&'static str>,
    pub(crate) error_condition: Option<&'static str>,
}
#[derive(Clone, Serialize)]
pub(crate) struct Handoff {
    pub(crate) correlation: Correlation,
    pub(crate) source: Source,
    pub(crate) local_call: &'static str,
    pub(crate) local_accepted: bool,
    pub(crate) last_local_refusal: Option<&'static str>,
    pub(crate) remote: &'static str,
    pub(crate) prior_remote_uncertain: bool,
    pub(crate) rearm: &'static str,
    pub(crate) route_end: &'static str,
    pub(crate) retired: bool,
}
#[derive(Clone, Serialize)]
pub(crate) struct OriginalState {
    pub(crate) begin: Option<AdmissionEvidence>,
    pub(crate) finalize: Option<AdmissionEvidence>,
    pub(crate) direct: Option<DirectEvidence>,
    pub(crate) handoff: Option<Handoff>,
    pub(crate) terminal: Option<&'static str>,
}
#[derive(Clone, Serialize)]
pub(crate) struct OriginalPrefix {
    pub(crate) seq: u32,
    pub(crate) state: OriginalState,
}
#[derive(Clone, Serialize)]
pub(crate) struct Slot {
    pub(crate) xml: String,
    pub(crate) source: Option<Source>,
}
#[derive(Clone, Serialize)]
pub(crate) struct HealthRead {
    pub(crate) seq: u32,
    pub(crate) phase: &'static str,
    pub(crate) mode: Mode,
}
#[derive(Clone, Serialize)]
pub(crate) struct Enqueue {
    pub(crate) seq: u32,
    pub(crate) source: Source,
    pub(crate) xml: String,
    pub(crate) result: &'static str,
}
#[derive(Clone, Serialize)]
pub(crate) struct Dequeue {
    pub(crate) seq: u32,
    pub(crate) source: Option<Source>,
    pub(crate) xml: String,
}
#[derive(Clone, Serialize)]
pub(crate) struct RemoteCall {
    pub(crate) seq: u32,
    pub(crate) source: Source,
    pub(crate) returned: Option<bool>,
}
#[derive(Clone, Serialize)]
pub(crate) struct RearmCall {
    pub(crate) seq: u32,
    pub(crate) source: Source,
    pub(crate) returned: bool,
}
#[derive(Clone, Default, Serialize)]
pub(crate) struct RouteEvidence {
    pub(crate) health_reads: Vec<HealthRead>,
    pub(crate) enqueue: Vec<Enqueue>,
    pub(crate) dequeued: Vec<Dequeue>,
    pub(crate) queue_remaining: Vec<Slot>,
    pub(crate) backpressure_disconnected: bool,
    pub(crate) remote_calls: Vec<RemoteCall>,
    pub(crate) rearm_calls: Vec<RearmCall>,
    pub(crate) handoff: Option<Handoff>,
}
#[derive(Serialize)]
pub(crate) struct OriginalEvidence {
    pub(crate) frame_id: Id,
    pub(crate) projection: Option<Projection>,
    pub(crate) prepared: Option<PreparedEvidence>,
    pub(crate) begin: Option<AdmissionEvidence>,
    pub(crate) finalize: Option<AdmissionEvidence>,
    pub(crate) direct: Option<DirectEvidence>,
    pub(crate) continuation: Option<Continuation>,
    pub(crate) route: RouteEvidence,
    pub(crate) terminal: Option<&'static str>,
    pub(crate) prefixes: Vec<OriginalPrefix>,
    pub(crate) polls: Vec<DriverPoll>,
}
#[derive(Clone, Serialize)]
pub(crate) struct NativeFact {
    pub(crate) source: Source,
    pub(crate) disposition: &'static str,
}
#[derive(Clone, Serialize)]
#[serde(tag = "kind")]
pub(crate) enum NativeAckKnowledge {
    NotRequested,
    NoCommitRequested,
    CommitCallEntered { fact: NativeFact },
    ReceiptKnown { fact: NativeFact },
}
#[derive(Clone, Serialize)]
pub(crate) struct NativeState {
    pub(crate) original: Option<Source>,
    pub(crate) preparation: &'static str,
    pub(crate) managed_by_sm: Option<bool>,
    pub(crate) fence_entered: bool,
    pub(crate) returned_fence: Option<Source>,
    pub(crate) writer_entered: bool,
    pub(crate) writer_result: Option<&'static str>,
    pub(crate) write_decision: Option<&'static str>,
    pub(crate) ack: NativeAckKnowledge,
    pub(crate) ack_returned: Option<bool>,
    pub(crate) terminal: Option<&'static str>,
}
#[derive(Clone, Serialize)]
pub(crate) struct NativePrefix {
    pub(crate) seq: u32,
    pub(crate) state: NativeState,
}
#[derive(Clone, Serialize)]
pub(crate) struct WriteCall {
    pub(crate) seq: u32,
    pub(crate) offered_len: u32,
    pub(crate) offered_sha256: String,
    pub(crate) accepted_bytes_hex: String,
    pub(crate) result: &'static str,
}
#[derive(Clone, Serialize)]
pub(crate) struct FlushCall {
    pub(crate) seq: u32,
    pub(crate) result: &'static str,
}
#[derive(Clone, Serialize)]
pub(crate) struct AckCall {
    pub(crate) seq: u32,
    pub(crate) source: Source,
    pub(crate) returned: Option<bool>,
}
#[derive(Clone, Serialize)]
pub(crate) struct ReceiptObservation {
    pub(crate) seq: u32,
    pub(crate) result: &'static str,
}
#[derive(Serialize)]
pub(crate) struct NativeEvidence {
    pub(crate) frame_id: Id,
    pub(crate) connection_id: Id,
    #[serde(flatten)]
    pub(crate) state: NativeState,
    pub(crate) write_calls: Vec<WriteCall>,
    pub(crate) flush_calls: Vec<FlushCall>,
    pub(crate) ack_calls: Vec<AckCall>,
    pub(crate) ownership_receipts: Vec<ReceiptObservation>,
    pub(crate) write_receipts: Vec<ReceiptObservation>,
    pub(crate) prefixes: Vec<NativePrefix>,
    pub(crate) polls: Vec<DriverPoll>,
}
