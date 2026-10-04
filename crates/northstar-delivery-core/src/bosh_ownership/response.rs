//! Response-specific BOSH facts. The actor remains the RID/policy authority;
//! immutable requests carry only its already selected operation inputs.
use super::{CompletionError, Operation, Rejected, Scope};
use crate::{MixDelivery, TransportOwnershipSource as Source};
use std::{collections::BTreeSet, future::Future, sync::Arc};
use uuid::Uuid;

/// Existing cache membership value: identities only, never lease tokens.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BoshResponseOwnership {
    pub c2s_message_ids: Vec<Uuid>,
    pub mix_delivery_ids: Vec<Uuid>,
}
impl BoshResponseOwnership {
    pub fn is_empty(&self) -> bool {
        self.c2s_message_ids.is_empty() && self.mix_delivery_ids.is_empty()
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseKind {
    Payload,
    TerminalControl,
    EmptyControl,
}
#[derive(Clone, Eq, PartialEq)]
pub enum BindKnowledge {
    NotRequired,
    NoCommitRequested,
    CommitCallEntered(Arc<BoshResponseOwnership>),
    ReceiptKnown(Arc<BoshResponseOwnership>),
}
impl std::fmt::Debug for BindKnowledge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NotRequired => "BindNotRequired",
            Self::NoCommitRequested => "NoCommitRequested",
            Self::CommitCallEntered(_) => "CommitCallEntered([redacted])",
            Self::ReceiptKnown(_) => "ReceiptKnown([redacted])",
        })
    }
}
#[derive(Clone, Eq, PartialEq)]
pub struct BindAttemptSnapshot {
    pub selected_end: Option<usize>,
    pub selected_len: usize,
    pub sources: Option<Arc<Vec<Source>>>,
    pub knowledge: BindKnowledge,
    pub returned: Option<Arc<BoshResponseOwnership>>,
    pub return_matches: bool,
    pub superseded_message: Option<Uuid>,
    pub restored: bool,
    pub restore_matches: bool,
    pub removed_indices: Vec<usize>,
}
impl std::fmt::Debug for BindAttemptSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoshBindAttempt")
            .field("selected_len", &self.selected_len)
            .field("knowledge", &self.knowledge)
            .field("return_matches", &self.return_matches)
            .field("restored", &self.restored)
            .field("removed", &self.removed_indices.len())
            .finish_non_exhaustive()
    }
}
#[derive(Clone, Eq, PartialEq)]
pub struct ResponseSnapshot {
    pub rid: u64,
    pub kind: ResponseKind,
    pub lineage: Arc<Vec<Option<Source>>>,
    pub removed: Vec<bool>,
    pub attempts: Vec<BindAttemptSnapshot>,
    pub construction_restored: usize,
    pub exposure_entered: bool,
    pub responder_calls: usize,
    pub accepted_responders: usize,
    pub refused_responders: usize,
    pub control_calls: usize,
    pub control_accepted: usize,
    pub control_refused: usize,
    pub empty_cache_evictions: usize,
    pub bookkeeping: bool,
    pub cached: bool,
}
impl std::fmt::Debug for ResponseSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoshResponseSnapshot")
            .field("rid", &self.rid)
            .field("kind", &self.kind)
            .field("lineage_len", &self.lineage.len())
            .field("attempts", &self.attempts)
            .field("accepted", &self.accepted_responders)
            .field("refused", &self.refused_responders)
            .field("cached", &self.cached)
            .finish_non_exhaustive()
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Knowledge {
    NoCommitRequested,
    CommitCallEntered,
    ReceiptKnown,
}
#[derive(Clone, Eq, PartialEq)]
pub struct RenewSnapshot {
    pub expected: Option<(u64, Arc<BoshResponseOwnership>)>,
    pub knowledge: Knowledge,
    pub returned: bool,
    pub return_matches: bool,
    pub ack_issued: bool,
    pub replay_calls: usize,
    pub replay_accepted: usize,
    pub replay_refused: usize,
    pub replay_bookkeeping: bool,
}
impl std::fmt::Debug for RenewSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoshRenewSnapshot")
            .field("cached_rid", &self.expected.as_ref().map(|(rid, _)| rid))
            .field("knowledge", &self.knowledge)
            .field("returned", &self.returned)
            .field("ack_issued", &self.ack_issued)
            .finish_non_exhaustive()
    }
}
/// A checked DELETE inside the transaction; durable settlement is known
/// only after the independently retained COMMIT receipt.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum DeletedSource {
    C2s {
        recipient_id: Uuid,
        message_id: Uuid,
    },
    Mix(MixDelivery),
}
impl std::fmt::Debug for DeletedSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::C2s { .. } => "C2s([redacted])",
            Self::Mix(_) => "Mix([redacted])",
        })
    }
}
#[derive(Clone, Eq, PartialEq)]
pub struct AckSnapshot {
    pub rid: u64,
    pub knowledge: Knowledge,
    pub deleted: Option<Arc<Vec<DeletedSource>>>,
    pub returned: bool,
    pub return_matches: bool,
    pub cache_evictions: usize,
    pub receipt_calls: usize,
    pub receipts_sent: usize,
    pub receipts_refused: usize,
}
impl std::fmt::Debug for AckSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoshAckSnapshot")
            .field("rid", &self.rid)
            .field("knowledge", &self.knowledge)
            .field(
                "deleted",
                &self.deleted.as_ref().map(|sources| sources.len()),
            )
            .field("returned", &self.returned)
            .field("cache_evictions", &self.cache_evictions)
            .finish_non_exhaustive()
    }
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ResponseSummary {
    pub responses: usize,
    pub bind_unknown: usize,
    pub bind_receipts: usize,
    pub accepted_responders: usize,
    pub control_accepted: usize,
    pub cached: usize,
    pub renew_unknown: usize,
    pub renew_receipts: usize,
    pub ack_unknown: usize,
    pub ack_receipts: usize,
    pub deleted: usize,
    pub evictions: usize,
    pub receipt_sends: usize,
}
impl Operation {
    pub fn begin_response(
        &self,
        rid: u64,
        kind: ResponseKind,
        lineage: Vec<Option<Source>>,
    ) -> Result<ResponseBuild, Rejected> {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        Self::open(&state)?;
        if kind != ResponseKind::Payload && !lineage.is_empty() {
            return Err(Rejected::Source);
        }
        let index = state.responses.len();
        let scope = state.scope;
        let removed = vec![false; lineage.len()];
        state.responses.push(ResponseSnapshot {
            rid,
            kind,
            lineage: Arc::new(lineage),
            removed,
            attempts: vec![],
            construction_restored: 0,
            exposure_entered: false,
            responder_calls: 0,
            accepted_responders: 0,
            refused_responders: 0,
            control_calls: 0,
            control_accepted: 0,
            control_refused: 0,
            empty_cache_evictions: 0,
            bookkeeping: false,
            cached: false,
        });
        Ok(ResponseBuild {
            operation: self.clone(),
            index,
            scope,
            rid,
        })
    }
    /// Observation-only hooks for existing fixed control responses. They do
    /// not authorize I/O, issue a bind/renew/ACK request, or produce a payload
    /// continuation. Late factual reporting remains possible after retirement;
    /// the real actor supplies its active timed operation. This preserves the
    /// pause path's existing no-new-error behavior rather than claiming that
    /// this hook universally gates raw control-response I/O.
    pub fn observe_empty_control(&self, rid: u64) -> ControlObservation {
        self.control_observation(rid, ResponseKind::EmptyControl)
    }
    pub fn observe_terminal_control(&self, rid: u64) -> ControlObservation {
        self.control_observation(rid, ResponseKind::TerminalControl)
    }
    fn control_observation(&self, rid: u64, kind: ResponseKind) -> ControlObservation {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let index = state.responses.len();
        state.responses.push(ResponseSnapshot {
            rid,
            kind,
            lineage: Arc::new(vec![]),
            removed: vec![],
            attempts: vec![],
            construction_restored: 0,
            exposure_entered: false,
            responder_calls: 0,
            accepted_responders: 0,
            refused_responders: 0,
            control_calls: 0,
            control_accepted: 0,
            control_refused: 0,
            empty_cache_evictions: 0,
            bookkeeping: false,
            cached: false,
        });
        ControlObservation {
            operation: self.clone(),
            index,
        }
    }
    pub fn begin_renew(
        &self,
        expected: Option<(u64, Arc<BoshResponseOwnership>)>,
    ) -> Result<RenewRequest, Rejected> {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        Self::open(&state)?;
        let index = state.renewals.len();
        let scope = state.scope;
        state.renewals.push(RenewSnapshot {
            expected: expected.clone(),
            knowledge: Knowledge::NoCommitRequested,
            returned: false,
            return_matches: false,
            ack_issued: false,
            replay_calls: 0,
            replay_accepted: 0,
            replay_refused: 0,
            replay_bookkeeping: false,
        });
        Ok(RenewRequest {
            operation: self.clone(),
            index,
            scope,
            expected,
        })
    }
}
pub struct ResponseBuild {
    operation: Operation,
    index: usize,
    scope: Scope,
    rid: u64,
}
impl std::fmt::Debug for ResponseBuild {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BoshResponseBuild { lineage: [redacted] }")
    }
}
impl ResponseBuild {
    pub fn terminal_control(&self) -> ControlObservation {
        ControlObservation {
            operation: self.operation.clone(),
            index: self.index,
        }
    }
    pub fn empty_cache_evicted(&self) {
        self.operation
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .responses[self.index]
            .empty_cache_evictions += 1;
    }
    pub fn construction_restored(&self, selected: usize) {
        self.operation
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .responses[self.index]
            .construction_restored += selected;
    }
    pub fn attempt(
        &self,
        sources: Vec<Source>,
        selected: impl ExactSizeIterator<Item = Option<Source>>,
    ) -> Result<BindRequest, Rejected> {
        let mut state = self.operation.0.lock().unwrap_or_else(|e| e.into_inner());
        Operation::open(&state)?;
        let selected_len = selected.len();
        let response = &mut state.responses[self.index];
        if response.exposure_entered
            || response.attempts.last().is_some_and(|last| {
                !last.restored || !last.restore_matches || last.removed_indices.is_empty()
            })
        {
            return Err(Rejected::State);
        }
        let selected_indices = response
            .lineage
            .iter()
            .enumerate()
            .filter(|(index, _)| !response.removed[*index])
            .take(selected_len)
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if selected_indices.len() != selected_len
            || !selected.eq(selected_indices
                .iter()
                .map(|index| response.lineage[*index]))
            || !sources.iter().copied().eq(selected_indices
                .iter()
                .filter_map(|index| response.lineage[*index]))
        {
            return Err(Rejected::Source);
        }
        let attempt = response.attempts.len();
        let sources = Arc::new(sources);
        response.attempts.push(BindAttemptSnapshot {
            selected_end: selected_indices.last().copied(),
            selected_len,
            knowledge: if sources.is_empty() {
                BindKnowledge::NotRequired
            } else {
                BindKnowledge::NoCommitRequested
            },
            sources: Some(sources.clone()),
            returned: None,
            return_matches: false,
            superseded_message: None,
            restored: false,
            restore_matches: false,
            removed_indices: vec![],
        });
        Ok(BindRequest {
            operation: self.operation.clone(),
            response: self.index,
            attempt,
            scope: self.scope,
            rid: self.rid,
            sources,
        })
    }
}
pub struct BindRequest {
    operation: Operation,
    response: usize,
    attempt: usize,
    scope: Scope,
    rid: u64,
    sources: Arc<Vec<Source>>,
}
impl std::fmt::Debug for BindRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BoshBindRequest { immutable inputs: [redacted] }")
    }
}
impl BindRequest {
    pub fn session_id(&self) -> Uuid {
        self.scope.session_id
    }
    pub fn rid(&self) -> u64 {
        self.rid
    }
    pub fn ttl_seconds(&self) -> u64 {
        self.scope.ttl_seconds
    }
    pub fn sources(&self) -> &[Source] {
        &self.sources
    }
    fn validate<'a>(
        &self,
        state: &'a mut super::Snapshot,
    ) -> Result<&'a mut BindAttemptSnapshot, Rejected> {
        Operation::open(state)?;
        if state.scope != self.scope {
            return Err(Rejected::Source);
        }
        let response = state
            .responses
            .get_mut(self.response)
            .ok_or(Rejected::State)?;
        if response.rid != self.rid {
            return Err(Rejected::Source);
        }
        let attempt = response
            .attempts
            .get_mut(self.attempt)
            .ok_or(Rejected::State)?;
        if !attempt
            .sources
            .as_ref()
            .is_some_and(|sources| Arc::ptr_eq(sources, &self.sources))
        {
            return Err(Rejected::Source);
        }
        Ok(attempt)
    }
    pub fn validate_for_io(&self) -> Result<(), Rejected> {
        let mut state = self.operation.0.lock().unwrap_or_else(|e| e.into_inner());
        let attempt = self.validate(&mut state)?;
        if attempt.knowledge != BindKnowledge::NoCommitRequested
            || attempt.returned.is_some()
            || attempt.restored
        {
            return Err(Rejected::State);
        }
        Ok(())
    }
    pub fn enter_commit(
        &self,
        ownership: BoshResponseOwnership,
    ) -> Result<BindCommitPermit, Rejected> {
        let mut state = self.operation.0.lock().unwrap_or_else(|e| e.into_inner());
        let attempt = self.validate(&mut state)?;
        if attempt.knowledge != BindKnowledge::NoCommitRequested
            || attempt.returned.is_some()
            || attempt.restored
        {
            return Err(Rejected::State);
        }
        let mut c2s = BTreeSet::new();
        let mut mix = BTreeSet::new();
        for source in self.sources.iter() {
            if !match source {
                Source::C2s(source) => c2s.insert(source.message_id),
                Source::Mix(source) => mix.insert(source.delivery_id),
            } {
                return Err(Rejected::Source);
            }
        }
        if !ownership.c2s_message_ids.iter().copied().eq(c2s)
            || !ownership.mix_delivery_ids.iter().copied().eq(mix)
        {
            return Err(Rejected::Receipt);
        }
        let ownership = Arc::new(ownership);
        attempt.knowledge = BindKnowledge::CommitCallEntered(ownership.clone());
        Ok(BindCommitPermit {
            operation: self.operation.clone(),
            response: self.response,
            attempt: self.attempt,
            ownership,
        })
    }
    pub fn returned(self, ownership: BoshResponseOwnership) -> Result<BoundResponse, Rejected> {
        let ownership = Arc::new(ownership);
        {
            let mut state = self.operation.0.lock().unwrap_or_else(|e| e.into_inner());
            let attempt = self.validate(&mut state)?;
            if attempt.returned.is_some() {
                return Err(Rejected::State);
            }
            attempt.return_matches = match &attempt.knowledge {
                BindKnowledge::NotRequired => ownership.is_empty(),
                BindKnowledge::ReceiptKnown(receipt) => receipt == &ownership,
                _ => false,
            };
            attempt.returned = Some(ownership.clone());
            if !attempt.return_matches {
                return Err(Rejected::Receipt);
            }
        }
        Ok(BoundResponse {
            request: self,
            ownership,
        })
    }
    pub fn supersession(self, message_id: Uuid) -> Result<Restoration, Rejected> {
        let selected_indices = {
            let mut state = self.operation.0.lock().unwrap_or_else(|e| e.into_inner());
            let attempt = self.validate(&mut state)?;
            if attempt.knowledge != BindKnowledge::NoCommitRequested
                || attempt.returned.is_some()
                || attempt.restored
            {
                return Err(Rejected::State);
            }
            attempt.superseded_message = Some(message_id);
            let selected_len = attempt.selected_len;
            let response = &state.responses[self.response];
            response
                .lineage
                .iter()
                .enumerate()
                .filter(|(index, _)| !response.removed[*index])
                .take(selected_len)
                .map(|(index, _)| index)
                .collect()
        };
        Ok(Restoration {
            request: self,
            selected_indices,
        })
    }
}
pub struct BindCommitPermit {
    operation: Operation,
    response: usize,
    attempt: usize,
    ownership: Arc<BoshResponseOwnership>,
}
impl BindCommitPermit {
    pub fn received(self) {
        self.operation
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .responses[self.response]
            .attempts[self.attempt]
            .knowledge = BindKnowledge::ReceiptKnown(self.ownership);
    }
}
pub struct Restoration {
    request: BindRequest,
    selected_indices: Vec<usize>,
}
impl Restoration {
    pub fn selected_indices(&self) -> &[usize] {
        &self.selected_indices
    }
    pub fn restored(self, removed_indices: Vec<usize>) -> Result<(), Rejected> {
        let mut state = self
            .request
            .operation
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let attempt = self.request.validate(&mut state)?;
        let message_id = attempt.superseded_message.ok_or(Rejected::State)?;
        if attempt.knowledge != BindKnowledge::NoCommitRequested || attempt.restored {
            return Err(Rejected::State);
        }
        let response = &mut state.responses[self.request.response];
        let expected = self
            .selected_indices
            .iter()
            .rev()
            .copied()
            .filter(|index| {
                response.lineage[*index]
                    .and_then(Source::c2s)
                    .is_some_and(|source| source.message_id == message_id)
            })
            .collect::<Vec<_>>();
        let matches = removed_indices == expected;
        let attempt = &mut response.attempts[self.request.attempt];
        attempt.restored = true;
        attempt.restore_matches = matches;
        attempt.removed_indices = removed_indices;
        // Keep the actual reported restoration even if its receipt is inconsistent.
        if !matches {
            return Err(Rejected::Source);
        }
        for index in &attempt.removed_indices {
            response.removed[*index] = true;
        }
        // Only a known pre-COMMIT, actually restored attempt is compacted.
        attempt.sources = None;
        Ok(())
    }
}
pub struct BoundResponse {
    request: BindRequest,
    ownership: Arc<BoshResponseOwnership>,
}
impl BoundResponse {
    pub fn ownership(&self) -> &Arc<BoshResponseOwnership> {
        &self.ownership
    }
    pub fn begin_exposure(self) -> Result<Exposure, Rejected> {
        {
            let mut state = self
                .request
                .operation
                .0
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let attempt = self.request.validate(&mut state)?;
            if !attempt.return_matches || attempt.restored {
                return Err(Rejected::Receipt);
            }
            let response = &mut state.responses[self.request.response];
            if response.exposure_entered {
                return Err(Rejected::State);
            }
            response.exposure_entered = true;
        }
        Ok(Exposure {
            operation: self.request.operation,
            response: self.request.response,
        })
    }
}
pub struct Exposure {
    operation: Operation,
    response: usize,
}
impl Exposure {
    pub fn sending(&self) {
        let mut state = self.operation.0.lock().unwrap_or_else(|e| e.into_inner());
        let response = &mut state.responses[self.response];
        if response.kind == ResponseKind::Payload {
            response.responder_calls += 1;
        } else {
            response.control_calls += 1;
        }
    }
    pub fn sent(&self, accepted: bool) {
        let mut state = self.operation.0.lock().unwrap_or_else(|e| e.into_inner());
        let response = &mut state.responses[self.response];
        match (response.kind == ResponseKind::Payload, accepted) {
            (true, true) => response.accepted_responders += 1,
            (true, false) => response.refused_responders += 1,
            (false, true) => response.control_accepted += 1,
            (false, false) => response.control_refused += 1,
        }
    }
    pub fn begin_bookkeeping(self) -> Result<Bookkeeping, Rejected> {
        let state = self.operation.0.lock().unwrap_or_else(|e| e.into_inner());
        Operation::open(&state)?;
        if state.responses[self.response].bookkeeping {
            return Err(Rejected::State);
        }
        drop(state);
        Ok(Bookkeeping {
            operation: self.operation,
            response: self.response,
        })
    }
}
pub struct Bookkeeping {
    operation: Operation,
    response: usize,
}
impl Bookkeeping {
    pub fn updated(&self) {
        self.operation
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .responses[self.response]
            .bookkeeping = true;
    }
    pub fn cached(self) {
        self.operation
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .responses[self.response]
            .cached = true;
    }
}
pub struct ControlObservation {
    operation: Operation,
    index: usize,
}
impl ControlObservation {
    pub fn sending(&self) {
        self.operation
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .responses[self.index]
            .control_calls += 1;
    }
    pub fn sent(&self, accepted: bool) {
        let mut state = self.operation.0.lock().unwrap_or_else(|e| e.into_inner());
        if accepted {
            state.responses[self.index].control_accepted += 1;
        } else {
            state.responses[self.index].control_refused += 1;
        }
    }
    pub fn updated(self) {
        self.operation
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .responses[self.index]
            .bookkeeping = true;
    }
}

pub struct RenewRequest {
    operation: Operation,
    index: usize,
    scope: Scope,
    expected: Option<(u64, Arc<BoshResponseOwnership>)>,
}
impl std::fmt::Debug for RenewRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BoshRenewRequest { immutable inputs: [redacted] }")
    }
}
impl RenewRequest {
    pub fn session_id(&self) -> Uuid {
        self.scope.session_id
    }
    pub fn ttl_seconds(&self) -> u64 {
        self.scope.ttl_seconds
    }
    pub fn expected(&self) -> Option<(u64, &BoshResponseOwnership)> {
        self.expected
            .as_ref()
            .map(|(rid, ownership)| (*rid, ownership.as_ref()))
    }
    fn validate<'a>(
        &self,
        state: &'a mut super::Snapshot,
    ) -> Result<&'a mut RenewSnapshot, Rejected> {
        Operation::open(state)?;
        if state.scope != self.scope {
            return Err(Rejected::Source);
        }
        let renewal = state.renewals.get_mut(self.index).ok_or(Rejected::State)?;
        if renewal.expected != self.expected {
            return Err(Rejected::Source);
        }
        Ok(renewal)
    }
    pub fn validate_for_io(&self) -> Result<(), Rejected> {
        let mut state = self.operation.0.lock().unwrap_or_else(|e| e.into_inner());
        let renewal = self.validate(&mut state)?;
        if renewal.knowledge != Knowledge::NoCommitRequested || renewal.returned {
            return Err(Rejected::State);
        }
        Ok(())
    }
    pub fn enter_commit(&self) -> Result<RenewCommitPermit, Rejected> {
        let mut state = self.operation.0.lock().unwrap_or_else(|e| e.into_inner());
        let renewal = self.validate(&mut state)?;
        if renewal.knowledge != Knowledge::NoCommitRequested || renewal.returned {
            return Err(Rejected::State);
        }
        renewal.knowledge = Knowledge::CommitCallEntered;
        Ok(RenewCommitPermit {
            operation: self.operation.clone(),
            index: self.index,
        })
    }
    pub fn returned(self) -> Result<Renewed, Rejected> {
        {
            let mut state = self.operation.0.lock().unwrap_or_else(|e| e.into_inner());
            let renewal = self.validate(&mut state)?;
            if renewal.returned {
                return Err(Rejected::State);
            }
            renewal.returned = true;
            renewal.return_matches = renewal.knowledge == Knowledge::ReceiptKnown;
            if !renewal.return_matches {
                return Err(Rejected::Receipt);
            }
        }
        Ok(Renewed { request: self })
    }
}
pub struct RenewCommitPermit {
    operation: Operation,
    index: usize,
}
impl RenewCommitPermit {
    pub fn received(self) {
        self.operation
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .renewals[self.index]
            .knowledge = Knowledge::ReceiptKnown;
    }
}
pub struct Renewed {
    request: RenewRequest,
}
impl Renewed {
    pub fn begin_ack(self, rid: u64) -> Result<AckRequest, Rejected> {
        let mut state = self
            .request
            .operation
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let renewal = self.request.validate(&mut state)?;
        if !renewal.returned
            || !renewal.return_matches
            || renewal.expected.is_some()
            || renewal.ack_issued
        {
            return Err(Rejected::State);
        }
        renewal.ack_issued = true;
        let index = state.acknowledgements.len();
        state.acknowledgements.push(AckSnapshot {
            rid,
            knowledge: Knowledge::NoCommitRequested,
            deleted: None,
            returned: false,
            return_matches: false,
            cache_evictions: 0,
            receipt_calls: 0,
            receipts_sent: 0,
            receipts_refused: 0,
        });
        Ok(AckRequest {
            operation: self.request.operation.clone(),
            index,
            scope: self.request.scope,
            rid,
        })
    }
    pub fn begin_replay(self) -> Result<ReplayExposure, Rejected> {
        {
            let mut state = self
                .request
                .operation
                .0
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let renewal = self.request.validate(&mut state)?;
            if !renewal.returned || !renewal.return_matches || renewal.expected.is_none() {
                return Err(Rejected::State);
            }
        }
        Ok(ReplayExposure {
            operation: self.request.operation,
            index: self.request.index,
        })
    }
}
pub struct ReplayExposure {
    operation: Operation,
    index: usize,
}
impl ReplayExposure {
    pub fn sending(&self) {
        self.operation
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .renewals[self.index]
            .replay_calls += 1;
    }
    pub fn sent(&self, accepted: bool) {
        let mut state = self.operation.0.lock().unwrap_or_else(|e| e.into_inner());
        if accepted {
            state.renewals[self.index].replay_accepted += 1;
        } else {
            state.renewals[self.index].replay_refused += 1;
        }
    }
    pub fn updated(self) {
        self.operation
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .renewals[self.index]
            .replay_bookkeeping = true;
    }
}
pub struct AckRequest {
    operation: Operation,
    index: usize,
    scope: Scope,
    rid: u64,
}
impl std::fmt::Debug for AckRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BoshAckRequest { immutable inputs: [redacted] }")
    }
}
impl AckRequest {
    pub fn session_id(&self) -> Uuid {
        self.scope.session_id
    }
    pub fn rid(&self) -> u64 {
        self.rid
    }
    fn validate<'a>(
        &self,
        state: &'a mut super::Snapshot,
    ) -> Result<&'a mut AckSnapshot, Rejected> {
        Operation::open(state)?;
        if state.scope != self.scope {
            return Err(Rejected::Source);
        }
        let ack = state
            .acknowledgements
            .get_mut(self.index)
            .ok_or(Rejected::State)?;
        if ack.rid != self.rid {
            return Err(Rejected::Source);
        }
        Ok(ack)
    }
    pub fn validate_for_io(&self) -> Result<(), Rejected> {
        let mut state = self.operation.0.lock().unwrap_or_else(|e| e.into_inner());
        let ack = self.validate(&mut state)?;
        if ack.knowledge != Knowledge::NoCommitRequested || ack.returned {
            return Err(Rejected::State);
        }
        Ok(())
    }
    pub fn enter_commit(&self, deleted: Vec<DeletedSource>) -> Result<AckCommitPermit, Rejected> {
        let mut state = self.operation.0.lock().unwrap_or_else(|e| e.into_inner());
        let ack = self.validate(&mut state)?;
        if ack.knowledge != Knowledge::NoCommitRequested || ack.returned {
            return Err(Rejected::State);
        }
        let deleted = Arc::new(deleted);
        ack.deleted = Some(deleted);
        ack.knowledge = Knowledge::CommitCallEntered;
        Ok(AckCommitPermit {
            operation: self.operation.clone(),
            index: self.index,
        })
    }
    pub fn returned(self) -> Result<Acknowledged, Rejected> {
        {
            let mut state = self.operation.0.lock().unwrap_or_else(|e| e.into_inner());
            let ack = self.validate(&mut state)?;
            if ack.returned {
                return Err(Rejected::State);
            }
            ack.returned = true;
            ack.return_matches = ack.knowledge == Knowledge::ReceiptKnown;
            if !ack.return_matches {
                return Err(Rejected::Receipt);
            }
        }
        Ok(Acknowledged {
            operation: self.operation,
            index: self.index,
            rid: self.rid,
        })
    }
}
pub struct AckCommitPermit {
    operation: Operation,
    index: usize,
}
impl AckCommitPermit {
    pub fn received(self) {
        self.operation
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .acknowledgements[self.index]
            .knowledge = Knowledge::ReceiptKnown;
    }
}
pub struct Acknowledged {
    operation: Operation,
    index: usize,
    rid: u64,
}
impl Acknowledged {
    pub fn rid(&self) -> u64 {
        self.rid
    }
    pub fn evicted(&self) {
        self.operation
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .acknowledgements[self.index]
            .cache_evictions += 1;
    }
    pub fn sending_receipt(&self) {
        self.operation
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .acknowledgements[self.index]
            .receipt_calls += 1;
    }
    pub fn receipt_sent(&self, accepted: bool) {
        let mut state = self.operation.0.lock().unwrap_or_else(|e| e.into_inner());
        if accepted {
            state.acknowledgements[self.index].receipts_sent += 1;
        } else {
            state.acknowledgements[self.index].receipts_refused += 1;
        }
    }
}
pub async fn bind_commit_observed<E>(
    future: impl Future<Output = Result<(), E>>,
    request: &BindRequest,
    receipt: BoshResponseOwnership,
) -> Result<(), CompletionError<E>> {
    let permit = request
        .enter_commit(receipt)
        .map_err(CompletionError::Binding)?;
    future.await.map_err(CompletionError::Repository)?;
    permit.received();
    Ok(())
}
pub async fn renew_commit_observed<E>(
    future: impl Future<Output = Result<(), E>>,
    request: &RenewRequest,
) -> Result<(), CompletionError<E>> {
    let permit = request.enter_commit().map_err(CompletionError::Binding)?;
    future.await.map_err(CompletionError::Repository)?;
    permit.received();
    Ok(())
}
pub async fn ack_commit_observed<E>(
    future: impl Future<Output = Result<(), E>>,
    request: &AckRequest,
    deleted: Vec<DeletedSource>,
) -> Result<(), CompletionError<E>> {
    let permit = request
        .enter_commit(deleted)
        .map_err(CompletionError::Binding)?;
    future.await.map_err(CompletionError::Repository)?;
    permit.received();
    Ok(())
}
