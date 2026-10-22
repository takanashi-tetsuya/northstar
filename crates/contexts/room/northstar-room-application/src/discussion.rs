//! One discussion invocation's acceptance knowledge and consuming live effects.
//! SQL authority, clocks, I/O, and asynchronous work on Drop stay in adapters.

use northstar_room_core::{MucDiscussion, MucDiscussionAdmission};
use std::{
    future::Future,
    sync::{Arc, Mutex, MutexGuard},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcceptanceClass {
    ArchiveAndIdentity,
    ArchiveOnly,
    IdentityOnly,
    Volatile,
}

impl AcceptanceClass {
    fn for_command(command: &MucDiscussion) -> Self {
        match (command.archive, command.origin_id.is_some()) {
            (true, true) => Self::ArchiveAndIdentity,
            (true, false) => Self::ArchiveOnly,
            (false, true) => Self::IdentityOnly,
            (false, false) => Self::Volatile,
        }
    }
}

struct PreparedInput {
    command: MucDiscussion,
    configured_domain: String,
}

/// Immutable input, not a receipt or a current-room authority capability.
/// Only the receiving application can supply the configured-domain value.
#[derive(Clone)]
pub struct PreparedDiscussion(Arc<PreparedInput>);

impl std::fmt::Debug for PreparedDiscussion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PreparedDiscussion { input: [redacted] }")
    }
}

impl PreparedDiscussion {
    pub(crate) fn new(command: MucDiscussion, configured_domain: String) -> Self {
        Self(Arc::new(PreparedInput {
            command,
            configured_domain,
        }))
    }

    pub fn command(&self) -> &MucDiscussion {
        &self.0.command
    }

    pub fn requested_class(&self) -> AcceptanceClass {
        AcceptanceClass::for_command(self.command())
    }

    fn same_input(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Rejected {
    Retired,
    RequestAlreadyIssued,
    NotStarted,
    AlreadyStarted,
    AlreadyReturned,
    Input,
    Invocation,
    Knowledge,
    Result,
    MissingReceipt,
    Fanout,
}

impl std::fmt::Display for Rejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MUC discussion rejected: {self:?}")
    }
}

impl std::error::Error for Rejected {}

/// A prospective/observed fact is not a capability. Replay deliberately has
/// no fresh class: the original archive presence is not returned by SQL.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitFact {
    outcome: MucDiscussionAdmission,
    fresh_class: Option<AcceptanceClass>,
}

impl CommitFact {
    pub fn outcome(self) -> MucDiscussionAdmission {
        self.outcome
    }

    pub fn fresh_class(self) -> Option<AcceptanceClass> {
        self.fresh_class
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Knowledge {
    NoCommitRequested,
    CommitCallEntered(CommitFact),
    ReceiptKnown(CommitFact),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Returned {
    Outcome(MucDiscussionAdmission),
    Error,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalReason {
    Completed,
    BackendFailure,
    TimedOut,
    Cancelled,
    Panicked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FanoutStage {
    Unavailable,
    Ready,
    Started,
    ClusterEntered,
    ClusterReturned,
    PrivacyEntered,
    Delivering,
    Completed,
}

/// A compact prefix of the acquired recipient order. It does not claim a
/// successful cluster publish, peer ACK, or durable endpoint delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FanoutPrefix {
    pub stage: FanoutStage,
    pub recipients: Option<usize>,
    pub next_recipient: usize,
    pub endpoint_pending: bool,
    pub blocked: usize,
    pub accepted: usize,
    pub rejected: usize,
}

impl Default for FanoutPrefix {
    fn default() -> Self {
        Self {
            stage: FanoutStage::Unavailable,
            recipients: None,
            next_recipient: 0,
            endpoint_pending: false,
            blocked: 0,
            accepted: 0,
            rejected: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Snapshot {
    pub request_issued: bool,
    pub repository_started: bool,
    pub knowledge: Knowledge,
    pub returned: Option<Returned>,
    pub fanout: FanoutPrefix,
    pub terminal: Option<TerminalReason>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KnowledgeClass {
    NoCommitRequested,
    CommitCallEntered,
    ReceiptKnown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReturnClass {
    NotReturned,
    Stored,
    Replay,
    Unauthorized,
    Stale,
    Error,
}

/// Safe for ordinary diagnostics: no command, stanza IDs or authority tuple.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Summary {
    pub repository_started: bool,
    pub knowledge: KnowledgeClass,
    pub receipt_class: Option<AcceptanceClass>,
    pub returned: ReturnClass,
    pub fanout: FanoutPrefix,
    pub terminal: Option<TerminalReason>,
}

impl Snapshot {
    pub fn summary(self) -> Summary {
        Summary {
            repository_started: self.repository_started,
            knowledge: match self.knowledge {
                Knowledge::NoCommitRequested => KnowledgeClass::NoCommitRequested,
                Knowledge::CommitCallEntered(_) => KnowledgeClass::CommitCallEntered,
                Knowledge::ReceiptKnown(_) => KnowledgeClass::ReceiptKnown,
            },
            receipt_class: match self.knowledge {
                Knowledge::ReceiptKnown(fact) => fact.fresh_class,
                _ => None,
            },
            returned: match self.returned {
                None => ReturnClass::NotReturned,
                Some(Returned::Error) => ReturnClass::Error,
                Some(Returned::Outcome(MucDiscussionAdmission::Stored(_))) => ReturnClass::Stored,
                Some(Returned::Outcome(MucDiscussionAdmission::Replay(_))) => ReturnClass::Replay,
                Some(Returned::Outcome(MucDiscussionAdmission::Unauthorized)) => {
                    ReturnClass::Unauthorized
                }
                Some(Returned::Outcome(MucDiscussionAdmission::Stale)) => ReturnClass::Stale,
            },
            fanout: self.fanout,
            terminal: self.terminal,
        }
    }
}

struct Invocation {
    prepared: PreparedDiscussion,
    state: Mutex<Snapshot>,
}

/// Cloning observation does not clone request, COMMIT or fanout authority.
#[derive(Clone)]
pub struct Observation(Arc<Invocation>);

impl std::fmt::Debug for Observation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MucDiscussionObservation { invocation-local facts }")
    }
}

fn active(state: &Snapshot) -> Result<(), Rejected> {
    if state.terminal.is_some() {
        return Err(Rejected::Retired);
    }
    Ok(())
}

fn awaiting_return(state: &Snapshot) -> Result<(), Rejected> {
    active(state)?;
    if state.returned.is_some() {
        return Err(Rejected::AlreadyReturned);
    }
    Ok(())
}

impl Observation {
    pub fn new(prepared: PreparedDiscussion) -> Self {
        Self(Arc::new(Invocation {
            prepared,
            state: Mutex::new(Snapshot {
                request_issued: false,
                repository_started: false,
                knowledge: Knowledge::NoCommitRequested,
                returned: None,
                fanout: FanoutPrefix::default(),
                terminal: None,
            }),
        }))
    }

    fn state(&self) -> MutexGuard<'_, Snapshot> {
        self.0
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }

    pub fn is_for(&self, prepared: &PreparedDiscussion) -> bool {
        self.0.prepared.same_input(prepared)
    }

    fn same_invocation(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }

    pub fn snapshot(&self) -> Snapshot {
        *self.state()
    }

    pub fn request(&self) -> Result<Request, Rejected> {
        let mut state = self.state();
        active(&state)?;
        if state.request_issued {
            return Err(Rejected::RequestAlreadyIssued);
        }
        state.request_issued = true;
        Ok(Request {
            observation: self.clone(),
        })
    }

    pub fn retire(&self, reason: TerminalReason) -> Summary {
        let mut state = self.state();
        if state.terminal.is_none() {
            state.terminal = Some(reason);
        }
        state.summary()
    }
}

/// Issued once. Repository input is obtained from this exact request.
pub struct Request {
    observation: Observation,
}

impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MucDiscussionRequest { input: [redacted] }")
    }
}

impl Request {
    pub fn command(&self) -> &MucDiscussion {
        self.observation.0.prepared.command()
    }

    pub(crate) fn valid_for_domain(&self, configured_domain: &str) -> Result<bool, Rejected> {
        awaiting_return(&self.observation.state())?;
        Ok(
            self.observation.0.prepared.0.configured_domain == configured_domain
                && self.command().authority_is_consistent(configured_domain),
        )
    }

    pub(crate) fn start(&self) -> Result<(), Rejected> {
        let mut state = self.observation.state();
        awaiting_return(&state)?;
        if state.repository_started {
            return Err(Rejected::AlreadyStarted);
        }
        state.repository_started = true;
        Ok(())
    }

    pub(crate) fn refuse_invalid_authority(&self) -> Result<Completion, Rejected> {
        let mut state = self.observation.state();
        awaiting_return(&state)?;
        if state.repository_started || state.knowledge != Knowledge::NoCommitRequested {
            return Err(Rejected::Knowledge);
        }
        state.returned = Some(Returned::Outcome(MucDiscussionAdmission::Unauthorized));
        Ok(Completion {
            observation: self.observation.clone(),
            outcome: MucDiscussionAdmission::Unauthorized,
            permit: None,
        })
    }

    fn proposed(&self, outcome: MucDiscussionAdmission) -> Result<CommitFact, Rejected> {
        let fresh_class = match outcome {
            MucDiscussionAdmission::Stored(id) if id == self.command().id => {
                Some(self.observation.0.prepared.requested_class())
            }
            MucDiscussionAdmission::Replay(_) if self.command().origin_id.is_some() => None,
            _ => return Err(Rejected::Result),
        };
        Ok(CommitFact {
            outcome,
            fresh_class,
        })
    }

    pub fn enter_commit(
        &self,
        outcome: MucDiscussionAdmission,
    ) -> Result<PreparedCommit, Rejected> {
        let fact = self.proposed(outcome)?;
        let mut state = self.observation.state();
        awaiting_return(&state)?;
        if !state.repository_started {
            return Err(Rejected::NotStarted);
        }
        if state.knowledge != Knowledge::NoCommitRequested {
            return Err(Rejected::Knowledge);
        }
        state.knowledge = Knowledge::CommitCallEntered(fact);
        Ok(PreparedCommit {
            observation: self.observation.clone(),
            fact,
        })
    }

    pub fn received(&self, prepared: PreparedCommit) -> Result<(), Rejected> {
        if !self.observation.same_invocation(&prepared.observation) {
            return Err(Rejected::Invocation);
        }
        let mut state = self.observation.state();
        awaiting_return(&state)?;
        if state.knowledge != Knowledge::CommitCallEntered(prepared.fact) {
            return Err(Rejected::Knowledge);
        }
        state.knowledge = Knowledge::ReceiptKnown(prepared.fact);
        Ok(())
    }

    pub(crate) fn returned(&self, outcome: MucDiscussionAdmission) -> Result<Completion, Rejected> {
        let mut state = self.observation.state();
        awaiting_return(&state)?;
        if !state.repository_started {
            return Err(Rejected::NotStarted);
        }
        let fresh = match outcome {
            MucDiscussionAdmission::Stored(_) | MucDiscussionAdmission::Replay(_) => {
                let proposed = self.proposed(outcome)?;
                match state.knowledge {
                    Knowledge::ReceiptKnown(receipt) if receipt == proposed => {}
                    Knowledge::NoCommitRequested => {
                        // A compatibility adapter's success is returned-only.
                        // It cannot mint the observed production continuation.
                        state.returned = Some(Returned::Outcome(outcome));
                        return Err(Rejected::MissingReceipt);
                    }
                    _ => return Err(Rejected::Result),
                }
                matches!(outcome, MucDiscussionAdmission::Stored(_))
            }
            MucDiscussionAdmission::Unauthorized | MucDiscussionAdmission::Stale => {
                if state.knowledge != Knowledge::NoCommitRequested {
                    return Err(Rejected::Result);
                }
                false
            }
        };
        state.returned = Some(Returned::Outcome(outcome));
        let permit = if fresh {
            state.fanout.stage = FanoutStage::Ready;
            Some(FanoutPermit {
                observation: self.observation.clone(),
            })
        } else {
            None
        };
        Ok(Completion {
            observation: self.observation.clone(),
            outcome,
            permit,
        })
    }

    pub(crate) fn failed(&self) -> Result<(), Rejected> {
        let mut state = self.observation.state();
        awaiting_return(&state)?;
        if !state.repository_started {
            return Err(Rejected::NotStarted);
        }
        state.returned = Some(Returned::Error);
        Ok(())
    }
}

/// Private invocation identity prevents pairing a token with another request,
/// even when every ordinary operation/stanza ID was copied.
pub struct PreparedCommit {
    observation: Observation,
    fact: CommitFact,
}

#[derive(Debug)]
pub enum CommitError<E> {
    Observation(Rejected),
    Commit(E),
}

/// Entry occurs when polled, not when this future is constructed. Successful
/// receipt observation precedes return without another suspension point.
pub async fn commit_observed<E>(
    commit: impl Future<Output = Result<(), E>>,
    request: &Request,
    outcome: MucDiscussionAdmission,
) -> Result<(), CommitError<E>> {
    let prepared = request
        .enter_commit(outcome)
        .map_err(CommitError::Observation)?;
    commit.await.map_err(CommitError::Commit)?;
    request.received(prepared).map_err(CommitError::Observation)
}

#[derive(Debug)]
pub enum AdmissionError<E> {
    Observation(Rejected),
    Repository(E),
}

pub struct Completion {
    observation: Observation,
    outcome: MucDiscussionAdmission,
    permit: Option<FanoutPermit>,
}

impl Completion {
    pub fn outcome(&self) -> MucDiscussionAdmission {
        self.outcome
    }

    pub fn into_fanout(self, expected: &Observation) -> Result<Option<FanoutPermit>, Rejected> {
        if !self.observation.same_invocation(expected) {
            return Err(Rejected::Invocation);
        }
        active(&self.observation.state())?;
        Ok(self.permit)
    }
}

/// One attempt of the already accepted, best-effort live effects. No retry,
/// acknowledgement, repository authority or asynchronous Drop is available.
pub struct FanoutPermit {
    observation: Observation,
}

impl FanoutPermit {
    pub fn start(self) -> Result<Fanout, Rejected> {
        {
            let mut state = self.observation.state();
            active(&state)?;
            if state.fanout.stage != FanoutStage::Ready {
                return Err(Rejected::Fanout);
            }
            state.fanout.stage = FanoutStage::Started;
        }
        Ok(Fanout {
            observation: self.observation,
        })
    }
}

pub struct Fanout {
    observation: Observation,
}

impl Fanout {
    fn advance(&self, from: FanoutStage, to: FanoutStage) -> Result<(), Rejected> {
        let mut state = self.observation.state();
        active(&state)?;
        if state.fanout.stage != from {
            return Err(Rejected::Fanout);
        }
        state.fanout.stage = to;
        Ok(())
    }

    pub fn enter_cluster(&self) -> Result<(), Rejected> {
        self.advance(FanoutStage::Started, FanoutStage::ClusterEntered)
    }

    pub fn cluster_returned(&self) -> Result<(), Rejected> {
        self.advance(FanoutStage::ClusterEntered, FanoutStage::ClusterReturned)
    }

    pub fn enter_privacy(&self, recipients: usize) -> Result<(), Rejected> {
        let mut state = self.observation.state();
        active(&state)?;
        if state.fanout.stage != FanoutStage::ClusterReturned {
            return Err(Rejected::Fanout);
        }
        state.fanout.recipients = Some(recipients);
        state.fanout.stage = FanoutStage::PrivacyEntered;
        Ok(())
    }

    pub fn privacy_returned(&self) -> Result<(), Rejected> {
        self.advance(FanoutStage::PrivacyEntered, FanoutStage::Delivering)
    }

    fn check_recipient(state: &Snapshot, index: usize, pending: bool) -> Result<(), Rejected> {
        active(state)?;
        if state.fanout.stage != FanoutStage::Delivering
            || state.fanout.next_recipient != index
            || state.fanout.recipients.is_none_or(|count| index >= count)
            || state.fanout.endpoint_pending != pending
        {
            return Err(Rejected::Fanout);
        }
        Ok(())
    }

    pub fn blocked(&self, index: usize) -> Result<(), Rejected> {
        let mut state = self.observation.state();
        Self::check_recipient(&state, index, false)?;
        state.fanout.blocked += 1;
        state.fanout.next_recipient += 1;
        Ok(())
    }

    pub fn enter_delivery(&self, index: usize) -> Result<(), Rejected> {
        let mut state = self.observation.state();
        Self::check_recipient(&state, index, false)?;
        state.fanout.endpoint_pending = true;
        Ok(())
    }

    pub fn delivery_returned(&self, index: usize, accepted: bool) -> Result<(), Rejected> {
        let mut state = self.observation.state();
        Self::check_recipient(&state, index, true)?;
        state.fanout.endpoint_pending = false;
        state.fanout.next_recipient += 1;
        if accepted {
            state.fanout.accepted += 1;
        } else {
            state.fanout.rejected += 1;
        }
        Ok(())
    }

    pub fn complete(self) -> Result<(), Rejected> {
        let mut state = self.observation.state();
        active(&state)?;
        if state.fanout.stage != FanoutStage::Delivering
            || state.fanout.recipients != Some(state.fanout.next_recipient)
            || state.fanout.endpoint_pending
        {
            return Err(Rejected::Fanout);
        }
        state.fanout.stage = FanoutStage::Completed;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MucDiscussionRepository, RepositoryFuture, RoomApplication};
    use northstar_room_core::{MucActorAuthority, MucActorPrincipal};
    use std::{
        pin::pin,
        task::{Context, Poll, Waker},
    };
    use uuid::Uuid;

    fn command(archive: bool, identity: bool) -> MucDiscussion {
        MucDiscussion {
            id: Uuid::from_u128(1),
            room_id: Uuid::from_u128(2),
            actor_scope: "alice@local.test".to_owned(),
            origin_id: identity.then(|| "origin".to_owned()),
            sender_jid: "alice@local.test/phone".to_owned(),
            nick: "Alice".to_owned(),
            stanza: "<message/>".to_owned(),
            encrypted: false,
            archive,
            retention_days: 0,
            authority: MucActorAuthority {
                clustered: false,
                expected_room_epoch: Uuid::from_u128(3),
                principal: MucActorPrincipal::Local {
                    user_id: Uuid::from_u128(4),
                    local_domain: "local.test".to_owned(),
                },
                actor_scope: "alice@local.test".to_owned(),
                full_jid: "alice@local.test/phone".to_owned(),
                nick: "Alice".to_owned(),
                occupant_incarnation: Uuid::from_u128(5),
                connection_uuid: Uuid::from_u128(6),
                expected_role: "participant".to_owned(),
                expected_affiliation: "member".to_owned(),
                cluster_target: None,
            },
        }
    }

    fn invocation(archive: bool, identity: bool) -> (Observation, Request) {
        let observation = Observation::new(PreparedDiscussion::new(
            command(archive, identity),
            "local.test".to_owned(),
        ));
        let request = observation.request().unwrap();
        (observation, request)
    }

    fn ready<F: Future>(future: F) -> F::Output {
        let mut future = pin!(future);
        match future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            Poll::Ready(output) => output,
            Poll::Pending => panic!("finite fixture unexpectedly suspended"),
        }
    }

    fn stored(request: &Request) -> MucDiscussionAdmission {
        MucDiscussionAdmission::Stored(request.command().id)
    }

    fn commit(request: &Request, outcome: MucDiscussionAdmission) {
        ready(commit_observed(
            std::future::ready(Ok::<(), ()>(())),
            request,
            outcome,
        ))
        .unwrap();
    }

    #[test]
    fn four_fresh_classes_are_receipts_without_inventing_volatile_recovery() {
        for (archive, identity, expected) in [
            (true, true, AcceptanceClass::ArchiveAndIdentity),
            (true, false, AcceptanceClass::ArchiveOnly),
            (false, true, AcceptanceClass::IdentityOnly),
            (false, false, AcceptanceClass::Volatile),
        ] {
            let (observation, request) = invocation(archive, identity);
            request.start().unwrap();
            commit(&request, stored(&request));
            let snapshot = observation.snapshot();
            assert_eq!(snapshot.summary().receipt_class, Some(expected));
            assert_eq!(snapshot.returned, None);
            assert_eq!(snapshot.fanout.stage, FanoutStage::Unavailable);
            let completion = request.returned(stored(&request)).unwrap();
            assert!(completion.into_fanout(&observation).unwrap().is_some());
        }
    }

    #[test]
    fn replay_keeps_original_id_and_does_not_infer_an_archive_class() {
        let (observation, request) = invocation(true, true);
        let original = MucDiscussionAdmission::Replay(Uuid::from_u128(99));
        request.start().unwrap();
        commit(&request, original);
        let before = observation.snapshot();
        assert_eq!(before.summary().receipt_class, None);
        assert!(matches!(
            request.returned(MucDiscussionAdmission::Replay(Uuid::from_u128(1))),
            Err(Rejected::Result)
        ));
        assert_eq!(observation.snapshot(), before);
        let completion = request.returned(original).unwrap();
        assert_eq!(completion.outcome(), original);
        assert!(completion.into_fanout(&observation).unwrap().is_none());
        assert_eq!(
            observation.snapshot().fanout.stage,
            FanoutStage::Unavailable
        );
    }

    #[test]
    fn invalid_proposals_and_cross_invocation_tokens_cannot_advance_state() {
        let (left, first) = invocation(false, false);
        let (right, second) = invocation(false, false);
        first.start().unwrap();
        second.start().unwrap();
        let before = left.snapshot();
        for wrong in [
            MucDiscussionAdmission::Stored(Uuid::from_u128(7)),
            MucDiscussionAdmission::Replay(Uuid::from_u128(1)),
            MucDiscussionAdmission::Unauthorized,
        ] {
            assert!(matches!(first.enter_commit(wrong), Err(Rejected::Result)));
            assert_eq!(left.snapshot(), before);
        }
        let token = first.enter_commit(stored(&first)).unwrap();
        assert_eq!(second.received(token), Err(Rejected::Invocation));
        assert_eq!(right.snapshot().knowledge, Knowledge::NoCommitRequested);
        assert!(matches!(
            first.enter_commit(stored(&first)),
            Err(Rejected::Knowledge)
        ));
    }

    #[test]
    fn commit_construction_precommit_and_inflight_drop_remain_distinct() {
        let (observation, request) = invocation(false, false);
        let unpolled = commit_observed(
            std::future::pending::<Result<(), ()>>(),
            &request,
            stored(&request),
        );
        drop(unpolled);
        assert!(!observation.snapshot().repository_started);
        assert_eq!(
            observation.snapshot().knowledge,
            Knowledge::NoCommitRequested
        );
        request.start().unwrap();
        let before = observation.snapshot();
        assert_eq!(before.knowledge, Knowledge::NoCommitRequested);
        let mut pending = Box::pin(commit_observed(
            std::future::pending::<Result<(), ()>>(),
            &request,
            stored(&request),
        ));
        assert!(pending
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        drop(pending);
        let summary = observation.retire(TerminalReason::Cancelled);
        assert_eq!(summary.knowledge, KnowledgeClass::CommitCallEntered);
        assert_eq!(summary.receipt_class, None);
        assert_eq!(summary.returned, ReturnClass::NotReturned);
    }

    #[test]
    fn receipt_survives_error_and_retirement_without_a_fanout_permit() {
        for reason in [
            TerminalReason::BackendFailure,
            TerminalReason::Cancelled,
            TerminalReason::Panicked,
        ] {
            let (observation, request) = invocation(false, false);
            request.start().unwrap();
            commit(&request, stored(&request));
            if reason == TerminalReason::BackendFailure {
                request.failed().unwrap();
            }
            let summary = observation.retire(reason);
            assert_eq!(summary.knowledge, KnowledgeClass::ReceiptKnown);
            assert_eq!(summary.receipt_class, Some(AcceptanceClass::Volatile));
            assert_eq!(summary.fanout.stage, FanoutStage::Unavailable);
            let before = observation.snapshot();
            assert!(matches!(
                request.returned(stored(&request)),
                Err(Rejected::Retired)
            ));
            assert!(matches!(observation.request(), Err(Rejected::Retired)));
            assert_eq!(observation.snapshot(), before);
        }
    }

    #[test]
    fn returned_only_success_is_not_promoted_to_a_commit_receipt() {
        let (observation, request) = invocation(true, true);
        request.start().unwrap();
        assert!(matches!(
            request.returned(stored(&request)),
            Err(Rejected::MissingReceipt)
        ));
        assert_eq!(
            observation.snapshot().knowledge,
            Knowledge::NoCommitRequested
        );
        assert_eq!(
            observation.snapshot().returned,
            Some(Returned::Outcome(stored(&request)))
        );
        assert_eq!(
            observation.snapshot().fanout.stage,
            FanoutStage::Unavailable
        );
        assert!(matches!(
            request.returned(stored(&request)),
            Err(Rejected::AlreadyReturned)
        ));
    }

    #[test]
    fn refusals_have_no_receipt_or_fanout_and_cannot_replace_positive_knowledge() {
        for refusal in [
            MucDiscussionAdmission::Unauthorized,
            MucDiscussionAdmission::Stale,
        ] {
            let (observation, request) = invocation(true, true);
            request.start().unwrap();
            let completion = request.returned(refusal).unwrap();
            assert_eq!(completion.outcome(), refusal);
            assert!(completion.into_fanout(&observation).unwrap().is_none());
            assert_eq!(
                observation.snapshot().knowledge,
                Knowledge::NoCommitRequested
            );

            let (accepted, request) = invocation(true, true);
            request.start().unwrap();
            commit(&request, stored(&request));
            let before = accepted.snapshot();
            assert!(matches!(request.returned(refusal), Err(Rejected::Result)));
            assert_eq!(accepted.snapshot(), before);
        }
    }

    #[test]
    fn failed_commit_remains_unknown_and_late_receipt_cannot_resurrect_retirement() {
        let (observation, request) = invocation(false, false);
        request.start().unwrap();
        assert!(matches!(
            ready(commit_observed(
                std::future::ready(Err("lost result")),
                &request,
                stored(&request)
            )),
            Err(CommitError::Commit("lost result"))
        ));
        request.failed().unwrap();
        let summary = observation.retire(TerminalReason::BackendFailure);
        assert_eq!(summary.knowledge, KnowledgeClass::CommitCallEntered);
        assert_eq!(summary.receipt_class, None);
        assert_eq!(summary.returned, ReturnClass::Error);

        let (observation, request) = invocation(false, false);
        request.start().unwrap();
        let prepared = request.enter_commit(stored(&request)).unwrap();
        observation.retire(TerminalReason::Cancelled);
        let before = observation.snapshot();
        assert_eq!(request.received(prepared), Err(Rejected::Retired));
        assert_eq!(observation.snapshot(), before);
    }

    #[test]
    fn consuming_completion_rejects_another_owner_with_identical_command_ids() {
        let (observation, request) = invocation(true, true);
        let (other, _) = invocation(true, true);
        request.start().unwrap();
        commit(&request, stored(&request));
        let completion = request.returned(stored(&request)).unwrap();
        assert!(matches!(
            completion.into_fanout(&other),
            Err(Rejected::Invocation)
        ));
        assert!(matches!(
            observation.request(),
            Err(Rejected::RequestAlreadyIssued)
        ));
    }

    #[test]
    fn fanout_keeps_a_sequential_prefix_and_freezes_it_on_retirement() {
        let (observation, request) = invocation(true, false);
        request.start().unwrap();
        commit(&request, stored(&request));
        let fanout = request
            .returned(stored(&request))
            .unwrap()
            .into_fanout(&observation)
            .unwrap()
            .unwrap()
            .start()
            .unwrap();
        fanout.enter_cluster().unwrap();
        fanout.cluster_returned().unwrap();
        fanout.enter_privacy(4).unwrap();
        fanout.privacy_returned().unwrap();
        fanout.enter_delivery(0).unwrap();
        assert_eq!(fanout.enter_delivery(1), Err(Rejected::Fanout));
        fanout.delivery_returned(0, false).unwrap();
        fanout.blocked(1).unwrap();
        fanout.enter_delivery(2).unwrap();
        fanout.delivery_returned(2, true).unwrap();
        fanout.enter_delivery(3).unwrap();
        let summary = observation.retire(TerminalReason::TimedOut);
        assert_eq!(
            (
                summary.fanout.rejected,
                summary.fanout.blocked,
                summary.fanout.accepted
            ),
            (1, 1, 1)
        );
        assert_eq!(summary.fanout.next_recipient, 3);
        assert!(summary.fanout.endpoint_pending);
        let before = observation.snapshot();
        assert_eq!(fanout.delivery_returned(3, true), Err(Rejected::Retired));
        assert_eq!(observation.snapshot(), before);
    }

    #[test]
    fn empty_fresh_fanout_completes_after_cluster_and_privacy() {
        let (observation, request) = invocation(false, false);
        request.start().unwrap();
        commit(&request, stored(&request));
        let fanout = request
            .returned(stored(&request))
            .unwrap()
            .into_fanout(&observation)
            .unwrap()
            .unwrap()
            .start()
            .unwrap();
        fanout.enter_cluster().unwrap();
        fanout.cluster_returned().unwrap();
        fanout.enter_privacy(0).unwrap();
        fanout.privacy_returned().unwrap();
        fanout.complete().unwrap();
        assert_eq!(observation.snapshot().fanout.stage, FanoutStage::Completed);
    }

    struct CountingRepository(Arc<std::sync::atomic::AtomicUsize>);

    impl MucDiscussionRepository for CountingRepository {
        type Error = ();
        fn admit_discussion<'a>(&'a self, command: &'a MucDiscussion) -> RepositoryFuture<'a, ()> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Box::pin(async move { Ok(MucDiscussionAdmission::Stored(command.id)) })
        }
    }

    #[test]
    fn receiving_domain_rejects_a_self_consistent_foreign_preparation_before_io() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let receiving = RoomApplication::new(CountingRepository(calls.clone()), "local.test");
        let foreign = RoomApplication::new(CountingRepository(calls.clone()), "evil.test");
        let mut input = command(true, true);
        input.actor_scope = "alice@evil.test".to_owned();
        input.sender_jid = "alice@evil.test/phone".to_owned();
        input.authority.actor_scope = input.actor_scope.clone();
        input.authority.full_jid = input.sender_jid.clone();
        input.authority.principal = MucActorPrincipal::Local {
            user_id: Uuid::from_u128(4),
            local_domain: "evil.test".to_owned(),
        };
        for prepared in [
            foreign.prepare_discussion(input.clone()),
            receiving.prepare_discussion(input),
        ] {
            let observation = Observation::new(prepared);
            let request = observation.request().unwrap();
            let result = ready(receiving.admit_discussion_observed(&request)).unwrap();
            assert_eq!(result.outcome(), MucDiscussionAdmission::Unauthorized);
            assert!(!observation.snapshot().repository_started);
            assert_eq!(
                observation.snapshot().knowledge,
                Knowledge::NoCommitRequested
            );
        }
        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 0);
    }

    #[test]
    fn legacy_repository_return_does_not_qualify_observed_application_success() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let application = RoomApplication::new(CountingRepository(calls.clone()), "local.test");
        let input = command(true, true);
        assert_eq!(
            ready(application.admit_discussion(&input)).unwrap(),
            MucDiscussionAdmission::Stored(input.id)
        );
        let observation = Observation::new(application.prepare_discussion(input));
        let request = observation.request().unwrap();
        assert!(matches!(
            ready(application.admit_discussion_observed(&request)),
            Err(AdmissionError::Observation(Rejected::MissingReceipt))
        ));
        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 2);
        assert_eq!(
            observation.snapshot().summary().returned,
            ReturnClass::Stored
        );
        assert_eq!(
            observation.snapshot().knowledge,
            Knowledge::NoCommitRequested
        );
    }
}
