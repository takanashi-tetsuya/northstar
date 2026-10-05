//! One foreground MIX invocation. PostgreSQL owns durable authority; this
//! owner retains observed facts and grants only one synchronous local wake.

use northstar_room_core::mix::{
    Admission, Existing, Ingress, Outcome, Replay, StoreCommand, Stored,
};
use std::{
    future::Future,
    sync::{Arc, Mutex, MutexGuard},
};

#[derive(Clone)]
pub struct PreparedIngress(Arc<Ingress>);

impl PreparedIngress {
    pub fn new(ingress: Ingress) -> Self {
        Self(Arc::new(ingress))
    }
    pub fn ingress(&self) -> &Ingress {
        &self.0
    }
    fn same_input(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Rejected {
    Retired,
    Input,
    Invocation,
    AlreadyIssued,
    AlreadyStarted,
    NotStarted,
    AlreadyReturned,
    Read,
    Knowledge,
    MissingReceipt,
    MissingReadEvidence,
    Result,
    Wake,
}
impl std::fmt::Display for Rejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MIX foreground rejected: {self:?}")
    }
}
impl std::error::Error for Rejected {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalReason {
    Completed,
    BackendFailure,
    TimedOut,
    Cancelled,
    Panicked,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ExistingKnowledge {
    pub raw: Option<Arc<Existing>>,
    pub authenticated: Option<Replay>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadReturned {
    Outcome(Replay),
    Error,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ReadKnowledge {
    pub issued: bool,
    pub started: bool,
    pub miss: bool,
    pub existing: ExistingKnowledge,
    pub returned: Option<ReadReturned>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Knowledge {
    /// This is only message admission. Capacity reconciliation may already
    /// have committed independently before the message transaction began.
    NoCommitRequested,
    CommitCallEntered(Arc<Stored>),
    ReceiptKnown(Arc<Stored>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Returned {
    /// The complete return was compared with the retained receipt. Keep its
    /// identity here and its one audience/projection in that receipt.
    AcceptedStored(northstar_room_core::mix::Id),
    /// Unvalidated/contradictory returns retain their actual input for diagnosis.
    Admission(Arc<Admission>),
    Error,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Wake {
    Unavailable,
    Ready,
    Invoked,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Snapshot {
    pub replay: ReadKnowledge,
    pub request_issued: bool,
    pub repository_started: bool,
    pub existing: ExistingKnowledge,
    pub knowledge: Knowledge,
    pub returned: Option<Returned>,
    pub wake: Wake,
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
    Conflict,
    TooLarge,
    NotParticipant,
    Error,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadReturnClass {
    NotReturned,
    Miss,
    Replay,
    Conflict,
    Error,
}

/// Payload-free terminal diagnostics. A read replay is never a COMMIT class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Summary {
    pub replay_started: bool,
    pub replay_returned: ReadReturnClass,
    pub raw_existing: bool,
    pub identity_classified: bool,
    pub repository_started: bool,
    pub knowledge: KnowledgeClass,
    pub returned: ReturnClass,
    pub wake: Wake,
    pub terminal: Option<TerminalReason>,
}

impl Snapshot {
    pub fn summary(&self) -> Summary {
        Summary {
            replay_started: self.replay.started,
            replay_returned: match self.replay.returned {
                None => ReadReturnClass::NotReturned,
                Some(ReadReturned::Error) => ReadReturnClass::Error,
                Some(ReadReturned::Outcome(Replay::Miss)) => ReadReturnClass::Miss,
                Some(ReadReturned::Outcome(Replay::Replay(_))) => ReadReturnClass::Replay,
                Some(ReadReturned::Outcome(Replay::Conflict)) => ReadReturnClass::Conflict,
            },
            raw_existing: self.existing.raw.is_some() || self.replay.existing.raw.is_some(),
            identity_classified: self.existing.authenticated.is_some()
                || self.replay.existing.authenticated.is_some(),
            repository_started: self.repository_started,
            knowledge: match self.knowledge {
                Knowledge::NoCommitRequested => KnowledgeClass::NoCommitRequested,
                Knowledge::CommitCallEntered(_) => KnowledgeClass::CommitCallEntered,
                Knowledge::ReceiptKnown(_) => KnowledgeClass::ReceiptKnown,
            },
            returned: match &self.returned {
                None => ReturnClass::NotReturned,
                Some(Returned::Error) => ReturnClass::Error,
                Some(Returned::AcceptedStored(_)) => ReturnClass::Stored,
                Some(Returned::Admission(admission)) => match admission.outcome {
                    Outcome::Stored(_) => ReturnClass::Stored,
                    Outcome::Replay(_) => ReturnClass::Replay,
                    Outcome::Conflict => ReturnClass::Conflict,
                    Outcome::TooLarge => ReturnClass::TooLarge,
                    Outcome::NotParticipant => ReturnClass::NotParticipant,
                },
            },
            wake: self.wake,
            terminal: self.terminal,
        }
    }
}

struct State {
    snapshot: Snapshot,
    command: Option<Arc<StoreCommand>>,
}
struct Invocation {
    prepared: PreparedIngress,
    state: Mutex<State>,
}

/// Cloneable observation refers to one private invocation. Frame UUIDs and
/// equal-looking input values are deliberately not invocation identities.
#[derive(Clone)]
pub struct Observation(Arc<Invocation>);

fn active(snapshot: &Snapshot) -> Result<(), Rejected> {
    if snapshot.terminal.is_some() {
        return Err(Rejected::Retired);
    }
    Ok(())
}
fn store_pending(snapshot: &Snapshot) -> Result<(), Rejected> {
    active(snapshot)?;
    if snapshot.returned.is_some() {
        return Err(Rejected::AlreadyReturned);
    }
    if !snapshot.repository_started {
        return Err(Rejected::NotStarted);
    }
    Ok(())
}
fn read_pending(snapshot: &Snapshot) -> Result<(), Rejected> {
    active(snapshot)?;
    if snapshot.replay.returned.is_some() {
        return Err(Rejected::AlreadyReturned);
    }
    if !snapshot.replay.started {
        return Err(Rejected::NotStarted);
    }
    Ok(())
}
fn classify(existing: &ExistingKnowledge, raw: &Existing, result: Replay) -> Result<(), Rejected> {
    if existing.raw.as_deref() != Some(raw) || existing.authenticated.is_some() {
        return Err(Rejected::Read);
    }
    match result {
        Replay::Replay(id) if id == raw.authoritative_id && raw.target_id.is_none() => Ok(()),
        Replay::Conflict => Ok(()),
        _ => Err(Rejected::Result),
    }
}

impl Observation {
    pub fn new(prepared: PreparedIngress) -> Self {
        Self(Arc::new(Invocation {
            prepared,
            state: Mutex::new(State {
                command: None,
                snapshot: Snapshot {
                    replay: ReadKnowledge::default(),
                    request_issued: false,
                    repository_started: false,
                    existing: ExistingKnowledge::default(),
                    knowledge: Knowledge::NoCommitRequested,
                    returned: None,
                    wake: Wake::Unavailable,
                    terminal: None,
                },
            }),
        }))
    }
    fn state(&self) -> MutexGuard<'_, State> {
        self.0
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }
    pub fn ingress(&self) -> &Ingress {
        self.0.prepared.ingress()
    }
    pub fn is_for(&self, prepared: &PreparedIngress) -> bool {
        self.0.prepared.same_input(prepared)
    }
    fn same_invocation(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
    pub fn snapshot(&self) -> Snapshot {
        self.state().snapshot.clone()
    }
    pub fn retire(&self, reason: TerminalReason) -> Summary {
        let mut state = self.state();
        state.snapshot.terminal.get_or_insert(reason);
        state.snapshot.summary()
    }
    pub fn replay_request(&self) -> Result<Option<ReplayRequest>, Rejected> {
        let mut state = self.state();
        active(&state.snapshot)?;
        if state.snapshot.replay.issued || state.snapshot.request_issued {
            return Err(Rejected::AlreadyIssued);
        }
        if self.ingress().identity.is_none() {
            return Ok(None);
        }
        state.snapshot.replay.issued = true;
        Ok(Some(ReplayRequest {
            observation: self.clone(),
        }))
    }
    pub fn store_request(&self, command: StoreCommand) -> Result<StoreRequest, Rejected> {
        let mut state = self.state();
        active(&state.snapshot)?;
        if state.snapshot.request_issued {
            return Err(Rejected::AlreadyIssued);
        }
        if !command.matches_ingress(self.ingress()) {
            return Err(Rejected::Input);
        }
        if self.ingress().identity.is_some()
            && (!state.snapshot.replay.miss
                || state.snapshot.replay.returned != Some(ReadReturned::Outcome(Replay::Miss)))
        {
            return Err(Rejected::Read);
        }
        let command = Arc::new(command);
        state.command = Some(command.clone());
        state.snapshot.request_issued = true;
        Ok(StoreRequest {
            observation: self.clone(),
            command,
        })
    }
}

/// Neither this request nor any returned permission is Clone or Copy.
pub struct ReplayRequest {
    observation: Observation,
}
impl ReplayRequest {
    pub fn ingress(&self) -> &Ingress {
        self.observation.ingress()
    }
    fn start(&self, configured_domain: &str) -> Result<(), Rejected> {
        let mut state = self.observation.state();
        active(&state.snapshot)?;
        if !self.ingress().matches_receiving_domain(configured_domain) {
            return Err(Rejected::Input);
        }
        if state.snapshot.replay.started {
            return Err(Rejected::AlreadyStarted);
        }
        state.snapshot.replay.started = true;
        Ok(())
    }
    pub fn observed_miss(&self) -> Result<(), Rejected> {
        let mut state = self.observation.state();
        read_pending(&state.snapshot)?;
        if state.snapshot.replay.miss || state.snapshot.replay.existing.raw.is_some() {
            return Err(Rejected::Read);
        }
        state.snapshot.replay.miss = true;
        Ok(())
    }
    pub fn observed_existing(&self, raw: Existing) -> Result<(), Rejected> {
        let mut state = self.observation.state();
        read_pending(&state.snapshot)?;
        if state.snapshot.replay.miss || state.snapshot.replay.existing.raw.is_some() {
            return Err(Rejected::Read);
        }
        state.snapshot.replay.existing.raw = Some(Arc::new(raw));
        Ok(())
    }
    /// Called only after the repository verifies the stored authenticators.
    pub fn authenticated(&self, raw: &Existing, result: Replay) -> Result<(), Rejected> {
        let mut state = self.observation.state();
        read_pending(&state.snapshot)?;
        classify(&state.snapshot.replay.existing, raw, result)?;
        state.snapshot.replay.existing.authenticated = Some(result);
        Ok(())
    }
    fn returned(&self, result: Replay) -> Result<Replay, Rejected> {
        let mut state = self.observation.state();
        read_pending(&state.snapshot)?;
        state.snapshot.replay.returned = Some(ReadReturned::Outcome(result));
        let known = match result {
            Replay::Miss => state.snapshot.replay.miss,
            _ => state.snapshot.replay.existing.authenticated == Some(result),
        };
        if !known {
            return Err(Rejected::MissingReadEvidence);
        }
        Ok(result)
    }
    fn failed(&self) -> Result<(), Rejected> {
        let mut state = self.observation.state();
        read_pending(&state.snapshot)?;
        state.snapshot.replay.returned = Some(ReadReturned::Error);
        Ok(())
    }
}

pub struct StoreRequest {
    observation: Observation,
    command: Arc<StoreCommand>,
}
impl StoreRequest {
    pub fn command(&self) -> &StoreCommand {
        &self.command
    }
    pub fn observation(&self) -> &Observation {
        &self.observation
    }
    fn start(&self, configured_domain: &str) -> Result<(), Rejected> {
        let mut state = self.observation.state();
        active(&state.snapshot)?;
        if !self
            .observation
            .ingress()
            .matches_receiving_domain(configured_domain)
            || !self.command.matches_ingress(self.observation.ingress())
            || !state
                .command
                .as_ref()
                .is_some_and(|command| Arc::ptr_eq(command, &self.command))
        {
            return Err(Rejected::Input);
        }
        if state.snapshot.repository_started {
            return Err(Rejected::AlreadyStarted);
        }
        state.snapshot.repository_started = true;
        Ok(())
    }
    /// SQL records this before awaiting rollback. It is not yet Replay.
    pub fn observed_existing(&self, raw: Existing) -> Result<(), Rejected> {
        let mut state = self.observation.state();
        store_pending(&state.snapshot)?;
        if self.command.identity.is_none()
            || state.snapshot.existing.raw.is_some()
            || state.snapshot.knowledge != Knowledge::NoCommitRequested
        {
            return Err(Rejected::Knowledge);
        }
        state.snapshot.existing.raw = Some(Arc::new(raw));
        Ok(())
    }
    pub fn authenticated(&self, raw: &Existing, result: Replay) -> Result<(), Rejected> {
        let mut state = self.observation.state();
        store_pending(&state.snapshot)?;
        if state.snapshot.knowledge != Knowledge::NoCommitRequested {
            return Err(Rejected::Knowledge);
        }
        classify(&state.snapshot.existing, raw, result)?;
        state.snapshot.existing.authenticated = Some(result);
        Ok(())
    }
    pub fn enter_commit(&self, stored: Stored) -> Result<PreparedCommit, Rejected> {
        let mut state = self.observation.state();
        store_pending(&state.snapshot)?;
        if state.snapshot.knowledge != Knowledge::NoCommitRequested
            || state.snapshot.existing.raw.is_some()
        {
            return Err(Rejected::Knowledge);
        }
        if !stored.matches_command(self.command(), self.observation.ingress()) {
            return Err(Rejected::Result);
        }
        let fact = Arc::new(stored);
        state.snapshot.knowledge = Knowledge::CommitCallEntered(fact.clone());
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
        store_pending(&state.snapshot)?;
        if !matches!(&state.snapshot.knowledge, Knowledge::CommitCallEntered(fact) if Arc::ptr_eq(fact, &prepared.fact))
        {
            return Err(Rejected::Knowledge);
        }
        state.snapshot.knowledge = Knowledge::ReceiptKnown(prepared.fact);
        Ok(())
    }
    fn returned(&self, admission: Admission) -> Result<Completion, Rejected> {
        let mut state = self.observation.state();
        store_pending(&state.snapshot)?;
        let admission = Arc::new(admission);
        // Preserve even contradictory raw returns beside positive knowledge.
        // They cannot create an accepted continuation or erase the receipt.
        state.snapshot.returned = Some(Returned::Admission(admission.clone()));
        let wake = match admission.outcome {
            Outcome::Stored(_) => match &state.snapshot.knowledge {
                Knowledge::ReceiptKnown(fact) if fact.matches_return(&admission) => {
                    fact.projection.is_some()
                }
                Knowledge::NoCommitRequested => return Err(Rejected::MissingReceipt),
                _ => return Err(Rejected::Result),
            },
            outcome => {
                if state.snapshot.knowledge != Knowledge::NoCommitRequested
                    || !admission.recipients.is_empty()
                {
                    return Err(Rejected::Result);
                }
                match outcome {
                    Outcome::Replay(id)
                        if state.snapshot.existing.authenticated == Some(Replay::Replay(id)) => {}
                    Outcome::Replay(_) => return Err(Rejected::MissingReadEvidence),
                    Outcome::Conflict if state.snapshot.existing.raw.is_some() => {
                        if state.snapshot.existing.authenticated != Some(Replay::Conflict) {
                            return Err(Rejected::MissingReadEvidence);
                        }
                    }
                    Outcome::Conflict | Outcome::TooLarge | Outcome::NotParticipant => {
                        if state.snapshot.existing.raw.is_some() {
                            return Err(Rejected::Result);
                        }
                    }
                    Outcome::Stored(_) => unreachable!(),
                }
                false
            }
        };
        if let Outcome::Stored(id) = admission.outcome {
            state.snapshot.returned = Some(Returned::AcceptedStored(id));
        }
        let permit = wake.then(|| {
            state.snapshot.wake = Wake::Ready;
            WakePermit {
                observation: self.observation.clone(),
            }
        });
        Ok(Completion {
            observation: self.observation.clone(),
            admission,
            permit,
        })
    }
    fn failed(&self) -> Result<(), Rejected> {
        let mut state = self.observation.state();
        store_pending(&state.snapshot)?;
        state.snapshot.returned = Some(Returned::Error);
        Ok(())
    }
}

pub struct PreparedCommit {
    observation: Observation,
    fact: Arc<Stored>,
}
#[derive(Debug)]
pub enum CommitError<E> {
    Observation(Rejected),
    Commit(E),
}

/// Called around the real COMMIT future. Constructing this future is not
/// entry. Successful receipt is recorded without an intervening await.
pub async fn commit_observed<E>(
    commit: impl Future<Output = Result<(), E>>,
    request: &StoreRequest,
    fact: Stored,
) -> Result<(), CommitError<E>> {
    let prepared = request
        .enter_commit(fact)
        .map_err(CommitError::Observation)?;
    commit.await.map_err(CommitError::Commit)?;
    request.received(prepared).map_err(CommitError::Observation)
}

#[derive(Debug)]
pub enum EffectError<E> {
    Observation(Rejected),
    Repository(E),
}

pub async fn read_observed<E>(
    request: &ReplayRequest,
    configured_domain: &str,
    effect: impl Future<Output = Result<Replay, E>>,
) -> Result<Replay, EffectError<E>> {
    request
        .start(configured_domain)
        .map_err(EffectError::Observation)?;
    match effect.await {
        Ok(result) => request.returned(result).map_err(EffectError::Observation),
        Err(error) => {
            request.failed().map_err(EffectError::Observation)?;
            Err(EffectError::Repository(error))
        }
    }
}

pub async fn admit_observed<E>(
    request: &StoreRequest,
    configured_domain: &str,
    effect: impl Future<Output = Result<Admission, E>>,
) -> Result<Completion, EffectError<E>> {
    request
        .start(configured_domain)
        .map_err(EffectError::Observation)?;
    match effect.await {
        Ok(result) => request.returned(result).map_err(EffectError::Observation),
        Err(error) => {
            request.failed().map_err(EffectError::Observation)?;
            Err(EffectError::Repository(error))
        }
    }
}

pub struct Completion {
    observation: Observation,
    admission: Arc<Admission>,
    permit: Option<WakePermit>,
}
impl Completion {
    pub fn into_wake(
        self,
        expected: &Observation,
    ) -> Result<(Arc<Admission>, Option<WakePermit>), Rejected> {
        if !self.observation.same_invocation(expected) {
            return Err(Rejected::Invocation);
        }
        active(&self.observation.state().snapshot)?;
        Ok((self.admission, self.permit))
    }
}

pub struct WakePermit {
    observation: Observation,
}
impl WakePermit {
    /// Consumption precedes the existing synchronous local wake invocation.
    /// This grants no claim, route, transport, delivery or settlement right.
    pub fn invoke(self, publish: impl FnOnce()) -> Result<(), Rejected> {
        {
            let mut state = self.observation.state();
            active(&state.snapshot)?;
            if state.snapshot.wake != Wake::Ready {
                return Err(Rejected::Wake);
            }
            state.snapshot.wake = Wake::Invoked;
        }
        publish();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use northstar_room_core::mix::{
        DeliveryProjection, Id, Participant, RecipientProjection, ReplayIdentity,
    };

    fn ingress(identity: bool) -> Ingress {
        Ingress {
            channel_id: Id::from_u128(1),
            channel_jid: "room@mix.local.test".into(),
            actor_bare: "alice@local.test".into(),
            actor_full: "alice@local.test/phone".into(),
            children: "<body>hello</body>".into(),
            encrypted: false,
            identity: identity.then(|| ReplayIdentity {
                client_id: "original".into(),
                canonical_semantics: vec![1, 2, 3],
            }),
        }
    }
    fn command(identity: bool) -> StoreCommand {
        let input = ingress(identity);
        StoreCommand {
            channel_id: input.channel_id,
            actor: input.actor_bare,
            item_id: Id::from_u128(2),
            payload: "<message><body>hello</body></message>".into(),
            identity: input.identity,
            delivery_payload: input.children,
            visible_jid: None,
            encrypted: false,
        }
    }
    fn participant() -> Participant {
        Participant {
            participant_id: Id::from_u128(3),
            jid: "bob@local.test".into(),
            nick: Some("Bob".into()),
        }
    }
    fn stored(audience: bool) -> Stored {
        Stored {
            authoritative_id: Id::from_u128(2),
            storage_id: Id::from_u128(4),
            channel_id: Id::from_u128(1),
            channel_jid: "room@mix.local.test".into(),
            projection: audience.then(|| DeliveryProjection {
                event_id: Id::from_u128(2),
                channel_id: Id::from_u128(1),
                channel_jid: "room@mix.local.test".into(),
                stanza_template: "<message to='bob@local.test'/>".into(),
                authoritative_stanza_id: Some(Id::from_u128(2)),
                archive: true,
                encrypted: false,
                recipients: vec![RecipientProjection {
                    participant: participant(),
                    delivery_id: Id::from_u128(5),
                    sequence: 91,
                }],
            }),
        }
    }
    fn admission(audience: bool) -> Admission {
        Admission {
            outcome: Outcome::Stored(Id::from_u128(2)),
            recipients: if audience {
                vec![participant()]
            } else {
                vec![]
            },
        }
    }
    fn existing() -> Existing {
        Existing {
            authoritative_id: Id::from_u128(99),
            semantic_key_id: "test".into(),
            semantic_mac: vec![7; 32],
            target_id: None,
        }
    }
    fn owner(identity: bool) -> Observation {
        let owner = Observation::new(PreparedIngress::new(ingress(identity)));
        if let Some(read) = owner.replay_request().unwrap() {
            read.start("mix.local.test").unwrap();
            read.observed_miss().unwrap();
            assert_eq!(read.returned(Replay::Miss), Ok(Replay::Miss));
        }
        owner
    }
    fn started_request(owner: &Observation, identity: bool) -> StoreRequest {
        let request = owner.store_request(command(identity)).unwrap();
        request.start("mix.local.test").unwrap();
        request
    }
    fn receipt(request: &StoreRequest, audience: bool) {
        let prepared = request.enter_commit(stored(audience)).unwrap();
        request.received(prepared).unwrap();
    }

    #[test]
    fn private_input_domain_and_single_start_are_enforced_before_changes() {
        let observation = owner(false);
        let mut changed = command(false);
        changed.delivery_payload.push('x');
        let before = observation.snapshot();
        assert!(matches!(
            observation.store_request(changed),
            Err(Rejected::Input)
        ));
        assert_eq!(observation.snapshot(), before);
        let request = observation.store_request(command(false)).unwrap();
        assert_eq!(request.start("mix.attacker.test"), Err(Rejected::Input));
        assert!(!observation.snapshot().repository_started);
        request.start("mix.local.test").unwrap();
        assert_eq!(
            request.start("mix.local.test"),
            Err(Rejected::AlreadyStarted)
        );
        assert!(matches!(
            observation.store_request(command(false)),
            Err(Rejected::AlreadyIssued)
        ));
        let mut claimed = ingress(false);
        claimed.channel_jid = "room@mix.attacker.test".into();
        assert!(claimed.matches_receiving_domain("mix.attacker.test"));
        assert!(!claimed.matches_receiving_domain("mix.local.test"));
    }

    #[test]
    fn identical_ids_and_shared_preparation_cannot_pair_private_invocations() {
        let prepared = PreparedIngress::new(ingress(false));
        let first = Observation::new(prepared.clone());
        let second = Observation::new(prepared);
        let a = started_request(&first, false);
        let b = started_request(&second, false);
        let foreign = b.enter_commit(stored(true)).unwrap();
        let before = first.snapshot();
        assert_eq!(a.received(foreign), Err(Rejected::Invocation));
        assert_eq!(first.snapshot(), before);
        receipt(&a, true);
        let completion = a.returned(admission(true)).unwrap();
        assert!(matches!(
            completion.into_wake(&second),
            Err(Rejected::Invocation)
        ));
        assert_eq!(first.snapshot().wake, Wake::Ready);
        assert_eq!(second.snapshot().wake, Wake::Unavailable);
    }

    #[test]
    fn replay_is_authenticated_read_evidence_and_preserves_original_id() {
        let observation = Observation::new(PreparedIngress::new(ingress(true)));
        assert!(matches!(
            observation.store_request(command(true)),
            Err(Rejected::Read)
        ));
        let read = observation.replay_request().unwrap().unwrap();
        read.start("mix.local.test").unwrap();
        let raw = existing();
        read.observed_existing(raw.clone()).unwrap();
        assert_eq!(observation.snapshot().replay.existing.authenticated, None);
        read.authenticated(&raw, Replay::Replay(Id::from_u128(99)))
            .unwrap();
        assert_eq!(
            read.returned(Replay::Replay(Id::from_u128(99))),
            Ok(Replay::Replay(Id::from_u128(99)))
        );
        assert!(matches!(
            observation.store_request(command(true)),
            Err(Rejected::Read)
        ));
        assert_eq!(
            observation.snapshot().knowledge,
            Knowledge::NoCommitRequested
        );
        assert_eq!(observation.snapshot().wake, Wake::Unavailable);
    }

    #[test]
    fn unobserved_read_returns_cannot_authorize_first_execution() {
        for result in [
            Replay::Miss,
            Replay::Replay(Id::from_u128(99)),
            Replay::Conflict,
        ] {
            let observation = Observation::new(PreparedIngress::new(ingress(true)));
            let read = observation.replay_request().unwrap().unwrap();
            read.start("mix.local.test").unwrap();
            assert_eq!(read.returned(result), Err(Rejected::MissingReadEvidence));
            assert_eq!(
                observation.snapshot().replay.returned,
                Some(ReadReturned::Outcome(result))
            );
            assert!(matches!(
                observation.store_request(command(true)),
                Err(Rejected::Read)
            ));
        }
    }

    #[test]
    fn raw_existing_requires_matching_repository_classification() {
        for result in [Replay::Replay(Id::from_u128(99)), Replay::Conflict] {
            let observation = owner(true);
            let request = started_request(&observation, true);
            let raw = existing();
            request.observed_existing(raw.clone()).unwrap();
            assert_eq!(observation.snapshot().existing.authenticated, None);
            let mut other = raw.clone();
            other.semantic_mac[0] ^= 1;
            assert_eq!(request.authenticated(&other, result), Err(Rejected::Read));
            request.authenticated(&raw, result).unwrap();
            let outcome = match result {
                Replay::Replay(id) => Outcome::Replay(id),
                _ => Outcome::Conflict,
            };
            let completion = request
                .returned(Admission {
                    outcome,
                    recipients: vec![],
                })
                .unwrap();
            assert!(completion.into_wake(&observation).unwrap().1.is_none());
            assert_eq!(
                observation.snapshot().knowledge,
                Knowledge::NoCommitRequested
            );
        }
    }

    #[test]
    fn receipt_free_refusals_are_valid_but_returned_only_success_is_not() {
        for outcome in [
            Outcome::Conflict,
            Outcome::TooLarge,
            Outcome::NotParticipant,
        ] {
            let observation = owner(false);
            let request = started_request(&observation, false);
            let result = request
                .returned(Admission {
                    outcome,
                    recipients: vec![],
                })
                .unwrap();
            assert!(result.into_wake(&observation).unwrap().1.is_none());
            assert_eq!(
                observation.snapshot().knowledge,
                Knowledge::NoCommitRequested
            );
        }
        for outcome in [
            Outcome::Stored(Id::from_u128(2)),
            Outcome::Replay(Id::from_u128(99)),
        ] {
            let observation = owner(true);
            let request = started_request(&observation, true);
            assert!(request
                .returned(Admission {
                    outcome,
                    recipients: vec![]
                })
                .is_err());
            assert!(
                matches!(observation.snapshot().returned, Some(Returned::Admission(value)) if value.outcome == outcome)
            );
            assert_eq!(observation.snapshot().wake, Wake::Unavailable);
        }
    }

    #[test]
    fn contradictory_returns_retain_positive_receipt_without_continuation() {
        for outcome in [
            Outcome::Replay(Id::from_u128(99)),
            Outcome::Conflict,
            Outcome::TooLarge,
            Outcome::NotParticipant,
            Outcome::Stored(Id::from_u128(77)),
        ] {
            let observation = owner(false);
            let request = started_request(&observation, false);
            receipt(&request, true);
            let expected = observation.snapshot().knowledge;
            assert!(matches!(
                request.returned(Admission {
                    outcome,
                    recipients: vec![]
                }),
                Err(Rejected::Result)
            ));
            assert_eq!(observation.snapshot().knowledge, expected);
            assert!(
                matches!(observation.snapshot().returned, Some(Returned::Admission(raw)) if raw.outcome == outcome)
            );
            assert_eq!(observation.snapshot().wake, Wake::Unavailable);
        }
    }

    #[test]
    fn exact_projection_is_retained_and_only_nonempty_acceptance_wakes_once() {
        for audience in [false, true] {
            let observation = owner(false);
            let request = started_request(&observation, false);
            receipt(&request, audience);
            let completion = request.returned(admission(audience)).unwrap();
            let (returned, permit) = completion.into_wake(&observation).unwrap();
            assert_eq!(*returned, admission(audience));
            assert_eq!(
                observation.snapshot().returned,
                Some(Returned::AcceptedStored(Id::from_u128(2)))
            );
            let calls = std::cell::Cell::new(0);
            if let Some(permit) = permit {
                permit
                    .invoke(|| {
                        assert_eq!(observation.snapshot().wake, Wake::Invoked);
                        calls.set(calls.get() + 1);
                    })
                    .unwrap();
            }
            assert_eq!(calls.get(), usize::from(audience));
            let Knowledge::ReceiptKnown(fact) = observation.snapshot().knowledge else {
                panic!("receipt missing");
            };
            assert_eq!(fact.storage_id, Id::from_u128(4));
            assert_eq!(*fact, stored(audience));
            assert!(matches!(
                request.returned(admission(audience)),
                Err(Rejected::AlreadyReturned)
            ));
        }
    }

    #[test]
    fn terminal_rejection_is_typed_and_late_callbacks_do_not_change_facts() {
        let observation = owner(true);
        let request = started_request(&observation, true);
        let prepared = request.enter_commit(stored(false)).unwrap();
        observation.retire(TerminalReason::Cancelled);
        let frozen = observation.snapshot();
        assert_eq!(request.received(prepared), Err(Rejected::Retired));
        assert_eq!(
            request.observed_existing(existing()),
            Err(Rejected::Retired)
        );
        assert!(matches!(
            request.returned(admission(false)),
            Err(Rejected::Retired)
        ));
        assert!(matches!(
            observation.replay_request(),
            Err(Rejected::Retired)
        ));
        assert!(matches!(
            observation.store_request(command(true)),
            Err(Rejected::Retired)
        ));
        assert_eq!(observation.snapshot(), frozen);
    }

    #[test]
    fn changed_audience_or_entered_only_return_cannot_override_positive_knowledge() {
        let observation = owner(false);
        let request = started_request(&observation, false);
        receipt(&request, true);
        let mut raw = admission(true);
        raw.recipients[0].jid = "mallory@local.test".into();
        assert!(matches!(
            request.returned(raw.clone()),
            Err(Rejected::Result)
        ));
        assert!(
            matches!(observation.snapshot().knowledge, Knowledge::ReceiptKnown(fact) if *fact == stored(true))
        );
        assert_eq!(
            observation.snapshot().returned,
            Some(Returned::Admission(Arc::new(raw)))
        );
        assert_eq!(observation.snapshot().wake, Wake::Unavailable);

        let observation = owner(false);
        let request = started_request(&observation, false);
        let _pending = request.enter_commit(stored(true)).unwrap();
        assert!(matches!(
            request.returned(Admission {
                outcome: Outcome::TooLarge,
                recipients: vec![]
            }),
            Err(Rejected::Result)
        ));
        assert!(matches!(
            observation.snapshot().knowledge,
            Knowledge::CommitCallEntered(_)
        ));
        assert_eq!(observation.snapshot().wake, Wake::Unavailable);
    }
}
