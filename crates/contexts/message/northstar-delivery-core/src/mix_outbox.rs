//! One observed Delivery claim and its consuming worker attempts. These
//! in-process permissions do not replace PostgreSQL's exact-source fences.

use crate::MixDelivery;
use std::{
    future::Future,
    sync::{Arc, Mutex, MutexGuard},
};
use uuid::Uuid;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Row {
    pub source: MixDelivery,
    pub event_id: Uuid,
    pub channel_id: Uuid,
    pub channel_jid: String,
    pub participant_id: Uuid,
    pub recipient_jid: String,
    pub recipient_nick: Option<String>,
    pub stanza: String,
    pub authoritative_stanza_id: Option<Uuid>,
    pub archive: bool,
    pub encrypted: bool,
    pub attempt_count: i32,
    pub route_wake_generation: i64,
}

pub type Rows = Arc<[Arc<Row>]>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClaimCommand {
    pub limit: i64,
    pub max_bytes: i64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Rejected {
    Retired,
    Invocation,
    Input,
    Issued,
    Started,
    NotStarted,
    Returned,
    Knowledge,
    MissingReceipt,
    Result,
    Phase,
    Transferred,
    LeaseLost,
    Settlement,
    Renewal,
}
impl std::fmt::Display for Rejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MIX outbox rejected: {self:?}")
    }
}
impl std::error::Error for Rejected {}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalReason {
    Completed,
    BackendFailure,
    Cancelled,
    TimedOut,
    Panicked,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClaimKnowledge {
    NoStatementEntered,
    ReadEmpty,
    AutocommitStatementEntered,
    StatementReceipt(Rows),
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClaimReturned {
    Accepted(usize),
    Rejected(Rows),
    Error,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimSnapshot {
    pub issued: bool,
    pub started: bool,
    pub knowledge: ClaimKnowledge,
    pub returned: Option<ClaimReturned>,
    pub terminal: Option<TerminalReason>,
}
struct ClaimInvocation {
    command: ClaimCommand,
    state: Mutex<ClaimSnapshot>,
}
#[derive(Clone)]
pub struct ClaimObservation(Arc<ClaimInvocation>);
impl ClaimObservation {
    pub fn new(command: ClaimCommand) -> Self {
        Self(Arc::new(ClaimInvocation {
            command,
            state: Mutex::new(ClaimSnapshot {
                issued: false,
                started: false,
                knowledge: ClaimKnowledge::NoStatementEntered,
                returned: None,
                terminal: None,
            }),
        }))
    }
    fn state(&self) -> MutexGuard<'_, ClaimSnapshot> {
        self.0.state.lock().unwrap_or_else(|e| e.into_inner())
    }
    pub fn snapshot(&self) -> ClaimSnapshot {
        self.state().clone()
    }
    pub fn request(&self) -> Result<ClaimRequest, Rejected> {
        let mut state = self.state();
        if state.terminal.is_some() {
            return Err(Rejected::Retired);
        }
        if state.issued {
            return Err(Rejected::Issued);
        }
        state.issued = true;
        Ok(ClaimRequest {
            observation: self.clone(),
        })
    }
    pub fn retire(&self, reason: TerminalReason) -> ClaimSnapshot {
        let mut state = self.state();
        state.terminal.get_or_insert(reason);
        state.clone()
    }
}
pub struct ClaimRequest {
    observation: ClaimObservation,
}
pub struct ClaimStatement {
    observation: ClaimObservation,
}
impl ClaimRequest {
    pub fn command(&self) -> ClaimCommand {
        self.observation.0.command
    }
    pub fn start(&self) -> Result<(), Rejected> {
        let mut state = self.observation.state();
        if state.terminal.is_some() {
            return Err(Rejected::Retired);
        }
        if state.started {
            return Err(Rejected::Started);
        }
        state.started = true;
        Ok(())
    }
    fn pending(state: &ClaimSnapshot) -> Result<(), Rejected> {
        if state.terminal.is_some() {
            return Err(Rejected::Retired);
        }
        if !state.started {
            return Err(Rejected::NotStarted);
        }
        if state.returned.is_some() {
            return Err(Rejected::Returned);
        }
        Ok(())
    }
    pub fn read_empty(&self) -> Result<(), Rejected> {
        let mut state = self.observation.state();
        Self::pending(&state)?;
        if state.knowledge != ClaimKnowledge::NoStatementEntered {
            return Err(Rejected::Knowledge);
        }
        state.knowledge = ClaimKnowledge::ReadEmpty;
        Ok(())
    }
    pub fn enter_statement(&self) -> Result<ClaimStatement, Rejected> {
        let mut state = self.observation.state();
        Self::pending(&state)?;
        if state.knowledge != ClaimKnowledge::NoStatementEntered {
            return Err(Rejected::Knowledge);
        }
        state.knowledge = ClaimKnowledge::AutocommitStatementEntered;
        Ok(ClaimStatement {
            observation: self.observation.clone(),
        })
    }
    pub fn received(&self, entered: ClaimStatement, rows: Rows) -> Result<(), Rejected> {
        if !Arc::ptr_eq(&self.observation.0, &entered.observation.0) {
            return Err(Rejected::Invocation);
        }
        let mut state = self.observation.state();
        Self::pending(&state)?;
        if state.knowledge != ClaimKnowledge::AutocommitStatementEntered {
            return Err(Rejected::Knowledge);
        }
        state.knowledge = ClaimKnowledge::StatementReceipt(rows);
        Ok(())
    }
    pub fn returned(&self, rows: Rows) -> Result<Vec<Attempt>, Rejected> {
        let mut state = self.observation.state();
        Self::pending(&state)?;
        state.returned = Some(ClaimReturned::Rejected(rows.clone()));
        let exact = match &state.knowledge {
            ClaimKnowledge::ReadEmpty => rows.is_empty(),
            ClaimKnowledge::StatementReceipt(receipt) => Arc::ptr_eq(receipt, &rows),
            _ => false,
        };
        if !exact {
            return Err(Rejected::MissingReceipt);
        }
        if rows
            .iter()
            .map(|row| row.source.delivery_id)
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != rows.len()
        {
            return Err(Rejected::Result);
        }
        state.returned = Some(ClaimReturned::Accepted(rows.len()));
        Ok(rows
            .iter()
            .map(|row| Attempt {
                observation: Observation::new(self.observation.clone(), row.clone()),
            })
            .collect())
    }
    pub fn failed(&self) -> Result<(), Rejected> {
        let mut state = self.observation.state();
        Self::pending(&state)?;
        state.returned = Some(ClaimReturned::Error);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArchiveResult {
    Stored(Uuid),
    Replay(Uuid),
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveCommand {
    pub personal_archive_id: Uuid,
    pub owner_id: Uuid,
    pub channel_jid: String,
    pub authoritative_stanza_id: Uuid,
    pub stanza: Arc<str>,
    pub encrypted: bool,
    pub client_stanza_id: Option<String>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArchiveKnowledge {
    NoCommitEntered,
    CommitCallEntered(ArchiveResult),
    ReceiptKnown(ArchiveResult),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArchiveReturned {
    Outcome(ArchiveResult),
    Error,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveSnapshot {
    pub issued: bool,
    pub started: bool,
    pub knowledge: ArchiveKnowledge,
    pub returned: Option<ArchiveReturned>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransferBoundary {
    SocketFenced(Uuid),
    SmPersisted(Uuid),
    BoshPersisted(Uuid),
    ClusterSocketFenced,
    ClusterSmPersisted,
    ClusterBoshPersisted,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferFact {
    pub target: String,
    pub boundary: TransferBoundary,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalResult {
    QueueFull,
    QueueClosed,
    HandoffClosed,
    Transferred(TransferBoundary),
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalPrefix {
    pub target: String,
    pub started: bool,
    pub enqueued: bool,
    pub returned: Option<LocalResult>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClusterPrefix {
    pub node: String,
    pub started: bool,
    pub returned: bool,
    pub handoff: Option<TransferBoundary>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteResult {
    CompletedByWorker,
    Transferred,
    Pending,
    Permanent,
    Retry,
    Cancelled,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoutePhase {
    Unprepared,
    Prepared,
    Started,
    Returned,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryResult {
    LeaseLost,
    Retried,
    RouteWokenAtAttemptLimit,
    DeadLettered,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SettlementKind {
    Ack,
    Defer,
    Retry,
    DeadLetter,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SettlementResult {
    /// False is no exact-token deletion, not proof of row absence or another owner.
    Ack(bool),
    /// False is no matching exact-source update.
    Defer(bool),
    Retry(RetryResult),
    /// False means NotMoved, including the existing ON CONFLICT outcome.
    DeadLetter(bool),
}
impl SettlementResult {
    pub fn kind(self) -> SettlementKind {
        match self {
            Self::Ack(_) => SettlementKind::Ack,
            Self::Defer(_) => SettlementKind::Defer,
            Self::Retry(_) => SettlementKind::Retry,
            Self::DeadLetter(_) => SettlementKind::DeadLetter,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SettlementKnowledge {
    NotEntered,
    CommitCallEntered(SettlementResult),
    AutocommitStatementEntered,
    ReceiptKnown(SettlementResult),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SettlementReturned {
    Outcome(SettlementResult),
    Error,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SettlementSnapshot {
    pub kind: SettlementKind,
    pub started: bool,
    pub knowledge: SettlementKnowledge,
    pub returned: Option<SettlementReturned>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RenewalKnowledge {
    NotEntered,
    AutocommitStatementEntered,
    StatementReceipt(bool),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RenewalReturned {
    Outcome(bool),
    Error,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenewalSnapshot {
    pub issued: u64,
    pub started: bool,
    pub pending: bool,
    pub knowledge: RenewalKnowledge,
    pub returned: Option<RenewalReturned>,
    pub last_receipt: Option<(u64, bool)>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Snapshot {
    pub route: RoutePhase,
    pub route_returned: Option<RouteResult>,
    pub archive: ArchiveSnapshot,
    pub local: Vec<LocalPrefix>,
    pub cluster: Vec<ClusterPrefix>,
    pub transfer: Option<TransferFact>,
    pub lease_lost: bool,
    pub aborted: bool,
    pub renewal_scope_closed: bool,
    pub renewal: RenewalSnapshot,
    pub settlement: Option<SettlementSnapshot>,
    pub terminal: Option<TerminalReason>,
}
struct State {
    snapshot: Snapshot,
    stanza: Option<Arc<str>>,
    archive: Option<Arc<ArchiveCommand>>,
}
struct Invocation {
    _batch: ClaimObservation,
    row: Arc<Row>,
    state: Mutex<State>,
}
#[derive(Clone)]
pub struct Observation(Arc<Invocation>);
impl Observation {
    fn new(batch: ClaimObservation, row: Arc<Row>) -> Self {
        Self(Arc::new(Invocation {
            _batch: batch,
            row,
            state: Mutex::new(State {
                stanza: None,
                archive: None,
                snapshot: Snapshot {
                    route: RoutePhase::Unprepared,
                    route_returned: None,
                    archive: ArchiveSnapshot {
                        issued: false,
                        started: false,
                        knowledge: ArchiveKnowledge::NoCommitEntered,
                        returned: None,
                    },
                    local: vec![],
                    cluster: vec![],
                    transfer: None,
                    lease_lost: false,
                    aborted: false,
                    renewal_scope_closed: false,
                    renewal: RenewalSnapshot {
                        issued: 0,
                        started: false,
                        pending: false,
                        knowledge: RenewalKnowledge::NotEntered,
                        returned: None,
                        last_receipt: None,
                    },
                    settlement: None,
                    terminal: None,
                },
            }),
        }))
    }
    fn state(&self) -> MutexGuard<'_, State> {
        self.0.state.lock().unwrap_or_else(|e| e.into_inner())
    }
    pub fn row(&self) -> &Row {
        &self.0.row
    }
    pub fn snapshot(&self) -> Snapshot {
        self.state().snapshot.clone()
    }
    pub fn retire(&self, reason: TerminalReason) -> Snapshot {
        let mut state = self.state();
        state.snapshot.terminal.get_or_insert(reason);
        state.snapshot.clone()
    }
    fn same(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
    pub fn renewal_request(&self) -> Result<RenewalRequest, Rejected> {
        let mut state = self.state();
        available(&state.snapshot)?;
        if state.snapshot.route != RoutePhase::Started
            || state.snapshot.renewal.pending
            || state.snapshot.renewal_scope_closed
        {
            return Err(Rejected::Renewal);
        }
        let renewal = &mut state.snapshot.renewal;
        renewal.issued += 1;
        renewal.started = false;
        renewal.pending = true;
        renewal.knowledge = RenewalKnowledge::NotEntered;
        renewal.returned = None;
        Ok(RenewalRequest {
            observation: self.clone(),
            ordinal: renewal.issued,
        })
    }
    /// The runtime calls this only after the existing route/renewal helper
    /// returns and has destroyed its children. Pending knowledge is retained;
    /// destruction is not a fabricated renewal result.
    pub fn close_renewal_scope(&self) -> Result<RenewalScopeClosed, Rejected> {
        let mut state = self.state();
        active(&state.snapshot)?;
        if state.snapshot.renewal_scope_closed
            || !matches!(
                state.snapshot.route,
                RoutePhase::Prepared | RoutePhase::Started | RoutePhase::Returned
            )
        {
            return Err(Rejected::Phase);
        }
        state.snapshot.renewal_scope_closed = true;
        Ok(RenewalScopeClosed {
            observation: self.clone(),
        })
    }
}
pub struct RenewalScopeClosed {
    observation: Observation,
}
fn active(state: &Snapshot) -> Result<(), Rejected> {
    if state.terminal.is_some() {
        return Err(Rejected::Retired);
    }
    Ok(())
}
fn available(state: &Snapshot) -> Result<(), Rejected> {
    active(state)?;
    if state.transfer.is_some() {
        return Err(Rejected::Transferred);
    }
    if state.lease_lost {
        return Err(Rejected::LeaseLost);
    }
    if state.aborted {
        return Err(Rejected::Phase);
    }
    if state.settlement.is_some() {
        return Err(Rejected::Settlement);
    }
    Ok(())
}
fn route_pending(state: &Snapshot) -> Result<(), Rejected> {
    active(state)?;
    if state.route != RoutePhase::Started || state.renewal_scope_closed {
        return Err(Rejected::Phase);
    }
    Ok(())
}
fn archive_allows_route(state: &Snapshot) -> Result<(), Rejected> {
    if state.archive.issued
        && !matches!((state.archive.knowledge, state.archive.returned),
        (ArchiveKnowledge::ReceiptKnown(known), Some(ArchiveReturned::Outcome(returned))) if known == returned)
    {
        return Err(Rejected::MissingReceipt);
    }
    Ok(())
}

/// Only a consumed successful batch completion can construct this value.
pub struct Attempt {
    observation: Observation,
}
impl Attempt {
    pub fn observation(&self) -> Observation {
        self.observation.clone()
    }
    pub fn row(&self) -> &Row {
        self.observation.row()
    }
    pub fn route(self, stanza: String) -> Result<RouteRequest, Rejected> {
        let document = roxmltree::Document::parse(&stanza).map_err(|_| Rejected::Input)?;
        if document.root_element().attribute("to") != Some(self.row().recipient_jid.as_str()) {
            return Err(Rejected::Input);
        }
        drop(document);
        let stanza: Arc<str> = Arc::from(stanza);
        {
            let mut state = self.observation.state();
            available(&state.snapshot)?;
            if state.snapshot.route != RoutePhase::Unprepared {
                return Err(Rejected::Issued);
            }
            state.stanza = Some(stanza.clone());
            state.snapshot.route = RoutePhase::Prepared;
        }
        Ok(RouteRequest {
            observation: self.observation,
            stanza,
        })
    }
    pub fn invalid_template(self, error: String) -> Result<SettlementRequest, Rejected> {
        issue_settlement(
            &self.observation,
            SettlementCommand::DeadLetter {
                reason: "invalid-template".into(),
                error,
            },
            true,
        )
    }
}

pub struct RouteRequest {
    observation: Observation,
    stanza: Arc<str>,
}
impl RouteRequest {
    pub fn observation(&self) -> &Observation {
        &self.observation
    }
    pub fn row(&self) -> &Row {
        self.observation.row()
    }
    pub fn stanza(&self) -> &str {
        &self.stanza
    }
    pub fn start(&self) -> Result<(), Rejected> {
        let mut state = self.observation.state();
        available(&state.snapshot)?;
        if state.snapshot.route != RoutePhase::Prepared
            || state.snapshot.renewal_scope_closed
            || !state
                .stanza
                .as_ref()
                .is_some_and(|stanza| Arc::ptr_eq(stanza, &self.stanza))
        {
            return Err(Rejected::Phase);
        }
        state.snapshot.route = RoutePhase::Started;
        Ok(())
    }
    pub fn archive_request(
        &self,
        owner_id: Uuid,
        personal_archive_id: Uuid,
        client_stanza_id: Option<String>,
    ) -> Result<ArchiveRequest, Rejected> {
        let mut state = self.observation.state();
        available(&state.snapshot)?;
        route_pending(&state.snapshot)?;
        if !self.row().archive || state.snapshot.archive.issued {
            return Err(Rejected::Phase);
        }
        let authoritative_stanza_id = self.row().authoritative_stanza_id.ok_or(Rejected::Input)?;
        let command = Arc::new(ArchiveCommand {
            personal_archive_id,
            owner_id,
            channel_jid: self.row().channel_jid.clone(),
            authoritative_stanza_id,
            stanza: self.stanza.clone(),
            encrypted: self.row().encrypted,
            client_stanza_id,
        });
        state.archive = Some(command.clone());
        state.snapshot.archive.issued = true;
        Ok(ArchiveRequest {
            observation: self.observation.clone(),
            command,
        })
    }
    pub fn local_request(&self, target: String) -> Result<LocalRequest, Rejected> {
        let mut state = self.observation.state();
        available(&state.snapshot)?;
        route_pending(&state.snapshot)?;
        archive_allows_route(&state.snapshot)?;
        if self.row().archive && !state.snapshot.archive.issued {
            return Err(Rejected::MissingReceipt);
        }
        if !state.snapshot.cluster.is_empty()
            || state
                .snapshot
                .local
                .last()
                .is_some_and(|entry| entry.returned.is_none())
        {
            return Err(Rejected::Phase);
        }
        let index = state.snapshot.local.len();
        state.snapshot.local.push(LocalPrefix {
            target: target.clone(),
            started: false,
            enqueued: false,
            returned: None,
        });
        Ok(LocalRequest {
            observation: self.observation.clone(),
            stanza: self.stanza.clone(),
            target,
            index,
        })
    }
    pub fn cluster_request(&self, node: String) -> Result<ClusterRequest, Rejected> {
        let mut state = self.observation.state();
        available(&state.snapshot)?;
        route_pending(&state.snapshot)?;
        archive_allows_route(&state.snapshot)?;
        if self.row().archive && !state.snapshot.archive.issued {
            return Err(Rejected::MissingReceipt);
        }
        if state
            .snapshot
            .local
            .last()
            .is_some_and(|entry| entry.returned.is_none())
            || state
                .snapshot
                .cluster
                .last()
                .is_some_and(|entry| !entry.returned)
        {
            return Err(Rejected::Phase);
        }
        let index = state.snapshot.cluster.len();
        state.snapshot.cluster.push(ClusterPrefix {
            node: node.clone(),
            started: false,
            returned: false,
            handoff: None,
        });
        Ok(ClusterRequest {
            observation: self.observation.clone(),
            stanza: self.stanza.clone(),
            node,
            index,
        })
    }
    pub fn returned(self, result: RouteResult) -> Result<RouteCompletion, Rejected> {
        {
            let mut state = self.observation.state();
            active(&state.snapshot)?;
            if state.snapshot.route != RoutePhase::Started {
                return Err(Rejected::Phase);
            }
            state.snapshot.route_returned = Some(result);
            state.snapshot.route = RoutePhase::Returned;
            if state.snapshot.aborted {
                return Err(Rejected::Phase);
            }
            if state.snapshot.archive.issued && state.snapshot.archive.returned.is_none() {
                state.snapshot.aborted = true;
                return Err(Rejected::MissingReceipt);
            }
            if state
                .snapshot
                .local
                .iter()
                .any(|entry| entry.returned.is_none())
                || state.snapshot.cluster.iter().any(|entry| !entry.returned)
            {
                state.snapshot.aborted = true;
                return Err(Rejected::MissingReceipt);
            }
            if result == RouteResult::Transferred {
                if state.snapshot.transfer.is_none() {
                    return Err(Rejected::MissingReceipt);
                }
            } else if state.snapshot.transfer.is_some() {
                return Err(Rejected::Transferred);
            }
            if state.snapshot.lease_lost {
                return Err(Rejected::LeaseLost);
            }
            if result == RouteResult::CompletedByWorker {
                archive_allows_route(&state.snapshot)?;
            }
        }
        Ok(RouteCompletion {
            observation: self.observation,
            result,
        })
    }
}

pub struct ArchiveRequest {
    observation: Observation,
    command: Arc<ArchiveCommand>,
}
pub struct ArchiveCommit {
    observation: Observation,
    result: ArchiveResult,
}
impl ArchiveRequest {
    pub fn command(&self) -> &ArchiveCommand {
        &self.command
    }
    pub fn start(&self) -> Result<(), Rejected> {
        let mut state = self.observation.state();
        route_pending(&state.snapshot)?;
        if state.snapshot.archive.started
            || !state
                .archive
                .as_ref()
                .is_some_and(|command| Arc::ptr_eq(command, &self.command))
        {
            return Err(Rejected::Started);
        }
        state.snapshot.archive.started = true;
        Ok(())
    }
    fn pending(state: &Snapshot) -> Result<(), Rejected> {
        route_pending(state)?;
        if !state.archive.started {
            return Err(Rejected::NotStarted);
        }
        if state.archive.returned.is_some() {
            return Err(Rejected::Returned);
        }
        Ok(())
    }
    pub fn enter_commit(&self, result: ArchiveResult) -> Result<ArchiveCommit, Rejected> {
        let mut state = self.observation.state();
        Self::pending(&state.snapshot)?;
        if state.snapshot.archive.knowledge != ArchiveKnowledge::NoCommitEntered {
            return Err(Rejected::Knowledge);
        }
        if matches!(result, ArchiveResult::Stored(id) if id != self.command.personal_archive_id) {
            return Err(Rejected::Result);
        }
        state.snapshot.archive.knowledge = ArchiveKnowledge::CommitCallEntered(result);
        Ok(ArchiveCommit {
            observation: self.observation.clone(),
            result,
        })
    }
    pub fn received(&self, prepared: ArchiveCommit) -> Result<(), Rejected> {
        if !self.observation.same(&prepared.observation) {
            return Err(Rejected::Invocation);
        }
        let mut state = self.observation.state();
        Self::pending(&state.snapshot)?;
        if state.snapshot.archive.knowledge != ArchiveKnowledge::CommitCallEntered(prepared.result)
        {
            return Err(Rejected::Knowledge);
        }
        state.snapshot.archive.knowledge = ArchiveKnowledge::ReceiptKnown(prepared.result);
        Ok(())
    }
    pub fn returned(&self, result: ArchiveResult) -> Result<ArchiveResult, Rejected> {
        let mut state = self.observation.state();
        Self::pending(&state.snapshot)?;
        state.snapshot.archive.returned = Some(ArchiveReturned::Outcome(result));
        if state.snapshot.archive.knowledge != ArchiveKnowledge::ReceiptKnown(result) {
            state.snapshot.aborted = true;
            return Err(Rejected::MissingReceipt);
        }
        Ok(result)
    }
    pub fn failed(&self) -> Result<(), Rejected> {
        let mut state = self.observation.state();
        Self::pending(&state.snapshot)?;
        state.snapshot.archive.returned = Some(ArchiveReturned::Error);
        Ok(())
    }
}

pub struct LocalRequest {
    observation: Observation,
    stanza: Arc<str>,
    target: String,
    index: usize,
}
impl LocalRequest {
    pub fn source(&self) -> MixDelivery {
        self.observation.row().source
    }
    pub fn stanza(&self) -> &str {
        &self.stanza
    }
    pub fn target(&self) -> &str {
        &self.target
    }
    pub fn start(&self) -> Result<(), Rejected> {
        let mut state = self.observation.state();
        available(&state.snapshot)?;
        route_pending(&state.snapshot)?;
        let entry = state
            .snapshot
            .local
            .get_mut(self.index)
            .ok_or(Rejected::Invocation)?;
        if entry.target != self.target || entry.started {
            return Err(Rejected::Started);
        }
        entry.started = true;
        Ok(())
    }
    pub fn enqueued(&self) -> Result<(), Rejected> {
        let mut state = self.observation.state();
        route_pending(&state.snapshot)?;
        let entry = state
            .snapshot
            .local
            .get_mut(self.index)
            .ok_or(Rejected::Invocation)?;
        if !entry.started {
            return Err(Rejected::NotStarted);
        }
        if entry.target != self.target || entry.enqueued || entry.returned.is_some() {
            return Err(Rejected::Phase);
        }
        entry.enqueued = true;
        Ok(())
    }
    pub fn returned(&self, result: LocalResult) -> Result<(), Rejected> {
        let mut state = self.observation.state();
        route_pending(&state.snapshot)?;
        let entry = state
            .snapshot
            .local
            .get_mut(self.index)
            .ok_or(Rejected::Invocation)?;
        if !entry.started {
            return Err(Rejected::NotStarted);
        }
        if entry.target != self.target || entry.returned.is_some() {
            return Err(Rejected::Phase);
        }
        entry.returned = Some(result);
        let enqueued = entry.enqueued;
        let requires_enqueue = matches!(
            result,
            LocalResult::HandoffClosed | LocalResult::Transferred(_)
        );
        if let LocalResult::Transferred(boundary) = result {
            if !matches!(
                boundary,
                TransferBoundary::SocketFenced(_)
                    | TransferBoundary::SmPersisted(_)
                    | TransferBoundary::BoshPersisted(_)
            ) {
                state.snapshot.aborted = true;
                return Err(Rejected::Result);
            }
            if state.snapshot.transfer.is_some() {
                return Err(Rejected::Transferred);
            }
            state.snapshot.transfer = Some(TransferFact {
                target: self.target.clone(),
                boundary,
            });
        }
        if enqueued != requires_enqueue {
            state.snapshot.aborted = true;
            return Err(Rejected::Result);
        }
        Ok(())
    }
}

pub struct ClusterRequest {
    observation: Observation,
    stanza: Arc<str>,
    node: String,
    index: usize,
}
impl ClusterRequest {
    pub fn source(&self) -> MixDelivery {
        self.observation.row().source
    }
    pub fn stanza(&self) -> &str {
        &self.stanza
    }
    pub fn recipient(&self) -> &str {
        &self.observation.row().recipient_jid
    }
    pub fn node(&self) -> &str {
        &self.node
    }
    pub fn start(&self) -> Result<(), Rejected> {
        let mut state = self.observation.state();
        available(&state.snapshot)?;
        route_pending(&state.snapshot)?;
        let entry = state
            .snapshot
            .cluster
            .get_mut(self.index)
            .ok_or(Rejected::Invocation)?;
        if entry.node != self.node || entry.started {
            return Err(Rejected::Started);
        }
        entry.started = true;
        Ok(())
    }
    /// The runtime calls this only on the return of its exact validated
    /// cluster invocation; a delivered boolean is never a handoff boundary.
    pub fn returned(&self, handoff: Option<TransferBoundary>) -> Result<(), Rejected> {
        let mut state = self.observation.state();
        route_pending(&state.snapshot)?;
        let entry = state
            .snapshot
            .cluster
            .get_mut(self.index)
            .ok_or(Rejected::Invocation)?;
        if !entry.started {
            return Err(Rejected::NotStarted);
        }
        if entry.node != self.node || entry.returned {
            return Err(Rejected::Phase);
        }
        entry.returned = true;
        entry.handoff = handoff;
        if handoff.is_some_and(|boundary| {
            !matches!(
                boundary,
                TransferBoundary::ClusterSocketFenced
                    | TransferBoundary::ClusterSmPersisted
                    | TransferBoundary::ClusterBoshPersisted
            )
        }) {
            state.snapshot.aborted = true;
            return Err(Rejected::Result);
        }
        if let Some(boundary) = handoff {
            if state.snapshot.transfer.is_some() {
                return Err(Rejected::Transferred);
            }
            state.snapshot.transfer = Some(TransferFact {
                target: self.node.clone(),
                boundary,
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SettlementCommand {
    Ack,
    Defer { delay_seconds: i64 },
    Retry { error: String },
    DeadLetter { reason: String, error: String },
}
impl SettlementCommand {
    pub fn kind(&self) -> SettlementKind {
        match self {
            Self::Ack => SettlementKind::Ack,
            Self::Defer { .. } => SettlementKind::Defer,
            Self::Retry { .. } => SettlementKind::Retry,
            Self::DeadLetter { .. } => SettlementKind::DeadLetter,
        }
    }
}
pub struct RouteCompletion {
    observation: Observation,
    result: RouteResult,
}
impl RouteCompletion {
    pub fn transferred(self, closed: RenewalScopeClosed) -> Result<(), Rejected> {
        if !self.observation.same(&closed.observation) {
            return Err(Rejected::Invocation);
        }
        let state = self.observation.state();
        active(&state.snapshot)?;
        if self.result != RouteResult::Transferred
            || state.snapshot.transfer.is_none()
            || !state.snapshot.renewal_scope_closed
        {
            return Err(Rejected::Result);
        }
        Ok(())
    }
    pub fn settlement(
        self,
        command: SettlementCommand,
        closed: RenewalScopeClosed,
    ) -> Result<Option<SettlementRequest>, Rejected> {
        if !self.observation.same(&closed.observation) {
            return Err(Rejected::Invocation);
        }
        active(&self.observation.state().snapshot)?;
        if self.result == RouteResult::Transferred || self.result == RouteResult::Cancelled {
            return Ok(None);
        }
        let expected = match self.result {
            RouteResult::CompletedByWorker => SettlementKind::Ack,
            RouteResult::Pending => SettlementKind::Defer,
            RouteResult::Permanent => SettlementKind::DeadLetter,
            RouteResult::Retry => SettlementKind::Retry,
            _ => unreachable!(),
        };
        if command.kind() != expected {
            return Err(Rejected::Settlement);
        }
        issue_settlement(&self.observation, command, false).map(Some)
    }
}
fn issue_settlement(
    observation: &Observation,
    command: SettlementCommand,
    invalid_template: bool,
) -> Result<SettlementRequest, Rejected> {
    let mut state = observation.state();
    available(&state.snapshot)?;
    if (invalid_template && state.snapshot.route != RoutePhase::Unprepared)
        || (!invalid_template && state.snapshot.route != RoutePhase::Returned)
    {
        return Err(Rejected::Phase);
    }
    if invalid_template {
        state.snapshot.renewal_scope_closed = true;
    }
    if !state.snapshot.renewal_scope_closed {
        return Err(Rejected::Renewal);
    }
    let kind = command.kind();
    state.snapshot.settlement = Some(SettlementSnapshot {
        kind,
        started: false,
        knowledge: SettlementKnowledge::NotEntered,
        returned: None,
    });
    Ok(SettlementRequest {
        observation: observation.clone(),
        command,
    })
}
pub struct SettlementRequest {
    observation: Observation,
    command: SettlementCommand,
}
pub struct SettlementBoundary {
    observation: Observation,
    kind: SettlementKind,
    prospective: Option<SettlementResult>,
}
impl SettlementRequest {
    pub fn source(&self) -> MixDelivery {
        self.observation.row().source
    }
    pub fn route_wake_generation(&self) -> i64 {
        self.observation.row().route_wake_generation
    }
    pub fn command(&self) -> &SettlementCommand {
        &self.command
    }
    pub fn start(&self) -> Result<(), Rejected> {
        let mut state = self.observation.state();
        active(&state.snapshot)?;
        if state.snapshot.transfer.is_some() {
            return Err(Rejected::Transferred);
        }
        if state.snapshot.lease_lost {
            return Err(Rejected::LeaseLost);
        }
        if state.snapshot.aborted || !state.snapshot.renewal_scope_closed {
            return Err(Rejected::Phase);
        }
        let settlement = state
            .snapshot
            .settlement
            .as_mut()
            .ok_or(Rejected::Settlement)?;
        if settlement.kind != self.command.kind() || settlement.started {
            return Err(Rejected::Started);
        }
        settlement.started = true;
        Ok(())
    }
    fn pending<'a>(&self, state: &'a mut Snapshot) -> Result<&'a mut SettlementSnapshot, Rejected> {
        active(state)?;
        let settlement = state.settlement.as_mut().ok_or(Rejected::Settlement)?;
        if settlement.kind != self.command.kind() {
            return Err(Rejected::Settlement);
        }
        if !settlement.started {
            return Err(Rejected::NotStarted);
        }
        if settlement.returned.is_some() {
            return Err(Rejected::Returned);
        }
        Ok(settlement)
    }
    pub fn enter_commit(&self, result: SettlementResult) -> Result<SettlementBoundary, Rejected> {
        let mut state = self.observation.state();
        let settlement = self.pending(&mut state.snapshot)?;
        if result.kind() != self.command.kind() || matches!(result, SettlementResult::Defer(_)) {
            return Err(Rejected::Result);
        }
        if settlement.knowledge != SettlementKnowledge::NotEntered {
            return Err(Rejected::Knowledge);
        }
        settlement.knowledge = SettlementKnowledge::CommitCallEntered(result);
        Ok(SettlementBoundary {
            observation: self.observation.clone(),
            kind: self.command.kind(),
            prospective: Some(result),
        })
    }
    pub fn enter_statement(&self) -> Result<SettlementBoundary, Rejected> {
        let mut state = self.observation.state();
        let settlement = self.pending(&mut state.snapshot)?;
        if self.command.kind() != SettlementKind::Defer
            || settlement.knowledge != SettlementKnowledge::NotEntered
        {
            return Err(Rejected::Knowledge);
        }
        settlement.knowledge = SettlementKnowledge::AutocommitStatementEntered;
        Ok(SettlementBoundary {
            observation: self.observation.clone(),
            kind: self.command.kind(),
            prospective: None,
        })
    }
    pub fn received(
        &self,
        prepared: SettlementBoundary,
        result: SettlementResult,
    ) -> Result<(), Rejected> {
        if !self.observation.same(&prepared.observation) {
            return Err(Rejected::Invocation);
        }
        let mut state = self.observation.state();
        let settlement = self.pending(&mut state.snapshot)?;
        if result.kind() != prepared.kind || result.kind() != self.command.kind() {
            return Err(Rejected::Result);
        }
        let expected = match prepared.prospective {
            Some(value) if value == result => SettlementKnowledge::CommitCallEntered(value),
            None => SettlementKnowledge::AutocommitStatementEntered,
            _ => return Err(Rejected::Result),
        };
        if settlement.knowledge != expected {
            return Err(Rejected::Knowledge);
        }
        settlement.knowledge = SettlementKnowledge::ReceiptKnown(result);
        Ok(())
    }
    pub fn returned(&self, result: SettlementResult) -> Result<SettlementResult, Rejected> {
        let mut state = self.observation.state();
        let settlement = self.pending(&mut state.snapshot)?;
        settlement.returned = Some(SettlementReturned::Outcome(result));
        if result.kind() != self.command.kind()
            || settlement.knowledge != SettlementKnowledge::ReceiptKnown(result)
        {
            return Err(Rejected::MissingReceipt);
        }
        Ok(result)
    }
    pub fn failed(&self) -> Result<(), Rejected> {
        let mut state = self.observation.state();
        let settlement = self.pending(&mut state.snapshot)?;
        settlement.returned = Some(SettlementReturned::Error);
        Ok(())
    }
}

pub struct RenewalRequest {
    observation: Observation,
    ordinal: u64,
}
pub struct RenewalStatement {
    observation: Observation,
    ordinal: u64,
}
impl RenewalRequest {
    pub fn source(&self) -> MixDelivery {
        self.observation.row().source
    }
    fn pending<'a>(&self, state: &'a mut Snapshot) -> Result<&'a mut RenewalSnapshot, Rejected> {
        route_pending(state)?;
        let renewal = &mut state.renewal;
        if !renewal.pending || renewal.issued != self.ordinal {
            return Err(Rejected::Renewal);
        }
        if renewal.returned.is_some() {
            return Err(Rejected::Returned);
        }
        Ok(renewal)
    }
    pub fn start(&self) -> Result<(), Rejected> {
        let mut state = self.observation.state();
        available(&state.snapshot)?;
        let renewal = self.pending(&mut state.snapshot)?;
        if renewal.started {
            return Err(Rejected::Started);
        }
        renewal.started = true;
        Ok(())
    }
    pub fn enter_statement(&self) -> Result<RenewalStatement, Rejected> {
        let mut state = self.observation.state();
        let renewal = self.pending(&mut state.snapshot)?;
        if !renewal.started {
            return Err(Rejected::NotStarted);
        }
        if renewal.knowledge != RenewalKnowledge::NotEntered {
            return Err(Rejected::Knowledge);
        }
        renewal.knowledge = RenewalKnowledge::AutocommitStatementEntered;
        Ok(RenewalStatement {
            observation: self.observation.clone(),
            ordinal: self.ordinal,
        })
    }
    pub fn received(&self, prepared: RenewalStatement, result: bool) -> Result<(), Rejected> {
        if !self.observation.same(&prepared.observation) || self.ordinal != prepared.ordinal {
            return Err(Rejected::Invocation);
        }
        let mut state = self.observation.state();
        let renewal = self.pending(&mut state.snapshot)?;
        if renewal.knowledge != RenewalKnowledge::AutocommitStatementEntered {
            return Err(Rejected::Knowledge);
        }
        renewal.knowledge = RenewalKnowledge::StatementReceipt(result);
        renewal.last_receipt = Some((self.ordinal, result));
        if !result {
            state.snapshot.lease_lost = true;
        }
        Ok(())
    }
    pub fn returned(&self, result: bool) -> Result<bool, Rejected> {
        let mut state = self.observation.state();
        let renewal = self.pending(&mut state.snapshot)?;
        renewal.returned = Some(RenewalReturned::Outcome(result));
        if renewal.knowledge != RenewalKnowledge::StatementReceipt(result) {
            state.snapshot.aborted = true;
            return Err(Rejected::MissingReceipt);
        }
        renewal.pending = false;
        Ok(result)
    }
    pub fn failed(&self) -> Result<(), Rejected> {
        let mut state = self.observation.state();
        let renewal = self.pending(&mut state.snapshot)?;
        renewal.returned = Some(RenewalReturned::Error);
        renewal.pending = false;
        state.snapshot.aborted = true;
        Ok(())
    }
}

#[derive(Debug)]
pub enum CommitError<E> {
    Observation(Rejected),
    Commit(E),
}
pub async fn archive_commit_observed<E>(
    commit: impl Future<Output = Result<(), E>>,
    request: &ArchiveRequest,
    result: ArchiveResult,
) -> Result<(), CommitError<E>> {
    let prepared = request
        .enter_commit(result)
        .map_err(CommitError::Observation)?;
    commit.await.map_err(CommitError::Commit)?;
    request.received(prepared).map_err(CommitError::Observation)
}
pub async fn settlement_commit_observed<E>(
    commit: impl Future<Output = Result<(), E>>,
    request: &SettlementRequest,
    result: SettlementResult,
) -> Result<(), CommitError<E>> {
    let prepared = request
        .enter_commit(result)
        .map_err(CommitError::Observation)?;
    commit.await.map_err(CommitError::Commit)?;
    request
        .received(prepared, result)
        .map_err(CommitError::Observation)
}

#[cfg(test)]
mod tests;
