//! Closed handoff authority and operation-local queue knowledge. Queue facts
//! never imply a socket write, peer acknowledgement, or durable settlement.
use northstar_abuse_policy::admission_execution::Correlation;
use northstar_delivery_core::DurableDelivery;
use northstar_message_core::DirectPostCommitMode;
use std::sync::{Arc, Mutex};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Rejected {
    State,
    Correlation,
    Source,
    Retired,
    Knowledge,
}
impl std::fmt::Display for Rejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "direct handoff rejected: {self:?}")
    }
}
impl std::error::Error for Rejected {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HealthDecision {
    Continue,
    Recover,
    AcceptedBeforeDegradation,
    Reject,
}

/// The existing owners choose where to read health. This function does not
/// add a read or unify the distinct C2S and federation checkpoint sequences.
pub fn health_decision(
    enforced: bool,
    mode: DirectPostCommitMode,
    durable: bool,
    history_committed: bool,
    accepted: bool,
) -> HealthDecision {
    if !enforced || mode == DirectPostCommitMode::Live {
        HealthDecision::Continue
    } else if durable || history_committed {
        HealthDecision::Recover
    } else if accepted {
        HealthDecision::AcceptedBeforeDegradation
    } else {
        HealthDecision::Reject
    }
}

pub fn live_reservation_valid(
    clustered: bool,
    message_id: uuid::Uuid,
    claim_id: Option<uuid::Uuid>,
) -> bool {
    !clustered || claim_id == Some(message_id)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Refusal {
    Full,
    Closed,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalKnowledge {
    NotRequested,
    CallEntered,
    Refused,
    Accepted,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoteKnowledge {
    NotRequested,
    CallEntered,
    NoPositiveReceipt,
    AcceptanceReported,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RearmKnowledge {
    NotRequested,
    CallEntered,
    CallReturned,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteEnd {
    NotStarted,
    Running,
    Returned,
    Dropped,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Snapshot {
    pub correlation: Correlation,
    pub source: DurableDelivery,
    pub local_accepted: bool,
    pub local_call: LocalKnowledge,
    pub last_local_refusal: Option<Refusal>,
    pub remote: RemoteKnowledge,
    /// An earlier remote call returned without a positive receipt. A later
    /// accepted fallback cannot disprove that earlier call also enqueued.
    pub prior_remote_uncertain: bool,
    pub rearm: RearmKnowledge,
    pub route_end: RouteEnd,
    pub retired: bool,
}

struct Witness {
    snapshot: Snapshot,
    queue_allowed: bool,
    local_pending: bool,
}

/// Only small, independently retained facts are shared with synchronous port
/// callbacks. Snapshots contain values, not shared mutable state. No lock is
/// held across an await and no method starts work on drop.
#[derive(Clone)]
pub struct HandoffHandle(Arc<Mutex<Witness>>);

impl std::fmt::Debug for HandoffHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HandoffHandle { operation-local knowledge }")
    }
}

impl HandoffHandle {
    fn new(correlation: Correlation, source: DurableDelivery) -> Self {
        Self(Arc::new(Mutex::new(Witness {
            snapshot: Snapshot {
                correlation,
                source,
                local_accepted: false,
                local_call: LocalKnowledge::NotRequested,
                last_local_refusal: None,
                remote: RemoteKnowledge::NotRequested,
                prior_remote_uncertain: false,
                rearm: RearmKnowledge::NotRequested,
                route_end: RouteEnd::NotStarted,
                retired: false,
            },
            queue_allowed: false,
            local_pending: false,
        })))
    }
    pub fn snapshot(&self) -> Snapshot {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).snapshot
    }
    fn start(&self, queue_allowed: bool) {
        let mut witness = self.0.lock().unwrap_or_else(|e| e.into_inner());
        witness.queue_allowed = queue_allowed;
        witness.snapshot.route_end = RouteEnd::Running;
    }
    pub(crate) fn retire(&self) {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .snapshot
            .retired = true;
    }
    fn validate(witness: &Witness, source: DurableDelivery) -> Result<(), Rejected> {
        if witness.snapshot.retired {
            return Err(Rejected::Retired);
        }
        if witness.snapshot.source != source {
            return Err(Rejected::Source);
        }
        if witness.snapshot.route_end != RouteEnd::Running {
            return Err(Rejected::State);
        }
        Ok(())
    }
    pub fn local_permit(&self, source: DurableDelivery) -> Result<LocalEnqueuePermit, Rejected> {
        let mut witness = self.0.lock().unwrap_or_else(|e| e.into_inner());
        Self::validate(&witness, source)?;
        if !witness.queue_allowed
            || witness.local_pending
            || witness.snapshot.local_accepted
            || matches!(
                witness.snapshot.remote,
                RemoteKnowledge::CallEntered | RemoteKnowledge::AcceptanceReported
            )
            || witness.snapshot.rearm != RearmKnowledge::NotRequested
        {
            return Err(Rejected::State);
        }
        witness.local_pending = true;
        Ok(LocalEnqueuePermit {
            witness: Some(self.clone()),
        })
    }
    pub fn remote_permit(&self, source: DurableDelivery) -> Result<RemotePermit, Rejected> {
        let mut witness = self.0.lock().unwrap_or_else(|e| e.into_inner());
        Self::validate(&witness, source)?;
        if !witness.queue_allowed
            || witness.local_pending
            || witness.snapshot.local_accepted
            || matches!(
                witness.snapshot.remote,
                RemoteKnowledge::CallEntered | RemoteKnowledge::AcceptanceReported
            )
            || witness.snapshot.rearm != RearmKnowledge::NotRequested
        {
            return Err(Rejected::State);
        }
        witness.snapshot.remote = RemoteKnowledge::CallEntered;
        Ok(RemotePermit {
            witness: self.clone(),
        })
    }
    pub fn rearm_permit(&self, source: DurableDelivery) -> Result<Option<RearmPermit>, Rejected> {
        let mut witness = self.0.lock().unwrap_or_else(|e| e.into_inner());
        Self::validate(&witness, source)?;
        if source.claim_id.is_none() || witness.snapshot.rearm != RearmKnowledge::NotRequested {
            return Ok(None);
        }
        if witness.snapshot.local_accepted
            || matches!(
                witness.snapshot.remote,
                RemoteKnowledge::CallEntered | RemoteKnowledge::AcceptanceReported
            )
            || witness.local_pending
        {
            return Err(Rejected::State);
        }
        witness.snapshot.rearm = RearmKnowledge::CallEntered;
        Ok(Some(RearmPermit {
            witness: self.clone(),
        }))
    }
    pub fn returned(&self) {
        let mut witness = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if !witness.snapshot.retired && witness.snapshot.route_end == RouteEnd::Running {
            witness.snapshot.route_end = RouteEnd::Returned;
        }
    }
    pub fn dropped(&self) {
        let mut witness = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if !witness.snapshot.retired && witness.snapshot.route_end == RouteEnd::Running {
            witness.snapshot.route_end = RouteEnd::Dropped;
        }
    }
}

/// A prevalidated permit is consumed on every real enqueue result. Positive
/// retention has no fallible correlation check after the item crossed the queue.
pub struct LocalEnqueuePermit {
    witness: Option<HandoffHandle>,
}
impl LocalEnqueuePermit {
    pub fn source(&self) -> DurableDelivery {
        self.witness
            .as_ref()
            .expect("unconsumed permit")
            .snapshot()
            .source
    }
    /// Called only after the actual owned item is sealed, immediately before
    /// invoking the sender. Preparing/rejecting a binding is not a queue call.
    pub fn enter(mut self) -> Result<EnteredLocalEnqueue, Rejected> {
        let witness = self.witness.as_ref().expect("unconsumed permit");
        {
            let mut state = witness.0.lock().unwrap_or_else(|e| e.into_inner());
            HandoffHandle::validate(&state, state.snapshot.source)?;
            state.snapshot.local_call = LocalKnowledge::CallEntered;
        }
        Ok(EnteredLocalEnqueue {
            witness: self.witness.take().expect("unconsumed permit"),
        })
    }
}
impl Drop for LocalEnqueuePermit {
    fn drop(&mut self) {
        if let Some(witness) = &self.witness {
            witness
                .0
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .local_pending = false;
        }
    }
}
pub struct EnteredLocalEnqueue {
    witness: HandoffHandle,
}
impl EnteredLocalEnqueue {
    pub fn accepted(self) {
        let mut witness = self.witness.0.lock().unwrap_or_else(|e| e.into_inner());
        witness.snapshot.local_accepted = true;
        witness.snapshot.local_call = LocalKnowledge::Accepted;
        witness.local_pending = false;
    }
    pub fn refused(self, refusal: Refusal) {
        let mut witness = self.witness.0.lock().unwrap_or_else(|e| e.into_inner());
        witness.snapshot.last_local_refusal = Some(refusal);
        witness.snapshot.local_call = LocalKnowledge::Refused;
        witness.local_pending = false;
    }
}

pub struct RemotePermit {
    witness: HandoffHandle,
}
impl RemotePermit {
    pub fn returned(self, positive: bool) {
        let mut witness = self.witness.0.lock().unwrap_or_else(|e| e.into_inner());
        witness.snapshot.prior_remote_uncertain |= !positive;
        witness.snapshot.remote = if positive {
            RemoteKnowledge::AcceptanceReported
        } else {
            RemoteKnowledge::NoPositiveReceipt
        };
    }
}

pub struct RearmPermit {
    witness: HandoffHandle,
}
impl RearmPermit {
    pub fn returned(self) {
        self.witness
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .snapshot
            .rearm = RearmKnowledge::CallReturned;
    }
}

#[derive(Debug)]
pub struct HealthPermit {
    correlation: Correlation,
    source: DurableDelivery,
}
#[derive(Debug)]
pub struct RouteGrant {
    correlation: Correlation,
    source: DurableDelivery,
}
#[derive(Debug)]
pub struct RecoveryGrant {
    correlation: Correlation,
    source: DurableDelivery,
}
impl RouteGrant {
    pub fn source(&self) -> DurableDelivery {
        self.source
    }
}
impl RecoveryGrant {
    pub fn source(&self) -> DurableDelivery {
        self.source
    }
}
#[derive(Debug)]
pub enum Next {
    CheckHealth(HealthPermit),
    Route(RouteGrant),
    Recover(RecoveryGrant),
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Health,
    RouteIssued,
    RecoveryIssued,
    Consumed,
}
pub(crate) struct Control {
    correlation: Correlation,
    source: DurableDelivery,
    phase: Phase,
    witness: HandoffHandle,
}
impl Control {
    pub(crate) fn new(
        correlation: Correlation,
        source: DurableDelivery,
        needs_health: bool,
    ) -> (Self, Next) {
        let control = Self {
            correlation,
            source,
            phase: if needs_health {
                Phase::Health
            } else {
                Phase::RecoveryIssued
            },
            witness: HandoffHandle::new(correlation, source),
        };
        let next = if needs_health {
            Next::CheckHealth(HealthPermit {
                correlation,
                source,
            })
        } else {
            Next::Recover(RecoveryGrant {
                correlation,
                source,
            })
        };
        (control, next)
    }
    pub(crate) fn observed_health(
        &mut self,
        permit: HealthPermit,
        mode: DirectPostCommitMode,
    ) -> Result<Next, Rejected> {
        if self.phase != Phase::Health {
            return Err(Rejected::State);
        }
        if permit.correlation != self.correlation || permit.source != self.source {
            return Err(Rejected::Correlation);
        }
        Ok(if mode == DirectPostCommitMode::Live {
            self.phase = Phase::RouteIssued;
            Next::Route(RouteGrant {
                correlation: self.correlation,
                source: self.source,
            })
        } else {
            self.phase = Phase::RecoveryIssued;
            Next::Recover(RecoveryGrant {
                correlation: self.correlation,
                source: self.source,
            })
        })
    }
    pub(crate) fn consume_route(
        &mut self,
        grant: RouteGrant,
        source: DurableDelivery,
    ) -> Result<HandoffHandle, Rejected> {
        if self.phase != Phase::RouteIssued {
            return Err(Rejected::State);
        }
        if grant.correlation != self.correlation
            || grant.source != self.source
            || source != self.source
        {
            return Err(Rejected::Source);
        }
        self.phase = Phase::Consumed;
        self.witness.start(true);
        Ok(self.witness.clone())
    }
    pub(crate) fn consume_recovery(
        &mut self,
        grant: RecoveryGrant,
    ) -> Result<HandoffHandle, Rejected> {
        if self.phase != Phase::RecoveryIssued {
            return Err(Rejected::State);
        }
        if grant.correlation != self.correlation || grant.source != self.source {
            return Err(Rejected::Source);
        }
        self.phase = Phase::Consumed;
        self.witness.start(false);
        Ok(self.witness.clone())
    }
    pub(crate) fn snapshot(&self) -> Snapshot {
        self.witness.snapshot()
    }
    pub(crate) fn retire(&self) {
        self.witness.retire();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn source() -> DurableDelivery {
        DurableDelivery {
            recipient_id: uuid::Uuid::from_u128(1),
            message_id: uuid::Uuid::from_u128(2),
            claim_id: Some(uuid::Uuid::from_u128(2)),
        }
    }
    fn control(id: u128) -> (Control, Next) {
        Control::new(
            Correlation {
                operation: uuid::Uuid::from_u128(id),
                effect: 4,
                generation: 0,
                attempt: 1,
            },
            source(),
            true,
        )
    }
    fn running() -> HandoffHandle {
        let (mut control, Next::CheckHealth(health)) = control(3) else {
            unreachable!()
        };
        let Next::Route(grant) = control
            .observed_health(health, DirectPostCommitMode::Live)
            .unwrap()
        else {
            unreachable!()
        };
        control.consume_route(grant, source()).unwrap()
    }
    #[test]
    fn grant_consumption_checks_operation_source_and_single_use_inertly() {
        let (mut first, Next::CheckHealth(health)) = control(3) else {
            unreachable!()
        };
        let (mut other, Next::CheckHealth(other_health)) = control(4) else {
            unreachable!()
        };
        let before = first.snapshot();
        assert!(first
            .observed_health(other_health, DirectPostCommitMode::Live)
            .is_err());
        assert_eq!(first.snapshot(), before);
        let Next::Route(grant) = first
            .observed_health(health, DirectPostCommitMode::Live)
            .unwrap()
        else {
            unreachable!()
        };
        let before = other.snapshot();
        assert!(other.consume_route(grant, source()).is_err());
        assert_eq!(other.snapshot(), before);
        let (mut valid, Next::CheckHealth(health)) = control(5) else {
            unreachable!()
        };
        let Next::Route(grant) = valid
            .observed_health(health, DirectPostCommitMode::Live)
            .unwrap()
        else {
            unreachable!()
        };
        let wrong = DurableDelivery {
            claim_id: None,
            ..source()
        };
        let before = valid.snapshot();
        assert!(valid.consume_route(grant, wrong).is_err());
        assert_eq!(valid.snapshot(), before);
    }
    #[test]
    fn queue_positive_is_sticky_across_route_drop_retirement_and_late_completion() {
        let handle = running();
        let permit = handle.local_permit(source()).unwrap().enter().unwrap();
        handle.dropped();
        handle.retire();
        permit.accepted();
        let snapshot = handle.snapshot();
        assert!(snapshot.local_accepted);
        assert_eq!(snapshot.route_end, RouteEnd::Dropped);
        handle.returned();
        handle.dropped();
        assert!(handle.local_permit(source()).is_err());
        assert_eq!(handle.snapshot(), snapshot);
    }
    #[test]
    fn remote_absence_survives_a_later_positive_fallback_and_pending_stays_unknown() {
        let handle = running();
        handle.remote_permit(source()).unwrap().returned(false);
        assert!(handle.snapshot().prior_remote_uncertain);
        handle.remote_permit(source()).unwrap().returned(true);
        assert_eq!(
            handle.snapshot().remote,
            RemoteKnowledge::AcceptanceReported
        );
        assert!(handle.snapshot().prior_remote_uncertain);
        assert!(handle.rearm_permit(source()).is_err());
        let pending = running();
        drop(pending.remote_permit(source()).unwrap());
        pending.dropped();
        assert_eq!(pending.snapshot().remote, RemoteKnowledge::CallEntered);
        assert!(pending.rearm_permit(source()).is_err());
    }
    #[test]
    fn rearm_entry_survives_drop_and_void_return_is_only_an_attempt() {
        let handle = running();
        let permit = handle.rearm_permit(source()).unwrap().unwrap();
        assert_eq!(handle.snapshot().rearm, RearmKnowledge::CallEntered);
        assert!(handle.rearm_permit(source()).unwrap().is_none());
        drop(permit);
        handle.dropped();
        assert_eq!(handle.snapshot().rearm, RearmKnowledge::CallEntered);
        let returned = running();
        returned.rearm_permit(source()).unwrap().unwrap().returned();
        assert_eq!(returned.snapshot().rearm, RearmKnowledge::CallReturned);
        assert!(!returned.snapshot().local_accepted);
    }
    #[test]
    fn shared_health_decisions_preserve_history_volatile_and_accepted_cases() {
        assert_eq!(
            health_decision(false, DirectPostCommitMode::Rejected, false, false, false),
            HealthDecision::Continue
        );
        assert_eq!(
            health_decision(true, DirectPostCommitMode::Live, true, false, false),
            HealthDecision::Continue
        );
        for mode in [
            DirectPostCommitMode::SpoolOnly,
            DirectPostCommitMode::Rejected,
        ] {
            assert_eq!(
                health_decision(true, mode, true, false, true),
                HealthDecision::Recover
            );
            assert_eq!(
                health_decision(true, mode, false, true, false),
                HealthDecision::Recover
            );
            assert_eq!(
                health_decision(true, mode, false, false, true),
                HealthDecision::AcceptedBeforeDegradation
            );
            assert_eq!(
                health_decision(true, mode, false, false, false),
                HealthDecision::Reject
            );
        }
    }
}
