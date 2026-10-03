use super::input::{
    bytes32, Command, CompletionInput, Envelope, Guard, InputError, Row, MODEL, OUTPUT_SCHEMA,
};
use chrono::{DateTime, Utc};
use northstar_abuse_policy::{admission_execution as core, admission_transaction as tx, PowProof};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

// Material lookup is indexed so physical-shard fixtures remain bounded work.
struct Context<'a> {
    input: &'a Envelope,
    actors: BTreeMap<&'a str, Uuid>,
    keys: BTreeMap<&'a str, &'a super::input::KeyBinding>,
    payloads: BTreeMap<&'a str, Vec<u8>>,
    leases: BTreeMap<&'a str, Uuid>,
}
impl<'a> Context<'a> {
    fn new(input: &'a Envelope) -> Self {
        Self {
            input,
            actors: input
                .bindings
                .actors
                .iter()
                .map(|b| (b.label.as_str(), b.uuid))
                .collect(),
            keys: input
                .bindings
                .keys
                .iter()
                .map(|b| (b.label.as_str(), b))
                .collect(),
            payloads: input
                .bindings
                .payloads
                .iter()
                .map(|b| {
                    (
                        b.label.as_str(),
                        bytes32(&b.hex).expect("validated material").to_vec(),
                    )
                })
                .collect(),
            leases: input
                .bindings
                .leases
                .iter()
                .map(|b| (b.label.as_str(), b.uuid))
                .collect(),
        }
    }
    fn actor(&self, label: &str) -> Uuid {
        self.actors[label]
    }
    fn key(&self, label: &str) -> &super::input::KeyBinding {
        self.keys[label]
    }
    fn payload(&self, label: &str) -> Vec<u8> {
        self.payloads[label].clone()
    }
    fn lease(&self, label: &str) -> Uuid {
        self.leases[label]
    }
}
impl std::ops::Deref for Context<'_> {
    type Target = Envelope;
    fn deref(&self) -> &Envelope {
        self.input
    }
}
#[derive(Clone)]
struct World {
    rows: BTreeMap<String, Row>,
    actors: BTreeMap<String, u64>,
    proofs: BTreeSet<Uuid>,
}
struct Transaction {
    staged: World,
    result: core::EffectResult,
    scope: Option<core::TransactionScope>,
    fact: Option<core::CommitFact>,
    domain: &'static str,
    reconciliation: Option<Value>,
}
fn now(us: i64) -> DateTime<Utc> {
    DateTime::from_timestamp_micros(us).expect("validated timestamp")
}
fn correlation(c: &Command) -> core::Correlation {
    core::Correlation {
        operation: c.operation_uuid,
        effect: c.effect_number,
        generation: c.generation,
        attempt: c.attempt,
    }
}
fn fence(e: &Context<'_>, key: &str, payload: &str, lease: &str) -> tx::AdmissionFence {
    tx::AdmissionFence {
        admission_key: bytes32(&e.key(key).hex).expect("validated key").to_vec(),
        payload_mac: e.payload(payload),
        lease_token: e.lease(lease),
    }
}
fn begin(e: &Context<'_>, actor: &str, g: &Guard) -> core::BeginRequest {
    core::BeginRequest {
        actor_id: e.actor(actor),
        account_bare: g.account_bare.clone(),
        normalized_target: g.normalized_target.clone(),
        origin_id: g.origin_id.clone(),
        normalized_payload: g.normalized_payload.clone(),
        pow_intent_payload: g.pow_intent_payload.clone(),
        subject: g.subject.clone(),
        actors: g.actors.clone(),
        proof: g.proof.as_ref().map(|p| PowProof {
            challenge_id: p.challenge_id,
            nonce: p.nonce.clone(),
        }),
    }
}
#[allow(clippy::too_many_arguments)]
fn command(
    e: &Context<'_>,
    action: &str,
    actor: &str,
    key: &str,
    payload: &str,
    lease: &str,
    g: &Guard,
    target: Option<&str>,
) -> core::Command {
    match action {
        "reserve" | "guard_memory" | "guard_persistent" => core::Command::Begin(begin(e, actor, g)),
        "finalize" => core::Command::Finalize(fence(e, key, payload, lease)),
        "reconcile" => core::Command::Reconcile {
            unresolved: correlation(
                e.commands
                    .iter()
                    .find(|c| Some(c.operation_id.as_str()) == target)
                    .expect("validated target"),
            ),
            fence: fence(e, key, payload, lease),
        },
        _ => unreachable!("validated command"),
    }
}
fn effect(e: &Context<'_>, c: &Command) -> core::Effect {
    core::Effect {
        correlation: correlation(c),
        command: command(
            e,
            &c.action,
            &c.actor,
            &c.key,
            &c.payload_tag,
            &c.lease,
            &c.guard,
            c.reconcile_of.as_deref(),
        ),
    }
}
fn completion_effect(e: &Context<'_>, c: &CompletionInput) -> core::Effect {
    core::Effect {
        correlation: core::Correlation {
            operation: c.operation_uuid,
            effect: c.effect_number,
            generation: c.generation,
            attempt: c.attempt,
        },
        command: command(
            e,
            &c.action,
            &c.actor,
            &c.key,
            &c.payload_tag,
            &c.lease,
            &c.guard,
            c.reconcile_of.as_deref(),
        ),
    }
}
fn row(e: &Context<'_>, r: &Row) -> tx::AdmissionRow {
    tx::AdmissionRow {
        admission_key: bytes32(&e.key(&r.key).hex).expect("validated key").to_vec(),
        key_id: e.key(&r.key).key_id.clone(),
        actor_id: e.actor(&r.actor),
        payload_mac: e.payload(&r.payload_tag),
        state: if r.state == "accepted" {
            tx::RowState::Accepted
        } else {
            tx::RowState::Pending
        },
        lease_token: e.lease(&r.lease),
        lease_expires_at: now(r.lease_until_us),
        expires_at: now(r.expires_at_us),
    }
}
fn counts(w: &World, actor: &str, time: i64) -> (usize, usize) {
    let retained = w.rows.values().filter(|r| r.actor == actor);
    (
        retained.clone().filter(|r| r.expires_at_us > time).count(),
        retained.count(),
    )
}
fn shard(e: &Context<'_>, key: &str) -> u8 {
    bytes32(&e.key(key).hex).expect("validated key")[8] % 64
}
fn mutate_guard(w: &mut World, c: &Command, consume: bool) -> Result<(), InputError> {
    if consume {
        if let Some(proof) = &c.guard.proof {
            if c.guard.allowed && !w.proofs.contains(&proof.challenge_id) {
                return Err(InputError::Command);
            }
            w.proofs.remove(&proof.challenge_id);
        }
    }
    *w.actors.get_mut(&c.actor).expect("validated actor") += c.guard.actor_sequence_delta;
    Ok(())
}
fn transaction(e: &Context<'_>, w: &World, c: &Command) -> Result<Transaction, InputError> {
    use core::{
        BeginCommitPurpose as P, BeginResult as B, CommitFact as F, EffectResult as R,
        TransactionScope as S,
    };
    let mut staged = w.clone();
    let mut reconciliation = None;
    let (result, scope, fact, domain) = match c.action.as_str() {
        "guard_memory" => {
            let decision = if c.guard.allowed {
                core::GuardDecision::Allowed
            } else {
                core::GuardDecision::Denied
            };
            (
                R::Begin(B::GuardOnly(decision)),
                None,
                None,
                if c.guard.allowed {
                    "GuardOnlyAllowed"
                } else {
                    "GuardOnlyDenied"
                },
            )
        }
        "guard_persistent" => {
            mutate_guard(&mut staged, c, true)?;
            let decision = if c.guard.allowed {
                core::GuardDecision::Allowed
            } else {
                core::GuardDecision::Denied
            };
            (
                R::Begin(B::GuardOnly(decision)),
                Some(S::GuardOnlyVerification),
                Some(F::GuardOnly(decision)),
                if c.guard.allowed {
                    "GuardOnlyAllowed"
                } else {
                    "GuardOnlyDenied"
                },
            )
        }
        "reserve" => {
            staged.rows.retain(|key, r| {
                !c.candidates.contains(key) || r.expires_at_us > c.times.admission_us
            });
            let candidates: Vec<_> = c
                .candidates
                .iter()
                .map(|key| tx::AdmissionCandidate {
                    key_id: e.key(key).key_id.clone(),
                    admission_key: bytes32(&e.key(key).hex).expect("validated key").to_vec(),
                    payload_mac: e.payload(&c.payload_tag),
                })
                .collect();
            let selected: Vec<_> = c
                .candidates
                .iter()
                .filter_map(|key| staged.rows.get(key).map(|r| row(e, r)))
                .collect();
            let decision = tx::decide_begin(
                e.actor(&c.actor),
                &candidates,
                &selected,
                now(c.times.admission_us),
            );
            match decision {
                Err(_) => (
                    R::Failed(core::FailureKind::Backend),
                    None,
                    None,
                    "IntegrityFailure",
                ),
                Ok(tx::BeginRowDecision::Conflict) => {
                    (R::Begin(B::Conflict), None, None, "Conflict")
                }
                Ok(tx::BeginRowDecision::ReplayAccepted) => (
                    R::Begin(B::ReplayAccepted),
                    Some(S::RatedBegin(P::ReplayRead)),
                    Some(F::ReplayAccepted),
                    "ReplayAccepted",
                ),
                Ok(tx::BeginRowDecision::InProgress { .. }) => {
                    mutate_guard(&mut staged, c, false)?;
                    (
                        R::Begin(B::InProgress),
                        Some(S::RatedBegin(P::PendingRequirement)),
                        Some(F::InProgress),
                        "InProgress",
                    )
                }
                Ok(tx::BeginRowDecision::Reclaim) => {
                    mutate_guard(&mut staged, c, false)?;
                    let old = staged
                        .rows
                        .values_mut()
                        .find(|r| c.candidates.contains(&r.key))
                        .expect("shared reclaim requires row");
                    old.lease = c.lease.clone();
                    old.lease_until_us =
                        tx::lease_expiry(now(c.times.admission_us)).timestamp_micros();
                    let reserved = fence(e, &old.key, &old.payload_tag, &old.lease);
                    (
                        R::Begin(B::Reserved(reserved.clone())),
                        Some(S::RatedBegin(P::Reclaim)),
                        Some(F::Reserved(reserved)),
                        "Proceed",
                    )
                }
                Ok(tx::BeginRowDecision::VerifyGuard) => {
                    mutate_guard(&mut staged, c, true)?;
                    if !c.guard.allowed {
                        (
                            R::Begin(B::Denied),
                            Some(S::RatedBegin(P::GuardDenial)),
                            Some(F::Denied),
                            "Denied",
                        )
                    } else {
                        if c.schedule.cleanup == "bounded_skip_locked" {
                            let mut doomed: Vec<_> = staged
                                .rows
                                .values()
                                .filter(|r| {
                                    shard(e, &r.key) == shard(e, &c.key)
                                        && r.expires_at_us <= c.times.admission_us
                                        && !c.schedule.locked_keys.contains(&r.key)
                                })
                                .map(|r| {
                                    (r.expires_at_us, e.key(&r.key).hex.clone(), r.key.clone())
                                })
                                .collect();
                            doomed.sort();
                            for (_, _, key) in doomed.into_iter().take(128) {
                                staged.rows.remove(&key);
                            }
                        }
                        let active = counts(&staged, &c.actor, c.times.admission_us).0 as i64;
                        let physical = staged
                            .rows
                            .keys()
                            .filter(|key| shard(e, key) == shard(e, &c.key))
                            .count();
                        let slot = if physical < 32768 {
                            Some((physical + 1) as i32)
                        } else {
                            None
                        };
                        if tx::decide_actor_capacity(active) == tx::CapacityDecision::Limited
                            || tx::decide_shard_reservation(slot) == tx::CapacityDecision::Limited
                        {
                            (R::Begin(B::CapacityLimited), None, None, "CapacityLimited")
                        } else {
                            staged.rows.insert(
                                c.key.clone(),
                                Row {
                                    actor: c.actor.clone(),
                                    key: c.key.clone(),
                                    payload_tag: c.payload_tag.clone(),
                                    state: "pending".into(),
                                    expires_at_us: tx::pending_expiry(now(c.times.admission_us))
                                        .timestamp_micros(),
                                    lease: c.lease.clone(),
                                    lease_until_us: tx::lease_expiry(now(c.times.admission_us))
                                        .timestamp_micros(),
                                },
                            );
                            let reserved = fence(e, &c.key, &c.payload_tag, &c.lease);
                            (
                                R::Begin(B::Reserved(reserved.clone())),
                                Some(S::RatedBegin(P::NewReservation)),
                                Some(F::Reserved(reserved)),
                                "Proceed",
                            )
                        }
                    }
                }
            }
        }
        "finalize" => {
            let locked = staged.rows.get(&c.key).map(|r| row(e, r));
            let f = fence(e, &c.key, &c.payload_tag, &c.lease);
            let d = tx::decide_finalize(locked.as_ref(), &f);
            let (scope, fact, domain) = match d {
                tx::FinalizeDecision::Missing => (None, None, "Missing"),
                tx::FinalizeDecision::PayloadConflict => (None, None, "Conflict"),
                tx::FinalizeDecision::LostFence => (None, None, "LeaseLost"),
                tx::FinalizeDecision::AlreadyAccepted => (
                    Some(S::AdmissionFinalize),
                    Some(F::Finalized {
                        fence: f,
                        result: core::FinalizeSuccess::AlreadyAccepted,
                    }),
                    "AlreadyAccepted",
                ),
                tx::FinalizeDecision::AcceptPending => {
                    let r = staged
                        .rows
                        .get_mut(&c.key)
                        .expect("shared accept requires row");
                    r.state = "accepted".into();
                    r.expires_at_us =
                        tx::accepted_expiry(now(c.times.finalize_us)).timestamp_micros();
                    (
                        Some(S::AdmissionFinalize),
                        Some(F::Finalized {
                            fence: f,
                            result: core::FinalizeSuccess::PendingAccepted,
                        }),
                        "Accepted",
                    )
                }
            };
            (R::Finalize(d), scope, fact, domain)
        }
        "reconcile" => {
            let locked = staged.rows.get(&c.key).map(|r| row(e, r));
            let d = tx::reconcile(
                locked.as_ref(),
                &fence(e, &c.key, &c.payload_tag, &c.lease),
                now(c.times.reconcile_us),
            );
            let (observation, lease, retention, domain) = match d {
                tx::ReconcileObservation::ExactPending { lease, retention } => (
                    "ExactPending",
                    Some(validity(lease)),
                    Some(validity(retention)),
                    "ReconcileExactPending",
                ),
                tx::ReconcileObservation::ExactAccepted { retention } => (
                    "ExactAccepted",
                    None,
                    Some(validity(retention)),
                    "ReconcileExactAccepted",
                ),
                tx::ReconcileObservation::Missing => ("Missing", None, None, "ReconcileMissing"),
                tx::ReconcileObservation::Superseded => {
                    ("Superseded", None, None, "ReconcileSuperseded")
                }
                tx::ReconcileObservation::Conflicting => {
                    ("Conflicting", None, None, "ReconcileConflicting")
                }
            };
            reconciliation =
                Some(json!({"observation":observation,"lease":lease,"retention":retention}));
            (R::Reconcile(d), None, None, domain)
        }
        _ => unreachable!("validated command"),
    };
    // No-COMMIT results discard every staged write, including exact-key expiry,
    // bounded cleanup, challenge deletion and actor changes.
    if scope.is_none() {
        staged = w.clone();
    }
    Ok(Transaction {
        staged,
        result,
        scope,
        fact,
        domain,
        reconciliation,
    })
}
fn validity(v: tx::TemporalValidity) -> &'static str {
    match v {
        tx::TemporalValidity::Current => "Current",
        tx::TemporalValidity::Expired => "Expired",
    }
}
fn scope_name(s: core::TransactionScope) -> &'static str {
    use core::{BeginCommitPurpose as P, TransactionScope as S};
    match s {
        S::RatedBegin(P::NewReservation) => "RatedBegin.NewReservation",
        S::RatedBegin(P::Reclaim) => "RatedBegin.Reclaim",
        S::RatedBegin(P::ReplayRead) => "RatedBegin.ReplayRead",
        S::RatedBegin(P::PendingRequirement) => "RatedBegin.PendingRequirement",
        S::RatedBegin(P::GuardDenial) => "RatedBegin.GuardDenial",
        S::AdmissionFinalize => "AdmissionFinalize",
        S::GuardOnlyVerification => "GuardOnlyVerification",
    }
}
fn reason(r: core::CompletionRejected) -> &'static str {
    match r {
        core::CompletionRejected::Correlation => "Correlation",
        core::CompletionRejected::Request => "Request",
        core::CompletionRejected::Kind => "Kind",
        core::CompletionRejected::Knowledge => "Knowledge",
        core::CompletionRejected::AlreadyCompleted => "AlreadyCompleted",
    }
}
fn receipt_flags(k: &core::Knowledge) -> (bool, bool) {
    if let core::Knowledge::ReceiptKnown(r) = k {
        (
            matches!(r.fact, core::CommitFact::Reserved(_)),
            matches!(r.fact, core::CommitFact::Finalized { .. }),
        )
    } else {
        (false, false)
    }
}
fn reservation_projection(
    e: &Context<'_>,
    current: &Command,
    original: &Command,
    knowledge: &core::Knowledge,
) -> Option<Value> {
    let core::Knowledge::ReceiptKnown(receipt) = knowledge else {
        return None;
    };
    let core::CommitFact::Reserved(fence) = &receipt.fact else {
        return None;
    };
    let key = e
        .bindings
        .keys
        .iter()
        .find(|b| bytes32(&b.hex).expect("validated key").as_slice() == fence.admission_key)
        .expect("synthetic bound key");
    let payload = e
        .bindings
        .payloads
        .iter()
        .find(|b| bytes32(&b.hex).expect("validated payload").as_slice() == fence.payload_mac)
        .expect("synthetic bound payload");
    let lease = e
        .bindings
        .leases
        .iter()
        .find(|b| b.uuid == fence.lease_token)
        .expect("synthetic bound lease");
    let applicable_key = if current.action == "reserve" {
        current.candidates.contains(&key.label)
    } else {
        current.key == key.label
    };
    Some(
        json!({"operation_id":original.operation_id,"effect_id":original.effect_id,"key":key.label,"payload_tag":payload.label,"lease":lease.label,
        "applies_to_command":applicable_key && current.payload_tag==payload.label && current.lease==lease.label}),
    )
}
pub fn execute(input: &Envelope, hash: &str) -> Result<Value, InputError> {
    input.validate()?;
    let context = Context::new(input);
    let e = &context;
    let mut world = World {
        rows: e
            .initial
            .rows
            .iter()
            .cloned()
            .map(|r| (r.key.clone(), r))
            .collect(),
        actors: e.initial.actor_sequences.clone(),
        proofs: e.initial.proofs.iter().copied().collect(),
    };
    let mut projection = Vec::new();
    let mut compatibility = Vec::new();
    let mut operations = BTreeMap::<String, (core::Coordinator, core::CommitWitness)>::new();
    let mut complete = true;
    let mut terminal = true;
    let mut cancelled = false;
    let mut total_events = 0;
    for (index, c) in e.commands.iter().enumerate() {
        let emitted = effect(e, c);
        let mut coordinator = core::Coordinator::new(emitted.correlation, emitted.command.clone());
        let mut witness = core::CommitWitness::new(emitted.clone());
        let before = world.clone();
        let unresolved_before = c
            .reconcile_of
            .as_ref()
            .and_then(|id| operations.get(id))
            .cloned();
        let cancelled_cut = [
            "before_effect_cancel",
            "commit_cancel",
            "receipt_before_cancel",
        ]
        .contains(&c.schedule.cut.as_str());
        let unknown = ["commit_unknown", "commit_cancel"].contains(&c.schedule.cut.as_str());
        let early = ["before_effect_cancel", "precommit_error"].contains(&c.schedule.cut.as_str());
        let transaction = if early {
            Transaction {
                staged: world.clone(),
                result: core::EffectResult::Failed(core::FailureKind::Backend),
                scope: None,
                fact: None,
                domain: if c.schedule.cut == "before_effect_cancel" {
                    "NotRequested"
                } else {
                    "BackendFailure"
                },
                reconciliation: None,
            }
        } else {
            transaction(e, &world, c)?
        };
        if e.stage1.is_some()
            && unknown
            && transaction.scope
                != Some(core::TransactionScope::RatedBegin(
                    core::BeginCommitPurpose::NewReservation,
                ))
        {
            return Err(InputError::Stage1);
        }
        let mut committed = false;
        if let Some(scope) = transaction.scope {
            witness
                .enter_commit(scope)
                .map_err(|_| InputError::Schedule)?;
            if c.schedule.world_commit {
                world = transaction.staged.clone();
                committed = true;
            }
            if !unknown {
                if !committed {
                    return Err(InputError::Schedule);
                }
                witness
                    .record_receipt(core::Receipt {
                        correlation: emitted.correlation,
                        scope,
                        fact: transaction.fact.clone().expect("scope has fact"),
                    })
                    .map_err(|_| InputError::Schedule)?;
            }
        } else if unknown || c.schedule.cut == "receipt_before_cancel" {
            return Err(InputError::Schedule);
        }
        let delivered_result = if unknown || early {
            core::EffectResult::Failed(core::FailureKind::Backend)
        } else {
            transaction.result.clone()
        };
        let mut rejections = Vec::new();
        let mut accepted = false;
        for (completion_index, saved) in c.schedule.completions.iter().enumerate() {
            let old = coordinator.clone();
            let known = witness.clone();
            let completion = core::Completion {
                effect: completion_effect(e, saved),
                result: delivered_result.clone(),
                knowledge: witness.knowledge().clone(),
            };
            match coordinator.complete(completion) {
                Ok(_)=>accepted=true,
                Err(error)=>rejections.push(json!({"index":completion_index,"reason":reason(error),"pending_preserved":coordinator==old,"receipt_preserved":witness==known})),
            }
        }
        let pending = coordinator.pending().is_some();
        if pending && !cancelled_cut {
            terminal = false;
        }
        cancelled |= cancelled_cut;
        let domain = match c.schedule.cut.as_str() {
            "before_effect_cancel" => "NotRequested",
            "precommit_error" => "BackendFailure",
            "commit_unknown" | "commit_cancel" => "Unknown",
            "receipt_before_cancel" => "ReceiptPreserved",
            _ if pending => "AwaitingCompletion",
            _ => transaction.domain,
        };
        let knowledge = match witness.knowledge() {
            core::Knowledge::NoCommitRequested => "NoCommitRequested",
            core::Knowledge::CommitCallEntered(_) => "CommitCallEntered",
            core::Knowledge::ReceiptKnown(_) => "ReceiptKnown",
        };
        let time = match c.action.as_str() {
            "finalize" => c.times.finalize_us,
            "reconcile" => c.times.reconcile_us,
            _ => c.times.admission_us,
        };
        let world_counts = counts(&world, &c.actor, time);
        let before_counts = counts(&before, &c.actor, time);
        let possible_counts = counts(&transaction.staged, &c.actor, time);
        let (minimum, maximum) = if unknown {
            (
                (
                    before_counts.0.min(possible_counts.0),
                    before_counts.1.min(possible_counts.1),
                ),
                (
                    before_counts.0.max(possible_counts.0),
                    before_counts.1.max(possible_counts.1),
                ),
            )
        } else {
            (world_counts, world_counts)
        };
        let (_, finalization_receipt) = receipt_flags(witness.knowledge());
        let mut reservation = reservation_projection(e, c, c, witness.knowledge());
        let wanted_key = bytes32(&e.key(&c.key).hex).expect("validated key");
        let mut causal = c.causal_id.as_deref();
        while reservation.is_none() {
            let Some(id) = causal else { break };
            let original = e
                .commands
                .iter()
                .find(|prior| prior.operation_id == id)
                .expect("validated causal operation");
            if let Some((_, prior)) = operations.get(id) {
                if let core::Knowledge::ReceiptKnown(receipt) = prior.knowledge() {
                    if let core::CommitFact::Reserved(fence) = &receipt.fact {
                        if fence.admission_key == wanted_key {
                            reservation = reservation_projection(e, c, original, prior.knowledge());
                        }
                    }
                }
            }
            causal = original.causal_id.as_deref();
        }
        let reservation_receipt = reservation.is_some();
        let mut reconciliation = transaction.reconciliation.clone();
        if let Some(observation) = reconciliation.as_mut() {
            let unresolved_after = c.reconcile_of.as_ref().and_then(|id| operations.get(id));
            let preserved = unresolved_before.as_ref() == unresolved_after
                && unresolved_after.is_some_and(|(_, w)| {
                    matches!(w.knowledge(), core::Knowledge::CommitCallEntered(_))
                        && c.reconcile_of.as_ref().is_some_and(|id| {
                            let original = e
                                .commands
                                .iter()
                                .find(|command| &command.operation_id == id)
                                .expect("validated unresolved operation");
                            w.effect() == &effect(e, original)
                        })
                });
            observation["unresolved_operation_preserved"] = preserved.into();
        }
        let r = world.rows.get(&c.key);
        let event = json!({
            "index":index,"operation_id":c.operation_id,"effect_id":c.effect_id,"causal_id":c.causal_id,"attempt":c.attempt,"generation":c.generation,
            "action":c.action,"kind":c.kind,"times":c.times,"domain":domain,"execution":if cancelled_cut {"Cancelled"} else {"Completed"},
            "knowledge":knowledge,"scope":transaction.scope.map(scope_name),
            "world":{"committed":committed,"result":transaction.domain,"active":world_counts.0,"retained":world_counts.1,"row_state":r.map(|r|r.state.as_str()).unwrap_or("Absent"),
                "expires_at_us":r.map(|r|r.expires_at_us),"lease":r.map(|r|&r.lease),"actor_sequence":world.actors[&c.actor],
                "proof_present":c.guard.proof.as_ref().map(|p|world.proofs.contains(&p.challenge_id))},
            "caller":{"active_min":minimum.0,"active_max":maximum.0,"retained_min":minimum.1,"retained_max":maximum.1,
                "reservation_receipt":reservation_receipt,"reservation":reservation,"finalization_receipt":finalization_receipt,"unresolved":unknown},
            "completion":{"accepted":accepted,"pending":pending,"rejections":rejections},"reconcile":reconciliation,
        });
        total_events += 1 + c.schedule.completions.len();
        if total_events > e.budgets.events
            || serde_json::to_vec(&projection).expect("JSON").len()
                + serde_json::to_vec(&event).expect("JSON").len()
                > e.budgets.evidence_bytes.saturating_sub(2048)
        {
            complete = false;
            terminal = false;
            break;
        }
        if e.stage1.is_some() {
            compatibility.push(super::stage1::projection(c, &event));
        }
        projection.push(event);
        operations.insert(c.operation_id.clone(), (coordinator, witness));
    }
    let mut output = json!({"schema":OUTPUT_SCHEMA,"adapter":"controlled_rust","model":MODEL,"scenario_id":e.scenario_id,"input_sha256":hash,
        "execution":if !complete||!terminal {"Inconclusive"} else if cancelled {"Cancelled"} else {"Completed"},"terminal":terminal,"evidence_complete":complete,
        "projection":projection,"compatibility_projection":if e.stage1.is_some() {Some(compatibility)} else {None},
        "limitations":["Controlled in-memory storage and scripted guard outcomes; shared Rust coordinator and locked-row decisions execute",
            "No SQL, locks, cryptographic verification, real clocks, wire, services or process-loss conformance",
            "World commit is injected adapter state; CommitCallEntered is caller knowledge, not proof COMMIT bytes were sent",
            "Exact-key-only cleanup is limited to the unchanged Stage1 bridge; native bounded cleanup uses declared skip-locked keys",
            "Late-finalize active4097 is a conditional model/source candidate with cleanup-survival premise, not a proven live product bug",
            "Reservation and finalization only; outer cancellation ownership, durable-message write, route, ACK and recovery remain Stage3"]});
    // Account for the full root and optional compatibility projection as well,
    // never just the rich events. A bounded prefix cannot qualify completion.
    while serde_json::to_vec(&output).expect("JSON").len() > e.budgets.evidence_bytes {
        let events = output["projection"]
            .as_array_mut()
            .expect("projection array");
        if events.pop().is_none() {
            return Err(InputError::Budget);
        }
        if let Some(events) = output["compatibility_projection"].as_array_mut() {
            events.pop();
        }
        output["evidence_complete"] = false.into();
        output["terminal"] = false.into();
        output["execution"] = "Inconclusive".into();
    }
    Ok(output)
}
