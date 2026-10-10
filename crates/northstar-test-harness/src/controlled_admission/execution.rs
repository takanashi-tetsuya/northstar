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
#[derive(Clone, PartialEq, Eq)]
struct World {
    rows: BTreeMap<String, Row>,
    actors: BTreeMap<String, u64>,
    proofs: BTreeSet<Uuid>,
}
// These are caller-model accounting limits, not process/RSS limits. The view
// limit applies to attempted successors BEFORE filtering or deduplication; the
// separate row/byte reservation covers simultaneous source, successor and
// transaction scratch content. The actual injected World has separate input
// bounds and is never a source for the caller's possible states.
const MAX_KNOWLEDGE_VIEWS: usize = 64;
const MAX_KNOWLEDGE_ROWS: usize = 1_000_000;
const MAX_KNOWLEDGE_BYTES: usize = 64 * 1024 * 1024;
const LIMITATIONS: [&str; 8] = [
    "Controlled in-memory storage and scripted guard outcomes; shared Rust coordinator and locked-row decisions execute",
    "No SQL, locks, cryptographic verification, real clocks, wire, services or process-loss conformance",
    "World commit is injected adapter state; CommitCallEntered is caller knowledge, not proof COMMIT bytes were sent",
    "Exact-key-only cleanup is limited to the unchanged Stage1 bridge; native bounded cleanup uses declared skip-locked keys",
    "Late-finalize active4097 is a conditional model/source candidate with cleanup-survival premise, not a proven live product bug",
    "Reservation and finalization only; outer cancellation ownership, durable-message write, route, ACK and recovery remain Stage3",
    "Caller knowledge uses bounded concrete storage alternatives; its modeled copy and serialized-byte limits are not process RSS limits",
    "Actor-policy clock inputs and guard outcomes remain scripted; controlled reconciliation timestamps are scripted, not PostgreSQL clock conformance",
];
// Static root-only upper bound, including simultaneous summaries. This literal
// includes the longest fixed enum strings, all false booleans, full-width
// bounded integers, a 64-byte hash, and the larger null compatibility value.
// Only the two validated <=128 ASCII labels and limitations contents are blank.
// No modeled execution or JSON sizing probe is needed to establish this bound.
const ROOT_FIXED_JSON: &str = concat!(
    "{\"schema\":\"northstar-admission-controlled-output-v4\",\"adapter\":\"controlled_rust\",",
    "\"model\":\"admission-controlled-v1\",\"scenario_id\":\"\",",
    "\"input_sha256\":\"0000000000000000000000000000000000000000000000000000000000000000\",",
    "\"execution\":\"EnvironmentInterrupted\",\"terminal\":false,\"evidence_complete\":false,",
    "\"coordinators_finished\":false,",
    "\"observation_failure\":{\"class\":\"UnmappedMaterial\",\"index\":255,\"operation_id\":\"\"},",
    "\"safety_failure\":{\"index\":255,\"active\":40256},",
    "\"knowledge_stop\":{\"index\":255,\"phase\":\"BeforeInitialState\",\"reason\":\"KnowledgeModelIncomplete\"},",
    "\"projection\":[],\"compatibility_projection\":null,\"limitations\":[]}"
);
const ROOT_MAX_BYTES: usize = ROOT_FIXED_JSON.len()
    + 2 * 128
    + LIMITATIONS[0].len()
    + LIMITATIONS[1].len()
    + LIMITATIONS[2].len()
    + LIMITATIONS[3].len()
    + LIMITATIONS[4].len()
    + LIMITATIONS[5].len()
    + LIMITATIONS[6].len()
    + LIMITATIONS[7].len()
    + 8 * 2
    + 7;
const _: () = assert!(ROOT_MAX_BYTES <= 2048);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KnowledgeStop {
    ViewBudget,
    RowBudget,
    ByteBudget,
    KnowledgeModelIncomplete,
    InconsistentObservation,
}
impl KnowledgeStop {
    fn name(self) -> &'static str {
        match self {
            Self::ViewBudget => "ViewBudget",
            Self::RowBudget => "RowBudget",
            Self::ByteBudget => "ByteBudget",
            Self::KnowledgeModelIncomplete => "KnowledgeModelIncomplete",
            Self::InconsistentObservation => "InconsistentObservation",
        }
    }
}

// Allocation-free upper bounds on serialized synthetic state. Labels are
// validated ASCII without escaping; constants include object/map punctuation,
// field names and the full decimal widths of both signed times and sequences.
fn row_bytes(actor: &str, key: &str, payload: &str, state: &str, lease: &str) -> usize {
    192 + 2 * key.len() + actor.len() + payload.len() + state.len() + lease.len()
}
fn state_bytes<'a>(
    mut rows: impl Iterator<Item = &'a Row>,
    actors: &BTreeMap<String, u64>,
    proofs: usize,
) -> Option<usize> {
    let base = proofs.checked_mul(64)?.checked_add(256)?;
    let total = actors
        .keys()
        .try_fold(base, |sum, actor| sum.checked_add(64 + actor.len()))?;
    rows.try_fold(total, |sum, r| {
        sum.checked_add(row_bytes(
            &r.actor,
            &r.key,
            &r.payload_tag,
            &r.state,
            &r.lease,
        ))
    })
}
fn world_bytes(w: &World) -> Option<usize> {
    state_bytes(w.rows.values(), &w.actors, w.proofs.len())
}
fn initial_knowledge(e: &Envelope) -> Result<Vec<World>, KnowledgeStop> {
    if e.initial.rows.len() > MAX_KNOWLEDGE_ROWS {
        return Err(KnowledgeStop::RowBudget);
    }
    let bytes = state_bytes(
        e.initial.rows.iter(),
        &e.initial.actor_sequences,
        e.initial.proofs.len(),
    )
    .ok_or(KnowledgeStop::ByteBudget)?;
    if bytes > MAX_KNOWLEDGE_BYTES {
        return Err(KnowledgeStop::ByteBudget);
    }
    // Only known initial material is copied, after reservation.
    Ok(vec![World {
        rows: e
            .initial
            .rows
            .iter()
            .cloned()
            .map(|r| (r.key.clone(), r))
            .collect(),
        actors: e.initial.actor_sequences.clone(),
        proofs: e.initial.proofs.iter().copied().collect(),
    }])
}
fn reserve_knowledge(views: &[World], c: &Command, factor: usize) -> Result<(), KnowledgeStop> {
    let successors = views
        .len()
        .checked_mul(factor)
        .ok_or(KnowledgeStop::ViewBudget)?;
    if successors > MAX_KNOWLEDGE_VIEWS {
        return Err(KnowledgeStop::ViewBudget);
    }
    let mut old_rows = 0usize;
    let mut next_rows = 0usize;
    let mut largest_rows = 0usize;
    let mut old_bytes = 0usize;
    let mut next_bytes = 0usize;
    let mut largest_bytes = 0usize;
    let added_row = usize::from(c.action == "reserve");
    // Also covers a reclaim's longer lease and finalize's state/expiry update.
    let added_bytes = row_bytes(&c.actor, &c.key, &c.payload_tag, "accepted", &c.lease);
    for view in views {
        old_rows = old_rows
            .checked_add(view.rows.len())
            .ok_or(KnowledgeStop::RowBudget)?;
        let rows = view
            .rows
            .len()
            .checked_add(added_row)
            .ok_or(KnowledgeStop::RowBudget)?;
        next_rows = next_rows
            .checked_add(rows)
            .ok_or(KnowledgeStop::RowBudget)?;
        largest_rows = largest_rows.max(rows);
        let bytes = world_bytes(view).ok_or(KnowledgeStop::ByteBudget)?;
        old_bytes = old_bytes
            .checked_add(bytes)
            .ok_or(KnowledgeStop::ByteBudget)?;
        let bytes = bytes
            .checked_add(added_bytes)
            .ok_or(KnowledgeStop::ByteBudget)?;
        next_bytes = next_bytes
            .checked_add(bytes)
            .ok_or(KnowledgeStop::ByteBudget)?;
        largest_bytes = largest_bytes.max(bytes);
    }
    // At most two full-state scratch copies coexist on rollback. On commit,
    // the second envelope covers bounded cleanup's key/hex tuples instead.
    // Up to eight AdmissionCandidate plus eight selected AdmissionRow DTOs
    // coexist. Charge sixteen rows and 1024 content bytes each separately;
    // validated key IDs, fixed byte arrays and timestamps fit that envelope.
    let rows = next_rows
        .checked_mul(factor)
        .and_then(|n| n.checked_add(old_rows))
        .and_then(|n| {
            largest_rows
                .checked_mul(2)
                .and_then(|scratch| n.checked_add(scratch))
        })
        .and_then(|n| n.checked_add(16))
        .ok_or(KnowledgeStop::RowBudget)?;
    if rows > MAX_KNOWLEDGE_ROWS {
        return Err(KnowledgeStop::RowBudget);
    }
    let bytes = next_bytes
        .checked_mul(factor)
        .and_then(|n| n.checked_add(old_bytes))
        .and_then(|n| {
            largest_bytes
                .checked_mul(2)
                .and_then(|scratch| n.checked_add(scratch))
        })
        .and_then(|n| n.checked_add(16 * 1024))
        .ok_or(KnowledgeStop::ByteBudget)?;
    if bytes > MAX_KNOWLEDGE_BYTES {
        return Err(KnowledgeStop::ByteBudget);
    }
    Ok(())
}

fn advance_knowledge(
    e: &Context<'_>,
    views: &mut Vec<World>,
    c: &Command,
    witness: &core::CommitWitness,
    state: &core::ExecutionState,
) -> Result<(), KnowledgeStop> {
    if views.is_empty() {
        return Err(KnowledgeStop::InconsistentObservation);
    }
    let delivered =
        match state {
            core::ExecutionState::Finished(core::ExecutionOutcome::Completed {
                result, ..
            }) if !matches!(result, core::EffectResult::Failed(_)) => Some(result),
            _ => None,
        };
    let retained = witness.knowledge();
    if matches!(retained, core::Knowledge::NoCommitRequested)
        && (delivered.is_none() || c.action == "guard_memory")
    {
        // No successful storage observation: do not even evaluate a speculative
        // transaction. Cancellation/precommit failure cannot select a view.
        return Ok(());
    }
    let factor = if matches!(retained, core::Knowledge::CommitCallEntered(_)) {
        2
    } else {
        1
    };
    reserve_knowledge(views, c, factor)?;
    let mut next = Vec::new();
    for view in views.iter() {
        // A scripted Allowed cannot justify deleting a missing-proof view. The
        // controlled guard lacks a contract for that alternative: stop the
        // entire analysis, retaining all prior views and observed actual facts.
        // A delivered read supplies its own as-of instant. Reusing the scripted
        // command time here would reinterpret the repository's actual evidence.
        let observed_at = match delivered {
            Some(core::EffectResult::Reconcile(result)) => Some(result.observation.observed_at),
            _ => None,
        };
        let candidate = transaction(e, view, c, observed_at)
            .map_err(|_| KnowledgeStop::KnowledgeModelIncomplete)?;
        let matches_witness = match retained {
            core::Knowledge::NoCommitRequested => candidate.scope.is_none(),
            core::Knowledge::CommitCallEntered(p) => {
                p.correlation == correlation(c)
                    && candidate.scope == Some(p.scope)
                    && candidate.fact.as_ref() == Some(&p.fact)
            }
            core::Knowledge::ReceiptKnown(r) => {
                r.correlation == correlation(c)
                    && candidate.scope == Some(r.scope)
                    && candidate.fact.as_ref() == Some(&r.fact)
            }
        };
        if !matches_witness || delivered.is_some_and(|result| result != &candidate.result) {
            continue;
        }
        if !matches!(retained, core::Knowledge::ReceiptKnown(_))
            && !next.iter().any(|known| known == view)
        {
            next.push(view.clone());
        }
        if !matches!(retained, core::Knowledge::NoCommitRequested)
            && !next.iter().any(|known| known == &candidate.staged)
        {
            next.push(candidate.staged);
        }
    }
    if next.is_empty() {
        return Err(KnowledgeStop::InconsistentObservation);
    }
    *views = next;
    Ok(())
}

fn knowledge_counts(views: &[World], actor: &str, time: i64) -> ((usize, usize), (usize, usize)) {
    let mut minimum = (usize::MAX, usize::MAX);
    let mut maximum = (0, 0);
    for view in views {
        let count = counts(view, actor, time);
        minimum = (minimum.0.min(count.0), minimum.1.min(count.1));
        maximum = (maximum.0.max(count.0), maximum.1.max(count.1));
    }
    (minimum, maximum)
}
struct Transaction {
    staged: World,
    result: core::EffectResult,
    scope: Option<core::TransactionScope>,
    fact: Option<core::CommitFact>,
    domain: &'static str,
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
fn caller_observation_time(state: &core::ExecutionState, fallback: i64) -> i64 {
    match state {
        core::ExecutionState::Finished(core::ExecutionOutcome::Completed {
            result: core::EffectResult::Reconcile(result),
            ..
        }) => result.observation.observed_at.timestamp_micros(),
        _ => fallback,
    }
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
fn transaction(
    e: &Context<'_>,
    w: &World,
    c: &Command,
    reconcile_at: Option<DateTime<Utc>>,
) -> Result<Transaction, InputError> {
    use core::{
        BeginCommitPurpose as P, BeginResult as B, CommitFact as F, EffectResult as R,
        TransactionScope as S,
    };
    let mut staged = w.clone();
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
                reconcile_at.unwrap_or_else(|| now(c.times.reconcile_us)),
            );
            let result = R::Reconcile(core::ReconcileResult {
                effect: Box::new(effect(e, c)),
                observation: d,
            });
            let domain = result_domain(&result);
            (result, None, None, domain)
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
fn failure_name(cause: core::FailureKind) -> &'static str {
    match cause {
        core::FailureKind::Backend => "Backend",
        core::FailureKind::ActorBusy => "ActorBusy",
        core::FailureKind::Cancelled => "Cancelled",
    }
}
fn failure_domain(cause: core::FailureKind) -> &'static str {
    match cause {
        core::FailureKind::Backend => "BackendFailure",
        core::FailureKind::ActorBusy => "ActorBusy",
        core::FailureKind::Cancelled => "CancelledFailure",
    }
}
fn result_domain(result: &core::EffectResult) -> &'static str {
    use core::{BeginResult as B, EffectResult as R, GuardDecision as G};
    match result {
        R::Begin(B::GuardOnly(G::Allowed)) => "GuardOnlyAllowed",
        R::Begin(B::GuardOnly(G::Denied)) => "GuardOnlyDenied",
        R::Begin(B::Reserved(_)) => "Proceed",
        R::Begin(B::ReplayAccepted) => "ReplayAccepted",
        R::Begin(B::InProgress) => "InProgress",
        R::Begin(B::Denied) => "Denied",
        R::Begin(B::Conflict) => "Conflict",
        R::Begin(B::CapacityLimited) => "CapacityLimited",
        R::Finalize(tx::FinalizeDecision::Missing) => "Missing",
        R::Finalize(tx::FinalizeDecision::PayloadConflict) => "Conflict",
        R::Finalize(tx::FinalizeDecision::LostFence) => "LeaseLost",
        R::Finalize(tx::FinalizeDecision::AlreadyAccepted) => "AlreadyAccepted",
        R::Finalize(tx::FinalizeDecision::AcceptPending) => "Accepted",
        R::Reconcile(result) => match result.observation.observation {
            tx::ReconcileObservation::ExactPending { .. } => "ReconcileExactPending",
            tx::ReconcileObservation::ExactAccepted { .. } => "ReconcileExactAccepted",
            tx::ReconcileObservation::Missing => "ReconcileMissing",
            tx::ReconcileObservation::Superseded => "ReconcileSuperseded",
            tx::ReconcileObservation::Conflicting => "ReconcileConflicting",
        },
        R::Failed(cause) => failure_domain(*cause),
    }
}
pub(super) fn coordinator_domain(state: &core::ExecutionState) -> &'static str {
    match state {
        core::ExecutionState::Waiting(_) => "AwaitingCompletion",
        core::ExecutionState::Finished(core::ExecutionOutcome::Completed { result, .. }) => {
            result_domain(result)
        }
        core::ExecutionState::Finished(core::ExecutionOutcome::PreCommitFailure(cause)) => {
            failure_domain(*cause)
        }
        core::ExecutionState::Finished(core::ExecutionOutcome::Unknown { .. }) => "Unknown",
        core::ExecutionState::Finished(core::ExecutionOutcome::ReceiptPreserved { .. }) => {
            "ReceiptPreserved"
        }
    }
}
fn fence_projection(e: &Envelope, fence: &tx::AdmissionFence) -> Value {
    // Never replace an unexpected core value with the current command's label.
    // Unbound material is an observation failure, not an invalid input. The
    // explicit discriminator is preserved as divergent/incomplete evidence.
    let key = e
        .bindings
        .keys
        .iter()
        .find(|b| bytes32(&b.hex).is_some_and(|bytes| bytes.as_slice() == fence.admission_key));
    let payload = e
        .bindings
        .payloads
        .iter()
        .find(|b| bytes32(&b.hex).is_some_and(|bytes| bytes.as_slice() == fence.payload_mac));
    let lease = e
        .bindings
        .leases
        .iter()
        .find(|b| b.uuid == fence.lease_token);
    json!({"mapped":key.is_some() && payload.is_some() && lease.is_some(),
        "key":key.map(|b| &b.label),"payload_tag":payload.map(|b| &b.label),"lease":lease.map(|b| &b.label)})
}
fn correlation_projection(e: &Envelope, value: core::Correlation) -> Value {
    let original = e
        .commands
        .iter()
        .find(|c| c.operation_uuid == value.operation);
    json!({"mapped":original.is_some(),"operation_id":original.map(|c| &c.operation_id),"effect_number":value.effect,
        "generation":value.generation,"attempt":value.attempt})
}
fn fact_projection(e: &Envelope, fact: &core::CommitFact) -> Value {
    use core::{CommitFact as F, FinalizeSuccess as S, GuardDecision as G};
    let (kind, fence) = match fact {
        F::Reserved(fence) => ("Reserved", Some(fence)),
        F::ReplayAccepted => ("ReplayAccepted", None),
        F::InProgress => ("InProgress", None),
        F::Denied => ("Denied", None),
        F::Finalized {
            fence,
            result: S::PendingAccepted,
        } => ("Finalized.PendingAccepted", Some(fence)),
        F::Finalized {
            fence,
            result: S::AlreadyAccepted,
        } => ("Finalized.AlreadyAccepted", Some(fence)),
        F::GuardOnly(G::Allowed) => ("GuardOnlyAllowed", None),
        F::GuardOnly(G::Denied) => ("GuardOnlyDenied", None),
    };
    json!({"kind":kind,"fence":fence.map(|f| fence_projection(e, f))})
}
fn knowledge_projection(e: &Envelope, knowledge: &core::Knowledge) -> Value {
    let (kind, details) = match knowledge {
        core::Knowledge::NoCommitRequested => ("NoCommitRequested", None),
        core::Knowledge::CommitCallEntered(p) => {
            ("CommitCallEntered", Some((p.correlation, p.scope, &p.fact)))
        }
        core::Knowledge::ReceiptKnown(r) => {
            ("ReceiptKnown", Some((r.correlation, r.scope, &r.fact)))
        }
    };
    let (correlation, scope, fact) = if let Some((correlation, scope, fact)) = details {
        (
            correlation_projection(e, correlation),
            json!(scope_name(scope)),
            fact_projection(e, fact),
        )
    } else {
        (Value::Null, Value::Null, Value::Null)
    };
    json!({"kind":kind,"correlation":correlation,"scope":scope,"fact":fact})
}
fn reconcile_projection(e: &Envelope, result: &core::ReconcileResult) -> Value {
    let (observation, lease, retention) = match result.observation.observation {
        tx::ReconcileObservation::ExactPending { lease, retention } => (
            "ExactPending",
            Some(validity(lease)),
            Some(validity(retention)),
        ),
        tx::ReconcileObservation::ExactAccepted { retention } => {
            ("ExactAccepted", None, Some(validity(retention)))
        }
        tx::ReconcileObservation::Missing => ("Missing", None, None),
        tx::ReconcileObservation::Superseded => ("Superseded", None, None),
        tx::ReconcileObservation::Conflicting => ("Conflicting", None, None),
    };
    let (unresolved, fence) = match &result.effect.command {
        core::Command::Reconcile { unresolved, fence } => (
            correlation_projection(e, *unresolved),
            fence_projection(e, fence),
        ),
        _ => (Value::Null, Value::Null),
    };
    json!({"observation":observation,"lease":lease,"retention":retention,
        "observed_at_us":result.observation.observed_at.timestamp_micros(),
        "observed_at_source":"Scripted",
        "correlation":correlation_projection(e, result.effect.correlation),
        "unresolved":unresolved,"fence":fence})
}
fn result_projection(e: &Envelope, result: &core::EffectResult) -> Value {
    use core::{BeginResult as B, EffectResult as R, GuardDecision as G};
    let kind = match result {
        R::Begin(B::GuardOnly(G::Allowed)) => "Begin.GuardOnlyAllowed",
        R::Begin(B::GuardOnly(G::Denied)) => "Begin.GuardOnlyDenied",
        R::Begin(B::Reserved(_)) => "Begin.Reserved",
        R::Begin(B::ReplayAccepted) => "Begin.ReplayAccepted",
        R::Begin(B::InProgress) => "Begin.InProgress",
        R::Begin(B::Denied) => "Begin.Denied",
        R::Begin(B::Conflict) => "Begin.Conflict",
        R::Begin(B::CapacityLimited) => "Begin.CapacityLimited",
        R::Finalize(tx::FinalizeDecision::Missing) => "Finalize.Missing",
        R::Finalize(tx::FinalizeDecision::PayloadConflict) => "Finalize.PayloadConflict",
        R::Finalize(tx::FinalizeDecision::LostFence) => "Finalize.LostFence",
        R::Finalize(tx::FinalizeDecision::AlreadyAccepted) => "Finalize.AlreadyAccepted",
        R::Finalize(tx::FinalizeDecision::AcceptPending) => "Finalize.AcceptPending",
        R::Reconcile(_) => "Reconcile",
        R::Failed(_) => "Failed",
    };
    let fence = if let R::Begin(B::Reserved(fence)) = result {
        Some(fence_projection(e, fence))
    } else {
        None
    };
    let reconcile = if let R::Reconcile(observation) = result {
        Some(reconcile_projection(e, observation))
    } else {
        None
    };
    let cause = if let R::Failed(cause) = result {
        Some(failure_name(*cause))
    } else {
        None
    };
    json!({"kind":kind,"fence":fence,"reconcile":reconcile,"cause":cause})
}
pub(super) fn coordinator_projection(e: &Envelope, state: &core::ExecutionState) -> Value {
    use core::{ExecutionOutcome as O, ExecutionState as S};
    let (status, outcome, result, cause, knowledge) = match state {
        S::Waiting(_) => ("Waiting", None, None, None, None),
        S::Finished(O::Completed { result, knowledge }) => (
            "Finished",
            Some("Completed"),
            Some(result_projection(e, result)),
            None,
            Some(knowledge_projection(e, knowledge)),
        ),
        S::Finished(O::PreCommitFailure(cause)) => (
            "Finished",
            Some("PreCommitFailure"),
            None,
            Some(failure_name(*cause)),
            Some(knowledge_projection(e, &core::Knowledge::NoCommitRequested)),
        ),
        S::Finished(O::Unknown { prepared, cause }) => (
            "Finished",
            Some("Unknown"),
            None,
            Some(failure_name(*cause)),
            Some(knowledge_projection(
                e,
                &core::Knowledge::CommitCallEntered(prepared.clone()),
            )),
        ),
        S::Finished(O::ReceiptPreserved { receipt, cause }) => (
            "Finished",
            Some("ReceiptPreserved"),
            None,
            Some(failure_name(*cause)),
            Some(knowledge_projection(
                e,
                &core::Knowledge::ReceiptKnown(receipt.clone()),
            )),
        ),
    };
    json!({"state":status,"outcome":outcome,"result":result,"cause":cause,"knowledge":knowledge})
}
fn projection_mapped(value: &Value) -> bool {
    match value {
        Value::Object(fields) => {
            fields.get("mapped") != Some(&Value::Bool(false))
                && fields.values().all(projection_mapped)
        }
        Value::Array(items) => items.iter().all(projection_mapped),
        _ => true,
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
        .find(|b| bytes32(&b.hex).expect("validated key").as_slice() == fence.admission_key)?;
    let payload =
        e.bindings.payloads.iter().find(|b| {
            bytes32(&b.hex).expect("validated payload").as_slice() == fence.payload_mac
        })?;
    let lease = e
        .bindings
        .leases
        .iter()
        .find(|b| b.uuid == fence.lease_token)?;
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
    // Public execute callers must satisfy the same bounded hash shape as parse.
    // Reject before any actual work so root-summary reservation remains valid.
    if hash.len() != 64 || !hash.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(InputError::Schema);
    }
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
    let mut coordinators_finished = true;
    let mut observation_failure = None;
    let mut safety_failure = None;
    let mut knowledge_stop = None;
    let mut views = match initial_knowledge(input) {
        Ok(views) => views,
        Err(reason) => {
            knowledge_stop = Some(json!({"index":0,
                "phase":"BeforeInitialState","reason":reason.name()}));
            complete = false;
            terminal = false;
            Vec::new()
        }
    };
    let mut cancelled = false;
    let mut total_events = 0;
    for (index, c) in e.commands.iter().enumerate() {
        if knowledge_stop.is_some() {
            break;
        }
        let emitted = effect(e, c);
        let mut coordinator = core::Coordinator::new(emitted.correlation, emitted.command.clone());
        let mut witness = core::CommitWitness::new(emitted.clone());
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
            }
        } else {
            transaction(e, &world, c, None)?
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
                .enter_commit(core::PreparedCommit {
                    correlation: emitted.correlation,
                    scope,
                    fact: transaction.fact.clone().expect("scope has fact"),
                })
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
        coordinator
            .observe_witness(&witness)
            .map_err(|_| InputError::Schedule)?;
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
        coordinators_finished &= !pending;
        if pending && !cancelled_cut {
            terminal = false;
        }
        cancelled |= cancelled_cut;
        // Complete()'s retained outcome is the authority for core observation.
        // A controlled cancellation suppresses delivery; it does not finish it.
        let observed = coordinator_projection(e, coordinator.state());
        let retained = knowledge_projection(e, witness.knowledge());
        let domain = coordinator_domain(coordinator.state());
        // This flag belongs to this operation only. Prior Unknown identities
        // stay in their original coordinators/witnesses even when current
        // storage alternatives converge or reconciliation narrows their rows.
        let unresolved = matches!(witness.knowledge(), core::Knowledge::CommitCallEntered(_));
        let time = match c.action.as_str() {
            "finalize" => c.times.finalize_us,
            "reconcile" => c.times.reconcile_us,
            _ => c.times.admission_us,
        };
        let world_counts = counts(&world, &c.actor, time);
        let caller_time = caller_observation_time(coordinator.state(), time);
        // Record actual failed facts before caller-model expansion or evidence
        // trimming. A partial state analysis cannot erase an observed failure.
        if safety_failure.is_none() && world_counts.0 > 4096 {
            safety_failure = Some(json!({"index":index,"active":world_counts.0}));
        }
        let knowledge_complete =
            match advance_knowledge(e, &mut views, c, &witness, coordinator.state()) {
                Ok(()) => true,
                Err(reason) => {
                    knowledge_stop = Some(json!({"index":index,
                    "phase":"AfterCommand","reason":reason.name()}));
                    complete = false;
                    terminal = false;
                    false
                }
            };
        let bounds = knowledge_complete.then(|| knowledge_counts(&views, &c.actor, caller_time));
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
        let mut reconciliation = match coordinator.state() {
            core::ExecutionState::Finished(core::ExecutionOutcome::Completed {
                result: core::EffectResult::Reconcile(observation),
                ..
            }) => Some(reconcile_projection(e, observation)),
            _ => None,
        };
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
            "action":c.action,"kind":c.kind,"times":c.times,"domain":domain,
            "execution":if cancelled_cut {"Cancelled"} else if pending {"Inconclusive"} else {"Completed"},
            "cancellation":cancelled_cut,"coordinator":observed,"witness":retained,
            "knowledge":retained["kind"],"scope":retained["scope"],
            "world":{"committed":committed,"result":transaction.domain,"active":world_counts.0,"retained":world_counts.1,"row_state":r.map(|r|r.state.as_str()).unwrap_or("Absent"),
                "expires_at_us":r.map(|r|r.expires_at_us),"lease":r.map(|r|&r.lease),"actor_sequence":world.actors[&c.actor],
                "proof_present":c.guard.proof.as_ref().map(|p|world.proofs.contains(&p.challenge_id))},
            "caller":{"active_min":bounds.map(|b|b.0.0),"active_max":bounds.map(|b|b.1.0),
                "retained_min":bounds.map(|b|b.0.1),"retained_max":bounds.map(|b|b.1.1),
                "knowledge_complete":knowledge_complete,"possible_states":knowledge_complete.then_some(views.len()),
                "reservation_receipt":reservation_receipt,"reservation":reservation,"finalization_receipt":finalization_receipt,"unresolved":unresolved},
            "completion":{"accepted":accepted,"pending":pending,"rejections":rejections},"reconcile":reconciliation,
        });
        // Keep the first failed observation outside the trim-able event list.
        // A later evidence budget cannot erase an already observed divergence.
        if observation_failure.is_none() && !projection_mapped(&event) {
            observation_failure = Some(json!({"class":"UnmappedMaterial","index":index,
                "operation_id":c.operation_id}));
        }
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
        if e.stage1.is_some() && knowledge_complete {
            compatibility.push(super::stage1::projection(c, &event));
        }
        projection.push(event);
        if observation_failure.is_some() || knowledge_stop.is_some() {
            complete = false;
            terminal = false;
            break;
        }
        operations.insert(c.operation_id.clone(), (coordinator, witness));
    }
    let mut output = json!({"schema":OUTPUT_SCHEMA,"adapter":"controlled_rust","model":MODEL,"scenario_id":e.scenario_id,"input_sha256":hash,
        "execution":if !complete||!terminal {"Inconclusive"} else if cancelled {"Cancelled"} else {"Completed"},"terminal":terminal,"evidence_complete":complete,
        "coordinators_finished":complete && coordinators_finished,
        "observation_failure":observation_failure,
        "safety_failure":safety_failure,"knowledge_stop":knowledge_stop,
        "projection":projection,"compatibility_projection":if e.stage1.is_some() {Some(compatibility)} else {None},
        "limitations":LIMITATIONS});
    // Account for the full root and optional compatibility projection as well,
    // never just the rich events. A bounded prefix cannot qualify completion.
    while serde_json::to_vec(&output).expect("JSON").len() > e.budgets.evidence_bytes {
        output["evidence_complete"] = false.into();
        output["terminal"] = false.into();
        output["coordinators_finished"] = false.into();
        output["execution"] = "Inconclusive".into();
        let events = output["projection"]
            .as_array_mut()
            .expect("projection array");
        if events.pop().is_none() {
            // Unreachable for validated bounded root fields by ROOT_MAX_BYTES.
            // Preserve already observed facts rather than reclassify them as a
            // rejected input if a future root extension violates that contract.
            break;
        }
        let retained_events = output["projection"]
            .as_array()
            .expect("projection array")
            .len();
        if let Some(events) = output["compatibility_projection"].as_array_mut() {
            // A native stopping event has no valid legacy numeric bounds, so
            // it never added a compatibility event in the first place.
            while events.len() > retained_events {
                events.pop();
            }
        }
    }
    Ok(output)
}

#[cfg(test)]
mod knowledge_budget_tests {
    use super::*;

    #[test]
    fn delivered_reconcile_time_drives_projection_filtering_and_caller_bounds() {
        let value = super::super::tests::reconcile_input();
        let (input, _) = super::super::parse(&serde_json::to_vec(&value).unwrap()).unwrap();
        let context = Context::new(&input);
        let empty = initial_knowledge(&input).unwrap().pop().unwrap();
        let pending = transaction(&context, &empty, &input.commands[0], None)
            .unwrap()
            .staged;
        let command = &input.commands[1];
        let emitted = effect(&context, command);
        let witness = core::CommitWitness::new(emitted.clone());
        let mut coordinator = core::Coordinator::new(emitted.correlation, emitted.command.clone());
        coordinator.observe_witness(&witness).unwrap();
        let actual_at = now(1_800_000_001);
        assert_ne!(actual_at, now(command.times.reconcile_us));
        let actual = transaction(&context, &pending, command, Some(actual_at))
            .unwrap()
            .result;
        let core::EffectResult::Reconcile(ref returned) = actual else {
            unreachable!()
        };
        let projected = reconcile_projection(&input, returned);
        assert_eq!(projected["observed_at_us"], 1_800_000_001i64);
        assert_eq!(projected["lease"], "Expired");
        assert_eq!(projected["retention"], "Expired");
        let mut unmapped = returned.clone();
        unmapped.effect.correlation.operation = Uuid::nil();
        assert!(!projection_mapped(&reconcile_projection(&input, &unmapped)));
        let mut views = vec![empty, pending.clone()];
        // An undelivered observation cannot replace the caller's clock or views.
        assert_eq!(
            caller_observation_time(coordinator.state(), command.times.reconcile_us),
            command.times.reconcile_us
        );
        advance_knowledge(&context, &mut views, command, &witness, coordinator.state()).unwrap();
        assert_eq!(views.len(), 2);
        coordinator
            .complete(core::Completion {
                effect: emitted,
                result: actual,
                knowledge: core::Knowledge::NoCommitRequested,
            })
            .unwrap();
        advance_knowledge(&context, &mut views, command, &witness, coordinator.state()).unwrap();
        assert!(views == vec![pending]);
        let caller_time = caller_observation_time(coordinator.state(), command.times.reconcile_us);
        assert_eq!(caller_time, actual_at.timestamp_micros());
        assert_eq!(counts(&views[0], &command.actor, caller_time), (0, 1));
    }

    #[test]
    fn maximal_root_with_all_summaries_fits_minimum_evidence_without_detail() {
        let mut root: Value = serde_json::from_str(ROOT_FIXED_JSON).unwrap();
        root["scenario_id"] = "s".repeat(128).into();
        root["observation_failure"]["operation_id"] = "o".repeat(128).into();
        root["limitations"] = json!(LIMITATIONS);
        assert_eq!(serde_json::to_vec(&root).unwrap().len(), ROOT_MAX_BYTES);
        assert_eq!(root["observation_failure"]["class"], "UnmappedMaterial");
        assert_eq!(root["safety_failure"]["active"], 40256);
        assert_eq!(root["knowledge_stop"]["reason"], "KnowledgeModelIncomplete");
    }

    #[test]
    fn inconsistent_observation_preserves_previous_views_instead_of_inventing_a_world() {
        let value = super::super::tests::input();
        let (input, _) = super::super::parse(&serde_json::to_vec(&value).unwrap()).unwrap();
        let context = Context::new(&input);
        let command = &input.commands[0];
        let emitted = effect(&context, command);
        let coordinator = core::Coordinator::new(emitted.correlation, emitted.command.clone());
        let mut witness = core::CommitWitness::new(emitted.clone());
        // A valid typed Begin witness, but inconsistent with the known empty
        // initial row set. Its prepared fact cannot be replaced with Reserved.
        witness
            .enter_commit(core::PreparedCommit {
                correlation: emitted.correlation,
                scope: core::TransactionScope::RatedBegin(core::BeginCommitPurpose::ReplayRead),
                fact: core::CommitFact::ReplayAccepted,
            })
            .unwrap();
        let mut views = initial_knowledge(&input).unwrap();
        let before = views.clone();
        assert_eq!(
            advance_knowledge(&context, &mut views, command, &witness, coordinator.state()),
            Err(KnowledgeStop::InconsistentObservation)
        );
        assert!(views == before);
    }
}
