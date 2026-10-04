//! Structural bridge to the unchanged synthetic v1 contract. No prediction is
//! executed here: compatibility observations come from shared Rust execution.
use super::input::{digest, Envelope, InputError, Row, Stage1, MAX_TIME};
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeSet;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Scenario {
    schema: String,
    model: String,
    scenario_id: String,
    purpose: String,
    policy: Policy,
    clock: Clock,
    actors: Vec<String>,
    initial_rows: Vec<Row>,
    commands: Vec<Command>,
    budgets: Budgets,
    termination: Termination,
    #[serde(deserialize_with = "super::input::required_option")]
    seed: Option<u64>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    actor_capacity: u64,
    accepted_ttl_us: u64,
    pending_ttl_us: u64,
    lease_us: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Clock {
    domain: String,
    unit: String,
    start_us: i64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Command {
    operation_id: String,
    effect_id: String,
    #[serde(deserialize_with = "super::input::required_option")]
    causal_id: Option<String>,
    attempt: u32,
    time_us: i64,
    action: String,
    kind: String,
    actor: String,
    key: String,
    payload_tag: String,
    lease: String,
    cut: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Budgets {
    domain_us: u64,
    wall_ms: u64,
    steps: u64,
    events: u64,
    evidence_bytes: u64,
    memory_bytes: u64,
    files: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Termination {
    after_commands: String,
    terminal_required: bool,
}
fn require(v: bool) -> Result<(), InputError> {
    if v {
        Ok(())
    } else {
        Err(InputError::Stage1)
    }
}
pub fn validate_bridge(e: &Envelope, bridge: &Stage1) -> Result<(), InputError> {
    require(digest(&bridge.scenario) == bridge.sha256)?;
    let s: Scenario =
        serde_json::from_value(bridge.scenario.clone()).map_err(|_| InputError::Stage1)?;
    require(
        s.schema == "northstar-admission-scenario-v1"
            && s.model == "admission-fixture-v1"
            && s.scenario_id == e.scenario_id
            && ["normal", "capacity", "replay", "ttl", "lease", "unknown"]
                .contains(&s.purpose.as_str()),
    )?;
    require(
        s.policy.actor_capacity == 4096
            && s.policy.accepted_ttl_us == 21_600_000_000
            && s.policy.pending_ttl_us == 1_800_000_000
            && s.policy.lease_us == 60_000_000,
    )?;
    require(
        s.clock.domain == "sql_model"
            && s.clock.unit == "microsecond"
            && (0..=MAX_TIME).contains(&s.clock.start_us),
    )?;
    require(s.termination.after_commands == "complete" && s.termination.terminal_required)?;
    require(
        s.seed.is_none_or(|v| v <= MAX_TIME as u64)
            && s.budgets.domain_us > 0
            && s.budgets.domain_us <= MAX_TIME as u64
            && s.budgets.wall_ms > 0
            && s.budgets.wall_ms <= MAX_TIME as u64
            && s.budgets.steps > 0
            && s.budgets.steps <= 20000
            && s.budgets.events > 0
            && s.budgets.events <= 20000
            && s.budgets.evidence_bytes > 0
            && s.budgets.evidence_bytes <= 8 * 1024 * 1024
            && s.budgets.memory_bytes > 0
            && s.budgets.memory_bytes <= MAX_TIME as u64
            && s.budgets.files <= MAX_TIME as u64,
    )?;
    require(
        s.actors.iter().collect::<BTreeSet<_>>()
            == e.bindings.actors.iter().map(|v| &v.label).collect()
            && s.actors.iter().collect::<BTreeSet<_>>().len() == s.actors.len()
            && serde_json::to_value(&s.initial_rows).ok()
                == serde_json::to_value(&e.initial.rows).ok()
            && e.initial.actor_sequences.values().all(|n| *n == 0)
            && e.initial.proofs.is_empty(),
    )?;
    require(
        s.commands.len() == e.commands.len()
            && s.commands.len() as u64 <= s.budgets.steps
            && s.commands.len() as u64 <= s.budgets.events,
    )?;
    let mut last_time = s.clock.start_us;
    let mut prior_cut = "none";
    for (c, actual) in s.commands.iter().zip(&e.commands) {
        require(
            c.operation_id == actual.operation_id
                && c.effect_id == actual.effect_id
                && c.causal_id == actual.causal_id
                && c.attempt == actual.attempt
                && c.action == actual.action
                && c.kind == actual.kind
                && c.actor == actual.actor
                && c.key == actual.key
                && c.payload_tag == actual.payload_tag
                && c.lease == actual.lease
                && actual.generation == 1
                && actual.candidates == vec![actual.key.clone()]
                && actual.guard.allowed
                && actual.guard.actor_sequence_delta == 0
                && actual.guard.proof.is_none()
                && actual.schedule.cleanup == "exact_key_only"
                && actual.schedule.locked_keys.is_empty(),
        )?;
        require(
            [
                actual.times.admission_us,
                actual.times.actor_policy_us,
                actual.times.finalize_us,
                actual.times.reconcile_us,
            ]
            .iter()
            .all(|t| *t == c.time_us)
                && c.time_us >= last_time
                && c.time_us - s.clock.start_us <= s.budgets.domain_us as i64
                && ["reserve", "finalize"].contains(&c.action.as_str())
                && prior_cut == "none",
        )?;
        let cut = match c.cut.as_str() {
            "none" => "none",
            "before_effect_cancel" => "before_effect_cancel",
            "reservation_commit_unknown" if c.action == "reserve" => "commit_unknown",
            _ => return Err(InputError::Stage1),
        };
        require(actual.schedule.cut == cut)?;
        if cut == "before_effect_cancel" {
            require(actual.schedule.completions.is_empty())?;
        } else {
            require(actual.schedule.completions.len() == 1)?;
            let expected = serde_json::json!({
                "operation_uuid":actual.operation_uuid,"effect_number":actual.effect_number,
                "generation":actual.generation,"attempt":actual.attempt,"action":actual.action,
                "actor":actual.actor,"key":actual.key,"payload_tag":actual.payload_tag,"lease":actual.lease,
                "guard":actual.guard,"reconcile_of":null,
            });
            require(serde_json::to_value(&actual.schedule.completions[0]).ok() == Some(expected))?;
        }
        last_time = c.time_us;
        prior_cut = &c.cut;
    }
    Ok(())
}

pub fn projection(c: &super::input::Command, event: &Value) -> Value {
    let caller = &event["caller"];
    let world = &event["world"];
    let unknown = event["domain"] == "Unknown";
    // The legacy fixture describes external cancellation as NotRequested.
    // Translate only the native observation of that action with a still-waiting
    // coordinator and no retained commit knowledge; never invent a core outcome.
    let cancelled_before_effect = event["cancellation"] == true
        && event["coordinator"]["state"] == "Waiting"
        && event["witness"]["kind"] == "NoCommitRequested";
    let domain = if cancelled_before_effect {
        Value::String("NotRequested".into())
    } else {
        event["domain"].clone()
    };
    let action = &c.action;
    serde_json::json!({
        "schema_version":1,"operation_id":c.operation_id,"effect_id":c.effect_id,"causal_id":c.causal_id,
        "attempt":c.attempt,"time_us":c.times.admission_us,"transition":action,"actor":c.actor,"key":c.key,"kind":c.kind,
        "execution":event["execution"],"domain":domain,
        "effect_status": if unknown {"Unknown"} else if cancelled_before_effect {"NotRequested"} else {"Confirmed"},
        "active_min":caller["active_min"],"active_max":caller["active_max"],
        "retained_min":caller["retained_min"],"retained_max":caller["retained_max"],
        "row_state":if unknown {Value::String("Unconfirmed".into())} else {world["row_state"].clone()},
        "expires_at_us":if unknown {Value::Null} else {world["expires_at_us"].clone()},
        "lease":if unknown {Value::Null} else {world["lease"].clone()},
    })
}
