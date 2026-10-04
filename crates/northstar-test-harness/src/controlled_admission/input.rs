//! Concrete, synthetic-only saved inputs. This format is deliberately separate
//! from authority-bearing production types and denies unknown/duplicate fields.
use serde::{de, Deserialize, Deserializer, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

pub const INPUT_SCHEMA: &str = "northstar-admission-controlled-input-v1";
pub const OUTPUT_SCHEMA: &str = "northstar-admission-controlled-output-v2";
pub const MODEL: &str = "admission-controlled-v1";
pub const MAX_INPUT: usize = 32 * 1024 * 1024;
pub const MAX_TIME: i64 = 9_000_000_000_000_000;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub schema: String,
    pub model: String,
    pub adapter: String,
    pub binding_version: String,
    pub scenario_id: String,
    pub scope: String,
    pub initial: Initial,
    pub bindings: Bindings,
    pub commands: Vec<Command>,
    pub budgets: Budgets,
    #[serde(deserialize_with = "required_option")]
    pub stage1: Option<Stage1>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Initial {
    pub rows: Vec<Row>,
    pub actor_sequences: BTreeMap<String, u64>,
    pub proofs: Vec<Uuid>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Row {
    pub actor: String,
    pub key: String,
    pub payload_tag: String,
    pub state: String,
    pub expires_at_us: i64,
    pub lease: String,
    pub lease_until_us: i64,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Bindings {
    pub actors: Vec<UuidBinding>,
    pub keys: Vec<KeyBinding>,
    pub payloads: Vec<HexBinding>,
    pub leases: Vec<UuidBinding>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UuidBinding {
    pub label: String,
    pub uuid: Uuid,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KeyBinding {
    pub label: String,
    pub key_id: String,
    pub hex: String,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HexBinding {
    pub label: String,
    pub hex: String,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Command {
    pub operation_id: String,
    pub operation_uuid: Uuid,
    pub effect_number: u64,
    pub effect_id: String,
    #[serde(deserialize_with = "required_option")]
    pub causal_id: Option<String>,
    pub attempt: u32,
    pub generation: u64,
    pub action: String,
    pub kind: String,
    pub actor: String,
    pub key: String,
    pub payload_tag: String,
    pub lease: String,
    pub candidates: Vec<String>,
    pub times: Times,
    pub guard: Guard,
    pub schedule: Schedule,
    #[serde(deserialize_with = "required_option")]
    pub reconcile_of: Option<String>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Times {
    pub admission_us: i64,
    pub actor_policy_us: i64,
    pub finalize_us: i64,
    pub reconcile_us: i64,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Guard {
    pub account_bare: String,
    pub normalized_target: String,
    #[serde(deserialize_with = "required_option")]
    pub origin_id: Option<String>,
    pub normalized_payload: String,
    pub pow_intent_payload: String,
    pub subject: String,
    pub actors: Vec<String>,
    #[serde(deserialize_with = "required_option")]
    pub proof: Option<Proof>,
    pub allowed: bool,
    pub actor_sequence_delta: u64,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Proof {
    pub challenge_id: Uuid,
    pub nonce: String,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Schedule {
    pub cut: String,
    pub world_commit: bool,
    pub cleanup: String,
    pub locked_keys: Vec<String>,
    pub completions: Vec<CompletionInput>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompletionInput {
    pub operation_uuid: Uuid,
    pub effect_number: u64,
    pub generation: u64,
    pub attempt: u32,
    pub action: String,
    pub actor: String,
    pub key: String,
    pub payload_tag: String,
    pub lease: String,
    pub guard: Guard,
    #[serde(deserialize_with = "required_option")]
    pub reconcile_of: Option<String>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Budgets {
    pub steps: usize,
    pub events: usize,
    pub evidence_bytes: usize,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Stage1 {
    pub scenario: Value,
    pub sha256: String,
}

/// Finite error categories, never raw deserialization/authority input text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputError {
    InputSize,
    Json,
    Schema,
    Fields,
    Binding,
    State,
    Command,
    Schedule,
    Budget,
    Stage1,
}
impl InputError {
    pub fn code(self) -> &'static str {
        match self {
            Self::InputSize => "input_size",
            Self::Json => "invalid_json",
            Self::Schema => "schema",
            Self::Fields => "fields",
            Self::Binding => "binding",
            Self::State => "initial_state",
            Self::Command => "command",
            Self::Schedule => "schedule",
            Self::Budget => "budget",
            Self::Stage1 => "stage1_bridge",
        }
    }
}
impl std::fmt::Display for InputError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for InputError {}

/// The preliminary recursive parse prevents duplicate fields even inside maps
/// and the embedded Stage1 JSON before serde's typed exact-field parsing.
struct StrictJson(Value);
impl<'de> Deserialize<'de> for StrictJson {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> de::Visitor<'de> for Visitor {
            type Value = StrictJson;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("strict JSON")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Self::Value, E> {
                Ok(StrictJson(v.into()))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
                Ok(StrictJson(v.into()))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
                Ok(StrictJson(v.into()))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> Result<Self::Value, E> {
                serde_json::Number::from_f64(v)
                    .map(|n| StrictJson(Value::Number(n)))
                    .ok_or_else(|| E::custom("nonfinite"))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(StrictJson(v.into()))
            }
            fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
                Ok(StrictJson(v.into()))
            }
            fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(StrictJson(Value::Null))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(StrictJson(Value::Null))
            }
            fn visit_seq<A: de::SeqAccess<'de>>(self, mut a: A) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(v) = a.next_element::<StrictJson>()? {
                    values.push(v.0);
                }
                Ok(StrictJson(Value::Array(values)))
            }
            fn visit_map<A: de::MapAccess<'de>>(self, mut a: A) -> Result<Self::Value, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some((k, v)) = a.next_entry::<String, StrictJson>()? {
                    if values.insert(k, v.0).is_some() {
                        return Err(de::Error::custom("duplicate"));
                    }
                }
                Ok(StrictJson(Value::Object(values)))
            }
        }
        d.deserialize_any(Visitor)
    }
}
pub(super) fn required_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}
pub fn digest(value: &Value) -> String {
    format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(value).expect("JSON value serializes"))
    )
}
pub fn parse(bytes: &[u8]) -> Result<(Envelope, String), InputError> {
    if bytes.len() > MAX_INPUT {
        return Err(InputError::InputSize);
    }
    let strict: StrictJson = serde_json::from_slice(bytes).map_err(|_| InputError::Json)?;
    canonical_material(&strict.0)?;
    let hash = digest(&strict.0);
    let envelope: Envelope = serde_json::from_value(strict.0).map_err(|_| InputError::Fields)?;
    envelope.validate()?;
    Ok((envelope, hash))
}
fn ensure(condition: bool, error: InputError) -> Result<(), InputError> {
    if condition {
        Ok(())
    } else {
        Err(error)
    }
}
fn label(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
}
pub fn bytes32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let mut out = [0; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}
fn unique<'a>(values: impl Iterator<Item = &'a str>) -> bool {
    let mut seen = BTreeSet::new();
    values.into_iter().all(|v| seen.insert(v))
}
impl Envelope {
    pub fn actor(&self, name: &str) -> Uuid {
        self.bindings
            .actors
            .iter()
            .find(|v| v.label == name)
            .expect("validated actor")
            .uuid
    }
    pub fn key(&self, name: &str) -> &KeyBinding {
        self.bindings
            .keys
            .iter()
            .find(|v| v.label == name)
            .expect("validated key")
    }
    pub fn payload(&self, name: &str) -> Vec<u8> {
        bytes32(
            &self
                .bindings
                .payloads
                .iter()
                .find(|v| v.label == name)
                .expect("validated payload")
                .hex,
        )
        .expect("validated hex")
        .to_vec()
    }
    pub fn lease(&self, name: &str) -> Uuid {
        self.bindings
            .leases
            .iter()
            .find(|v| v.label == name)
            .expect("validated lease")
            .uuid
    }
    pub fn validate(&self) -> Result<(), InputError> {
        ensure(
            self.schema == INPUT_SCHEMA
                && self.model == MODEL
                && self.adapter == "controlled_rust"
                && self.binding_version == "synthetic-material-v1"
                && self.scope == "reservation_finalization_only",
            InputError::Schema,
        )?;
        ensure(label(&self.scenario_id), InputError::Schema)?;
        ensure(
            (1..=256).contains(&self.budgets.steps)
                && (1..=4096).contains(&self.budgets.events)
                && (2048..=8 * 1024 * 1024).contains(&self.budgets.evidence_bytes),
            InputError::Budget,
        )?;
        ensure(
            !self.commands.is_empty()
                && self.commands.len() <= self.budgets.steps
                && self.initial.rows.len() <= 40000,
            InputError::Budget,
        )?;
        let b = &self.bindings;
        ensure(
            !b.actors.is_empty()
                && b.actors.len() <= 64
                && !b.keys.is_empty()
                && b.keys.len() <= 40512
                && !b.payloads.is_empty()
                && b.payloads.len() <= 512
                && !b.leases.is_empty()
                && b.leases.len() <= 40512,
            InputError::Binding,
        )?;
        for values in [&b.actors, &b.leases] {
            ensure(
                values.iter().all(|v| label(&v.label))
                    && unique(values.iter().map(|v| v.label.as_str()))
                    && values.iter().map(|v| v.uuid).collect::<BTreeSet<_>>().len() == values.len(),
                InputError::Binding,
            )?;
        }
        ensure(
            b.keys
                .iter()
                .all(|v| label(&v.label) && label(&v.key_id) && bytes32(&v.hex).is_some())
                && unique(b.keys.iter().map(|v| v.label.as_str()))
                && unique(b.keys.iter().map(|v| v.hex.as_str())),
            InputError::Binding,
        )?;
        ensure(
            b.payloads
                .iter()
                .all(|v| label(&v.label) && bytes32(&v.hex).is_some())
                && unique(b.payloads.iter().map(|v| v.label.as_str()))
                && unique(b.payloads.iter().map(|v| v.hex.as_str())),
            InputError::Binding,
        )?;
        let actors: BTreeSet<_> = b.actors.iter().map(|v| v.label.as_str()).collect();
        let keys: BTreeSet<_> = b.keys.iter().map(|v| v.label.as_str()).collect();
        let payloads: BTreeSet<_> = b.payloads.iter().map(|v| v.label.as_str()).collect();
        let leases: BTreeSet<_> = b.leases.iter().map(|v| v.label.as_str()).collect();
        let material = |actor: &str, key: &str, payload: &str, lease: &str| {
            actors.contains(actor)
                && keys.contains(key)
                && payloads.contains(payload)
                && leases.contains(lease)
        };
        ensure(
            self.initial
                .actor_sequences
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
                == actors
                && self
                    .initial
                    .actor_sequences
                    .values()
                    .all(|v| *v <= 1_000_000)
                && self
                    .initial
                    .proofs
                    .iter()
                    .copied()
                    .collect::<BTreeSet<_>>()
                    .len()
                    == self.initial.proofs.len(),
            InputError::State,
        )?;
        ensure(
            unique(self.initial.rows.iter().map(|r| r.key.as_str())),
            InputError::State,
        )?;
        for row in &self.initial.rows {
            ensure(
                material(&row.actor, &row.key, &row.payload_tag, &row.lease)
                    && ["pending", "accepted"].contains(&row.state.as_str())
                    && (-MAX_TIME..=MAX_TIME).contains(&row.expires_at_us)
                    && (-MAX_TIME..=MAX_TIME).contains(&row.lease_until_us),
                InputError::State,
            )?;
        }
        let mut operations = BTreeMap::<&str, &Command>::new();
        let mut effects = BTreeSet::new();
        let mut correlations = BTreeSet::new();
        let mut prior_times = [0, 0, 0, 0];
        for c in &self.commands {
            ensure(
                label(&c.operation_id)
                    && label(&c.effect_id)
                    && effects.insert(c.effect_id.as_str())
                    && !operations.contains_key(c.operation_id.as_str())
                    && correlations.insert(c.operation_uuid)
                    && (1..=MAX_TIME as u64).contains(&c.effect_number)
                    && (1..=20000).contains(&c.attempt)
                    && (0..=20000).contains(&c.generation),
                InputError::Command,
            )?;
            ensure(
                c.causal_id
                    .as_deref()
                    .is_none_or(|v| operations.contains_key(v))
                    && material(&c.actor, &c.key, &c.payload_tag, &c.lease)
                    && ["direct", "muc", "mix"].contains(&c.kind.as_str())
                    && [
                        "reserve",
                        "finalize",
                        "reconcile",
                        "guard_memory",
                        "guard_persistent",
                    ]
                    .contains(&c.action.as_str()),
                InputError::Command,
            )?;
            ensure(
                !c.candidates.is_empty()
                    && c.candidates.len() <= 8
                    && c.candidates[0] == c.key
                    && c.candidates.iter().all(|v| keys.contains(v.as_str()))
                    && unique(c.candidates.iter().map(String::as_str)),
                InputError::Command,
            )?;
            ensure(
                [
                    c.times.admission_us,
                    c.times.actor_policy_us,
                    c.times.finalize_us,
                    c.times.reconcile_us,
                ]
                .iter()
                .all(|t| (0..=MAX_TIME).contains(t)),
                InputError::Command,
            )?;
            let times = [
                c.times.admission_us,
                c.times.actor_policy_us,
                c.times.finalize_us,
                c.times.reconcile_us,
            ];
            ensure(
                times.iter().zip(prior_times).all(|(new, old)| *new >= old),
                InputError::Command,
            )?;
            prior_times = times;
            validate_guard(&c.guard)?;
            let s = &c.schedule;
            ensure(
                [
                    "none",
                    "before_effect_cancel",
                    "precommit_error",
                    "commit_unknown",
                    "commit_cancel",
                    "receipt_before_cancel",
                ]
                .contains(&s.cut.as_str())
                    && ["exact_key_only", "bounded_skip_locked"].contains(&s.cleanup.as_str())
                    && (s.cleanup != "exact_key_only" || self.stage1.is_some())
                    && unique(s.locked_keys.iter().map(String::as_str))
                    && s.locked_keys.iter().all(|v| keys.contains(v.as_str())),
                InputError::Schedule,
            )?;
            ensure(s.completions.len() <= 16, InputError::Schedule)?;
            for completion in &s.completions {
                ensure(
                    (1..=MAX_TIME as u64).contains(&completion.effect_number)
                        && completion.generation <= 20000
                        && (1..=20000).contains(&completion.attempt)
                        && [
                            "reserve",
                            "finalize",
                            "reconcile",
                            "guard_memory",
                            "guard_persistent",
                        ]
                        .contains(&completion.action.as_str())
                        && material(
                            &completion.actor,
                            &completion.key,
                            &completion.payload_tag,
                            &completion.lease,
                        )
                        && completion
                            .reconcile_of
                            .as_deref()
                            .is_none_or(|v| operations.contains_key(v))
                        && (completion.action == "reconcile") == completion.reconcile_of.is_some(),
                    InputError::Schedule,
                )?;
                validate_guard(&completion.guard)?;
            }
            ensure(
                if ["none", "precommit_error", "commit_unknown"].contains(&s.cut.as_str()) {
                    !s.completions.is_empty()
                } else {
                    s.completions.is_empty()
                },
                InputError::Schedule,
            )?;
            ensure(
                !["before_effect_cancel", "precommit_error"].contains(&s.cut.as_str())
                    || !s.world_commit,
                InputError::Schedule,
            )?;
            ensure(
                !["none", "receipt_before_cancel"].contains(&s.cut.as_str()) || s.world_commit,
                InputError::Schedule,
            )?;
            ensure(
                (c.action == "reconcile") == c.reconcile_of.is_some(),
                InputError::Command,
            )?;
            if let Some(target) = c.reconcile_of.as_deref() {
                let prior = operations.get(target).ok_or(InputError::Command)?;
                ensure(
                    ["commit_unknown", "commit_cancel"].contains(&prior.schedule.cut.as_str())
                        && ["reserve", "finalize"].contains(&prior.action.as_str())
                        && prior.actor == c.actor
                        && prior.key == c.key
                        && prior.payload_tag == c.payload_tag
                        && prior.lease == c.lease,
                    InputError::Command,
                )?;
            }
            if c.action == "finalize" {
                ensure(
                    c.causal_id
                        .as_deref()
                        .and_then(|id| operations.get(id))
                        .is_none_or(|p| {
                            !["guard_memory", "guard_persistent"].contains(&p.action.as_str())
                        }),
                    InputError::Command,
                )?;
            }
            if c.action == "reserve" {
                ensure(
                    !operations.values().any(|p| {
                        ["commit_unknown", "commit_cancel"].contains(&p.schedule.cut.as_str())
                            && p.key == c.key
                            && p.actor == c.actor
                    }),
                    InputError::Command,
                )?;
            }
            operations.insert(&c.operation_id, c);
        }
        if let Some(stage1) = &self.stage1 {
            self.validate_stage1(stage1)?;
        }
        Ok(())
    }
    fn validate_stage1(&self, stage1: &Stage1) -> Result<(), InputError> {
        // Full structural validation is kept independent of the Stage1 predictor.
        super::stage1::validate_bridge(self, stage1)
    }
}

fn validate_guard(g: &Guard) -> Result<(), InputError> {
    ensure(
        [
            &g.account_bare,
            &g.normalized_target,
            &g.normalized_payload,
            &g.pow_intent_payload,
            &g.subject,
        ]
        .iter()
        .all(|s| !s.is_empty() && s.len() <= 1024 && s.is_ascii())
            && g.origin_id.as_ref().is_none_or(|s| label(s))
            && !g.actors.is_empty()
            && g.actors.len() <= 16
            && g.actors.iter().all(|s| label(s))
            && unique(g.actors.iter().map(String::as_str))
            && g.actor_sequence_delta <= 10
            && g.proof
                .as_ref()
                .is_none_or(|p| !p.nonce.is_empty() && p.nonce.len() <= 128 && p.nonce.is_ascii()),
        InputError::Command,
    )
}

fn canonical_material(value: &Value) -> Result<(), InputError> {
    match value {
        Value::String(s) if !s.is_ascii() => Err(InputError::Binding),
        Value::Array(values) => {
            for v in values {
                canonical_material(v)?;
            }
            Ok(())
        }
        Value::Object(map) => {
            for (key, v) in map {
                if !key.is_ascii() {
                    return Err(InputError::Fields);
                }
                if ["uuid", "operation_uuid", "challenge_id"].contains(&key.as_str()) {
                    let s = v.as_str().ok_or(InputError::Binding)?;
                    if Uuid::parse_str(s).map(|u| u.to_string()).ok().as_deref() != Some(s) {
                        return Err(InputError::Binding);
                    }
                }
                if key == "proofs" {
                    for proof in v.as_array().ok_or(InputError::Binding)? {
                        let text = proof.as_str().ok_or(InputError::Binding)?;
                        if Uuid::parse_str(text).map(|u| u.to_string()).ok().as_deref()
                            != Some(text)
                        {
                            return Err(InputError::Binding);
                        }
                    }
                }
                canonical_material(v)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}
