use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use dashmap::DashMap;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AbuseAction {
    Registration,
    Message,
    Report,
    Appeal,
    Login,
}

impl AbuseAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Registration => "registration",
            Self::Message => "message",
            Self::Report => "report",
            Self::Appeal => "appeal",
            Self::Login => "login",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "registration" => Some(Self::Registration),
            "message" => Some(Self::Message),
            "report" => Some(Self::Report),
            "appeal" => Some(Self::Appeal),
            "login" => Some(Self::Login),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct PowProof {
    pub challenge_id: Uuid,
    pub nonce: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct WorkRequirement {
    pub action: &'static str,
    pub step: u32,
    pub work_factor: u64,
    pub max_work_factor: u64,
    pub hard_wait_seconds: u64,
    pub retry_after_seconds: u64,
    pub cooldown_seconds: u64,
    pub approximate_max_device_seconds: u64,
    pub notice: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct PowChallenge {
    pub challenge_id: Uuid,
    pub prefix: String,
    pub expires_in_seconds: u64,
    pub requirement: WorkRequirement,
}

#[derive(Debug)]
pub enum GuardError {
    Required(WorkRequirement),
    Invalid(&'static str, WorkRequirement),
}

impl GuardError {
    pub fn requirement(&self) -> &WorkRequirement {
        match self {
            Self::Required(requirement) | Self::Invalid(_, requirement) => requirement,
        }
    }

    pub fn message(&self) -> &'static str {
        match self {
            Self::Required(_) => "proof of work or cooldown is required",
            Self::Invalid(message, _) => message,
        }
    }
}

#[derive(Clone, Copy)]
pub struct AbuseConfig {
    pub base_work_factor: u64,
    pub max_work_factor: u64,
    pub window: Duration,
    pub cooldown_step: Duration,
    pub max_wait: Duration,
}

struct ActorState {
    events: VecDeque<Instant>,
    penalty_level: u32,
    last_activity: Instant,
    blocked_until: Instant,
    sequence: u64,
}

impl ActorState {
    fn new(now: Instant) -> Self {
        Self {
            events: VecDeque::new(),
            penalty_level: 0,
            last_activity: now,
            blocked_until: now,
            sequence: 0,
        }
    }
}

struct StoredChallenge {
    action: AbuseAction,
    subject: String,
    prefix: String,
    work_factor: u64,
    not_before: Instant,
    expires_at: Instant,
    actor_sequences: Vec<(String, u64)>,
    requirement: WorkRequirement,
}

pub struct AbuseGuard {
    config: AbuseConfig,
    states: DashMap<String, ActorState>,
    challenges: DashMap<Uuid, StoredChallenge>,
    latest_challenges: DashMap<String, Uuid>,
    challenge_issues: DashMap<String, VecDeque<Instant>>,
}

impl AbuseGuard {
    pub fn new(config: AbuseConfig) -> Self {
        Self {
            config,
            states: DashMap::new(),
            challenges: DashMap::new(),
            latest_challenges: DashMap::new(),
            challenge_issues: DashMap::new(),
        }
    }

    pub fn issue(&self, action: AbuseAction, subject: &str, actors: &[String]) -> PowChallenge {
        self.cleanup_challenges();
        let now = Instant::now();
        for actor in actors {
            let mut issues = self
                .challenge_issues
                .entry(format!("challenge:{actor}"))
                .or_default();
            while issues
                .front()
                .is_some_and(|time| now.saturating_duration_since(*time) > self.config.window)
            {
                issues.pop_front();
            }
            if issues.len() >= 30 {
                drop(issues);
                self.punish(action, actors, now);
                break;
            }
            issues.push_back(now);
        }
        let requirement = self.requirement(action, actors, now);
        let mut random = [0_u8; 18];
        rand::thread_rng().fill_bytes(&mut random);
        let id = Uuid::new_v4();
        let challenge_key = format!("{}:{subject}", action.as_str());
        if let Some(previous_id) = self.latest_challenges.insert(challenge_key.clone(), id) {
            self.challenges.remove(&previous_id);
        }
        let prefix = format!(
            "northstar:{}:{}:{}:{}:",
            id,
            action.as_str(),
            subject,
            URL_SAFE_NO_PAD.encode(random),
        );
        let actor_sequences = actors
            .iter()
            .map(|actor| {
                let key = state_key(action, actor);
                let sequence = self
                    .states
                    .get(&key)
                    .map(|state| state.sequence)
                    .unwrap_or(0);
                (key, sequence)
            })
            .collect();
        let ttl =
            Duration::from_secs(120).max(Duration::from_secs(requirement.hard_wait_seconds + 30));
        self.challenges.insert(
            id,
            StoredChallenge {
                action,
                subject: subject.to_owned(),
                prefix: prefix.clone(),
                work_factor: requirement.work_factor,
                not_before: now + Duration::from_secs(requirement.hard_wait_seconds),
                expires_at: now + ttl,
                actor_sequences,
                requirement: requirement.clone(),
            },
        );
        PowChallenge {
            challenge_id: id,
            prefix,
            expires_in_seconds: ttl.as_secs(),
            requirement,
        }
    }

    pub fn verify_or_allow(
        &self,
        action: AbuseAction,
        subject: &str,
        actors: &[String],
        proof: Option<&PowProof>,
    ) -> Result<WorkRequirement, GuardError> {
        let now = Instant::now();
        let current = self.requirement(action, actors, now);
        if current.work_factor <= 1 && current.retry_after_seconds == 0 && proof.is_none() {
            self.record(action, actors, now, &current);
            return Ok(current);
        }
        let Some(proof) = proof else {
            self.punish(action, actors, now);
            return Err(GuardError::Required(current));
        };
        let Some((_, challenge)) = self.challenges.remove(&proof.challenge_id) else {
            self.punish(action, actors, now);
            return Err(GuardError::Invalid(
                "proof-of-work challenge is missing or already used",
                current,
            ));
        };
        let challenge_key = format!("{}:{subject}", action.as_str());
        if self
            .latest_challenges
            .get(&challenge_key)
            .is_some_and(|entry| *entry == proof.challenge_id)
        {
            self.latest_challenges.remove(&challenge_key);
        }
        if challenge.action != action || challenge.subject != subject {
            self.punish(action, actors, now);
            return Err(GuardError::Invalid(
                "proof-of-work challenge does not match this operation",
                current,
            ));
        }
        if now > challenge.expires_at {
            return Err(GuardError::Invalid(
                "proof-of-work challenge expired",
                current,
            ));
        }
        if now < challenge.not_before {
            return Err(GuardError::Invalid(
                "hard cooldown has not finished",
                challenge.requirement,
            ));
        }
        for (key, expected) in &challenge.actor_sequences {
            let actual = self
                .states
                .get(key)
                .map(|state| state.sequence)
                .unwrap_or(0);
            if actual != *expected {
                return Err(GuardError::Invalid(
                    "another operation already advanced this rate-limit step",
                    current,
                ));
            }
        }
        if proof.nonce.is_empty()
            || proof.nonce.len() > 64
            || !proof.nonce.bytes().all(|byte| byte.is_ascii_digit())
        {
            self.punish(action, actors, now);
            return Err(GuardError::Invalid(
                "proof-of-work nonce is invalid",
                current,
            ));
        }
        let mut hasher = Sha256::new();
        hasher.update(challenge.prefix.as_bytes());
        hasher.update(proof.nonce.as_bytes());
        let digest = hasher.finalize();
        let value = u64::from_be_bytes(digest[..8].try_into().expect("SHA-256 prefix"));
        let target = u64::MAX / challenge.work_factor.max(1);
        if value > target {
            self.punish(action, actors, now);
            return Err(GuardError::Invalid(
                "proof of work is insufficient",
                current,
            ));
        }
        self.record(action, actors, now, &challenge.requirement);
        Ok(challenge.requirement)
    }

    pub fn current_requirement(&self, action: AbuseAction, actors: &[String]) -> WorkRequirement {
        self.requirement(action, actors, Instant::now())
    }

    pub fn record_failure(&self, action: AbuseAction, actors: &[String]) {
        let now = Instant::now();
        let requirement = self.requirement(action, actors, now);
        self.record(action, actors, now, &requirement);
    }

    fn requirement(&self, action: AbuseAction, actors: &[String], now: Instant) -> WorkRequirement {
        let policy = policy(action, self.config.base_work_factor);
        let mut event_count = 0_usize;
        let mut penalty = 0_u32;
        let mut retry_after = 0_u64;
        for actor in actors {
            let key = state_key(action, actor);
            if let Some(mut state) = self.states.get_mut(&key) {
                decay(
                    &mut state,
                    now,
                    self.config.window,
                    self.config.cooldown_step,
                );
                event_count = event_count.max(state.events.len());
                penalty = penalty.max(state.penalty_level);
                retry_after =
                    retry_after.max(state.blocked_until.saturating_duration_since(now).as_secs());
            }
        }
        let step = event_count
            .saturating_add(1)
            .saturating_sub(policy.free_burst) as u32;
        let squared = u64::from(step).saturating_mul(u64::from(step));
        let penalty_multiplier = 1_u64.checked_shl(penalty.min(20)).unwrap_or(u64::MAX);
        let work_factor = if step == 0 || policy.base_work == 0 {
            1
        } else {
            policy
                .base_work
                .saturating_mul(squared)
                .saturating_mul(penalty_multiplier)
                .clamp(1, self.config.max_work_factor)
        };
        let hard_wait = hard_wait_seconds(action, step, penalty)
            .min(self.config.max_wait.as_secs())
            .max(retry_after);
        WorkRequirement {
            action: action.as_str(),
            step,
            work_factor,
            max_work_factor: self.config.max_work_factor,
            hard_wait_seconds: hard_wait,
            retry_after_seconds: retry_after,
            cooldown_seconds: self.config.cooldown_step.as_secs().saturating_mul(1_u64 << penalty.min(10)),
            approximate_max_device_seconds: 8,
            notice: "Work rises in quadratic steps, has a fixed maximum, and falls one cooldown step at a time after activity stops.",
        }
    }

    fn record(
        &self,
        action: AbuseAction,
        actors: &[String],
        now: Instant,
        requirement: &WorkRequirement,
    ) {
        for actor in actors {
            let key = state_key(action, actor);
            let mut state = self
                .states
                .entry(key)
                .or_insert_with(|| ActorState::new(now));
            decay(
                &mut state,
                now,
                self.config.window,
                self.config.cooldown_step,
            );
            state.events.push_back(now);
            state.sequence = state.sequence.wrapping_add(1);
            state.last_activity = now;
            if requirement.hard_wait_seconds > 0 {
                state.blocked_until = now + Duration::from_secs(requirement.hard_wait_seconds);
            }
        }
    }

    fn punish(&self, action: AbuseAction, actors: &[String], now: Instant) {
        for actor in actors {
            let key = state_key(action, actor);
            let mut state = self
                .states
                .entry(key)
                .or_insert_with(|| ActorState::new(now));
            decay(
                &mut state,
                now,
                self.config.window,
                self.config.cooldown_step,
            );
            state.events.push_back(now);
            state.penalty_level = state.penalty_level.saturating_add(1).min(10);
            state.sequence = state.sequence.wrapping_add(1);
            state.last_activity = now;
            let wait = 2_u64
                .saturating_pow(state.penalty_level.min(9))
                .min(self.config.max_wait.as_secs());
            state.blocked_until = now + Duration::from_secs(wait);
        }
    }

    pub(crate) fn cleanup_challenges(&self) {
        let now = Instant::now();
        self.challenges
            .retain(|_, challenge| challenge.expires_at > now);
        self.latest_challenges
            .retain(|_, challenge_id| self.challenges.contains_key(challenge_id));
    }
}

#[derive(Clone, Copy)]
struct Policy {
    free_burst: usize,
    base_work: u64,
}

fn policy(action: AbuseAction, base: u64) -> Policy {
    match action {
        AbuseAction::Registration => Policy {
            free_burst: 1,
            base_work: 0,
        },
        AbuseAction::Message => Policy {
            free_burst: 6,
            base_work: base,
        },
        AbuseAction::Report => Policy {
            free_burst: 0,
            base_work: base.saturating_mul(2),
        },
        AbuseAction::Appeal => Policy {
            free_burst: 0,
            base_work: base.saturating_mul(8),
        },
        AbuseAction::Login => Policy {
            free_burst: 5,
            base_work: base,
        },
    }
}

fn hard_wait_seconds(action: AbuseAction, step: u32, penalty: u32) -> u64 {
    let base: u64 = match step {
        0..=3 => 0,
        4..=7 => 2,
        8..=11 => 10,
        12..=15 => 30,
        _ => 120,
    };
    let strict: u64 = if action == AbuseAction::Appeal { 15 } else { 0 };
    base.max(strict).saturating_mul(1_u64 << penalty.min(8))
}

fn state_key(action: AbuseAction, actor: &str) -> String {
    if actor.starts_with("behavior:") {
        actor.to_owned()
    } else {
        format!("{}:{actor}", action.as_str())
    }
}

fn decay(state: &mut ActorState, now: Instant, window: Duration, cooldown_step: Duration) {
    while state
        .events
        .front()
        .is_some_and(|time| now.saturating_duration_since(*time) > window)
    {
        state.events.pop_front();
    }
    if cooldown_step.is_zero() || state.penalty_level == 0 {
        return;
    }
    let elapsed = now.saturating_duration_since(state.last_activity);
    let steps =
        (elapsed.as_secs() / cooldown_step.as_secs().max(1)).min(u64::from(state.penalty_level));
    if steps > 0 {
        state.penalty_level = state.penalty_level.saturating_sub(steps as u32);
        state.last_activity += cooldown_step.saturating_mul(steps as u32);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guard() -> AbuseGuard {
        AbuseGuard::new(AbuseConfig {
            base_work_factor: 100,
            max_work_factor: 10_000,
            window: Duration::from_secs(60),
            cooldown_step: Duration::from_secs(60),
            max_wait: Duration::from_secs(900),
        })
    }

    fn solve(challenge: &PowChallenge) -> PowProof {
        let target = u64::MAX / challenge.requirement.work_factor.max(1);
        for nonce in 0_u64.. {
            let nonce = nonce.to_string();
            let mut hasher = Sha256::new();
            hasher.update(challenge.prefix.as_bytes());
            hasher.update(nonce.as_bytes());
            let digest = hasher.finalize();
            let value = u64::from_be_bytes(digest[..8].try_into().unwrap());
            if value <= target {
                return PowProof {
                    challenge_id: challenge.challenge_id,
                    nonce,
                };
            }
        }
        unreachable!()
    }

    #[test]
    fn message_work_grows_quadratically_after_free_burst() {
        let guard = guard();
        let actors = vec!["user:1".to_owned()];
        for _ in 0..6 {
            let requirement = guard
                .verify_or_allow(AbuseAction::Message, "user:1", &actors, None)
                .unwrap();
            assert_eq!(requirement.work_factor, 1);
        }
        let requirement = guard.current_requirement(AbuseAction::Message, &actors);
        assert_eq!(requirement.step, 1);
        assert_eq!(requirement.work_factor, 100);
        let challenge = guard.issue(AbuseAction::Message, "user:1", &actors);
        guard
            .verify_or_allow(
                AbuseAction::Message,
                "user:1",
                &actors,
                Some(&solve(&challenge)),
            )
            .unwrap();
        let requirement = guard.current_requirement(AbuseAction::Message, &actors);
        assert_eq!(requirement.step, 2);
        assert_eq!(requirement.work_factor, 400);

        let challenge = guard.issue(AbuseAction::Message, "user:1", &actors);
        guard
            .verify_or_allow(
                AbuseAction::Message,
                "user:1",
                &actors,
                Some(&solve(&challenge)),
            )
            .unwrap();
        let requirement = guard.current_requirement(AbuseAction::Message, &actors);
        assert_eq!(requirement.step, 3);
        assert_eq!(requirement.work_factor, 900);
    }

    #[test]
    fn reports_require_pow_immediately_and_appeals_are_stricter() {
        let guard = guard();
        let actors = vec!["user:1".to_owned()];
        assert_eq!(
            guard
                .current_requirement(AbuseAction::Report, &actors)
                .work_factor,
            200
        );
        let appeal = guard.current_requirement(AbuseAction::Appeal, &actors);
        assert_eq!(appeal.work_factor, 800);
        assert_eq!(appeal.hard_wait_seconds, 15);
    }
}
