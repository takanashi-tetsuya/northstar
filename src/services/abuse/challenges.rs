//! Challenge dispatch, capacity enforcement, in-memory proof processing, rate requirements, penalties, and memory cleanup.

use super::*;

impl AbuseGuard {
    pub(super) fn challenge_capacity_groups(
        &self,
        action: AbuseAction,
        actors: &[String],
    ) -> Vec<(Vec<String>, usize)> {
        let mut groups = actors
            .iter()
            .map(|actor| {
                let mut keys = vec![opaque_challenge_capacity_key(
                    action,
                    actor,
                    &self.actor_key_secret,
                )];
                if let Some(previous) = self.previous_actor_key_secret.as_deref() {
                    keys.push(opaque_challenge_capacity_key(action, actor, previous));
                }
                keys.sort();
                keys.dedup();
                let limit = if actor.starts_with("ip:") {
                    MAX_ACTIVE_POW_CHALLENGES_PER_IP
                } else {
                    MAX_ACTIVE_POW_CHALLENGES_PER_ACTOR
                };
                (keys, limit)
            })
            .collect::<Vec<_>>();
        groups.sort_by(|left, right| left.0.cmp(&right.0));
        groups.dedup_by(|left, right| left.0 == right.0);
        groups
    }

    pub(super) fn challenge_issue_groups(
        &self,
        action: AbuseAction,
        actors: &[String],
    ) -> Vec<(Vec<String>, usize)> {
        let mut groups = actors
            .iter()
            .map(|actor| {
                let mut keys = vec![format!(
                    "challenge:{}",
                    opaque_challenge_capacity_key(action, actor, &self.actor_key_secret)
                )];
                if !actor.starts_with("ip:") {
                    keys.push(format!(
                        "challenge:{}",
                        opaque_actor_key(action, actor, &self.actor_key_secret)
                    ));
                }
                if let Some(previous) = self.previous_actor_key_secret.as_deref() {
                    keys.push(format!(
                        "challenge:{}",
                        opaque_challenge_capacity_key(action, actor, previous)
                    ));
                    if !actor.starts_with("ip:") {
                        keys.push(format!(
                            "challenge:{}",
                            opaque_actor_key(action, actor, previous)
                        ));
                    }
                }
                keys.sort();
                keys.dedup();
                let limit = if actor.starts_with("ip:") {
                    MAX_CHALLENGE_ISSUES_PER_IP_WINDOW
                } else {
                    self.challenge_issue_limit(action)
                };
                (keys, limit)
            })
            .collect::<Vec<_>>();
        groups.sort_by(|left, right| left.0.cmp(&right.0));
        groups.dedup_by(|left, right| left.0 == right.0);
        groups
    }

    pub(super) fn is_shared_ip_actor(action: AbuseAction, actors_len: usize, actor: &str) -> bool {
        action != AbuseAction::Registration && actors_len > 1 && actor.starts_with("ip:")
    }

    pub async fn issue(
        &self,
        action: AbuseAction,
        subject: &str,
        actors: &[String],
    ) -> anyhow::Result<PowChallenge> {
        if !self.legacy_v1_allowed() {
            return Err(LegacyPowV1Disabled.into());
        }
        self.issue_bound(action, subject, actors, None).await
    }

    pub async fn issue_v2(
        &self,
        action: AbuseAction,
        subject: &str,
        actors: &[String],
        intent: &PowIntent,
    ) -> anyhow::Result<PowChallenge> {
        anyhow::ensure!(
            action_accepts_intent(action, intent.method(), intent.path()),
            "PoW intent action mismatch"
        );
        self.issue_bound(action, subject, actors, Some(intent))
            .await
    }

    pub(super) async fn issue_bound(
        &self,
        action: AbuseAction,
        subject: &str,
        actors: &[String],
        intent: Option<&PowIntent>,
    ) -> anyhow::Result<PowChallenge> {
        if self.persistence.is_some() {
            self.issue_persistent_bound(action, subject, actors, intent)
                .await
        } else {
            self.issue_memory_bound(action, subject, actors, intent)
        }
    }

    pub(super) fn issue_memory_bound(
        &self,
        action: AbuseAction,
        subject: &str,
        actors: &[String],
        intent: Option<&PowIntent>,
    ) -> anyhow::Result<PowChallenge> {
        let _issue_gate = self
            .challenge_issue_gate
            .lock()
            .expect("challenge issue mutex poisoned");
        self.maybe_cleanup();
        let now = Instant::now();
        let issue_groups = self.challenge_issue_groups(action, actors);
        let mut normalized_issues = Vec::with_capacity(issue_groups.len());
        for (keys, limit) in issue_groups {
            let mut events = keys
                .iter()
                .filter_map(|key| self.challenge_issues.get(key))
                .flat_map(|events| events.iter().copied().collect::<Vec<_>>())
                .collect::<Vec<_>>();
            events.sort();
            events.dedup();
            events.retain(|time| now.saturating_duration_since(*time) <= self.config.window);
            if events.len() >= limit {
                let retry_after_seconds = events
                    .first()
                    .map(|oldest| {
                        ceil_seconds(
                            self.config
                                .window
                                .saturating_sub(now.saturating_duration_since(*oldest)),
                        )
                    })
                    .unwrap_or(1);
                return Err(ChallengeCapacityExceeded {
                    retry_after_seconds,
                }
                .into());
            }
            normalized_issues.push((keys, events));
        }

        let active = self
            .challenges
            .iter()
            .filter(|challenge| challenge.expires_at > now)
            .collect::<Vec<_>>();
        if active.len() >= MAX_ACTIVE_POW_CHALLENGES_GLOBAL {
            let retry_after_seconds = active
                .iter()
                .map(|challenge| ceil_seconds(challenge.expires_at.saturating_duration_since(now)))
                .min()
                .unwrap_or(1);
            return Err(ChallengeCapacityExceeded {
                retry_after_seconds,
            }
            .into());
        }
        let capacity_groups = self.challenge_capacity_groups(action, actors);
        for (keys, limit) in &capacity_groups {
            let matching = active
                .iter()
                .filter(|challenge| {
                    challenge
                        .capacity_actors
                        .iter()
                        .any(|stored| keys.binary_search(stored).is_ok())
                })
                .collect::<Vec<_>>();
            if matching.len() >= *limit {
                let retry_after_seconds = matching
                    .iter()
                    .map(|challenge| {
                        ceil_seconds(challenge.expires_at.saturating_duration_since(now))
                    })
                    .min()
                    .unwrap_or(1);
                return Err(ChallengeCapacityExceeded {
                    retry_after_seconds,
                }
                .into());
            }
        }
        drop(active);

        for (keys, mut events) in normalized_issues {
            events.push(now);
            for key in keys {
                self.challenge_issues
                    .insert(key, events.iter().copied().collect());
            }
        }

        let requirement = self.requirement(action, actors, now);
        let issued_at = chrono::Utc::now();
        let mut random = [0_u8; 18];
        rand::thread_rng().fill_bytes(&mut random);
        let id = Uuid::new_v4();
        let server_nonce = URL_SAFE_NO_PAD.encode(random);
        let version = if intent.is_some() {
            POW_INTENT_VERSION
        } else {
            1
        };
        let ttl =
            Duration::from_secs(120).max(Duration::from_secs(requirement.hard_wait_seconds + 30));
        let expires_at =
            issued_at + chrono::Duration::seconds(i64::try_from(ttl.as_secs()).unwrap_or(i64::MAX));
        let prefix = pow_prefix(
            &self.actor_key_secret,
            version,
            id,
            action,
            &self.actor_key_id,
            subject,
            actors,
            requirement.work_factor,
            issued_at,
            expires_at,
            &server_nonce,
            intent,
        );
        let actor_sequences = actors
            .iter()
            .filter(|actor| !Self::is_shared_ip_actor(action, actors.len(), actor))
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
        let mut capacity_actors = capacity_groups
            .into_iter()
            .flat_map(|(keys, _)| keys)
            .collect::<Vec<_>>();
        capacity_actors.sort();
        capacity_actors.dedup();
        self.challenges.insert(
            id,
            StoredChallenge {
                protocol_version: version,
                action,
                subject: subject.to_owned(),
                intent: intent.cloned(),
                key_id: self.actor_key_id.clone(),
                prefix: prefix.clone(),
                work_factor: requirement.work_factor,
                issued_at,
                expires_at_wall: expires_at,
                server_nonce: server_nonce.clone(),
                not_before: now + Duration::from_secs(requirement.hard_wait_seconds),
                expires_at: now + ttl,
                actor_sequences,
                capacity_actors,
                requirement: requirement.clone(),
            },
        );
        Ok(PowChallenge {
            version,
            challenge_id: id,
            prefix,
            key_id: self.actor_key_id.clone(),
            issued_at,
            expires_at,
            expires_in_seconds: ttl.as_secs(),
            server_nonce,
            intent: intent.map(PowIntent::view),
            requirement,
        })
    }

    pub(super) fn challenge_issue_limit(&self, action: AbuseAction) -> usize {
        match action {
            // The bundled capable client intentionally prefetches a one-use
            // challenge for each outgoing stanza. Do not punish that normal
            // pattern before the ordinary message window itself can decide.
            AbuseAction::Message => self.config.message_free_burst.saturating_mul(5).max(300),
            _ => 30,
        }
    }

    pub async fn verify_or_allow_v2(
        &self,
        action: AbuseAction,
        subject: &str,
        actors: &[String],
        proof: Option<&PowProof>,
        intent: &PowIntent,
    ) -> anyhow::Result<std::result::Result<WorkRequirement, GuardError>> {
        self.verify_or_allow_bound(action, subject, actors, proof, Some(intent))
            .await
    }

    pub(super) async fn verify_or_allow_bound(
        &self,
        action: AbuseAction,
        subject: &str,
        actors: &[String],
        proof: Option<&PowProof>,
        intent: Option<&PowIntent>,
    ) -> anyhow::Result<std::result::Result<WorkRequirement, GuardError>> {
        if self.persistence.is_some() {
            self.verify_persistent_bound(action, subject, actors, proof, intent)
                .await
        } else {
            Ok(self.verify_memory_bound(action, subject, actors, proof, intent))
        }
    }

    pub(super) fn verify_memory_bound(
        &self,
        action: AbuseAction,
        subject: &str,
        actors: &[String],
        proof: Option<&PowProof>,
        intent: Option<&PowIntent>,
    ) -> Result<WorkRequirement, GuardError> {
        self.maybe_cleanup();
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
        let intent_matches = match challenge.intent.as_ref() {
            Some(challenge_intent) => intent == Some(challenge_intent),
            None => self.legacy_v1_allowed(),
        };
        let binding_matches = if challenge.protocol_version == POW_INTENT_VERSION {
            self.actor_secret_for_id(&challenge.key_id)
                .zip(intent)
                .is_some_and(|(secret, expected)| {
                    let expected_prefix = pow_prefix(
                        secret,
                        challenge.protocol_version,
                        proof.challenge_id,
                        action,
                        &challenge.key_id,
                        subject,
                        actors,
                        challenge.work_factor,
                        challenge.issued_at,
                        challenge.expires_at_wall,
                        &challenge.server_nonce,
                        Some(expected),
                    );
                    bool::from(
                        challenge
                            .prefix
                            .as_bytes()
                            .ct_eq(expected_prefix.as_bytes()),
                    )
                })
        } else {
            challenge.protocol_version == 1
        };
        if challenge.action != action
            || challenge.subject != subject
            || !intent_matches
            || !binding_matches
        {
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
            if actual != *expected
                && !prefetched_message_challenge_remains_sufficient(
                    action,
                    &challenge.requirement,
                    &current,
                )
            {
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

    pub async fn current_requirement(
        &self,
        action: AbuseAction,
        actors: &[String],
    ) -> anyhow::Result<WorkRequirement> {
        if self.persistence.is_some() {
            self.current_requirement_persistent(action, actors).await
        } else {
            Ok(self.requirement(action, actors, Instant::now()))
        }
    }

    pub async fn record_failure(
        &self,
        action: AbuseAction,
        actors: &[String],
    ) -> anyhow::Result<()> {
        if self.persistence.is_some() {
            self.record_failure_persistent(action, actors).await
        } else {
            self.record_failure_memory(action, actors);
            Ok(())
        }
    }

    pub(super) fn record_failure_memory(&self, action: AbuseAction, actors: &[String]) {
        self.maybe_cleanup();
        let now = Instant::now();
        let requirement = self.requirement(action, actors, now);
        self.record(action, actors, now, &requirement);
    }

    pub(super) fn requirement(
        &self,
        action: AbuseAction,
        actors: &[String],
        now: Instant,
    ) -> WorkRequirement {
        let policy = policy(
            action,
            self.config.base_work_factor,
            self.config.message_free_burst,
        );
        let mut event_count = 0_usize;
        let mut penalty = 0_u32;
        let mut retry_after = 0_u64;
        for actor in actors {
            let is_shared_ip = Self::is_shared_ip_actor(action, actors.len(), actor);
            let key = state_key(action, actor);
            if let Some(mut state) = self.states.get_mut(&key) {
                decay(
                    &mut state,
                    now,
                    self.config.window,
                    self.config.cooldown_step,
                );
                event_count = event_count.max(if is_shared_ip {
                    state.events.len() / 20
                } else {
                    state.events.len()
                });
                if !is_shared_ip {
                    penalty = penalty.max(state.penalty_level);
                    retry_after = retry_after
                        .max(state.blocked_until.saturating_duration_since(now).as_secs());
                }
            }
        }
        build_requirement(
            action,
            policy,
            event_count,
            penalty,
            retry_after,
            &self.config,
        )
    }

    pub(super) fn record(
        &self,
        action: AbuseAction,
        actors: &[String],
        now: Instant,
        requirement: &WorkRequirement,
    ) {
        for actor in actors {
            let is_shared_ip = Self::is_shared_ip_actor(action, actors.len(), actor);
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
            if requirement.hard_wait_seconds > 0 && !is_shared_ip {
                state.blocked_until = now + Duration::from_secs(requirement.hard_wait_seconds);
            }
        }
    }

    pub(super) fn punish(&self, action: AbuseAction, actors: &[String], now: Instant) {
        for actor in actors {
            let is_shared_ip = Self::is_shared_ip_actor(action, actors.len(), actor);
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
            if is_shared_ip {
                continue;
            }
            state.penalty_level = state.penalty_level.saturating_add(1).min(10);
            let wait = 2_u64
                .saturating_pow(state.penalty_level.min(9))
                .min(self.config.max_wait.as_secs());
            state.blocked_until = now + Duration::from_secs(wait);
        }
    }

    pub(super) fn cleanup_challenges_memory(&self) {
        let now = Instant::now();
        self.challenges
            .retain(|_, challenge| challenge.expires_at > now);
        self.challenge_issues.retain(|_, issues| {
            while issues
                .front()
                .is_some_and(|time| now.saturating_duration_since(*time) > self.config.window)
            {
                issues.pop_front();
            }
            !issues.is_empty()
        });

        // A penalty is capped at ten levels. Each higher level takes twice as
        // long as the preceding level to cool, so cleanup must retain state
        // through the complete geometric decay horizon. Once the window,
        // maximum wait and that horizon have elapsed, retaining the actor key
        // cannot affect a future decision and only lets an attacker grow the
        // map forever.
        let stale_after = self
            .config
            .window
            .max(self.config.max_wait)
            .max(max_penalty_decay_horizon(self.config.cooldown_step));
        self.states.retain(|_, state| {
            state.blocked_until > now
                || now.saturating_duration_since(state.last_activity) <= stale_after
        });
    }

    pub(super) fn maybe_cleanup(&self) {
        let now = Instant::now();
        let Ok(mut last_cleanup) = self.last_cleanup.try_lock() else {
            return;
        };
        if now.saturating_duration_since(*last_cleanup) < Duration::from_secs(10) {
            return;
        }
        *last_cleanup = now;
        drop(last_cleanup);
        self.cleanup_challenges_memory();
    }
}

pub(super) fn build_requirement(
    action: AbuseAction,
    policy: Policy,
    event_count: usize,
    penalty: u32,
    retry_after: u64,
    config: &AbuseConfig,
) -> WorkRequirement {
    northstar_abuse_policy::build_requirement(
        action,
        policy,
        event_count,
        penalty,
        retry_after,
        config,
    )
}

pub(super) fn decay(
    state: &mut ActorState,
    now: Instant,
    window: Duration,
    cooldown_step: Duration,
) {
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
    let (level, consumed) = decayed_penalty(state.penalty_level, elapsed, cooldown_step);
    if level != state.penalty_level {
        state.penalty_level = level;
        state.last_activity += consumed;
    }
}

pub(super) fn decayed_penalty(
    level: u32,
    elapsed: Duration,
    cooldown_step: Duration,
) -> (u32, Duration) {
    northstar_abuse_policy::decayed_penalty(level, elapsed, cooldown_step)
}

pub(super) fn max_penalty_decay_horizon(cooldown_step: Duration) -> Duration {
    northstar_abuse_policy::max_penalty_decay_horizon(cooldown_step)
}
