//! Durable actor-state transitions, persistent proof operations, database coordination, and admission lease implementations.

use super::*;

pub(super) fn actor_state_keys(
    action: AbuseAction,
    actors: &[String],
    secret: &[u8],
) -> Vec<String> {
    let mut keys: Vec<String> = actors
        .iter()
        .map(|actor| opaque_actor_key(action, actor, secret))
        .collect();
    keys.sort();
    keys.dedup();
    keys
}

pub(super) fn trim_db_events(
    events: &mut Vec<chrono::DateTime<chrono::Utc>>,
    now: chrono::DateTime<chrono::Utc>,
    window: Duration,
) {
    let cutoff = now - chrono_duration(window);
    events.retain(|event| *event >= cutoff && *event <= now);
    // Independent of configuration mistakes or clock jumps, keep the row
    // bounded.  Counts above this cap already map to the maximum step.
    if events.len() > 4_096 {
        events.drain(..events.len() - 4_096);
    }
}

pub(super) fn decay_db_states(
    states: &mut [DbActorState],
    now: chrono::DateTime<chrono::Utc>,
    config: &AbuseConfig,
) {
    for state in states {
        trim_db_events(&mut state.events, now, config.window);
        if state.penalty_level == 0 || config.cooldown_step.is_zero() {
            continue;
        }
        let elapsed = now
            .signed_duration_since(state.last_activity)
            .num_seconds()
            .max(0) as u64;
        let (level, consumed) = decayed_penalty(
            state.penalty_level,
            Duration::from_secs(elapsed),
            config.cooldown_step,
        );
        if level != state.penalty_level {
            state.penalty_level = level;
            state.last_activity += chrono_duration(consumed);
        }
    }
}

pub(super) fn requirement_from_db(
    action: AbuseAction,
    states: &[DbActorState],
    shared_ip_keys: &HashSet<String>,
    now: chrono::DateTime<chrono::Utc>,
    config: &AbuseConfig,
) -> WorkRequirement {
    let policy = policy(action, config.base_work_factor, config.message_free_burst);
    let event_count = states
        .iter()
        .map(|state| {
            if shared_ip_keys.contains(&state.key) {
                // Authenticated users behind a carrier-grade NAT must not
                // consume each other's normal burst. The shared source is a
                // high-volume safety signal; account/behaviour remain primary.
                state.events.len() / 20
            } else {
                state.events.len()
            }
        })
        .max()
        .unwrap_or(0);
    let penalty = states
        .iter()
        .filter(|state| !shared_ip_keys.contains(&state.key))
        .map(|state| state.penalty_level)
        .max()
        .unwrap_or(0);
    let retry_after = states
        .iter()
        .filter(|state| !shared_ip_keys.contains(&state.key))
        .map(|state| {
            let millis = state
                .blocked_until
                .signed_duration_since(now)
                .num_milliseconds();
            if millis <= 0 {
                0
            } else {
                u64::try_from((millis + 999) / 1_000).unwrap_or(u64::MAX)
            }
        })
        .max()
        .unwrap_or(0);
    build_requirement(action, policy, event_count, penalty, retry_after, config)
}

pub(super) fn record_db_states(
    states: &mut [DbActorState],
    shared_ip_keys: &HashSet<String>,
    now: chrono::DateTime<chrono::Utc>,
    requirement: &WorkRequirement,
) {
    for state in states {
        state.events.push(now);
        state.sequence = state.sequence.saturating_add(1);
        state.last_activity = now;
        if requirement.hard_wait_seconds > 0 && !shared_ip_keys.contains(&state.key) {
            state.blocked_until =
                now + chrono_duration(Duration::from_secs(requirement.hard_wait_seconds));
        }
    }
}

pub(super) fn punish_db_states(
    states: &mut [DbActorState],
    shared_ip_keys: &HashSet<String>,
    now: chrono::DateTime<chrono::Utc>,
    config: &AbuseConfig,
) {
    for state in states {
        state.events.push(now);
        state.sequence = state.sequence.saturating_add(1);
        state.last_activity = now;
        if shared_ip_keys.contains(&state.key) {
            continue;
        }
        state.penalty_level = state.penalty_level.saturating_add(1).min(10);
        let wait = 2_u64
            .saturating_pow(state.penalty_level.min(9))
            .min(config.max_wait.as_secs());
        state.blocked_until = now + chrono_duration(Duration::from_secs(wait));
    }
}

impl std::fmt::Debug for MessageAdmissionLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MessageAdmissionLease { authority: [redacted] }")
    }
}

impl MessageAdmissionLease {
    pub(crate) fn new(
        admission_key: Vec<u8>,
        payload_mac: Vec<u8>,
        lease_token: Uuid,
        offline_dedupe: MessageDedupeIdentity,
    ) -> Self {
        Self {
            admission_key,
            payload_mac,
            lease_token,
            offline_dedupe,
        }
    }

    pub(crate) fn acceptance(&self) -> MessageAdmissionAcceptance<'_> {
        MessageAdmissionAcceptance {
            admission_key: &self.admission_key,
            payload_mac: &self.payload_mac,
            lease_token: self.lease_token,
        }
    }
}

impl MessageAdmissionAcceptance<'_> {
    pub(crate) fn admission_key(&self) -> &[u8] {
        self.admission_key
    }

    pub(crate) fn payload_mac(&self) -> &[u8] {
        self.payload_mac
    }

    pub(crate) fn lease_token(&self) -> Uuid {
        self.lease_token
    }
}

impl AbuseGuard {
    pub(super) async fn acquire_db_state_gates(
        &self,
        action: AbuseAction,
        actors: &[String],
    ) -> Vec<tokio::sync::OwnedMutexGuard<()>> {
        let mut shards = self
            .persistent_actor_state_keys(action, actors)
            .into_iter()
            .map(|key| {
                let digest = Sha256::digest(key.as_bytes());
                let prefix = u64::from_be_bytes(
                    digest[..8]
                        .try_into()
                        .expect("SHA-256 has an eight-byte prefix"),
                );
                usize::try_from(prefix % ABUSE_STATE_GATE_SHARDS as u64)
                    .expect("gate shard index fits usize")
            })
            .collect::<Vec<_>>();
        shards.sort_unstable();
        shards.dedup();
        let mut guards = Vec::with_capacity(shards.len());
        for shard in shards {
            guards.push(Arc::clone(&self.db_state_gates[shard]).lock_owned().await);
        }
        guards
    }

    pub(super) fn persistent_shared_ip_keys(
        &self,
        action: AbuseAction,
        actors: &[String],
    ) -> HashSet<String> {
        if action == AbuseAction::Registration || actors.len() <= 1 {
            return HashSet::new();
        }
        let mut keys = HashSet::new();
        for actor in actors.iter().filter(|actor| actor.starts_with("ip:")) {
            keys.insert(opaque_actor_key(action, actor, &self.actor_key_secret));
            if let Some(previous) = self.previous_actor_key_secret.as_deref() {
                keys.insert(opaque_actor_key(action, actor, previous));
            }
        }
        keys
    }

    /// Seed a newly rotated HMAC row from its previous opaque row. Mutations
    /// during the overlap then advance both rows, so removing PREVIOUS after
    /// the decay horizon does not reset the surviving penalty history.
    pub(super) fn merge_previous_actor_states(
        &self,
        action: AbuseAction,
        actors: &[String],
        states: &mut [DbActorState],
    ) {
        let Some(previous) = self.previous_actor_key_secret.as_deref() else {
            return;
        };
        for actor in actors {
            let old_key = opaque_actor_key(action, actor, previous);
            let new_key = opaque_actor_key(action, actor, &self.actor_key_secret);
            if old_key == new_key {
                continue;
            }
            let Some(old) = states.iter().find(|state| state.key == old_key) else {
                continue;
            };
            let old_snapshot = (
                old.events.clone(),
                old.penalty_level,
                old.last_activity,
                old.blocked_until,
                old.sequence,
            );
            let Some(new) = states.iter_mut().find(|state| state.key == new_key) else {
                continue;
            };
            if new.sequence >= old_snapshot.4 {
                continue;
            }
            new.events = old_snapshot.0;
            new.penalty_level = old_snapshot.1;
            new.last_activity = old_snapshot.2;
            new.blocked_until = old_snapshot.3;
            new.sequence = old_snapshot.4;
        }
    }

    pub(crate) fn current_requirement_decision(
        &self,
        action: AbuseAction,
        actors: &[String],
        states: &mut [DbActorState],
        now: chrono::DateTime<chrono::Utc>,
    ) -> WorkRequirement {
        let shared_ip_keys = self.persistent_shared_ip_keys(action, actors);
        decay_db_states(states, now, &self.config);
        self.merge_previous_actor_states(action, actors, states);
        requirement_from_db(action, states, &shared_ip_keys, now, &self.config)
    }

    pub(crate) fn record_failure_decision(
        &self,
        action: AbuseAction,
        actors: &[String],
        states: &mut [DbActorState],
        now: chrono::DateTime<chrono::Utc>,
    ) {
        let shared_ip_keys = self.persistent_shared_ip_keys(action, actors);
        let requirement = self.current_requirement_decision(action, actors, states, now);
        record_db_states(states, &shared_ip_keys, now, &requirement);
    }

    pub(super) async fn issue_persistent_bound(
        &self,
        action: AbuseAction,
        subject: &str,
        actors: &[String],
        intent: Option<&PowIntent>,
    ) -> anyhow::Result<PowChallenge> {
        use crate::db::abuse_challenge_issuance_repository::{IssueRecord, IssueRequest};

        let persistence = self.persistence.as_ref().expect("persistent abuse storage");
        let _db_state_gates = self.acquire_db_state_gates(action, actors).await;
        let request = IssueRequest {
            issue_groups: self.challenge_issue_groups(action, actors),
            capacity_groups: self.challenge_capacity_groups(action, actors),
            actor_state_keys: self.persistent_actor_state_keys(action, actors),
            window: self.config.window,
        };
        let shared_ip_keys = self.persistent_shared_ip_keys(action, actors);
        let (primary_key_id, primary_secret) = self.primary_actor_key();
        let subject_hash = subject_hash(action, subject, primary_secret);
        let primary_actor_state_keys = actor_state_keys(action, actors, primary_secret);
        persistence
            .issue(
                request,
                Box::new(|states, now| {
                    decay_db_states(states, now, &self.config);
                    self.merge_previous_actor_states(action, actors, states);
                    let requirement =
                        requirement_from_db(action, states, &shared_ip_keys, now, &self.config);
                    let mut random = [0_u8; 18];
                    rand::thread_rng().fill_bytes(&mut random);
                    let id = Uuid::new_v4();
                    let server_nonce = URL_SAFE_NO_PAD.encode(random);
                    let ttl = Duration::from_secs(120)
                        .max(Duration::from_secs(requirement.hard_wait_seconds + 30));
                    let expires_at = now + chrono_duration(ttl);
                    let version = if intent.is_some() {
                        POW_INTENT_VERSION
                    } else {
                        1
                    };
                    let prefix = pow_prefix(
                        primary_secret,
                        version,
                        id,
                        action,
                        primary_key_id,
                        subject,
                        actors,
                        requirement.work_factor,
                        now,
                        expires_at,
                        &server_nonce,
                        intent,
                    );
                    // During key rotation, sign only the primary generation's sequence
                    // snapshot; a dual-key verifier may load additional mirrored rows.
                    let actor_sequences = serde_json::Value::Object(
                        states
                            .iter()
                            .filter(|state| {
                                primary_actor_state_keys.contains(&state.key)
                                    && !shared_ip_keys.contains(&state.key)
                            })
                            .map(|state| {
                                (state.key.clone(), serde_json::Value::from(state.sequence))
                            })
                            .collect(),
                    );
                    Ok(IssueRecord {
                        action,
                        challenge: PowChallenge {
                            version,
                            challenge_id: id,
                            prefix,
                            key_id: primary_key_id.to_owned(),
                            issued_at: now,
                            expires_at,
                            expires_in_seconds: ttl.as_secs(),
                            server_nonce,
                            intent: intent.map(PowIntent::view),
                            requirement,
                        },
                        subject_hash: subject_hash.clone(),
                        actor_sequences,
                        intent_method: intent.map(|intent| intent.method.clone()),
                        intent_path: intent.map(|intent| intent.path.clone()),
                        body_sha256: intent.map(|intent| intent.body_sha256.to_vec()),
                    })
                }),
            )
            .await
    }

    pub(super) async fn current_requirement_persistent(
        &self,
        action: AbuseAction,
        actors: &[String],
    ) -> anyhow::Result<WorkRequirement> {
        let persistence = self.persistence.as_ref().expect("persistent abuse storage");
        let _db_state_gates = self.acquire_db_state_gates(action, actors).await;
        let keys = self.persistent_actor_state_keys(action, actors);
        let shared_ip_keys = self.persistent_shared_ip_keys(action, actors);
        persistence
            .current_requirement(
                &keys,
                Box::new(|states, now| {
                    decay_db_states(states, now, &self.config);
                    self.merge_previous_actor_states(action, actors, states);
                    requirement_from_db(action, states, &shared_ip_keys, now, &self.config)
                }),
            )
            .await
    }

    pub(super) async fn record_failure_persistent(
        &self,
        action: AbuseAction,
        actors: &[String],
    ) -> anyhow::Result<()> {
        let persistence = self.persistence.as_ref().expect("persistent abuse storage");
        let _db_state_gates = self.acquire_db_state_gates(action, actors).await;
        let keys = self.persistent_actor_state_keys(action, actors);
        persistence
            .record_failure(
                &keys,
                Box::new(|states, now| {
                    self.record_failure_decision(action, actors, states, now);
                }),
            )
            .await
    }

    pub(super) async fn verify_persistent_bound(
        &self,
        action: AbuseAction,
        subject: &str,
        actors: &[String],
        proof: Option<&PowProof>,
        intent: Option<&PowIntent>,
    ) -> anyhow::Result<std::result::Result<WorkRequirement, GuardError>> {
        self.verify_persistent_bound_observed(action, subject, actors, proof, intent, None)
            .await
    }

    pub(super) async fn verify_persistent_bound_observed(
        &self,
        action: AbuseAction,
        subject: &str,
        actors: &[String],
        proof: Option<&PowProof>,
        intent: Option<&PowIntent>,
        witness: Option<&AdmissionWitness>,
    ) -> anyhow::Result<std::result::Result<WorkRequirement, GuardError>> {
        let persistence = self.persistence.as_ref().expect("persistent abuse storage");
        let _db_state_gates = self.acquire_db_state_gates(action, actors).await;
        let keys = self.persistent_actor_state_keys(action, actors);
        persistence
            .verify(
                &keys,
                proof.map(|proof| proof.challenge_id),
                Box::new(|states, now, challenge| {
                    self.decide_persistent_verification(
                        PersistentVerificationInput {
                            action,
                            subject,
                            actors,
                            proof,
                            intent,
                        },
                        states,
                        now,
                        challenge,
                    )
                }),
                witness,
            )
            .await
    }

    pub(crate) fn decide_persistent_verification(
        &self,
        input: PersistentVerificationInput<'_>,
        states: &mut [DbActorState],
        now: chrono::DateTime<chrono::Utc>,
        challenge: Option<crate::db::abuse_verification_repository::ConsumedChallenge>,
    ) -> anyhow::Result<crate::db::abuse_verification_repository::VerificationDecision> {
        use crate::db::abuse_verification_repository::VerificationDecision;
        let PersistentVerificationInput {
            action,
            subject,
            actors,
            proof,
            intent,
        } = input;

        let shared_ip_keys = self.persistent_shared_ip_keys(action, actors);
        decay_db_states(states, now, &self.config);
        self.merge_previous_actor_states(action, actors, states);
        let current = requirement_from_db(action, states, &shared_ip_keys, now, &self.config);

        let Some(proof) = proof else {
            if current.work_factor <= 1 && current.retry_after_seconds == 0 {
                record_db_states(states, &shared_ip_keys, now, &current);
                return Ok(VerificationDecision {
                    outcome: Ok(current),
                    persist_states: true,
                });
            }
            punish_db_states(states, &shared_ip_keys, now, &self.config);
            return Ok(VerificationDecision {
                outcome: Err(GuardError::Required(current)),
                persist_states: true,
            });
        };
        let Some(challenge) = challenge else {
            punish_db_states(states, &shared_ip_keys, now, &self.config);
            return Ok(VerificationDecision {
                outcome: Err(GuardError::Invalid(
                    "proof-of-work challenge is missing or already used",
                    current,
                )),
                persist_states: true,
            });
        };
        let challenge_requirement: WorkRequirement =
            serde_json::from_value(challenge.requirement.clone())?;
        let protocol_version = u16::try_from(challenge.protocol_version).unwrap_or(u16::MAX);
        let intent_matches = if protocol_version == 1 {
            self.legacy_v1_allowed()
        } else if protocol_version == POW_INTENT_VERSION {
            intent.is_some_and(|expected| {
                challenge.intent_method.as_deref() == Some(expected.method.as_str())
                    && challenge.intent_path.as_deref() == Some(expected.path.as_str())
                    && challenge.body_sha256.as_deref() == Some(expected.body_sha256.as_slice())
            })
        } else {
            false
        };
        let valid_identity = self
            .actor_secret_for_id(&challenge.key_id)
            .is_some_and(|secret| {
                if challenge.action != action.as_str()
                    || challenge.subject_hash != subject_hash(action, subject, secret)
                {
                    return false;
                }
                if protocol_version != POW_INTENT_VERSION {
                    return protocol_version == 1;
                }
                let Some(expected) = intent else {
                    return false;
                };
                let Some(issued_at) = challenge.issued_at else {
                    return false;
                };
                let Some(server_nonce) = challenge.server_nonce.as_deref() else {
                    return false;
                };
                let work_factor = u64::try_from(challenge.work_factor).unwrap_or(u64::MAX);
                let expected_prefix = pow_prefix(
                    secret,
                    protocol_version,
                    proof.challenge_id,
                    action,
                    &challenge.key_id,
                    subject,
                    actors,
                    work_factor,
                    issued_at,
                    challenge.expires_at,
                    server_nonce,
                    Some(expected),
                );
                bool::from(
                    challenge
                        .prefix
                        .as_bytes()
                        .ct_eq(expected_prefix.as_bytes()),
                )
            });
        if !valid_identity || !intent_matches {
            tracing::debug!(
                action = action.as_str(),
                valid_identity,
                intent_matches,
                "rejected a PoW v2 challenge whose operation binding changed"
            );
            punish_db_states(states, &shared_ip_keys, now, &self.config);
            return Ok(VerificationDecision {
                outcome: Err(GuardError::Invalid(
                    "proof-of-work challenge does not match this operation",
                    current,
                )),
                persist_states: true,
            });
        }
        if now > challenge.expires_at {
            return Ok(VerificationDecision {
                outcome: Err(GuardError::Invalid(
                    "proof-of-work challenge expired",
                    current,
                )),
                persist_states: false,
            });
        }
        if now < challenge.not_before {
            return Ok(VerificationDecision {
                outcome: Err(GuardError::Invalid(
                    "hard cooldown has not finished",
                    challenge_requirement,
                )),
                persist_states: false,
            });
        }
        let expected: serde_json::Map<String, serde_json::Value> = challenge
            .actor_sequences
            .as_object()
            .cloned()
            .unwrap_or_default();
        // An old-key challenge signs only its own key set. Newly mirrored
        // state rows do not by themselves indicate replay.
        let sequences_match = expected.iter().all(|(key, sequence)| {
            states
                .iter()
                .find(|state| state.key == *key)
                .is_some_and(|state| {
                    sequence.as_i64() == Some(state.sequence)
                        && !shared_ip_keys.contains(&state.key)
                })
        });
        if !sequences_match
            && !prefetched_message_challenge_remains_sufficient(
                action,
                &challenge_requirement,
                &current,
            )
        {
            return Ok(VerificationDecision {
                outcome: Err(GuardError::Invalid(
                    "another operation already advanced this rate-limit step",
                    current,
                )),
                persist_states: false,
            });
        }
        if proof.nonce.is_empty()
            || proof.nonce.len() > 64
            || !proof.nonce.bytes().all(|byte| byte.is_ascii_digit())
        {
            punish_db_states(states, &shared_ip_keys, now, &self.config);
            return Ok(VerificationDecision {
                outcome: Err(GuardError::Invalid(
                    "proof-of-work nonce is invalid",
                    current,
                )),
                persist_states: true,
            });
        }
        let mut hasher = Sha256::new();
        hasher.update(challenge.prefix.as_bytes());
        hasher.update(proof.nonce.as_bytes());
        let digest = hasher.finalize();
        let value = u64::from_be_bytes(digest[..8].try_into().expect("SHA-256 prefix"));
        let work_factor = u64::try_from(challenge.work_factor).unwrap_or(u64::MAX);
        if value > u64::MAX / work_factor.max(1) {
            punish_db_states(states, &shared_ip_keys, now, &self.config);
            return Ok(VerificationDecision {
                outcome: Err(GuardError::Invalid(
                    "proof of work is insufficient",
                    current,
                )),
                persist_states: true,
            });
        }
        record_db_states(states, &shared_ip_keys, now, &challenge_requirement);
        Ok(VerificationDecision {
            outcome: Ok(challenge_requirement),
            persist_states: true,
        })
    }

    pub(crate) async fn cleanup_challenges(&self) -> anyhow::Result<()> {
        if let Some(persistence) = self.persistence.as_ref() {
            let stale_seconds = self
                .config
                .window
                .max(self.config.max_wait)
                .max(max_penalty_decay_horizon(self.config.cooldown_step))
                .as_secs();
            return persistence
                .cleanup(self.config.window.as_secs(), stale_seconds)
                .await;
        }
        self.cleanup_challenges_memory();
        Ok(())
    }
}
