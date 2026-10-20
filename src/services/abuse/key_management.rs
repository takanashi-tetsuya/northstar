//! Guard initialization, deployment key rotation, content identity capabilities, and proof signing material.

use super::*;

pub(super) fn opaque_actor_key(action: AbuseAction, actor: &str, secret: &[u8]) -> String {
    northstar_abuse_policy::opaque_actor_key(action, actor, secret)
}

pub(super) fn opaque_challenge_capacity_key(
    action: AbuseAction,
    actor: &str,
    secret: &[u8],
) -> String {
    northstar_abuse_policy::opaque_challenge_capacity_key(action, actor, secret)
}

pub(super) fn derive_actor_key_secret(secret: &[u8]) -> Vec<u8> {
    northstar_abuse_policy::derive_actor_key_secret(secret).to_vec()
}

/// A public commitment produced by the private content-identity keyring. It
/// contains no reusable key material and is safe to pass to a repository.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ContentIdentityAuthenticator {
    pub(super) key_id: String,
    pub(super) mac: [u8; 32],
}

impl ContentIdentityAuthenticator {
    pub(crate) fn key_id(&self) -> &str {
        &self.key_id
    }

    pub(crate) fn mac(&self) -> &[u8; 32] {
        &self.mac
    }
}

/// Current/previous commitments for one exact canonical payload. The first
/// entry follows the existing rolling-overlap writer rule; verification is
/// constant-time once the non-secret key generation ID has been selected.
#[derive(Clone, Debug)]
pub(crate) struct ContentIdentityAuthenticators {
    pub(super) candidates: Vec<ContentIdentityAuthenticator>,
}

impl ContentIdentityAuthenticators {
    pub(crate) fn primary(&self) -> &ContentIdentityAuthenticator {
        self.candidates
            .first()
            .expect("a content identity keyring always has a primary generation")
    }

    pub(crate) fn verifies(&self, key_id: &str, expected: &[u8]) -> bool {
        self.candidates.iter().any(|candidate| {
            candidate.key_id == key_id && bool::from(candidate.mac.as_slice().ct_eq(expected))
        })
    }
}

pub(super) struct ContentIdentityGeneration {
    pub(super) key_id: String,
    pub(super) key: Zeroizing<Vec<u8>>,
}

impl PersonalMessageContentKeyring {
    pub(crate) fn authenticators(&self, canonical_payload: &[u8]) -> ContentIdentityAuthenticators {
        content_identity_authenticators(
            &self.generations,
            ContentIdentityPurpose::PersonalMessage,
            canonical_payload,
        )
    }
}

/// Least-authority capability for XEP-0369 channel message replay identities.
/// It cannot produce personal-message or MIX-retraction commitments even
/// though all generations originate from the same mounted deployment secret.
#[derive(Clone)]
pub(crate) struct MixMessageContentKeyring {
    pub(super) generations: Arc<Vec<ContentIdentityGeneration>>,
}

impl MixMessageContentKeyring {
    pub(crate) fn authenticators(&self, canonical_payload: &[u8]) -> ContentIdentityAuthenticators {
        content_identity_authenticators(
            &self.generations,
            ContentIdentityPurpose::MixMessage,
            canonical_payload,
        )
    }
}

/// Least-authority capability for XEP-0425 MIX retraction replay identities.
/// Keeping it distinct from channel-message identity prevents a compromised
/// service path from forging an authenticator for the other operation family.
#[derive(Clone)]
pub(crate) struct MixRetractionContentKeyring {
    pub(super) generations: Arc<Vec<ContentIdentityGeneration>>,
}

impl MixRetractionContentKeyring {
    pub(crate) fn authenticators(&self, canonical_payload: &[u8]) -> ContentIdentityAuthenticators {
        content_identity_authenticators(
            &self.generations,
            ContentIdentityPurpose::MixRetraction,
            canonical_payload,
        )
    }
}

impl PersonalRetractionContentKeyring {
    pub(crate) fn authenticators(&self, canonical_payload: &[u8]) -> ContentIdentityAuthenticators {
        content_identity_authenticators(
            &self.generations,
            ContentIdentityPurpose::PersonalRetraction,
            canonical_payload,
        )
    }
}

pub(super) fn content_identity_authenticators(
    generations: &[ContentIdentityGeneration],
    purpose: ContentIdentityPurpose,
    canonical_payload: &[u8],
) -> ContentIdentityAuthenticators {
    let candidates = generations
        .iter()
        .map(|generation| {
            let mut mac = Hmac::<Sha256>::new_from_slice(generation.key.as_slice())
                .expect("derived HMAC key is valid");
            mac.update(b"northstar/content-identity/mac/v1\0");
            message_admission_mac_field(&mut mac, purpose.label());
            message_admission_mac_field(&mut mac, canonical_payload);
            ContentIdentityAuthenticator {
                key_id: generation.key_id.clone(),
                mac: mac.finalize().into_bytes().into(),
            }
        })
        .collect();
    ContentIdentityAuthenticators { candidates }
}

pub(super) fn derive_content_identity_key(
    actor_secret: &[u8],
    purpose: ContentIdentityPurpose,
) -> Vec<u8> {
    let purpose = match purpose {
        ContentIdentityPurpose::PersonalMessage => {
            northstar_abuse_policy::ContentIdentityPurpose::PersonalMessage
        }
        ContentIdentityPurpose::PersonalRetraction => {
            northstar_abuse_policy::ContentIdentityPurpose::PersonalRetraction
        }
        ContentIdentityPurpose::MixMessage => {
            northstar_abuse_policy::ContentIdentityPurpose::MixMessage
        }
        ContentIdentityPurpose::MixRetraction => {
            northstar_abuse_policy::ContentIdentityPurpose::MixRetraction
        }
    };
    northstar_abuse_policy::derive_content_identity_key(actor_secret, purpose).to_vec()
}

pub(super) fn actor_key_id(secret: &[u8]) -> String {
    northstar_abuse_policy::actor_key_id(secret)
}

pub(super) fn subject_hash(action: AbuseAction, subject: &str, secret: &[u8]) -> Vec<u8> {
    northstar_abuse_policy::subject_hash(action, subject, secret).to_vec()
}

#[allow(clippy::too_many_arguments)]
pub(super) fn pow_prefix(
    secret: &[u8],
    version: u16,
    id: Uuid,
    action: AbuseAction,
    key_id: &str,
    subject: &str,
    actors: &[String],
    work_factor: u64,
    issued_at: chrono::DateTime<chrono::Utc>,
    expires_at: chrono::DateTime<chrono::Utc>,
    server_nonce: &str,
    intent: Option<&PowIntent>,
) -> String {
    northstar_abuse_policy::compute_pow_prefix_with_commitment(
        secret,
        version,
        id,
        action,
        key_id,
        subject,
        actors,
        work_factor,
        issued_at,
        expires_at,
        server_nonce,
        intent.map(PowIntent::commitment),
    )
}

impl AbuseGuard {
    pub(crate) fn persistent_storage_enabled(&self) -> bool {
        self.persistence.is_some()
    }

    pub fn new(config: AbuseConfig) -> Self {
        Self {
            config,
            persistence: None,
            actor_key_secret: Zeroizing::new(Vec::new()),
            actor_key_id: "memory-only".to_owned(),
            previous_actor_key_secret: None,
            previous_actor_key_id: None,
            write_with_previous_actor_key: false,
            // In-memory guards exist only in unit tests. Production state
            // always overwrites this through the deployment constructor.
            legacy_v1_compatibility_until: Some(chrono::DateTime::<chrono::Utc>::MAX_UTC),
            states: DashMap::new(),
            challenges: DashMap::new(),
            challenge_issues: DashMap::new(),
            challenge_issue_gate: Mutex::new(()),
            last_cleanup: Mutex::new(Instant::now()),
            db_state_gates: (0..ABUSE_STATE_GATE_SHARDS)
                .map(|_| Arc::new(tokio::sync::Mutex::new(())))
                .collect(),
        }
    }

    pub(crate) fn new_persistent_for_deployment(
        config: AbuseConfig,
        persistence: Arc<dyn AbusePersistence>,
        shared_secret: Option<&[u8]>,
        previous_shared_secret: Option<&[u8]>,
        write_with_previous_actor_key: bool,
        legacy_v1_compatibility_until: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Self {
        let mut guard = Self::new(config);
        guard.persistence = Some(persistence);
        if let Some(secret) = shared_secret {
            guard.actor_key_secret = Zeroizing::new(derive_actor_key_secret(secret));
        } else {
            let mut key = vec![0_u8; 32];
            rand::thread_rng().fill_bytes(&mut key);
            guard.actor_key_secret = Zeroizing::new(key);
            tracing::warn!(
                "ABUSE_STATE_HMAC_KEY is unset; durable anti-abuse actor keys cannot be shared across restarts or nodes"
            );
        }
        guard.actor_key_id = actor_key_id(&guard.actor_key_secret);
        guard.previous_actor_key_secret = previous_shared_secret
            .map(derive_actor_key_secret)
            .map(Zeroizing::new);
        guard.previous_actor_key_id = guard
            .previous_actor_key_secret
            .as_ref()
            .map(|secret| actor_key_id(secret.as_slice()));
        guard.write_with_previous_actor_key =
            write_with_previous_actor_key && guard.previous_actor_key_secret.is_some();
        guard.legacy_v1_compatibility_until = legacy_v1_compatibility_until;
        guard
    }

    pub(super) fn legacy_v1_allowed(&self) -> bool {
        self.legacy_v1_compatibility_until
            .is_some_and(|deadline| chrono::Utc::now() <= deadline)
    }

    /// Irreversible, purpose-separated identifiers used only to prove that
    /// every process is operating in the PostgreSQL-authorized key generation.
    /// They are safe to persist and log; the mounted HMAC material is never
    /// returned by this interface.
    pub(crate) fn deployment_key_ids(&self) -> (&str, Option<&str>) {
        (&self.actor_key_id, self.previous_actor_key_id.as_deref())
    }

    /// MIX channel-message admission receives a purpose-separated capability;
    /// it cannot authenticate personal messages or any retraction family.
    pub(crate) fn mix_message_content_keyring(&self) -> MixMessageContentKeyring {
        MixMessageContentKeyring {
            generations: self.content_identity_generations(ContentIdentityPurpose::MixMessage),
        }
    }

    /// MIX retraction admission receives a separate capability from MIX
    /// messages so the two durable replay journals cannot forge each other.
    pub(crate) fn mix_retraction_content_keyring(&self) -> MixRetractionContentKeyring {
        MixRetractionContentKeyring {
            generations: self.content_identity_generations(ContentIdentityPurpose::MixRetraction),
        }
    }

    /// The previous deployment key must remain available until every durable
    /// object which can reference it and the complete exponential penalty
    /// history have expired.  Keeping this calculation beside the constants
    /// prevents the deployment protocol from drifting away from abuse policy.
    pub(crate) fn minimum_key_rotation_overlap(&self) -> Duration {
        self.config
            .window
            .max(self.config.max_wait)
            .max(self.config.max_wait.saturating_add(Duration::from_secs(30)))
            .max(max_penalty_decay_horizon(self.config.cooldown_step))
            .max(MESSAGE_ADMISSION_ACCEPTED_TTL)
            .max(OFFLINE_MESSAGE_ADMISSION_REPLAY_GRACE)
    }

    pub(super) fn primary_actor_key(&self) -> (&str, &[u8]) {
        if self.write_with_previous_actor_key {
            if let (Some(key_id), Some(secret)) = (
                self.previous_actor_key_id.as_deref(),
                self.previous_actor_key_secret.as_deref(),
            ) {
                return (key_id, secret);
            }
        }
        (&self.actor_key_id, &self.actor_key_secret)
    }

    pub(super) fn persistent_actor_key_candidates(&self) -> Vec<(&str, &[u8])> {
        let primary = self.primary_actor_key();
        let mut candidates = vec![primary];
        let current = (self.actor_key_id.as_str(), self.actor_key_secret.as_slice());
        if current.0 != primary.0 {
            candidates.push(current);
        }
        if let (Some(key_id), Some(secret)) = (
            self.previous_actor_key_id.as_deref(),
            self.previous_actor_key_secret.as_deref(),
        ) {
            if key_id != primary.0 {
                candidates.push((key_id, secret));
            }
        }
        candidates
    }

    pub(super) fn actor_secret_for_id(&self, key_id: &str) -> Option<&[u8]> {
        if key_id == "legacy-current" {
            Some(self.primary_actor_key().1)
        } else if self.actor_key_id == key_id {
            Some(&self.actor_key_secret)
        } else if self.previous_actor_key_id.as_deref() == Some(key_id) {
            self.previous_actor_key_secret
                .as_ref()
                .map(|secret| secret.as_slice())
        } else {
            None
        }
    }

    pub(crate) fn persistent_actor_state_keys(
        &self,
        action: AbuseAction,
        actors: &[String],
    ) -> Vec<String> {
        let mut keys = actor_state_keys(action, actors, &self.actor_key_secret);
        if let Some(previous) = self.previous_actor_key_secret.as_deref() {
            keys.extend(actor_state_keys(action, actors, previous));
            keys.sort();
            keys.dedup();
        }
        keys
    }
}
