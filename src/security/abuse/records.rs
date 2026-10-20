//! Records the abuse guard exchanges with its repositories: actor state rows, challenge issuance and verification, and the key deployment identity.

use super::{AbuseAction, GuardError, PowChallenge, WorkRequirement};
use chrono::{DateTime, Utc};
use std::time::Duration;

#[derive(Debug)]
pub(crate) struct DbActorState {
    pub(crate) key: String,
    pub(crate) events: Vec<DateTime<Utc>>,
    pub(crate) penalty_level: u32,
    pub(crate) last_activity: DateTime<Utc>,
    pub(crate) blocked_until: DateTime<Utc>,
    pub(crate) sequence: i64,
}

pub(crate) struct IssueRequest {
    pub(crate) issue_groups: Vec<(Vec<String>, usize)>,
    pub(crate) capacity_groups: Vec<(Vec<String>, usize)>,
    pub(crate) actor_state_keys: Vec<String>,
    pub(crate) window: Duration,
}

/// The application signs this record after the repository has locked the
/// actor state. All cryptographic and rotation decisions stay with the guard.
pub(crate) struct IssueRecord {
    pub(crate) action: AbuseAction,
    pub(crate) challenge: PowChallenge,
    pub(crate) subject_hash: Vec<u8>,
    pub(crate) actor_sequences: serde_json::Value,
    pub(crate) intent_method: Option<String>,
    pub(crate) intent_path: Option<String>,
    pub(crate) body_sha256: Option<Vec<u8>>,
}

pub(crate) struct ConsumedChallenge {
    pub(crate) action: String,
    pub(crate) subject_hash: Vec<u8>,
    pub(crate) key_id: String,
    pub(crate) prefix: String,
    pub(crate) work_factor: i64,
    pub(crate) not_before: DateTime<Utc>,
    pub(crate) expires_at: DateTime<Utc>,
    pub(crate) actor_sequences: serde_json::Value,
    pub(crate) requirement: serde_json::Value,
    pub(crate) protocol_version: i16,
    pub(crate) intent_method: Option<String>,
    pub(crate) intent_path: Option<String>,
    pub(crate) body_sha256: Option<Vec<u8>>,
    pub(crate) server_nonce: Option<String>,
    pub(crate) issued_at: Option<DateTime<Utc>>,
}

pub(crate) struct VerificationDecision {
    pub(crate) outcome: std::result::Result<WorkRequirement, GuardError>,
    pub(crate) persist_states: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AbuseKeyDeploymentIdentity {
    pub xmpp_domain: String,
    pub epoch: i64,
    pub current_key_id: String,
    pub previous_key_id: Option<String>,
    /// Set only after every node has been rolled to current=new/previous=old.
    /// This fences the old generation and starts the complete expiry horizon.
    pub retire_previous: bool,
    pub minimum_overlap: Duration,
}
