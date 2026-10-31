//! Records the abuse guard exchanges with its repositories: actor state rows, challenge issuance and verification, and the key deployment identity.

use super::{AbuseAction, GuardError, PowChallenge, WorkRequirement};
use chrono::{DateTime, Utc};
use std::time::Duration;

#[derive(Debug)]
pub struct DbActorState {
    pub key: String,
    pub events: Vec<DateTime<Utc>>,
    pub penalty_level: u32,
    pub last_activity: DateTime<Utc>,
    pub blocked_until: DateTime<Utc>,
    pub sequence: i64,
}

pub struct IssueRequest {
    pub issue_groups: Vec<(Vec<String>, usize)>,
    pub capacity_groups: Vec<(Vec<String>, usize)>,
    pub actor_state_keys: Vec<String>,
    pub window: Duration,
}

/// The application signs this record after the repository has locked the
/// actor state. All cryptographic and rotation decisions stay with the guard.
pub struct IssueRecord {
    pub action: AbuseAction,
    pub challenge: PowChallenge,
    pub subject_hash: Vec<u8>,
    pub actor_sequences: serde_json::Value,
    pub intent_method: Option<String>,
    pub intent_path: Option<String>,
    pub body_sha256: Option<Vec<u8>>,
}

pub struct ConsumedChallenge {
    pub action: String,
    pub subject_hash: Vec<u8>,
    pub key_id: String,
    pub prefix: String,
    pub work_factor: i64,
    pub not_before: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub actor_sequences: serde_json::Value,
    pub requirement: serde_json::Value,
    pub protocol_version: i16,
    pub intent_method: Option<String>,
    pub intent_path: Option<String>,
    pub body_sha256: Option<Vec<u8>>,
    pub server_nonce: Option<String>,
    pub issued_at: Option<DateTime<Utc>>,
}

pub struct VerificationDecision {
    pub outcome: std::result::Result<WorkRequirement, GuardError>,
    pub persist_states: bool,
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
