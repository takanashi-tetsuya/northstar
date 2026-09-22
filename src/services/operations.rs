//! Durable operation and fan-out target projections, without worker lease credentials.
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde_json::Value;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationPolicy {
    ReauthorizeUntilEffect,
    CommittedConsequence,
}

impl AuthorizationPolicy {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::ReauthorizeUntilEffect => "reauthorize_until_effect",
            Self::CommittedConsequence => "committed_consequence",
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self> {
        match value {
            "reauthorize_until_effect" => Ok(Self::ReauthorizeUntilEffect),
            "committed_consequence" => Ok(Self::CommittedConsequence),
            _ => anyhow::bail!("stored operation authorization policy is invalid"),
        }
    }

    pub fn label(self) -> &'static str {
        self.as_str()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationStatus {
    Pending,
    Running,
    Succeeded,
    Failed,
    Canceled,
    Indeterminate,
}

impl OperationStatus {
    pub(crate) fn parse(value: &str) -> Result<Self> {
        match value {
            "pending" => Ok(Self::Pending),
            "running" => Ok(Self::Running),
            "succeeded" => Ok(Self::Succeeded),
            "failed" => Ok(Self::Failed),
            "canceled" => Ok(Self::Canceled),
            "indeterminate" => Ok(Self::Indeterminate),
            _ => anyhow::bail!("stored operation status is invalid"),
        }
    }

    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Failed | Self::Canceled | Self::Indeterminate
        )
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Canceled => "canceled",
            Self::Indeterminate => "indeterminate",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct OperationPageBoundary {
    pub created_at: DateTime<Utc>,
    pub id: Uuid,
}

#[derive(Clone, Debug)]
pub struct OperationPage {
    pub items: Vec<OperationRecord>,
    pub next: Option<OperationPageBoundary>,
    pub database_now: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct OperationTargetPage {
    pub items: Vec<OperationTargetRecord>,
    pub next: Option<OperationPageBoundary>,
    pub database_now: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct OperationRecord {
    pub id: Uuid,
    pub request_id: Uuid,
    #[cfg(test)]
    pub idempotency_id: Option<Uuid>,
    pub actor_id: Option<Uuid>,
    pub actor_subject_id: Uuid,
    pub actor_auth_generation: i64,
    pub authorization_policy: AuthorizationPolicy,
    pub kind: String,
    pub target: Option<String>,
    pub status: OperationStatus,
    pub payload_version: i16,
    pub payload: Value,
    pub result: Option<Value>,
    pub error_code: Option<String>,
    pub attempts: i32,
    pub max_attempts: i32,
    pub next_attempt_at: DateTime<Utc>,
    pub deadline_at: DateTime<Utc>,
    pub cancel_requested_at: Option<DateTime<Utc>>,
    pub point_of_no_return_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug)]
pub struct OperationTargetRecord {
    pub id: Uuid,
    pub operation_id: Uuid,
    pub target_key: String,
    pub ordinal: i64,
    pub status: OperationStatus,
    pub payload: Value,
    pub result: Option<Value>,
    pub error_code: Option<String>,
    pub attempts: i32,
    pub max_attempts: i32,
    pub next_attempt_at: DateTime<Utc>,
    pub deadline_at: DateTime<Utc>,
    pub cancel_requested_at: Option<DateTime<Utc>>,
    pub point_of_no_return_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}
