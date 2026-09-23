//! Durable operation projections, cancellation and reconciliation policy.
use crate::services::api_mutations::{
    AdminMutationAdmission, ApiMutationOutcome, ApiMutationRejection, StoredApiResponse,
};
use anyhow::{Context, Result};
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

const MAX_ERROR_CODE_BYTES: usize = 128;
pub(crate) const MAX_RESULT_BYTES: usize = 1024 * 1024;
pub(crate) fn validate_json(value: &Value, maximum: usize, label: &str) -> Result<()> {
    anyhow::ensure!(
        serde_json::to_vec(value)?.len() <= maximum,
        "{label} exceeds its encoded size limit"
    );
    Ok(())
}

pub(crate) fn contains_secret_key(value: &Value) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(key, value)| {
            let key = key.to_ascii_lowercase().replace('-', "_");
            key.contains("password")
                || key.contains("passwd")
                || key.contains("passphrase")
                || key.contains("secret")
                || key.contains("private_key")
                || key.contains("api_key")
                || key.contains("apikey")
                || key.contains("access_token")
                || key.contains("refresh_token")
                || key.contains("session_token")
                || key.contains("client_secret")
                || key.contains("bearer")
                || key == "token"
                || key == "authorization"
                || key == "cookie"
                || key == "set_cookie"
                || contains_secret_key(value)
        }),
        Value::Array(values) => values.iter().any(contains_secret_key),
        _ => false,
    }
}

fn contains_sensitive_text(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    [
        "password",
        "passwd",
        "passphrase",
        "secret",
        "private_key",
        "private-key",
        "private key",
        "api_key",
        "api-key",
        "apikey",
        "access_token",
        "access-token",
        "refresh_token",
        "refresh-token",
        "session_token",
        "session-token",
        "client_secret",
        "client-secret",
        "authorization:",
        "bearer ",
        "cookie:",
        "set-cookie:",
        "-----begin private key-----",
        "-----begin encrypted private key-----",
        "-----begin rsa private key-----",
        "-----begin ec private key-----",
        "-----begin openssh private key-----",
    ]
    .iter()
    .any(|indicator| lower.contains(indicator))
}

/// Validate operator-supplied reconciliation data before it is persisted.
/// Successful reconciliation may carry a bounded, non-secret result and must
/// not carry an error code. Failed reconciliation must carry a valid error
/// code and cannot carry a result, avoiding ambiguous terminal records.
pub fn validate_manual_reconciliation_content(
    succeeded: bool,
    result: Option<&Value>,
    error_code: Option<&str>,
    evidence_note: &str,
) -> Result<()> {
    anyhow::ensure!(
        !evidence_note.is_empty() && evidence_note.len() <= 4096,
        "reconciliation evidence note is invalid"
    );
    anyhow::ensure!(
        evidence_note.chars().all(|character| {
            let code = character as u32;
            matches!(character, '\t' | '\n' | '\r')
                || (!(code <= 0x1f || (0x7f..=0x9f).contains(&code))
                    && !(0x202a..=0x202e).contains(&code)
                    && !(0x2066..=0x2069).contains(&code))
        }),
        "reconciliation evidence note contains unsafe control characters"
    );
    anyhow::ensure!(
        !contains_sensitive_text(evidence_note),
        "evidence note must not contain credentials"
    );
    if let Some(result) = result {
        validate_json(result, MAX_RESULT_BYTES, "reconciliation result")?;
        anyhow::ensure!(
            !contains_secret_key(result),
            "reconciliation result contains credentials"
        );
    }
    if succeeded {
        anyhow::ensure!(
            error_code.is_none(),
            "successful reconciliation must not include an error code"
        );
    } else {
        anyhow::ensure!(
            result.is_none(),
            "failed reconciliation must not include a result"
        );
        validate_error_code(error_code.context("failed reconciliation requires an error code")?)?;
    }
    Ok(())
}

pub(crate) fn validate_error_code(error_code: &str) -> Result<()> {
    anyhow::ensure!(
        !error_code.is_empty()
            && error_code.len() <= MAX_ERROR_CODE_BYTES
            && error_code.bytes().all(|byte| byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || byte == b'_'
                || byte == b'-'),
        "operation error code is invalid"
    );
    Ok(())
}

pub(crate) struct ReconciliationInput<'a> {
    pub(crate) succeeded: bool,
    pub(crate) result: Option<&'a Value>,
    pub(crate) error_code: Option<&'a str>,
    pub(crate) evidence_note: &'a str,
}
impl ReconciliationInput<'_> {
    fn validate(mut self) -> Result<Self> {
        self.evidence_note = self.evidence_note.trim();
        validate_manual_reconciliation_content(
            self.succeeded,
            self.result,
            self.error_code,
            self.evidence_note,
        )?;
        Ok(self)
    }
}

pub(crate) trait OperationAdminRepository: Send + Sync {
    fn cancel(
        &self,
        admission: AdminMutationAdmission<'_>,
        id: Uuid,
    ) -> impl std::future::Future<Output = Result<ApiMutationOutcome<StoredApiResponse>>> + Send;
    fn reconcile(
        &self,
        admission: AdminMutationAdmission<'_>,
        id: Uuid,
        input: ReconciliationInput<'_>,
    ) -> impl std::future::Future<Output = Result<ApiMutationOutcome<StoredApiResponse>>> + Send;
    fn reconcile_target(
        &self,
        admission: AdminMutationAdmission<'_>,
        operation_id: Uuid,
        target_id: Uuid,
        input: ReconciliationInput<'_>,
    ) -> impl std::future::Future<Output = Result<ApiMutationOutcome<StoredApiResponse>>> + Send;
}

#[derive(Clone)]
pub(crate) struct OperationAdminService<R> {
    repository: R,
}
impl<R: OperationAdminRepository> OperationAdminService<R> {
    pub(crate) fn new(repository: R) -> Self {
        Self { repository }
    }
    pub(crate) async fn cancel(
        &self,
        admission: AdminMutationAdmission<'_>,
        id: Uuid,
    ) -> Result<ApiMutationOutcome<StoredApiResponse>> {
        if id.is_nil() {
            return Ok(ApiMutationOutcome::Rejected(
                ApiMutationRejection::BadRequest("operation id must not be nil"),
            ));
        }
        self.repository.cancel(admission, id).await
    }
    pub(crate) async fn reconcile(
        &self,
        admission: AdminMutationAdmission<'_>,
        id: Uuid,
        input: ReconciliationInput<'_>,
    ) -> Result<ApiMutationOutcome<StoredApiResponse>> {
        if id.is_nil() {
            return Ok(ApiMutationOutcome::Rejected(
                ApiMutationRejection::BadRequest("operation id must not be nil"),
            ));
        }
        let input = match input.validate() {
            Ok(input) => input,
            Err(_) => {
                return Ok(ApiMutationOutcome::Rejected(
                    ApiMutationRejection::BadRequest("invalid reconciliation data"),
                ))
            }
        };
        self.repository.reconcile(admission, id, input).await
    }
    pub(crate) async fn reconcile_target(
        &self,
        admission: AdminMutationAdmission<'_>,
        operation_id: Uuid,
        target_id: Uuid,
        input: ReconciliationInput<'_>,
    ) -> Result<ApiMutationOutcome<StoredApiResponse>> {
        if operation_id.is_nil() || target_id.is_nil() {
            return Ok(ApiMutationOutcome::Rejected(
                ApiMutationRejection::BadRequest("operation target id must not be nil"),
            ));
        }
        let input = match input.validate() {
            Ok(input) => input,
            Err(_) => {
                return Ok(ApiMutationOutcome::Rejected(
                    ApiMutationRejection::BadRequest("invalid reconciliation data"),
                ))
            }
        };
        self.repository
            .reconcile_target(admission, operation_id, target_id, input)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn manual_reconciliation_combinations_and_secret_detection_are_strict() {
        assert!(validate_manual_reconciliation_content(
            true,
            Some(&json!({"delivery_count": 1})),
            None,
            "Verified the external delivery ledger entry.",
        )
        .is_ok());
        assert!(validate_manual_reconciliation_content(
            false,
            None,
            Some("operator_confirmed_not_applied"),
            "Verified that no external effect was applied.",
        )
        .is_ok());

        assert!(validate_manual_reconciliation_content(
            true,
            None,
            Some("must_not_coexist"),
            "Verified the external result.",
        )
        .is_err());
        assert!(validate_manual_reconciliation_content(
            false,
            Some(&json!({"ambiguous": true})),
            Some("failed"),
            "Verified the external result.",
        )
        .is_err());
        assert!(validate_manual_reconciliation_content(
            false,
            None,
            None,
            "Verified the external result.",
        )
        .is_err());
        assert!(validate_manual_reconciliation_content(
            false,
            None,
            Some("INVALID CODE"),
            "Verified the external result.",
        )
        .is_err());

        for evidence in [
            "Authorization: Basic Zm9vOmJhcg==",
            "Bearer abcdef",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            "client_secret was copied here",
            "Cookie: sid=value",
        ] {
            assert!(validate_manual_reconciliation_content(true, None, None, evidence).is_err());
        }
        assert!(validate_manual_reconciliation_content(
            true,
            Some(&json!({"nested": {"refresh-token": "credential"}})),
            None,
            "Verified the external result.",
        )
        .is_err());
    }
}
