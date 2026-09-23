//! Complete legal-hold and governance-export use cases.
use crate::services::{
    api_mutations::{AdminMutationAdmission, ApiMutationOutcome, StoredApiResponse},
    api_queries::ApiReadAuthority,
};
use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

pub const GOVERNANCE_EXPORT_LEASE_SECONDS: i64 = 15 * 60;
pub(crate) const GOVERNANCE_EXPORT_REPLAY_MAX_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "id")]
pub enum LegalHoldTarget {
    PersonalArchive(Uuid),
    MucArchive(Uuid),
    OfflineMessage(Uuid),
    ReportEvidence(Uuid),
    PersonalArchiveOwner(Uuid),
    MucArchiveRoom(Uuid),
    OfflineMessageRecipient(Uuid),
    ReportEvidenceReport(Uuid),
}

#[derive(Debug, thiserror::Error)]
pub enum LegalHoldError {
    #[error("legal-hold operation is not authorized")]
    Forbidden,
    #[error("legal hold or one of its targets does not exist")]
    NotFound,
    #[error("legal hold is already released or conflicts with immutable history")]
    Conflict,
    #[error("governance export cursor is invalid or expired")]
    InvalidCursor,
    #[error("legal hold request is invalid")]
    Invalid,
    #[error("legal hold backend failed")]
    Internal(#[source] anyhow::Error),
}

#[derive(Debug, Serialize)]
pub struct LegalHoldSummary {
    pub id: Uuid,
    pub title: String,
    pub authority_reference: String,
    pub reason: String,
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub released_by: Option<Uuid>,
    pub released_at: Option<DateTime<Utc>>,
    pub release_reason: Option<String>,
    pub target_count: i64,
}

#[derive(Debug, Serialize)]
pub struct AuditExportEntry {
    pub id: i64,
    pub actor_id: Option<Uuid>,
    pub action: String,
    pub target: Option<String>,
    pub details: serde_json::Value,
    pub ip_address: Option<String>,
    pub request_id: Option<Uuid>,
    pub operation_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub previous_hash: String,
    pub entry_hash: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditExportCursor {
    pub export_id: Uuid,
    pub after_id: i64,
    pub snapshot_max_id: i64,
    pub snapshot_at: DateTime<Utc>,
    pub chain_root: [u8; 32],
}

#[derive(Debug, Serialize)]
pub struct AuditExport {
    pub format: &'static str,
    pub export_id: Uuid,
    pub exported_at: DateTime<Utc>,
    pub snapshot_at: DateTime<Utc>,
    pub snapshot_max_id: i64,
    pub lease_expires_at: DateTime<Utc>,
    pub first_id: Option<i64>,
    pub last_id: Option<i64>,
    pub entries: Vec<AuditExportEntry>,
    pub chain_start_sha256: String,
    pub chain_root_sha256: String,
    pub complete: bool,
    /// Kept for wire compatibility; `next_cursor` is the authoritative
    /// continuation signal and makes every bounded page retrievable.
    pub truncated: bool,
    #[serde(skip)]
    pub next: Option<AuditExportCursor>,
}

#[derive(Debug, Serialize)]
pub struct HeldRecordExport {
    pub resource_type: String,
    pub record_id: Uuid,
    pub subject_id: Uuid,
    pub encrypted: bool,
    pub record_created_at: DateTime<Utc>,
    /// For OMEMO-backed archive/offline records this is the original encrypted
    /// stanza. Encrypted report evidence has no authoritative ciphertext
    /// column, so its user-supplied decrypted body is deliberately omitted.
    pub server_visible_payload: Option<String>,
    pub payload_disposition: String,
    pub previous_hash: String,
    pub entry_hash: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegalHoldExportCursor {
    pub export_id: Uuid,
    pub after_resource_order: i64,
    pub after_created_at: DateTime<Utc>,
    pub after_record_id: Uuid,
    pub snapshot_at: DateTime<Utc>,
    pub chain_root: [u8; 32],
}

#[derive(Debug, Serialize)]
pub struct LegalHoldExport {
    pub format: &'static str,
    pub export_id: Uuid,
    pub exported_at: DateTime<Utc>,
    pub snapshot_at: DateTime<Utc>,
    pub lease_expires_at: Option<DateTime<Utc>>,
    pub hold: LegalHoldSummary,
    pub records: Vec<HeldRecordExport>,
    pub chain_start_sha256: String,
    pub chain_root_sha256: String,
    pub complete: bool,
    pub truncated: bool,
    #[serde(skip)]
    pub next: Option<LegalHoldExportCursor>,
}

#[derive(Debug)]
pub(crate) enum GovernanceError {
    Hold(LegalHoldError),
    InvalidCursor,
    BadRequest(&'static str),
    Internal(anyhow::Error),
}

#[derive(Debug)]
pub(crate) struct GovernanceFailure {
    pub(crate) error: GovernanceError,
    pub(crate) operation_failed: bool,
    pub(crate) cursor_rejected: bool,
}
impl GovernanceFailure {
    pub(crate) fn quiet(error: GovernanceError) -> Self {
        Self {
            error,
            operation_failed: false,
            cursor_rejected: false,
        }
    }
    pub(crate) fn internal(error: impl Into<anyhow::Error>) -> Self {
        Self::quiet(GovernanceError::Internal(error.into()))
    }
    pub(crate) fn hold(error: LegalHoldError) -> Self {
        Self::quiet(GovernanceError::Hold(error))
    }
    pub(crate) fn operation(mut self) -> Self {
        self.operation_failed = true;
        self
    }
    pub(crate) fn rejected_cursor() -> Self {
        Self {
            error: GovernanceError::InvalidCursor,
            operation_failed: false,
            cursor_rejected: true,
        }
    }
    pub(crate) fn export(error: LegalHoldError) -> Self {
        let cursor_rejected = matches!(&error, LegalHoldError::InvalidCursor);
        Self {
            error: GovernanceError::Hold(error),
            operation_failed: true,
            cursor_rejected,
        }
    }
}

pub(crate) fn ensure_governance_export_size(bytes: &[u8]) -> Result<(), GovernanceFailure> {
    if bytes.len() > GOVERNANCE_EXPORT_REPLAY_MAX_BYTES {
        return Err(GovernanceFailure::quiet(GovernanceError::BadRequest(
            "governance export exceeds the 1 MiB idempotent replay bound; reduce max_rows",
        )));
    }
    Ok(())
}

pub(crate) struct CreateHoldCommand<'a> {
    pub(crate) admission: AdminMutationAdmission<'a>,
    pub(crate) title: &'a str,
    pub(crate) authority_reference: &'a str,
    pub(crate) reason: &'a str,
    pub(crate) targets: &'a [LegalHoldTarget],
}
pub(crate) struct HoldExportCommand<'a> {
    pub(crate) admission: AdminMutationAdmission<'a>,
    pub(crate) hold_id: Uuid,
    pub(crate) max_rows: i64,
    pub(crate) cursor: Option<&'a str>,
}
pub(crate) struct AuditExportCommand<'a> {
    pub(crate) admission: AdminMutationAdmission<'a>,
    pub(crate) start: Option<DateTime<Utc>>,
    pub(crate) end: Option<DateTime<Utc>>,
    pub(crate) max_rows: i64,
    pub(crate) cursor: Option<&'a str>,
}

/// Encodes only governance continuations. Verification receives the database
/// clock from the transaction already owning the export request.
pub(crate) trait GovernanceCursorCodec: Send + Sync {
    fn decode_hold(
        &self,
        actor: Uuid,
        hold: Uuid,
        token: &str,
        now: DateTime<Utc>,
    ) -> Result<LegalHoldExportCursor, GovernanceFailure>;
    fn decode_audit(
        &self,
        actor: Uuid,
        start: Option<DateTime<Utc>>,
        end: Option<DateTime<Utc>>,
        token: &str,
        now: DateTime<Utc>,
    ) -> Result<AuditExportCursor, GovernanceFailure>;
    fn encode_hold(
        &self,
        actor: Uuid,
        export: &LegalHoldExport,
    ) -> Result<Option<String>, GovernanceFailure>;
    fn encode_audit(
        &self,
        actor: Uuid,
        start: Option<DateTime<Utc>>,
        end: Option<DateTime<Utc>>,
        export: &AuditExport,
    ) -> Result<Option<String>, GovernanceFailure>;
}

pub(crate) trait GovernanceRepository: Send + Sync {
    fn list_holds(
        &self,
        actor: ApiReadAuthority<'_>,
        active_only: bool,
        limit: i64,
        access_key_sha256: &str,
    ) -> impl std::future::Future<Output = Result<Vec<LegalHoldSummary>, GovernanceFailure>> + Send;
    fn create_hold(
        &self,
        command: CreateHoldCommand<'_>,
    ) -> impl std::future::Future<
        Output = Result<ApiMutationOutcome<StoredApiResponse>, GovernanceFailure>,
    > + Send;
    fn release_hold(
        &self,
        admission: AdminMutationAdmission<'_>,
        id: Uuid,
        reason: &str,
    ) -> impl std::future::Future<
        Output = Result<ApiMutationOutcome<StoredApiResponse>, GovernanceFailure>,
    > + Send;
    fn export_hold(
        &self,
        command: HoldExportCommand<'_>,
    ) -> impl std::future::Future<
        Output = Result<ApiMutationOutcome<StoredApiResponse>, GovernanceFailure>,
    > + Send;
    fn export_audit(
        &self,
        command: AuditExportCommand<'_>,
    ) -> impl std::future::Future<
        Output = Result<ApiMutationOutcome<StoredApiResponse>, GovernanceFailure>,
    > + Send;
}

#[derive(Clone)]
pub(crate) struct GovernanceService<R> {
    repository: R,
}
impl<R: GovernanceRepository> GovernanceService<R> {
    pub(crate) fn new(repository: R) -> Self {
        Self { repository }
    }
    pub(crate) async fn list_holds(
        &self,
        actor: ApiReadAuthority<'_>,
        active_only: bool,
        limit: i64,
        access_key_sha256: &str,
    ) -> Result<Vec<LegalHoldSummary>, GovernanceFailure> {
        self.repository
            .list_holds(actor, active_only, limit, access_key_sha256)
            .await
    }
    pub(crate) async fn create_hold(
        &self,
        command: CreateHoldCommand<'_>,
    ) -> Result<ApiMutationOutcome<StoredApiResponse>, GovernanceFailure> {
        self.repository.create_hold(command).await
    }
    pub(crate) async fn release_hold(
        &self,
        admission: AdminMutationAdmission<'_>,
        id: Uuid,
        reason: &str,
    ) -> Result<ApiMutationOutcome<StoredApiResponse>, GovernanceFailure> {
        self.repository.release_hold(admission, id, reason).await
    }
    pub(crate) async fn export_hold(
        &self,
        command: HoldExportCommand<'_>,
    ) -> Result<ApiMutationOutcome<StoredApiResponse>, GovernanceFailure> {
        self.repository.export_hold(command).await
    }
    pub(crate) async fn export_audit(
        &self,
        command: AuditExportCommand<'_>,
    ) -> Result<ApiMutationOutcome<StoredApiResponse>, GovernanceFailure> {
        self.repository.export_audit(command).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn governance_export_never_silently_exceeds_replay_storage() {
        assert!(
            ensure_governance_export_size(&vec![0; GOVERNANCE_EXPORT_REPLAY_MAX_BYTES]).is_ok()
        );
        assert!(
            matches!(ensure_governance_export_size(&vec![0; GOVERNANCE_EXPORT_REPLAY_MAX_BYTES+1]),
            Err(GovernanceFailure { error: GovernanceError::BadRequest(message), .. }) if message.contains("reduce max_rows"))
        );
    }
}
