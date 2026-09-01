use crate::abuse::{AbuseAction, PowIntent, PowIntentRequest, PowProof};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationRequest {
    pub username: String,
    pub password: String,
    pub invitation_token: Option<String>,
    pub pow: Option<PowProof>,
}

impl Drop for RegistrationRequest {
    fn drop(&mut self) {
        self.password.zeroize();
        if let Some(token) = &mut self.invitation_token {
            token.zeroize();
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credentials {
    pub username: String,
    pub password: String,
    pub pow: Option<PowProof>,
}

impl Drop for Credentials {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

#[derive(Serialize)]
pub struct SessionResponse {
    pub token: String,
    pub jid: String,
    pub is_admin: bool,
}

impl Drop for SessionResponse {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChallengeRequest {
    pub action: String,
    pub username: Option<String>,
    pub intent: Option<PowIntentRequest>,
}

impl RegistrationRequest {
    pub fn pow_intent(&self) -> PowIntent {
        PowIntent::http_json(
            AbuseAction::Registration,
            "/api/v1/register",
            &serde_json::json!({
                "invitation_token": self.invitation_token,
                "password": self.password,
                "username": self.username,
            }),
        )
    }
}

impl Credentials {
    pub fn pow_intent(&self) -> PowIntent {
        PowIntent::http_json(
            AbuseAction::Login,
            "/api/v1/login",
            &serde_json::json!({
                "password": self.password,
                "username": self.username,
            }),
        )
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasswordChange {
    pub current_password: String,
    pub new_password: String,
    pub pow: Option<PowProof>,
}

impl Drop for PasswordChange {
    fn drop(&mut self) {
        self.current_password.zeroize();
        self.new_password.zeroize();
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OmemoRecoveryPrepareRequest {
    pub transfer_id: uuid::Uuid,
    pub source_device_id: u32,
    pub poll_secret: String,
}

impl std::fmt::Debug for OmemoRecoveryPrepareRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OmemoRecoveryPrepareRequest")
            .field("transfer_id", &self.transfer_id)
            .field("source_device_id", &self.source_device_id)
            .field("poll_secret", &"[REDACTED]")
            .finish()
    }
}

impl Drop for OmemoRecoveryPrepareRequest {
    fn drop(&mut self) {
        self.poll_secret.zeroize();
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OmemoRecoverySealRequest {
    pub package_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OmemoRecoveryConsumeRequest {
    pub package_sha256: String,
    pub consumer_secret: String,
}

impl std::fmt::Debug for OmemoRecoveryConsumeRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OmemoRecoveryConsumeRequest")
            .field("package_sha256", &self.package_sha256)
            .field("consumer_secret", &"[REDACTED]")
            .finish()
    }
}

impl Drop for OmemoRecoveryConsumeRequest {
    fn drop(&mut self) {
        self.consumer_secret.zeroize();
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OmemoRecoveryPollRequest {
    pub poll_secret: String,
}

impl std::fmt::Debug for OmemoRecoveryPollRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OmemoRecoveryPollRequest")
            .field("poll_secret", &"[REDACTED]")
            .finish()
    }
}

impl Drop for OmemoRecoveryPollRequest {
    fn drop(&mut self) {
        self.poll_secret.zeroize();
    }
}

impl PasswordChange {
    pub fn pow_intent(&self) -> PowIntent {
        PowIntent::http_json_method(
            AbuseAction::PasswordChange,
            "PATCH",
            "/api/v1/me/password",
            &serde_json::json!({
                "current_password": self.current_password,
                "new_password": self.new_password,
            }),
        )
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryQuery {
    pub r#with: Option<String>,
    pub start: Option<DateTime<Utc>>,
    pub end: Option<DateTime<Utc>>,
    /// XEP-0313 extended-form chronological lower archive UID bound.
    pub after_id: Option<uuid::Uuid>,
    /// XEP-0313 extended-form chronological upper archive UID bound.
    pub before_id: Option<uuid::Uuid>,
    /// Comma-separated immutable archive UIDs. The handler rejects empty,
    /// duplicate and over-large sets before touching PostgreSQL.
    pub ids: Option<String>,
    /// Explicit RSM edge page: `first` or `last`.
    pub page: Option<String>,
    /// RSM page strictly before this immutable archive UID.
    pub before: Option<uuid::Uuid>,
    /// RSM page strictly after this immutable archive UID.
    pub after: Option<uuid::Uuid>,
    /// RSM page beginning at this zero-based result index.
    pub index: Option<i64>,
    /// XEP-0059 page size. Unlike the legacy `limit`, zero is valid and
    /// returns metadata without messages.
    pub max: Option<i64>,
    /// Reverse only the returned page, matching XEP-0313 `flip-page`.
    pub flip: Option<bool>,
    /// Legacy descending keyset page size retained for existing web clients.
    pub limit: Option<i64>,
    /// Legacy opaque continuation token retained for existing web clients.
    pub cursor: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceItem {
    /// The immutable MAM archive UUID returned by `/api/v1/history`.
    pub archive_id: uuid::Uuid,
    pub client_message_id: Option<String>,
    pub body_text: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportRequest {
    pub reported_jid: String,
    pub category: String,
    pub evidence: Vec<EvidenceItem>,
    pub description: Option<String>,
    pub pow: Option<PowProof>,
}

impl ReportRequest {
    pub fn pow_intent(&self) -> PowIntent {
        PowIntent::http_json(
            AbuseAction::Report,
            "/api/v1/reports",
            &serde_json::json!({
                "category": self.category,
                "description": self.description,
                "evidence": self.evidence.iter().map(|item| serde_json::json!({
                    "archive_id": item.archive_id,
                    "body_text": item.body_text,
                    "client_message_id": item.client_message_id,
                })).collect::<Vec<_>>(),
                "reported_jid": self.reported_jid,
            }),
        )
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppealRequest {
    pub reason: String,
    pub pow: Option<PowProof>,
}

impl AppealRequest {
    pub fn pow_intent(&self, report_id: uuid::Uuid) -> PowIntent {
        PowIntent::http_json(
            AbuseAction::Appeal,
            &format!("/api/v1/reports/{report_id}/appeals"),
            &serde_json::json!({"reason": self.reason}),
        )
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserPatch {
    pub disabled: Option<bool>,
    pub admin: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModerationPatch {
    pub status: String,
    pub resolution: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvitationRequest {
    pub label: String,
    pub max_uses: Option<i32>,
    pub expires_in_hours: Option<i32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BooleanToggle {
    pub enabled: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserRetentionPolicyRequest {
    pub personal_mam_days: Option<i32>,
    pub offline_message_days: Option<i32>,
    pub moderation_evidence_days: Option<i32>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MucRetentionPolicyRequest {
    /// `null` restores the operator default. Room owners may only shorten;
    /// restoring/lengthening requires a server administrator.
    pub retention_days: Option<i32>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegalHoldTargetRequest {
    pub kind: String,
    pub id: uuid::Uuid,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegalHoldCreateRequest {
    pub title: String,
    pub authority_reference: String,
    pub reason: String,
    pub targets: Vec<LegalHoldTargetRequest>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegalHoldReleaseRequest {
    pub reason: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernanceExportRequest {
    pub start: Option<DateTime<Utc>>,
    pub end: Option<DateTime<Utc>>,
    pub max_rows: Option<i64>,
    /// Opaque, signed continuation returned by the preceding export page.
    pub cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegalHoldPageQuery {
    pub active_only: Option<bool>,
    pub limit: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct SessionView {
    pub connection_id: uuid::Uuid,
    pub node: String,
    pub jid: String,
    pub ip: Option<String>,
    pub resource: String,
    /// XEP-0280 is negotiated per resource. Exposing this non-secret runtime
    /// flag makes a successful control IQ distinguishable from a fanout or
    /// transport problem during production diagnosis.
    pub carbons_enabled: bool,
    pub connected_duration_seconds: u64,
}

#[derive(Serialize)]
pub struct OfflineMessagesStats {
    pub total_messages: i64,
    pub estimated_bytes: i64,
}

#[derive(Serialize)]
pub struct MucRoomView {
    pub id: uuid::Uuid,
    pub localpart: String,
    pub title: Option<String>,
    pub created_at: DateTime<Utc>,
    pub public: bool,
    pub persistent: bool,
    pub members_only: bool,
    pub moderated: bool,
    pub non_anonymous: bool,
    pub current_occupants: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BroadcastRequest {
    pub message: String,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CursorPage {
    pub limit: Option<i64>,
    pub cursor: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportPageQuery {
    pub limit: Option<i64>,
    pub cursor: Option<String>,
    pub status: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{extract::Query, http::Uri};

    #[test]
    fn recovery_capabilities_are_redacted_from_debug_output() {
        let secret = "recovery-secret-that-must-not-reach-a-log";
        let prepare = OmemoRecoveryPrepareRequest {
            transfer_id: uuid::Uuid::nil(),
            source_device_id: 7,
            poll_secret: secret.to_owned(),
        };
        let consume = OmemoRecoveryConsumeRequest {
            package_sha256: "00".repeat(32),
            consumer_secret: secret.to_owned(),
        };
        let poll = OmemoRecoveryPollRequest {
            poll_secret: secret.to_owned(),
        };
        for formatted in [
            format!("{prepare:?}"),
            format!("{consume:?}"),
            format!("{poll:?}"),
        ] {
            assert!(formatted.contains("[REDACTED]"));
            assert!(!formatted.contains(secret));
        }
    }

    #[test]
    fn collection_queries_reject_unknown_and_duplicate_fields() {
        let valid: Uri = "/?limit=25&cursor=opaque".parse().unwrap();
        let Query(page) = Query::<CursorPage>::try_from_uri(&valid).unwrap();
        assert_eq!(page.limit, Some(25));
        assert_eq!(page.cursor.as_deref(), Some("opaque"));

        for invalid in [
            "/?limit=25&offset=0",
            "/?limit=25&limit=10",
            "/?cursor=a&cursor=b",
        ] {
            let uri: Uri = invalid.parse().unwrap();
            assert!(
                Query::<CursorPage>::try_from_uri(&uri).is_err(),
                "{invalid}"
            );
        }

        let unknown_history: Uri = "/?with=a%40example.test&status=closed".parse().unwrap();
        assert!(Query::<HistoryQuery>::try_from_uri(&unknown_history).is_err());
        let unsupported_direction: Uri = "/?direction=incoming".parse().unwrap();
        assert!(Query::<HistoryQuery>::try_from_uri(&unsupported_direction).is_err());

        let archive_id = uuid::Uuid::new_v4();
        let mam_history: Uri = format!(
            "/?with=a%40example.test%2FPhone&start=2026-08-29T00%3A00%3A00Z&before={archive_id}&max=0&flip=true"
        )
        .parse()
        .unwrap();
        let Query(mam_history) = Query::<HistoryQuery>::try_from_uri(&mam_history).unwrap();
        assert_eq!(mam_history.before, Some(archive_id));
        assert_eq!(mam_history.max, Some(0));
        assert_eq!(mam_history.flip, Some(true));
        assert!(mam_history.start.is_some());

        let unknown_report: Uri = "/?status=closed&offset=0".parse().unwrap();
        assert!(Query::<ReportPageQuery>::try_from_uri(&unknown_report).is_err());
    }
}
