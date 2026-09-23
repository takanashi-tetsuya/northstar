use crate::api::idempotency::{mutation_rejection, stored_api_response};
use crate::api::*;
use crate::error::AppError;
use crate::services::{
    api_mutations::{
        AdminMutationAdmission, ApiMutationOutcome, ApiPrincipalKind, StoredApiResponse,
    },
    governance::*,
    retention_policy::{RetentionMutationAdmission, RetentionPolicyError, UserRetentionPolicy},
};
use crate::state::GovernanceContext;
use axum::{extract::State, http::HeaderMap, response::Response, Json};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use uuid::Uuid;

fn require_explicit_idempotency_key(headers: &HeaderMap) -> Result<&str, AppError> {
    let mut values = headers.get_all("idempotency-key").iter();
    let Some(value) = values.next() else {
        return Err(AppError::BadRequest(
            "Idempotency-Key is required for data-governance writes and exports".into(),
        ));
    };
    if values.next().is_some() {
        return Err(AppError::BadRequest(
            "exactly one Idempotency-Key header is allowed".into(),
        ));
    }
    let value = value
        .to_str()
        .map_err(|_| AppError::BadRequest("Idempotency-Key is invalid".into()))?;
    if !(8..=200).contains(&value.len()) || !value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
    {
        return Err(AppError::BadRequest(
            "Idempotency-Key must contain 8 to 200 visible ASCII bytes".into(),
        ));
    }
    Ok(value)
}

fn access_key_sha256(key: &str) -> String {
    let mut output = String::with_capacity(64);
    for byte in Sha256::digest(key.as_bytes()) {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn retention_error(error: RetentionPolicyError) -> AppError {
    match error {
        RetentionPolicyError::Unauthorized => AppError::Unauthorized,
        RetentionPolicyError::Forbidden => AppError::Forbidden,
        RetentionPolicyError::NotFound => AppError::NotFound(error.to_string()),
        RetentionPolicyError::Internal(error) => AppError::Internal(error),
    }
}

fn governance_error(failure: GovernanceFailure) -> AppError {
    match failure.error {
        GovernanceError::Hold(error) => match error {
            LegalHoldError::Forbidden => AppError::Forbidden,
            LegalHoldError::NotFound => AppError::NotFound(error.to_string()),
            LegalHoldError::Conflict => AppError::Conflict(error.to_string()),
            LegalHoldError::InvalidCursor => AppError::InvalidCursor,
            LegalHoldError::Invalid => AppError::BadRequest(error.to_string()),
            LegalHoldError::Internal(error) => AppError::from_internal(error),
        },
        GovernanceError::InvalidCursor => AppError::InvalidCursor,
        GovernanceError::BadRequest(message) => AppError::BadRequest(message.into()),
        GovernanceError::Internal(error) => AppError::Internal(error),
    }
}
fn governance_response(
    outcome: ApiMutationOutcome<StoredApiResponse>,
) -> Result<Response, AppError> {
    match outcome {
        ApiMutationOutcome::Committed(response) => stored_api_response(response),
        ApiMutationOutcome::Replay(response) => idempotency_replay_response(response),
        ApiMutationOutcome::Rejected(rejection) => Err(mutation_rejection(rejection)),
    }
}

fn retention_response(
    outcome: ApiMutationOutcome<StoredApiResponse>,
) -> Result<Response, AppError> {
    match outcome {
        ApiMutationOutcome::Committed(response) => stored_api_response(response),
        ApiMutationOutcome::Replay(response) => idempotency_replay_response(response),
        ApiMutationOutcome::Rejected(rejection) => Err(mutation_rejection(rejection)),
    }
}

fn governance_export_rows(
    requested: Option<i64>,
    default: i64,
    maximum: i64,
) -> Result<i64, AppError> {
    let rows = requested.unwrap_or(default);
    if !(1..=maximum).contains(&rows) {
        return Err(AppError::BadRequest(format!(
            "max_rows must be between 1 and {maximum}"
        )));
    }
    Ok(rows)
}

pub async fn get_my_retention(
    State(state): State<crate::state::RetentionPolicyContext>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    let policy = state
        .user_policy(bearer_token(&headers)?)
        .await
        .map_err(retention_error)?;
    Ok(Json(json!({
        "policy":policy,
        "operator_limits":state.retention_policy_service().limits(),
        "zero_operator_limit_means":"inherited_cleanup_disabled; an explicit shorter user policy remains effective"
    })))
}

pub async fn update_my_retention(
    State(state): State<crate::state::RetentionPolicyContext>,
    headers: HeaderMap,
    request: ApiJson<UserRetentionPolicyRequest>,
) -> Result<Response, AppError> {
    require_explicit_idempotency_key(&headers)?;
    let token = zeroize::Zeroizing::new(bearer_token(&headers)?.to_owned());
    let idempotency = request.idempotency(
        None,
        token.as_bytes(),
        ApiPrincipalKind::User,
        "PUT",
        "/api/v1/me/retention",
    );
    let admission = RetentionMutationAdmission {
        session_token: &token,
        idempotency,
    };
    let policy = UserRetentionPolicy {
        personal_mam_days: request.personal_mam_days,
        offline_message_days: request.offline_message_days,
        moderation_evidence_days: request.moderation_evidence_days,
    };
    let outcome = state
        .retention_policy_service()
        .set_user_policy(admission, policy)
        .await
        .map_err(retention_error)?;
    retention_response(outcome)
}

pub async fn get_muc_retention(
    State(state): State<crate::state::RetentionPolicyContext>,
    headers: HeaderMap,
    ApiPath(room_id): ApiPath<Uuid>,
) -> Result<Json<Value>, AppError> {
    let policy = state
        .muc_policy(bearer_token(&headers)?, room_id)
        .await
        .map_err(retention_error)?;
    Ok(Json(json!({
        "room_id":room_id,
        "retention_days":policy,
        "operator_limit_days":state.retention_policy_service().muc_limit_days()
    })))
}

pub async fn update_muc_retention(
    State(state): State<crate::state::RetentionPolicyContext>,
    headers: HeaderMap,
    ApiPath(room_id): ApiPath<Uuid>,
    request: ApiJson<MucRetentionPolicyRequest>,
) -> Result<Response, AppError> {
    require_explicit_idempotency_key(&headers)?;
    let token = zeroize::Zeroizing::new(bearer_token(&headers)?.to_owned());
    let mut idempotency = request.idempotency(
        None,
        token.as_bytes(),
        ApiPrincipalKind::User,
        "PUT",
        "/api/v1/muc_rooms/{id}/retention",
    );
    idempotency.target_scope = room_id.as_bytes();
    let admission = RetentionMutationAdmission {
        session_token: &token,
        idempotency,
    };
    let outcome = state
        .retention_policy_service()
        .set_muc_policy(admission, room_id, request.retention_days)
        .await
        .map_err(retention_error)?;
    retention_response(outcome)
}

fn parse_hold_targets(
    targets: &[LegalHoldTargetRequest],
) -> Result<Vec<LegalHoldTarget>, AppError> {
    targets
        .iter()
        .map(|target| {
            Ok(match target.kind.as_str() {
                "personal_archive" => LegalHoldTarget::PersonalArchive(target.id),
                "muc_archive" => LegalHoldTarget::MucArchive(target.id),
                "offline_message" => LegalHoldTarget::OfflineMessage(target.id),
                "report_evidence" => LegalHoldTarget::ReportEvidence(target.id),
                "personal_archive_owner" => LegalHoldTarget::PersonalArchiveOwner(target.id),
                "muc_archive_room" => LegalHoldTarget::MucArchiveRoom(target.id),
                "offline_message_recipient" => LegalHoldTarget::OfflineMessageRecipient(target.id),
                "report_evidence_report" => LegalHoldTarget::ReportEvidenceReport(target.id),
                _ => {
                    return Err(AppError::BadRequest(
                        "unknown legal-hold target kind".into(),
                    ));
                }
            })
        })
        .collect()
}

pub async fn list_legal_holds(
    State(state): State<GovernanceContext>,
    actor: ApiAdmin,
    headers: HeaderMap,
    ApiQuery(query): ApiQuery<LegalHoldPageQuery>,
) -> Result<Json<Value>, AppError> {
    let access_key = require_explicit_idempotency_key(&headers)?;
    let limit = pagination::checked_limit(query.limit, 100, 100)?;
    let holds = state
        .list_holds(
            actor.read_authority(),
            query.active_only.unwrap_or(false),
            limit,
            &access_key_sha256(access_key),
        )
        .await
        .map_err(governance_error)?;
    Ok(Json(json!({"legal_holds":holds})))
}

pub async fn create_legal_hold(
    State(state): State<GovernanceContext>,
    actor: ApiAdmin,
    headers: HeaderMap,
    request: ApiJson<LegalHoldCreateRequest>,
) -> Result<Response, AppError> {
    require_explicit_idempotency_key(&headers)?;
    let targets = parse_hold_targets(&request.targets)?;
    let mut idempotency = request.idempotency(
        Some(actor.id),
        actor.id.as_bytes(),
        ApiPrincipalKind::Admin,
        "POST",
        "/api/v1/admin/legal-holds",
    );
    idempotency.target_scope = b"legal-hold:create";
    let outcome = state
        .create_hold(CreateHoldCommand {
            admission: AdminMutationAdmission {
                authority: actor.read_authority(),
                idempotency,
            },
            title: &request.title,
            authority_reference: &request.authority_reference,
            reason: &request.reason,
            targets: &targets,
        })
        .await
        .map_err(governance_error)?;
    governance_response(outcome)
}

pub async fn release_legal_hold(
    State(state): State<GovernanceContext>,
    actor: ApiAdmin,
    headers: HeaderMap,
    ApiPath(id): ApiPath<Uuid>,
    request: ApiJson<LegalHoldReleaseRequest>,
) -> Result<Response, AppError> {
    require_explicit_idempotency_key(&headers)?;
    let mut idempotency = request.idempotency(
        Some(actor.id),
        actor.id.as_bytes(),
        ApiPrincipalKind::Admin,
        "POST",
        "/api/v1/admin/legal-holds/{id}/release",
    );
    idempotency.target_scope = id.as_bytes();
    let outcome = state
        .release_hold(
            AdminMutationAdmission {
                authority: actor.read_authority(),
                idempotency,
            },
            id,
            &request.reason,
        )
        .await
        .map_err(governance_error)?;
    governance_response(outcome)
}

pub async fn export_legal_hold(
    State(state): State<GovernanceContext>,
    actor: ApiAdmin,
    headers: HeaderMap,
    ApiPath(id): ApiPath<Uuid>,
    request: ApiJson<GovernanceExportRequest>,
) -> Result<Response, AppError> {
    require_explicit_idempotency_key(&headers)?;
    if request.start.is_some() || request.end.is_some() {
        return Err(AppError::BadRequest(
            "legal-hold export does not accept start/end filters".into(),
        ));
    }
    let max_rows = governance_export_rows(request.max_rows, 100, 100)?;
    let mut idempotency = request.idempotency(
        Some(actor.id),
        actor.id.as_bytes(),
        ApiPrincipalKind::Admin,
        "POST",
        "/api/v1/admin/legal-holds/{id}/export",
    );
    idempotency.target_scope = id.as_bytes();
    let outcome = state
        .export_hold(HoldExportCommand {
            admission: AdminMutationAdmission {
                authority: actor.read_authority(),
                idempotency,
            },
            hold_id: id,
            max_rows,
            cursor: request.cursor.as_deref(),
        })
        .await
        .map_err(governance_error)?;
    governance_response(outcome)
}

pub async fn export_audit(
    State(state): State<GovernanceContext>,
    actor: ApiAdmin,
    headers: HeaderMap,
    request: ApiJson<GovernanceExportRequest>,
) -> Result<Response, AppError> {
    require_explicit_idempotency_key(&headers)?;
    if request
        .start
        .as_ref()
        .zip(request.end.as_ref())
        .is_some_and(|(start, end)| start >= end)
    {
        return Err(AppError::BadRequest(
            "audit export start must precede end".into(),
        ));
    }
    let max_rows = governance_export_rows(request.max_rows, 500, 500)?;
    let mut idempotency = request.idempotency(
        Some(actor.id),
        actor.id.as_bytes(),
        ApiPrincipalKind::Admin,
        "POST",
        "/api/v1/admin/audit/export",
    );
    idempotency.target_scope = b"audit:export";
    let outcome = state
        .export_audit(AuditExportCommand {
            admission: AdminMutationAdmission {
                authority: actor.read_authority(),
                idempotency,
            },
            start: request.start,
            end: request.end,
            max_rows,
            cursor: request.cursor.as_deref(),
        })
        .await
        .map_err(governance_error)?;
    governance_response(outcome)
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_kinds_are_closed_and_typed() {
        let id = Uuid::nil();
        let parsed = parse_hold_targets(&[LegalHoldTargetRequest {
            kind: "muc_archive_room".into(),
            id,
        }])
        .unwrap();
        assert_eq!(parsed, vec![LegalHoldTarget::MucArchiveRoom(id)]);
        assert!(parse_hold_targets(&[LegalHoldTargetRequest {
            kind: "arbitrary_table".into(),
            id,
        }])
        .is_err());
    }

    #[test]
    fn governance_row_limits_reject_instead_of_silently_clamping() {
        assert_eq!(governance_export_rows(None, 100, 100).unwrap(), 100);
        assert_eq!(governance_export_rows(Some(1), 100, 100).unwrap(), 1);
        assert!(governance_export_rows(Some(0), 100, 100).is_err());
        assert!(governance_export_rows(Some(101), 100, 100).is_err());
    }

    #[test]
    fn governance_mutations_require_one_explicit_idempotency_key() {
        let mut headers = HeaderMap::new();
        assert!(require_explicit_idempotency_key(&headers).is_err());
        headers.insert(
            "idempotency-key",
            "governance-test-key-0001".parse().unwrap(),
        );
        assert_eq!(
            require_explicit_idempotency_key(&headers).unwrap(),
            "governance-test-key-0001"
        );
        headers.append("idempotency-key", "duplicate-key-0002".parse().unwrap());
        assert!(require_explicit_idempotency_key(&headers).is_err());
        assert_eq!(access_key_sha256("stable-key").len(), 64);
    }
}
