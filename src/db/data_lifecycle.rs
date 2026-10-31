pub use crate::services::governance::{
    AuditExport, AuditExportCursor, AuditExportEntry, HeldRecordExport, LegalHoldError,
    LegalHoldExport, LegalHoldExportCursor, LegalHoldSummary, LegalHoldTarget,
};
use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::collections::HashSet;
use uuid::Uuid;

pub const MAX_HOLD_TARGETS: usize = 1_000;
pub const MAX_GOVERNANCE_EXPORT_ROWS: i64 = 10_000;
pub const GOVERNANCE_EXPORT_LEASE_SECONDS: i64 =
    crate::services::governance::GOVERNANCE_EXPORT_LEASE_SECONDS;
pub const GOVERNANCE_SNAPSHOT_ISOLATION_SQL: &str =
    "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ";

use crate::services::retention_policy::{
    effective_days, policy_does_not_extend, valid_requested_days,
};
pub use crate::services::retention_policy::{
    RetentionPolicyError, RetentionPolicyLimits, UserRetentionPolicy,
};

/// Set the three account-owned retention policies in the caller's existing
/// authorization/idempotency transaction.  A normal user can only move an
/// effective cutoff earlier.  Administrators may restore or lengthen a user
/// policy, but never beyond the operator's global ceiling.
pub async fn set_user_retention_policy_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    actor_id: Uuid,
    user_id: Uuid,
    requested: UserRetentionPolicy,
    limits: RetentionPolicyLimits,
    request_id: Uuid,
) -> std::result::Result<(), RetentionPolicyError> {
    if !valid_requested_days(requested.personal_mam_days, limits.personal_mam_days, 1)
        || !valid_requested_days(
            requested.offline_message_days,
            limits.offline_message_days,
            1,
        )
        || !valid_requested_days(
            requested.moderation_evidence_days,
            limits.moderation_evidence_days,
            30,
        )
    {
        return Err(RetentionPolicyError::Forbidden);
    }
    let actor_is_admin: Option<bool> =
        sqlx::query_scalar("SELECT is_admin FROM users WHERE id=$1 FOR KEY SHARE")
            .bind(actor_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(|error| RetentionPolicyError::Internal(error.into()))?;
    let Some(actor_is_admin) = actor_is_admin else {
        return Err(RetentionPolicyError::Forbidden);
    };
    let subject_exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE id=$1)")
        .bind(user_id)
        .fetch_one(&mut **tx)
        .await
        .map_err(|error| RetentionPolicyError::Internal(error.into()))?;
    if !subject_exists {
        return Err(RetentionPolicyError::NotFound);
    }
    if actor_id != user_id && !actor_is_admin {
        return Err(RetentionPolicyError::Forbidden);
    }
    let old = sqlx::query(
        "SELECT personal_mam_days,offline_message_days,moderation_evidence_days
           FROM user_retention_policies WHERE user_id=$1 FOR UPDATE",
    )
    .bind(user_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| RetentionPolicyError::Internal(error.into()))?
    .map(|row| UserRetentionPolicy {
        personal_mam_days: row.get("personal_mam_days"),
        offline_message_days: row.get("offline_message_days"),
        moderation_evidence_days: row.get("moderation_evidence_days"),
    })
    .unwrap_or_default();
    if !actor_is_admin && !policy_does_not_extend(old, requested, limits) {
        return Err(RetentionPolicyError::Forbidden);
    }
    if requested == UserRetentionPolicy::default() {
        sqlx::query("DELETE FROM user_retention_policies WHERE user_id=$1")
            .bind(user_id)
            .execute(&mut **tx)
            .await
            .map_err(|error| RetentionPolicyError::Internal(error.into()))?;
    } else {
        sqlx::query(
            "INSERT INTO user_retention_policies(
                 user_id,personal_mam_days,offline_message_days,
                 moderation_evidence_days,updated_by,updated_at
             ) VALUES($1,$2,$3,$4,$5,clock_timestamp())
             ON CONFLICT(user_id) DO UPDATE SET
                 personal_mam_days=EXCLUDED.personal_mam_days,
                 offline_message_days=EXCLUDED.offline_message_days,
                 moderation_evidence_days=EXCLUDED.moderation_evidence_days,
                 updated_by=EXCLUDED.updated_by,updated_at=clock_timestamp()",
        )
        .bind(user_id)
        .bind(requested.personal_mam_days)
        .bind(requested.offline_message_days)
        .bind(requested.moderation_evidence_days)
        .bind(actor_id)
        .execute(&mut **tx)
        .await
        .map_err(|error| RetentionPolicyError::Internal(error.into()))?;
    }
    sqlx::query(
        "INSERT INTO audit_log(actor_id,action,target,details,request_id)
         VALUES($1,'data.retention.user.update',$2,$3,$4)",
    )
    .bind(actor_id)
    .bind(user_id.to_string())
    .bind(serde_json::json!({"previous":old,"current":requested}))
    .bind(request_id)
    .execute(&mut **tx)
    .await
    .map_err(|error| RetentionPolicyError::Internal(error.into()))?;
    Ok(())
}

pub async fn user_retention_policy_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
) -> Result<UserRetentionPolicy> {
    Ok(sqlx::query(
        "SELECT personal_mam_days,offline_message_days,moderation_evidence_days
           FROM user_retention_policies WHERE user_id=$1",
    )
    .bind(user_id)
    .fetch_optional(&mut **tx)
    .await?
    .map(|row| UserRetentionPolicy {
        personal_mam_days: row.get("personal_mam_days"),
        offline_message_days: row.get("offline_message_days"),
        moderation_evidence_days: row.get("moderation_evidence_days"),
    })
    .unwrap_or_default())
}

pub async fn muc_retention_policy_authorized_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    actor_id: Uuid,
    room_id: Uuid,
) -> std::result::Result<Option<i32>, RetentionPolicyError> {
    let row = sqlx::query(
        "SELECT policy.retention_days,
                actor.is_admin OR room.owner_id=$1 OR EXISTS(
                    SELECT 1 FROM muc_affiliations affiliation
                     WHERE affiliation.room_id=room.id AND affiliation.user_id=$1
                       AND affiliation.affiliation='owner'
                ) AS authorized
           FROM muc_rooms room
           JOIN users actor ON actor.id=$1
           LEFT JOIN muc_retention_policies policy ON policy.room_id=room.id
          WHERE room.id=$2",
    )
    .bind(actor_id)
    .bind(room_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| RetentionPolicyError::Internal(error.into()))?
    .ok_or(RetentionPolicyError::NotFound)?;
    if !row.get::<bool, _>("authorized") {
        return Err(RetentionPolicyError::Forbidden);
    }
    Ok(row.get("retention_days"))
}

/// Room retention belongs to the shared room archive.  Only a server
/// administrator or an owner affiliation may change it.  Room owners can
/// shorten the effective policy; extending/restoring it requires admin RBAC.
pub async fn set_muc_retention_policy_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    actor_id: Uuid,
    room_id: Uuid,
    requested_days: Option<i32>,
    global_days: i64,
    request_id: Uuid,
) -> std::result::Result<(), RetentionPolicyError> {
    if !valid_requested_days(requested_days, global_days, 1) {
        return Err(RetentionPolicyError::Forbidden);
    }
    let actor_is_admin: Option<bool> =
        sqlx::query_scalar("SELECT is_admin FROM users WHERE id=$1 FOR KEY SHARE")
            .bind(actor_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(|error| RetentionPolicyError::Internal(error.into()))?;
    let Some(actor_is_admin) = actor_is_admin else {
        return Err(RetentionPolicyError::Forbidden);
    };
    // Keep room and secondary-owner authority stable until the policy and its
    // replay response commit. Cluster mutations lock the room first; legacy
    // affiliation writers conflict with the exact affiliation lock below.
    let room_owner: Option<Option<Uuid>> =
        sqlx::query_scalar("SELECT owner_id FROM muc_rooms WHERE id=$1 FOR SHARE")
            .bind(room_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(|error| RetentionPolicyError::Internal(error.into()))?;
    let Some(room_owner) = room_owner else {
        return Err(RetentionPolicyError::NotFound);
    };
    if !actor_is_admin && room_owner != Some(actor_id) {
        let affiliation: Option<String> = sqlx::query_scalar(
            "SELECT affiliation FROM muc_affiliations
             WHERE room_id=$1 AND user_id=$2 FOR SHARE",
        )
        .bind(room_id)
        .bind(actor_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|error| RetentionPolicyError::Internal(error.into()))?;
        if affiliation.as_deref() != Some("owner") {
            return Err(RetentionPolicyError::Forbidden);
        }
    }
    let old: Option<i32> = sqlx::query_scalar(
        "SELECT retention_days FROM muc_retention_policies WHERE room_id=$1 FOR UPDATE",
    )
    .bind(room_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| RetentionPolicyError::Internal(error.into()))?;
    if !actor_is_admin
        && effective_days(requested_days, global_days) > effective_days(old, global_days)
    {
        return Err(RetentionPolicyError::Forbidden);
    }
    if let Some(days) = requested_days {
        sqlx::query(
            "INSERT INTO muc_retention_policies(room_id,retention_days,updated_by,updated_at)
             VALUES($1,$2,$3,clock_timestamp())
             ON CONFLICT(room_id) DO UPDATE SET retention_days=EXCLUDED.retention_days,
                 updated_by=EXCLUDED.updated_by,updated_at=clock_timestamp()",
        )
        .bind(room_id)
        .bind(days)
        .bind(actor_id)
        .execute(&mut **tx)
        .await
        .map_err(|error| RetentionPolicyError::Internal(error.into()))?;
    } else {
        sqlx::query("DELETE FROM muc_retention_policies WHERE room_id=$1")
            .bind(room_id)
            .execute(&mut **tx)
            .await
            .map_err(|error| RetentionPolicyError::Internal(error.into()))?;
    }
    sqlx::query(
        "INSERT INTO audit_log(actor_id,action,target,details,request_id)
         VALUES($1,'data.retention.muc.update',$2,$3,$4)",
    )
    .bind(actor_id)
    .bind(room_id.to_string())
    .bind(serde_json::json!({"previous_days":old,"current_days":requested_days}))
    .bind(request_id)
    .execute(&mut **tx)
    .await
    .map_err(|error| RetentionPolicyError::Internal(error.into()))?;
    Ok(())
}

#[derive(Debug)]
pub struct CreateLegalHold<'a> {
    pub id: Uuid,
    pub title: &'a str,
    pub authority_reference: &'a str,
    pub reason: &'a str,
    pub targets: &'a [LegalHoldTarget],
    pub request_id: Uuid,
}

async fn require_admin(
    tx: &mut Transaction<'_, Postgres>,
    actor_id: Uuid,
) -> std::result::Result<(), LegalHoldError> {
    let authorized: bool = sqlx::query_scalar(
        "SELECT COALESCE((SELECT is_admin AND NOT is_disabled FROM users WHERE id=$1),FALSE)",
    )
    .bind(actor_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(|error| LegalHoldError::Internal(error.into()))?;
    if !authorized {
        return Err(LegalHoldError::Forbidden);
    }
    Ok(())
}

fn valid_hold_text(input: &CreateLegalHold<'_>) -> bool {
    !input.title.trim().is_empty()
        && input.title.len() <= 1_024
        && !input.authority_reference.trim().is_empty()
        && input.authority_reference.len() <= 2_048
        && !input.reason.trim().is_empty()
        && input.reason.len() <= 16_384
        && !input.targets.is_empty()
        && input.targets.len() <= MAX_HOLD_TARGETS
}

/// Create a typed hold. Exact targets are row-locked. Controlled scopes take
/// a rare SHARE table lock, so a concurrent cleanup either finishes before
/// the hold begins or observes the committed scope; it cannot delete a row in
/// the middle of establishing the hold.
pub async fn create_legal_hold_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    actor_id: Uuid,
    input: &CreateLegalHold<'_>,
) -> std::result::Result<(), LegalHoldError> {
    require_admin(tx, actor_id).await?;
    if !valid_hold_text(input)
        || input.targets.iter().copied().collect::<HashSet<_>>().len() != input.targets.len()
    {
        return Err(LegalHoldError::Invalid);
    }
    let has_personal_scope = input
        .targets
        .iter()
        .any(|target| matches!(target, LegalHoldTarget::PersonalArchiveOwner(_)));
    let has_muc_scope = input
        .targets
        .iter()
        .any(|target| matches!(target, LegalHoldTarget::MucArchiveRoom(_)));
    let has_offline_scope = input
        .targets
        .iter()
        .any(|target| matches!(target, LegalHoldTarget::OfflineMessageRecipient(_)));
    let has_report_scope = input
        .targets
        .iter()
        .any(|target| matches!(target, LegalHoldTarget::ReportEvidenceReport(_)));
    if has_personal_scope {
        sqlx::query("LOCK TABLE message_archive IN SHARE MODE")
            .execute(&mut **tx)
            .await
            .map_err(|error| LegalHoldError::Internal(error.into()))?;
    }
    if has_muc_scope {
        sqlx::query("LOCK TABLE muc_messages IN SHARE MODE")
            .execute(&mut **tx)
            .await
            .map_err(|error| LegalHoldError::Internal(error.into()))?;
    }
    if has_offline_scope {
        sqlx::query("LOCK TABLE offline_messages IN SHARE MODE")
            .execute(&mut **tx)
            .await
            .map_err(|error| LegalHoldError::Internal(error.into()))?;
    }
    if has_report_scope {
        sqlx::query("LOCK TABLE abuse_report_evidence IN SHARE MODE")
            .execute(&mut **tx)
            .await
            .map_err(|error| LegalHoldError::Internal(error.into()))?;
    }
    let inserted = sqlx::query(
        "INSERT INTO legal_holds(
             id,title,authority_reference,reason,created_by,created_request_id
         ) VALUES($1,$2,$3,$4,$5,$6)
         ON CONFLICT(created_request_id) DO NOTHING",
    )
    .bind(input.id)
    .bind(input.title.trim())
    .bind(input.authority_reference.trim())
    .bind(input.reason.trim())
    .bind(actor_id)
    .bind(input.request_id)
    .execute(&mut **tx)
    .await
    .map_err(|error| LegalHoldError::Internal(error.into()))?
    .rows_affected();
    if inserted != 1 {
        return Err(LegalHoldError::Conflict);
    }
    for target in input.targets {
        insert_hold_target(tx, input.id, *target).await?;
    }
    let target_kinds: Vec<&'static str> = input
        .targets
        .iter()
        .map(|target| match target {
            LegalHoldTarget::PersonalArchive(_) => "personal_archive",
            LegalHoldTarget::MucArchive(_) => "muc_archive",
            LegalHoldTarget::OfflineMessage(_) => "offline_message",
            LegalHoldTarget::ReportEvidence(_) => "report_evidence",
            LegalHoldTarget::PersonalArchiveOwner(_) => "personal_archive_owner",
            LegalHoldTarget::MucArchiveRoom(_) => "muc_archive_room",
            LegalHoldTarget::OfflineMessageRecipient(_) => "offline_message_recipient",
            LegalHoldTarget::ReportEvidenceReport(_) => "report_evidence_report",
        })
        .collect();
    sqlx::query(
        "INSERT INTO audit_log(actor_id,action,target,details,request_id)
         VALUES($1,'data.legal_hold.create',$2,$3,$4)",
    )
    .bind(actor_id)
    .bind(input.id.to_string())
    .bind(serde_json::json!({"target_count":input.targets.len(),"target_kinds":target_kinds}))
    .bind(input.request_id)
    .execute(&mut **tx)
    .await
    .map_err(|error| LegalHoldError::Internal(error.into()))?;
    Ok(())
}

async fn insert_hold_target(
    tx: &mut Transaction<'_, Postgres>,
    hold_id: Uuid,
    target: LegalHoldTarget,
) -> std::result::Result<(), LegalHoldError> {
    let affected = match target {
        LegalHoldTarget::PersonalArchive(id) => {
            sqlx::query(
                "INSERT INTO legal_hold_personal_archives(
                 hold_id,archive_id,owner_id,encrypted,record_created_at)
             SELECT $1,id,owner_id,encrypted,created_at FROM message_archive
              WHERE id=$2 FOR UPDATE",
            )
            .bind(hold_id)
            .bind(id)
            .execute(&mut **tx)
            .await
        }
        LegalHoldTarget::MucArchive(id) => {
            sqlx::query(
                "INSERT INTO legal_hold_muc_archives(
                 hold_id,message_id,room_id,encrypted,record_created_at)
             SELECT $1,id,room_id,encrypted,created_at FROM muc_messages
              WHERE id=$2 FOR UPDATE",
            )
            .bind(hold_id)
            .bind(id)
            .execute(&mut **tx)
            .await
        }
        LegalHoldTarget::OfflineMessage(id) => {
            sqlx::query(
                "INSERT INTO legal_hold_offline_messages(
                 hold_id,message_id,recipient_id,encrypted,record_created_at)
             SELECT $1,id,recipient_id,encrypted,created_at FROM offline_messages
              WHERE id=$2 FOR UPDATE",
            )
            .bind(hold_id)
            .bind(id)
            .execute(&mut **tx)
            .await
        }
        LegalHoldTarget::ReportEvidence(id) => {
            sqlx::query(
                "INSERT INTO legal_hold_report_evidence(
                 hold_id,evidence_id,report_id,encrypted,record_created_at)
             SELECT $1,id,report_id,encrypted,created_at FROM abuse_report_evidence
              WHERE id=$2 FOR UPDATE",
            )
            .bind(hold_id)
            .bind(id)
            .execute(&mut **tx)
            .await
        }
        LegalHoldTarget::PersonalArchiveOwner(id) => {
            insert_scope(tx, hold_id, "personal_archive_owner", id, "users").await
        }
        LegalHoldTarget::MucArchiveRoom(id) => {
            insert_scope(tx, hold_id, "muc_archive_room", id, "muc_rooms").await
        }
        LegalHoldTarget::OfflineMessageRecipient(id) => {
            insert_scope(tx, hold_id, "offline_message_recipient", id, "users").await
        }
        LegalHoldTarget::ReportEvidenceReport(id) => {
            insert_scope(tx, hold_id, "report_evidence_report", id, "abuse_reports").await
        }
    }
    .map_err(|error| LegalHoldError::Internal(error.into()))?;
    if affected.rows_affected() != 1 {
        return Err(LegalHoldError::NotFound);
    }
    Ok(())
}

async fn insert_scope(
    tx: &mut Transaction<'_, Postgres>,
    hold_id: Uuid,
    scope_type: &'static str,
    subject_id: Uuid,
    table: &'static str,
) -> std::result::Result<sqlx::postgres::PgQueryResult, sqlx::Error> {
    debug_assert!(matches!(table, "users" | "muc_rooms" | "abuse_reports"));
    let query = format!(
        "INSERT INTO legal_hold_scopes(hold_id,scope_type,subject_id)
         SELECT $1,$2,id FROM {table} WHERE id=$3 FOR KEY SHARE"
    );
    sqlx::query(&query)
        .bind(hold_id)
        .bind(scope_type)
        .bind(subject_id)
        .execute(&mut **tx)
        .await
}

pub async fn release_legal_hold_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    actor_id: Uuid,
    hold_id: Uuid,
    reason: &str,
    request_id: Uuid,
) -> std::result::Result<(), LegalHoldError> {
    let outcome: String = sqlx::query_scalar("SELECT northstar_release_legal_hold($1,$2,$3,$4)")
        .bind(actor_id)
        .bind(hold_id)
        .bind(reason)
        .bind(request_id)
        .fetch_one(&mut **tx)
        .await
        .map_err(|error| LegalHoldError::Internal(error.into()))?;
    match outcome.as_str() {
        "released" | "replayed" => Ok(()),
        "forbidden" => Err(LegalHoldError::Forbidden),
        "not_found" => Err(LegalHoldError::NotFound),
        "conflict" => Err(LegalHoldError::Conflict),
        "invalid" => Err(LegalHoldError::Invalid),
        unexpected => Err(LegalHoldError::Internal(anyhow::anyhow!(
            "database returned unknown legal-hold release outcome: {unexpected}"
        ))),
    }
}

/// Reading governance data is itself audited. The read and access event use
/// one repeatable-read transaction, so the returned snapshot has an exact
/// audit boundary.
pub async fn list_legal_holds_audited(
    pool: &PgPool,
    actor_id: Uuid,
    expected_auth_generation: i64,
    presented_session: &str,
    active_only: bool,
    limit: i64,
    access_key_sha256: &str,
) -> std::result::Result<Vec<LegalHoldSummary>, LegalHoldError> {
    if access_key_sha256.len() != 64
        || !access_key_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(LegalHoldError::Invalid);
    }
    if !(1..=100).contains(&limit) {
        return Err(LegalHoldError::Invalid);
    }
    let mut tx = pool
        .begin()
        .await
        .map_err(|error| LegalHoldError::Internal(error.into()))?;
    sqlx::query(GOVERNANCE_SNAPSHOT_ISOLATION_SQL)
        .execute(&mut *tx)
        .await
        .map_err(|error| LegalHoldError::Internal(error.into()))?;
    if !northstar_auth_postgres::users::authorize_admin_in_tx(
        &mut tx,
        actor_id,
        expected_auth_generation,
        presented_session,
    )
    .await
    .map_err(LegalHoldError::Internal)?
    {
        tx.rollback()
            .await
            .map_err(|error| LegalHoldError::Internal(error.into()))?;
        return Err(LegalHoldError::Forbidden);
    }
    sqlx::query(
        "INSERT INTO audit_log(actor_id,action,target,details)
         VALUES($1,'data.legal_hold.view',NULL,$2)",
    )
    .bind(actor_id)
    .bind(serde_json::json!({
        "active_only":active_only,
        "limit":limit,
        "access_key_sha256":access_key_sha256
    }))
    .execute(&mut *tx)
    .await
    .map_err(|error| LegalHoldError::Internal(error.into()))?;
    let rows = sqlx::query(
        "SELECT hold.id,hold.title,hold.authority_reference,hold.reason,
                hold.created_by,hold.created_at,hold.released_by,hold.released_at,
                hold.release_reason,
                (SELECT COUNT(*) FROM (
                    SELECT archive_id FROM legal_hold_personal_archives WHERE hold_id=hold.id
                    UNION ALL SELECT message_id FROM legal_hold_muc_archives WHERE hold_id=hold.id
                    UNION ALL SELECT message_id FROM legal_hold_offline_messages WHERE hold_id=hold.id
                    UNION ALL SELECT evidence_id FROM legal_hold_report_evidence WHERE hold_id=hold.id
                    UNION ALL SELECT subject_id FROM legal_hold_scopes WHERE hold_id=hold.id
                ) targets)::BIGINT AS target_count
           FROM legal_holds hold
          WHERE (NOT $1 OR hold.released_at IS NULL)
          ORDER BY hold.created_at DESC,hold.id DESC LIMIT $2",
    )
    .bind(active_only)
    .bind(limit)
    .fetch_all(&mut *tx)
    .await
    .map_err(|error| LegalHoldError::Internal(error.into()))?;
    let output = rows
        .into_iter()
        .map(|row| LegalHoldSummary {
            id: row.get("id"),
            title: row.get("title"),
            authority_reference: row.get("authority_reference"),
            reason: row.get("reason"),
            created_by: row.get("created_by"),
            created_at: row.get("created_at"),
            released_by: row.get("released_by"),
            released_at: row.get("released_at"),
            release_reason: row.get("release_reason"),
            target_count: row.get("target_count"),
        })
        .collect();
    tx.commit()
        .await
        .map_err(|error| LegalHoldError::Internal(error.into()))?;
    Ok(output)
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[usize::from(byte >> 4)] as char);
        output.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    output
}

#[derive(Serialize)]
struct HeldRecordHashPayload<'a> {
    resource_type: &'a str,
    record_id: Uuid,
    subject_id: Uuid,
    encrypted: bool,
    record_created_at: DateTime<Utc>,
    server_visible_payload: Option<&'a str>,
    payload_disposition: &'a str,
}

fn chain_next(previous: [u8; 32], canonical: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(previous);
    hasher.update((canonical.len() as u64).to_be_bytes());
    hasher.update(canonical);
    hasher.finalize().into()
}

fn hash_optional_timestamp(hasher: &mut Sha256, value: Option<DateTime<Utc>>) {
    hasher.update([u8::from(value.is_some())]);
    if let Some(value) = value {
        hasher.update(value.timestamp_micros().to_be_bytes());
    }
}

fn legal_hold_chain_genesis(
    export_id: Uuid,
    actor_id: Uuid,
    hold_id: Uuid,
    snapshot_at: DateTime<Utc>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"northstar/legal-hold-export/v2\0");
    hasher.update(export_id.as_bytes());
    hasher.update(actor_id.as_bytes());
    hasher.update(hold_id.as_bytes());
    hasher.update(snapshot_at.timestamp_micros().to_be_bytes());
    hasher.finalize().into()
}

fn audit_chain_genesis(
    export_id: Uuid,
    actor_id: Uuid,
    snapshot_at: DateTime<Utc>,
    snapshot_max_id: i64,
    start: Option<DateTime<Utc>>,
    end: Option<DateTime<Utc>>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"northstar/audit-export/v2\0");
    hasher.update(export_id.as_bytes());
    hasher.update(actor_id.as_bytes());
    hasher.update(snapshot_at.timestamp_micros().to_be_bytes());
    hasher.update(snapshot_max_id.to_be_bytes());
    hash_optional_timestamp(&mut hasher, start);
    hash_optional_timestamp(&mut hasher, end);
    hasher.finalize().into()
}

async fn locked_hold_summary(
    tx: &mut Transaction<'_, Postgres>,
    hold_id: Uuid,
) -> std::result::Result<LegalHoldSummary, LegalHoldError> {
    let row = sqlx::query(
        "SELECT hold.id,hold.title,hold.authority_reference,hold.reason,
                hold.created_by,hold.created_at,hold.released_by,hold.released_at,
                hold.release_reason,
                (SELECT COUNT(*) FROM (
                    SELECT archive_id FROM legal_hold_personal_archives WHERE hold_id=hold.id
                    UNION ALL SELECT message_id FROM legal_hold_muc_archives WHERE hold_id=hold.id
                    UNION ALL SELECT message_id FROM legal_hold_offline_messages WHERE hold_id=hold.id
                    UNION ALL SELECT evidence_id FROM legal_hold_report_evidence WHERE hold_id=hold.id
                    UNION ALL SELECT subject_id FROM legal_hold_scopes WHERE hold_id=hold.id
                ) targets)::BIGINT AS target_count
           FROM legal_holds hold WHERE hold.id=$1 FOR UPDATE OF hold",
    )
    .bind(hold_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| LegalHoldError::Internal(error.into()))?
    .ok_or(LegalHoldError::NotFound)?;
    Ok(LegalHoldSummary {
        id: row.get("id"),
        title: row.get("title"),
        authority_reference: row.get("authority_reference"),
        reason: row.get("reason"),
        created_by: row.get("created_by"),
        created_at: row.get("created_at"),
        released_by: row.get("released_by"),
        released_at: row.get("released_at"),
        release_reason: row.get("release_reason"),
        target_count: row.get("target_count"),
    })
}

const HELD_RECORD_PAGE_SQL: &str = r#"
WITH held_records AS (
    SELECT 1::BIGINT AS resource_order,'personal_archive'::TEXT AS resource_type,
           link.archive_id AS record_id,link.owner_id AS subject_id,link.encrypted,
           link.record_created_at,archive.stanza AS payload,
           CASE WHEN archive.id IS NULL THEN 'released_record_expired'
                WHEN link.encrypted THEN 'ciphertext'
                ELSE 'server_plaintext' END::TEXT AS disposition
      FROM legal_hold_personal_archives link
      LEFT JOIN message_archive archive ON archive.id=link.archive_id
     WHERE link.hold_id=$1 AND link.record_created_at <= $2
    UNION ALL
    SELECT 1,'personal_archive',archive.id,archive.owner_id,archive.encrypted,
           archive.created_at,archive.stanza,
           CASE WHEN archive.encrypted THEN 'ciphertext' ELSE 'server_plaintext' END
      FROM legal_hold_scopes scope_link
      JOIN message_archive archive ON archive.owner_id=scope_link.subject_id
     WHERE scope_link.hold_id=$1 AND scope_link.scope_type='personal_archive_owner'
       AND archive.created_at <= $2
    UNION ALL
    SELECT 2,'muc_archive',link.message_id,link.room_id,link.encrypted,
           link.record_created_at,archive.stanza,
           CASE WHEN archive.id IS NULL THEN 'released_record_expired'
                WHEN link.encrypted THEN 'ciphertext'
                ELSE 'server_plaintext' END
      FROM legal_hold_muc_archives link
      LEFT JOIN muc_messages archive ON archive.id=link.message_id
     WHERE link.hold_id=$1 AND link.record_created_at <= $2
    UNION ALL
    SELECT 2,'muc_archive',archive.id,archive.room_id,archive.encrypted,
           archive.created_at,archive.stanza,
           CASE WHEN archive.encrypted THEN 'ciphertext' ELSE 'server_plaintext' END
      FROM legal_hold_scopes scope_link
      JOIN muc_messages archive ON archive.room_id=scope_link.subject_id
     WHERE scope_link.hold_id=$1 AND scope_link.scope_type='muc_archive_room'
       AND archive.created_at <= $2
    UNION ALL
    SELECT 3,'offline_message',link.message_id,link.recipient_id,link.encrypted,
           link.record_created_at,COALESCE(message.stanza,snapshot.stanza),
           CASE WHEN COALESCE(message.id,snapshot.message_id) IS NULL
                     THEN 'released_record_expired'
                WHEN link.encrypted THEN 'ciphertext'
                ELSE 'server_plaintext' END
      FROM legal_hold_offline_messages link
      LEFT JOIN offline_messages message ON message.id=link.message_id
      LEFT JOIN legal_hold_offline_snapshots snapshot
        ON snapshot.hold_id=link.hold_id AND snapshot.message_id=link.message_id
     WHERE link.hold_id=$1 AND link.record_created_at <= $2
    UNION ALL
    SELECT 3,'offline_message',snapshot.message_id,snapshot.recipient_id,
           snapshot.encrypted,snapshot.record_created_at,snapshot.stanza,
           CASE WHEN snapshot.encrypted THEN 'ciphertext' ELSE 'server_plaintext' END
      FROM legal_hold_offline_snapshots snapshot
     WHERE snapshot.hold_id=$1 AND snapshot.record_created_at <= $2
    UNION ALL
    SELECT 3,'offline_message',message.id,message.recipient_id,message.encrypted,
           message.created_at,message.stanza,
           CASE WHEN message.encrypted THEN 'ciphertext' ELSE 'server_plaintext' END
      FROM legal_hold_scopes scope_link
      JOIN offline_messages message ON message.recipient_id=scope_link.subject_id
     WHERE scope_link.hold_id=$1 AND scope_link.scope_type='offline_message_recipient'
       AND message.created_at <= $2
    UNION ALL
    SELECT 4,'report_evidence',link.evidence_id,link.report_id,link.encrypted,
           link.record_created_at,
           CASE WHEN evidence.encrypted THEN NULL ELSE evidence.body_text END,
           CASE WHEN evidence.id IS NULL THEN 'released_record_expired'
                WHEN evidence.encrypted THEN 'encrypted_evidence_plaintext_omitted'
                ELSE 'server_plaintext' END
      FROM legal_hold_report_evidence link
      LEFT JOIN abuse_report_evidence evidence ON evidence.id=link.evidence_id
     WHERE link.hold_id=$1 AND link.record_created_at <= $2
    UNION ALL
    SELECT 4,'report_evidence',evidence.id,evidence.report_id,evidence.encrypted,
           evidence.created_at,
           CASE WHEN evidence.encrypted THEN NULL ELSE evidence.body_text END,
           CASE WHEN evidence.encrypted THEN 'encrypted_evidence_plaintext_omitted'
                ELSE 'server_plaintext' END
      FROM legal_hold_scopes scope_link
      JOIN abuse_report_evidence evidence ON evidence.report_id=scope_link.subject_id
     WHERE scope_link.hold_id=$1 AND scope_link.scope_type='report_evidence_report'
       AND evidence.created_at <= $2
), deduplicated AS (
    SELECT DISTINCT ON(resource_order,record_id) * FROM held_records
     ORDER BY resource_order,record_id,payload NULLS LAST,disposition
)
SELECT resource_order,resource_type,record_id,subject_id,encrypted,
       record_created_at,payload,disposition
  FROM deduplicated
 WHERE $3::BIGINT IS NULL
    OR (resource_order,record_created_at,record_id) > ($3,$4,$5)
 ORDER BY resource_order,record_created_at,record_id
 LIMIT $6
"#;

/// Export one immutable page.  The initial active-hold page briefly locks all
/// four source tables, chooses a database-time cutoff, and creates a
/// non-renewable lease.  Hold release and payload cleanup are then fenced until
/// the final page completes or the lease/cursor expires.
pub async fn export_legal_hold_page_in_tx(
    transaction: &mut Transaction<'_, Postgres>,
    actor_id: Uuid,
    hold_id: Uuid,
    max_rows: i64,
    initial_export_id: Uuid,
    continuation: Option<LegalHoldExportCursor>,
    access_request_id: Uuid,
) -> std::result::Result<LegalHoldExport, LegalHoldError> {
    let max_rows = max_rows.clamp(1, MAX_GOVERNANCE_EXPORT_ROWS);
    require_admin(transaction, actor_id).await?;
    let hold = locked_hold_summary(transaction, hold_id).await?;
    let active = hold.released_at.is_none();

    let (
        export_id,
        snapshot_at,
        lease_expires_at,
        after_order,
        after_created_at,
        after_record_id,
        mut previous,
    ) = if let Some(cursor) = continuation {
        if !active {
            return Err(LegalHoldError::InvalidCursor);
        }
        let database_now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut **transaction)
            .await
            .map_err(|error| LegalHoldError::Internal(error.into()))?;
        let lease = sqlx::query(
            "SELECT actor_id,hold_id,snapshot_at,expires_at,completed_at
               FROM governance_export_leases
              WHERE id=$1 AND export_kind='legal_hold' FOR UPDATE",
        )
        .bind(cursor.export_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|error| LegalHoldError::Internal(error.into()))?
        .ok_or(LegalHoldError::InvalidCursor)?;
        let lease_snapshot: DateTime<Utc> = lease.get("snapshot_at");
        let expires_at: DateTime<Utc> = lease.get("expires_at");
        if lease.get::<Uuid, _>("actor_id") != actor_id
            || lease.get::<Option<Uuid>, _>("hold_id") != Some(hold_id)
            || lease_snapshot != cursor.snapshot_at
            || lease
                .get::<Option<DateTime<Utc>>, _>("completed_at")
                .is_some()
            || database_now >= expires_at
            || !(1..=4).contains(&cursor.after_resource_order)
        {
            return Err(LegalHoldError::InvalidCursor);
        }
        (
            cursor.export_id,
            lease_snapshot,
            Some(expires_at),
            Some(cursor.after_resource_order),
            Some(cursor.after_created_at),
            Some(cursor.after_record_id),
            cursor.chain_root,
        )
    } else {
        if active {
            // This barrier closes the "backdated uncommitted row" window:
            // every pre-cutoff writer commits before snapshot_at and later
            // writers receive a later database timestamp.
            sqlx::query(
                "LOCK TABLE message_archive,muc_messages,offline_messages,
                            abuse_report_evidence IN SHARE MODE",
            )
            .execute(&mut **transaction)
            .await
            .map_err(|error| LegalHoldError::Internal(error.into()))?;
        }
        let snapshot_at: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut **transaction)
            .await
            .map_err(|error| LegalHoldError::Internal(error.into()))?;
        let expires_at =
            active.then(|| snapshot_at + Duration::seconds(GOVERNANCE_EXPORT_LEASE_SECONDS));
        if let Some(expires_at) = expires_at {
            sqlx::query(
                "INSERT INTO governance_export_leases(
                     id,export_kind,actor_id,hold_id,snapshot_at,expires_at
                 ) VALUES($1,'legal_hold',$2,$3,$4,$5)",
            )
            .bind(initial_export_id)
            .bind(actor_id)
            .bind(hold_id)
            .bind(snapshot_at)
            .bind(expires_at)
            .execute(&mut **transaction)
            .await
            .map_err(|error| LegalHoldError::Internal(error.into()))?;
        }
        (
            initial_export_id,
            snapshot_at,
            expires_at,
            None,
            None,
            None,
            legal_hold_chain_genesis(initial_export_id, actor_id, hold_id, snapshot_at),
        )
    };
    let chain_start = previous;
    let rows = sqlx::query(HELD_RECORD_PAGE_SQL)
        .bind(hold_id)
        .bind(snapshot_at)
        .bind(after_order)
        .bind(after_created_at)
        .bind(after_record_id)
        .bind(max_rows + 1)
        .fetch_all(&mut **transaction)
        .await
        .map_err(|error| LegalHoldError::Internal(error.into()))?;
    let has_more = rows.len() as i64 > max_rows;
    if !active && has_more {
        // Released payload is no longer fenced.  Returning a cursor would
        // falsely promise a stable second page.
        return Err(LegalHoldError::Conflict);
    }
    let mut records = Vec::with_capacity(rows.len().min(max_rows as usize));
    let mut last_key = None;
    for row in rows.into_iter().take(max_rows as usize) {
        let resource_order: i64 = row.get("resource_order");
        let resource_type: String = row.get("resource_type");
        let record_id = row.get("record_id");
        let subject_id = row.get("subject_id");
        let encrypted = row.get("encrypted");
        let record_created_at = row.get("record_created_at");
        let payload: Option<String> = row.get("payload");
        let disposition: String = row.get("disposition");
        let canonical = serde_json::to_vec(&HeldRecordHashPayload {
            resource_type: &resource_type,
            record_id,
            subject_id,
            encrypted,
            record_created_at,
            server_visible_payload: payload.as_deref(),
            payload_disposition: &disposition,
        })
        .context("could not canonicalize legal-hold export row")
        .map_err(LegalHoldError::Internal)?;
        let next_hash = chain_next(previous, &canonical);
        records.push(HeldRecordExport {
            resource_type,
            record_id,
            subject_id,
            encrypted,
            record_created_at,
            server_visible_payload: payload,
            payload_disposition: disposition,
            previous_hash: hex(&previous),
            entry_hash: hex(&next_hash),
        });
        previous = next_hash;
        last_key = Some((resource_order, record_created_at, record_id));
    }
    sqlx::query(
        "INSERT INTO audit_log(actor_id,action,target,details,request_id)
         VALUES($1,'data.legal_hold.export',$2,$3,$4)",
    )
    .bind(actor_id)
    .bind(hold_id.to_string())
    .bind(serde_json::json!({
        "export_id":export_id,"snapshot_at":snapshot_at,"max_rows":max_rows,
        "after_resource_order":after_order,"after_created_at":after_created_at,
        "after_record_id":after_record_id,"complete":!has_more
    }))
    .bind(access_request_id)
    .execute(&mut **transaction)
    .await
    .map_err(|error| LegalHoldError::Internal(error.into()))?;
    if active && !has_more {
        let completed = sqlx::query(
            "UPDATE governance_export_leases SET completed_at=clock_timestamp()
              WHERE id=$1 AND completed_at IS NULL AND expires_at > clock_timestamp()",
        )
        .bind(export_id)
        .execute(&mut **transaction)
        .await
        .map_err(|error| LegalHoldError::Internal(error.into()))?
        .rows_affected();
        if completed != 1 {
            return Err(LegalHoldError::InvalidCursor);
        }
    }
    let next = if has_more {
        let (resource_order, record_created_at, record_id) =
            last_key.ok_or(LegalHoldError::Internal(anyhow::anyhow!(
                "legal-hold page has continuation without a boundary"
            )))?;
        Some(LegalHoldExportCursor {
            export_id,
            after_resource_order: resource_order,
            after_created_at: record_created_at,
            after_record_id: record_id,
            snapshot_at,
            chain_root: previous,
        })
    } else {
        None
    };
    Ok(LegalHoldExport {
        format: "northstar-legal-hold-chain-v2",
        export_id,
        exported_at: sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut **transaction)
            .await
            .map_err(|error| LegalHoldError::Internal(error.into()))?,
        snapshot_at,
        lease_expires_at,
        hold,
        records,
        chain_start_sha256: hex(&chain_start),
        chain_root_sha256: hex(&previous),
        complete: !has_more,
        truncated: has_more,
        next,
    })
}

#[derive(Serialize)]
struct AuditHashPayload<'a> {
    id: i64,
    actor_id: Option<Uuid>,
    action: &'a str,
    target: Option<&'a str>,
    details: &'a serde_json::Value,
    ip_address: Option<&'a str>,
    request_id: Option<Uuid>,
    operation_id: Option<Uuid>,
    created_at: DateTime<Utc>,
}

const AUDIT_EXPORT_PAGE_SQL: &str = r#"
SELECT id,actor_id,action,target,details,ip_address::TEXT AS ip_address,
       request_id,operation_id,created_at
  FROM audit_log
 WHERE ($1::TIMESTAMPTZ IS NULL OR created_at >= $1)
   AND ($2::TIMESTAMPTZ IS NULL OR created_at < $2)
   AND id > $3 AND id <= $4
   AND NOT (
       action='data.audit.export'
       AND target IS NOT DISTINCT FROM $5::TEXT
   )
 ORDER BY id LIMIT $6
"#;

/// Produce one keyset page from a fixed high-water mark.  Initial creation
/// takes a short SHARE table lock so every previously allocated audit id has
/// either committed or rolled back before `snapshot_max_id` is chosen.  The
/// access event for this page is inserted afterwards and therefore cannot
/// enter its own export.
pub struct AuditExportPageRequest {
    pub actor_id: Uuid,
    pub start: Option<DateTime<Utc>>,
    pub end: Option<DateTime<Utc>>,
    pub max_rows: i64,
    pub initial_export_id: Uuid,
    pub continuation: Option<AuditExportCursor>,
    pub access_request_id: Uuid,
}

pub async fn export_audit_log_page_in_tx(
    transaction: &mut Transaction<'_, Postgres>,
    request: AuditExportPageRequest,
) -> std::result::Result<AuditExport, LegalHoldError> {
    let AuditExportPageRequest {
        actor_id,
        start,
        end,
        max_rows,
        initial_export_id,
        continuation,
        access_request_id,
    } = request;
    let max_rows = max_rows.clamp(1, MAX_GOVERNANCE_EXPORT_ROWS);
    require_admin(transaction, actor_id).await?;
    if start.zip(end).is_some_and(|(start, end)| start >= end) {
        return Err(LegalHoldError::Invalid);
    }
    let (export_id, snapshot_at, snapshot_max_id, expires_at, after_id, mut previous) =
        if let Some(cursor) = continuation {
            let database_now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
                .fetch_one(&mut **transaction)
                .await
                .map_err(|error| LegalHoldError::Internal(error.into()))?;
            let lease = sqlx::query(
                "SELECT actor_id,filter_start,filter_end,snapshot_at,snapshot_max_id,
                        expires_at,completed_at
                   FROM governance_export_leases
                  WHERE id=$1 AND export_kind='audit' FOR UPDATE",
            )
            .bind(cursor.export_id)
            .fetch_optional(&mut **transaction)
            .await
            .map_err(|error| LegalHoldError::Internal(error.into()))?
            .ok_or(LegalHoldError::InvalidCursor)?;
            let lease_snapshot: DateTime<Utc> = lease.get("snapshot_at");
            let lease_max: i64 = lease.get("snapshot_max_id");
            let lease_expires: DateTime<Utc> = lease.get("expires_at");
            if lease.get::<Uuid, _>("actor_id") != actor_id
                || lease.get::<Option<DateTime<Utc>>, _>("filter_start") != start
                || lease.get::<Option<DateTime<Utc>>, _>("filter_end") != end
                || lease_snapshot != cursor.snapshot_at
                || lease_max != cursor.snapshot_max_id
                || cursor.after_id < 0
                || cursor.after_id > lease_max
                || lease
                    .get::<Option<DateTime<Utc>>, _>("completed_at")
                    .is_some()
                || database_now >= lease_expires
            {
                return Err(LegalHoldError::InvalidCursor);
            }
            (
                cursor.export_id,
                lease_snapshot,
                lease_max,
                lease_expires,
                cursor.after_id,
                cursor.chain_root,
            )
        } else {
            // SHARE conflicts with INSERT/DELETE table locks. It is held only
            // for this bounded first page and eliminates uncommitted lower-id
            // rows from a later continuation snapshot. Serialize initial
            // exporters first so two compatible SHARE holders never deadlock
            // while each upgrades itself to insert its access-audit row.
            sqlx::query("SELECT pg_advisory_xact_lock(1314079572,2)")
                .execute(&mut **transaction)
                .await
                .map_err(|error| LegalHoldError::Internal(error.into()))?;
            sqlx::query("LOCK TABLE audit_log IN SHARE MODE")
                .execute(&mut **transaction)
                .await
                .map_err(|error| LegalHoldError::Internal(error.into()))?;
            let snapshot_at: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
                .fetch_one(&mut **transaction)
                .await
                .map_err(|error| LegalHoldError::Internal(error.into()))?;
            let snapshot_max_id: i64 = sqlx::query_scalar(
                "SELECT COALESCE(MAX(id),0)::BIGINT FROM audit_log
                  WHERE ($1::TIMESTAMPTZ IS NULL OR created_at >= $1)
                    AND ($2::TIMESTAMPTZ IS NULL OR created_at < $2)",
            )
            .bind(start)
            .bind(end)
            .fetch_one(&mut **transaction)
            .await
            .map_err(|error| LegalHoldError::Internal(error.into()))?;
            let expires_at = snapshot_at + Duration::seconds(GOVERNANCE_EXPORT_LEASE_SECONDS);
            sqlx::query(
                "INSERT INTO governance_export_leases(
                     id,export_kind,actor_id,filter_start,filter_end,snapshot_at,
                     snapshot_max_id,expires_at
                 ) VALUES($1,'audit',$2,$3,$4,$5,$6,$7)",
            )
            .bind(initial_export_id)
            .bind(actor_id)
            .bind(start)
            .bind(end)
            .bind(snapshot_at)
            .bind(snapshot_max_id)
            .bind(expires_at)
            .execute(&mut **transaction)
            .await
            .map_err(|error| LegalHoldError::Internal(error.into()))?;
            (
                initial_export_id,
                snapshot_at,
                snapshot_max_id,
                expires_at,
                0,
                audit_chain_genesis(
                    initial_export_id,
                    actor_id,
                    snapshot_at,
                    snapshot_max_id,
                    start,
                    end,
                ),
            )
        };
    let chain_start = previous;
    sqlx::query(
        "INSERT INTO audit_log(actor_id,action,target,details,request_id)
         VALUES($1,'data.audit.export',$2,$3,$4)",
    )
    .bind(actor_id)
    .bind(export_id.to_string())
    .bind(serde_json::json!({
        "export_id":export_id,"start":start,"end":end,"max_rows":max_rows,
        "after_id":after_id,"snapshot_at":snapshot_at,
        "snapshot_max_id":snapshot_max_id
    }))
    .bind(access_request_id)
    .execute(&mut **transaction)
    .await
    .map_err(|error| LegalHoldError::Internal(error.into()))?;
    let rows = sqlx::query(AUDIT_EXPORT_PAGE_SQL)
        .bind(start)
        .bind(end)
        .bind(after_id)
        .bind(snapshot_max_id)
        // The high-water mark already excludes normally allocated access-event
        // IDs.  Binding the fresh export UUID here makes that invariant explicit
        // even if a database owner has moved the sequence behind existing rows.
        .bind(export_id.to_string())
        .bind(max_rows + 1)
        .fetch_all(&mut **transaction)
        .await
        .map_err(|error| LegalHoldError::Internal(error.into()))?;
    let has_more = rows.len() as i64 > max_rows;
    let mut entries = Vec::with_capacity(rows.len().min(max_rows as usize));
    for row in rows.into_iter().take(max_rows as usize) {
        let id = row.get("id");
        let actor_id = row.get("actor_id");
        let action: String = row.get("action");
        let target: Option<String> = row.get("target");
        let details: serde_json::Value = row.get("details");
        let ip_address: Option<String> = row.get("ip_address");
        let request_id = row.get("request_id");
        let operation_id = row.get("operation_id");
        let created_at = row.get("created_at");
        let payload = serde_json::to_vec(&AuditHashPayload {
            id,
            actor_id,
            action: &action,
            target: target.as_deref(),
            details: &details,
            ip_address: ip_address.as_deref(),
            request_id,
            operation_id,
            created_at,
        })
        .context("could not canonicalize audit export row")
        .map_err(LegalHoldError::Internal)?;
        let next = chain_next(previous, &payload);
        entries.push(AuditExportEntry {
            id,
            actor_id,
            action,
            target,
            details,
            ip_address,
            request_id,
            operation_id,
            created_at,
            previous_hash: hex(&previous),
            entry_hash: hex(&next),
        });
        previous = next;
    }
    if !has_more {
        let completed = sqlx::query(
            "UPDATE governance_export_leases SET completed_at=clock_timestamp()
              WHERE id=$1 AND completed_at IS NULL AND expires_at > clock_timestamp()",
        )
        .bind(export_id)
        .execute(&mut **transaction)
        .await
        .map_err(|error| LegalHoldError::Internal(error.into()))?
        .rows_affected();
        if completed != 1 {
            return Err(LegalHoldError::InvalidCursor);
        }
    }
    let next = if has_more {
        Some(AuditExportCursor {
            export_id,
            after_id: entries.last().map(|entry| entry.id).ok_or_else(|| {
                LegalHoldError::Internal(anyhow::anyhow!(
                    "audit page has continuation without a boundary"
                ))
            })?,
            snapshot_max_id,
            snapshot_at,
            chain_root: previous,
        })
    } else {
        None
    };
    Ok(AuditExport {
        format: "northstar-audit-chain-v2",
        export_id,
        exported_at: sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut **transaction)
            .await
            .map_err(|error| LegalHoldError::Internal(error.into()))?,
        snapshot_at,
        snapshot_max_id,
        lease_expires_at: expires_at,
        first_id: entries.first().map(|entry| entry.id),
        last_id: entries.last().map(|entry| entry.id),
        entries,
        chain_start_sha256: hex(&chain_start),
        chain_root_sha256: hex(&previous),
        complete: !has_more,
        truncated: has_more,
        next,
    })
}

pub async fn purge_audit_log_batch(
    pool: &PgPool,
    retention_days: i64,
    batch_size: i64,
) -> Result<u64> {
    let retention_days = i32::try_from(retention_days).context("audit retention exceeds i32")?;
    let removed: i64 = sqlx::query_scalar("SELECT northstar_purge_audit_log($1,$2)")
        .bind(retention_days)
        .bind(i32::try_from(batch_size.clamp(1, 10_000)).unwrap_or(10_000))
        .fetch_one(pool)
        .await?;
    Ok(u64::try_from(removed).unwrap_or(0))
}

pub async fn purge_released_hold_snapshots_batch(
    pool: &PgPool,
    global_retention_days: i64,
    batch_size: i64,
) -> Result<u64> {
    let retention_days =
        i32::try_from(global_retention_days).context("offline retention exceeds i32")?;
    let removed: i64 =
        sqlx::query_scalar("SELECT northstar_purge_released_hold_offline_snapshots($1,$2)")
            .bind(retention_days)
            .bind(i32::try_from(batch_size.clamp(1, 10_000)).unwrap_or(10_000))
            .fetch_one(pool)
            .await?;
    Ok(u64::try_from(removed).unwrap_or(0))
}

pub async fn purge_governance_export_leases_batch(
    pool: &PgPool,
    retention_days: i64,
    batch_size: i64,
) -> Result<u64> {
    let retention_days =
        i32::try_from(retention_days).context("governance export retention exceeds i32")?;
    let removed: i64 = sqlx::query_scalar("SELECT northstar_purge_governance_export_leases($1,$2)")
        .bind(retention_days)
        .bind(i32::try_from(batch_size.clamp(1, 10_000)).unwrap_or(10_000))
        .fetch_one(pool)
        .await?;
    Ok(u64::try_from(removed).unwrap_or(0))
}

#[cfg(test)]
mod tests;
