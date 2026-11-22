use anyhow::{Context, Result};
pub use northstar_operations_application::governance::{
    AuditExport, AuditExportCursor, AuditExportEntry, HeldRecordExport, LegalHoldError,
    LegalHoldExport, LegalHoldExportCursor, LegalHoldSummary, LegalHoldTarget,
};
use northstar_time::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Row, Transaction};
#[cfg(test)]
use std::collections::HashSet;
use uuid::Uuid;

mod audit_export;
mod held_record_export;
mod legal_hold;

pub use self::audit_export::{export_audit_log_page_in_tx, AuditExportPageRequest};
pub use self::held_record_export::export_legal_hold_page_in_tx;
pub use self::legal_hold::{
    create_legal_hold_in_tx, list_legal_holds_audited_in_tx, release_legal_hold_in_tx,
    validate_legal_hold_listing, CreateLegalHold,
};

#[cfg(test)]
use self::audit_export::{audit_chain_genesis, AUDIT_EXPORT_PAGE_SQL};
#[cfg(test)]
use self::held_record_export::HELD_RECORD_PAGE_SQL;

pub const MAX_HOLD_TARGETS: usize = 1_000;
pub const MAX_GOVERNANCE_EXPORT_ROWS: i64 = 10_000;
pub const GOVERNANCE_EXPORT_LEASE_SECONDS: i64 =
    northstar_operations_application::governance::GOVERNANCE_EXPORT_LEASE_SECONDS;
pub const GOVERNANCE_SNAPSHOT_ISOLATION_SQL: &str =
    "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ";

use northstar_operations_application::retention_policy::{
    effective_days, policy_does_not_extend, valid_requested_days,
};
pub use northstar_operations_application::retention_policy::{
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

pub(super) async fn require_admin(
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

pub(super) fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[usize::from(byte >> 4)] as char);
        output.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    output
}

pub(super) fn chain_next(previous: [u8; 32], canonical: &[u8]) -> [u8; 32] {
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
#[path = "data_lifecycle_tests.rs"]
mod tests;
