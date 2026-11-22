//! Legal hold creation, release, and audited listing.

use super::{require_admin, LegalHoldError, LegalHoldSummary, LegalHoldTarget, MAX_HOLD_TARGETS};
use sqlx::{Postgres, Row, Transaction};
use std::collections::HashSet;
use uuid::Uuid;

#[derive(Debug)]
pub struct CreateLegalHold<'a> {
    pub id: Uuid,
    pub title: &'a str,
    pub authority_reference: &'a str,
    pub reason: &'a str,
    pub targets: &'a [LegalHoldTarget],
    pub request_id: Uuid,
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
    sqlx::query(sqlx::AssertSqlSafe(query.as_str()))
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

/// The bounds of an audited legal hold listing, checked before the listing's transaction opens.
pub fn validate_legal_hold_listing(
    limit: i64,
    access_key_sha256: &str,
) -> std::result::Result<(), LegalHoldError> {
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
    Ok(())
}

/// Reading governance data is itself audited. The caller's repeatable-read
/// transaction gives the returned snapshot an exact audit boundary.
pub async fn list_legal_holds_audited_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    actor_id: Uuid,
    active_only: bool,
    limit: i64,
    access_key_sha256: &str,
) -> std::result::Result<Vec<LegalHoldSummary>, LegalHoldError> {
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
    .execute(&mut **tx)
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
    .fetch_all(&mut **tx)
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
    Ok(output)
}
