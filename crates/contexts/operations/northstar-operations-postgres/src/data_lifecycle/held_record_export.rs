//! Paginated export of records subject to a legal hold.

use super::{
    chain_next, hex, require_admin, HeldRecordExport, LegalHoldError, LegalHoldExport,
    LegalHoldExportCursor, LegalHoldSummary, GOVERNANCE_EXPORT_LEASE_SECONDS,
    MAX_GOVERNANCE_EXPORT_ROWS,
};
use anyhow::Context;
use northstar_time::{DateTime, Duration, Utc};
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

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

pub(super) const HELD_RECORD_PAGE_SQL: &str = r#"
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
