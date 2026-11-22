//! Paginated export of an audit log snapshot.

use super::{
    chain_next, hash_optional_timestamp, hex, require_admin, AuditExport, AuditExportCursor,
    AuditExportEntry, LegalHoldError, GOVERNANCE_EXPORT_LEASE_SECONDS, MAX_GOVERNANCE_EXPORT_ROWS,
};
use anyhow::Context;
use northstar_time::{DateTime, Duration, Utc};
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

pub(super) fn audit_chain_genesis(
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

pub(super) const AUDIT_EXPORT_PAGE_SQL: &str = r#"
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
