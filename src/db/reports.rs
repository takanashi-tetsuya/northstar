use crate::auth;
use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use sqlx::Row;
use uuid::Uuid;

pub async fn moderation_counts(pool: &PgPool) -> Result<(i64, i64, i64)> {
    let pending_reports = sqlx::query_scalar(
        "SELECT COUNT(*) FROM abuse_reports WHERE status IN ('submitted','reviewing')",
    )
    .fetch_one(pool)
    .await?;
    let pending_appeals = sqlx::query_scalar(
        "SELECT COUNT(*) FROM abuse_appeals WHERE status IN ('submitted','reviewing')",
    )
    .fetch_one(pool)
    .await?;
    let active_invitations = sqlx::query_scalar(
        "SELECT COUNT(*) FROM invitation_tokens WHERE revoked_at IS NULL AND (expires_at IS NULL OR expires_at > NOW()) AND use_count < max_uses",
    )
    .fetch_one(pool)
    .await?;
    Ok((pending_reports, pending_appeals, active_invitations))
}

#[derive(Debug)]
pub struct ReportEvidenceInput {
    pub client_message_id: Option<String>,
    pub sender_jid: String,
    pub sent_at: Option<DateTime<Utc>>,
    pub body_text: String,
    pub encrypted: bool,
}

pub async fn create_invitation(
    pool: &PgPool,
    actor_id: Uuid,
    label: &str,
    max_uses: i32,
    expires_at: Option<DateTime<Utc>>,
) -> Result<(Uuid, String)> {
    let token = auth::new_session_token();
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO invitation_tokens (id, token_hash, label, created_by, max_uses, expires_at) VALUES ($1, $2, $3, $4, $5, $6)")
        .bind(id).bind(auth::token_hash(&token)).bind(label).bind(actor_id).bind(max_uses).bind(expires_at)
        .execute(pool).await?;
    Ok((id, token))
}

pub async fn list_invitations(pool: &PgPool) -> Result<Vec<serde_json::Value>> {
    let rows = sqlx::query("SELECT i.id, i.label, i.max_uses, i.use_count, i.expires_at, i.revoked_at, i.created_at, u.username AS created_by FROM invitation_tokens i LEFT JOIN users u ON u.id = i.created_by ORDER BY i.created_at DESC LIMIT 200")
        .fetch_all(pool).await?;
    Ok(rows
        .iter()
        .map(|row| {
            serde_json::json!({
                "id":row.get::<Uuid,_>("id"), "label":row.get::<String,_>("label"),
                "max_uses":row.get::<i32,_>("max_uses"), "use_count":row.get::<i32,_>("use_count"),
                "expires_at":row.get::<Option<DateTime<Utc>>,_>("expires_at"),
                "revoked_at":row.get::<Option<DateTime<Utc>>,_>("revoked_at"),
                "created_at":row.get::<DateTime<Utc>,_>("created_at"),
                "created_by":row.get::<Option<String>,_>("created_by"),
            })
        })
        .collect())
}

pub async fn revoke_invitation(pool: &PgPool, id: Uuid) -> Result<bool> {
    Ok(sqlx::query(
        "UPDATE invitation_tokens SET revoked_at = COALESCE(revoked_at, NOW()) WHERE id = $1",
    )
    .bind(id)
    .execute(pool)
    .await?
    .rows_affected()
        == 1)
}

pub async fn create_report(
    pool: &PgPool,
    reporter_id: Uuid,
    reported_jid: &str,
    category: &str,
    description: &str,
    evidence: &[ReportEvidenceInput],
) -> Result<Uuid> {
    let id = Uuid::new_v4();
    let mut tx = pool.begin().await?;
    sqlx::query("INSERT INTO abuse_reports (id, reporter_id, reported_jid, category, description) VALUES ($1, $2, $3, $4, $5)")
        .bind(id).bind(reporter_id).bind(reported_jid).bind(category).bind(description)
        .execute(&mut *tx).await?;
    for (position, item) in evidence.iter().enumerate() {
        sqlx::query("INSERT INTO abuse_report_evidence (id, report_id, client_message_id, sender_jid, sent_at, body_text, encrypted, position) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)")
            .bind(Uuid::new_v4()).bind(id).bind(&item.client_message_id).bind(&item.sender_jid)
            .bind(item.sent_at).bind(&item.body_text).bind(item.encrypted).bind(position as i32)
            .execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(id)
}

pub async fn create_appeal(
    pool: &PgPool,
    report_id: Uuid,
    appellant_id: Uuid,
    reason: &str,
) -> Result<Uuid> {
    let id = Uuid::new_v4();
    let inserted = sqlx::query(
        "INSERT INTO abuse_appeals (id, report_id, appellant_id, reason) SELECT $1, r.id, $2, $3 FROM abuse_reports r WHERE r.id = $4 AND r.reporter_id = $2 AND r.status IN ('actioned','rejected','closed') ON CONFLICT (report_id) DO NOTHING",
    )
    .bind(id).bind(appellant_id).bind(reason).bind(report_id).execute(pool).await?.rows_affected();
    if inserted != 1 {
        anyhow::bail!("report cannot be appealed, is not resolved, or already has an appeal");
    }
    Ok(id)
}

pub async fn list_reports(
    pool: &PgPool,
    reporter_id: Option<Uuid>,
    limit: i64,
) -> Result<Vec<serde_json::Value>> {
    let rows = sqlx::query(
        "SELECT r.id, r.reporter_id, reporter.username AS reporter_username, r.reported_jid, r.category, r.description, r.status, r.resolution, r.resolved_at, r.created_at, r.updated_at, admin.username AS assigned_admin, COALESCE((SELECT jsonb_agg(jsonb_build_object('id',e.id,'client_message_id',e.client_message_id,'sender_jid',e.sender_jid,'sent_at',e.sent_at,'body_text',e.body_text,'encrypted',e.encrypted,'position',e.position) ORDER BY e.position) FROM abuse_report_evidence e WHERE e.report_id=r.id),'[]'::jsonb) AS evidence, (SELECT jsonb_build_object('id',a.id,'reason',a.reason,'status',a.status,'resolution',a.resolution,'created_at',a.created_at,'updated_at',a.updated_at) FROM abuse_appeals a WHERE a.report_id=r.id) AS appeal FROM abuse_reports r JOIN users reporter ON reporter.id=r.reporter_id LEFT JOIN users admin ON admin.id=r.assigned_admin_id WHERE ($1::uuid IS NULL OR r.reporter_id=$1) ORDER BY CASE r.status WHEN 'submitted' THEN 0 WHEN 'reviewing' THEN 1 ELSE 2 END, r.created_at DESC LIMIT $2",
    ).bind(reporter_id).bind(limit.clamp(1, 200)).fetch_all(pool).await?;
    Ok(rows.iter().map(report_json).collect())
}

pub async fn admin_update_report(
    pool: &PgPool,
    id: Uuid,
    actor_id: Uuid,
    status: &str,
    resolution: &str,
) -> Result<bool> {
    Ok(sqlx::query("UPDATE abuse_reports SET status=$3, resolution=$4, assigned_admin_id=$2, resolved_at=CASE WHEN $3 IN ('actioned','rejected','closed') THEN NOW() ELSE NULL END, updated_at=NOW() WHERE id=$1")
        .bind(id).bind(actor_id).bind(status).bind(resolution).execute(pool).await?.rows_affected() == 1)
}

pub async fn admin_update_appeal(
    pool: &PgPool,
    id: Uuid,
    actor_id: Uuid,
    status: &str,
    resolution: &str,
) -> Result<bool> {
    Ok(sqlx::query("UPDATE abuse_appeals SET status=$3, resolution=$4, assigned_admin_id=$2, resolved_at=CASE WHEN $3 IN ('upheld','denied') THEN NOW() ELSE NULL END, updated_at=NOW() WHERE id=$1")
        .bind(id).bind(actor_id).bind(status).bind(resolution).execute(pool).await?.rows_affected() == 1)
}

fn report_json(row: &sqlx::postgres::PgRow) -> serde_json::Value {
    serde_json::json!({
        "id":row.get::<Uuid,_>("id"), "reporter_id":row.get::<Uuid,_>("reporter_id"),
        "reporter_username":row.get::<String,_>("reporter_username"), "reported_jid":row.get::<String,_>("reported_jid"),
        "category":row.get::<String,_>("category"), "description":row.get::<String,_>("description"),
        "status":row.get::<String,_>("status"), "resolution":row.get::<Option<String>,_>("resolution"),
        "resolved_at":row.get::<Option<DateTime<Utc>>,_>("resolved_at"), "created_at":row.get::<DateTime<Utc>,_>("created_at"),
        "updated_at":row.get::<DateTime<Utc>,_>("updated_at"), "assigned_admin":row.get::<Option<String>,_>("assigned_admin"),
        "evidence":row.get::<serde_json::Value,_>("evidence"), "appeal":row.get::<Option<serde_json::Value>,_>("appeal"),
    })
}

pub async fn audit(
    pool: &PgPool,
    actor: Option<Uuid>,
    action: &str,
    target: Option<&str>,
    details: serde_json::Value,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO audit_log (actor_id, action, target, details) VALUES ($1, $2, $3, $4)",
    )
    .bind(actor)
    .bind(action)
    .bind(target)
    .bind(details)
    .execute(pool)
    .await?;
    Ok(())
}
