use crate::auth;
pub use crate::services::reports::ReportEvidenceInput;
use anyhow::Result;
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use sqlx::Row;
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum AppealCreateError {
    #[error("report cannot be appealed, is not resolved, or already has an appeal")]
    Conflict,
    #[error("appeal backend failed")]
    Internal(#[source] anyhow::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum ReportCreateError {
    #[error("report evidence is not an archived message owned by the reporter and associated with the reported JID")]
    InvalidEvidence(&'static str),
    #[error("report backend failed")]
    Internal(#[source] anyhow::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum ModerationUpdateError {
    #[error("moderation record does not exist")]
    NotFound,
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "production handlers retain the fail-closed match arm although authorization is performed before this repository call"
        )
    )]
    #[error("administrator authorization changed")]
    Unauthorized,
    #[error("moderation status transition is not allowed")]
    InvalidTransition,
    #[error("moderation backend failed")]
    Internal(#[source] anyhow::Error),
}

pub async fn moderation_counts_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(i64, i64, i64)> {
    let pending_reports = sqlx::query_scalar(
        "SELECT COUNT(*) FROM abuse_reports WHERE status IN ('submitted','reviewing')",
    )
    .fetch_one(&mut **tx)
    .await?;
    let pending_appeals = sqlx::query_scalar(
        "SELECT COUNT(*) FROM abuse_appeals WHERE status IN ('submitted','reviewing')",
    )
    .fetch_one(&mut **tx)
    .await?;
    let active_invitations = sqlx::query_scalar(
        "SELECT COUNT(*) FROM invitation_tokens WHERE revoked_at IS NULL AND (expires_at IS NULL OR expires_at > NOW()) AND use_count < max_uses",
    )
    .fetch_one(&mut **tx)
    .await?;
    Ok((pending_reports, pending_appeals, active_invitations))
}

/// Purge a bounded batch of completed moderation cases. Evidence and appeals
/// cascade with the report; pending reports and pending/reviewing appeals are
/// never eligible. Audit rows intentionally remain as a content-free action
/// trail after the copied message material has expired.
pub async fn purge_resolved_moderation_batch(
    pool: &PgPool,
    retention_days: i64,
    batch_size: i64,
) -> Result<u64> {
    if batch_size <= 0 {
        return Ok(0);
    }
    anyhow::ensure!(
        (0..=36_500).contains(&retention_days),
        "invalid moderation retention ceiling"
    );
    let deleted = sqlx::query_scalar::<_, Uuid>(
        "WITH doomed AS (
            SELECT report.id
            FROM abuse_reports AS report
            LEFT JOIN user_retention_policies AS policy
              ON policy.user_id=report.reporter_id
            WHERE report.status IN ('actioned','rejected','closed')
              AND report.resolved_at IS NOT NULL
              AND COALESCE(
                    policy.moderation_evidence_days,NULLIF($1::BIGINT,0)
                  ) IS NOT NULL
              AND report.resolved_at < clock_timestamp() - (
                    COALESCE(
                        policy.moderation_evidence_days,NULLIF($1::BIGINT,0)
                    )::BIGINT * INTERVAL '1 day')
              AND NOT EXISTS (
                  SELECT 1 FROM abuse_appeals AS appeal
                  WHERE appeal.report_id=report.id
                    AND (
                        appeal.status IN ('submitted','reviewing')
                        OR appeal.resolved_at IS NULL
                        OR appeal.resolved_at >= clock_timestamp() - (
                            COALESCE(
                                policy.moderation_evidence_days,NULLIF($1::BIGINT,0)
                            )::BIGINT * INTERVAL '1 day')
                    )
              )
              AND NOT EXISTS (
                  SELECT 1 FROM legal_holds hold
                   WHERE hold.released_at IS NULL AND (
                       EXISTS (
                           SELECT 1 FROM legal_hold_scopes scope_link
                            WHERE scope_link.hold_id=hold.id
                              AND scope_link.scope_type='report_evidence_report'
                              AND scope_link.subject_id=report.id
                       )
                       OR EXISTS (
                           SELECT 1 FROM abuse_report_evidence evidence
                           JOIN legal_hold_report_evidence exact_link
                             ON exact_link.evidence_id=evidence.id
                            AND exact_link.hold_id=hold.id
                            WHERE evidence.report_id=report.id
                       )
                   )
              )
            ORDER BY report.resolved_at, report.id
            LIMIT $2
            FOR UPDATE OF report SKIP LOCKED
         )
         DELETE FROM abuse_reports AS report
         USING doomed WHERE report.id=doomed.id
         RETURNING report.id",
    )
    .bind(retention_days)
    .bind(batch_size.min(10_000))
    .fetch_all(pool)
    .await?;
    Ok(deleted.len() as u64)
}

#[allow(clippy::too_many_arguments)]
pub async fn create_invitation_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    actor_id: Uuid,
    id: Uuid,
    token: &str,
    label: &str,
    max_uses: i32,
    expires_in_hours: Option<i32>,
    request_id: Option<Uuid>,
) -> Result<()> {
    anyhow::ensure!(
        token.len() == 64 && token.bytes().all(|byte| byte.is_ascii_alphanumeric()),
        "invalid invitation token"
    );
    anyhow::ensure!(
        !label.is_empty()
            && label.len() <= 512
            && label.chars().count() <= 128
            && label.chars().all(|character| {
                let code = character as u32;
                !(code <= 0x1f
                    || (0x7f..=0x9f).contains(&code)
                    || (0x202a..=0x202e).contains(&code))
            }),
        "invalid invitation label"
    );
    anyhow::ensure!(
        (1..=100_000).contains(&max_uses),
        "invalid invitation use limit"
    );
    anyhow::ensure!(
        expires_in_hours.is_none_or(|hours| (1..=8760).contains(&hours)),
        "invalid invitation expiry"
    );
    sqlx::query("INSERT INTO invitation_tokens (id, token_hash, label, created_by, max_uses, expires_at) VALUES ($1, $2, $3, $4, $5, CASE WHEN $6::integer IS NULL THEN NULL ELSE clock_timestamp()+($6::bigint*INTERVAL '1 hour') END)")
        .bind(id).bind(auth::token_hash(token)).bind(label).bind(actor_id).bind(max_uses).bind(expires_in_hours)
        .execute(&mut **tx).await?;
    sqlx::query("INSERT INTO audit_log (actor_id, action, target, details, request_id) VALUES ($1, 'admin.invitation.create', $2, $3, $4)")
        .bind(actor_id).bind(id.to_string()).bind(serde_json::json!({"label":label,"max_uses":max_uses}))
        .bind(request_id)
        .execute(&mut **tx).await?;
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvitationRevokeOutcome {
    Revoked,
    AlreadyRevoked,
    NotFound,
}

pub async fn revoke_invitation_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    actor_id: Uuid,
    id: Uuid,
    request_id: Option<Uuid>,
) -> Result<InvitationRevokeOutcome> {
    let revoked_at: Option<Option<DateTime<Utc>>> =
        sqlx::query_scalar("SELECT revoked_at FROM invitation_tokens WHERE id=$1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut **tx)
            .await?;
    let outcome = match revoked_at {
        None => InvitationRevokeOutcome::NotFound,
        Some(Some(_)) => InvitationRevokeOutcome::AlreadyRevoked,
        Some(None) => {
            sqlx::query("UPDATE invitation_tokens SET revoked_at=clock_timestamp() WHERE id=$1")
                .bind(id)
                .execute(&mut **tx)
                .await?;
            InvitationRevokeOutcome::Revoked
        }
    };
    sqlx::query("INSERT INTO audit_log (actor_id, action, target, details, request_id) VALUES ($1, 'admin.invitation.revoke', $2, $3, $4)")
        .bind(actor_id)
        .bind(id.to_string())
        .bind(serde_json::json!({
            "outcome": match outcome {
                InvitationRevokeOutcome::Revoked => "revoked",
                InvitationRevokeOutcome::AlreadyRevoked => "already_revoked",
                InvitationRevokeOutcome::NotFound => "not_found",
            }
        }))
        .bind(request_id)
        .execute(&mut **tx).await?;
    Ok(outcome)
}

#[cfg(test)]
pub async fn create_report(
    pool: &PgPool,
    reporter_id: Uuid,
    reported_jid: &str,
    category: &str,
    description: &str,
    evidence: &[ReportEvidenceInput],
) -> std::result::Result<Uuid, ReportCreateError> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|error| ReportCreateError::Internal(error.into()))?;
    let id = create_report_in_tx(
        &mut tx,
        reporter_id,
        reported_jid,
        category,
        description,
        evidence,
        None,
    )
    .await?;
    tx.commit()
        .await
        .map_err(|error| ReportCreateError::Internal(error.into()))?;
    Ok(id)
}

struct ArchivedEvidence {
    peer_jid: String,
    stanza: String,
    encrypted: bool,
    stanza_id: Option<String>,
    created_at: DateTime<Utc>,
}

#[allow(clippy::too_many_arguments)]
pub async fn create_report_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    reporter_id: Uuid,
    reported_jid: &str,
    category: &str,
    description: &str,
    evidence: &[ReportEvidenceInput],
    request_id: Option<Uuid>,
) -> std::result::Result<Uuid, ReportCreateError> {
    let mut unique = HashSet::with_capacity(evidence.len());
    if evidence.iter().any(|item| !unique.insert(item.archive_id)) {
        return Err(ReportCreateError::InvalidEvidence(
            "archive_id is duplicated",
        ));
    }
    let archive_ids = evidence
        .iter()
        .map(|item| item.archive_id)
        .collect::<Vec<_>>();
    let rows = sqlx::query(
        "SELECT id,peer_jid,stanza,encrypted,stanza_id,created_at
         FROM message_archive WHERE owner_id=$1 AND id=ANY($2)
         ORDER BY id FOR SHARE",
    )
    .bind(reporter_id)
    .bind(&archive_ids)
    .fetch_all(&mut **tx)
    .await
    .map_err(|error| ReportCreateError::Internal(error.into()))?;
    if rows.len() != evidence.len() {
        return Err(ReportCreateError::InvalidEvidence(
            "archive_id is not owned by the reporter",
        ));
    }
    let mut archives = rows
        .into_iter()
        .map(|archive| {
            (
                archive.get::<Uuid, _>("id"),
                ArchivedEvidence {
                    peer_jid: archive.get("peer_jid"),
                    stanza: archive.get("stanza"),
                    encrypted: archive.get("encrypted"),
                    stanza_id: archive.get("stanza_id"),
                    created_at: archive.get("created_at"),
                },
            )
        })
        .collect::<HashMap<_, _>>();
    let mut snapshots = Vec::with_capacity(evidence.len());
    for item in evidence {
        let archive =
            archives
                .remove(&item.archive_id)
                .ok_or(ReportCreateError::InvalidEvidence(
                    "archive_id is not owned by the reporter",
                ))?;
        let peer_jid = archive.peer_jid;
        if crate::jid::canonical_bare_key(&peer_jid).ok().as_deref() != Some(reported_jid) {
            return Err(ReportCreateError::InvalidEvidence(
                "archive_id is not associated with the reported JID",
            ));
        }
        let archive_client_id = archive.stanza_id;
        if item
            .client_message_id
            .as_ref()
            .is_some_and(|asserted| archive_client_id.as_deref() != Some(asserted.as_str()))
        {
            return Err(ReportCreateError::InvalidEvidence(
                "client_message_id does not match the archive",
            ));
        }
        let (sender_jid, body_text, source) =
            evidence_from_archive(&archive.stanza, archive.encrypted, &item.body_text)?;
        let hash = Sha256::digest(archive.stanza.as_bytes()).to_vec();
        snapshots.push((
            item.archive_id,
            hash,
            source,
            archive_client_id,
            sender_jid,
            archive.created_at,
            body_text,
            archive.encrypted,
        ));
    }
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO abuse_reports (id, reporter_id, reported_jid, category, description) VALUES ($1, $2, $3, $4, $5)")
        .bind(id).bind(reporter_id).bind(reported_jid).bind(category).bind(description)
        .execute(&mut **tx).await.map_err(|error| ReportCreateError::Internal(error.into()))?;
    for (position, snapshot) in snapshots.into_iter().enumerate() {
        sqlx::query("INSERT INTO abuse_report_evidence (id, report_id, archive_id, archive_stanza_hash, evidence_source, client_message_id, sender_jid, sent_at, body_text, encrypted, position) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)")
            .bind(Uuid::new_v4()).bind(id).bind(snapshot.0).bind(snapshot.1).bind(snapshot.2)
            .bind(snapshot.3).bind(snapshot.4).bind(snapshot.5).bind(snapshot.6).bind(snapshot.7)
            .bind(i32::try_from(position).expect("report evidence is bounded to 20"))
            .execute(&mut **tx).await.map_err(|error| ReportCreateError::Internal(error.into()))?;
    }
    sqlx::query("INSERT INTO audit_log (actor_id,action,target,details,request_id) VALUES ($1,'abuse.report.create',$2,$3,$4)")
        .bind(reporter_id)
        .bind(id.to_string())
        .bind(serde_json::json!({"reported_jid":reported_jid,"evidence_count":evidence.len()}))
        .bind(request_id)
        .execute(&mut **tx).await.map_err(|error| ReportCreateError::Internal(error.into()))?;
    Ok(id)
}

fn evidence_from_archive(
    stanza: &str,
    encrypted: bool,
    submitted_body: &str,
) -> std::result::Result<(String, String, &'static str), ReportCreateError> {
    let document = roxmltree::Document::parse(stanza)
        .map_err(|_| ReportCreateError::InvalidEvidence("archived stanza is not valid XML"))?;
    let root = document.root_element();
    if root.tag_name().name() != "message" {
        return Err(ReportCreateError::InvalidEvidence(
            "archive_id does not reference a message stanza",
        ));
    }
    let sender = root
        .attribute("from")
        .ok_or(ReportCreateError::InvalidEvidence(
            "archived message has no authoritative sender",
        ))?;
    let sender = crate::jid::canonicalize(sender)
        .map_err(|_| ReportCreateError::InvalidEvidence("archived message sender is invalid"))?;
    if encrypted {
        return Ok((
            sender,
            submitted_body.to_owned(),
            "user_decrypted_omemo_unverified",
        ));
    }
    let body = root
        .children()
        .find(|child| {
            child.is_element()
                && child.tag_name().name() == "body"
                && matches!(child.tag_name().namespace(), None | Some("jabber:client"))
        })
        .and_then(|body| body.text())
        .filter(|body| !body.trim().is_empty())
        .ok_or(ReportCreateError::InvalidEvidence(
            "plaintext archive has no message body",
        ))?;
    Ok((sender, body.to_owned(), "server_verified_plaintext"))
}

#[cfg(test)]
pub async fn create_appeal(
    pool: &PgPool,
    report_id: Uuid,
    appellant_id: Uuid,
    reason: &str,
) -> std::result::Result<Uuid, AppealCreateError> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|error| AppealCreateError::Internal(error.into()))?;
    let id = create_appeal_in_tx(&mut tx, report_id, appellant_id, reason, None).await?;
    tx.commit()
        .await
        .map_err(|error| AppealCreateError::Internal(error.into()))?;
    Ok(id)
}

pub async fn create_appeal_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    report_id: Uuid,
    appellant_id: Uuid,
    reason: &str,
    request_id: Option<Uuid>,
) -> std::result::Result<Uuid, AppealCreateError> {
    let eligible: Option<bool> = sqlx::query_scalar(
        "SELECT reporter_id=$2 AND status IN ('actioned','rejected','closed')
         FROM abuse_reports WHERE id=$1 FOR UPDATE",
    )
    .bind(report_id)
    .bind(appellant_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| AppealCreateError::Internal(error.into()))?;
    if eligible != Some(true) {
        return Err(AppealCreateError::Conflict);
    }
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM abuse_appeals WHERE report_id=$1)")
            .bind(report_id)
            .fetch_one(&mut **tx)
            .await
            .map_err(|error| AppealCreateError::Internal(error.into()))?;
    if exists {
        return Err(AppealCreateError::Conflict);
    }
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO abuse_appeals(id,report_id,appellant_id,reason) VALUES($1,$2,$3,$4)")
        .bind(id)
        .bind(report_id)
        .bind(appellant_id)
        .bind(reason)
        .execute(&mut **tx)
        .await
        .map_err(|error| AppealCreateError::Internal(error.into()))?;
    sqlx::query("INSERT INTO audit_log(actor_id,action,target,details,request_id) VALUES($1,'abuse.appeal.create',$2,$3,$4)")
        .bind(appellant_id).bind(id.to_string()).bind(serde_json::json!({"report_id":report_id}))
        .bind(request_id)
        .execute(&mut **tx).await.map_err(|error| AppealCreateError::Internal(error.into()))?;
    Ok(id)
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
pub async fn admin_update_report_api(
    pool: &PgPool,
    id: Uuid,
    actor_id: Uuid,
    actor_generation: i64,
    presented_session: &str,
    status: &str,
    resolution: &str,
) -> std::result::Result<(), ModerationUpdateError> {
    update_moderation_record(
        pool,
        ModerationKind::Report,
        id,
        actor_id,
        status,
        resolution,
        Some((actor_generation, presented_session)),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
pub async fn admin_update_appeal_api(
    pool: &PgPool,
    id: Uuid,
    actor_id: Uuid,
    actor_generation: i64,
    presented_session: &str,
    status: &str,
    resolution: &str,
) -> std::result::Result<(), ModerationUpdateError> {
    update_moderation_record(
        pool,
        ModerationKind::Appeal,
        id,
        actor_id,
        status,
        resolution,
        Some((actor_generation, presented_session)),
    )
    .await
}

pub async fn admin_update_report_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    id: Uuid,
    actor_id: Uuid,
    status: &str,
    resolution: &str,
    request_id: Uuid,
) -> std::result::Result<(), ModerationUpdateError> {
    update_moderation_record_in_tx(
        tx,
        ModerationKind::Report,
        id,
        actor_id,
        status,
        resolution,
        Some(request_id),
    )
    .await
}

pub async fn admin_update_appeal_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    id: Uuid,
    actor_id: Uuid,
    status: &str,
    resolution: &str,
    request_id: Uuid,
) -> std::result::Result<(), ModerationUpdateError> {
    update_moderation_record_in_tx(
        tx,
        ModerationKind::Appeal,
        id,
        actor_id,
        status,
        resolution,
        Some(request_id),
    )
    .await
}

#[derive(Clone, Copy)]
enum ModerationKind {
    Report,
    Appeal,
}

#[cfg(test)]
async fn update_moderation_record(
    pool: &PgPool,
    kind: ModerationKind,
    id: Uuid,
    actor_id: Uuid,
    status: &str,
    resolution: &str,
    api_authorization: Option<(i64, &str)>,
) -> std::result::Result<(), ModerationUpdateError> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|error| ModerationUpdateError::Internal(error.into()))?;
    if let Some((actor_generation, presented_session)) = api_authorization {
        let authorized = crate::db::authorize_admin_in_tx(
            &mut tx,
            actor_id,
            actor_generation,
            presented_session,
        )
        .await
        .map_err(ModerationUpdateError::Internal)?;
        if !authorized {
            tx.rollback()
                .await
                .map_err(|error| ModerationUpdateError::Internal(error.into()))?;
            return Err(ModerationUpdateError::Unauthorized);
        }
    }
    update_moderation_record_in_tx(&mut tx, kind, id, actor_id, status, resolution, None).await?;
    tx.commit()
        .await
        .map_err(|error| ModerationUpdateError::Internal(error.into()))?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn update_moderation_record_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    kind: ModerationKind,
    id: Uuid,
    actor_id: Uuid,
    status: &str,
    resolution: &str,
    request_id: Option<Uuid>,
) -> std::result::Result<(), ModerationUpdateError> {
    let select = match kind {
        ModerationKind::Report => "SELECT status FROM abuse_reports WHERE id=$1 FOR UPDATE",
        ModerationKind::Appeal => "SELECT status FROM abuse_appeals WHERE id=$1 FOR UPDATE",
    };
    let current: Option<String> = sqlx::query_scalar(select)
        .bind(id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|error| ModerationUpdateError::Internal(error.into()))?;
    let Some(current) = current else {
        sqlx::query(
            "INSERT INTO audit_log (actor_id, action, target, details, request_id)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(actor_id)
        .bind(match kind {
            ModerationKind::Report => "admin.report.update",
            ModerationKind::Appeal => "admin.appeal.update",
        })
        .bind(id.to_string())
        .bind(serde_json::json!({"status":status,"outcome":"not_found"}))
        .bind(request_id)
        .execute(&mut **tx)
        .await
        .map_err(|error| ModerationUpdateError::Internal(error.into()))?;
        return Err(ModerationUpdateError::NotFound);
    };
    if !valid_moderation_transition(kind, &current, status) {
        sqlx::query(
            "INSERT INTO audit_log (actor_id, action, target, details, request_id)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(actor_id)
        .bind(match kind {
            ModerationKind::Report => "admin.report.update",
            ModerationKind::Appeal => "admin.appeal.update",
        })
        .bind(id.to_string())
        .bind(serde_json::json!({
            "status":status,
            "previous_status":current,
            "outcome":"invalid_transition"
        }))
        .bind(request_id)
        .execute(&mut **tx)
        .await
        .map_err(|error| ModerationUpdateError::Internal(error.into()))?;
        return Err(ModerationUpdateError::InvalidTransition);
    }
    let update = match kind {
        ModerationKind::Report => "UPDATE abuse_reports SET status=$3, resolution=$4, assigned_admin_id=$2, resolved_at=CASE WHEN $3 IN ('actioned','rejected','closed') THEN COALESCE(resolved_at, NOW()) ELSE NULL END, updated_at=NOW() WHERE id=$1",
        ModerationKind::Appeal => "UPDATE abuse_appeals SET status=$3, resolution=$4, assigned_admin_id=$2, resolved_at=CASE WHEN $3 IN ('upheld','denied') THEN COALESCE(resolved_at, NOW()) ELSE NULL END, updated_at=NOW() WHERE id=$1",
    };
    sqlx::query(update)
        .bind(id)
        .bind(actor_id)
        .bind(status)
        .bind(resolution)
        .execute(&mut **tx)
        .await
        .map_err(|error| ModerationUpdateError::Internal(error.into()))?;
    sqlx::query(
        "INSERT INTO audit_log (actor_id, action, target, details, request_id) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(actor_id)
    .bind(match kind {
        ModerationKind::Report => "admin.report.update",
        ModerationKind::Appeal => "admin.appeal.update",
    })
    .bind(id.to_string())
    .bind(serde_json::json!({"status":status,"outcome":"updated"}))
    .bind(request_id)
    .execute(&mut **tx)
    .await
    .map_err(|error| ModerationUpdateError::Internal(error.into()))?;
    Ok(())
}

fn valid_moderation_transition(kind: ModerationKind, current: &str, next: &str) -> bool {
    if current == next {
        return matches!(current, "submitted" | "reviewing");
    }
    match kind {
        ModerationKind::Report => {
            matches!(current, "submitted" | "reviewing")
                && matches!(next, "reviewing" | "actioned" | "rejected" | "closed")
        }
        ModerationKind::Appeal => {
            matches!(current, "submitted" | "reviewing")
                && matches!(next, "reviewing" | "upheld" | "denied")
        }
    }
}

#[cfg(test)]
mod tests;
