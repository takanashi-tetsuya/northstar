//! Stable PostgreSQL keyset pages for REST collections.
//!
//! Every query orders by the immutable `(created_at DESC, id DESC)` tuple,
//! applies visibility filters before the strict boundary, and fetches one
//! extra row to determine whether another page exists.

use anyhow::{ensure, Result};
use chrono::{DateTime, Utc};
use northstar_postgres::database_cursor_clock_in_tx;
#[cfg(any(test, feature = "test-support"))]
use serde::Serialize;
use sqlx::{PgPool, Postgres, QueryBuilder, Row, Transaction};
use uuid::Uuid;

pub use northstar_operations_application::api_queries::{
    InvitationPageRow, KeysetPage, MucRoomPageRow, PageBoundary, ReportPageRow, UserPageRow,
};

#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Serialize)]
pub struct HistoryPageRow {
    pub id: Uuid,
    pub peer_jid: String,
    pub stanza: String,
    pub encrypted: bool,
    pub stanza_id: Option<String>,
    pub created_at: DateTime<Utc>,
}

pub fn checked_fetch_limit(limit: i64) -> Result<i64> {
    ensure!(
        (1..=100).contains(&limit),
        "page limit must be between 1 and 100"
    );
    Ok(limit + 1)
}

pub fn checked_report_fetch_limit(limit: i64) -> Result<i64> {
    ensure!(
        (1..=25).contains(&limit),
        "report page limit must be between 1 and 25"
    );
    Ok(limit + 1)
}

/// Obtain the authority clock used to verify an incoming cursor before its
/// boundary can be passed to a page query. The returned page carries a fresh
/// database clock for issuing its continuation cursor.
pub async fn database_cursor_clock(pool: &PgPool) -> Result<DateTime<Utc>> {
    Ok(sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(pool)
        .await?)
}

fn finish<T>(
    mut rows: Vec<T>,
    limit: i64,
    database_now: DateTime<Utc>,
    boundary: impl Fn(&T) -> PageBoundary,
) -> KeysetPage<T> {
    let has_more = rows.len() > limit as usize;
    rows.truncate(limit as usize);
    let next =
        has_more.then(|| boundary(rows.last().expect("a page with an extra row is nonempty")));
    KeysetPage {
        rows,
        next,
        database_now,
    }
}

#[cfg(any(test, feature = "test-support"))]
pub async fn history_page(
    pool: &PgPool,
    owner_id: Uuid,
    canonical_peer_jid: Option<&str>,
    after: Option<PageBoundary>,
    limit: i64,
) -> Result<KeysetPage<HistoryPageRow>> {
    let fetch_limit = checked_fetch_limit(limit)?;
    let database_now = database_cursor_clock(pool).await?;
    let mut query = QueryBuilder::<Postgres>::new(
        "SELECT id,peer_jid,stanza,encrypted,stanza_id,created_at
         FROM message_archive
         WHERE owner_id=",
    );
    query.push_bind(owner_id);
    if let Some(peer) = canonical_peer_jid {
        query.push(" AND peer_jid=").push_bind(peer);
    }
    if let Some(boundary) = after {
        query
            .push(" AND (created_at,id)<(")
            .push_bind(boundary.created_at)
            .push(",")
            .push_bind(boundary.id)
            .push(")");
    }
    query
        .push(" ORDER BY created_at DESC,id DESC LIMIT ")
        .push_bind(fetch_limit);
    let rows = query.build().fetch_all(pool).await?;
    Ok(finish(
        rows.into_iter()
            .map(|row| HistoryPageRow {
                id: row.get("id"),
                peer_jid: row.get("peer_jid"),
                stanza: row.get("stanza"),
                encrypted: row.get("encrypted"),
                stanza_id: row.get("stanza_id"),
                created_at: row.get("created_at"),
            })
            .collect(),
        limit,
        database_now,
        |row| PageBoundary {
            created_at: row.created_at,
            id: row.id,
        },
    ))
}

#[derive(Clone, Copy)]
enum ReportVisibility {
    Reporter(Uuid),
    Administrator,
}

async fn reports_page_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    visibility: ReportVisibility,
    status: Option<&str>,
    after: Option<PageBoundary>,
    limit: i64,
) -> Result<KeysetPage<ReportPageRow>> {
    ensure!(
        status.is_none_or(|value| matches!(
            value,
            "submitted" | "reviewing" | "actioned" | "rejected" | "closed"
        )),
        "invalid report status filter"
    );
    let fetch_limit = checked_report_fetch_limit(limit)?;
    let database_now = database_cursor_clock_in_tx(tx).await?;
    let mut query = QueryBuilder::<Postgres>::new(
        "SELECT r.id,r.reporter_id,reporter.username AS reporter_username,r.reported_jid,
                r.category,r.description,r.status,r.resolution,r.resolved_at,r.created_at,r.updated_at,
                admin.username AS assigned_admin,
                COALESCE((SELECT jsonb_agg(jsonb_build_object(
                    'id',e.id,'archive_id',e.archive_id,'archive_stanza_hash',
                    CASE WHEN e.archive_stanza_hash IS NULL THEN NULL ELSE encode(e.archive_stanza_hash,'hex') END,
                    'evidence_source',e.evidence_source,'client_message_id',e.client_message_id,
                    'sender_jid',e.sender_jid,'sent_at',e.sent_at,'body_text',e.body_text,
                    'encrypted',e.encrypted,'position',e.position) ORDER BY e.position)
                  FROM abuse_report_evidence e WHERE e.report_id=r.id),'[]'::jsonb) AS evidence,
                (SELECT jsonb_build_object('id',a.id,'reason',a.reason,'status',a.status,
                    'resolution',a.resolution,'created_at',a.created_at,'updated_at',a.updated_at)
                 FROM abuse_appeals a WHERE a.report_id=r.id) AS appeal
         FROM abuse_reports r JOIN users reporter ON reporter.id=r.reporter_id
         LEFT JOIN users admin ON admin.id=r.assigned_admin_id WHERE TRUE",
    );
    match visibility {
        ReportVisibility::Reporter(id) => {
            query.push(" AND r.reporter_id=").push_bind(id);
        }
        ReportVisibility::Administrator => {}
    }
    if let Some(status) = status {
        query.push(" AND r.status=").push_bind(status);
    }
    if let Some(boundary) = after {
        query
            .push(" AND (r.created_at,r.id)<(")
            .push_bind(boundary.created_at)
            .push(",")
            .push_bind(boundary.id)
            .push(")");
    }
    query
        .push(" ORDER BY r.created_at DESC,r.id DESC LIMIT ")
        .push_bind(fetch_limit);
    let rows = query.build().fetch_all(&mut **tx).await?;
    Ok(finish(
        rows.into_iter()
            .map(|row| ReportPageRow {
                id: row.get("id"),
                reporter_id: row.get("reporter_id"),
                reporter_username: row.get("reporter_username"),
                reported_jid: row.get("reported_jid"),
                category: row.get("category"),
                description: row.get("description"),
                status: row.get("status"),
                resolution: row.get("resolution"),
                assigned_admin: row.get("assigned_admin"),
                resolved_at: row.get("resolved_at"),
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
                evidence: row.get("evidence"),
                appeal: row.get("appeal"),
            })
            .collect(),
        limit,
        database_now,
        |row| PageBoundary {
            created_at: row.created_at,
            id: row.id,
        },
    ))
}

/// Reports visible to one authenticated reporter. This API cannot represent
/// the fail-open "all reporters" scope.
#[cfg(any(test, feature = "test-support"))]
pub async fn own_reports_page(
    pool: &PgPool,
    reporter_id: Uuid,
    status: Option<&str>,
    after: Option<PageBoundary>,
    limit: i64,
) -> Result<KeysetPage<ReportPageRow>> {
    let mut tx = pool.begin().await?;
    let page = own_reports_page_in_tx(&mut tx, reporter_id, status, after, limit).await?;
    tx.commit().await?;
    Ok(page)
}

pub async fn own_reports_page_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    reporter_id: Uuid,
    status: Option<&str>,
    after: Option<PageBoundary>,
    limit: i64,
) -> Result<KeysetPage<ReportPageRow>> {
    reports_page_in_tx(
        tx,
        ReportVisibility::Reporter(reporter_id),
        status,
        after,
        limit,
    )
    .await
}

/// Full moderation queue. Callers must establish administrator authorization
/// before invoking this deliberately admin-named data-layer function.
#[cfg(any(test, feature = "test-support"))]
pub async fn admin_reports_page(
    pool: &PgPool,
    status: Option<&str>,
    after: Option<PageBoundary>,
    limit: i64,
) -> Result<KeysetPage<ReportPageRow>> {
    let mut tx = pool.begin().await?;
    let page = admin_reports_page_in_tx(&mut tx, status, after, limit).await?;
    tx.commit().await?;
    Ok(page)
}

pub async fn admin_reports_page_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    status: Option<&str>,
    after: Option<PageBoundary>,
    limit: i64,
) -> Result<KeysetPage<ReportPageRow>> {
    reports_page_in_tx(tx, ReportVisibility::Administrator, status, after, limit).await
}

#[cfg(any(test, feature = "test-support"))]
pub async fn users_page(
    pool: &PgPool,
    after: Option<PageBoundary>,
    limit: i64,
) -> Result<KeysetPage<UserPageRow>> {
    let mut tx = pool.begin().await?;
    let page = users_page_in_tx(&mut tx, after, limit).await?;
    tx.commit().await?;
    Ok(page)
}

pub async fn users_page_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    after: Option<PageBoundary>,
    limit: i64,
) -> Result<KeysetPage<UserPageRow>> {
    let fetch_limit = checked_fetch_limit(limit)?;
    let database_now = database_cursor_clock_in_tx(tx).await?;
    let mut query = QueryBuilder::<Postgres>::new(
        "SELECT id,username,display_name,is_admin,is_disabled,created_at,last_login_at FROM users",
    );
    if let Some(boundary) = after {
        query
            .push(" WHERE (created_at,id)<(")
            .push_bind(boundary.created_at)
            .push(",")
            .push_bind(boundary.id)
            .push(")");
    }
    query
        .push(" ORDER BY created_at DESC,id DESC LIMIT ")
        .push_bind(fetch_limit);
    let rows = query.build().fetch_all(&mut **tx).await?;
    Ok(finish(
        rows.into_iter()
            .map(|r| UserPageRow {
                id: r.get("id"),
                username: r.get("username"),
                display_name: r.get("display_name"),
                is_admin: r.get("is_admin"),
                is_disabled: r.get("is_disabled"),
                created_at: r.get("created_at"),
                last_login_at: r.get("last_login_at"),
            })
            .collect(),
        limit,
        database_now,
        |r| PageBoundary {
            created_at: r.created_at,
            id: r.id,
        },
    ))
}

#[cfg(any(test, feature = "test-support"))]
pub async fn invitations_page(
    pool: &PgPool,
    after: Option<PageBoundary>,
    limit: i64,
) -> Result<KeysetPage<InvitationPageRow>> {
    let mut tx = pool.begin().await?;
    let page = invitations_page_in_tx(&mut tx, after, limit).await?;
    tx.commit().await?;
    Ok(page)
}

pub async fn invitations_page_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    after: Option<PageBoundary>,
    limit: i64,
) -> Result<KeysetPage<InvitationPageRow>> {
    let fetch_limit = checked_fetch_limit(limit)?;
    let database_now = database_cursor_clock_in_tx(tx).await?;
    let mut query = QueryBuilder::<Postgres>::new(
        "SELECT i.id,i.label,i.max_uses,i.use_count,i.expires_at,i.revoked_at,i.created_at,u.username AS created_by FROM invitation_tokens i LEFT JOIN users u ON u.id=i.created_by",
    );
    if let Some(boundary) = after {
        query
            .push(" WHERE (i.created_at,i.id)<(")
            .push_bind(boundary.created_at)
            .push(",")
            .push_bind(boundary.id)
            .push(")");
    }
    query
        .push(" ORDER BY i.created_at DESC,i.id DESC LIMIT ")
        .push_bind(fetch_limit);
    let rows = query.build().fetch_all(&mut **tx).await?;
    Ok(finish(
        rows.into_iter()
            .map(|r| InvitationPageRow {
                id: r.get("id"),
                label: r.get("label"),
                created_by: r.get("created_by"),
                max_uses: r.get("max_uses"),
                use_count: r.get("use_count"),
                expires_at: r.get("expires_at"),
                revoked_at: r.get("revoked_at"),
                created_at: r.get("created_at"),
            })
            .collect(),
        limit,
        database_now,
        |r| PageBoundary {
            created_at: r.created_at,
            id: r.id,
        },
    ))
}

/// Complete room inventory, including non-public rooms. This is intentionally
/// distinct from XMPP/public room discovery and must only be exposed after the
/// route has established current administrator authorization.
#[cfg(any(test, feature = "test-support"))]
pub async fn admin_muc_rooms_page(
    pool: &PgPool,
    after: Option<PageBoundary>,
    limit: i64,
) -> Result<KeysetPage<MucRoomPageRow>> {
    let mut tx = pool.begin().await?;
    let page = admin_muc_rooms_page_in_tx(&mut tx, after, limit).await?;
    tx.commit().await?;
    Ok(page)
}

pub async fn admin_muc_rooms_page_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    after: Option<PageBoundary>,
    limit: i64,
) -> Result<KeysetPage<MucRoomPageRow>> {
    let fetch_limit = checked_fetch_limit(limit)?;
    let database_now = database_cursor_clock_in_tx(tx).await?;
    let mut query = QueryBuilder::<Postgres>::new(
        "SELECT id,localpart,title,public,persistent,members_only,moderated,non_anonymous,created_at
           FROM muc_rooms WHERE destroyed_at IS NULL",
    );
    if let Some(boundary) = after {
        query
            .push(" AND (created_at,id)<(")
            .push_bind(boundary.created_at)
            .push(",")
            .push_bind(boundary.id)
            .push(")");
    }
    query
        .push(" ORDER BY created_at DESC,id DESC LIMIT ")
        .push_bind(fetch_limit);
    let rows = query.build().fetch_all(&mut **tx).await?;
    Ok(finish(
        rows.into_iter()
            .map(|r| MucRoomPageRow {
                id: r.get("id"),
                localpart: r.get("localpart"),
                title: r.get("title"),
                public: r.get("public"),
                persistent: r.get("persistent"),
                members_only: r.get("members_only"),
                moderated: r.get("moderated"),
                non_anonymous: r.get("non_anonymous"),
                created_at: r.get("created_at"),
            })
            .collect(),
        limit,
        database_now,
        |r| PageBoundary {
            created_at: r.created_at,
            id: r.id,
        },
    ))
}
