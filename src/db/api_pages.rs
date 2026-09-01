//! Stable PostgreSQL keyset pages for REST collections.
//!
//! Every query orders by the immutable `(created_at DESC, id DESC)` tuple,
//! applies visibility filters before the strict boundary, and fetches one
//! extra row to determine whether another page exists.

use anyhow::{ensure, Result};
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::{PgPool, Postgres, QueryBuilder, Row, Transaction};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PageBoundary {
    pub created_at: DateTime<Utc>,
    pub id: Uuid,
}

#[derive(Debug)]
pub struct KeysetPage<T> {
    pub rows: Vec<T>,
    pub next: Option<PageBoundary>,
    /// PostgreSQL time captured for this page. Routes must use this value when
    /// issuing the continuation cursor, never a web node's wall clock.
    pub database_now: DateTime<Utc>,
}

#[cfg(test)]
#[derive(Debug, Serialize)]
pub struct HistoryPageRow {
    pub id: Uuid,
    pub peer_jid: String,
    pub stanza: String,
    pub encrypted: bool,
    pub stanza_id: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct ReportPageRow {
    pub id: Uuid,
    pub reporter_id: Uuid,
    pub reporter_username: String,
    pub reported_jid: String,
    pub category: String,
    pub description: String,
    pub status: String,
    pub resolution: Option<String>,
    pub assigned_admin: Option<String>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub evidence: serde_json::Value,
    pub appeal: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct UserPageRow {
    pub id: Uuid,
    pub username: String,
    pub display_name: Option<String>,
    pub is_admin: bool,
    pub is_disabled: bool,
    pub created_at: DateTime<Utc>,
    pub last_login_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
pub struct InvitationPageRow {
    pub id: Uuid,
    pub label: String,
    pub created_by: Option<String>,
    pub max_uses: i32,
    pub use_count: i32,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct MucRoomPageRow {
    pub id: Uuid,
    pub localpart: String,
    pub title: Option<String>,
    pub public: bool,
    pub persistent: bool,
    pub members_only: bool,
    pub moderated: bool,
    pub non_anonymous: bool,
    pub created_at: DateTime<Utc>,
}

fn checked_fetch_limit(limit: i64) -> Result<i64> {
    ensure!(
        (1..=100).contains(&limit),
        "page limit must be between 1 and 100"
    );
    Ok(limit + 1)
}

fn checked_report_fetch_limit(limit: i64) -> Result<i64> {
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

pub async fn database_cursor_clock_in_tx(
    tx: &mut Transaction<'_, Postgres>,
) -> Result<DateTime<Utc>> {
    Ok(sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut **tx)
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

#[cfg(test)]
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
#[cfg(test)]
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
#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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
#[cfg(test)]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_limit_and_boundary_are_strictly_bounded() {
        assert!(checked_fetch_limit(1).is_ok());
        assert!(checked_fetch_limit(100).is_ok());
        assert!(checked_fetch_limit(0).is_err());
        assert!(checked_fetch_limit(101).is_err());
        assert!(checked_report_fetch_limit(1).is_ok());
        assert!(checked_report_fetch_limit(25).is_ok());
        assert!(checked_report_fetch_limit(0).is_err());
        assert!(checked_report_fetch_limit(26).is_err());

        let migration = include_str!("../../migrations/0060_api_keyset_pages.sql");
        assert!(!migration.contains("CREATE INDEX message_archive"));
        assert!(!migration.contains("CREATE INDEX users"));
        assert!(!migration.contains("CREATE INDEX invitation_tokens"));
        assert!(!migration.contains("CREATE INDEX muc_rooms"));
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn postgres_keyset_pages_are_stable_isolated_and_indexed() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();
        let marker = Uuid::new_v4();
        let started_at = database_cursor_clock(&pool).await.unwrap();
        let tied: DateTime<Utc> =
            sqlx::query_scalar("SELECT date_trunc('second',clock_timestamp())")
                .fetch_one(&pool)
                .await
                .unwrap();
        let mut user_ids = (0..7).map(|_| Uuid::new_v4()).collect::<Vec<_>>();
        user_ids.sort_unstable();
        let owner = user_ids[0];
        let other = user_ids[1];
        for (ordinal, id) in user_ids.iter().copied().enumerate() {
            sqlx::query("INSERT INTO users(id,username,password_hash,created_at) VALUES($1,$2,'test-only',$3)")
                .bind(id)
                .bind(format!("page-user-{ordinal}-{}", &marker.simple().to_string()[..8]))
                .bind(tied)
                .execute(&pool)
                .await
                .unwrap();
        }
        for _ in 0..7 {
            let id = Uuid::new_v4();
            sqlx::query("INSERT INTO message_archive(id,owner_id,peer_jid,peer_full_jid,stanza,encrypted,created_at) VALUES($1,$2,'peer@example.test','peer@example.test/phone','<message/>',FALSE,$3)")
                .bind(id).bind(owner).bind(tied).execute(&pool).await.unwrap();
        }
        let other_history = Uuid::new_v4();
        sqlx::query("INSERT INTO message_archive(id,owner_id,peer_jid,peer_full_jid,stanza,encrypted,created_at) VALUES($1,$2,'peer@example.test','peer@example.test/phone','<message/>',FALSE,$3)")
            .bind(other_history).bind(other).bind(tied).execute(&pool).await.unwrap();
        let different_peer_history = Uuid::new_v4();
        sqlx::query("INSERT INTO message_archive(id,owner_id,peer_jid,peer_full_jid,stanza,encrypted,created_at) VALUES($1,$2,'different@example.test','different@example.test/phone','<message/>',FALSE,$3)")
            .bind(different_peer_history).bind(owner).bind(tied).execute(&pool).await.unwrap();

        let first = history_page(&pool, owner, Some("peer@example.test"), None, 3)
            .await
            .unwrap();
        assert_eq!(first.rows.len(), 3);
        assert!(first.database_now >= started_at);
        let first_ids = first
            .rows
            .iter()
            .map(|row| row.id)
            .collect::<std::collections::HashSet<_>>();
        let boundary = first.next.unwrap();
        // A newer concurrent insert must not shift the continuation window.
        let inserted = Uuid::new_v4();
        sqlx::query("INSERT INTO message_archive(id,owner_id,peer_jid,peer_full_jid,stanza,encrypted,created_at) VALUES($1,$2,'peer@example.test','peer@example.test/phone','<message/>',FALSE,$3+INTERVAL '1 second')")
            .bind(inserted).bind(owner).bind(tied).execute(&pool).await.unwrap();
        // Deleting an already-returned row also must not duplicate survivors.
        sqlx::query("DELETE FROM message_archive WHERE id=$1")
            .bind(first.rows[0].id)
            .execute(&pool)
            .await
            .unwrap();
        let second = history_page(&pool, owner, Some("peer@example.test"), Some(boundary), 100)
            .await
            .unwrap();
        assert!(second.rows.iter().all(|row| !first_ids.contains(&row.id)));
        assert!(first
            .rows
            .iter()
            .chain(&second.rows)
            .all(|row| row.id != inserted
                && row.id != other_history
                && row.id != different_peer_history));
        assert_eq!(second.rows.len(), 4);

        // Reporter visibility is fail-closed at the public function boundary.
        let own_report_ids = (0..7).map(|_| Uuid::new_v4()).collect::<Vec<_>>();
        let other_report_ids = (0..2).map(|_| Uuid::new_v4()).collect::<Vec<_>>();
        for (id, reporter, status) in own_report_ids
            .iter()
            .copied()
            .map(|id| (id, owner, "submitted"))
            .chain(
                other_report_ids
                    .iter()
                    .copied()
                    .map(|id| (id, other, "reviewing")),
            )
        {
            sqlx::query("INSERT INTO abuse_reports(id,reporter_id,reported_jid,category,description,status,created_at,updated_at) VALUES($1,$2,'reported@example.test','spam','fixture',$3,$4,$4)")
                .bind(id).bind(reporter).bind(status).bind(tied).execute(&pool).await.unwrap();
        }
        let own = own_reports_page(&pool, owner, None, None, 3).await.unwrap();
        assert_eq!(own.rows.len(), 3);
        let own_first_ids = own
            .rows
            .iter()
            .map(|row| row.id)
            .collect::<std::collections::HashSet<_>>();
        let own_boundary = own.next.expect("seven reports require a continuation");
        let concurrent_report = Uuid::new_v4();
        sqlx::query("INSERT INTO abuse_reports(id,reporter_id,reported_jid,category,description,status,created_at,updated_at) VALUES($1,$2,'reported@example.test','spam','fixture','submitted',$3+INTERVAL '1 second',$3+INTERVAL '1 second')")
            .bind(concurrent_report).bind(owner).bind(tied).execute(&pool).await.unwrap();
        sqlx::query("DELETE FROM abuse_reports WHERE id=$1")
            .bind(own.rows[0].id)
            .execute(&pool)
            .await
            .unwrap();
        let own_second = own_reports_page(&pool, owner, None, Some(own_boundary), 25)
            .await
            .unwrap();
        assert_eq!(own_second.rows.len(), 4);
        assert!(own_second
            .rows
            .iter()
            .all(|row| !own_first_ids.contains(&row.id) && row.id != concurrent_report));
        assert!(own_second.rows.iter().all(|row| row.reporter_id == owner));
        let admin = admin_reports_page(&pool, None, None, 25).await.unwrap();
        assert!(admin.rows.iter().any(|row| row.id == concurrent_report));
        assert!(other_report_ids
            .iter()
            .all(|id| admin.rows.iter().any(|row| row.id == *id)));
        let reviewing = admin_reports_page(&pool, Some("reviewing"), None, 25)
            .await
            .unwrap();
        assert_eq!(reviewing.rows.len(), 2);
        assert!(reviewing.rows.iter().all(|row| row.reporter_id == other));
        assert!(admin_reports_page(&pool, None, None, 26).await.is_err());

        // The remaining admin collections use the same timestamp/id tie-break.
        let invitation_ids = (0..5).map(|_| Uuid::new_v4()).collect::<Vec<_>>();
        for (ordinal, id) in invitation_ids.iter().copied().enumerate() {
            sqlx::query("INSERT INTO invitation_tokens(id,token_hash,label,created_by,max_uses,created_at) VALUES($1,$2,$3,$4,1,$5)")
                .bind(id)
                .bind(id.as_bytes().to_vec())
                .bind(format!("page-{ordinal}-{marker}"))
                .bind(owner)
                .bind(tied)
                .execute(&pool)
                .await
                .unwrap();
        }
        let invite_first = invitations_page(&pool, None, 2).await.unwrap();
        let invite_first_ids = invite_first
            .rows
            .iter()
            .map(|row| row.id)
            .collect::<std::collections::HashSet<_>>();
        let invite_boundary = invite_first
            .next
            .expect("five invitations require a continuation");
        let concurrent_invite = Uuid::new_v4();
        sqlx::query("INSERT INTO invitation_tokens(id,token_hash,label,created_by,max_uses,created_at) VALUES($1,$2,$3,$4,1,$5+INTERVAL '1 second')")
            .bind(concurrent_invite)
            .bind(concurrent_invite.as_bytes().to_vec())
            .bind(format!("page-concurrent-{marker}"))
            .bind(other)
            .bind(tied)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM invitation_tokens WHERE id=$1")
            .bind(invite_first.rows[0].id)
            .execute(&pool)
            .await
            .unwrap();
        let invite_second = invitations_page(&pool, Some(invite_boundary), 100)
            .await
            .unwrap();
        let invite_seen = invite_first
            .rows
            .iter()
            .chain(&invite_second.rows)
            .map(|row| row.id)
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(invite_seen.len(), 5);
        assert!(invite_second
            .rows
            .iter()
            .all(|row| !invite_first_ids.contains(&row.id) && row.id != concurrent_invite));
        assert!(invitations_page(&pool, None, 100)
            .await
            .unwrap()
            .rows
            .iter()
            .any(|row| row.id == concurrent_invite
                && row
                    .created_by
                    .as_deref()
                    .is_some_and(|name| name.starts_with("page-user-1-"))));

        let room_ids = (0..5).map(|_| Uuid::new_v4()).collect::<Vec<_>>();
        for (ordinal, id) in room_ids.iter().copied().enumerate() {
            sqlx::query(
                "INSERT INTO muc_rooms(id,localpart,owner_id,created_at) VALUES($1,$2,$3,$4)",
            )
            .bind(id)
            .bind(format!(
                "page-{ordinal}-{}",
                &marker.simple().to_string()[..8]
            ))
            .bind(owner)
            .bind(tied)
            .execute(&pool)
            .await
            .unwrap();
        }
        let room_first = admin_muc_rooms_page(&pool, None, 2).await.unwrap();
        let room_first_ids = room_first
            .rows
            .iter()
            .map(|row| row.id)
            .collect::<std::collections::HashSet<_>>();
        let room_boundary = room_first.next.expect("five rooms require a continuation");
        let concurrent_room = Uuid::new_v4();
        sqlx::query("INSERT INTO muc_rooms(id,localpart,owner_id,public,created_at) VALUES($1,$2,$3,FALSE,$4+INTERVAL '1 second')")
            .bind(concurrent_room)
            .bind(format!("page-concurrent-{}", &marker.simple().to_string()[..8]))
            .bind(other)
            .bind(tied)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM muc_rooms WHERE id=$1")
            .bind(room_first.rows[0].id)
            .execute(&pool)
            .await
            .unwrap();
        let room_second = admin_muc_rooms_page(&pool, Some(room_boundary), 100)
            .await
            .unwrap();
        let room_seen = room_first
            .rows
            .iter()
            .chain(&room_second.rows)
            .map(|row| row.id)
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(room_seen.len(), 5);
        assert!(room_second
            .rows
            .iter()
            .all(|row| !room_first_ids.contains(&row.id) && row.id != concurrent_room));
        assert!(admin_muc_rooms_page(&pool, None, 100)
            .await
            .unwrap()
            .rows
            .iter()
            .any(|row| row.id == concurrent_room && !row.public));

        let user_first = users_page(&pool, None, 2).await.unwrap();
        let user_first_ids = user_first
            .rows
            .iter()
            .map(|row| row.id)
            .collect::<std::collections::HashSet<_>>();
        let user_boundary = user_first.next.expect("seven users require a continuation");
        let concurrent_user = Uuid::new_v4();
        sqlx::query("INSERT INTO users(id,username,password_hash,created_at) VALUES($1,$2,'test-only',$3+INTERVAL '1 second')")
            .bind(concurrent_user)
            .bind(format!("page-concurrent-user-{}", &marker.simple().to_string()[..8]))
            .bind(tied)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM users WHERE id=$1")
            .bind(user_first.rows[0].id)
            .execute(&pool)
            .await
            .unwrap();
        let user_second = users_page(&pool, Some(user_boundary), 100).await.unwrap();
        assert_eq!(user_first.rows.len(), 2);
        assert_eq!(user_second.rows.len(), 5);
        assert!(user_second
            .rows
            .iter()
            .all(|row| !user_first_ids.contains(&row.id) && row.id != concurrent_user));

        let mut explain_tx = pool.begin().await.unwrap();
        sqlx::query("SET LOCAL enable_seqscan=off")
            .execute(&mut *explain_tx)
            .await
            .unwrap();
        let (archive_peer_index_valid, archive_peer_index_ready, archive_peer_index_definition): (
            bool,
            bool,
            String,
        ) = sqlx::query_as(
            "SELECT definition.indisvalid,
                    definition.indisready,
                    pg_get_indexdef(definition.indexrelid)
               FROM pg_index definition
              WHERE definition.indexrelid =
                    to_regclass('message_archive_owner_peer_bare_time_id_idx')",
        )
        .fetch_one(&mut *explain_tx)
        .await
        .unwrap();
        assert!(archive_peer_index_valid && archive_peer_index_ready);
        assert_eq!(
            archive_peer_index_definition
                .rsplit_once(" USING btree ")
                .map(|(_, columns)| columns),
            Some("(owner_id, peer_jid, created_at, id)"),
            "archive peer keyset index definition drifted: {archive_peer_index_definition}"
        );
        let plan: Vec<String> = sqlx::query_scalar("EXPLAIN (COSTS OFF) SELECT id FROM message_archive WHERE owner_id=$1 AND peer_jid=$2 AND (created_at,id)<($3,$4) ORDER BY created_at DESC,id DESC LIMIT 101")
            .bind(owner).bind("peer@example.test").bind(tied).bind(Uuid::from_u128(u128::MAX)).fetch_all(&mut *explain_tx).await.unwrap();
        let rendered_plan = plan.join("\n");
        assert!(
            rendered_plan.contains("Index Scan") || rendered_plan.contains("Index Only Scan"),
            "archive keyset query did not have an ordered index path:\n{rendered_plan}"
        );
        assert!(
            !rendered_plan.contains("Sort"),
            "archive keyset query required an explicit sort:\n{rendered_plan}"
        );
        let archive_keyset_indexes: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_indexes
             WHERE schemaname=current_schema()
               AND indexname IN ('message_archive_owner_time_id_idx',
                                 'message_archive_owner_peer_bare_time_id_idx')",
        )
        .fetch_one(&mut *explain_tx)
        .await
        .unwrap();
        assert_eq!(archive_keyset_indexes, 2);
        explain_tx.rollback().await.unwrap();
        pool.close().await;
    }
}
