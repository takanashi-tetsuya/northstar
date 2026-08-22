use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgPool;
use sqlx::Row;
use uuid::Uuid;

#[derive(Debug, Serialize)]
pub struct ArchiveRow {
    pub id: Uuid,
    pub peer_jid: String,
    pub stanza: String,
    pub encrypted: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug)]
pub enum ArchiveCursor {
    Latest,
    Before(Uuid),
    After(Uuid),
}

#[derive(Debug)]
pub struct ArchivePage {
    pub rows: Vec<ArchiveRow>,
    pub total: i64,
    pub first_index: i64,
    pub complete: bool,
}

pub async fn archive_message(
    pool: &PgPool,
    owner_id: Uuid,
    peer_jid: &str,
    stanza: &str,
    encrypted: bool,
    stanza_id: Option<&str>,
) -> Result<()> {
    sqlx::query("INSERT INTO message_archive (id, owner_id, peer_jid, stanza, encrypted, stanza_id) VALUES ($1, $2, $3, $4, $5, $6)")
        .bind(Uuid::new_v4()).bind(owner_id).bind(peer_jid).bind(stanza).bind(encrypted).bind(stanza_id)
        .execute(pool).await?;
    Ok(())
}

pub async fn list_archive(
    pool: &PgPool,
    owner_id: Uuid,
    peer: Option<&str>,
    limit: i64,
) -> Result<Vec<ArchiveRow>> {
    let rows = sqlx::query(
        "SELECT id, peer_jid, stanza, encrypted, created_at FROM message_archive WHERE owner_id = $1 AND ($2::text IS NULL OR peer_jid = $2) ORDER BY created_at DESC LIMIT $3",
    )
    .bind(owner_id).bind(peer).bind(limit.clamp(1, 200)).fetch_all(pool).await?;
    Ok(rows
        .iter()
        .map(|r| ArchiveRow {
            id: r.get("id"),
            peer_jid: r.get("peer_jid"),
            stanza: r.get("stanza"),
            encrypted: r.get("encrypted"),
            created_at: r.get("created_at"),
        })
        .collect())
}

pub async fn archive_page(
    pool: &PgPool,
    owner_id: Uuid,
    peer: Option<&str>,
    start: Option<DateTime<Utc>>,
    end: Option<DateTime<Utc>>,
    cursor: ArchiveCursor,
    max: i64,
) -> Result<Option<ArchivePage>> {
    let max = max.clamp(0, 200);
    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM message_archive WHERE owner_id = $1 AND ($2::text IS NULL OR peer_jid = $2) AND ($3::timestamptz IS NULL OR created_at >= $3) AND ($4::timestamptz IS NULL OR created_at <= $4)",
    )
    .bind(owner_id)
    .bind(peer)
    .bind(start)
    .bind(end)
    .fetch_one(pool)
    .await?;

    let cursor_point = match cursor {
        ArchiveCursor::Before(id) | ArchiveCursor::After(id) => {
            let point = sqlx::query(
                "SELECT created_at FROM message_archive WHERE owner_id = $1 AND id = $2 AND ($3::text IS NULL OR peer_jid = $3) AND ($4::timestamptz IS NULL OR created_at >= $4) AND ($5::timestamptz IS NULL OR created_at <= $5)",
            )
            .bind(owner_id)
            .bind(id)
            .bind(peer)
            .bind(start)
            .bind(end)
            .fetch_optional(pool)
            .await?;
            let Some(point) = point else { return Ok(None) };
            Some((point.get::<DateTime<Utc>, _>("created_at"), id))
        }
        ArchiveCursor::Latest => None,
    };

    let fetch_limit = max + 1;
    let rows = match (cursor, cursor_point) {
        (ArchiveCursor::After(_), Some((created_at, id))) => {
            sqlx::query("SELECT id, peer_jid, stanza, encrypted, created_at FROM message_archive WHERE owner_id = $1 AND ($2::text IS NULL OR peer_jid = $2) AND ($3::timestamptz IS NULL OR created_at >= $3) AND ($4::timestamptz IS NULL OR created_at <= $4) AND (created_at, id) > ($5, $6) ORDER BY created_at ASC, id ASC LIMIT $7")
                .bind(owner_id).bind(peer).bind(start).bind(end).bind(created_at).bind(id).bind(fetch_limit).fetch_all(pool).await?
        }
        (ArchiveCursor::Before(_), Some((created_at, id))) => {
            sqlx::query("SELECT id, peer_jid, stanza, encrypted, created_at FROM message_archive WHERE owner_id = $1 AND ($2::text IS NULL OR peer_jid = $2) AND ($3::timestamptz IS NULL OR created_at >= $3) AND ($4::timestamptz IS NULL OR created_at <= $4) AND (created_at, id) < ($5, $6) ORDER BY created_at DESC, id DESC LIMIT $7")
                .bind(owner_id).bind(peer).bind(start).bind(end).bind(created_at).bind(id).bind(fetch_limit).fetch_all(pool).await?
        }
        (ArchiveCursor::Latest, None) => {
            sqlx::query("SELECT id, peer_jid, stanza, encrypted, created_at FROM message_archive WHERE owner_id = $1 AND ($2::text IS NULL OR peer_jid = $2) AND ($3::timestamptz IS NULL OR created_at >= $3) AND ($4::timestamptz IS NULL OR created_at <= $4) ORDER BY created_at DESC, id DESC LIMIT $5")
                .bind(owner_id).bind(peer).bind(start).bind(end).bind(fetch_limit).fetch_all(pool).await?
        }
        _ => unreachable!("cursor and cursor point must match"),
    };
    let mut rows: Vec<ArchiveRow> = rows.iter().map(archive_from_row).collect();
    let has_more = rows.len() > max as usize;
    if has_more {
        rows.truncate(max as usize);
    }
    if !matches!(cursor, ArchiveCursor::After(_)) {
        rows.reverse();
    }
    let first_index = if let Some(first) = rows.first() {
        sqlx::query_scalar("SELECT COUNT(*) FROM message_archive WHERE owner_id = $1 AND ($2::text IS NULL OR peer_jid = $2) AND ($3::timestamptz IS NULL OR created_at >= $3) AND ($4::timestamptz IS NULL OR created_at <= $4) AND (created_at, id) < ($5, $6)")
            .bind(owner_id).bind(peer).bind(start).bind(end).bind(first.created_at).bind(first.id).fetch_one(pool).await?
    } else {
        0
    };
    Ok(Some(ArchivePage {
        rows,
        total,
        first_index,
        complete: !has_more,
    }))
}

pub async fn store_offline(
    pool: &PgPool,
    recipient_id: Uuid,
    sender_jid: &str,
    stanza: &str,
    encrypted: bool,
) -> Result<()> {
    sqlx::query("INSERT INTO offline_messages (id, recipient_id, sender_jid, stanza, encrypted) VALUES ($1, $2, $3, $4, $5)")
        .bind(Uuid::new_v4()).bind(recipient_id).bind(sender_jid).bind(stanza).bind(encrypted)
        .execute(pool).await?;
    Ok(())
}

pub async fn take_offline(pool: &PgPool, recipient_id: Uuid) -> Result<Vec<String>> {
    let mut tx = pool.begin().await?;
    let rows = sqlx::query("SELECT id, stanza FROM offline_messages WHERE recipient_id = $1 ORDER BY created_at LIMIT 500 FOR UPDATE")
        .bind(recipient_id).fetch_all(&mut *tx).await?;
    let ids: Vec<Uuid> = rows.iter().map(|r| r.get("id")).collect();
    if !ids.is_empty() {
        sqlx::query("DELETE FROM offline_messages WHERE id = ANY($1)")
            .bind(&ids)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(rows.iter().map(|r| r.get("stanza")).collect())
}

pub async fn cleanup_expired_offline_messages(pool: &PgPool, ttl_days: i64) -> Result<u64> {
    let result = sqlx::query(
        "DELETE FROM offline_messages WHERE created_at < NOW() - make_interval(days => $1::int)",
    )
    .bind(i32::try_from(ttl_days).unwrap_or(i32::MAX))
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

fn archive_from_row(row: &sqlx::postgres::PgRow) -> ArchiveRow {
    ArchiveRow {
        id: row.get("id"),
        peer_jid: row.get("peer_jid"),
        stanza: row.get("stanza"),
        encrypted: row.get("encrypted"),
        created_at: row.get("created_at"),
    }
}
