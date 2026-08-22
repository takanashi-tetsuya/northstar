use anyhow::Result;
use sqlx::PgPool;
use sqlx::Row;
use uuid::Uuid;

#[derive(Debug)]
pub struct UploadSlot {
    pub id: Uuid,
    pub content_type: String,
    pub size: i64,
}

pub async fn create_upload_slot(
    pool: &PgPool,
    user_id: Uuid,
    filename: &str,
    content_type: &str,
    size: i64,
    token_hash: &[u8],
) -> Result<Uuid> {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO upload_slots (id, user_id, filename, content_type, size, token_hash, expires_at) VALUES ($1, $2, $3, $4, $5, $6, NOW() + INTERVAL '15 minutes')",
    )
    .bind(id)
    .bind(user_id)
    .bind(filename)
    .bind(content_type)
    .bind(size)
    .bind(token_hash)
    .execute(pool)
    .await?;
    Ok(id)
}

pub async fn upload_slot_for_put(
    pool: &PgPool,
    id: Uuid,
    token_hash: &[u8],
) -> Result<Option<UploadSlot>> {
    let row = sqlx::query(
        "SELECT id, content_type, size FROM upload_slots WHERE id = $1 AND token_hash = $2 AND expires_at > NOW() AND NOT uploaded",
    )
    .bind(id)
    .bind(token_hash)
    .fetch_optional(pool)
    .await?;
    Ok(row.as_ref().map(upload_slot_from_row))
}

pub async fn complete_upload(pool: &PgPool, id: Uuid) -> Result<()> {
    sqlx::query("UPDATE upload_slots SET uploaded = TRUE WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn uploaded_file(pool: &PgPool, id: Uuid) -> Result<Option<UploadSlot>> {
    let row =
        sqlx::query("SELECT id, content_type, size FROM upload_slots WHERE id = $1 AND uploaded")
            .bind(id)
            .fetch_optional(pool)
            .await?;
    Ok(row.as_ref().map(upload_slot_from_row))
}

fn upload_slot_from_row(row: &sqlx::postgres::PgRow) -> UploadSlot {
    UploadSlot {
        id: row.get("id"),
        content_type: row.get("content_type"),
        size: row.get("size"),
    }
}

pub async fn cleanup_expired_upload_slots(pool: &sqlx::PgPool) -> anyhow::Result<u64> {
    let res = sqlx::query("DELETE FROM upload_slots WHERE expires_at <= NOW() AND NOT uploaded")
        .execute(pool)
        .await?;
    Ok(res.rows_affected())
}
