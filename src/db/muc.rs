use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use sqlx::Row;
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct MucRoom {
    pub id: Uuid,
    pub localpart: String,
    pub title: Option<String>,
    pub persistent: bool,
    pub members_only: bool,
    pub public: bool,
    pub moderated: bool,
    pub non_anonymous: bool,
    pub max_occupants: i32,
    pub subject: Option<String>,
}

#[derive(Debug)]
pub struct MucMessage {
    pub sender_jid: String,
    pub stanza: String,
    pub created_at: DateTime<Utc>,
}

pub async fn get_or_create_muc_room(
    pool: &PgPool,
    localpart: &str,
    creator_id: Uuid,
) -> Result<(MucRoom, bool)> {
    let mut transaction = pool.begin().await?;
    let room_id = Uuid::new_v4();
    let inserted = sqlx::query(
        "INSERT INTO muc_rooms (id, localpart, owner_id) VALUES ($1, $2, $3) ON CONFLICT (localpart) DO NOTHING",
    )
    .bind(room_id)
    .bind(localpart)
    .bind(creator_id)
    .execute(&mut *transaction)
    .await?
    .rows_affected()
        == 1;
    if inserted {
        sqlx::query(
            "INSERT INTO muc_affiliations (room_id, user_id, affiliation) VALUES ($1, $2, 'owner')",
        )
        .bind(room_id)
        .bind(creator_id)
        .execute(&mut *transaction)
        .await?;
    }
    let row = sqlx::query("SELECT * FROM muc_rooms WHERE localpart = $1")
        .bind(localpart)
        .fetch_one(&mut *transaction)
        .await?;
    transaction.commit().await?;
    Ok((muc_room_from_row(&row), inserted))
}

pub async fn muc_room(pool: &PgPool, localpart: &str) -> Result<Option<MucRoom>> {
    let row = sqlx::query("SELECT * FROM muc_rooms WHERE localpart = $1")
        .bind(localpart)
        .fetch_optional(pool)
        .await?;
    Ok(row.as_ref().map(muc_room_from_row))
}

pub async fn public_muc_rooms(pool: &PgPool, limit: i64) -> Result<Vec<MucRoom>> {
    let rows = sqlx::query("SELECT * FROM muc_rooms WHERE public ORDER BY localpart LIMIT $1")
        .bind(limit.clamp(1, 500))
        .fetch_all(pool)
        .await?;
    Ok(rows.iter().map(muc_room_from_row).collect())
}

pub async fn muc_affiliation(
    pool: &PgPool,
    room_id: Uuid,
    user_id: Uuid,
) -> Result<Option<String>> {
    sqlx::query_scalar(
        "SELECT affiliation FROM muc_affiliations WHERE room_id = $1 AND user_id = $2",
    )
    .bind(room_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .map_err(Into::into)
}

pub async fn archive_muc_message(
    pool: &PgPool,
    room_id: Uuid,
    sender_jid: &str,
    nick: &str,
    stanza: &str,
    encrypted: bool,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO muc_messages (id, room_id, sender_jid, nick, stanza, encrypted) VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(Uuid::new_v4())
    .bind(room_id)
    .bind(sender_jid)
    .bind(nick)
    .bind(stanza)
    .bind(encrypted)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn set_muc_subject(pool: &PgPool, room_id: Uuid, subject: &str) -> Result<()> {
    sqlx::query("UPDATE muc_rooms SET subject = $2 WHERE id = $1")
        .bind(room_id)
        .bind(subject)
        .execute(pool)
        .await?;
    Ok(())
}

pub struct MucConfigUpdate<'a> {
    pub title: Option<&'a str>,
    pub persistent: bool,
    pub members_only: bool,
    pub public: bool,
    pub moderated: bool,
    pub non_anonymous: bool,
    pub max_occupants: i32,
}

pub async fn update_muc_config(
    pool: &PgPool,
    room_id: Uuid,
    config: MucConfigUpdate<'_>,
) -> Result<()> {
    sqlx::query(
        "UPDATE muc_rooms SET title = $2, persistent = $3, members_only = $4, public = $5, moderated = $6, non_anonymous = $7, max_occupants = $8 WHERE id = $1",
    )
    .bind(room_id)
    .bind(config.title)
    .bind(config.persistent)
    .bind(config.members_only)
    .bind(config.public)
    .bind(config.moderated)
    .bind(config.non_anonymous)
    .bind(config.max_occupants.clamp(2, 1000))
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn delete_muc_room(pool: &PgPool, room_id: Uuid) -> Result<()> {
    sqlx::query("DELETE FROM muc_rooms WHERE id = $1")
        .bind(room_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn muc_history(pool: &PgPool, room_id: Uuid, limit: i64) -> Result<Vec<MucMessage>> {
    let rows = sqlx::query(
        "SELECT sender_jid, stanza, created_at FROM muc_messages WHERE room_id = $1 ORDER BY created_at DESC, id DESC LIMIT $2",
    )
    .bind(room_id)
    .bind(limit.clamp(1, 100))
    .fetch_all(pool)
    .await?;
    let mut messages: Vec<MucMessage> = rows
        .iter()
        .map(|row| MucMessage {
            sender_jid: row.get("sender_jid"),
            stanza: row.get("stanza"),
            created_at: row.get("created_at"),
        })
        .collect();
    messages.reverse();
    Ok(messages)
}

pub async fn delete_temporary_muc_room(pool: &PgPool, room_id: Uuid) -> Result<()> {
    sqlx::query("DELETE FROM muc_rooms WHERE id = $1 AND NOT persistent")
        .bind(room_id)
        .execute(pool)
        .await?;
    Ok(())
}

fn muc_room_from_row(row: &sqlx::postgres::PgRow) -> MucRoom {
    MucRoom {
        id: row.get("id"),
        localpart: row.get("localpart"),
        title: row.get("title"),
        persistent: row.get("persistent"),
        members_only: row.get("members_only"),
        public: row.get("public"),
        moderated: row.get("moderated"),
        non_anonymous: row.get("non_anonymous"),
        max_occupants: row.get("max_occupants"),
        subject: row.get("subject"),
    }
}

pub async fn set_muc_affiliation(
    pool: &PgPool,
    room_id: Uuid,
    username: &str,
    affiliation: &str,
) -> Result<()> {
    if affiliation == "none" {
        sqlx::query(
            "DELETE FROM muc_affiliations WHERE room_id = $1 AND user_id = (SELECT id FROM users WHERE username = $2)",
        )
        .bind(room_id)
        .bind(username)
        .execute(pool)
        .await?;
    } else {
        sqlx::query(
            "INSERT INTO muc_affiliations (room_id, user_id, affiliation, updated_at) 
             SELECT $1, id, $3, NOW() FROM users WHERE username = $2
             ON CONFLICT (room_id, user_id) DO UPDATE SET affiliation = EXCLUDED.affiliation, updated_at = NOW()",
        )
        .bind(room_id)
        .bind(username)
        .bind(affiliation)
        .execute(pool)
        .await?;
    }
    Ok(())
}

pub async fn get_muc_affiliations(
    pool: &PgPool,
    room_id: Uuid,
    affiliation: &str,
) -> Result<Vec<String>> {
    let rows = sqlx::query(
        "SELECT u.username FROM muc_affiliations a JOIN users u ON a.user_id = u.id WHERE a.room_id = $1 AND a.affiliation = $2",
    )
    .bind(room_id)
    .bind(affiliation)
    .fetch_all(pool)
    .await?;
    let mut usernames = Vec::with_capacity(rows.len());
    for row in rows {
        usernames.push(row.get::<String, _>("username"));
    }
    Ok(usernames)
}
