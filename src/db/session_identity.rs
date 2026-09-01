//! Domain-bound RFC 7622 migration for durable authorization session state.

use anyhow::{Context, Result};
use serde_json::Value;
#[cfg(test)]
use sqlx::PgPool;
use sqlx::{Postgres, Row, Transaction};
use std::collections::BTreeMap;
use uuid::Uuid;

const CANONICALIZER_VERSION: i32 = 2;

#[derive(Debug)]
struct SmRow {
    id: Uuid,
    user_id: Uuid,
    full_jid: String,
    canonical_full_jid: String,
    resource: String,
    canonical_resource: String,
    joined_rooms: Value,
    canonical_joined_rooms: Value,
    directed_presence: Value,
    canonical_directed_presence: Value,
}

#[derive(Debug)]
struct AdminRow {
    id: Uuid,
    owner_full_jid: String,
    canonical_owner_full_jid: String,
}

#[derive(Debug)]
struct IntentRow {
    room_jid: String,
    canonical_room_jid: String,
    localpart: String,
    canonical_localpart: String,
}

fn expected_user_bare(username: &str, domain: &str) -> Result<String> {
    crate::jid::canonicalize_bare(&format!("{username}@{domain}"))
}

fn canonical_owned_full(
    table: &str,
    row: &str,
    value: &str,
    username: &str,
    domain: &str,
) -> Result<String> {
    let full = crate::jid::canonical_session_key(value).with_context(|| {
        format!("session JID migration rejected invalid full JID in {table} row {row}: {value:?}")
    })?;
    anyhow::ensure!(
        crate::jid::canonical_bare_key(&full)? == expected_user_bare(username, domain)?,
        "session JID migration rejected ownership mismatch in {table} row {row}: {value:?} does not belong to {username:?}@{domain:?}; correct or remove this row and restart"
    );
    Ok(full)
}

#[cfg(test)]
pub async fn canonicalize_session_authorization_storage(
    pool: &PgPool,
    configured_domain: &str,
) -> Result<()> {
    let mut transaction = pool.begin().await?;
    canonicalize_session_authorization_storage_in_transaction(&mut transaction, configured_domain)
        .await?;
    transaction.commit().await?;
    Ok(())
}

pub(crate) async fn canonicalize_session_authorization_storage_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    configured_domain: &str,
) -> Result<()> {
    let domain = crate::jid::prepare_domainpart(configured_domain)
        .context("configured XMPP domain is invalid during session identity migration")?;
    let migration = format!("session-authorization-rfc7622-ulabel-v2:{domain}");
    let conference_domain = crate::jid::prepare_domainpart(&format!("conference.{domain}"))?;
    sqlx::query("SET LOCAL lock_timeout='30s'")
        .execute(&mut **transaction)
        .await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,7622))")
        .bind(&migration)
        .execute(&mut **transaction)
        .await
        .context(
            "timed out after 30 seconds waiting for the session identity migration gate; stop another concurrent migration, then restart",
        )?;
    let complete: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM jid_identity_migrations WHERE migration=$1 AND canonicalizer_version=$2)",
    )
    .bind(&migration)
    .bind(CANONICALIZER_VERSION)
    .fetch_one(&mut **transaction)
    .await?;
    if complete {
        return Ok(());
    }

    sqlx::query(
        "LOCK TABLE users, sm_resume_sessions, admin_command_sessions,
         api_muc_destroy_intents, api_operation_journal IN ACCESS EXCLUSIVE MODE",
    )
    .execute(&mut **transaction)
    .await
    .context(
        "timed out after 30 seconds waiting to lock session authorization tables; stop other Northstar nodes using this database, then restart the migration",
    )?;

    let sm = load_sm(transaction, &domain).await?;
    ensure_sm_unique(&sm)?;
    let admin = load_admin(transaction, &domain).await?;
    let intents = load_intents(transaction, &conference_domain).await?;
    ensure_intents_unique(&intents)?;

    let mut transformed = 0_i64;
    for row in &sm {
        if row.full_jid != row.canonical_full_jid
            || row.resource != row.canonical_resource
            || row.joined_rooms != row.canonical_joined_rooms
            || row.directed_presence != row.canonical_directed_presence
        {
            transformed += sqlx::query(
                "UPDATE sm_resume_sessions
                 SET full_jid=$2,resource=$3,joined_rooms=$4,directed_presence=$5
                 WHERE id=$1",
            )
            .bind(row.id)
            .bind(&row.canonical_full_jid)
            .bind(&row.canonical_resource)
            .bind(&row.canonical_joined_rooms)
            .bind(&row.canonical_directed_presence)
            .execute(&mut **transaction)
            .await?
            .rows_affected() as i64;
        }
    }
    for row in &admin {
        if row.owner_full_jid != row.canonical_owner_full_jid {
            transformed +=
                sqlx::query("UPDATE admin_command_sessions SET owner_full_jid=$2 WHERE id=$1")
                    .bind(row.id)
                    .bind(&row.canonical_owner_full_jid)
                    .execute(&mut **transaction)
                    .await?
                    .rows_affected() as i64;
        }
    }
    for row in &intents {
        if row.room_jid != row.canonical_room_jid || row.localpart != row.canonical_localpart {
            transformed += sqlx::query(
                "UPDATE api_muc_destroy_intents SET room_jid=$2,localpart=$3 WHERE room_jid=$1",
            )
            .bind(&row.room_jid)
            .bind(&row.canonical_room_jid)
            .bind(&row.canonical_localpart)
            .execute(&mut **transaction)
            .await?
            .rows_affected() as i64;
        }
    }

    sqlx::query(
        "INSERT INTO jid_identity_migrations(migration,canonicalizer_version,transformed_rows) VALUES($1,$2,$3)",
    )
    .bind(&migration)
    .bind(CANONICALIZER_VERSION)
    .bind(transformed)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn load_sm(transaction: &mut Transaction<'_, Postgres>, domain: &str) -> Result<Vec<SmRow>> {
    let rows = sqlx::query(
        "SELECT s.id,s.user_id,u.username,s.full_jid,s.resource,s.joined_rooms,s.directed_presence
         FROM sm_resume_sessions s JOIN users u ON u.id=s.user_id ORDER BY s.id",
    )
    .fetch_all(&mut **transaction)
    .await?;
    let mut result = Vec::with_capacity(rows.len());
    for row in rows {
        let id: Uuid = row.get("id");
        let user_id: Uuid = row.get("user_id");
        let username: String = row.get("username");
        let full_jid: String = row.get("full_jid");
        let resource: String = row.get("resource");
        let canonical_full_jid = canonical_owned_full(
            "sm_resume_sessions.full_jid",
            &id.to_string(),
            &full_jid,
            &username,
            domain,
        )?;
        let canonical_resource =
            crate::jid::prepare_resourcepart(&resource).with_context(|| {
                format!(
                    "session JID migration rejected invalid resource in SM row {id}: {resource:?}"
                )
            })?;
        let full_resource = crate::jid::CanonicalJid::parse(&canonical_full_jid)?
            .resourcepart()
            .context("canonical SM full JID lost its resource")?
            .to_owned();
        anyhow::ensure!(
            canonical_resource == full_resource,
            "session JID migration rejected SM row {id}: resource column {resource:?} does not match full_jid resource {full_resource:?}"
        );
        let joined_rooms: Value = row.get("joined_rooms");
        let canonical_joined_rooms = canonicalize_joined_rooms(id, &joined_rooms)?;
        let directed_presence: Value = row.get("directed_presence");
        let canonical_directed_presence = canonicalize_directed(id, &directed_presence)?;
        result.push(SmRow {
            id,
            user_id,
            full_jid,
            canonical_full_jid,
            resource,
            canonical_resource,
            joined_rooms,
            canonical_joined_rooms,
            directed_presence,
            canonical_directed_presence,
        });
    }
    Ok(result)
}

fn canonicalize_joined_rooms(id: Uuid, value: &Value) -> Result<Value> {
    let memberships = serde_json::from_value::<Vec<super::sm::SmMucMembership>>(value.clone())
        .with_context(|| format!("invalid joined_rooms JSON in SM row {id}"))?;
    let mut unique = BTreeMap::new();
    let mut canonical = Vec::with_capacity(memberships.len());
    for mut membership in memberships {
        let room = crate::jid::canonicalize_bare(&membership.room_jid).with_context(|| {
            format!(
                "invalid joined room {:?} in SM row {id}",
                membership.room_jid
            )
        })?;
        anyhow::ensure!(
            crate::jid::CanonicalJid::parse_bare(&room)?
                .localpart()
                .is_some(),
            "SM row {id} joined room must have a localpart: {room:?}"
        );
        if let Some(previous) = unique.insert(room.clone(), membership.room_jid.clone()) {
            anyhow::bail!(
                "session JID migration found joined-room collision in SM row {id}: {previous:?} and {:?} both map to {room:?}",
                membership.room_jid
            );
        }
        membership.room_jid = room;
        canonical.push(membership);
    }
    Ok(serde_json::to_value(canonical)?)
}

fn canonicalize_directed(id: Uuid, value: &Value) -> Result<Value> {
    let values = serde_json::from_value::<Vec<String>>(value.clone())
        .with_context(|| format!("invalid directed_presence JSON in SM row {id}"))?;
    let mut unique = BTreeMap::new();
    let mut canonical = Vec::with_capacity(values.len());
    for original in values {
        let jid = crate::jid::canonicalize(&original).with_context(|| {
            format!("invalid directed presence JID {original:?} in SM row {id}")
        })?;
        if let Some(previous) = unique.insert(jid.clone(), original.clone()) {
            anyhow::bail!(
                "session JID migration found directed-presence collision in SM row {id}: {previous:?} and {original:?} both map to {jid:?}"
            );
        }
        canonical.push(jid);
    }
    Ok(serde_json::to_value(canonical)?)
}

fn ensure_sm_unique(rows: &[SmRow]) -> Result<()> {
    let mut sessions = BTreeMap::<(Uuid, &str), Uuid>::new();
    for row in rows {
        if let Some(previous) = sessions.insert((row.user_id, &row.canonical_full_jid), row.id) {
            anyhow::bail!(
                "session JID migration found canonical SM binding collision for user {} full JID {:?}: sessions {previous} and {}; remove the stale session explicitly and restart",
                row.user_id,
                row.canonical_full_jid,
                row.id
            );
        }
    }
    Ok(())
}

async fn load_admin(
    transaction: &mut Transaction<'_, Postgres>,
    domain: &str,
) -> Result<Vec<AdminRow>> {
    sqlx::query(
        "SELECT s.id,u.username,s.owner_full_jid FROM admin_command_sessions s
         JOIN users u ON u.id=s.owner_id ORDER BY s.id",
    )
    .fetch_all(&mut **transaction)
    .await?
    .into_iter()
    .map(|row| {
        let id: Uuid = row.get("id");
        let username: String = row.get("username");
        let owner_full_jid: String = row.get("owner_full_jid");
        let canonical_owner_full_jid = canonical_owned_full(
            "admin_command_sessions.owner_full_jid",
            &id.to_string(),
            &owner_full_jid,
            &username,
            domain,
        )?;
        Ok(AdminRow {
            id,
            owner_full_jid,
            canonical_owner_full_jid,
        })
    })
    .collect()
}

async fn load_intents(
    transaction: &mut Transaction<'_, Postgres>,
    conference_domain: &str,
) -> Result<Vec<IntentRow>> {
    let rows = sqlx::query(
        "SELECT i.room_jid,i.localpart,o.kind,o.target,o.payload
         FROM api_muc_destroy_intents i JOIN api_operation_journal o ON o.id=i.operation_id
         ORDER BY i.room_jid",
    )
    .fetch_all(&mut **transaction)
    .await?;
    let mut result = Vec::with_capacity(rows.len());
    for row in rows {
        let room_jid: String = row.get("room_jid");
        let localpart: String = row.get("localpart");
        let canonical_room_jid = crate::jid::canonicalize_bare(&room_jid)
            .with_context(|| format!("invalid MUC destroy intent room JID {room_jid:?}"))?;
        let parsed = crate::jid::CanonicalJid::parse_bare(&canonical_room_jid)?;
        let room_localpart = parsed
            .localpart()
            .context("MUC destroy intent room must contain a localpart")?;
        anyhow::ensure!(
            parsed.domainpart() == conference_domain,
            "MUC destroy intent {room_jid:?} is outside configured service {conference_domain:?}"
        );
        let canonical_localpart = crate::jid::prepare_localpart(&localpart)
            .with_context(|| format!("invalid MUC destroy intent localpart {localpart:?}"))?;
        anyhow::ensure!(
            canonical_localpart == room_localpart,
            "MUC destroy intent room/localpart mismatch: {room_jid:?} vs {localpart:?}"
        );
        let kind: String = row.get("kind");
        let target: Option<String> = row.get("target");
        let payload: Value = row.get("payload");
        let payload_room = payload.get("room_jid").and_then(Value::as_str);
        anyhow::ensure!(
            kind == "admin.muc_destroy"
                && target.as_deref() == Some(canonical_room_jid.as_str())
                && payload_room == Some(canonical_room_jid.as_str()),
            "MUC destroy intent {room_jid:?} disagrees with immutable operation kind/target/payload; repair or cancel the operation explicitly, then restart"
        );
        result.push(IntentRow {
            room_jid,
            canonical_room_jid,
            localpart,
            canonical_localpart,
        });
    }
    Ok(result)
}

fn ensure_intents_unique(rows: &[IntentRow]) -> Result<()> {
    let mut rooms = BTreeMap::new();
    let mut localparts = BTreeMap::new();
    for row in rows {
        if let Some(previous) = rooms.insert(&row.canonical_room_jid, &row.room_jid) {
            anyhow::bail!(
                "session JID migration found MUC intent room collision: {previous:?} and {:?} map to {:?}",
                row.room_jid,
                row.canonical_room_jid
            );
        }
        if let Some(previous) = localparts.insert(&row.canonical_localpart, &row.room_jid) {
            anyhow::bail!(
                "session JID migration found MUC intent localpart collision: {previous:?} and {:?} use {:?}",
                row.room_jid,
                row.canonical_localpart
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use serde_json::json;

    async fn insert_sm(
        pool: &PgPool,
        id: Uuid,
        user_id: Uuid,
        token_byte: u8,
        full_jid: &str,
        resource: &str,
    ) {
        sqlx::query(
            "INSERT INTO sm_resume_sessions
               (id,token_hash,user_id,auth_generation,full_jid,resource,connection_id,
                resume_timeout_seconds,peer_ip,joined_rooms,directed_presence,
                resumable,live_lease_until,expires_at)
             VALUES($1,$2,$3,0,$4,$5,$6,300,'192.0.2.1',$7,$8,TRUE,NOW(),NOW()+INTERVAL '5 minutes')",
        )
        .bind(id)
        .bind(vec![token_byte; 32])
        .bind(user_id)
        .bind(full_jid)
        .bind(resource)
        .bind(Uuid::new_v4())
        .bind(json!([{"room_jid":"room@conference.bücher.example","nick":"Nick"}]))
        .bind(json!([
            "friend@bücher.example/Phone",
            "friend@bücher.example/phone"
        ]))
        .execute(pool)
        .await
        .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires a random isolated TEST_DATABASE_URL PostgreSQL schema"]
    async fn postgres_session_identity_is_owned_atomic_resource_exact_and_idempotent() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to a random isolated PostgreSQL schema");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .unwrap();
        db::migrate(&pool).await.unwrap();
        let user = db::create_user(
            &pool,
            "alice",
            "test-password-long-enough",
            true,
            false,
            4096,
            false,
        )
        .await
        .unwrap();
        let sm_id = Uuid::new_v4();
        insert_sm(
            &pool,
            sm_id,
            user.id,
            31,
            "alice@bücher.example/Phone",
            "Phone",
        )
        .await;
        let lowercase_resource_id = Uuid::new_v4();
        insert_sm(
            &pool,
            lowercase_resource_id,
            user.id,
            30,
            "alice@bücher.example/phone",
            "phone",
        )
        .await;
        sqlx::query(
            "INSERT INTO sm_resume_stanzas(session_id,position,stanza)
             VALUES($1,0,'<message from=\"alice@bücher.example/Phone\"/>')",
        )
        .bind(sm_id)
        .execute(&pool)
        .await
        .unwrap();
        let admin_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO admin_command_sessions
               (id,owner_id,owner_full_jid,owner_auth_generation,node,stage,expires_at)
             VALUES($1,$2,'alice@bücher.example/Console',0,'test:command','form',NOW()+INTERVAL '5 minutes')",
        )
        .bind(admin_id)
        .bind(user.id)
        .execute(&pool)
        .await
        .unwrap();

        let operation_id = Uuid::new_v4();
        let canonical_room = "café@conference.bücher.example";
        sqlx::query(
            "INSERT INTO api_operation_journal
               (id,request_id,actor_id,actor_subject_id,actor_auth_generation,
                authorization_policy,kind,target,status,payload,result,completed_at)
             VALUES($1,$2,$3,$3,0,'committed_consequence','admin.muc_destroy',$4,
                    'succeeded',$5,'{}',clock_timestamp())",
        )
        .bind(operation_id)
        .bind(Uuid::new_v4())
        .bind(user.id)
        .bind(canonical_room)
        .bind(json!({"room_jid":canonical_room}))
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO api_muc_destroy_intents(room_jid,localpart,operation_id)
             VALUES('café@conference.bücher.example','café',$1)",
        )
        .bind(operation_id)
        .execute(&pool)
        .await
        .unwrap();

        canonicalize_session_authorization_storage(&pool, "bücher.example")
            .await
            .unwrap();
        let sm: (String, String, Value, Value) = sqlx::query_as(
            "SELECT full_jid,resource,joined_rooms,directed_presence
             FROM sm_resume_sessions WHERE id=$1",
        )
        .bind(sm_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(sm.0, "alice@bücher.example/Phone");
        assert_eq!(sm.1, "Phone");
        assert_eq!(
            sm.2,
            json!([{"room_jid":"room@conference.bücher.example","nick":"Nick"}])
        );
        let lowercase_resource: (String, String) =
            sqlx::query_as("SELECT full_jid,resource FROM sm_resume_sessions WHERE id=$1")
                .bind(lowercase_resource_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            lowercase_resource,
            ("alice@bücher.example/phone".to_owned(), "phone".to_owned())
        );
        assert_eq!(
            sm.3,
            json!(["friend@bücher.example/Phone", "friend@bücher.example/phone"])
        );
        let raw_stanza: String = sqlx::query_scalar(
            "SELECT stanza FROM sm_resume_stanzas WHERE session_id=$1 AND position=0",
        )
        .bind(sm_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(raw_stanza, "<message from=\"alice@bücher.example/Phone\"/>");
        let owner: String =
            sqlx::query_scalar("SELECT owner_full_jid FROM admin_command_sessions WHERE id=$1")
                .bind(admin_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(owner, "alice@bücher.example/Console");
        let intent: (String, String) = sqlx::query_as(
            "SELECT room_jid,localpart FROM api_muc_destroy_intents WHERE operation_id=$1",
        )
        .bind(operation_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(intent, (canonical_room.to_owned(), "café".to_owned()));
        let operation_payload: Value =
            sqlx::query_scalar("SELECT payload FROM api_operation_journal WHERE id=$1")
                .bind(operation_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(operation_payload, json!({"room_jid":canonical_room}));
        let orphans: (i64, i64, i64) = sqlx::query_as(
            "SELECT
               (SELECT COUNT(*) FROM sm_resume_stanzas q LEFT JOIN sm_resume_sessions s ON s.id=q.session_id WHERE s.id IS NULL),
               (SELECT COUNT(*) FROM admin_command_sessions a LEFT JOIN users u ON u.id=a.owner_id WHERE u.id IS NULL),
               (SELECT COUNT(*) FROM api_muc_destroy_intents i LEFT JOIN api_operation_journal o ON o.id=i.operation_id WHERE o.id IS NULL)",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(orphans, (0, 0, 0));
        canonicalize_session_authorization_storage(&pool, "bücher.example")
            .await
            .unwrap();

        let wrong_domain = canonicalize_session_authorization_storage(&pool, "other.example")
            .await
            .unwrap_err()
            .to_string();
        assert!(
            wrong_domain.contains("ownership mismatch"),
            "{wrong_domain}"
        );
        let wrong_marker_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM jid_identity_migrations WHERE migration=$1)",
        )
        .bind("session-authorization-rfc7622-ulabel-v2:other.example")
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(!wrong_marker_exists);

        let marker = "session-authorization-rfc7622-ulabel-v2:bücher.example";
        sqlx::query("DELETE FROM jid_identity_migrations WHERE migration=$1")
            .bind(marker)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("UPDATE admin_command_sessions SET owner_full_jid='alice@bücher.example/Console' WHERE id=$1")
            .bind(admin_id)
            .execute(&pool)
            .await
            .unwrap();
        let collision_id = Uuid::new_v4();
        insert_sm(
            &pool,
            collision_id,
            user.id,
            32,
            "alice@bücher.example/Phone",
            "Phone",
        )
        .await;
        let error = canonicalize_session_authorization_storage(&pool, "bücher.example")
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("canonical SM binding collision"), "{error}");
        let untouched: String =
            sqlx::query_scalar("SELECT full_jid FROM sm_resume_sessions WHERE id=$1")
                .bind(collision_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(untouched, "alice@bücher.example/Phone");
        let untouched_admin: String =
            sqlx::query_scalar("SELECT owner_full_jid FROM admin_command_sessions WHERE id=$1")
                .bind(admin_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(untouched_admin, "alice@bücher.example/Console");
        let marker_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM jid_identity_migrations WHERE migration=$1)",
        )
        .bind(marker)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(!marker_exists);
    }
}
