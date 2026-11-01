//! Durable XEP-0408 MIX/MUC mirror associations.
//!
//! XEP-0408 describes deployment and discovery models; it deliberately does
//! not define a message or presence translation protocol.  The database model
//! is consequently a strict one-to-one association, not a relay queue.  A link
//! may only be created when the same bare JID owns both existing entities.

use anyhow::Result;
use sqlx::{PgPool, Row};
use uuid::Uuid;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MixMucMirror {
    pub mix_channel_id: Uuid,
    pub muc_room_id: Uuid,
    pub localpart: String,
    pub mix_domain: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinkMixMucOutcome {
    Linked,
    AlreadyLinked,
    MissingCounterpart,
    NotCommonOwner,
    Conflict,
}

fn mirror_from_row(row: &sqlx::postgres::PgRow) -> MixMucMirror {
    MixMucMirror {
        mix_channel_id: row.get("mix_channel_id"),
        muc_room_id: row.get("muc_room_id"),
        localpart: row.get("localpart"),
        mix_domain: row.get("service_domain"),
    }
}

pub async fn mix_muc_mirror_for_mix(
    pool: &PgPool,
    mix_channel_id: Uuid,
) -> Result<Option<MixMucMirror>> {
    let row = sqlx::query(
        "SELECT mm.mix_channel_id, mm.muc_room_id, c.localpart, c.service_domain
         FROM mix_muc_mirrors mm
         JOIN mix_channels c ON c.id = mm.mix_channel_id
         JOIN muc_rooms r ON r.id = mm.muc_room_id
         WHERE mm.mix_channel_id = $1 AND r.destroyed_at IS NULL
           AND r.localpart = c.localpart",
    )
    .bind(mix_channel_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.as_ref().map(mirror_from_row))
}

pub async fn mix_muc_mirror_for_muc(
    pool: &PgPool,
    muc_room_id: Uuid,
) -> Result<Option<MixMucMirror>> {
    let row = sqlx::query(
        "SELECT mm.mix_channel_id, mm.muc_room_id, c.localpart, c.service_domain
         FROM mix_muc_mirrors mm
         JOIN mix_channels c ON c.id = mm.mix_channel_id
         JOIN muc_rooms r ON r.id = mm.muc_room_id
         WHERE mm.muc_room_id = $1 AND r.destroyed_at IS NULL
           AND r.localpart = c.localpart",
    )
    .bind(muc_room_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.as_ref().map(mirror_from_row))
}

/// Service-level XEP-0408 discovery is only honest when the deployment really
/// is partially integrated: every local MIX channel has one same-address MUC
/// room and every MUC room has one same-address MIX channel. Entity-level
/// discovery can still describe an individual valid association.
pub async fn mix_muc_mirror_service_complete(pool: &PgPool, mix_domain: &str) -> Result<bool> {
    sqlx::query_scalar(
        "SELECT EXISTS (
             SELECT 1 FROM mix_muc_mirrors mm
             JOIN mix_channels c ON c.id = mm.mix_channel_id
             JOIN muc_rooms r ON r.id = mm.muc_room_id
             WHERE c.service_domain = $1 AND r.destroyed_at IS NULL
               AND c.localpart = r.localpart
         )
         AND NOT EXISTS (
             SELECT 1 FROM mix_channels c
             WHERE c.service_domain = $1
               AND NOT EXISTS (
                   SELECT 1 FROM mix_muc_mirrors mm
                   JOIN muc_rooms r ON r.id = mm.muc_room_id
                   WHERE mm.mix_channel_id = c.id AND r.destroyed_at IS NULL
                     AND r.localpart = c.localpart
               )
         )
         AND NOT EXISTS (
             SELECT 1 FROM muc_rooms r
             WHERE r.destroyed_at IS NULL AND NOT EXISTS (
                 SELECT 1 FROM mix_muc_mirrors mm
                 JOIN mix_channels c ON c.id = mm.mix_channel_id
                 WHERE mm.muc_room_id = r.id
                   AND c.service_domain = $1
                   AND c.localpart = r.localpart
             )
         )",
    )
    .bind(northstar_xmpp_types::jid::prepare_domainpart(mix_domain)?)
    .fetch_one(pool)
    .await
    .map_err(Into::into)
}

/// Atomically link existing, same-address local entities when `actor_bare_jid`
/// is still an owner on both sides.  Uniqueness constraints make concurrent
/// attempts idempotent and prevent fan-in/fan-out mirror graphs.
pub async fn link_mix_muc_by_localpart(
    pool: &PgPool,
    mix_domain: &str,
    localpart: &str,
    actor_bare_jid: &str,
    local_domain: &str,
) -> Result<LinkMixMucOutcome> {
    let mix_domain = northstar_xmpp_types::jid::prepare_domainpart(mix_domain)?;
    let local_domain = northstar_xmpp_types::jid::prepare_domainpart(local_domain)?;
    let localpart = northstar_xmpp_types::jid::prepare_localpart(localpart)?;
    let actor = northstar_xmpp_types::jid::CanonicalJid::parse_bare(actor_bare_jid)?;
    let Some(actor_localpart) = actor.localpart() else {
        return Ok(LinkMixMucOutcome::NotCommonOwner);
    };
    let actor_bare_jid = actor.to_string();

    let mut transaction = pool.begin().await?;
    let pair = sqlx::query(
        "SELECT c.id AS mix_channel_id, r.id AS muc_room_id
         FROM mix_channels c
         JOIN muc_rooms r ON r.localpart = c.localpart
         WHERE c.service_domain = $1 AND c.localpart = $2
           AND r.destroyed_at IS NULL
         FOR UPDATE OF c, r",
    )
    .bind(&mix_domain)
    .bind(&localpart)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(pair) = pair else {
        transaction.rollback().await?;
        return Ok(LinkMixMucOutcome::MissingCounterpart);
    };
    let mix_channel_id: Uuid = pair.get("mix_channel_id");
    let muc_room_id: Uuid = pair.get("muc_room_id");

    let mix_owner: bool = sqlx::query_scalar(
        "SELECT EXISTS (
             SELECT 1 FROM mix_channel_roles
             WHERE channel_id = $1 AND jid = $2 AND role = 'owner'
         )",
    )
    .bind(mix_channel_id)
    .bind(&actor_bare_jid)
    .fetch_one(&mut *transaction)
    .await?;
    let muc_owner: bool = if actor.domainpart() == local_domain {
        sqlx::query_scalar(
            "SELECT EXISTS (
                 SELECT 1 FROM muc_affiliations a
                 JOIN users u ON u.id = a.user_id
                 WHERE a.room_id = $1 AND u.username = $2 AND a.affiliation = 'owner'
             )",
        )
        .bind(muc_room_id)
        .bind(actor_localpart)
        .fetch_one(&mut *transaction)
        .await?
    } else {
        sqlx::query_scalar(
            "SELECT EXISTS (
                 SELECT 1 FROM muc_external_affiliations
                 WHERE room_id = $1 AND jid = $2 AND affiliation = 'owner'
             )",
        )
        .bind(muc_room_id)
        .bind(&actor_bare_jid)
        .fetch_one(&mut *transaction)
        .await?
    };
    if !mix_owner || !muc_owner {
        transaction.rollback().await?;
        return Ok(LinkMixMucOutcome::NotCommonOwner);
    }

    if let Some(existing) = sqlx::query(
        "SELECT mix_channel_id, muc_room_id FROM mix_muc_mirrors
         WHERE mix_channel_id = $1 OR muc_room_id = $2
         FOR UPDATE",
    )
    .bind(mix_channel_id)
    .bind(muc_room_id)
    .fetch_optional(&mut *transaction)
    .await?
    {
        let matches = existing.get::<Uuid, _>("mix_channel_id") == mix_channel_id
            && existing.get::<Uuid, _>("muc_room_id") == muc_room_id;
        transaction.rollback().await?;
        return Ok(if matches {
            LinkMixMucOutcome::AlreadyLinked
        } else {
            LinkMixMucOutcome::Conflict
        });
    }

    sqlx::query(
        "INSERT INTO mix_muc_mirrors (mix_channel_id, muc_room_id, created_by)
         VALUES ($1, $2, $3)",
    )
    .bind(mix_channel_id)
    .bind(muc_room_id)
    .bind(&actor_bare_jid)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(LinkMixMucOutcome::Linked)
}

/// Reconcile pre-existing same-localpart entities at startup.  Only pairs for
/// which the recorded MIX creator remains an owner of both sides are linked.
/// This is set-based and conflict-safe, avoiding unbounded per-channel startup
/// queries and preserving any existing explicit one-to-one association.
pub async fn reconcile_mix_muc_mirrors(
    pool: &PgPool,
    mix_domain: &str,
    local_domain: &str,
) -> Result<u64> {
    let mix_domain = northstar_xmpp_types::jid::prepare_domainpart(mix_domain)?;
    let local_domain = northstar_xmpp_types::jid::prepare_domainpart(local_domain)?;
    let result = sqlx::query(
        "INSERT INTO mix_muc_mirrors (mix_channel_id, muc_room_id, created_by)
         SELECT c.id, r.id, c.creator_jid
         FROM mix_channels c
         JOIN muc_rooms r ON r.localpart = c.localpart
         WHERE c.service_domain = $1 AND r.destroyed_at IS NULL
           AND EXISTS (
               SELECT 1 FROM mix_channel_roles cr
               WHERE cr.channel_id = c.id
                 AND cr.jid = c.creator_jid
                 AND cr.role = 'owner'
           )
           AND (
               (
                   split_part(c.creator_jid, '@', 2) = $2
                   AND EXISTS (
                       SELECT 1 FROM muc_affiliations ma
                       JOIN users u ON u.id = ma.user_id
                       WHERE ma.room_id = r.id
                         AND ma.affiliation = 'owner'
                         AND u.username = split_part(c.creator_jid, '@', 1)
                   )
               )
               OR EXISTS (
                   SELECT 1 FROM muc_external_affiliations me
                   WHERE me.room_id = r.id
                     AND me.affiliation = 'owner'
                     AND me.jid = c.creator_jid
               )
           )
         ON CONFLICT DO NOTHING",
    )
    .bind(&mix_domain)
    .bind(&local_domain)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}
