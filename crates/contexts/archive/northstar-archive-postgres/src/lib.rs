//! PostgreSQL adapter of the archive context: the personal message archive and its XEP-0313 preferences, and the
//! MAM page and boundary queries over personal and room archives.

#![forbid(unsafe_code)]

use anyhow::Result;
use northstar_archive_application::MAX_MAM_PAGE_SIZE;
use northstar_archive_core::{
    classify_mam_blocked_jids, decide_mam_archive_admission, finish_mam_page, mam_referenced_ids,
    resolve_mam_query, MamArchiveAdmissionFacts, MamBlockedIdentitySource, MamBlockedPattern,
    MamQueryBounds,
};
use northstar_xep_0313::MAX_PREFS_JIDS;
use sqlx::{PgPool, Postgres, QueryBuilder, Row, Transaction};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

mod mam_query;

pub use self::mam_query::*;

pub use northstar_archive_core::{
    ArchiveBoundary, ArchivePage, ArchiveRow, MamArchiveQuery,
    MamDbRoomReadOutcome as MamRoomReadOutcome, MamPreferences, MamRoomArchiveAccess, MamRsmPage,
};

/// Snapshot the oldest and newest viewer-visible MAM ids for XEP-0386 Bind 2
/// metadata. Visibility, both endpoints and any concurrent writer are held to
/// one repeatable-read snapshot.
pub async fn archive_boundaries_visible(
    pool: &PgPool,
    owner_id: Uuid,
) -> Result<(Option<ArchiveBoundary>, Option<ArchiveBoundary>)> {
    archive_boundaries_for(pool, MamArchiveSource::User(owner_id), Some(owner_id)).await
}

/// Read personal Bind 2/MAM boundary metadata inside a caller-owned
/// authorization transaction.  AuthenticationService uses this after locking
/// the exact account generation, so a password rotation or account disablement
/// cannot commit between credential validation and the metadata snapshot.
pub async fn archive_boundaries_visible_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    owner_id: Uuid,
) -> Result<(Option<ArchiveBoundary>, Option<ArchiveBoundary>)> {
    archive_boundaries_for_in_transaction(
        transaction,
        MamArchiveSource::User(owner_id),
        Some(owner_id),
    )
    .await
}

#[cfg(any(test, feature = "test-support"))]
pub async fn muc_archive_boundaries_visible(
    pool: &PgPool,
    room_id: Uuid,
    viewer_id: Uuid,
) -> Result<(Option<ArchiveBoundary>, Option<ArchiveBoundary>)> {
    archive_boundaries_for(pool, MamArchiveSource::Muc(room_id), Some(viewer_id)).await
}

pub async fn mam_preferences(pool: &PgPool, user_id: Uuid) -> Result<MamPreferences> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *transaction)
        .await?;
    let preferences = mam_preferences_in_transaction(&mut transaction, user_id).await?;
    transaction.commit().await?;
    Ok(preferences)
}

pub async fn mam_preferences_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
) -> Result<MamPreferences> {
    let default_policy = sqlx::query_scalar::<_, String>(
        "SELECT default_policy FROM mam_preferences WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_optional(&mut **transaction)
    .await?
    .unwrap_or_else(|| "always".to_owned());
    let rows = sqlx::query(
        "SELECT jid, policy FROM mam_preference_jids WHERE user_id = $1 ORDER BY policy, jid",
    )
    .bind(user_id)
    .fetch_all(&mut **transaction)
    .await?;
    let mut preferences = MamPreferences {
        default_policy,
        always: Vec::new(),
        never: Vec::new(),
    };
    for row in rows {
        let jid: String = row.get("jid");
        match row.get::<String, _>("policy").as_str() {
            "always" => preferences.always.push(jid),
            "never" => preferences.never.push(jid),
            _ => {}
        }
    }
    Ok(preferences)
}

pub async fn set_mam_preferences(
    pool: &PgPool,
    user_id: Uuid,
    preferences: &MamPreferences,
) -> Result<()> {
    anyhow::ensure!(
        preferences
            .always
            .len()
            .saturating_add(preferences.never.len())
            <= MAX_PREFS_JIDS,
        "MAM preferences exceed the JID limit"
    );
    anyhow::ensure!(
        matches!(
            preferences.default_policy.as_str(),
            "always" | "never" | "roster"
        ),
        "invalid MAM default policy"
    );
    let mut all_jids = HashSet::with_capacity(
        preferences
            .always
            .len()
            .saturating_add(preferences.never.len()),
    );
    let mut always = Vec::with_capacity(preferences.always.len());
    for jid in &preferences.always {
        let jid = northstar_xmpp_types::jid::canonicalize(jid)?;
        anyhow::ensure!(
            all_jids.insert(jid.clone()),
            "duplicate canonical JID in MAM preferences: {jid}"
        );
        always.push(jid);
    }
    let mut never = Vec::with_capacity(preferences.never.len());
    for jid in &preferences.never {
        let jid = northstar_xmpp_types::jid::canonicalize(jid)?;
        anyhow::ensure!(
            all_jids.insert(jid.clone()),
            "duplicate canonical JID in MAM preferences: {jid}"
        );
        never.push(jid);
    }
    let mut transaction = pool.begin().await?;
    sqlx::query(
        "INSERT INTO mam_preferences (user_id, default_policy) VALUES ($1, $2) ON CONFLICT (user_id) DO UPDATE SET default_policy = EXCLUDED.default_policy, updated_at = NOW()",
    )
    .bind(user_id)
    .bind(&preferences.default_policy)
    .execute(&mut *transaction)
    .await?;
    sqlx::query("DELETE FROM mam_preference_jids WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut *transaction)
        .await?;
    for (policy, entries) in [("always", always.as_slice()), ("never", never.as_slice())] {
        for jid in entries {
            sqlx::query(
                "INSERT INTO mam_preference_jids (user_id, jid, policy) VALUES ($1, $2, $3)",
            )
            .bind(user_id)
            .bind(jid)
            .bind(policy)
            .execute(&mut *transaction)
            .await?;
        }
    }
    transaction.commit().await?;
    Ok(())
}

pub async fn archive_allowed(pool: &PgPool, owner_id: Uuid, peer_jid: &str) -> Result<bool> {
    let peer_jid = northstar_xmpp_types::jid::canonicalize(peer_jid)?;
    let peer_bare = northstar_xmpp_types::jid::canonical_bare_key(&peer_jid)?;
    // Read every policy input in one statement. The pure domain rule chooses
    // full JID, bare JID, then account default without mixing snapshots.
    let row = sqlx::query(
        "SELECT
             (SELECT policy FROM mam_preference_jids WHERE user_id=$1 AND jid=$2) AS full_policy,
             (SELECT policy FROM mam_preference_jids WHERE user_id=$1 AND jid=$3) AS bare_policy,
             (SELECT default_policy FROM mam_preferences WHERE user_id=$1) AS default_policy,
             EXISTS(SELECT 1 FROM roster_items WHERE owner_id=$1 AND contact_jid=$3) AS roster_member",
    )
    .bind(owner_id)
    .bind(&peer_jid)
    .bind(&peer_bare)
    .fetch_one(pool)
    .await?;
    let full_policy: Option<String> = row.try_get("full_policy")?;
    let bare_policy: Option<String> = row.try_get("bare_policy")?;
    let default_policy: Option<String> = row.try_get("default_policy")?;
    Ok(decide_mam_archive_admission(MamArchiveAdmissionFacts {
        full_jid_policy: full_policy.as_deref(),
        bare_jid_policy: bare_policy.as_deref(),
        default_policy: default_policy.as_deref(),
        roster_member: row.try_get("roster_member")?,
    }))
}

#[cfg(any(test, feature = "test-support"))]
pub async fn archive_message(
    pool: &PgPool,
    id: Uuid,
    owner_id: Uuid,
    peer_jid: &str,
    stanza: &str,
    encrypted: bool,
    stanza_id: Option<&str>,
) -> Result<()> {
    let peer_full_jid = northstar_xmpp_types::jid::canonicalize(peer_jid)?;
    let peer_bare_jid = northstar_xmpp_types::jid::canonical_bare_key(&peer_full_jid)?;
    sqlx::query("INSERT INTO message_archive (id, owner_id, peer_jid, peer_full_jid, stanza, encrypted, stanza_id) VALUES ($1, $2, $3, $4, $5, $6, $7)")
        .bind(id).bind(owner_id).bind(peer_bare_jid).bind(peer_full_jid).bind(stanza).bind(encrypted).bind(stanza_id)
        .execute(pool).await?;
    Ok(())
}

#[cfg(test)]
mod mam_query_tests;
