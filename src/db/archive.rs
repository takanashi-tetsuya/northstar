use crate::abuse::ContentIdentityAuthenticators;
use anyhow::Result;
use chrono::{DateTime, Utc};
use rand::RngCore;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, QueryBuilder, Row, Transaction};
use std::collections::HashSet;
#[cfg(test)]
use std::time::Duration;
use subtle::ConstantTimeEq;
use uuid::Uuid;

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
pub(crate) async fn archive_boundaries_visible_in_transaction(
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

#[cfg(test)]
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

async fn mam_preferences_in_transaction(
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
        let jid = crate::jid::canonicalize(jid)?;
        anyhow::ensure!(
            all_jids.insert(jid.clone()),
            "duplicate canonical JID in MAM preferences: {jid}"
        );
        always.push(jid);
    }
    let mut never = Vec::with_capacity(preferences.never.len());
    for jid in &preferences.never {
        let jid = crate::jid::canonicalize(jid)?;
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
    let peer_jid = crate::jid::canonicalize(peer_jid)?;
    let peer_bare = crate::jid::canonical_bare_key(&peer_jid)?;
    // Explicit full/bare policy, account default and roster membership are
    // decided by one PostgreSQL statement. A concurrent preference rewrite
    // therefore cannot splice an old explicit row into a new default policy.
    sqlx::query_scalar::<_, bool>(
        "WITH effective AS (
             SELECT COALESCE(
                 (SELECT policy FROM mam_preference_jids
                   WHERE user_id=$1
                     AND (jid=$2 OR (position('/' in jid)=0 AND jid=$3))
                   ORDER BY CASE WHEN jid=$2 THEN 0 ELSE 1 END
                   LIMIT 1),
                 (SELECT default_policy FROM mam_preferences WHERE user_id=$1),
                 'always'
             ) AS policy
         )
         SELECT CASE effective.policy
                  WHEN 'always' THEN TRUE
                  WHEN 'roster' THEN EXISTS(
                      SELECT 1 FROM roster_items
                       WHERE owner_id=$1 AND contact_jid=$3
                  )
                  ELSE FALSE
                END
           FROM effective",
    )
    .bind(owner_id)
    .bind(&peer_jid)
    .bind(&peer_bare)
    .fetch_one(pool)
    .await
    .map_err(Into::into)
}

#[cfg(test)]
pub async fn archive_message(
    pool: &PgPool,
    id: Uuid,
    owner_id: Uuid,
    peer_jid: &str,
    stanza: &str,
    encrypted: bool,
    stanza_id: Option<&str>,
) -> Result<()> {
    let peer_full_jid = crate::jid::canonicalize(peer_jid)?;
    let peer_bare_jid = crate::jid::canonical_bare_key(&peer_full_jid)?;
    sqlx::query("INSERT INTO message_archive (id, owner_id, peer_jid, peer_full_jid, stanza, encrypted, stanza_id) VALUES ($1, $2, $3, $4, $5, $6, $7)")
        .bind(id).bind(owner_id).bind(peer_bare_jid).bind(peer_full_jid).bind(stanza).bind(encrypted).bind(stanza_id)
        .execute(pool).await?;
    Ok(())
}

#[derive(Clone, Debug)]
pub struct PersonalArchiveWrite<'a> {
    pub id: Uuid,
    pub owner_id: Uuid,
    pub peer_jid: &'a str,
    pub stanza: &'a str,
    pub encrypted: bool,
    pub stanza_id: Option<&'a str>,
}

#[derive(Clone, Debug)]
pub struct PersonalHistoryIdentity<'a> {
    pub kind: &'a str,
    /// Exact authority spelling observed at the protocol boundary.  The
    /// canonical companion below is used for uniqueness; retaining both lets
    /// a digest collision or non-canonical replay fail closed.
    pub actor_scope_raw: &'a str,
    pub actor_scope: &'a str,
    pub target_scope: &'a str,
    pub identity_value: &'a str,
    /// Purpose-separated current/previous HMAC commitments computed by the
    /// application service. The identity record never receives an additional
    /// copy of the stanza bytes carried by its authorized projections.
    pub payload_authenticators: ContentIdentityAuthenticators,
    /// Compatibility-only SHA-256 used to verify and upgrade rows written
    /// before migration 0104. New rows never persist this value.
    pub legacy_payload_digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PersonalHistoryAdmission {
    Stored(Vec<Uuid>),
    Replay(Vec<Uuid>),
    AccountUnavailable,
}

pub struct PersonalS2sOutboxAdmission<'a> {
    /// Local account whose authority causes this durable federation write.
    pub local_actor_id: Uuid,
    pub target_domain: &'a str,
    pub stanza: &'a str,
    pub bounce_to: Option<&'a str>,
    pub policy: super::S2sOutboxPolicy,
}

/// One transient, database-backed C2S copy. It is intentionally separate
/// from MAM: the row exists only until a transport confirms the stanza, but
/// it closes the process-crash window before an online socket write.
pub struct PersonalC2sDeliveryAdmission<'a> {
    pub id: Uuid,
    pub recipient_id: Uuid,
    /// Canonical bare JID owned by `recipient_id` at the application boundary.
    pub recipient_bare_jid: &'a str,
    /// Present for local C2S senders; absent for authenticated remote domains.
    pub local_actor_id: Option<Uuid>,
    pub sender_jid: &'a str,
    pub stanza: &'a str,
    /// Canonical resource affinity derived from an explicit full-JID `to`
    /// only for a `normal` message. Account-scoped/bare/chat delivery is NULL.
    pub target_full_jid: Option<&'a str>,
    pub encrypted: bool,
    pub policy: OfflineStorePolicy,
}

#[derive(Debug, thiserror::Error)]
#[error("durable C2S delivery reached the recipient queue capacity")]
pub(crate) struct C2sDeliveryCapacityExceeded;

#[derive(Debug, thiserror::Error)]
#[error("conflicting personal history identity")]
pub(crate) struct PersonalHistoryIdentityConflict;

/// Atomically write every personal MAM projection of one message.  When a
/// trusted XEP-0359 identity is supplied, concurrent retries are admitted
/// exactly once. Raw identity/authority values are compared exactly and
/// content is verified through purpose-separated current/previous HMAC
/// commitments. Migration-only SHA-256 evidence is upgraded on exact replay;
/// the admission record never receives or persists an extra plaintext copy.
pub async fn admit_personal_history(
    pool: &PgPool,
    identity: Option<&PersonalHistoryIdentity<'_>>,
    writes: &[PersonalArchiveWrite<'_>],
) -> Result<PersonalHistoryAdmission> {
    admit_personal_history_inner(pool, identity, writes, None, None).await
}

/// Atomically commit all enabled MAM projections and the transient C2S
/// delivery row. An authoritative origin/stanza ID therefore cannot become a
/// history-only tombstone after a crash, and an exact retry never fans out a
/// second live copy.
pub async fn admit_personal_history_and_c2s_delivery(
    pool: &PgPool,
    identity: Option<&PersonalHistoryIdentity<'_>>,
    writes: &[PersonalArchiveWrite<'_>],
    delivery: &PersonalC2sDeliveryAdmission<'_>,
) -> Result<PersonalHistoryAdmission> {
    admit_personal_history_inner(pool, identity, writes, None, Some(delivery)).await
}

/// Atomically admit one federated personal message and its optional sender
/// MAM projection. The S2S outbox remains the recoverable projection when
/// archive policy suppresses plaintext MAM. An outbox quota/DB failure leaves
/// no identity/history ghost; an exact replay never enqueues a second stanza.
pub async fn admit_outbound_personal_history(
    pool: &PgPool,
    identity: Option<&PersonalHistoryIdentity<'_>>,
    writes: &[PersonalArchiveWrite<'_>],
    outbox: &PersonalS2sOutboxAdmission<'_>,
) -> Result<PersonalHistoryAdmission> {
    admit_personal_history_inner(pool, identity, writes, Some(outbox), None).await
}

async fn admit_personal_history_inner(
    pool: &PgPool,
    identity: Option<&PersonalHistoryIdentity<'_>>,
    writes: &[PersonalArchiveWrite<'_>],
    outbox: Option<&PersonalS2sOutboxAdmission<'_>>,
    c2s_delivery: Option<&PersonalC2sDeliveryAdmission<'_>>,
) -> Result<PersonalHistoryAdmission> {
    let mut transaction = pool.begin().await?;
    let outcome = admit_personal_history_in_transaction(
        &mut transaction,
        identity,
        writes,
        outbox,
        c2s_delivery,
    )
    .await?;
    transaction.commit().await?;
    Ok(outcome)
}

/// Repository half of a larger application-owned admission transaction.
///
/// The caller owns commit/rollback. In particular, a replay does not commit
/// the transaction here: a service may still need to roll back projections
/// made by another repository before returning its typed replay result.
pub(crate) async fn admit_personal_history_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    identity: Option<&PersonalHistoryIdentity<'_>>,
    writes: &[PersonalArchiveWrite<'_>],
    outbox: Option<&PersonalS2sOutboxAdmission<'_>>,
    c2s_delivery: Option<&PersonalC2sDeliveryAdmission<'_>>,
) -> Result<PersonalHistoryAdmission> {
    anyhow::ensure!(
        (!writes.is_empty() || outbox.is_some() || c2s_delivery.is_some()) && writes.len() <= 2,
        "personal history admission must contain an owner projection or durable delivery"
    );
    let mut required_accounts = writes
        .iter()
        .map(|write| write.owner_id)
        .collect::<Vec<_>>();
    if let Some(outbox) = outbox {
        required_accounts.push(outbox.local_actor_id);
    }
    if let Some(delivery) = c2s_delivery {
        required_accounts.push(delivery.recipient_id);
        required_accounts.extend(delivery.local_actor_id);
    }
    if !super::lock_enabled_users_in_transaction(transaction, &required_accounts).await? {
        return Ok(PersonalHistoryAdmission::AccountUnavailable);
    }
    anyhow::ensure!(
        identity.is_none() || !writes.is_empty() || outbox.is_some() || c2s_delivery.is_some(),
        "personal history identity requires a recoverable archive, S2S, or C2S projection"
    );
    let mut normalized = Vec::with_capacity(writes.len());
    let mut owner_ids = HashSet::new();
    let mut archive_ids = HashSet::new();
    for write in writes {
        anyhow::ensure!(
            owner_ids.insert(write.owner_id),
            "personal history admission contains duplicate owners"
        );
        anyhow::ensure!(
            archive_ids.insert(write.id),
            "personal history admission contains duplicate archive ids"
        );
        anyhow::ensure!(
            !write.stanza.is_empty() && write.stanza.len() <= 1_048_576,
            "personal archive stanza must contain 1 byte to 1 MiB"
        );
        if let Some(stanza_id) = write.stanza_id {
            anyhow::ensure!(
                !stanza_id.is_empty()
                    && stanza_id.len() <= 128
                    && !stanza_id.chars().any(char::is_control),
                "client stanza id must contain 1 to 128 non-control bytes"
            );
        }
        let peer_full_jid = crate::jid::canonicalize(write.peer_jid)?;
        let peer_bare_jid = crate::jid::canonical_bare_key(&peer_full_jid)?;
        normalized.push((write, peer_bare_jid, peer_full_jid));
    }

    let identity_values = if let Some(identity) = identity {
        anyhow::ensure!(
            matches!(identity.kind, "local-origin" | "remote-stanza"),
            "unsupported personal history identity kind"
        );
        anyhow::ensure!(
            !identity.actor_scope_raw.is_empty() && identity.actor_scope_raw.len() <= 3071,
            "raw actor scope must contain 1 to 3071 bytes"
        );
        let actor_scope = crate::jid::canonicalize(identity.actor_scope)?;
        anyhow::ensure!(
            actor_scope == identity.actor_scope,
            "personal history actor scope must already be canonical"
        );
        let target_scope = crate::jid::canonicalize(identity.target_scope)?;
        anyhow::ensure!(
            target_scope == identity.target_scope,
            "personal history target scope must already be canonical"
        );
        anyhow::ensure!(
            !identity.identity_value.is_empty()
                && identity.identity_value.len() <= 1024
                && !identity.identity_value.chars().any(char::is_control),
            "personal history identity must contain 1 to 1024 non-control bytes"
        );
        let mut identity_hasher = Sha256::new();
        identity_hasher.update(b"northstar:personal-history-identity:v1\0");
        identity_hasher.update(identity.identity_value.as_bytes());
        let identity_digest = identity_hasher.finalize().to_vec();
        Some((actor_scope, target_scope, identity_digest))
    } else {
        None
    };

    let normalized_delivery = if let Some(delivery) = c2s_delivery {
        anyhow::ensure!(
            !delivery.stanza.is_empty() && delivery.stanza.len() <= 1_048_576,
            "C2S delivery stanza must contain 1 byte to 1 MiB"
        );
        let sender_jid = crate::jid::canonicalize(delivery.sender_jid)?;
        anyhow::ensure!(
            delivery.policy.max_messages > 0
                && delivery.policy.max_bytes > 0
                && delivery.policy.ttl_days >= 0,
            "C2S delivery policy is invalid"
        );
        Some((delivery, sender_jid))
    } else {
        None
    };

    // Allocate the S2S projection identity before inserting the admission.
    // Its foreign key is deferred because the outbox row is inserted later in
    // this same transaction, after replay admission has succeeded.
    let s2s_outbox_id = outbox.map(|_| Uuid::new_v4());
    if let (Some(identity), Some((actor_scope, target_scope, identity_digest))) =
        (identity, identity_values.as_ref())
    {
        let admission_id = Uuid::new_v4();
        let sender_archive_id = writes.first().map(|write| write.id);
        let recipient_archive_id = writes.get(1).map(|write| write.id);
        let offline_message_id = c2s_delivery.map(|delivery| delivery.id);
        let primary_authenticator = identity.payload_authenticators.primary();
        let inserted = sqlx::query(
            "INSERT INTO personal_message_admissions
             (id,identity_kind,actor_scope_raw,actor_scope,target_scope,
              identity_value,identity_digest,payload_key_id,payload_mac,
              sender_archive_id,recipient_archive_id,offline_message_id,s2s_outbox_id)
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
             ON CONFLICT (identity_kind,actor_scope,target_scope,identity_digest)
             DO NOTHING",
        )
        .bind(admission_id)
        .bind(identity.kind)
        .bind(identity.actor_scope_raw)
        .bind(actor_scope)
        .bind(target_scope)
        .bind(identity.identity_value)
        .bind(identity_digest)
        .bind(primary_authenticator.key_id())
        .bind(primary_authenticator.mac().as_slice())
        .bind(sender_archive_id)
        .bind(recipient_archive_id)
        .bind(offline_message_id)
        .bind(s2s_outbox_id)
        .execute(&mut **transaction)
        .await?
        .rows_affected()
            == 1;
        if !inserted {
            let row = sqlx::query(
                "SELECT id,actor_scope_raw,identity_value,payload_key_id,payload_mac,payload_digest,
                        sender_archive_id,recipient_archive_id
                   FROM personal_message_admissions
                  WHERE identity_kind=$1 AND actor_scope=$2 AND target_scope=$3
                    AND identity_digest=$4
                  FOR UPDATE",
            )
            .bind(identity.kind)
            .bind(actor_scope)
            .bind(target_scope)
            .bind(identity_digest)
            .fetch_optional(&mut **transaction)
            .await?;
            let Some(row) = row else {
                anyhow::bail!(
                    "personal history identity conflict row disappeared during admission"
                );
            };
            let stored_key_id = row.get::<Option<String>, _>("payload_key_id");
            let stored_mac = row.get::<Option<Vec<u8>>, _>("payload_mac");
            let legacy_digest = row.get::<Option<Vec<u8>>, _>("payload_digest");
            let keyed_exact = match (stored_key_id.as_deref(), stored_mac.as_deref()) {
                (Some(key_id), Some(mac)) if legacy_digest.is_none() => {
                    identity.payload_authenticators.verifies(key_id, mac)
                }
                _ => false,
            };
            let legacy_exact = match (
                stored_key_id.as_deref(),
                stored_mac.as_deref(),
                legacy_digest.as_deref(),
            ) {
                (None, None, Some(digest)) if digest.len() == 32 => {
                    bool::from(digest.ct_eq(identity.legacy_payload_digest.as_slice()))
                }
                _ => false,
            };
            let exact_replay = row.get::<String, _>("actor_scope_raw") == identity.actor_scope_raw
                && row.get::<String, _>("identity_value") == identity.identity_value
                && (keyed_exact || legacy_exact);
            if !exact_replay {
                return Err(PersonalHistoryIdentityConflict.into());
            }
            if legacy_exact {
                let upgraded = sqlx::query(
                    "UPDATE personal_message_admissions
                        SET payload_key_id=$2,payload_mac=$3,payload_digest=NULL
                      WHERE id=$1 AND payload_key_id IS NULL AND payload_mac IS NULL
                        AND payload_digest IS NOT NULL",
                )
                .bind(row.get::<Uuid, _>("id"))
                .bind(primary_authenticator.key_id())
                .bind(primary_authenticator.mac().as_slice())
                .execute(&mut **transaction)
                .await?;
                anyhow::ensure!(
                    upgraded.rows_affected() == 1,
                    "legacy personal history evidence changed while locked"
                );
            }
            let existing = [
                row.get::<Option<Uuid>, _>("sender_archive_id"),
                row.get::<Option<Uuid>, _>("recipient_archive_id"),
            ]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
            return Ok(PersonalHistoryAdmission::Replay(existing));
        }
    }

    for (write, peer_bare_jid, peer_full_jid) in normalized {
        sqlx::query(
            "INSERT INTO message_archive
             (id,owner_id,peer_jid,peer_full_jid,stanza,encrypted,stanza_id)
             VALUES($1,$2,$3,$4,$5,$6,$7)",
        )
        .bind(write.id)
        .bind(write.owner_id)
        .bind(peer_bare_jid)
        .bind(peer_full_jid)
        .bind(write.stanza)
        .bind(write.encrypted)
        .bind(write.stanza_id)
        .execute(&mut **transaction)
        .await?;
    }
    if let Some(outbox) = outbox {
        super::enqueue_s2s_outbox_with_id_in_transaction(
            transaction,
            s2s_outbox_id.expect("an outbound admission always allocates an outbox id"),
            outbox.target_domain,
            outbox.stanza,
            outbox.bounce_to,
            outbox.policy,
        )
        .await?;
    }
    if let Some((delivery, sender_jid)) = normalized_delivery {
        insert_c2s_delivery_in_transaction(transaction, delivery, &sender_jid).await?;
    }
    Ok(PersonalHistoryAdmission::Stored(
        writes.iter().map(|write| write.id).collect(),
    ))
}

pub(crate) async fn insert_c2s_delivery_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    delivery: &PersonalC2sDeliveryAdmission<'_>,
    sender_jid: &str,
) -> Result<()> {
    let (target_resource, stanza_target_bare_jid) = normalized_c2s_target_resource(delivery)?;
    let recipient_bare_jid = crate::jid::canonicalize_bare(delivery.recipient_bare_jid)?;
    anyhow::ensure!(
        recipient_bare_jid == delivery.recipient_bare_jid,
        "C2S delivery recipient bare JID must already be canonical"
    );
    if let Some(stanza_target_bare_jid) = stanza_target_bare_jid.as_deref() {
        anyhow::ensure!(
            stanza_target_bare_jid == recipient_bare_jid.as_str(),
            "C2S delivery target domain does not match recipient authority"
        );
    }
    let recipient = crate::jid::CanonicalJid::parse_bare(&recipient_bare_jid)?;
    let recipient_username = sqlx::query_scalar::<_, String>(
        "SELECT username FROM users WHERE id=$1 AND NOT is_disabled FOR SHARE",
    )
    .bind(delivery.recipient_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or_else(|| anyhow::anyhow!("C2S delivery recipient account is unavailable"))?;
    anyhow::ensure!(
        recipient.localpart() == Some(recipient_username.as_str()),
        "C2S delivery recipient authority does not own recipient account"
    );
    // Serialize account capacity admission exactly like normal offline
    // storage. The row is a transient outbox even when the user is online.
    sqlx::query("SELECT pg_advisory_xact_lock_shared(5645368709120102)")
        .execute(&mut **transaction)
        .await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::TEXT, 3))")
        .bind(delivery.recipient_id.to_string())
        .execute(&mut **transaction)
        .await?;
    {
        sqlx::query(
            "WITH expired AS MATERIALIZED (
                 SELECT message.id FROM offline_messages message
                  WHERE message.recipient_id=$1
                    AND COALESCE(
                        (SELECT retention.offline_message_days
                           FROM user_retention_policies retention
                          WHERE retention.user_id=$1),NULLIF($2::BIGINT,0)
                    ) IS NOT NULL
                    AND message.created_at < clock_timestamp()-(
                        COALESCE(
                            (SELECT retention.offline_message_days
                               FROM user_retention_policies retention
                              WHERE retention.user_id=$1),NULLIF($2::BIGINT,0)
                        )::BIGINT*INTERVAL '1 day')
                    AND (message.delivery_claim_id IS NULL
                         OR message.delivery_claim_expires_at<=clock_timestamp())
                    AND NOT EXISTS (
                        SELECT 1 FROM sm_resume_stanzas sm
                         WHERE sm.delivery_message_id=message.id
                    )
                    AND NOT EXISTS (
                        SELECT 1 FROM bosh_delivery_fences bosh
                         WHERE bosh.message_id=message.id
                    )
                    AND NOT EXISTS (
                        SELECT 1 FROM legal_holds hold
                         WHERE hold.released_at IS NULL AND (
                             EXISTS (SELECT 1 FROM legal_hold_offline_messages link
                                      WHERE link.hold_id=hold.id AND link.message_id=message.id)
                             OR EXISTS (SELECT 1 FROM legal_hold_scopes scope_link
                                        WHERE scope_link.hold_id=hold.id
                                          AND scope_link.scope_type='offline_message_recipient'
                                          AND scope_link.subject_id=message.recipient_id)
                         )
                    )
                  FOR UPDATE OF message SKIP LOCKED
             )
             DELETE FROM offline_messages message USING expired
              WHERE message.id=expired.id",
        )
        .bind(delivery.recipient_id)
        .bind(delivery.policy.ttl_days)
        .execute(&mut **transaction)
        .await?;
    }
    let (current_messages, current_bytes): (i64, i64) = sqlx::query_as(
        "SELECT COUNT(*)::BIGINT,COALESCE(SUM(octet_length(stanza)),0)::BIGINT
           FROM offline_messages WHERE recipient_id=$1",
    )
    .bind(delivery.recipient_id)
    .fetch_one(&mut **transaction)
    .await?;
    let stanza_bytes = i64::try_from(delivery.stanza.len()).unwrap_or(i64::MAX);
    if current_messages >= delivery.policy.max_messages
        || current_bytes
            .checked_add(stanza_bytes)
            .is_none_or(|bytes| bytes > delivery.policy.max_bytes)
    {
        return Err(C2sDeliveryCapacityExceeded.into());
    }
    sqlx::query(
        "INSERT INTO offline_messages
         (id,recipient_id,sender_jid,stanza,target_resource,encrypted,mam_backed)
         VALUES($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(delivery.id)
    .bind(delivery.recipient_id)
    .bind(sender_jid)
    .bind(delivery.stanza)
    .bind(target_resource)
    .bind(delivery.encrypted)
    .bind(delivery.policy.mam_backed)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

/// Re-derive resource affinity from the persisted stanza at the repository
/// boundary. This prevents an internal caller from binding a bare/chat row to
/// one resource, omitting affinity from an explicit full-JID normal message,
/// or changing the target independently of the authenticated XML payload.
fn normalized_c2s_target_resource(
    delivery: &PersonalC2sDeliveryAdmission<'_>,
) -> Result<(Option<String>, Option<String>)> {
    let document = roxmltree::Document::parse(delivery.stanza)?;
    let root = document.root_element();
    anyhow::ensure!(
        root.tag_name().name() == "message",
        "C2S delivery projection must contain one message stanza"
    );
    let target = root
        .attribute("to")
        .map(crate::jid::CanonicalJid::parse)
        .transpose()?;
    let target_bare_jid = target.as_ref().map(|target| target.bare().to_string());
    let expected = target
        .as_ref()
        .filter(|target| {
            root.attribute("type").unwrap_or("normal") == "normal"
                && target.resourcepart().is_some()
        })
        .map(ToString::to_string);
    let supplied = delivery
        .target_full_jid
        .map(crate::jid::canonical_session_key)
        .transpose()?;
    anyhow::ensure!(
        supplied == expected,
        "C2S delivery target resource affinity does not match stanza routing semantics"
    );
    if let Some(raw) = delivery.target_full_jid {
        anyhow::ensure!(
            supplied.as_deref() == Some(raw),
            "C2S delivery target resource affinity must already be canonical"
        );
    }
    let target_resource = expected
        .as_deref()
        .map(crate::jid::CanonicalJid::parse)
        .transpose()?
        .and_then(|target| target.resourcepart().map(str::to_owned));
    Ok((target_resource, target_bare_jid))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceArchiveAdmission {
    Stored(Uuid),
    Replay(Uuid),
}

/// Store a reflected MIX message in a personal archive exactly once per
/// channel authority and authoritative stanza-id.  A retry with the same key
/// is accepted only when all persisted content is identical; a conflicting
/// payload is rejected instead of being silently misclassified as a replay.
#[allow(clippy::too_many_arguments)]
pub async fn archive_mix_message_once(
    pool: &PgPool,
    personal_archive_id: Uuid,
    owner_id: Uuid,
    channel_jid: &str,
    authoritative_stanza_id: Uuid,
    stanza: &str,
    encrypted: bool,
    client_stanza_id: Option<&str>,
) -> Result<SourceArchiveAdmission> {
    anyhow::ensure!(
        !stanza.is_empty() && stanza.len() <= 1_048_576,
        "MIX archive stanza must contain 1 to 1048576 bytes"
    );
    if let Some(client_stanza_id) = client_stanza_id {
        anyhow::ensure!(
            !client_stanza_id.is_empty() && client_stanza_id.len() <= 128,
            "client stanza id must contain 1 to 128 bytes"
        );
    }
    let channel = crate::jid::CanonicalJid::parse_bare(channel_jid)?;
    anyhow::ensure!(
        channel.localpart().is_some(),
        "MIX channel authority must be a bare channel JID"
    );
    let channel = channel.to_string();
    anyhow::ensure!(
        channel == channel_jid,
        "MIX channel authority must already be canonical"
    );
    let mut digest = Sha256::new();
    digest.update(b"northstar:personal-mix-archive:v1\0");
    digest.update((channel.len() as u32).to_be_bytes());
    digest.update(channel.as_bytes());
    digest.update(authoritative_stanza_id.as_bytes());
    digest.update([u8::from(encrypted)]);
    digest.update((stanza.len() as u32).to_be_bytes());
    digest.update(stanza.as_bytes());
    let payload_digest = digest.finalize().to_vec();

    let mut transaction = pool.begin().await?;
    let inserted = sqlx::query(
        "INSERT INTO message_archive
         (id, owner_id, peer_jid, peer_full_jid, stanza, encrypted, stanza_id,
          source_by, source_stanza_id, source_payload_digest)
         VALUES ($1, $2, $3, $3, $4, $5, $6, $3, $7, $8)
         ON CONFLICT (owner_id, source_by, source_stanza_id)
         WHERE source_stanza_id IS NOT NULL
         DO NOTHING",
    )
    .bind(personal_archive_id)
    .bind(owner_id)
    .bind(&channel)
    .bind(stanza)
    .bind(encrypted)
    .bind(client_stanza_id)
    .bind(authoritative_stanza_id)
    .bind(&payload_digest)
    .execute(&mut *transaction)
    .await?
    .rows_affected()
        == 1;
    if inserted {
        transaction.commit().await?;
        return Ok(SourceArchiveAdmission::Stored(personal_archive_id));
    }

    let row = sqlx::query(
        "SELECT id, peer_jid, peer_full_jid, stanza, encrypted, stanza_id,
                source_by, source_stanza_id, source_payload_digest
         FROM message_archive
         WHERE owner_id=$1 AND source_by=$2 AND source_stanza_id=$3
         FOR SHARE",
    )
    .bind(owner_id)
    .bind(&channel)
    .bind(authoritative_stanza_id)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(row) = row else {
        anyhow::bail!("MIX source identity conflict row disappeared during admission");
    };
    let exact_replay = row.get::<String, _>("peer_jid") == channel
        && row.get::<String, _>("peer_full_jid") == channel
        && row.get::<String, _>("stanza") == stanza
        && row.get::<bool, _>("encrypted") == encrypted
        && row.get::<Option<String>, _>("stanza_id").as_deref() == client_stanza_id
        && row.get::<Option<String>, _>("source_by").as_deref() == Some(channel.as_str())
        && row.get::<Option<Uuid>, _>("source_stanza_id") == Some(authoritative_stanza_id)
        && row
            .get::<Option<Vec<u8>>, _>("source_payload_digest")
            .as_deref()
            == Some(payload_digest.as_slice());
    anyhow::ensure!(exact_replay, "conflicting MIX source stanza identity");
    let existing_id: Uuid = row.get("id");
    transaction.commit().await?;
    Ok(SourceArchiveAdmission::Replay(existing_id))
}

#[derive(Clone, Copy)]
enum MamArchiveSource {
    User(Uuid),
    Muc(Uuid),
}

impl MamArchiveSource {
    fn table(self) -> &'static str {
        match self {
            Self::User(_) => "message_archive",
            Self::Muc(_) => "muc_messages",
        }
    }

    fn owner_column(self) -> &'static str {
        match self {
            Self::User(_) => "owner_id",
            Self::Muc(_) => "room_id",
        }
    }

    fn owner_id(self) -> Uuid {
        match self {
            Self::User(id) | Self::Muc(id) => id,
        }
    }

    fn select_columns(self) -> &'static str {
        match self {
            Self::User(_) => {
                "id, peer_full_jid AS peer_jid, stanza, encrypted, stanza_id, created_at"
            }
            // MUC stanza_id is an authoritative UUID rather than the
            // personal archive's optional client id. Expose no client id
            // through the shared row type instead of conflating the two.
            Self::Muc(_) => {
                "id, sender_jid AS peer_jid, stanza, encrypted, NULL::TEXT AS stanza_id, created_at"
            }
        }
    }

    fn visible_full_identity(self) -> &'static str {
        match self {
            Self::User(_) => "peer_full_jid",
            // A full-JID block is resource-specific. New rows retain a bare
            // actor_scope for bare/domain matching, while sender_jid preserves
            // the originating resource for this exact comparison.
            Self::Muc(_) => "sender_jid",
        }
    }

    fn visible_bare_identity(self) -> &'static str {
        match self {
            Self::User(_) => "peer_jid",
            Self::Muc(_) => "split_part(COALESCE(actor_scope, sender_jid), '/', 1)",
        }
    }

    fn visible_domain_identity(self) -> &'static str {
        match self {
            Self::User(_) => {
                "CASE WHEN position('@' in peer_jid) > 0 THEN split_part(peer_jid, '@', 2) ELSE peer_jid END"
            }
            Self::Muc(_) => {
                "CASE WHEN position('@' in split_part(COALESCE(actor_scope, sender_jid), '/', 1)) > 0 THEN split_part(split_part(COALESCE(actor_scope, sender_jid), '/', 1), '@', 2) ELSE split_part(COALESCE(actor_scope, sender_jid), '/', 1) END"
            }
        }
    }
}

#[derive(Clone, Debug)]
enum MamBlockedPattern {
    Full(String),
    Bare(String),
    Domain(String),
}

async fn mam_blocked_patterns(
    transaction: &mut Transaction<'_, Postgres>,
    viewer_id: Option<Uuid>,
) -> Result<Vec<MamBlockedPattern>> {
    let Some(viewer_id) = viewer_id else {
        return Ok(Vec::new());
    };
    let patterns = sqlx::query_scalar::<_, String>(
        "SELECT blocked_jid FROM blocked_jids WHERE owner_id=$1 ORDER BY blocked_jid",
    )
    .bind(viewer_id)
    .fetch_all(&mut **transaction)
    .await?;
    Ok(patterns
        .into_iter()
        .filter_map(|value| {
            let jid = crate::jid::CanonicalJid::parse(&value).ok()?;
            if jid.resourcepart().is_some() {
                Some(MamBlockedPattern::Full(jid.to_string()))
            } else if jid.localpart().is_some() {
                Some(MamBlockedPattern::Bare(jid.bare()))
            } else {
                Some(MamBlockedPattern::Domain(jid.domainpart().to_owned()))
            }
        })
        .collect())
}

fn push_mam_visibility(
    query_builder: &mut QueryBuilder<'_, Postgres>,
    source: MamArchiveSource,
    blocked_patterns: &[MamBlockedPattern],
) {
    for pattern in blocked_patterns {
        query_builder.push(" AND ");
        match pattern {
            MamBlockedPattern::Full(value) => query_builder
                .push(source.visible_full_identity())
                .push(" <> ")
                .push_bind(value.clone()),
            MamBlockedPattern::Bare(value) => query_builder
                .push(source.visible_bare_identity())
                .push(" <> ")
                .push_bind(value.clone()),
            MamBlockedPattern::Domain(value) => query_builder
                .push(source.visible_domain_identity())
                .push(" <> ")
                .push_bind(value.clone()),
        };
    }
}

async fn archive_boundaries_for(
    pool: &PgPool,
    source: MamArchiveSource,
    viewer_id: Option<Uuid>,
) -> Result<(Option<ArchiveBoundary>, Option<ArchiveBoundary>)> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *transaction)
        .await?;
    let boundaries =
        archive_boundaries_for_in_transaction(&mut transaction, source, viewer_id).await?;
    transaction.commit().await?;
    Ok(boundaries)
}

async fn archive_boundaries_for_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    source: MamArchiveSource,
    viewer_id: Option<Uuid>,
) -> Result<(Option<ArchiveBoundary>, Option<ArchiveBoundary>)> {
    let blocked_patterns = mam_blocked_patterns(transaction, viewer_id).await?;

    let boundary = |descending: bool| {
        let mut builder = QueryBuilder::<Postgres>::new("SELECT id, created_at FROM ");
        builder
            .push(source.table())
            .push(" WHERE ")
            .push(source.owner_column())
            .push(" = ")
            .push_bind(source.owner_id());
        push_mam_visibility(&mut builder, source, &blocked_patterns);
        builder.push(if descending {
            " ORDER BY created_at DESC, id DESC LIMIT 1"
        } else {
            " ORDER BY created_at ASC, id ASC LIMIT 1"
        });
        builder
    };
    let first = boundary(false)
        .build()
        .fetch_optional(&mut **transaction)
        .await?;
    let last = boundary(true)
        .build()
        .fetch_optional(&mut **transaction)
        .await?;
    let convert = |row: sqlx::postgres::PgRow| ArchiveBoundary {
        id: row.get("id"),
        created_at: row.get("created_at"),
    };
    Ok((first.map(convert), last.map(convert)))
}

fn push_mam_archive_base(
    query_builder: &mut QueryBuilder<'_, Postgres>,
    source: MamArchiveSource,
    blocked_patterns: &[MamBlockedPattern],
) {
    query_builder
        .push(" WHERE ")
        .push(source.owner_column())
        .push(" = ")
        .push_bind(source.owner_id());
    push_mam_visibility(query_builder, source, blocked_patterns);
}

fn push_mam_scope(
    query_builder: &mut QueryBuilder<'_, Postgres>,
    source: MamArchiveSource,
    query: &MamArchiveQuery,
    blocked_patterns: &[MamBlockedPattern],
    after_point: Option<(DateTime<Utc>, Uuid)>,
    before_point: Option<(DateTime<Utc>, Uuid)>,
) {
    push_mam_archive_base(query_builder, source, blocked_patterns);
    if let Some(with_jid) = &query.with_jid {
        let full = with_jid.contains('/');
        if full {
            query_builder.push(" AND ");
            match source {
                MamArchiveSource::User(_) => query_builder.push("peer_full_jid"),
                MamArchiveSource::Muc(_) => query_builder.push("sender_jid"),
            };
            query_builder.push(" = ").push_bind(with_jid.clone());
        } else {
            query_builder.push(" AND ");
            match source {
                MamArchiveSource::User(_) => query_builder.push("peer_jid"),
                MamArchiveSource::Muc(_) => query_builder.push("split_part(sender_jid, '/', 1)"),
            };
            query_builder.push(" = ").push_bind(with_jid.clone());
        }
    }
    if let Some(start) = query.start {
        query_builder.push(" AND created_at >= ").push_bind(start);
    }
    if let Some(end) = query.end {
        query_builder.push(" AND created_at <= ").push_bind(end);
    }
    if let Some((created_at, id)) = after_point {
        query_builder
            .push(" AND (created_at, id) > (")
            .push_bind(created_at)
            .push(", ")
            .push_bind(id)
            .push(")");
    }
    if let Some((created_at, id)) = before_point {
        query_builder
            .push(" AND (created_at, id) < (")
            .push_bind(created_at)
            .push(", ")
            .push_bind(id)
            .push(")");
    }
    if !query.ids.is_empty() {
        query_builder
            .push(" AND id = ANY(")
            .push_bind(query.ids.clone())
            .push(")");
    }
}

async fn mam_archive_point(
    transaction: &mut Transaction<'_, Postgres>,
    source: MamArchiveSource,
    blocked_patterns: &[MamBlockedPattern],
    id: Uuid,
) -> Result<Option<DateTime<Utc>>> {
    let mut builder = QueryBuilder::<Postgres>::new("SELECT created_at FROM ");
    builder.push(source.table());
    // XEP-0313 requires a referenced UID to be present in the archive. It
    // does not require the cursor itself to satisfy the query's independent
    // `with`, time or `ids` filters. Resolve the opaque chronological point
    // in the same visibility snapshot, then apply filters to returned rows.
    push_mam_archive_base(&mut builder, source, blocked_patterns);
    builder.push(" AND id = ").push_bind(id);
    Ok(builder
        .build_query_scalar()
        .fetch_optional(&mut **transaction)
        .await?)
}

async fn mam_archive_page_for(
    pool: &PgPool,
    source: MamArchiveSource,
    viewer_id: Option<Uuid>,
    query: &MamArchiveQuery,
) -> Result<Option<ArchivePage>> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *transaction)
        .await?;
    let page =
        mam_archive_page_for_in_transaction(&mut transaction, source, viewer_id, query).await?;
    transaction.commit().await?;
    Ok(page)
}

async fn mam_archive_page_for_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    source: MamArchiveSource,
    viewer_id: Option<Uuid>,
    query: &MamArchiveQuery,
) -> Result<Option<ArchivePage>> {
    let blocked_patterns = mam_blocked_patterns(transaction, viewer_id).await?;

    // Every UID referenced by the extended form or RSM must exist in this
    // archive. The repeatable-read snapshot prevents a concurrent deletion
    // from changing validation, count and page selection midway through the
    // response.
    let mut requested_ids = query.ids.clone();
    requested_ids.extend(query.before_id);
    requested_ids.extend(query.after_id);
    match query.page {
        MamRsmPage::Before(id) | MamRsmPage::After(id) => requested_ids.push(id),
        MamRsmPage::First | MamRsmPage::Last | MamRsmPage::Index(_) => {}
    }
    let requested_ids = requested_ids
        .into_iter()
        .collect::<HashSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if !requested_ids.is_empty() {
        let mut builder = QueryBuilder::<Postgres>::new("SELECT COUNT(*) FROM ");
        builder.push(source.table());
        push_mam_archive_base(&mut builder, source, &blocked_patterns);
        builder
            .push(" AND id = ANY(")
            .push_bind(requested_ids.clone())
            .push(")");
        let found: i64 = builder
            .build_query_scalar()
            .fetch_one(&mut **transaction)
            .await?;
        if found != requested_ids.len() as i64 {
            return Ok(None);
        }
    }

    let form_after = match query.after_id {
        Some(id) => Some((
            mam_archive_point(transaction, source, &blocked_patterns, id)
                .await?
                .expect("validated MAM id disappeared from repeatable-read snapshot"),
            id,
        )),
        None => None,
    };
    let form_before = match query.before_id {
        Some(id) => Some((
            mam_archive_point(transaction, source, &blocked_patterns, id)
                .await?
                .expect("validated MAM id disappeared from repeatable-read snapshot"),
            id,
        )),
        None => None,
    };

    let mut count_builder = QueryBuilder::<Postgres>::new("SELECT COUNT(*) FROM ");
    count_builder.push(source.table());
    push_mam_scope(
        &mut count_builder,
        source,
        query,
        &blocked_patterns,
        form_after,
        form_before,
    );
    let total: i64 = count_builder
        .build_query_scalar()
        .fetch_one(&mut **transaction)
        .await?;

    let (rsm_after, rsm_before, descending) = match query.page {
        MamRsmPage::First => (None, None, false),
        MamRsmPage::Last => (None, None, true),
        MamRsmPage::Index(_) => (None, None, false),
        MamRsmPage::After(id) => (
            Some((
                mam_archive_point(transaction, source, &blocked_patterns, id)
                    .await?
                    .expect("validated MAM RSM id disappeared"),
                id,
            )),
            None,
            false,
        ),
        MamRsmPage::Before(id) => (
            None,
            Some((
                mam_archive_point(transaction, source, &blocked_patterns, id)
                    .await?
                    .expect("validated MAM RSM id disappeared"),
                id,
            )),
            true,
        ),
    };

    let max = query.max.clamp(0, 100);
    let page_after = match (form_after, rsm_after) {
        (Some(left), Some(right)) => Some(std::cmp::max(left, right)),
        (left, right) => left.or(right),
    };
    let page_before = match (form_before, rsm_before) {
        (Some(left), Some(right)) => Some(std::cmp::min(left, right)),
        (left, right) => left.or(right),
    };
    let mut page_builder = QueryBuilder::<Postgres>::new("SELECT ");
    page_builder
        .push(source.select_columns())
        .push(" FROM ")
        .push(source.table());
    push_mam_scope(
        &mut page_builder,
        source,
        query,
        &blocked_patterns,
        page_after,
        page_before,
    );
    page_builder.push(if descending {
        " ORDER BY created_at DESC, id DESC LIMIT "
    } else {
        " ORDER BY created_at ASC, id ASC LIMIT "
    });
    page_builder.push_bind(max + 1);
    if let MamRsmPage::Index(index) = query.page {
        page_builder.push(" OFFSET ").push_bind(index);
    }
    let fetched = page_builder.build().fetch_all(&mut **transaction).await?;
    let mut rows = fetched.iter().map(archive_from_row).collect::<Vec<_>>();
    let has_more = rows.len() > max as usize;
    if has_more {
        rows.truncate(max as usize);
    }
    if descending {
        rows.reverse();
    }

    let first_index = if let Some(first) = rows.first() {
        let mut index_builder = QueryBuilder::<Postgres>::new("SELECT COUNT(*) FROM ");
        index_builder.push(source.table());
        push_mam_scope(
            &mut index_builder,
            source,
            query,
            &blocked_patterns,
            form_after,
            form_before,
        );
        index_builder
            .push(" AND (created_at, id) < (")
            .push_bind(first.created_at)
            .push(", ")
            .push_bind(first.id)
            .push(")");
        index_builder
            .build_query_scalar()
            .fetch_one(&mut **transaction)
            .await?
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

async fn authorize_mam_room_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    localpart: &str,
    viewer_id: Uuid,
    currently_joined: bool,
) -> Result<MamRoomReadOutcome<()>> {
    let row = sqlx::query(
        "SELECT r.id,r.localpart,r.members_only,r.non_anonymous,r.password_hash,
                r.occupant_id_secret,a.affiliation
           FROM muc_rooms r
           LEFT JOIN muc_affiliations a
             ON a.room_id=r.id AND a.user_id=$2
          WHERE r.localpart=$1 AND r.destroyed_at IS NULL",
    )
    .bind(localpart)
    .bind(viewer_id)
    .fetch_optional(&mut **transaction)
    .await?;
    let Some(row) = row else {
        return Ok(MamRoomReadOutcome::Missing);
    };
    let affiliation: Option<String> = row.try_get("affiliation")?;
    if affiliation.as_deref() == Some("outcast")
        || (row.try_get::<bool, _>("members_only")?
            && !matches!(affiliation.as_deref(), Some("owner" | "admin" | "member")))
        || (row.try_get::<Option<String>, _>("password_hash")?.is_some() && !currently_joined)
    {
        return Ok(MamRoomReadOutcome::Forbidden);
    }
    let room_id: Uuid = row.try_get("id")?;
    let occupant_id_secret = match row.try_get::<Option<Vec<u8>>, _>("occupant_id_secret")? {
        Some(secret) if !secret.is_empty() => secret,
        _ => {
            // Historical rooms created before XEP-0421 support may not have a
            // secret. Repair it inside this same snapshot before returning an
            // authorized archive capability.
            let mut secret = vec![0_u8; 32];
            rand::thread_rng().fill_bytes(&mut secret);
            let updated = sqlx::query(
                "UPDATE muc_rooms SET occupant_id_secret=$2
                  WHERE id=$1 AND occupant_id_secret IS NULL",
            )
            .bind(room_id)
            .bind(&secret)
            .execute(&mut **transaction)
            .await?;
            anyhow::ensure!(
                updated.rows_affected() == 1,
                "MAM room occupant-id secret changed during snapshot authorization"
            );
            secret
        }
    };
    let reveal_real_jid = row.try_get::<bool, _>("non_anonymous")?
        || matches!(affiliation.as_deref(), Some("owner" | "admin"));
    Ok(MamRoomReadOutcome::Allowed {
        access: MamRoomArchiveAccess {
            room_id,
            localpart: row.try_get("localpart")?,
            occupant_id_secret,
            reveal_real_jid,
        },
        value: (),
    })
}

async fn authorize_federated_mam_room_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    localpart: &str,
    viewer_bare_jid: &str,
    currently_joined: bool,
) -> Result<MamRoomReadOutcome<()>> {
    // The room row is the durable identity fence for this authorization.  A
    // shared lock prevents destroy/recreate and room-policy changes from
    // committing between the policy decision and the caller's durable
    // projection (for example, an S2S outbox stream).
    let row = sqlx::query(
        "SELECT id,localpart,members_only,non_anonymous,password_hash,
                occupant_id_secret
           FROM muc_rooms
          WHERE localpart=$1 AND destroyed_at IS NULL
          FOR SHARE",
    )
    .bind(localpart)
    .fetch_optional(&mut **transaction)
    .await?;
    let Some(row) = row else {
        return Ok(MamRoomReadOutcome::Missing);
    };
    let room_id: Uuid = row.try_get("id")?;

    // Legacy affiliation writers serialize on this advisory lock while the
    // clustered writers lock the room row above.  Taking both, in the same
    // order used by this read capability, makes either mutation family wait
    // until the authorized projection commits.  Read the affiliation only
    // after the advisory lock so a waiter observes the winning mutation.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::TEXT, 29))")
        .bind(room_id.to_string())
        .execute(&mut **transaction)
        .await?;
    let affiliation: Option<String> = sqlx::query_scalar(
        "SELECT affiliation FROM muc_external_affiliations
          WHERE room_id=$1 AND jid=$2 FOR SHARE",
    )
    .bind(room_id)
    .bind(viewer_bare_jid)
    .fetch_optional(&mut **transaction)
    .await?;
    if affiliation.as_deref() == Some("outcast")
        || (row.try_get::<bool, _>("members_only")?
            && !matches!(affiliation.as_deref(), Some("owner" | "admin" | "member")))
        || (row.try_get::<Option<String>, _>("password_hash")?.is_some() && !currently_joined)
    {
        return Ok(MamRoomReadOutcome::Forbidden);
    }
    let occupant_id_secret = match row.try_get::<Option<Vec<u8>>, _>("occupant_id_secret")? {
        Some(secret) if !secret.is_empty() => secret,
        _ => {
            let mut secret = vec![0_u8; 32];
            rand::thread_rng().fill_bytes(&mut secret);
            let updated = sqlx::query(
                "UPDATE muc_rooms SET occupant_id_secret=$2
                  WHERE id=$1 AND occupant_id_secret IS NULL",
            )
            .bind(room_id)
            .bind(&secret)
            .execute(&mut **transaction)
            .await?;
            anyhow::ensure!(
                updated.rows_affected() == 1,
                "federated MAM room occupant-id secret changed during snapshot authorization"
            );
            secret
        }
    };
    let reveal_real_jid = row.try_get::<bool, _>("non_anonymous")?
        || matches!(affiliation.as_deref(), Some("owner" | "admin"));
    Ok(MamRoomReadOutcome::Allowed {
        access: MamRoomArchiveAccess {
            room_id,
            localpart: row.try_get("localpart")?,
            occupant_id_secret,
            reveal_real_jid,
        },
        value: (),
    })
}

pub async fn authorize_mam_room(
    pool: &PgPool,
    localpart: &str,
    viewer_id: Uuid,
    currently_joined: bool,
) -> Result<MamRoomReadOutcome<()>> {
    let mut transaction = pool.begin().await?;
    // This is intentionally read-write only for the one-time legacy
    // occupant-id-secret repair above. All policy and returned identity are
    // still derived from one repeatable-read snapshot.
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut *transaction)
        .await?;
    let outcome =
        authorize_mam_room_in_transaction(&mut transaction, localpart, viewer_id, currently_joined)
            .await?;
    transaction.commit().await?;
    Ok(outcome)
}

pub async fn authorize_federated_mam_room(
    pool: &PgPool,
    localpart: &str,
    viewer_bare_jid: &str,
    currently_joined: bool,
) -> Result<MamRoomReadOutcome<()>> {
    let viewer_bare_jid = crate::jid::CanonicalJid::parse_bare(viewer_bare_jid)?;
    anyhow::ensure!(
        viewer_bare_jid.localpart().is_some(),
        "federated MAM viewer must be a user bare JID"
    );
    let mut transaction = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut *transaction)
        .await?;
    let outcome = authorize_federated_mam_room_in_transaction(
        &mut transaction,
        localpart,
        &viewer_bare_jid.to_string(),
        currently_joined,
    )
    .await?;
    transaction.commit().await?;
    Ok(outcome)
}

pub async fn mam_room_archive_boundaries_authorized(
    pool: &PgPool,
    localpart: &str,
    viewer_id: Uuid,
    currently_joined: bool,
) -> Result<MamRoomReadOutcome<(Option<ArchiveBoundary>, Option<ArchiveBoundary>)>> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut *transaction)
        .await?;
    let access = match authorize_mam_room_in_transaction(
        &mut transaction,
        localpart,
        viewer_id,
        currently_joined,
    )
    .await?
    {
        MamRoomReadOutcome::Allowed { access, .. } => access,
        MamRoomReadOutcome::Missing => {
            transaction.commit().await?;
            return Ok(MamRoomReadOutcome::Missing);
        }
        MamRoomReadOutcome::Forbidden => {
            transaction.commit().await?;
            return Ok(MamRoomReadOutcome::Forbidden);
        }
    };
    let value = archive_boundaries_for_in_transaction(
        &mut transaction,
        MamArchiveSource::Muc(access.room_id),
        Some(viewer_id),
    )
    .await?;
    transaction.commit().await?;
    Ok(MamRoomReadOutcome::Allowed { access, value })
}

pub async fn mam_room_archive_page_authorized(
    pool: &PgPool,
    localpart: &str,
    viewer_id: Uuid,
    currently_joined: bool,
    query: &MamArchiveQuery,
) -> Result<MamRoomReadOutcome<Option<ArchivePage>>> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut *transaction)
        .await?;
    let access = match authorize_mam_room_in_transaction(
        &mut transaction,
        localpart,
        viewer_id,
        currently_joined,
    )
    .await?
    {
        MamRoomReadOutcome::Allowed { access, .. } => access,
        MamRoomReadOutcome::Missing => {
            transaction.commit().await?;
            return Ok(MamRoomReadOutcome::Missing);
        }
        MamRoomReadOutcome::Forbidden => {
            transaction.commit().await?;
            return Ok(MamRoomReadOutcome::Forbidden);
        }
    };
    if !access.reveal_real_jid && query.with_jid.is_some() {
        transaction.commit().await?;
        return Ok(MamRoomReadOutcome::Forbidden);
    }
    let value = mam_archive_page_for_in_transaction(
        &mut transaction,
        MamArchiveSource::Muc(access.room_id),
        Some(viewer_id),
        query,
    )
    .await?;
    transaction.commit().await?;
    Ok(MamRoomReadOutcome::Allowed { access, value })
}

pub async fn mam_federated_room_archive_boundaries_authorized(
    pool: &PgPool,
    localpart: &str,
    viewer_bare_jid: &str,
    currently_joined: bool,
) -> Result<MamRoomReadOutcome<(Option<ArchiveBoundary>, Option<ArchiveBoundary>)>> {
    let viewer_bare_jid = crate::jid::CanonicalJid::parse_bare(viewer_bare_jid)?;
    anyhow::ensure!(
        viewer_bare_jid.localpart().is_some(),
        "federated MAM viewer must be a user bare JID"
    );
    let mut transaction = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut *transaction)
        .await?;
    let access = match authorize_federated_mam_room_in_transaction(
        &mut transaction,
        localpart,
        &viewer_bare_jid.to_string(),
        currently_joined,
    )
    .await?
    {
        MamRoomReadOutcome::Allowed { access, .. } => access,
        MamRoomReadOutcome::Missing => {
            transaction.commit().await?;
            return Ok(MamRoomReadOutcome::Missing);
        }
        MamRoomReadOutcome::Forbidden => {
            transaction.commit().await?;
            return Ok(MamRoomReadOutcome::Forbidden);
        }
    };
    let value = archive_boundaries_for_in_transaction(
        &mut transaction,
        MamArchiveSource::Muc(access.room_id),
        None,
    )
    .await?;
    transaction.commit().await?;
    Ok(MamRoomReadOutcome::Allowed { access, value })
}

#[cfg(test)]
pub async fn mam_federated_room_archive_page_authorized(
    pool: &PgPool,
    localpart: &str,
    viewer_bare_jid: &str,
    currently_joined: bool,
    query: &MamArchiveQuery,
) -> Result<MamRoomReadOutcome<Option<ArchivePage>>> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut *transaction)
        .await?;
    let outcome = mam_federated_room_archive_page_authorized_in_transaction(
        &mut transaction,
        localpart,
        viewer_bare_jid,
        currently_joined,
        query,
    )
    .await?;
    transaction.commit().await?;
    Ok(outcome)
}

/// Resolve federated room authority and page its archive inside a transaction
/// owned by the application service.  The caller may append a durable
/// response projection before commit without reopening a TOCTOU window.
pub(crate) async fn mam_federated_room_archive_page_authorized_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    localpart: &str,
    viewer_bare_jid: &str,
    currently_joined: bool,
    query: &MamArchiveQuery,
) -> Result<MamRoomReadOutcome<Option<ArchivePage>>> {
    let viewer_bare_jid = crate::jid::CanonicalJid::parse_bare(viewer_bare_jid)?;
    anyhow::ensure!(
        viewer_bare_jid.localpart().is_some(),
        "federated MAM viewer must be a user bare JID"
    );
    let access = match authorize_federated_mam_room_in_transaction(
        transaction,
        localpart,
        &viewer_bare_jid.to_string(),
        currently_joined,
    )
    .await?
    {
        MamRoomReadOutcome::Allowed { access, .. } => access,
        MamRoomReadOutcome::Missing => return Ok(MamRoomReadOutcome::Missing),
        MamRoomReadOutcome::Forbidden => return Ok(MamRoomReadOutcome::Forbidden),
    };
    if !access.reveal_real_jid && query.with_jid.is_some() {
        return Ok(MamRoomReadOutcome::Forbidden);
    }
    let value = mam_archive_page_for_in_transaction(
        transaction,
        MamArchiveSource::Muc(access.room_id),
        None,
        query,
    )
    .await?;
    Ok(MamRoomReadOutcome::Allowed { access, value })
}

pub async fn mam_user_archive_page(
    pool: &PgPool,
    owner_id: Uuid,
    query: &MamArchiveQuery,
) -> Result<Option<ArchivePage>> {
    mam_archive_page_for(
        pool,
        MamArchiveSource::User(owner_id),
        Some(owner_id),
        query,
    )
    .await
}

/// Personal MAM page inside a caller-owned exact-bearer authorization
/// transaction. The API layer keeps the account and session rows locked from
/// its authorization check through this repeatable archive snapshot.
pub(crate) async fn mam_user_archive_page_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    owner_id: Uuid,
    query: &MamArchiveQuery,
) -> Result<Option<ArchivePage>> {
    mam_archive_page_for_in_transaction(
        transaction,
        MamArchiveSource::User(owner_id),
        Some(owner_id),
        query,
    )
    .await
}

/// MUC MAM with XEP-0191 visibility applied inside the same repeatable-read
/// snapshot as cursor validation, count, index and page selection.
#[cfg(test)]
pub async fn mam_muc_archive_page_visible(
    pool: &PgPool,
    room_id: Uuid,
    viewer_id: Uuid,
    query: &MamArchiveQuery,
) -> Result<Option<ArchivePage>> {
    mam_archive_page_for(pool, MamArchiveSource::Muc(room_id), Some(viewer_id), query).await
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfflineStoreOutcome {
    Stored,
    Replay,
    QuotaExceeded,
    RecipientUnavailable,
}

#[derive(Debug, Clone, Copy)]
pub struct OfflineStorePolicy {
    pub max_messages: i64,
    pub max_bytes: i64,
    pub ttl_days: i64,
    /// True only when the exact stanza is already recoverable from personal
    /// MAM. Bind 2 may discard this duplicate but must retain temporary-only
    /// XEP-0334 no-permanent-store rows.
    pub mam_backed: bool,
}

const OFFLINE_DEDUPE_CAPACITY_SHARDS: u8 = 64;
const MAX_OFFLINE_DEDUPE_PER_SHARD: i32 = 32_768;
const MAX_OFFLINE_DEDUPE_PER_RECIPIENT: i64 = 4_096;
const OFFLINE_DEDUPE_FOREGROUND_CLEANUP: i64 = 128;

#[cfg(test)]
pub async fn store_offline(
    pool: &PgPool,
    recipient_id: Uuid,
    sender_jid: &str,
    stanza: &str,
    encrypted: bool,
    policy: OfflineStorePolicy,
) -> Result<OfflineStoreOutcome> {
    store_offline_idempotent_inner(
        pool,
        recipient_id,
        None,
        sender_jid,
        stanza,
        encrypted,
        policy,
        None,
    )
    .await
}

/// Authority-aware offline storage for application services which may carry
/// an explicit full-JID normal message (notably direct MUC invitations). The
/// resourcepart is derived from the stanza and the supplied bare JID is bound
/// to the recipient UUID before insertion.
pub async fn store_offline_for_recipient(
    pool: &PgPool,
    recipient_id: Uuid,
    recipient_bare_jid: &str,
    sender_jid: &str,
    stanza: &str,
    encrypted: bool,
    policy: OfflineStorePolicy,
) -> Result<OfflineStoreOutcome> {
    store_offline_idempotent_inner(
        pool,
        recipient_id,
        Some(recipient_bare_jid),
        sender_jid,
        stanza,
        encrypted,
        policy,
        None,
    )
    .await
}

/// Atomically enqueue a temporary offline stanza and retain a compact replay
/// tombstone after transport-confirmed delivery removes the content row. The stable lookup
/// digest contains a random origin/challenge identity but no plaintext JID or
/// stanza. Rotating-key HMAC candidates authenticate the payload; an unknown
/// old key or any content mismatch fails closed instead of creating a second
/// queue entry.
#[cfg(test)]
pub async fn store_offline_idempotent(
    pool: &PgPool,
    recipient_id: Uuid,
    sender_jid: &str,
    stanza: &str,
    encrypted: bool,
    policy: OfflineStorePolicy,
    identity: Option<&crate::abuse::MessageDedupeIdentity>,
) -> Result<OfflineStoreOutcome> {
    store_offline_idempotent_inner(
        pool,
        recipient_id,
        None,
        sender_jid,
        stanza,
        encrypted,
        policy,
        identity,
    )
    .await
}

/// Authority-aware variant of idempotent offline storage. This is the only
/// repository entry point for a potentially resource-affine normal stanza:
/// the target resource is derived from the XML while the target bare JID is
/// checked against the recipient UUID in the same transaction.
#[allow(clippy::too_many_arguments)]
pub async fn store_offline_idempotent_for_recipient(
    pool: &PgPool,
    recipient_id: Uuid,
    recipient_bare_jid: &str,
    sender_jid: &str,
    stanza: &str,
    encrypted: bool,
    policy: OfflineStorePolicy,
    identity: Option<&crate::abuse::MessageDedupeIdentity>,
) -> Result<OfflineStoreOutcome> {
    store_offline_idempotent_inner(
        pool,
        recipient_id,
        Some(recipient_bare_jid),
        sender_jid,
        stanza,
        encrypted,
        policy,
        identity,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn store_offline_idempotent_inner(
    pool: &PgPool,
    recipient_id: Uuid,
    recipient_bare_jid: Option<&str>,
    sender_jid: &str,
    stanza: &str,
    encrypted: bool,
    policy: OfflineStorePolicy,
    identity: Option<&crate::abuse::MessageDedupeIdentity>,
) -> Result<OfflineStoreOutcome> {
    let (recipient_authority, target_resource) =
        normalized_offline_target_resource(stanza, recipient_bare_jid)?;
    if let Some(identity) = identity {
        anyhow::ensure!(
            identity.identity_digest.len() == 32 && !identity.candidates.is_empty(),
            "offline message identity is malformed"
        );
        anyhow::ensure!(
            identity.candidates.iter().all(|candidate| {
                !candidate.key_id.is_empty()
                    && candidate.key_id.len() <= 64
                    && candidate.payload_mac.len() == 32
            }),
            "offline message payload authenticator is malformed"
        );
    }
    let mut transaction = pool.begin().await?;
    // Linearize durable delivery against account disable/delete.  The
    // administrator's FOR UPDATE cannot pass this shared row lock until the
    // queue projection commits, while a disable that won first is observed as
    // unavailable before any admission/tombstone row is created.
    if !super::lock_enabled_users_in_transaction(&mut transaction, &[recipient_id]).await? {
        transaction.rollback().await?;
        return Ok(OfflineStoreOutcome::RecipientUnavailable);
    }
    if let Some(recipient_authority) = recipient_authority.as_ref() {
        let recipient_username = sqlx::query_scalar::<_, String>(
            "SELECT username FROM users WHERE id=$1 AND NOT is_disabled FOR SHARE",
        )
        .bind(recipient_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or_else(|| anyhow::anyhow!("offline recipient account is unavailable"))?;
        anyhow::ensure!(
            crate::jid::CanonicalJid::parse_bare(recipient_authority)?.localpart()
                == Some(recipient_username.as_str()),
            "offline recipient authority does not own recipient account"
        );
    }
    // The global queue gate gives the administrator clear operation exact
    // snapshot semantics without enumerating recipient locks. Normal enqueue
    // remains concurrent because this is a shared advisory lock.
    sqlx::query("SELECT pg_advisory_xact_lock_shared(5645368709120102)")
        .execute(&mut *transaction)
        .await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::TEXT, 3))")
        .bind(recipient_id.to_string())
        .execute(&mut *transaction)
        .await?;
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut *transaction)
        .await?;
    if let Some(identity) = identity {
        // Expired retention can never mask the live key being considered.
        // The trigger releases its capacity slot in this same transaction.
        sqlx::query(
            "DELETE FROM offline_message_admissions
              WHERE identity_digest=$1 AND offline_message_id IS NULL
                AND expires_at IS NOT NULL AND expires_at <= $2",
        )
        .bind(&identity.identity_digest)
        .bind(now)
        .execute(&mut *transaction)
        .await?;
        if let Some(row) = sqlx::query(
            "SELECT recipient_id,payload_key_id,payload_mac
               FROM offline_message_admissions
              WHERE identity_digest=$1 FOR UPDATE",
        )
        .bind(&identity.identity_digest)
        .fetch_optional(&mut *transaction)
        .await?
        {
            let stored_key_id: String = row.get("payload_key_id");
            let stored_payload_mac: Vec<u8> = row.get("payload_mac");
            let exact = row.get::<Uuid, _>("recipient_id") == recipient_id
                && identity.candidates.iter().any(|candidate| {
                    candidate.key_id == stored_key_id
                        && bool::from(
                            candidate
                                .payload_mac
                                .as_slice()
                                .ct_eq(stored_payload_mac.as_slice()),
                        )
                });
            anyhow::ensure!(exact, "conflicting offline message identity");
            transaction.commit().await?;
            return Ok(OfflineStoreOutcome::Replay);
        }
    }
    {
        sqlx::query(
            "WITH expired AS MATERIALIZED (
                 SELECT message.id FROM offline_messages message
                  WHERE message.recipient_id=$1
                    AND COALESCE(
                        (SELECT retention.offline_message_days
                           FROM user_retention_policies retention
                          WHERE retention.user_id=$1),NULLIF($2::BIGINT,0)
                    ) IS NOT NULL
                    AND message.created_at < clock_timestamp()-(
                        COALESCE(
                            (SELECT retention.offline_message_days
                               FROM user_retention_policies retention
                              WHERE retention.user_id=$1),NULLIF($2::BIGINT,0)
                        )::BIGINT*INTERVAL '1 day')
                    AND (message.delivery_claim_id IS NULL
                         OR message.delivery_claim_expires_at<=clock_timestamp())
                    AND NOT EXISTS (
                        SELECT 1 FROM sm_resume_stanzas sm
                         WHERE sm.delivery_message_id=message.id
                    )
                    AND NOT EXISTS (
                        SELECT 1 FROM bosh_delivery_fences bosh
                         WHERE bosh.message_id=message.id
                    )
                    AND NOT EXISTS (
                        SELECT 1 FROM legal_holds hold
                         WHERE hold.released_at IS NULL AND (
                             EXISTS (SELECT 1 FROM legal_hold_offline_messages link
                                      WHERE link.hold_id=hold.id AND link.message_id=message.id)
                             OR EXISTS (SELECT 1 FROM legal_hold_scopes scope_link
                                        WHERE scope_link.hold_id=hold.id
                                          AND scope_link.scope_type='offline_message_recipient'
                                          AND scope_link.subject_id=message.recipient_id)
                         )
                    )
                  FOR UPDATE OF message SKIP LOCKED
             )
             DELETE FROM offline_messages message USING expired
              WHERE message.id=expired.id",
        )
        .bind(recipient_id)
        .bind(policy.ttl_days)
        .execute(&mut *transaction)
        .await?;
    }
    let (current_messages, current_bytes): (i64, i64) = sqlx::query_as(
        "SELECT COUNT(*)::BIGINT, COALESCE(SUM(octet_length(stanza)), 0)::BIGINT
           FROM offline_messages WHERE recipient_id = $1",
    )
    .bind(recipient_id)
    .fetch_one(&mut *transaction)
    .await?;
    let stanza_bytes = i64::try_from(stanza.len()).unwrap_or(i64::MAX);
    if current_messages >= policy.max_messages
        || current_bytes
            .checked_add(stanza_bytes)
            .is_none_or(|projected| projected > policy.max_bytes)
    {
        return Ok(OfflineStoreOutcome::QuotaExceeded);
    }
    let offline_message_id = Uuid::new_v4();
    if let Some(identity) = identity {
        let capacity_shard =
            i16::from(identity.identity_digest[0] % OFFLINE_DEDUPE_CAPACITY_SHARDS);
        sqlx::query(
            "WITH doomed AS (
                 SELECT identity_digest FROM offline_message_admissions
                  WHERE capacity_shard=$1 AND offline_message_id IS NULL
                    AND expires_at IS NOT NULL AND expires_at <= $2
                  ORDER BY expires_at,identity_digest
                  LIMIT $3 FOR UPDATE SKIP LOCKED
             )
             DELETE FROM offline_message_admissions AS target
              USING doomed WHERE target.identity_digest=doomed.identity_digest",
        )
        .bind(capacity_shard)
        .bind(now)
        .bind(OFFLINE_DEDUPE_FOREGROUND_CLEANUP)
        .execute(&mut *transaction)
        .await?;
        let recipient_active: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM offline_message_admissions
              WHERE recipient_id=$1 AND (expires_at IS NULL OR expires_at > $2)",
        )
        .bind(recipient_id)
        .bind(now)
        .fetch_one(&mut *transaction)
        .await?;
        if recipient_active >= MAX_OFFLINE_DEDUPE_PER_RECIPIENT {
            return Ok(OfflineStoreOutcome::QuotaExceeded);
        }
        let capacity_reserved = sqlx::query_scalar::<_, i32>(
            "UPDATE offline_message_admission_capacity
                SET active_records=active_records+1
              WHERE shard=$1 AND active_records < $2
              RETURNING active_records",
        )
        .bind(capacity_shard)
        .bind(MAX_OFFLINE_DEDUPE_PER_SHARD)
        .fetch_optional(&mut *transaction)
        .await?
        .is_some();
        if !capacity_reserved {
            return Ok(OfflineStoreOutcome::QuotaExceeded);
        }
        let current = identity
            .candidates
            .first()
            .expect("validated offline dedupe identity has a current HMAC");
        sqlx::query(
            "INSERT INTO offline_message_admissions
             (identity_digest,payload_key_id,recipient_id,offline_message_id,
              capacity_shard,payload_mac,expires_at)
             VALUES($1,$2,$3,$4,$5,$6,
                    CASE WHEN $7::bigint=0 THEN NULL
                         ELSE $8 + (($7 + 1) * INTERVAL '1 day') END)",
        )
        .bind(&identity.identity_digest)
        .bind(&current.key_id)
        .bind(recipient_id)
        .bind(offline_message_id)
        .bind(capacity_shard)
        .bind(&current.payload_mac)
        .bind(policy.ttl_days)
        .bind(now)
        .execute(&mut *transaction)
        .await?;
    }
    sqlx::query("INSERT INTO offline_messages (id, recipient_id, sender_jid, stanza, target_resource, encrypted, mam_backed) VALUES ($1, $2, $3, $4, $5, $6, $7)")
        .bind(offline_message_id).bind(recipient_id).bind(sender_jid).bind(stanza).bind(target_resource).bind(encrypted).bind(policy.mam_backed)
        .execute(&mut *transaction).await?;
    transaction.commit().await?;
    Ok(OfflineStoreOutcome::Stored)
}

fn normalized_offline_target_resource(
    stanza: &str,
    recipient_bare_jid: Option<&str>,
) -> Result<(Option<String>, Option<String>)> {
    let document = roxmltree::Document::parse(stanza)?;
    let root = document.root_element();
    anyhow::ensure!(
        root.tag_name().name() == "message",
        "offline projection must contain one message stanza"
    );
    let recipient_authority = recipient_bare_jid
        .map(crate::jid::canonicalize_bare)
        .transpose()?;
    if let (Some(raw), Some(canonical)) = (recipient_bare_jid, recipient_authority.as_deref()) {
        anyhow::ensure!(
            raw == canonical,
            "offline recipient authority must be canonical"
        );
    }
    let Some(raw_target) = root.attribute("to") else {
        return Ok((recipient_authority, None));
    };
    let target = crate::jid::CanonicalJid::parse(raw_target)?;
    if let Some(recipient_authority) = recipient_authority.as_deref() {
        anyhow::ensure!(
            target.bare() == recipient_authority,
            "offline stanza target does not match recipient authority"
        );
    }
    let target_resource = if root.attribute("type").unwrap_or("normal") == "normal" {
        match target.resourcepart() {
            Some(resource) => {
                anyhow::ensure!(
                    recipient_authority.is_some(),
                    "resource-affine offline delivery requires recipient authority"
                );
                Some(resource.to_owned())
            }
            None => None,
        }
    } else {
        None
    };
    Ok((recipient_authority, target_resource))
}

#[cfg(test)]
#[test]
fn offline_resource_affinity_is_derived_from_authoritative_message_routing() {
    assert_eq!(
        normalized_offline_target_resource(
            "<message to='alice@example.test/Phone'/>",
            Some("alice@example.test")
        )
        .unwrap(),
        (
            Some("alice@example.test".to_owned()),
            Some("Phone".to_owned())
        )
    );
    for stanza in [
        "<message to='alice@example.test'/>",
        "<message type='chat' to='alice@example.test/Phone'/>",
        "<message/>",
    ] {
        assert_eq!(
            normalized_offline_target_resource(stanza, Some("alice@example.test"))
                .unwrap()
                .1,
            None
        );
    }
    assert!(
        normalized_offline_target_resource("<message to='alice@example.test/Phone'/>", None)
            .is_err()
    );
    assert!(normalized_offline_target_resource(
        "<message to='alice@evil.test/Phone'/>",
        Some("alice@example.test")
    )
    .is_err());
}

/// Deliver queued offline messages without deleting a stanza until it has
/// been accepted by the connection's outbound queue. The per-recipient
/// advisory lock prevents two resources that announce presence concurrently
/// from claiming the same rows. If the connection closes or remains
/// backpressured, the unsent suffix stays durable for the next availability
/// transition.
#[cfg(test)]
pub async fn deliver_offline(
    pool: &PgPool,
    recipient_id: Uuid,
    ttl_days: i64,
    outbound: &crate::outbound::OutboundSender,
    active_privacy_list: Option<&str>,
) -> Result<usize> {
    deliver_offline_mode(
        pool,
        recipient_id,
        ttl_days,
        outbound,
        false,
        active_privacy_list,
    )
    .await
}

/// Bind 2 MAM catch-up consumes permanently archived queue duplicates but
/// still delivers temporary-only XEP-0334 no-permanent-store messages.
#[cfg(test)]
pub async fn deliver_bind2_offline(
    pool: &PgPool,
    recipient_id: Uuid,
    ttl_days: i64,
    outbound: &crate::outbound::OutboundSender,
    active_privacy_list: Option<&str>,
) -> Result<usize> {
    deliver_offline_mode(
        pool,
        recipient_id,
        ttl_days,
        outbound,
        true,
        active_privacy_list,
    )
    .await
}

#[cfg(test)]
async fn deliver_offline_mode(
    pool: &PgPool,
    recipient_id: Uuid,
    ttl_days: i64,
    outbound: &crate::outbound::OutboundSender,
    bind2_mam_catchup: bool,
    active_privacy_list: Option<&str>,
) -> Result<usize> {
    super::replay::deliver_offline_leased(
        pool,
        recipient_id,
        ttl_days,
        outbound,
        bind2_mam_catchup,
        active_privacy_list,
    )
    .await
}

pub async fn offline_message_count(pool: &PgPool, recipient_id: Uuid) -> Result<i64> {
    sqlx::query_scalar("SELECT COUNT(*) FROM offline_messages WHERE recipient_id = $1")
        .bind(recipient_id)
        .fetch_one(pool)
        .await
        .map_err(Into::into)
}

#[cfg(test)]
mod offline_queue_tests {
    use super::*;
    use crate::abuse::{AbuseConfig, AbuseGuard, MessageDedupeCandidate, MessageDedupeIdentity};
    use crate::db;
    use std::sync::Arc;
    use tokio::sync::Barrier;

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn concurrent_writers_reject_new_message_instead_of_evicting_old_history() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(8)
            .connect(&url)
            .await
            .unwrap();
        db::migrate(&pool).await.unwrap();
        let user_id = Uuid::new_v4();
        sqlx::query("INSERT INTO users (id, username, password_hash) VALUES ($1, $2, 'test')")
            .bind(user_id)
            .bind(format!("offline-{}", &user_id.simple().to_string()[..12]))
            .execute(&pool)
            .await
            .unwrap();
        let barrier = Arc::new(Barrier::new(3));
        let mut tasks = Vec::new();
        for id in ["one", "two"] {
            let pool = pool.clone();
            let barrier = Arc::clone(&barrier);
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                store_offline(
                    &pool,
                    user_id,
                    "sender@example.test/Phone",
                    &format!("<message id='{id}'/>"),
                    true,
                    OfflineStorePolicy {
                        max_messages: 1,
                        max_bytes: 1024,
                        ttl_days: 30,
                        mam_backed: false,
                    },
                )
                .await
                .unwrap()
            }));
        }
        barrier.wait().await;
        let outcomes = futures::future::join_all(tasks)
            .await
            .into_iter()
            .map(|result| result.unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == OfflineStoreOutcome::Stored)
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == OfflineStoreOutcome::QuotaExceeded)
                .count(),
            1
        );
        assert_eq!(offline_message_count(&pool, user_id).await.unwrap(), 1);
        sqlx::query("DELETE FROM users WHERE id=$1")
            .bind(user_id)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn offline_dedupe_rotation_grace_capacity_and_cleanup_are_bounded() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(8)
            .connect(&url)
            .await
            .unwrap();
        db::migrate(&pool).await.unwrap();
        let marker = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        sqlx::query("INSERT INTO users (id, username, password_hash) VALUES ($1, $2, 'test')")
            .bind(user_id)
            .bind(format!("dedupe-{}", &marker.simple().to_string()[..12]))
            .execute(&pool)
            .await
            .unwrap();
        let policy = OfflineStorePolicy {
            max_messages: 10_000,
            max_bytes: 64 * 1_048_576,
            ttl_days: 365,
            mam_backed: false,
        };
        let old_mac = vec![0x11; 32];
        let new_mac = vec![0x22; 32];
        let digest = sha2::Sha256::digest(format!("offline:{marker}").as_bytes()).to_vec();
        let old_identity = MessageDedupeIdentity {
            identity_digest: digest.clone(),
            candidates: vec![MessageDedupeCandidate {
                key_id: "old-key".to_owned(),
                payload_mac: old_mac.clone(),
            }],
        };
        assert_eq!(
            store_offline_idempotent(
                &pool,
                user_id,
                "alice@example.test/Phone",
                "<message id='dedupe-one'/>",
                true,
                policy,
                Some(&old_identity),
            )
            .await
            .unwrap(),
            OfflineStoreOutcome::Stored
        );

        // During the rolling overlap, old-only nodes still coexist. The old
        // key therefore remains primary for fresh writes while the new
        // authenticator is carried as the secondary candidate.
        let rotated_identity = MessageDedupeIdentity {
            identity_digest: digest.clone(),
            candidates: vec![
                MessageDedupeCandidate {
                    key_id: "old-key".to_owned(),
                    payload_mac: old_mac,
                },
                MessageDedupeCandidate {
                    key_id: "new-key".to_owned(),
                    payload_mac: new_mac,
                },
            ],
        };
        assert_eq!(
            store_offline_idempotent(
                &pool,
                user_id,
                "alice@example.test/Phone",
                "<message id='dedupe-one'/>",
                true,
                policy,
                Some(&rotated_identity),
            )
            .await
            .unwrap(),
            OfflineStoreOutcome::Replay
        );
        let conflicting_identity = MessageDedupeIdentity {
            identity_digest: digest.clone(),
            candidates: vec![MessageDedupeCandidate {
                key_id: "old-key".to_owned(),
                payload_mac: vec![0x33; 32],
            }],
        };
        assert!(store_offline_idempotent(
            &pool,
            user_id,
            "alice@example.test/Phone",
            "<message id='changed'/>",
            true,
            policy,
            Some(&conflicting_identity),
        )
        .await
        .unwrap_err()
        .to_string()
        .contains("conflicting offline message identity"));
        assert_eq!(offline_message_count(&pool, user_id).await.unwrap(), 1);

        let (tx, mut rx) = tokio::sync::mpsc::channel(2);
        let tx = crate::outbound::OutboundSender::new(tx);
        assert_eq!(
            deliver_offline(&pool, user_id, 365, &tx, None)
                .await
                .unwrap(),
            1
        );
        drop(tx);
        let delivered = rx.recv().await.unwrap();
        crate::db::replay::acknowledge_durable_delivery(&pool, delivered.durable_delivery.unwrap())
            .await
            .unwrap();
        assert_eq!(delivered.stanza, "<message id='dedupe-one'/>");
        assert!(rx.recv().await.is_none());
        assert_eq!(offline_message_count(&pool, user_id).await.unwrap(), 0);
        let remaining_grace_seconds: f64 = sqlx::query_scalar(
            "SELECT EXTRACT(EPOCH FROM (expires_at-clock_timestamp()))::float8
               FROM offline_message_admissions WHERE identity_digest=$1",
        )
        .bind(&digest)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(
            (30.0 * 86_400.0 - 30.0..=30.0 * 86_400.0).contains(&remaining_grace_seconds),
            "post-delivery replay grace was not bounded to 30 days: {remaining_grace_seconds}"
        );
        assert_eq!(
            store_offline_idempotent(
                &pool,
                user_id,
                "alice@example.test/Phone",
                "<message id='dedupe-one'/>",
                true,
                policy,
                Some(&rotated_identity),
            )
            .await
            .unwrap(),
            OfflineStoreOutcome::Replay
        );
        assert_eq!(offline_message_count(&pool, user_id).await.unwrap(), 0);

        // Fill the recipient limit with compact detached tombstones. The
        // rejected business insert must not leak an offline row or capacity
        // reservation; deleting the fixture immediately restores service.
        let fixture_shard = 63_i16;
        let existing_for_user: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM offline_message_admissions WHERE recipient_id=$1",
        )
        .bind(user_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        let fixture_count = MAX_OFFLINE_DEDUPE_PER_RECIPIENT - existing_for_user;
        let mut fixture_tx = pool.begin().await.unwrap();
        sqlx::query(
            "UPDATE offline_message_admission_capacity
                SET active_records=active_records+$2 WHERE shard=$1",
        )
        .bind(fixture_shard)
        .bind(i32::try_from(fixture_count).unwrap())
        .execute(&mut *fixture_tx)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO offline_message_admissions
             (identity_digest,payload_key_id,recipient_id,capacity_shard,payload_mac,expires_at)
             SELECT decode(md5('offline-fixture:' || $1 || value::text) ||
                           md5('offline-fixture-key:' || $1 || value::text),'hex'),
                    'recipient-fixture',$2,$3,
                    decode(md5('offline-payload:' || $1 || value::text) ||
                           md5('offline-mac:' || $1 || value::text),'hex'),
                    clock_timestamp()+INTERVAL '30 days'
               FROM generate_series(1,$4::integer) AS value",
        )
        .bind(marker.simple().to_string())
        .bind(user_id)
        .bind(fixture_shard)
        .bind(i32::try_from(fixture_count).unwrap())
        .execute(&mut *fixture_tx)
        .await
        .unwrap();
        fixture_tx.commit().await.unwrap();
        let overflow_digest =
            sha2::Sha256::digest(format!("overflow:{marker}").as_bytes()).to_vec();
        let overflow_identity = MessageDedupeIdentity {
            identity_digest: overflow_digest,
            candidates: vec![MessageDedupeCandidate {
                key_id: "new-key".to_owned(),
                payload_mac: vec![0x44; 32],
            }],
        };
        assert_eq!(
            store_offline_idempotent(
                &pool,
                user_id,
                "alice@example.test/Phone",
                "<message id='recipient-overflow'/>",
                true,
                policy,
                Some(&overflow_identity),
            )
            .await
            .unwrap(),
            OfflineStoreOutcome::QuotaExceeded
        );
        assert_eq!(offline_message_count(&pool, user_id).await.unwrap(), 0);
        sqlx::query(
            "DELETE FROM offline_message_admissions WHERE payload_key_id='recipient-fixture'",
        )
        .execute(&pool)
        .await
        .unwrap();
        assert_eq!(
            store_offline_idempotent(
                &pool,
                user_id,
                "alice@example.test/Phone",
                "<message id='recipient-overflow'/>",
                true,
                policy,
                Some(&overflow_identity),
            )
            .await
            .unwrap(),
            OfflineStoreOutcome::Stored
        );

        // A full target shard is a hard global bound. Its rejection rolls
        // back the queue row, and the trigger-backed counter equals physical
        // rows again after restoring the fixture.
        let global_digest = sha2::Sha256::digest(format!("global:{marker}").as_bytes()).to_vec();
        let global_shard = i16::from(global_digest[0] % OFFLINE_DEDUPE_CAPACITY_SHARDS);
        let actual_shard_count: i32 = sqlx::query_scalar(
            "SELECT COUNT(*)::integer FROM offline_message_admissions WHERE capacity_shard=$1",
        )
        .bind(global_shard)
        .fetch_one(&pool)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE offline_message_admission_capacity SET active_records=$2 WHERE shard=$1",
        )
        .bind(global_shard)
        .bind(MAX_OFFLINE_DEDUPE_PER_SHARD)
        .execute(&pool)
        .await
        .unwrap();
        let global_identity = MessageDedupeIdentity {
            identity_digest: global_digest,
            candidates: vec![MessageDedupeCandidate {
                key_id: "new-key".to_owned(),
                payload_mac: vec![0x55; 32],
            }],
        };
        assert_eq!(
            store_offline_idempotent(
                &pool,
                user_id,
                "alice@example.test/Phone",
                "<message id='global-overflow'/>",
                true,
                policy,
                Some(&global_identity),
            )
            .await
            .unwrap(),
            OfflineStoreOutcome::QuotaExceeded
        );
        assert_eq!(offline_message_count(&pool, user_id).await.unwrap(), 1);
        sqlx::query(
            "UPDATE offline_message_admission_capacity SET active_records=$2 WHERE shard=$1",
        )
        .bind(global_shard)
        .bind(actual_shard_count)
        .execute(&pool)
        .await
        .unwrap();

        // Background cleanup is bounded to one batch and the DELETE trigger
        // releases every slot transactionally.
        let cleanup_count = 1_001_i32;
        let cleanup_shard = 62_i16;
        let mut cleanup_tx = pool.begin().await.unwrap();
        sqlx::query(
            "UPDATE offline_message_admission_capacity
                SET active_records=active_records+$2 WHERE shard=$1",
        )
        .bind(cleanup_shard)
        .bind(cleanup_count)
        .execute(&mut *cleanup_tx)
        .await
        .unwrap();
        sqlx::query(
             "INSERT INTO offline_message_admissions
             (identity_digest,payload_key_id,recipient_id,capacity_shard,payload_mac,created_at,expires_at)
             SELECT decode(md5('offline-expired:' || $1 || value::text) ||
                           md5('offline-expired-key:' || $1 || value::text),'hex'),
                    'cleanup-expired',$2,$3,
                    decode(md5('offline-expired-payload:' || $1 || value::text) ||
                           md5('offline-expired-mac:' || $1 || value::text),'hex'),
                    clock_timestamp()-INTERVAL '2 seconds',
                    clock_timestamp()-INTERVAL '1 second'
               FROM generate_series(1,$4::integer) AS value",
        )
        .bind(marker.simple().to_string())
        .bind(user_id)
        .bind(cleanup_shard)
        .bind(cleanup_count)
        .execute(&mut *cleanup_tx)
        .await
        .unwrap();
        cleanup_tx.commit().await.unwrap();
        let guard = AbuseGuard::new_persistent(
            AbuseConfig {
                base_work_factor: 2,
                max_work_factor: 4_096,
                window: Duration::from_secs(60),
                cooldown_step: Duration::from_secs(60),
                max_wait: Duration::from_secs(8),
                message_free_burst: 60,
                approximate_max_device_seconds: 8,
            },
            pool.clone(),
            Some(b"offline-cleanup-test-key-at-least-32-bytes"),
            None,
        );
        guard.cleanup_challenges().await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM offline_message_admissions WHERE payload_key_id='cleanup-expired'",
            )
            .fetch_one(&pool)
            .await
            .unwrap(),
            1
        );
        guard.cleanup_challenges().await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM offline_message_admissions WHERE payload_key_id='cleanup-expired'",
            )
            .fetch_one(&pool)
            .await
            .unwrap(),
            0
        );
        let counters_match: bool = sqlx::query_scalar(
            "SELECT NOT EXISTS(
                 SELECT 1 FROM offline_message_admission_capacity capacity
                  WHERE capacity.active_records <> (
                    SELECT COUNT(*)::integer FROM offline_message_admissions admission
                     WHERE admission.capacity_shard=capacity.shard
                  )
             )",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(counters_match);

        sqlx::query("DELETE FROM users WHERE id=$1")
            .bind(user_id)
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;
    }
}

fn archive_from_row(row: &sqlx::postgres::PgRow) -> ArchiveRow {
    ArchiveRow {
        id: row.get("id"),
        peer_jid: row.get("peer_jid"),
        stanza: row.get("stanza"),
        encrypted: row.get("encrypted"),
        stanza_id: row.get("stanza_id"),
        created_at: row.get("created_at"),
    }
}

#[cfg(test)]
mod mam_query_tests {
    use super::*;

    fn query(with_jid: &str) -> MamArchiveQuery {
        MamArchiveQuery {
            with_jid: Some(with_jid.to_owned()),
            start: None,
            end: None,
            before_id: None,
            after_id: None,
            ids: Vec::new(),
            page: MamRsmPage::First,
            max: 50,
        }
    }

    #[test]
    fn personal_with_filter_distinguishes_bare_and_full_jids() {
        let owner = Uuid::nil();
        let mut bare = QueryBuilder::<Postgres>::new("SELECT id FROM message_archive");
        push_mam_scope(
            &mut bare,
            MamArchiveSource::User(owner),
            &query("bob@example.test"),
            &[],
            None,
            None,
        );
        assert!(bare.sql().contains("peer_jid ="));
        assert!(!bare.sql().contains("lower(peer_jid)"));
        assert!(!bare.sql().contains("peer_full_jid"));

        let mut full = QueryBuilder::<Postgres>::new("SELECT id FROM message_archive");
        push_mam_scope(
            &mut full,
            MamArchiveSource::User(owner),
            &query("bob@example.test/phone"),
            &[],
            None,
            None,
        );
        assert!(full.sql().contains("peer_full_jid ="));
        assert!(!full.sql().contains("lower(peer_full_jid)"));
    }

    #[test]
    fn mam_scope_is_parameterized_and_keyset_only() {
        let owner = Uuid::nil();
        let anchor = (
            DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap(),
            Uuid::from_u128(7),
        );
        let mut builder = QueryBuilder::<Postgres>::new("SELECT id FROM message_archive");
        push_mam_scope(
            &mut builder,
            MamArchiveSource::User(owner),
            &query("mallory@example.test/' OR true --"),
            &[],
            Some(anchor),
            None,
        );
        let sql = builder.sql();
        assert!(!sql.contains("mallory"));
        assert!(!sql.to_ascii_uppercase().contains("OFFSET"));
        assert!(sql.contains("(created_at, id) >"));
    }
}

#[cfg(test)]
mod history_identity_pg_tests {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::Barrier;

    fn personal_identity<'a>(
        kind: &'a str,
        actor_scope_raw: &'a str,
        actor_scope: &'a str,
        target_scope: &'a str,
        identity_value: &'a str,
        payload: &str,
    ) -> PersonalHistoryIdentity<'a> {
        PersonalHistoryIdentity {
            kind,
            actor_scope_raw,
            actor_scope,
            target_scope,
            identity_value,
            payload_authenticators: crate::abuse::test_personal_message_content_keyring()
                .authenticators(payload.as_bytes()),
            legacy_payload_digest: Sha256::digest(payload.as_bytes()).into(),
        }
    }

    fn page_query() -> MamArchiveQuery {
        MamArchiveQuery {
            with_jid: None,
            start: None,
            end: None,
            before_id: None,
            after_id: None,
            ids: Vec::new(),
            page: MamRsmPage::First,
            max: 50,
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
    async fn mam_policy_and_room_reads_keep_one_authorization_snapshot() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let admin = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(60))
            .connect(&url)
            .await
            .unwrap();
        let schema = format!("history_identity_test_{}", Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&admin)
            .await
            .unwrap();
        eprintln!("isolated_schema_created={schema}");
        let connection_schema = schema.clone();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(8)
            .acquire_timeout(Duration::from_secs(60))
            .after_connect(move |connection, _| {
                let statement = format!("SET search_path TO {connection_schema}");
                Box::pin(async move {
                    sqlx::query(&statement).execute(connection).await?;
                    Ok(())
                })
            })
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();

        let viewer_id = Uuid::new_v4();
        sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test')")
            .bind(viewer_id)
            .bind(format!(
                "mam-snapshot-{}",
                &viewer_id.simple().to_string()[..12]
            ))
            .execute(&pool)
            .await
            .unwrap();

        // A sensitive HTTP history read holds the exact account and bearer
        // rows from authorization through the complete MAM projection.  A
        // concurrent logout must therefore serialize after that projection,
        // and the same bearer must be rejected immediately afterwards.
        let bearer = crate::db::create_api_session(&pool, viewer_id, 1)
            .await
            .unwrap();
        let archive_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO message_archive(
                 id,owner_id,peer_jid,peer_full_jid,stanza,encrypted)
             VALUES($1,$2,'peer@remote.test','peer@remote.test/device',
                    '<message xmlns=\"jabber:client\" id=\"authorized-history\"/>',FALSE)",
        )
        .bind(archive_id)
        .bind(viewer_id)
        .execute(&pool)
        .await
        .unwrap();
        let mut authorized_history = pool.begin().await.unwrap();
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .execute(&mut *authorized_history)
            .await
            .unwrap();
        assert!(
            crate::db::authorize_user_in_tx(&mut authorized_history, viewer_id, 0, &bearer,)
                .await
                .unwrap()
        );
        let mut logout = {
            let pool = pool.clone();
            let bearer = bearer.clone();
            tokio::spawn(async move {
                let mut tx = pool.begin().await.unwrap();
                sqlx::query("SET LOCAL lock_timeout='5s'")
                    .execute(&mut *tx)
                    .await
                    .unwrap();
                let deleted =
                    crate::db::delete_api_session_audited_in_tx(&mut tx, &bearer, Uuid::new_v4())
                        .await
                        .unwrap();
                tx.commit().await.unwrap();
                deleted
            })
        };
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut logout)
                .await
                .is_err(),
            "logout committed before the authorized history projection finished"
        );
        let page =
            mam_user_archive_page_in_transaction(&mut authorized_history, viewer_id, &page_query())
                .await
                .unwrap()
                .unwrap();
        assert!(page.rows.iter().any(|row| row.id == archive_id));
        authorized_history.commit().await.unwrap();
        assert!(tokio::time::timeout(Duration::from_secs(5), &mut logout)
            .await
            .expect("logout deadlocked with authorized history")
            .unwrap());
        let mut stale = pool.begin().await.unwrap();
        assert!(
            !crate::db::authorize_user_in_tx(&mut stale, viewer_id, 0, &bearer)
                .await
                .unwrap()
        );
        stale.rollback().await.unwrap();

        let old_preferences = MamPreferences {
            default_policy: "never".to_owned(),
            always: vec!["peer@remote.test".to_owned()],
            never: Vec::new(),
        };
        let new_preferences = MamPreferences {
            default_policy: "always".to_owned(),
            always: Vec::new(),
            never: vec!["peer@remote.test".to_owned()],
        };
        set_mam_preferences(&pool, viewer_id, &old_preferences)
            .await
            .unwrap();
        let mut preference_snapshot = pool.begin().await.unwrap();
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *preference_snapshot)
            .await
            .unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "SELECT default_policy FROM mam_preferences WHERE user_id=$1",
            )
            .bind(viewer_id)
            .fetch_one(&mut *preference_snapshot)
            .await
            .unwrap(),
            "never"
        );
        set_mam_preferences(&pool, viewer_id, &new_preferences)
            .await
            .unwrap();
        assert_eq!(
            mam_preferences_in_transaction(&mut preference_snapshot, viewer_id)
                .await
                .unwrap(),
            old_preferences,
            "default policy and explicit JIDs must come from one snapshot"
        );
        preference_snapshot.commit().await.unwrap();
        assert_eq!(
            mam_preferences(&pool, viewer_id).await.unwrap(),
            new_preferences
        );
        assert!(!archive_allowed(&pool, viewer_id, "peer@remote.test/Phone")
            .await
            .unwrap());

        set_mam_preferences(
            &pool,
            viewer_id,
            &MamPreferences {
                default_policy: "roster".to_owned(),
                always: Vec::new(),
                never: Vec::new(),
            },
        )
        .await
        .unwrap();
        sqlx::query("INSERT INTO roster_items(owner_id,contact_jid) VALUES($1,$2)")
            .bind(viewer_id)
            .bind("peer@remote.test")
            .execute(&pool)
            .await
            .unwrap();
        assert!(archive_allowed(&pool, viewer_id, "peer@remote.test/Phone")
            .await
            .unwrap());
        sqlx::query("DELETE FROM roster_items WHERE owner_id=$1")
            .bind(viewer_id)
            .execute(&pool)
            .await
            .unwrap();
        assert!(!archive_allowed(&pool, viewer_id, "peer@remote.test/Phone")
            .await
            .unwrap());

        let room_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO muc_rooms(id,localpart,owner_id,members_only,occupant_id_secret)
             VALUES($1,'snapshot-room',$2,TRUE,$3)",
        )
        .bind(room_id)
        .bind(viewer_id)
        .bind(vec![7_u8; 32])
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO muc_affiliations(room_id,user_id,affiliation)
             VALUES($1,$2,'member')",
        )
        .bind(room_id)
        .bind(viewer_id)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO muc_external_affiliations(room_id,jid,affiliation)
             VALUES($1,'remote@remote.test','member')",
        )
        .bind(room_id)
        .execute(&pool)
        .await
        .unwrap();
        let message_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO muc_messages
             (id,room_id,sender_jid,nick,stanza,encrypted,message_kind,actor_scope)
             VALUES($1,$2,'sender@remote.test/Phone','Sender','<message/>',FALSE,
                    'discussion','sender@remote.test')",
        )
        .bind(message_id)
        .bind(room_id)
        .execute(&pool)
        .await
        .unwrap();

        let mut local_snapshot = pool.begin().await.unwrap();
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .execute(&mut *local_snapshot)
            .await
            .unwrap();
        let local_access = match authorize_mam_room_in_transaction(
            &mut local_snapshot,
            "snapshot-room",
            viewer_id,
            false,
        )
        .await
        .unwrap()
        {
            MamRoomReadOutcome::Allowed { access, .. } => access,
            other => panic!("member was not authorized: {other:?}"),
        };
        sqlx::query(
            "UPDATE muc_affiliations SET affiliation='outcast'
              WHERE room_id=$1 AND user_id=$2",
        )
        .bind(room_id)
        .bind(viewer_id)
        .execute(&pool)
        .await
        .unwrap();
        let local_boundaries = archive_boundaries_for_in_transaction(
            &mut local_snapshot,
            MamArchiveSource::Muc(local_access.room_id),
            Some(viewer_id),
        )
        .await
        .unwrap();
        assert_eq!(local_boundaries.0.map(|row| row.id), Some(message_id));
        let local_page = mam_archive_page_for_in_transaction(
            &mut local_snapshot,
            MamArchiveSource::Muc(local_access.room_id),
            Some(viewer_id),
            &page_query(),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(local_page.rows[0].id, message_id);
        local_snapshot.commit().await.unwrap();
        assert!(matches!(
            mam_room_archive_page_authorized(
                &pool,
                "snapshot-room",
                viewer_id,
                false,
                &page_query(),
            )
            .await
            .unwrap(),
            MamRoomReadOutcome::Forbidden
        ));

        let mut federated_snapshot = pool.begin().await.unwrap();
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .execute(&mut *federated_snapshot)
            .await
            .unwrap();
        let (federated_access, federated_page) =
            match mam_federated_room_archive_page_authorized_in_transaction(
                &mut federated_snapshot,
                "snapshot-room",
                "remote@remote.test",
                false,
                &page_query(),
            )
            .await
            .unwrap()
            {
                MamRoomReadOutcome::Allowed {
                    access,
                    value: Some(page),
                } => (access, page),
                other => panic!("federated member was not authorized: {other:?}"),
            };
        let writer_pool = pool.clone();
        let mut affiliation_writer = tokio::spawn(async move {
            sqlx::query(
                "UPDATE muc_external_affiliations SET affiliation='outcast'
                  WHERE room_id=$1 AND jid='remote@remote.test'",
            )
            .bind(room_id)
            .execute(&writer_pool)
            .await
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut affiliation_writer)
                .await
                .is_err(),
            "the federated authority row must stay locked through its durable projection"
        );
        assert_eq!(federated_access.room_id, room_id);
        assert_eq!(federated_page.rows[0].id, message_id);
        federated_snapshot.commit().await.unwrap();
        affiliation_writer.await.unwrap().unwrap();
        assert!(matches!(
            mam_federated_room_archive_page_authorized(
                &pool,
                "snapshot-room",
                "remote@remote.test",
                false,
                &page_query(),
            )
            .await
            .unwrap(),
            MamRoomReadOutcome::Forbidden
        ));

        sqlx::query(
            "UPDATE muc_external_affiliations SET affiliation='member'
              WHERE room_id=$1 AND jid='remote@remote.test'",
        )
        .bind(room_id)
        .execute(&pool)
        .await
        .unwrap();

        // A failure while appending the terminal response must leave neither
        // a visible prefix nor a successful fin in the durable outbox.
        let mut atomic_stream = pool.begin().await.unwrap();
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .execute(&mut *atomic_stream)
            .await
            .unwrap();
        assert!(matches!(
            mam_federated_room_archive_page_authorized_in_transaction(
                &mut atomic_stream,
                "snapshot-room",
                "remote@remote.test",
                false,
                &page_query(),
            )
            .await
            .unwrap(),
            MamRoomReadOutcome::Allowed { value: Some(_), .. }
        ));
        let one_row_policy = crate::db::S2sOutboxPolicy {
            ttl_seconds: 300,
            max_rows: 1,
            max_bytes: 1024 * 1024,
            max_per_domain: 1,
        };
        crate::db::enqueue_s2s_outbox_in_transaction(
            &mut atomic_stream,
            "remote.test",
            "<iq xmlns='jabber:server' type='result' id='first'/>",
            None,
            one_row_policy,
        )
        .await
        .unwrap();
        assert!(crate::db::enqueue_s2s_outbox_in_transaction(
            &mut atomic_stream,
            "remote.test",
            "<iq xmlns='jabber:server' type='result' id='fin'/>",
            None,
            one_row_policy,
        )
        .await
        .is_err());
        atomic_stream.rollback().await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM s2s_outbox")
                .fetch_one(&pool)
                .await
                .unwrap(),
            0
        );

        // The exact room UUID remains fenced until the authorized projection
        // ends. A destroy plus same-localpart recreation cannot redirect the
        // in-flight read to the replacement room.
        let mut identity_fence = pool.begin().await.unwrap();
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .execute(&mut *identity_fence)
            .await
            .unwrap();
        let access = match mam_federated_room_archive_page_authorized_in_transaction(
            &mut identity_fence,
            "snapshot-room",
            "remote@remote.test",
            false,
            &page_query(),
        )
        .await
        .unwrap()
        {
            MamRoomReadOutcome::Allowed { access, .. } => access,
            other => panic!("room identity fence was not authorized: {other:?}"),
        };
        assert_eq!(access.room_id, room_id);
        let replacement_id = Uuid::new_v4();
        let replacement_pool = pool.clone();
        let mut replacement = tokio::spawn(async move {
            let mut tx = replacement_pool.begin().await.unwrap();
            sqlx::query(
                "UPDATE muc_rooms
                    SET destroyed_at=clock_timestamp(),destroyed_operation_id=$2
                  WHERE id=$1",
            )
            .bind(room_id)
            .bind(Uuid::new_v4())
            .execute(&mut *tx)
            .await
            .unwrap();
            sqlx::query(
                "INSERT INTO muc_rooms(id,localpart,owner_id,members_only,occupant_id_secret)
                 VALUES($1,'snapshot-room',$2,TRUE,$3)",
            )
            .bind(replacement_id)
            .bind(viewer_id)
            .bind(vec![8_u8; 32])
            .execute(&mut *tx)
            .await
            .unwrap();
            tx.commit().await.unwrap();
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut replacement)
                .await
                .is_err(),
            "destroy/recreate must wait for the exact authorized room snapshot"
        );
        identity_fence.commit().await.unwrap();
        replacement.await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, Uuid>(
                "SELECT id FROM muc_rooms
                  WHERE localpart='snapshot-room' AND destroyed_at IS NULL",
            )
            .fetch_one(&pool)
            .await
            .unwrap(),
            replacement_id
        );

        pool.close().await;
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&admin)
            .await
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
    async fn mix_source_dedupe_and_mam_visibility_share_one_snapshot_scope() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let admin = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(60))
            .connect(&url)
            .await
            .unwrap();
        let schema = format!("history_identity_test_{}", Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&admin)
            .await
            .unwrap();
        // Emitted only after this test has acquired ownership. The outer
        // harness can then recover a schema left by a panic without ever
        // dropping a coincidentally pre-existing namespace.
        eprintln!("isolated_schema_created={schema}");
        let connection_schema = schema.clone();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(8)
            .acquire_timeout(Duration::from_secs(60))
            .after_connect(move |connection, _| {
                let statement = format!("SET search_path TO {connection_schema}");
                Box::pin(async move {
                    sqlx::query(&statement).execute(connection).await?;
                    Ok(())
                })
            })
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();

        let owner_id = Uuid::new_v4();
        sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,'mamowner','test')")
            .bind(owner_id)
            .execute(&pool)
            .await
            .unwrap();
        let recipient_owner_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO users(id,username,password_hash) VALUES($1,'mamrecipient','test')",
        )
        .bind(recipient_owner_id)
        .execute(&pool)
        .await
        .unwrap();

        let history_barrier = Arc::new(Barrier::new(3));
        let mut history_tasks = Vec::new();
        for _ in 0..2 {
            let pool = pool.clone();
            let history_barrier = Arc::clone(&history_barrier);
            history_tasks.push(tokio::spawn(async move {
                let sender_archive_id = Uuid::new_v4();
                let recipient_archive_id = Uuid::new_v4();
                let writes = [
                    PersonalArchiveWrite {
                        id: sender_archive_id,
                        owner_id,
                        peer_jid: "mamrecipient@local.test/Phone",
                        stanza: "<message id='history-sender'/>",
                        encrypted: false,
                        stanza_id: Some("client-history-id"),
                    },
                    PersonalArchiveWrite {
                        id: recipient_archive_id,
                        owner_id: recipient_owner_id,
                        peer_jid: "mamowner@local.test/Laptop",
                        stanza: "<message id='history-recipient'/>",
                        encrypted: false,
                        stanza_id: Some("client-history-id"),
                    },
                ];
                let identity = personal_identity(
                    "local-origin",
                    "mamowner@local.test",
                    "mamowner@local.test",
                    "mamrecipient@local.test",
                    "origin-atomic-1",
                    "<message id='client-history-id'><origin-id xmlns='urn:xmpp:sid:0' id='origin-atomic-1'/></message>",
                );
                history_barrier.wait().await;
                admit_personal_history(&pool, Some(&identity), &writes)
                    .await
                    .unwrap()
            }));
        }
        history_barrier.wait().await;
        let history_outcomes = futures::future::join_all(history_tasks)
            .await
            .into_iter()
            .map(Result::unwrap)
            .collect::<Vec<_>>();
        assert_eq!(
            history_outcomes
                .iter()
                .filter(|outcome| matches!(outcome, PersonalHistoryAdmission::Stored(_)))
                .count(),
            1
        );
        assert_eq!(
            history_outcomes
                .iter()
                .filter(|outcome| matches!(outcome, PersonalHistoryAdmission::Replay(_)))
                .count(),
            1
        );
        let admitted_ids = match &history_outcomes[0] {
            PersonalHistoryAdmission::Stored(ids) | PersonalHistoryAdmission::Replay(ids) => ids,
            PersonalHistoryAdmission::AccountUnavailable => {
                panic!("enabled fixture account unexpectedly unavailable")
            }
        };
        assert!(history_outcomes.iter().all(|outcome| match outcome {
            PersonalHistoryAdmission::Stored(ids) | PersonalHistoryAdmission::Replay(ids) =>
                ids == admitted_ids,
            PersonalHistoryAdmission::AccountUnavailable => false,
        }));
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM message_archive WHERE id=ANY($1::UUID[])",
            )
            .bind(admitted_ids)
            .fetch_one(&pool)
            .await
            .unwrap(),
            2
        );
        let conflicting_writes = [PersonalArchiveWrite {
            id: Uuid::new_v4(),
            owner_id,
            peer_jid: "mamrecipient@local.test/Phone",
            stanza: "<message id='forged-history'/>",
            encrypted: false,
            stanza_id: Some("client-history-id"),
        }];
        let conflicting_identity = personal_identity(
            "local-origin",
            "mamowner@local.test",
            "mamowner@local.test",
            "mamrecipient@local.test",
            "origin-atomic-1",
            "<message id='forged-history'/>",
        );
        assert!(
            admit_personal_history(&pool, Some(&conflicting_identity), &conflicting_writes)
                .await
                .unwrap_err()
                .to_string()
                .contains("conflicting personal history identity")
        );

        let rollback_archive_id = Uuid::new_v4();
        let rollback_writes = [
            PersonalArchiveWrite {
                id: rollback_archive_id,
                owner_id,
                peer_jid: "mamrecipient@local.test",
                stanza: "<message id='rollback-a'/>",
                encrypted: false,
                stanza_id: None,
            },
            PersonalArchiveWrite {
                id: Uuid::new_v4(),
                owner_id: Uuid::new_v4(),
                peer_jid: "missing@local.test",
                stanza: "<message id='rollback-b'/>",
                encrypted: false,
                stanza_id: None,
            },
        ];
        let rollback_identity = personal_identity(
            "local-origin",
            "mamowner@local.test",
            "mamowner@local.test",
            "missing@local.test",
            "origin-rollback",
            "<message id='rollback'/>",
        );
        assert_eq!(
            admit_personal_history(&pool, Some(&rollback_identity), &rollback_writes)
                .await
                .unwrap(),
            PersonalHistoryAdmission::AccountUnavailable,
            "the authorization snapshot must reject a missing projection owner before any admission or archive write",
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM message_archive WHERE id=$1")
                .bind(rollback_archive_id)
                .fetch_one(&pool)
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM personal_message_admissions WHERE identity_value='origin-rollback'",
            )
            .fetch_one(&pool)
            .await
            .unwrap(),
            0
        );

        let failed_outbox_archive_id = Uuid::new_v4();
        let failed_outbox_write = [PersonalArchiveWrite {
            id: failed_outbox_archive_id,
            owner_id,
            peer_jid: "remote@remote.test",
            stanza: "<message id='atomic-outbox-failure'/>",
            encrypted: false,
            stanza_id: Some("atomic-outbox-failure"),
        }];
        let rejecting_outbox = PersonalS2sOutboxAdmission {
            local_actor_id: owner_id,
            target_domain: "remote.test",
            stanza: "<message from='mamowner@local.test' to='remote@remote.test'/>",
            bounce_to: Some("mamowner@local.test/Phone"),
            policy: super::super::S2sOutboxPolicy {
                ttl_seconds: 300,
                max_rows: 0,
                max_bytes: 1_000_000,
                max_per_domain: 100,
            },
        };
        assert!(admit_outbound_personal_history(
            &pool,
            None,
            &failed_outbox_write,
            &rejecting_outbox,
        )
        .await
        .is_err());
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM message_archive WHERE id=$1")
                .bind(failed_outbox_archive_id)
                .fetch_one(&pool)
                .await
                .unwrap(),
            0,
            "outbox capacity failure must roll back the paired MAM row"
        );

        let accepted_outbox_archive_id = Uuid::new_v4();
        let accepted_outbox_write = [PersonalArchiveWrite {
            id: accepted_outbox_archive_id,
            owner_id,
            peer_jid: "remote@remote.test",
            stanza: "<message id='atomic-outbox-success'/>",
            encrypted: false,
            stanza_id: Some("atomic-outbox-success"),
        }];
        let accepting_outbox = PersonalS2sOutboxAdmission {
            policy: super::super::S2sOutboxPolicy {
                max_rows: 100,
                ..rejecting_outbox.policy
            },
            ..rejecting_outbox
        };
        let accepted_outbox_identity = personal_identity(
            "local-origin",
            "mamowner@local.test",
            "mamowner@local.test",
            "remote@remote.test",
            "origin-atomic-outbox-success",
            "<message id='atomic-outbox-success'/>",
        );
        assert!(matches!(
            admit_outbound_personal_history(
                &pool,
                Some(&accepted_outbox_identity),
                &accepted_outbox_write,
                &accepting_outbox,
            )
            .await
            .unwrap(),
            PersonalHistoryAdmission::Stored(_)
        ));
        let replay_outbox_write = [PersonalArchiveWrite {
            id: Uuid::new_v4(),
            ..accepted_outbox_write[0].clone()
        }];
        assert!(matches!(
            admit_outbound_personal_history(
                &pool,
                Some(&accepted_outbox_identity),
                &replay_outbox_write,
                &accepting_outbox,
            )
            .await
            .unwrap(),
            PersonalHistoryAdmission::Replay(_)
        ));
        let conflicting_outbox_identity = personal_identity(
            "local-origin",
            "mamowner@local.test",
            "mamowner@local.test",
            "remote@remote.test",
            "origin-atomic-outbox-success",
            "<message id='changed-outbox-payload'/>",
        );
        assert!(admit_outbound_personal_history(
            &pool,
            Some(&conflicting_outbox_identity),
            &replay_outbox_write,
            &accepting_outbox,
        )
        .await
        .unwrap_err()
        .to_string()
        .contains("conflicting personal history identity"));
        let (paired_archive, paired_outbox): (i64, i64) = (
            sqlx::query_scalar("SELECT COUNT(*) FROM message_archive WHERE id=$1")
                .bind(accepted_outbox_archive_id)
                .fetch_one(&pool)
                .await
                .unwrap(),
            sqlx::query_scalar("SELECT COUNT(*) FROM s2s_outbox WHERE target_domain='remote.test'")
                .fetch_one(&pool)
                .await
                .unwrap(),
        );
        assert_eq!((paired_archive, paired_outbox), (1, 1));

        // A plaintext message can deliberately have no MAM projection when
        // REQUIRE_ENCRYPTED_ARCHIVE is enabled. The durable S2S outbox still
        // has to consume its origin-id atomically so retry and conflict
        // semantics do not depend on archive policy.
        let plaintext_outbox = PersonalS2sOutboxAdmission {
            local_actor_id: owner_id,
            target_domain: "plaintext.remote.test",
            stanza: "<message from='mamowner@local.test' to='remote@plaintext.remote.test'><body>plaintext</body></message>",
            bounce_to: Some("mamowner@local.test/Phone"),
            policy: accepting_outbox.policy,
        };
        let plaintext_identity = personal_identity(
            "local-origin",
            "mamowner@local.test",
            "mamowner@local.test",
            "remote@plaintext.remote.test",
            "origin-plaintext-without-mam",
            plaintext_outbox.stanza,
        );
        assert_eq!(
            admit_outbound_personal_history(
                &pool,
                Some(&plaintext_identity),
                &[],
                &plaintext_outbox,
            )
            .await
            .unwrap(),
            PersonalHistoryAdmission::Stored(Vec::new())
        );
        assert_eq!(
            admit_outbound_personal_history(
                &pool,
                Some(&plaintext_identity),
                &[],
                &plaintext_outbox,
            )
            .await
            .unwrap(),
            PersonalHistoryAdmission::Replay(Vec::new())
        );
        let changed_plaintext_identity = personal_identity(
            "local-origin",
            "mamowner@local.test",
            "mamowner@local.test",
            "remote@plaintext.remote.test",
            "origin-plaintext-without-mam",
            "<message><body>changed plaintext</body></message>",
        );
        assert!(admit_outbound_personal_history(
            &pool,
            Some(&changed_plaintext_identity),
            &[],
            &plaintext_outbox,
        )
        .await
        .unwrap_err()
        .to_string()
        .contains("conflicting personal history identity"));
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM s2s_outbox WHERE target_domain='plaintext.remote.test'",
            )
            .fetch_one(&pool)
            .await
            .unwrap(),
            1
        );
        let plaintext_outbox_id = sqlx::query_scalar::<_, Option<Uuid>>(
            "SELECT s2s_outbox_id
               FROM personal_message_admissions
              WHERE identity_kind='local-origin'
                AND identity_value='origin-plaintext-without-mam'",
        )
        .fetch_one(&pool)
        .await
        .unwrap()
        .expect("the admission must own its recoverable S2S outbox projection");
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM s2s_outbox WHERE id=$1")
                .bind(plaintext_outbox_id)
                .fetch_one(&pool)
                .await
                .unwrap(),
            1
        );

        // Completing the transient outbox must retain a bounded identity
        // tombstone. Otherwise a socket-write/delete success followed by an
        // exact client replay would enqueue the same logical message again.
        sqlx::query("DELETE FROM s2s_outbox WHERE id=$1")
            .bind(plaintext_outbox_id)
            .execute(&pool)
            .await
            .unwrap();
        let completed_projection = sqlx::query_as::<_, (Option<Uuid>, Option<DateTime<Utc>>)>(
            "SELECT s2s_outbox_id,delivery_completed_at
               FROM personal_message_admissions
              WHERE identity_kind='local-origin'
                AND identity_value='origin-plaintext-without-mam'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(completed_projection.0, None);
        assert!(completed_projection.1.is_some());
        assert_eq!(
            admit_outbound_personal_history(
                &pool,
                Some(&plaintext_identity),
                &[],
                &plaintext_outbox,
            )
            .await
            .unwrap(),
            PersonalHistoryAdmission::Replay(Vec::new())
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM s2s_outbox WHERE target_domain='plaintext.remote.test'",
            )
            .fetch_one(&pool)
            .await
            .unwrap(),
            0,
            "a completed origin-id replay must not recreate its S2S outbox"
        );
        assert!(admit_outbound_personal_history(
            &pool,
            Some(&changed_plaintext_identity),
            &[],
            &plaintext_outbox,
        )
        .await
        .unwrap_err()
        .to_string()
        .contains("conflicting personal history identity"));

        let plaintext_c2s_id = Uuid::new_v4();
        let plaintext_c2s = PersonalC2sDeliveryAdmission {
            id: plaintext_c2s_id,
            recipient_id: recipient_owner_id,
            recipient_bare_jid: "mamrecipient@local.test",
            local_actor_id: Some(owner_id),
            sender_jid: "mamowner@local.test/Phone",
            stanza: "<message from='mamowner@local.test/Phone' to='mamrecipient@local.test'><body>local plaintext</body></message>",
            target_full_jid: None,
            encrypted: false,
            policy: OfflineStorePolicy {
                max_messages: 100,
                max_bytes: 1_000_000,
                ttl_days: 30,
                mam_backed: false,
            },
        };
        let plaintext_c2s_identity = personal_identity(
            "local-origin",
            "mamowner@local.test",
            "mamowner@local.test",
            "mamrecipient@local.test",
            "origin-local-plaintext-without-mam",
            plaintext_c2s.stanza,
        );
        assert_eq!(
            admit_personal_history_and_c2s_delivery(
                &pool,
                Some(&plaintext_c2s_identity),
                &[],
                &plaintext_c2s,
            )
            .await
            .unwrap(),
            PersonalHistoryAdmission::Stored(Vec::new())
        );
        assert_eq!(
            admit_personal_history_and_c2s_delivery(
                &pool,
                Some(&plaintext_c2s_identity),
                &[],
                &plaintext_c2s,
            )
            .await
            .unwrap(),
            PersonalHistoryAdmission::Replay(Vec::new())
        );
        let changed_c2s_identity = personal_identity(
            "local-origin",
            "mamowner@local.test",
            "mamowner@local.test",
            "mamrecipient@local.test",
            "origin-local-plaintext-without-mam",
            "<message><body>changed local plaintext</body></message>",
        );
        assert!(admit_personal_history_and_c2s_delivery(
            &pool,
            Some(&changed_c2s_identity),
            &[],
            &plaintext_c2s,
        )
        .await
        .unwrap_err()
        .to_string()
        .contains("conflicting personal history identity"));
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM offline_messages WHERE id=$1")
                .bind(plaintext_c2s_id)
                .fetch_one(&pool)
                .await
                .unwrap(),
            1
        );
        sqlx::query("DELETE FROM message_archive WHERE owner_id=ANY($1::UUID[])")
            .bind(vec![owner_id, recipient_owner_id])
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM personal_message_admissions")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM offline_messages WHERE id=$1")
            .bind(plaintext_c2s_id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM s2s_outbox")
            .execute(&pool)
            .await
            .unwrap();
        let bob_id = Uuid::new_v4();
        let carol_id = Uuid::new_v4();
        archive_message(
            &pool,
            bob_id,
            owner_id,
            "bob@example.test/Phone",
            "<message id='bob'/>",
            false,
            Some("bob-client"),
        )
        .await
        .unwrap();
        archive_message(
            &pool,
            carol_id,
            owner_id,
            "carol@example.test/Laptop",
            "<message id='carol'/>",
            false,
            Some("carol-client"),
        )
        .await
        .unwrap();

        let mut wrong_filter_cursor = page_query();
        wrong_filter_cursor.with_jid = Some("bob@example.test".to_owned());
        wrong_filter_cursor.page = MamRsmPage::After(carol_id);
        let filtered_after_other_peer =
            mam_user_archive_page(&pool, owner_id, &wrong_filter_cursor)
                .await
                .unwrap()
                .expect("the cursor exists in the archive's visible scope");
        assert!(filtered_after_other_peer.rows.is_empty());
        assert_eq!(filtered_after_other_peer.total, 1);
        assert!(filtered_after_other_peer.complete);

        sqlx::query("INSERT INTO blocked_jids(owner_id,blocked_jid) VALUES($1,$2)")
            .bind(owner_id)
            .bind("bob@example.test")
            .execute(&pool)
            .await
            .unwrap();
        let mut blocked_cursor = page_query();
        blocked_cursor.page = MamRsmPage::After(bob_id);
        assert!(mam_user_archive_page(&pool, owner_id, &blocked_cursor)
            .await
            .unwrap()
            .is_none());
        let visible = mam_user_archive_page(&pool, owner_id, &page_query())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(visible.total, 1);
        assert_eq!(visible.rows.len(), 1);
        assert_eq!(visible.rows[0].id, carol_id);
        let personal_boundaries = archive_boundaries_visible(&pool, owner_id).await.unwrap();
        assert_eq!(
            personal_boundaries.0.as_ref().map(|row| row.id),
            Some(carol_id)
        );
        assert_eq!(
            personal_boundaries.1.as_ref().map(|row| row.id),
            Some(carol_id)
        );

        let room_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO muc_rooms(id,localpart,owner_id,occupant_id_secret)
             VALUES($1,'visible-room',$2,$3)",
        )
        .bind(room_id)
        .bind(owner_id)
        .bind(vec![5_u8; 32])
        .execute(&pool)
        .await
        .unwrap();
        let muc_bob_id = Uuid::new_v4();
        let muc_carol_id = Uuid::new_v4();
        for (id, actor, sender, nick) in [
            (
                muc_bob_id,
                "bob@example.test",
                "bob@example.test/Phone",
                "Bob",
            ),
            (
                muc_carol_id,
                "carol@example.test",
                "carol@example.test/Laptop",
                "Carol",
            ),
        ] {
            sqlx::query(
                "INSERT INTO muc_messages
                 (id,room_id,sender_jid,nick,stanza,encrypted,message_kind,actor_scope)
                 VALUES($1,$2,$3,$4,'<message/>',FALSE,'discussion',$5)",
            )
            .bind(id)
            .bind(room_id)
            .bind(sender)
            .bind(nick)
            .bind(actor)
            .execute(&pool)
            .await
            .unwrap();
        }
        let mut blocked_muc_cursor = page_query();
        blocked_muc_cursor.page = MamRsmPage::After(muc_bob_id);
        assert!(
            mam_muc_archive_page_visible(&pool, room_id, owner_id, &blocked_muc_cursor)
                .await
                .unwrap()
                .is_none()
        );
        let visible_muc = mam_muc_archive_page_visible(&pool, room_id, owner_id, &page_query())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(visible_muc.total, 1);
        assert_eq!(visible_muc.rows[0].id, muc_carol_id);
        let muc_boundaries = muc_archive_boundaries_visible(&pool, room_id, owner_id)
            .await
            .unwrap();
        assert_eq!(
            muc_boundaries.0.as_ref().map(|row| row.id),
            Some(muc_carol_id)
        );
        assert_eq!(
            muc_boundaries.1.as_ref().map(|row| row.id),
            Some(muc_carol_id)
        );

        for (sender, id) in [
            ("bob@example.test/Phone", "blocked-offline"),
            ("carol@example.test/Laptop", "visible-offline"),
        ] {
            assert_eq!(
                store_offline(
                    &pool,
                    owner_id,
                    sender,
                    &format!("<message id='{id}'/>"),
                    false,
                    OfflineStorePolicy {
                        max_messages: 10,
                        max_bytes: 16_384,
                        ttl_days: 30,
                        mam_backed: false,
                    },
                )
                .await
                .unwrap(),
                OfflineStoreOutcome::Stored
            );
        }
        let (offline_tx, mut offline_rx) = tokio::sync::mpsc::channel(4);
        let offline_tx = crate::outbound::OutboundSender::new(offline_tx);
        assert_eq!(
            deliver_offline(&pool, owner_id, 30, &offline_tx, None)
                .await
                .unwrap(),
            1
        );
        drop(offline_tx);
        let delivered = offline_rx.recv().await.unwrap();
        crate::db::replay::acknowledge_durable_delivery(&pool, delivered.durable_delivery.unwrap())
            .await
            .unwrap();
        assert_eq!(delivered.stanza, "<message id='visible-offline'/>");
        assert!(offline_rx.recv().await.is_none());
        assert_eq!(offline_message_count(&pool, owner_id).await.unwrap(), 0);

        for (id, mam_backed) in [
            ("bind2-mam-duplicate", true),
            ("bind2-temporary-only", false),
        ] {
            assert_eq!(
                store_offline(
                    &pool,
                    recipient_owner_id,
                    "sender@remote.test/Phone",
                    &format!("<message id='{id}'/>"),
                    false,
                    OfflineStorePolicy {
                        max_messages: 10,
                        max_bytes: 16_384,
                        ttl_days: 30,
                        mam_backed,
                    },
                )
                .await
                .unwrap(),
                OfflineStoreOutcome::Stored
            );
        }
        let (bind2_tx, mut bind2_rx) = tokio::sync::mpsc::channel(4);
        let bind2_tx = crate::outbound::OutboundSender::new(bind2_tx);
        assert_eq!(
            deliver_bind2_offline(&pool, recipient_owner_id, 30, &bind2_tx, None)
                .await
                .unwrap(),
            1
        );
        drop(bind2_tx);
        let delivered = bind2_rx.recv().await.unwrap();
        crate::db::replay::acknowledge_durable_delivery(&pool, delivered.durable_delivery.unwrap())
            .await
            .unwrap();
        assert_eq!(delivered.stanza, "<message id='bind2-temporary-only'/>");
        assert!(bind2_rx.recv().await.is_none());
        assert_eq!(
            offline_message_count(&pool, recipient_owner_id)
                .await
                .unwrap(),
            0
        );

        let source_id = Uuid::new_v4();
        let barrier = Arc::new(Barrier::new(3));
        let mut tasks = Vec::new();
        for _ in 0..2 {
            let pool = pool.clone();
            let barrier = Arc::clone(&barrier);
            tasks.push(tokio::spawn(async move {
                let archive_id = Uuid::new_v4();
                barrier.wait().await;
                archive_mix_message_once(
                    &pool,
                    archive_id,
                    owner_id,
                    "room@mix.remote.test",
                    source_id,
                    "<message id='remote-reflection'/>",
                    true,
                    Some("client-origin"),
                )
                .await
                .unwrap()
            }));
        }
        barrier.wait().await;
        let outcomes = futures::future::join_all(tasks)
            .await
            .into_iter()
            .map(Result::unwrap)
            .collect::<Vec<_>>();
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, SourceArchiveAdmission::Stored(_)))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, SourceArchiveAdmission::Replay(_)))
                .count(),
            1
        );
        let stable_personal_id = match outcomes[0] {
            SourceArchiveAdmission::Stored(id) | SourceArchiveAdmission::Replay(id) => id,
        };
        assert!(outcomes.iter().all(|outcome| match *outcome {
            SourceArchiveAdmission::Stored(id) | SourceArchiveAdmission::Replay(id) =>
                id == stable_personal_id,
        }));
        assert!(archive_mix_message_once(
            &pool,
            Uuid::new_v4(),
            owner_id,
            "room@mix.remote.test",
            source_id,
            "<message id='forged-replay'/>",
            true,
            Some("client-origin"),
        )
        .await
        .unwrap_err()
        .to_string()
        .contains("conflicting MIX source stanza identity"));

        let channel_id = Uuid::new_v4();
        let internal_id = Uuid::new_v4();
        let authoritative_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO mix_channels(id,service_domain,localpart,creator_jid)
             VALUES($1,'mix.local.test','stable','alice@local.test')",
        )
        .bind(channel_id)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO mix_events(id,channel_id,node,item_id,payload)
             VALUES($1,$2,'urn:xmpp:mix:nodes:messages',$3,'<message/>')",
        )
        .bind(internal_id)
        .bind(channel_id)
        .bind(authoritative_id.to_string())
        .execute(&pool)
        .await
        .unwrap();
        let stored_authority: Uuid =
            sqlx::query_scalar("SELECT authoritative_id FROM mix_events WHERE id=$1")
                .bind(internal_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(stored_authority, authoritative_id);

        pool.close().await;
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&admin)
            .await
            .unwrap();
        admin.close().await;
    }
}
