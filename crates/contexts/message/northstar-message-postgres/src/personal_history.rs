//! Personal admission records, the transient C2S delivery row and its live reservation.

use crate::direct_spool_wake::record_direct_spool_wake_in_transaction;
use crate::offline::OfflineStorePolicy;
use anyhow::Result;
use northstar_abuse_policy::ContentIdentityAuthenticators;
use northstar_postgres::cluster_lock::lock_direct_spool_instance_claims_in_transaction;
use sqlx::{PgPool, Postgres, Row, Transaction};
use subtle::ConstantTimeEq;
use uuid::Uuid;

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
    pub policy: northstar_federation_core::S2sOutboxPolicy,
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
pub struct C2sDeliveryCapacityExceeded;

#[derive(Debug, thiserror::Error)]
#[error("conflicting personal history identity")]
pub struct PersonalHistoryIdentityConflict;

/// Reserve the newly inserted durable row for its postcommit primary route.
/// The initial token is deliberately the row UUID, allowing every transport
/// to receive the same exact claim without a second result-shape projection.
pub async fn reserve_cluster_live_delivery_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    recipient_id: Uuid,
    message_id: Uuid,
) -> Result<()> {
    let updated = sqlx::query(
        "UPDATE offline_messages
            SET delivery_claim_id=$2,
                delivery_claim_expires_at=clock_timestamp()+INTERVAL '60 seconds'
          WHERE recipient_id=$1 AND id=$2 AND delivery_claim_id IS NULL",
    )
    .bind(recipient_id)
    .bind(message_id)
    .execute(&mut **transaction)
    .await?
    .rows_affected();
    anyhow::ensure!(
        updated == 1,
        "new direct delivery lost its live reservation before commit"
    );
    Ok(())
}

/// Release only the initial claim if no transport has taken it, and refresh
/// the persistent wake in the same transaction. A socket fence rotates the
/// token; SM and BOSH transfers clear it while creating their own owner.
pub async fn release_cluster_live_delivery_reservation_and_rearm(
    pool: &PgPool,
    domain: &str,
    recipient_id: Uuid,
    message_id: Uuid,
    claim_id: Uuid,
) -> Result<bool> {
    anyhow::ensure!(
        claim_id == message_id,
        "direct live reservation token is not the durable message ID"
    );
    let mut transaction = pool.begin().await?;
    lock_direct_spool_instance_claims_in_transaction(&mut transaction).await?;
    let released = sqlx::query(
        "UPDATE offline_messages
            SET delivery_claim_id=NULL,delivery_claim_expires_at=NULL
          WHERE recipient_id=$1 AND id=$2 AND delivery_claim_id=$3",
    )
    .bind(recipient_id)
    .bind(message_id)
    .bind(claim_id)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    if released == 1 {
        record_direct_spool_wake_in_transaction(&mut transaction, domain, recipient_id).await?;
    }
    transaction.commit().await?;
    Ok(released == 1)
}

pub async fn insert_c2s_delivery_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    delivery: &PersonalC2sDeliveryAdmission<'_>,
    sender_jid: &str,
) -> Result<()> {
    let (target_resource, stanza_target_bare_jid) = normalized_c2s_target_resource(delivery)?;
    let recipient_bare_jid =
        northstar_xmpp_types::jid::canonicalize_bare(delivery.recipient_bare_jid)?;
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
    let recipient = northstar_xmpp_types::jid::CanonicalJid::parse_bare(&recipient_bare_jid)?;
    let recipient_matches: bool =
        sqlx::query_scalar("SELECT northstar_lock_enabled_user_name($1,$2)")
            .bind(delivery.recipient_id)
            .bind(recipient.localpart().unwrap_or_default())
            .fetch_one(&mut **transaction)
            .await?;
    anyhow::ensure!(
        recipient_matches,
        "C2S delivery recipient account is unavailable or authority does not match"
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
pub fn normalized_c2s_target_resource(
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
        .map(northstar_xmpp_types::jid::CanonicalJid::parse)
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
        .map(northstar_xmpp_types::jid::canonical_session_key)
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
        .map(northstar_xmpp_types::jid::CanonicalJid::parse)
        .transpose()?
        .and_then(|target| target.resourcepart().map(str::to_owned));
    Ok((target_resource, target_bare_jid))
}

/// The rows a personal admission will own, fixed before it is recorded.
pub struct PersonalAdmissionProjections {
    pub sender_archive_id: Option<Uuid>,
    pub recipient_archive_id: Option<Uuid>,
    pub offline_message_id: Option<Uuid>,
    pub s2s_outbox_id: Option<Uuid>,
}

/// Records a personal admission. A new identity returns `None`; an exact replay returns the
/// archive rows of the original admission; anything else under the same identity is a
/// [`PersonalHistoryIdentityConflict`]. The caller owns commit and rollback.
pub async fn claim_personal_admission_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    identity: &PersonalHistoryIdentity<'_>,
    actor_scope: &str,
    target_scope: &str,
    identity_digest: &[u8],
    projections: PersonalAdmissionProjections,
) -> Result<Option<Vec<Uuid>>> {
    let admission_id = Uuid::new_v4();
    let primary_authenticator = identity.payload_authenticators.primary();
    let inserted = sqlx::query(
        "INSERT INTO personal_message_admissions
         (id,identity_kind,actor_scope_raw,actor_scope,target_scope,
          identity_value,identity_digest,payload_key_id,payload_mac,
          sender_archive_id,recipient_archive_id,offline_message_id,s2s_outbox_id)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
         ON CONFLICT (
            identity_kind,
            (pg_catalog.md5(
                'northstar:personal-admission-actor-scope:v1:'::pg_catalog.text
                || actor_scope::pg_catalog.text
            )),
            (pg_catalog.md5(
                'northstar:personal-admission-target-scope:v1:'::pg_catalog.text
                || target_scope::pg_catalog.text
            )),
            identity_digest
         )
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
    .bind(projections.sender_archive_id)
    .bind(projections.recipient_archive_id)
    .bind(projections.offline_message_id)
    .bind(projections.s2s_outbox_id)
    .execute(&mut **transaction)
    .await?
    .rows_affected()
        == 1;
    if !inserted {
        let row = sqlx::query(
            "SELECT id,actor_scope_raw,actor_scope,target_scope,identity_value,
                    payload_key_id,payload_mac,payload_digest,
                    sender_archive_id,recipient_archive_id
               FROM personal_message_admissions
              WHERE identity_kind=$1
                AND pg_catalog.md5(
                      'northstar:personal-admission-actor-scope:v1:'::pg_catalog.text
                      || actor_scope::pg_catalog.text
                    ) = pg_catalog.md5(
                      'northstar:personal-admission-actor-scope:v1:'::pg_catalog.text
                      || $2::pg_catalog.text
                    )
                AND pg_catalog.md5(
                      'northstar:personal-admission-target-scope:v1:'::pg_catalog.text
                      || target_scope::pg_catalog.text
                    ) = pg_catalog.md5(
                      'northstar:personal-admission-target-scope:v1:'::pg_catalog.text
                      || $3::pg_catalog.text
                    )
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
            anyhow::bail!("personal history identity conflict row disappeared during admission");
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
        // The unique B-tree uses bounded scope fingerprints so a valid
        // maximum-size JID cannot exceed PostgreSQL's index tuple limit.
        // Fingerprints only locate a conflict candidate: all identity
        // scopes and the originally observed authority spelling remain
        // exact comparisons. A hash collision is therefore a typed
        // conflict, never a cross-principal replay.
        let exact_replay = row.get::<String, _>("actor_scope") == actor_scope
            && row.get::<String, _>("target_scope") == target_scope
            && row.get::<String, _>("actor_scope_raw") == identity.actor_scope_raw
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
        return Ok(Some(existing));
    }
    Ok(None)
}

#[cfg(test)]
mod source_contract_tests;
