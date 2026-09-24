use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rand::Rng;
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    time::Duration,
};
use uuid::Uuid;

const REPLAY_PAGE_SIZE: i64 = 64;
const CLAIM_LEASE_SECONDS: i64 = 60;
const BOSH_FENCE_MAX_AGE_SECONDS: i64 = 300;
// The resource owner outlives every page claim. If a process crashes after
// claiming a page, takeover cannot occur until those row claims are already
// eligible in the same pass; otherwise the replacement would observe an
// apparently empty queue and messages would wait for another login.
pub(crate) use crate::services::replay::OWNER_LEASE_SECONDS as REPLAY_OWNER_LEASE_SECONDS;

pub use crate::services::replay::{
    OfflineReplayBusyUntil, OfflineReplayLease, OfflineReplayLeaseAcquire, PendingPresenceCursor,
    PendingPresenceReplay, PendingPresenceReplayPage,
};

#[cfg(test)]
impl OfflineReplayLeaseAcquire {
    fn into_acquired(self) -> Option<OfflineReplayLease> {
        match self {
            Self::Acquired(lease) => Some(lease),
            Self::BusyUntil(_) => None,
        }
    }

    fn is_acquired(&self) -> bool {
        matches!(self, Self::Acquired(_))
    }
}

#[derive(Clone, Debug)]
pub struct ClaimedOfflineMessage {
    pub id: Uuid,
    pub sender_jid: String,
    pub stanza: String,
}

#[derive(Debug)]
pub struct ClaimedOfflinePage {
    pub claim_token: Uuid,
    pub messages: Vec<ClaimedOfflineMessage>,
}

#[derive(Debug)]
pub enum OfflineReplayPageOutcome {
    Claimed(ClaimedOfflinePage),
    Empty,
    LeaseLost,
}

async fn pending_presence_replay_page_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    recipient_id: Uuid,
    local_domain: &str,
    after: Option<&PendingPresenceCursor>,
) -> Result<Vec<PendingPresenceReplay>> {
    let after_created_at = after.map(|cursor| cursor.created_at);
    let after_source = after.map_or(0_i16, |cursor| cursor.source);
    let after_key = after.map_or("", |cursor| cursor.key.as_str());
    let rows = sqlx::query(
        "WITH pending AS ( \
             SELECT p.created_at,0::SMALLINT AS source,p.requester_id::TEXT AS cursor_key, \
                    u.username || '@' || $6 AS requester,p.stanza \
               FROM pending_presence_subscriptions p \
               JOIN users u ON u.id=p.requester_id \
              WHERE p.recipient_id=$1 \
             UNION ALL \
             SELECT p.created_at,1::SMALLINT AS source,p.from_jid AS cursor_key, \
                    p.from_jid AS requester,p.stanza \
               FROM federated_presence_pending p WHERE p.recipient_id=$1 \
         ) \
         SELECT created_at,source,cursor_key,requester,stanza FROM pending \
          WHERE $2::TIMESTAMPTZ IS NULL \
             OR (created_at,source,cursor_key) > ($2,$3,$4) \
          ORDER BY created_at,source,cursor_key LIMIT $5",
    )
    .bind(recipient_id)
    .bind(after_created_at)
    .bind(after_source)
    .bind(after_key)
    .bind(REPLAY_PAGE_SIZE)
    .bind(local_domain)
    .fetch_all(&mut **transaction)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| PendingPresenceReplay {
            requester: row.get("requester"),
            stanza: row.get("stanza"),
            cursor: PendingPresenceCursor {
                created_at: row.get("created_at"),
                source: row.get("source"),
                key: row.get("cursor_key"),
            },
        })
        .collect())
}

#[derive(Clone, Debug)]
struct ReplayPrivacyRule {
    deny: bool,
    match_type: Option<String>,
    match_value: Option<String>,
    message: bool,
    iq: bool,
    presence_in: bool,
    presence_out: bool,
}

#[derive(Clone, Debug)]
enum ReplayPrivacyPolicy {
    None,
    Rules(Vec<ReplayPrivacyRule>),
}

#[derive(Clone, Debug, Default)]
struct ReplayRosterPolicy {
    subscription: String,
    groups: Vec<String>,
}

async fn replay_policy_snapshot(
    transaction: &mut Transaction<'_, Postgres>,
    owner_id: Uuid,
    active_privacy_list: Option<&str>,
    candidates: &[String],
) -> Result<(
    Vec<String>,
    ReplayPrivacyPolicy,
    HashMap<String, ReplayRosterPolicy>,
)> {
    let blocked_patterns = sqlx::query_scalar::<_, String>(
        "SELECT blocked_jid FROM blocked_jids WHERE owner_id=$1 ORDER BY blocked_jid",
    )
    .bind(owner_id)
    .fetch_all(&mut **transaction)
    .await?;
    let selected = match active_privacy_list {
        Some(name) => Some(name.to_owned()),
        None => {
            sqlx::query_scalar::<_, String>(
                "SELECT list_name FROM privacy_default_lists WHERE owner_id=$1",
            )
            .bind(owner_id)
            .fetch_optional(&mut **transaction)
            .await?
        }
    };
    let privacy = if let Some(selected) = selected {
        let rows = sqlx::query(
            "SELECT l.name,i.action,i.match_type,i.match_value,
                    i.filter_message,i.filter_iq,i.filter_presence_in,i.filter_presence_out
               FROM privacy_lists l
               LEFT JOIN privacy_list_items i
                 ON i.owner_id=l.owner_id AND i.list_name=l.name
              WHERE l.owner_id=$1 AND l.name=$2
              ORDER BY i.item_order",
        )
        .bind(owner_id)
        .bind(selected)
        .fetch_all(&mut **transaction)
        .await?;
        anyhow::ensure!(
            !rows.is_empty(),
            "selected privacy list is unavailable during offline replay"
        );
        let mut rules = Vec::new();
        for row in rows {
            let Some(action) = row.try_get::<Option<String>, _>("action")? else {
                // A valid list with no items is represented by the LEFT JOIN
                // row and permits all traffic.
                continue;
            };
            anyhow::ensure!(
                action == "allow" || action == "deny",
                "invalid privacy action in offline replay snapshot"
            );
            rules.push(ReplayPrivacyRule {
                deny: action == "deny",
                match_type: row.try_get::<Option<String>, _>("match_type")?,
                match_value: row.try_get::<Option<String>, _>("match_value")?,
                message: row.try_get::<bool, _>("filter_message")?,
                iq: row.try_get::<bool, _>("filter_iq")?,
                presence_in: row.try_get::<bool, _>("filter_presence_in")?,
                presence_out: row.try_get::<bool, _>("filter_presence_out")?,
            });
        }
        ReplayPrivacyPolicy::Rules(rules)
    } else {
        ReplayPrivacyPolicy::None
    };

    let mut candidate_bares = candidates
        .iter()
        .map(|candidate| crate::jid::CanonicalJid::parse(candidate).map(|jid| jid.bare()))
        .collect::<Result<Vec<_>>>()?;
    candidate_bares.sort_unstable();
    candidate_bares.dedup();
    let roster_rows = sqlx::query(
        "SELECT contact_jid,subscription,groups FROM roster_items
          WHERE owner_id=$1 AND contact_jid=ANY($2::TEXT[])",
    )
    .bind(owner_id)
    .bind(&candidate_bares)
    .fetch_all(&mut **transaction)
    .await?;
    let mut roster = HashMap::with_capacity(roster_rows.len());
    for row in roster_rows {
        let groups =
            serde_json::from_value::<Vec<String>>(row.try_get::<serde_json::Value, _>("groups")?)?;
        roster.insert(
            row.get("contact_jid"),
            ReplayRosterPolicy {
                subscription: row.get("subscription"),
                groups,
            },
        );
    }
    Ok((blocked_patterns, privacy, roster))
}

fn replay_policy_denies(
    owner_bare_jid: &str,
    candidate: &str,
    kind: super::PrivacyStanzaKind,
    blocked_patterns: &[String],
    privacy: &ReplayPrivacyPolicy,
    roster: &HashMap<String, ReplayRosterPolicy>,
) -> Result<bool> {
    let owner = crate::jid::CanonicalJid::parse_bare(owner_bare_jid)?;
    let candidate = crate::jid::CanonicalJid::parse(candidate)?;
    let same_account = candidate.localpart().is_some() && candidate.bare() == owner.bare();
    if !same_account
        && blocked_patterns
            .iter()
            .any(|pattern| super::blocked_jid_matches(pattern, &candidate.to_string()))
    {
        return Ok(true);
    }
    let rules = match privacy {
        ReplayPrivacyPolicy::None => return Ok(false),
        ReplayPrivacyPolicy::Rules(rules) => rules,
    };
    let roster = roster.get(&candidate.bare());
    for rule in rules {
        let stanza_matches = if !(rule.message || rule.iq || rule.presence_in || rule.presence_out)
        {
            true
        } else {
            match kind {
                super::PrivacyStanzaKind::Message => rule.message,
                super::PrivacyStanzaKind::Iq => rule.iq,
                super::PrivacyStanzaKind::PresenceIn => rule.presence_in,
                super::PrivacyStanzaKind::PresenceOut => rule.presence_out,
            }
        };
        if !stanza_matches {
            continue;
        }
        let entity_matches = match (rule.match_type.as_deref(), rule.match_value.as_deref()) {
            (None, None) => true,
            (Some("jid"), Some(value)) => super::blocked_jid_matches(value, &candidate.to_string()),
            (Some("group"), Some(value)) => {
                roster.is_some_and(|entry| entry.groups.iter().any(|group| group == value))
            }
            (Some("subscription"), Some(value)) => {
                roster.map_or("none", |entry| entry.subscription.as_str()) == value
            }
            _ => false,
        };
        if entity_matches {
            return Ok(rule.deny);
        }
    }
    Ok(false)
}

/// A bounded union page of local and federated subscription requests whose
/// XEP-0191/XEP-0016 decision is derived from one repeatable-read snapshot.
/// Pending requests are intentionally not consumed: RFC 6121 shows the same
/// outstanding request once to each newly available resource.
pub async fn pending_presence_replay_page_filtered(
    pool: &PgPool,
    recipient_id: Uuid,
    owner_bare_jid: &str,
    local_domain: &str,
    active_privacy_list: Option<&str>,
    after: Option<&PendingPresenceCursor>,
) -> Result<PendingPresenceReplayPage> {
    let local_domain = crate::jid::prepare_domainpart(local_domain)?;
    let owner_bare_jid = crate::jid::canonicalize_bare(owner_bare_jid)?;
    let mut transaction = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *transaction)
        .await?;
    let rows = pending_presence_replay_page_in_transaction(
        &mut transaction,
        recipient_id,
        &local_domain,
        after,
    )
    .await?;
    let next_cursor = rows.last().map(|row| row.cursor.clone());
    let complete = rows.len() < REPLAY_PAGE_SIZE as usize;
    let candidates = rows
        .iter()
        .map(|row| row.requester.clone())
        .collect::<Vec<_>>();
    let (blocked_patterns, privacy, roster) = replay_policy_snapshot(
        &mut transaction,
        recipient_id,
        active_privacy_list,
        &candidates,
    )
    .await?;
    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        if !replay_policy_denies(
            &owner_bare_jid,
            &row.requester,
            super::PrivacyStanzaKind::PresenceIn,
            &blocked_patterns,
            &privacy,
            &roster,
        )? {
            items.push(row);
        }
    }
    transaction.commit().await?;
    Ok(PendingPresenceReplayPage {
        items,
        next_cursor,
        complete,
    })
}

#[cfg(test)]
pub async fn pending_presence_replay_page(
    pool: &PgPool,
    recipient_id: Uuid,
    local_domain: &str,
    after: Option<&PendingPresenceCursor>,
) -> Result<Vec<PendingPresenceReplay>> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *transaction)
        .await?;
    let page = pending_presence_replay_page_in_transaction(
        &mut transaction,
        recipient_id,
        local_domain,
        after,
    )
    .await?;
    transaction.commit().await?;
    Ok(page)
}

fn validate_replay_lease_seconds(lease_seconds: i64) -> Result<()> {
    anyhow::ensure!(
        (75..=300).contains(&lease_seconds),
        "offline replay owner lease must be between 75 and 300 seconds"
    );
    Ok(())
}

/// Acquire the logical XEP-0160 replay owner for one bound resource. Distinct
/// resources of the same account may replay concurrently, while the composite
/// `(recipient_id, resource, owner_token)` fence keeps each resource
/// single-flight. This is deliberately a bounded PostgreSQL row lease rather
/// than a session advisory lock: a slow socket never retains a pool connection,
/// and a crashed process becomes recoverable after `expires_at`.
pub async fn acquire_offline_replay_lease(
    pool: &PgPool,
    recipient_id: Uuid,
    owner_resource: &str,
    owner_token: Uuid,
    explicit_cutoff: Option<DateTime<Utc>>,
    lease_seconds: i64,
) -> Result<OfflineReplayLeaseAcquire> {
    validate_replay_lease_seconds(lease_seconds)?;
    anyhow::ensure!(
        (1..=1023).contains(&owner_resource.len()),
        "offline replay resource must be between 1 and 1023 bytes"
    );
    // A conflicting INSERT can disappear between statements if its owner
    // releases immediately. Retry that narrow race with a new transaction;
    // every returned wait duration is still measured by PostgreSQL.
    for race_attempt in 0..2 {
        let mut transaction = pool.begin().await?;
        let database_now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *transaction)
            .await?;
        let acquired = sqlx::query_scalar::<_, DateTime<Utc>>(
            "INSERT INTO offline_replay_leases(
                 recipient_id,resource,owner_token,acquired_at,renewed_at,expires_at
             ) VALUES(
                 $1,$2,$3,$4,$4,
                 $4+($5::DOUBLE PRECISION*INTERVAL '1 second')
             )
             ON CONFLICT(recipient_id,resource) DO UPDATE
                SET owner_token=EXCLUDED.owner_token,
                    acquired_at=EXCLUDED.acquired_at,
                    renewed_at=EXCLUDED.renewed_at,
                    expires_at=EXCLUDED.expires_at
              WHERE offline_replay_leases.expires_at<=$4
             RETURNING acquired_at",
        )
        .bind(recipient_id)
        .bind(owner_resource)
        .bind(owner_token)
        .bind(database_now)
        .bind(lease_seconds)
        .fetch_optional(&mut *transaction)
        .await?;
        if acquired.is_some() {
            transaction.commit().await?;
            return Ok(OfflineReplayLeaseAcquire::Acquired(OfflineReplayLease {
                recipient_id,
                resource: owner_resource.to_owned(),
                owner_token,
                // Explicit cutoffs are captured with PostgreSQL clock at an
                // earlier availability transition. Clamp defensively so an
                // accidental application-clock value cannot widen the epoch.
                replay_started_at: explicit_cutoff
                    .map_or(database_now, |cutoff| cutoff.min(database_now)),
            }));
        }

        let busy = sqlx::query_as::<_, (DateTime<Utc>, i64)>(
            "SELECT expires_at,
                    GREATEST(
                      0,
                      CEIL(EXTRACT(EPOCH FROM
                        (expires_at-clock_timestamp()))*1000)
                    )::BIGINT AS retry_after_ms
               FROM offline_replay_leases
              WHERE recipient_id=$1 AND resource=$2",
        )
        .bind(recipient_id)
        .bind(owner_resource)
        .fetch_optional(&mut *transaction)
        .await?;
        if let Some((expires_at, retry_after_ms)) = busy {
            transaction.commit().await?;
            return Ok(OfflineReplayLeaseAcquire::BusyUntil(
                OfflineReplayBusyUntil {
                    expires_at,
                    retry_after: Duration::from_millis(
                        u64::try_from(retry_after_ms).unwrap_or(u64::MAX),
                    ),
                },
            ));
        }
        transaction.rollback().await?;
        if race_attempt == 1 {
            anyhow::bail!("offline replay lease conflict disappeared twice during acquisition");
        }
    }
    unreachable!("bounded replay-lease acquisition loop always returns")
}

/// Release only the exact logical owner. A stale process can never delete a
/// lease acquired by its replacement.
pub async fn release_offline_replay_lease(
    pool: &PgPool,
    lease: &OfflineReplayLease,
) -> Result<bool> {
    Ok(sqlx::query(
        "DELETE FROM offline_replay_leases
          WHERE recipient_id=$1 AND resource=$2 AND owner_token=$3",
    )
    .bind(lease.recipient_id)
    .bind(&lease.resource)
    .bind(lease.owner_token)
    .execute(pool)
    .await?
    .rows_affected()
        == 1)
}

#[derive(Clone, Debug)]
struct ClaimedOfflineCandidate {
    message: ClaimedOfflineMessage,
    mam_backed: bool,
    created_at: DateTime<Utc>,
}

const SERIALIZATION_RETRY_ATTEMPTS: usize = 3;
const SERIALIZATION_RETRY_BASE_MILLIS: u64 = 8;
const SERIALIZATION_RETRY_MAX_MILLIS: u64 = 96;

#[cfg(test)]
struct ReplayClaimTestHook {
    snapshot_fixed: std::sync::Arc<tokio::sync::Barrier>,
    resume_after_competing_commit: std::sync::Arc<tokio::sync::Barrier>,
    fired: std::sync::atomic::AtomicBool,
    serialization_retries: std::sync::atomic::AtomicUsize,
}

#[cfg(test)]
impl ReplayClaimTestHook {
    async fn pause_once_after_snapshot(&self) {
        if !self.fired.swap(true, std::sync::atomic::Ordering::AcqRel) {
            self.snapshot_fixed.wait().await;
            self.resume_after_competing_commit.wait().await;
        }
    }
}

#[cfg(test)]
type ReplayClaimHookRef<'a> = Option<&'a ReplayClaimTestHook>;
#[cfg(not(test))]
type ReplayClaimHookRef<'a> = ();

fn postgres_serialization_failure(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<sqlx::Error>()
            .and_then(sqlx::Error::as_database_error)
            .and_then(|database| database.code())
            .as_deref()
            == Some("40001")
    })
}

fn serialization_retry_delay(attempt: usize) -> Duration {
    let shift = u32::try_from(attempt.min(4)).unwrap_or(4);
    let base = SERIALIZATION_RETRY_BASE_MILLIS
        .saturating_mul(1_u64 << shift)
        .min(SERIALIZATION_RETRY_MAX_MILLIS / 2);
    let jitter = rand::thread_rng().gen_range(0..=base);
    Duration::from_millis(
        base.saturating_add(jitter)
            .min(SERIALIZATION_RETRY_MAX_MILLIS),
    )
}

/// Claim one bounded page and apply XEP-0191/XEP-0016 policy in the same
/// repeatable-read write transaction.  Suppressed rows are consumed before
/// commit; no unfiltered DTO can escape an authorization snapshot.
#[allow(clippy::too_many_arguments)]
pub async fn claim_offline_replay_page(
    pool: &PgPool,
    lease: &OfflineReplayLease,
    ttl_days: i64,
    owner_bare_jid: &str,
    owner_full_jid: &str,
    active_privacy_list: Option<&str>,
    bind2_mam_catchup: bool,
    lease_seconds: i64,
) -> Result<OfflineReplayPageOutcome> {
    #[cfg(test)]
    let test_hook = None;
    #[cfg(not(test))]
    let test_hook = ();
    claim_offline_replay_page_retrying(
        pool,
        lease,
        ttl_days,
        owner_bare_jid,
        owner_full_jid,
        active_privacy_list,
        bind2_mam_catchup,
        lease_seconds,
        test_hook,
    )
    .await
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
async fn claim_offline_replay_page_with_test_hook(
    pool: &PgPool,
    lease: &OfflineReplayLease,
    ttl_days: i64,
    owner_bare_jid: &str,
    owner_full_jid: &str,
    active_privacy_list: Option<&str>,
    bind2_mam_catchup: bool,
    lease_seconds: i64,
    test_hook: &ReplayClaimTestHook,
) -> Result<OfflineReplayPageOutcome> {
    claim_offline_replay_page_retrying(
        pool,
        lease,
        ttl_days,
        owner_bare_jid,
        owner_full_jid,
        active_privacy_list,
        bind2_mam_catchup,
        lease_seconds,
        Some(test_hook),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn claim_offline_replay_page_retrying(
    pool: &PgPool,
    lease: &OfflineReplayLease,
    ttl_days: i64,
    owner_bare_jid: &str,
    owner_full_jid: &str,
    active_privacy_list: Option<&str>,
    bind2_mam_catchup: bool,
    lease_seconds: i64,
    test_hook: ReplayClaimHookRef<'_>,
) -> Result<OfflineReplayPageOutcome> {
    for attempt in 0..=SERIALIZATION_RETRY_ATTEMPTS {
        let result = claim_offline_replay_page_once(
            pool,
            lease,
            ttl_days,
            owner_bare_jid,
            owner_full_jid,
            active_privacy_list,
            bind2_mam_catchup,
            lease_seconds,
            test_hook,
        )
        .await;
        match result {
            Err(error)
                if attempt < SERIALIZATION_RETRY_ATTEMPTS
                    && postgres_serialization_failure(&error) =>
            {
                #[cfg(test)]
                if let Some(hook) = test_hook {
                    hook.serialization_retries
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                // `claim_offline_replay_page_once` has returned and dropped
                // its aborted Transaction before this await. The next pass
                // therefore obtains a fresh PostgreSQL snapshot.
                tokio::time::sleep(serialization_retry_delay(attempt)).await;
            }
            other => return other,
        }
    }
    unreachable!("bounded serialization retry loop always returns")
}

#[allow(clippy::too_many_arguments)]
async fn claim_offline_replay_page_once(
    pool: &PgPool,
    lease: &OfflineReplayLease,
    ttl_days: i64,
    owner_bare_jid: &str,
    owner_full_jid: &str,
    active_privacy_list: Option<&str>,
    bind2_mam_catchup: bool,
    lease_seconds: i64,
    _test_hook: ReplayClaimHookRef<'_>,
) -> Result<OfflineReplayPageOutcome> {
    validate_replay_lease_seconds(lease_seconds)?;
    let owner_bare_jid = crate::jid::canonicalize_bare(owner_bare_jid)?;
    let raw_owner_full_jid = owner_full_jid;
    let owner_full_jid = crate::jid::canonical_session_key(raw_owner_full_jid)?;
    anyhow::ensure!(
        owner_full_jid == raw_owner_full_jid,
        "offline replay resource must already be canonical"
    );
    let owner_full = crate::jid::CanonicalJid::parse(&owner_full_jid)?;
    anyhow::ensure!(
        owner_full.bare() == owner_bare_jid,
        "offline replay resource does not belong to replay owner"
    );
    let owner_resource = owner_full
        .resourcepart()
        .expect("canonical_session_key requires a resourcepart")
        .to_owned();
    anyhow::ensure!(
        owner_resource == lease.resource,
        "lease resource does not match owner_full_jid resource"
    );
    let claim_token = Uuid::new_v4();
    let mut transaction = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut *transaction)
        .await?;
    let lease_renewed = sqlx::query(
        "UPDATE offline_replay_leases
            SET renewed_at=clock_timestamp(),
                expires_at=clock_timestamp()+($4::DOUBLE PRECISION*INTERVAL '1 second')
          WHERE recipient_id=$1 AND resource=$2 AND owner_token=$3
            AND expires_at>clock_timestamp()",
    )
    .bind(lease.recipient_id)
    .bind(&lease.resource)
    .bind(lease.owner_token)
    .bind(lease_seconds)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    if lease_renewed != 1 {
        transaction.rollback().await?;
        return Ok(OfflineReplayPageOutcome::LeaseLost);
    }

    #[cfg(test)]
    if let Some(hook) = _test_hook {
        hook.pause_once_after_snapshot().await;
    }

    // Retention runs before an expired BOSH response is handed off. Thus an
    // old row remains protected by any response fence until this transaction
    // atomically takes responsibility for retrying it.
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
              ORDER BY message.created_at,message.id
              FOR UPDATE OF message SKIP LOCKED LIMIT 256
         )
         DELETE FROM offline_messages message USING expired
          WHERE message.id=expired.id",
    )
    .bind(lease.recipient_id)
    .bind(ttl_days)
    .execute(&mut *transaction)
    .await?;

    // Expiry is a lease hand-off, not merely a timestamp predicate.  Every
    // binder uses the offline-row -> response-fence lock order.
    sqlx::query(
        "WITH expired AS (
             SELECT message.id
               FROM offline_messages message
               JOIN bosh_delivery_fences fence ON fence.message_id=message.id
              WHERE message.recipient_id=$1
                AND fence.expires_at<=clock_timestamp()
              ORDER BY fence.expires_at,message.id
              FOR UPDATE OF message SKIP LOCKED LIMIT 256
         )
         DELETE FROM bosh_delivery_fences fence USING expired
          WHERE fence.message_id=expired.id
            AND fence.expires_at<=clock_timestamp()",
    )
    .bind(lease.recipient_id)
    .execute(&mut *transaction)
    .await?;

    let rows = sqlx::query(
        "WITH candidates AS (
             SELECT id FROM offline_messages
              WHERE recipient_id=$1
                AND created_at <= $5
                AND (target_resource IS NULL OR target_resource=$6)
                AND NOT EXISTS (
                    SELECT 1 FROM sm_resume_stanzas sm
                     WHERE sm.delivery_message_id=offline_messages.id
                )
                AND NOT EXISTS (
                    SELECT 1 FROM bosh_delivery_fences bosh
                     WHERE bosh.message_id=offline_messages.id
                )
                AND (delivery_claim_id IS NULL
                     OR delivery_claim_expires_at<=clock_timestamp())
              ORDER BY created_at,id FOR UPDATE SKIP LOCKED LIMIT $3
         )
         UPDATE offline_messages AS message
            SET delivery_claim_id=$2,
                delivery_claim_expires_at=clock_timestamp()+($4*INTERVAL '1 second')
           FROM candidates WHERE message.id=candidates.id
         RETURNING message.id,message.sender_jid,message.stanza,message.mam_backed,
                   message.created_at",
    )
    .bind(lease.recipient_id)
    .bind(claim_token)
    .bind(REPLAY_PAGE_SIZE)
    .bind(CLAIM_LEASE_SECONDS)
    .bind(lease.replay_started_at)
    .bind(owner_resource)
    .fetch_all(&mut *transaction)
    .await?;
    if rows.is_empty() {
        transaction.commit().await?;
        return Ok(OfflineReplayPageOutcome::Empty);
    }
    let mut candidates = rows
        .into_iter()
        .map(|row| {
            Ok(ClaimedOfflineCandidate {
                message: ClaimedOfflineMessage {
                    id: row.try_get("id")?,
                    sender_jid: row.try_get("sender_jid")?,
                    stanza: row.try_get("stanza")?,
                },
                mam_backed: row.try_get("mam_backed")?,
                created_at: row.try_get("created_at")?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    candidates.sort_by_key(|row| (row.created_at, row.message.id));
    let senders = candidates
        .iter()
        .map(|row| row.message.sender_jid.clone())
        .collect::<Vec<_>>();
    let (blocked_patterns, privacy, roster) = replay_policy_snapshot(
        &mut transaction,
        lease.recipient_id,
        active_privacy_list,
        &senders,
    )
    .await?;
    let mut suppressed = Vec::new();
    let mut messages = Vec::with_capacity(candidates.len());
    for row in candidates {
        let denied = replay_policy_denies(
            &owner_bare_jid,
            &row.message.sender_jid,
            super::PrivacyStanzaKind::Message,
            &blocked_patterns,
            &privacy,
            &roster,
        )?;
        if (bind2_mam_catchup && row.mam_backed) || denied {
            suppressed.push(row.message.id);
        } else {
            messages.push(row.message);
        }
    }
    if !suppressed.is_empty() {
        let removed = sqlx::query(
            "DELETE FROM offline_messages
              WHERE recipient_id=$1 AND delivery_claim_id=$2 AND id=ANY($3::UUID[])",
        )
        .bind(lease.recipient_id)
        .bind(claim_token)
        .bind(&suppressed)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        anyhow::ensure!(
            removed == suppressed.len() as u64,
            "offline suppression lost its exact page claim"
        );
    }
    transaction.commit().await?;
    if messages.is_empty() {
        // The page contained only policy/MAM-suppressed projections.  Report
        // an empty claimed page so the caller continues to the next page
        // rather than treating this as the high-water end.
        return Ok(OfflineReplayPageOutcome::Claimed(ClaimedOfflinePage {
            claim_token,
            messages,
        }));
    }
    Ok(OfflineReplayPageOutcome::Claimed(ClaimedOfflinePage {
        claim_token,
        messages,
    }))
}

/// Atomically renew both the resource-scoped coordinator and the exact unsent
/// page suffix immediately before another stanza can enter the transport queue.
/// A stale owner gets `false` and must not send.
pub async fn renew_offline_replay_before_send(
    pool: &PgPool,
    lease: &OfflineReplayLease,
    page_claim_token: Uuid,
    pending_ids: &[Uuid],
    lease_seconds: i64,
) -> Result<bool> {
    validate_replay_lease_seconds(lease_seconds)?;
    anyhow::ensure!(
        !pending_ids.is_empty(),
        "offline replay renewal suffix is empty"
    );
    let mut unique = pending_ids.to_vec();
    unique.sort_unstable();
    unique.dedup();
    anyhow::ensure!(
        unique.len() == pending_ids.len(),
        "offline replay renewal suffix contains duplicates"
    );
    let mut transaction = pool.begin().await?;
    let owner = sqlx::query(
        "UPDATE offline_replay_leases
            SET renewed_at=clock_timestamp(),
                expires_at=clock_timestamp()+($4::DOUBLE PRECISION*INTERVAL '1 second')
          WHERE recipient_id=$1 AND resource=$2 AND owner_token=$3
            AND expires_at>clock_timestamp()",
    )
    .bind(lease.recipient_id)
    .bind(&lease.resource)
    .bind(lease.owner_token)
    .bind(lease_seconds)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    if owner != 1 {
        transaction.rollback().await?;
        return Ok(false);
    }
    let rows = sqlx::query(
        "UPDATE offline_messages
            SET delivery_claim_expires_at=clock_timestamp()+($4*INTERVAL '1 second')
          WHERE recipient_id=$1 AND delivery_claim_id=$2 AND id=ANY($3::UUID[])",
    )
    .bind(lease.recipient_id)
    .bind(page_claim_token)
    .bind(&unique)
    .bind(CLAIM_LEASE_SECONDS)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    if rows != unique.len() as u64 {
        transaction.rollback().await?;
        return Ok(false);
    }
    transaction.commit().await?;
    Ok(true)
}

/// Clear only claims which have not crossed queue acceptance.  Earlier rows
/// from the same page retain their exact transport fence and are never made
/// concurrently replayable by suffix cleanup.
pub async fn release_untransferred_offline_claims(
    pool: &PgPool,
    recipient_id: Uuid,
    page_claim_token: Uuid,
    message_ids: &[Uuid],
) -> Result<u64> {
    if message_ids.is_empty() {
        return Ok(0);
    }
    let mut unique = message_ids.to_vec();
    unique.sort_unstable();
    unique.dedup();
    anyhow::ensure!(
        unique.len() == message_ids.len(),
        "offline replay release suffix contains duplicates"
    );
    let released = sqlx::query(
        "UPDATE offline_messages
            SET delivery_claim_id=NULL,delivery_claim_expires_at=NULL
          WHERE recipient_id=$1 AND delivery_claim_id=$2 AND id=ANY($3::UUID[])",
    )
    .bind(recipient_id)
    .bind(page_claim_token)
    .bind(&unique)
    .execute(pool)
    .await?
    .rows_affected();
    anyhow::ensure!(
        released == unique.len() as u64,
        "offline replay unsent suffix lost its exact page claim"
    );
    Ok(released)
}

/// Test-only compatibility drain used by repository regression fixtures. The
/// production protocol owns all network awaits through ReplayService.
#[cfg(test)]
pub async fn deliver_offline_leased(
    pool: &PgPool,
    recipient_id: Uuid,
    ttl_days: i64,
    outbound: &crate::outbound::OutboundSender,
    bind2_mam_catchup: bool,
    active_privacy_list: Option<&str>,
) -> Result<usize> {
    deliver_offline_leased_before(
        pool,
        recipient_id,
        ttl_days,
        outbound,
        bind2_mam_catchup,
        active_privacy_list,
        sqlx::query_scalar::<_, DateTime<Utc>>("SELECT clock_timestamp()")
            .fetch_one(pool)
            .await?,
    )
    .await
}

/// Replay only rows that existed at the semantic availability transition.
/// Callers which perform other awaited work before starting the replay pass a
/// database-clock cutoff captured at that transition.
#[cfg(test)]
pub async fn deliver_offline_leased_before(
    pool: &PgPool,
    recipient_id: Uuid,
    ttl_days: i64,
    outbound: &crate::outbound::OutboundSender,
    bind2_mam_catchup: bool,
    active_privacy_list: Option<&str>,
    replay_started_at: DateTime<Utc>,
) -> Result<usize> {
    let owner_token = Uuid::new_v4();
    let lease = match acquire_offline_replay_lease(
        pool,
        recipient_id,
        "test-replay",
        owner_token,
        Some(replay_started_at),
        REPLAY_OWNER_LEASE_SECONDS,
    )
    .await?
    {
        OfflineReplayLeaseAcquire::Acquired(lease) => lease,
        OfflineReplayLeaseAcquire::BusyUntil(_) => return Ok(0),
    };
    let username: String = sqlx::query_scalar("SELECT username FROM users WHERE id=$1")
        .bind(recipient_id)
        .fetch_one(pool)
        .await?;
    let result = deliver_offline_pages_for_test(
        pool,
        &lease,
        ttl_days,
        outbound,
        bind2_mam_catchup,
        active_privacy_list,
        &format!("{username}@localhost"),
    )
    .await;
    let release = release_offline_replay_lease(pool, &lease).await;
    anyhow::ensure!(
        release?,
        "offline replay owner lease was lost before release"
    );
    result
}

#[cfg(test)]
async fn deliver_offline_pages_for_test(
    pool: &PgPool,
    lease: &OfflineReplayLease,
    ttl_days: i64,
    outbound: &crate::outbound::OutboundSender,
    bind2_mam_catchup: bool,
    active_privacy_list: Option<&str>,
    owner_bare_jid: &str,
) -> Result<usize> {
    let owner_full_jid = format!("{owner_bare_jid}/{}", lease.resource);
    let mut delivered = 0usize;
    loop {
        let page = match claim_offline_replay_page(
            pool,
            lease,
            ttl_days,
            owner_bare_jid,
            &owner_full_jid,
            active_privacy_list,
            bind2_mam_catchup,
            REPLAY_OWNER_LEASE_SECONDS,
        )
        .await?
        {
            OfflineReplayPageOutcome::Claimed(page) => page,
            OfflineReplayPageOutcome::Empty => break,
            OfflineReplayPageOutcome::LeaseLost => {
                anyhow::bail!("offline replay owner lease was lost")
            }
        };
        if page.messages.is_empty() {
            continue;
        }
        for (index, row) in page.messages.iter().enumerate() {
            let suffix = page.messages[index..]
                .iter()
                .map(|row| row.id)
                .collect::<Vec<_>>();
            if !renew_offline_replay_before_send(
                pool,
                lease,
                page.claim_token,
                &suffix,
                REPLAY_OWNER_LEASE_SECONDS,
            )
            .await?
            {
                anyhow::bail!("offline replay ownership was lost before transport send");
            }
            match tokio::time::timeout(
                std::time::Duration::from_secs(5),
                outbound.send_durable(
                    row.stanza.clone(),
                    crate::outbound::DurableDelivery {
                        recipient_id: lease.recipient_id,
                        message_id: row.id,
                        claim_id: Some(page.claim_token),
                    },
                ),
            )
            .await
            {
                // Queue acceptance is not delivery. The TCP/WebSocket
                // transport owns the fenced delete after a recoverable write.
                Ok(Ok(())) => delivered += 1,
                Ok(Err(_)) => {
                    release_untransferred_offline_claims(
                        pool,
                        lease.recipient_id,
                        page.claim_token,
                        &suffix,
                    )
                    .await?;
                    return Ok(delivered);
                }
                Err(_) => {
                    outbound.disconnect_backpressured_transport();
                    release_untransferred_offline_claims(
                        pool,
                        lease.recipient_id,
                        page.claim_token,
                        &suffix,
                    )
                    .await?;
                    return Ok(delivered);
                }
            }
        }
    }
    Ok(delivered)
}

/// Complete a live (unclaimed) or replay (fenced) C2S delivery only after the
/// transport has crossed its write/recovery boundary. A missing live row is
/// an idempotent acknowledgement; a missing claimed row means the replay
/// worker lost its fence and must be reported.
pub async fn acknowledge_durable_delivery(
    pool: &PgPool,
    delivery: crate::outbound::DurableDelivery,
) -> Result<()> {
    acknowledge_durable_deliveries(pool, std::slice::from_ref(&delivery)).await
}

/// Atomically acknowledge a complete transport boundary. Every claimed/live
/// ownership fence is validated before any row is deleted, so failure on a
/// later stanza cannot partially consume the prefix while the caller retains
/// its old XEP-0198 `h` and in-memory queue.
pub async fn acknowledge_durable_deliveries(
    pool: &PgPool,
    deliveries: &[crate::outbound::DurableDelivery],
) -> Result<()> {
    if deliveries.is_empty() {
        return Ok(());
    }
    let mut deliveries = deliveries.to_vec();
    deliveries.sort_unstable_by_key(|delivery| (delivery.recipient_id, delivery.message_id));
    anyhow::ensure!(
        deliveries
            .windows(2)
            .all(|window| window[0].message_id != window[1].message_id),
        "duplicate durable delivery in one acknowledgement batch"
    );
    let mut transaction = pool.begin().await?;
    let mut present = Vec::with_capacity(deliveries.len());
    for delivery in &deliveries {
        let row = sqlx::query(
            "SELECT delivery_claim_id FROM offline_messages
              WHERE recipient_id=$1 AND id=$2 FOR UPDATE",
        )
        .bind(delivery.recipient_id)
        .bind(delivery.message_id)
        .fetch_optional(&mut *transaction)
        .await?;
        match (row, delivery.claim_id) {
            (None, None) => present.push(false),
            (None, Some(_)) => {
                anyhow::bail!("offline delivery claim was lost before acknowledgement")
            }
            (Some(row), Some(expected_claim)) => {
                anyhow::ensure!(
                    row.try_get::<Option<Uuid>, _>("delivery_claim_id")? == Some(expected_claim),
                    "offline delivery claim was lost before acknowledgement"
                );
                present.push(true);
            }
            (Some(row), None) => {
                anyhow::ensure!(
                    row.try_get::<Option<Uuid>, _>("delivery_claim_id")?
                        .is_none(),
                    "live transport acknowledgement does not own the offline replay claim"
                );
                let transport_owned: bool = sqlx::query_scalar(
                    "SELECT EXISTS(
                         SELECT 1 FROM sm_resume_stanzas WHERE delivery_message_id=$1
                     ) OR EXISTS(
                         SELECT 1 FROM bosh_delivery_fences WHERE message_id=$1
                     )",
                )
                .bind(delivery.message_id)
                .fetch_one(&mut *transaction)
                .await?;
                anyhow::ensure!(
                    !transport_owned,
                    "live transport acknowledgement does not own the durable delivery"
                );
                present.push(true);
            }
        }
    }
    for (delivery, present) in deliveries.iter().zip(present) {
        if !present {
            continue;
        }
        let removed = sqlx::query(
            "DELETE FROM offline_messages
              WHERE recipient_id=$1 AND id=$2 AND delivery_claim_id IS NOT DISTINCT FROM $3",
        )
        .bind(delivery.recipient_id)
        .bind(delivery.message_id)
        .bind(delivery.claim_id)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        anyhow::ensure!(
            removed == 1,
            "durable delivery disappeared during acknowledgement"
        );
    }
    transaction.commit().await?;
    tracing::debug!(
        deliveries = deliveries.len(),
        "atomically acknowledged durable C2S delivery batch"
    );
    Ok(())
}

/// Fence one non-SM TCP/WebSocket write immediately before bytes are exposed
/// to the peer.  A live delivery enters routing without a replay claim, while
/// an offline replay can wait in the bounded transport queue long enough for
/// its original claim lease to approach expiry.  Taking or renewing the exact
/// claim here closes both windows: retention and another replay worker must
/// wait until the bounded socket write either acknowledges this claim or its
/// lease expires after a crash/timeout.
pub async fn fence_durable_socket_write(
    pool: &PgPool,
    delivery: crate::outbound::DurableDelivery,
) -> Result<crate::outbound::DurableDelivery> {
    let claim_id = delivery.claim_id.unwrap_or_else(Uuid::new_v4);
    let mut transaction = pool.begin().await?;
    let row = sqlx::query(
        "SELECT delivery_claim_id FROM offline_messages
          WHERE recipient_id=$1 AND id=$2 FOR UPDATE",
    )
    .bind(delivery.recipient_id)
    .bind(delivery.message_id)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(row) = row else {
        anyhow::bail!("durable delivery disappeared before socket write fencing");
    };
    let stored_claim: Option<Uuid> = row.try_get("delivery_claim_id")?;
    anyhow::ensure!(
        stored_claim == delivery.claim_id,
        "durable delivery claim changed before socket write fencing"
    );
    let transport_owned: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM sm_resume_stanzas WHERE delivery_message_id=$1
         ) OR EXISTS(
             SELECT 1 FROM bosh_delivery_fences WHERE message_id=$1
         )",
    )
    .bind(delivery.message_id)
    .fetch_one(&mut *transaction)
    .await?;
    anyhow::ensure!(
        !transport_owned,
        "durable delivery is already owned by another recoverable transport"
    );
    let updated = sqlx::query(
        "UPDATE offline_messages
            SET delivery_claim_id=$3,
                delivery_claim_expires_at=clock_timestamp()+($4*INTERVAL '1 second')
          WHERE recipient_id=$1 AND id=$2",
    )
    .bind(delivery.recipient_id)
    .bind(delivery.message_id)
    .bind(claim_id)
    .bind(CLAIM_LEASE_SECONDS)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    anyhow::ensure!(
        updated == 1,
        "durable delivery disappeared during socket write fencing"
    );
    transaction.commit().await?;
    Ok(crate::outbound::DurableDelivery {
        claim_id: Some(claim_id),
        ..delivery
    })
}

/// Bind all durable sources carried by one BOSH response in one transaction.
///
/// C2S offline rows are transferred directly at response construction, while
/// MIX sources were transferred to a pending BOSH fence before entering the
/// actor FIFO. Binding both source families atomically means an HTTP response
/// is either recoverably owned in full or not exposed at all.
pub async fn bind_bosh_transport_response(
    pool: &PgPool,
    session_id: Uuid,
    response_rid: u64,
    sources: &[crate::outbound::TransportOwnershipSource],
    ttl_seconds: u64,
) -> Result<crate::outbound::BoshResponseOwnership> {
    let response_rid = i64::try_from(response_rid).context("BOSH RID exceeds bigint")?;
    let ttl_seconds = i64::try_from(ttl_seconds.clamp(1, BOSH_FENCE_MAX_AGE_SECONDS as u64))
        .context("BOSH delivery-fence TTL is too large")?;
    let mut c2s = BTreeMap::new();
    let mut mix = BTreeMap::new();
    for source in sources {
        match source {
            crate::outbound::TransportOwnershipSource::C2s(delivery) => {
                anyhow::ensure!(
                    c2s.insert(delivery.message_id, *delivery).is_none(),
                    "duplicate C2S durable delivery in one BOSH response"
                );
            }
            crate::outbound::TransportOwnershipSource::Mix(delivery) => {
                anyhow::ensure!(
                    mix.insert(delivery.delivery_id, *delivery).is_none(),
                    "duplicate MIX durable delivery in one BOSH response"
                );
            }
        }
    }
    anyhow::ensure!(
        c2s.len().saturating_add(mix.len()) <= 512,
        "BOSH response fence limit exceeded"
    );

    let mut transaction = pool.begin().await?;
    let existing_count: i64 = sqlx::query_scalar(
        "SELECT (
             SELECT COUNT(*) FROM bosh_delivery_fences
              WHERE session_id=$1
                AND first_owned_at>clock_timestamp()-INTERVAL '5 minutes'
         ) + (
             SELECT COUNT(*) FROM mix_bosh_delivery_fences
              WHERE session_id=$1
                AND first_owned_at>clock_timestamp()-INTERVAL '5 minutes'
         )",
    )
    .bind(session_id)
    .fetch_one(&mut *transaction)
    .await?;
    anyhow::ensure!(
        existing_count.saturating_add(i64::try_from(c2s.len() + mix.len()).unwrap_or(i64::MAX))
            <= 512,
        "BOSH unacknowledged fence limit exceeded"
    );
    let response_rids = sqlx::query_scalar::<_, i64>(
        "SELECT response_rid FROM bosh_delivery_fences
          WHERE session_id=$1
         UNION
         SELECT response_rid FROM mix_bosh_delivery_fences
          WHERE session_id=$1 AND response_rid IS NOT NULL",
    )
    .bind(session_id)
    .fetch_all(&mut *transaction)
    .await?
    .into_iter()
    .collect::<BTreeSet<_>>();
    anyhow::ensure!(
        response_rids.len() < 2 || response_rids.contains(&response_rid),
        "BOSH unacknowledged response limit exceeded"
    );

    for delivery in c2s.values() {
        let offline = sqlx::query(
            "SELECT delivery_claim_id FROM offline_messages
              WHERE recipient_id=$1 AND id=$2 FOR UPDATE",
        )
        .bind(delivery.recipient_id)
        .bind(delivery.message_id)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(offline) = offline else {
            anyhow::bail!("durable delivery disappeared before BOSH response binding");
        };
        let sm_owned: bool = sqlx::query_scalar(
            "SELECT EXISTS(
                 SELECT 1 FROM sm_resume_stanzas WHERE delivery_message_id=$1
             )",
        )
        .bind(delivery.message_id)
        .fetch_one(&mut *transaction)
        .await?;
        anyhow::ensure!(
            !sm_owned,
            "durable delivery is already owned by an XEP-0198 sequence"
        );
        let existing = sqlx::query(
            "SELECT session_id,response_rid,expires_at>clock_timestamp() AS active
               FROM bosh_delivery_fences WHERE message_id=$1 FOR UPDATE",
        )
        .bind(delivery.message_id)
        .fetch_optional(&mut *transaction)
        .await?;
        if let Some(existing) = existing {
            let owner: Uuid = existing.try_get("session_id")?;
            let rid: i64 = existing.try_get("response_rid")?;
            if owner == session_id && rid == response_rid {
                anyhow::ensure!(
                    offline
                        .try_get::<Option<Uuid>, _>("delivery_claim_id")?
                        .is_none(),
                    "BOSH response fence lost ownership to another replay claim"
                );
                let renewed = sqlx::query(
                    "UPDATE bosh_delivery_fences
                        SET expires_at=LEAST(clock_timestamp()+($2*INTERVAL '1 second'),
                                             first_owned_at+INTERVAL '5 minutes')
                      WHERE message_id=$1
                        AND first_owned_at>clock_timestamp()-INTERVAL '5 minutes'",
                )
                .bind(delivery.message_id)
                .bind(ttl_seconds)
                .execute(&mut *transaction)
                .await?
                .rows_affected();
                anyhow::ensure!(
                    renewed == 1,
                    "BOSH response exceeded maximum acknowledgement age"
                );
                continue;
            }
            anyhow::ensure!(
                !existing.try_get::<bool, _>("active")?,
                "durable delivery is owned by another active BOSH response"
            );
            sqlx::query("DELETE FROM bosh_delivery_fences WHERE message_id=$1")
                .bind(delivery.message_id)
                .execute(&mut *transaction)
                .await?;
        }
        anyhow::ensure!(
            offline.try_get::<Option<Uuid>, _>("delivery_claim_id")? == delivery.claim_id,
            "durable delivery claim changed before BOSH response binding"
        );
        sqlx::query(
            "UPDATE offline_messages
                SET delivery_claim_id=NULL,delivery_claim_expires_at=NULL
              WHERE recipient_id=$1 AND id=$2",
        )
        .bind(delivery.recipient_id)
        .bind(delivery.message_id)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO bosh_delivery_fences(
                message_id,recipient_id,session_id,response_rid,expires_at,first_owned_at
             ) VALUES($1,$2,$3,$4,
                LEAST(clock_timestamp()+($5*INTERVAL '1 second'),clock_timestamp()+INTERVAL '5 minutes'),
                clock_timestamp())",
        )
        .bind(delivery.message_id)
        .bind(delivery.recipient_id)
        .bind(session_id)
        .bind(response_rid)
        .bind(ttl_seconds)
        .execute(&mut *transaction)
        .await?;
    }

    for source in mix.values() {
        // The recipient row is the first lock in every MIX transfer path;
        // lock it before the BOSH fence to preserve that global order.
        let recipient = sqlx::query(
            "SELECT lease_token FROM mix_delivery_recipients
              WHERE delivery_id=$1 FOR UPDATE",
        )
        .bind(source.delivery_id)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(recipient) = recipient else {
            anyhow::bail!("MIX delivery disappeared before BOSH response binding");
        };
        anyhow::ensure!(
            recipient.try_get::<Option<Uuid>, _>("lease_token")? == Some(source.lease_token),
            "MIX delivery lease changed before BOSH response binding"
        );
        let fence = sqlx::query(
            "SELECT session_id,response_rid,lease_token,
                    expires_at>clock_timestamp() AS active
               FROM mix_bosh_delivery_fences
              WHERE delivery_id=$1 FOR UPDATE",
        )
        .bind(source.delivery_id)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(fence) = fence else {
            anyhow::bail!("MIX BOSH response has no pending ownership fence");
        };
        anyhow::ensure!(
            fence.try_get::<Uuid, _>("session_id")? == session_id
                && fence.try_get::<Uuid, _>("lease_token")? == source.lease_token,
            "MIX BOSH response fence is owned by another transport"
        );
        anyhow::ensure!(
            fence.try_get::<bool, _>("active")?,
            "MIX BOSH response fence expired before response binding"
        );
        let stored_rid: Option<i64> = fence.try_get("response_rid")?;
        anyhow::ensure!(
            stored_rid.is_none() || stored_rid == Some(response_rid),
            "MIX BOSH source was bound to a different response"
        );
        let bound = sqlx::query(
            "UPDATE mix_bosh_delivery_fences
                SET response_rid=$3,
                    bound_at=COALESCE(bound_at,clock_timestamp()),
                    expires_at=LEAST(clock_timestamp()+($4*INTERVAL '1 second'),
                                     first_owned_at+INTERVAL '5 minutes')
              WHERE delivery_id=$1 AND lease_token=$2",
        )
        .bind(source.delivery_id)
        .bind(source.lease_token)
        .bind(response_rid)
        .bind(ttl_seconds)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        anyhow::ensure!(bound == 1, "MIX BOSH response fence lost ownership");
    }
    transaction.commit().await?;
    Ok(crate::outbound::BoshResponseOwnership {
        c2s_message_ids: c2s.into_keys().collect(),
        mix_delivery_ids: mix.into_keys().collect(),
    })
}

/// Transfer durable C2S rows to the exact BOSH response which will carry
/// them. This commits before the HTTP response bytes are exposed to the peer.
///
/// The production BOSH coordinator uses the typed transport variant below so
/// one response can own both C2S and MIX rows.  This C2S-only surface remains
/// a test fixture for independently exercising legacy response semantics.
#[cfg(test)]
pub async fn bind_bosh_delivery_response(
    pool: &PgPool,
    session_id: Uuid,
    response_rid: u64,
    deliveries: &[crate::outbound::DurableDelivery],
    ttl_seconds: u64,
) -> Result<()> {
    let response_rid = i64::try_from(response_rid).context("BOSH RID exceeds bigint")?;
    let ttl_seconds = i64::try_from(ttl_seconds.clamp(1, 86_400))
        .context("BOSH delivery-fence TTL is too large")?;
    let mut unique = std::collections::BTreeMap::new();
    for delivery in deliveries {
        anyhow::ensure!(
            unique.insert(delivery.message_id, *delivery).is_none(),
            "duplicate durable delivery in one BOSH response"
        );
    }
    anyhow::ensure!(unique.len() <= 512, "BOSH response fence limit exceeded");
    let mut transaction = pool.begin().await?;
    let existing_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM bosh_delivery_fences
          WHERE session_id=$1 AND first_owned_at>clock_timestamp()-INTERVAL '5 minutes'",
    )
    .bind(session_id)
    .fetch_one(&mut *transaction)
    .await?;
    anyhow::ensure!(
        existing_count.saturating_add(i64::try_from(unique.len()).unwrap_or(i64::MAX)) <= 512,
        "BOSH unacknowledged fence limit exceeded"
    );
    let response_rows = sqlx::query(
        "SELECT COUNT(DISTINCT response_rid) AS response_count,
                BOOL_OR(response_rid=$2) AS already_bound
           FROM bosh_delivery_fences WHERE session_id=$1",
    )
    .bind(session_id)
    .bind(response_rid)
    .fetch_one(&mut *transaction)
    .await?;
    let response_count: i64 = response_rows.try_get("response_count")?;
    let already_bound: Option<bool> = response_rows.try_get("already_bound")?;
    anyhow::ensure!(
        response_count < 2 || already_bound == Some(true),
        "BOSH unacknowledged response limit exceeded"
    );
    for delivery in unique.values() {
        // All binders acquire the offline row first and in UUID order, so two
        // concurrent resources cannot form a fence lock cycle.
        let offline = sqlx::query(
            "SELECT delivery_claim_id FROM offline_messages
              WHERE recipient_id=$1 AND id=$2 FOR UPDATE",
        )
        .bind(delivery.recipient_id)
        .bind(delivery.message_id)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(offline) = offline else {
            anyhow::bail!("durable delivery disappeared before BOSH response binding");
        };
        let sm_owned: bool = sqlx::query_scalar(
            "SELECT EXISTS(
                 SELECT 1 FROM sm_resume_stanzas WHERE delivery_message_id=$1
             )",
        )
        .bind(delivery.message_id)
        .fetch_one(&mut *transaction)
        .await?;
        anyhow::ensure!(
            !sm_owned,
            "durable delivery is already owned by an XEP-0198 sequence"
        );
        let existing = sqlx::query(
            "SELECT session_id,response_rid,expires_at>clock_timestamp() AS active
               FROM bosh_delivery_fences WHERE message_id=$1 FOR UPDATE",
        )
        .bind(delivery.message_id)
        .fetch_optional(&mut *transaction)
        .await?;
        if let Some(existing) = existing {
            let owner: Uuid = existing.try_get("session_id")?;
            let rid: i64 = existing.try_get("response_rid")?;
            if owner == session_id && rid == response_rid {
                anyhow::ensure!(
                    offline
                        .try_get::<Option<Uuid>, _>("delivery_claim_id")?
                        .is_none(),
                    "BOSH response fence lost ownership to another replay claim"
                );
                let renewed = sqlx::query(
                    "UPDATE bosh_delivery_fences
                        SET expires_at=LEAST(clock_timestamp()+($2*INTERVAL '1 second'),
                                             first_owned_at+INTERVAL '5 minutes')
                      WHERE message_id=$1 AND first_owned_at>clock_timestamp()-INTERVAL '5 minutes'",
                )
                .bind(delivery.message_id)
                .bind(ttl_seconds)
                .execute(&mut *transaction)
                .await?
                .rows_affected();
                anyhow::ensure!(
                    renewed == 1,
                    "BOSH response exceeded maximum acknowledgement age"
                );
                continue;
            }
            anyhow::ensure!(
                !existing.try_get::<bool, _>("active")?,
                "durable delivery is owned by another active BOSH response"
            );
            sqlx::query("DELETE FROM bosh_delivery_fences WHERE message_id=$1")
                .bind(delivery.message_id)
                .execute(&mut *transaction)
                .await?;
        }
        let stored_claim: Option<Uuid> = offline.try_get("delivery_claim_id")?;
        anyhow::ensure!(
            stored_claim == delivery.claim_id,
            "durable delivery claim changed before BOSH response binding"
        );
        sqlx::query(
            "UPDATE offline_messages
                SET delivery_claim_id=NULL,delivery_claim_expires_at=NULL
              WHERE recipient_id=$1 AND id=$2",
        )
        .bind(delivery.recipient_id)
        .bind(delivery.message_id)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO bosh_delivery_fences(
                message_id,recipient_id,session_id,response_rid,expires_at,first_owned_at
             ) VALUES($1,$2,$3,$4,
                LEAST(clock_timestamp()+($5*INTERVAL '1 second'),clock_timestamp()+INTERVAL '5 minutes'),
                clock_timestamp())",
        )
        .bind(delivery.message_id)
        .bind(delivery.recipient_id)
        .bind(session_id)
        .bind(response_rid)
        .bind(ttl_seconds)
        .execute(&mut *transaction)
        .await?;
    }
    transaction.commit().await?;
    Ok(())
}

/// C2S-only test fixture; runtime renewal uses `renew_bosh_transport_fences`.
#[cfg(test)]
pub async fn renew_bosh_delivery_fences(
    pool: &PgPool,
    session_id: Uuid,
    expected_response: Option<(u64, &[Uuid])>,
    ttl_seconds: u64,
) -> Result<()> {
    let ttl_seconds = i64::try_from(ttl_seconds.clamp(1, 86_400))
        .context("BOSH delivery-fence TTL is too large")?;
    let mut transaction = pool.begin().await?;
    let leases = sqlx::query(
        "SELECT message_id,response_rid,
                expires_at>clock_timestamp() AND first_owned_at>clock_timestamp()-INTERVAL '5 minutes' AS active
           FROM bosh_delivery_fences
          WHERE session_id=$1 ORDER BY message_id FOR UPDATE",
    )
    .bind(session_id)
    .fetch_all(&mut *transaction)
    .await?;
    for lease in &leases {
        anyhow::ensure!(
            lease.try_get::<bool, _>("active")?,
            "BOSH durable delivery lease expired before renewal"
        );
    }
    anyhow::ensure!(
        leases.len() <= 512,
        "BOSH unacknowledged fence limit exceeded"
    );
    let response_count = leases
        .iter()
        .filter_map(|lease| lease.try_get::<i64, _>("response_rid").ok())
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    anyhow::ensure!(
        response_count <= 2,
        "BOSH unacknowledged response limit exceeded"
    );
    if let Some((response_rid, expected_message_ids)) = expected_response {
        let response_rid =
            i64::try_from(response_rid).context("BOSH response RID exceeds bigint")?;
        let expected = expected_message_ids
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>();
        anyhow::ensure!(
            expected.len() == expected_message_ids.len(),
            "duplicate durable delivery in cached BOSH response"
        );
        let mut actual = std::collections::BTreeSet::new();
        for lease in &leases {
            if lease.try_get::<i64, _>("response_rid")? == response_rid {
                anyhow::ensure!(
                    actual.insert(lease.try_get::<Uuid, _>("message_id")?),
                    "duplicate durable delivery fence in one BOSH response"
                );
            }
        }
        anyhow::ensure!(
            actual == expected,
            "cached BOSH response no longer owns its exact durable delivery fences"
        );
    }
    let renewed = sqlx::query(
        "UPDATE bosh_delivery_fences
            SET expires_at=LEAST(clock_timestamp()+($2*INTERVAL '1 second'),
                                 first_owned_at+INTERVAL '5 minutes')
          WHERE session_id=$1 AND first_owned_at>clock_timestamp()-INTERVAL '5 minutes'",
    )
    .bind(session_id)
    .bind(ttl_seconds)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    anyhow::ensure!(
        renewed as usize == leases.len(),
        "BOSH acknowledgement-age fence was lost during renewal"
    );
    transaction.commit().await?;
    Ok(())
}

/// Complete all durable messages covered by a valid XEP-0124 client response
/// acknowledgement. Deleting each offline row cascades its BOSH fence.
///
/// This is the C2S-only test fixture. Runtime acknowledgement goes through
/// the typed transport owner so MIX rows cannot be skipped.
#[cfg(test)]
pub async fn acknowledge_bosh_delivery_responses(
    pool: &PgPool,
    session_id: Uuid,
    acknowledged_rid: u64,
) -> Result<usize> {
    let acknowledged_rid =
        i64::try_from(acknowledged_rid).context("BOSH acknowledgement exceeds bigint")?;
    let mut transaction = pool.begin().await?;
    let mut rows = sqlx::query(
        "SELECT recipient_id,message_id FROM bosh_delivery_fences
          WHERE session_id=$1 AND response_rid<=$2
          ORDER BY message_id",
    )
    .bind(session_id)
    .bind(acknowledged_rid)
    .fetch_all(&mut *transaction)
    .await?;
    rows.sort_unstable_by_key(|row| row.get::<Uuid, _>("message_id"));
    for row in &rows {
        let recipient_id: Uuid = row.try_get("recipient_id")?;
        let message_id: Uuid = row.try_get("message_id")?;
        let offline = sqlx::query_scalar::<_, bool>(
            "SELECT TRUE FROM offline_messages
              WHERE recipient_id=$1 AND id=$2 FOR UPDATE",
        )
        .bind(recipient_id)
        .bind(message_id)
        .fetch_optional(&mut *transaction)
        .await?;
        anyhow::ensure!(offline.is_some(), "BOSH-owned durable delivery disappeared");
        let still_owned = sqlx::query_scalar::<_, bool>(
            "SELECT expires_at>clock_timestamp()
               FROM bosh_delivery_fences
              WHERE message_id=$1 AND session_id=$2 AND response_rid<=$3
              FOR UPDATE",
        )
        .bind(message_id)
        .bind(session_id)
        .bind(acknowledged_rid)
        .fetch_optional(&mut *transaction)
        .await?;
        anyhow::ensure!(
            still_owned == Some(true),
            "BOSH durable delivery lease was lost before acknowledgement"
        );
        let deleted = sqlx::query("DELETE FROM offline_messages WHERE recipient_id=$1 AND id=$2")
            .bind(recipient_id)
            .bind(message_id)
            .execute(&mut *transaction)
            .await?
            .rows_affected();
        anyhow::ensure!(deleted == 1, "BOSH-owned durable delivery disappeared");
    }
    transaction.commit().await?;
    Ok(rows.len())
}

/// C2S-only test fixture; runtime release uses `release_bosh_transport_fences`.
#[cfg(test)]
pub async fn release_bosh_delivery_fences(pool: &PgPool, session_id: Uuid) -> Result<()> {
    sqlx::query("DELETE FROM bosh_delivery_fences WHERE session_id=$1")
        .bind(session_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Renew both C2S and MIX BOSH ownership records as one coherent actor
/// snapshot. Cached-response replay passes its immutable source identities so
/// a mismatched or partially lost response fails closed before bytes repeat.
pub async fn renew_bosh_transport_fences(
    pool: &PgPool,
    session_id: Uuid,
    expected_response: Option<(u64, &crate::outbound::BoshResponseOwnership)>,
    ttl_seconds: u64,
) -> Result<()> {
    let ttl_seconds = i64::try_from(ttl_seconds.clamp(1, BOSH_FENCE_MAX_AGE_SECONDS as u64))
        .context("BOSH delivery-fence TTL is too large")?;
    let mut transaction = pool.begin().await?;
    let c2s = sqlx::query(
        "SELECT message_id,response_rid,
                expires_at>clock_timestamp() AND first_owned_at>clock_timestamp()-INTERVAL '5 minutes' AS active
           FROM bosh_delivery_fences
          WHERE session_id=$1 ORDER BY message_id FOR UPDATE",
    )
    .bind(session_id)
    .fetch_all(&mut *transaction)
    .await?;
    let mix = sqlx::query(
        "SELECT delivery_id,response_rid,
                expires_at>clock_timestamp() AND first_owned_at>clock_timestamp()-INTERVAL '5 minutes' AS active
           FROM mix_bosh_delivery_fences
          WHERE session_id=$1 ORDER BY delivery_id FOR UPDATE",
    )
    .bind(session_id)
    .fetch_all(&mut *transaction)
    .await?;
    for fence in c2s.iter().chain(mix.iter()) {
        anyhow::ensure!(
            fence.try_get::<bool, _>("active")?,
            "BOSH durable transport lease expired before renewal"
        );
    }
    anyhow::ensure!(
        c2s.len().saturating_add(mix.len()) <= 512,
        "BOSH unacknowledged fence limit exceeded"
    );
    let response_count = c2s
        .iter()
        .filter_map(|fence| fence.try_get::<i64, _>("response_rid").ok())
        .chain(mix.iter().filter_map(|fence| {
            fence
                .try_get::<Option<i64>, _>("response_rid")
                .ok()
                .flatten()
        }))
        .collect::<BTreeSet<_>>()
        .len();
    anyhow::ensure!(
        response_count <= 2,
        "BOSH unacknowledged response limit exceeded"
    );
    if let Some((response_rid, expected)) = expected_response {
        let response_rid = i64::try_from(response_rid).context("BOSH RID exceeds bigint")?;
        let actual_c2s = c2s
            .iter()
            .filter_map(|fence| {
                (fence.try_get::<i64, _>("response_rid").ok() == Some(response_rid))
                    .then(|| fence.try_get::<Uuid, _>("message_id").ok())
                    .flatten()
            })
            .collect::<BTreeSet<_>>();
        let actual_mix = mix
            .iter()
            .filter_map(|fence| {
                (fence
                    .try_get::<Option<i64>, _>("response_rid")
                    .ok()
                    .flatten()
                    == Some(response_rid))
                .then(|| fence.try_get::<Uuid, _>("delivery_id").ok())
                .flatten()
            })
            .collect::<BTreeSet<_>>();
        let expected_c2s = expected
            .c2s_message_ids
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let expected_mix = expected
            .mix_delivery_ids
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        anyhow::ensure!(
            actual_c2s == expected_c2s && actual_mix == expected_mix,
            "cached BOSH response no longer owns its exact durable transport sources"
        );
    }
    let renewed_c2s = sqlx::query(
        "UPDATE bosh_delivery_fences
            SET expires_at=LEAST(clock_timestamp()+($2*INTERVAL '1 second'),
                                 first_owned_at+INTERVAL '5 minutes')
          WHERE session_id=$1 AND first_owned_at>clock_timestamp()-INTERVAL '5 minutes'",
    )
    .bind(session_id)
    .bind(ttl_seconds)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    let renewed_mix = sqlx::query(
        "UPDATE mix_bosh_delivery_fences
            SET expires_at=LEAST(clock_timestamp()+($2*INTERVAL '1 second'),
                                 first_owned_at+INTERVAL '5 minutes')
          WHERE session_id=$1 AND first_owned_at>clock_timestamp()-INTERVAL '5 minutes'",
    )
    .bind(session_id)
    .bind(ttl_seconds)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    anyhow::ensure!(
        renewed_c2s as usize == c2s.len() && renewed_mix as usize == mix.len(),
        "BOSH acknowledgement-age fence was lost during renewal"
    );
    transaction.commit().await?;
    Ok(())
}

/// Atomically consume all C2S and MIX sources covered by a valid BOSH client
/// acknowledgement. MIX deletion validates the rotated BOSH lease token, so
/// an acknowledgement can never remove a newly reclaimed recipient row.
pub async fn acknowledge_bosh_transport_responses(
    pool: &PgPool,
    session_id: Uuid,
    acknowledged_rid: u64,
) -> Result<usize> {
    let acknowledged_rid =
        i64::try_from(acknowledged_rid).context("BOSH acknowledgement exceeds bigint")?;
    let mut transaction = pool.begin().await?;
    let c2s = sqlx::query(
        "SELECT recipient_id,message_id FROM bosh_delivery_fences
          WHERE session_id=$1 AND response_rid<=$2
          ORDER BY message_id",
    )
    .bind(session_id)
    .bind(acknowledged_rid)
    .fetch_all(&mut *transaction)
    .await?;
    for fence in &c2s {
        let recipient_id: Uuid = fence.try_get("recipient_id")?;
        let message_id: Uuid = fence.try_get("message_id")?;
        let offline = sqlx::query_scalar::<_, bool>(
            "SELECT TRUE FROM offline_messages WHERE recipient_id=$1 AND id=$2 FOR UPDATE",
        )
        .bind(recipient_id)
        .bind(message_id)
        .fetch_optional(&mut *transaction)
        .await?;
        anyhow::ensure!(offline.is_some(), "BOSH-owned durable delivery disappeared");
        let active = sqlx::query_scalar::<_, bool>(
            "SELECT expires_at>clock_timestamp()
               FROM bosh_delivery_fences
              WHERE message_id=$1 AND session_id=$2 AND response_rid<=$3 FOR UPDATE",
        )
        .bind(message_id)
        .bind(session_id)
        .bind(acknowledged_rid)
        .fetch_optional(&mut *transaction)
        .await?;
        anyhow::ensure!(
            active == Some(true),
            "BOSH durable delivery lease was lost before acknowledgement"
        );
        let deleted = sqlx::query("DELETE FROM offline_messages WHERE recipient_id=$1 AND id=$2")
            .bind(recipient_id)
            .bind(message_id)
            .execute(&mut *transaction)
            .await?
            .rows_affected();
        anyhow::ensure!(deleted == 1, "BOSH-owned durable delivery disappeared");
    }
    let mix = sqlx::query(
        "SELECT delivery_id,lease_token FROM mix_bosh_delivery_fences
          WHERE session_id=$1 AND response_rid<=$2
          ORDER BY delivery_id",
    )
    .bind(session_id)
    .bind(acknowledged_rid)
    .fetch_all(&mut *transaction)
    .await?;
    for fence in &mix {
        let delivery_id: Uuid = fence.try_get("delivery_id")?;
        let lease_token: Uuid = fence.try_get("lease_token")?;
        let recipient = sqlx::query_scalar::<_, Uuid>(
            "SELECT lease_token FROM mix_delivery_recipients WHERE delivery_id=$1 FOR UPDATE",
        )
        .bind(delivery_id)
        .fetch_optional(&mut *transaction)
        .await?;
        anyhow::ensure!(
            recipient == Some(lease_token),
            "MIX BOSH-owned delivery lease changed before acknowledgement"
        );
        let active = sqlx::query_scalar::<_, bool>(
            "SELECT expires_at>clock_timestamp()
               FROM mix_bosh_delivery_fences
              WHERE delivery_id=$1 AND lease_token=$2 AND session_id=$3
                AND response_rid<=$4 FOR UPDATE",
        )
        .bind(delivery_id)
        .bind(lease_token)
        .bind(session_id)
        .bind(acknowledged_rid)
        .fetch_optional(&mut *transaction)
        .await?;
        anyhow::ensure!(
            active == Some(true),
            "MIX BOSH delivery lease was lost before acknowledgement"
        );
        let deleted = sqlx::query(
            "DELETE FROM mix_delivery_recipients WHERE delivery_id=$1 AND lease_token=$2",
        )
        .bind(delivery_id)
        .bind(lease_token)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        anyhow::ensure!(deleted == 1, "MIX BOSH-owned delivery disappeared");
    }
    transaction.commit().await?;
    Ok(c2s.len().saturating_add(mix.len()))
}

/// Release an actor's unacknowledged BOSH transport sources without consuming
/// them. C2S rows become eligible through their deleted fences; MIX rows keep
/// their event/sequence but lose only the exact rotated BOSH lease.
pub async fn release_bosh_transport_fences(pool: &PgPool, session_id: Uuid) -> Result<()> {
    let mut transaction = pool.begin().await?;
    sqlx::query("DELETE FROM bosh_delivery_fences WHERE session_id=$1")
        .bind(session_id)
        .execute(&mut *transaction)
        .await?;
    let mix = sqlx::query(
        "SELECT delivery_id,lease_token FROM mix_bosh_delivery_fences
          WHERE session_id=$1 ORDER BY delivery_id",
    )
    .bind(session_id)
    .fetch_all(&mut *transaction)
    .await?;
    for fence in &mix {
        let delivery_id: Uuid = fence.try_get("delivery_id")?;
        let lease_token: Uuid = fence.try_get("lease_token")?;
        let recipient = sqlx::query_scalar::<_, Uuid>(
            "SELECT lease_token FROM mix_delivery_recipients WHERE delivery_id=$1 FOR UPDATE",
        )
        .bind(delivery_id)
        .fetch_optional(&mut *transaction)
        .await?;
        let owned = sqlx::query_scalar::<_, Uuid>(
            "SELECT lease_token FROM mix_bosh_delivery_fences
              WHERE delivery_id=$1 AND session_id=$2 FOR UPDATE",
        )
        .bind(delivery_id)
        .bind(session_id)
        .fetch_optional(&mut *transaction)
        .await?;
        if recipient == Some(lease_token) && owned == Some(lease_token) {
            let released = sqlx::query(
                "UPDATE mix_delivery_recipients
                    SET lease_token=NULL,lease_until=NULL,next_attempt_at=clock_timestamp()
                  WHERE delivery_id=$1 AND lease_token=$2",
            )
            .bind(delivery_id)
            .bind(lease_token)
            .execute(&mut *transaction)
            .await?
            .rows_affected();
            anyhow::ensure!(
                released == 1,
                "MIX BOSH lease release lost its recipient row"
            );
        }
        sqlx::query(
            "DELETE FROM mix_bosh_delivery_fences
              WHERE delivery_id=$1 AND session_id=$2 AND lease_token=$3",
        )
        .bind(delivery_id)
        .bind(session_id)
        .bind(lease_token)
        .execute(&mut *transaction)
        .await?;
    }
    transaction.commit().await?;
    Ok(())
}

#[cfg(test)]
mod bosh_ack_bound_schema_tests {
    #[test]
    fn renewal_is_bounded_by_immutable_ack_age() {
        let migration = include_str!("../../migrations/0096_bosh_ack_ownership_bounds.sql");
        let source = include_str!("replay.rs");
        for required in [
            "first_owned_at TIMESTAMPTZ NOT NULL",
            "expires_at<=first_owned_at+INTERVAL '5 minutes'",
            "first_owned_at>clock_timestamp()-INTERVAL '5 minutes'",
            "response_count <= 2",
            "leases.len() <= 512",
        ] {
            assert!(
                migration.contains(required) || source.contains(required),
                "missing BOSH ACK ownership bound {required}"
            );
        }
    }
}

#[cfg(test)]
#[path = "replay_tests.rs"]
mod tests;
