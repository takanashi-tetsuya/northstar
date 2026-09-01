use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rand::Rng;
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::{collections::HashMap, time::Duration};
use uuid::Uuid;

const REPLAY_PAGE_SIZE: i64 = 64;
const CLAIM_LEASE_SECONDS: i64 = 60;
// The resource owner outlives every page claim. If a process crashes after
// claiming a page, takeover cannot occur until those row claims are already
// eligible in the same pass; otherwise the replacement would observe an
// apparently empty queue and messages would wait for another login.
pub(crate) const REPLAY_OWNER_LEASE_SECONDS: i64 = 90;

#[derive(Clone, Debug)]
pub struct PendingPresenceCursor {
    created_at: DateTime<Utc>,
    source: i16,
    key: String,
}

#[derive(Clone, Debug)]
pub struct PendingPresenceReplay {
    pub requester: String,
    pub stanza: Option<String>,
    pub cursor: PendingPresenceCursor,
}

#[derive(Debug)]
pub struct PendingPresenceReplayPage {
    pub items: Vec<PendingPresenceReplay>,
    pub next_cursor: Option<PendingPresenceCursor>,
    pub complete: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OfflineReplayLease {
    pub recipient_id: Uuid,
    pub resource: String,
    pub owner_token: Uuid,
    pub replay_started_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OfflineReplayBusyUntil {
    pub expires_at: DateTime<Utc>,
    /// Remaining lease time measured by PostgreSQL in the same query which
    /// returned `expires_at`. Callers must use this monotonic duration rather
    /// than subtracting an application-wall-clock value.
    pub retry_after: Duration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OfflineReplayLeaseAcquire {
    Acquired(OfflineReplayLease),
    BusyUntil(OfflineReplayBusyUntil),
}

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

/// Transfer durable C2S rows to the exact BOSH response which will carry
/// them. This commits before the HTTP response bytes are exposed to the peer.
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

pub async fn release_bosh_delivery_fences(pool: &PgPool, session_id: Uuid) -> Result<()> {
    sqlx::query("DELETE FROM bosh_delivery_fences WHERE session_id=$1")
        .bind(session_id)
        .execute(pool)
        .await?;
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
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    async fn insert_replay_message(
        pool: &PgPool,
        recipient_id: Uuid,
        sender: &str,
        stanza: &str,
    ) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO offline_messages(
                id,recipient_id,sender_jid,stanza,encrypted,mam_backed
             ) VALUES($1,$2,$3,$4,FALSE,FALSE)",
        )
        .bind(id)
        .bind(recipient_id)
        .bind(sender)
        .bind(stanza)
        .execute(pool)
        .await
        .unwrap();
        id
    }

    async fn insert_resource_replay_message(
        pool: &PgPool,
        recipient_id: Uuid,
        target_resource: Option<&str>,
        stanza_id: &str,
    ) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO offline_messages(
                id,recipient_id,sender_jid,stanza,target_resource,encrypted,mam_backed
             ) VALUES($1,$2,'sender@remote.test/Phone',$3,$4,FALSE,FALSE)",
        )
        .bind(id)
        .bind(recipient_id)
        .bind(format!("<message id='{stanza_id}'/>"))
        .bind(target_resource)
        .execute(pool)
        .await
        .unwrap();
        id
    }

    #[test]
    fn resource_owner_lease_strictly_outlives_page_claim_and_jitter() {
        const {
            assert!(REPLAY_OWNER_LEASE_SECONDS >= CLAIM_LEASE_SECONDS + 15);
        }
        let migration = include_str!("../../migrations/0103_offline_replay_leases.sql");
        assert!(migration.contains("expires_at >= renewed_at + INTERVAL '75 seconds'"));
        assert!(!migration.to_ascii_lowercase().contains("public."));
        let migration_0122 =
            include_str!("../../migrations/0122_offline_replay_resource_leases.sql");
        assert!(migration_0122.contains("PRIMARY KEY (recipient_id, resource)"));
        assert!(!migration_0122.to_ascii_lowercase().contains("public."));
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn replay_enforces_resource_affinity_and_immutable_ownership() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();
        let recipient = Uuid::new_v4();
        let other_recipient = Uuid::new_v4();
        let recipient_text = recipient.simple().to_string();
        let suffix = &recipient_text[..12];
        let username = format!("affinity{suffix}");
        let other_username = format!("affinityother{suffix}");
        for (id, username) in [(recipient, &username), (other_recipient, &other_username)] {
            sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test')")
                .bind(id)
                .bind(username)
                .execute(&pool)
                .await
                .unwrap();
        }
        let account_scoped =
            insert_resource_replay_message(&pool, recipient, None, "account-scoped").await;
        let phone =
            insert_resource_replay_message(&pool, recipient, Some("Phone"), "phone-only").await;
        let tablet =
            insert_resource_replay_message(&pool, recipient, Some("Tablet"), "tablet-only").await;

        let phone_lease = acquire_offline_replay_lease(
            &pool,
            recipient,
            "Phone",
            Uuid::new_v4(),
            None,
            REPLAY_OWNER_LEASE_SECONDS,
        )
        .await
        .unwrap()
        .into_acquired()
        .unwrap();
        let phone_page = match claim_offline_replay_page(
            &pool,
            &phone_lease,
            30,
            &format!("{username}@example.test"),
            &format!("{username}@example.test/Phone"),
            None,
            false,
            REPLAY_OWNER_LEASE_SECONDS,
        )
        .await
        .unwrap()
        {
            OfflineReplayPageOutcome::Claimed(page) => page,
            other => panic!("expected phone replay page, got {other:?}"),
        };
        let phone_ids = phone_page
            .messages
            .iter()
            .map(|message| message.id)
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(phone_ids, [account_scoped, phone].into_iter().collect());
        assert!(!phone_ids.contains(&tablet));
        assert!(release_offline_replay_lease(&pool, &phone_lease)
            .await
            .unwrap());

        let tablet_lease = acquire_offline_replay_lease(
            &pool,
            recipient,
            "Tablet",
            Uuid::new_v4(),
            None,
            REPLAY_OWNER_LEASE_SECONDS,
        )
        .await
        .unwrap()
        .into_acquired()
        .unwrap();
        let tablet_page = match claim_offline_replay_page(
            &pool,
            &tablet_lease,
            30,
            &format!("{username}@example.test"),
            &format!("{username}@example.test/Tablet"),
            None,
            false,
            REPLAY_OWNER_LEASE_SECONDS,
        )
        .await
        .unwrap()
        {
            OfflineReplayPageOutcome::Claimed(page) => page,
            other => panic!("expected tablet replay page, got {other:?}"),
        };
        assert_eq!(tablet_page.messages.len(), 1);
        assert_eq!(tablet_page.messages[0].id, tablet);

        assert!(
            sqlx::query("UPDATE offline_messages SET target_resource='Other' WHERE id=$1")
                .bind(tablet)
                .execute(&pool)
                .await
                .is_err()
        );
        assert!(
            sqlx::query("UPDATE offline_messages SET recipient_id=$2 WHERE id=$1")
                .bind(tablet)
                .bind(other_recipient)
                .execute(&pool)
                .await
                .is_err()
        );

        let _ = release_offline_replay_lease(&pool, &tablet_lease).await;
        sqlx::query("DELETE FROM users WHERE id=ANY($1)")
            .bind(vec![recipient, other_recipient])
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn logical_owner_is_exclusive_crash_recoverable_and_does_not_hold_the_pool() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .acquire_timeout(std::time::Duration::from_secs(1))
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();
        let recipient = Uuid::new_v4();
        let username = format!("lease{}", &recipient.simple().to_string()[..12]);
        sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test')")
            .bind(recipient)
            .bind(&username)
            .execute(&pool)
            .await
            .unwrap();
        for index in 0..3 {
            insert_replay_message(
                &pool,
                recipient,
                "sender@example.test/Phone",
                &format!("<message id='lease-{index}'/>"),
            )
            .await;
        }

        let first_token = Uuid::new_v4();
        let second_token = Uuid::new_v4();
        let (first, second) = tokio::join!(
            acquire_offline_replay_lease(
                &pool,
                recipient,
                "test-replay",
                first_token,
                None,
                REPLAY_OWNER_LEASE_SECONDS,
            ),
            acquire_offline_replay_lease(
                &pool,
                recipient,
                "test-replay",
                second_token,
                None,
                REPLAY_OWNER_LEASE_SECONDS,
            ),
        );
        let first = first.unwrap();
        let second = second.unwrap();
        assert_ne!(first.is_acquired(), second.is_acquired());
        let owner = first
            .into_acquired()
            .or_else(|| second.into_acquired())
            .unwrap();
        let page = match claim_offline_replay_page(
            &pool,
            &owner,
            30,
            &format!("{username}@example.test"),
            &format!("{username}@example.test/test-replay"),
            None,
            false,
            REPLAY_OWNER_LEASE_SECONDS,
        )
        .await
        .unwrap()
        {
            OfflineReplayPageOutcome::Claimed(page) => page,
            other => panic!("expected claimed page, got {other:?}"),
        };
        assert_eq!(page.messages.len(), 3);

        // Model a slow client after the short page transaction has returned.
        // The blocked network await owns no PostgreSQL connection, so even a
        // two-connection pool remains immediately usable.
        let (slow_tx, mut slow_rx) = mpsc::channel(1);
        let slow_tx = crate::outbound::OutboundSender::new(slow_tx);
        slow_tx.send("occupied".to_owned()).await.unwrap();
        let slow_message = page.messages[0].clone();
        let slow_claim = page.claim_token;
        let slow_sender = slow_tx.clone();
        let blocked_send = tokio::spawn(async move {
            slow_sender
                .send_durable(
                    slow_message.stanza,
                    crate::outbound::DurableDelivery {
                        recipient_id: recipient,
                        message_id: slow_message.id,
                        claim_id: Some(slow_claim),
                    },
                )
                .await
        });
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        assert!(!blocked_send.is_finished());
        let probe = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            sqlx::query_scalar::<_, i32>("SELECT 1").fetch_one(&pool),
        )
        .await
        .expect("a slow transport must not retain a primary pool connection")
        .unwrap();
        assert_eq!(probe, 1);
        assert_eq!(slow_rx.recv().await.unwrap().stanza, "occupied");
        assert!(blocked_send.await.unwrap().is_ok());
        drop(slow_rx);

        // Only the unsent suffix is released. The accepted prefix retains its
        // exact claim until the durable transport acknowledgement.
        let accepted = page.messages[0].id;
        let suffix = page.messages[1..]
            .iter()
            .map(|message| message.id)
            .collect::<Vec<_>>();
        assert_eq!(
            release_untransferred_offline_claims(&pool, recipient, page.claim_token, &suffix,)
                .await
                .unwrap(),
            2
        );
        let claims = sqlx::query(
            "SELECT id,delivery_claim_id FROM offline_messages
              WHERE recipient_id=$1 ORDER BY id",
        )
        .bind(recipient)
        .fetch_all(&pool)
        .await
        .unwrap();
        for row in claims {
            let id: Uuid = row.get("id");
            let claim: Option<Uuid> = row.get("delivery_claim_id");
            assert_eq!(claim, (id == accepted).then_some(page.claim_token));
        }
        acknowledge_durable_delivery(
            &pool,
            crate::outbound::DurableDelivery {
                recipient_id: recipient,
                message_id: accepted,
                claim_id: Some(page.claim_token),
            },
        )
        .await
        .unwrap();
        assert!(release_offline_replay_lease(&pool, &owner).await.unwrap());

        // Crash after claiming the remaining page: by the time the longer
        // account lease expires, the 60-second row claims have also expired.
        // The replacement owner claims them in this same login/replay pass.
        let crashed = acquire_offline_replay_lease(
            &pool,
            recipient,
            "test-replay",
            Uuid::new_v4(),
            None,
            REPLAY_OWNER_LEASE_SECONDS,
        )
        .await
        .unwrap()
        .into_acquired()
        .unwrap();
        let crashed_page = match claim_offline_replay_page(
            &pool,
            &crashed,
            30,
            &format!("{username}@example.test"),
            &format!("{username}@example.test/test-replay"),
            None,
            false,
            REPLAY_OWNER_LEASE_SECONDS,
        )
        .await
        .unwrap()
        {
            OfflineReplayPageOutcome::Claimed(page) => page,
            other => panic!("expected crash fixture page, got {other:?}"),
        };
        assert_eq!(crashed_page.messages.len(), 2);
        sqlx::query(
            "UPDATE offline_replay_leases
                SET acquired_at=clock_timestamp()-INTERVAL '100 seconds',
                    renewed_at=clock_timestamp()-INTERVAL '100 seconds',
                    expires_at=clock_timestamp()-INTERVAL '10 seconds'
              WHERE recipient_id=$1 AND owner_token=$2",
        )
        .bind(recipient)
        .bind(crashed.owner_token)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE offline_messages
                SET delivery_claim_expires_at=clock_timestamp()-INTERVAL '40 seconds'
              WHERE recipient_id=$1 AND delivery_claim_id=$2",
        )
        .bind(recipient)
        .bind(crashed_page.claim_token)
        .execute(&pool)
        .await
        .unwrap();
        let replacement = acquire_offline_replay_lease(
            &pool,
            recipient,
            "test-replay",
            Uuid::new_v4(),
            None,
            REPLAY_OWNER_LEASE_SECONDS,
        )
        .await
        .unwrap()
        .into_acquired()
        .unwrap();
        let crashed_ids = crashed_page
            .messages
            .iter()
            .map(|message| message.id)
            .collect::<Vec<_>>();
        assert!(!renew_offline_replay_before_send(
            &pool,
            &crashed,
            crashed_page.claim_token,
            &crashed_ids,
            REPLAY_OWNER_LEASE_SECONDS,
        )
        .await
        .unwrap());
        assert!(!release_offline_replay_lease(&pool, &crashed).await.unwrap());
        let replacement_page = match claim_offline_replay_page(
            &pool,
            &replacement,
            30,
            &format!("{username}@example.test"),
            &format!("{username}@example.test/test-replay"),
            None,
            false,
            REPLAY_OWNER_LEASE_SECONDS,
        )
        .await
        .unwrap()
        {
            OfflineReplayPageOutcome::Claimed(page) => page,
            other => panic!("replacement did not recover crash page: {other:?}"),
        };
        let replacement_ids = replacement_page
            .messages
            .iter()
            .map(|message| message.id)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            replacement_ids,
            crashed_ids
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>()
        );
        release_untransferred_offline_claims(
            &pool,
            recipient,
            replacement_page.claim_token,
            &replacement_ids.iter().copied().collect::<Vec<_>>(),
        )
        .await
        .unwrap();
        assert!(release_offline_replay_lease(&pool, &replacement)
            .await
            .unwrap());
        sqlx::query("DELETE FROM users WHERE id=$1")
            .bind(recipient)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn replay_policy_snapshot_is_consistent_and_missing_policy_rolls_back() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();
        let recipient = Uuid::new_v4();
        let username = format!("policy{}", &recipient.simple().to_string()[..12]);
        sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test')")
            .bind(recipient)
            .bind(&username)
            .execute(&pool)
            .await
            .unwrap();
        let message_id = insert_replay_message(
            &pool,
            recipient,
            "sender@example.test/Phone",
            "<message id='policy-rollback'/>",
        )
        .await;
        let lease = acquire_offline_replay_lease(
            &pool,
            recipient,
            "test-replay",
            Uuid::new_v4(),
            None,
            REPLAY_OWNER_LEASE_SECONDS,
        )
        .await
        .unwrap()
        .into_acquired()
        .unwrap();
        let missing = claim_offline_replay_page(
            &pool,
            &lease,
            30,
            &format!("{username}@example.test"),
            &format!("{username}@example.test/test-replay"),
            Some("missing-active-list"),
            false,
            REPLAY_OWNER_LEASE_SECONDS,
        )
        .await;
        assert!(missing.is_err());
        let row = sqlx::query(
            "SELECT delivery_claim_id,delivery_claim_expires_at
               FROM offline_messages WHERE id=$1",
        )
        .bind(message_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(row.get::<Option<Uuid>, _>("delivery_claim_id"), None);
        assert_eq!(
            row.get::<Option<DateTime<Utc>>, _>("delivery_claim_expires_at"),
            None
        );

        let allow = crate::db::PrivacyList {
            name: "snapshot".to_owned(),
            items: vec![crate::db::PrivacyItem {
                order: 1,
                action: crate::db::PrivacyAction::Allow,
                match_type: None,
                match_value: None,
                message: false,
                iq: false,
                presence_in: false,
                presence_out: false,
            }],
        };
        crate::db::replace_privacy_list(&pool, recipient, &allow)
            .await
            .unwrap();
        let mut snapshot = pool.begin().await.unwrap();
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *snapshot)
            .await
            .unwrap();
        let candidates = vec!["sender@example.test/Phone".to_owned()];
        let (blocked, privacy, roster) =
            replay_policy_snapshot(&mut snapshot, recipient, Some("snapshot"), &candidates)
                .await
                .unwrap();
        assert!(!replay_policy_denies(
            &format!("{username}@example.test"),
            &candidates[0],
            crate::db::PrivacyStanzaKind::Message,
            &blocked,
            &privacy,
            &roster,
        )
        .unwrap());
        let deny = crate::db::PrivacyList {
            name: "snapshot".to_owned(),
            items: vec![crate::db::PrivacyItem {
                order: 1,
                action: crate::db::PrivacyAction::Deny,
                match_type: None,
                match_value: None,
                message: false,
                iq: false,
                presence_in: false,
                presence_out: false,
            }],
        };
        crate::db::replace_privacy_list(&pool, recipient, &deny)
            .await
            .unwrap();
        let (blocked_again, privacy_again, roster_again) =
            replay_policy_snapshot(&mut snapshot, recipient, Some("snapshot"), &candidates)
                .await
                .unwrap();
        assert!(!replay_policy_denies(
            &format!("{username}@example.test"),
            &candidates[0],
            crate::db::PrivacyStanzaKind::Message,
            &blocked_again,
            &privacy_again,
            &roster_again,
        )
        .unwrap());
        snapshot.commit().await.unwrap();
        let mut fresh = pool.begin().await.unwrap();
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *fresh)
            .await
            .unwrap();
        let (fresh_blocked, fresh_privacy, fresh_roster) =
            replay_policy_snapshot(&mut fresh, recipient, Some("snapshot"), &candidates)
                .await
                .unwrap();
        assert!(replay_policy_denies(
            &format!("{username}@example.test"),
            &candidates[0],
            crate::db::PrivacyStanzaKind::Message,
            &fresh_blocked,
            &fresh_privacy,
            &fresh_roster,
        )
        .unwrap());
        fresh.commit().await.unwrap();
        assert!(release_offline_replay_lease(&pool, &lease).await.unwrap());
        sqlx::query("DELETE FROM users WHERE id=$1")
            .bind(recipient)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn durable_ack_batch_validates_every_fence_before_deleting_any_row() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();
        let recipient = Uuid::new_v4();
        sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test')")
            .bind(recipient)
            .bind(format!("ackbatch{}", &recipient.simple().to_string()[..12]))
            .execute(&pool)
            .await
            .unwrap();
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        let actual_claim = Uuid::new_v4();
        for (message_id, claim_id) in [(first, None), (second, Some(actual_claim))] {
            sqlx::query(
                "INSERT INTO offline_messages(
                    id,recipient_id,sender_jid,stanza,encrypted,mam_backed,
                    delivery_claim_id,delivery_claim_expires_at
                 ) VALUES($1,$2,'sender@example.test','<message/>',FALSE,FALSE,$3,
                          CASE WHEN $3::UUID IS NULL THEN NULL ELSE NOW()+INTERVAL '1 minute' END)",
            )
            .bind(message_id)
            .bind(recipient)
            .bind(claim_id)
            .execute(&pool)
            .await
            .unwrap();
        }
        let first_delivery = crate::outbound::DurableDelivery {
            recipient_id: recipient,
            message_id: first,
            claim_id: None,
        };
        let invalid_second = crate::outbound::DurableDelivery {
            recipient_id: recipient,
            message_id: second,
            claim_id: Some(Uuid::new_v4()),
        };
        assert!(
            acknowledge_durable_deliveries(&pool, &[first_delivery, invalid_second])
                .await
                .is_err()
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM offline_messages WHERE id=ANY($1)",)
                .bind(vec![first, second])
                .fetch_one(&pool)
                .await
                .unwrap(),
            2,
            "a later invalid fence must roll back the valid prefix"
        );
        let valid_second = crate::outbound::DurableDelivery {
            claim_id: Some(actual_claim),
            ..invalid_second
        };
        acknowledge_durable_deliveries(&pool, &[first_delivery, valid_second])
            .await
            .unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM offline_messages WHERE id=ANY($1)",)
                .bind(vec![first, second])
                .fetch_one(&pool)
                .await
                .unwrap(),
            0
        );
        sqlx::query("DELETE FROM users WHERE id=$1")
            .bind(recipient)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn replay_high_water_excludes_rows_inserted_after_replay_started() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(8)
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();
        let recipient = Uuid::new_v4();
        sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test')")
            .bind(recipient)
            .bind(format!("water{}", &recipient.simple().to_string()[..12]))
            .execute(&pool)
            .await
            .unwrap();
        for index in 0..65_u32 {
            sqlx::query(
                "INSERT INTO offline_messages \
                 (id,recipient_id,sender_jid,stanza,encrypted,mam_backed) \
                 VALUES($1,$2,'sender@example.test',$3,FALSE,FALSE)",
            )
            .bind(Uuid::new_v4())
            .bind(recipient)
            .bind(format!("<message id='before-{index}'/>"))
            .execute(&pool)
            .await
            .unwrap();
        }

        let (tx, mut rx) = mpsc::channel(1);
        let tx = crate::outbound::OutboundSender::new(tx);
        let delivery_pool = pool.clone();
        let delivery = tokio::spawn(async move {
            deliver_offline_leased(&delivery_pool, recipient, 30, &tx, false, None)
                .await
                .unwrap()
        });
        let first = rx.recv().await.expect("first pre-existing row");
        let late_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO offline_messages \
             (id,recipient_id,sender_jid,stanza,encrypted,mam_backed) \
             VALUES($1,$2,'late@example.test','<message id=''after-start''/>',FALSE,FALSE)",
        )
        .bind(late_id)
        .bind(recipient)
        .execute(&pool)
        .await
        .unwrap();

        acknowledge_durable_delivery(&pool, first.durable_delivery.unwrap())
            .await
            .unwrap();
        let mut delivered = vec![first.stanza];
        while delivered.len() < 65 {
            let item = rx.recv().await.expect("remaining pre-existing row");
            assert!(!item.stanza.contains("after-start"));
            acknowledge_durable_delivery(&pool, item.durable_delivery.unwrap())
                .await
                .unwrap();
            delivered.push(item.stanza);
        }
        assert_eq!(delivery.await.unwrap(), 65);
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM offline_messages WHERE recipient_id=$1 AND id=$2",
            )
            .bind(recipient)
            .bind(late_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
            1
        );
        sqlx::query("DELETE FROM users WHERE id=$1")
            .bind(recipient)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn replay_is_paged_exclusive_and_retryable() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(8)
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();
        let recipient = Uuid::new_v4();
        sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test')")
            .bind(recipient)
            .bind(format!("replay{}", &recipient.simple().to_string()[..12]))
            .execute(&pool)
            .await
            .unwrap();
        let first_message_id = Uuid::new_v4();
        for index in 0..600_u32 {
            sqlx::query(
                "INSERT INTO offline_messages \
                 (id,recipient_id,sender_jid,stanza,encrypted,mam_backed,created_at) \
                 VALUES($1,$2,'sender@example.test',$3,FALSE,FALSE, \
                        clock_timestamp()+($4*INTERVAL '1 microsecond'))",
            )
            .bind(if index == 0 {
                first_message_id
            } else {
                Uuid::new_v4()
            })
            .bind(recipient)
            .bind(format!("<message id='{index}'/>"))
            .bind(i64::from(index))
            .execute(&pool)
            .await
            .unwrap();
        }

        // Model a process that died while holding a claim. The next worker
        // cannot steal it before expiry, but it becomes retryable afterwards.
        sqlx::query(
            "UPDATE offline_messages SET delivery_claim_id=$2, \
             delivery_claim_expires_at=clock_timestamp()+INTERVAL '1 hour' WHERE id=$1",
        )
        .bind(first_message_id)
        .bind(Uuid::new_v4())
        .execute(&pool)
        .await
        .unwrap();

        // A closed queue must release the complete first claim immediately.
        let (closed_tx, closed_rx) = mpsc::channel(1);
        drop(closed_rx);
        let closed_tx = crate::outbound::OutboundSender::new(closed_tx);
        assert_eq!(
            deliver_offline_leased(&pool, recipient, 30, &closed_tx, false, None)
                .await
                .unwrap(),
            0
        );
        let claimed: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM offline_messages WHERE delivery_claim_id IS NOT NULL",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(claimed, 1);

        sqlx::query(
            "UPDATE offline_messages SET delivery_claim_expires_at=clock_timestamp()-INTERVAL '1 second' \
             WHERE id=$1",
        )
        .bind(first_message_id)
        .execute(&pool)
        .await
        .unwrap();

        let (tx, mut rx) = mpsc::channel(8);
        let tx = crate::outbound::OutboundSender::new(tx);
        let pool_for_delivery = pool.clone();
        let delivery = tokio::spawn(async move {
            deliver_offline_leased(&pool_for_delivery, recipient, 30, &tx, false, None)
                .await
                .unwrap()
        });
        let mut received = Vec::new();
        while let Some(item) = rx.recv().await {
            acknowledge_durable_delivery(&pool, item.durable_delivery.unwrap())
                .await
                .unwrap();
            received.push(item.stanza);
            if received.len() == 600 {
                break;
            }
        }
        assert_eq!(delivery.await.unwrap(), 600);
        assert_eq!(received.len(), 600);
        assert_eq!(received.first().unwrap(), "<message id='0'/>");
        assert_eq!(received.last().unwrap(), "<message id='599'/>");
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM offline_messages WHERE recipient_id=$1",
            )
            .bind(recipient)
            .fetch_one(&pool)
            .await
            .unwrap(),
            0
        );

        sqlx::query(
            "INSERT INTO blocked_jids(owner_id,blocked_jid) VALUES($1,'blocked@example.test')",
        )
        .bind(recipient)
        .execute(&pool)
        .await
        .unwrap();
        let privacy = crate::db::PrivacyList {
            name: "offline-replay".to_owned(),
            items: vec![
                crate::db::PrivacyItem {
                    order: 1,
                    action: crate::db::PrivacyAction::Deny,
                    match_type: Some(crate::db::PrivacyMatchType::Jid),
                    match_value: Some("private@example.test".to_owned()),
                    message: true,
                    iq: false,
                    presence_in: false,
                    presence_out: false,
                },
                crate::db::PrivacyItem {
                    order: 2,
                    action: crate::db::PrivacyAction::Allow,
                    match_type: None,
                    match_value: None,
                    message: false,
                    iq: false,
                    presence_in: false,
                    presence_out: false,
                },
            ],
        };
        crate::db::replace_privacy_list(&pool, recipient, &privacy)
            .await
            .unwrap();
        for (sender, id) in [
            ("blocked@example.test/Phone", "blocked"),
            ("private@example.test/Phone", "private"),
            ("allowed@example.test/Phone", "allowed"),
        ] {
            sqlx::query(
                "INSERT INTO offline_messages \
                 (id,recipient_id,sender_jid,stanza,encrypted,mam_backed) \
                 VALUES($1,$2,$3,$4,FALSE,FALSE)",
            )
            .bind(Uuid::new_v4())
            .bind(recipient)
            .bind(sender)
            .bind(format!("<message id='{id}'/>"))
            .execute(&pool)
            .await
            .unwrap();
        }
        let (policy_tx, mut policy_rx) = mpsc::channel(8);
        let policy_tx = crate::outbound::OutboundSender::new(policy_tx);
        assert_eq!(
            deliver_offline_leased(
                &pool,
                recipient,
                30,
                &policy_tx,
                false,
                Some("offline-replay"),
            )
            .await
            .unwrap(),
            1
        );
        drop(policy_tx);
        let allowed = policy_rx.recv().await.unwrap();
        acknowledge_durable_delivery(&pool, allowed.durable_delivery.unwrap())
            .await
            .unwrap();
        assert_eq!(allowed.stanza, "<message id='allowed'/>");
        assert!(policy_rx.recv().await.is_none());

        // Two resources can become available at the same instant. The
        // account-scoped advisory owner prevents page 1 and page 2 from being
        // split across those resources; one receives the entire ordered
        // queue and the other observes an already-owned replay.
        for index in 0..129_u32 {
            sqlx::query(
                "INSERT INTO offline_messages \
                 (id,recipient_id,sender_jid,stanza,encrypted,mam_backed,created_at) \
                 VALUES($1,$2,'race@example.test',$3,FALSE,FALSE, \
                        clock_timestamp()+($4*INTERVAL '1 microsecond'))",
            )
            .bind(Uuid::new_v4())
            .bind(recipient)
            .bind(format!("<message id='race-{index}'/>"))
            .bind(i64::from(index))
            .execute(&pool)
            .await
            .unwrap();
        }
        let (first_tx, mut first_rx) = mpsc::channel(129);
        let (second_tx, mut second_rx) = mpsc::channel(129);
        let first_tx = crate::outbound::OutboundSender::new(first_tx);
        let second_tx = crate::outbound::OutboundSender::new(second_tx);
        let (first, second) = tokio::join!(
            deliver_offline_leased(&pool, recipient, 30, &first_tx, false, None),
            deliver_offline_leased(&pool, recipient, 30, &second_tx, false, None),
        );
        drop(first_tx);
        drop(second_tx);
        let mut first_messages = Vec::new();
        while let Some(message) = first_rx.recv().await {
            acknowledge_durable_delivery(&pool, message.durable_delivery.unwrap())
                .await
                .unwrap();
            first_messages.push(message.stanza);
        }
        let mut second_messages = Vec::new();
        while let Some(message) = second_rx.recv().await {
            acknowledge_durable_delivery(&pool, message.durable_delivery.unwrap())
                .await
                .unwrap();
            second_messages.push(message.stanza);
        }
        assert_eq!(first.unwrap() + second.unwrap(), 129);
        let winner = if first_messages.is_empty() {
            &second_messages
        } else {
            assert!(second_messages.is_empty());
            &first_messages
        };
        assert_eq!(winner.len(), 129);
        assert_eq!(winner.first().unwrap(), "<message id='race-0'/>");
        assert_eq!(winner.last().unwrap(), "<message id='race-128'/>");

        // More than one transport queue of pending subscription requests is
        // paged without truncation, and remains available to a second newly
        // available resource rather than being consumed globally.
        for index in 0..600_u32 {
            sqlx::query(
                "INSERT INTO federated_presence_pending(recipient_id,from_jid,stanza,created_at) \
                 VALUES($1,$2,$3,clock_timestamp()+($4*INTERVAL '1 microsecond'))",
            )
            .bind(recipient)
            .bind(format!("sender{index:04}@remote.test"))
            .bind(format!(
                "<presence from='sender{index:04}@remote.test' type='subscribe'/>"
            ))
            .bind(i64::from(index))
            .execute(&pool)
            .await
            .unwrap();
        }
        for _resource in 0..2 {
            let mut cursor = None;
            let mut requesters = Vec::new();
            loop {
                let page =
                    pending_presence_replay_page(&pool, recipient, "example.test", cursor.as_ref())
                        .await
                        .unwrap();
                assert!(page.len() <= REPLAY_PAGE_SIZE as usize);
                if page.is_empty() {
                    break;
                }
                cursor = page.last().map(|row| row.cursor.clone());
                requesters.extend(page.into_iter().map(|row| row.requester));
            }
            assert_eq!(requesters.len(), 600);
            assert_eq!(requesters.first().unwrap(), "sender0000@remote.test");
            assert_eq!(requesters.last().unwrap(), "sender0599@remote.test");
        }
        sqlx::query("DELETE FROM users WHERE id=$1")
            .bind(recipient)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn bosh_delivery_is_owned_by_response_rid_until_a_live_client_ack() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();
        let recipient = Uuid::new_v4();
        let username = format!("boshfence{}", &recipient.simple().to_string()[..10]);
        sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test')")
            .bind(recipient)
            .bind(&username)
            .execute(&pool)
            .await
            .unwrap();

        let message_id = Uuid::new_v4();
        let claim_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO offline_messages(
                id,recipient_id,sender_jid,stanza,encrypted,mam_backed,
                delivery_claim_id,delivery_claim_expires_at
             ) VALUES($1,$2,'sender@example.test','<message id=''bosh''/>',FALSE,FALSE,
                      $3,clock_timestamp()+INTERVAL '1 hour')",
        )
        .bind(message_id)
        .bind(recipient)
        .bind(claim_id)
        .execute(&pool)
        .await
        .unwrap();
        let delivery = crate::outbound::DurableDelivery {
            recipient_id: recipient,
            message_id,
            claim_id: Some(claim_id),
        };
        assert!(
            acknowledge_durable_delivery(
                &pool,
                crate::outbound::DurableDelivery {
                    claim_id: None,
                    ..delivery
                },
            )
            .await
            .is_err(),
            "an unfenced live writer must not consume another replay claim"
        );
        let session_id = Uuid::new_v4();
        bind_bosh_delivery_response(&pool, session_id, 100, &[delivery], 60)
            .await
            .unwrap();
        assert!(acknowledge_durable_delivery(&pool, delivery).await.is_err());
        // Rebuilding the exact response is idempotent, but a second BOSH
        // session cannot steal the same live response fence.
        bind_bosh_delivery_response(&pool, session_id, 100, &[delivery], 60)
            .await
            .unwrap();
        assert!(
            bind_bosh_delivery_response(&pool, Uuid::new_v4(), 100, &[delivery], 60)
                .await
                .is_err()
        );
        let claim: Option<Uuid> =
            sqlx::query_scalar("SELECT delivery_claim_id FROM offline_messages WHERE id=$1")
                .bind(message_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(claim, None);
        assert_eq!(
            acknowledge_bosh_delivery_responses(&pool, session_id, 99)
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM offline_messages WHERE id=$1")
                .bind(message_id)
                .fetch_one(&pool)
                .await
                .unwrap(),
            1
        );
        renew_bosh_delivery_fences(&pool, session_id, Some((100, &[message_id])), 60)
            .await
            .unwrap();
        assert_eq!(
            acknowledge_bosh_delivery_responses(&pool, session_id, 100)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM offline_messages WHERE id=$1")
                .bind(message_id)
                .fetch_one(&pool)
                .await
                .unwrap(),
            0
        );

        // A non-SM socket takes an exact short claim immediately before its
        // bounded write. Queue acceptance alone cannot authorize deletion,
        // and a crash before acknowledgement leaves the row reclaimable when
        // this lease expires.
        let socket_message = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO offline_messages(id,recipient_id,sender_jid,stanza,encrypted,mam_backed)
             VALUES($1,$2,'sender@example.test','<message id=''socket''/>',FALSE,FALSE)",
        )
        .bind(socket_message)
        .bind(recipient)
        .execute(&pool)
        .await
        .unwrap();
        let unfenced_socket = crate::outbound::DurableDelivery {
            recipient_id: recipient,
            message_id: socket_message,
            claim_id: None,
        };
        let fenced_socket = fence_durable_socket_write(&pool, unfenced_socket)
            .await
            .unwrap();
        assert!(fenced_socket.claim_id.is_some());
        assert!(acknowledge_durable_delivery(&pool, unfenced_socket)
            .await
            .is_err());
        acknowledge_durable_delivery(&pool, fenced_socket)
            .await
            .unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM offline_messages WHERE id=$1")
                .bind(socket_message)
                .fetch_one(&pool)
                .await
                .unwrap(),
            0
        );

        // Once a response lease expires it cannot be renewed or acknowledged
        // by the stale actor. Candidate selection first removes the expired
        // fence, then atomically gives the offline row a fresh replay claim.
        let expired_message = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO offline_messages(id,recipient_id,sender_jid,stanza,encrypted,mam_backed)
             VALUES($1,$2,'sender@example.test','<message id=''expired''/>',FALSE,FALSE)",
        )
        .bind(expired_message)
        .bind(recipient)
        .execute(&pool)
        .await
        .unwrap();
        let expired_delivery = crate::outbound::DurableDelivery {
            recipient_id: recipient,
            message_id: expired_message,
            claim_id: None,
        };
        let expired_session = Uuid::new_v4();
        bind_bosh_delivery_response(&pool, expired_session, 200, &[expired_delivery], 60)
            .await
            .unwrap();
        assert!(
            acknowledge_durable_delivery(&pool, expired_delivery)
                .await
                .is_err(),
            "an unfenced transport ACK must not consume a BOSH-owned live row"
        );
        sqlx::query(
            "UPDATE offline_messages
                SET created_at=clock_timestamp()-INTERVAL '31 days'
              WHERE id=$1",
        )
        .bind(expired_message)
        .execute(&pool)
        .await
        .unwrap();
        let active_lease = acquire_offline_replay_lease(
            &pool,
            recipient,
            "test-replay",
            Uuid::new_v4(),
            None,
            REPLAY_OWNER_LEASE_SECONDS,
        )
        .await
        .unwrap()
        .into_acquired()
        .unwrap();
        let active_fence_probe = claim_offline_replay_page(
            &pool,
            &active_lease,
            30,
            &format!("{username}@example.test"),
            &format!("{username}@example.test/test-replay"),
            None,
            false,
            REPLAY_OWNER_LEASE_SECONDS,
        )
        .await
        .unwrap();
        assert!(matches!(
            active_fence_probe,
            OfflineReplayPageOutcome::Empty
        ));
        assert!(release_offline_replay_lease(&pool, &active_lease)
            .await
            .unwrap());
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM offline_messages WHERE id=$1")
                .bind(expired_message)
                .fetch_one(&pool)
                .await
                .unwrap(),
            1,
            "retention must not delete a BOSH-owned response before client ack"
        );
        sqlx::query(
            "UPDATE bosh_delivery_fences SET expires_at=clock_timestamp()-INTERVAL '1 second'
              WHERE session_id=$1",
        )
        .bind(expired_session)
        .execute(&pool)
        .await
        .unwrap();
        assert!(renew_bosh_delivery_fences(
            &pool,
            expired_session,
            Some((200, &[expired_message])),
            60,
        )
        .await
        .is_err());
        let replay_lease = acquire_offline_replay_lease(
            &pool,
            recipient,
            "test-replay",
            Uuid::new_v4(),
            None,
            REPLAY_OWNER_LEASE_SECONDS,
        )
        .await
        .unwrap()
        .into_acquired()
        .unwrap();
        let page = match claim_offline_replay_page(
            &pool,
            &replay_lease,
            30,
            &format!("{username}@example.test"),
            &format!("{username}@example.test/test-replay"),
            None,
            false,
            REPLAY_OWNER_LEASE_SECONDS,
        )
        .await
        .unwrap()
        {
            OfflineReplayPageOutcome::Claimed(page) => page,
            other => panic!("expected reclaimed BOSH page, got {other:?}"),
        };
        assert_eq!(page.messages.len(), 1);
        assert_eq!(page.messages[0].id, expired_message);
        assert_eq!(
            acknowledge_bosh_delivery_responses(&pool, expired_session, 200)
                .await
                .unwrap(),
            0
        );
        assert!(
            bind_bosh_delivery_response(&pool, expired_session, 200, &[expired_delivery], 60,)
                .await
                .is_err()
        );
        release_untransferred_offline_claims(
            &pool,
            recipient,
            page.claim_token,
            &[expired_message],
        )
        .await
        .unwrap();
        assert!(release_offline_replay_lease(&pool, &replay_lease)
            .await
            .unwrap());

        sqlx::query("DELETE FROM users WHERE id=$1")
            .bind(recipient)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn concurrent_resources_replay_without_starvation_and_fence_wrong_claims() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(std::time::Duration::from_secs(2))
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();
        let recipient = Uuid::new_v4();
        let username = format!("concur{}", &recipient.simple().to_string()[..12]);
        sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test')")
            .bind(recipient)
            .bind(&username)
            .execute(&pool)
            .await
            .unwrap();

        // 1. Insert 1 account-scoped, 1 phone-only, 1 tablet-only message.
        let account_msg =
            insert_resource_replay_message(&pool, recipient, None, "account-wide").await;
        let phone_msg =
            insert_resource_replay_message(&pool, recipient, Some("Phone"), "phone-only").await;
        let tablet_msg =
            insert_resource_replay_message(&pool, recipient, Some("Tablet"), "tablet-only").await;

        // 2. Phone acquires its lease and HOLDS it (does not release).
        let phone_token = Uuid::new_v4();
        let phone_lease = acquire_offline_replay_lease(
            &pool,
            recipient,
            "Phone",
            phone_token,
            None,
            REPLAY_OWNER_LEASE_SECONDS,
        )
        .await
        .unwrap()
        .into_acquired()
        .expect("Phone lease acquisition must succeed");

        // 3. Concurrently, Tablet acquires its lease while Phone is STILL holding its lease.
        // Under the old account-level design, Tablet would return None (starvation).
        // Under the resource-scoped design, Tablet MUST succeed!
        let tablet_token = Uuid::new_v4();
        let tablet_lease = acquire_offline_replay_lease(
            &pool,
            recipient,
            "Tablet",
            tablet_token,
            None,
            REPLAY_OWNER_LEASE_SECONDS,
        )
        .await
        .unwrap()
        .into_acquired()
        .expect("Tablet lease acquisition must succeed in parallel with Phone");

        // 4. Duplicate acquire on Phone's exact resource must be rejected (single-flight per resource).
        let dup_phone = acquire_offline_replay_lease(
            &pool,
            recipient,
            "Phone",
            Uuid::new_v4(),
            None,
            REPLAY_OWNER_LEASE_SECONDS,
        )
        .await
        .unwrap();
        assert!(
            !dup_phone.is_acquired(),
            "duplicate active lease on Phone must be rejected"
        );

        // 5. Both resources claim concurrently. The account-scoped row may be
        // won by either resource, but row-level SKIP LOCKED fencing must make
        // it appear exactly once while each affine row stays on its resource.
        let owner_bare = format!("{username}@example.test");
        let phone_full = format!("{username}@example.test/Phone");
        let tablet_full = format!("{username}@example.test/Tablet");
        let (phone_claim, tablet_claim) = tokio::join!(
            claim_offline_replay_page(
                &pool,
                &phone_lease,
                30,
                &owner_bare,
                &phone_full,
                None,
                false,
                REPLAY_OWNER_LEASE_SECONDS,
            ),
            claim_offline_replay_page(
                &pool,
                &tablet_lease,
                30,
                &owner_bare,
                &tablet_full,
                None,
                false,
                REPLAY_OWNER_LEASE_SECONDS,
            )
        );
        let phone_page = match phone_claim.unwrap() {
            OfflineReplayPageOutcome::Claimed(page) => page,
            other => panic!("expected phone claimed page, got {other:?}"),
        };
        let tablet_page = match tablet_claim.unwrap() {
            OfflineReplayPageOutcome::Claimed(page) => page,
            other => panic!("expected tablet claimed page, got {other:?}"),
        };
        let phone_ids = phone_page
            .messages
            .iter()
            .map(|m| m.id)
            .collect::<std::collections::HashSet<_>>();
        assert!(phone_ids.contains(&phone_msg));
        assert!(!phone_ids.contains(&tablet_msg));

        let tablet_ids = tablet_page
            .messages
            .iter()
            .map(|m| m.id)
            .collect::<std::collections::HashSet<_>>();
        assert!(tablet_ids.contains(&tablet_msg));
        assert!(!tablet_ids.contains(&phone_msg));
        assert_eq!(
            usize::from(phone_ids.contains(&account_msg))
                + usize::from(tablet_ids.contains(&account_msg)),
            1,
            "the account-scoped row must be claimed exactly once"
        );

        // 7. Security: Attempting to use Phone lease to claim Tablet JID must fail.
        let cross_claim = claim_offline_replay_page(
            &pool,
            &phone_lease,
            30,
            &format!("{username}@example.test"),
            &format!("{username}@example.test/Tablet"),
            None,
            false,
            REPLAY_OWNER_LEASE_SECONDS,
        )
        .await;
        assert!(
            cross_claim.is_err(),
            "cross-resource claim must be rejected"
        );

        // 8. Security: Renewing with wrong owner_token must return false.
        let wrong_token_lease = OfflineReplayLease {
            recipient_id: recipient,
            resource: "Phone".to_owned(),
            owner_token: Uuid::new_v4(),
            replay_started_at: phone_lease.replay_started_at,
        };
        let renew_wrong = renew_offline_replay_before_send(
            &pool,
            &wrong_token_lease,
            phone_page.claim_token,
            &[phone_msg],
            REPLAY_OWNER_LEASE_SECONDS,
        )
        .await
        .unwrap();
        assert!(!renew_wrong, "renew with wrong owner token must fail");

        // 9. Security: Renewing with wrong resource must return false.
        let wrong_res_lease = OfflineReplayLease {
            recipient_id: recipient,
            resource: "Desktop".to_owned(),
            owner_token: phone_token,
            replay_started_at: phone_lease.replay_started_at,
        };
        let renew_wrong_res = renew_offline_replay_before_send(
            &pool,
            &wrong_res_lease,
            phone_page.claim_token,
            &[phone_msg],
            REPLAY_OWNER_LEASE_SECONDS,
        )
        .await
        .unwrap();
        assert!(!renew_wrong_res, "renew with wrong resource must fail");

        // 10. Security: Releasing with wrong owner_token or wrong resource must return false.
        assert!(!release_offline_replay_lease(&pool, &wrong_token_lease)
            .await
            .unwrap());
        assert!(!release_offline_replay_lease(&pool, &wrong_res_lease)
            .await
            .unwrap());

        // 11. Clean release.
        assert!(release_offline_replay_lease(&pool, &phone_lease)
            .await
            .unwrap());
        assert!(release_offline_replay_lease(&pool, &tablet_lease)
            .await
            .unwrap());

        // 12. Immutability trigger: updating recipient_id or resource on offline_replay_leases must fail.
        let test_lease = acquire_offline_replay_lease(
            &pool,
            recipient,
            "ImmutableTest",
            Uuid::new_v4(),
            None,
            REPLAY_OWNER_LEASE_SECONDS,
        )
        .await
        .unwrap()
        .into_acquired()
        .unwrap();
        assert!(
            sqlx::query("UPDATE offline_replay_leases SET resource='Modified' WHERE recipient_id=$1 AND resource='ImmutableTest'")
                .bind(recipient)
                .execute(&pool)
                .await
                .is_err()
        );
        let _ = release_offline_replay_lease(&pool, &test_lease).await;

        sqlx::query("DELETE FROM users WHERE id=$1")
            .bind(recipient)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn repeatable_read_account_claim_serialization_retries_with_fresh_snapshot() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(std::time::Duration::from_secs(2))
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();
        let recipient = Uuid::new_v4();
        let username = format!("rrretry{}", &recipient.simple().to_string()[..12]);
        sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test')")
            .bind(recipient)
            .bind(&username)
            .execute(&pool)
            .await
            .unwrap();
        let account_message =
            insert_resource_replay_message(&pool, recipient, None, "rr-account").await;
        let phone_message =
            insert_resource_replay_message(&pool, recipient, Some("Phone"), "rr-phone").await;
        let tablet_message =
            insert_resource_replay_message(&pool, recipient, Some("Tablet"), "rr-tablet").await;
        let phone_lease = acquire_offline_replay_lease(
            &pool,
            recipient,
            "Phone",
            Uuid::new_v4(),
            None,
            REPLAY_OWNER_LEASE_SECONDS,
        )
        .await
        .unwrap()
        .into_acquired()
        .unwrap();
        let tablet_lease = acquire_offline_replay_lease(
            &pool,
            recipient,
            "Tablet",
            Uuid::new_v4(),
            None,
            REPLAY_OWNER_LEASE_SECONDS,
        )
        .await
        .unwrap()
        .into_acquired()
        .unwrap();
        let hook = ReplayClaimTestHook {
            snapshot_fixed: std::sync::Arc::new(tokio::sync::Barrier::new(2)),
            resume_after_competing_commit: std::sync::Arc::new(tokio::sync::Barrier::new(2)),
            fired: std::sync::atomic::AtomicBool::new(false),
            serialization_retries: std::sync::atomic::AtomicUsize::new(0),
        };
        let owner_bare = format!("{username}@example.test");
        let phone_full = format!("{owner_bare}/Phone");
        let tablet_full = format!("{owner_bare}/Tablet");

        let tablet_claim = claim_offline_replay_page_with_test_hook(
            &pool,
            &tablet_lease,
            30,
            &owner_bare,
            &tablet_full,
            None,
            false,
            REPLAY_OWNER_LEASE_SECONDS,
            &hook,
        );
        let phone_claim_after_tablet_snapshot = async {
            hook.snapshot_fixed.wait().await;
            let result = claim_offline_replay_page(
                &pool,
                &phone_lease,
                30,
                &owner_bare,
                &phone_full,
                None,
                false,
                REPLAY_OWNER_LEASE_SECONDS,
            )
            .await;
            hook.resume_after_competing_commit.wait().await;
            result
        };
        let (tablet_claim, phone_claim) =
            tokio::join!(tablet_claim, phone_claim_after_tablet_snapshot);
        let phone_page = match phone_claim.unwrap() {
            OfflineReplayPageOutcome::Claimed(page) => page,
            other => panic!("expected phone page, got {other:?}"),
        };
        let tablet_page = match tablet_claim.unwrap() {
            OfflineReplayPageOutcome::Claimed(page) => page,
            other => panic!("expected tablet page after serialization retry, got {other:?}"),
        };
        assert_eq!(
            hook.serialization_retries
                .load(std::sync::atomic::Ordering::Acquire),
            1,
            "the forced stale RR snapshot must be discarded exactly once"
        );
        let phone_ids = phone_page
            .messages
            .iter()
            .map(|message| message.id)
            .collect::<std::collections::HashSet<_>>();
        let tablet_ids = tablet_page
            .messages
            .iter()
            .map(|message| message.id)
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(
            phone_ids,
            [account_message, phone_message].into_iter().collect()
        );
        assert_eq!(tablet_ids, [tablet_message].into_iter().collect());

        release_untransferred_offline_claims(
            &pool,
            recipient,
            phone_page.claim_token,
            &phone_ids.iter().copied().collect::<Vec<_>>(),
        )
        .await
        .unwrap();
        release_untransferred_offline_claims(
            &pool,
            recipient,
            tablet_page.claim_token,
            &tablet_ids.iter().copied().collect::<Vec<_>>(),
        )
        .await
        .unwrap();
        assert!(release_offline_replay_lease(&pool, &phone_lease)
            .await
            .unwrap());
        assert!(release_offline_replay_lease(&pool, &tablet_lease)
            .await
            .unwrap());
        sqlx::query("DELETE FROM users WHERE id=$1")
            .bind(recipient)
            .execute(&pool)
            .await
            .unwrap();
    }
}
