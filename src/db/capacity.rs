use anyhow::{Context, Result};
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::collections::HashSet;
use uuid::Uuid;

const CAPACITY_SHARDS: i64 = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeploymentCapacityConfiguration {
    pub epoch: i64,
    pub accounts: i64,
    pub muc_rooms: i64,
    pub muc_rooms_per_owner: i64,
    pub live_sessions: i64,
    pub sessions_per_account: i64,
    pub resumable_sessions: i64,
}

impl DeploymentCapacityConfiguration {
    pub fn from_config(config: &crate::config::Config) -> Result<Self> {
        Ok(Self {
            epoch: config.deployment_capacity_epoch,
            accounts: config.max_accounts_total,
            muc_rooms: config.max_muc_rooms_total,
            muc_rooms_per_owner: config.max_muc_rooms_per_owner,
            live_sessions: config.max_live_sessions_total,
            sessions_per_account: i64::try_from(config.max_sessions_per_account)
                .context("MAX_SESSIONS_PER_ACCOUNT is too large")?,
            resumable_sessions: i64::try_from(config.sm_max_resumable_sessions)
                .context("SM_MAX_RESUMABLE_SESSIONS is too large")?,
        })
    }

    fn values(self) -> [(&'static str, i64); 4] {
        [
            ("account", self.accounts),
            ("muc_room", self.muc_rooms),
            ("live_session", self.live_sessions),
            ("sm_session", self.resumable_sessions),
        ]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LiveSessionReservation {
    Reserved,
    ReplacedResumable,
    Conflict,
    CapacityExhausted,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DeploymentCapacitySnapshot {
    pub configuration_epoch: i64,
    pub accounts_used: i64,
    pub accounts_limit: i64,
    pub muc_rooms_used: i64,
    pub muc_rooms_limit: i64,
    pub live_sessions_used: i64,
    pub live_sessions_limit: i64,
    pub resumable_sessions_used: i64,
    pub resumable_sessions_limit: i64,
    pub muc_rooms_per_owner_limit: i64,
    pub sessions_per_account_limit: i64,
}

/// Install or validate the deployment-wide authority before any listener or
/// bootstrap-account mutation starts. A capacity change requires exactly the
/// next epoch. Reusing an epoch with different values and rolling back an epoch
/// both fail closed, which prevents nodes with different local `.env` files
/// from silently enforcing different ceilings.
pub async fn reconcile_deployment_capacity(
    pool: &PgPool,
    configured: DeploymentCapacityConfiguration,
) -> Result<()> {
    let mut tx = pool.begin().await?;
    sqlx::query("SET LOCAL lock_timeout='30s'")
        .execute(&mut *tx)
        .await?;
    // Fixed integer namespace keys are stable across PostgreSQL major
    // versions. Persisted allocation placement and the startup gate must not
    // inherit hashtextextended's version-specific output.
    sqlx::query("SELECT pg_advisory_xact_lock(1314079572,3)")
        .execute(&mut *tx)
        .await
        .context("could not acquire deployment capacity authority gate")?;
    // The startup-only reconciliation may count and rebuild. Runtime creates
    // never do so. Locking authoritative rows and ledger tables together makes
    // the repair one atomic snapshot even when another already-running node
    // shares this PostgreSQL deployment.
    sqlx::query_scalar::<_, bool>("SELECT northstar_session_capacity_reconcile_lock()")
        .fetch_one(&mut *tx)
        .await
        .context("could not lock deployment capacity authority tables")?;

    prepare_expired_live_lease_cleanup(&mut tx).await?;
    sqlx::query_scalar::<_, i64>("SELECT northstar_session_delete_expired_live_leases()")
        .fetch_one(&mut *tx)
        .await?;

    let current = sqlx::query(
        "SELECT configuration_epoch,account_limit,muc_room_limit,
                muc_rooms_per_owner_limit,live_session_limit,
                sessions_per_account_limit,resumable_session_limit
           FROM deployment_capacity_limits WHERE singleton FOR UPDATE",
    )
    .fetch_one(&mut *tx)
    .await?;
    let current_configuration = DeploymentCapacityConfiguration {
        epoch: current.try_get("configuration_epoch")?,
        accounts: current.try_get("account_limit")?,
        muc_rooms: current.try_get("muc_room_limit")?,
        muc_rooms_per_owner: current.try_get("muc_rooms_per_owner_limit")?,
        live_sessions: current.try_get("live_session_limit")?,
        sessions_per_account: current.try_get("sessions_per_account_limit")?,
        resumable_sessions: current.try_get("resumable_session_limit")?,
    };
    validate_authority_transition(current_configuration, configured)?;

    let counts: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT COUNT(*) FROM users),
                (SELECT COUNT(*) FROM muc_rooms WHERE destroyed_at IS NULL),
                (SELECT COUNT(*) FROM deployment_session_leases),
                (SELECT COUNT(*) FROM sm_resume_sessions)",
    )
    .fetch_one(&mut *tx)
    .await?;
    anyhow::ensure!(
        counts.0 <= configured.accounts
            && counts.1 <= configured.muc_rooms
            && counts.2 <= configured.live_sessions
            && counts.3 <= configured.resumable_sessions,
        "configured deployment capacity is below authoritative usage (accounts {}/{}, rooms {}/{}, live sessions {}/{}, SM sessions {}/{})",
        counts.0,
        configured.accounts,
        counts.1,
        configured.muc_rooms,
        counts.2,
        configured.live_sessions,
        counts.3,
        configured.resumable_sessions
    );
    let owner_max: i64 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(n),0) FROM (
             SELECT COUNT(*) n FROM muc_rooms
              WHERE destroyed_at IS NULL AND owner_id IS NOT NULL GROUP BY owner_id
         ) q",
    )
    .fetch_one(&mut *tx)
    .await?;
    let live_account_max: i64 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(n),0) FROM (
             SELECT COUNT(*) n FROM deployment_session_leases GROUP BY user_id
         ) q",
    )
    .fetch_one(&mut *tx)
    .await?;
    let sm_account_max: i64 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(n),0) FROM (
             SELECT COUNT(*) n FROM sm_resume_sessions GROUP BY user_id
         ) q",
    )
    .fetch_one(&mut *tx)
    .await?;
    anyhow::ensure!(
        owner_max <= configured.muc_rooms_per_owner
            && live_account_max <= configured.sessions_per_account
            && sm_account_max <= configured.sessions_per_account,
        "configured per-account capacity is below authoritative usage (rooms {}/{}, live sessions {}/{}, SM sessions {}/{})",
        owner_max,
        configured.muc_rooms_per_owner,
        live_account_max,
        configured.sessions_per_account,
        sm_account_max,
        configured.sessions_per_account
    );

    reconcile_allocations(&mut tx, configured).await?;
    rebuild_account_counters(&mut tx).await?;
    sqlx::query(
        "UPDATE deployment_capacity_limits SET
            configuration_epoch=$1,account_limit=$2,muc_room_limit=$3,
            muc_rooms_per_owner_limit=$4,live_session_limit=$5,
            sessions_per_account_limit=$6,resumable_session_limit=$7,
            configured_at=clock_timestamp()
          WHERE singleton",
    )
    .bind(configured.epoch)
    .bind(configured.accounts)
    .bind(configured.muc_rooms)
    .bind(configured.muc_rooms_per_owner)
    .bind(configured.live_sessions)
    .bind(configured.sessions_per_account)
    .bind(configured.resumable_sessions)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

async fn prepare_expired_live_lease_cleanup(tx: &mut Transaction<'_, Postgres>) -> Result<()> {
    // Expired rows are safe to remove, but their fail-closed DELETE trigger
    // still requires an exact allocation and owner counter. Repair only that
    // doomed subset first so a crash-corrupted/missing ledger row cannot make
    // startup cleanup impossible. Temporary headroom is transaction-local;
    // the configured hard budgets are installed later in the same transaction
    // and nothing is committed if surviving authoritative usage does not fit.
    sqlx::query(
        "UPDATE deployment_capacity_shards s
            SET used=q.used,capacity=GREATEST(s.capacity,q.used)
           FROM (
              SELECT s2.shard,COUNT(a.entity_id)::BIGINT used
                FROM deployment_capacity_shards s2
                LEFT JOIN deployment_capacity_allocations a
                  ON a.resource_kind='live_session' AND a.shard=s2.shard
               WHERE s2.resource_kind='live_session'
               GROUP BY s2.shard
           ) q
          WHERE s.resource_kind='live_session' AND s.shard=q.shard",
    )
    .execute(&mut **tx)
    .await?;
    let missing = sqlx::query_scalar::<_, Uuid>(
        "SELECT s.lease_id FROM deployment_session_leases s
          WHERE s.lease_until<=clock_timestamp()
            AND NOT EXISTS(
                SELECT 1 FROM deployment_capacity_allocations a
                 WHERE a.resource_kind='live_session' AND a.entity_id=s.lease_id
            )
          ORDER BY s.lease_id",
    )
    .fetch_all(&mut **tx)
    .await?;
    if !missing.is_empty() {
        let temporary_headroom = i64::try_from(missing.len())
            .context("too many expired live-session leases to reconcile")?;
        sqlx::query(
            "UPDATE deployment_capacity_shards
                SET capacity=used+$1
              WHERE resource_kind='live_session'",
        )
        .bind(temporary_headroom)
        .execute(&mut **tx)
        .await?;
        for lease_id in missing {
            let allocation = sqlx::query_scalar::<_, Option<i16>>(
                "SELECT northstar_capacity_acquire('live_session',$1)",
            )
            .bind(lease_id)
            .fetch_one(&mut **tx)
            .await?;
            anyhow::ensure!(
                allocation.is_some(),
                "could not restore expired live-session allocation {lease_id} before cleanup"
            );
        }
    }
    sqlx::query("DELETE FROM deployment_account_capacity WHERE resource_kind='live_session'")
        .execute(&mut **tx)
        .await?;
    sqlx::query(
        "INSERT INTO deployment_account_capacity(resource_kind,owner_id,used)
         SELECT 'live_session',user_id,COUNT(*)
           FROM deployment_session_leases GROUP BY user_id",
    )
    .execute(&mut **tx)
    .await?;
    Ok(())
}

fn validate_authority_transition(
    current: DeploymentCapacityConfiguration,
    configured: DeploymentCapacityConfiguration,
) -> Result<()> {
    if current.epoch == 0 {
        anyhow::ensure!(
            configured.epoch == 1,
            "DEPLOYMENT_CAPACITY_EPOCH must adopt bootstrap authority at epoch 1 (configured={})",
            configured.epoch
        );
        return Ok(());
    }
    anyhow::ensure!(
        configured.epoch >= current.epoch,
        "DEPLOYMENT_CAPACITY_EPOCH {} is older than PostgreSQL authority epoch {}",
        configured.epoch,
        current.epoch
    );
    if configured.epoch == current.epoch {
        anyhow::ensure!(
            configured == current,
            "deployment capacity values differ at PostgreSQL authority epoch {}; use the authority values on every node or increment DEPLOYMENT_CAPACITY_EPOCH once",
            configured.epoch
        );
    } else {
        let next_epoch = current
            .epoch
            .checked_add(1)
            .context("PostgreSQL deployment capacity authority epoch is exhausted")?;
        anyhow::ensure!(
            configured.epoch == next_epoch,
            "DEPLOYMENT_CAPACITY_EPOCH must advance by exactly one (database={}, configured={})",
            current.epoch,
            configured.epoch
        );
    }
    Ok(())
}

async fn reconcile_allocations(
    tx: &mut Transaction<'_, Postgres>,
    configured: DeploymentCapacityConfiguration,
) -> Result<()> {
    // Allocation rows are the persisted shard authority. Never re-hash an
    // existing entity during startup: this keeps placement stable across
    // PostgreSQL upgrades. Remove only allocations whose authoritative object
    // is absent, recompute counters, then backfill only missing mappings.
    sqlx::query(
        "DELETE FROM deployment_capacity_allocations a WHERE
             (a.resource_kind='account' AND NOT EXISTS(SELECT 1 FROM users u WHERE u.id=a.entity_id))
          OR (a.resource_kind='muc_room' AND NOT EXISTS(
                SELECT 1 FROM muc_rooms r
                 WHERE r.id=a.entity_id AND r.destroyed_at IS NULL))
          OR (a.resource_kind='live_session' AND NOT EXISTS(SELECT 1 FROM deployment_session_leases s WHERE s.lease_id=a.entity_id))
          OR (a.resource_kind='sm_session' AND NOT EXISTS(SELECT 1 FROM sm_resume_sessions s WHERE s.id=a.entity_id))",
    )
        .execute(&mut **tx)
        .await?;
    sqlx::query(
        "UPDATE deployment_capacity_shards s
            SET used=COALESCE(q.used,0),capacity=GREATEST(s.capacity,COALESCE(q.used,0))
           FROM (
              SELECT kinds.resource_kind,kinds.shard,COUNT(a.entity_id)::BIGINT used
                FROM deployment_capacity_shards kinds
                LEFT JOIN deployment_capacity_allocations a
                  ON a.resource_kind=kinds.resource_kind AND a.shard=kinds.shard
               GROUP BY kinds.resource_kind,kinds.shard
           ) q
          WHERE s.resource_kind=q.resource_kind AND s.shard=q.shard",
    )
    .execute(&mut **tx)
    .await?;

    // Install the requested exact hard budgets before backfilling missing
    // allocations. Existing persisted placement is never re-hashed. If that
    // placement does not fit a lower snapshot, fail closed and require a
    // staged rebalance/limit increase rather than silently moving ownership.
    for (kind, limit) in configured.values() {
        for shard in 0..CAPACITY_SHARDS {
            let hard_budget = shard_budget(limit, shard);
            let shard = i16::try_from(shard).expect("capacity shard fits SMALLINT");
            let used: i64 = sqlx::query_scalar(
                "SELECT used FROM deployment_capacity_shards
                  WHERE resource_kind=$1 AND shard=$2 FOR UPDATE",
            )
            .bind(kind)
            .bind(shard)
            .fetch_one(&mut **tx)
            .await?;
            anyhow::ensure!(
                used <= hard_budget,
                "configured {kind} capacity cannot represent persisted shard {shard}: usage {used}, hard budget {hard_budget}; raise the limit/epoch or perform a staged offline rebalance"
            );
            sqlx::query(
                "UPDATE deployment_capacity_shards SET capacity=$3
                  WHERE resource_kind=$1 AND shard=$2",
            )
            .bind(kind)
            .bind(shard)
            .bind(hard_budget)
            .execute(&mut **tx)
            .await?;
        }
    }

    for (kind, statement) in [
        ("account", "SELECT u.id FROM users u WHERE NOT EXISTS(SELECT 1 FROM deployment_capacity_allocations a WHERE a.resource_kind='account' AND a.entity_id=u.id) ORDER BY u.id"),
        ("muc_room", "SELECT r.id FROM muc_rooms r WHERE r.destroyed_at IS NULL AND NOT EXISTS(SELECT 1 FROM deployment_capacity_allocations a WHERE a.resource_kind='muc_room' AND a.entity_id=r.id) ORDER BY r.id"),
        ("live_session", "SELECT s.lease_id FROM deployment_session_leases s WHERE NOT EXISTS(SELECT 1 FROM deployment_capacity_allocations a WHERE a.resource_kind='live_session' AND a.entity_id=s.lease_id) ORDER BY s.lease_id"),
        ("sm_session", "SELECT s.id FROM sm_resume_sessions s WHERE NOT EXISTS(SELECT 1 FROM deployment_capacity_allocations a WHERE a.resource_kind='sm_session' AND a.entity_id=s.id) ORDER BY s.id"),
    ] {
        let missing = sqlx::query_scalar::<_, Uuid>(statement)
            .fetch_all(&mut **tx)
            .await?;
        for entity in missing {
            let allocation = sqlx::query_scalar::<_, Option<i16>>(
                "SELECT northstar_capacity_acquire($1,$2)",
            )
                .bind(kind)
                .bind(entity)
                .fetch_one(&mut **tx)
                .await?;
            anyhow::ensure!(
                allocation.is_some(),
                "deployment {kind} capacity is full while backfilling authoritative entity {entity}"
            );
        }
    }
    let accounting_matches: bool = sqlx::query_scalar(
        "SELECT NOT EXISTS(
             SELECT 1 FROM deployment_capacity_shards s
             WHERE s.used <> (
                 SELECT COUNT(*) FROM deployment_capacity_allocations a
                  WHERE a.resource_kind=s.resource_kind AND a.shard=s.shard
             )
         )",
    )
    .fetch_one(&mut **tx)
    .await?;
    anyhow::ensure!(
        accounting_matches,
        "deployment capacity shard accounting diverged during reconciliation"
    );
    Ok(())
}

async fn rebuild_account_counters(tx: &mut Transaction<'_, Postgres>) -> Result<()> {
    sqlx::query("DELETE FROM deployment_account_capacity")
        .execute(&mut **tx)
        .await?;
    sqlx::query(
        "INSERT INTO deployment_account_capacity(resource_kind,owner_id,used)
         SELECT 'muc_room',owner_id,COUNT(*) FROM muc_rooms
          WHERE destroyed_at IS NULL AND owner_id IS NOT NULL GROUP BY owner_id",
    )
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "INSERT INTO deployment_account_capacity(resource_kind,owner_id,used)
         SELECT 'live_session',user_id,COUNT(*) FROM deployment_session_leases GROUP BY user_id",
    )
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "INSERT INTO deployment_account_capacity(resource_kind,owner_id,used)
         SELECT 'sm_session',user_id,COUNT(*) FROM sm_resume_sessions GROUP BY user_id",
    )
    .execute(&mut **tx)
    .await?;
    Ok(())
}

fn shard_budget(limit: i64, shard: i64) -> i64 {
    limit / CAPACITY_SHARDS
        + if shard < limit % CAPACITY_SHARDS {
            1
        } else {
            0
        }
}

pub async fn reserve_live_session_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
    connection_id: Uuid,
    user_id: Uuid,
    full_jid: &str,
    lease_seconds: u64,
    allow_resumable_replacement: bool,
) -> Result<LiveSessionReservation> {
    let full_jid = crate::jid::canonical_session_key(full_jid)?;
    let lease_seconds = i64::try_from(lease_seconds).context("capacity lease is too large")?;
    let outcome: String =
        sqlx::query_scalar("SELECT northstar_session_reserve_live($1,$2,$3,$4,$5)")
            .bind(connection_id)
            .bind(user_id)
            .bind(&full_jid)
            .bind(lease_seconds)
            .bind(allow_resumable_replacement)
            .fetch_one(&mut **tx)
            .await?;
    match outcome.as_str() {
        "reserved" => Ok(LiveSessionReservation::Reserved),
        "replaced_resumable" => Ok(LiveSessionReservation::ReplacedResumable),
        "conflict" => Ok(LiveSessionReservation::Conflict),
        "capacity_exhausted" => Ok(LiveSessionReservation::CapacityExhausted),
        other => anyhow::bail!("unknown live-session capability outcome: {other}"),
    }
}

/// Revalidate a phase-one binding reservation while credential state commits.
/// A resumable replacement remains a persistent claim: its old stable lease is
/// transferred only by the post-transport publication callback.
pub async fn finalize_binding_live_session_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
    connection_id: Uuid,
    user_id: Uuid,
    full_jid: &str,
    lease_seconds: u64,
) -> Result<bool> {
    let full_jid = crate::jid::canonical_session_key(full_jid)?;
    let _ = lease_seconds;
    Ok(
        sqlx::query_scalar("SELECT northstar_session_finalize_binding($1,$2,$3)")
            .bind(connection_id)
            .bind(user_id)
            .bind(&full_jid)
            .fetch_one(&mut **tx)
            .await?,
    )
}

/// Transactional form used by authentication publication. The binding lease
/// transfer and staged login epoch can therefore become visible in one commit.
pub(crate) async fn publish_binding_live_session_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
    connection_id: Uuid,
    user_id: Uuid,
    full_jid: &str,
    lease_seconds: u64,
) -> Result<bool> {
    let full_jid = crate::jid::canonical_session_key(full_jid)?;
    let lease_seconds = i64::try_from(lease_seconds).context("capacity lease is too large")?;
    Ok(
        sqlx::query_scalar("SELECT northstar_session_publish_binding($1,$2,$3,$4)")
            .bind(connection_id)
            .bind(user_id)
            .bind(&full_jid)
            .bind(lease_seconds)
            .fetch_one(&mut **tx)
            .await?,
    )
}

#[allow(clippy::too_many_arguments)]
pub async fn transfer_claimed_sm_live_session_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
    sm_session_id: Uuid,
    claim_token: Uuid,
    old_connection_id: Uuid,
    new_connection_id: Uuid,
    user_id: Uuid,
    full_jid: &str,
    lease_seconds: u64,
) -> Result<LiveSessionReservation> {
    let full_jid = crate::jid::canonical_session_key(full_jid)?;
    let lease_seconds = i64::try_from(lease_seconds).context("capacity lease is too large")?;
    let outcome: String =
        sqlx::query_scalar("SELECT northstar_session_transfer_sm($1,$2,$3,$4,$5,$6,$7)")
            .bind(sm_session_id)
            .bind(claim_token)
            .bind(old_connection_id)
            .bind(new_connection_id)
            .bind(user_id)
            .bind(&full_jid)
            .bind(lease_seconds)
            .fetch_one(&mut **tx)
            .await?;
    match outcome.as_str() {
        "reserved" => Ok(LiveSessionReservation::Reserved),
        "replaced_resumable" => Ok(LiveSessionReservation::ReplacedResumable),
        "conflict" => Ok(LiveSessionReservation::Conflict),
        other => anyhow::bail!("unknown SM live-session transfer outcome: {other}"),
    }
}

pub async fn release_live_session(pool: &PgPool, connection_id: Uuid) -> Result<bool> {
    Ok(
        sqlx::query_scalar("SELECT northstar_session_release_live($1)")
            .bind(connection_id)
            .fetch_one(pool)
            .await?,
    )
}

pub async fn refresh_live_session_leases(
    pool: &PgPool,
    connection_ids: &[Uuid],
    lease_seconds: u64,
) -> Result<HashSet<Uuid>> {
    if connection_ids.is_empty() {
        return Ok(HashSet::new());
    }
    let lease_seconds = i64::try_from(lease_seconds).context("capacity lease is too large")?;
    let rows =
        sqlx::query_scalar("SELECT connection_id FROM northstar_session_refresh_live($1,$2)")
            .bind(connection_ids)
            .bind(lease_seconds)
            .fetch_all(pool)
            .await?;
    Ok(rows.into_iter().collect())
}

pub async fn cleanup_expired_live_session_leases(pool: &PgPool, limit: i64) -> Result<u64> {
    let removed: i64 = sqlx::query_scalar("SELECT northstar_session_cleanup_live($1)")
        .bind(limit.clamp(1, 10_000))
        .fetch_one(pool)
        .await?;
    u64::try_from(removed).context("negative live-session cleanup count")
}

pub async fn extend_live_session_lease_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
    connection_id: Uuid,
    lease_seconds: u64,
) -> Result<bool> {
    let lease_seconds = i64::try_from(lease_seconds).context("capacity lease is too large")?;
    Ok(
        sqlx::query_scalar("SELECT northstar_session_extend_live($1,$2)")
            .bind(connection_id)
            .bind(lease_seconds)
            .fetch_one(&mut **tx)
            .await?,
    )
}

#[cfg(test)]
pub async fn deployment_capacity_snapshot(pool: &PgPool) -> Result<DeploymentCapacitySnapshot> {
    let row = sqlx::query(
        "SELECT
            (SELECT configuration_epoch FROM deployment_capacity_limits WHERE singleton) configuration_epoch,
            COALESCE(SUM(used) FILTER (WHERE resource_kind='account'),0)::pg_catalog.int8 accounts_used,
            COALESCE(SUM(capacity) FILTER (WHERE resource_kind='account'),0)::pg_catalog.int8 accounts_limit,
            COALESCE(SUM(used) FILTER (WHERE resource_kind='muc_room'),0)::pg_catalog.int8 muc_rooms_used,
            COALESCE(SUM(capacity) FILTER (WHERE resource_kind='muc_room'),0)::pg_catalog.int8 muc_rooms_limit,
            COALESCE(SUM(used) FILTER (WHERE resource_kind='live_session'),0)::pg_catalog.int8 live_sessions_used,
            COALESCE(SUM(capacity) FILTER (WHERE resource_kind='live_session'),0)::pg_catalog.int8 live_sessions_limit,
            COALESCE(SUM(used) FILTER (WHERE resource_kind='sm_session'),0)::pg_catalog.int8 resumable_sessions_used,
            COALESCE(SUM(capacity) FILTER (WHERE resource_kind='sm_session'),0)::pg_catalog.int8 resumable_sessions_limit,
            (SELECT muc_rooms_per_owner_limit FROM deployment_capacity_limits WHERE singleton) muc_rooms_per_owner_limit,
            (SELECT sessions_per_account_limit FROM deployment_capacity_limits WHERE singleton) sessions_per_account_limit
         FROM deployment_capacity_shards",
    )
    .fetch_one(pool)
    .await?;
    Ok(DeploymentCapacitySnapshot {
        configuration_epoch: row.try_get("configuration_epoch")?,
        accounts_used: row.try_get("accounts_used")?,
        accounts_limit: row.try_get("accounts_limit")?,
        muc_rooms_used: row.try_get("muc_rooms_used")?,
        muc_rooms_limit: row.try_get("muc_rooms_limit")?,
        live_sessions_used: row.try_get("live_sessions_used")?,
        live_sessions_limit: row.try_get("live_sessions_limit")?,
        resumable_sessions_used: row.try_get("resumable_sessions_used")?,
        resumable_sessions_limit: row.try_get("resumable_sessions_limit")?,
        muc_rooms_per_owner_limit: row.try_get("muc_rooms_per_owner_limit")?,
        sessions_per_account_limit: row.try_get("sessions_per_account_limit")?,
    })
}

pub fn is_capacity_exhausted(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<sqlx::Error>()
            .is_some_and(is_capacity_sqlx_error)
            || cause.to_string().contains("capacity exhausted")
    })
}

#[cfg(test)]
mod lock_order_schema_tests {
    #[test]
    fn bulk_capacity_locks_have_one_global_order_and_bounded_retry() {
        let migration = include_str!("../../migrations/0090_deployment_capacity_ledger.sql");
        for required in [
            "northstar_capacity_lock_batch",
            "ORDER BY a.resource_kind,a.shard,a.entity_id",
            "FOR UPDATE OF s,a",
            "WHEN deadlock_detected",
            "attempt>=3",
        ] {
            assert!(
                migration.contains(required),
                "missing capacity lock invariant {required}"
            );
        }
    }
}

fn is_capacity_sqlx_error(error: &sqlx::Error) -> bool {
    error.as_database_error().is_some_and(|database| {
        database.code().as_deref() == Some("P0001")
            && database.message().contains("capacity exhausted")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn shard_budgets_sum_to_exact_limit() {
        for limit in [1, 63, 64, 65, 1_000, 4_096, 100_003] {
            let budgets = (0..CAPACITY_SHARDS)
                .map(|shard| shard_budget(limit, shard))
                .collect::<Vec<_>>();
            assert_eq!(budgets.iter().sum::<i64>(), limit);
            assert!(budgets.iter().all(|budget| *budget >= 0));
            assert!(budgets.iter().max().unwrap() - budgets.iter().min().unwrap() <= 1);
        }
    }

    #[test]
    fn authority_epoch_is_monotonic_and_snapshot_fenced() {
        let current = DeploymentCapacityConfiguration {
            epoch: 7,
            accounts: 100,
            muc_rooms: 50,
            muc_rooms_per_owner: 10,
            live_sessions: 200,
            sessions_per_account: 8,
            resumable_sessions: 200,
        };
        assert!(validate_authority_transition(current, current).is_ok());
        assert!(validate_authority_transition(
            current,
            DeploymentCapacityConfiguration {
                epoch: 8,
                accounts: 101,
                ..current
            }
        )
        .is_ok());
        assert!(validate_authority_transition(
            current,
            DeploymentCapacityConfiguration {
                accounts: 101,
                ..current
            }
        )
        .is_err());
        assert!(validate_authority_transition(
            current,
            DeploymentCapacityConfiguration {
                epoch: 6,
                ..current
            }
        )
        .is_err());
        assert!(validate_authority_transition(
            current,
            DeploymentCapacityConfiguration {
                epoch: 9,
                ..current
            }
        )
        .is_err());
        let bootstrap = DeploymentCapacityConfiguration {
            epoch: 0,
            ..current
        };
        assert!(validate_authority_transition(
            bootstrap,
            DeploymentCapacityConfiguration {
                epoch: 1,
                ..current
            }
        )
        .is_ok());
        assert!(validate_authority_transition(bootstrap, current).is_err());
    }

    #[test]
    fn capacity_error_classification_is_narrow_and_stable() {
        assert!(is_capacity_exhausted(&anyhow::anyhow!(
            "deployment live-session capacity exhausted"
        )));
        assert!(!is_capacity_exhausted(&anyhow::anyhow!(
            "database unavailable"
        )));
    }

    #[test]
    fn destroyed_muc_rooms_release_capacity_once_and_are_not_backfilled() {
        let migration = include_str!("../../migrations/0090_deployment_capacity_ledger.sql");
        assert!(migration.contains("northstar_muc_capacity_destroy_update"));
        assert!(migration.contains("OLD.destroyed_at IS NULL AND NEW.destroyed_at IS NOT NULL"));
        assert!(migration.contains("Do not transfer/release that owner a second time"));
        assert!(migration.contains("WHERE destroyed_at IS NULL ORDER BY id"));
        assert!(migration.contains("ELSIF OLD.destroyed_at IS NULL"));
        assert!(migration.contains("muc_rooms_deployment_capacity_destroy_update"));
    }

    #[test]
    fn session_authorities_are_capability_only_and_secret_columns_stay_private() {
        let migration = include_str!("../../migrations/0114_session_authority_capabilities.sql");
        let grants = include_str!("../../deploy/postgres-init/lib/apply-northstar-grants.sql");
        assert!(!migration.contains("public."));
        for required in [
            "northstar_session_reserve_live",
            "northstar_session_transfer_sm",
            "northstar_sm_claim",
            "northstar_sm_activate",
            "northstar_sm_take_teardown",
            "northstar_session_capability_catalog_healthy",
            "REVOKE ALL ON TABLE deployment_session_leases",
        ] {
            assert!(migration.contains(required), "missing {required}");
        }
        assert!(grants
            .contains("runtime session leases and SM bearer state violate capability-only ACLs"));
        assert!(grants.contains("'token_hash','SELECT'"));
        assert!(grants.contains("'claim_token','SELECT'"));
        assert_eq!(
            grants
                .matches("northstar_sm_claim(bytea,uuid,inet,uuid,text,bool,uuid,int8)")
                .count(),
            3
        );
        assert_eq!(
            grants
                .matches("northstar_session_reserve_live(uuid,uuid,text,int8,bool)")
                .count(),
            3
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
    async fn postgres_capacity_fixture_is_atomic_leased_and_idempotent() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let admin = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(60))
            .connect(&url)
            .await
            .unwrap();
        let schema = format!("capacity_test_{}", Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&admin)
            .await
            .unwrap();
        let connection_schema = schema.clone();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
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
        let authority = DeploymentCapacityConfiguration {
            epoch: 1,
            accounts: 1,
            muc_rooms: 64,
            muc_rooms_per_owner: 2,
            live_sessions: 64,
            sessions_per_account: 2,
            resumable_sessions: 64,
        };
        reconcile_deployment_capacity(&pool, authority)
            .await
            .unwrap();
        let user_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO users(id,username,password_hash) VALUES($1,'capacity-owner','test')",
        )
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
        let account_rejected = sqlx::query(
            "INSERT INTO users(id,username,password_hash) VALUES($1,'capacity-second','test')",
        )
        .bind(Uuid::new_v4())
        .execute(&pool)
        .await
        .unwrap_err();
        assert!(is_capacity_sqlx_error(&account_rejected));

        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        for (connection, resource) in [(first, "one"), (second, "two")] {
            let mut tx = pool.begin().await.unwrap();
            assert_eq!(
                reserve_live_session_in_transaction(
                    &mut tx,
                    connection,
                    user_id,
                    &format!("capacity-owner@example.test/{resource}"),
                    120,
                    false,
                )
                .await
                .unwrap(),
                LiveSessionReservation::Reserved
            );
            tx.commit().await.unwrap();
        }
        let mut rejected = pool.begin().await.unwrap();
        assert_eq!(
            reserve_live_session_in_transaction(
                &mut rejected,
                Uuid::new_v4(),
                user_id,
                "capacity-owner@example.test/three",
                120,
                false,
            )
            .await
            .unwrap(),
            LiveSessionReservation::CapacityExhausted
        );
        rejected.rollback().await.unwrap();
        let transferred = Uuid::new_v4();
        let mut transfer = pool.begin().await.unwrap();
        sqlx::query(
            "UPDATE deployment_session_leases
                SET connection_id=$2,updated_at=clock_timestamp()
              WHERE connection_id=$1",
        )
        .bind(first)
        .bind(transferred)
        .execute(&mut *transfer)
        .await
        .unwrap();
        transfer.commit().await.unwrap();
        let stable_allocation: bool = sqlx::query_scalar(
            "SELECT EXISTS(
                 SELECT 1 FROM deployment_capacity_allocations
                  WHERE resource_kind='live_session' AND entity_id=$1
             ) AND NOT EXISTS(
                 SELECT 1 FROM deployment_capacity_allocations
                  WHERE resource_kind='live_session' AND entity_id=$2
             )",
        )
        .bind(first)
        .bind(transferred)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(stable_allocation);
        assert!(!release_live_session(&pool, first).await.unwrap());
        assert!(release_live_session(&pool, transferred).await.unwrap());
        assert!(!release_live_session(&pool, transferred).await.unwrap());

        sqlx::query("UPDATE deployment_session_leases SET lease_until=clock_timestamp()-INTERVAL '1 second' WHERE connection_id=$1")
            .bind(second)
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            cleanup_expired_live_session_leases(&pool, 10)
                .await
                .unwrap(),
            1
        );
        let live_owner_counter_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(
                 SELECT 1 FROM deployment_account_capacity
                  WHERE resource_kind='live_session' AND owner_id=$1
             )",
        )
        .bind(user_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(!live_owner_counter_exists);

        for localpart in ["room-one", "room-two"] {
            sqlx::query("INSERT INTO muc_rooms(id,localpart,owner_id) VALUES($1,$2,$3)")
                .bind(Uuid::new_v4())
                .bind(localpart)
                .bind(user_id)
                .execute(&pool)
                .await
                .unwrap();
        }
        let owner_rejected =
            sqlx::query("INSERT INTO muc_rooms(id,localpart,owner_id) VALUES($1,'room-three',$2)")
                .bind(Uuid::new_v4())
                .bind(user_id)
                .execute(&pool)
                .await
                .unwrap_err();
        assert!(is_capacity_sqlx_error(&owner_rejected));

        let snapshot = deployment_capacity_snapshot(&pool).await.unwrap();
        assert_eq!(snapshot.accounts_used, 1);
        assert_eq!(snapshot.muc_rooms_used, 2);
        assert_eq!(snapshot.live_sessions_used, 0);
        sqlx::query("DELETE FROM users WHERE id=$1")
            .bind(user_id)
            .execute(&pool)
            .await
            .unwrap();
        let room_owner_counter_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(
                 SELECT 1 FROM deployment_account_capacity
                  WHERE resource_kind='muc_room' AND owner_id=$1
             )",
        )
        .bind(user_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(!room_owner_counter_exists);
        let final_snapshot = deployment_capacity_snapshot(&pool).await.unwrap();
        assert_eq!(final_snapshot.accounts_used, 0);

        pool.close().await;
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&admin)
            .await
            .unwrap();
    }
}
