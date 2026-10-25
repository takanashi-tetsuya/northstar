use anyhow::{Context, Result};
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::collections::{BTreeMap, BTreeSet, HashSet};
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
    pub fn from_config(config: &crate::platform::config::Config) -> Result<Self> {
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

#[cfg(test)]
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
    sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        .execute(&mut *tx)
        .await?;
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

    // Protect exact mappings AND shared accounting before any repair write.
    // The DB transaction timestamp predates lock wait, conservatively retaining
    // rows that expire while startup waits. All P/D decisions reuse it.
    let protected_ids = sqlx::query_scalar::<_, Uuid>(
        "SELECT lease_id FROM deployment_session_leases
          WHERE lease_until<=transaction_timestamp()
            AND northstar_session_recovery_retention(lease_id,transaction_timestamp())
                  IN ('opportunity','resume_claim') ORDER BY lease_id",
    )
    .fetch_all(&mut *tx)
    .await?;
    let protected = read_retention_projection(&mut tx, &protected_ids).await?;
    let mut retention_delta = RetentionRepairDelta::default();
    prepare_expired_live_lease_cleanup(&mut tx, &protected, &mut retention_delta).await?;
    delete_doomed_live_leases(&mut tx, &protected, &mut retention_delta).await?;

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
    let reconciliation_required =
        authority_reconciliation_required(current_configuration, configured)?;
    if !reconciliation_required
        && deployment_capacity_authority_is_consistent(&mut tx, configured).await?
    {
        // A peer has already committed this exact authority epoch and its
        // immutable ledgers still agree with the live entities. Do not turn
        // every process start into a global repair write: runtime mutations
        // maintain these ledgers atomically, while any detected divergence
        // below deliberately takes the slower recovery path.
        let final_projection = read_retention_projection(&mut tx, &protected_ids).await?;
        protected.validate_final(
            &final_projection,
            &retention_delta,
            configured.live_sessions,
        )?;
        tx.commit().await?;
        return Ok(());
    }

    // Only bootstrap, a deliberate epoch transition, or an audited divergence
    // reaches the repair-only lock. This preserves the recovery authority
    // without making ordinary peer startup serialize the full deployment.

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

    reconcile_allocations(&mut tx, configured, &protected, &mut retention_delta).await?;
    rebuild_account_counters(&mut tx, &protected).await?;
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
    let final_projection = read_retention_projection(&mut tx, &protected_ids).await?;
    protected.validate_final(
        &final_projection,
        &retention_delta,
        configured.live_sessions,
    )?;
    tx.commit().await?;
    Ok(())
}

async fn prepare_expired_live_lease_cleanup(
    tx: &mut Transaction<'_, Postgres>,
    protected: &ProtectedRetentionProjection,
    delta: &mut RetentionRepairDelta,
) -> Result<()> {
    // Only expired, unprotected D rows may be removed. Their DELETE trigger
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
          WHERE s.resource_kind='live_session' AND s.shard=q.shard
            AND NOT (s.shard=ANY($1))",
    )
    .bind(protected.shard_ids())
    .execute(&mut **tx)
    .await?;
    let missing = sqlx::query_scalar::<_, Uuid>(
        "SELECT s.lease_id FROM deployment_session_leases s
          WHERE s.lease_until<=transaction_timestamp()
            AND northstar_session_recovery_retention(s.lease_id,transaction_timestamp())='none'
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
            anyhow::ensure!(
                !protected.bindings.contains_key(&lease_id),
                "protected SM allocation cannot be repaired before cleanup"
            );
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
            record_retention_allocation_addition(tx, lease_id, delta).await?;
        }
    }
    sqlx::query("DELETE FROM deployment_account_capacity WHERE resource_kind='live_session' AND NOT (owner_id=ANY($1))")
        .bind(protected.owner_ids())
        .execute(&mut **tx)
        .await?;
    sqlx::query(
        "INSERT INTO deployment_account_capacity(resource_kind,owner_id,used)
         SELECT 'live_session',user_id,COUNT(*)
           FROM deployment_session_leases WHERE NOT (user_id=ANY($1)) GROUP BY user_id",
    )
    .bind(protected.owner_ids())
    .execute(&mut **tx)
    .await?;
    Ok(())
}

// This is a startup integrity projection, not a second SM eligibility model.
// PostgreSQL alone classifies P at transaction_timestamp() under the existing
// reconciliation table locks. Keep complete shared sets so a neighbor's valid
// release/acquire can be distinguished from repair of a protected charge.
#[derive(Clone, Debug, Eq, PartialEq)]
struct RetentionAllocation {
    shard: i16,
    created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RetentionBinding {
    connection_id: Uuid,
    user_id: Uuid,
    full_jid: String,
    lease_until: chrono::DateTime<chrono::Utc>,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
    allocation: RetentionAllocation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RetentionShard {
    used: i64,
    capacity: i64,
}

#[derive(Clone, Debug, Default)]
struct ProtectedRetentionProjection {
    bindings: BTreeMap<Uuid, RetentionBinding>,
    shards: BTreeMap<i16, RetentionShard>,
    owners: BTreeMap<Uuid, i64>,
    allocations: BTreeMap<Uuid, RetentionAllocation>,
    owner_leases: BTreeMap<Uuid, Uuid>,
}

#[derive(Default)]
struct RetentionRepairDelta {
    added_allocations: BTreeMap<Uuid, RetentionAllocation>,
    removed_allocations: BTreeMap<Uuid, RetentionAllocation>,
    deleted_leases: BTreeMap<Uuid, Uuid>,
}

impl ProtectedRetentionProjection {
    fn shard_ids(&self) -> Vec<i16> {
        self.shards.keys().copied().collect()
    }

    fn owner_ids(&self) -> Vec<Uuid> {
        self.owners.keys().copied().collect()
    }

    fn validate_integrity(&self) -> Result<()> {
        for (id, binding) in &self.bindings {
            anyhow::ensure!(
                self.allocations.get(id) == Some(&binding.allocation)
                    && self.shards.contains_key(&binding.allocation.shard)
                    && self.owner_leases.get(id) == Some(&binding.user_id)
                    && self.owners.contains_key(&binding.user_id),
                "protected SM binding lost its exact allocation or owner charge"
            );
        }
        let mut shard_counts = BTreeMap::<i16, i64>::new();
        for allocation in self.allocations.values() {
            anyhow::ensure!(
                self.shards.contains_key(&allocation.shard),
                "SM retention projection contains an undeclared shared shard"
            );
            let count = shard_counts.entry(allocation.shard).or_default();
            *count = count
                .checked_add(1)
                .context("protected SM shard count overflow")?;
        }
        let mut owner_counts = BTreeMap::<Uuid, i64>::new();
        for owner in self.owner_leases.values() {
            anyhow::ensure!(
                self.owners.contains_key(owner),
                "SM retention projection contains an undeclared shared owner"
            );
            let count = owner_counts.entry(*owner).or_default();
            *count = count
                .checked_add(1)
                .context("protected SM owner count overflow")?;
        }
        for (shard, counter) in &self.shards {
            let actual = shard_counts.get(shard).copied().unwrap_or(0);
            anyhow::ensure!(
                counter.used == actual && counter.used >= 0 && counter.used <= counter.capacity,
                "protected SM shard accounting is corrupt before repair or after reconciliation"
            );
        }
        for (owner, used) in &self.owners {
            let actual = owner_counts.get(owner).copied().unwrap_or(0);
            anyhow::ensure!(
                *used == actual && *used >= 0,
                "protected SM account accounting is corrupt before repair or after reconciliation"
            );
        }
        Ok(())
    }

    fn validate_final(
        &self,
        final_projection: &Self,
        delta: &RetentionRepairDelta,
        live_session_limit: i64,
    ) -> Result<()> {
        self.validate_integrity()?;
        final_projection.validate_integrity()?;
        anyhow::ensure!(
            self.bindings == final_projection.bindings,
            "protected SM binding/allocation identity changed during startup"
        );
        anyhow::ensure!(
            self.shards.keys().eq(final_projection.shards.keys())
                && self.owners.keys().eq(final_projection.owners.keys()),
            "protected SM shared-accounting identity changed during startup"
        );
        for id in self.bindings.keys() {
            anyhow::ensure!(
                !delta.added_allocations.contains_key(id)
                    && !delta.removed_allocations.contains_key(id)
                    && !delta.deleted_leases.contains_key(id),
                "protected SM identity entered a repair or deletion set"
            );
        }
        let mut expected_allocations = self.allocations.clone();
        for (id, removed) in &delta.removed_allocations {
            if self.shards.contains_key(&removed.shard) {
                if let Some(original) = expected_allocations.remove(id) {
                    anyhow::ensure!(
                        original == *removed,
                        "removed SM allocation identity changed"
                    );
                } else {
                    anyhow::ensure!(
                        delta.added_allocations.get(id) == Some(removed),
                        "unexplained protected-shard allocation removal"
                    );
                }
            }
        }
        for (id, added) in &delta.added_allocations {
            if self.shards.contains_key(&added.shard) {
                if let Some(removed) = delta.removed_allocations.get(id) {
                    anyhow::ensure!(
                        removed == added,
                        "temporary doomed allocation changed identity"
                    );
                } else {
                    anyhow::ensure!(
                        expected_allocations.insert(*id, added.clone()).is_none(),
                        "existing SM allocation was reacquired during startup"
                    );
                }
            }
        }
        anyhow::ensure!(
            expected_allocations == final_projection.allocations,
            "protected SM shard changed outside exact allowed repair deltas"
        );
        let mut expected_leases = self.owner_leases.clone();
        for (id, owner) in &delta.deleted_leases {
            if self.owners.contains_key(owner) {
                anyhow::ensure!(
                    expected_leases.remove(id) == Some(*owner),
                    "deleted SM neighbor was not an exact prechecked lease"
                );
            }
        }
        anyhow::ensure!(
            expected_leases == final_projection.owner_leases,
            "protected SM owner changed outside actual doomed-neighbor deletion"
        );
        for (shard, counter) in &final_projection.shards {
            anyhow::ensure!(
                counter.capacity == shard_budget(live_session_limit, i64::from(*shard)),
                "protected SM shard capacity disagrees with the configured authority epoch"
            );
        }
        // Integrity plus exact complete-set comparisons above imply used =
        // previous used + actual added - actual removed on protected shards,
        // and previous owner used - actual deleted D neighbors. A temporary D
        // allocation present in both delta sets has net zero charge.
        Ok(())
    }
}

async fn read_retention_projection(
    tx: &mut Transaction<'_, Postgres>,
    protected_ids: &[Uuid],
) -> Result<ProtectedRetentionProjection> {
    let mut projection = ProtectedRetentionProjection::default();
    if protected_ids.is_empty() {
        return Ok(projection);
    }
    let rows = sqlx::query(
        "SELECT lease.lease_id,lease.connection_id,lease.user_id,lease.full_jid,
                lease.lease_until,lease.created_at,lease.updated_at,
                allocation.shard,allocation.created_at AS allocation_created_at
           FROM deployment_session_leases lease
           LEFT JOIN deployment_capacity_allocations allocation
             ON allocation.resource_kind='live_session' AND allocation.entity_id=lease.lease_id
          WHERE lease.lease_id=ANY($1) ORDER BY lease.lease_id",
    )
    .bind(protected_ids)
    .fetch_all(&mut **tx)
    .await?;
    for row in rows {
        let shard: Option<i16> = row.try_get("shard")?;
        let allocation_created_at: Option<chrono::DateTime<chrono::Utc>> =
            row.try_get("allocation_created_at")?;
        let allocation = RetentionAllocation {
            shard: shard.context("protected SM binding is missing its existing allocation")?,
            created_at: allocation_created_at
                .context("protected SM binding is missing its allocation identity")?,
        };
        projection.bindings.insert(
            row.try_get("lease_id")?,
            RetentionBinding {
                connection_id: row.try_get("connection_id")?,
                user_id: row.try_get("user_id")?,
                full_jid: row.try_get("full_jid")?,
                lease_until: row.try_get("lease_until")?,
                created_at: row.try_get("created_at")?,
                updated_at: row.try_get("updated_at")?,
                allocation,
            },
        );
    }
    anyhow::ensure!(
        projection.bindings.len() == protected_ids.len(),
        "protected SM binding disappeared during startup"
    );
    let shards = projection
        .bindings
        .values()
        .map(|b| b.allocation.shard)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let owners = projection
        .bindings
        .values()
        .map(|b| b.user_id)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let rows = sqlx::query(
        "SELECT shard,used,capacity FROM deployment_capacity_shards
          WHERE resource_kind='live_session' AND shard=ANY($1) ORDER BY shard",
    )
    .bind(&shards)
    .fetch_all(&mut **tx)
    .await?;
    for row in rows {
        projection.shards.insert(
            row.try_get("shard")?,
            RetentionShard {
                used: row.try_get("used")?,
                capacity: row.try_get("capacity")?,
            },
        );
    }
    let rows = sqlx::query(
        "SELECT owner_id,used FROM deployment_account_capacity
          WHERE resource_kind='live_session' AND owner_id=ANY($1) ORDER BY owner_id",
    )
    .bind(&owners)
    .fetch_all(&mut **tx)
    .await?;
    for row in rows {
        projection
            .owners
            .insert(row.try_get("owner_id")?, row.try_get("used")?);
    }
    let rows = sqlx::query(
        "SELECT entity_id,shard,created_at FROM deployment_capacity_allocations
          WHERE resource_kind='live_session' AND shard=ANY($1) ORDER BY entity_id",
    )
    .bind(&shards)
    .fetch_all(&mut **tx)
    .await?;
    for row in rows {
        projection.allocations.insert(
            row.try_get("entity_id")?,
            RetentionAllocation {
                shard: row.try_get("shard")?,
                created_at: row.try_get("created_at")?,
            },
        );
    }
    let rows = sqlx::query(
        "SELECT lease_id,user_id FROM deployment_session_leases
          WHERE user_id=ANY($1) ORDER BY lease_id",
    )
    .bind(&owners)
    .fetch_all(&mut **tx)
    .await?;
    for row in rows {
        projection
            .owner_leases
            .insert(row.try_get("lease_id")?, row.try_get("user_id")?);
    }
    projection.validate_integrity()?;
    // These projections are proportional to P and its shared accounting sets,
    // not constant-space. Later startup qualification must measure peak memory.
    tracing::debug!(
        protected_bindings = projection.bindings.len(),
        shared_allocations = projection.allocations.len(),
        shared_owner_leases = projection.owner_leases.len(),
        "captured protected SM retention accounting projection"
    );
    Ok(projection)
}

async fn record_retention_allocation_addition(
    tx: &mut Transaction<'_, Postgres>,
    entity: Uuid,
    delta: &mut RetentionRepairDelta,
) -> Result<()> {
    let row = sqlx::query(
        "SELECT shard,created_at FROM deployment_capacity_allocations
          WHERE resource_kind='live_session' AND entity_id=$1",
    )
    .bind(entity)
    .fetch_one(&mut **tx)
    .await?;
    anyhow::ensure!(
        delta
            .added_allocations
            .insert(
                entity,
                RetentionAllocation {
                    shard: row.try_get("shard")?,
                    created_at: row.try_get("created_at")?,
                }
            )
            .is_none(),
        "live-session allocation was acquired twice during startup"
    );
    Ok(())
}

async fn delete_doomed_live_leases(
    tx: &mut Transaction<'_, Postgres>,
    protected: &ProtectedRetentionProjection,
    delta: &mut RetentionRepairDelta,
) -> Result<()> {
    // Table locks and the one trusted startup time make this the same D as
    // the no-argument mutation capability. Record actual pre-delete identities
    // after temporary missing-allocation repair, including its net-zero rows.
    let rows = sqlx::query(
        "SELECT lease.lease_id,lease.user_id,allocation.shard,allocation.created_at
           FROM deployment_session_leases lease
           JOIN deployment_capacity_allocations allocation
             ON allocation.resource_kind='live_session' AND allocation.entity_id=lease.lease_id
          WHERE lease.lease_until<=transaction_timestamp()
            AND northstar_session_recovery_retention(lease.lease_id,transaction_timestamp())='none'
          ORDER BY lease.lease_id",
    )
    .fetch_all(&mut **tx)
    .await?;
    let mut deleted = BTreeMap::new();
    let mut removed = BTreeMap::new();
    for row in rows {
        let id: Uuid = row.try_get("lease_id")?;
        anyhow::ensure!(
            !protected.bindings.contains_key(&id),
            "protected SM lease entered D"
        );
        deleted.insert(id, row.try_get::<Uuid, _>("user_id")?);
        removed.insert(
            id,
            RetentionAllocation {
                shard: row.try_get("shard")?,
                created_at: row.try_get("created_at")?,
            },
        );
    }
    let count =
        sqlx::query_scalar::<_, i64>("SELECT northstar_session_delete_expired_live_leases()")
            .fetch_one(&mut **tx)
            .await?;
    anyhow::ensure!(
        count == i64::try_from(deleted.len())?,
        "startup reaper deleted a different exact doomed set"
    );
    let remaining: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM deployment_session_leases WHERE lease_id=ANY($1))",
    )
    .bind(deleted.keys().copied().collect::<Vec<_>>())
    .fetch_one(&mut **tx)
    .await?;
    anyhow::ensure!(
        !remaining,
        "startup reaper retained a recorded doomed lease"
    );
    delta.deleted_leases.extend(deleted);
    delta.removed_allocations.extend(removed);
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

fn authority_reconciliation_required(
    current: DeploymentCapacityConfiguration,
    configured: DeploymentCapacityConfiguration,
) -> Result<bool> {
    validate_authority_transition(current, configured)?;
    Ok(current != configured)
}

/// Check the durable projections that ordinary runtime mutations keep atomic.
/// The caller already owns the deployment advisory gate, so a false result is
/// safe to hand to the repair-only path below. This query intentionally has no
/// side effects: healthy peers may verify a committed epoch without rewriting
/// allocation placement, counters, or the capacity-limit timestamp.
async fn deployment_capacity_authority_is_consistent(
    tx: &mut Transaction<'_, Postgres>,
    configured: DeploymentCapacityConfiguration,
) -> Result<bool> {
    sqlx::query_scalar(
        r#"WITH requested_limits(resource_kind, requested_limit) AS (
               VALUES
                 ('account'::text, $1::bigint),
                 ('muc_room'::text, $2::bigint),
                 ('live_session'::text, $3::bigint),
                 ('sm_session'::text, $4::bigint)
           ), expected_shards AS (
               SELECT requested_limits.resource_kind, shards.shard::smallint AS shard,
                      (requested_limits.requested_limit / 64)
                        + CASE WHEN shards.shard < (requested_limits.requested_limit % 64)
                               THEN 1 ELSE 0 END AS capacity
                 FROM requested_limits CROSS JOIN generate_series(0, 63) AS shards(shard)
           ), expected_entities(resource_kind, entity_id) AS (
               SELECT 'account'::text, id FROM users
               UNION ALL
               SELECT 'muc_room'::text, id FROM muc_rooms WHERE destroyed_at IS NULL
               UNION ALL
               SELECT 'live_session'::text, lease_id FROM deployment_session_leases
               UNION ALL
               SELECT 'sm_session'::text, id FROM sm_resume_sessions
           ), actual_entities(resource_kind, entity_id) AS (
               SELECT resource_kind, entity_id FROM deployment_capacity_allocations
           ), expected_counters(resource_kind, owner_id, used) AS (
               SELECT 'muc_room'::text, owner_id, COUNT(*)::bigint FROM muc_rooms
                WHERE destroyed_at IS NULL AND owner_id IS NOT NULL GROUP BY owner_id
               UNION ALL
               SELECT 'live_session'::text, user_id, COUNT(*)::bigint
                 FROM deployment_session_leases GROUP BY user_id
               UNION ALL
               SELECT 'sm_session'::text, user_id, COUNT(*)::bigint
                 FROM sm_resume_sessions GROUP BY user_id
           ), actual_counters(resource_kind, owner_id, used) AS (
               SELECT resource_kind, owner_id, used FROM deployment_account_capacity
                WHERE resource_kind IN ('muc_room', 'live_session', 'sm_session')
           )
           SELECT (SELECT COUNT(*) = 256 FROM deployment_capacity_shards)
              AND NOT EXISTS(
                  SELECT 1 FROM expected_shards expected
                   FULL OUTER JOIN deployment_capacity_shards actual
                     ON actual.resource_kind = expected.resource_kind
                    AND actual.shard = expected.shard
                   WHERE actual.resource_kind IS NULL OR expected.resource_kind IS NULL
                      OR actual.capacity <> expected.capacity
              )
              AND NOT EXISTS(
                  SELECT 1 FROM deployment_capacity_shards shard
                   WHERE shard.used <> (
                      SELECT COUNT(*) FROM deployment_capacity_allocations allocation
                       WHERE allocation.resource_kind = shard.resource_kind
                         AND allocation.shard = shard.shard
                   )
              )
              AND NOT EXISTS(
                  SELECT resource_kind, entity_id FROM expected_entities
                  EXCEPT SELECT resource_kind, entity_id FROM actual_entities
              )
              AND NOT EXISTS(
                  SELECT resource_kind, entity_id FROM actual_entities
                  EXCEPT SELECT resource_kind, entity_id FROM expected_entities
              )
              AND NOT EXISTS(
                  SELECT 1 FROM deployment_session_leases
                   WHERE lease_until <= transaction_timestamp()
                     AND northstar_session_recovery_retention(lease_id,transaction_timestamp())='none' 
              )
              AND NOT EXISTS(
                  SELECT resource_kind, owner_id, used FROM expected_counters
                  EXCEPT SELECT resource_kind, owner_id, used FROM actual_counters
              )
              AND NOT EXISTS(
                  SELECT resource_kind, owner_id, used FROM actual_counters
                  EXCEPT SELECT resource_kind, owner_id, used FROM expected_counters
              )"#,
    )
    .bind(configured.accounts)
    .bind(configured.muc_rooms)
    .bind(configured.live_sessions)
    .bind(configured.resumable_sessions)
    .fetch_one(&mut **tx)
    .await
    .context("could not audit deployment capacity authority")
}

async fn reconcile_allocations(
    tx: &mut Transaction<'_, Postgres>,
    configured: DeploymentCapacityConfiguration,
    protected: &ProtectedRetentionProjection,
    delta: &mut RetentionRepairDelta,
) -> Result<()> {
    // Allocation rows are the persisted shard authority. Never re-hash an
    // existing entity during startup: this keeps placement stable across
    // PostgreSQL upgrades. Remove only allocations whose authoritative object
    // is absent, recompute counters, then backfill only missing mappings.
    let removed = sqlx::query(
        "DELETE FROM deployment_capacity_allocations a WHERE
             (a.resource_kind='account' AND NOT EXISTS(SELECT 1 FROM users u WHERE u.id=a.entity_id))
          OR (a.resource_kind='muc_room' AND NOT EXISTS(
                SELECT 1 FROM muc_rooms r
                 WHERE r.id=a.entity_id AND r.destroyed_at IS NULL))
          OR (a.resource_kind='live_session' AND NOT EXISTS(SELECT 1 FROM deployment_session_leases s WHERE s.lease_id=a.entity_id))
          OR (a.resource_kind='sm_session' AND NOT EXISTS(SELECT 1 FROM sm_resume_sessions s WHERE s.id=a.entity_id))
          RETURNING a.resource_kind,a.entity_id,a.shard,a.created_at",
    )
        .fetch_all(&mut **tx)
        .await?;
    let mut protected_shard_removals = BTreeMap::<i16, i64>::new();
    for row in removed {
        if row.try_get::<String, _>("resource_kind")? == "live_session" {
            let id: Uuid = row.try_get("entity_id")?;
            let allocation = RetentionAllocation {
                shard: row.try_get("shard")?,
                created_at: row.try_get("created_at")?,
            };
            anyhow::ensure!(
                !protected.bindings.contains_key(&id)
                    && !delta.removed_allocations.contains_key(&id),
                "protected or already removed SM allocation entered orphan cleanup"
            );
            if protected.shards.contains_key(&allocation.shard) {
                *protected_shard_removals
                    .entry(allocation.shard)
                    .or_default() += 1;
            }
            delta.removed_allocations.insert(id, allocation);
        }
    }
    // Raw orphan allocation DELETE has no release trigger. Apply only the
    // exact known removals to a prevalidated protected shard; never recompute
    // or repair that counter from a potentially corrupt aggregate.
    for (shard, removed) in protected_shard_removals {
        let changed = sqlx::query(
            "UPDATE deployment_capacity_shards SET used=used-$2
              WHERE resource_kind='live_session' AND shard=$1 AND used>=$2",
        )
        .bind(shard)
        .bind(removed)
        .execute(&mut **tx)
        .await?
        .rows_affected();
        anyhow::ensure!(
            changed == 1,
            "protected SM orphan-release charge is corrupt"
        );
    }
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
          WHERE s.resource_kind=q.resource_kind AND s.shard=q.shard
            AND NOT (s.resource_kind='live_session' AND s.shard=ANY($1))",
    )
    .bind(protected.shard_ids())
    .execute(&mut **tx)
    .await?;

    // Install the requested exact hard budgets before backfilling missing
    // allocations. The enclosing reconciliation capability already holds a
    // table-level authority lock, so 256 sequential SELECT/UPDATE round trips
    // add latency but no isolation. Derive the complete requested matrix once,
    // reject the first unrepresentable persisted placement, then replace every
    // shard budget in one statement. This preserves the exact shard placement
    // contract while keeping cold starts bounded under parallel deployment.
    let unrepresentable = sqlx::query(
        "WITH requested_limits(resource_kind,requested_limit) AS (
             VALUES
               ('account'::text,$1::bigint),
               ('muc_room'::text,$2::bigint),
               ('live_session'::text,$3::bigint),
               ('sm_session'::text,$4::bigint)
         ),
         desired AS (
             SELECT requested_limits.resource_kind,
                    shards.shard::smallint AS shard,
                    (requested_limits.requested_limit / 64)
                      + CASE
                          WHEN shards.shard < (requested_limits.requested_limit % 64)
                            THEN 1
                          ELSE 0
                        END AS hard_budget
               FROM requested_limits
               CROSS JOIN generate_series(0,63) AS shards(shard)
         )
         SELECT existing.resource_kind,existing.shard,existing.used,desired.hard_budget
           FROM deployment_capacity_shards existing
           JOIN desired
             ON desired.resource_kind=existing.resource_kind
            AND desired.shard=existing.shard
          WHERE existing.used > desired.hard_budget
          ORDER BY existing.resource_kind,existing.shard
          LIMIT 1",
    )
    .bind(configured.accounts)
    .bind(configured.muc_rooms)
    .bind(configured.live_sessions)
    .bind(configured.resumable_sessions)
    .fetch_optional(&mut **tx)
    .await?;
    if let Some(row) = unrepresentable {
        let kind: String = row.try_get("resource_kind")?;
        let shard: i16 = row.try_get("shard")?;
        let used: i64 = row.try_get("used")?;
        let hard_budget: i64 = row.try_get("hard_budget")?;
        anyhow::bail!(
            "configured {kind} capacity cannot represent persisted shard {shard}: usage {used}, hard budget {hard_budget}; raise the limit/epoch or perform a staged offline rebalance"
        );
    }
    let expected_shards = i64::try_from(configured.values().len())
        .expect("deployment capacity resource-kind count fits i64")
        * CAPACITY_SHARDS;
    let updated_shards = sqlx::query(
        "WITH requested_limits(resource_kind,requested_limit) AS (
             VALUES
               ('account'::text,$1::bigint),
               ('muc_room'::text,$2::bigint),
               ('live_session'::text,$3::bigint),
               ('sm_session'::text,$4::bigint)
         ),
         desired AS (
             SELECT requested_limits.resource_kind,
                    shards.shard::smallint AS shard,
                    (requested_limits.requested_limit / 64)
                      + CASE
                          WHEN shards.shard < (requested_limits.requested_limit % 64)
                            THEN 1
                          ELSE 0
                        END AS hard_budget
               FROM requested_limits
               CROSS JOIN generate_series(0,63) AS shards(shard)
         )
         UPDATE deployment_capacity_shards existing
            SET capacity=desired.hard_budget
           FROM desired
          WHERE existing.resource_kind=desired.resource_kind
            AND existing.shard=desired.shard",
    )
    .bind(configured.accounts)
    .bind(configured.muc_rooms)
    .bind(configured.live_sessions)
    .bind(configured.resumable_sessions)
    .execute(&mut **tx)
    .await?
    .rows_affected();
    anyhow::ensure!(
        updated_shards == u64::try_from(expected_shards).expect("expected shard count is positive"),
        "deployment capacity shard matrix is incomplete during reconciliation (updated={updated_shards}, expected={expected_shards})"
    );

    let missing_protected: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM deployment_session_leases lease
          WHERE lease.lease_until<=transaction_timestamp()
            AND northstar_session_recovery_retention(lease.lease_id,transaction_timestamp())<>'none'
            AND NOT EXISTS(SELECT 1 FROM deployment_capacity_allocations allocation
                WHERE allocation.resource_kind='live_session' AND allocation.entity_id=lease.lease_id))",
    )
    .fetch_one(&mut **tx).await?;
    anyhow::ensure!(
        !missing_protected,
        "protected SM allocation cannot enter general backfill"
    );

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
            anyhow::ensure!(
                kind != "live_session" || !protected.bindings.contains_key(&entity),
                "protected SM allocation cannot be reacquired"
            );
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
            if kind == "live_session" {
                record_retention_allocation_addition(tx, entity, delta).await?;
            }
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

async fn rebuild_account_counters(
    tx: &mut Transaction<'_, Postgres>,
    protected: &ProtectedRetentionProjection,
) -> Result<()> {
    sqlx::query("DELETE FROM deployment_account_capacity WHERE NOT (resource_kind='live_session' AND owner_id=ANY($1))")
        .bind(protected.owner_ids())
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
         SELECT 'live_session',user_id,COUNT(*) FROM deployment_session_leases
          WHERE NOT (user_id=ANY($1)) GROUP BY user_id",
    )
    .bind(protected.owner_ids())
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
    let full_jid = northstar_xmpp_types::jid::canonical_session_key(full_jid)?;
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
    let full_jid = northstar_xmpp_types::jid::canonical_session_key(full_jid)?;
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
    let full_jid = northstar_xmpp_types::jid::canonical_session_key(full_jid)?;
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
    let full_jid = northstar_xmpp_types::jid::canonical_session_key(full_jid)?;
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

/// Attempt the deployment-wide lease reaper role without queuing behind an
/// already-active peer. Session renewal is local and critical; reaping is
/// shared maintenance and must never make every otherwise idle node compete
/// for the same cleanup work. The transaction-scoped advisory lock releases
/// automatically on commit, rollback, or connection loss.
pub async fn try_cleanup_expired_live_session_leases(
    pool: &PgPool,
    limit: i64,
) -> Result<Option<u64>> {
    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        .execute(&mut *tx)
        .await?;
    sqlx::query("SET LOCAL lock_timeout='500ms'")
        .execute(&mut *tx)
        .await?;
    let elected: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(1314079572,4)")
        .fetch_one(&mut *tx)
        .await?;
    if !elected {
        tx.rollback().await?;
        return Ok(None);
    }
    let removed: i64 = sqlx::query_scalar("SELECT northstar_session_cleanup_live($1)")
        .bind(limit.clamp(1, 10_000))
        .fetch_one(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Some(
        u64::try_from(removed).context("negative live-session cleanup count")?,
    ))
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
mod lock_order_schema_tests;

fn is_capacity_sqlx_error(error: &sqlx::Error) -> bool {
    error.as_database_error().is_some_and(|database| {
        database.code().as_deref() == Some("P0001")
            && database.message().contains("capacity exhausted")
    })
}

#[cfg(test)]
mod tests;
