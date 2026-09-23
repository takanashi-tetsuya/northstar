//! Database-owned metrics projection. One connection and one repeatable-read
//! read-only transaction keep all gauges on the same PostgreSQL snapshot.
use crate::services::metrics_snapshot::*;
use sqlx::{PgPool, Row};

#[derive(Clone)]
pub(crate) struct PostgresMetricsSnapshotRepository {
    pool: PgPool,
}
impl PostgresMetricsSnapshotRepository {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}
impl MetricsSnapshotRepository for PostgresMetricsSnapshotRepository {
    async fn collect(
        &self,
        component_domains: &[String],
    ) -> anyhow::Result<DatabaseMetricsSnapshot> {
        let mut transaction = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *transaction)
            .await?;

        let sm_sessions: i64 =
            sqlx::query_scalar("SELECT northstar_sm_count('active',NULL,NULL,NULL)")
                .fetch_one(&mut *transaction)
                .await?;

        let row = sqlx::query(
        "WITH active AS MATERIALIZED (
            SELECT target_domain, stanza, created_at, next_attempt_at,
                   locked_until, enqueue_sequence
            FROM s2s_outbox
            WHERE expires_at > NOW()
        ), domain_heads AS (
            SELECT DISTINCT ON (target_domain)
                   target_domain, next_attempt_at, locked_until
            FROM active
            ORDER BY target_domain, enqueue_sequence
        )
        SELECT
            (SELECT COUNT(*)::BIGINT FROM active) AS pending_rows,
            (SELECT COALESCE(SUM(octet_length(stanza)), 0)::BIGINT FROM active) AS pending_bytes,
            (SELECT COALESCE(EXTRACT(EPOCH FROM (NOW() - MIN(created_at))), 0)::DOUBLE PRECISION FROM active) AS oldest_age_seconds,
            (SELECT COUNT(*)::BIGINT FROM active WHERE locked_until > NOW()) AS locked_rows,
            (SELECT COUNT(*)::BIGINT FROM active WHERE target_domain = ANY($1::TEXT[])) AS component_pending_rows,
            (SELECT COUNT(*)::BIGINT FROM domain_heads
             WHERE next_attempt_at <= NOW()
               AND (locked_until IS NULL OR locked_until <= NOW())) AS due_rows",
    )
    .bind(component_domains)
    .fetch_one(&mut *transaction)
    .await?;
        let s2s = S2sOutboxSnapshot {
            pending_rows: row.try_get("pending_rows")?,
            pending_bytes: row.try_get("pending_bytes")?,
            oldest_age_seconds: row.try_get::<f64, _>("oldest_age_seconds")?.max(0.0),
            due_rows: row.try_get("due_rows")?,
            locked_rows: row.try_get("locked_rows")?,
            component_pending_rows: row.try_get("component_pending_rows")?,
        };

        let row = sqlx::query(
            "SELECT
            COUNT(*) FILTER (WHERE status='pending')::BIGINT AS pending,
            COUNT(*) FILTER (WHERE status='running')::BIGINT AS running,
            COUNT(*) FILTER (WHERE status='indeterminate')::BIGINT AS indeterminate,
            COALESCE(EXTRACT(EPOCH FROM (
                clock_timestamp() - MIN(created_at) FILTER (
                    WHERE status IN ('pending','running')
                )
            )),0)::FLOAT8 AS oldest_active_age_seconds
         FROM api_operation_journal",
        )
        .fetch_one(&mut *transaction)
        .await?;
        let operations = ApiOperationSnapshot {
            pending: row.try_get("pending")?,
            running: row.try_get("running")?,
            indeterminate: row.try_get("indeterminate")?,
            oldest_active_age_seconds: row.try_get::<f64, _>("oldest_active_age_seconds")?.max(0.0),
        };

        let row = sqlx::query(
            "SELECT pending,running,oldest_age_seconds,maximum_attempts,queued,capacity
           FROM northstar_admin_session_cleanup_snapshot()",
        )
        .fetch_one(&mut *transaction)
        .await?;
        let cleanup = AdminSessionCleanupSnapshot {
            pending: row.try_get("pending")?,
            running: row.try_get("running")?,
            oldest_age_seconds: row.try_get("oldest_age_seconds")?,
            maximum_attempts: row.try_get("maximum_attempts")?,
            queued: row.try_get("queued")?,
            capacity: row.try_get("capacity")?,
        };

        let pending_reports: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM abuse_reports WHERE status IN ('submitted','reviewing')",
        )
        .fetch_one(&mut *transaction)
        .await?;
        let pending_appeals: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM abuse_appeals WHERE status IN ('submitted','reviewing')",
        )
        .fetch_one(&mut *transaction)
        .await?;
        let active_invitations: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM invitation_tokens WHERE revoked_at IS NULL
           AND (expires_at IS NULL OR expires_at > NOW()) AND use_count < max_uses",
        )
        .fetch_one(&mut *transaction)
        .await?;

        let (
            active_holds,
            preserved_offline_records,
            active_export_leases,
            expired_incomplete_export_leases,
        ): (i64, i64, i64, i64) = sqlx::query_as(
            "SELECT
            (SELECT COUNT(*) FROM legal_holds WHERE released_at IS NULL)::BIGINT,
            (SELECT COUNT(*) FROM legal_hold_offline_snapshots)::BIGINT,
            (SELECT COUNT(*) FROM governance_export_leases
              WHERE completed_at IS NULL AND expires_at > clock_timestamp())::BIGINT,
            (SELECT COUNT(*) FROM governance_export_leases
              WHERE completed_at IS NULL AND expires_at <= clock_timestamp())::BIGINT",
        )
        .fetch_one(&mut *transaction)
        .await?;
        let governance = DataGovernanceSnapshot {
            active_holds,
            preserved_offline_records,
            active_export_leases,
            expired_incomplete_export_leases,
        };

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
    .fetch_one(&mut *transaction)
    .await?;
        let capacity = DeploymentCapacitySnapshot {
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
        };

        transaction.commit().await?;
        Ok((
            sm_sessions,
            s2s,
            operations,
            cleanup,
            (pending_reports, pending_appeals, active_invitations),
            governance,
            capacity,
        ))
    }
}
