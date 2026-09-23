//! PostgreSQL adapter for generation-fenced durable SM teardown.

use crate::{db, services::sm_teardown::*};
use anyhow::Result;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Clone)]
pub(crate) struct PostgresSmTeardownRepository {
    pool: PgPool,
}

impl PostgresSmTeardownRepository {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl SmTeardownClaim for db::SmTeardownSnapshot {
    fn teardown_lease(&self) -> SmTeardownLease {
        SmTeardownLease {
            session_id: self.session_id,
            token: self.teardown_token,
        }
    }
}

impl SmTeardownRepository for PostgresSmTeardownRepository {
    type Snapshot = db::SmTeardownSnapshot;

    async fn take_before_generation(
        &self,
        user_id: Uuid,
        generation_exclusive: i64,
        lease_seconds: u64,
    ) -> Result<SmTeardownBatch<Self::Snapshot>> {
        let batch = db::take_user_sm_sessions_before_auth_generation_for_teardown(
            &self.pool,
            user_id,
            generation_exclusive,
            lease_seconds,
        )
        .await?;
        Ok(SmTeardownBatch {
            snapshots: batch.snapshots,
            pending: batch.pending,
        })
    }

    async fn count_before_generation(
        &self,
        user_id: Uuid,
        generation_exclusive: i64,
    ) -> Result<i64> {
        db::count_user_sm_rows_before_auth_generation(&self.pool, user_id, generation_exclusive)
            .await
    }

    async fn finalize(&self, lease: SmTeardownLease) -> Result<bool> {
        db::finalize_sm_teardown(&self.pool, lease.session_id, lease.token).await
    }
}
