//! PostgreSQL adapter for the reserved runtime-control connection.

use crate::{
    db::{self, DurableServiceControl, RuntimeControlReadPhase},
    services::runtime_control::{RuntimeControlRepository, RuntimePolicySnapshot},
};
use anyhow::Result;
use sqlx::{pool::PoolConnection, Postgres};

pub(crate) struct PostgresRuntimeControlRepository {
    connection: PoolConnection<Postgres>,
}

impl PostgresRuntimeControlRepository {
    pub(crate) fn new(connection: PoolConnection<Postgres>) -> Self {
        Self { connection }
    }
}

impl RuntimeControlRepository for PostgresRuntimeControlRepository {
    async fn policy_snapshot(
        &mut self,
        read_phase: impl FnMut(RuntimeControlReadPhase) + Send,
    ) -> Result<RuntimePolicySnapshot> {
        let (island_mode, registration_closed, blacklist, whitelist) =
            db::runtime_control_snapshot(&mut self.connection, read_phase).await?;
        Ok(RuntimePolicySnapshot {
            island_mode,
            registration_closed,
            blacklist,
            whitelist,
        })
    }

    async fn service_control(&mut self) -> Result<Option<DurableServiceControl>> {
        db::poll_admin_service_control(&mut self.connection).await
    }
}
