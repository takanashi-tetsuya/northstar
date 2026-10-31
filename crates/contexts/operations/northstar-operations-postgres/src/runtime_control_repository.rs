//! PostgreSQL adapter for the reserved runtime-control connection.

use crate::admin_commands::{self as db, DurableServiceControl, RuntimeControlReadPhase};
use anyhow::Result;
use northstar_operations_application::runtime_control::{
    RuntimeControlRepository, RuntimePolicySnapshot,
};
use sqlx::{pool::PoolConnection, Postgres};

pub struct PostgresRuntimeControlRepository {
    connection: PoolConnection<Postgres>,
}

impl PostgresRuntimeControlRepository {
    pub fn new(connection: PoolConnection<Postgres>) -> Self {
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
