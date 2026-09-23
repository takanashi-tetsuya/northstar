//! Read-only PostgreSQL adapter for live-session credential maintenance.

use crate::services::session_authority_sweep::{AccountAuthState, SessionAuthoritySweepRepository};
use anyhow::Result;
use sqlx::PgPool;
use std::collections::HashMap;
use uuid::Uuid;

pub(crate) struct PostgresSessionAuthoritySweepRepository {
    pool: PgPool,
}

impl PostgresSessionAuthoritySweepRepository {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl SessionAuthoritySweepRepository for PostgresSessionAuthoritySweepRepository {
    async fn auth_states_for_users(
        &self,
        user_ids: &[Uuid],
    ) -> Result<HashMap<Uuid, AccountAuthState>> {
        Ok(crate::db::auth_states_for_users(&self.pool, user_ids)
            .await?
            .into_iter()
            .map(|(user_id, state)| {
                (
                    user_id,
                    AccountAuthState {
                        auth_generation: state.auth_generation,
                        is_disabled: state.is_disabled,
                    },
                )
            })
            .collect())
    }

    async fn user_agent_login_epochs(
        &self,
        agents: &[(Uuid, Uuid)],
    ) -> Result<HashMap<(Uuid, Uuid), i64>> {
        crate::db::user_agent_login_epochs(&self.pool, agents).await
    }
}
