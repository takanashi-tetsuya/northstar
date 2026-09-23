//! PostgreSQL adapter for an exact cluster session-route authority read.

use crate::services::session_termination_authority::{
    SessionRouteAuthority, SessionTerminationAuthorityRepository,
};
use anyhow::Result;
use sqlx::PgPool;

pub(crate) struct PostgresSessionTerminationAuthorityRepository {
    pool: PgPool,
}

impl PostgresSessionTerminationAuthorityRepository {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl SessionTerminationAuthorityRepository for PostgresSessionTerminationAuthorityRepository {
    async fn route_authority(
        &self,
        namespace: &str,
        full_jid: &str,
    ) -> Result<Option<SessionRouteAuthority>> {
        Ok(
            crate::db::cluster_session_route_authority(&self.pool, namespace, full_jid)
                .await?
                .map(|route| SessionRouteAuthority {
                    owner_node_id: route.owner_node_id,
                    owner_instance_uuid: route.owner_instance_uuid,
                    owner_instance_epoch: route.owner_instance_epoch,
                    connection_uuid: route.connection_uuid,
                }),
        )
    }
}
