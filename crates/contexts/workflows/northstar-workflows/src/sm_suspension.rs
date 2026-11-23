//! PostgreSQL authority for the SM suspension recovery worker.
use anyhow::Result;
use northstar_room_application::muc_service::ClusterMucOccupancy;
use northstar_room_postgres::cluster_muc::{
    resolve_cluster_muc_occupancies_batch, suspend_cluster_muc_authority, ClusterMucOccupancyLookup,
};
use northstar_session_application::sm_suspension::*;
use sqlx::PgPool;
use uuid::Uuid;

pub struct PostgresSmSuspensionRepository {
    pool: PgPool,
}

impl PostgresSmSuspensionRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl SmSuspensionRepository for PostgresSmSuspensionRepository {
    async fn suspend_exact_session(
        &self,
        request: SmSuspensionRequest<'_>,
        limits: SmSuspensionLimits,
    ) -> Result<bool> {
        let snapshot = crate::sm::SmSessionSnapshot::from(request.snapshot);
        crate::sm::suspend_activated_sm_resume_exact(
            &self.pool,
            request.session_id,
            request.connection_id,
            request.user_id,
            request.auth_generation,
            &snapshot,
            request.ttl_seconds,
            limits.max_stanzas,
            limits.max_bytes,
        )
        .await
    }

    async fn append_suspended_stanza(
        &self,
        session_id: Uuid,
        source_id: Uuid,
        stanza: &str,
        max_stanzas: usize,
        max_bytes: usize,
    ) -> Result<bool> {
        crate::sm::append_suspended_sm_stanza(
            &self.pool,
            session_id,
            source_id,
            stanza,
            max_stanzas,
            max_bytes,
        )
        .await
    }

    async fn suspend_muc_occupant(
        &self,
        request: MucSuspensionRequest<'_>,
    ) -> Result<Option<ClusterMucOccupancy>> {
        let Some(resolved) = resolve_cluster_muc_occupancies_batch(
            &self.pool,
            &[ClusterMucOccupancyLookup {
                room_localpart: request.room_localpart.to_owned(),
                full_jid: request.occupant.full_jid.clone(),
                nick: request.occupant.nick.clone(),
                occupant_incarnation: request.occupant.cluster_epoch,
                connection_uuid: request.occupant.connection_id,
            }],
            request.node_id,
        )
        .await?
        .into_iter()
        .next() else {
            return Ok(None);
        };
        suspend_cluster_muc_authority(
            &self.pool,
            request.operation_id,
            &resolved.target,
            request.node_id,
            request.sm_session_id,
            request.lease,
        )
        .await
    }

    async fn committed_muc_wake(
        &self,
        operation_id: Uuid,
    ) -> Result<Option<northstar_room_application::muc_service::ClusterMucWakeDescriptor>> {
        northstar_room_postgres::cluster_muc::cluster_muc_wake_descriptor(&self.pool, operation_id)
            .await
    }
}
