//! PostgreSQL authority for the SM suspension recovery worker.
use crate::db;
use anyhow::{Context, Result};
use northstar_session_application::sm_suspension::*;
use sqlx::PgPool;
use uuid::Uuid;

pub(crate) struct PostgresSmSuspensionRepository {
    pool: PgPool,
}

impl PostgresSmSuspensionRepository {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl SmSuspensionRepository for PostgresSmSuspensionRepository {
    async fn suspend_exact_session(
        &self,
        request: SmSuspensionRequest<'_>,
        limits: SmSuspensionLimits,
    ) -> Result<bool> {
        let snapshot = db::SmSessionSnapshot::from(request.snapshot);
        db::suspend_activated_sm_resume_exact(
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
        db::append_suspended_sm_stanza(
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
    ) -> Result<northstar_room_application::muc_service::ClusterMucTransitionOutcome> {
        let room = northstar_room_postgres::muc::muc_room(&self.pool, request.room_localpart)
            .await?
            .context("SM suspension references a missing MUC room")?;
        let target = northstar_room_postgres::cluster_muc::cluster_muc_occupancy_target(
            &self.pool,
            room.id,
            request.occupant_incarnation,
            request.connection_id,
        )
        .await?
        .context("SM suspension lost its exact MUC occupancy")?;
        northstar_room_postgres::cluster_muc::transition_cluster_muc_occupancy(
            &self.pool,
            request.operation_id,
            &target,
            "suspend",
            request.node_id,
            None,
            None,
            Some(request.sm_session_id),
            request.lease,
        )
        .await
        .map(Into::into)
    }

    async fn committed_muc_wake(
        &self,
        operation_id: Uuid,
    ) -> Result<Option<northstar_room_application::muc_service::ClusterMucWakeDescriptor>> {
        northstar_room_postgres::cluster_muc::cluster_muc_wake_descriptor(&self.pool, operation_id)
            .await
    }
}
