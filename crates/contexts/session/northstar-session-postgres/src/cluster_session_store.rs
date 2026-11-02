//! The PostgreSQL implementation of the cluster's session-store port.

use northstar_security::{cluster_bus::SignedClusterEnvelope, cluster_keys::ClusterNodeInstance};
use northstar_session_application::{
    cluster_session_store::{ClusterSessionRouteOwner, ClusterSessionStore, ClusterStoreFuture},
    session_termination_authority::SessionRouteAuthority,
};
use northstar_session_core::SessionRouteClaimProof;
use sqlx::PgPool;
use std::time::Duration;
use uuid::Uuid;

#[derive(Clone)]
pub struct PostgresClusterSessionStore {
    pool: PgPool,
}

impl PostgresClusterSessionStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl ClusterSessionStore for PostgresClusterSessionStore {
    fn claim_node_instance<'a>(
        &'a self,
        namespace: &'a str,
        node_id: &'a str,
        instance_uuid: Uuid,
        signing_key_id: &'a str,
        signing_key_epoch: i64,
        lease: Duration,
    ) -> ClusterStoreFuture<'a, ClusterNodeInstance> {
        Box::pin(async move {
            crate::cluster_keys::claim_cluster_node_instance(
                &self.pool,
                namespace,
                node_id,
                instance_uuid,
                signing_key_id,
                signing_key_epoch,
                lease,
            )
            .await
        })
    }

    fn admit_envelope_replay<'a>(
        &'a self,
        namespace: &'a str,
        envelope: &'a SignedClusterEnvelope,
    ) -> ClusterStoreFuture<'a, bool> {
        Box::pin(async move {
            crate::cluster_keys::admit_cluster_envelope_replay(&self.pool, namespace, envelope)
                .await
        })
    }

    fn is_replay_validation_rejection(&self, error: &anyhow::Error) -> bool {
        crate::cluster_keys::cluster_replay_validation_rejection(error)
    }

    fn claim_session_route<'a>(
        &'a self,
        owner: ClusterSessionRouteOwner<'a>,
        bare_jid: &'a str,
        proof: SessionRouteClaimProof,
        lease: Duration,
    ) -> ClusterStoreFuture<'a, bool> {
        Box::pin(async move {
            crate::cluster_session_route::claim_cluster_session_route(
                &self.pool,
                owner.namespace,
                owner.full_jid,
                bare_jid,
                owner.owner_node_id,
                owner.owner_instance_uuid,
                owner.owner_instance_epoch,
                owner.connection_uuid,
                proof.into(),
                lease,
            )
            .await
        })
    }

    fn refresh_session_route<'a>(
        &'a self,
        owner: ClusterSessionRouteOwner<'a>,
        lease: Duration,
    ) -> ClusterStoreFuture<'a, bool> {
        Box::pin(async move {
            crate::cluster_session_route::refresh_cluster_session_route(
                &self.pool,
                owner.namespace,
                owner.full_jid,
                owner.owner_node_id,
                owner.owner_instance_uuid,
                owner.owner_instance_epoch,
                owner.connection_uuid,
                lease,
            )
            .await
        })
    }

    fn release_session_route<'a>(
        &'a self,
        owner: ClusterSessionRouteOwner<'a>,
    ) -> ClusterStoreFuture<'a, bool> {
        Box::pin(async move {
            crate::cluster_session_route::release_cluster_session_route(
                &self.pool,
                owner.namespace,
                owner.full_jid,
                owner.owner_node_id,
                owner.owner_instance_uuid,
                owner.owner_instance_epoch,
                owner.connection_uuid,
            )
            .await
        })
    }

    fn session_route_authority<'a>(
        &'a self,
        namespace: &'a str,
        full_jid: &'a str,
    ) -> ClusterStoreFuture<'a, Option<SessionRouteAuthority>> {
        Box::pin(async move {
            Ok(
                crate::cluster_session_route::cluster_session_route_authority(
                    &self.pool, namespace, full_jid,
                )
                .await?
                .map(|route| SessionRouteAuthority {
                    owner_node_id: route.owner_node_id,
                    owner_instance_uuid: route.owner_instance_uuid,
                    owner_instance_epoch: route.owner_instance_epoch,
                    connection_uuid: route.connection_uuid,
                }),
            )
        })
    }

    fn session_nodes_for_bare<'a>(
        &'a self,
        namespace: &'a str,
        bare_jid: &'a str,
    ) -> ClusterStoreFuture<'a, Vec<String>> {
        Box::pin(async move {
            crate::cluster_session_route::cluster_session_nodes_for_bare(
                &self.pool, namespace, bare_jid,
            )
            .await
        })
    }
}
