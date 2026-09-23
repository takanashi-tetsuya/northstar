//! PostgreSQL adapter for the private readiness persistence probe.

use crate::cluster::ClusterReadinessAuthority;
use crate::db::{
    self, AbuseKeyDeploymentIdentity, AdminSessionCleanupSnapshot, ClusterKeyDeploymentIdentity,
    ClusterNodeInstance,
};
use crate::services::readiness::ReadinessRepository;
use anyhow::{ensure, Result};
use sqlx::PgPool;

#[derive(Clone)]
pub(crate) struct PostgresReadinessRepository {
    pool: PgPool,
}

impl PostgresReadinessRepository {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl ReadinessRepository for PostgresReadinessRepository {
    async fn validate_abuse_key(&self, identity: &AbuseKeyDeploymentIdentity) -> Result<()> {
        db::validate_abuse_key_deployment(&self.pool, identity).await
    }

    async fn validate_cluster_key(&self, identity: &ClusterKeyDeploymentIdentity) -> Result<()> {
        db::validate_cluster_key_deployment(&self.pool, identity).await
    }

    async fn validate_cluster_instance(&self, authority: &ClusterReadinessAuthority) -> Result<()> {
        let instances = db::active_cluster_node_instances(
            &self.pool,
            &authority.key_identity.xmpp_domain,
            std::slice::from_ref(&authority.instance_node_id),
        )
        .await?;
        ensure!(
            instances
                .iter()
                .any(|instance| cluster_instance_matches(authority, instance)),
            "this process no longer owns the authoritative cluster node-instance lease"
        );
        Ok(())
    }

    async fn admin_session_cleanup_snapshot(&self) -> Result<AdminSessionCleanupSnapshot> {
        db::admin_session_cleanup_snapshot(&self.pool).await
    }
}

fn cluster_instance_matches(
    authority: &ClusterReadinessAuthority,
    instance: &ClusterNodeInstance,
) -> bool {
    instance.node_id == authority.instance_node_id
        && instance.instance_uuid == authority.instance_uuid
        && instance.instance_epoch == authority.instance_epoch
        && instance.signing_key_id == authority.signing_key_id
        && instance.signing_key_epoch == authority.signing_key_epoch
        && !instance.lease_remaining.is_zero()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use uuid::Uuid;

    #[test]
    fn readiness_instance_requires_exact_live_lease_identity() {
        let authority = ClusterReadinessAuthority {
            key_identity: ClusterKeyDeploymentIdentity {
                xmpp_domain: "example.test".into(),
                node_id: "node-a".into(),
                epoch: 5,
                current_key_id: "key-a".into(),
                current_public_key_sha256: "digest".into(),
                previous_key_id: None,
                previous_public_key_sha256: None,
                staged_next_key_id: None,
                staged_next_public_key_sha256: None,
            },
            instance_node_id: "node-a".into(),
            instance_uuid: Uuid::from_u128(1),
            instance_epoch: 7,
            signing_key_id: "key-a".into(),
            signing_key_epoch: 5,
        };
        let mut instance = ClusterNodeInstance {
            node_id: "node-a".into(),
            instance_uuid: Uuid::from_u128(1),
            instance_epoch: 7,
            signing_key_id: "key-a".into(),
            signing_key_epoch: 5,
            lease_remaining: Duration::from_secs(1),
        };
        assert!(cluster_instance_matches(&authority, &instance));

        instance.node_id = "node-b".into();
        assert!(!cluster_instance_matches(&authority, &instance));
        instance.node_id = "node-a".into();
        instance.instance_uuid = Uuid::from_u128(2);
        assert!(!cluster_instance_matches(&authority, &instance));
        instance.instance_uuid = authority.instance_uuid;
        instance.instance_epoch += 1;
        assert!(!cluster_instance_matches(&authority, &instance));
        instance.instance_epoch = authority.instance_epoch;
        instance.signing_key_id = "key-b".into();
        assert!(!cluster_instance_matches(&authority, &instance));
        instance.signing_key_id = authority.signing_key_id.clone();
        instance.signing_key_epoch += 1;
        assert!(!cluster_instance_matches(&authority, &instance));
        instance.signing_key_epoch = authority.signing_key_epoch;
        instance.lease_remaining = Duration::ZERO;
        assert!(!cluster_instance_matches(&authority, &instance));
    }
}
