//! PostgreSQL cluster key and process-instance authority checks.
//!
//! Peer key and instance caches are installed at separate points: a failed
//! instance read must not undo an already successful peer-key refresh.

use crate::cluster::ClusterReadinessAuthority;
use crate::db::{
    ClusterKeyDeploymentIdentity, ClusterNodeInstance, ClusterPeerKeyAuthority,
    ExpectedClusterPeerKey,
};
use anyhow::{ensure, Result};
use std::{future::Future, time::Duration};

pub(crate) trait ClusterAuthorityRepository: Send + Sync {
    fn validate_cluster_key(
        &self,
        identity: &ClusterKeyDeploymentIdentity,
    ) -> impl Future<Output = Result<()>> + Send;

    fn validate_peer_keys(
        &self,
        domain: &str,
        expected: &[ExpectedClusterPeerKey],
    ) -> impl Future<Output = Result<()>> + Send;

    fn peer_keys(
        &self,
        domain: &str,
        nodes: &[String],
    ) -> impl Future<Output = Result<Vec<ClusterPeerKeyAuthority>>> + Send;

    fn active_instances(
        &self,
        domain: &str,
        nodes: &[String],
    ) -> impl Future<Output = Result<Vec<ClusterNodeInstance>>> + Send;

    fn heartbeat_instance(
        &self,
        authority: &ClusterReadinessAuthority,
        lease: Duration,
    ) -> impl Future<Output = Result<()>> + Send;
}

pub(crate) struct ClusterAuthorityService<R> {
    repository: R,
}

impl<R: ClusterAuthorityRepository> ClusterAuthorityService<R> {
    pub(crate) fn new(repository: R) -> Self {
        Self { repository }
    }

    pub(crate) async fn validate_cluster_key(
        &self,
        identity: &ClusterKeyDeploymentIdentity,
    ) -> Result<()> {
        self.repository.validate_cluster_key(identity).await
    }

    pub(crate) async fn validate_local_instance(
        &self,
        authority: &ClusterReadinessAuthority,
    ) -> Result<()> {
        let rows = self
            .repository
            .active_instances(
                &authority.key_identity.xmpp_domain,
                std::slice::from_ref(&authority.instance_node_id),
            )
            .await?;
        ensure!(
            rows.iter().any(|instance| {
                instance.node_id == authority.instance_node_id
                    && instance.instance_uuid == authority.instance_uuid
                    && instance.instance_epoch == authority.instance_epoch
                    && instance.signing_key_id == authority.signing_key_id
                    && instance.signing_key_epoch == authority.signing_key_epoch
                    && !instance.lease_remaining.is_zero()
            }),
            "this process no longer owns the authoritative cluster node-instance lease"
        );
        Ok(())
    }

    pub(crate) async fn heartbeat_local_instance(
        &self,
        authority: &ClusterReadinessAuthority,
        lease: Duration,
    ) -> Result<()> {
        self.repository.heartbeat_instance(authority, lease).await
    }

    /// Preserve the original two-stage cache update. Each query is independently
    /// committed; neither cache callback runs before its corresponding read.
    pub(crate) async fn refresh_peers<InstallKeys, InstallInstances>(
        &self,
        domain: &str,
        expected: &[ExpectedClusterPeerKey],
        nodes: &[String],
        install_keys: InstallKeys,
        install_instances: InstallInstances,
    ) -> Result<()>
    where
        InstallKeys: FnOnce(Vec<ClusterPeerKeyAuthority>),
        InstallInstances: FnOnce(Vec<ClusterNodeInstance>),
    {
        self.repository.validate_peer_keys(domain, expected).await?;
        let keys = self.repository.peer_keys(domain, nodes).await?;
        install_keys(keys);
        let instances = self.repository.active_instances(domain, nodes).await?;
        install_instances(instances);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Failure {
        None,
        PeerValidation,
        PeerRead,
        InstanceRead,
    }

    struct StubRepository {
        calls: Mutex<Vec<&'static str>>,
        failure: Failure,
        instances: Vec<ClusterNodeInstance>,
    }

    impl ClusterAuthorityRepository for &StubRepository {
        async fn validate_cluster_key(&self, _: &ClusterKeyDeploymentIdentity) -> Result<()> {
            self.calls.lock().unwrap().push("local-key");
            Ok(())
        }

        async fn validate_peer_keys(&self, _: &str, _: &[ExpectedClusterPeerKey]) -> Result<()> {
            self.calls.lock().unwrap().push("peer-validation");
            if self.failure == Failure::PeerValidation {
                anyhow::bail!("peer validation failed");
            }
            Ok(())
        }

        async fn peer_keys(&self, _: &str, _: &[String]) -> Result<Vec<ClusterPeerKeyAuthority>> {
            self.calls.lock().unwrap().push("peer-read");
            if self.failure == Failure::PeerRead {
                anyhow::bail!("peer read failed");
            }
            Ok(Vec::new())
        }

        async fn active_instances(
            &self,
            _: &str,
            _: &[String],
        ) -> Result<Vec<ClusterNodeInstance>> {
            self.calls.lock().unwrap().push("instance-read");
            if self.failure == Failure::InstanceRead {
                anyhow::bail!("instance read failed");
            }
            Ok(self.instances.clone())
        }

        async fn heartbeat_instance(
            &self,
            _: &ClusterReadinessAuthority,
            _: Duration,
        ) -> Result<()> {
            self.calls.lock().unwrap().push("heartbeat");
            Ok(())
        }
    }

    #[tokio::test]
    async fn refresh_installs_keys_before_reading_instances_and_short_circuits_failures() {
        for (failure, expected_calls) in [
            (
                Failure::None,
                vec![
                    "peer-validation",
                    "peer-read",
                    "install-keys",
                    "instance-read",
                    "install-instances",
                ],
            ),
            (Failure::PeerValidation, vec!["peer-validation"]),
            (Failure::PeerRead, vec!["peer-validation", "peer-read"]),
            (
                Failure::InstanceRead,
                vec![
                    "peer-validation",
                    "peer-read",
                    "install-keys",
                    "instance-read",
                ],
            ),
        ] {
            let repository = StubRepository {
                calls: Mutex::new(Vec::new()),
                failure,
                instances: Vec::new(),
            };
            let calls = &repository.calls;
            let service = ClusterAuthorityService::new(&repository);
            let result = service
                .refresh_peers(
                    "example.test",
                    &[],
                    &[],
                    |_| calls.lock().unwrap().push("install-keys"),
                    |_| calls.lock().unwrap().push("install-instances"),
                )
                .await;
            assert_eq!(result.is_ok(), failure == Failure::None);
            assert_eq!(*calls.lock().unwrap(), expected_calls);
        }
    }

    #[tokio::test]
    async fn local_lease_validation_requires_exact_live_process_and_signing_identity() {
        let authority = ClusterReadinessAuthority {
            key_identity: ClusterKeyDeploymentIdentity {
                xmpp_domain: "example.test".into(),
                node_id: "node-a".into(),
                epoch: 4,
                current_key_id: "key-a".into(),
                current_public_key_sha256: "digest".into(),
                previous_key_id: None,
                previous_public_key_sha256: None,
                staged_next_key_id: None,
                staged_next_public_key_sha256: None,
            },
            instance_node_id: "node-a".into(),
            instance_uuid: uuid::Uuid::from_u128(1),
            instance_epoch: 7,
            signing_key_id: "key-a".into(),
            signing_key_epoch: 4,
        };
        let valid = ClusterNodeInstance {
            node_id: authority.instance_node_id.clone(),
            instance_uuid: authority.instance_uuid,
            instance_epoch: authority.instance_epoch,
            signing_key_id: authority.signing_key_id.clone(),
            signing_key_epoch: authority.signing_key_epoch,
            lease_remaining: Duration::from_secs(1),
        };
        for (instance, expected) in [
            (valid.clone(), true),
            (
                ClusterNodeInstance {
                    node_id: "node-b".into(),
                    ..valid.clone()
                },
                false,
            ),
            (
                ClusterNodeInstance {
                    instance_uuid: uuid::Uuid::from_u128(2),
                    ..valid.clone()
                },
                false,
            ),
            (
                ClusterNodeInstance {
                    instance_epoch: 8,
                    ..valid.clone()
                },
                false,
            ),
            (
                ClusterNodeInstance {
                    signing_key_id: "key-b".into(),
                    ..valid.clone()
                },
                false,
            ),
            (
                ClusterNodeInstance {
                    signing_key_epoch: 5,
                    ..valid.clone()
                },
                false,
            ),
            (
                ClusterNodeInstance {
                    lease_remaining: Duration::ZERO,
                    ..valid.clone()
                },
                false,
            ),
        ] {
            let repository = StubRepository {
                calls: Mutex::new(Vec::new()),
                failure: Failure::None,
                instances: vec![instance],
            };
            let service = ClusterAuthorityService::new(&repository);
            assert_eq!(
                service.validate_local_instance(&authority).await.is_ok(),
                expected
            );
            assert_eq!(*repository.calls.lock().unwrap(), ["instance-read"]);
        }
    }
}
