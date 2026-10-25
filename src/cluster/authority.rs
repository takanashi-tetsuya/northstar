//! Cluster key and process-instance authority: peer keys, claims, refresh and release.

use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct AuthorizedClusterInstance {
    pub(super) instance_uuid: uuid::Uuid,
    pub(super) instance_epoch: i64,
    pub(super) signing_key_id: String,
    pub(super) signing_key_epoch: i64,
    pub(super) valid_until: Instant,
    pub(super) refresh_until: Instant,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct AuthorizedPeerKeys {
    pub(super) epoch: i64,
    pub(super) current_key_id: String,
    pub(super) previous_key_id: Option<String>,
    pub(super) refresh_until: Instant,
}

impl AuthorizedPeerKeys {
    pub(super) fn accepts(&self, key_id: &str, key_epoch: i64, now: Instant) -> bool {
        self.refresh_until > now
            && ((key_epoch == self.epoch && self.current_key_id == key_id)
                || (self.epoch > 1
                    && key_epoch == self.epoch - 1
                    && self.previous_key_id.as_deref() == Some(key_id)))
    }
}

pub(super) fn authoritative_instance_matches(
    authority: &AuthorizedClusterInstance,
    connection_uuid: uuid::Uuid,
    connection_epoch: i64,
    signing_key_id: &str,
    signing_key_epoch: i64,
    now: Instant,
) -> bool {
    authority.instance_uuid == connection_uuid
        && authority.instance_epoch == connection_epoch
        && authority.signing_key_id == signing_key_id
        && authority.signing_key_epoch == signing_key_epoch
        && authority.valid_until > now
        && authority.refresh_until > now
}

pub(super) async fn refresh_peer_authority_with<R: ClusterAuthorityRepository>(
    service: &ClusterAuthorityService<R>,
    domain: &str,
    expected: &[northstar_security::cluster_keys::ExpectedClusterPeerKey],
    nodes: &[String],
    authorized_peer_keys: &dashmap::DashMap<String, AuthorizedPeerKeys>,
    authorized_instances: &dashmap::DashMap<String, AuthorizedClusterInstance>,
) -> Result<()> {
    service
        .refresh_peers(
            domain,
            expected,
            nodes,
            |key_authorities| {
                let replacements = key_authorities
                    .into_iter()
                    .map(|authority| {
                        (
                            authority.node_id,
                            AuthorizedPeerKeys {
                                epoch: authority.epoch,
                                current_key_id: authority.current_key_id,
                                previous_key_id: authority.previous_key_id,
                                refresh_until: Instant::now() + Duration::from_secs(10),
                            },
                        )
                    })
                    .collect::<HashMap<_, _>>();
                authorized_peer_keys.retain(|node, _| replacements.contains_key(node));
                for (node, authority) in replacements {
                    authorized_peer_keys.insert(node, authority);
                }
            },
            |active| {
                let replacements = active
                    .into_iter()
                    .map(|instance| {
                        (
                            instance.node_id,
                            AuthorizedClusterInstance {
                                instance_uuid: instance.instance_uuid,
                                instance_epoch: instance.instance_epoch,
                                signing_key_id: instance.signing_key_id,
                                signing_key_epoch: instance.signing_key_epoch,
                                valid_until: Instant::now()
                                    + instance
                                        .lease_remaining
                                        .saturating_sub(Duration::from_secs(1)),
                                refresh_until: Instant::now() + Duration::from_secs(10),
                            },
                        )
                    })
                    .collect::<HashMap<_, _>>();
                authorized_instances.retain(|node, _| replacements.contains_key(node));
                for (node, instance) in replacements {
                    authorized_instances.insert(node, instance);
                }
            },
        )
        .await
}

impl ClusterManager {
    pub fn key_authority_identity(
        &self,
    ) -> Option<northstar_security::cluster_keys::ClusterKeyDeploymentIdentity> {
        let security = self.security.as_ref()?;
        Some(
            northstar_security::cluster_keys::ClusterKeyDeploymentIdentity {
                xmpp_domain: self.namespace.clone(),
                node_id: security.node_id.clone(),
                epoch: security.key_epoch,
                current_key_id: security.current_key_id.clone(),
                current_public_key_sha256: security.current_public_key_sha256.clone(),
                previous_key_id: security.previous_key_id.clone(),
                previous_public_key_sha256: security.previous_public_key_sha256.clone(),
                staged_next_key_id: security.staged_next_key_id.clone(),
                staged_next_public_key_sha256: security.staged_next_public_key_sha256.clone(),
            },
        )
    }

    pub(crate) fn readiness_authority_snapshot(&self) -> Option<ClusterReadinessAuthority> {
        let security = self.security.as_ref()?;
        Some(ClusterReadinessAuthority {
            key_identity: self.key_authority_identity()?,
            instance_node_id: self.node_id.clone(),
            instance_uuid: self.connection_uuid,
            instance_epoch: self.instance_epoch.load(Ordering::Acquire),
            signing_key_id: security.current_key_id.clone(),
            signing_key_epoch: security.key_epoch,
        })
    }

    pub(crate) fn readiness_probe(&self) -> ClusterReadinessProbe {
        ClusterReadinessProbe {
            health: Arc::clone(&self.health),
            authority: self.readiness_authority_snapshot(),
            instance_epoch: Arc::clone(&self.instance_epoch),
        }
    }

    pub fn peer_key_authority_identities(
        &self,
    ) -> Vec<northstar_security::cluster_keys::ClusterKeyDeploymentIdentity> {
        self.security
            .as_ref()
            .map(|security| {
                security
                    .peer_key_authorities()
                    .into_iter()
                    .map(
                        |peer| northstar_security::cluster_keys::ClusterKeyDeploymentIdentity {
                            xmpp_domain: self.namespace.clone(),
                            node_id: peer.node_id,
                            epoch: peer.epoch,
                            current_key_id: peer.current_key_id,
                            current_public_key_sha256: peer.current_public_key_sha256,
                            previous_key_id: peer.previous_key_id,
                            previous_public_key_sha256: peer.previous_public_key_sha256,
                            staged_next_key_id: peer.staged_next_key_id,
                            staged_next_public_key_sha256: peer.staged_next_public_key_sha256,
                        },
                    )
                    .collect()
            })
            .unwrap_or_default()
    }

    pub async fn activate(&self) -> Result<()> {
        if self.is_enabled() {
            anyhow::ensure!(
                self.instance_epoch.load(Ordering::Acquire) >= 1,
                "cluster node instance authority was not claimed"
            );
            self.touch_node().await?;
        }
        Ok(())
    }

    pub async fn claim_instance_authority(&self, pool: &sqlx::PgPool) -> Result<()> {
        if !self.is_enabled() {
            return Ok(());
        }
        let security = self
            .security
            .as_ref()
            .context("cluster signing identity is missing")?;
        let instance = crate::db::claim_cluster_node_instance(
            pool,
            &self.namespace,
            &self.node_id,
            self.connection_uuid,
            &security.current_key_id,
            security.key_epoch,
            Duration::from_secs(NODE_TTL_SECONDS),
        )
        .await?;
        self.install_instance_epoch(instance.instance_epoch)
    }

    pub fn install_instance_epoch(&self, instance_epoch: i64) -> Result<()> {
        anyhow::ensure!(
            instance_epoch >= 1,
            "cluster instance epoch must be positive"
        );
        let previous = self.instance_epoch.swap(instance_epoch, Ordering::AcqRel);
        anyhow::ensure!(
            previous == 0 || previous == instance_epoch,
            "cluster instance epoch changed inside one process"
        );
        Ok(())
    }

    pub async fn refresh_instance_authority(&self, pool: &sqlx::PgPool) -> Result<()> {
        // Bootstrap still owns its local pool before AppState is constructed.
        // Runtime workers use the AppState-owned typed authority service.
        let service = ClusterAuthorityService::new(
            crate::db::cluster_authority_repository::PostgresClusterAuthorityRepository::new(
                pool.clone(),
            ),
        );
        self.refresh_instance_authority_with(&service).await
    }

    pub(crate) async fn refresh_instance_authority_with<R: ClusterAuthorityRepository>(
        &self,
        service: &ClusterAuthorityService<R>,
    ) -> Result<()> {
        let Some(security) = self.security.as_ref() else {
            return Ok(());
        };
        let nodes = security.peer_node_ids();
        let expected = security.peer_key_authorities();
        refresh_peer_authority_with(
            service,
            &self.namespace,
            &expected,
            &nodes,
            &self.authorized_peer_keys,
            &self.authorized_instances,
        )
        .await
    }

    pub(crate) async fn release_instance_authority_with<R: ClusterInstanceReleaseRepository>(
        &self,
        service: &ClusterInstanceReleaseService<R>,
    ) -> Result<bool> {
        if !self.is_enabled() {
            return Ok(false);
        }
        let security = self
            .security
            .as_ref()
            .context("cluster signing identity is missing")?;
        service
            .release(&ClusterInstanceReleaseIdentity {
                xmpp_domain: self.namespace.clone(),
                node_id: self.node_id.clone(),
                instance_uuid: self.connection_uuid,
                instance_epoch: self.instance_epoch.load(Ordering::Acquire),
                signing_key_id: security.current_key_id.clone(),
                signing_key_epoch: security.key_epoch,
            })
            .await
    }

    pub(super) fn key(&self, suffix: String) -> String {
        format!("{}:{suffix}", self.key_prefix)
    }

    pub(super) fn process_instance_token(&self) -> Result<String> {
        let epoch = self.instance_epoch.load(Ordering::Acquire);
        anyhow::ensure!(epoch >= 1, "cluster process instance is not authoritative");
        Ok(format!("{}.{}", self.connection_uuid.simple(), epoch))
    }

    pub(super) fn process_alive_key(&self) -> Result<String> {
        Ok(self.key(format!(
            "node_instance:{}:{}:alive",
            self.node_id,
            self.process_instance_token()?
        )))
    }
}
