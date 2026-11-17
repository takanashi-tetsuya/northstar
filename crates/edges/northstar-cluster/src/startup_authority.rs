//! Cluster startup signing-key reconciliation, instance claim and initial lease publication.

use crate::ClusterManager;
use anyhow::{Context, Result};
use northstar_security::cluster_keys::ClusterKeyDeploymentIdentity;
use northstar_session_application::cluster_authority::{
    ClusterAuthorityRepository, ClusterAuthorityService,
};
use std::future::Future;

/// Signing-key deployment reconciliation around the instance claim. The root binds it to PostgreSQL.
pub trait ClusterKeyDeploymentPort: Send + Sync {
    fn reconcile_before_instance_claim(
        &self,
        identity: &ClusterKeyDeploymentIdentity,
    ) -> impl Future<Output = Result<()>> + Send;

    fn reconcile_peer(
        &self,
        peer: &ClusterKeyDeploymentIdentity,
    ) -> impl Future<Output = Result<()>> + Send;

    fn finalize(
        &self,
        identity: &ClusterKeyDeploymentIdentity,
    ) -> impl Future<Output = Result<()>> + Send;
}

impl ClusterManager {
    /// With a signing identity, prepare the local key deployment, reconcile peers in
    /// `peer_key_authority_identities()` order, claim the instance, finalize the local
    /// deployment, then refresh peer instance authority. Activate after the identity
    /// branch succeeds or is skipped; stop immediately if any step fails.
    pub async fn establish_startup_authority<
        K: ClusterKeyDeploymentPort,
        R: ClusterAuthorityRepository,
    >(
        &self,
        keys: &K,
        authority: &ClusterAuthorityService<R>,
    ) -> Result<()> {
        if let Some(identity) = self.key_authority_identity() {
            keys.reconcile_before_instance_claim(&identity)
                .await
                .context("cluster signing-key authority preparation failed")?;
            for peer in self.peer_key_authority_identities() {
                keys.reconcile_peer(&peer).await.with_context(|| {
                    format!(
                        "configured cluster peer {} key authority is inconsistent",
                        peer.node_id
                    )
                })?;
            }
            self.claim_instance_authority()
                .await
                .context("cluster node ID is already owned by another live process")?;
            keys.finalize(&identity)
                .await
                .context("cluster signing-key authority finalization failed")?;
            self.refresh_instance_authority_with(authority)
                .await
                .context("could not load peer cluster instance authority")?;
        }
        self.activate()
            .await
            .context("failed to publish the initial signed cluster node lease")?;
        Ok(())
    }
}
