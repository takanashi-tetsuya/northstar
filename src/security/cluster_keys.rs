//! Cluster signing-key deployment, peer key and node instance records, and the identity of the cluster readiness probe.

use std::time::Duration;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClusterKeyDeploymentIdentity {
    pub xmpp_domain: String,
    pub node_id: String,
    pub epoch: i64,
    pub current_key_id: String,
    pub current_public_key_sha256: String,
    pub previous_key_id: Option<String>,
    pub previous_public_key_sha256: Option<String>,
    pub staged_next_key_id: Option<String>,
    pub staged_next_public_key_sha256: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClusterNodeInstance {
    pub node_id: String,
    pub instance_uuid: uuid::Uuid,
    pub instance_epoch: i64,
    pub signing_key_id: String,
    pub signing_key_epoch: i64,
    /// Remaining lifetime measured by PostgreSQL's clock at snapshot time.
    /// Callers convert this duration to a monotonic local deadline and never
    /// compare a database timestamp with the host wall clock.
    pub lease_remaining: Duration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpectedClusterPeerKey {
    pub node_id: String,
    pub epoch: i64,
    pub current_key_id: String,
    pub current_public_key_sha256: String,
    pub previous_key_id: Option<String>,
    pub previous_public_key_sha256: Option<String>,
    pub staged_next_key_id: Option<String>,
    pub staged_next_public_key_sha256: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClusterPeerKeyAuthority {
    pub node_id: String,
    pub epoch: i64,
    pub current_key_id: String,
    pub previous_key_id: Option<String>,
    pub staged_next_key_id: Option<String>,
}

/// Immutable identity used by the readiness persistence probe. Capturing the
/// local lease epoch alongside the configured key avoids passing live cluster
/// control-plane authority into the service or repository.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ClusterReadinessAuthority {
    pub(crate) key_identity: crate::security::cluster_keys::ClusterKeyDeploymentIdentity,
    pub(crate) instance_node_id: String,
    pub(crate) instance_uuid: uuid::Uuid,
    pub(crate) instance_epoch: i64,
    pub(crate) signing_key_id: String,
    pub(crate) signing_key_epoch: i64,
}
