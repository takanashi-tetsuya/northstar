//! Read-only readiness context for the private readiness listeners.

use crate::repositories::HttpRepositories;

/// Private observability capability. It contains only read-only live probes
/// and the existing typed persistence service, never the node or a mutable
/// cluster, worker, connection, upload, or SM owner.
pub struct ReadinessContext<R: HttpRepositories> {
    pub connection: northstar_runtime::connection_actors::ConnectionAdmissionReadiness,
    pub sm: northstar_session_application::sm_capacity::SmMemoryReadiness,
    pub upload: northstar_upload_application::safety::UploadSafetyReadiness,
    pub cluster: std::sync::Arc<dyn northstar_operations_application::readiness::ClusterReadiness>,
    pub workers: northstar_runtime::workers::WorkerReadinessProbe,
    pub abuse_key_deployment: Option<northstar_abuse_policy::model::AbuseKeyDeploymentIdentity>,
    pub persistence: northstar_operations_application::readiness::ReadinessService<R::Readiness>,
}

impl<R: HttpRepositories> ReadinessContext<R> {
    pub fn connection_accepting(&self) -> bool {
        self.connection.is_accepting()
    }

    pub fn sm_ready(&self) -> bool {
        self.sm.is_ready()
    }

    pub fn upload_state(&self) -> northstar_upload_application::UploadSafetyState {
        self.upload.state()
    }

    pub fn cluster_error(&self) -> Option<String> {
        self.cluster.readiness_error()
    }

    pub fn worker_error(&self) -> Option<String> {
        self.workers.readiness_error()
    }

    pub fn cluster_authority_snapshot(
        &self,
    ) -> Option<northstar_security::cluster_keys::ClusterReadinessAuthority> {
        self.cluster.authority_snapshot()
    }

    pub async fn validate_persistence(
        &self,
        cluster_authority: Option<&northstar_security::cluster_keys::ClusterReadinessAuthority>,
    ) -> anyhow::Result<()> {
        self.persistence
            .validate_persistence(self.abuse_key_deployment.as_ref(), cluster_authority)
            .await
    }
}
