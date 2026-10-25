//! Read-only readiness context for the private readiness listeners.

/// Private observability capability. It contains only read-only live probes
/// and the existing typed persistence service, never AppState or a mutable
/// cluster, worker, connection, upload, or SM owner.
pub(crate) struct ReadinessContext {
    pub(crate) connection: northstar_runtime::connection_actors::ConnectionAdmissionReadiness,
    pub(crate) sm: crate::services::sm_capacity::SmMemoryReadiness,
    pub(crate) upload: northstar_upload_application::safety::UploadSafetyReadiness,
    pub(crate) cluster: crate::cluster::ClusterReadinessProbe,
    pub(crate) workers: northstar_runtime::workers::WorkerReadinessProbe,
    pub(crate) abuse_key_deployment:
        Option<crate::services::abuse::records::AbuseKeyDeploymentIdentity>,
    pub(crate) persistence: crate::services::readiness::ReadinessService<
        crate::db::readiness_repository::PostgresReadinessRepository,
    >,
}

impl ReadinessContext {
    pub(crate) fn connection_accepting(&self) -> bool {
        self.connection.is_accepting()
    }

    pub(crate) fn sm_ready(&self) -> bool {
        self.sm.is_ready()
    }

    pub(crate) fn upload_state(&self) -> northstar_upload_application::UploadSafetyState {
        self.upload.state()
    }

    pub(crate) fn cluster_error(&self) -> Option<String> {
        self.cluster.readiness_error()
    }

    pub(crate) fn worker_error(&self) -> Option<String> {
        self.workers.readiness_error()
    }

    pub(crate) fn cluster_authority_snapshot(
        &self,
    ) -> Option<northstar_security::cluster_keys::ClusterReadinessAuthority> {
        self.cluster.authority_snapshot()
    }

    pub(crate) async fn validate_persistence(
        &self,
        cluster_authority: Option<&northstar_security::cluster_keys::ClusterReadinessAuthority>,
    ) -> anyhow::Result<()> {
        self.persistence
            .validate_persistence(self.abuse_key_deployment.as_ref(), cluster_authority)
            .await
    }
}
