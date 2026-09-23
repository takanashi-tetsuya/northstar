use super::AppState;

impl AppState {
    /// Claim a route that remains unpublished until the login transaction
    /// commits. The binding proof is fixed at this boundary.
    pub(crate) async fn claim_staged_binding_route(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
    ) -> anyhow::Result<bool> {
        self.cluster
            .try_register_session(
                full_jid,
                connection_id,
                crate::services::sm::SessionRouteClaimProof::Binding,
            )
            .await
    }

    pub(crate) async fn release_staged_binding_route(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
    ) -> anyhow::Result<()> {
        self.release_exact_local_session_route(full_jid, connection_id)
            .await
    }

    pub(crate) async fn claim_sm_resume_route(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
        session_id: uuid::Uuid,
        claim_token: uuid::Uuid,
    ) -> anyhow::Result<bool> {
        self.cluster
            .try_register_session(
                full_jid,
                connection_id,
                crate::services::sm::SessionRouteClaimProof::SmResume {
                    session_id,
                    claim_token,
                },
            )
            .await
    }

    pub(crate) async fn release_exact_local_session_route(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
    ) -> anyhow::Result<()> {
        self.cluster
            .unregister_session(full_jid, connection_id)
            .await
    }

    pub(crate) async fn notify_remote_user_agent_replacement(
        &self,
        account: &str,
        user_id: uuid::Uuid,
        device_id: uuid::Uuid,
        epoch: i64,
    ) -> anyhow::Result<()> {
        self.cluster
            .send_user_agent_replacement(account, user_id, device_id, epoch)
            .await
    }

    pub(crate) async fn notify_remote_account_generation_teardown(
        &self,
        account: &str,
        user_id: uuid::Uuid,
        auth_generation: i64,
    ) -> anyhow::Result<()> {
        self.cluster
            .send_account_generation_teardown(account, user_id, auth_generation)
            .await
    }

    pub(crate) async fn notify_remote_session_instance_termination(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
    ) -> anyhow::Result<bool> {
        self.cluster
            .send_session_instance_termination(full_jid, connection_id)
            .await
    }
}
