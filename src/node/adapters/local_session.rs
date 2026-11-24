//! `ServerNode` methods beside the live C2S session table: privacy evaluation, bind and SM finalization, route
//! removal and SM teardown. The table's own operations are `LocalSessionTable`'s, in northstar-stream.

use crate::node::*;
use northstar_session_application::sm_teardown::SmTeardownService;
use northstar_workflows::sm_teardown_repository::PostgresSmTeardownRepository;

impl ServerNode {
    /// Evaluate one resource's session-local XEP-0016 selection (or the
    /// account default when no active list is selected) without renewing it.
    /// The capacity lease heartbeat renews the selection separately. Callers apply
    /// XEP-0191 first; a blocking hit is never overridden by an allow rule.
    /// Stanza paths that still hold a storage-level kind convert it at this
    /// boundary; the service layer owns the mapping.
    pub async fn privacy_allows_session(
        &self,
        session: &OnlineSession,
        peer: &str,
        kind: impl Into<northstar_roster_application::privacy::PrivacyStanzaKind>,
    ) -> anyhow::Result<bool> {
        let active = session.privacy_active_snapshot();
        self.message
            .message_service
            .privacy_allows_session(
                session.user_id,
                session.connection_id,
                active.as_deref(),
                peer,
                kind.into(),
            )
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn finalize_resource_binding(
        &self,
        connection_id: uuid::Uuid,
        user_id: uuid::Uuid,
        expected_auth_generation: i64,
        full_jid: &str,
        device_id: Option<uuid::Uuid>,
        fast_plan: Option<&northstar_auth_application::authentication::FastCommitPlan>,
        observation: Option<
            &northstar_auth_application::authentication::publication::PreparedCredential,
        >,
    ) -> anyhow::Result<northstar_session_application::sm::BindingFinalizationOutcome> {
        self.session
            .sm_service
            .finalize_binding_observed(
                connection_id,
                user_id,
                expected_auth_generation,
                full_jid,
                self.config.capacity_session_lease_seconds,
                device_id,
                fast_plan,
                observation,
            )
            .await
    }

    pub(crate) async fn finalize_sm_resume(
        &self,
        request: northstar_session_application::sm::SmResumeFinalizationRequest<'_>,
        observation: Option<
            &northstar_auth_application::authentication::publication::PreparedCredential,
        >,
    ) -> anyhow::Result<northstar_session_application::sm::SmResumeFinalizationOutcome> {
        self.session
            .sm_service
            .finalize_resume_observed(request, observation)
            .await
    }

    /// Remove exactly one local route incarnation. Every rollback and Drop
    /// path must use this instead of an unconditional DashMap removal: a late
    /// old connection must never delete a newly bound/resumed replacement.
    pub fn remove_session_if_connection(
        &self,
        key: &str,
        connection_id: uuid::Uuid,
    ) -> Option<OnlineSession> {
        self.session_cleanup_local()
            .remove_session_if_connection(key, connection_id)
    }

    /// Revoke local account routes and request durable SM revocation.
    /// Remote nodes receive the generation fence over Redis, with a 30-second
    /// maintenance sweep as fallback while PostgreSQL remains available.
    pub async fn disconnect_account(&self, user_id: uuid::Uuid, bare_account_jid: &str) {
        self.account_teardown_runtime()
            .disconnect_account(user_id, bare_account_jid)
            .await;
    }

    pub async fn revoke_sm_session_with_teardown(&self, id: uuid::Uuid) -> anyhow::Result<()> {
        self.sm_teardown_claims()
            .revoke_exact(id, |snapshot| {
                let runtime = self.sm_teardown_runtime();
                async move {
                    runtime
                        .teardown_snapshot(
                            &crate::node::adapters::sm_teardown_runtime::sm_teardown_snapshot(
                                &snapshot,
                            ),
                        )
                        .await
                }
            })
            .await
    }

    pub(in crate::node) fn sm_teardown_claims(
        &self,
    ) -> SmTeardownService<PostgresSmTeardownRepository> {
        SmTeardownService::new(
            PostgresSmTeardownRepository::new(self.pool.clone()),
            self.config.sm_claim_lease_seconds,
        )
    }
}
