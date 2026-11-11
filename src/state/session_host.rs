//! The node's side of the client session core.

use super::AppState;
use crate::state::Sasl2FastTokenPolicy;
use crate::xmpp::protocol::{ProtocolSession, SessionHost};
use dashmap::DashMap;
use northstar_room_application::muc_service::LocalMucOccupantIdentity;
use northstar_session_core::JoinedMucMembership;
use northstar_stream::local_routes::muc::MucOccupant;
use northstar_stream::local_routes::session::OnlineSession;
use std::sync::atomic::AtomicU8;
use std::sync::Arc;
use std::time::Duration;

impl SessionHost for AppState {
    fn drop_session(session: &mut ProtocolSession) {
        session.drop_on_node();
    }

    fn account_service(
        &self,
    ) -> &northstar_auth_application::account::AccountService<
        northstar_workflows::account_repository::WorkflowAccountRepository,
    > {
        AppState::account_service(self)
    }

    async fn associate_local_muc_sm_session(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
        sm_session_id: uuid::Uuid,
        memberships: &DashMap<String, JoinedMucMembership>,
    ) {
        AppState::associate_local_muc_sm_session(
            self,
            full_jid,
            connection_id,
            sm_session_id,
            memberships,
        )
        .await
    }

    fn authentication_service(
        &self,
    ) -> &northstar_auth_application::authentication::AuthenticationService<
        northstar_workflows::authentication_effects::PostgresAuthenticationRepository,
    > {
        AppState::authentication_service(self)
    }

    fn c2s_authentication_telemetry(
        &self,
    ) -> crate::xmpp::capabilities::C2sAuthenticationTelemetry<'_> {
        AppState::c2s_authentication_telemetry(self)
    }

    fn c2s_post_action_telemetry(
        &self,
    ) -> northstar_session_application::post_actions::PostActionTelemetry<'_> {
        AppState::c2s_post_action_telemetry(self)
    }

    fn c2s_resource_bind_timeout_seconds(&self) -> u64 {
        AppState::c2s_resource_bind_timeout_seconds(self)
    }

    fn capacity_session_lease_seconds(&self) -> u64 {
        AppState::capacity_session_lease_seconds(self)
    }

    fn caps_by_jid(&self) -> &northstar_protocol_runtime::caps::CapsResourceIndex {
        AppState::caps_by_jid(self)
    }

    fn caps_cache(&self) -> &northstar_protocol_runtime::caps::CapsCacheIndex {
        AppState::caps_cache(self)
    }

    fn challenge_issue_service(
        &self,
    ) -> &northstar_abuse_application::challenge::ChallengeIssueService<
        northstar_abuse_postgres::challenge::PostgresChallengeRepository,
    > {
        AppState::challenge_issue_service(self)
    }

    async fn claim_staged_binding_route(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
    ) -> anyhow::Result<bool> {
        AppState::claim_staged_binding_route(self, full_jid, connection_id).await
    }

    async fn finalize_resource_binding(
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
        AppState::finalize_resource_binding(
            self,
            connection_id,
            user_id,
            expected_auth_generation,
            full_jid,
            device_id,
            fast_plan,
            observation,
        )
        .await
    }

    fn local_domain(&self) -> &str {
        AppState::local_domain(self)
    }

    fn mix_service(
        &self,
    ) -> &northstar_room_application::mix_service::MixService<
        northstar_workflows::room_effects::PostgresMixRepository,
    > {
        AppState::mix_service(self)
    }

    fn outbound_stanza_telemetry(&self) -> crate::xmpp::capabilities::OutboundStanzaTelemetry<'_> {
        AppState::outbound_stanza_telemetry(self)
    }

    fn push_service(
        &self,
    ) -> &northstar_message_application::push::PushService<
        northstar_workflows::push_repository::PostgresPushRepository,
    > {
        AppState::push_service(self)
    }

    fn push_subscription_telemetry(
        &self,
    ) -> crate::xmpp::capabilities::PushSubscriptionTelemetry<'_> {
        AppState::push_subscription_telemetry(self)
    }

    fn record_bosh_session_closed(&self) {
        AppState::record_bosh_session_closed(self)
    }

    fn record_c2s_backpressure_disconnect(&self) {
        AppState::record_c2s_backpressure_disconnect(self)
    }

    fn registration_is_closed(&self) -> bool {
        AppState::registration_is_closed(self)
    }

    fn registration_requires_invitation(&self) -> bool {
        AppState::registration_requires_invitation(self)
    }

    fn registration_telemetry(&self) -> crate::xmpp::capabilities::RegistrationTelemetry<'_> {
        AppState::registration_telemetry(self)
    }

    async fn release_staged_binding_route(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
    ) -> anyhow::Result<()> {
        AppState::release_staged_binding_route(self, full_jid, connection_id).await
    }

    fn remove_local_muc_occupant_exact(
        &self,
        identity: LocalMucOccupantIdentity<'_>,
    ) -> Option<MucOccupant> {
        AppState::remove_local_muc_occupant_exact(self, identity)
    }

    fn remove_session_if_connection(
        &self,
        key: &str,
        connection_id: uuid::Uuid,
    ) -> Option<OnlineSession> {
        AppState::remove_session_if_connection(self, key, connection_id)
    }

    fn replay_service(
        &self,
    ) -> &northstar_session_application::replay::ReplayService<
        northstar_session_postgres::replay_repository::PostgresReplayRepository,
    > {
        AppState::replay_service(self)
    }

    fn sasl2_authentication_telemetry(
        &self,
    ) -> crate::xmpp::capabilities::Sasl2AuthenticationTelemetry<'_> {
        AppState::sasl2_authentication_telemetry(self)
    }

    fn sasl2_authentication_timer(&self) -> northstar_telemetry::metrics::OwnedDurationTimer {
        AppState::sasl2_authentication_timer(self)
    }

    fn sasl2_fast_token_policy(&self) -> Sasl2FastTokenPolicy {
        AppState::sasl2_fast_token_policy(self)
    }

    fn sasl_login_abuse_service(
        &self,
    ) -> &northstar_abuse_application::login::SaslLoginAbuseService<
        northstar_abuse_postgres::login::PostgresSaslLoginAbuseRepository,
    > {
        AppState::sasl_login_abuse_service(self)
    }

    fn session_bind_telemetry(&self) -> crate::xmpp::capabilities::SessionBindTelemetry<'_> {
        AppState::session_bind_telemetry(self)
    }

    fn session_drop_fallback_telemetry(
        &self,
    ) -> crate::xmpp::capabilities::SessionDropFallbackTelemetry<'_> {
        AppState::session_drop_fallback_telemetry(self)
    }

    fn set_local_carbons_for_connection(
        &self,
        key: &str,
        connection_id: uuid::Uuid,
        enabled: bool,
    ) -> bool {
        AppState::set_local_carbons_for_connection(self, key, connection_id, enabled)
    }

    fn sm_memory_governor(
        &self,
    ) -> &Arc<northstar_session_application::sm_capacity::SmMemoryGovernor> {
        AppState::sm_memory_governor(self)
    }

    fn sm_service(
        &self,
    ) -> &northstar_session_application::sm::SmService<
        northstar_workflows::sm_repository::PostgresSmRepository,
    > {
        AppState::sm_service(self)
    }

    fn sm_session_telemetry(&self) -> crate::xmpp::capabilities::SmSessionTelemetry<'_> {
        AppState::sm_session_telemetry(self)
    }

    fn staged_session_is_current(
        &self,
        key: &str,
        connection_id: uuid::Uuid,
        user_id: uuid::Uuid,
        auth_generation: i64,
        lifecycle: &Arc<AtomicU8>,
    ) -> bool {
        AppState::staged_session_is_current(
            self,
            key,
            connection_id,
            user_id,
            auth_generation,
            lifecycle,
        )
    }

    fn tls_context(&self) -> &northstar_security::tls::TlsContext {
        AppState::tls_context(self)
    }

    fn try_stage_bound_session(&self, key: String, session: OnlineSession) -> bool {
        AppState::try_stage_bound_session(self, key, session)
    }

    fn unauthenticated_timeout(&self) -> Duration {
        AppState::unauthenticated_timeout(self)
    }

    fn worker_registry(&self) -> &Arc<northstar_runtime::workers::WorkerRegistry> {
        AppState::worker_registry(self)
    }

    fn xmpp_extension_enabled(&self, id: northstar_xep_core::XepId) -> bool {
        AppState::xmpp_extension_enabled(self, id)
    }
}
