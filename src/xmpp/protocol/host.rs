//! What a protocol session needs from the node it runs in.

use super::ProtocolSession;
use crate::state::Sasl2FastTokenPolicy;
use dashmap::DashMap;
use northstar_room_application::muc_service::LocalMucOccupantIdentity;
use northstar_session_core::JoinedMucMembership;
use northstar_stream::local_routes::muc::MucOccupant;
use northstar_stream::local_routes::session::OnlineSession;
use std::sync::atomic::AtomicU8;
use std::sync::Arc;
use std::time::Duration;

/// The node a [`ProtocolSession`] runs in. The composition root implements it; the session core reaches the node
/// through it as each part of the core becomes generic over the host.
pub trait SessionHost: Sized + Send + Sync + 'static {
    /// Finalizes a session dropped without its asynchronous cleanup.
    fn drop_session(session: &mut ProtocolSession<Self>);
    /// See `AppState::account_service`.
    fn account_service(
        &self,
    ) -> &northstar_auth_application::account::AccountService<
        northstar_workflows::account_repository::WorkflowAccountRepository,
    >;
    /// Associate MUC occupants which were joined before SM enable with the
    /// newly-created durable stream epoch and update their Redis control
    /// records. This also makes active-session revocation exact and immune to
    /// nick reuse races.
    fn associate_local_muc_sm_session(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
        sm_session_id: uuid::Uuid,
        memberships: &DashMap<String, JoinedMucMembership>,
    ) -> impl std::future::Future<Output = ()> + Send;
    /// See `AppState::authentication_service`.
    fn authentication_service(
        &self,
    ) -> &northstar_auth_application::authentication::AuthenticationService<
        northstar_workflows::authentication_effects::PostgresAuthenticationRepository,
    >;
    /// See `AppState::c2s_authentication_telemetry`.
    fn c2s_authentication_telemetry(
        &self,
    ) -> crate::xmpp::capabilities::C2sAuthenticationTelemetry<'_>;
    /// See `AppState::c2s_post_action_telemetry`.
    fn c2s_post_action_telemetry(
        &self,
    ) -> northstar_session_application::post_actions::PostActionTelemetry<'_>;
    /// See `AppState::c2s_resource_bind_timeout_seconds`.
    fn c2s_resource_bind_timeout_seconds(&self) -> u64;
    /// See `AppState::capacity_session_lease_seconds`.
    fn capacity_session_lease_seconds(&self) -> u64;
    /// See `AppState::caps_by_jid`.
    fn caps_by_jid(&self) -> &northstar_protocol_runtime::caps::CapsResourceIndex;
    /// See `AppState::caps_cache`.
    fn caps_cache(&self) -> &northstar_protocol_runtime::caps::CapsCacheIndex;
    /// See `AppState::challenge_issue_service`.
    fn challenge_issue_service(
        &self,
    ) -> &northstar_abuse_application::challenge::ChallengeIssueService<
        northstar_abuse_postgres::challenge::PostgresChallengeRepository,
    >;
    /// Claim a route that remains unpublished until the login transaction
    /// commits. The binding proof is fixed at this boundary.
    fn claim_staged_binding_route(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
    ) -> impl std::future::Future<Output = anyhow::Result<bool>> + Send;
    /// See `AppState::finalize_resource_binding`.
    #[allow(clippy::too_many_arguments)]
    fn finalize_resource_binding(
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
    ) -> impl std::future::Future<
        Output = anyhow::Result<northstar_session_application::sm::BindingFinalizationOutcome>,
    > + Send;
    /// Validated local identity for protocol routing without exposing Config.
    fn local_domain(&self) -> &str;
    /// See `AppState::mix_service`.
    fn mix_service(
        &self,
    ) -> &northstar_room_application::mix_service::MixService<
        northstar_workflows::room_effects::PostgresMixRepository,
    >;
    /// See `AppState::outbound_stanza_telemetry`.
    fn outbound_stanza_telemetry(&self) -> crate::xmpp::capabilities::OutboundStanzaTelemetry<'_>;
    /// See `AppState::push_service`.
    fn push_service(
        &self,
    ) -> &northstar_message_application::push::PushService<
        northstar_workflows::push_repository::PostgresPushRepository,
    >;
    /// See `AppState::push_subscription_telemetry`.
    fn push_subscription_telemetry(
        &self,
    ) -> crate::xmpp::capabilities::PushSubscriptionTelemetry<'_>;
    /// See `AppState::record_bosh_session_closed`.
    fn record_bosh_session_closed(&self);
    /// See `AppState::record_c2s_backpressure_disconnect`.
    fn record_c2s_backpressure_disconnect(&self);
    /// Read the public-registration kill switch with acquire ordering.
    fn registration_is_closed(&self) -> bool;
    /// See `AppState::registration_requires_invitation`.
    fn registration_requires_invitation(&self) -> bool;
    /// See `AppState::registration_telemetry`.
    fn registration_telemetry(&self) -> crate::xmpp::capabilities::RegistrationTelemetry<'_>;
    /// See `AppState::release_staged_binding_route`.
    fn release_staged_binding_route(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
    ) -> impl std::future::Future<Output = anyhow::Result<()>> + Send;
    /// Compare and remove under one map shard lock. Callers retain the removed
    /// value for any post-removal delivery; no map guard crosses an await.
    fn remove_local_muc_occupant_exact(
        &self,
        identity: LocalMucOccupantIdentity<'_>,
    ) -> Option<MucOccupant>;
    /// Remove exactly one local route incarnation. Every rollback and Drop
    /// path must use this instead of an unconditional DashMap removal: a late
    /// old connection must never delete a newly bound/resumed replacement.
    fn remove_session_if_connection(
        &self,
        key: &str,
        connection_id: uuid::Uuid,
    ) -> Option<OnlineSession>;
    /// See `AppState::replay_service`.
    fn replay_service(
        &self,
    ) -> &northstar_session_application::replay::ReplayService<
        northstar_session_postgres::replay_repository::PostgresReplayRepository,
    >;
    /// See `AppState::sasl2_authentication_telemetry`.
    fn sasl2_authentication_telemetry(
        &self,
    ) -> crate::xmpp::capabilities::Sasl2AuthenticationTelemetry<'_>;
    /// See `AppState::sasl2_authentication_timer`.
    fn sasl2_authentication_timer(&self) -> northstar_telemetry::metrics::OwnedDurationTimer;
    /// See `AppState::sasl2_fast_token_policy`.
    fn sasl2_fast_token_policy(&self) -> Sasl2FastTokenPolicy;
    /// See `AppState::sasl_login_abuse_service`.
    fn sasl_login_abuse_service(
        &self,
    ) -> &northstar_abuse_application::login::SaslLoginAbuseService<
        northstar_abuse_postgres::login::PostgresSaslLoginAbuseRepository,
    >;
    /// See `AppState::session_bind_telemetry`.
    fn session_bind_telemetry(&self) -> crate::xmpp::capabilities::SessionBindTelemetry<'_>;
    /// See `AppState::session_drop_fallback_telemetry`.
    fn session_drop_fallback_telemetry(
        &self,
    ) -> crate::xmpp::capabilities::SessionDropFallbackTelemetry<'_>;
    /// A carbon preference is session-local and must be visible to fan-out
    /// before its IQ result is sent to the same connection.
    fn set_local_carbons_for_connection(
        &self,
        key: &str,
        connection_id: uuid::Uuid,
        enabled: bool,
    ) -> bool;
    /// See `AppState::sm_memory_governor`.
    fn sm_memory_governor(
        &self,
    ) -> &Arc<northstar_session_application::sm_capacity::SmMemoryGovernor>;
    /// See `AppState::sm_service`.
    fn sm_service(
        &self,
    ) -> &northstar_session_application::sm::SmService<
        northstar_workflows::sm_repository::PostgresSmRepository,
    >;
    /// See `AppState::sm_session_telemetry`.
    fn sm_session_telemetry(&self) -> crate::xmpp::capabilities::SmSessionTelemetry<'_>;
    /// See `AppState::staged_session_is_current`.
    fn staged_session_is_current(
        &self,
        key: &str,
        connection_id: uuid::Uuid,
        user_id: uuid::Uuid,
        auth_generation: i64,
        lifecycle: &Arc<AtomicU8>,
    ) -> bool;
    /// See `AppState::tls_context`.
    fn tls_context(&self) -> &northstar_security::tls::TlsContext;
    /// Reserve a non-routable bind candidate under the same map entry guard
    /// that rejects a concurrent bind or resume for this full JID.
    fn try_stage_bound_session(&self, key: String, session: OnlineSession) -> bool;
    /// See `AppState::unauthenticated_timeout`.
    fn unauthenticated_timeout(&self) -> Duration;
    /// See `AppState::worker_registry`.
    fn worker_registry(&self) -> &Arc<northstar_runtime::workers::WorkerRegistry>;
    /// See `AppState::xmpp_extension_enabled`.
    fn xmpp_extension_enabled(&self, id: northstar_xep_core::XepId) -> bool;
}
