//! The node's side of the client session core.

use crate::node::adapters::session_cleanup::SessionCleanupAdapters;
use crate::node::hosts::iq_route::IQ_ROUTES;
use crate::node::CommittedLocalMucResume;
use crate::node::FederationRouter;
use crate::node::RestoredLocalMucOccupants;
use crate::node::ServerNode;
use crate::xmpp::protocol::messaging::MessageHandlers;
use crate::xmpp::protocol::ClientSession;
use crate::xmpp::protocol::SessionHost;
use anyhow::Result;
use dashmap::DashMap;
use northstar_auth_application::account_teardown::FinalizeAccountDeletion;
use northstar_auth_application::authentication::Sasl2FastTokenPolicy;
use northstar_mix_xmpp::MixHandlers;
use northstar_muc_xmpp::MucHandlers;
use northstar_pubsub_xmpp::PubSubHandlers;
use northstar_room_application::muc_service::LocalMucOccupantIdentity;
use northstar_roster_xmpp::PresenceHandlers;
use northstar_session_application::sm::{SmBufferLimits, SmSessionPolicy};
use northstar_session_core::JoinedMucMembership;
use northstar_session_core::LocalCapsEpoch;
use northstar_stream::local_routes::muc::MucOccupant;
use northstar_stream::local_routes::muc::RestoreLocalMucOccupantsRequest;
use northstar_stream::local_routes::muc::SuspendedMucEndpoint;
use northstar_stream::local_routes::session::OnlineSession;
use northstar_stream::local_routes::session::SmPresenceEpoch;
use northstar_stream::local_routes::session::SmStagedRouteClaim;
use northstar_stream::protocol::dispatch::route::ClientIqRoute;
use northstar_stream::session_cleanup::service::SessionCleanupService;
use northstar_stream::transport::Action;
use northstar_stream::IqRouter;
use roxmltree::Node;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

impl SessionHost for ServerNode {
    type AccountStore = northstar_workflows::account_repository::WorkflowAccountRepository;
    type AuthenticationStore =
        northstar_workflows::authentication_effects::PostgresAuthenticationRepository;
    type ChallengeStore = northstar_abuse_postgres::challenge::PostgresChallengeRepository;
    type MixStore = northstar_workflows::room_effects::PostgresMixRepository;
    type PushStore = northstar_workflows::push_repository::PostgresPushRepository;
    type ReplayStore = northstar_session_postgres::replay_repository::PostgresReplayRepository;
    type LoginAbuseStore = northstar_abuse_postgres::login::PostgresSaslLoginAbuseRepository;
    type SmStore = northstar_workflows::sm_repository::PostgresSmRepository;
    type PresenceStore = northstar_workflows::presence_repository::PostgresPresenceRepository;
    type PrivacyStore = northstar_roster_postgres::privacy::PostgresPrivacyRepository;

    fn drop_session(session: &mut ClientSession) {
        session.drop_on_node();
    }

    fn account_service(
        &self,
    ) -> &northstar_auth_application::account::AccountService<
        northstar_workflows::account_repository::WorkflowAccountRepository,
    > {
        self.auth.account_service()
    }

    async fn associate_local_muc_sm_session(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
        sm_session_id: uuid::Uuid,
        memberships: &DashMap<String, JoinedMucMembership>,
    ) {
        northstar_muc_xmpp::resume::associate_local_muc_sm_session(
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
        self.auth.authentication_service()
    }

    fn c2s_authentication_telemetry(
        &self,
    ) -> northstar_session_application::telemetry::C2sAuthenticationTelemetry<'_> {
        northstar_session_application::telemetry::C2sAuthenticationTelemetry::new(
            &self.metrics.authentication_backend_failures_total,
            &self.metrics.fast_credential_integrity_failures_total,
            &self.metrics.authentication_failures_total,
            &self.metrics.rate_limited_total,
        )
    }

    fn c2s_post_action_telemetry(
        &self,
    ) -> northstar_session_application::post_actions::PostActionTelemetry<'_> {
        northstar_session_application::post_actions::PostActionTelemetry::new(
            &self.metrics.post_action_tasks_started_total,
            &self.metrics.post_action_tasks_completed_total,
            &self.metrics.post_action_tasks_panicked_total,
            &self.metrics.post_action_tasks_aborted_total,
            &self.metrics.post_action_capacity_rejections_total,
        )
    }

    fn c2s_resource_bind_timeout_seconds(&self) -> u64 {
        self.config.resource_bind_timeout_seconds
    }

    fn capacity_session_lease_seconds(&self) -> u64 {
        self.config.capacity_session_lease_seconds
    }

    fn caps_by_jid(&self) -> &northstar_protocol_runtime::caps::CapsResourceIndex {
        ServerNode::caps_by_jid(self)
    }

    fn federated_caps_gates(&self) -> &northstar_protocol_runtime::caps::FederatedCapsGateIndex {
        ServerNode::federated_caps_gates(self)
    }

    fn caps_cache(&self) -> &northstar_protocol_runtime::caps::CapsCacheIndex {
        ServerNode::caps_cache(self)
    }

    fn challenge_issue_service(
        &self,
    ) -> &northstar_abuse_application::challenge::ChallengeIssueService<
        northstar_abuse_postgres::challenge::PostgresChallengeRepository,
    > {
        self.abuse.challenge_issue_service()
    }

    async fn claim_staged_binding_route(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
    ) -> anyhow::Result<bool> {
        self.cluster
            .claim_staged_binding_route(full_jid, connection_id)
            .await
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
        ServerNode::finalize_resource_binding(
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
        &self.config.domain
    }

    fn mix_service(
        &self,
    ) -> &northstar_room_application::mix_service::MixService<
        northstar_workflows::room_effects::PostgresMixRepository,
    > {
        self.room.mix_service()
    }

    fn outbound_stanza_telemetry(
        &self,
    ) -> northstar_session_application::telemetry::OutboundStanzaTelemetry<'_> {
        northstar_session_application::telemetry::OutboundStanzaTelemetry::new(
            &self.metrics.stanzas_out_total,
        )
    }

    fn push_service(
        &self,
    ) -> &northstar_message_application::push::PushService<
        northstar_workflows::push_repository::PostgresPushRepository,
    > {
        self.message.push_service()
    }

    fn push_subscription_telemetry(
        &self,
    ) -> northstar_session_application::telemetry::PushSubscriptionTelemetry<'_> {
        northstar_session_application::telemetry::PushSubscriptionTelemetry::new(
            &self.metrics.rate_limited_total,
            &self.metrics.push_subscriptions_rate_limited_total,
        )
    }

    fn record_bosh_session_closed(&self) {
        self.metrics.record_bosh_session_closed()
    }

    fn record_c2s_backpressure_disconnect(&self) {
        self.metrics.record_c2s_backpressure_disconnect()
    }

    fn registration_is_closed(&self) -> bool {
        self.config.registration_dependency_locked()
            || self.registration_closed.load(Ordering::Acquire)
    }

    fn registration_requires_invitation(&self) -> bool {
        self.config.registration_requires_invitation(
            self.config.registration_dependency_locked()
                || self.registration_closed.load(Ordering::Acquire),
        )
    }

    fn registration_telemetry(
        &self,
    ) -> northstar_session_application::telemetry::RegistrationTelemetry<'_> {
        northstar_session_application::telemetry::RegistrationTelemetry::new(
            &self.metrics.anti_abuse_backend_failures_total,
            &self.metrics.registrations_total,
            &self.metrics.rate_limited_total,
            &self.metrics.capacity_reservations_rejected_total,
        )
    }

    async fn release_staged_binding_route(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
    ) -> anyhow::Result<()> {
        self.cluster
            .release_staged_binding_route(full_jid, connection_id)
            .await
    }

    fn remove_local_muc_occupant_exact(
        &self,
        identity: LocalMucOccupantIdentity<'_>,
    ) -> Option<MucOccupant> {
        self.room
            .muc_occupants
            .remove_local_muc_occupant_exact(identity)
    }

    fn remove_session_if_connection(
        &self,
        key: &str,
        connection_id: uuid::Uuid,
    ) -> Option<OnlineSession> {
        ServerNode::remove_session_if_connection(self, key, connection_id)
    }

    fn replay_service(
        &self,
    ) -> &northstar_session_application::replay::ReplayService<
        northstar_session_postgres::replay_repository::PostgresReplayRepository,
    > {
        self.session.replay_service()
    }

    fn sasl2_authentication_telemetry(
        &self,
    ) -> northstar_session_application::telemetry::Sasl2AuthenticationTelemetry<'_> {
        northstar_session_application::telemetry::Sasl2AuthenticationTelemetry::new(
            &self.metrics.fast_credential_integrity_failures_total,
            &self.metrics.authentication_backend_failures_total,
        )
    }

    fn sasl2_authentication_timer(&self) -> northstar_telemetry::metrics::OwnedDurationTimer {
        self.metrics
            .authentication_duration_seconds
            .start_owned_timer()
    }

    fn sasl2_fast_token_policy(&self) -> Sasl2FastTokenPolicy {
        northstar_auth_application::authentication::Sasl2FastTokenPolicy {
            enabled: self.config.fast_token_enabled,
            rotation_days: self.config.fast_token_rotation_days,
            ttl_days: self.config.fast_token_ttl_days,
            strong_reauth_max_days: self.config.fast_strong_reauth_max_days,
        }
    }

    fn sasl_login_abuse_service(
        &self,
    ) -> &northstar_abuse_application::login::SaslLoginAbuseService<
        northstar_abuse_postgres::login::PostgresSaslLoginAbuseRepository,
    > {
        self.abuse.sasl_login_abuse_service()
    }

    fn session_bind_telemetry(
        &self,
    ) -> northstar_session_application::telemetry::SessionBindTelemetry<'_> {
        northstar_session_application::telemetry::SessionBindTelemetry::new(
            &self.metrics.capacity_reservations_rejected_total,
            &self.metrics.active_sessions,
        )
    }

    fn session_drop_fallback_telemetry(
        &self,
    ) -> northstar_session_application::telemetry::SessionDropFallbackTelemetry<'_> {
        northstar_session_application::telemetry::SessionDropFallbackTelemetry::new(
            &self.metrics.session_drop_fallbacks_total,
        )
    }

    fn set_local_carbons_for_connection(
        &self,
        key: &str,
        connection_id: uuid::Uuid,
        enabled: bool,
    ) -> bool {
        self.sessions
            .set_local_carbons_for_connection(key, connection_id, enabled)
    }

    fn sm_memory_governor(
        &self,
    ) -> &Arc<northstar_session_application::sm_capacity::SmMemoryGovernor> {
        ServerNode::sm_memory_governor(self)
    }

    fn sm_service(
        &self,
    ) -> &northstar_session_application::sm::SmService<
        northstar_workflows::sm_repository::PostgresSmRepository,
    > {
        self.session.sm_service()
    }

    fn sm_session_telemetry(
        &self,
    ) -> northstar_session_application::telemetry::SmSessionTelemetry<'_> {
        northstar_session_application::telemetry::SmSessionTelemetry::new(
            &self.metrics.capacity_reservations_rejected_total,
            &self.metrics.active_sessions,
        )
    }

    fn staged_session_is_current(
        &self,
        key: &str,
        connection_id: uuid::Uuid,
        user_id: uuid::Uuid,
        auth_generation: i64,
        lifecycle: &Arc<AtomicU8>,
    ) -> bool {
        self.sessions.staged_session_is_current(
            key,
            connection_id,
            user_id,
            auth_generation,
            lifecycle,
        )
    }

    fn tls_context(&self) -> &northstar_security::tls::TlsContext {
        &self.tls_context
    }

    fn try_stage_bound_session(&self, key: String, session: OnlineSession) -> bool {
        self.sessions.try_stage_bound_session(key, session)
    }

    fn unauthenticated_timeout(&self) -> Duration {
        self.config.unauthenticated_timeout()
    }

    fn worker_registry(&self) -> &Arc<northstar_runtime::workers::WorkerRegistry> {
        ServerNode::worker_registry(self)
    }

    fn xmpp_extension_enabled(&self, id: northstar_xep_core::XepId) -> bool {
        self.config.xmpp_extension_enabled(id)
    }

    async fn abort_local_muc_resume(
        &self,
        restored: &RestoredLocalMucOccupants,
        snapshot_backed: bool,
    ) {
        northstar_muc_xmpp::resume::abort_local_muc_resume(self, restored, snapshot_backed).await
    }

    fn activate_session_if_current(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
        user_id: uuid::Uuid,
        auth_generation: i64,
        lifecycle: &Arc<AtomicU8>,
        disconnect: &CancellationToken,
    ) -> bool {
        self.sessions.activate_session_if_current(
            full_jid,
            connection_id,
            user_id,
            auth_generation,
            lifecycle,
            disconnect,
        )
    }

    async fn begin_suspended_muc_resume(
        &self,
        endpoints: &[Arc<SuspendedMucEndpoint>],
        base_stanzas: usize,
        base_bytes: usize,
    ) -> bool {
        northstar_stream::local_routes::suspended_muc::begin_suspended_muc_resume(
            endpoints,
            base_stanzas,
            base_bytes,
        )
        .await
    }

    fn c2s_scram_sha1_enabled(&self) -> bool {
        self.config.scram_sha1_enabled
    }

    fn caps_effect_dispatcher(
        &self,
    ) -> &Arc<northstar_protocol_runtime::caps::CapsEffectDispatcher> {
        ServerNode::caps_effect_dispatcher(self)
    }

    fn caps_effect_telemetry(
        &self,
    ) -> northstar_session_application::telemetry::CapsEffectTelemetry<'_> {
        northstar_session_application::telemetry::CapsEffectTelemetry::new(
            &self.metrics.caps_effect_coalesced_total,
            &self.metrics.caps_effect_queue_saturated_total,
            &self.metrics.caps_effect_failures_total,
            &self.metrics.caps_effect_latency_seconds,
        )
    }

    type RestoredMuc = RestoredLocalMucOccupants;

    async fn checkpoint_local_muc_resume(&self, restored: &RestoredLocalMucOccupants) -> bool {
        northstar_muc_xmpp::resume::checkpoint_local_muc_resume(restored).await
    }

    async fn claim_sm_resume_route(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
        session_id: uuid::Uuid,
        claim_token: uuid::Uuid,
    ) -> anyhow::Result<bool> {
        self.cluster
            .claim_sm_resume_route(full_jid, connection_id, session_id, claim_token)
            .await
    }

    fn clear_suspended_sm_capacity(&self, endpoints: &[Arc<SuspendedMucEndpoint>]) {
        northstar_stream::local_routes::suspended_muc::clear_suspended_sm_capacity(endpoints)
    }

    async fn commit_local_muc_resume(
        &self,
        restored: RestoredLocalMucOccupants,
        sender: &northstar_stream::outbound::OutboundSender,
        capacity: northstar_session_application::sm_capacity::SmCapacityLease,
    ) -> CommittedLocalMucResume {
        northstar_muc_xmpp::resume::commit_local_muc_resume(self, restored, sender, capacity).await
    }

    async fn finalize_sm_resume(
        &self,
        request: northstar_session_application::sm::SmResumeFinalizationRequest<'_>,
        observation: Option<
            &northstar_auth_application::authentication::publication::PreparedCredential,
        >,
    ) -> anyhow::Result<northstar_session_application::sm::SmResumeFinalizationOutcome> {
        ServerNode::finalize_sm_resume(self, request, observation).await
    }

    fn local_caps_epoch_is_current(
        &self,
        full_jid: &str,
        epoch: LocalCapsEpoch,
        expected_gate: Option<&Arc<tokio::sync::Mutex<()>>>,
    ) -> bool {
        self.sessions
            .local_caps_epoch_is_current(full_jid, epoch, expected_gate)
    }

    fn local_caps_observer_connection_is_current(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
        expected_gate: &Arc<tokio::sync::Mutex<()>>,
    ) -> bool {
        self.sessions.local_caps_observer_connection_is_current(
            full_jid,
            connection_id,
            expected_gate,
        )
    }

    async fn mark_suspended_muc_durable(&self, endpoints: Vec<Arc<SuspendedMucEndpoint>>) -> bool {
        ServerNode::mark_suspended_muc_durable(self, endpoints).await
    }

    async fn notify_remote_user_agent_replacement(
        &self,
        account: &str,
        user_id: uuid::Uuid,
        device_id: uuid::Uuid,
        epoch: i64,
    ) -> anyhow::Result<()> {
        self.cluster
            .notify_remote_user_agent_replacement(account, user_id, device_id, epoch)
            .await
    }

    async fn pause_suspended_muc_delivery(
        &self,
        sm_session_id: uuid::Uuid,
    ) -> Vec<Arc<SuspendedMucEndpoint>> {
        northstar_stream::local_routes::suspended_muc::pause_suspended_muc_delivery(
            &self.room.muc_occupants,
            &self.room.suspended_muc_sessions,
            sm_session_id,
        )
        .await
    }

    fn pending_caps(&self) -> &northstar_protocol_runtime::caps::PendingCapsIndex {
        ServerNode::pending_caps(self)
    }

    fn publish_user_agent_epoch_if_current(
        &self,
        key: &str,
        connection_id: uuid::Uuid,
        user_id: uuid::Uuid,
        auth_generation: i64,
        lifecycle: &Arc<AtomicU8>,
        user_agent_epoch: Option<i64>,
    ) -> bool {
        self.sessions.publish_user_agent_epoch_if_current(
            key,
            connection_id,
            user_id,
            auth_generation,
            lifecycle,
            user_agent_epoch,
        )
    }

    fn push_delivery_telemetry(
        &self,
    ) -> northstar_session_application::telemetry::PushDeliveryTelemetry<'_> {
        northstar_session_application::telemetry::PushDeliveryTelemetry::new(
            &self.metrics.push_notifications_failed_total,
            &self.metrics.push_notifications_routed_total,
            &self.metrics.push_notifications_attempted_total,
        )
    }

    async fn release_exact_local_session_route(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
    ) -> anyhow::Result<()> {
        self.cluster
            .release_exact_local_session_route(full_jid, connection_id)
            .await
    }

    async fn restore_local_muc_occupants(
        &self,
        request: RestoreLocalMucOccupantsRequest<'_>,
    ) -> RestoredLocalMucOccupants {
        northstar_muc_xmpp::resume::restore_local_muc_occupants(self, request).await
    }

    async fn revoke_sm_session_with_teardown(&self, id: uuid::Uuid) -> anyhow::Result<()> {
        ServerNode::revoke_sm_session_with_teardown(self, id).await
    }

    async fn seal_suspended_muc_endpoints(&self, endpoints: &[Arc<SuspendedMucEndpoint>]) {
        ServerNode::seal_suspended_muc_endpoints(self, endpoints).await
    }

    fn session_entries_for(&self, jid: &str) -> Vec<(String, OnlineSession)> {
        self.sessions.session_entries_for(jid)
    }

    fn sm_buffer_limits(&self) -> SmBufferLimits {
        northstar_session_application::sm::SmBufferLimits {
            max_unacked_stanzas: self.config.sm_max_unacked_stanzas,
            max_unacked_bytes: self.config.sm_max_unacked_bytes,
            max_snapshot_bytes: self.config.sm_max_snapshot_bytes,
        }
    }

    fn sm_ip_binding(&self) -> &str {
        &self.config.sm_ip_binding
    }

    fn sm_pending_route_removal_signal(
        &self,
        key: &str,
        old_connection_id: uuid::Uuid,
        user_id: uuid::Uuid,
        sm_session_id: uuid::Uuid,
        cancel_live_route: bool,
    ) -> Option<tokio::sync::watch::Receiver<bool>> {
        self.sessions.sm_pending_route_removal_signal(
            key,
            old_connection_id,
            user_id,
            sm_session_id,
            cancel_live_route,
        )
    }

    fn sm_presence_epoch(&self, key: &str) -> Option<SmPresenceEpoch> {
        self.sessions.sm_presence_epoch(key)
    }

    fn sm_session_policy(&self) -> SmSessionPolicy {
        northstar_session_application::sm::SmSessionPolicy {
            require_same_device: self.config.sm_require_same_device,
            resume_timeout_seconds: self.config.sm_resume_timeout_seconds,
            live_lease_seconds: self.config.sm_live_lease_seconds,
            claim_lease_seconds: self.config.sm_claim_lease_seconds,
            max_per_account: self.config.max_sessions_per_account,
            max_global: self.config.sm_max_resumable_sessions,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn enqueue_sm_suspension_recovery(
        &self,
        account: northstar_session_application::SessionCleanupAccount,
        connection_id: uuid::Uuid,
        session_id: uuid::Uuid,
        snapshot: northstar_session_application::sm::SmSessionSnapshot,
        ttl_seconds: u64,
        endpoints: Vec<Arc<northstar_stream::local_routes::muc::SuspendedMucEndpoint>>,
        capacity: northstar_session_application::sm_capacity::SmCapacityLease,
    ) -> bool {
        ServerNode::sm_suspension_recovery_queue(self).enqueue(
            account,
            connection_id,
            session_id,
            snapshot,
            ttl_seconds,
            endpoints,
            capacity,
        )
    }

    fn enqueue_sm_promote_recovery(
        &self,
        connection_id: uuid::Uuid,
        session_id: uuid::Uuid,
        endpoints: Vec<Arc<northstar_stream::local_routes::muc::SuspendedMucEndpoint>>,
        capacity: northstar_session_application::sm_capacity::SmCapacityLease,
    ) -> bool {
        ServerNode::sm_suspension_recovery_queue(self).enqueue_promote(
            connection_id,
            session_id,
            endpoints,
            capacity,
        )
    }

    fn stage_sm_resumed_session(
        &self,
        key: String,
        candidate: OnlineSession,
        claimant_user: uuid::Uuid,
        claimed_sm_id: uuid::Uuid,
        expected_gate: &Arc<tokio::sync::Mutex<()>>,
    ) -> SmStagedRouteClaim {
        self.sessions.stage_sm_resumed_session(
            key,
            candidate,
            claimant_user,
            claimed_sm_id,
            expected_gate,
        )
    }

    fn muc_domain(&self) -> String {
        northstar_muc_xmpp::muc::muc_service_domain(self.config.domain.as_str())
    }

    fn mix_domain(&self) -> String {
        northstar_mix_xmpp::local_mix_domain(self.config.domain.as_str())
    }

    fn pubsub_domain(&self) -> String {
        northstar_pubsub_xmpp::pubsub::pubsub_domain(self)
    }

    fn upload_domain(&self) -> String {
        northstar_upload_xmpp::upload_service_domain(self.config.domain.as_str())
    }

    fn http_upload_enabled(&self) -> bool {
        self.config.xmpp_http_upload_enabled()
    }

    async fn dispatch_message(
        session: &ClientSession,
        root: Node<'_, '_>,
        raw: &str,
        client_raw: &str,
    ) -> Result<Action> {
        session.message(root, raw, client_raw).await
    }

    async fn dispatch_muc_message(
        session: &ClientSession,
        root: Node<'_, '_>,
        raw: &str,
    ) -> Result<Action> {
        ClientSession::muc_message(session, root, raw).await
    }

    async fn dispatch_mix_message(
        session: &ClientSession,
        root: Node<'_, '_>,
        raw: &str,
    ) -> Result<Option<Action>> {
        ClientSession::try_mix_message(session, root, raw).await
    }

    async fn dispatch_pubsub_authorization_response(
        session: &ClientSession,
        root: Node<'_, '_>,
    ) -> Result<bool> {
        match ClientSession::pubsub_authorization_response(session, root).await {
            Err(error) if northstar_pubsub_application::is_pubsub_mutation_busy(&error) => {
                tracing::warn!(
                    "dropping PubSub authorization form while mutation capacity is exhausted"
                );
                Ok(true)
            }
            result => result,
        }
    }

    async fn dispatch_presence(
        session: &mut ClientSession,
        root: Node<'_, '_>,
        raw: &str,
    ) -> Result<Action> {
        session.presence(root, raw).await
    }

    async fn dispatch_mix_iq(session: &ClientSession, raw: &str) -> Result<Option<Action>> {
        session.try_mix_iq(raw).await
    }

    async fn authorized_muc_occupant(
        session: &ClientSession,
        room_jid: &str,
    ) -> Result<Option<MucOccupant>> {
        session.authorized_muc_occupant(room_jid).await
    }

    fn iq_routes() -> &'static IqRouter<ClientIqRoute<ServerNode>> {
        &IQ_ROUTES
    }

    async fn blocked_muc_recipient_accounts(
        &self,
        occupants: &[MucOccupant],
        stanza_senders: &[String],
    ) -> std::collections::HashSet<String> {
        self.muc_delivery_context()
            .blocked_muc_recipient_accounts(occupants, stanza_senders)
            .await
    }

    async fn deliver_to_muc_occupant(&self, occupant: &MucOccupant, stanza: String) -> bool {
        self.muc_delivery_context()
            .deliver_to_muc_occupant(occupant, stanza)
            .await
    }

    type S2sOutbox = FederationRouter;

    fn federation_outbox(&self) -> &FederationRouter {
        &self.federation.federation_outbox
    }

    fn inbound_stanza_telemetry(
        &self,
    ) -> northstar_session_application::telemetry::InboundStanzaTelemetry<'_> {
        northstar_session_application::telemetry::InboundStanzaTelemetry::new(
            &self.metrics.stanzas_in_total,
        )
    }

    fn local_muc_occupant_by_nick(&self, room_jid: &str, nick: &str) -> Option<MucOccupant> {
        self.room
            .muc_occupants
            .local_muc_occupant_by_nick(room_jid, nick)
    }

    async fn personal_message_remote_resource_exists(&self, jid: &str) -> bool {
        self.cluster
            .personal_message_remote_resource_exists(jid)
            .await
    }

    fn presence_service(
        &self,
    ) -> &northstar_roster_application::presence::PresenceService<
        northstar_workflows::presence_repository::PostgresPresenceRepository,
    > {
        self.roster.presence_service()
    }

    async fn privacy_allows_session(
        &self,
        session: &OnlineSession,
        peer: &str,
        kind: impl Into<northstar_roster_application::privacy::PrivacyStanzaKind> + Send,
    ) -> anyhow::Result<bool> {
        ServerNode::privacy_allows_session(self, session, peer, kind).await
    }

    fn privacy_service(
        &self,
    ) -> &northstar_roster_application::privacy::PrivacyService<
        northstar_roster_postgres::privacy::PostgresPrivacyRepository,
    > {
        self.roster.privacy_service()
    }

    async fn route_client_iq_to_remote_resource(&self, full_jid: &str, stanza: &str) -> bool {
        self.cluster
            .route_client_iq_to_remote_resource(full_jid, stanza)
            .await
    }

    fn xmpp_external_route_domain_allowed(&self, domain: &str) -> bool {
        self.config.external_route_domain_allowed(domain)
    }

    fn xmpp_route_enabled(
        &self,
        stanza: northstar_xep_core::StanzaKind,
        namespace: &str,
        local_name: &str,
    ) -> bool {
        self.config
            .xmpp_route_enabled(stanza, namespace, local_name)
    }

    type Cleanup = SessionCleanupService<SessionCleanupAdapters>;

    fn session_cleanup(self: Arc<Self>) -> SessionCleanupService<SessionCleanupAdapters> {
        self.compose_session_cleanup()
    }

    async fn finalize_account_deletion(
        &self,
        user_id: uuid::Uuid,
        username: &str,
    ) -> Result<FinalizeAccountDeletion> {
        northstar_auth_xmpp::account_deletion::finalize(
            &self.account_deletion_recovery_context(),
            user_id,
            username,
        )
        .await
    }

    fn account_abuse_telemetry(
        &self,
    ) -> northstar_session_application::telemetry::AccountAbuseTelemetry<'_> {
        northstar_session_application::telemetry::AccountAbuseTelemetry::new(
            &self.metrics.anti_abuse_backend_failures_total,
            &self.metrics.rate_limited_total,
        )
    }

    async fn disconnect_account(&self, user_id: uuid::Uuid, bare_account_jid: &str) {
        ServerNode::disconnect_account(self, user_id, bare_account_jid).await
    }

    async fn replay_pubsub_last_items(
        self: Arc<Self>,
        outbound: northstar_stream::outbound::OutboundSender,
        recipient_id: uuid::Uuid,
        active_privacy_list: Option<String>,
        connection_id: uuid::Uuid,
        recipient: String,
        show: &'static str,
    ) -> anyhow::Result<()> {
        northstar_pubsub_xmpp::delivery::deliver_last_items_on_presence(
            self.pubsub.pubsub_service(),
            northstar_pubsub_xmpp::pubsub::pubsub_domain(self.as_ref()),
            outbound,
            recipient_id,
            active_privacy_list,
            connection_id,
            recipient,
            show,
        )
        .await
    }
}
