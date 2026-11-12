//! The node's side of the client session core.

use super::AppState;
use crate::s2s::FederationRouter;
use crate::state::session_cleanup::SessionCleanupService;
use crate::state::CommittedLocalMucResume;
use crate::state::RestoredLocalMucOccupants;
use crate::xmpp::protocol::dispatch::iq_routes::{RootIqRoute, IQ_ROUTES};
use crate::xmpp::protocol::messaging::MessageHandlers;
use crate::xmpp::protocol::mix::MixHandlers;
use crate::xmpp::protocol::muc::MucHandlers;
use crate::xmpp::protocol::presence::PresenceHandlers;
use crate::xmpp::protocol::pubsub::PubSubHandlers;
use crate::xmpp::protocol::ClientSession;
use crate::xmpp::protocol::SessionHost;
use anyhow::Result;
use dashmap::DashMap;
use northstar_auth_application::account_teardown::FinalizeAccountDeletion;
use northstar_auth_application::authentication::Sasl2FastTokenPolicy;
use northstar_room_application::muc_service::LocalMucOccupantIdentity;
use northstar_session_application::sm::{SmBufferLimits, SmSessionPolicy};
use northstar_session_core::JoinedMucMembership;
use northstar_session_core::LocalCapsEpoch;
use northstar_stream::local_routes::muc::MucOccupant;
use northstar_stream::local_routes::muc::RestoreLocalMucOccupantsRequest;
use northstar_stream::local_routes::muc::SuspendedMucEndpoint;
use northstar_stream::local_routes::session::OnlineSession;
use northstar_stream::local_routes::session::SmPresenceEpoch;
use northstar_stream::local_routes::session::SmStagedRouteClaim;
use northstar_stream::transport::Action;
use northstar_stream::IqRouter;
use roxmltree::Node;
use std::sync::atomic::AtomicU8;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

impl SessionHost for AppState {
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
    ) -> northstar_session_application::telemetry::C2sAuthenticationTelemetry<'_> {
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

    fn federated_caps_gates(&self) -> &northstar_protocol_runtime::caps::FederatedCapsGateIndex {
        AppState::federated_caps_gates(self)
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

    fn outbound_stanza_telemetry(
        &self,
    ) -> northstar_session_application::telemetry::OutboundStanzaTelemetry<'_> {
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
    ) -> northstar_session_application::telemetry::PushSubscriptionTelemetry<'_> {
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

    fn registration_telemetry(
        &self,
    ) -> northstar_session_application::telemetry::RegistrationTelemetry<'_> {
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
    ) -> northstar_session_application::telemetry::Sasl2AuthenticationTelemetry<'_> {
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

    fn session_bind_telemetry(
        &self,
    ) -> northstar_session_application::telemetry::SessionBindTelemetry<'_> {
        AppState::session_bind_telemetry(self)
    }

    fn session_drop_fallback_telemetry(
        &self,
    ) -> northstar_session_application::telemetry::SessionDropFallbackTelemetry<'_> {
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

    fn sm_session_telemetry(
        &self,
    ) -> northstar_session_application::telemetry::SmSessionTelemetry<'_> {
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

    async fn abort_local_muc_resume(
        &self,
        restored: &RestoredLocalMucOccupants,
        snapshot_backed: bool,
    ) {
        AppState::abort_local_muc_resume(self, restored, snapshot_backed).await
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
        AppState::activate_session_if_current(
            self,
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
        AppState::begin_suspended_muc_resume(self, endpoints, base_stanzas, base_bytes).await
    }

    fn c2s_scram_sha1_enabled(&self) -> bool {
        AppState::c2s_scram_sha1_enabled(self)
    }

    fn caps_effect_dispatcher(
        &self,
    ) -> &Arc<northstar_protocol_runtime::caps::CapsEffectDispatcher> {
        AppState::caps_effect_dispatcher(self)
    }

    fn caps_effect_telemetry(
        &self,
    ) -> northstar_session_application::telemetry::CapsEffectTelemetry<'_> {
        AppState::caps_effect_telemetry(self)
    }

    type RestoredMuc = RestoredLocalMucOccupants;

    async fn checkpoint_local_muc_resume(&self, restored: &RestoredLocalMucOccupants) -> bool {
        AppState::checkpoint_local_muc_resume(self, restored).await
    }

    async fn claim_sm_resume_route(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
        session_id: uuid::Uuid,
        claim_token: uuid::Uuid,
    ) -> anyhow::Result<bool> {
        AppState::claim_sm_resume_route(self, full_jid, connection_id, session_id, claim_token)
            .await
    }

    fn clear_suspended_sm_capacity(&self, endpoints: &[Arc<SuspendedMucEndpoint>]) {
        AppState::clear_suspended_sm_capacity(self, endpoints)
    }

    async fn commit_local_muc_resume(
        &self,
        restored: RestoredLocalMucOccupants,
        sender: &northstar_stream::outbound::OutboundSender,
        capacity: northstar_session_application::sm_capacity::SmCapacityLease,
    ) -> CommittedLocalMucResume {
        AppState::commit_local_muc_resume(self, restored, sender, capacity).await
    }

    async fn finalize_sm_resume(
        &self,
        request: northstar_session_application::sm::SmResumeFinalizationRequest<'_>,
        observation: Option<
            &northstar_auth_application::authentication::publication::PreparedCredential,
        >,
    ) -> anyhow::Result<northstar_session_application::sm::SmResumeFinalizationOutcome> {
        AppState::finalize_sm_resume(self, request, observation).await
    }

    fn local_caps_epoch_is_current(
        &self,
        full_jid: &str,
        epoch: LocalCapsEpoch,
        expected_gate: Option<&Arc<tokio::sync::Mutex<()>>>,
    ) -> bool {
        AppState::local_caps_epoch_is_current(self, full_jid, epoch, expected_gate)
    }

    fn local_caps_observer_connection_is_current(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
        expected_gate: &Arc<tokio::sync::Mutex<()>>,
    ) -> bool {
        AppState::local_caps_observer_connection_is_current(
            self,
            full_jid,
            connection_id,
            expected_gate,
        )
    }

    async fn mark_suspended_muc_durable(&self, endpoints: Vec<Arc<SuspendedMucEndpoint>>) -> bool {
        AppState::mark_suspended_muc_durable(self, endpoints).await
    }

    async fn notify_remote_user_agent_replacement(
        &self,
        account: &str,
        user_id: uuid::Uuid,
        device_id: uuid::Uuid,
        epoch: i64,
    ) -> anyhow::Result<()> {
        AppState::notify_remote_user_agent_replacement(self, account, user_id, device_id, epoch)
            .await
    }

    async fn pause_suspended_muc_delivery(
        &self,
        sm_session_id: uuid::Uuid,
    ) -> Vec<Arc<SuspendedMucEndpoint>> {
        AppState::pause_suspended_muc_delivery(self, sm_session_id).await
    }

    fn pending_caps(&self) -> &northstar_protocol_runtime::caps::PendingCapsIndex {
        AppState::pending_caps(self)
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
        AppState::publish_user_agent_epoch_if_current(
            self,
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
        AppState::push_delivery_telemetry(self)
    }

    async fn release_exact_local_session_route(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
    ) -> anyhow::Result<()> {
        AppState::release_exact_local_session_route(self, full_jid, connection_id).await
    }

    async fn restore_local_muc_occupants(
        &self,
        request: RestoreLocalMucOccupantsRequest<'_>,
    ) -> RestoredLocalMucOccupants {
        AppState::restore_local_muc_occupants(self, request).await
    }

    async fn revoke_sm_session_with_teardown(&self, id: uuid::Uuid) -> anyhow::Result<()> {
        AppState::revoke_sm_session_with_teardown(self, id).await
    }

    async fn seal_suspended_muc_endpoints(&self, endpoints: &[Arc<SuspendedMucEndpoint>]) {
        AppState::seal_suspended_muc_endpoints(self, endpoints).await
    }

    fn session_entries_for(&self, jid: &str) -> Vec<(String, OnlineSession)> {
        AppState::session_entries_for(self, jid)
    }

    fn sm_buffer_limits(&self) -> SmBufferLimits {
        AppState::sm_buffer_limits(self)
    }

    fn sm_ip_binding(&self) -> &str {
        AppState::sm_ip_binding(self)
    }

    fn sm_pending_route_removal_signal(
        &self,
        key: &str,
        old_connection_id: uuid::Uuid,
        user_id: uuid::Uuid,
        sm_session_id: uuid::Uuid,
        cancel_live_route: bool,
    ) -> Option<tokio::sync::watch::Receiver<bool>> {
        AppState::sm_pending_route_removal_signal(
            self,
            key,
            old_connection_id,
            user_id,
            sm_session_id,
            cancel_live_route,
        )
    }

    fn sm_presence_epoch(&self, key: &str) -> Option<SmPresenceEpoch> {
        AppState::sm_presence_epoch(self, key)
    }

    fn sm_session_policy(&self) -> SmSessionPolicy {
        AppState::sm_session_policy(self)
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
        AppState::sm_suspension_recovery_queue(self).enqueue(
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
        AppState::sm_suspension_recovery_queue(self).enqueue_promote(
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
        AppState::stage_sm_resumed_session(
            self,
            key,
            candidate,
            claimant_user,
            claimed_sm_id,
            expected_gate,
        )
    }

    fn muc_domain(&self) -> String {
        northstar_muc_xmpp::muc::muc_service_domain(self.local_domain())
    }

    fn mix_domain(&self) -> String {
        northstar_mix_xmpp::local_mix_domain(self.local_domain())
    }

    fn pubsub_domain(&self) -> String {
        northstar_pubsub_xmpp::pubsub::pubsub_domain(self)
    }

    fn upload_domain(&self) -> String {
        northstar_upload_xmpp::upload_service_domain(self.local_domain())
    }

    fn http_upload_enabled(&self) -> bool {
        self.xmpp_http_upload_enabled()
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

    fn iq_routes() -> &'static IqRouter<RootIqRoute<AppState>> {
        &IQ_ROUTES
    }

    async fn blocked_muc_recipient_accounts(
        &self,
        occupants: &[MucOccupant],
        stanza_senders: &[String],
    ) -> std::collections::HashSet<String> {
        AppState::blocked_muc_recipient_accounts(self, occupants, stanza_senders).await
    }

    async fn deliver_to_muc_occupant(&self, occupant: &MucOccupant, stanza: String) -> bool {
        AppState::deliver_to_muc_occupant(self, occupant, stanza).await
    }

    type S2sOutbox = FederationRouter;

    fn federation_outbox(&self) -> &FederationRouter {
        AppState::federation_outbox(self)
    }

    fn inbound_stanza_telemetry(
        &self,
    ) -> northstar_session_application::telemetry::InboundStanzaTelemetry<'_> {
        AppState::inbound_stanza_telemetry(self)
    }

    fn local_muc_occupant_by_nick(&self, room_jid: &str, nick: &str) -> Option<MucOccupant> {
        AppState::local_muc_occupant_by_nick(self, room_jid, nick)
    }

    async fn personal_message_remote_resource_exists(&self, jid: &str) -> bool {
        AppState::personal_message_remote_resource_exists(self, jid).await
    }

    fn presence_service(
        &self,
    ) -> &northstar_roster_application::presence::PresenceService<
        northstar_workflows::presence_repository::PostgresPresenceRepository,
    > {
        AppState::presence_service(self)
    }

    async fn privacy_allows_session(
        &self,
        session: &OnlineSession,
        peer: &str,
        kind: impl Into<northstar_roster_application::privacy::PrivacyStanzaKind> + Send,
    ) -> anyhow::Result<bool> {
        AppState::privacy_allows_session(self, session, peer, kind).await
    }

    fn privacy_service(
        &self,
    ) -> &northstar_roster_application::privacy::PrivacyService<
        northstar_roster_postgres::privacy::PostgresPrivacyRepository,
    > {
        AppState::privacy_service(self)
    }

    async fn route_client_iq_to_remote_resource(&self, full_jid: &str, stanza: &str) -> bool {
        AppState::route_client_iq_to_remote_resource(self, full_jid, stanza).await
    }

    fn xmpp_external_route_domain_allowed(&self, domain: &str) -> bool {
        AppState::xmpp_external_route_domain_allowed(self, domain)
    }

    fn xmpp_route_enabled(
        &self,
        stanza: northstar_xep_core::StanzaKind,
        namespace: &str,
        local_name: &str,
    ) -> bool {
        AppState::xmpp_route_enabled(self, stanza, namespace, local_name)
    }

    type Cleanup = SessionCleanupService;

    fn session_cleanup(self: Arc<Self>) -> SessionCleanupService {
        SessionCleanupService::new(self)
    }

    async fn finalize_account_deletion(
        &self,
        user_id: uuid::Uuid,
        username: &str,
    ) -> Result<FinalizeAccountDeletion> {
        crate::state::account_recovery::finalize(self, user_id, username).await
    }

    fn account_abuse_telemetry(
        &self,
    ) -> northstar_session_application::telemetry::AccountAbuseTelemetry<'_> {
        AppState::account_abuse_telemetry(self)
    }

    async fn disconnect_account(&self, user_id: uuid::Uuid, bare_account_jid: &str) {
        AppState::disconnect_account(self, user_id, bare_account_jid).await
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
        crate::state::pubsub_delivery::deliver_last_items_on_presence(
            self,
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
