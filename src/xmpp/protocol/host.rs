//! What a protocol session needs from the node it runs in.

use super::dispatch::iq_routes::RootIqRoute;
use super::ProtocolSession;
use crate::s2s::FederationRouter;
use crate::state::account_recovery::FinalizeAccountDeletion;
use crate::state::session_cleanup::SessionCleanupService;
use crate::state::CommittedLocalMucResume;
use crate::state::RestoredLocalMucOccupants;
use crate::state::Sasl2FastTokenPolicy;
use crate::state::SmBufferLimits;
use crate::state::SmSessionPolicy;
use anyhow::Result;
use dashmap::DashMap;
use northstar_room_application::muc_service::LocalMucOccupantIdentity;
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
    ) -> northstar_session_application::telemetry::C2sAuthenticationTelemetry<'_>;
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
    fn federated_caps_gates(&self) -> &northstar_protocol_runtime::caps::FederatedCapsGateIndex;
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
    fn outbound_stanza_telemetry(
        &self,
    ) -> northstar_session_application::telemetry::OutboundStanzaTelemetry<'_>;
    /// See `AppState::push_service`.
    fn push_service(
        &self,
    ) -> &northstar_message_application::push::PushService<
        northstar_workflows::push_repository::PostgresPushRepository,
    >;
    /// See `AppState::push_subscription_telemetry`.
    fn push_subscription_telemetry(
        &self,
    ) -> northstar_session_application::telemetry::PushSubscriptionTelemetry<'_>;
    /// See `AppState::record_bosh_session_closed`.
    fn record_bosh_session_closed(&self);
    /// See `AppState::record_c2s_backpressure_disconnect`.
    fn record_c2s_backpressure_disconnect(&self);
    /// Read the public-registration kill switch with acquire ordering.
    fn registration_is_closed(&self) -> bool;
    /// See `AppState::registration_requires_invitation`.
    fn registration_requires_invitation(&self) -> bool;
    /// See `AppState::registration_telemetry`.
    fn registration_telemetry(
        &self,
    ) -> northstar_session_application::telemetry::RegistrationTelemetry<'_>;
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
    ) -> northstar_session_application::telemetry::Sasl2AuthenticationTelemetry<'_>;
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
    fn session_bind_telemetry(
        &self,
    ) -> northstar_session_application::telemetry::SessionBindTelemetry<'_>;
    /// See `AppState::session_drop_fallback_telemetry`.
    fn session_drop_fallback_telemetry(
        &self,
    ) -> northstar_session_application::telemetry::SessionDropFallbackTelemetry<'_>;
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
    fn sm_session_telemetry(
        &self,
    ) -> northstar_session_application::telemetry::SmSessionTelemetry<'_>;
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
    /// Roll a failed restore back to a suspended actor without taking suffix
    /// ownership away from its sole durable source. `snapshot_backed` is true
    /// only after the protocol session itself contains the staged suffix; in
    /// that case successful connection cleanup clears this backup instead of
    /// appending it again.
    fn abort_local_muc_resume(
        &self,
        restored: &RestoredLocalMucOccupants,
        snapshot_backed: bool,
    ) -> impl std::future::Future<Output = ()> + Send;
    /// Publish only the exact staged route incarnation that survived every
    /// authorization and lifecycle fence.  The DashMap write guard provides
    /// a local linearization point with account/session revocation helpers;
    /// the cancellation/lifecycle recheck after publication also closes a
    /// concurrent out-of-band transport cancellation window.
    fn activate_session_if_current(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
        user_id: uuid::Uuid,
        auth_generation: i64,
        lifecycle: &Arc<AtomicU8>,
        disconnect: &CancellationToken,
    ) -> bool;
    /// Install the exact post-finalization replay base. `claim_resume` is only
    /// a preliminary snapshot: acknowledgements may advance before the
    /// PostgreSQL activation CAS returns. Keeping the endpoint in `Waiting`
    /// until this method prevents that stale claim size from opening excess
    /// stanza or byte budget.
    fn begin_suspended_muc_resume(
        &self,
        endpoints: &[Arc<SuspendedMucEndpoint>],
        base_stanzas: usize,
        base_bytes: usize,
    ) -> impl std::future::Future<Output = bool> + Send;
    /// See `AppState::c2s_scram_sha1_enabled`.
    fn c2s_scram_sha1_enabled(&self) -> bool;
    /// See `AppState::caps_effect_dispatcher`.
    fn caps_effect_dispatcher(
        &self,
    ) -> &Arc<northstar_protocol_runtime::caps::CapsEffectDispatcher>;
    /// See `AppState::caps_effect_telemetry`.
    fn caps_effect_telemetry(
        &self,
    ) -> northstar_session_application::telemetry::CapsEffectTelemetry<'_>;
    /// Transfer the volatile suffix to the exact live SM checkpoint. The
    /// queue is cleared only after PostgreSQL accepted that checkpoint, while
    /// the endpoint mutex still excludes both delivery and transport
    /// publication. A later socket failure therefore re-suspends the snapshot
    /// without appending a duplicate copy of the suffix.
    fn checkpoint_local_muc_resume(
        &self,
        restored: &RestoredLocalMucOccupants,
    ) -> impl std::future::Future<Output = bool> + Send;
    /// See `AppState::claim_sm_resume_route`.
    fn claim_sm_resume_route(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
        session_id: uuid::Uuid,
        claim_token: uuid::Uuid,
    ) -> impl std::future::Future<Output = anyhow::Result<bool>> + Send;
    /// See `AppState::clear_suspended_sm_capacity`.
    fn clear_suspended_sm_capacity(&self, endpoints: &[Arc<SuspendedMucEndpoint>]);
    /// Publish a restore plan only after the `<resumed/>` control and complete
    /// replay have reached the transport. The endpoint mutex is held while all
    /// exact actors are swapped, so an arriving stanza observes either the
    /// sealed gate or the final live route, never a partially transferred FIFO.
    fn commit_local_muc_resume(
        &self,
        restored: RestoredLocalMucOccupants,
        sender: &northstar_stream::outbound::OutboundSender,
        capacity: northstar_session_application::sm_capacity::SmCapacityLease,
    ) -> impl std::future::Future<Output = CommittedLocalMucResume> + Send;
    /// See `AppState::finalize_sm_resume`.
    fn finalize_sm_resume(
        &self,
        request: northstar_session_application::sm::SmResumeFinalizationRequest<'_>,
        observation: Option<
            &northstar_auth_application::authentication::publication::PreparedCredential,
        >,
    ) -> impl std::future::Future<
        Output = anyhow::Result<northstar_session_application::sm::SmResumeFinalizationOutcome>,
    > + Send;
    /// See `AppState::local_caps_epoch_is_current`.
    fn local_caps_epoch_is_current(
        &self,
        full_jid: &str,
        epoch: LocalCapsEpoch,
        expected_gate: Option<&Arc<tokio::sync::Mutex<()>>>,
    ) -> bool;
    /// See `AppState::local_caps_observer_connection_is_current`.
    fn local_caps_observer_connection_is_current(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
        expected_gate: &Arc<tokio::sync::Mutex<()>>,
    ) -> bool;
    /// See `AppState::mark_suspended_muc_durable`.
    fn mark_suspended_muc_durable(
        &self,
        endpoints: Vec<Arc<SuspendedMucEndpoint>>,
    ) -> impl std::future::Future<Output = bool> + Send;
    /// See `AppState::notify_remote_user_agent_replacement`.
    fn notify_remote_user_agent_replacement(
        &self,
        account: &str,
        user_id: uuid::Uuid,
        device_id: uuid::Uuid,
        epoch: i64,
    ) -> impl std::future::Future<Output = anyhow::Result<()>> + Send;
    /// See `AppState::pause_suspended_muc_delivery`.
    fn pause_suspended_muc_delivery(
        &self,
        sm_session_id: uuid::Uuid,
    ) -> impl std::future::Future<Output = Vec<Arc<SuspendedMucEndpoint>>> + Send;
    /// See `AppState::pending_caps`.
    fn pending_caps(&self) -> &northstar_protocol_runtime::caps::PendingCapsIndex;
    /// See `AppState::publish_user_agent_epoch_if_current`.
    fn publish_user_agent_epoch_if_current(
        &self,
        key: &str,
        connection_id: uuid::Uuid,
        user_id: uuid::Uuid,
        auth_generation: i64,
        lifecycle: &Arc<AtomicU8>,
        user_agent_epoch: Option<i64>,
    ) -> bool;
    /// See `AppState::push_delivery_telemetry`.
    fn push_delivery_telemetry(
        &self,
    ) -> northstar_session_application::telemetry::PushDeliveryTelemetry<'_>;
    /// See `AppState::release_exact_local_session_route`.
    fn release_exact_local_session_route(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
    ) -> impl std::future::Future<Output = anyhow::Result<()>> + Send;
    /// Reattach only memberships that can still be proven valid. Existing
    /// suspended actors are swapped in place; after a process restart a new
    /// actor is recreated without join broadcast or history replay. The
    /// volatile suspension FIFO moves into the returned replay suffix so the
    /// resumed stream emits it strictly after `<resumed/>` and the durable
    /// unacked replay.
    fn restore_local_muc_occupants(
        &self,
        request: RestoreLocalMucOccupantsRequest<'_>,
    ) -> impl std::future::Future<Output = RestoredLocalMucOccupants> + Send;
    /// See `AppState::revoke_sm_session_with_teardown`.
    fn revoke_sm_session_with_teardown(
        &self,
        id: uuid::Uuid,
    ) -> impl std::future::Future<Output = anyhow::Result<()>> + Send;
    /// See `AppState::seal_suspended_muc_endpoints`.
    fn seal_suspended_muc_endpoints(
        &self,
        endpoints: &[Arc<SuspendedMucEndpoint>],
    ) -> impl std::future::Future<Output = ()> + Send;
    /// See `AppState::session_entries_for`.
    fn session_entries_for(&self, jid: &str) -> Vec<(String, OnlineSession)>;
    /// See `AppState::sm_buffer_limits`.
    fn sm_buffer_limits(&self) -> SmBufferLimits;
    /// See `AppState::sm_ip_binding`.
    fn sm_ip_binding(&self) -> &str;
    /// See `AppState::sm_pending_route_removal_signal`.
    fn sm_pending_route_removal_signal(
        &self,
        key: &str,
        old_connection_id: uuid::Uuid,
        user_id: uuid::Uuid,
        sm_session_id: uuid::Uuid,
        cancel_live_route: bool,
    ) -> Option<tokio::sync::watch::Receiver<bool>>;
    /// See `AppState::sm_presence_epoch`.
    fn sm_presence_epoch(&self, key: &str) -> Option<SmPresenceEpoch>;
    /// See `AppState::sm_session_policy`.
    fn sm_session_policy(&self) -> SmSessionPolicy;
    /// See `AppState::sm_suspension_recovery_queue`.
    fn sm_suspension_recovery_queue(
        &self,
    ) -> &Arc<crate::state::session_cleanup::SmSuspensionRecoveryQueue>;
    /// Inspect/insert inside one DashMap entry operation. The caller owns the
    /// returned gate and route-incarnation handles before any async wait.
    fn stage_sm_resumed_session(
        &self,
        key: String,
        candidate: OnlineSession,
        claimant_user: uuid::Uuid,
        claimed_sm_id: uuid::Uuid,
        expected_gate: &Arc<tokio::sync::Mutex<()>>,
    ) -> SmStagedRouteClaim;
    /// The MUC service domain (`conference.<local domain>`).
    fn muc_domain(&self) -> String;
    /// The MIX service domain.
    fn mix_domain(&self) -> String;
    /// The PubSub service domain.
    fn pubsub_domain(&self) -> String;
    /// The HTTP upload service domain (`upload.<local domain>`).
    fn upload_domain(&self) -> String;
    /// Whether the XEP-0363 HTTP upload service is enabled.
    fn http_upload_enabled(&self) -> bool;
    /// Handles a client `<message/>` (the message, MUC and MIX contexts).
    fn dispatch_message(
        session: &ProtocolSession<Self>,
        root: Node<'_, '_>,
        raw: &str,
        client_raw: &str,
    ) -> impl std::future::Future<Output = Result<Action>> + Send;
    /// Handles a client `<presence/>` (the roster and room contexts).
    fn dispatch_presence(
        session: &mut ProtocolSession<Self>,
        root: Node<'_, '_>,
        raw: &str,
    ) -> impl std::future::Future<Output = Result<Action>> + Send;
    /// Answers an IQ addressed to a MIX channel, or `None` when the IQ is not one.
    fn dispatch_mix_iq(
        session: &ProtocolSession<Self>,
        raw: &str,
    ) -> impl std::future::Future<Output = Result<Option<Action>>> + Send;
    /// The session's own occupant of the local MUC room `room_jid`, while its membership is authorized.
    fn authorized_muc_occupant(
        session: &ProtocolSession<Self>,
        room_jid: &str,
    ) -> impl std::future::Future<Output = Result<Option<MucOccupant>>> + Send;
    /// The IQ routes the client dispatch hands requests to.
    fn iq_routes() -> &'static IqRouter<RootIqRoute<Self>>;
    /// See `AppState::blocked_muc_recipient_accounts`.
    fn blocked_muc_recipient_accounts(
        &self,
        occupants: &[MucOccupant],
        stanza_senders: &[String],
    ) -> impl std::future::Future<Output = std::collections::HashSet<String>> + Send;
    /// See `AppState::deliver_to_muc_occupant`.
    fn deliver_to_muc_occupant(
        &self,
        occupant: &MucOccupant,
        stanza: String,
    ) -> impl std::future::Future<Output = bool> + Send;
    /// See `AppState::federation_outbox`.
    fn federation_outbox(&self) -> &FederationRouter;
    /// See `AppState::inbound_stanza_telemetry`.
    fn inbound_stanza_telemetry(
        &self,
    ) -> northstar_session_application::telemetry::InboundStanzaTelemetry<'_>;
    /// See `AppState::local_muc_occupant_by_nick`.
    fn local_muc_occupant_by_nick(&self, room_jid: &str, nick: &str) -> Option<MucOccupant>;
    /// A failed route lookup supplies no evidence of an exact remote resource.
    fn personal_message_remote_resource_exists(
        &self,
        jid: &str,
    ) -> impl std::future::Future<Output = bool> + Send;
    /// See `AppState::presence_service`.
    fn presence_service(
        &self,
    ) -> &northstar_roster_application::presence::PresenceService<
        northstar_workflows::presence_repository::PostgresPresenceRepository,
    >;
    /// Evaluate one resource's session-local XEP-0016 selection (or the
    /// account default when no active list is selected). Callers must apply
    /// XEP-0191 first; a blocking hit is never overridden by an allow rule.
    /// Stanza paths that still hold a storage-level kind convert it at this
    /// boundary; the service layer owns the mapping.
    fn privacy_allows_session(
        &self,
        session: &OnlineSession,
        peer: &str,
        kind: impl Into<northstar_roster_application::privacy::PrivacyStanzaKind> + Send,
    ) -> impl std::future::Future<Output = anyhow::Result<bool>> + Send;
    /// See `AppState::privacy_service`.
    fn privacy_service(
        &self,
    ) -> &northstar_roster_application::privacy::PrivacyService<
        northstar_roster_postgres::privacy::PostgresPrivacyRepository,
    >;
    /// Client IQs addressed to a full JID stop at the first accepting node.
    fn route_client_iq_to_remote_resource(
        &self,
        full_jid: &str,
        stanza: &str,
    ) -> impl std::future::Future<Output = bool> + Send;
    /// See `AppState::xmpp_external_route_domain_allowed`.
    fn xmpp_external_route_domain_allowed(&self, domain: &str) -> bool;
    /// See `AppState::xmpp_route_enabled`.
    fn xmpp_route_enabled(
        &self,
        stanza: northstar_xep_core::StanzaKind,
        namespace: &str,
        local_name: &str,
    ) -> bool;
    /// The bounded cleanup service of one session finalization.
    fn session_cleanup(self: Arc<Self>) -> SessionCleanupService;
    /// Commits a XEP-0077 account deletion that the session's proof authorized.
    fn finalize_account_deletion(
        &self,
        user_id: uuid::Uuid,
        username: &str,
    ) -> impl std::future::Future<Output = Result<FinalizeAccountDeletion>> + Send;
    /// See `AppState::account_abuse_telemetry`.
    fn account_abuse_telemetry(
        &self,
    ) -> northstar_session_application::telemetry::AccountAbuseTelemetry<'_>;
    /// Revoke local account routes and request durable SM revocation.
    /// Remote nodes receive the generation fence over Redis, with a 30-second
    /// maintenance sweep as fallback while PostgreSQL remains available.
    fn disconnect_account(
        &self,
        user_id: uuid::Uuid,
        bare_account_jid: &str,
    ) -> impl std::future::Future<Output = ()> + Send;
    /// Replays the last published PubSub items to a resource that became available (XEP-0060
    /// `send_last_published_item=on_sub_and_presence`).
    #[allow(clippy::too_many_arguments)]
    fn replay_pubsub_last_items(
        self: Arc<Self>,
        outbound: northstar_stream::outbound::OutboundSender,
        recipient_id: uuid::Uuid,
        active_privacy_list: Option<String>,
        connection_id: uuid::Uuid,
        recipient: String,
        show: &'static str,
    ) -> impl std::future::Future<Output = Result<()>> + Send + 'static;
}
