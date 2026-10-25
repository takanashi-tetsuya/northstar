pub(crate) mod blocking;
pub(crate) mod caps;
pub(crate) mod commands;
pub(crate) mod csi;
pub(crate) mod discovery;
pub(crate) mod dispatch;
pub(crate) mod extdisco;
pub(crate) mod federated_muc;
pub(crate) mod ibr;
pub(crate) mod mam;
pub(crate) mod messaging;
pub(crate) mod misc;
pub(crate) mod mix;
pub(crate) mod mix_muc;
pub(crate) mod muc;
pub(crate) mod pep;
pub(crate) mod presence;
pub(crate) mod privacy;
pub(crate) mod private;
pub(crate) mod pubsub;
pub(crate) mod replay;
pub(crate) mod retractions;
pub(crate) mod roster;
pub(crate) mod sasl2;
pub(crate) mod sm;
mod sm_owner;
pub(crate) mod upload;
pub(crate) mod vcard;

use super::capabilities::PostActionTelemetry;
use super::xml_builder::XmlElement;
use crate::services::xml_util::*;
use crate::state::{AppState, SmBufferLimits, SmSessionPolicy};
use anyhow::{Context, Result};
use dashmap::DashSet;

use roxmltree::Node;
use std::{
    collections::VecDeque,
    future::Future,
    net::IpAddr,
    pin::Pin,
    sync::{
        atomic::AtomicBool, atomic::AtomicI16, atomic::AtomicU64, atomic::AtomicU8,
        atomic::Ordering, Arc,
    },
};
use zeroize::{Zeroize, Zeroizing};

mod legacy_auth;
mod session_sm;
mod session_transport;

#[cfg(test)]
use self::legacy_auth::{legacy_sasl_auth, legacy_sasl_payload};
use self::session_sm::durable_delivery_managed_by_sm;
pub use self::session_sm::ResumePayload;
pub(crate) use self::session_sm::ResumeTransportParts;
pub use self::session_transport::Action;
#[cfg(test)]
use self::session_transport::{
    client_stream_limits_feature, resource_bind_deadline_for, unauthenticated_timed_out_for,
};
pub(crate) use self::session_transport::{ClientTransport, StreamLimits, TlsSessionEvidence};

const MAX_SASL_ATTEMPTS_PER_STREAM: u8 = 5;
const MAX_POST_ACTION_TASKS_PER_SESSION: usize = 16;
const POST_ACTION_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

type PostActionFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

struct PendingPostAction {
    name: &'static str,
    future: PostActionFuture,
}

struct PostActionSupervisor {
    pending: VecDeque<PendingPostAction>,
    running: tokio::task::JoinSet<&'static str>,
    transport_ready: bool,
    closed: bool,
}

impl Default for PostActionSupervisor {
    fn default() -> Self {
        Self {
            pending: VecDeque::new(),
            running: tokio::task::JoinSet::new(),
            transport_ready: true,
            closed: false,
        }
    }
}

impl PostActionSupervisor {
    fn defer<F>(
        &mut self,
        name: &'static str,
        task: F,
        telemetry: &PostActionTelemetry<'_>,
    ) -> Result<()>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        anyhow::ensure!(!self.closed, "session post-action supervisor is closed");
        self.reap(telemetry);
        if self.pending.len().saturating_add(self.running.len())
            >= MAX_POST_ACTION_TASKS_PER_SESSION
        {
            telemetry.capacity_rejected();
            anyhow::bail!("per-session post-action task capacity was exhausted");
        }
        self.pending.push_back(PendingPostAction {
            name,
            future: Box::pin(task),
        });
        Ok(())
    }

    fn start(&mut self, telemetry: &PostActionTelemetry<'_>) {
        if self.closed {
            return;
        }
        self.transport_ready = true;
        self.reap(telemetry);
        while let Some(task) = self.pending.pop_front() {
            telemetry.started();
            self.running.spawn(async move {
                task.future.await;
                task.name
            });
        }
    }

    fn reap(&mut self, telemetry: &PostActionTelemetry<'_>) {
        while let Some(result) = self.running.try_join_next() {
            observe_post_action_join(result, telemetry);
        }
    }

    async fn abort_and_drain(&mut self, telemetry: &PostActionTelemetry<'_>) {
        self.reap(telemetry);
        let aborted = self.pending.len().saturating_add(self.running.len());
        self.pending.clear();
        self.running.abort_all();
        telemetry.aborted(aborted);
        let drain = async {
            while let Some(result) = self.running.join_next().await {
                observe_post_action_join(result, telemetry);
            }
        };
        if tokio::time::timeout(POST_ACTION_DRAIN_TIMEOUT, drain)
            .await
            .is_err()
        {
            tracing::error!(
                remaining = self.running.len(),
                "aborted post-action tasks did not drain within the shutdown budget"
            );
        }
    }

    fn abort_now(&mut self, telemetry: &PostActionTelemetry<'_>) {
        self.reap(telemetry);
        let aborted = self.pending.len().saturating_add(self.running.len());
        self.pending.clear();
        self.running.abort_all();
        telemetry.aborted(aborted);
    }
}

/// Shared with the exact local route so cluster recovery can request a
/// bounded offline replay without racing an in-progress presence action.
/// The transport opens the gate only after its current action reaches the
/// socket or BOSH response FIFO.
#[derive(Clone, Default)]
pub(crate) struct PostActionHandle(Arc<std::sync::Mutex<PostActionSupervisor>>);

impl PostActionHandle {
    fn begin_action(&self) {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .transport_ready = false;
    }

    fn defer<F>(
        &self,
        name: &'static str,
        task: F,
        telemetry: &PostActionTelemetry<'_>,
    ) -> Result<()>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .defer(name, task, telemetry)
    }

    pub(crate) fn defer_recovery<F>(
        &self,
        name: &'static str,
        task: F,
        telemetry: &PostActionTelemetry<'_>,
    ) -> Result<()>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let mut supervisor = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        supervisor.defer(name, task, telemetry)?;
        if supervisor.transport_ready {
            supervisor.start(telemetry);
        }
        Ok(())
    }

    fn start(&self, telemetry: &PostActionTelemetry<'_>) {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .start(telemetry);
    }

    fn take_for_shutdown(&self) -> PostActionSupervisor {
        let mut supervisor = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        supervisor.closed = true;
        let mut owned = std::mem::take(&mut *supervisor);
        supervisor.closed = true;
        owned.closed = true;
        owned
    }

    fn abort_now(&self, telemetry: &PostActionTelemetry<'_>) {
        let mut supervisor = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        supervisor.closed = true;
        supervisor.abort_now(telemetry);
    }
}

fn observe_post_action_join(
    result: std::result::Result<&'static str, tokio::task::JoinError>,
    telemetry: &PostActionTelemetry<'_>,
) {
    match result {
        Ok(name) => {
            telemetry.completed();
            tracing::trace!(task = name, "C2S post-action task completed");
        }
        Err(error) if error.is_cancelled() => {}
        Err(error) => {
            telemetry.panicked();
            tracing::error!(?error, "C2S post-action task panicked");
        }
    }
}

/// Ownership evidence survives a failed or cancelled database reply.
#[derive(Default)]
struct LiveSessionOwnership {
    attempted: bool,
}

impl LiveSessionOwnership {
    async fn attempt<T>(&mut self, operation: impl std::future::Future<Output = T>) -> T {
        self.attempted = true;
        operation.await
    }

    fn may_own(&self) -> bool {
        self.attempted
    }
}

/// Transport-independent XEP-0198 state owned by one protocol session.
/// Keeping the counters, durable identity and capacity lease together makes
/// replacement and finalization update the same session substate.
#[derive(Default)]
struct SmSubstate {
    enabled: bool,
    db_id: Option<uuid::Uuid>,
    session_id_shared: Arc<std::sync::RwLock<Option<uuid::Uuid>>>,
    resume_allowed: bool,
    resume_timeout_seconds: u64,
    inbound_h: u32,
    outbound_h: u32,
    acked_h: u32,
    unacked: VecDeque<crate::xmpp::outbound::SmUnackedStanza>,
    /// Process-local bytes retained for a resumable XEP-0198 epoch.
    capacity: Option<crate::services::sm_capacity::SmCapacityLease>,
    /// One replaceable observation; retained old handles keep their own facts.
    current_operation: Option<northstar_delivery_core::sm_ownership::Observation>,
}

/// Presence epochs stay with the protocol session across transport changes.
/// The shared gate and generation counters are also published to the live
/// route, so an SM replacement must inherit the exact same instances.
#[derive(Default)]
struct PresenceSubstate {
    /// Serializes MIX presence changes with exact-route replacement and cleanup.
    mix_presence_gate: Arc<tokio::sync::Mutex<()>>,
    /// Prevents an older caps job from recreating a retracted directed item.
    mix_presence_fallback_suppressed: Arc<DashSet<String>>,
    /// Advances on each local XEP-0115 observation, independently of availability.
    caps_observation_generation: Arc<AtomicU64>,
    /// Broadcast presence restored only after the resumed route is active.
    resumed_caps_presence: Option<String>,
    /// Cancels replay work from an older available/unavailable transition.
    availability_generation: Arc<AtomicU64>,
}

/// Read-only transport observation of the two independent session exit
/// signals. The transport owns process shutdown separately; only protocol and
/// application authority may cancel a session or its outbound queue.
#[derive(Clone)]
pub(crate) struct SessionTerminationSignals {
    policy_revoke: tokio_util::sync::CancellationToken,
    backpressure: tokio_util::sync::CancellationToken,
}

/// Fixed SM admission and replay limits for this connection. AppState owns
/// immutable configuration; durable ownership still belongs to the SM service.
struct SmRuntimePolicy {
    session: SmSessionPolicy,
    buffer: SmBufferLimits,
    ip_binding: String,
}

impl SmRuntimePolicy {
    fn from_state(state: &AppState) -> Self {
        Self {
            session: state.sm_session_policy(),
            buffer: state.sm_buffer_limits(),
            ip_binding: state.sm_ip_binding().to_owned(),
        }
    }
}

impl SessionTerminationSignals {
    #[cfg(test)]
    pub(super) fn from_test_tokens(
        policy_revoke: tokio_util::sync::CancellationToken,
        backpressure: tokio_util::sync::CancellationToken,
    ) -> Self {
        Self {
            policy_revoke,
            backpressure,
        }
    }
}

pub struct ProtocolSession {
    state: Arc<AppState>,
    sm_runtime_policy: SmRuntimePolicy,
    outbound: crate::xmpp::outbound::OutboundSender,
    /// Authoritative transport-security decision. Native TLS and trusted
    /// HTTPS-proxied WebSocket/BOSH transports set this flag; framing type is
    /// never used as an authentication bypass.
    secure_transport: bool,
    transport: ClientTransport,
    frame_executions: super::frame_execution::SessionExecutions,
    stream_limits: Option<StreamLimits>,
    pub(crate) peer_ip: IpAddr,
    connected_at: std::time::Instant,
    pub(crate) last_activity: Arc<std::sync::RwLock<std::time::Instant>>,
    /// Whether this transport has a currently open XML stream. STARTTLS and
    /// legacy SASL both invalidate it and require a fresh opening tag before
    /// any further negotiation or application stanza is accepted.
    negotiation: northstar_session_core::StreamNegotiation,
    authenticated: Option<crate::services::authentication::AuthenticatedAccount>,
    pub(crate) authenticated_at: Option<std::time::Instant>,
    pub(crate) full_jid: Option<String>,
    pub(crate) registered_key: Option<String>,
    pub(crate) available: Option<Arc<AtomicBool>>,
    presence: PresenceSubstate,
    pub(crate) carbons: Arc<AtomicBool>,
    pub(crate) priority: Arc<AtomicI16>,
    pub(crate) show: Arc<AtomicU8>,
    pub(crate) blocklist_requested: Arc<AtomicBool>,
    pub(crate) roster_requested: Arc<AtomicBool>,
    pub(crate) roster_sync: Arc<northstar_roster_application::RosterSyncGate>,
    pub(crate) mix_roster_annotations: Arc<AtomicBool>,
    /// XEP-0016 active list is scoped to this resource/session. `None` means
    /// the account default applies. Sharing it with `OnlineSession` lets
    /// inbound fanout make the same decision as this protocol actor.
    pub(crate) privacy_active: Arc<std::sync::RwLock<Option<String>>>,
    pub(crate) privacy_requested: Arc<AtomicBool>,
    pub(crate) directed_presence: Arc<DashSet<String>>,
    pub(crate) last_presence: Arc<std::sync::RwLock<Option<String>>>,
    pub(crate) joined_rooms:
        Arc<dashmap::DashMap<String, northstar_session_core::JoinedMucMembership>>,
    csi: csi::CsiSubstate,
    /// Bind 2 clients catch up through MAM metadata and must never receive the
    /// legacy offline queue again on their initial presence.
    pub(crate) bind2_mam_catchup: bool,
    sm: SmSubstate,
    pub(crate) sasl_state: Option<Box<dyn northstar_auth_core::SaslMechanism>>,
    /// Exact account incarnation which supplied the verifier for the current
    /// SCRAM exchange. `Some(None)` records a dummy verifier for an unknown or
    /// disabled identity, preventing delete/recreate between challenge and
    /// final proof from authenticating a different account.
    pub(crate) sasl_scram_fence:
        Option<Option<crate::services::authentication::AuthenticationFence>>,
    pub(crate) legacy_sasl_awaiting_initial_response: bool,
    pub(crate) sasl2_state: Option<sasl2::Sasl2Context>,
    /// Active XEP-0389 challenge transport. A response is accepted only after
    /// this connection selected an advertised flow and received a challenge.
    pub(crate) ibr_flow: Option<ibr::IbrFlowTransport>,
    pub(crate) ibr_pow_enabled: bool,
    /// One unauthenticated transport may bootstrap at most one account. After
    /// a successful XEP-0077/XEP-0389 registration only SASL is expected.
    pub(crate) user_agent_id: Option<uuid::Uuid>,
    pub(crate) user_agent_epoch: Option<i64>,
    /// Proof that credential-side effects already committed. It is retained
    /// until the transport confirms the first terminal success/resumed frame;
    /// failure paths must close rather than manufacture a contradictory SASL
    /// failure or execute the commit a second time.
    pub(crate) pending_credential_commit: Option<super::auth_publication::KnownCredentialOwner>,
    channel_bindings: Option<northstar_auth_core::ChannelBindings>,
    /// Bare JIDs authenticated by the optional C2S client-certificate PKIX
    /// verifier and id-on-xmppAddr SAN parser for this exact TLS connection.
    client_certificate_identities: Vec<String>,
    /// Exact DER chain and TLS snapshot which authenticated this transport.
    /// They remain inert until SASL EXTERNAL succeeds; password/SCRAM/FAST
    /// sessions are never registered for CRL-triggered draining merely
    /// because the client happened to present a certificate.
    client_certificate_chain: Vec<tokio_rustls::rustls::pki_types::CertificateDer<'static>>,
    tls_generation: u64,
    _certificate_session: Option<crate::security::tls::CertificateSessionGuard>,
    disconnect: tokio_util::sync::CancellationToken,
    /// Stable owner of the durable stream row.  A resumed transport gets a
    /// fresh value so a late checkpoint from the old connection cannot win.
    pub(crate) connection_id: uuid::Uuid,
    /// Monotonic evidence that this connection attempted durable capacity
    /// ownership. Set before the first database await: an error or cancelled
    /// response does not prove that its exact lease was never committed.
    live_session_ownership: LiveSessionOwnership,
    /// 0 active, 1 owned by explicit/fallback cleanup, 2 atomically superseded
    /// by the exact XEP-0198 claimant.
    pub(crate) route_lifecycle: Arc<AtomicU8>,
    /// Set only after exact process-local route/MUC ownership has been
    /// synchronously quiesced. A cancelled finalizer which claimed lifecycle
    /// state 1 but never reached that point must still trigger Drop fallback.
    local_quiesced: bool,
    /// Work that writes to `outbound` must not run while `handle()` still owns
    /// the only receiver task. Transports start these futures only after the
    /// action/control frame has been accepted.
    // Deferred futures are `Send` but intentionally not `Sync`. Keep the
    // queue behind a real synchronization boundary so read-only async session
    // methods do not inherit a false `ProtocolSession: !Sync` requirement.
    // Every mutation still uses `&mut ProtocolSession` and `get_mut()`, so no
    // mutex guard is ever held across an await.
    post_actions: PostActionHandle,
}

struct SessionAuthPublication<'a> {
    session: &'a mut ProtocolSession,
}
impl super::auth_publication::PublicationPort for SessionAuthPublication<'_> {
    fn connection(&self) -> uuid::Uuid {
        self.session.connection_id
    }
    async fn publish(
        &mut self,
        invocation: &crate::services::authentication::publication::Invocation<'_>,
    ) -> crate::services::authentication::AuthenticationResult<Option<i64>> {
        self.session
            .state
            .authentication_service()
            .publish_credential_commit_observed(invocation)
            .await
    }
    fn epoch_and_mapping(
        &mut self,
        route: &super::auth_publication::BoundRoute,
        epoch: Option<i64>,
    ) -> bool {
        if self.session.registered_key.as_deref() != Some(route.key.as_str())
            || self.session.authenticated.as_ref().is_none_or(|user| {
                user.id != route.user || user.auth_generation != route.generation
            })
            || !Arc::ptr_eq(&self.session.route_lifecycle, &route.lifecycle)
        {
            return false;
        }
        let current = self.session.state.publish_user_agent_epoch_if_current(
            &route.key,
            route.connection,
            route.user,
            route.generation,
            &route.lifecycle,
            epoch,
        );
        if current {
            self.session.user_agent_epoch = epoch;
        }
        current
    }
    fn activate(&mut self, route: &super::auth_publication::BoundRoute) -> bool {
        self.session.state.activate_session_if_current(
            &route.key,
            route.connection,
            route.user,
            route.generation,
            &route.lifecycle,
            &route.disconnect,
        )
    }
    async fn caps(&mut self, intent: Option<super::auth_publication::CapsIntent>) {
        self.session.rebind_captured_caps_observation(intent).await;
    }
    fn notify_local(&mut self, intent: &super::auth_publication::NotificationIntent, epoch: i64) {
        for (other_key, session) in self.session.state.session_entries_for(&intent.account) {
            if other_key != intent.excluded_key
                && session.user_id == intent.user
                && session.user_agent_id == Some(intent.device)
                && session.user_agent_epoch.is_some_and(|value| value < epoch)
            {
                session.disconnect.cancel();
            }
        }
    }
    async fn notify_remote(
        &mut self,
        intent: &super::auth_publication::NotificationIntent,
        epoch: i64,
    ) -> Result<()> {
        self.session
            .state
            .notify_remote_user_agent_replacement(
                &intent.account,
                intent.user,
                intent.device,
                epoch,
            )
            .await
    }
    fn rejected(
        &mut self,
        result: super::frame_execution::PublicationResult,
        error: Option<&anyhow::Error>,
    ) {
        use super::frame_execution::PublicationResult;
        match result {
            PublicationResult::BackendFailure => {
                self.session
                    .state
                    .c2s_authentication_telemetry()
                    .backend_failed();
                tracing::error!(?error, connection_id = %self.session.connection_id, "could not publish transport-confirmed authentication epoch");
            }
            PublicationResult::IntegrityRejected => {
                self.session
                    .state
                    .c2s_authentication_telemetry()
                    .integrity_failed();
                tracing::error!(connection_id = %self.session.connection_id, "authentication publication integrity failure");
            }
            PublicationResult::CredentialRejected => {
                tracing::warn!(connection_id = %self.session.connection_id, "transport-confirmed authentication publication fence was lost");
            }
            _ => {}
        }
        self.session.sm.resume_allowed = false;
    }
    fn notification_deferred(&mut self, error: &anyhow::Error) {
        tracing::warn!(
            ?error,
            "cross-node user-agent replacement was not acknowledged; maintenance will retry"
        );
    }
}

impl ProtocolSession {
    /// The production entry point shared by TCP, WebSocket and BOSH. Tests
    /// can still exercise `handle` directly without a transport budget.
    pub(crate) async fn process_frame(
        &mut self,
        frame: &str,
    ) -> std::result::Result<Action, super::frame_execution::FrameFailure> {
        let execution = self.frame_executions.begin(self.transport, frame);
        execution.run(self.handle(frame)).await
    }

    pub(super) fn muc_discussion_operation(
        &self,
        prepared: &crate::services::muc::discussion::PreparedDiscussion,
    ) -> Result<
        Option<crate::services::muc::discussion::Observation>,
        crate::services::muc::discussion::Rejected,
    > {
        self.frame_executions.muc_discussion(prepared)
    }

    pub(crate) fn defer_after_transport<F>(&mut self, name: &'static str, task: F) -> Result<()>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.post_actions
            .defer(name, task, &self.state.c2s_post_action_telemetry())
    }

    pub(crate) fn start_post_action_tasks(&mut self) {
        self.post_actions
            .start(&self.state.c2s_post_action_telemetry());
    }

    pub(super) fn prepare_credential_attempt(
        &self,
        kind: crate::services::authentication::publication::CredentialKind,
    ) -> Result<super::auth_publication::CredentialAttempt> {
        super::auth_publication::CredentialAttempt::new(
            self.frame_executions.auth_origin(),
            self.connection_id,
            kind,
        )
    }

    pub(super) fn retain_credential_commit(
        &mut self,
        receipt: crate::services::authentication::CredentialCommitReceipt,
        attempt: super::auth_publication::CredentialAttempt,
    ) -> Result<()> {
        let owner = attempt.into_owner(receipt)?;
        anyhow::ensure!(
            self.pending_credential_commit.is_none(),
            "unsealed credential receipt already pending"
        );
        if let Some(origin) = owner.origin() {
            origin.retain_auth_receipt(owner.observation().clone())?;
        }
        self.pending_credential_commit = Some(owner);
        Ok(())
    }

    fn seal_auth_control(
        &mut self,
        control: &str,
        resumed: bool,
    ) -> Result<super::auth_publication::AuthControlHolder> {
        use super::auth_publication::{
            BoundRoute, CapsIntent, CapturedEffects, NotificationIntent, RouteIntent,
        };
        let (route, caps, notification) = if let Some(key) = self.registered_key.clone() {
            let user = self
                .authenticated
                .as_ref()
                .context("bound auth control has no principal")?;
            let route = RouteIntent::Bound(BoundRoute {
                key: key.clone(),
                user: user.id,
                generation: user.auth_generation,
                connection: self.connection_id,
                lifecycle: self.route_lifecycle.clone(),
                disconnect: self.disconnect.clone(),
            });
            let caps = if resumed {
                self.presence
                    .resumed_caps_presence
                    .take()
                    .map(|presence| CapsIntent {
                        presence,
                        key: key.clone(),
                        connection: self.connection_id,
                        gate: self.presence.mix_presence_gate.clone(),
                        generation: self.presence.caps_observation_generation.clone(),
                    })
            } else {
                None
            };
            let notification = self.user_agent_id.map(|device| NotificationIntent {
                account: format!("{}@{}", user.username, self.state.local_domain()),
                user: user.id,
                device,
                excluded_key: key,
            });
            (route, caps, notification)
        } else {
            (RouteIntent::Unbound, None, None)
        };
        let owner = self
            .pending_credential_commit
            .take()
            .context("auth control has no returned credential receipt")?;
        owner.seal(
            control,
            CapturedEffects {
                route,
                caps,
                notification,
            },
        )
    }

    /// The transport supplies the exact consumed control owner; no latest
    /// session receipt/frame slot is consulted after successful transport.
    pub(crate) async fn publish_committed_authentication_and_route(
        &mut self,
        owner: super::auth_publication::OwnedPublication,
    ) -> bool {
        let origin = owner.origin();
        let mut port = SessionAuthPublication { session: self };
        let future = owner.publish(&mut port);
        if let Some(execution) = origin {
            execution.observe_publication(future).await
        } else {
            // Explicit compatibility for handle()-only callers: its missing
            // frame origin was captured at receipt return, never guessed now.
            future.await.transport_succeeded()
        }
    }

    /// Record one transport item before it crosses the socket boundary.
    /// Returns `true` when XEP-0198 owns the durable fence and the transport
    /// must therefore wait for a client `<a/>` instead of deleting the spool
    /// row after `write()`.
    pub(crate) async fn record_outbound_item(
        &mut self,
        item: &crate::xmpp::outbound::OutboundItem,
    ) -> Result<bool> {
        let mut turn = self.sm_transport_turn();
        let observation = turn.start(northstar_delivery_core::sm_ownership::Purpose::Record);
        sm_owner::SmTurnRunner::new(observation.clone(), async move {
            let result = turn.record_item(item, &observation).await;
            if result.is_err() {
                observation.returned_error();
            }
            result
        })
        .await
    }

    async fn record_outbound_with_source(
        &mut self,
        stanza: &str,
        durable_source: Option<crate::xmpp::outbound::TransportOwnershipSource>,
    ) -> Result<()> {
        let mut turn = self.sm_transport_turn();
        let observation = turn.start(northstar_delivery_core::sm_ownership::Purpose::Record);
        sm_owner::SmTurnRunner::new(observation.clone(), async move {
            let result = turn
                .record_source(stanza, durable_source, &observation)
                .await;
            if result.is_err() {
                observation.returned_error();
            }
            result
        })
        .await
    }

    pub(crate) async fn checkpoint_sm(&mut self) -> Result<()> {
        let mut turn = self.sm_transport_turn();
        let observation = turn.start(northstar_delivery_core::sm_ownership::Purpose::Checkpoint);
        sm_owner::SmTurnRunner::new(observation.clone(), async move {
            let result = turn.checkpoint_in_turn(&observation).await;
            if result.is_err() {
                observation.returned_error();
            }
            result
        })
        .await
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SessionCleanupOwnership {
    Acquired,
    AlreadyFinalizing,
    SupersededBySm,
}

fn drop_requires_local_quiesce(local_quiesced: bool, lifecycle_state: u8) -> bool {
    !local_quiesced && lifecycle_state != 2
}

fn claim_session_cleanup(lifecycle: &AtomicU8) -> SessionCleanupOwnership {
    match lifecycle.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => SessionCleanupOwnership::Acquired,
        Err(2) => SessionCleanupOwnership::SupersededBySm,
        Err(_) => SessionCleanupOwnership::AlreadyFinalizing,
    }
}

fn begin_owned_session_cleanup(
    disconnect: &tokio_util::sync::CancellationToken,
    resume_allowed: bool,
) -> bool {
    // Cleanup also cancels this token. Preserve whether the connection had
    // already been revoked; ordinary transport loss must remain resumable.
    let may_resume = resume_allowed && !disconnect.is_cancelled();
    disconnect.cancel();
    may_resume
}

#[derive(Debug)]
pub(crate) enum SessionFinalizationOutcome {
    Completed(crate::state::session_cleanup::CleanupReport),
    AlreadyFinalized,
    SupersededBySm(crate::state::session_cleanup::CleanupReport),
}

impl SessionFinalizationOutcome {
    /// Observe bounded cleanup failures even when the transport no longer has
    /// a useful response channel. Returning the original typed outcome keeps
    /// finalization ownership visible to tests and future transport policy.
    fn observed(self) -> Self {
        let (kind, report) = match &self {
            Self::Completed(report) => ("completed", Some(report)),
            Self::SupersededBySm(report) => ("superseded-by-sm", Some(report)),
            Self::AlreadyFinalized => ("already-finalized", None),
        };
        if let Some(report) = report.filter(|report| !report.is_clean()) {
            tracing::warn!(
                finalization = kind,
                failures = ?report.failures,
                "session finalization completed with recoverable cleanup failures"
            );
        }
        self
    }
}

impl ProtocolSession {
    fn cleanup_account(&self) -> Option<northstar_session_application::SessionCleanupAccount> {
        self.authenticated.as_ref().map(|user| {
            northstar_session_application::SessionCleanupAccount {
                user_id: user.id,
                username: user.username.clone(),
                auth_generation: user.auth_generation,
            }
        })
    }

    /// Deterministically retire one C2S protocol actor.
    ///
    /// The local route/MUC ownership fence is taken synchronously before any
    /// await. Post-transport workers are then aborted and joined, after which
    /// the bounded cleanup service completes every independent durable or
    /// network side effect. A STARTTLS upgrade does not call this method: the
    /// same actor remains live until the upgraded transport actually exits.
    pub(crate) async fn finalize(&mut self) -> SessionFinalizationOutcome {
        let account = self.cleanup_account();
        let service =
            crate::state::session_cleanup::SessionCleanupService::new(Arc::clone(&self.state));
        match claim_session_cleanup(&self.route_lifecycle) {
            SessionCleanupOwnership::AlreadyFinalizing => {
                return SessionFinalizationOutcome::AlreadyFinalized.observed();
            }
            SessionCleanupOwnership::SupersededBySm => {
                self.disconnect.cancel();
                self.joined_rooms.clear();
                self.registered_key = None;
                self.full_jid = None;
                self.available = None;
                self.sm.db_id = None;
                self.sm.capacity = None;
                self._certificate_session = None;
                self.local_quiesced = true;
                let telemetry = self.state.c2s_post_action_telemetry();
                self.post_actions
                    .take_for_shutdown()
                    .abort_and_drain(&telemetry)
                    .await;
                let report = service
                    .clear_transferred_privacy(account.as_ref(), self.connection_id)
                    .await;
                return SessionFinalizationOutcome::SupersededBySm(report).observed();
            }
            SessionCleanupOwnership::Acquired => {}
        }

        // The old SM owner took the other branch above. This branch must
        // sample external revocation before it cancels its own workers.
        let resume_allowed = begin_owned_session_cleanup(&self.disconnect, self.sm.resume_allowed);
        let active_privacy_list = self
            .privacy_active
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let directed_presence = self
            .directed_presence
            .iter()
            .map(|target| target.key().clone())
            .collect::<Vec<_>>();
        self.directed_presence.clear();

        let sm_session_id = self.sm.db_id.take();
        let resumable = self.sm.enabled
            && resume_allowed
            && self.registered_key.is_some()
            && sm_session_id.is_some()
            && account.is_some()
            && self.sm.capacity.is_some();
        let sm = if resumable {
            let snapshot = self.take_sm_snapshot();
            crate::state::session_cleanup::SessionSmCleanup::Suspend {
                session_id: sm_session_id.expect("resumable session has an SM id"),
                snapshot,
                ttl_seconds: self.sm.resume_timeout_seconds.max(1),
                capacity: self
                    .sm
                    .capacity
                    .take()
                    .expect("resumable session owns its SM capacity lease"),
            }
        } else if let Some(session_id) = sm_session_id {
            crate::state::session_cleanup::SessionSmCleanup::Revoke { session_id }
        } else {
            crate::state::session_cleanup::SessionSmCleanup::None
        };
        self.sm.resume_allowed = false;
        if !resumable {
            self.sm.capacity = None;
        }

        let plan = crate::state::session_cleanup::SessionCleanupPlan {
            connection_id: self.connection_id,
            may_own_live_session: self.live_session_ownership.may_own(),
            mix_presence_gate: Arc::clone(&self.presence.mix_presence_gate),
            account,
            registered_key: self.registered_key.take(),
            full_jid: self.full_jid.take(),
            available: self.available.take(),
            active_privacy_list,
            directed_presence,
            joined_rooms: Arc::clone(&self.joined_rooms),
            sm,
        };
        let work = service.quiesce(plan);
        // There must be no cancellation point between the lifecycle claim and
        // this marker. Drop can now safely avoid repeating local quiescing.
        self.local_quiesced = true;
        let telemetry = self.state.c2s_post_action_telemetry();
        self.post_actions
            .take_for_shutdown()
            .abort_and_drain(&telemetry)
            .await;
        self._certificate_session = None;
        SessionFinalizationOutcome::Completed(service.finish(work).await).observed()
    }

    /// Panic/cancellation fallback. This deliberately performs only
    /// process-local, exact-identity quiescing: no database access, network
    /// call or detached task is legal from Drop.
    fn synchronous_drop_fallback(&mut self) {
        self.local_quiesced = true;
        self.state.session_drop_fallback_telemetry().started();
        self.state.worker_registry().observer_error(
            "session-cleanup",
            "ProtocolSession dropped before awaited cleanup",
        );
        self.disconnect.cancel();
        self.post_actions
            .abort_now(&self.state.c2s_post_action_telemetry());
        if let Some(key) = self.registered_key.take() {
            let _ = self
                .state
                .remove_session_if_connection(&key, self.connection_id);
        }
        if let Some(available) = self.available.take() {
            available.store(false, Ordering::Release);
        }
        let full_jid = self.full_jid.take().unwrap_or_default();
        let memberships = self
            .joined_rooms
            .iter()
            .map(|membership| (membership.key().clone(), membership.value().clone()))
            .collect::<Vec<_>>();
        for (room_jid, membership) in memberships {
            self.joined_rooms
                .remove_if(&room_jid, |_, current| current == &membership);
            self.state.remove_local_muc_occupant_exact(
                crate::services::muc::LocalMucOccupantIdentity {
                    room_jid: &room_jid,
                    nick: &membership.nick,
                    full_jid: &full_jid,
                    connection_id: self.connection_id,
                    cluster_epoch: membership.cluster_epoch,
                },
            );
        }
        self.directed_presence.clear();
        *self
            .privacy_active
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
        self.sm.db_id = None;
        tracing::error!(
            connection_id = %self.connection_id,
            "ProtocolSession reached Drop without awaited finalization; local ownership was quiesced and durable leases must recover by expiry/reconciliation"
        );
    }
}

impl Drop for ProtocolSession {
    fn drop(&mut self) {
        if !drop_requires_local_quiesce(
            self.local_quiesced,
            self.route_lifecycle.load(Ordering::Acquire),
        ) {
            self.post_actions
                .abort_now(&self.state.c2s_post_action_telemetry());
            return;
        }
        match claim_session_cleanup(&self.route_lifecycle) {
            SessionCleanupOwnership::Acquired | SessionCleanupOwnership::AlreadyFinalizing => {
                // AlreadyFinalizing with local_quiesced=false is the exact
                // cancellation window after a 0→1 claim and before quiesce.
                self.synchronous_drop_fallback()
            }
            SessionCleanupOwnership::SupersededBySm => {
                self.post_actions
                    .abort_now(&self.state.c2s_post_action_telemetry());
                self.joined_rooms.clear();
                self.registered_key = None;
                self.full_jid = None;
                self.sm.db_id = None;
            }
        }
    }
}

#[cfg(test)]
mod legacy_sasl_wire_tests;
