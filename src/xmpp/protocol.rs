pub(crate) mod blocking;
pub(crate) mod caps;
pub(crate) mod commands;
pub(crate) mod csi;
pub(crate) mod discovery;
pub(crate) mod dispatch;
pub(crate) mod extdisco;
pub(crate) mod federated_muc;
pub(crate) mod ibr;
pub(crate) mod jingle;
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
pub(crate) mod upload;
pub(crate) mod vcard;

use super::xml_builder::XmlElement;
use super::xml_util::*;
use crate::state::AppState;
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

const MAX_SASL_ATTEMPTS_PER_STREAM: u8 = 5;
const MAX_POST_ACTION_TASKS_PER_SESSION: usize = 16;
const POST_ACTION_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

fn stream_features_element() -> XmlElement {
    XmlElement::new("stream:features").attr("xmlns:stream", "http://etherx.jabber.org/streams")
}

fn push_generated_feature(parent: &mut XmlElement, feature: &str, label: &'static str) {
    if feature.is_empty() {
        return;
    }
    if let Err(error) = parent.push_validated_fragment(feature) {
        // Every current producer uses XmlElement itself. Keep this validation
        // boundary because feature providers live in separate protocol
        // modules and may later carry data restored from durable storage.
        tracing::error!(
            ?error,
            feature = label,
            "refused malformed generated stream feature"
        );
    }
}

type PostActionFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

struct PendingPostAction {
    name: &'static str,
    future: PostActionFuture,
}

#[derive(Default)]
struct PostActionSupervisor {
    pending: VecDeque<PendingPostAction>,
    running: tokio::task::JoinSet<&'static str>,
}

impl PostActionSupervisor {
    fn defer<F>(
        &mut self,
        name: &'static str,
        task: F,
        metrics: &crate::metrics::Metrics,
    ) -> Result<()>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.reap(metrics);
        if self.pending.len().saturating_add(self.running.len())
            >= MAX_POST_ACTION_TASKS_PER_SESSION
        {
            metrics
                .post_action_capacity_rejections_total
                .fetch_add(1, Ordering::Relaxed);
            anyhow::bail!("per-session post-action task capacity was exhausted");
        }
        self.pending.push_back(PendingPostAction {
            name,
            future: Box::pin(task),
        });
        Ok(())
    }

    fn start(&mut self, metrics: &crate::metrics::Metrics) {
        self.reap(metrics);
        while let Some(task) = self.pending.pop_front() {
            metrics
                .post_action_tasks_started_total
                .fetch_add(1, Ordering::Relaxed);
            self.running.spawn(async move {
                task.future.await;
                task.name
            });
        }
    }

    fn reap(&mut self, metrics: &crate::metrics::Metrics) {
        while let Some(result) = self.running.try_join_next() {
            observe_post_action_join(result, metrics);
        }
    }

    async fn abort_and_drain(&mut self, metrics: &crate::metrics::Metrics) {
        self.reap(metrics);
        let aborted = self.pending.len().saturating_add(self.running.len());
        self.pending.clear();
        self.running.abort_all();
        metrics
            .post_action_tasks_aborted_total
            .fetch_add(aborted as u64, Ordering::Relaxed);
        let drain = async {
            while let Some(result) = self.running.join_next().await {
                observe_post_action_join(result, metrics);
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

    fn abort_now(&mut self, metrics: &crate::metrics::Metrics) {
        self.reap(metrics);
        let aborted = self.pending.len().saturating_add(self.running.len());
        self.pending.clear();
        self.running.abort_all();
        metrics
            .post_action_tasks_aborted_total
            .fetch_add(aborted as u64, Ordering::Relaxed);
    }
}

fn observe_post_action_join(
    result: std::result::Result<&'static str, tokio::task::JoinError>,
    metrics: &crate::metrics::Metrics,
) {
    match result {
        Ok(name) => {
            metrics
                .post_action_tasks_completed_total
                .fetch_add(1, Ordering::Relaxed);
            tracing::trace!(task = name, "C2S post-action task completed");
        }
        Err(error) if error.is_cancelled() => {}
        Err(error) => {
            metrics
                .post_action_tasks_panicked_total
                .fetch_add(1, Ordering::Relaxed);
            tracing::error!(?error, "C2S post-action task panicked");
        }
    }
}

pub enum Action {
    Send(String),
    SendMany(Vec<String>),
    /// Ordered outbound items deferred by CSI. Unlike ordinary protocol
    /// replies these may carry a durable-delivery fence which the transport
    /// must complete only at its negotiated recovery boundary (SM h, BOSH
    /// response ack, or the explicit non-SM socket-write fallback).
    SendManyItems(Vec<crate::outbound::OutboundItem>),
    /// The first frame is the terminal authentication success. Publish the
    /// staged login epoch and already-committed route only after that frame
    /// reaches the transport.
    SendManyThenActivate(Vec<String>),
    /// Send each terminal payload in order and then close the XML stream.
    /// Unlike ordinary outbound stanzas these frames are not added to an SM
    /// resume queue: the operation producing them has already revoked the
    /// authenticated session and resumption must be impossible.
    SendManyAndClose(Vec<String>),
    Resume(ResumePayload),
    StartTls,
    CloseWith(String),
    Close,
    None,
}

/// Transport-owned XEP-0198 replay payload. The capacity leases are acquired
/// before the replay strings are cloned and remain attached until a transport
/// has written, queued for ordered HTTP delivery, or discarded the complete
/// action. This prevents many simultaneous resumes from bypassing the process
/// SM memory governor with an otherwise short-lived `Vec<String>` clone.
pub struct ResumePayload {
    control: String,
    /// Ordered nonzas which must follow the resume control before any replayed
    /// stanza. SASL2 uses this for the mandatory post-success stream features.
    post_control: Vec<String>,
    replay: Vec<String>,
    activate_route: bool,
    transient_capacity: Vec<crate::services::sm_capacity::SmCapacityLease>,
}

pub(crate) struct ResumeTransportParts {
    pub(crate) control: String,
    pub(crate) post_control: Vec<String>,
    pub(crate) replay: Vec<String>,
    pub(crate) activate_route: bool,
    pub(crate) transient_capacity: Vec<crate::services::sm_capacity::SmCapacityLease>,
}

impl ResumePayload {
    pub(crate) fn from_sm_unacked(
        governor: &Arc<crate::services::sm_capacity::SmMemoryGovernor>,
        control: String,
        post_control: Vec<String>,
        replay_source: &VecDeque<crate::outbound::SmUnackedStanza>,
        activate_route: bool,
    ) -> Result<Self> {
        let requested_bytes = resume_payload_requested_bytes(
            &control,
            &post_control,
            replay_source.iter().map(|entry| entry.stanza.len()),
            replay_source.len(),
        )
        .context("XEP-0198 transport replay allocation overflow")?;
        let transient_capacity = governor
            .try_reserve_transient(requested_bytes)
            .context("XEP-0198 transport replay memory capacity reached")?;

        // Allocate every clone only after the complete process reservation.
        // Explicit capacities make the preflight and actual resident charge
        // identical rather than relying on `collect` growth heuristics.
        let mut replay = Vec::with_capacity(replay_source.len());
        for entry in replay_source {
            let mut stanza = String::with_capacity(entry.stanza.len());
            stanza.push_str(&entry.stanza);
            replay.push(stanza);
        }
        let actual_bytes = resume_payload_actual_bytes(&control, &post_control, &replay)
            .context("XEP-0198 transport replay allocation overflow")?;
        anyhow::ensure!(
            actual_bytes <= requested_bytes,
            "XEP-0198 transport replay allocation exceeded its reservation"
        );
        Ok(Self {
            control,
            post_control,
            replay,
            activate_route,
            transient_capacity,
        })
    }

    pub(crate) fn control(&self) -> &str {
        &self.control
    }

    pub(crate) fn replace_envelope(
        &mut self,
        control: String,
        post_control: Vec<String>,
        reserved_bytes: usize,
        mut capacity: Vec<crate::services::sm_capacity::SmCapacityLease>,
    ) -> Result<()> {
        let actual = control
            .capacity()
            .checked_add(
                post_control
                    .capacity()
                    .checked_mul(std::mem::size_of::<String>())
                    .context("SASL2 resume post-control allocation overflow")?,
            )
            .and_then(|bytes| {
                post_control
                    .iter()
                    .try_fold(bytes, |bytes, stanza| bytes.checked_add(stanza.capacity()))
            })
            .context("SASL2 resume transport envelope allocation overflow")?;
        anyhow::ensure!(
            actual <= reserved_bytes,
            "SASL2 resume transport envelope exceeded its reservation"
        );
        self.control = control;
        self.post_control = post_control;
        self.transient_capacity.append(&mut capacity);
        Ok(())
    }

    pub(crate) fn into_transport_parts(self) -> ResumeTransportParts {
        ResumeTransportParts {
            control: self.control,
            post_control: self.post_control,
            replay: self.replay,
            activate_route: self.activate_route,
            transient_capacity: self.transient_capacity,
        }
    }
}

fn resume_payload_requested_bytes(
    control: &String,
    post_control: &Vec<String>,
    mut replay_lengths: impl Iterator<Item = usize>,
    replay_count: usize,
) -> Option<usize> {
    let bytes = control.capacity().checked_add(
        post_control
            .capacity()
            .checked_mul(std::mem::size_of::<String>())?,
    )?;
    let bytes = post_control
        .iter()
        .try_fold(bytes, |bytes, stanza| bytes.checked_add(stanza.capacity()))?;
    let bytes = bytes.checked_add(replay_count.checked_mul(std::mem::size_of::<String>())?)?;
    replay_lengths.try_fold(bytes, usize::checked_add)
}

fn resume_payload_actual_bytes(
    control: &String,
    post_control: &Vec<String>,
    replay: &Vec<String>,
) -> Option<usize> {
    let bytes = control
        .capacity()
        .checked_add(
            post_control
                .capacity()
                .checked_mul(std::mem::size_of::<String>())?,
        )?
        .checked_add(
            replay
                .capacity()
                .checked_mul(std::mem::size_of::<String>())?,
        )?;
    let bytes = post_control
        .iter()
        .chain(replay)
        .try_fold(bytes, |bytes, stanza| bytes.checked_add(stanza.capacity()))?;
    Some(bytes)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ClientTransport {
    Tcp,
    WebSocket,
    Bosh,
}

fn client_stream_limits_feature(transport: ClientTransport, authenticated: bool) -> String {
    match transport {
        // BOSH has request-body overhead plus independently configurable
        // request and inactivity bounds. Advertising the native-stream values
        // would promise a stanza size or idle window that the HTTP binding may
        // not accept, so XEP-0124 remains authoritative for this transport.
        ClientTransport::Bosh => String::new(),
        ClientTransport::Tcp | ClientTransport::WebSocket => {
            XmlElement::namespaced("limits", "urn:xmpp:stream-limits:0")
                .child(XmlElement::new("max-bytes").text(super::MAX_XMPP_FRAME_BYTES.to_string()))
                .child(
                    XmlElement::new("idle-seconds").text(
                        if authenticated {
                            super::C2S_AUTHENTICATED_IDLE_TIMEOUT.as_secs()
                        } else {
                            super::C2S_NEGOTIATION_IDLE_TIMEOUT.as_secs()
                        }
                        .to_string(),
                    ),
                )
                .finish()
        }
    }
}

pub struct ProtocolSession {
    pub(crate) state: Arc<AppState>,
    pub(crate) outbound: crate::outbound::OutboundSender,
    /// Authoritative transport-security decision. Native TLS and trusted
    /// HTTPS-proxied WebSocket/BOSH transports set this flag; framing type is
    /// never used as an authentication bypass.
    pub secure_transport: bool,
    pub(crate) transport: ClientTransport,
    pub(crate) websocket: bool,
    pub(crate) peer_ip: IpAddr,
    pub(crate) connected_at: std::time::Instant,
    pub(crate) last_activity: Arc<std::sync::RwLock<std::time::Instant>>,
    /// Whether this transport has a currently open XML stream. STARTTLS and
    /// legacy SASL both invalidate it and require a fresh opening tag before
    /// any further negotiation or application stanza is accepted.
    pub(crate) negotiation: northstar_session_core::StreamNegotiation,
    pub(crate) authenticated: Option<crate::services::authentication::AuthenticatedAccount>,
    pub(crate) authenticated_at: Option<std::time::Instant>,
    pub(crate) full_jid: Option<String>,
    pub(crate) registered_key: Option<String>,
    pub(crate) available: Option<Arc<AtomicBool>>,
    /// Exact resource-scoped MIX presence epoch gate. It is copied into the
    /// published `OnlineSession`, transferred across a live SM replacement,
    /// and crossed by finalization after route removal before suspension or
    /// unavailable publication can proceed.
    pub(crate) mix_presence_gate: Arc<tokio::sync::Mutex<()>>,
    /// Latest-wins state for explicitly directed MIX presence. A caps job may
    /// fill an uninitialised presence item, but must not recreate one that the
    /// same live resource deliberately retracted.
    pub(crate) mix_presence_fallback_suppressed: Arc<DashSet<String>>,
    /// Exact generation of the latest local XEP-0115 observation. This is
    /// separate from availability generation because a client may replace its
    /// caps advertisement while remaining available.
    pub(crate) caps_observation_generation: Arc<AtomicU64>,
    /// Authoritative broadcast presence restored by a successful XEP-0198
    /// claim. It remains inert while the replacement route is staged and is
    /// rebound to the new connection epoch only after the transport confirms
    /// `<resumed/>` and activates that exact route.
    pub(crate) resumed_caps_presence: Option<String>,
    /// Changes on every unavailable/available transition. Deferred replay
    /// workers use it to stop an older availability epoch without affecting a
    /// later reconnect on the same transport.
    pub(crate) availability_generation: Arc<AtomicU64>,
    pub(crate) carbons: Arc<AtomicBool>,
    pub(crate) priority: Arc<AtomicI16>,
    pub(crate) show: Arc<AtomicU8>,
    pub(crate) blocklist_requested: Arc<AtomicBool>,
    pub(crate) roster_requested: Arc<AtomicBool>,
    pub(crate) roster_sync: Arc<crate::services::roster::RosterSyncGate>,
    pub(crate) mix_roster_annotations: Arc<AtomicBool>,
    /// XEP-0016 active list is scoped to this resource/session. `None` means
    /// the account default applies. Sharing it with `OnlineSession` lets
    /// inbound fanout make the same decision as this protocol actor.
    pub(crate) privacy_active: Arc<std::sync::RwLock<Option<String>>>,
    pub(crate) privacy_requested: Arc<AtomicBool>,
    pub(crate) directed_presence: Arc<DashSet<String>>,
    pub(crate) last_presence: Arc<std::sync::RwLock<Option<String>>>,
    pub(crate) joined_rooms: Arc<dashmap::DashMap<String, crate::state::JoinedMucMembership>>,
    pub(crate) csi_state: northstar_xep_0352::CsiStateMachine,
    pub(crate) csi_deferred: northstar_xep_0352::DeferredQueue<crate::outbound::OutboundItem>,
    /// Bind 2 clients catch up through MAM metadata and must never receive the
    /// legacy offline queue again on their initial presence.
    pub(crate) bind2_mam_catchup: bool,
    pub(crate) sm_enabled: bool,
    pub(crate) sm_db_id: Option<uuid::Uuid>,
    pub(crate) sm_session_id_shared: Arc<std::sync::RwLock<Option<uuid::Uuid>>>,
    pub(crate) sm_resume_allowed: bool,
    pub(crate) sm_resume_timeout_seconds: u64,
    pub(crate) sm_inbound_h: u32,
    pub(crate) sm_outbound_h: u32,
    pub(crate) sm_acked_h: u32,
    pub(crate) sm_unacked: VecDeque<crate::outbound::SmUnackedStanza>,
    /// Process-local bytes retained for a resumable XEP-0198 epoch. The same
    /// RAII lease is transferred into exact disconnect recovery.
    pub(crate) sm_capacity: Option<crate::services::sm_capacity::SmCapacityLease>,
    pub(crate) sasl_state: Option<Box<dyn crate::auth::SaslMechanism>>,
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
    /// One unauthenticated transport may bootstrap at most one account. After
    /// a successful XEP-0077/XEP-0389 registration only SASL is expected.
    pub(crate) user_agent_id: Option<uuid::Uuid>,
    pub(crate) user_agent_epoch: Option<i64>,
    /// Proof that credential-side effects already committed. It is retained
    /// until the transport confirms the first terminal success/resumed frame;
    /// failure paths must close rather than manufacture a contradictory SASL
    /// failure or execute the commit a second time.
    pub(crate) pending_credential_commit:
        Option<crate::services::authentication::CredentialCommitReceipt>,
    pub(crate) channel_bindings: Option<crate::auth::ChannelBindings>,
    /// Bare JIDs authenticated by the optional C2S client-certificate PKIX
    /// verifier and id-on-xmppAddr SAN parser for this exact TLS connection.
    pub(crate) client_certificate_identities: Vec<String>,
    /// Exact DER chain and TLS snapshot which authenticated this transport.
    /// They remain inert until SASL EXTERNAL succeeds; password/SCRAM/FAST
    /// sessions are never registered for CRL-triggered draining merely
    /// because the client happened to present a certificate.
    pub(crate) client_certificate_chain:
        Vec<tokio_rustls::rustls::pki_types::CertificateDer<'static>>,
    pub(crate) tls_generation: u64,
    _certificate_session: Option<crate::tls::CertificateSessionGuard>,
    pub(crate) disconnect: tokio_util::sync::CancellationToken,
    /// Stable owner of the durable stream row.  A resumed transport gets a
    /// fresh value so a late checkpoint from the old connection cannot win.
    pub(crate) connection_id: uuid::Uuid,
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
    post_actions: std::sync::Mutex<PostActionSupervisor>,
}

impl ProtocolSession {
    pub fn new(
        state: Arc<AppState>,
        outbound: crate::outbound::OutboundSender,
        secure_transport: bool,
        transport: ClientTransport,
        peer_ip: IpAddr,
    ) -> Self {
        Self {
            state,
            outbound,
            secure_transport,
            transport,
            websocket: transport == ClientTransport::WebSocket,
            peer_ip,
            connected_at: std::time::Instant::now(),
            last_activity: Arc::new(std::sync::RwLock::new(std::time::Instant::now())),
            negotiation: northstar_session_core::StreamNegotiation::default(),
            authenticated: None,
            authenticated_at: None,
            full_jid: None,
            registered_key: None,
            available: None,
            mix_presence_gate: Arc::new(tokio::sync::Mutex::new(())),
            mix_presence_fallback_suppressed: Arc::new(DashSet::new()),
            caps_observation_generation: Arc::new(AtomicU64::new(0)),
            resumed_caps_presence: None,
            availability_generation: Arc::new(AtomicU64::new(0)),
            carbons: Arc::new(AtomicBool::new(false)),
            priority: Arc::new(AtomicI16::new(0)),
            show: Arc::new(AtomicU8::new(0)),
            blocklist_requested: Arc::new(AtomicBool::new(false)),
            roster_requested: Arc::new(AtomicBool::new(false)),
            roster_sync: Arc::new(crate::services::roster::RosterSyncGate::default()),
            mix_roster_annotations: Arc::new(AtomicBool::new(false)),
            privacy_active: Arc::new(std::sync::RwLock::new(None)),
            privacy_requested: Arc::new(AtomicBool::new(false)),
            directed_presence: Arc::new(DashSet::new()),
            last_presence: Arc::new(std::sync::RwLock::new(None)),
            joined_rooms: Arc::new(dashmap::DashMap::new()),
            csi_state: northstar_xep_0352::CsiStateMachine::new(),
            csi_deferred: csi::default_queue(),
            bind2_mam_catchup: false,
            sm_enabled: false,
            sm_db_id: None,
            sm_session_id_shared: Arc::new(std::sync::RwLock::new(None)),
            sm_resume_allowed: false,
            sm_resume_timeout_seconds: 0,
            sm_inbound_h: 0,
            sm_outbound_h: 0,
            sm_acked_h: 0,
            sm_unacked: VecDeque::new(),
            sm_capacity: None,
            sasl_state: None,
            sasl_scram_fence: None,
            legacy_sasl_awaiting_initial_response: false,
            sasl2_state: None,
            ibr_flow: None,
            user_agent_id: None,
            user_agent_epoch: None,
            pending_credential_commit: None,
            channel_bindings: None,
            client_certificate_identities: Vec::new(),
            client_certificate_chain: Vec::new(),
            tls_generation: 0,
            _certificate_session: None,
            disconnect: tokio_util::sync::CancellationToken::new(),
            connection_id: uuid::Uuid::new_v4(),
            route_lifecycle: Arc::new(AtomicU8::new(0)),
            local_quiesced: false,
            post_actions: std::sync::Mutex::new(PostActionSupervisor::default()),
        }
    }

    pub(crate) fn defer_after_transport<F>(&mut self, name: &'static str, task: F) -> Result<()>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.post_actions
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .defer(name, task, &self.state.metrics)
    }

    pub(crate) fn start_post_action_tasks(&mut self) {
        self.post_actions
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .start(&self.state.metrics);
    }

    pub(crate) fn activate_committed_route(&self) -> bool {
        let (Some(key), Some(user)) = (self.registered_key.as_deref(), self.authenticated.as_ref())
        else {
            return false;
        };
        self.state.activate_session_if_current(
            key,
            self.connection_id,
            user.id,
            user.auth_generation,
            &self.route_lifecycle,
            &self.disconnect,
        )
    }

    /// Transport-success continuation for SASL2, Bind2 and SM resumption.
    /// Credential state may already be committed because an issued FAST token
    /// is part of the success frame. Only the replacement epoch is staged; it
    /// becomes visible through an exact operation/connection fence here.
    pub(crate) async fn publish_committed_authentication_and_route(&mut self) -> bool {
        let published_epoch = if let Some(receipt) = self.pending_credential_commit.take() {
            match self
                .state
                .authentication_service()
                .publish_credential_commit(&receipt)
                .await
            {
                crate::services::authentication::AuthenticationResult::Authenticated(epoch) => {
                    epoch
                }
                crate::services::authentication::AuthenticationResult::BackendFailure(error) => {
                    self.state
                        .metrics
                        .authentication_backend_failures_total
                        .fetch_add(1, Ordering::Relaxed);
                    tracing::error!(
                        ?error,
                        connection_id = %self.connection_id,
                        "could not publish transport-confirmed authentication epoch"
                    );
                    self.sm_resume_allowed = false;
                    return false;
                }
                crate::services::authentication::AuthenticationResult::IntegrityFailure => {
                    self.state
                        .metrics
                        .fast_credential_integrity_failures_total
                        .fetch_add(1, Ordering::Relaxed);
                    tracing::error!(
                        connection_id = %self.connection_id,
                        "authentication publication integrity failure"
                    );
                    self.sm_resume_allowed = false;
                    return false;
                }
                _ => {
                    tracing::warn!(
                        connection_id = %self.connection_id,
                        "transport-confirmed authentication publication fence was lost"
                    );
                    self.sm_resume_allowed = false;
                    return false;
                }
            }
        } else {
            None
        };
        self.user_agent_epoch = published_epoch;

        let Some(key) = self.registered_key.as_deref() else {
            return true;
        };
        let Some(user) = self.authenticated.clone() else {
            return false;
        };
        let route_is_current = self.state.sessions.get_mut(key).is_some_and(|mut session| {
            if session.connection_id == self.connection_id
                && session.user_id == user.id
                && session.auth_generation == user.auth_generation
                && Arc::ptr_eq(&session.lifecycle, &self.route_lifecycle)
                && !session.disconnect.is_cancelled()
                && session.lifecycle.load(Ordering::Acquire) == 0
            {
                session.user_agent_epoch = published_epoch;
                true
            } else {
                false
            }
        });
        if !route_is_current || !self.activate_committed_route() {
            self.sm_resume_allowed = false;
            return false;
        }

        // A capability observation belongs to a connection incarnation, not
        // merely to a full JID. The old route's exact mapping/pending/jobs were
        // retired by compare-and-remove. Rebuild the observation under the
        // transferred resource gate now that the replacement is routable, so
        // live and durable resumes do not depend on the client repeating its
        // unchanged initial presence.
        self.rebind_resumed_caps_observation().await;

        if let (Some(device_id), Some(epoch)) = (self.user_agent_id, published_epoch) {
            let account = format!("{}@{}", user.username, self.state.config.domain);
            let current = self.registered_key.as_deref();
            for (other_key, session) in self.state.session_entries_for(&account) {
                if Some(other_key.as_str()) != current
                    && session.user_id == user.id
                    && session.user_agent_id == Some(device_id)
                    && session.user_agent_epoch.is_some_and(|value| value < epoch)
                {
                    session.disconnect.cancel();
                }
            }
            if let Err(error) = self
                .state
                .cluster
                .send_user_agent_replacement(&account, user.id, device_id, epoch)
                .await
            {
                tracing::warn!(
                    ?error,
                    user_id = %user.id,
                    %device_id,
                    epoch,
                    "cross-node user-agent replacement was not acknowledged; maintenance will retry"
                );
            }
        }
        true
    }

    pub(crate) fn resource_bind_deadline(&self) -> Option<std::time::Instant> {
        resource_bind_deadline_for(
            self.authenticated.is_some(),
            self.full_jid.is_some(),
            self.authenticated_at,
            self.state.config.resource_bind_timeout_seconds,
        )
    }

    fn external_certificate_session(&self) -> Result<crate::tls::CertificateSessionGuard> {
        self.state.tls.register_certificate_session(
            self.connection_id,
            crate::tls::CertificateSessionKind::C2s,
            self.client_certificate_chain.clone(),
            self.tls_generation,
            self.disconnect.clone(),
        )
    }

    fn register_external_certificate_session(&mut self) -> Result<()> {
        if self._certificate_session.is_none() {
            self._certificate_session = Some(self.external_certificate_session()?);
        }
        Ok(())
    }

    pub(crate) fn begin_sasl_attempt(&mut self) -> Option<Action> {
        if !self
            .negotiation
            .reserve_sasl_attempt(MAX_SASL_ATTEMPTS_PER_STREAM)
        {
            self.sasl_state = None;
            self.sasl_scram_fence = None;
            self.legacy_sasl_awaiting_initial_response = false;
            self.sasl2_state = None;
            return Some(Action::CloseWith(stream_error("policy-violation")));
        }
        None
    }

    pub async fn record_outbound(&mut self, stanza: &str) -> Result<()> {
        self.record_outbound_with_delivery(stanza, None).await
    }

    /// Record one transport item before it crosses the socket boundary.
    /// Returns `true` when XEP-0198 owns the durable fence and the transport
    /// must therefore wait for a client `<a/>` instead of deleting the spool
    /// row after `write()`.
    pub(crate) async fn record_outbound_item(
        &mut self,
        item: &crate::outbound::OutboundItem,
    ) -> Result<bool> {
        let managed_by_sm = durable_delivery_managed_by_sm(
            self.sm_enabled,
            &item.stanza,
            item.durable_delivery.is_some(),
        );
        self.record_outbound_with_delivery(&item.stanza, item.durable_delivery)
            .await?;
        if managed_by_sm {
            item.confirm_transport_ownership();
        }
        Ok(managed_by_sm)
    }

    async fn record_outbound_with_delivery(
        &mut self,
        stanza: &str,
        durable_delivery: Option<crate::outbound::DurableDelivery>,
    ) -> Result<()> {
        self.state
            .metrics
            .stanzas_out_total
            .fetch_add(1, Ordering::Relaxed);
        if self.sm_enabled && is_counted_stanza(stanza) {
            let next_bytes = self
                .sm_unacked
                .iter()
                .map(|entry| entry.stanza.len())
                .sum::<usize>()
                .saturating_add(stanza.len());
            if self.sm_unacked.len() >= self.state.config.sm_max_unacked_stanzas
                || next_bytes > self.state.config.sm_max_unacked_bytes
            {
                self.sm_resume_allowed = false;
                anyhow::bail!("XEP-0198 unacknowledged queue capacity reached");
            }
            let projected = self
                .sm_resident_bytes()
                .and_then(|bytes| {
                    bytes
                        .checked_add(std::mem::size_of::<crate::outbound::SmUnackedStanza>())
                        .and_then(|bytes| bytes.checked_add(stanza.len()))
                })
                .context("XEP-0198 projected resident-size overflow")?;
            if projected > self.state.config.sm_max_snapshot_bytes
                || self
                    .sm_capacity
                    .as_ref()
                    .is_none_or(|lease| lease.try_grow_to(projected).is_err())
            {
                self.sm_resume_allowed = false;
                anyhow::bail!("XEP-0198 process memory capacity reached");
            }
            self.sm_outbound_h = self.sm_outbound_h.wrapping_add(1);
            self.sm_unacked
                .push_back(crate::outbound::SmUnackedStanza::with_delivery(
                    stanza.to_owned(),
                    durable_delivery,
                ));
            self.checkpoint_sm().await?;
        } else if durable_delivery.is_some() {
            // With SM disabled, counted RFC 6120 stanzas are legitimately
            // completed at the transport write boundary. Non-counted control
            // elements always use that path as well. Only an active SM session
            // can take ownership of a counted stanza's durable fence.
            debug_assert!(!self.sm_enabled || !is_counted_stanza(stanza));
        }
        Ok(())
    }

    pub fn record_replayed(&self) {
        self.state
            .metrics
            .stanzas_out_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn sm_snapshot(&self) -> crate::services::sm::SmSessionSnapshot {
        self.sm_snapshot_with_unacked(self.sm_unacked.iter().cloned().collect())
    }

    fn sm_snapshot_with_unacked(
        &self,
        unacked: Vec<crate::outbound::SmUnackedStanza>,
    ) -> crate::services::sm::SmSessionSnapshot {
        crate::services::sm::SmSessionSnapshot {
            inbound_h: self.sm_inbound_h,
            outbound_h: self.sm_outbound_h,
            acked_h: self.sm_acked_h,
            available: self
                .available
                .as_ref()
                .is_some_and(|available| available.load(Ordering::Relaxed)),
            carbons: self.carbons.load(Ordering::Acquire),
            priority: self.priority.load(Ordering::Relaxed),
            blocklist_requested: self.blocklist_requested.load(Ordering::Relaxed),
            roster_requested: self.roster_requested.load(Ordering::Relaxed),
            active_privacy_list: self
                .privacy_active
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone(),
            privacy_requested: self.privacy_requested.load(Ordering::Relaxed),
            peer_ip: self.peer_ip,
            user_agent_id: self.user_agent_id,
            joined_rooms: self
                .joined_rooms
                .iter()
                .map(|membership| crate::services::sm::SmMucMembership {
                    room_jid: membership.key().clone(),
                    nick: membership.nick.clone(),
                })
                .collect(),
            directed_presence: self
                .directed_presence
                .iter()
                .map(|jid| jid.key().clone())
                .collect(),
            last_presence: self
                .last_presence
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone(),
            unacked,
        }
    }

    /// Transfer the large replay FIFO into cleanup ownership. Finalization
    /// must not clone a full per-stream snapshot while the live actor still
    /// owns the same bytes; all remaining metadata is independently bounded.
    fn take_sm_snapshot(&mut self) -> crate::services::sm::SmSessionSnapshot {
        let unacked = std::mem::take(&mut self.sm_unacked).into();
        self.sm_snapshot_with_unacked(unacked)
    }

    /// Resident charge of the live SM state without cloning its replay FIFO.
    /// This mirrors `SmSessionSnapshot::resident_bytes` and is used to reserve
    /// both retained growth and short-lived snapshot clones before allocation.
    pub(crate) fn sm_resident_bytes(&self) -> Option<usize> {
        let mut bytes = std::mem::size_of::<crate::services::sm::SmSessionSnapshot>();
        let mut add = |value: usize| {
            bytes = bytes.checked_add(value)?;
            Some(())
        };
        if let Some(value) = self
            .privacy_active
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
        {
            add(value.len())?;
        }
        if let Some(value) = self
            .last_presence
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
        {
            add(value.len())?;
        }
        add(self
            .joined_rooms
            .len()
            .checked_mul(std::mem::size_of::<crate::services::sm::SmMucMembership>())?)?;
        for membership in self.joined_rooms.iter() {
            add(membership.key().len())?;
            add(membership.nick.len())?;
        }
        add(self
            .directed_presence
            .len()
            .checked_mul(std::mem::size_of::<String>())?)?;
        for jid in self.directed_presence.iter() {
            add(jid.key().len())?;
        }
        add(self
            .sm_unacked
            .len()
            .checked_mul(std::mem::size_of::<crate::outbound::SmUnackedStanza>())?)?;
        for stanza in &self.sm_unacked {
            add(stanza.stanza.len())?;
        }
        Some(bytes)
    }

    pub(crate) async fn checkpoint_sm(&mut self) -> Result<()> {
        let Some(id) = self.sm_db_id else {
            return Ok(());
        };
        let live_bytes = self
            .sm_resident_bytes()
            .context("XEP-0198 live resident-size overflow")?;
        let _snapshot_clone_capacity = self
            .state
            .sm_memory_governor()
            .try_reserve_live(live_bytes)
            .context("XEP-0198 transient snapshot capacity reached")?;
        let snapshot = self.sm_snapshot();
        let snapshot_bytes = snapshot
            .resident_bytes()
            .context("XEP-0198 snapshot resident-size overflow")?;
        if snapshot_bytes > self.state.config.sm_max_snapshot_bytes
            || self
                .sm_capacity
                .as_ref()
                .is_none_or(|lease| lease.try_grow_to(snapshot_bytes).is_err())
        {
            self.sm_resume_allowed = false;
            anyhow::bail!("XEP-0198 process memory capacity reached");
        }
        let updated = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            self.state.sm_service().checkpoint_session(
                id,
                self.connection_id,
                &snapshot,
                self.sm_resume_timeout_seconds,
                self.state.config.sm_live_lease_seconds,
                self.state.config.sm_max_unacked_stanzas,
                self.state.config.sm_max_unacked_bytes,
            ),
        )
        .await
        .context("XEP-0198 checkpoint database operation timed out")??;
        anyhow::ensure!(updated, "durable XEP-0198 stream lease was lost");
        Ok(())
    }

    pub(crate) fn open_stream(&self) -> String {
        let to = self
            .negotiation
            .stream_from()
            .map(|username| format!("{}@{}", username, self.state.config.domain));
        if self.websocket {
            let _ = self.outbound.try_send(self.features());
            XmlElement::namespaced("open", "urn:ietf:params:xml:ns:xmpp-framing")
                .attr("from", &self.state.config.domain)
                .optional_attr("to", to.as_deref())
                .attr("id", stream_id())
                .attr("version", "1.0")
                .attr("xml:lang", "en")
                .finish()
        } else {
            let mut opening = XmlElement::new("stream:stream")
                .attr("from", &self.state.config.domain)
                .optional_attr("to", to.as_deref())
                .attr("id", stream_id())
                .attr("version", "1.0")
                .attr("xml:lang", "en")
                .attr("xmlns", "jabber:client")
                .attr("xmlns:stream", "http://etherx.jabber.org/streams")
                .open();
            opening.push_str(&self.features());
            opening
        }
    }

    pub(crate) fn features(&self) -> String {
        let limits = client_stream_limits_feature(self.transport, self.authenticated.is_some());
        if self.authenticated.is_some() {
            let mut features = stream_features_element();
            if self.full_jid.is_none() {
                features.push_child(XmlElement::namespaced(
                    "bind",
                    "urn:ietf:params:xml:ns:xmpp-bind",
                ));
                features.push_child(
                    XmlElement::namespaced("session", "urn:ietf:params:xml:ns:xmpp-session")
                        .child(XmlElement::new("optional")),
                );
            }
            features.push_child(XmlElement::namespaced("ver", "urn:xmpp:features:rosterver"));
            if !self.sm_enabled
                && self
                    .state
                    .config
                    .xmpp_extensions
                    .enabled(northstar_xep_0198::XEP_ID)
            {
                features.push_child(XmlElement::namespaced("sm", northstar_xep_0198::NAMESPACE));
            }
            if self
                .state
                .config
                .xmpp_extensions
                .enabled(northstar_xep_0352::XEP_ID)
            {
                features.push_child(XmlElement::namespaced("csi", northstar_xep_0352::NAMESPACE));
            }
            push_generated_feature(&mut features, &limits, "stream limits");
            return features.finish();
        }
        if !self.secure_transport {
            return stream_features_element()
                .child(
                    XmlElement::namespaced("starttls", "urn:ietf:params:xml:ns:xmpp-tls")
                        .child(XmlElement::new("required")),
                )
                .finish();
        }
        let mut register = String::new();
        if !self.state.registration_is_closed() {
            // XEP-0077 explicitly supports required extension fields through
            // XEP-0004 data forms, including an invitation token. Legacy
            // element-only submissions remain accepted only when they satisfy
            // the configured registration policy.
            register.push_str(
                &XmlElement::namespaced("register", "http://jabber.org/features/iq-register")
                    .finish(),
            );
            register.push_str(&ibr::ibr_stream_feature());
        }
        let mut features = stream_features_element();
        if let Some(bindings) = self.channel_bindings.as_ref() {
            push_generated_feature(&mut features, &bindings.feature_xml(), "channel bindings");
        }
        let mut mechanisms =
            XmlElement::namespaced("mechanisms", "urn:ietf:params:xml:ns:xmpp-sasl");
        if !self.client_certificate_identities.is_empty() {
            mechanisms.push_child(XmlElement::new("mechanism").text("EXTERNAL"));
        }
        if self.channel_bindings.is_some() {
            mechanisms.push_child(XmlElement::new("mechanism").text("SCRAM-SHA-256-PLUS"));
        }
        mechanisms.push_child(XmlElement::new("mechanism").text("SCRAM-SHA-256"));
        if self.state.config.scram_sha1_enabled {
            if self.channel_bindings.is_some() {
                mechanisms.push_child(XmlElement::new("mechanism").text("SCRAM-SHA-1-PLUS"));
            }
            mechanisms.push_child(XmlElement::new("mechanism").text("SCRAM-SHA-1"));
        }
        mechanisms.push_child(XmlElement::new("mechanism").text("PLAIN"));
        features.push_child(mechanisms);
        let sasl2 = sasl2::authentication_feature_xml(self);
        push_generated_feature(&mut features, &sasl2, "SASL2 authentication");
        push_generated_feature(&mut features, &register, "in-band registration");
        push_generated_feature(&mut features, &limits, "stream limits");
        features.finish()
    }

    pub(crate) async fn authenticate(&mut self, root: Node<'_, '_>) -> Result<Action> {
        if !self.secure_transport {
            return Ok(Action::Send(failure(
                "urn:ietf:params:xml:ns:xmpp-sasl",
                "encryption-required",
            )));
        }

        if self.authenticated.is_some() || self.sasl_state.is_some() || self.sasl2_state.is_some() {
            return Ok(Action::Send(failure(
                "urn:ietf:params:xml:ns:xmpp-sasl",
                "malformed-request",
            )));
        }
        self.sasl_scram_fence = None;
        let (mechanism, payload) = match legacy_sasl_auth(root) {
            Some(request) => request,
            None => {
                return Ok(Action::Send(failure(
                    "urn:ietf:params:xml:ns:xmpp-sasl",
                    "malformed-request",
                )));
            }
        };

        let mut sasl_mech: Box<dyn crate::auth::SaslMechanism> = match mechanism.as_str() {
            "EXTERNAL" if !self.client_certificate_identities.is_empty() => Box::new(
                crate::auth::ExternalMechanism::new(self.client_certificate_identities.clone()),
            ),
            "PLAIN" => Box::new(crate::auth::PlainMechanism::new(
                self.state.config.domain.clone(),
            )),
            "SCRAM-SHA-256" => {
                if self.channel_bindings.is_some() {
                    Box::new(
                        crate::auth::ScramSha256Mechanism::new_with_channel_binding_support(
                            self.state.config.domain.clone(),
                        ),
                    )
                } else {
                    Box::new(crate::auth::ScramSha256Mechanism::new(
                        self.state.config.domain.clone(),
                    ))
                }
            }
            "SCRAM-SHA-256-PLUS" => {
                let Some(bindings) = self.channel_bindings.clone() else {
                    return Ok(Action::Send(failure(
                        "urn:ietf:params:xml:ns:xmpp-sasl",
                        "invalid-mechanism",
                    )));
                };
                Box::new(crate::auth::ScramSha256Mechanism::new_plus(
                    self.state.config.domain.clone(),
                    bindings,
                ))
            }
            "SCRAM-SHA-1" if self.state.config.scram_sha1_enabled => {
                if self.channel_bindings.is_some() {
                    Box::new(
                        crate::auth::ScramSha256Mechanism::new_sha1_with_channel_binding_support(
                            self.state.config.domain.clone(),
                        ),
                    )
                } else {
                    Box::new(crate::auth::ScramSha256Mechanism::new_sha1(
                        self.state.config.domain.clone(),
                    ))
                }
            }
            "SCRAM-SHA-1-PLUS" if self.state.config.scram_sha1_enabled => {
                let Some(bindings) = self.channel_bindings.clone() else {
                    return Ok(Action::Send(failure(
                        "urn:ietf:params:xml:ns:xmpp-sasl",
                        "invalid-mechanism",
                    )));
                };
                Box::new(crate::auth::ScramSha256Mechanism::new_sha1_plus(
                    self.state.config.domain.clone(),
                    bindings,
                ))
            }
            _ => {
                return Ok(Action::Send(failure(
                    "urn:ietf:params:xml:ns:xmpp-sasl",
                    "invalid-mechanism",
                )));
            }
        };
        self.legacy_sasl_awaiting_initial_response = false;

        let Some(payload) = payload else {
            self.legacy_sasl_awaiting_initial_response = true;
            return self
                .process_sasl_step(sasl_mech, crate::auth::SaslStep::Challenge(String::new()))
                .await;
        };
        let payload = match sasl2::normalize_base64_payload(payload) {
            Ok(payload) => payload,
            Err(condition) => {
                return Ok(Action::Send(failure(
                    "urn:ietf:params:xml:ns:xmpp-sasl",
                    condition,
                )));
            }
        };
        let step = sasl_mech.initial_response(&payload);
        self.process_sasl_step(sasl_mech, step).await
    }

    pub(crate) async fn sasl_response(&mut self, root: Node<'_, '_>) -> Result<Action> {
        let Some(payload) = legacy_sasl_payload(root) else {
            self.sasl_state = None;
            self.sasl_scram_fence = None;
            self.legacy_sasl_awaiting_initial_response = false;
            return Ok(Action::Send(failure(
                "urn:ietf:params:xml:ns:xmpp-sasl",
                "malformed-request",
            )));
        };

        if self.sasl_state.is_none() {
            return Ok(Action::Send(failure(
                "urn:ietf:params:xml:ns:xmpp-sasl",
                "not-authorized",
            )));
        }
        let payload = match sasl2::normalize_base64_payload(payload) {
            Ok(payload) => payload,
            Err(condition) => {
                self.sasl_state = None;
                self.sasl_scram_fence = None;
                self.legacy_sasl_awaiting_initial_response = false;
                return Ok(Action::Send(failure(
                    "urn:ietf:params:xml:ns:xmpp-sasl",
                    condition,
                )));
            }
        };
        let mut sasl_mech = self
            .sasl_state
            .take()
            .expect("SASL exchange presence checked above");

        let step = if std::mem::take(&mut self.legacy_sasl_awaiting_initial_response) {
            sasl_mech.initial_response(&payload)
        } else {
            sasl_mech.response(&payload)
        };
        self.process_sasl_step(sasl_mech, step).await
    }

    pub(crate) fn sasl_abort(&mut self, root: Node<'_, '_>) -> Action {
        if !legacy_sasl_payload(root).is_some_and(|payload| payload.trim().is_empty())
            || self.sasl_state.is_none()
            || self.sasl2_state.is_some()
        {
            self.sasl_state = None;
            self.sasl_scram_fence = None;
            self.legacy_sasl_awaiting_initial_response = false;
            return Action::Send(failure(
                "urn:ietf:params:xml:ns:xmpp-sasl",
                "malformed-request",
            ));
        }
        self.sasl_state = None;
        self.sasl_scram_fence = None;
        self.legacy_sasl_awaiting_initial_response = false;
        Action::Send(failure("urn:ietf:params:xml:ns:xmpp-sasl", "aborted"))
    }

    async fn process_sasl_step(
        &mut self,
        mut sasl_mech: Box<dyn crate::auth::SaslMechanism>,
        mut step: crate::auth::SaslStep,
    ) -> Result<Action> {
        if let crate::auth::SaslStep::NeedsCredentials(ref username) = step {
            let algorithm = sasl_mech
                .scram_algorithm()
                .expect("only SCRAM mechanisms request stored credentials");
            match self.sasl_login_is_limited(username).await {
                Ok(true) => {
                    self.sasl_state = None;
                    return Ok(self.sasl_rate_limit_failure());
                }
                Ok(false) => {}
                Err(error) => {
                    return Ok(self.authentication_backend_failure(
                        sasl_mech.name(),
                        username,
                        "load login abuse state",
                        &error,
                    ));
                }
            }
            match self
                .state
                .authentication_service()
                .scram_credentials(username, algorithm)
                .await
            {
                crate::services::authentication::AuthenticationResult::Authenticated(creds) => {
                    let (fence, salt, iterations, stored_key, server_key) =
                        creds.into_mechanism_parts();
                    self.sasl_scram_fence = Some(Some(fence));
                    step = sasl_mech.provide_credentials(salt, iterations, stored_key, server_key);
                }
                crate::services::authentication::AuthenticationResult::UnknownCredentials
                | crate::services::authentication::AuthenticationResult::Disabled
                | crate::services::authentication::AuthenticationResult::StaleGeneration
                | crate::services::authentication::AuthenticationResult::ExpiredCredentials
                | crate::services::authentication::AuthenticationResult::ReplayedCredentials => {
                    self.sasl_scram_fence = Some(None);
                    let (salt, iterations, stored_key, server_key) = self
                        .state
                        .authentication_service()
                        .dummy_scram_credentials(username, algorithm);
                    step = sasl_mech.provide_credentials(salt, iterations, stored_key, server_key);
                }
                crate::services::authentication::AuthenticationResult::IntegrityFailure => {
                    self.state
                        .metrics
                        .fast_credential_integrity_failures_total
                        .fetch_add(1, Ordering::Relaxed);
                    tracing::error!("credential integrity failure while loading SCRAM verifier");
                    return Ok(Action::Send(failure(
                        "urn:ietf:params:xml:ns:xmpp-sasl",
                        "temporary-auth-failure",
                    )));
                }
                crate::services::authentication::AuthenticationResult::BackendFailure(error) => {
                    return Ok(self.authentication_backend_failure(
                        sasl_mech.name(),
                        username,
                        "load SCRAM verifier",
                        &error,
                    ));
                }
            }
        }

        match step {
            crate::auth::SaslStep::Success(username, mut data_opt) => {
                let authenticated_with_external = sasl_mech.name() == "EXTERNAL";
                self.legacy_sasl_awaiting_initial_response = false;
                match self.sasl_login_is_limited(&username).await {
                    Ok(true) => {
                        if let Some(password) =
                            data_opt.as_mut().filter(|_| sasl_mech.name() == "PLAIN")
                        {
                            password.zeroize();
                        }
                        self.sasl_state = None;
                        return Ok(self.sasl_rate_limit_failure());
                    }
                    Ok(false) => {}
                    Err(error) => {
                        if let Some(password) = data_opt.as_mut() {
                            password.zeroize();
                        }
                        return Ok(self.authentication_backend_failure(
                            sasl_mech.name(),
                            &username,
                            "load login abuse state",
                            &error,
                        ));
                    }
                }
                let legacy_stream_identity_mismatch = self.sasl2_state.is_none()
                    && self
                        .negotiation
                        .stream_from()
                        .is_some_and(|stream_from| stream_from != username);
                let user_result = if sasl_mech.name() == "PLAIN" {
                    let password = data_opt.take();
                    if let Some(password) = password.as_deref() {
                        self.state
                            .authentication_service()
                            .authenticate_plain(&username, password)
                            .await
                    } else {
                        crate::services::authentication::AuthenticationResult::UnknownCredentials
                    }
                } else if sasl_mech.name().starts_with("SCRAM-") {
                    let fence = self.sasl_scram_fence.take().flatten();
                    self.state
                        .authentication_service()
                        .complete_scram(&username, fence)
                        .await
                } else {
                    self.state
                        .authentication_service()
                        .authenticate_external(&username)
                        .await
                };
                let user_result = if legacy_stream_identity_mismatch
                    && matches!(
                        &user_result,
                        crate::services::authentication::AuthenticationResult::Authenticated(_)
                    ) {
                    crate::services::authentication::AuthenticationResult::UnknownCredentials
                } else {
                    user_result
                };
                let user = match user_result {
                    crate::services::authentication::AuthenticationResult::Authenticated(user) => {
                        Some(user)
                    }
                    crate::services::authentication::AuthenticationResult::UnknownCredentials => {
                        None
                    }
                    crate::services::authentication::AuthenticationResult::Disabled => {
                        tracing::debug!(%username, mechanism = sasl_mech.name(), "authentication rejected for a disabled account");
                        None
                    }
                    crate::services::authentication::AuthenticationResult::StaleGeneration
                    | crate::services::authentication::AuthenticationResult::ExpiredCredentials
                    | crate::services::authentication::AuthenticationResult::ReplayedCredentials => {
                        tracing::debug!(%username, mechanism = sasl_mech.name(), "authentication rejected by a stale credential fence");
                        None
                    }
                    crate::services::authentication::AuthenticationResult::IntegrityFailure => {
                        self.state
                            .metrics
                            .fast_credential_integrity_failures_total
                            .fetch_add(1, Ordering::Relaxed);
                        tracing::error!(
                            "credential integrity failure while completing authentication"
                        );
                        return Ok(Action::Send(failure(
                            "urn:ietf:params:xml:ns:xmpp-sasl",
                            "temporary-auth-failure",
                        )));
                    }
                    crate::services::authentication::AuthenticationResult::BackendFailure(
                        error,
                    ) => {
                        return Ok(self.authentication_backend_failure(
                            sasl_mech.name(),
                            &username,
                            "complete authentication",
                            &error,
                        ));
                    }
                };

                match user {
                    Some(user) => {
                        self.sasl_scram_fence = None;
                        tracing::info!(username = %user.username, "XMPP authentication succeeded");
                        if self.sasl2_state.is_some() {
                            let additional_data = if sasl_mech.name().starts_with("SCRAM-") {
                                data_opt.map(|value| Zeroizing::new(value.as_bytes().to_vec()))
                            } else {
                                None
                            };
                            return self
                                .complete_sasl2(user, additional_data, authenticated_with_external)
                                .await;
                        }
                        if authenticated_with_external {
                            self.register_external_certificate_session()?;
                            if self.disconnect.is_cancelled() {
                                self.sasl_state = None;
                                return Ok(Action::Close);
                            }
                        }
                        self.authenticated = Some(user);
                        self.authenticated_at = Some(std::time::Instant::now());
                        // RFC 6120 legacy SASL success resets the stream. Bind
                        // and all other post-authentication traffic must wait
                        // for a fresh client stream opening. SASL2 is handled
                        // above and deliberately keeps the stream open.
                        self.negotiation.require_new_stream();
                        let mut success =
                            XmlElement::namespaced("success", "urn:ietf:params:xml:ns:xmpp-sasl");
                        if sasl_mech.name().starts_with("SCRAM-") {
                            if let Some(server_final) = data_opt {
                                use base64::Engine;
                                success = success.text(
                                    base64::engine::general_purpose::STANDARD
                                        .encode(server_final.as_bytes()),
                                );
                            }
                        }
                        let success_xml = success.finish();
                        Ok(Action::Send(success_xml))
                    }
                    None => {
                        self.sasl_scram_fence = None;
                        if let Err(error) = self.record_sasl_failure(Some(&username)).await {
                            return Ok(self.authentication_backend_failure(
                                sasl_mech.name(),
                                &username,
                                "record failed login",
                                &error,
                            ));
                        }
                        self.state
                            .metrics
                            .authentication_failures_total
                            .fetch_add(1, Ordering::Relaxed);
                        self.sasl_state = None;
                        self.legacy_sasl_awaiting_initial_response = false;
                        if self.sasl2_state.take().is_some() {
                            Ok(Action::Send(sasl2::failure_xml("not-authorized", None)))
                        } else {
                            Ok(Action::Send(failure(
                                "urn:ietf:params:xml:ns:xmpp-sasl",
                                "not-authorized",
                            )))
                        }
                    }
                }
            }
            crate::auth::SaslStep::Challenge(challenge_data) => {
                use base64::Engine;
                let b64 = base64::engine::general_purpose::STANDARD.encode(challenge_data);
                self.sasl_state = Some(sasl_mech);
                let namespace = if self.sasl2_state.is_some() {
                    sasl2::SASL2_NS
                } else {
                    "urn:ietf:params:xml:ns:xmpp-sasl"
                };
                Ok(Action::Send(
                    XmlElement::new("challenge")
                        .attr("xmlns", namespace)
                        .text(b64)
                        .finish(),
                ))
            }
            crate::auth::SaslStep::Failure(err) => {
                tracing::warn!("SASL authentication failed: {}", err);
                let condition = err.condition();
                let attempted_username = sasl_mech.attempted_username().map(str::to_owned);
                if let Err(error) = self
                    .record_sasl_failure(attempted_username.as_deref())
                    .await
                {
                    return Ok(self.authentication_backend_failure(
                        sasl_mech.name(),
                        attempted_username.as_deref().unwrap_or("[unparsed]"),
                        "record malformed login",
                        &error,
                    ));
                }
                self.sasl_state = None;
                self.sasl_scram_fence = None;
                self.legacy_sasl_awaiting_initial_response = false;
                self.state
                    .metrics
                    .authentication_failures_total
                    .fetch_add(1, Ordering::Relaxed);
                if self.sasl2_state.take().is_some() {
                    Ok(Action::Send(sasl2::failure_xml(condition, None)))
                } else {
                    Ok(Action::Send(failure(
                        "urn:ietf:params:xml:ns:xmpp-sasl",
                        condition,
                    )))
                }
            }
            crate::auth::SaslStep::NeedsCredentials(_) => {
                unreachable!("NeedsCredentials should be handled above")
            }
        }
    }

    fn sasl_abuse_actors(&self, username: Option<&str>) -> Vec<String> {
        username
            .and_then(|username| crate::api::login_abuse_identity(self.peer_ip, username))
            .map(|(_, actors)| actors)
            .unwrap_or_else(|| vec![crate::api::ip_actor(self.peer_ip)])
    }

    async fn sasl_login_is_limited(&self, username: &str) -> Result<bool> {
        let actors = self.sasl_abuse_actors(Some(username));
        let requirement = self
            .state
            .abuse
            .current_requirement(crate::abuse::AbuseAction::Login, &actors)
            .await?;
        Ok(requirement.work_factor > 1 || requirement.retry_after_seconds > 0)
    }

    async fn record_sasl_failure(&self, username: Option<&str>) -> Result<()> {
        let actors = self.sasl_abuse_actors(username);
        self.state
            .abuse
            .record_failure(crate::abuse::AbuseAction::Login, &actors)
            .await
    }

    fn sasl_rate_limit_failure(&mut self) -> Action {
        self.legacy_sasl_awaiting_initial_response = false;
        self.sasl_scram_fence = None;
        self.state
            .metrics
            .rate_limited_total
            .fetch_add(1, Ordering::Relaxed);
        if self.sasl2_state.take().is_some() {
            Action::Send(sasl2::failure_xml(
                "temporary-auth-failure",
                Some("login rate limit active; retry after cooldown"),
            ))
        } else {
            Action::Send(failure(
                "urn:ietf:params:xml:ns:xmpp-sasl",
                "temporary-auth-failure",
            ))
        }
    }

    fn authentication_backend_failure(
        &mut self,
        mechanism: &str,
        username: &str,
        operation: &str,
        error: &anyhow::Error,
    ) -> Action {
        self.legacy_sasl_awaiting_initial_response = false;
        self.sasl_state = None;
        self.sasl_scram_fence = None;
        self.state
            .metrics
            .authentication_backend_failures_total
            .fetch_add(1, Ordering::Relaxed);
        tracing::error!(
            %mechanism,
            %username,
            %operation,
            integrity_failure = crate::auth::is_password_verifier_integrity_error(error),
            ?error,
            "XMPP authentication backend failed"
        );
        if self.sasl2_state.take().is_some() {
            Action::Send(sasl2::failure_xml("temporary-auth-failure", None))
        } else {
            Action::Send(failure(
                "urn:ietf:params:xml:ns:xmpp-sasl",
                "temporary-auth-failure",
            ))
        }
    }
}

fn resource_bind_deadline_for(
    authenticated: bool,
    bound: bool,
    authenticated_at: Option<std::time::Instant>,
    timeout_seconds: u64,
) -> Option<std::time::Instant> {
    if authenticated && !bound {
        authenticated_at.map(|instant| instant + std::time::Duration::from_secs(timeout_seconds))
    } else {
        None
    }
}

fn legacy_sasl_auth(root: Node<'_, '_>) -> Option<(String, Option<Zeroizing<String>>)> {
    if root.tag_name().name() != "auth"
        || root.tag_name().namespace() != Some("urn:ietf:params:xml:ns:xmpp-sasl")
        || root
            .attributes()
            .any(|attribute| attribute.namespace().is_some() || attribute.name() != "mechanism")
        || root.children().any(|child| child.is_element())
    {
        return None;
    }
    let mechanism = root.attribute("mechanism")?;
    let text_nodes = root
        .children()
        .filter(|child| child.is_text())
        .filter_map(|child| child.text())
        .collect::<Vec<_>>();
    let payload = (!text_nodes.is_empty()).then(|| Zeroizing::new(text_nodes.concat()));
    if mechanism.is_empty()
        || mechanism.len() > 128
        || payload
            .as_ref()
            .is_some_and(|payload| payload.len() > 65_536)
    {
        return None;
    }
    Some((mechanism.to_owned(), payload))
}

fn legacy_sasl_payload(root: Node<'_, '_>) -> Option<Zeroizing<String>> {
    if root.attributes().len() != 0 || root.children().any(|child| child.is_element()) {
        return None;
    }
    let payload = root
        .children()
        .filter(|child| child.is_text())
        .filter_map(|child| child.text())
        .collect::<String>();
    (payload.len() <= 65_536).then(|| Zeroizing::new(payload))
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

#[derive(Debug)]
pub(crate) enum SessionFinalizationOutcome {
    Completed(crate::services::session_cleanup::CleanupReport),
    AlreadyFinalized,
    SupersededBySm(crate::services::session_cleanup::CleanupReport),
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
    fn cleanup_account(&self) -> Option<crate::services::session_cleanup::SessionCleanupAccount> {
        self.authenticated.as_ref().map(|user| {
            crate::services::session_cleanup::SessionCleanupAccount {
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
            crate::services::session_cleanup::SessionCleanupService::new(Arc::clone(&self.state));
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
                self.sm_db_id = None;
                self.sm_capacity = None;
                self._certificate_session = None;
                self.local_quiesced = true;
                self.post_actions
                    .get_mut()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .abort_and_drain(&self.state.metrics)
                    .await;
                let report = service
                    .clear_transferred_privacy(account.as_ref(), self.connection_id)
                    .await;
                return SessionFinalizationOutcome::SupersededBySm(report).observed();
            }
            SessionCleanupOwnership::Acquired => {}
        }

        self.disconnect.cancel();
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

        let sm_session_id = self.sm_db_id.take();
        let resumable = self.sm_enabled
            && self.sm_resume_allowed
            && self.registered_key.is_some()
            && sm_session_id.is_some()
            && account.is_some()
            && self.sm_capacity.is_some();
        let sm = if resumable {
            let snapshot = self.take_sm_snapshot();
            crate::services::session_cleanup::SessionSmCleanup::Suspend {
                session_id: sm_session_id.expect("resumable session has an SM id"),
                snapshot,
                ttl_seconds: self.sm_resume_timeout_seconds.max(1),
                capacity: self
                    .sm_capacity
                    .take()
                    .expect("resumable session owns its SM capacity lease"),
            }
        } else if let Some(session_id) = sm_session_id {
            crate::services::session_cleanup::SessionSmCleanup::Revoke { session_id }
        } else {
            crate::services::session_cleanup::SessionSmCleanup::None
        };
        self.sm_resume_allowed = false;
        if !resumable {
            self.sm_capacity = None;
        }

        let plan = crate::services::session_cleanup::SessionCleanupPlan {
            connection_id: self.connection_id,
            mix_presence_gate: Arc::clone(&self.mix_presence_gate),
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
        self.post_actions
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .abort_and_drain(&self.state.metrics)
            .await;
        self._certificate_session = None;
        SessionFinalizationOutcome::Completed(service.finish(work).await).observed()
    }

    /// Panic/cancellation fallback. This deliberately performs only
    /// process-local, exact-identity quiescing: no database access, network
    /// call or detached task is legal from Drop.
    fn synchronous_drop_fallback(&mut self) {
        self.local_quiesced = true;
        self.state
            .metrics
            .session_drop_fallbacks_total
            .fetch_add(1, Ordering::Relaxed);
        self.state.worker_registry().observer_error(
            "session-cleanup",
            "ProtocolSession dropped before awaited cleanup",
        );
        self.disconnect.cancel();
        self.post_actions
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .abort_now(&self.state.metrics);
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
            let key = crate::xmpp::xml_util::muc_occupant_key(&room_jid, &membership.nick);
            self.state.muc_occupants.remove_if(&key, |_, current| {
                crate::state::muc_departure_identity_matches(
                    current,
                    &full_jid,
                    self.connection_id,
                    membership.cluster_epoch,
                )
            });
        }
        self.directed_presence.clear();
        *self
            .privacy_active
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
        self.sm_db_id = None;
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
                .get_mut()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .abort_now(&self.state.metrics);
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
                    .get_mut()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .abort_now(&self.state.metrics);
                self.joined_rooms.clear();
                self.registered_key = None;
                self.full_jid = None;
                self.sm_db_id = None;
            }
        }
    }
}

fn durable_delivery_managed_by_sm(
    sm_enabled: bool,
    stanza: &str,
    has_durable_delivery: bool,
) -> bool {
    sm_enabled && has_durable_delivery && is_counted_stanza(stanza)
}

#[cfg(test)]
mod legacy_sasl_wire_tests {
    use super::{
        client_stream_limits_feature, drop_requires_local_quiesce, durable_delivery_managed_by_sm,
        legacy_sasl_auth, legacy_sasl_payload, resource_bind_deadline_for, Action, ClientTransport,
        PostActionSupervisor, ResumePayload,
    };
    use roxmltree::Document;

    fn document(xml: &str) -> Document<'_> {
        Document::parse(xml).unwrap()
    }

    #[test]
    fn durable_counted_stanza_uses_transport_ownership_without_stream_management() {
        let stanza = "<message xmlns='jabber:client' to='bob@example.test'/>";
        assert!(!durable_delivery_managed_by_sm(false, stanza, true));
        assert!(durable_delivery_managed_by_sm(true, stanza, true));
        assert!(!durable_delivery_managed_by_sm(true, stanza, false));
        assert!(!durable_delivery_managed_by_sm(
            true,
            "<a xmlns='urn:xmpp:sm:3' h='1'/>",
            true
        ));
    }

    #[test]
    fn accepts_only_the_bounded_legacy_sasl_wire_shape() {
        let auth = document(
            "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>AGFsaWNlAHNlY3JldA==</auth>",
        );
        let (mechanism, payload) = legacy_sasl_auth(auth.root_element()).unwrap();
        assert_eq!(mechanism, "PLAIN");
        assert_eq!(
            payload.as_ref().map(|payload| payload.as_str()),
            Some("AGFsaWNlAHNlY3JldA==")
        );
        let response = document(
            "<response xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>Y2xpZW50LWZpbmFs</response>",
        );
        assert_eq!(
            legacy_sasl_payload(response.root_element())
                .as_ref()
                .map(|payload| payload.as_str()),
            Some("Y2xpZW50LWZpbmFs")
        );
    }

    #[test]
    fn cancelled_finalizer_after_claim_still_requires_drop_quiesce() {
        // lifecycle=1 models cancellation immediately after finalize won its
        // 0→1 CAS but before SessionCleanupService::quiesce returned.
        assert!(drop_requires_local_quiesce(false, 1));
        assert!(drop_requires_local_quiesce(false, 0));
        assert!(!drop_requires_local_quiesce(true, 1));
        // State 2 belongs exclusively to the exact SM claimant.
        assert!(!drop_requires_local_quiesce(false, 2));
    }

    #[test]
    fn distinguishes_an_omitted_initial_response_from_explicit_empty_data() {
        for mechanism in ["PLAIN", "SCRAM-SHA-256"] {
            let omitted_xml =
                format!("<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='{mechanism}'/>");
            let omitted = document(&omitted_xml);
            let (parsed_mechanism, payload) = legacy_sasl_auth(omitted.root_element()).unwrap();
            assert_eq!(parsed_mechanism, mechanism);
            assert!(payload.is_none());

            let explicit_empty_xml = format!(
                "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='{mechanism}'>=</auth>"
            );
            let explicit_empty = document(&explicit_empty_xml);
            let (parsed_mechanism, payload) =
                legacy_sasl_auth(explicit_empty.root_element()).unwrap();
            assert_eq!(parsed_mechanism, mechanism);
            assert_eq!(payload.as_ref().map(|payload| payload.as_str()), Some("="));
        }
    }

    #[test]
    fn rejects_sasl_attribute_and_child_smuggling() {
        for xml in [
            "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>AA==</auth>",
            "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN' extra='x'>AA==</auth>",
            "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'><response>AA==</response></auth>",
            "<auth xmlns='urn:evil' mechanism='PLAIN'>AA==</auth>",
        ] {
            let document = document(xml);
            assert!(
                legacy_sasl_auth(document.root_element()).is_none(),
                "accepted {xml}"
            );
        }
        for xml in [
            "<response xmlns='urn:ietf:params:xml:ns:xmpp-sasl' extra='x'>AA==</response>",
            "<response xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><x/>AA==</response>",
        ] {
            let document = document(xml);
            assert!(
                legacy_sasl_payload(document.root_element()).is_none(),
                "accepted {xml}"
            );
        }
    }

    #[test]
    fn resource_bind_deadline_applies_only_to_authenticated_unbound_streams() {
        let authenticated_at = std::time::Instant::now();
        assert_eq!(
            resource_bind_deadline_for(true, false, Some(authenticated_at), 30),
            Some(authenticated_at + std::time::Duration::from_secs(30))
        );
        assert_eq!(
            resource_bind_deadline_for(false, false, Some(authenticated_at), 30),
            None
        );
        // SASL2 Bind 2 and successful inline SM resume reach this state.
        assert_eq!(
            resource_bind_deadline_for(true, true, Some(authenticated_at), 30),
            None
        );
        assert_eq!(resource_bind_deadline_for(true, false, None, 30), None);
    }

    #[test]
    fn stream_limits_match_each_transport_and_authentication_phase() {
        for transport in [ClientTransport::Tcp, ClientTransport::WebSocket] {
            assert_eq!(
                client_stream_limits_feature(transport, false),
                "<limits xmlns='urn:xmpp:stream-limits:0'><max-bytes>1048576</max-bytes><idle-seconds>15</idle-seconds></limits>"
            );
            assert_eq!(
                client_stream_limits_feature(transport, true),
                "<limits xmlns='urn:xmpp:stream-limits:0'><max-bytes>1048576</max-bytes><idle-seconds>300</idle-seconds></limits>"
            );
        }
        assert_eq!(
            client_stream_limits_feature(ClientTransport::Bosh, true),
            ""
        );
    }

    fn resume_test_governor(
        max_bytes: usize,
    ) -> (
        std::sync::Arc<crate::services::sm_capacity::SmMemoryGovernor>,
        std::sync::Arc<crate::services::sm_capacity::SmCapacityMetrics>,
    ) {
        let metrics =
            std::sync::Arc::new(crate::services::sm_capacity::SmCapacityMetrics::default());
        let governor = crate::services::sm_capacity::SmMemoryGovernor::new(
            max_bytes,
            600,
            8,
            600,
            std::sync::Arc::clone(&metrics),
        )
        .unwrap();
        (governor, metrics)
    }

    fn replay_source(bytes: usize) -> std::collections::VecDeque<crate::outbound::SmUnackedStanza> {
        std::collections::VecDeque::from([crate::outbound::SmUnackedStanza::plain(
            "x".repeat(bytes),
        )])
    }

    fn resume_payload(
        governor: &std::sync::Arc<crate::services::sm_capacity::SmMemoryGovernor>,
        source: &std::collections::VecDeque<crate::outbound::SmUnackedStanza>,
    ) -> anyhow::Result<ResumePayload> {
        let mut control = String::with_capacity(64);
        control.push_str("<resumed xmlns='urn:xmpp:sm:3'/>");
        ResumePayload::from_sm_unacked(governor, control, Vec::new(), source, false)
    }

    #[test]
    fn simultaneous_resume_actions_share_the_global_transient_budget() {
        let (governor, metrics) = resume_test_governor(900);
        let source = replay_source(320);
        let first = resume_payload(&governor, &source).unwrap();
        let second = resume_payload(&governor, &source).unwrap();
        assert!(resume_payload(&governor, &source).is_err());
        assert!(
            metrics
                .reserved_bytes
                .load(std::sync::atomic::Ordering::Relaxed)
                <= 900
        );
        drop(first);
        let replacement = resume_payload(&governor, &source).unwrap();
        drop(second);
        drop(replacement);
        assert_eq!(
            metrics
                .reserved_bytes
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    #[test]
    fn dropping_resume_action_releases_every_transport_clone_reservation() {
        let (governor, metrics) = resume_test_governor(900);
        let action = Action::Resume(resume_payload(&governor, &replay_source(320)).unwrap());
        assert!(
            metrics
                .reserved_bytes
                .load(std::sync::atomic::Ordering::Relaxed)
                > 0
        );
        drop(action);
        assert_eq!(
            metrics
                .reserved_bytes
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    #[test]
    fn transport_failure_drops_resume_capacity_with_the_failed_action() {
        fn fail_transport(action: Action) -> Result<(), ()> {
            let Action::Resume(payload) = action else {
                return Ok(());
            };
            let parts = payload.into_transport_parts();
            let _capacity_held_through_failed_write = parts.transient_capacity;
            Err(())
        }

        let (governor, metrics) = resume_test_governor(900);
        let action = Action::Resume(resume_payload(&governor, &replay_source(320)).unwrap());
        assert!(fail_transport(action).is_err());
        assert_eq!(
            metrics
                .reserved_bytes
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    #[tokio::test]
    async fn post_transport_resume_publication_cannot_run_while_replay_is_pending() {
        let metrics = crate::metrics::Metrics::default();
        let published = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let task_published = std::sync::Arc::clone(&published);
        let mut supervisor = PostActionSupervisor::default();
        supervisor
            .defer(
                "resume-route-publication",
                async move {
                    task_published.store(true, std::sync::atomic::Ordering::Release);
                },
                &metrics,
            )
            .unwrap();

        tokio::task::yield_now().await;
        assert!(!published.load(std::sync::atomic::Ordering::Acquire));
        supervisor.start(&metrics);
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while !published.load(std::sync::atomic::Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        supervisor.reap(&metrics);
    }
}
