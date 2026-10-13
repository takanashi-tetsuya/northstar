//! Production-bounded XEP-0124 / XEP-0206 connection manager.
//!
//! Each BOSH session owns one actor and one `ProtocolSession`. HTTP handlers
//! never lock or mutate protocol state directly: they submit bounded commands
//! and await a one-shot response. This preserves RID order even when two HTTP
//! requests arrive concurrently and prevents transport-specific protocol
//! behavior from drifting away from TCP/WebSocket behavior.

mod action;
mod ownership;
mod response_owner;
#[cfg(test)]
pub(crate) use response_owner::stage4_saved;
#[cfg(test)]
mod saved_case;
#[cfg(test)]
pub(crate) use ownership::{sm_record_composition, RecordPort as BoshRecordPort};
#[cfg(test)]
pub(crate) use saved_case::{run as run_saved_case, validate as validate_saved_case};

use crate::state::{AppState, ClientConnectionGuard};
use crate::transport_parsing::parse_bosh_frame;
use crate::xmpp::frame_execution::FrameFailure;
use crate::xmpp::protocol::{ClientTransport, ProtocolSession, ResumeTransportParts};
use crate::xmpp::xml_builder::XmlElement;
use anyhow::Context;
use axum::body::{Body, Bytes};
use axum::extract::{ConnectInfo, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use futures::FutureExt;
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use roxmltree::Document;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;
use tokio::sync::{mpsc, oneshot, OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;

const HTTP_BIND_NS: &str = "http://jabber.org/protocol/httpbind";
const XBOSH_NS: &str = "urn:xmpp:xbosh";
const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";
const MAX_RID: u64 = 9_007_199_254_740_991;
const RESPONSE_CACHE_SIZE: usize = 2;
const MAX_UNACKNOWLEDGED_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAX_RESPONSE_ACK_AGE: Duration = Duration::from_secs(300);
const MAX_RESPONSE_REPLAYS: u8 = 2;
const BOSH_BACKEND_OPERATION_TIMEOUT: Duration = Duration::from_secs(5);

fn superseded_bosh_message_id(error: &anyhow::Error) -> Option<uuid::Uuid> {
    error
        .downcast_ref::<crate::outbound::DurableDeliverySuperseded>()
        .map(|superseded| superseded.message_id)
}

#[derive(Clone)]
pub struct BoshManager {
    inner: Arc<BoshManagerInner>,
}

struct BoshManagerInner {
    sessions: DashMap<[u8; 32], BoshHandle>,
    sid_mac_key: [u8; 32],
    session_slots: Arc<Semaphore>,
    body_read_slots: Arc<Semaphore>,
}

#[derive(Clone)]
struct BoshHandle {
    commands: mpsc::Sender<BoshCommand>,
    requests: Arc<Semaphore>,
    control_request: Arc<Semaphore>,
    overactivity: CancellationToken,
}

enum BoshCommand {
    Request {
        request: Box<BoshRequest>,
        response: oneshot::Sender<BoshHttpResponse>,
    },
    // Actor-only event synthesized from the sticky signal, never enqueued.
    Overactivity,
}

async fn next_bosh_command(
    commands: &mut mpsc::Receiver<BoshCommand>,
    overactivity: &CancellationToken,
) -> Option<BoshCommand> {
    // Prioritize overload over queued requests without changing the actor's
    // other event priorities or cancelling an already selected operation.
    tokio::select! {
        biased;
        _ = overactivity.cancelled() => Some(BoshCommand::Overactivity),
        command = commands.recv() => command,
    }
}

#[derive(Clone, Debug)]
struct BoshRequest {
    rid: u64,
    sid: Option<String>,
    to: Option<String>,
    from: Option<String>,
    wait: Option<u64>,
    hold: Option<u8>,
    ver: Option<String>,
    content: Option<String>,
    ack: Option<u64>,
    key: Option<String>,
    newkey: Option<String>,
    pause: Option<u64>,
    terminate: bool,
    restart: bool,
    xmpp_version: Option<String>,
    language: Option<String>,
    payloads: Vec<String>,
    fingerprint: [u8; 32],
    /// Captured immediately after the bounded HTTP body is parsed. Keeping
    /// arrival time on the request prevents slow stanza/database processing
    /// from making an overactive client appear compliant with `polling`.
    received_at: Instant,
}

#[derive(Clone, Debug)]
struct BoshHttpResponse {
    // RID replay, duplicate HTTP waiters and Hyper share one ref-counted byte
    // allocation. Cloning a response must never allocate another multi-
    // megabyte SM replay buffer outside the governor.
    body: Bytes,
    content_type: String,
}

struct BoshCapacityBody {
    body: String,
    _holds: Vec<Arc<Vec<crate::services::sm_capacity::SmCapacityLease>>>,
}

impl AsRef<[u8]> for BoshCapacityBody {
    fn as_ref(&self) -> &[u8] {
        self.body.as_bytes()
    }
}

fn bosh_response_bytes(
    body: String,
    holds: Vec<Arc<Vec<crate::services::sm_capacity::SmCapacityLease>>>,
) -> Bytes {
    if holds.is_empty() {
        Bytes::from(body)
    } else {
        // `Bytes::from_owner` binds the leases to the exact ref-counted body
        // allocation. Cache clones, duplicate waiters and Hyper retain them
        // until their last byte owner is consumed or dropped on failure.
        Bytes::from_owner(BoshCapacityBody {
            body,
            _holds: holds,
        })
    }
}

struct PendingRequest {
    request: BoshRequest,
    responders: Vec<oneshot::Sender<BoshHttpResponse>>,
}

#[derive(Clone)]
struct CachedResponse {
    rid: u64,
    fingerprint: [u8; 32],
    response: BoshHttpResponse,
    durable_ownership: Arc<crate::outbound::BoshResponseOwnership>,
    transport_receipts: Vec<mpsc::UnboundedSender<()>>,
    owned_at: Instant,
    response_bytes: usize,
    replays: u8,
}

struct HeldRequest {
    pending: PendingRequest,
    deadline: Instant,
}

#[derive(Debug, Eq, PartialEq)]
enum RidDisposition {
    Expected,
    BufferedOneAhead,
    Old,
    OutsideWindow,
}

struct BoshActor {
    manager: BoshManager,
    session_key: [u8; 32],
    protocol: ProtocolSession,
    replay_service: crate::state::BoshReplayService,
    mix_service: crate::state::BoshMixService,
    sm_memory_governor: Arc<crate::services::sm_capacity::SmMemoryGovernor>,
    commands: mpsc::Receiver<BoshCommand>,
    outbound: mpsc::Receiver<crate::outbound::OutboundItem>,
    next_rid: u64,
    highest_received: u64,
    highest_responded: u64,
    buffered: BTreeMap<u64, PendingRequest>,
    held: Option<HeldRequest>,
    replay: VecDeque<CachedResponse>,
    output: VecDeque<crate::outbound::OutboundItem>,
    output_bytes: usize,
    wait: Duration,
    hold: u8,
    inactivity: Duration,
    active_inactivity: Duration,
    polling: Duration,
    max_pause: u64,
    max_response_bytes: usize,
    max_output_stanzas: usize,
    max_output_bytes: usize,
    content_type: String,
    last_response: Instant,
    last_empty_poll: Option<Instant>,
    expected_key: Option<String>,
    client_acknowledgements: bool,
    delivery_session_id: uuid::Uuid,
    delivery_fence_ttl_seconds: u64,
    /// One current-or-last operation; retained old readers remain independent.
    ownership_operation: Option<northstar_delivery_core::bosh_ownership::Operation>,
    actor_shutdown: CancellationToken,
    overactivity: CancellationToken,
    _connection_guard: ClientConnectionGuard,
    _session_slot: OwnedSemaphorePermit,
}

impl BoshManager {
    pub fn new(max_sessions: usize, max_body_reads: usize) -> Self {
        let mut sid_mac_key = [0_u8; 32];
        OsRng.fill_bytes(&mut sid_mac_key);
        Self {
            inner: Arc::new(BoshManagerInner {
                sessions: DashMap::new(),
                sid_mac_key,
                session_slots: Arc::new(Semaphore::new(max_sessions)),
                body_read_slots: Arc::new(Semaphore::new(max_body_reads)),
            }),
        }
    }

    fn sid_key(&self, sid: &str) -> [u8; 32] {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.inner.sid_mac_key)
            .expect("HMAC accepts a 32-byte key");
        mac.update(sid.as_bytes());
        mac.finalize().into_bytes().into()
    }

    fn try_body_read(&self) -> Option<OwnedSemaphorePermit> {
        Arc::clone(&self.inner.body_read_slots)
            .try_acquire_owned()
            .ok()
    }

    async fn create(
        &self,
        state: Arc<AppState>,
        request: BoshRequest,
        peer_ip: IpAddr,
        connection_guard: ClientConnectionGuard,
    ) -> Result<BoshHttpResponse, &'static str> {
        let session_slot = Arc::clone(&self.inner.session_slots)
            .try_acquire_owned()
            .map_err(|_| "policy-violation")?;
        let to = request.to.as_deref().ok_or("improper-addressing")?;
        if crate::jid::prepare_domainpart(to).ok().as_deref() != Some(state.local_domain()) {
            return Err("host-unknown");
        }
        if !request.payloads.is_empty()
            || request.pause.is_some()
            || request.terminate
            || request.restart
        {
            return Err("bad-request");
        }
        if request.ack.is_some_and(|ack| ack != 1) {
            return Err("bad-request");
        }
        if request
            .xmpp_version
            .as_deref()
            .is_some_and(|version| version != "1.0")
        {
            return Err("bad-request");
        }

        let policy = state.bosh_policy();
        let wait_seconds = negotiated_wait(request.wait, policy.max_wait_seconds);
        let requested_hold = negotiated_hold(request.hold, wait_seconds);
        let requests = usize::from(requested_hold) + 1;
        let content_type = request
            .content
            .clone()
            .unwrap_or_else(|| "text/xml; charset=utf-8".to_owned());

        let (outbound_tx, outbound_rx) = mpsc::channel(policy.max_output_stanzas);
        let mut protocol = ProtocolSession::new(
            state.clone(),
            crate::outbound::OutboundSender::new(outbound_tx),
            true,
            ClientTransport::Bosh,
            None,
            peer_ip,
        );
        capture_bosh_stream(
            &mut protocol,
            request.to.as_deref(),
            request.from.as_deref(),
            request.language.as_deref(),
        )
        .map_err(|_| "improper-addressing")?;
        let features = protocol.features();

        let (command_tx, command_rx) = mpsc::channel(4);
        let overactivity = CancellationToken::new();
        let handle = BoshHandle {
            commands: command_tx,
            requests: Arc::new(Semaphore::new(requests)),
            // XEP-0124 section 12 permits one additional request above the
            // negotiated `requests` window when that request terminates or
            // pauses the session.
            control_request: Arc::new(Semaphore::new(1)),
            overactivity: overactivity.clone(),
        };
        let (sid, session_key) = loop {
            let mut bytes = [0_u8; 32];
            OsRng.fill_bytes(&mut bytes);
            let candidate = URL_SAFE_NO_PAD.encode(bytes);
            let key = self.sid_key(&candidate);
            if let Entry::Vacant(entry) = self.inner.sessions.entry(key) {
                entry.insert(handle.clone());
                break (candidate, key);
            }
        };

        let actors = state.connection_actors().clone();
        let actor_shutdown = actors.shutdown_token().child_token();
        let actor = BoshActor {
            manager: self.clone(),
            session_key,
            replay_service: state.replay_service().clone(),
            mix_service: state.mix_service().clone(),
            sm_memory_governor: Arc::clone(state.sm_memory_governor()),
            protocol,
            commands: command_rx,
            outbound: outbound_rx,
            next_rid: request.rid + 1,
            highest_received: request.rid,
            highest_responded: request.rid,
            buffered: BTreeMap::new(),
            held: None,
            replay: VecDeque::new(),
            output: VecDeque::new(),
            output_bytes: 0,
            wait: Duration::from_secs(wait_seconds),
            hold: requested_hold,
            inactivity: Duration::from_secs(policy.inactivity_seconds),
            active_inactivity: Duration::from_secs(policy.inactivity_seconds),
            polling: Duration::from_secs(policy.polling_seconds),
            max_pause: policy.max_pause_seconds,
            max_response_bytes: policy.max_response_bytes,
            max_output_stanzas: policy.max_output_stanzas,
            max_output_bytes: policy.max_output_bytes,
            content_type: content_type.clone(),
            last_response: Instant::now(),
            last_empty_poll: None,
            expected_key: request.newkey.clone(),
            client_acknowledgements: request.ack == Some(1),
            delivery_session_id: uuid::Uuid::new_v4(),
            delivery_fence_ttl_seconds: policy
                .inactivity_seconds
                .max(policy.max_pause_seconds)
                .max(wait_seconds)
                .saturating_add(30)
                .min(86_400),
            ownership_operation: None,
            actor_shutdown,
            overactivity,
            _connection_guard: connection_guard,
            _session_slot: session_slot,
        };
        if let Err(error) = actors.try_spawn(
            crate::connection_actors::ConnectionActorKind::C2sBosh,
            Some(peer_ip.to_string()),
            actor.run(),
        ) {
            // SID publication and actor admission are one logical operation.
            // The SID has not yet been returned to the client, so removing the
            // exact freshly inserted key is a complete rollback.
            self.inner.sessions.remove(&session_key);
            tracing::debug!(%peer_ip, ?error, "rejected BOSH connection actor admission");
            return Err("resource-constraint");
        }
        state.record_bosh_session_opened();

        let version = negotiated_bosh_version(request.ver.as_deref());
        let body = XmlElement::new("body")
            .attr("xmlns", HTTP_BIND_NS)
            .attr("xmlns:xmpp", XBOSH_NS)
            .attr("sid", sid)
            .attr("wait", wait_seconds)
            .attr("hold", requested_hold)
            .attr("requests", requests)
            .attr("inactivity", policy.inactivity_seconds)
            .attr("polling", policy.polling_seconds)
            .attr("maxpause", policy.max_pause_seconds)
            .attr("ver", version)
            .attr("from", state.local_domain())
            .attr("ack", request.rid)
            .attr("xmpp:version", "1.0")
            .attr("xmpp:restartlogic", "true")
            .validated_fragment(&features)
            .map_err(|_| "internal-server-error")?
            .finish();
        Ok(BoshHttpResponse {
            body: Bytes::from(body),
            content_type,
        })
    }

    async fn request(&self, request: BoshRequest) -> BoshHttpResponse {
        let Some(sid) = request.sid.as_deref() else {
            return terminal_response("bad-request");
        };
        let key = self.sid_key(sid);
        let Some(handle) = self.inner.sessions.get(&key).map(|entry| entry.clone()) else {
            return terminal_response("item-not-found");
        };
        if handle.overactivity.is_cancelled() {
            return terminal_response("policy-violation");
        }
        let is_extra_control = request.pause.is_some() || request.terminate;
        let permit = match Arc::clone(&handle.requests).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) if is_extra_control => {
                match Arc::clone(&handle.control_request).try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        handle.overactivity.cancel();
                        return terminal_response("policy-violation");
                    }
                }
            }
            Err(_) => {
                // One sticky signal survives caller cancellation and a full
                // mailbox without retaining an unpermitted HTTP send waiter.
                handle.overactivity.cancel();
                return terminal_response("policy-violation");
            }
        };
        let (response_tx, response_rx) = oneshot::channel();
        if handle
            .commands
            .send(BoshCommand::Request {
                request: Box::new(request),
                response: response_tx,
            })
            .await
            .is_err()
        {
            return terminal_response("item-not-found");
        }
        let response = response_rx
            .await
            .unwrap_or_else(|_| terminal_response("item-not-found"));
        drop(permit);
        response
    }

    fn remove(&self, key: &[u8; 32]) {
        self.inner.sessions.remove(key);
    }
}

impl BoshActor {
    async fn run(mut self) {
        let actor = AssertUnwindSafe(self.run_loop()).catch_unwind().await;
        let cleanup = AssertUnwindSafe(self.finish()).catch_unwind().await;
        match actor {
            Ok(()) => {
                if let Err(panic) = cleanup {
                    std::panic::resume_unwind(panic);
                }
            }
            Err(panic) => {
                if cleanup.is_err() {
                    tracing::error!(
                        session_id = %self.delivery_session_id,
                        "BOSH exact-once finalizer also panicked while unwinding an actor panic"
                    );
                }
                std::panic::resume_unwind(panic);
            }
        }
    }

    fn begin_ownership_operation(
        &mut self,
        kind: northstar_delivery_core::bosh_ownership::OperationKind,
    ) -> northstar_delivery_core::bosh_ownership::Operation {
        // Vec::new allocates no transfer metadata here; per-item records are
        // created only inside the existing timed child. Cleanup keeps this
        // last observation and never rewrites it as a release receipt.
        let operation = northstar_delivery_core::bosh_ownership::Operation::new(
            northstar_delivery_core::bosh_ownership::Scope {
                session_id: self.delivery_session_id,
                ttl_seconds: self.delivery_fence_ttl_seconds,
                kind,
            },
        );
        self.ownership_operation = Some(operation.clone());
        operation
    }

    async fn run_loop(&mut self) {
        let signals = self.protocol.termination_signals();
        let mut maintenance = tokio::time::interval(Duration::from_secs(1));
        maintenance.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut keep_running = true;
        while keep_running {
            // A selected operation keeps its existing completion/deadline.
            // At the next event boundary, overload wins over queued work.
            if self.overactivity.is_cancelled() {
                self.terminate_for_overactivity();
                break;
            }
            let now = Instant::now();
            let hold_deadline = self
                .held
                .as_ref()
                .map(|held| held.deadline)
                .unwrap_or(now + Duration::from_secs(86_400));
            let buffered_deadline = self
                .buffered
                .values()
                .map(|pending| pending.request.received_at + self.wait)
                .min()
                .unwrap_or(now + Duration::from_secs(86_400));
            let request_held = self.held.is_some() || !self.buffered.is_empty();
            let inactivity_deadline =
                inactivity_deadline(self.last_response, self.active_inactivity, request_held)
                    .unwrap_or(now + Duration::from_secs(86_400));
            let resource_bind_deadline = self
                .protocol
                .resource_bind_deadline()
                .unwrap_or(now + Duration::from_secs(86_400));
            tokio::select! {
                _ = self.actor_shutdown.cancelled() => {
                    // Root shutdown is a transport loss. Preserve negotiated
                    // XEP-0198 resumability while terminating held HTTP calls.
                    self.terminate_waiters("system-shutdown");
                    break;
                }
                _ = signals.backpressured() => {
                    tracing::warn!(peer_ip = %self.protocol.peer_ip, "closed slow BOSH XMPP client after an ordered outbound delivery could not be queued; recoverable messages remain available for replay and committed state will resynchronize after reconnect");
                    self.terminate_waiters("policy-violation");
                    break;
                }
                _ = signals.revoked() => {
                    self.protocol.forbid_sm_resume();
                    self.terminate_waiters("system-shutdown");
                    break;
                }
                command = next_bosh_command(&mut self.commands, &self.overactivity) => {
                    match command {
                        Some(BoshCommand::Request { request, response }) => {
                            let operation = self.begin_ownership_operation(northstar_delivery_core::bosh_ownership::OperationKind::Request);
                            keep_running = match ownership::OperationRunner::new(operation.clone(), tokio::time::timeout(
                                BOSH_BACKEND_OPERATION_TIMEOUT,
                                self.accept_request(*request, response, &operation),
                            ))
                            .await
                            {
                                Ok(keep_running) => keep_running,
                                Err(_) => {
                                    tracing::warn!(session_id = %self.delivery_session_id, "BOSH backend request budget expired");
                                    false
                                }
                            };
                            if !keep_running {
                                self.protocol.forbid_sm_resume();
                            }
                        }
                        Some(BoshCommand::Overactivity) => {
                            self.terminate_for_overactivity();
                            keep_running = false;
                        }
                        None => break,
                    }
                }
                stanza = self.outbound.recv(), if self.has_output_capacity() => {
                    match stanza {
                        Some(stanza) => {
                            let operation = self.begin_ownership_operation(northstar_delivery_core::bosh_ownership::OperationKind::Outbound);
                            if !matches!(
                                ownership::OperationRunner::new(operation.clone(), tokio::time::timeout(
                                    BOSH_BACKEND_OPERATION_TIMEOUT,
                                    self.queue_outbound(stanza, &operation),
                                ))
                                .await,
                                Ok(true)
                            ) {
                                self.protocol.forbid_sm_resume();
                                self.terminate_waiters("policy-violation");
                                keep_running = false;
                            } else if self.held.is_some()
                                && !matches!(
                                    {
                                        let operation = self.begin_ownership_operation(northstar_delivery_core::bosh_ownership::OperationKind::HeldResponse);
                                        ownership::OperationRunner::new(operation.clone(), tokio::time::timeout(
                                            BOSH_BACKEND_OPERATION_TIMEOUT,
                                            self.finish_held(None, &operation),
                                        )).await
                                    },
                                    Ok(true)
                                )
                            {
                                self.protocol.forbid_sm_resume();
                                self.terminate_waiters("internal-server-error");
                                keep_running = false;
                            }
                        }
                        None => {
                            self.protocol.forbid_sm_resume();
                            self.terminate_waiters("internal-server-error");
                            keep_running = false;
                        }
                    }
                }
                _ = tokio::time::sleep_until(hold_deadline.into()), if self.held.is_some() => {
                    let operation = self.begin_ownership_operation(northstar_delivery_core::bosh_ownership::OperationKind::HeldResponse);
                    if !matches!(
                        ownership::OperationRunner::new(operation.clone(), tokio::time::timeout(
                            BOSH_BACKEND_OPERATION_TIMEOUT,
                            self.finish_held(None, &operation),
                        ))
                        .await,
                        Ok(true)
                    ) {
                        self.protocol.forbid_sm_resume();
                        self.terminate_waiters("internal-server-error");
                        keep_running = false;
                    }
                }
                _ = tokio::time::sleep_until(buffered_deadline.into()), if !self.buffered.is_empty() => {
                    self.expire_buffered_requests(Instant::now());
                }
                _ = tokio::time::sleep_until(inactivity_deadline.into()), if !request_held => {
                    keep_running = false;
                }
                _ = tokio::time::sleep_until(resource_bind_deadline.into()), if self.protocol.resource_bind_deadline().is_some() => {
                    self.protocol.forbid_sm_resume();
                    self.terminate_waiters("policy-violation");
                    keep_running = false;
                }
                _ = maintenance.tick() => {
                    if self.protocol.unauthenticated_timed_out(Instant::now()) {
                        self.terminate_waiters("policy-violation");
                        keep_running = false;
                    } else if self.protocol.has_sm_session()
                        && self.protocol.checkpoint_sm().await.is_err()
                    {
                        self.protocol.forbid_sm_resume();
                        self.terminate_waiters("internal-server-error");
                        keep_running = false;
                    }
                }
            }
        }
    }

    async fn finish(&mut self) {
        if self.protocol.termination_signals().is_backpressured() {
            self.protocol.record_backpressure_disconnect();
        }
        // Stop admitting HTTP requests before durable/session finalization.
        // Every terminate, timeout, command-channel and backpressure exit
        // converges on this single exact-once actor epilogue.
        self.manager.remove(&self.session_key);
        match tokio::time::timeout(
            BOSH_BACKEND_OPERATION_TIMEOUT,
            self.replay_service
                .release_bosh_fences(self.delivery_session_id),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::error!(?error, session_id = %self.delivery_session_id, "failed to release BOSH durable delivery fences")
            }
            Err(_) => {
                tracing::error!(session_id = %self.delivery_session_id, "timed out releasing BOSH durable delivery fences")
            }
        }
        // The typed outcome records whether this actor owned cleanup or an SM
        // handoff already did; recoverable cleanup failures are observed by
        // ProtocolSession::finalize itself.
        let _ = self.protocol.finalize().await;
        self.protocol.record_bosh_session_closed();
    }

    async fn accept_request(
        &mut self,
        request: BoshRequest,
        response: oneshot::Sender<BoshHttpResponse>,
        operation: &northstar_delivery_core::bosh_ownership::Operation,
    ) -> bool {
        if !valid_client_response_ack(
            self.client_acknowledgements,
            self.highest_responded,
            request.rid,
            request.ack,
        ) {
            let _ = response.send(terminal_response("bad-request"));
            self.terminate_waiters("other-request");
            return false;
        }
        let response = match response_owner::replay_cached(
            &mut self.replay,
            &request,
            response,
            &mut self.last_response,
            operation,
            &response_owner::ServiceReplay {
                service: &self.replay_service,
            },
        )
        .await
        {
            response_owner::ReplayOutcome::Miss(response) => response,
            response_owner::ReplayOutcome::Sent { terminate } => {
                if terminate {
                    self.terminate_waiters("other-request");
                }
                return !terminate;
            }
            response_owner::ReplayOutcome::Failed {
                responder,
                error: _error,
            } => {
                let _ = responder.send(terminal_response("internal-server-error"));
                self.protocol.forbid_sm_resume();
                self.terminate_waiters("internal-server-error");
                return false;
            }
        };
        if let Some(held) = self
            .held
            .as_mut()
            .filter(|held| held.pending.request.rid == request.rid)
        {
            if !replace_duplicate_responders(
                &mut held.pending,
                &request,
                response,
                &self.content_type,
            ) {
                self.terminate_waiters("other-request");
                return false;
            }
            return true;
        }
        if let Some(pending) = self.buffered.get_mut(&request.rid) {
            if !replace_duplicate_responders(pending, &request, response, &self.content_type) {
                self.terminate_waiters("other-request");
                return false;
            }
            return true;
        }
        match classify_rid(self.next_rid, request.rid) {
            RidDisposition::Expected | RidDisposition::BufferedOneAhead => {}
            RidDisposition::Old | RidDisposition::OutsideWindow => {
                let _ = response.send(terminal_response("item-not-found"));
                self.terminate_waiters("other-request");
                return false;
            }
        }
        self.highest_received = self.highest_received.max(request.rid);
        // Receiving the first valid request after a pause restores the
        // normal inactivity interval even when that RID has to wait for an
        // immediately preceding request to arrive.
        self.active_inactivity = self.inactivity;
        self.buffered.insert(
            request.rid,
            PendingRequest {
                request,
                responders: vec![response],
            },
        );

        loop {
            if let (Some(held), Some(next)) =
                (self.held.as_ref(), self.buffered.get(&self.next_rid))
            {
                if too_frequent_held_empty_request(
                    &held.pending.request,
                    &next.request,
                    self.polling,
                ) {
                    // With hold=1, receiving the second allowed request while
                    // the first is still held is normal only when the client
                    // has data to send. A second empty request inside the
                    // advertised polling interval is XEP-0124 overactivity.
                    self.protocol.forbid_sm_resume();
                    self.terminate_waiters("policy-violation");
                    return false;
                }
            }
            if self.held.is_some()
                && self
                    .buffered
                    .get(&self.next_rid)
                    .is_some_and(|pending| pending.request.terminate)
            {
                // XEP-0124 requires the terminate acknowledgement on the
                // oldest held HTTP connection and an empty response on the
                // terminating request's connection. Process the newer
                // request's payload first, but swap only the responders so
                // the two HTTP responses retain that prescribed placement.
                let mut oldest = self.held.take().expect("held request was checked").pending;
                let mut terminating = self
                    .buffered
                    .remove(&self.next_rid)
                    .expect("terminating request was checked");
                let final_rid = self.next_rid == MAX_RID;
                if !final_rid {
                    self.next_rid += 1;
                }
                std::mem::swap(&mut oldest.responders, &mut terminating.responders);
                let _ = self.process_pending(terminating, operation).await;
                if !self.finish_pending(oldest, None, false, operation).await {
                    self.protocol.forbid_sm_resume();
                }
                self.terminate_waiters("other-request");
                return false;
            }
            if self.held.is_some()
                && self.buffered.contains_key(&self.next_rid)
                && !self.finish_held(None, operation).await
            {
                self.protocol.forbid_sm_resume();
                self.terminate_waiters("internal-server-error");
                return false;
            }
            if self.held.is_some() {
                break;
            }
            let Some(pending) = self.buffered.remove(&self.next_rid) else {
                break;
            };
            let final_rid = self.next_rid == MAX_RID;
            if final_rid && !pending.request.terminate {
                let _ = self
                    .finish_pending(pending, Some("item-not-found"), false, operation)
                    .await;
                self.terminate_waiters("other-request");
                return false;
            }
            if !final_rid {
                self.next_rid += 1;
            }
            if !self.process_pending(pending, operation).await {
                self.terminate_waiters("other-request");
                return false;
            }
        }
        true
    }

    async fn process_pending(
        &mut self,
        pending: PendingRequest,
        operation: &northstar_delivery_core::bosh_ownership::Operation,
    ) -> bool {
        let request = &pending.request;
        self.active_inactivity = self.inactivity;
        if !advance_bosh_key_sequence(
            &mut self.expected_key,
            request.key.as_deref(),
            request.newkey.as_deref(),
        ) {
            let _ = self
                .finish_pending(pending, Some("item-not-found"), false, operation)
                .await;
            return false;
        }
        if let Some(condition) = bosh_request_shape_error(request, self.protocol.is_stream_open()) {
            let _ = self
                .finish_pending(pending, Some(condition), false, operation)
                .await;
            return false;
        }
        // A SID alone is insufficient when the negotiated SHA-1 key sequence
        // is active. Apply the client response acknowledgement only after the
        // request has passed both its key proof and structural checks.
        if let Err(error) = self
            .renew_and_apply_response_ack(request.ack, operation)
            .await
        {
            tracing::error!(?error, session_id = %self.delivery_session_id, ack = ?request.ack, "failed to commit authenticated BOSH response acknowledgement");
            let _ = self
                .finish_pending(pending, Some("internal-server-error"), false, operation)
                .await;
            return false;
        }

        if let Some(pause) = request.pause {
            if pause > self.max_pause {
                let _ = self
                    .finish_pending(pending, Some("policy-violation"), false, operation)
                    .await;
                return false;
            }
            self.last_empty_poll = None;
            self.active_inactivity = Duration::from_secs(pause);
            self.finish_pending_empty(pending, operation);
            return true;
        }

        if request.restart {
            if !request.payloads.is_empty() {
                tracing::debug!(
                    payloads = request.payloads.len(),
                    "ignored payloads attached to a BOSH stream restart"
                );
            }
            let domain = self.protocol.local_domain().to_owned();
            let restart_to = match validated_bosh_restart_target(request.to.as_deref(), &domain) {
                Ok(target) => target,
                Err(condition) => {
                    let _ = self
                        .finish_pending(pending, Some(condition), false, operation)
                        .await;
                    return false;
                }
            };
            if capture_bosh_stream(
                &mut self.protocol,
                Some(&restart_to),
                request.from.as_deref(),
                request.language.as_deref(),
            )
            .is_err()
            {
                let _ = self
                    .finish_pending(pending, Some("improper-addressing"), false, operation)
                    .await;
                return false;
            }
            if !self.push_output(self.protocol.features()) {
                let _ = self
                    .finish_pending(pending, Some("policy-violation"), false, operation)
                    .await;
                return false;
            }
        } else {
            let mut failure = None;
            for payload in &request.payloads {
                match self.protocol.process_frame(payload).await {
                    Ok(action) => {
                        if !self.apply_action(action, operation).await {
                            failure = Some("remote-stream-error");
                            break;
                        }
                    }
                    Err(FrameFailure::Backend(error)) => {
                        tracing::debug!(?error, "BOSH XMPP stanza processing failed");
                        failure = Some("internal-server-error");
                        break;
                    }
                    Err(FrameFailure::TimedOut) => {
                        tracing::warn!(session_id = %self.delivery_session_id, "BOSH stanza backend budget expired");
                        failure = Some("internal-server-error");
                        break;
                    }
                }
            }
            if let Some(condition) = failure {
                let _ = self
                    .finish_pending(pending, Some(condition), false, operation)
                    .await;
                return false;
            }
        }
        while self.has_output_capacity() {
            let Ok(stanza) = self.outbound.try_recv() else {
                break;
            };
            if !self.queue_outbound(stanza, operation).await {
                let _ = self
                    .finish_pending(pending, Some("policy-violation"), false, operation)
                    .await;
                return false;
            }
        }

        if request.terminate {
            self.protocol.forbid_sm_resume();
            let _ = self
                .finish_pending(pending, Some("terminate"), false, operation)
                .await;
            self.terminate_waiters("other-request");
            return false;
        }
        if !self.output.is_empty() || request.restart {
            // A non-empty response breaks the consecutive-empty-poll pair
            // defined by XEP-0124 section 12.
            self.last_empty_poll = None;
            if !self.finish_pending(pending, None, true, operation).await {
                return false;
            }
        } else if self.hold == 0 {
            if request.payloads.is_empty()
                && self.last_empty_poll.is_some_and(|previous| {
                    within_polling_interval(previous, request.received_at, self.polling)
                })
            {
                let _ = self
                    .finish_pending(pending, Some("policy-violation"), false, operation)
                    .await;
                return false;
            }
            self.last_empty_poll = request.payloads.is_empty().then_some(request.received_at);
            if !self.finish_pending(pending, None, true, operation).await {
                return false;
            }
        } else {
            self.held = Some(HeldRequest {
                pending,
                deadline: Instant::now() + self.wait,
            });
        }
        true
    }

    async fn record_and_push(&mut self, stanza: String) -> bool {
        self.protocol.record_outbound(&stanza).await.is_ok() && self.push_output(stanza)
    }

    async fn renew_and_apply_response_ack(
        &mut self,
        ack: Option<u64>,
        operation: &northstar_delivery_core::bosh_ownership::Operation,
    ) -> anyhow::Result<()> {
        response_owner::renew_and_acknowledge(
            &mut self.replay,
            ack,
            operation,
            &response_owner::ServiceReplay {
                service: &self.replay_service,
            },
        )
        .await
    }

    async fn record_and_push_item(
        &mut self,
        item: crate::outbound::OutboundItem,
        operation: &northstar_delivery_core::bosh_ownership::Operation,
    ) -> bool {
        let mut output = ownership::Output {
            items: &mut self.output,
            bytes: &mut self.output_bytes,
            max_stanzas: self.max_output_stanzas,
            max_bytes: self.max_output_bytes,
        };
        let transfer = ownership::ServiceTransfer {
            service: &self.mix_service,
        };
        match ownership::record_and_push(
            &mut output,
            item,
            operation,
            &mut self.protocol,
            &transfer,
        )
        .await
        {
            Ok(accepted) => accepted,
            Err(ownership::RecordPushError::Record(error))
                if superseded_bosh_message_id(&error).is_some() =>
            {
                tracing::debug!(?error, "superseded durable BOSH/SM item skipped");
                true
            }
            Err(ownership::RecordPushError::Record(error)) => {
                tracing::error!(?error, "failed to record BOSH outbound item");
                false
            }
            Err(ownership::RecordPushError::Transfer { source, error }) => {
                tracing::error!(?error, delivery_id = %source.delivery_id, session_id = %self.delivery_session_id, "failed to persist MIX BOSH transport ownership");
                false
            }
        }
    }

    async fn queue_outbound(
        &mut self,
        item: crate::outbound::OutboundItem,
        operation: &northstar_delivery_core::bosh_ownership::Operation,
    ) -> bool {
        // BOSH cannot prove an individual stanza reached the peer without
        // response/SM acknowledgement, so a durable row remains available for
        // safe replay even after the item leaves CSI's defer buffer.
        let Some(item) = self.protocol.csi_filter_outbound(item) else {
            return true;
        };
        self.record_and_push_item(item, operation).await
    }

    fn push_output(&mut self, stanza: String) -> bool {
        self.push_output_item(crate::outbound::OutboundItem::plain(stanza))
    }

    fn push_output_item(&mut self, item: crate::outbound::OutboundItem) -> bool {
        ownership::Output {
            items: &mut self.output,
            bytes: &mut self.output_bytes,
            max_stanzas: self.max_output_stanzas,
            max_bytes: self.max_output_bytes,
        }
        .push(item)
    }

    fn has_output_capacity(&self) -> bool {
        self.output.len() < self.max_output_stanzas && self.output_bytes < self.max_output_bytes
    }

    async fn finish_held(
        &mut self,
        condition: Option<&str>,
        operation: &northstar_delivery_core::bosh_ownership::Operation,
    ) -> bool {
        if let Some(held) = self.held.take() {
            return self
                .finish_pending(held.pending, condition, true, operation)
                .await;
        }
        true
    }

    fn expire_buffered_requests(&mut self, now: Instant) {
        let expired = take_expired_buffered(&mut self.buffered, self.wait, now);
        if expired.is_empty() {
            return;
        }
        let recoverable = BoshHttpResponse {
            body: Bytes::from(
                bosh_body_element(None, false, None)
                    .attr("type", "error")
                    .finish(),
            ),
            content_type: self.content_type.clone(),
        };
        for pending in expired {
            for responder in pending.responders {
                let _ = responder.send(recoverable.clone());
            }
        }
        self.highest_received = self
            .buffered
            .keys()
            .next_back()
            .copied()
            .unwrap_or_else(|| self.next_rid.saturating_sub(1));
        self.last_response = now;
    }

    async fn finish_pending(
        &mut self,
        pending: PendingRequest,
        condition: Option<&str>,
        cache: bool,
        operation: &northstar_delivery_core::bosh_ownership::Operation,
    ) -> bool {
        let rid = pending.request.rid;
        let metadata = response_owner::Metadata {
            rid,
            fingerprint: pending.request.fingerprint,
            cache: cache && condition.is_none() && pending.request.pause.is_none(),
        };
        let received_rid =
            highest_contiguous_buffered_rid(self.next_rid, self.highest_received, &self.buffered);
        let bound = response_owner::prepare(
            &mut response_owner::Fields {
                output: &mut self.output,
                output_bytes: &mut self.output_bytes,
                replay: &mut self.replay,
                governor: &self.sm_memory_governor,
                max_response_bytes: self.max_response_bytes,
                max_output_stanzas: self.max_output_stanzas,
                content_type: &self.content_type,
                received_rid,
            },
            metadata,
            condition,
            operation,
            &response_owner::ServiceReplay {
                service: &self.replay_service,
            },
        )
        .await;
        let bound = match bound {
            Ok(bound) => bound,
            Err(failure) => {
                match failure.stage {
                    response_owner::FailureStage::Construction => {
                        tracing::error!(error = ?failure.error, rid, "failed to construct bounded BOSH response")
                    }
                    response_owner::FailureStage::Binding => {
                        tracing::error!(error = ?failure.error, session_id = %self.delivery_session_id, rid, "failed to bind durable BOSH transport sources")
                    }
                    response_owner::FailureStage::Limit => {}
                }
                failure.send(pending.responders, &self.content_type);
                return false;
            }
        };
        let bound = match bound.for_connection(self.protocol.connection_id) {
            Ok(bound) => bound,
            Err(_) => return false,
        };
        let exposed = match bound.expose(pending.responders) {
            Ok(exposed) => exposed,
            Err(error) => {
                tracing::error!(?error, rid, "BOSH bound response continuation was lost");
                return false;
            }
        };
        let ready = match exposed
            .publish_authentication(|owners| async {
                for owner in owners {
                    if !self
                        .protocol
                        .publish_committed_authentication_and_route(owner)
                        .await
                    {
                        return false;
                    }
                }
                true
            })
            .await
        {
            Ok(ready) => ready,
            Err(_) => return false,
        };
        ready
            .finish(
                &mut self.last_response,
                &mut self.highest_responded,
                &mut self.replay,
            )
            .is_ok()
    }

    fn finish_pending_empty(
        &mut self,
        pending: PendingRequest,
        operation: &northstar_delivery_core::bosh_ownership::Operation,
    ) {
        response_owner::finish_empty_control(
            pending.request.rid,
            pending.responders,
            &self.content_type,
            &mut self.last_response,
            &mut self.highest_responded,
            operation,
        );
    }

    fn terminate_for_overactivity(&mut self) {
        self.protocol.forbid_sm_resume();
        self.terminate_waiters("policy-violation");
    }

    fn terminate_waiters(&mut self, condition: &str) {
        if let Some(held) = self.held.take() {
            let response = terminal_response_with_content(condition, &self.content_type);
            for responder in held.pending.responders {
                let _ = responder.send(response.clone());
            }
        }
        let response = terminal_response_with_content(condition, &self.content_type);
        for (_, pending) in std::mem::take(&mut self.buffered) {
            for responder in pending.responders {
                let _ = responder.send(response.clone());
            }
        }
    }
}

fn queue_bosh_resume_payload(
    output: &mut VecDeque<crate::outbound::OutboundItem>,
    output_bytes: &mut usize,
    max_output_stanzas: usize,
    max_output_bytes: usize,
    payload: ResumeTransportParts,
) -> bool {
    let ResumeTransportParts {
        control,
        post_control,
        replay,
        activate_route,
        auth_publication,
        transient_capacity,
    } = payload;
    let Some(batch_count) = 1usize
        .checked_add(post_control.len())
        .and_then(|count| count.checked_add(replay.len()))
    else {
        return false;
    };
    let Some(batch_bytes) = post_control
        .iter()
        .chain(&replay)
        .try_fold(control.len(), |bytes, stanza| {
            bytes.checked_add(stanza.len())
        })
    else {
        return false;
    };
    if output
        .len()
        .checked_add(batch_count)
        .is_none_or(|count| count > max_output_stanzas)
        || output_bytes
            .checked_add(batch_bytes)
            .is_none_or(|bytes| bytes > max_output_bytes)
    {
        return false;
    }

    let hold = Arc::new(transient_capacity);
    let control = crate::outbound::OutboundItem::resume_fragment(control, Arc::clone(&hold));
    let control = if activate_route {
        let Some(holder) = auth_publication else {
            return false;
        };
        match control.with_auth_publication(holder) {
            Ok(control) => control,
            Err(_) => return false,
        }
    } else {
        if auth_publication.is_some() {
            return false;
        }
        control
    };
    output.push_back(control);
    for stanza in post_control.into_iter().chain(replay) {
        output.push_back(crate::outbound::OutboundItem::resume_fragment(
            stanza,
            Arc::clone(&hold),
        ));
    }
    *output_bytes += batch_bytes;
    true
}

type BoshResponseBody = (
    BoshHttpResponse,
    Vec<crate::outbound::TransportOwnershipSource>,
    Vec<mpsc::UnboundedSender<()>>,
    VecDeque<crate::outbound::OutboundItem>,
);

type BoshResponsePayload = (
    String,
    Vec<crate::outbound::TransportOwnershipSource>,
    Vec<mpsc::UnboundedSender<()>>,
    Vec<Arc<Vec<crate::services::sm_capacity::SmCapacityLease>>>,
    VecDeque<crate::outbound::OutboundItem>,
);

/// Put a failed response attempt back ahead of later actor output. An exact
/// superseded C2S item is the only one discarded; every other stanza and its
/// receipt keep their original relative order for response reconstruction.
fn restore_response_items(
    output: &mut VecDeque<crate::outbound::OutboundItem>,
    output_bytes: &mut usize,
    selected: VecDeque<crate::outbound::OutboundItem>,
    superseded: Option<uuid::Uuid>,
) -> bool {
    restore_response_items_observed(output, output_bytes, selected, superseded, |_| {})
}

fn restore_response_items_observed(
    output: &mut VecDeque<crate::outbound::OutboundItem>,
    output_bytes: &mut usize,
    selected: VecDeque<crate::outbound::OutboundItem>,
    superseded: Option<uuid::Uuid>,
    mut on_removed: impl FnMut(usize),
) -> bool {
    let mut removed = false;
    for (index, item) in selected.into_iter().enumerate().rev() {
        if superseded.is_some_and(|id| {
            item.c2s_delivery()
                .is_some_and(|source| source.message_id == id)
        }) {
            on_removed(index);
            removed = true;
            continue;
        }
        *output_bytes = output_bytes
            .checked_add(item.stanza.len())
            .expect("restoring previously bounded BOSH output bytes");
        output.push_front(item);
    }
    removed
}

fn take_response_payload(
    output: &mut VecDeque<crate::outbound::OutboundItem>,
    output_bytes: &mut usize,
    max_response_bytes: usize,
    governor: &Arc<crate::services::sm_capacity::SmMemoryGovernor>,
) -> anyhow::Result<BoshResponsePayload> {
    const WRAPPER_RESERVE: usize = 256;
    let mut selected = 0usize;
    let mut selected_bytes = 0usize;
    for stanza in output.iter() {
        if selected > 0
            && selected_bytes
                .saturating_add(stanza.stanza.len())
                .saturating_add(WRAPPER_RESERVE)
                > max_response_bytes
        {
            break;
        }
        if selected == 0 && stanza.stanza.len().saturating_add(WRAPPER_RESERVE) > max_response_bytes
        {
            anyhow::bail!("one BOSH output stanza exceeds the response byte limit");
        }
        selected_bytes = selected_bytes
            .checked_add(stanza.stanza.len())
            .context("BOSH response payload byte count overflow")?;
        selected += 1;
    }

    let mut transient_sm_capacity = Vec::new();
    let mut seen_capacity = std::collections::HashSet::new();
    for item in output.iter().take(selected) {
        if let Some(capacity) = &item.transient_sm_capacity {
            let identity = Arc::as_ptr(capacity) as usize;
            if seen_capacity.insert(identity) {
                transient_sm_capacity.push(Arc::clone(capacity));
            }
        }
    }
    if !transient_sm_capacity.is_empty() {
        // XmlElement's validated-fragment boundary temporarily owns `payload`,
        // its parser wrapper/copy and the final response. The original action
        // lease accounts for one copy; reserve the other two before allocating
        // any response buffer. The final String is moved into `Bytes`, so RID
        // cache, duplicate waiters and Hyper all share that one allocation.
        let construction_bytes = selected_bytes
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(WRAPPER_RESERVE * 4))
            .context("BOSH resume response construction capacity overflow")?;
        let extra = governor
            .try_reserve_transient(construction_bytes)
            .context("BOSH resume response memory capacity reached")?;
        transient_sm_capacity.push(Arc::new(extra));
    }

    let mut payload = String::with_capacity(selected_bytes);
    let mut sources = Vec::new();
    let mut transport_receipts = Vec::new();
    let mut selected_items = VecDeque::with_capacity(selected);
    for _ in 0..selected {
        let stanza = output.pop_front().expect("front was present");
        *output_bytes = output_bytes
            .checked_sub(stanza.stanza.len())
            .context("BOSH output byte accounting underflow")?;
        payload.push_str(&stanza.stanza);
        if let Some(receipt) = &stanza.transport_receipt {
            transport_receipts.push(receipt.clone());
        }
        if let Some(receipt) = &stanza.transport_write_receipt {
            transport_receipts.push(receipt.clone());
        }
        if let Some(source) = stanza.durable_source {
            sources.push(source);
        }
        selected_items.push_back(stanza);
    }
    Ok((
        payload,
        sources,
        transport_receipts,
        transient_sm_capacity,
        selected_items,
    ))
}

pub async fn http_bind(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: axum::extract::Request,
) -> Response {
    let headers = request.headers().clone();
    if !secure_proxy_request(peer.ip(), &headers, state.trusted_proxy_ips()) {
        return cors_response(StatusCode::OK, terminal_response("policy-violation"));
    }
    if !supported_request_headers(&headers) {
        return cors_response(StatusCode::OK, terminal_response("bad-request"));
    }
    let Some(body_read_slot) = state.bosh_manager().try_body_read() else {
        return cors_response(StatusCode::OK, terminal_response("policy-violation"));
    };
    let policy = state.bosh_policy();
    let body = match tokio::time::timeout(
        Duration::from_secs(policy.body_read_timeout_seconds),
        axum::body::to_bytes(request.into_body(), policy.max_request_bytes),
    )
    .await
    {
        Ok(Ok(body)) => body,
        Ok(Err(_)) => {
            return cors_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                terminal_response("policy-violation"),
            );
        }
        Err(_) => {
            return cors_response(StatusCode::OK, terminal_response("policy-violation"));
        }
    };
    let parsed = std::str::from_utf8(&body)
        .map_err(|_| "bad-request")
        .and_then(|raw| parse_body(raw, policy.max_stanzas_per_request));
    drop(body);
    drop(body_read_slot);
    let response = match parsed {
        Ok(request) if request.sid.is_some() => state.bosh_manager().request(request).await,
        Ok(request) => {
            let peer_ip = crate::api::client_ip(peer.ip(), &headers, &state);
            match state.acquire_client_connection(peer_ip) {
                Some(guard) => match state
                    .bosh_manager()
                    .create(Arc::clone(&state), request, peer_ip, guard)
                    .await
                {
                    Ok(response) => response,
                    Err(condition) => terminal_response(condition),
                },
                None => terminal_response("policy-violation"),
            }
        }
        Err(condition) => terminal_response(condition),
    };
    cors_response(StatusCode::OK, response)
}

pub async fn http_bind_options() -> Response {
    let mut response = StatusCode::NO_CONTENT.into_response();
    apply_cors(response.headers_mut());
    response
}

fn cors_response(status: StatusCode, response: BoshHttpResponse) -> Response {
    let BoshHttpResponse { body, content_type } = response;
    let content_type = HeaderValue::from_str(&content_type)
        .unwrap_or_else(|_| HeaderValue::from_static("text/xml; charset=utf-8"));
    // `Bytes` transfers the same ref-counted allocation into Hyper. Cached
    // response replay and duplicate RID waiters therefore create no hidden
    // body clones and all owners retain the same capacity lease.
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, content_type);
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, max-age=0"),
    );
    apply_cors(response.headers_mut());
    response
}

fn apply_cors(headers: &mut HeaderMap) {
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("POST, OPTIONS"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("Content-Type"),
    );
    headers.insert(
        header::ACCESS_CONTROL_MAX_AGE,
        HeaderValue::from_static("86400"),
    );
}

fn secure_proxy_request(peer_ip: IpAddr, headers: &HeaderMap, trusted: &[IpAddr]) -> bool {
    if !trusted.contains(&peer_ip) {
        return false;
    }
    let mut values = headers.get_all("x-forwarded-proto").iter();
    matches!((values.next(), values.next()), (Some(value), None) if value
        .to_str()
        .ok()
        .is_some_and(|value| !value.contains(',') && value.trim().eq_ignore_ascii_case("https")))
}

fn supported_request_headers(headers: &HeaderMap) -> bool {
    let mut content_types = headers.get_all(header::CONTENT_TYPE).iter();
    let content_type_ok = match (content_types.next(), content_types.next()) {
        (None, None) => true,
        // XEP-0124 section 14.2 explicitly tells connection managers to
        // ignore the request Content-Type. Browsers and older BOSH clients
        // legitimately use text/plain or form media types. The bounded body
        // is still parsed as one strict XML document below.
        (Some(value), None) => value.to_str().is_ok_and(|value| value.len() <= 256),
        _ => false,
    };
    let mut content_encodings = headers.get_all(header::CONTENT_ENCODING).iter();
    let content_encoding_ok = match (content_encodings.next(), content_encodings.next()) {
        (None, None) => true,
        (Some(value), None) => value
            .to_str()
            .ok()
            .is_some_and(|value| value.eq_ignore_ascii_case("identity")),
        _ => false,
    };
    content_type_ok && content_encoding_ok
}

fn classify_rid(next_rid: u64, rid: u64) -> RidDisposition {
    if rid < next_rid {
        RidDisposition::Old
    } else if rid == next_rid {
        RidDisposition::Expected
    } else if rid == next_rid.saturating_add(1) {
        RidDisposition::BufferedOneAhead
    } else {
        RidDisposition::OutsideWindow
    }
}

fn valid_client_response_ack(
    acknowledgements_announced: bool,
    highest_responded: u64,
    request_rid: u64,
    ack: Option<u64>,
) -> bool {
    ack.is_none_or(|ack| {
        acknowledgements_announced && ack < request_rid && ack <= highest_responded
    })
}

fn advance_bosh_key_sequence(
    expected_key: &mut Option<String>,
    key: Option<&str>,
    newkey: Option<&str>,
) -> bool {
    match expected_key.as_deref() {
        None => key.is_none() && newkey.is_none(),
        Some(expected) => {
            let Some(key) = key else {
                return false;
            };
            let digest = Sha1::digest(key.as_bytes());
            let mut actual = String::with_capacity(40);
            for byte in digest {
                use std::fmt::Write as _;
                let _ = write!(&mut actual, "{byte:02x}");
            }
            if !bool::from(actual.as_bytes().ct_eq(expected.as_bytes())) {
                return false;
            }
            *expected_key = Some(newkey.unwrap_or(key).to_owned());
            true
        }
    }
}

fn replay_response(
    replay: &mut VecDeque<CachedResponse>,
    request: &BoshRequest,
) -> Option<(
    BoshHttpResponse,
    bool,
    Arc<crate::outbound::BoshResponseOwnership>,
)> {
    let cached = replay.iter_mut().find(|cached| cached.rid == request.rid)?;
    if cached.fingerprint != request.fingerprint {
        return Some((
            terminal_response("bad-request"),
            true,
            Arc::new(crate::outbound::BoshResponseOwnership::default()),
        ));
    }
    if cached.replays >= MAX_RESPONSE_REPLAYS {
        return Some((
            terminal_response("policy-violation"),
            true,
            Arc::new(crate::outbound::BoshResponseOwnership::default()),
        ));
    }
    cached.replays += 1;
    Some((
        cached.response.clone(),
        false,
        cached.durable_ownership.clone(),
    ))
}

fn bosh_unacknowledged_limit_exceeded(
    replay: &VecDeque<CachedResponse>,
    next_response_bytes: usize,
    now: Instant,
) -> bool {
    replay.len() >= RESPONSE_CACHE_SIZE
        || replay
            .iter()
            .map(|cached| cached.response_bytes)
            .sum::<usize>()
            .saturating_add(next_response_bytes)
            > MAX_UNACKNOWLEDGED_RESPONSE_BYTES
        || replay
            .front()
            .is_some_and(|cached| now.duration_since(cached.owned_at) >= MAX_RESPONSE_ACK_AGE)
}

fn replace_duplicate_responders(
    pending: &mut PendingRequest,
    request: &BoshRequest,
    newest: oneshot::Sender<BoshHttpResponse>,
    content_type: &str,
) -> bool {
    if pending.request.fingerprint != request.fingerprint {
        let _ = newest.send(terminal_response_with_content("bad-request", content_type));
        return false;
    }
    let recoverable = BoshHttpResponse {
        body: Bytes::from(
            bosh_body_element(None, false, None)
                .attr("type", "error")
                .finish(),
        ),
        content_type: content_type.to_owned(),
    };
    for previous in std::mem::take(&mut pending.responders) {
        let _ = previous.send(recoverable.clone());
    }
    pending.responders.push(newest);
    true
}

fn inactivity_deadline(
    last_response: Instant,
    inactivity: Duration,
    request_held: bool,
) -> Option<Instant> {
    (!request_held).then_some(last_response + inactivity)
}

fn take_expired_buffered(
    buffered: &mut BTreeMap<u64, PendingRequest>,
    wait: Duration,
    now: Instant,
) -> Vec<PendingRequest> {
    let expired = buffered
        .iter()
        .filter_map(|(rid, pending)| (pending.request.received_at + wait <= now).then_some(*rid))
        .collect::<Vec<_>>();
    expired
        .into_iter()
        .filter_map(|rid| buffered.remove(&rid))
        .collect()
}

fn within_polling_interval(previous: Instant, current: Instant, polling: Duration) -> bool {
    current
        .checked_duration_since(previous)
        .is_some_and(|elapsed| elapsed < polling)
}

fn too_frequent_held_empty_request(
    previous: &BoshRequest,
    current: &BoshRequest,
    polling: Duration,
) -> bool {
    current.payloads.is_empty()
        && current.pause.is_none()
        && !current.terminate
        && within_polling_interval(previous.received_at, current.received_at, polling)
}

fn bosh_body_element(
    condition: Option<&str>,
    terminate: bool,
    highest_contiguous_received: Option<u64>,
) -> XmlElement {
    let mut body = XmlElement::new("body").attr("xmlns", HTTP_BIND_NS);
    if terminate {
        body = body.attr("type", "terminate");
        if let Some(condition) = condition.filter(|condition| *condition != "terminate") {
            body = body.attr("condition", condition);
            if condition == "remote-stream-error" {
                body = body.attr("xmlns:stream", "http://etherx.jabber.org/streams");
            }
        }
    } else if let Some(highest_contiguous_received) = highest_contiguous_received {
        body = body.attr("ack", highest_contiguous_received);
    }
    body
}

fn highest_contiguous_buffered_rid(
    next_rid: u64,
    highest_received: u64,
    buffered: &BTreeMap<u64, PendingRequest>,
) -> Option<u64> {
    if highest_received < next_rid || !buffered.contains_key(&next_rid) {
        return None;
    }
    let mut contiguous = next_rid;
    while contiguous < highest_received {
        let Some(candidate) = contiguous.checked_add(1) else {
            break;
        };
        if !buffered.contains_key(&candidate) {
            break;
        }
        contiguous = candidate;
    }
    Some(contiguous)
}

fn parse_body(raw: &str, max_stanzas: usize) -> Result<BoshRequest, &'static str> {
    let frame = parse_bosh_frame(
        raw,
        max_stanzas,
        crate::xmpp::MAX_XMPP_FRAME_BYTES,
        HTTP_BIND_NS,
    )?;
    let document = Document::parse(&frame).map_err(|_| "bad-request")?;
    let root = document.root_element();

    let sid = attr(root, "sid").map(str::to_owned);
    let creation = sid.is_none();
    for attribute in root.attributes() {
        let allowed = match attribute.namespace() {
            None => {
                let common = matches!(attribute.name(), "rid" | "sid" | "ack");
                common
                    || (creation
                        && matches!(
                            attribute.name(),
                            "to" | "from"
                                | "wait"
                                | "hold"
                                | "ver"
                                | "route"
                                | "content"
                                | "newkey"
                        ))
                    || (!creation
                        && matches!(
                            attribute.name(),
                            "to" | "from" | "pause" | "type" | "key" | "newkey"
                        ))
            }
            Some(XBOSH_NS) => {
                (creation && attribute.name() == "version")
                    || (!creation && attribute.name() == "restart")
            }
            Some(XML_NS) => attribute.name() == "lang",
            _ => false,
        };
        if !allowed {
            return Err("bad-request");
        }
    }

    let rid = positive_number(attr(root, "rid").ok_or("bad-request")?)?;
    if creation && rid >= MAX_RID {
        return Err("bad-request");
    }
    let ack = attr(root, "ack").map(positive_number).transpose()?;
    let key = attr(root, "key").map(bosh_key).transpose()?;
    let newkey = attr(root, "newkey").map(bosh_key).transpose()?;
    let wait = attr(root, "wait").map(nonnegative_number).transpose()?;
    let hold = attr(root, "hold")
        .map(nonnegative_number)
        .transpose()?
        .map(u8::try_from)
        .transpose()
        .map_err(|_| "bad-request")?;
    let pause = attr(root, "pause").map(nonnegative_number).transpose()?;
    let terminate = match attr(root, "type") {
        None => false,
        Some("terminate") => true,
        Some(_) => return Err("bad-request"),
    };
    let restart = match root.attribute((XBOSH_NS, "restart")) {
        None | Some("0" | "false") => false,
        Some("1" | "true") => true,
        Some(_) => return Err("bad-request"),
    };
    let xmpp_version = root.attribute((XBOSH_NS, "version")).map(str::to_owned);
    let content = attr(root, "content")
        .map(validate_content_type)
        .transpose()?;
    if attr(root, "route").is_some_and(|route| route.chars().any(char::is_control)) {
        return Err("bad-request");
    }

    let payloads = root
        .children()
        .filter(|child| child.is_element())
        .map(|child| {
            frame
                .get(child.range())
                .map(str::to_owned)
                .ok_or("bad-request")
        })
        .collect::<Result<Vec<_>, _>>()?;
    if attr(root, "ver").is_some_and(|version| parse_bosh_version(version).is_none()) {
        return Err("bad-request");
    }
    let fingerprint = Sha256::digest(raw.as_bytes()).into();
    Ok(BoshRequest {
        rid,
        sid,
        to: attr(root, "to").map(str::to_owned),
        from: attr(root, "from").map(str::to_owned),
        wait,
        hold,
        ver: attr(root, "ver").map(str::to_owned),
        content,
        ack,
        key,
        newkey,
        pause,
        terminate,
        restart,
        xmpp_version,
        language: root.attribute((XML_NS, "lang")).map(str::to_owned),
        payloads,
        fingerprint,
        received_at: Instant::now(),
    })
}

fn bosh_key(value: &str) -> Result<String, &'static str> {
    (value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| value.to_ascii_lowercase())
        .ok_or("bad-request")
}

fn attr<'a>(root: roxmltree::Node<'a, 'a>, name: &str) -> Option<&'a str> {
    root.attribute(name)
}

fn positive_number(value: &str) -> Result<u64, &'static str> {
    let parsed = nonnegative_number(value)?;
    (parsed > 0 && parsed <= MAX_RID)
        .then_some(parsed)
        .ok_or("bad-request")
}

fn nonnegative_number(value: &str) -> Result<u64, &'static str> {
    if value.is_empty()
        || value.len() > 16
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err("bad-request");
    }
    value.parse().map_err(|_| "bad-request")
}

fn validate_content_type(value: &str) -> Result<String, &'static str> {
    let mut parts = value.split(';');
    let essence = parts.next().unwrap_or_default().trim();
    let valid_parameters = parts.all(|parameter| {
        matches!(
            parameter.trim().to_ascii_lowercase().as_str(),
            "charset=utf-8" | "charset=\"utf-8\""
        )
    });
    if value.is_empty()
        || value.len() > 128
        || value.chars().any(char::is_control)
        || HeaderValue::from_str(value).is_err()
        || !valid_parameters
        || !matches!(
            essence.to_ascii_lowercase().as_str(),
            "text/xml" | "application/xml" | "application/xmpp+xml"
        )
    {
        return Err("bad-request");
    }
    Ok(value.to_owned())
}

fn negotiated_bosh_version(client: Option<&str>) -> String {
    let Some(client) = client else {
        return "1.11".to_owned();
    };
    let Some((major, minor)) = parse_bosh_version(client) else {
        return "1.11".to_owned();
    };
    if major < 1 || (major == 1 && minor < 11) {
        format!("{major}.{minor}")
    } else {
        "1.11".to_owned()
    }
}

fn negotiated_wait(client: Option<u64>, maximum: u64) -> u64 {
    client.unwrap_or(maximum).min(maximum)
}

fn negotiated_hold(client: Option<u8>, wait: u64) -> u8 {
    if wait == 0 {
        0
    } else {
        client.unwrap_or(1).min(1)
    }
}

fn parse_bosh_version(value: &str) -> Option<(u16, u16)> {
    let (major, minor) = value.split_once('.')?;
    if major.is_empty()
        || minor.is_empty()
        || major.len() > 5
        || minor.len() > 5
        || !major.bytes().all(|byte| byte.is_ascii_digit())
        || !minor.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    Some((major.parse().ok()?, minor.parse().ok()?))
}

fn capture_bosh_stream(
    protocol: &mut ProtocolSession,
    to: Option<&str>,
    from: Option<&str>,
    language: Option<&str>,
) -> Result<(), ()> {
    let opening = XmlElement::new("stream:stream")
        .attr("xmlns:stream", "http://etherx.jabber.org/streams")
        .attr("xmlns", "jabber:client")
        .optional_attr("to", to)
        .optional_attr("from", from)
        .optional_attr("xml:lang", language)
        .attr("version", "1.0")
        .open();
    protocol.capture_stream_from(&opening).map_err(|_| ())
}

fn bosh_request_shape_error(request: &BoshRequest, stream_opened: bool) -> Option<&'static str> {
    if (request.to.is_some() || request.from.is_some()) && !request.restart {
        return Some("bad-request");
    }
    if request.pause.is_some()
        && (request.terminate || request.restart || !request.payloads.is_empty())
    {
        return Some("bad-request");
    }
    if request.restart && (request.terminate || stream_opened) {
        return Some("bad-request");
    }
    None
}

/// XEP-0206 restart requests are allowed to repeat the `to` attribute. Use
/// the configured canonical domain for the synthetic stream opening after
/// validating the supplied value, so a valid legacy restart cannot be
/// rejected merely because its XML spelling differs in case or IDNA form.
fn validated_bosh_restart_target(
    requested: Option<&str>,
    configured_domain: &str,
) -> Result<String, &'static str> {
    match requested {
        Some(value)
            if crate::jid::prepare_domainpart(value).ok().as_deref() == Some(configured_domain) =>
        {
            Ok(configured_domain.to_owned())
        }
        Some(_) => Err("improper-addressing"),
        None => Ok(configured_domain.to_owned()),
    }
}

fn terminal_response(condition: &str) -> BoshHttpResponse {
    terminal_response_with_content(condition, "text/xml; charset=utf-8")
}

fn terminal_response_with_content(condition: &str, content_type: &str) -> BoshHttpResponse {
    BoshHttpResponse {
        body: Bytes::from(bosh_body_element(Some(condition), true, None).finish()),
        content_type: content_type.to_owned(),
    }
}

#[cfg(test)]
mod tests;
