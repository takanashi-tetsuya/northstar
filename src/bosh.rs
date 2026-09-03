//! Production-bounded XEP-0124 / XEP-0206 connection manager.
//!
//! Each BOSH session owns one actor and one `ProtocolSession`. HTTP handlers
//! never lock or mutate protocol state directly: they submit bounded commands
//! and await a one-shot response. This preserves RID order even when two HTTP
//! requests arrive concurrently and prevents transport-specific protocol
//! behavior from drifting away from TCP/WebSocket behavior.

use crate::state::{AppState, ClientConnectionGuard};
use crate::transport_parsing::parse_bosh_frame;
use crate::xmpp::protocol::{Action, ClientTransport, ProtocolSession, ResumeTransportParts};
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
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;
use tokio::sync::{mpsc, oneshot, OwnedSemaphorePermit, Semaphore};

const HTTP_BIND_NS: &str = "http://jabber.org/protocol/httpbind";
const XBOSH_NS: &str = "urn:xmpp:xbosh";
const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";
const MAX_RID: u64 = 9_007_199_254_740_991;
const RESPONSE_CACHE_SIZE: usize = 2;
const MAX_UNACKNOWLEDGED_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAX_RESPONSE_ACK_AGE: Duration = Duration::from_secs(300);
const MAX_RESPONSE_REPLAYS: u8 = 2;
const BOSH_BACKEND_OPERATION_TIMEOUT: Duration = Duration::from_secs(5);

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
}

enum BoshCommand {
    Request {
        request: Box<BoshRequest>,
        response: oneshot::Sender<BoshHttpResponse>,
    },
    Overactivity,
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
    durable_message_ids: Vec<uuid::Uuid>,
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
    /// Set when the next non-empty HTTP response contains the terminal
    /// authentication/resume control. Publication happens only after that
    /// response has been handed to the HTTP transport task.
    auth_publication_pending: bool,
    actor_shutdown: tokio_util::sync::CancellationToken,
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
        if crate::jid::prepare_domainpart(to).ok().as_deref() != Some(state.config.domain.as_str())
        {
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

        let wait_seconds = negotiated_wait(request.wait, state.config.bosh_max_wait_seconds);
        let requested_hold = negotiated_hold(request.hold, wait_seconds);
        let requests = usize::from(requested_hold) + 1;
        let content_type = request
            .content
            .clone()
            .unwrap_or_else(|| "text/xml; charset=utf-8".to_owned());

        let (outbound_tx, outbound_rx) = mpsc::channel(state.config.bosh_max_output_stanzas);
        let mut protocol = ProtocolSession::new(
            state.clone(),
            crate::outbound::OutboundSender::new(outbound_tx),
            true,
            ClientTransport::Bosh,
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
        let handle = BoshHandle {
            commands: command_tx,
            requests: Arc::new(Semaphore::new(requests)),
            // XEP-0124 section 12 permits one additional request above the
            // negotiated `requests` window when that request terminates or
            // pauses the session.
            control_request: Arc::new(Semaphore::new(1)),
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
            inactivity: Duration::from_secs(state.config.bosh_inactivity_seconds),
            active_inactivity: Duration::from_secs(state.config.bosh_inactivity_seconds),
            polling: Duration::from_secs(state.config.bosh_polling_seconds),
            max_pause: state.config.bosh_max_pause_seconds,
            max_response_bytes: state.config.bosh_max_response_bytes,
            max_output_stanzas: state.config.bosh_max_output_stanzas,
            max_output_bytes: state.config.bosh_max_output_bytes,
            content_type: content_type.clone(),
            last_response: Instant::now(),
            last_empty_poll: None,
            expected_key: request.newkey.clone(),
            client_acknowledgements: request.ack == Some(1),
            delivery_session_id: uuid::Uuid::new_v4(),
            delivery_fence_ttl_seconds: state
                .config
                .bosh_inactivity_seconds
                .max(state.config.bosh_max_pause_seconds)
                .max(wait_seconds)
                .saturating_add(30)
                .min(86_400),
            auth_publication_pending: false,
            actor_shutdown,
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
        state
            .metrics
            .bosh_sessions_total
            .fetch_add(1, Ordering::Relaxed);
        state
            .metrics
            .bosh_sessions_active
            .fetch_add(1, Ordering::Relaxed);

        let version = negotiated_bosh_version(request.ver.as_deref());
        let body = XmlElement::new("body")
            .attr("xmlns", HTTP_BIND_NS)
            .attr("xmlns:xmpp", XBOSH_NS)
            .attr("sid", sid)
            .attr("wait", wait_seconds)
            .attr("hold", requested_hold)
            .attr("requests", requests)
            .attr("inactivity", state.config.bosh_inactivity_seconds)
            .attr("polling", state.config.bosh_polling_seconds)
            .attr("maxpause", state.config.bosh_max_pause_seconds)
            .attr("ver", version)
            .attr("from", &state.config.domain)
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
        let is_extra_control = request.pause.is_some() || request.terminate;
        let permit = match Arc::clone(&handle.requests).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) if is_extra_control => {
                match Arc::clone(&handle.control_request).try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        let _ = handle.commands.send(BoshCommand::Overactivity).await;
                        return terminal_response("policy-violation");
                    }
                }
            }
            Err(_) => {
                // Do not use `try_send` here: losing the command while the
                // actor mailbox is full would return a terminal response but
                // leave the offending session alive.
                let _ = handle.commands.send(BoshCommand::Overactivity).await;
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

    async fn run_loop(&mut self) {
        let disconnect = self.protocol.disconnect.clone();
        let backpressure_disconnect = self.protocol.outbound.backpressure_disconnect();
        let state = Arc::clone(&self.protocol.state);
        let mut maintenance = tokio::time::interval(Duration::from_secs(1));
        maintenance.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut keep_running = true;
        while keep_running {
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
                _ = backpressure_disconnect.cancelled() => {
                    tracing::warn!(peer_ip = %self.protocol.peer_ip, "closed slow BOSH XMPP client after an ordered outbound delivery could not be queued; recoverable messages remain available for replay and committed state will resynchronize after reconnect");
                    self.terminate_waiters("policy-violation");
                    break;
                }
                _ = disconnect.cancelled() => {
                    self.protocol.sm_resume_allowed = false;
                    self.terminate_waiters("system-shutdown");
                    break;
                }
                command = self.commands.recv() => {
                    match command {
                        Some(BoshCommand::Request { request, response }) => {
                            keep_running = match tokio::time::timeout(
                                BOSH_BACKEND_OPERATION_TIMEOUT,
                                self.accept_request(*request, response),
                            )
                            .await
                            {
                                Ok(keep_running) => keep_running,
                                Err(_) => {
                                    tracing::warn!(session_id = %self.delivery_session_id, "BOSH backend request budget expired");
                                    false
                                }
                            };
                            if !keep_running {
                                self.protocol.sm_resume_allowed = false;
                            }
                        }
                        Some(BoshCommand::Overactivity) => {
                            self.protocol.sm_resume_allowed = false;
                            self.terminate_waiters("policy-violation");
                            keep_running = false;
                        }
                        None => break,
                    }
                }
                stanza = self.outbound.recv(), if self.has_output_capacity() => {
                    match stanza {
                        Some(stanza) => {
                            if !matches!(
                                tokio::time::timeout(
                                    BOSH_BACKEND_OPERATION_TIMEOUT,
                                    self.queue_outbound(stanza),
                                )
                                .await,
                                Ok(true)
                            ) {
                                self.protocol.sm_resume_allowed = false;
                                self.terminate_waiters("policy-violation");
                                keep_running = false;
                            } else if self.held.is_some()
                                && !matches!(
                                    tokio::time::timeout(
                                        BOSH_BACKEND_OPERATION_TIMEOUT,
                                        self.finish_held(None),
                                    )
                                    .await,
                                    Ok(true)
                                )
                            {
                                self.protocol.sm_resume_allowed = false;
                                self.terminate_waiters("internal-server-error");
                                keep_running = false;
                            }
                        }
                        None => {
                            self.protocol.sm_resume_allowed = false;
                            self.terminate_waiters("internal-server-error");
                            keep_running = false;
                        }
                    }
                }
                _ = tokio::time::sleep_until(hold_deadline.into()), if self.held.is_some() => {
                    if !matches!(
                        tokio::time::timeout(
                            BOSH_BACKEND_OPERATION_TIMEOUT,
                            self.finish_held(None),
                        )
                        .await,
                        Ok(true)
                    ) {
                        self.protocol.sm_resume_allowed = false;
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
                    self.protocol.sm_resume_allowed = false;
                    self.terminate_waiters("policy-violation");
                    keep_running = false;
                }
                _ = maintenance.tick() => {
                    if self.protocol.authenticated.is_none()
                        && self.protocol.connected_at.elapsed()
                            >= Duration::from_secs(state.config.unauthenticated_timeout_seconds)
                    {
                        self.terminate_waiters("policy-violation");
                        keep_running = false;
                    } else if self.protocol.sm_db_id.is_some()
                        && self.protocol.checkpoint_sm().await.is_err()
                    {
                        self.protocol.sm_resume_allowed = false;
                        self.terminate_waiters("internal-server-error");
                        keep_running = false;
                    }
                }
            }
        }
    }

    async fn finish(&mut self) {
        let state = Arc::clone(&self.protocol.state);
        if self
            .protocol
            .outbound
            .backpressure_disconnect()
            .is_cancelled()
        {
            state
                .metrics
                .c2s_backpressure_disconnects_total
                .fetch_add(1, Ordering::Relaxed);
        }
        // Stop admitting HTTP requests before durable/session finalization.
        // Every terminate, timeout, command-channel and backpressure exit
        // converges on this single exact-once actor epilogue.
        self.manager.remove(&self.session_key);
        match tokio::time::timeout(
            BOSH_BACKEND_OPERATION_TIMEOUT,
            state
                .replay_service()
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
        state
            .metrics
            .bosh_sessions_active
            .fetch_sub(1, Ordering::Relaxed);
    }

    async fn accept_request(
        &mut self,
        request: BoshRequest,
        response: oneshot::Sender<BoshHttpResponse>,
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
        if let Some((reply, terminate, durable_message_ids)) =
            replay_response(&mut self.replay, &request)
        {
            // An exact cached fingerprint proves this request already passed
            // the BOSH key/shape checks when it was first processed. It does
            // not carry a new acknowledgement, but it does keep the response
            // lease alive while replaying byte-identical cached bytes.
            if !terminate
                && self
                    .renew_delivery_fences(Some((request.rid, &durable_message_ids)))
                    .await
                    .is_err()
            {
                let _ = response.send(terminal_response("internal-server-error"));
                self.protocol.sm_resume_allowed = false;
                self.terminate_waiters("internal-server-error");
                return false;
            }
            let _ = response.send(reply);
            if terminate {
                self.terminate_waiters("other-request");
            } else {
                self.last_response = Instant::now();
            }
            return !terminate;
        }
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
                    self.protocol.sm_resume_allowed = false;
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
                let _ = self.process_pending(terminating).await;
                if !self.finish_pending(oldest, None, false).await {
                    self.protocol.sm_resume_allowed = false;
                }
                self.terminate_waiters("other-request");
                return false;
            }
            if self.held.is_some()
                && self.buffered.contains_key(&self.next_rid)
                && !self.finish_held(None).await
            {
                self.protocol.sm_resume_allowed = false;
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
                    .finish_pending(pending, Some("item-not-found"), false)
                    .await;
                self.terminate_waiters("other-request");
                return false;
            }
            if !final_rid {
                self.next_rid += 1;
            }
            if !self.process_pending(pending).await {
                self.terminate_waiters("other-request");
                return false;
            }
        }
        true
    }

    async fn process_pending(&mut self, pending: PendingRequest) -> bool {
        let request = &pending.request;
        self.active_inactivity = self.inactivity;
        if !advance_bosh_key_sequence(
            &mut self.expected_key,
            request.key.as_deref(),
            request.newkey.as_deref(),
        ) {
            let _ = self
                .finish_pending(pending, Some("item-not-found"), false)
                .await;
            return false;
        }
        if let Some(condition) =
            bosh_request_shape_error(request, self.protocol.negotiation.is_open())
        {
            let _ = self.finish_pending(pending, Some(condition), false).await;
            return false;
        }
        // A SID alone is insufficient when the negotiated SHA-1 key sequence
        // is active. Apply the client response acknowledgement only after the
        // request has passed both its key proof and structural checks.
        if let Err(error) = self.renew_and_apply_response_ack(request.ack).await {
            tracing::error!(?error, session_id = %self.delivery_session_id, ack = ?request.ack, "failed to commit authenticated BOSH response acknowledgement");
            let _ = self
                .finish_pending(pending, Some("internal-server-error"), false)
                .await;
            return false;
        }

        if let Some(pause) = request.pause {
            if pause > self.max_pause {
                let _ = self
                    .finish_pending(pending, Some("policy-violation"), false)
                    .await;
                return false;
            }
            self.last_empty_poll = None;
            self.active_inactivity = Duration::from_secs(pause);
            self.finish_pending_empty(pending);
            return true;
        }

        if request.restart {
            if !request.payloads.is_empty() {
                tracing::debug!(
                    payloads = request.payloads.len(),
                    "ignored payloads attached to a BOSH stream restart"
                );
            }
            let domain = self.protocol.state.config.domain.clone();
            let restart_to = match validated_bosh_restart_target(request.to.as_deref(), &domain) {
                Ok(target) => target,
                Err(condition) => {
                    let _ = self.finish_pending(pending, Some(condition), false).await;
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
                    .finish_pending(pending, Some("improper-addressing"), false)
                    .await;
                return false;
            }
            if !self.push_output(self.protocol.features()) {
                let _ = self
                    .finish_pending(pending, Some("policy-violation"), false)
                    .await;
                return false;
            }
        } else {
            let mut failure = None;
            for payload in &request.payloads {
                match tokio::time::timeout(
                    BOSH_BACKEND_OPERATION_TIMEOUT,
                    self.protocol.handle(payload),
                )
                .await
                {
                    Ok(Ok(action)) => {
                        if !self.apply_action(action).await {
                            failure = Some("remote-stream-error");
                            break;
                        }
                    }
                    Ok(Err(error)) => {
                        tracing::debug!(?error, "BOSH XMPP stanza processing failed");
                        failure = Some("internal-server-error");
                        break;
                    }
                    Err(_) => {
                        tracing::warn!(session_id = %self.delivery_session_id, "BOSH stanza backend budget expired");
                        failure = Some("internal-server-error");
                        break;
                    }
                }
            }
            if let Some(condition) = failure {
                let _ = self.finish_pending(pending, Some(condition), false).await;
                return false;
            }
        }
        while self.has_output_capacity() {
            let Ok(stanza) = self.outbound.try_recv() else {
                break;
            };
            if !self.queue_outbound(stanza).await {
                let _ = self
                    .finish_pending(pending, Some("policy-violation"), false)
                    .await;
                return false;
            }
        }

        if request.terminate {
            self.protocol.sm_resume_allowed = false;
            let _ = self.finish_pending(pending, Some("terminate"), false).await;
            self.terminate_waiters("other-request");
            return false;
        }
        if !self.output.is_empty() || request.restart {
            // A non-empty response breaks the consecutive-empty-poll pair
            // defined by XEP-0124 section 12.
            self.last_empty_poll = None;
            if !self.finish_pending(pending, None, true).await {
                return false;
            }
        } else if self.hold == 0 {
            if request.payloads.is_empty()
                && self.last_empty_poll.is_some_and(|previous| {
                    within_polling_interval(previous, request.received_at, self.polling)
                })
            {
                let _ = self
                    .finish_pending(pending, Some("policy-violation"), false)
                    .await;
                return false;
            }
            self.last_empty_poll = request.payloads.is_empty().then_some(request.received_at);
            if !self.finish_pending(pending, None, true).await {
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

    async fn apply_action(&mut self, action: Action) -> bool {
        match action {
            Action::Send(reply) => {
                let accepted = self.record_and_push(reply).await;
                if accepted {
                    self.protocol.start_post_action_tasks();
                }
                accepted
            }
            Action::SendMany(replies) => {
                for reply in replies {
                    if !self.record_and_push(reply).await {
                        return false;
                    }
                }
                self.protocol.start_post_action_tasks();
                true
            }
            Action::SendManyItems(items) => {
                for item in items {
                    if !self.record_and_push_item(item).await {
                        return false;
                    }
                }
                self.protocol.start_post_action_tasks();
                true
            }
            Action::SendManyThenActivate(replies) => {
                for (index, reply) in replies.into_iter().enumerate() {
                    if !self.record_and_push(reply).await {
                        return false;
                    }
                    if index == 0 {
                        self.auth_publication_pending = true;
                    }
                }
                self.protocol.start_post_action_tasks();
                true
            }
            Action::SendManyAndClose(replies) => {
                self.protocol.sm_resume_allowed = false;
                for reply in replies {
                    if !self.push_output(reply) {
                        return false;
                    }
                }
                false
            }
            Action::Resume(payload) => {
                let ResumeTransportParts {
                    control,
                    post_control,
                    replay,
                    activate_route,
                    transient_capacity,
                } = payload.into_transport_parts();
                if self.protocol.record_outbound(&control).await.is_err() {
                    return false;
                }
                if activate_route {
                    self.auth_publication_pending = true;
                }
                for nonza in &post_control {
                    if self.protocol.record_outbound(nonza).await.is_err() {
                        return false;
                    }
                }
                let replay_count = replay.len();
                if !queue_bosh_resume_payload(
                    &mut self.output,
                    &mut self.output_bytes,
                    self.max_output_stanzas,
                    self.max_output_bytes,
                    ResumeTransportParts {
                        control,
                        post_control,
                        replay,
                        activate_route,
                        transient_capacity,
                    },
                ) {
                    return false;
                }
                // Replay counters advance only after the whole ordered batch
                // has been admitted atomically to the bounded BOSH FIFO.
                for _ in 0..replay_count {
                    self.protocol.record_replayed();
                }
                self.protocol.start_post_action_tasks();
                true
            }
            Action::StartTls => self.push_output(
                "<failure xmlns='urn:ietf:params:xml:ns:xmpp-tls'><unexpected-request/></failure>"
                    .to_owned(),
            ),
            Action::CloseWith(reply) => {
                self.protocol.sm_resume_allowed = false;
                if !self.push_output(reply.clone()) {
                    // A stream error is the authoritative final payload. If
                    // ordinary queued stanzas consumed the bounded output
                    // budget, discard those stanzas rather than silently
                    // losing the error that explains why the stream closed.
                    self.output.clear();
                    self.output_bytes = 0;
                    let _ = self.push_output(reply);
                }
                false
            }
            Action::Close => {
                self.protocol.sm_resume_allowed = false;
                false
            }
            Action::None => {
                self.protocol.start_post_action_tasks();
                true
            }
        }
    }

    async fn record_and_push(&mut self, stanza: String) -> bool {
        self.protocol.record_outbound(&stanza).await.is_ok() && self.push_output(stanza)
    }

    async fn renew_delivery_fences(
        &self,
        expected_response: Option<(u64, &[uuid::Uuid])>,
    ) -> anyhow::Result<()> {
        self.protocol
            .state
            .replay_service()
            .renew_bosh_fences(
                self.delivery_session_id,
                expected_response,
                self.delivery_fence_ttl_seconds,
            )
            .await
    }

    async fn renew_and_apply_response_ack(&mut self, ack: Option<u64>) -> anyhow::Result<()> {
        // Renew before consuming `ack`: an expired lease must never be
        // resurrected after another transport became eligible to claim the
        // same offline row.
        self.renew_delivery_fences(None).await?;
        if let Some(ack) = ack {
            self.protocol
                .state
                .replay_service()
                .acknowledge_bosh_responses(self.delivery_session_id, ack)
                .await?;
            while self.replay.front().is_some_and(|cached| cached.rid <= ack) {
                if let Some(cached) = self.replay.pop_front() {
                    for receipt in cached.transport_receipts {
                        let _ = receipt.send(());
                    }
                }
            }
        }
        Ok(())
    }

    async fn record_and_push_item(&mut self, mut item: crate::outbound::OutboundItem) -> bool {
        let managed_by_sm = match self.protocol.record_outbound_item(&item).await {
            Ok(managed) => managed,
            Err(error) => {
                tracing::error!(?error, "failed to record BOSH outbound item");
                return false;
            }
        };
        if managed_by_sm {
            // The SM sequence entry now owns this fence. A later BOSH response
            // acknowledgement must not complete it before the XEP-0198 h.
            item.durable_delivery = None;
        }
        self.push_output_item(item)
    }

    async fn queue_outbound(&mut self, item: crate::outbound::OutboundItem) -> bool {
        // BOSH cannot prove an individual stanza reached the peer without
        // response/SM acknowledgement, so a durable row remains available for
        // safe replay even after the item leaves CSI's defer buffer.
        let Some(item) = self.protocol.csi_filter_outbound(item) else {
            return true;
        };
        self.record_and_push_item(item).await
    }

    fn push_output(&mut self, stanza: String) -> bool {
        self.push_output_item(crate::outbound::OutboundItem::plain(stanza))
    }

    fn push_output_item(&mut self, item: crate::outbound::OutboundItem) -> bool {
        let next_bytes = self.output_bytes.saturating_add(item.stanza.len());
        if self.output.len() >= self.max_output_stanzas || next_bytes > self.max_output_bytes {
            return false;
        }
        self.output_bytes = next_bytes;
        self.output.push_back(item);
        true
    }

    fn has_output_capacity(&self) -> bool {
        self.output.len() < self.max_output_stanzas && self.output_bytes < self.max_output_bytes
    }

    async fn finish_held(&mut self, condition: Option<&str>) -> bool {
        if let Some(held) = self.held.take() {
            return self.finish_pending(held.pending, condition, true).await;
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
    ) -> bool {
        let rid = pending.request.rid;
        let built = if condition == Some("remote-stream-error") {
            self.response_body(condition, true)
        } else if condition == Some("terminate") {
            Ok((
                BoshHttpResponse {
                    body: Bytes::from(bosh_body_element(None, true, None).finish()),
                    content_type: self.content_type.clone(),
                },
                Vec::new(),
                Vec::new(),
            ))
        } else if let Some(condition) = condition {
            // Binding errors and graceful termination never expose ordinary
            // queued XMPP payloads. This is especially important for an
            // invalid key: a party that knows only SID/RID must not receive
            // messages while being told that its key proof failed.
            Ok((
                terminal_response_with_content(condition, &self.content_type),
                Vec::new(),
                Vec::new(),
            ))
        } else {
            self.response_body(None, false)
        };
        let (response, deliveries, transport_receipts) = match built {
            Ok(built) => built,
            Err(error) => {
                tracing::error!(?error, rid, "failed to construct bounded BOSH response");
                let response =
                    terminal_response_with_content("internal-server-error", &self.content_type);
                for responder in pending.responders {
                    let _ = responder.send(response.clone());
                }
                return false;
            }
        };
        let response_bytes = response.body.len();
        if cache && condition.is_none() && pending.request.pause.is_none() {
            while self.replay.len() >= RESPONSE_CACHE_SIZE
                && self.replay.front().is_some_and(|cached| {
                    cached.durable_message_ids.is_empty() && cached.transport_receipts.is_empty()
                })
            {
                self.replay.pop_front();
            }
            let now = Instant::now();
            if bosh_unacknowledged_limit_exceeded(&self.replay, response_bytes, now) {
                let _ = self
                    .protocol
                    .state
                    .replay_service()
                    .release_bosh_fences(self.delivery_session_id)
                    .await;
                let terminal =
                    terminal_response_with_content("policy-violation", &self.content_type);
                for responder in pending.responders {
                    let _ = responder.send(terminal.clone());
                }
                return false;
            }
        }
        if !deliveries.is_empty() {
            if let Err(error) = self
                .protocol
                .state
                .replay_service()
                .bind_bosh_response(
                    self.delivery_session_id,
                    rid,
                    &deliveries,
                    self.delivery_fence_ttl_seconds,
                )
                .await
            {
                // The HTTP response has not been exposed yet. Fail closed and
                // leave every offline row recoverable instead of creating an
                // untracked transport-write window.
                tracing::error!(?error, session_id = %self.delivery_session_id, rid, "failed to bind durable deliveries to BOSH response");
                let response =
                    terminal_response_with_content("internal-server-error", &self.content_type);
                for responder in pending.responders {
                    let _ = responder.send(response.clone());
                }
                return false;
            }
        }
        let mut exposed_to_transport = false;
        for responder in pending.responders {
            exposed_to_transport |= responder.send(response.clone()).is_ok();
        }
        if self.auth_publication_pending {
            if !exposed_to_transport {
                return false;
            }
            self.auth_publication_pending = false;
            if !self
                .protocol
                .publish_committed_authentication_and_route()
                .await
            {
                return false;
            }
        }
        self.last_response = Instant::now();
        self.highest_responded = self.highest_responded.max(rid);
        if cache && condition.is_none() && pending.request.pause.is_none() {
            let durable_message_ids = deliveries
                .iter()
                .map(|delivery| delivery.message_id)
                .collect();
            self.replay.push_back(CachedResponse {
                rid: pending.request.rid,
                fingerprint: pending.request.fingerprint,
                response,
                durable_message_ids,
                transport_receipts,
                owned_at: Instant::now(),
                response_bytes,
                replays: 0,
            });
        }
        true
    }

    fn finish_pending_empty(&mut self, pending: PendingRequest) {
        let rid = pending.request.rid;
        let response = BoshHttpResponse {
            body: Bytes::from(bosh_body_element(None, false, None).finish()),
            content_type: self.content_type.clone(),
        };
        for responder in pending.responders {
            let _ = responder.send(response.clone());
        }
        self.last_response = Instant::now();
        self.highest_responded = self.highest_responded.max(rid);
    }

    fn response_body(
        &mut self,
        condition: Option<&str>,
        terminate: bool,
    ) -> anyhow::Result<(
        BoshHttpResponse,
        Vec<crate::outbound::DurableDelivery>,
        Vec<mpsc::UnboundedSender<()>>,
    )> {
        let (payload, deliveries, transport_receipts, transient_sm_capacity) =
            take_response_payload(
                &mut self.output,
                &mut self.output_bytes,
                self.max_response_bytes,
                self.protocol.state.sm_memory_governor(),
            )?;
        let body = bosh_body_element(
            condition,
            terminate,
            highest_contiguous_buffered_rid(self.next_rid, self.highest_received, &self.buffered),
        );
        let body = body
            .validated_fragment(&payload)
            .map_err(|error| {
                anyhow::anyhow!("malformed protocol output at BOSH boundary: {error}")
            })?
            .finish();
        Ok((
            BoshHttpResponse {
                body: bosh_response_bytes(body, transient_sm_capacity),
                content_type: self.content_type.clone(),
            },
            deliveries,
            transport_receipts,
        ))
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
        activate_route: _,
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
    output.push_back(crate::outbound::OutboundItem::resume_fragment(
        control,
        Arc::clone(&hold),
    ));
    for stanza in post_control.into_iter().chain(replay) {
        output.push_back(crate::outbound::OutboundItem::resume_fragment(
            stanza,
            Arc::clone(&hold),
        ));
    }
    *output_bytes += batch_bytes;
    true
}

type BoshResponsePayload = (
    String,
    Vec<crate::outbound::DurableDelivery>,
    Vec<mpsc::UnboundedSender<()>>,
    Vec<Arc<Vec<crate::services::sm_capacity::SmCapacityLease>>>,
);

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
    let mut deliveries = Vec::new();
    let mut transport_receipts = Vec::new();
    for _ in 0..selected {
        let stanza = output.pop_front().expect("front was present");
        *output_bytes = output_bytes
            .checked_sub(stanza.stanza.len())
            .context("BOSH output byte accounting underflow")?;
        payload.push_str(&stanza.stanza);
        if let Some(receipt) = stanza.transport_receipt {
            transport_receipts.push(receipt);
        }
        if let Some(delivery) = stanza.durable_delivery {
            deliveries.push(delivery);
        }
    }
    Ok((
        payload,
        deliveries,
        transport_receipts,
        transient_sm_capacity,
    ))
}

pub async fn http_bind(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: axum::extract::Request,
) -> Response {
    let headers = request.headers().clone();
    if !secure_proxy_request(peer.ip(), &headers, &state.config.trusted_proxy_ips) {
        return cors_response(StatusCode::OK, terminal_response("policy-violation"));
    }
    if !supported_request_headers(&headers) {
        return cors_response(StatusCode::OK, terminal_response("bad-request"));
    }
    let Some(body_read_slot) = state.bosh_manager().try_body_read() else {
        return cors_response(StatusCode::OK, terminal_response("policy-violation"));
    };
    let body = match tokio::time::timeout(
        Duration::from_secs(state.config.bosh_body_read_timeout_seconds),
        axum::body::to_bytes(request.into_body(), state.config.bosh_max_request_bytes),
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
        .and_then(|raw| parse_body(raw, state.config.bosh_max_stanzas_per_request));
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
) -> Option<(BoshHttpResponse, bool, Vec<uuid::Uuid>)> {
    let cached = replay.iter_mut().find(|cached| cached.rid == request.rid)?;
    if cached.fingerprint != request.fingerprint {
        return Some((terminal_response("bad-request"), true, Vec::new()));
    }
    if cached.replays >= MAX_RESPONSE_REPLAYS {
        return Some((terminal_response("policy-violation"), true, Vec::new()));
    }
    cached.replays += 1;
    Some((
        cached.response.clone(),
        false,
        cached.durable_message_ids.clone(),
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
mod tests {
    use super::*;

    fn response_body_text(response: &BoshHttpResponse) -> &str {
        std::str::from_utf8(response.body.as_ref())
            .expect("BOSH responses are built from server-owned UTF-8 XML")
    }

    fn response_test_governor() -> Arc<crate::services::sm_capacity::SmMemoryGovernor> {
        crate::services::sm_capacity::SmMemoryGovernor::new(
            1024 * 1024,
            256 * 1024,
            16,
            256 * 1024,
            Arc::new(crate::services::sm_capacity::SmCapacityMetrics::default()),
        )
        .unwrap()
    }

    #[test]
    fn creation_and_auth_flow_shapes_are_strict() {
        let creation = parse_body(
            "<body xmlns='http://jabber.org/protocol/httpbind' rid='1573741820' to='example.test' wait='60' hold='1' ver='1.11' xml:lang='ja' xmpp:version='1.0' xmlns:xmpp='urn:xmpp:xbosh'/>",
            64,
        )
        .unwrap();
        assert_eq!(creation.rid, 1_573_741_820);
        assert!(creation.sid.is_none());
        assert_eq!(creation.xmpp_version.as_deref(), Some("1.0"));
        assert_eq!(creation.language.as_deref(), Some("ja"));

        let auth = parse_body(
            "<body xmlns='http://jabber.org/protocol/httpbind' rid='1573741821' sid='secret'><auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>AA==</auth></body>",
            64,
        )
        .unwrap();
        assert_eq!(auth.payloads.len(), 1);
        assert!(auth.payloads[0].contains("urn:ietf:params:xml:ns:xmpp-sasl"));
    }

    #[test]
    fn restart_terminate_and_pause_shapes_are_unambiguous() {
        let restart = parse_body(
            "<body xmlns='http://jabber.org/protocol/httpbind' xmlns:xmpp='urn:xmpp:xbosh' rid='12' sid='s' to='example.test' xmpp:restart='true'/>",
            64,
        )
        .unwrap();
        assert!(restart.restart);
        assert!(!restart.terminate);
        assert_eq!(bosh_request_shape_error(&restart, false), None);
        assert_eq!(
            validated_bosh_restart_target(restart.to.as_deref(), "example.test"),
            Ok("example.test".to_owned())
        );
        assert_eq!(
            validated_bosh_restart_target(Some("LOCALHOST"), "localhost"),
            Ok("localhost".to_owned())
        );
        assert_eq!(
            validated_bosh_restart_target(Some("elsewhere.test"), "example.test"),
            Err("improper-addressing")
        );

        let terminate = parse_body(
            "<body xmlns='http://jabber.org/protocol/httpbind' rid='13' sid='s' type='terminate'><presence xmlns='jabber:client' type='unavailable'/></body>",
            64,
        )
        .unwrap();
        assert!(terminate.terminate);
        assert_eq!(terminate.payloads.len(), 1);

        assert!(parse_body(
            "<body xmlns='http://jabber.org/protocol/httpbind' rid='14' sid='s' pause='60'><presence/></body>",
            64,
        )
        .is_ok());
    }

    #[test]
    fn rejects_restricted_xml_unknown_attributes_and_body_text() {
        for body in [
            "<body xmlns='http://jabber.org/protocol/httpbind' rid='1' evil='x'/>",
            "<body xmlns='http://jabber.org/protocol/httpbind' rid='1'>text</body>",
            "<body xmlns='http://jabber.org/protocol/httpbind' rid='1'><!--x--></body>",
            "<body xmlns='http://jabber.org/protocol/httpbind' rid='1'>&xxe;</body>",
            "<evil xmlns='http://jabber.org/protocol/httpbind' rid='1'/>",
            "<body xmlns='http://jabber.org/protocol/httpbind' rid='1' secure='true'/>",
            "<body xmlns='http://jabber.org/protocol/httpbind' rid='1' content='text/html'/>",
            "<body xmlns='http://jabber.org/protocol/httpbind' rid='1' content='text/xml; charset=utf-7'/>",
        ] {
            assert!(parse_body(body, 64).is_err(), "accepted {body}");
        }
        assert!(parse_body(
            "<?xml version='1.0' encoding='UTF-8'?><body xmlns='http://jabber.org/protocol/httpbind' rid='1'/>",
            64,
        )
        .is_ok());
    }

    #[test]
    fn request_and_stanza_limits_are_enforced() {
        let body =
            "<body xmlns='http://jabber.org/protocol/httpbind' rid='1' sid='s'><iq/><iq/></body>";
        assert_eq!(parse_body(body, 1).unwrap_err(), "policy-violation");
        let oversized_stanza = format!(
            "<body xmlns='http://jabber.org/protocol/httpbind' rid='2' sid='s'><message><body>{}</body></message></body>",
            "x".repeat(crate::xmpp::MAX_XMPP_FRAME_BYTES)
        );
        assert_eq!(
            parse_body(&oversized_stanza, 64).unwrap_err(),
            "policy-violation"
        );
        assert!(parse_body(&"x".repeat(4 * 1024 * 1024 + 1), 64).is_err());
        assert!(parse_body(
            "<body xmlns='http://jabber.org/protocol/httpbind' rid='9007199254740991'/>",
            64
        )
        .is_err());
        assert!(parse_body(
            "<body xmlns='http://jabber.org/protocol/httpbind' rid='9007199254740991' sid='s' type='terminate'/>",
            64
        )
        .is_ok());
    }

    #[test]
    fn structural_complexity_is_rejected_before_bosh_dom_processing() {
        // `parse_body` deliberately routes the complete HTTP body through the
        // same XmlEntityFramer used by TCP, WebSocket, S2S and components
        // before calling roxmltree::Document::parse. These inputs are small in
        // bytes but otherwise create disproportionate DOM/attribute state.
        let element_flood = format!(
            "<body xmlns='http://jabber.org/protocol/httpbind' rid='2' sid='s'><message>{}</message></body>",
            "<x/>".repeat(20_000)
        );
        assert!(element_flood.len() < 4 * 1024 * 1024);
        assert!(parse_body(&element_flood, 64).is_err());

        let attributes = (0..=128)
            .map(|index| format!(" a{index}='x'"))
            .collect::<String>();
        let attribute_flood = format!(
            "<body xmlns='http://jabber.org/protocol/httpbind' rid='3' sid='s'><message{attributes}/></body>"
        );
        assert!(parse_body(&attribute_flood, 64).is_err());
    }

    #[test]
    fn sid_keys_are_secret_and_session_fixation_resistant() {
        let manager = BoshManager::new(4, 2);
        let first = manager.sid_key("attacker-selected");
        let second = manager.sid_key("attacker-selected-2");
        assert_ne!(first, second);
        assert_ne!(
            first.as_slice(),
            Sha256::digest(b"attacker-selected").as_slice()
        );
    }

    #[tokio::test]
    async fn request_cap_is_exactly_two() {
        let handle = BoshHandle {
            commands: mpsc::channel(1).0,
            requests: Arc::new(Semaphore::new(2)),
            control_request: Arc::new(Semaphore::new(1)),
        };
        let first = Arc::clone(&handle.requests).try_acquire_owned().unwrap();
        let second = Arc::clone(&handle.requests).try_acquire_owned().unwrap();
        assert!(Arc::clone(&handle.requests).try_acquire_owned().is_err());
        assert!(Arc::clone(&handle.control_request)
            .try_acquire_owned()
            .is_ok());
        drop(first);
        assert!(Arc::clone(&handle.requests).try_acquire_owned().is_ok());
        drop(second);
    }

    #[test]
    fn request_body_reads_are_globally_load_shed() {
        let manager = BoshManager::new(4, 1);
        let permit = manager.try_body_read().unwrap();
        assert!(manager.try_body_read().is_none());
        drop(permit);
        assert!(manager.try_body_read().is_some());
    }

    #[test]
    fn rid_window_buffers_only_one_out_of_order_request() {
        assert_eq!(classify_rid(101, 101), RidDisposition::Expected);
        assert_eq!(classify_rid(101, 102), RidDisposition::BufferedOneAhead);
        assert_eq!(classify_rid(101, 100), RidDisposition::Old);
        assert_eq!(classify_rid(101, 103), RidDisposition::OutsideWindow);
    }

    #[test]
    fn client_response_ack_cannot_discard_an_unsent_response() {
        assert!(valid_client_response_ack(true, 12, 14, Some(12)));
        assert!(!valid_client_response_ack(true, 12, 14, Some(13)));
        assert!(!valid_client_response_ack(true, 14, 14, Some(14)));
        assert!(!valid_client_response_ack(false, 12, 14, Some(12)));
        assert!(valid_client_response_ack(false, 12, 14, None));
    }

    #[test]
    fn parses_and_normalizes_bosh_sha1_keys() {
        let creation = parse_body(
            "<body xmlns='http://jabber.org/protocol/httpbind' rid='1' to='example.test' newkey='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'/>",
            64,
        )
        .unwrap();
        assert_eq!(
            creation.newkey.as_deref(),
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
        assert!(creation.key.is_none());
        assert!(parse_body(
            "<body xmlns='http://jabber.org/protocol/httpbind' rid='1' to='example.test' key='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'/>",
            64,
        )
        .is_err());
        assert!(parse_body(
            "<body xmlns='http://jabber.org/protocol/httpbind' rid='2' sid='s' key='short'/>",
            64,
        )
        .is_err());
    }

    #[test]
    fn verifies_and_rotates_the_bosh_key_sequence() {
        fn digest_hex(value: &str) -> String {
            Sha1::digest(value.as_bytes())
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect()
        }

        let k0 = "0123456789abcdef0123456789abcdef01234567";
        let k1 = digest_hex(k0);
        let k2 = digest_hex(&k1);
        let mut expected = Some(k2);
        assert!(advance_bosh_key_sequence(&mut expected, Some(&k1), None));
        assert_eq!(expected.as_deref(), Some(k1.as_str()));

        let replacement = "abcdef0123456789abcdef0123456789abcdef01";
        assert!(advance_bosh_key_sequence(
            &mut expected,
            Some(k0),
            Some(replacement),
        ));
        assert_eq!(expected.as_deref(), Some(replacement));
        assert!(!advance_bosh_key_sequence(&mut expected, None, None));
        assert!(!advance_bosh_key_sequence(
            &mut expected,
            Some("ffffffffffffffffffffffffffffffffffffffff"),
            None,
        ));

        let mut unprotected = None;
        assert!(advance_bosh_key_sequence(&mut unprotected, None, None));
        assert!(!advance_bosh_key_sequence(
            &mut unprotected,
            None,
            Some(replacement),
        ));
    }

    #[test]
    fn duplicate_rid_replays_only_an_identical_request() {
        let request = parse_body(
            "<body xmlns='http://jabber.org/protocol/httpbind' rid='12' sid='s'/>",
            64,
        )
        .unwrap();
        let response = BoshHttpResponse {
            body: Bytes::from(
                "<body xmlns='http://jabber.org/protocol/httpbind'><iq/></body>".to_owned(),
            ),
            content_type: "text/xml; charset=utf-8".to_owned(),
        };
        let mut replay = VecDeque::from([CachedResponse {
            rid: request.rid,
            fingerprint: request.fingerprint,
            response: response.clone(),
            durable_message_ids: vec![uuid::Uuid::from_u128(7)],
            transport_receipts: Vec::new(),
            owned_at: Instant::now(),
            response_bytes: response.body.len(),
            replays: 0,
        }]);
        let (replayed, terminate, durable_message_ids) =
            replay_response(&mut replay, &request).unwrap();
        assert!(!terminate);
        assert_eq!(replayed.body, response.body);
        assert_eq!(durable_message_ids, vec![uuid::Uuid::from_u128(7)]);

        let changed = parse_body(
            "<body xmlns='http://jabber.org/protocol/httpbind' rid='12' sid='s'><presence/></body>",
            64,
        )
        .unwrap();
        let (rejected, terminate, durable_message_ids) =
            replay_response(&mut replay, &changed).unwrap();
        assert!(terminate);
        assert!(durable_message_ids.is_empty());
        assert!(response_body_text(&rejected).contains("condition='bad-request'"));

        let mut bounded = VecDeque::from([CachedResponse {
            rid: request.rid,
            fingerprint: request.fingerprint,
            response,
            durable_message_ids: Vec::new(),
            transport_receipts: Vec::new(),
            owned_at: Instant::now(),
            response_bytes: 64,
            replays: MAX_RESPONSE_REPLAYS,
        }]);
        let now = Instant::now();
        assert!(!bosh_unacknowledged_limit_exceeded(&bounded, 1, now));
        assert!(bosh_unacknowledged_limit_exceeded(
            &bounded,
            MAX_UNACKNOWLEDGED_RESPONSE_BYTES,
            now
        ));
        let mut count_limited = bounded.clone();
        count_limited.push_back(bounded.front().unwrap().clone());
        assert!(bosh_unacknowledged_limit_exceeded(&count_limited, 1, now));
        count_limited.pop_back();
        count_limited.front_mut().unwrap().owned_at = now - MAX_RESPONSE_ACK_AGE;
        assert!(bosh_unacknowledged_limit_exceeded(&count_limited, 1, now));
        let (rejected, terminate, durable_message_ids) =
            replay_response(&mut bounded, &request).unwrap();
        assert!(terminate);
        assert!(durable_message_ids.is_empty());
        assert!(response_body_text(&rejected).contains("condition='policy-violation'"));
    }

    #[test]
    fn response_payload_preserves_durable_fences_until_rid_binding() {
        let delivery = crate::outbound::DurableDelivery {
            recipient_id: uuid::Uuid::from_u128(1),
            message_id: uuid::Uuid::from_u128(2),
            claim_id: Some(uuid::Uuid::from_u128(3)),
        };
        let first =
            crate::outbound::OutboundItem::durable("<message id='durable'/>".to_owned(), delivery);
        let second = crate::outbound::OutboundItem::plain("<presence/>".to_owned());
        let mut bytes = first.stanza.len() + second.stanza.len();
        let mut output = VecDeque::from([first.clone(), second.clone()]);
        let governor = response_test_governor();
        let (payload, fences, receipts, holds) =
            take_response_payload(&mut output, &mut bytes, 4_096, &governor).unwrap();
        assert_eq!(payload, format!("{}{}", first.stanza, second.stanza));
        assert_eq!(fences, vec![delivery]);
        assert!(receipts.is_empty());
        assert!(holds.is_empty());
        assert_eq!(bytes, 0);
        assert!(output.is_empty());

        let oversized = crate::outbound::OutboundItem::durable("<message/>".repeat(32), delivery);
        let mut bytes = oversized.stanza.len();
        let mut output = VecDeque::from([oversized.clone()]);
        assert!(take_response_payload(&mut output, &mut bytes, 256, &governor).is_err());
        assert_eq!(
            output.front().map(|item| &item.stanza),
            Some(&oversized.stanza)
        );
        assert_eq!(bytes, output.front().unwrap().stanza.len());
    }

    #[test]
    fn response_payload_keeps_resume_control_and_replay_before_late_suffix() {
        // Resume processing pushes these entries before it starts the
        // post-transport route-publication task. A stanza accepted by that
        // task is therefore necessarily appended behind the complete replay,
        // even if the task runs before this HTTP response is assembled.
        let control = crate::outbound::OutboundItem::plain(
            "<resumed xmlns='urn:xmpp:sm:3' h='0' previd='session'/>".to_owned(),
        );
        let replay = crate::outbound::OutboundItem::plain(
            "<message id='durable-replay'><body>old</body></message>".to_owned(),
        );
        let suffix = crate::outbound::OutboundItem::plain(
            "<message id='volatile-suffix'><body>new</body></message>".to_owned(),
        );
        let mut output = VecDeque::from([control.clone(), replay.clone(), suffix.clone()]);
        let mut bytes = output.iter().map(|item| item.stanza.len()).sum();
        let (payload, _, _, _) =
            take_response_payload(&mut output, &mut bytes, 4_096, &response_test_governor())
                .unwrap();
        assert_eq!(
            payload,
            format!("{}{}{}", control.stanza, replay.stanza, suffix.stanza)
        );
    }

    #[test]
    fn bosh_response_and_transport_drop_retain_then_release_resume_capacity() {
        let metrics = Arc::new(crate::services::sm_capacity::SmCapacityMetrics::default());
        let governor = crate::services::sm_capacity::SmMemoryGovernor::new(
            1024 * 1024,
            256 * 1024,
            16,
            256 * 1024,
            Arc::clone(&metrics),
        )
        .unwrap();
        let source = VecDeque::from([crate::outbound::SmUnackedStanza::plain(
            "<message id='resume'><body>".to_owned() + &"x".repeat(4_096) + "</body></message>",
        )]);
        let action = crate::xmpp::protocol::ResumePayload::from_sm_unacked(
            &governor,
            "<resumed xmlns='urn:xmpp:sm:3' h='0' previd='session'/>".to_owned(),
            Vec::new(),
            &source,
            false,
        )
        .unwrap();
        let mut output = VecDeque::new();
        let mut bytes = 0;
        assert!(queue_bosh_resume_payload(
            &mut output,
            &mut bytes,
            16,
            64 * 1024,
            action.into_transport_parts(),
        ));
        let (body, _, _, holds) =
            take_response_payload(&mut output, &mut bytes, 64 * 1024, &governor).unwrap();
        assert!(output.is_empty());
        assert!(!holds.is_empty());
        let cached = BoshHttpResponse {
            body: bosh_response_bytes(body, holds),
            content_type: "text/xml; charset=utf-8".to_owned(),
        };
        let transport = cors_response(StatusCode::OK, cached.clone());
        drop(cached);
        assert!(
            metrics
                .reserved_bytes
                .load(std::sync::atomic::Ordering::Relaxed)
                > 0
        );
        // Dropping the HTTP response models both a completed body and a
        // failed/cancelled Hyper transport; the ref-counted Bytes owner keeps
        // the RAII holds alive through either path.
        drop(transport);
        assert_eq!(
            metrics
                .reserved_bytes
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    #[tokio::test]
    async fn duplicate_pending_rid_releases_old_http_request_and_keeps_newest() {
        let request = parse_body(
            "<body xmlns='http://jabber.org/protocol/httpbind' rid='2' sid='s'/>",
            64,
        )
        .unwrap();
        let (old_tx, old_rx) = oneshot::channel();
        let mut pending = PendingRequest {
            request: request.clone(),
            responders: vec![old_tx],
        };
        let (new_tx, mut new_rx) = oneshot::channel();
        assert!(replace_duplicate_responders(
            &mut pending,
            &request,
            new_tx,
            "text/xml"
        ));
        assert!(response_body_text(&old_rx.await.unwrap()).contains("type='error'"));
        assert!(matches!(
            new_rx.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ));
        pending
            .responders
            .pop()
            .unwrap()
            .send(BoshHttpResponse {
                body: Bytes::from("latest"),
                content_type: "text/xml".to_owned(),
            })
            .unwrap();
        assert_eq!(new_rx.await.unwrap().body.as_ref(), b"latest");
    }

    #[test]
    fn inactivity_runs_only_without_a_held_request() {
        let now = Instant::now();
        let limit = Duration::from_secs(30);
        assert_eq!(inactivity_deadline(now, limit, false), Some(now + limit));
        assert_eq!(inactivity_deadline(now, limit, true), None);
    }

    #[test]
    fn out_of_order_request_is_released_at_the_negotiated_wait_deadline() {
        let now = Instant::now();
        let mut request = parse_body(
            "<body xmlns='http://jabber.org/protocol/httpbind' rid='102' sid='s'/>",
            64,
        )
        .unwrap();
        request.received_at = now - Duration::from_secs(6);
        let mut buffered = BTreeMap::from([(
            102,
            PendingRequest {
                request,
                responders: Vec::new(),
            },
        )]);
        assert_eq!(
            take_expired_buffered(&mut buffered, Duration::from_secs(5), now).len(),
            1
        );
        assert!(buffered.is_empty());
    }

    #[test]
    fn remote_stream_errors_and_maximum_rid_acknowledgements_are_well_formed() {
        // XEP-0124 section 13 specifies an empty type='terminate' body.
        // `newkey` is client-to-connection-manager key-sequence state and is
        // never reflected in the termination acknowledgement.
        let graceful = bosh_body_element(None, true, None).finish();
        assert!(graceful.contains("type='terminate'"));
        assert!(!graceful.contains("newkey="));

        let remote = bosh_body_element(Some("remote-stream-error"), true, None).finish();
        assert!(remote.contains("type='terminate'"));
        assert!(remote.contains("condition='remote-stream-error'"));
        assert!(remote.contains("xmlns:stream='http://etherx.jabber.org/streams'"));

        let ack = bosh_body_element(None, false, Some(MAX_RID)).finish();
        assert!(ack.contains(&format!("ack='{MAX_RID}'")));
    }

    #[test]
    fn response_ack_never_claims_an_out_of_order_rid_across_a_gap() {
        fn pending(request: BoshRequest) -> PendingRequest {
            PendingRequest {
                request,
                responders: Vec::new(),
            }
        }

        let ahead = parse_body(
            "<body xmlns='http://jabber.org/protocol/httpbind' rid='102' sid='s'/>",
            64,
        )
        .unwrap();
        let mut buffered = BTreeMap::from([(102, pending(ahead))]);
        assert_eq!(highest_contiguous_buffered_rid(101, 102, &buffered), None);

        let expected = parse_body(
            "<body xmlns='http://jabber.org/protocol/httpbind' rid='101' sid='s'/>",
            64,
        )
        .unwrap();
        buffered.insert(101, pending(expected));
        assert_eq!(
            highest_contiguous_buffered_rid(101, 102, &buffered),
            Some(102)
        );
    }

    #[test]
    fn secure_transport_requires_a_trusted_https_proxy() {
        let peer: IpAddr = "127.0.0.1".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
        assert!(secure_proxy_request(peer, &headers, &[peer]));
        assert!(!secure_proxy_request(peer, &headers, &[]));
        headers.insert("x-forwarded-proto", HeaderValue::from_static("https, http"));
        assert!(!secure_proxy_request(peer, &headers, &[peer]));
        headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
        headers.append("x-forwarded-proto", HeaderValue::from_static("https"));
        assert!(!secure_proxy_request(peer, &headers, &[peer]));
        headers.insert("x-forwarded-proto", HeaderValue::from_static("http"));
        assert!(!secure_proxy_request(peer, &headers, &[peer]));
    }

    #[test]
    fn request_headers_ignore_media_type_but_reject_compression_and_ambiguity() {
        let mut headers = HeaderMap::new();
        assert!(supported_request_headers(&headers));
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/xml; charset=utf-8"),
        );
        assert!(supported_request_headers(&headers));
        headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        assert!(!supported_request_headers(&headers));
        headers.remove(header::CONTENT_ENCODING);
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html"));
        assert!(supported_request_headers(&headers));
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/xml"));
        headers.append(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/xml"),
        );
        assert!(!supported_request_headers(&headers));
    }

    #[tokio::test]
    async fn cors_is_scoped_and_cache_safe() {
        let response = http_bind_options().await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(response.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN], "*");
        assert_eq!(
            response.headers()[header::ACCESS_CONTROL_ALLOW_METHODS],
            "POST, OPTIONS"
        );
    }

    #[test]
    fn terminal_xml_escapes_untrusted_conditions() {
        let response = terminal_response("bad' condition");
        assert!(response_body_text(&response).contains("bad&apos; condition"));
        assert!(!response_body_text(&response).contains("condition='bad' condition'"));
    }

    #[test]
    fn bosh_version_negotiation_is_bounded() {
        assert_eq!(negotiated_bosh_version(Some("1.6")), "1.6");
        assert_eq!(negotiated_bosh_version(Some("1.99")), "1.11");
        assert_eq!(negotiated_bosh_version(Some("garbage")), "1.11");
        assert!(parse_body(
            "<body xmlns='http://jabber.org/protocol/httpbind' rid='1' ver='garbage'/>",
            64
        )
        .is_err());
    }

    #[test]
    fn wait_negotiation_respects_the_client_and_server_caps() {
        assert_eq!(negotiated_wait(None, 60), 60);
        assert_eq!(negotiated_wait(Some(0), 60), 0);
        assert_eq!(negotiated_wait(Some(120), 60), 60);
        assert_eq!(negotiated_hold(Some(1), 0), 0);
        assert_eq!(negotiated_hold(Some(2), 60), 1);
    }

    #[test]
    fn polling_interval_uses_http_arrival_time_and_exact_boundary() {
        let now = Instant::now();
        assert!(within_polling_interval(
            now,
            now + Duration::from_secs(4),
            Duration::from_secs(5)
        ));
        assert!(!within_polling_interval(
            now,
            now + Duration::from_secs(5),
            Duration::from_secs(5)
        ));
        assert!(!within_polling_interval(
            now + Duration::from_secs(1),
            now,
            Duration::from_secs(5)
        ));
    }

    #[test]
    fn held_empty_overactivity_exempts_pause_terminate_and_payload_requests() {
        let now = Instant::now();
        let mut previous = parse_body(
            "<body xmlns='http://jabber.org/protocol/httpbind' rid='10' sid='s'/>",
            64,
        )
        .unwrap();
        let mut current = parse_body(
            "<body xmlns='http://jabber.org/protocol/httpbind' rid='11' sid='s'/>",
            64,
        )
        .unwrap();
        previous.received_at = now;
        current.received_at = now + Duration::from_secs(1);
        assert!(too_frequent_held_empty_request(
            &previous,
            &current,
            Duration::from_secs(5)
        ));

        current.pause = Some(30);
        assert!(!too_frequent_held_empty_request(
            &previous,
            &current,
            Duration::from_secs(5)
        ));
        current.pause = None;
        current.terminate = true;
        assert!(!too_frequent_held_empty_request(
            &previous,
            &current,
            Duration::from_secs(5)
        ));
        current.terminate = false;
        current.payloads.push("<presence/>".to_owned());
        assert!(!too_frequent_held_empty_request(
            &previous,
            &current,
            Duration::from_secs(5)
        ));
    }
}
