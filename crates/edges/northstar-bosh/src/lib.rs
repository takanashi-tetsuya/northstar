//! Production-bounded XEP-0124 / XEP-0206 connection manager.
//!
//! Each BOSH session owns one actor and one protocol session. HTTP handlers
//! never lock or mutate protocol state directly: they submit bounded commands
//! and await a one-shot response. This preserves RID order even when two HTTP
//! requests arrive concurrently and prevents transport-specific protocol
//! behavior from drifting away from TCP/WebSocket behavior.
//!
//! The node is reached only through [`host::BoshHost`] and each session only through `northstar_stream`'s
//! `StreamSession` and [`RecordPort`]; the composition root implements both.

#![forbid(unsafe_code)]

mod action;
mod actor;
mod actor_output;
pub mod host;
mod http;
mod manager;
mod ownership;
mod protocol_session;
mod response_owner;
pub use ownership::RecordPort;
#[cfg(any(test, feature = "test-support"))]
pub mod stage4_support;

use self::host::BoshHost;
#[cfg(test)]
use http::cors_response;
pub use http::{http_bind, http_bind_options};
use http::{BoshResponseBody, BoshResponsePayload};

use anyhow::Context;
#[cfg(test)]
use axum::body::Body;
use axum::body::Bytes;
#[cfg(test)]
use axum::extract::{ConnectInfo, State};
#[cfg(test)]
use axum::http::StatusCode;
use axum::http::{header, HeaderMap, HeaderValue};
use dashmap::DashMap;
#[cfg(test)]
use futures::FutureExt;
use northstar_stream::resume::ResumeTransportParts;
#[cfg(test)]
use northstar_stream::transport::ClientTransport;
use northstar_stream::transport_parsing::parse_bosh_frame;
use northstar_xml_builder::XmlElement;
use roxmltree::Document;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, VecDeque};
use std::net::IpAddr;
#[cfg(test)]
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;
use tokio::sync::{mpsc, oneshot, OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;

mod request_policy;
mod response_output;

#[cfg(test)]
use self::request_policy::{
    advance_bosh_key_sequence, bosh_request_shape_error, capture_bosh_stream, classify_rid,
    highest_contiguous_buffered_rid, inactivity_deadline, negotiated_bosh_version, negotiated_hold,
    negotiated_wait, parse_body, replace_duplicate_responders, secure_proxy_request,
    supported_request_headers, take_expired_buffered, too_frequent_held_empty_request,
    valid_client_response_ack, validated_bosh_restart_target, within_polling_interval,
};
#[cfg(test)]
use self::response_output::terminal_response;
use self::response_output::{
    bosh_body_element, bosh_response_bytes, bosh_unacknowledged_limit_exceeded,
    queue_bosh_resume_payload, replay_response, restore_response_items,
    restore_response_items_observed, superseded_bosh_message_id, take_response_payload,
    terminal_response_with_content,
};

const HTTP_BIND_NS: &str = "http://jabber.org/protocol/httpbind";
const XBOSH_NS: &str = "urn:xmpp:xbosh";
const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";
const MAX_RID: u64 = 9_007_199_254_740_991;
const RESPONSE_CACHE_SIZE: usize = 2;
const MAX_UNACKNOWLEDGED_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAX_RESPONSE_ACK_AGE: Duration = Duration::from_secs(300);
const MAX_RESPONSE_REPLAYS: u8 = 2;
pub const BOSH_BACKEND_OPERATION_TIMEOUT: Duration = Duration::from_secs(5);

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
pub struct BoshRequest {
    pub rid: u64,
    pub sid: Option<String>,
    pub to: Option<String>,
    pub from: Option<String>,
    pub wait: Option<u64>,
    pub hold: Option<u8>,
    pub ver: Option<String>,
    pub content: Option<String>,
    pub ack: Option<u64>,
    pub key: Option<String>,
    pub newkey: Option<String>,
    pub pause: Option<u64>,
    pub terminate: bool,
    pub restart: bool,
    pub xmpp_version: Option<String>,
    pub language: Option<String>,
    pub payloads: Vec<String>,
    pub fingerprint: [u8; 32],
    /// Captured immediately after the bounded HTTP body is parsed. Keeping
    /// arrival time on the request prevents slow stanza/database processing
    /// from making an overactive client appear compliant with `polling`.
    pub received_at: Instant,
}

#[derive(Clone, Debug)]
pub struct BoshHttpResponse {
    // RID replay, duplicate HTTP waiters and Hyper share one ref-counted byte
    // allocation. Cloning a response must never allocate another multi-
    // megabyte SM replay buffer outside the governor.
    pub body: Bytes,
    pub content_type: String,
}

struct PendingRequest {
    request: BoshRequest,
    responders: Vec<oneshot::Sender<BoshHttpResponse>>,
}

#[derive(Clone)]
pub struct CachedResponse {
    pub rid: u64,
    pub fingerprint: [u8; 32],
    pub response: BoshHttpResponse,
    pub durable_ownership: Arc<northstar_stream::outbound::BoshResponseOwnership>,
    pub transport_receipts: Vec<mpsc::UnboundedSender<()>>,
    pub owned_at: Instant,
    pub response_bytes: usize,
    pub replays: u8,
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

struct BoshActor<H: BoshHost> {
    manager: BoshManager,
    session_key: [u8; 32],
    protocol: H::Session,
    replay_service: northstar_session_application::replay::ReplayService<H::ReplayStore>,
    mix_service: northstar_room_application::mix_service::MixService<H::MixStore>,
    sm_memory_governor: Arc<northstar_session_application::sm_capacity::SmMemoryGovernor>,
    commands: mpsc::Receiver<BoshCommand>,
    outbound: mpsc::Receiver<northstar_stream::outbound::OutboundItem>,
    next_rid: u64,
    highest_received: u64,
    highest_responded: u64,
    buffered: BTreeMap<u64, PendingRequest>,
    held: Option<HeldRequest>,
    replay: VecDeque<CachedResponse>,
    output: VecDeque<northstar_stream::outbound::OutboundItem>,
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
    _connection_guard: H::ConnectionGuard,
    _session_slot: OwnedSemaphorePermit,
}

#[cfg(test)]
mod sm_record_tests;
#[cfg(test)]
mod tests;
