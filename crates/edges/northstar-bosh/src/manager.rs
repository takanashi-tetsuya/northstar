//! Manage BOSH session admission and dispatch requests to session actors.

use crate::host::BoshHost;
use crate::request_policy::{
    capture_bosh_stream, negotiated_bosh_version, negotiated_hold, negotiated_wait,
};
use crate::response_output::terminal_response;
use crate::{
    BoshActor, BoshCommand, BoshHandle, BoshHttpResponse, BoshManager, BoshManagerInner,
    BoshRequest, HTTP_BIND_NS, XBOSH_NS,
};
use axum::body::Bytes;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use dashmap::{mapref::entry::Entry, DashMap};
use hmac::{Hmac, Mac};
use northstar_stream::session::StreamSession;
use northstar_stream::transport::ClientTransport;
use northstar_xml_builder::XmlElement;
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use std::collections::{BTreeMap, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot, OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;

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

    pub(super) fn sid_key(&self, sid: &str) -> [u8; 32] {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.inner.sid_mac_key)
            .expect("HMAC accepts a 32-byte key");
        mac.update(sid.as_bytes());
        mac.finalize().into_bytes().into()
    }

    pub(super) fn try_body_read(&self) -> Option<OwnedSemaphorePermit> {
        Arc::clone(&self.inner.body_read_slots)
            .try_acquire_owned()
            .ok()
    }

    pub(super) async fn create<H: BoshHost>(
        &self,
        host: Arc<H>,
        request: BoshRequest,
        peer_ip: IpAddr,
        connection_guard: H::ConnectionGuard,
    ) -> Result<BoshHttpResponse, &'static str> {
        let session_slot = Arc::clone(&self.inner.session_slots)
            .try_acquire_owned()
            .map_err(|_| "policy-violation")?;
        let to = request.to.as_deref().ok_or("improper-addressing")?;
        if northstar_xmpp_types::jid::prepare_domainpart(to)
            .ok()
            .as_deref()
            != Some(host.local_domain())
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

        let policy = host.bosh_policy();
        let wait_seconds = negotiated_wait(request.wait, policy.max_wait_seconds);
        let requested_hold = negotiated_hold(request.hold, wait_seconds);
        let requests = usize::from(requested_hold) + 1;
        let content_type = request
            .content
            .clone()
            .unwrap_or_else(|| "text/xml; charset=utf-8".to_owned());

        let (outbound_tx, outbound_rx) = mpsc::channel(policy.max_output_stanzas);
        let mut protocol = Arc::clone(&host).open_session(
            northstar_stream::outbound::OutboundSender::new(outbound_tx),
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

        let actors = host.connection_actors().clone();
        let actor_shutdown = actors.shutdown_token().child_token();
        let actor = BoshActor::<H> {
            manager: self.clone(),
            session_key,
            replay_service: host.replay_service().clone(),
            mix_service: host.mix_service().clone(),
            sm_memory_governor: Arc::clone(host.sm_memory_governor()),
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
            northstar_runtime::connection_actors::ConnectionActorKind::C2sBosh,
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
        host.record_bosh_session_opened();

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
            .attr("from", host.local_domain())
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

    pub(super) async fn request(&self, request: BoshRequest) -> BoshHttpResponse {
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

    pub(super) fn remove(&self, key: &[u8; 32]) {
        self.inner.sessions.remove(key);
    }
}
