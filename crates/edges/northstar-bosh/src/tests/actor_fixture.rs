use super::actor_host::{TestHost, CONTENT_TYPE, DELIVERY_SESSION};
use crate::host::BoshHost;
use crate::*;
use northstar_delivery_core::bosh_ownership::Operation;
use northstar_stream::host::TransportHost;
use northstar_stream::outbound::{DurableDelivery, OutboundItem, OutboundSender};
use std::future::Future;
use std::net::Ipv4Addr;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll, Waker};
use uuid::Uuid;

pub(super) const SID: &str = "actor-fixture";

pub(super) fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut TaskContext::from_waker(Waker::noop()))
}

pub(super) fn request(rid: u64, attributes: &str, payload: &str) -> BoshRequest {
    parse_body(&format!(
        "<body xmlns='http://jabber.org/protocol/httpbind' rid='{rid}' sid='{SID}' {attributes}>{payload}</body>"
    ), 16).unwrap()
}

pub(super) fn durable(id: u128) -> OutboundItem {
    OutboundItem::durable(
        format!("<message xmlns='jabber:client' id='{id}'/>"),
        DurableDelivery {
            recipient_id: Uuid::from_u128(10001),
            message_id: Uuid::from_u128(id),
            claim_id: Some(Uuid::from_u128(id + 100)),
        },
    )
}

pub(super) fn submit(
    manager: &BoshManager,
    request: BoshRequest,
) -> Pin<Box<impl Future<Output = BoshHttpResponse> + '_>> {
    let mut future = Box::pin(tokio::task::unconstrained(manager.request(request)));
    assert!(poll_once(future.as_mut()).is_pending());
    future
}

// Retain the real actor for state/operation assertions, registering its real
// mailbox with the manager. Requests still cross the manager's permit and RID
// boundary; the HTTP test separately covers manager-owned actor creation.
pub(super) struct Harness {
    pub host: Arc<TestHost>,
    pub actor: BoshActor<TestHost>,
    pub outbound: mpsc::Sender<OutboundItem>,
}

impl Harness {
    pub(super) fn new(hold: u8) -> Self {
        let host = TestHost::new();
        let policy = host.bosh_policy();
        let manager = host.manager.clone();
        let session_key = manager.sid_key(SID);
        let slot = manager
            .inner
            .session_slots
            .clone()
            .try_acquire_owned()
            .unwrap();
        let peer = Ipv4Addr::LOCALHOST.into();
        let connection_guard = host.acquire_client_connection(peer).unwrap();
        let (outbound, outbound_rx) = mpsc::channel(policy.max_output_stanzas);
        let mut protocol = host.clone().open_session(
            OutboundSender::new(outbound.clone()),
            true,
            ClientTransport::Bosh,
            None,
            peer,
        );
        capture_bosh_stream(&mut protocol, Some("example.test"), None, None).unwrap();
        let (commands, receiver) = mpsc::channel(4);
        let overactivity = CancellationToken::new();
        manager.inner.sessions.insert(
            session_key,
            BoshHandle {
                commands,
                requests: Arc::new(Semaphore::new(usize::from(hold) + 1)),
                control_request: Arc::new(Semaphore::new(1)),
                overactivity: overactivity.clone(),
            },
        );
        let actor = BoshActor {
            manager,
            session_key,
            protocol,
            replay_service: host.replay_service().clone(),
            mix_service: host.mix_service().clone(),
            sm_memory_governor: host.sm_memory_governor().clone(),
            commands: receiver,
            outbound: outbound_rx,
            next_rid: 2,
            highest_received: 1,
            highest_responded: 1,
            buffered: BTreeMap::new(),
            held: None,
            replay: VecDeque::new(),
            output: VecDeque::new(),
            output_bytes: 0,
            wait: Duration::from_secs(60),
            hold,
            inactivity: Duration::from_secs(policy.inactivity_seconds),
            active_inactivity: Duration::from_secs(policy.inactivity_seconds),
            polling: Duration::from_secs(policy.polling_seconds),
            max_pause: policy.max_pause_seconds,
            max_response_bytes: policy.max_response_bytes,
            max_output_stanzas: policy.max_output_stanzas,
            max_output_bytes: policy.max_output_bytes,
            content_type: CONTENT_TYPE.to_owned(),
            last_response: Instant::now(),
            last_empty_poll: None,
            expected_key: None,
            client_acknowledgements: true,
            delivery_session_id: DELIVERY_SESSION,
            delivery_fence_ttl_seconds: 150,
            ownership_operation: None,
            actor_shutdown: host.actors.shutdown_token().child_token(),
            overactivity,
            _connection_guard: connection_guard,
            _session_slot: slot,
        };
        host.trace.clear();
        Self {
            host,
            actor,
            outbound,
        }
    }

    pub(super) fn pump(&mut self) -> bool {
        poll_once(Box::pin(tokio::task::unconstrained(self.actor.run_loop())).as_mut()).is_pending()
    }

    pub(super) fn respond(&mut self, request: BoshRequest) -> BoshHttpResponse {
        let manager = self.host.manager.clone();
        let mut response = submit(&manager, request);
        self.pump();
        let Poll::Ready(response) = poll_once(response.as_mut()) else {
            panic!("actor did not answer the selected request");
        };
        response
    }

    pub(super) fn queue(&mut self, item: OutboundItem) {
        self.outbound.try_send(item).unwrap();
        assert!(self.pump());
    }

    pub(super) fn operation(&self) -> Operation {
        self.actor.ownership_operation.as_ref().unwrap().clone()
    }

    pub(super) fn registered(&self) -> bool {
        self.host
            .manager
            .inner
            .sessions
            .contains_key(&self.actor.session_key)
    }

    pub(super) async fn finish(&mut self) {
        self.actor.finish().await;
        assert!(!self.registered());
    }
}

pub(super) async fn http(host: Arc<TestHost>, body: String) -> (StatusCode, String) {
    let request = axum::http::Request::builder()
        .header("x-forwarded-proto", "https")
        .body(Body::from(body))
        .unwrap();
    let response = http_bind(
        State(host),
        ConnectInfo(SocketAddr::from((Ipv4Addr::LOCALHOST, 5280))),
        request,
    )
    .await;
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .unwrap();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}
