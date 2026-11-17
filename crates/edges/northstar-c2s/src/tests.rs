use super::*;
use crate::auth_publication_write_tests::MemoryWrite;
use crate::direct_delivery::DirectWritePort;
use northstar_auth_application::authentication::publication as auth_facts;
use northstar_delivery_core::native_write::{self, AckRequest};
use northstar_stream::auth_publication::fixture::{
    fixture_bound_control, Cut as PublicationCut, FakePort as PublicationPort,
};
use northstar_stream::auth_publication::{AuthReplies, OwnedPublication};
use northstar_stream::host::TransportHost;
use northstar_stream::outbound::{
    DurableDelivery, MixDelivery, OutboundItem, OutboundSender, TransportOwnershipSource,
};
use northstar_stream::transport::Action;
use std::{
    pin::Pin,
    sync::Mutex,
    task::{Context as TaskContext, Poll},
};
use tokio::sync::{oneshot, Notify};
use tokio_rustls::rustls;
use tokio_util::sync::CancellationToken;
use tracing::instrument::WithSubscriber;
use uuid::Uuid;

#[test]
fn sm_lease_polling_keeps_the_existing_floor_and_ratio() {
    assert_eq!(sm_lease_poll_interval(1), Duration::from_secs(1));
    assert_eq!(sm_lease_poll_interval(2), Duration::from_secs(1));
    assert_eq!(sm_lease_poll_interval(3), Duration::from_secs(1));
    assert_eq!(sm_lease_poll_interval(8), Duration::from_secs(2));
    assert_eq!(sm_lease_poll_interval(9), Duration::from_secs(3));
}

#[tokio::test]
async fn websocket_terminal_write_runs_after_session_disconnect_is_latched() {
    let disconnect = tokio_util::sync::CancellationToken::new();
    disconnect.cancel();
    let mut write_polled = false;

    assert!(
        bounded_websocket_terminal_write(async {
            assert!(disconnect.is_cancelled());
            write_polled = true;
            Ok::<(), ()>(())
        })
        .await
    );
    assert!(write_polled);
}

#[test]
fn websocket_shutdown_finishes_exactly_one_terminal_sequence() {
    let mut terminal = WebSocketTerminalSequence::default();
    assert!(needs_shutdown_terminal_sequence(false, true, &terminal));
    assert!(terminal.begin());
    assert!(!needs_shutdown_terminal_sequence(true, true, &terminal));
    assert!(!terminal.begin());
}

#[test]
fn websocket_terminal_action_orders_replies_before_both_close_frames() {
    let messages = websocket_terminal_messages(
        vec!["<iq id='account-remove' type='result'/>".to_owned()],
        true,
    );
    assert_eq!(messages.len(), 3);
    assert!(matches!(
        &messages[0],
        Message::Text(reply) if reply.contains("account-remove")
    ));
    assert!(matches!(
        &messages[1],
        Message::Text(close) if close.as_str() == websocket_close()
    ));
    assert!(matches!(&messages[2], Message::Close(None)));
}

#[test]
fn peer_idle_deadline_changes_only_for_peer_traffic_or_authentication() {
    let started = tokio::time::Instant::now();
    let limits = native_stream_limits();
    let mut tracker = PeerIdleTracker::new(limits, false, started);
    assert_eq!(tracker.deadline, started + C2S_NEGOTIATION_IDLE_TIMEOUT);

    // Local queue/timer selection does not call either mutating method.
    // Merely re-entering the loop with the same auth state must preserve
    // the original absolute deadline.
    let local_event = started + Duration::from_secs(5);
    tracker.synchronize_authentication(false, local_event);
    assert_eq!(tracker.deadline, started + C2S_NEGOTIATION_IDLE_TIMEOUT);

    tracker.note_peer_traffic(false, local_event);
    assert_eq!(tracker.deadline, local_event + C2S_NEGOTIATION_IDLE_TIMEOUT);

    let authenticated_at = started + Duration::from_secs(7);
    tracker.synchronize_authentication(true, authenticated_at);
    assert_eq!(
        tracker.deadline,
        authenticated_at + C2S_AUTHENTICATED_IDLE_TIMEOUT
    );
}

#[test]
fn peer_idle_deadline_uses_transport_supplied_limits() {
    let limits = northstar_stream::transport::StreamLimits {
        max_bytes: 128,
        negotiation_idle: Duration::from_secs(2),
        authenticated_idle: Duration::from_secs(7),
    };
    let started = tokio::time::Instant::now();
    let mut tracker = PeerIdleTracker::new(limits, false, started);
    assert_eq!(tracker.deadline, started + Duration::from_secs(2));
    tracker.synchronize_authentication(true, started + Duration::from_secs(1));
    assert_eq!(tracker.deadline, started + Duration::from_secs(8));
    tracker.note_peer_traffic(true, started + Duration::from_secs(3));
    assert_eq!(tracker.deadline, started + Duration::from_secs(10));
}

#[test]
fn accepts_utf8_split_between_network_reads() {
    let encoded = "消息".as_bytes();
    let mut pending = encoded[..2].to_vec();
    let mut output = String::new();
    append_utf8(&mut pending, &mut output).unwrap();
    assert!(output.is_empty());
    pending.extend_from_slice(&encoded[2..]);
    append_utf8(&mut pending, &mut output).unwrap();
    assert_eq!(output, "消息");
}

#[test]
fn websocket_frames_must_start_with_markup() {
    assert!(northstar_stream::transport_parsing::websocket_frame_starts_with_markup("<response/>"));
    assert!(
        northstar_stream::transport_parsing::websocket_frame_starts_with_markup(
            "<?xml version='1.0'?><response/>"
        )
    );
    for invalid in ["", " <response/>", "\n<response/>", "x<response/>"] {
        assert!(
            !northstar_stream::transport_parsing::websocket_frame_starts_with_markup(invalid),
            "{invalid:?}"
        );
    }
}

#[test]
fn websocket_accepts_a_strict_utf8_xml_declaration() {
    let mut framer = XmlEntityFramer::default();
    assert_eq!(
        take_websocket_frame("<?xml version='1.0' encoding='UTF-8'?><open xmlns='urn:ietf:params:xml:ns:xmpp-framing'/>", &mut framer, MAX_XMPP_FRAME_BYTES).unwrap(),
        "<open xmlns='urn:ietf:params:xml:ns:xmpp-framing'/>"
    );
    assert!(take_websocket_frame(
        "<?xml version='1.0'?><message xmlns='jabber:client'/>",
        &mut framer,
        MAX_XMPP_FRAME_BYTES,
    )
    .is_err());
}

#[test]
fn websocket_message_contains_exactly_one_frame_and_no_stream_whitespace() {
    let mut framer = XmlEntityFramer::default();
    assert_eq!(
        take_websocket_frame(
            "<message xmlns='jabber:client'/>",
            &mut framer,
            MAX_XMPP_FRAME_BYTES
        )
        .unwrap(),
        "<message xmlns='jabber:client'/>"
    );
    for invalid in [
        "",
        " <message xmlns='jabber:client'/>",
        "<message xmlns='jabber:client'/> ",
        "<message xmlns='jabber:client'/><presence xmlns='jabber:client'/>",
        "<message xmlns='jabber:client'>",
    ] {
        assert!(
            take_websocket_frame(
                invalid,
                &mut XmlEntityFramer::default(),
                MAX_XMPP_FRAME_BYTES
            )
            .is_err(),
            "{invalid:?}"
        );
    }
}

#[test]
fn websocket_frame_honors_the_advertised_one_mib_octet_limit() {
    let oversized = format!(
        "<message xmlns='jabber:client'><body>{}</body></message>",
        "x".repeat(MAX_XMPP_FRAME_BYTES)
    );
    assert!(take_websocket_frame(
        &oversized,
        &mut XmlEntityFramer::default(),
        MAX_XMPP_FRAME_BYTES
    )
    .is_err());
}

#[test]
fn websocket_stream_headers_require_the_framing_namespace() {
    let server_open = websocket_server_open("example.test");
    let document = roxmltree::Document::parse(&server_open).unwrap();
    let root = document.root_element();
    assert_eq!(root.tag_name().namespace(), Some(WEBSOCKET_FRAMING_NS));
    assert_eq!(root.attribute("from"), Some("example.test"));
    assert_eq!(root.attribute("version"), Some("1.0"));
    assert_eq!(
        root.attribute(("http://www.w3.org/XML/1998/namespace", "lang")),
        Some("en")
    );
    assert!(!websocket_has_invalid_stream_header_namespace(
        "<open xmlns='urn:ietf:params:xml:ns:xmpp-framing'/>"
    ));
    assert!(!websocket_has_invalid_stream_header_namespace(
        "<message xmlns='jabber:client'/>"
    ));
    assert!(websocket_has_invalid_stream_header_namespace(
        "<open xmlns='jabber:client'/>"
    ));
    assert!(websocket_has_invalid_stream_header_namespace("<close/>"));
    assert!(!websocket_close_has_content(
        "<close xmlns='urn:ietf:params:xml:ns:xmpp-framing'/>"
    ));
    assert!(websocket_close_has_content(
        "<close xmlns='urn:ietf:params:xml:ns:xmpp-framing'> </close>"
    ));
    assert!(websocket_close_has_content(
        "<close xmlns='urn:ietf:params:xml:ns:xmpp-framing'><x/></close>"
    ));
}

#[tokio::test]
async fn tcp_initial_header_failure_opens_errors_and_closes_the_stream() {
    let (mut client, mut server) = tokio::io::duplex(4096);
    tcp_fatal_error(
        &mut server,
        "example.test",
        true,
        &northstar_xml_builder::stream::stream_error("invalid-namespace"),
    )
    .await
    .unwrap();
    drop(server);
    let mut received = String::new();
    client.read_to_string(&mut received).await.unwrap();
    assert!(received.starts_with("<stream:stream from='example.test'"));
    assert!(received.contains("<invalid-namespace"));
    assert!(received.ends_with("</stream:stream>"));
}

#[tokio::test]
async fn tcp_backend_failure_is_a_terminal_internal_server_error_on_wire() {
    let (mut client, mut server) = tokio::io::duplex(4096);
    tcp_fatal_error(
        &mut server,
        "example.test",
        false,
        &northstar_xml_builder::stream::stream_error("internal-server-error"),
    )
    .await
    .unwrap();
    drop(server);
    let mut received = String::new();
    client.read_to_string(&mut received).await.unwrap();
    assert!(received.contains("<internal-server-error"));
    assert!(received.ends_with("</stream:stream>"));
}

#[tokio::test]
async fn tcp_terminal_write_failure_returns_instead_of_hanging() {
    let (client, mut server) = tokio::io::duplex(1);
    drop(client);
    let result = tokio::time::timeout(
        Duration::from_millis(250),
        tcp_fatal_error(
            &mut server,
            "example.test",
            false,
            &northstar_xml_builder::stream::stream_error("internal-server-error"),
        ),
    )
    .await;
    assert!(result.is_ok(), "terminal write exceeded the test bound");
    assert!(result.unwrap().is_err());
}

const CONNECTION: Uuid = Uuid::from_u128(0x567);
const CONTROL: &str = "<success/>";
const SUFFIX: &str = "<features/>";

#[derive(Clone, Debug, Eq, PartialEq)]
enum NativeEvent {
    Open(Uuid, ClientTransport, bool),
    Tls(Uuid, u64),
    Frame(Uuid, String),
    Record(String),
    RecordDropped,
    Fence(TransportOwnershipSource),
    Ack(TransportOwnershipSource),
    WriteReceipt,
    OwnershipReceipt,
    Bytes(Vec<u8>),
    Flushed,
    Publish(Uuid),
    Published(bool),
    Replayed,
    PostAction,
    ForbidResume,
    Finalize(Uuid),
    Finalized(Uuid),
    SessionDropped(Uuid),
}

#[derive(Default)]
struct NativeTrace {
    events: Mutex<Vec<NativeEvent>>,
    summaries: Mutex<Vec<String>>,
    changed: Notify,
}

impl NativeTrace {
    fn push(&self, event: NativeEvent) {
        self.events.lock().unwrap().push(event);
        self.changed.notify_one();
    }

    fn events(&self) -> Vec<NativeEvent> {
        self.events.lock().unwrap().clone()
    }

    async fn wait_for(&self, event: NativeEvent) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let changed = self.changed.notified();
                if self.events().contains(&event) {
                    break;
                }
                changed.await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("missing {event:?}: {:?}", self.events()));
    }

    fn summary_contains(&self, expected: &str, label: &str) {
        let summaries = self.summaries.lock().unwrap();
        assert_eq!(summaries.len(), 1, "{label}: {summaries:?}");
        assert!(summaries[0].contains(expected), "{label}: {summaries:?}");
    }
}

// Observe the production retirement event, including cancellation while record is
// still borrowed. A lease-only reconstruction would never emit this event.
#[derive(Clone)]
struct NativeSubscriber(Arc<NativeTrace>);

impl tracing::Subscriber for NativeSubscriber {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        metadata.target() == "northstar_server::xmpp::native_write"
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        struct SummaryVisitor<'a>(&'a NativeTrace);
        impl tracing::field::Visit for SummaryVisitor<'_> {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "summary" {
                    self.0.summaries.lock().unwrap().push(format!("{value:?}"));
                }
            }
        }
        event.record(&mut SummaryVisitor(&self.0));
    }
}

struct RecordDrop(Arc<NativeTrace>);

impl Drop for RecordDrop {
    fn drop(&mut self) {
        assert!(self.0.summaries.lock().unwrap().is_empty());
        self.0.push(NativeEvent::RecordDropped);
    }
}

struct ReceiptProbe {
    write: Mutex<mpsc::UnboundedReceiver<()>>,
    ownership: Mutex<mpsc::UnboundedReceiver<()>>,
}

impl ReceiptProbe {
    fn attach(item: &mut OutboundItem) -> Arc<Self> {
        let (write, write_rx) = mpsc::unbounded_channel();
        let (ownership, ownership_rx) = mpsc::unbounded_channel();
        item.transport_write_receipt = Some(write);
        item.transport_receipt = Some(ownership);
        Arc::new(Self {
            write: Mutex::new(write_rx),
            ownership: Mutex::new(ownership_rx),
        })
    }

    fn assert_empty(&self, label: &str) {
        assert!(self.write.lock().unwrap().try_recv().is_err(), "{label}");
        assert!(
            self.ownership.lock().unwrap().try_recv().is_err(),
            "{label}"
        );
    }

    fn receive_once(&self, trace: &NativeTrace) {
        assert_eq!(self.write.lock().unwrap().try_recv(), Ok(()));
        trace.push(NativeEvent::WriteReceipt);
        assert_eq!(self.ownership.lock().unwrap().try_recv(), Ok(()));
        trace.push(NativeEvent::OwnershipReceipt);
        self.assert_empty("receipts must each be sent once");
    }
}

#[derive(Clone, Copy)]
enum NativeAck {
    Success,
    NoMatch,
    Error,
    Pending,
}

struct RecordingSession {
    trace: Arc<NativeTrace>,
    signals: SessionTerminationSignals,
    pending_record: bool,
    receipts: Option<Arc<ReceiptProbe>>,
    expected_source: Option<TransportOwnershipSource>,
    ack: NativeAck,
    publication_cut: PublicationCut,
    finalize_release: CancellationToken,
    panic_finalize: bool,
    _outbound: Option<OutboundSender>,
}

impl RecordingSession {
    fn new(trace: Arc<NativeTrace>) -> Self {
        let finalize_release = CancellationToken::new();
        finalize_release.cancel();
        Self {
            trace,
            signals: SessionTerminationSignals::new(
                CancellationToken::new(),
                CancellationToken::new(),
            ),
            pending_record: false,
            receipts: None,
            expected_source: None,
            ack: NativeAck::Success,
            publication_cut: PublicationCut::Success,
            finalize_release,
            panic_finalize: false,
            _outbound: None,
        }
    }

    async fn acknowledge(&self, request: &AckRequest) -> Result<bool> {
        assert_eq!(Some(request.source()), self.expected_source);
        request
            .validate_source(self.expected_source.unwrap())
            .unwrap();
        self.receipts.as_ref().unwrap().receive_once(&self.trace);
        self.trace.push(NativeEvent::Ack(request.source()));
        match self.ack {
            NativeAck::Pending => std::future::pending::<()>().await,
            NativeAck::Error => anyhow::bail!("recorded ACK failure"),
            NativeAck::Success | NativeAck::NoMatch => {}
        }
        let matched = !matches!(self.ack, NativeAck::NoMatch);
        native_write::commit_observed(
            async { Ok::<(), std::io::Error>(()) },
            request,
            if matched {
                native_write::AckDisposition::Deleted
            } else {
                native_write::AckDisposition::NoMatchingMix
            },
        )
        .await?;
        Ok(matched)
    }
}

impl DirectWritePort for RecordingSession {
    async fn record(&mut self, item: &OutboundItem) -> Result<bool> {
        self.trace.push(NativeEvent::Record(item.stanza.clone()));
        if self.pending_record {
            let _drop = RecordDrop(self.trace.clone());
            std::future::pending::<()>().await;
        }
        Ok(false)
    }
    async fn fence_c2s(&self, delivery: DurableDelivery) -> Result<DurableDelivery> {
        self.trace
            .push(NativeEvent::Fence(TransportOwnershipSource::C2s(delivery)));
        Ok(DurableDelivery {
            claim_id: Some(Uuid::from_u128(12)),
            ..delivery
        })
    }
    async fn fence_mix(&self, delivery: MixDelivery) -> Result<MixDelivery> {
        self.trace
            .push(NativeEvent::Fence(TransportOwnershipSource::Mix(delivery)));
        Ok(MixDelivery {
            lease_token: Uuid::from_u128(13),
            ..delivery
        })
    }
    async fn acknowledge_c2s(&self, request: &AckRequest) -> Result<()> {
        assert!(matches!(request.source(), TransportOwnershipSource::C2s(_)));
        self.acknowledge(request).await.map(|_| ())
    }
    async fn acknowledge_mix(&self, request: &AckRequest) -> Result<bool> {
        assert!(matches!(request.source(), TransportOwnershipSource::Mix(_)));
        self.acknowledge(request).await
    }
    fn connection_id(&self) -> Uuid {
        CONNECTION
    }
}

impl StreamSession for RecordingSession {
    fn connection_id(&self) -> Uuid {
        CONNECTION
    }
    fn peer_ip(&self) -> std::net::IpAddr {
        std::net::Ipv4Addr::LOCALHOST.into()
    }
    fn local_domain(&self) -> &str {
        "example.test"
    }
    fn is_stream_open(&self) -> bool {
        true
    }
    fn is_authenticated(&self) -> bool {
        false
    }
    fn sasl2_in_progress(&self) -> bool {
        false
    }
    fn unauthenticated_timed_out(&self, _: std::time::Instant) -> bool {
        false
    }
    fn resource_bind_deadline(&self) -> Option<std::time::Instant> {
        None
    }
    fn termination_signals(&self) -> SessionTerminationSignals {
        self.signals.clone()
    }
    fn features(&self) -> String {
        SUFFIX.to_owned()
    }
    fn capture_stream_from(&mut self, _: &str) -> Result<(), &'static str> {
        Ok(())
    }
    fn activate_tls(&mut self, evidence: TlsSessionEvidence) {
        assert!(evidence.channel_bindings.is_some());
        self.trace
            .push(NativeEvent::Tls(CONNECTION, evidence.generation));
    }
    async fn process_frame(&mut self, frame: &str) -> Result<Action, FrameFailure> {
        self.trace
            .push(NativeEvent::Frame(CONNECTION, frame.to_owned()));
        match frame {
            "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>" => Ok(Action::StartTls),
            "<panic/>" => panic!("recorded transport panic"),
            "<backend/>" => Err(FrameFailure::Backend(anyhow::anyhow!(
                "recorded backend failure"
            ))),
            "<timeout/>" => Err(FrameFailure::TimedOut),
            "<exit/>" => Ok(Action::Close),
            _ => Ok(Action::None),
        }
    }
    async fn publish_committed_authentication_and_route(
        &mut self,
        owner: OwnedPublication,
    ) -> bool {
        assert_eq!(owner.connection(), CONNECTION);
        assert_eq!(
            owner.observation().snapshot().transport,
            auth_facts::Transport::Written,
        );
        self.trace.push(NativeEvent::Publish(owner.connection()));
        let mut port = PublicationPort::new(CONNECTION, self.publication_cut);
        let result = owner.publish(&mut port).await.transport_succeeded();
        assert_eq!(port.events.first(), Some(&"service"));
        self.trace.push(NativeEvent::Published(result));
        result
    }
    fn start_post_action_tasks(&mut self) {
        self.trace.push(NativeEvent::PostAction);
    }
    fn csi_filter_outbound(&mut self, item: OutboundItem) -> Option<OutboundItem> {
        Some(item)
    }
    async fn record_outbound(&mut self, stanza: &str) -> Result<()> {
        self.trace.push(NativeEvent::Record(stanza.to_owned()));
        Ok(())
    }
    fn record_replayed(&self) {
        self.trace.push(NativeEvent::Replayed);
    }
    fn record_bosh_session_closed(&self) {
        panic!("native transport called BOSH metric");
    }
    fn record_backpressure_disconnect(&self) {}
    fn forbid_sm_resume(&mut self) {
        self.trace.push(NativeEvent::ForbidResume);
    }
    fn has_sm_session(&self) -> bool {
        false
    }
    async fn checkpoint_sm(&mut self) -> Result<()> {
        panic!("no SM session was installed");
    }
    async fn finalize(&mut self) {
        self.trace.push(NativeEvent::Finalize(CONNECTION));
        self.finalize_release.cancelled().await;
        assert!(!self.panic_finalize, "recorded finalizer panic");
        self.trace.push(NativeEvent::Finalized(CONNECTION));
    }
}

impl Drop for RecordingSession {
    fn drop(&mut self) {
        self.trace.push(NativeEvent::SessionDropped(CONNECTION));
    }
}

struct ObservedMemoryWrite {
    inner: MemoryWrite,
    trace: Arc<NativeTrace>,
}

impl AsyncWrite for ObservedMemoryWrite {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, bytes);
        if let Poll::Ready(Ok(count)) = &result {
            self.trace
                .push(NativeEvent::Bytes(bytes[..*count].to_vec()));
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        let result = Pin::new(&mut self.inner).poll_flush(cx);
        if matches!(result, Poll::Ready(Ok(()))) {
            self.trace.push(NativeEvent::Flushed);
        }
        result
    }
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn durable_item(mix: bool) -> (OutboundItem, TransportOwnershipSource) {
    if mix {
        let source = MixDelivery {
            delivery_id: Uuid::from_u128(3),
            lease_token: Uuid::from_u128(4),
        };
        let (item, _) = OutboundItem::durable_mix("<message id='mix'/>".to_owned(), source);
        (
            item,
            TransportOwnershipSource::Mix(MixDelivery {
                lease_token: Uuid::from_u128(13),
                ..source
            }),
        )
    } else {
        let source = DurableDelivery {
            recipient_id: Uuid::from_u128(1),
            message_id: Uuid::from_u128(2),
            claim_id: Some(Uuid::from_u128(2)),
        };
        (
            OutboundItem::durable("<message id='c2s'/>".to_owned(), source),
            TransportOwnershipSource::C2s(DurableDelivery {
                claim_id: Some(Uuid::from_u128(12)),
                ..source
            }),
        )
    }
}

// Use an ordinary HTTP upgrade to obtain axum's private WebSocket type. The
// listener task is joined before returning; only the two connected endpoints remain.
async fn websocket_pair() -> (WebSocket, TcpStream) {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let (socket_tx, socket_rx) = oneshot::channel();
    let socket_tx = Arc::new(Mutex::new(Some(socket_tx)));
    let app = axum::Router::new().route(
        "/",
        axum::routing::get(move |upgrade: axum::extract::ws::WebSocketUpgrade| {
            let socket_tx = socket_tx.clone();
            async move {
                upgrade.on_upgrade(move |socket| async move {
                    let _ = socket_tx.lock().unwrap().take().unwrap().send(socket);
                })
            }
        }),
    );
    let shutdown = CancellationToken::new();
    let stopped = shutdown.clone();
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(stopped.cancelled_owned())
            .await
            .unwrap();
    });
    let mut client = TcpStream::connect(address).await.unwrap();
    client.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n").await.unwrap();
    let mut headers = Vec::new();
    while !headers.ends_with(b"\r\n\r\n") {
        headers.push(client.read_u8().await.unwrap());
        assert!(headers.len() < 4096);
    }
    assert!(headers.starts_with(b"HTTP/1.1 101"));
    let socket = socket_rx.await.unwrap();
    shutdown.cancel();
    server.await.unwrap();
    (socket, client)
}

async fn websocket_text(client: &mut TcpStream, text: &str) {
    assert!(text.len() < 126);
    let mut frame = vec![0x81, 0x80 | text.len() as u8, 0, 0, 0, 0];
    frame.extend_from_slice(text.as_bytes());
    client.write_all(&frame).await.unwrap();
}

async fn read_websocket_text(client: &mut TcpStream) -> String {
    assert_eq!(client.read_u8().await.unwrap(), 0x81);
    let length = client.read_u8().await.unwrap();
    assert!(length < 126);
    let mut bytes = vec![0; usize::from(length)];
    client.read_exact(&mut bytes).await.unwrap();
    String::from_utf8(bytes).unwrap()
}

fn authentication_action(
    resume: bool,
    activation: bool,
    holder_present: bool,
) -> (Action, auth_facts::Observation) {
    let (holder, observation) = fixture_bound_control(CONTROL, CONNECTION, false);
    if resume {
        use northstar_session_application::sm_capacity::{SmCapacityMetrics, SmMemoryGovernor};
        let governor = SmMemoryGovernor::new(
            65_536,
            32_768,
            4,
            32_768,
            Arc::new(SmCapacityMetrics::default()),
        )
        .unwrap();
        let mut payload = northstar_stream::resume::ResumePayload::from_sm_unacked(
            &governor,
            CONTROL.to_owned(),
            vec![SUFFIX.to_owned()],
            &Default::default(),
            activation,
        )
        .unwrap();
        payload.auth_publication = holder_present.then_some(holder);
        (Action::Resume(payload), observation)
    } else {
        assert!(activation && holder_present);
        (
            Action::SendManyThenActivate(AuthReplies {
                replies: vec![CONTROL.to_owned(), SUFFIX.to_owned()],
                holder,
            }),
            observation,
        )
    }
}

fn poll_native<F: Future>(trace: &Arc<NativeTrace>, future: Pin<&mut F>) -> Poll<F::Output> {
    tracing::subscriber::with_default(NativeSubscriber(trace.clone()), || {
        future.poll(&mut TaskContext::from_waker(futures::task::noop_waker_ref()))
    })
}

fn cancel_record<F: Future>(trace: &Arc<NativeTrace>, future: F, label: &str) {
    let mut future = Box::pin(future);
    assert!(poll_native(trace, future.as_mut()).is_pending(), "{label}");
    assert!(trace.summaries.lock().unwrap().is_empty(), "{label}");
    tracing::subscriber::with_default(NativeSubscriber(trace.clone()), || drop(future));
    assert!(
        trace.events().contains(&NativeEvent::RecordDropped),
        "{label}"
    );
    trace.summary_contains("preparation: Recording", label);
    trace.summary_contains("terminal: Some(Cancelled)", label);
}

async fn within<F: Future>(label: &str, future: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(5), future)
        .await
        .unwrap_or_else(|_| panic!("{label} exceeded its bound"))
}

fn publication_count(trace: &NativeTrace) -> usize {
    trace
        .events()
        .iter()
        .filter(|event| matches!(event, NativeEvent::Publish(_)))
        .count()
}

fn assert_tcp_publication_order(trace: &NativeTrace, suffix_written: bool, label: &str) {
    let events = trace.events();
    let publish = events
        .iter()
        .position(|event| *event == NativeEvent::Publish(CONNECTION))
        .unwrap();
    let first_bytes: Vec<u8> = events[..publish]
        .iter()
        .flat_map(|event| match event {
            NativeEvent::Bytes(bytes) => bytes.clone(),
            _ => vec![],
        })
        .collect();
    assert_eq!(first_bytes, CONTROL.as_bytes(), "{label}");
    assert_eq!(events[publish - 1], NativeEvent::Flushed, "{label}");
    assert_eq!(
        events[0],
        NativeEvent::Record(CONTROL.to_owned()),
        "{label}"
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| **event == NativeEvent::Record(CONTROL.to_owned()))
            .count(),
        1,
        "{label}",
    );
    assert_eq!(
        events.contains(&NativeEvent::Record(SUFFIX.to_owned())),
        suffix_written,
        "{label}",
    );
    assert_eq!(publication_count(trace), 1, "{label}");
}

#[tokio::test]
async fn native_writers_preserve_receipts_cancellation_and_authentication_order() {
    for (label, websocket) in [
        ("tcp_receiving_owner", false),
        ("websocket_receiving_owner", true),
    ] {
        let trace = Arc::new(NativeTrace::default());
        let mut session = RecordingSession::new(trace.clone());
        session.pending_record = true;
        let (item, _) = durable_item(false);
        if websocket {
            let (mut socket, _client) = within(label, websocket_pair()).await;
            let shutdown = CancellationToken::new();
            let signals = session.termination_signals();
            let cancellation = WebSocketSendCancellation {
                actor_shutdown: &shutdown,
                signals: &signals,
            };
            let mut terminal = WebSocketTerminalSequence::default();
            cancel_record(
                &trace,
                websocket_record_and_send_item(
                    &mut socket,
                    &mut session,
                    &item,
                    false,
                    &mut terminal,
                    &cancellation,
                ),
                label,
            );
        } else {
            let mut io = MemoryWrite::default();
            cancel_record(
                &trace,
                tcp_record_and_send_item(&mut io, &mut session, &item, false),
                label,
            );
            assert!(io.bytes.is_empty(), "{label}");
        }
        assert_eq!(
            trace.events(),
            [NativeEvent::Record(item.stanza), NativeEvent::RecordDropped],
            "{label}",
        );
    }

    for mix in [false, true] {
        for (label, cut, ack) in [
            ("full_write", 0, NativeAck::Success),
            ("partial_error", 1, NativeAck::Success),
            ("flush_error", 2, NativeAck::Success),
            ("pending_prefix", 3, NativeAck::Success),
            ("pending_flush", 4, NativeAck::Success),
            ("ack_error", 0, NativeAck::Error),
            ("ack_pending", 0, NativeAck::Pending),
            ("mix_no_match", 0, NativeAck::NoMatch),
        ] {
            if !mix && matches!(ack, NativeAck::NoMatch) {
                continue;
            }
            let trace = Arc::new(NativeTrace::default());
            let mut session = RecordingSession::new(trace.clone());
            let (mut item, expected) = durable_item(mix);
            let receipts = ReceiptProbe::attach(&mut item);
            session.receipts = Some(receipts.clone());
            session.expected_source = Some(expected);
            session.ack = ack;
            let mut io = ObservedMemoryWrite {
                inner: MemoryWrite {
                    fail_at: (cut == 1).then_some(1),
                    fail_flush: cut == 2,
                    pending_after: (cut == 3).then_some(3),
                    pending_flush: cut == 4,
                    ..MemoryWrite::default()
                },
                trace: trace.clone(),
            };
            let mut future = Box::pin(tcp_record_and_send_item(
                &mut io,
                &mut session,
                &item,
                false,
            ));
            let result = poll_native(&trace, future.as_mut());
            if cut >= 3 || matches!(ack, NativeAck::Pending) {
                assert!(result.is_pending(), "{label}");
                assert!(trace.summaries.lock().unwrap().is_empty(), "{label}");
            } else if cut == 0 {
                assert!(matches!(result, Poll::Ready(Ok(true))), "{label}");
            } else {
                let Poll::Ready(Err(error)) = result else {
                    panic!("{label}: lost writer error");
                };
                assert!(
                    error.to_string().contains(if cut == 1 {
                        "controlled partial write"
                    } else {
                        "controlled flush failure"
                    }),
                    "{label}: {error}",
                );
            }
            tracing::subscriber::with_default(NativeSubscriber(trace.clone()), || drop(future));
            let events = trace.events();
            assert_eq!(
                events[0],
                NativeEvent::Record(item.stanza.clone()),
                "{label}"
            );
            assert_eq!(
                events[1],
                NativeEvent::Fence(item.durable_source.unwrap()),
                "{label}",
            );
            assert_eq!(
                events
                    .iter()
                    .filter(|event| matches!(event, NativeEvent::Record(_)))
                    .count(),
                1,
                "{label}",
            );
            assert_eq!(
                events
                    .iter()
                    .filter(|event| matches!(event, NativeEvent::Ack(_)))
                    .count(),
                usize::from(cut == 0),
                "{label}",
            );
            if cut == 0 {
                assert_eq!(io.inner.bytes, item.stanza.as_bytes(), "{label}");
                assert_eq!(io.inner.flushes, 1, "{label}");
                let at = events
                    .iter()
                    .position(|event| *event == NativeEvent::Flushed)
                    .unwrap();
                assert_eq!(
                    &events[at + 1..],
                    [
                        NativeEvent::WriteReceipt,
                        NativeEvent::OwnershipReceipt,
                        NativeEvent::Ack(expected),
                    ],
                    "{label}",
                );
                trace.summary_contains("writer_result: Some(FullWrite)", label);
                trace.summary_contains(
                    match ack {
                        NativeAck::Success | NativeAck::NoMatch => "ack_returned: Some(true)",
                        NativeAck::Error => "ack_returned: Some(false)",
                        NativeAck::Pending => "ack_returned: None",
                    },
                    label,
                );
            } else {
                receipts.assert_empty(label);
                trace.summary_contains(
                    if cut >= 3 {
                        "writer_result: None"
                    } else {
                        "writer_result: Some(Failed)"
                    },
                    label,
                );
                trace.summary_contains("ack: NotRequested", label);
            }
            trace.summary_contains(
                if cut >= 3 || matches!(ack, NativeAck::Pending) {
                    "terminal: Some(Cancelled)"
                } else {
                    "terminal: Some(Returned)"
                },
                label,
            );
        }
    }

    for mix in [false, true] {
        for (label, cancel, ack) in [
            ("websocket_full_write", 0, NativeAck::Success),
            ("websocket_shutdown", 1, NativeAck::Success),
            ("websocket_revocation", 2, NativeAck::Success),
            ("websocket_backpressure", 3, NativeAck::Success),
            ("websocket_ack_error", 0, NativeAck::Error),
            ("websocket_mix_no_match", 0, NativeAck::NoMatch),
        ] {
            if !mix && matches!(ack, NativeAck::NoMatch) {
                continue;
            }
            within(label, async {
                let (mut socket, mut client) = websocket_pair().await;
                let trace = Arc::new(NativeTrace::default());
                let mut session = RecordingSession::new(trace.clone());
                let (mut item, expected) = durable_item(mix);
                let receipts = ReceiptProbe::attach(&mut item);
                session.receipts = Some(receipts.clone());
                session.expected_source = Some(expected);
                session.ack = ack;
                let shutdown = CancellationToken::new();
                let revoke = CancellationToken::new();
                let backpressure = CancellationToken::new();
                match cancel {
                    1 => shutdown.cancel(),
                    2 => revoke.cancel(),
                    3 => backpressure.cancel(),
                    _ => {}
                }
                let signals = SessionTerminationSignals::new(revoke, backpressure);
                let cancellation = WebSocketSendCancellation {
                    actor_shutdown: &shutdown,
                    signals: &signals,
                };
                let mut terminal = WebSocketTerminalSequence::default();
                let result = websocket_record_and_send_item(
                    &mut socket,
                    &mut session,
                    &item,
                    false,
                    &mut terminal,
                    &cancellation,
                )
                .with_subscriber(NativeSubscriber(trace.clone()))
                .await;
                assert_eq!(result, cancel == 0, "{label}");
                if cancel == 0 {
                    assert_eq!(
                        read_websocket_text(&mut client).await,
                        item.stanza,
                        "{label}"
                    );
                    assert_eq!(
                        trace.events(),
                        [
                            NativeEvent::Record(item.stanza.clone()),
                            NativeEvent::Fence(item.durable_source.unwrap()),
                            NativeEvent::WriteReceipt,
                            NativeEvent::OwnershipReceipt,
                            NativeEvent::Ack(expected),
                        ],
                        "{label}",
                    );
                    trace.summary_contains(
                        if matches!(ack, NativeAck::Error) {
                            "ack_returned: Some(false)"
                        } else {
                            "ack_returned: Some(true)"
                        },
                        label,
                    );
                } else {
                    receipts.assert_empty(label);
                    assert_eq!(
                        trace.events(),
                        [
                            NativeEvent::Record(item.stanza.clone()),
                            NativeEvent::Fence(item.durable_source.unwrap()),
                        ],
                        "{label}",
                    );
                    trace.summary_contains("writer_result: Some(Failed)", label);
                    trace.summary_contains("ack: NotRequested", label);
                }
                drop(socket);
                let mut extra = Vec::new();
                client.read_to_end(&mut extra).await.unwrap();
                assert!(extra.is_empty(), "{label}: unexpected bytes {extra:?}");
            })
            .await;
        }
    }

    for (label, connection, stanza) in [
        ("auth_wrong_connection", Uuid::from_u128(99), CONTROL),
        ("auth_wrong_control", CONNECTION, "<different/>"),
    ] {
        let trace = Arc::new(NativeTrace::default());
        let mut session = RecordingSession::new(trace.clone());
        let (holder, observation) = fixture_bound_control(CONTROL, connection, false);
        let mut io = MemoryWrite::default();
        assert!(
            tcp_record_and_send_auth(&mut io, &mut session, stanza.to_owned(), holder, false)
                .await
                .is_err(),
            "{label}",
        );
        assert!(trace.events().is_empty(), "{label}");
        assert!(io.bytes.is_empty(), "{label}");
        assert_eq!(
            observation.snapshot().publication,
            auth_facts::Knowledge::NotStarted,
            "{label}",
        );
    }

    for resume in [false, true] {
        for (label, cut) in [
            ("auth_success", 0),
            ("auth_partial_error", 1),
            ("auth_flush_error", 2),
            ("auth_publication_rejected", 3),
            ("auth_pending_flush", 4),
        ] {
            let trace = Arc::new(NativeTrace::default());
            let mut session = RecordingSession::new(trace.clone());
            if cut == 3 {
                session.publication_cut = PublicationCut::RouteRejected;
            }
            let (action, observation) = authentication_action(resume, true, true);
            let mut io = ObservedMemoryWrite {
                inner: MemoryWrite {
                    fail_at: (cut == 1).then_some(1),
                    fail_flush: cut == 2,
                    pending_flush: cut == 4,
                    ..MemoryWrite::default()
                },
                trace: trace.clone(),
            };
            if cut == 4 {
                let mut future = Box::pin(tcp_action::apply(&mut io, &mut session, action, false));
                assert!(futures::poll!(&mut future).is_pending(), "{label}");
                assert_eq!(publication_count(&trace), 0, "{label}");
                drop(future);
                assert_eq!(io.inner.bytes, CONTROL.as_bytes(), "{label}");
                assert_eq!(
                    observation.snapshot().transport,
                    auth_facts::Transport::WriteEntered,
                    "{label}",
                );
                continue;
            }
            let result = tcp_action::apply(&mut io, &mut session, action, false).await;
            if cut == 1 || cut == 2 {
                assert!(result.is_err(), "{label}");
                assert_eq!(publication_count(&trace), 0, "{label}");
                assert_eq!(
                    observation.snapshot().publication,
                    auth_facts::Knowledge::NotStarted,
                    "{label}",
                );
            } else {
                match result {
                    Ok(tcp_action::TcpActionDisposition::Continue) => assert_eq!(cut, 0, "{label}"),
                    Ok(tcp_action::TcpActionDisposition::Close) => assert_eq!(cut, 3, "{label}"),
                    _ => panic!("{label}: unexpected action result"),
                }
                assert_tcp_publication_order(&trace, cut == 0, label);
                assert_eq!(
                    io.inner.bytes,
                    if cut == 0 {
                        format!("{CONTROL}{SUFFIX}").into_bytes()
                    } else {
                        CONTROL.as_bytes().to_vec()
                    },
                    "{label}",
                );
                assert_eq!(
                    observation.snapshot().transport,
                    auth_facts::Transport::Written,
                    "{label}",
                );
            }
        }

        for (label, cut) in [
            ("websocket_auth_success", 0),
            ("websocket_auth_cancelled", 1),
            ("websocket_auth_publication_rejected", 2),
        ] {
            within(label, async {
                let (mut socket, mut client) = websocket_pair().await;
                let trace = Arc::new(NativeTrace::default());
                let mut session = RecordingSession::new(trace.clone());
                if cut == 2 {
                    session.publication_cut = PublicationCut::RouteRejected;
                }
                let (action, observation) = authentication_action(resume, true, true);
                let shutdown = CancellationToken::new();
                if cut == 1 {
                    shutdown.cancel();
                }
                let signals = session.termination_signals();
                let cancellation = WebSocketSendCancellation {
                    actor_shutdown: &shutdown,
                    signals: &signals,
                };
                let mut terminal = WebSocketTerminalSequence::default();
                assert_eq!(
                    websocket_action::apply(
                        &mut socket,
                        &mut session,
                        Ok(action),
                        false,
                        &mut terminal,
                        &cancellation,
                    )
                    .await,
                    cut == 0,
                    "{label}",
                );
                assert_eq!(publication_count(&trace), usize::from(cut != 1), "{label}");
                if cut == 1 {
                    assert_eq!(
                        observation.snapshot().publication,
                        auth_facts::Knowledge::NotStarted,
                        "{label}",
                    );
                } else {
                    assert_eq!(read_websocket_text(&mut client).await, CONTROL, "{label}");
                    let mut expected = vec![
                        NativeEvent::Record(CONTROL.to_owned()),
                        NativeEvent::Publish(CONNECTION),
                        NativeEvent::Published(cut == 0),
                    ];
                    if cut == 0 {
                        assert_eq!(read_websocket_text(&mut client).await, SUFFIX, "{label}");
                        expected.push(NativeEvent::Record(SUFFIX.to_owned()));
                    }
                    assert_eq!(trace.events(), expected, "{label}");
                }
                drop(socket);
                let mut extra = Vec::new();
                client.read_to_end(&mut extra).await.unwrap();
                assert!(extra.is_empty(), "{label}");
            })
            .await;
        }
    }

    for (label, activation, holder_present) in [
        ("resume_missing_holder", true, false),
        ("resume_unexpected_holder", false, true),
        ("resume_without_activation", false, false),
    ] {
        let valid = activation == holder_present;
        let trace = Arc::new(NativeTrace::default());
        let mut session = RecordingSession::new(trace.clone());
        let (action, _) = authentication_action(true, activation, holder_present);
        let mut io = MemoryWrite::default();
        let result = tcp_action::apply(&mut io, &mut session, action, false).await;
        assert_eq!(result.is_ok(), valid, "{label}");
        assert_eq!(publication_count(&trace), 0, "{label}");
        assert_eq!(io.bytes.is_empty(), !valid, "{label}");
        within(label, async {
            let (mut socket, mut client) = websocket_pair().await;
            let trace = Arc::new(NativeTrace::default());
            let mut session = RecordingSession::new(trace.clone());
            let (action, _) = authentication_action(true, activation, holder_present);
            let shutdown = CancellationToken::new();
            let signals = session.termination_signals();
            let cancellation = WebSocketSendCancellation {
                actor_shutdown: &shutdown,
                signals: &signals,
            };
            let mut terminal = WebSocketTerminalSequence::default();
            assert_eq!(
                websocket_action::apply(
                    &mut socket,
                    &mut session,
                    Ok(action),
                    false,
                    &mut terminal,
                    &cancellation,
                )
                .await,
                valid,
                "{label}",
            );
            assert_eq!(publication_count(&trace), 0, "{label}");
            if valid {
                assert_eq!(read_websocket_text(&mut client).await, CONTROL, "{label}");
                assert_eq!(read_websocket_text(&mut client).await, SUFFIX, "{label}");
            } else {
                assert_eq!(trace.events(), [NativeEvent::ForbidResume], "{label}");
            }
            drop(socket);
            let mut extra = Vec::new();
            client.read_to_end(&mut extra).await.unwrap();
            assert!(extra.is_empty(), "{label}");
        })
        .await;
    }

    // Only this section uses virtual time; all loopback endpoints above are closed.
    tokio::time::pause();
    for (label, cancel) in [
        ("pending_write_shutdown", 1),
        ("pending_write_revocation", 2),
        ("pending_write_backpressure", 3),
        ("write_deadline", 0),
    ] {
        let shutdown = CancellationToken::new();
        let revoke = CancellationToken::new();
        let backpressure = CancellationToken::new();
        let signals = SessionTerminationSignals::new(revoke.clone(), backpressure.clone());
        let cancellation = WebSocketSendCancellation {
            actor_shutdown: &shutdown,
            signals: &signals,
        };
        let mut future = Box::pin(bounded_websocket_live_write(
            std::future::pending::<Result<(), ()>>(),
            &cancellation,
        ));
        assert!(futures::poll!(&mut future).is_pending(), "{label}");
        tokio::time::advance(Duration::from_secs(9)).await;
        assert!(
            futures::poll!(&mut future).is_pending(),
            "{label}: deadline fired early"
        );
        match cancel {
            1 => shutdown.cancel(),
            2 => revoke.cancel(),
            3 => backpressure.cancel(),
            // The timer wheel rounds a deadline up to its next millisecond tick.
            _ => tokio::time::advance(Duration::from_millis(1_001)).await,
        }
        assert_eq!(futures::poll!(&mut future), Poll::Ready(false), "{label}");
    }
    tokio::time::resume();
}

struct RecordingHost {
    trace: Arc<NativeTrace>,
    actors: northstar_runtime::connection_actors::ConnectionActorRegistry,
    finalize_release: CancellationToken,
    panic_finalize: bool,
}

impl RecordingHost {
    fn new(panic_finalize: bool) -> Arc<Self> {
        Arc::new(Self {
            trace: Arc::new(NativeTrace::default()),
            actors: northstar_runtime::connection_actors::ConnectionActorRegistry::new(1),
            finalize_release: CancellationToken::new(),
            panic_finalize,
        })
    }
}

impl TransportHost for RecordingHost {
    type Session = RecordingSession;
    type ConnectionGuard = ();

    fn local_domain(&self) -> &str {
        "example.test"
    }
    fn acquire_client_connection(self: &Arc<Self>, _: std::net::IpAddr) -> Option<()> {
        Some(())
    }
    fn connection_actors(&self) -> &northstar_runtime::connection_actors::ConnectionActorRegistry {
        &self.actors
    }
    fn open_session(
        self: Arc<Self>,
        outbound: OutboundSender,
        secure_transport: bool,
        transport: ClientTransport,
        stream_limits: Option<StreamLimits>,
        peer_ip: std::net::IpAddr,
    ) -> RecordingSession {
        assert!(peer_ip.is_loopback());
        let limits = stream_limits.unwrap();
        assert_eq!(limits.max_bytes, MAX_XMPP_FRAME_BYTES);
        self.trace
            .push(NativeEvent::Open(CONNECTION, transport, secure_transport));
        let mut session = RecordingSession::new(self.trace.clone());
        session.finalize_release = self.finalize_release.clone();
        session.panic_finalize = self.panic_finalize;
        session._outbound = Some(outbound);
        session
    }
}

impl C2sHost for RecordingHost {
    fn tls_context(&self) -> &northstar_security::tls::TlsContext {
        panic!("connection entry points receive their TLS snapshot directly");
    }
    fn record_c2s_tcp_connection(&self) {}
    fn record_c2s_websocket_connection(&self) {}
    fn sm_live_lease_seconds(&self) -> u64 {
        60
    }
    fn c2s_backpressure_telemetry(&self) -> C2sBackpressureTelemetry {
        northstar_telemetry::metrics::Metrics::default().c2s_backpressure_telemetry()
    }
}

// The RFC 8032 first test vector supplies a fixed Ed25519 key. Certificate
// trust is pinned to these exact bytes by the test client; TLS still verifies
// the handshake signature. No certificate file, clock or ambient trust is used.
fn tls_certificate() -> Vec<u8> {
    fn der(tag: u8, content: &[u8]) -> Vec<u8> {
        assert!(content.len() < 256);
        let mut output = vec![tag];
        if content.len() >= 128 {
            output.push(0x81);
        }
        output.push(content.len() as u8);
        output.extend_from_slice(content);
        output
    }
    let algorithm = [0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70];
    let public_key = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
        0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
        0x51, 0x1a,
    ];
    let common_name = der(
        0x30,
        &[
            &[0x06, 0x03, 0x55, 0x04, 0x03][..],
            &der(0x0c, b"example.test"),
        ]
        .concat(),
    );
    let name = der(0x30, &der(0x31, &common_name));
    let validity = der(
        0x30,
        &[der(0x17, b"260101000000Z"), der(0x18, b"20991231235959Z")].concat(),
    );
    let key_bits = der(0x03, &[&[0][..], &public_key].concat());
    let spki = der(0x30, &[&algorithm[..], &key_bits].concat());
    let tbs = der(
        0x30,
        &[
            &[0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01][..],
            &algorithm,
            &name,
            &validity,
            &name,
            &spki,
        ]
        .concat(),
    );
    // The pinned client does not validate the certificate's issuer signature.
    der(0x30, &[&tbs[..], &algorithm, &der(0x03, &[0; 65])].concat())
}

#[derive(Debug)]
struct PinnedTestCertificate;

impl rustls::client::danger::ServerCertVerifier for PinnedTestCertificate {
    fn verify_server_cert(
        &self,
        certificate: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        assert_eq!(certificate.as_ref(), tls_certificate());
        assert!(intermediates.is_empty());
        assert_eq!(
            server_name,
            &rustls::pki_types::ServerName::try_from("example.test").unwrap(),
        );
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &rustls::pki_types::CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            certificate,
            signature,
            &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &rustls::pki_types::CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            certificate,
            signature,
            &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![rustls::SignatureScheme::ED25519]
    }
}

fn native_tls_pair() -> (TlsAcceptor, tokio_rustls::TlsConnector) {
    let mut private_key = vec![
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    private_key.extend_from_slice(&[
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ]);
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut server = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(tls_certificate())],
            rustls::pki_types::PrivatePkcs8KeyDer::from(private_key).into(),
        )
        .unwrap();
    server.alpn_protocols = vec![b"xmpp-client".to_vec()];
    let mut client = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedTestCertificate))
        .with_no_client_auth();
    client.alpn_protocols = vec![b"xmpp-client".to_vec()];
    (
        TlsAcceptor::from(Arc::new(server)),
        tokio_rustls::TlsConnector::from(Arc::new(client)),
    )
}

async fn tcp_pair() -> (TcpStream, TcpStream, SocketAddr) {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let (client, accepted) = tokio::join!(TcpStream::connect(address), listener.accept());
    let (server, peer) = accepted.unwrap();
    (client.unwrap(), server, peer)
}

enum NativeClient {
    Tcp(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
    WebSocket(TcpStream),
}

impl NativeClient {
    async fn frame(&mut self, frame: &str) {
        match self {
            Self::Tcp(client) => client.write_all(frame.as_bytes()).await.unwrap(),
            Self::Tls(client) => {
                client.write_all(frame.as_bytes()).await.unwrap();
                client.flush().await.unwrap();
            }
            Self::WebSocket(client) => websocket_text(client, frame).await,
        }
    }
    async fn eof(&mut self, partial_utf8: bool) {
        match self {
            Self::Tcp(client) => {
                if partial_utf8 {
                    client.write_all(&[0xe2]).await.unwrap();
                }
                client.shutdown().await.unwrap();
            }
            Self::Tls(client) => {
                if partial_utf8 {
                    client.write_all(&[0xe2]).await.unwrap();
                }
                client.shutdown().await.unwrap();
            }
            Self::WebSocket(client) => {
                assert!(!partial_utf8);
                client.shutdown().await.unwrap();
            }
        }
    }
}

async fn open_native_connection(
    kind: &str,
    host: Arc<RecordingHost>,
) -> (NativeClient, tokio::task::JoinHandle<Result<()>>) {
    let shutdown = CancellationToken::new();
    if kind == "websocket" {
        let (socket, client) = websocket_pair().await;
        let task = tokio::spawn(async move {
            websocket_connection(socket, host, std::net::Ipv4Addr::LOCALHOST.into(), shutdown)
                .await;
            Ok(())
        });
        return (NativeClient::WebSocket(client), task);
    }
    let (client, server, peer) = tcp_pair().await;
    let (acceptor, connector) = native_tls_pair();
    if kind == "direct_tls" {
        let task = tokio::spawn(xmpps_tcp_connection(
            server,
            peer,
            host,
            acceptor,
            Some(vec![7; 32]),
            7,
            shutdown,
        ));
        let secure = connector
            .connect(
                rustls::pki_types::ServerName::try_from("example.test").unwrap(),
                client,
            )
            .await
            .unwrap();
        (NativeClient::Tls(Box::new(secure)), task)
    } else {
        let task = tokio::spawn(tcp_connection(
            server,
            peer,
            host,
            acceptor,
            Some(vec![7; 32]),
            7,
            shutdown,
        ));
        (NativeClient::Tcp(client), task)
    }
}

fn panic_text(payload: &(dyn std::any::Any + Send)) -> &str {
    payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .expect("string panic payload")
}

#[tokio::test]
async fn native_entries_finalize_once_and_starttls_keeps_the_original_session() {
    for kind in ["tcp", "direct_tls", "websocket"] {
        for label in [
            "eof",
            "close_action",
            "backend_failure",
            "frame_timeout",
            "transport_panic",
            "finalizer_panic",
            "both_panics",
            "read_error",
        ] {
            if kind == "websocket" && label == "read_error" {
                continue;
            }
            within(label, async {
                let cleanup_panics = matches!(label, "finalizer_panic" | "both_panics");
                let transport_panics = matches!(label, "transport_panic" | "both_panics");
                let host = RecordingHost::new(cleanup_panics);
                let trace = host.trace.clone();
                let (mut client, task) = open_native_connection(kind, host.clone()).await;
                client.frame("<message id='before-exit'/>").await;
                trace
                    .wait_for(NativeEvent::Frame(
                        CONNECTION,
                        "<message id='before-exit'/>".to_owned(),
                    ))
                    .await;
                assert!(
                    !trace.events().contains(&NativeEvent::Finalize(CONNECTION)),
                    "{kind}/{label}",
                );
                match label {
                    "transport_panic" | "both_panics" => client.frame("<panic/>").await,
                    "backend_failure" => client.frame("<backend/>").await,
                    "frame_timeout" => client.frame("<timeout/>").await,
                    "close_action" => client.frame("<exit/>").await,
                    _ => client.eof(label == "read_error").await,
                }
                trace.wait_for(NativeEvent::Finalize(CONNECTION)).await;
                assert!(
                    !task.is_finished(),
                    "{kind}/{label}: finalizer was detached"
                );
                assert!(
                    !trace
                        .events()
                        .contains(&NativeEvent::SessionDropped(CONNECTION)),
                    "{kind}/{label}",
                );
                host.finalize_release.cancel();
                let result = task.await;
                if transport_panics || cleanup_panics {
                    let Err(error) = result else {
                        panic!("{kind}/{label}: swallowed panic");
                    };
                    assert!(error.is_panic(), "{kind}/{label}");
                    let payload = error.into_panic();
                    assert_eq!(
                        panic_text(payload.as_ref()),
                        if transport_panics {
                            "recorded transport panic"
                        } else {
                            "recorded finalizer panic"
                        },
                        "{kind}/{label}",
                    );
                } else {
                    let result = result.unwrap();
                    if label == "read_error" {
                        let Err(error) = result else {
                            panic!("{kind}/{label}: swallowed read error");
                        };
                        assert_eq!(
                            error.to_string(),
                            "XMPP stream ended inside a UTF-8 character",
                            "{kind}/{label}",
                        );
                    } else {
                        assert!(result.is_ok(), "{kind}/{label}: {result:?}");
                    }
                }
                let events = trace.events();
                let expected_open = NativeEvent::Open(
                    CONNECTION,
                    if kind == "websocket" {
                        ClientTransport::WebSocket
                    } else {
                        ClientTransport::Tcp
                    },
                    kind == "websocket",
                );
                assert_eq!(events.first(), Some(&expected_open), "{kind}/{label}");
                for event in [
                    expected_open,
                    NativeEvent::Finalize(CONNECTION),
                    NativeEvent::SessionDropped(CONNECTION),
                ] {
                    assert_eq!(
                        events.iter().filter(|actual| **actual == event).count(),
                        1,
                        "{kind}/{label}: {events:?}",
                    );
                }
                assert_eq!(
                    events.last(),
                    Some(&NativeEvent::SessionDropped(CONNECTION)),
                    "{kind}/{label}",
                );
                assert_eq!(
                    events.contains(&NativeEvent::Finalized(CONNECTION)),
                    !cleanup_panics,
                    "{kind}/{label}",
                );
                assert_eq!(
                    events
                        .iter()
                        .filter(|event| **event == NativeEvent::PostAction)
                        .count(),
                    1,
                    "{kind}/{label}: frame continuation count",
                );
                let frames: Vec<_> = events
                    .iter()
                    .filter_map(|event| match event {
                        NativeEvent::Frame(connection, frame) => {
                            Some((*connection, frame.as_str()))
                        }
                        _ => None,
                    })
                    .collect();
                let mut expected_frames = vec![(CONNECTION, "<message id='before-exit'/>")];
                let terminal_frame = match label {
                    "transport_panic" | "both_panics" => Some("<panic/>"),
                    "backend_failure" => Some("<backend/>"),
                    "frame_timeout" => Some("<timeout/>"),
                    "close_action" => Some("<exit/>"),
                    _ => None,
                };
                if let Some(frame) = terminal_frame {
                    expected_frames.push((CONNECTION, frame));
                }
                assert_eq!(
                    frames, expected_frames,
                    "{kind}/{label}: exact frame ingress"
                );
                if matches!(label, "backend_failure" | "frame_timeout") {
                    assert!(
                        events.contains(&NativeEvent::ForbidResume),
                        "{kind}/{label}"
                    );
                }
                if kind == "direct_tls" {
                    assert_eq!(
                        events
                            .iter()
                            .filter(|event| **event == NativeEvent::Tls(CONNECTION, 7))
                            .count(),
                        1,
                        "{kind}/{label}",
                    );
                }
            })
            .await;
        }
    }

    for label in ["starttls_success", "starttls_handshake_failure"] {
        within(label, async {
            let host = RecordingHost::new(false);
            let trace = host.trace.clone();
            let (mut client, server, peer) = tcp_pair().await;
            let (acceptor, connector) = native_tls_pair();
            let task = tokio::spawn(tcp_connection(
                server,
                peer,
                host.clone(),
                acceptor,
                Some(vec![7; 32]),
                7,
                CancellationToken::new(),
            ));
            let starttls = "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>";
            client.write_all(starttls.as_bytes()).await.unwrap();
            let proceed = "<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>";
            let mut bytes = vec![0; proceed.len()];
            client.read_exact(&mut bytes).await.unwrap();
            assert_eq!(bytes, proceed.as_bytes(), "{label}");
            assert_eq!(
                trace.events(),
                [
                    NativeEvent::Open(CONNECTION, ClientTransport::Tcp, false),
                    NativeEvent::Frame(CONNECTION, starttls.to_owned()),
                ],
                "{label}: upgrade finalized or replaced the plain session",
            );
            if label == "starttls_success" {
                let mut secure = connector
                    .connect(
                        rustls::pki_types::ServerName::try_from("example.test").unwrap(),
                        client,
                    )
                    .await
                    .unwrap();
                trace.wait_for(NativeEvent::Tls(CONNECTION, 7)).await;
                secure
                    .write_all(b"<message id='after-tls'/>")
                    .await
                    .unwrap();
                secure.flush().await.unwrap();
                trace
                    .wait_for(NativeEvent::Frame(
                        CONNECTION,
                        "<message id='after-tls'/>".to_owned(),
                    ))
                    .await;
                assert!(
                    !trace.events().contains(&NativeEvent::Finalize(CONNECTION)),
                    "{label}"
                );
                secure.shutdown().await.unwrap();
            } else {
                client.write_all(b"not a TLS record").await.unwrap();
                client.shutdown().await.unwrap();
            }
            trace.wait_for(NativeEvent::Finalize(CONNECTION)).await;
            assert!(!task.is_finished(), "{label}: finalizer was detached");
            host.finalize_release.cancel();
            let result = task.await.unwrap();
            assert_eq!(
                result.is_ok(),
                label == "starttls_success",
                "{label}: {result:?}"
            );
            let events = trace.events();
            assert_eq!(
                events
                    .iter()
                    .filter(|event| matches!(event, NativeEvent::Open(..)))
                    .count(),
                1,
                "{label}",
            );
            assert_eq!(
                events
                    .iter()
                    .filter(|event| **event == NativeEvent::Finalize(CONNECTION))
                    .count(),
                1,
                "{label}",
            );
            assert_eq!(
                &events[events.len() - 3..],
                [
                    NativeEvent::Finalize(CONNECTION),
                    NativeEvent::Finalized(CONNECTION),
                    NativeEvent::SessionDropped(CONNECTION),
                ],
                "{label}",
            );
        })
        .await;
    }
}
