use super::mix_store::MixStore;
use super::replay_store::{Call, ReplayStore};
use crate::host::{BoshHost, BoshPolicy};
use crate::{BoshManager, RecordPort};
use anyhow::Result;
use axum::http::HeaderMap;
use northstar_abuse_policy::content_identity::{
    MixMessageContentKeyring, MixRetractionContentKeyring,
};
use northstar_auth_application::authentication::publication::Transport;
use northstar_delivery_core::{DurableDeliverySuperseded, MixDelivery, TransportOwnershipSource};
use northstar_room_application::mix_service::MixService;
use northstar_runtime::connection_actors::ConnectionActorRegistry;
use northstar_session_application::replay::ReplayService;
use northstar_session_application::sm_capacity::SmMemoryGovernor;
use northstar_stream::auth_publication::fixture::{Cut, FakePort};
use northstar_stream::auth_publication::OwnedPublication;
use northstar_stream::frame_execution::{FrameExecution, FrameFailure, Stage};
use northstar_stream::host::TransportHost;
use northstar_stream::outbound::{OutboundItem, OutboundSender};
use northstar_stream::session::StreamSession;
use northstar_stream::transport::{
    Action, ClientTransport, SessionTerminationSignals, StreamLimits, TlsSessionEvidence,
};
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

pub(super) const CONNECTION: Uuid = Uuid::from_u128(9001);
pub(super) const DELIVERY_SESSION: Uuid = Uuid::from_u128(9002);
pub(super) const SUPERSEDED_MESSAGE: Uuid = Uuid::from_u128(9004);
pub(super) const CONTENT_TYPE: &str = "application/xmpp+xml; charset=utf-8";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ItemFacts {
    pub stanza: String,
    pub pointer: usize,
    pub source: Option<TransportOwnershipSource>,
    pub handoff: bool,
    pub receipt: bool,
    pub write_receipt: bool,
}

impl ItemFacts {
    pub(super) fn new(item: &OutboundItem) -> Self {
        Self {
            stanza: item.stanza.clone(),
            pointer: item.stanza.as_ptr() as usize,
            source: item.durable_source,
            handoff: item.mix_handoff.is_some(),
            receipt: item.transport_receipt.is_some(),
            write_receipt: item.transport_write_receipt.is_some(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum Event {
    Read(&'static str),
    Acquire(IpAddr),
    Open {
        secure: bool,
        peer: IpAddr,
    },
    Capture(String),
    Session(&'static str),
    Frame(String),
    Csi(ItemFacts),
    Record(ItemFacts),
    RecordStanza(String),
    Publish {
        connection: Uuid,
        control: Uuid,
        transport: Transport,
    },
    Published {
        control: Uuid,
        succeeded: bool,
    },
    Transfer {
        source: MixDelivery,
        session_id: Uuid,
        ttl_seconds: u64,
    },
    Replay(Call),
}

#[derive(Clone, Default)]
pub(super) struct Trace(Arc<Mutex<Vec<Event>>>);

impl Trace {
    pub(super) fn push(&self, event: Event) {
        self.0.lock().unwrap().push(event);
    }

    pub(super) fn events(&self) -> Vec<Event> {
        self.0.lock().unwrap().clone()
    }

    pub(super) fn clear(&self) {
        self.0.lock().unwrap().clear();
    }

    pub(super) fn effects(&self) -> Vec<Event> {
        self.events()
            .into_iter()
            .filter(|event| !matches!(event, Event::Read(_)))
            .collect()
    }
}

#[derive(Clone, Copy)]
pub(super) enum RecordCut {
    Pass,
    Superseded,
    Pending,
    Panic,
}

#[derive(Clone, Copy, Default)]
pub(super) enum PublicationCut {
    #[default]
    Pass,
    Reject,
    Gated,
}

pub(super) struct TestHost {
    pub manager: BoshManager,
    pub trace: Trace,
    pub replay: ReplayStore,
    pub mix: MixStore,
    pub actors: ConnectionActorRegistry,
    pub record_cut: Arc<Mutex<RecordCut>>,
    pub frame_items: Arc<Mutex<Vec<OutboundItem>>>,
    pub frame_actions: Arc<Mutex<VecDeque<Action>>>,
    pub frame_executions: Arc<Mutex<Vec<FrameExecution>>>,
    pub publication_cuts: Arc<Mutex<VecDeque<PublicationCut>>>,
    pub publication_gate: Arc<tokio::sync::Semaphore>,
    pub reject_stanza_record: Arc<Mutex<bool>>,
    pub policy_revoke: CancellationToken,
    pub backpressure: CancellationToken,
    pub outbound: Mutex<Option<OutboundSender>>,
    replay_service: ReplayService<ReplayStore>,
    mix_service: MixService<MixStore>,
    governor: Arc<SmMemoryGovernor>,
    proxies: [IpAddr; 1],
}

impl TestHost {
    pub(super) fn new() -> Arc<Self> {
        let trace = Trace::default();
        let replay = ReplayStore::with_trace(trace.clone());
        let mix = MixStore::new(trace.clone());
        let generations = Arc::new(Vec::new());
        Arc::new(Self {
            manager: BoshManager::new(1, 1),
            replay_service: ReplayService::new(replay.clone(), "example.test", 30),
            mix_service: MixService::new(
                mix.clone(),
                MixMessageContentKeyring::new(generations.clone()),
                MixRetractionContentKeyring::new(generations),
                2,
                "public".to_owned(),
            )
            .unwrap(),
            governor: super::response_test_governor(),
            actors: ConnectionActorRegistry::new(1),
            trace,
            replay,
            mix,
            record_cut: Arc::new(Mutex::new(RecordCut::Pass)),
            frame_items: Arc::new(Mutex::new(vec![])),
            frame_actions: Arc::new(Mutex::new(VecDeque::new())),
            frame_executions: Arc::new(Mutex::new(vec![])),
            publication_cuts: Arc::new(Mutex::new(VecDeque::new())),
            publication_gate: Arc::new(tokio::sync::Semaphore::new(0)),
            reject_stanza_record: Arc::new(Mutex::new(false)),
            policy_revoke: CancellationToken::new(),
            backpressure: CancellationToken::new(),
            outbound: Mutex::new(None),
            proxies: [Ipv4Addr::LOCALHOST.into()],
        })
    }
}

pub(super) struct ConnectionGuard(Trace);

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.push(Event::Session("connection dropped"));
    }
}

impl TransportHost for TestHost {
    type Session = RecordingSession;
    type ConnectionGuard = ConnectionGuard;

    fn local_domain(&self) -> &str {
        self.trace.push(Event::Read("host domain"));
        "example.test"
    }

    fn acquire_client_connection(self: &Arc<Self>, ip: IpAddr) -> Option<ConnectionGuard> {
        self.trace.push(Event::Acquire(ip));
        Some(ConnectionGuard(self.trace.clone()))
    }

    fn connection_actors(&self) -> &ConnectionActorRegistry {
        self.trace.push(Event::Read("connection actors"));
        &self.actors
    }

    fn open_session(
        self: Arc<Self>,
        outbound: OutboundSender,
        secure_transport: bool,
        transport: ClientTransport,
        stream_limits: Option<StreamLimits>,
        peer_ip: IpAddr,
    ) -> RecordingSession {
        assert!(matches!(transport, ClientTransport::Bosh));
        assert!(stream_limits.is_none());
        self.trace.push(Event::Open {
            secure: secure_transport,
            peer: peer_ip,
        });
        *self.outbound.lock().unwrap() = Some(outbound);
        RecordingSession {
            trace: self.trace.clone(),
            record_cut: self.record_cut.clone(),
            frame_items: self.frame_items.clone(),
            frame_actions: self.frame_actions.clone(),
            frame_executions: self.frame_executions.clone(),
            publication_cuts: self.publication_cuts.clone(),
            publication_gate: self.publication_gate.clone(),
            reject_stanza_record: self.reject_stanza_record.clone(),
            signals: SessionTerminationSignals::new(
                self.policy_revoke.clone(),
                self.backpressure.clone(),
            ),
        }
    }
}

impl BoshHost for TestHost {
    type ReplayStore = ReplayStore;
    type MixStore = MixStore;

    fn bosh_manager(&self) -> &BoshManager {
        self.trace.push(Event::Read("BOSH manager"));
        &self.manager
    }

    fn bosh_policy(&self) -> BoshPolicy {
        self.trace.push(Event::Read("BOSH policy"));
        BoshPolicy {
            max_wait_seconds: 60,
            inactivity_seconds: 120,
            polling_seconds: 0,
            max_pause_seconds: 90,
            body_read_timeout_seconds: 5,
            max_request_bytes: 16 * 1024,
            max_response_bytes: 16 * 1024,
            max_stanzas_per_request: 16,
            max_output_stanzas: 16,
            max_output_bytes: 32 * 1024,
        }
    }

    fn trusted_proxy_ips(&self) -> &[IpAddr] {
        self.trace.push(Event::Read("trusted proxies"));
        &self.proxies
    }

    fn client_ip(&self, peer_ip: IpAddr, _: &HeaderMap) -> IpAddr {
        self.trace.push(Event::Read("client IP"));
        peer_ip
    }

    fn replay_service(&self) -> &ReplayService<ReplayStore> {
        self.trace.push(Event::Read("replay service"));
        &self.replay_service
    }

    fn mix_service(&self) -> &MixService<MixStore> {
        self.trace.push(Event::Read("MIX service"));
        &self.mix_service
    }

    fn sm_memory_governor(&self) -> &Arc<SmMemoryGovernor> {
        self.trace.push(Event::Read("SM governor"));
        &self.governor
    }

    fn record_bosh_session_opened(&self) {
        self.trace.push(Event::Session("opened"));
    }
}

pub(super) struct RecordingSession {
    trace: Trace,
    record_cut: Arc<Mutex<RecordCut>>,
    frame_items: Arc<Mutex<Vec<OutboundItem>>>,
    frame_actions: Arc<Mutex<VecDeque<Action>>>,
    frame_executions: Arc<Mutex<Vec<FrameExecution>>>,
    publication_cuts: Arc<Mutex<VecDeque<PublicationCut>>>,
    publication_gate: Arc<tokio::sync::Semaphore>,
    reject_stanza_record: Arc<Mutex<bool>>,
    signals: SessionTerminationSignals,
}

struct RecordDrop(Trace);

impl Drop for RecordDrop {
    fn drop(&mut self) {
        self.0.push(Event::Session("record dropped"));
    }
}

struct FrameDrop(Trace);

impl Drop for FrameDrop {
    fn drop(&mut self) {
        self.0.push(Event::Session("frame dropped"));
    }
}

impl RecordPort for RecordingSession {
    async fn record(&mut self, item: &OutboundItem) -> Result<bool> {
        self.trace.push(Event::Record(ItemFacts::new(item)));
        let cut = *self.record_cut.lock().unwrap();
        match cut {
            RecordCut::Pass => Ok(false),
            RecordCut::Superseded => Err(DurableDeliverySuperseded {
                message_id: SUPERSEDED_MESSAGE,
            }
            .into()),
            RecordCut::Pending => {
                let _drop = RecordDrop(self.trace.clone());
                std::future::pending().await
            }
            RecordCut::Panic => panic!("first record poll panicked"),
        }
    }
}

impl StreamSession for RecordingSession {
    fn connection_id(&self) -> Uuid {
        self.trace.push(Event::Read("connection ID"));
        CONNECTION
    }
    fn peer_ip(&self) -> IpAddr {
        self.trace.push(Event::Read("peer IP"));
        Ipv4Addr::LOCALHOST.into()
    }
    fn local_domain(&self) -> &str {
        self.trace.push(Event::Read("session domain"));
        "example.test"
    }
    fn is_stream_open(&self) -> bool {
        self.trace.push(Event::Read("stream open"));
        true
    }
    fn is_authenticated(&self) -> bool {
        self.trace.push(Event::Read("authenticated"));
        true
    }
    fn sasl2_in_progress(&self) -> bool {
        self.trace.push(Event::Read("SASL2 in progress"));
        false
    }
    fn unauthenticated_timed_out(&self, _: Instant) -> bool {
        self.trace.push(Event::Read("authentication deadline"));
        false
    }
    fn resource_bind_deadline(&self) -> Option<Instant> {
        self.trace.push(Event::Read("resource bind deadline"));
        None
    }
    fn termination_signals(&self) -> SessionTerminationSignals {
        self.trace.push(Event::Read("termination signals"));
        self.signals.clone()
    }
    fn features(&self) -> String {
        self.trace.push(Event::Read("features"));
        "<stream:features xmlns:stream='http://etherx.jabber.org/streams'/>".to_owned()
    }
    fn capture_stream_from(&mut self, opening: &str) -> Result<(), &'static str> {
        self.trace.push(Event::Capture(opening.to_owned()));
        Ok(())
    }
    fn activate_tls(&mut self, _: TlsSessionEvidence) {
        panic!("BOSH must already be secure");
    }
    async fn process_frame(&mut self, frame: &str) -> Result<Action, FrameFailure> {
        self.trace.push(Event::Frame(frame.to_owned()));
        let execution = {
            let mut executions = self.frame_executions.lock().unwrap();
            let execution = FrameExecution::for_saved_case(
                ClientTransport::Bosh,
                frame,
                Uuid::from_u128(9100 + executions.len() as u128),
            );
            executions.push(execution.clone());
            execution
        };
        execution
            .run(async {
                execution.enter(Stage::Handler);
                Ok(match frame {
                    "<items/>" => Action::SendManyItems(std::mem::take(
                        &mut *self.frame_items.lock().unwrap(),
                    )),
                    "<actions/>" => self.frame_actions.lock().unwrap().pop_front().unwrap(),
                    "<backend/>" => anyhow::bail!("recorded frame backend failure"),
                    "<pending/>" => {
                        let _drop = FrameDrop(self.trace.clone());
                        std::future::pending().await
                    }
                    "<panic/>" => panic!("recorded frame panic"),
                    _ => Action::None,
                })
            })
            .await
    }
    async fn publish_committed_authentication_and_route(
        &mut self,
        owner: OwnedPublication,
    ) -> bool {
        let snapshot = owner.observation().snapshot();
        self.trace.push(Event::Publish {
            connection: owner.connection(),
            control: snapshot.control,
            transport: snapshot.transport,
        });
        let cut = self
            .publication_cuts
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_default();
        if matches!(cut, PublicationCut::Gated) {
            self.publication_gate.acquire().await.unwrap().forget();
        }
        let mut port = FakePort::new(
            CONNECTION,
            if matches!(cut, PublicationCut::Reject) {
                Cut::BeforeCommit
            } else {
                Cut::Success
            },
        );
        let succeeded = owner.publish(&mut port).await.transport_succeeded();
        self.trace.push(Event::Published {
            control: snapshot.control,
            succeeded,
        });
        succeeded
    }
    fn start_post_action_tasks(&mut self) {
        self.trace.push(Event::Session("post action"));
    }
    fn csi_filter_outbound(&mut self, item: OutboundItem) -> Option<OutboundItem> {
        self.trace.push(Event::Csi(ItemFacts::new(&item)));
        Some(item)
    }
    async fn record_outbound(&mut self, stanza: &str) -> Result<()> {
        self.trace.push(Event::RecordStanza(stanza.to_owned()));
        anyhow::ensure!(
            !*self.reject_stanza_record.lock().unwrap(),
            "recorded stanza failure"
        );
        Ok(())
    }
    fn record_replayed(&self) {
        self.trace.push(Event::Session("replayed"));
    }
    fn record_bosh_session_closed(&self) {
        self.trace.push(Event::Session("closed"));
    }
    fn record_backpressure_disconnect(&self) {
        self.trace.push(Event::Session("backpressure"));
    }
    fn forbid_sm_resume(&mut self) {
        self.trace.push(Event::Session("forbid resume"));
    }
    fn has_sm_session(&self) -> bool {
        self.trace.push(Event::Read("has SM session"));
        false
    }
    async fn checkpoint_sm(&mut self) -> Result<()> {
        panic!("no SM session was installed");
    }
    async fn finalize(&mut self) {
        self.trace.push(Event::Session("finalize"));
    }
}

impl Drop for RecordingSession {
    fn drop(&mut self) {
        self.trace.push(Event::Session("session dropped"));
    }
}
