//! The transports' view of a protocol session.

use super::ProtocolSession;
use northstar_stream::auth_publication::OwnedPublication;
use northstar_stream::frame_execution::FrameFailure;
use northstar_stream::outbound::OutboundItem;
use northstar_stream::session::StreamSession;
use northstar_stream::transport::{Action, SessionTerminationSignals, TlsSessionEvidence};
use std::{future::Future, net::IpAddr, time::Instant};
use uuid::Uuid;

impl StreamSession for ProtocolSession {
    fn connection_id(&self) -> Uuid {
        self.connection_id
    }

    fn peer_ip(&self) -> IpAddr {
        self.peer_ip
    }

    fn local_domain(&self) -> &str {
        ProtocolSession::local_domain(self)
    }

    fn is_stream_open(&self) -> bool {
        ProtocolSession::is_stream_open(self)
    }

    fn is_authenticated(&self) -> bool {
        ProtocolSession::is_authenticated(self)
    }

    fn sasl2_in_progress(&self) -> bool {
        self.sasl2_state.is_some()
    }

    fn unauthenticated_timed_out(&self, now: Instant) -> bool {
        ProtocolSession::unauthenticated_timed_out(self, now)
    }

    fn resource_bind_deadline(&self) -> Option<Instant> {
        ProtocolSession::resource_bind_deadline(self)
    }

    fn termination_signals(&self) -> SessionTerminationSignals {
        ProtocolSession::termination_signals(self)
    }

    fn features(&self) -> String {
        ProtocolSession::features(self)
    }

    fn capture_stream_from(&mut self, opening: &str) -> Result<(), &'static str> {
        ProtocolSession::capture_stream_from(self, opening).map_err(|error| error.condition())
    }

    fn activate_tls(&mut self, evidence: TlsSessionEvidence) {
        ProtocolSession::activate_tls(self, evidence);
    }

    fn process_frame(
        &mut self,
        frame: &str,
    ) -> impl Future<Output = Result<Action, FrameFailure>> + Send {
        ProtocolSession::process_frame(self, frame)
    }

    fn publish_committed_authentication_and_route(
        &mut self,
        owner: OwnedPublication,
    ) -> impl Future<Output = bool> + Send {
        ProtocolSession::publish_committed_authentication_and_route(self, owner)
    }

    fn start_post_action_tasks(&mut self) {
        ProtocolSession::start_post_action_tasks(self);
    }

    fn csi_filter_outbound(&mut self, item: OutboundItem) -> Option<OutboundItem> {
        ProtocolSession::csi_filter_outbound(self, item)
    }

    fn record_outbound(&mut self, stanza: &str) -> impl Future<Output = anyhow::Result<()>> + Send {
        ProtocolSession::record_outbound(self, stanza)
    }

    fn record_replayed(&self) {
        ProtocolSession::record_replayed(self);
    }

    fn record_bosh_session_closed(&self) {
        ProtocolSession::record_bosh_session_closed(self);
    }

    fn record_backpressure_disconnect(&self) {
        ProtocolSession::record_backpressure_disconnect(self);
    }

    fn forbid_sm_resume(&mut self) {
        ProtocolSession::forbid_sm_resume(self);
    }

    fn has_sm_session(&self) -> bool {
        ProtocolSession::has_sm_session(self)
    }

    fn checkpoint_sm(&mut self) -> impl Future<Output = anyhow::Result<()>> + Send {
        ProtocolSession::checkpoint_sm(self)
    }

    async fn finalize(&mut self) {
        ProtocolSession::finalize(self).await;
    }
}
