//! What a transport may ask of the protocol session it carries. TCP, direct TLS, WebSocket and BOSH
//! drive a session only through this trait: they open its stream, feed it frames, apply the
//! [`Action`] it returns, record what they write for stream management and finalize it when the
//! connection ends. Authentication, routing and every context behind the session stay hidden.

use crate::auth_publication::OwnedPublication;
use crate::frame_execution::FrameFailure;
use crate::outbound::OutboundItem;
use crate::transport::{Action, SessionTerminationSignals, TlsSessionEvidence};
use std::{future::Future, net::IpAddr, time::Instant};
use uuid::Uuid;

pub trait StreamSession: Send {
    /// The connection this session belongs to.
    fn connection_id(&self) -> Uuid;

    /// The client address, for logs.
    fn peer_ip(&self) -> IpAddr;

    /// The served domain, for stream headers and stream errors.
    fn local_domain(&self) -> &str;

    /// Transports may inspect the stream state; only protocol handling changes it.
    fn is_stream_open(&self) -> bool;

    fn is_authenticated(&self) -> bool;

    /// XEP-0388 forbids whitespace keepalives while a SASL2 exchange is in progress.
    fn sasl2_in_progress(&self) -> bool;

    /// The authentication clock belongs to the session; the transport decides how to close.
    fn unauthenticated_timed_out(&self, now: Instant) -> bool;

    fn resource_bind_deadline(&self) -> Option<Instant>;

    fn termination_signals(&self) -> SessionTerminationSignals;

    /// The current `<stream:features/>` element.
    fn features(&self) -> String;

    /// Checks the addressing of a stream header the transport synthesised; the error is the
    /// stream error condition.
    fn capture_stream_from(&mut self, opening: &str) -> Result<(), &'static str>;

    fn activate_tls(&mut self, evidence: TlsSessionEvidence);

    /// Runs one complete frame under its frame execution.
    fn process_frame(
        &mut self,
        frame: &str,
    ) -> impl Future<Output = Result<Action, FrameFailure>> + Send;

    /// Publishes a committed authentication once the transport wrote its final control; the
    /// session's route goes live only then. False means the transport must close the stream.
    fn publish_committed_authentication_and_route(
        &mut self,
        owner: OwnedPublication,
    ) -> impl Future<Output = bool> + Send;

    /// Starts the work an action deferred until the transport had applied it.
    fn start_post_action_tasks(&mut self);

    /// Applies the client state indication to transient outbound traffic.
    fn csi_filter_outbound(&mut self, item: OutboundItem) -> Option<OutboundItem>;

    /// Records a stanza for stream management before the transport writes it.
    fn record_outbound(&mut self, stanza: &str) -> impl Future<Output = anyhow::Result<()>> + Send;

    fn record_replayed(&self);

    fn record_bosh_session_closed(&self);

    fn record_backpressure_disconnect(&self);

    /// A fatal or explicit terminal outcome leaves the connection ineligible for resumption.
    fn forbid_sm_resume(&mut self);

    fn has_sm_session(&self) -> bool;

    fn checkpoint_sm(&mut self) -> impl Future<Output = anyhow::Result<()>> + Send;

    /// Releases the session's routes and runs its cleanup; the transport only awaits it.
    fn finalize(&mut self) -> impl Future<Output = ()> + Send;
}
