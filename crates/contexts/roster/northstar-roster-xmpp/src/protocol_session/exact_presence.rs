use crate::exact_presence::{ExactPresenceHost, ExactPresenceSession};
use crate::RosterSessionHost;
use northstar_stream::protocol::{ProtocolSession, SessionHost};

impl<H: SessionHost + RosterSessionHost> ExactPresenceSession for ProtocolSession<H> {
    fn exact_presence_host(&self) -> &impl ExactPresenceHost {
        self.host().as_ref()
    }
}
