//! The protocol session as this context sees it: the impls of this crate's session ports for
//! `northstar_stream::protocol::ProtocolSession`.

use crate::ports::{MixFrameObserver, MixHost, MixSession, MixSessionUser};
use dashmap::DashSet;
use northstar_stream::protocol::{ProtocolSession, SessionHost};
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

// From src/xmpp/protocol/mix.rs.
impl<H: SessionHost + MixHost> MixSession for ProtocolSession<H> {
    type Host = H;

    fn host(&self) -> &Arc<H> {
        self.host()
    }

    fn user(&self) -> Option<MixSessionUser<'_>> {
        self.authenticated.as_ref().map(|user| MixSessionUser {
            id: user.id,
            username: &user.username,
        })
    }

    fn full_jid(&self) -> Option<&str> {
        self.full_jid.as_deref()
    }

    fn connection_id(&self) -> Uuid {
        self.connection_id
    }

    fn mix_presence_gate(&self) -> &Arc<Mutex<()>> {
        &self.presence.mix_presence_gate
    }

    fn mix_presence_fallback_suppressed(&self) -> &DashSet<String> {
        &self.presence.mix_presence_fallback_suppressed
    }

    fn frame_observer(&self) -> &dyn MixFrameObserver {
        &self.frame_executions
    }
}
