//! The client session as the roster context's handlers see it.

use super::{ProtocolSession, SessionHost};
use northstar_roster_core::PresenceAccount;

impl<H: SessionHost> northstar_roster_xmpp::SessionIdentity for ProtocolSession<H> {
    fn session_account(&self) -> Option<PresenceAccount> {
        self.authenticated.as_ref().map(|user| PresenceAccount {
            id: user.id,
            username: user.username.clone(),
            auth_generation: user.auth_generation,
        })
    }

    fn session_local_domain(&self) -> &str {
        self.host.local_domain()
    }
}
