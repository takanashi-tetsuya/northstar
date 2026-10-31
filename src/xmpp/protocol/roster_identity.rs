//! The client session as the roster context's handlers see it.

use super::ProtocolSession;
use northstar_roster_core::PresenceAccount;

impl northstar_roster_xmpp::SessionIdentity for ProtocolSession {
    fn session_account(&self) -> Option<PresenceAccount> {
        self.authenticated.as_ref().map(|user| PresenceAccount {
            id: user.id,
            username: user.username.clone(),
            auth_generation: user.auth_generation,
        })
    }

    fn session_local_domain(&self) -> &str {
        self.state.local_domain()
    }
}
