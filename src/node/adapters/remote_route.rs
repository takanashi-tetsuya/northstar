//! The session remote routing port, carried by authenticated S2S routes.

use crate::node::ServerNode;
use northstar_session_application::RemoteRoutePort;

impl RemoteRoutePort for ServerNode {
    async fn send_volatile(
        &self,
        source_domain: &str,
        target_domain: &str,
        stanza: String,
    ) -> bool {
        northstar_s2s::outbound::send_volatile_on_authenticated_route(
            self,
            source_domain,
            target_domain,
            stanza,
        )
        .await
    }
}
