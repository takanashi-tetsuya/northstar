//! The session remote routing port, carried by authenticated S2S routes.

use super::AppState;
use northstar_session_application::RemoteRoutePort;

impl RemoteRoutePort for AppState {
    async fn send_volatile(
        &self,
        source_domain: &str,
        target_domain: &str,
        stanza: String,
    ) -> bool {
        crate::s2s::send_volatile_on_authenticated_route(self, source_domain, target_domain, stanza)
            .await
    }
}
