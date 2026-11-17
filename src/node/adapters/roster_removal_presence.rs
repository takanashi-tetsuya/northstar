//! Node-owned routes for roster-removal presence delivery.

use crate::node::ServerNode;
use anyhow::Result;
use northstar_roster_application::privacy::PrivacyStanzaKind;
use northstar_roster_core::ClusterPresenceAuthority;
use northstar_roster_xmpp::roster_push::RosterRemovalPresenceRoutes;
use northstar_stream::local_routes::session::OnlineSession;

impl RosterRemovalPresenceRoutes for ServerNode {
    fn removal_presence_sessions(&self, target_bare: &str) -> Vec<(String, OnlineSession)> {
        self.session
            .live()
            .sessions()
            .session_entries_for(target_bare)
    }

    async fn removal_presence_privacy_allows(
        &self,
        session: &OnlineSession,
        owner_bare: &str,
        kind: PrivacyStanzaKind,
    ) -> Result<bool> {
        self.privacy_allows_session(session, owner_bare, kind).await
    }

    async fn route_remote_removal_presence(
        &self,
        target_bare: &str,
        stanza: &str,
        authority: ClusterPresenceAuthority,
    ) {
        self.cluster
            .route_remote_roster_removal_presence(target_bare, stanza, authority)
            .await;
    }
}
