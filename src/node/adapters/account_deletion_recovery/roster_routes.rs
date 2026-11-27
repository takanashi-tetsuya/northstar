use super::{OnlineSession, RosterPushDeliveryAdapters};
use anyhow::Result;
use northstar_roster_core::ExactPresenceRoute;
use northstar_roster_xmpp::roster_push::RosterPushRoutes;
use uuid::Uuid;

impl RosterPushRoutes for RosterPushDeliveryAdapters {
    fn with_local_roster_session<T>(
        &self,
        full_jid: &str,
        handoff: impl FnOnce(&OnlineSession) -> T,
    ) -> Option<T> {
        self.sessions
            .get(full_jid)
            .map(|session| handoff(session.value()))
    }

    async fn capture_remote_roster_routes(
        &self,
        account: &str,
        (owner_id, generation): (Uuid, i64),
    ) -> Result<Vec<ExactPresenceRoute>> {
        Ok(self
            .cluster
            .capture_remote_message_routes(account, owner_id, generation)
            .await?
            .into_iter()
            .map(|route| ExactPresenceRoute {
                account_id: route.account_id,
                auth_generation: route.auth_generation,
                connection_id: route.connection_id,
                full_jid: route.full_jid,
                node_id: route.node_id,
            })
            .collect())
    }
}
