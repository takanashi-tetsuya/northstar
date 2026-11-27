//! Node-owned routes for committed roster-context fan-out.

use crate::node::ServerNode;
use anyhow::Result;
use northstar_roster_xmpp::fanout::RosterFanoutRoutes;
use northstar_roster_xmpp::roster_push::RemoteRouteFailure;
use northstar_roster_xmpp::PostAcceptFailureTelemetry;
use northstar_stream::local_routes::session::OnlineSession;
use std::sync::Arc;

impl RosterFanoutRoutes for ServerNode {
    fn fanout_sessions(&self, jid: &str) -> Vec<(String, OnlineSession)> {
        self.session.live().sessions().session_entries_for(jid)
    }

    fn record_fanout_failure(&self) {
        PostAcceptFailureTelemetry::new(Arc::clone(
            &self.metrics.post_accept_side_effect_failures_total,
        ))
        .record_failure();
    }

    async fn remote_blocklist_push(
        &self,
        owner: &str,
        push: impl FnMut() -> String + Send,
    ) -> Result<Vec<RemoteRouteFailure>> {
        self.cluster
            .route_remote_blocklist_push(owner, push)
            .await
            .map(|failures| {
                failures
                    .into_iter()
                    .map(|failure| RemoteRouteFailure {
                        node_id: failure.node_id,
                        error: failure.error,
                    })
                    .collect()
            })
    }

    async fn remote_privacy_push(
        &self,
        account: &str,
        base: &str,
    ) -> Result<Vec<RemoteRouteFailure>> {
        self.cluster
            .route_remote_privacy_push(account, base)
            .await
            .map(|failures| {
                failures
                    .into_iter()
                    .map(|failure| RemoteRouteFailure {
                        node_id: failure.node_id,
                        error: failure.error,
                    })
                    .collect()
            })
    }
}
