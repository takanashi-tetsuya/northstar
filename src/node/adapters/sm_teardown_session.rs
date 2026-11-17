//! Exact local and cluster session fencing for durable SM teardown.

use crate::node::{OnlineSession, ServerNode};
use dashmap::DashMap;
use northstar_cluster::ClusterSmSessionTeardownNotifier;
use northstar_stream::local_routes::session_table::{fence_local_session_in, LocalSessionFence};
use std::sync::Arc;
use uuid::Uuid;

pub(in crate::node) struct SmTeardownSessionEffects {
    sessions: Arc<DashMap<String, OnlineSession>>,
    notifier: ClusterSmSessionTeardownNotifier,
}

impl ServerNode {
    pub(in crate::node) fn sm_teardown_session_effects(&self) -> SmTeardownSessionEffects {
        SmTeardownSessionEffects {
            sessions: Arc::clone(self.session.live().sessions()),
            notifier: self.cluster.sm_session_teardown_notifier(),
        }
    }
}

impl SmTeardownSessionEffects {
    pub(in crate::node) async fn fence_and_notify(
        &self,
        full_jid: &str,
        sm_session_id: Uuid,
    ) -> anyhow::Result<()> {
        fence_local_session_in(
            &self.sessions,
            full_jid,
            LocalSessionFence::Sm(sm_session_id),
        );
        self.notifier
            .send_sm_session_teardown(full_jid, sm_session_id)
            .await
    }
}
