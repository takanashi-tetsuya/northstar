//! Exact local and cluster session fencing for durable SM teardown.

use super::{AppState, OnlineSession};
use crate::cluster::ClusterSmSessionTeardownNotifier;
use dashmap::DashMap;
use std::sync::{atomic::Ordering, Arc};
use uuid::Uuid;

pub(super) struct SmTeardownSessionEffects {
    sessions: Arc<DashMap<String, OnlineSession>>,
    notifier: ClusterSmSessionTeardownNotifier,
}

impl AppState {
    pub(super) fn sm_teardown_session_effects(&self) -> SmTeardownSessionEffects {
        SmTeardownSessionEffects {
            sessions: Arc::clone(&self.sessions),
            notifier: self.cluster.sm_session_teardown_notifier(),
        }
    }
}

impl SmTeardownSessionEffects {
    pub(super) async fn fence_and_notify(
        &self,
        full_jid: &str,
        sm_session_id: Uuid,
    ) -> anyhow::Result<()> {
        if let Some(session) = self.sessions.get_mut(full_jid) {
            let matches = *session
                .sm_session_id
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                == Some(sm_session_id);
            if matches {
                session.routable.store(false, Ordering::Release);
                session.disconnect.cancel();
            }
        }
        self.notifier
            .send_sm_session_teardown(full_jid, sm_session_id)
            .await
    }
}
