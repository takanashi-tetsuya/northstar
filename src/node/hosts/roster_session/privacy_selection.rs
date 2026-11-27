use crate::node::ServerNode;
use anyhow::Result;
use northstar_roster_application::privacy::PrivacySelectionOutcome;
use northstar_roster_core::RosterActor;
use northstar_roster_xmpp::privacy::PrivacySelectionHost;
use northstar_stream::protocol::{ProtocolSession, SessionSmHost};
use northstar_workflows::sm_repository::{activate_privacy_selection, PrivacySelectionCheckpoint};
use std::sync::{atomic::Ordering, Arc};

impl PrivacySelectionHost for ServerNode {
    async fn commit_privacy_selection(
        &self,
        session: &ProtocolSession<Self>,
        actor: &RosterActor,
        name: Option<&str>,
    ) -> Result<PrivacySelectionOutcome> {
        let checkpoint = session
            .sm
            .db_id
            .map(|session_id| PrivacySelectionCheckpoint {
                session_id,
                snapshot: (&session.sm_privacy_selection_snapshot()).into(),
                ttl_seconds: session.sm.resume_timeout_seconds,
                live_lease_seconds: self.sm_session_policy().live_lease_seconds,
            });
        activate_privacy_selection(&self.pool, actor, name, checkpoint).await
    }

    fn publish_privacy_selection(
        &self,
        session: &ProtocolSession<Self>,
        actor: &RosterActor,
        name: Option<&str>,
    ) -> bool {
        self.session
            .live()
            .sessions()
            .get(&actor.full_jid)
            .is_some_and(|route| {
                if route.connection_id != actor.connection_id
                    || route.user_id != actor.account_id
                    || route.auth_generation != actor.auth_generation
                    || !route.routable.load(Ordering::Acquire)
                    || route.lifecycle.load(Ordering::Acquire) != 0
                    || route.disconnect.is_cancelled()
                    || !Arc::ptr_eq(&route.privacy_active, &session.privacy_active)
                {
                    return false;
                }
                *route
                    .privacy_active
                    .write()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) = name.map(str::to_owned);
                !route.disconnect.is_cancelled() && route.lifecycle.load(Ordering::Acquire) == 0
            })
    }
}
