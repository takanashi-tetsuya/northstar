use anyhow::Result;
use northstar_roster_core::ExactPresenceRoute;
use northstar_stream::local_routes::session::OnlineSession;
use std::future::Future;
use uuid::Uuid;

/// Captures remote routes and pins a local entry through its roster queue handoff.
pub trait RosterPushRoutes {
    fn with_local_roster_session<T>(
        &self,
        full_jid: &str,
        handoff: impl FnOnce(&OnlineSession) -> T,
    ) -> Option<T>;

    fn capture_remote_roster_routes(
        &self,
        account: &str,
        owner: (Uuid, i64),
    ) -> impl Future<Output = Result<Vec<ExactPresenceRoute>>> + Send;
}
