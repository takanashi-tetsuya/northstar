use super::LocalSessionTable;
use northstar_message_application::messaging::ExactMessageRoute;
use std::sync::atomic::Ordering;

impl LocalSessionTable {
    /// A carbon preference is session-local and must be visible to fan-out
    /// before its IQ result is sent to the same connection.
    pub fn set_local_carbons_for_connection(
        &self,
        key: &str,
        connection_id: uuid::Uuid,
        enabled: bool,
    ) -> bool {
        let Some(route) = self.0.get(key) else {
            return false;
        };
        if route.connection_id != connection_id {
            return false;
        }
        route.carbons.store(enabled, Ordering::Release);
        true
    }

    pub fn with_exact_carbon_route<T>(
        &self,
        route: &ExactMessageRoute,
        muc_scope: Option<(&str, &str)>,
        accept: impl FnOnce(&super::OnlineSession) -> T,
    ) -> Option<T> {
        self.with_exact_message_route(route, |session| {
            (muc_scope.is_none_or(|(room, nick)| session.joined_muc_as(room, nick))
                && session.carbons.load(Ordering::Acquire))
            .then(|| accept(session))
        })
        .flatten()
    }
}
