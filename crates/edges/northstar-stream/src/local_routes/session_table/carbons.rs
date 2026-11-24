use super::LocalSessionTable;
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
}
