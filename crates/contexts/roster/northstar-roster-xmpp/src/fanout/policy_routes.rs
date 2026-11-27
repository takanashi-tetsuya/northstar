use northstar_stream::local_routes::session_table::LocalSessionTable;

pub trait PolicyPushLocalRoutes: Send + Sync {
    fn policy_sessions(&self) -> LocalSessionTable;
}
