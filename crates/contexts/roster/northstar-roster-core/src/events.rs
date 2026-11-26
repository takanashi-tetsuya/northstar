use northstar_time::{DateTime, Utc};
use uuid::Uuid;

/// Supplies time and protocol IDs for roster, presence and privacy effects.
pub trait RosterEventSource: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
    fn new_protocol_id(&self) -> Uuid;
}
