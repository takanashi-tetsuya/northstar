use northstar_roster_core::RosterEventSource;
use northstar_time::{DateTime, Utc};
use uuid::Uuid;

/// Uses the system UTC clock and random version 4 protocol IDs.
pub struct SystemRosterEvents;

impl RosterEventSource for SystemRosterEvents {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }

    fn new_protocol_id(&self) -> Uuid {
        Uuid::new_v4()
    }
}
