use northstar_message_core::MessageEventSource;
use northstar_time::{DateTime, Utc};
use uuid::Uuid;

pub struct SystemMessageEvents;

impl MessageEventSource for SystemMessageEvents {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }

    fn new_stanza_id(&self) -> Uuid {
        Uuid::new_v4()
    }
}
