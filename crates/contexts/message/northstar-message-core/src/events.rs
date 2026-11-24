use northstar_time::{DateTime, Utc};
use uuid::Uuid;

/// Time and stanza identities supplied at the message handler boundary.
pub trait MessageEventSource: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
    fn new_stanza_id(&self) -> Uuid;
}
