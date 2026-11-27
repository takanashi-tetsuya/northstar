use northstar_stream::protocol::{ProtocolSession, SessionHost};

/// Wakes the destination of an already committed subscription retry.
pub trait SubscriptionRetryWake {
    fn wake_subscription_retry(&self, domain: &str);
}

impl<H: SessionHost + crate::RosterSessionHost> SubscriptionRetryWake for ProtocolSession<H> {
    fn wake_subscription_retry(&self, domain: &str) {
        self.host().wake_subscription_retry(domain);
    }
}
