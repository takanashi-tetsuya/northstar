use super::ServerNode;
use northstar_roster_xmpp::SubscriptionRetryWake;

impl SubscriptionRetryWake for ServerNode {
    fn wake_subscription_retry(&self, domain: &str) {
        self.federation
            .federation_outbox
            .wake_admitted_route(domain);
    }
}
