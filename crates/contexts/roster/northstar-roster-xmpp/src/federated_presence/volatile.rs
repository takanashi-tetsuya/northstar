use std::future::Future;

/// Sends a post-commit revocation without storing it for retry.
pub trait SubscriptionRevocationRoute: Sync {
    fn send_volatile_subscription_revocation(
        &self,
        verified_peer: &str,
        stanza: String,
    ) -> impl Future<Output = bool> + Send;
}
