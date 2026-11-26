//! XEP-0191 blocking commands.

use northstar_roster_application::blocking::{BlockingRepository, BlockingService};

mod mutation;
mod presence;
mod push;
mod query;

pub use mutation::{block, unblock};
pub use query::blocklist;

/// What a client session provides to the XEP-0191 handlers.
pub trait BlockingSession: crate::SessionIdentity {
    /// The blocking service, over the repository the composition root binds.
    fn blocking_service(&self) -> &BlockingService<impl BlockingRepository>;
    /// Records that this session asked for the blocklist, which makes it a target of later pushes.
    fn blocking_mark_requested(&self);
    /// Delivers the XEP-0191 `payload` as a push to every resource of `owner` that asked for the
    /// blocklist, on this node and on the others.
    fn blocking_push_change(
        &self,
        owner: &str,
        payload: &str,
    ) -> impl std::future::Future<Output = ()> + Send;
    /// Runs the polite-blocking presence transition of `owner`'s resources towards `targets` and
    /// towards the directed-presence peers `changed_patterns` match, on this node and on the
    /// others. `available` says whether the patterns were unblocked.
    fn blocking_presence_change(
        &self,
        owner: &str,
        targets: &[String],
        changed_patterns: &[String],
        available: bool,
    ) -> impl std::future::Future<Output = ()> + Send;
}

#[cfg(test)]
mod tests {
    use super::push::blocking_change_payload;

    #[test]
    fn blocking_values_cannot_escape_the_structural_builder() {
        let payload =
            blocking_change_payload("block", &["mallory@example.test/'/><injected/>".to_owned()])
                .unwrap();
        let document = roxmltree::Document::parse(&payload).unwrap();
        let root = document.root_element();
        let item = root.children().find(|node| node.is_element()).unwrap();
        assert_eq!(root.tag_name().name(), "block");
        assert_eq!(root.tag_name().namespace(), Some("urn:xmpp:blocking"));
        assert_eq!(
            item.attribute("jid"),
            Some("mallory@example.test/'/><injected/>")
        );
        assert_eq!(root.children().filter(|node| node.is_element()).count(), 1);
    }
}
