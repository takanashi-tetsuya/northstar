//! XEP-0191 blocking commands.

use northstar_roster_application::blocking::{BlockingRepository, BlockingService};
use northstar_roster_application::blocking_mutation::CommittedBlockingChange;

mod command_host;
mod mutation;
mod presence;
mod push;
mod query;

pub use command_host::BlockingMutationHost;
pub use mutation::{block, unblock};
pub use query::blocklist;

/// What a client session provides to the XEP-0191 handlers.
pub trait BlockingSession: crate::SessionIdentity + BlockingMutationHost {
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
    /// Delivers presence to the exact audience captured by the commit.
    fn blocking_presence_change(
        &self,
        change: CommittedBlockingChange,
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
