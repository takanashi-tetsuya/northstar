//! A route item for tests that have no transport.

use northstar_delivery_core::DurableDelivery;
use northstar_message_core::route_item::RouteItem;

pub(crate) struct TestItem {
    pub(crate) stanza: String,
    delivery: Option<DurableDelivery>,
}
impl RouteItem for TestItem {
    fn plain(stanza: String) -> Self {
        Self {
            stanza,
            delivery: None,
        }
    }
    fn durable(stanza: String, delivery: DurableDelivery) -> Self {
        Self {
            stanza,
            delivery: Some(delivery),
        }
    }
    fn stanza(&self) -> &str {
        &self.stanza
    }
    fn c2s_delivery(&self) -> Option<DurableDelivery> {
        self.delivery
    }
    fn validate_durable_source_shape(&self) -> bool {
        true
    }
}
