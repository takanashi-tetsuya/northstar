use super::{DurableDelivery, RoutePort};
use crate::messaging::{DirectMessageRoutePort, ExactMessageRoutePort};
use northstar_message_core::DirectPostCommitMode;

impl DirectMessageRoutePort for RoutePort {
    fn direct_route_mode(&self) -> DirectPostCommitMode {
        DirectPostCommitMode::Live
    }

    fn clustered_direct_routes(&self) -> bool {
        false
    }

    async fn rearm_direct_route(&self, _: DurableDelivery) {
        unreachable!("route-only tests do not rearm reservations");
    }
}

impl ExactMessageRoutePort for RoutePort {}
