use super::{FullJidFallbackPort, OnlineRouteResult};
use northstar_delivery_core::DurableDelivery;
use northstar_message_core::route_item::{RouteEnqueue, RouteSendError};
use std::future::Future;
use uuid::Uuid;

/// A sampled transport, not permission to route to a later holder of the JID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExactMessageRoute {
    pub full_jid: String,
    pub account_id: Uuid,
    pub auth_generation: i64,
    pub connection_id: Uuid,
    pub node_id: Option<String>,
    pub priority: Option<i16>,
    pub available: Option<bool>,
}

pub trait ExactMessageRoutePort: FullJidFallbackPort {
    /// None means the port does not offer clustered ranking; an empty capture
    /// does not fall back to discovering a new remote audience.
    fn capture_remote_message_routes(
        &self,
        _jid: &str,
        _recipient_id: Uuid,
    ) -> impl Future<Output = Option<Vec<ExactMessageRoute>>> + Send {
        std::future::ready(None)
    }

    fn route_exact_remote_primary(
        &self,
        _jid: &str,
        _route: &ExactMessageRoute,
        _stanza: &str,
        _delivery: Option<DurableDelivery>,
    ) -> impl Future<Output = OnlineRouteResult> + Send {
        std::future::ready(OnlineRouteResult::default())
    }

    fn try_direct_local(
        &self,
        _full_jid: &str,
        _recipient_id: Uuid,
        session: &Self::Session,
        enqueue: RouteEnqueue<Self::Item>,
    ) -> Result<(), RouteSendError<Self::Item>> {
        self.try_local(session, enqueue)
    }

    fn route_direct_remote(
        &self,
        _recipient_id: Uuid,
        jid: &str,
        _excluded_full_jids: &[&str],
        stanza: &str,
        delivery: Option<DurableDelivery>,
        deliver_all: bool,
    ) -> impl Future<Output = OnlineRouteResult> + Send {
        async move {
            if deliver_all {
                OnlineRouteResult {
                    delivered: self.route_available_remote(jid, stanza, delivery).await,
                    accepted_full_jid: None,
                }
            } else {
                self.route_remote_primary(jid, stanza, delivery).await
            }
        }
    }
}
