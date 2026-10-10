//! Federation-origin transport and telemetry capability for the shared direct
//! route owner. Admission, XML errors, history, Push and Carbons stay inbound.

use crate::{
    outbound::DurableDelivery,
    services::messaging::{
        DirectMessageRoutePort, FullJidFallbackPort, OnlineRoutePort, OnlineRouteResult,
    },
    state::{AppState, OnlineSession},
};
use anyhow::Result;

pub(super) struct S2sDirectRoutePort<'a>(pub(super) &'a AppState);

impl OnlineRoutePort for S2sDirectRoutePort<'_> {
    type Session = OnlineSession;

    fn try_local(
        &self,
        session: &Self::Session,
        enqueue: crate::outbound::RouteEnqueue,
    ) -> Result<(), crate::outbound::RouteSendError> {
        OnlineRoutePort::try_local(self.0, session, enqueue)
    }

    fn record_local_accept(&self, durable: bool) {
        self.0.s2s_online_queue_telemetry().accepted(durable);
    }

    async fn route_available_remote(
        &self,
        jid: &str,
        stanza: &str,
        delivery: Option<DurableDelivery>,
    ) -> bool {
        self.0
            .route_s2s_message_to_available_remote_resources(jid, stanza, delivery)
            .await
    }

    async fn route_remote_primary(
        &self,
        jid: &str,
        stanza: &str,
        delivery: Option<DurableDelivery>,
    ) -> OnlineRouteResult {
        let routed = self
            .0
            .route_s2s_message_to_remote_primary(jid, stanza, delivery)
            .await;
        OnlineRouteResult {
            delivered: routed.delivered,
            accepted_full_jid: routed.accepted_full_jid,
        }
    }
}

impl FullJidFallbackPort for S2sDirectRoutePort<'_> {
    fn fallback_sessions(&self, bare: &str) -> Vec<(String, Self::Session)> {
        FullJidFallbackPort::fallback_sessions(self.0, bare)
    }

    fn available_priority(&self, session: &Self::Session) -> Option<i16> {
        FullJidFallbackPort::available_priority(self.0, session)
    }

    fn priority(&self, session: &Self::Session) -> i16 {
        FullJidFallbackPort::priority(self.0, session)
    }

    async fn privacy_allows_fallback(&self, session: &Self::Session, sender: &str) -> Result<bool> {
        FullJidFallbackPort::privacy_allows_fallback(self.0, session, sender).await
    }

    fn post_accept_failed(&self) {
        self.0.s2s_inbound_delivery_telemetry().post_accept_failed();
    }
}

impl DirectMessageRoutePort for S2sDirectRoutePort<'_> {
    fn direct_route_mode(&self) -> crate::cluster::DirectPostCommitMode {
        DirectMessageRoutePort::direct_route_mode(self.0)
    }

    fn clustered_direct_routes(&self) -> bool {
        DirectMessageRoutePort::clustered_direct_routes(self.0)
    }

    async fn rearm_direct_route(&self, delivery: DurableDelivery) {
        DirectMessageRoutePort::rearm_direct_route(self.0, delivery).await;
    }
}
