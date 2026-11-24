use crate::ports::FederatedMessageHost;
use anyhow::Result;
use northstar_message_application::messaging::{
    DirectMessageRoutePort, FullJidFallbackPort, OnlineRoutePort, OnlineRouteResult,
};
use northstar_message_core::DirectPostCommitMode;
use northstar_stream::local_routes::session::OnlineSession;
use northstar_stream::outbound::{DurableDelivery, OutboundItem};

/// Federation-origin transport and telemetry for the shared direct route owner. Admission, XML errors, history,
/// Push and Carbons stay in this module.
pub(super) struct FederatedDirectRoute<'a, H>(pub(super) &'a H);

impl<H: FederatedMessageHost> OnlineRoutePort for FederatedDirectRoute<'_, H> {
    type Item = OutboundItem;
    type Session = OnlineSession;

    fn try_local(
        &self,
        session: &Self::Session,
        enqueue: northstar_stream::outbound::RouteEnqueue,
    ) -> Result<(), northstar_stream::outbound::RouteSendError> {
        OnlineRoutePort::try_local(self.0, session, enqueue)
    }

    fn record_local_accept(&self, durable: bool) {
        self.0.record_s2s_online_accept(durable);
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
        self.0
            .route_s2s_message_to_remote_primary(jid, stanza, delivery)
            .await
    }
}

impl<H: FederatedMessageHost> FullJidFallbackPort for FederatedDirectRoute<'_, H> {
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
        self.0.record_s2s_post_accept_failure();
    }
}

impl<H: FederatedMessageHost> DirectMessageRoutePort for FederatedDirectRoute<'_, H> {
    fn direct_route_mode(&self) -> DirectPostCommitMode {
        DirectMessageRoutePort::direct_route_mode(self.0)
    }

    fn clustered_direct_routes(&self) -> bool {
        DirectMessageRoutePort::clustered_direct_routes(self.0)
    }

    async fn rearm_direct_route(&self, delivery: DurableDelivery) {
        DirectMessageRoutePort::rearm_direct_route(self.0, delivery).await;
    }
}
