//! Personal-message route ports over the local session table and the cluster routes.

use super::{AppState, OnlineSession};
use anyhow::Result;
use northstar_message_application::messaging::{
    DirectMessageRoutePort, FullJidFallbackPort, OnlineRoutePort, OnlineRouteResult,
};
use northstar_roster_application::privacy::PrivacyStanzaKind;
use northstar_stream::outbound::DurableDelivery;
use std::sync::atomic::Ordering;
use uuid::Uuid;

impl OnlineRoutePort for AppState {
    type Item = northstar_stream::outbound::OutboundItem;
    type Session = OnlineSession;

    fn try_local(
        &self,
        session: &Self::Session,
        enqueue: northstar_stream::outbound::RouteEnqueue,
    ) -> Result<(), northstar_stream::outbound::RouteSendError> {
        session.sender.try_send_route_item(enqueue)
    }

    fn record_local_accept(&self, durable: bool) {
        self.personal_message_telemetry()
            .online_queue_result(true, durable);
    }

    async fn route_available_remote(
        &self,
        jid: &str,
        stanza: &str,
        delivery: Option<DurableDelivery>,
    ) -> bool {
        self.cluster()
            .route_personal_message_to_available_remote_resources(jid, stanza, delivery)
            .await
    }

    async fn route_remote_primary(
        &self,
        jid: &str,
        stanza: &str,
        delivery: Option<DurableDelivery>,
    ) -> OnlineRouteResult {
        self.cluster()
            .route_personal_message_to_remote_primary(
                jid,
                stanza,
                delivery,
                &self.personal_message_telemetry(),
            )
            .await
    }
}

impl FullJidFallbackPort for AppState {
    fn fallback_sessions(&self, bare: &str) -> Vec<(String, Self::Session)> {
        self.session_entries_for(bare)
    }

    fn available_priority(&self, session: &Self::Session) -> Option<i16> {
        if !session.available.load(Ordering::Relaxed) {
            return None;
        }
        let priority = session.priority.load(Ordering::Relaxed);
        (priority >= 0).then_some(priority)
    }

    fn priority(&self, session: &Self::Session) -> i16 {
        session.priority.load(Ordering::Relaxed)
    }

    async fn privacy_allows_fallback(&self, session: &Self::Session, sender: &str) -> Result<bool> {
        self.privacy_allows_session(session, sender, PrivacyStanzaKind::Message)
            .await
    }

    fn post_accept_failed(&self) {
        self.personal_message_telemetry().post_accept_failed();
    }
}

impl DirectMessageRoutePort for AppState {
    fn direct_route_mode(&self) -> crate::cluster::DirectPostCommitMode {
        self.message_service().direct_mode()
    }

    fn clustered_direct_routes(&self) -> bool {
        self.message_service().clustered_direct_admission_enabled()
    }

    async fn rearm_direct_route(&self, delivery: DurableDelivery) {
        let mut claim_id = delivery.claim_id;
        self.message_service()
            .rearm_unrouted_live_direct(delivery.recipient_id, delivery.message_id, &mut claim_id)
            .await;
    }
}

/// An old cluster peer may acknowledge only with a delivered count. Accept a
/// positive receipt rather than risk duplicating a stanza in offline storage.
impl AppState {
    pub(crate) async fn wake_committed_direct_muc_invite(&self, operation_id: Uuid) -> Result<()> {
        self.muc_service()
            .wake_committed_operation(&self.cluster, operation_id)
            .await
    }
}
