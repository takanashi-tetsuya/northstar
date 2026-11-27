//! Personal-message route ports over the local session table and the cluster routes.

use crate::node::{OnlineSession, ServerNode};
use anyhow::Result;
use northstar_message_application::messaging::{
    DirectMessageRoutePort, ExactMessageRoute, ExactMessageRoutePort, FullJidFallbackPort,
    OnlineRoutePort, OnlineRouteResult, ResourceStanzaPolicy,
};
use northstar_message_core::route_item::QueueRefusal;
use northstar_message_xmpp::ports::MessageHost;
use northstar_stream::outbound::DurableDelivery;
use northstar_xep_0016::PrivacyStanzaKind;
use std::sync::atomic::Ordering;
use uuid::Uuid;

impl OnlineRoutePort for ServerNode {
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
        self.cluster
            .route_personal_message_to_available_remote_resources(jid, stanza, delivery)
            .await
    }

    async fn route_remote_primary(
        &self,
        jid: &str,
        stanza: &str,
        delivery: Option<DurableDelivery>,
    ) -> OnlineRouteResult {
        self.cluster
            .route_personal_message_to_remote_primary(
                jid,
                stanza,
                delivery,
                &self.personal_message_telemetry(),
            )
            .await
    }
}

impl FullJidFallbackPort for ServerNode {
    fn fallback_sessions(&self, bare: &str) -> Vec<(String, Self::Session)> {
        self.session.live().sessions().session_entries_for(bare)
    }

    fn available_priority(&self, session: &Self::Session) -> Option<i16> {
        session.available_priority()
    }

    fn priority(&self, session: &Self::Session) -> i16 {
        session.priority.load(Ordering::Relaxed)
    }

    async fn privacy_allows_fallback(&self, session: &Self::Session, sender: &str) -> Result<bool> {
        let active = session.privacy_active_snapshot();
        let allowed = self
            .message
            .message_service()
            .allows_resource_stanza(
                ResourceStanzaPolicy {
                    account: None,
                    account_id: session.user_id,
                    auth_generation: Some(session.auth_generation),
                    connection_id: session.connection_id,
                    expects_active: active.is_some(),
                    peer: sender,
                    kind: PrivacyStanzaKind::Message,
                },
                false,
            )
            .await?;
        Ok(allowed && session.privacy_active_snapshot() == active)
    }

    fn post_accept_failed(&self) {
        self.personal_message_telemetry().post_accept_failed();
    }
}

impl DirectMessageRoutePort for ServerNode {
    fn direct_route_mode(&self) -> northstar_cluster::DirectPostCommitMode {
        self.message.message_service().direct_mode()
    }

    fn clustered_direct_routes(&self) -> bool {
        self.message
            .message_service()
            .clustered_direct_admission_enabled()
    }

    async fn rearm_direct_route(&self, delivery: DurableDelivery) {
        let mut claim_id = delivery.claim_id;
        self.message
            .message_service()
            .rearm_unrouted_live_direct(delivery.recipient_id, delivery.message_id, &mut claim_id)
            .await;
    }
}

impl ExactMessageRoutePort for ServerNode {
    #[expect(
        clippy::result_large_err,
        reason = "return the exact refused outbound item"
    )]
    fn try_direct_local(
        &self,
        full_jid: &str,
        recipient_id: Uuid,
        session: &Self::Session,
        enqueue: northstar_stream::outbound::RouteEnqueue,
    ) -> Result<(), northstar_stream::outbound::RouteSendError> {
        if session.user_id != recipient_id {
            return enqueue.send_with(|item| Err(QueueRefusal::Closed(item)));
        }
        let (available, priority) = session.presence_route_state();
        self.session.live().sessions().try_send_exact_message_route(
            &ExactMessageRoute {
                full_jid: full_jid.to_owned(),
                account_id: session.user_id,
                auth_generation: session.auth_generation,
                connection_id: session.connection_id,
                node_id: None,
                priority: Some(priority),
                available: Some(available),
            },
            enqueue,
        )
    }

    async fn capture_remote_message_routes(
        &self,
        jid: &str,
        recipient_id: Uuid,
    ) -> Option<Vec<ExactMessageRoute>> {
        if !self.cluster.is_enabled() {
            return None;
        }
        let Ok(Some(account)) =
            northstar_auth_postgres::users::find_enabled_user_by_id(&self.pool, recipient_id).await
        else {
            return Some(Vec::new());
        };
        Some(
            self.cluster
                .capture_remote_message_routes(jid, recipient_id, account.auth_generation)
                .await
                .unwrap_or_default(),
        )
    }

    async fn route_exact_remote_primary(
        &self,
        jid: &str,
        route: &ExactMessageRoute,
        stanza: &str,
        delivery: Option<DurableDelivery>,
    ) -> OnlineRouteResult {
        self.cluster
            .route_exact_remote_message(
                jid,
                std::slice::from_ref(route),
                stanza,
                delivery,
                false,
                &self.personal_message_telemetry(),
            )
            .await
    }

    async fn route_direct_remote(
        &self,
        recipient_id: Uuid,
        jid: &str,
        excluded_full_jids: &[&str],
        stanza: &str,
        delivery: Option<DurableDelivery>,
        deliver_all: bool,
    ) -> OnlineRouteResult {
        let Some(mut routes) = self.capture_remote_message_routes(jid, recipient_id).await else {
            return OnlineRouteResult::default();
        };
        routes.retain(|route| !excluded_full_jids.contains(&route.full_jid.as_str()));
        self.cluster
            .route_exact_remote_message(
                jid,
                &routes,
                stanza,
                delivery,
                deliver_all,
                &self.personal_message_telemetry(),
            )
            .await
    }
}

/// An old cluster peer may acknowledge only with a delivered count. Accept a
/// positive receipt rather than risk duplicating a stanza in offline storage.
impl ServerNode {
    pub(crate) async fn wake_committed_direct_muc_invite(&self, operation_id: Uuid) -> Result<()> {
        self.room
            .muc_service()
            .wake_committed_operation(&self.cluster, operation_id)
            .await
    }
}
