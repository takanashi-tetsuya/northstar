//! Live session and cluster transport for application-owned Carbon fanout.

use crate::node::{OnlineSession, ServerNode};
use anyhow::Result;
use northstar_message_application::message_carbons::{
    CarbonDeliveryPort, CarbonExclusion, CarbonExclusions, CarbonFanout, Direction,
};
use northstar_message_application::messaging::ExactMessageRoute;
use northstar_message_xmpp::ports::MessageHost;
use northstar_roster_application::privacy::PrivacyStanzaKind;
use northstar_xmpp_types::jid::CanonicalJid;
use std::sync::atomic::Ordering;
use uuid::Uuid;

impl CarbonDeliveryPort for ServerNode {
    type Session = OnlineSession;

    fn enabled(&self) -> bool {
        self.config
            .xmpp_extension_enabled(northstar_xep_0280::XEP_ID)
    }

    fn sessions(&self, bare: &str) -> Vec<(String, Self::Session)> {
        self.session.live().sessions().session_entries_for(bare)
    }

    fn carbon_enabled(&self, session: &Self::Session) -> bool {
        session.carbons.load(Ordering::Acquire)
    }

    fn in_muc_scope(&self, session: &Self::Session, room: &str, nick: &str) -> bool {
        session.joined_muc_as(room, nick)
    }

    fn wrap(&self, direction: Direction, from: &str, to: &str, forwarded: &str) -> Option<String> {
        northstar_message_core::validation::carbon_message(direction.as_str(), from, to, forwarded)
    }

    async fn privacy_allows(
        &self,
        session: &Self::Session,
        peer: &str,
        kind: PrivacyStanzaKind,
    ) -> Result<bool> {
        self.privacy_allows_session(session, peer, kind).await
    }

    async fn enqueue(&self, session: &Self::Session, stanza: String) -> bool {
        session.sender.send(stanza).await.is_ok()
    }

    fn local_route(&self, jid: &str, session: &Self::Session) -> Option<ExactMessageRoute> {
        Some(ExactMessageRoute {
            full_jid: jid.to_owned(),
            account_id: session.user_id,
            auth_generation: session.auth_generation,
            connection_id: session.connection_id,
            node_id: None,
            priority: None,
            available: None,
        })
    }

    async fn enqueue_captured(
        &self,
        route: Option<&ExactMessageRoute>,
        session: &Self::Session,
        stanza: String,
        request: CarbonFanout<'_>,
        peer: &str,
    ) -> Result<bool> {
        let Some(route) = route else {
            return Ok(false);
        };
        let table = self.session.live().sessions();
        let active_list = session.privacy_active_snapshot();
        Ok(session.sender.send_if_current(stanza, || {
            table.with_exact_carbon_route(route, request.muc_scope, |current| {
                current.privacy_active_snapshot() == active_list
            }) == Some(true)
        }, async {
            match self.message.message_service().allows_carbon_on_route(
                route, active_list.as_deref(), peer,
            ).await {
                Ok(allowed) => allowed,
                Err(error) => {
                    tracing::warn!(?error, target_jid = %route.full_jid, "privacy policy failed closed for a local Carbon");
                    false
                }
            }
        }).await?)
    }

    async fn capture_remote(
        &self,
        bare: &str,
        account_id: Option<Uuid>,
        exclusions: CarbonExclusions<'_>,
        _muc_scope: Option<(&str, &str)>,
    ) -> Vec<ExactMessageRoute> {
        if !self.cluster.is_enabled() {
            return Vec::new();
        }
        match self
            .capture_remote_carbon_routes(bare, account_id, exclusions)
            .await
        {
            Ok(routes) => routes,
            Err(error) => {
                self.delivery_failed();
                tracing::warn!(%bare, ?error, "cluster Carbon audience lookup failed after primary acceptance");
                Vec::new()
            }
        }
    }

    async fn route_captured_remote(&self, request: CarbonFanout<'_>, routes: &[ExactMessageRoute]) {
        let telemetry = self.personal_message_telemetry();
        match request.direction {
            Direction::Sent => {
                self.cluster
                    .route_sent_carbons_to_remote_resources(
                        request.bare,
                        request.forwarded,
                        routes,
                        request.muc_scope,
                        &telemetry,
                    )
                    .await
            }
            Direction::Received => {
                self.cluster
                    .route_received_carbons_to_remote_resources(
                        request.bare,
                        request.forwarded,
                        routes,
                        &telemetry,
                    )
                    .await
            }
        }
    }

    fn delivery_failed(&self) {
        self.personal_message_telemetry().carbon_delivery_failed();
    }

    fn target_timed_out(&self) {
        self.personal_message_telemetry().carbon_target_timed_out();
    }
}

impl ServerNode {
    async fn capture_remote_carbon_routes(
        &self,
        bare: &str,
        account_id: Option<Uuid>,
        exclusions: CarbonExclusions<'_>,
    ) -> Result<Vec<ExactMessageRoute>> {
        let account = if let Some(id) = account_id {
            northstar_auth_postgres::users::find_enabled_user_by_id(&self.pool, id).await?
        } else {
            let bare = CanonicalJid::parse_bare(bare)?;
            let Some(username) = bare.localpart() else {
                return Ok(Vec::new());
            };
            northstar_auth_postgres::users::find_enabled_user(&self.pool, username).await?
        };
        let Some(account) = account else {
            return Ok(Vec::new());
        };
        if matches!(exclusions.origin, Some(CarbonExclusion::Exact(origin)) if origin.auth_generation != account.auth_generation)
        {
            return Ok(Vec::new());
        }
        let mut routes = self
            .cluster
            .capture_remote_message_routes(bare, account.id, account.auth_generation)
            .await?;
        // Remote opt-in is not sampled here: the owning node checks the named
        // connection's Carbons flag immediately before its queue.
        routes.retain(|route| !exclusions.excludes(&route.full_jid, Some(route)));
        Ok(routes)
    }
}
