//! Live session and cluster transport for application-owned Carbon fanout.

use super::{AppState, OnlineSession};
use crate::services::{
    message_carbons::{CarbonDeliveryPort, Direction},
    privacy::PrivacyStanzaKind,
};
use anyhow::Result;
use std::sync::atomic::Ordering;

impl CarbonDeliveryPort for AppState {
    type Session = OnlineSession;

    fn enabled(&self) -> bool {
        self.xmpp_extension_enabled(northstar_xep_0280::XEP_ID)
    }

    fn sessions(&self, bare: &str) -> Vec<(String, Self::Session)> {
        self.session_entries_for(bare)
    }

    fn carbon_enabled(&self, session: &Self::Session) -> bool {
        session.carbons.load(Ordering::Acquire)
    }

    fn in_muc_scope(&self, session: &Self::Session, room: &str, nick: &str) -> bool {
        session
            .muc_memberships
            .get(room)
            .is_some_and(|membership| membership.nick == nick)
    }

    fn wrap(&self, direction: Direction, from: &str, to: &str, forwarded: &str) -> Option<String> {
        crate::xmpp::xml_util::carbon_message(direction.as_str(), from, to, forwarded)
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

    async fn route_sent_remote(
        &self,
        bare: &str,
        forwarded: &str,
        current: &str,
        delivered_self: Option<&str>,
        muc_scope: Option<(&str, &str)>,
    ) {
        self.route_sent_carbons_to_remote_resources(
            bare,
            forwarded,
            current,
            delivered_self,
            muc_scope,
        )
        .await;
    }

    async fn route_received_remote(
        &self,
        recipient: &str,
        delivered: Option<&str>,
        forwarded: &str,
    ) {
        self.route_received_carbons_to_remote_resources(recipient, delivered, forwarded)
            .await;
    }

    fn delivery_failed(&self) {
        self.personal_message_telemetry().carbon_delivery_failed();
    }

    fn target_timed_out(&self) {
        self.personal_message_telemetry().carbon_target_timed_out();
    }
}
