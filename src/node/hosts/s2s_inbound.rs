//! Bind the S2S inbound router to the node's application services and context adapters.

use crate::node::ServerNode;
use anyhow::Result;
use northstar_pubsub_application::profile::PublicVCard;
use northstar_pubsub_core::PubSubAccount;
use northstar_roster_core::PresenceAccount;
use northstar_s2s::inbound_host::{InboundHost, InboundPepRequest, PubSubReply};
use northstar_stream::local_routes::session::OnlineSession;
use roxmltree::Node;
use std::sync::Arc;
use uuid::Uuid;

impl InboundHost for ServerNode {
    fn local_domain(&self) -> &str {
        &self.config.domain
    }

    fn island_mode_enabled(&self) -> bool {
        self.federation.federation_write_policy.enabled()
    }

    fn federation_entity_allowed(&self, entity: &str) -> bool {
        ServerNode::federation_entity_allowed(self, entity)
    }

    fn s2s_component_domain_configured(&self, domain: &str) -> bool {
        self.config.component_domain_configured(domain)
    }

    fn s2s_ping_route_enabled(&self) -> bool {
        self.config.s2s_ping_route_enabled()
    }

    fn s2s_ping_feature_enabled(&self) -> bool {
        self.config
            .xmpp_extension_enabled(northstar_xep_0199::XEP_ID)
    }

    async fn send_to_component(&self, domain: &str, stanza: String) -> bool {
        self.federation
            .federation_outbox
            .send(domain, stanza, None)
            .await
    }

    async fn federated_mix_iq(
        self: Arc<Self>,
        authenticated_domain: &str,
        raw: String,
    ) -> Result<bool> {
        northstar_mix_xmpp::federated_mix_iq(self, authenticated_domain, raw).await
    }

    async fn federated_mix_message(
        self: Arc<Self>,
        authenticated_domain: &str,
        raw: String,
    ) -> Result<bool> {
        northstar_mix_xmpp::federated_mix_message(self, authenticated_domain, raw).await
    }

    async fn federated_mix_presence(
        self: Arc<Self>,
        authenticated_domain: &str,
        raw: String,
    ) -> Result<bool> {
        northstar_mix_xmpp::federated_mix_presence(self, authenticated_domain, raw).await
    }

    async fn federated_muc_presence(
        &self,
        authenticated_domain: &str,
        connection_id: Uuid,
        root: Node<'_, '_>,
        raw: &str,
    ) -> Result<Option<String>> {
        northstar_muc_xmpp::federated_muc::federated_muc_presence(
            self,
            authenticated_domain,
            connection_id,
            root,
            raw,
        )
        .await
    }

    async fn federated_muc_message(
        &self,
        authenticated_domain: &str,
        connection_id: Uuid,
        root: Node<'_, '_>,
        raw: &str,
    ) -> Result<Option<String>> {
        northstar_muc_xmpp::federated_muc::federated_muc_message(
            self,
            authenticated_domain,
            connection_id,
            root,
            raw,
        )
        .await
    }

    async fn federated_muc_iq(
        &self,
        authenticated_domain: &str,
        connection_id: Uuid,
        root: Node<'_, '_>,
        raw: &str,
    ) -> Result<Option<String>> {
        northstar_muc_xmpp::federated_muc::federated_muc_iq(
            self,
            authenticated_domain,
            connection_id,
            root,
            raw,
        )
        .await
    }

    async fn handle_pubsub_authorization_response(
        &self,
        from: &str,
        root: Node<'_, '_>,
    ) -> Result<()> {
        northstar_pubsub_xmpp::pubsub::handle_authorization_response(self, from, root).await
    }

    async fn route_inbound_message(
        &self,
        root: Node<'_, '_>,
        raw: &str,
        from: &str,
        to: &str,
        authenticated_domain: &str,
    ) -> Result<Option<String>> {
        northstar_message_xmpp::federated_message::route_inbound_message(
            self,
            root,
            raw,
            from,
            to,
            authenticated_domain,
        )
        .await
    }

    async fn route_inbound_presence(
        &self,
        root: Node<'_, '_>,
        raw: &str,
        from: &str,
        to: &str,
        connection_id: Uuid,
    ) -> Result<Option<String>> {
        northstar_roster_xmpp::federated_presence::route_inbound_presence(
            self,
            root,
            raw,
            from,
            to,
            connection_id,
        )
        .await
    }

    async fn find_enabled_presence_user(&self, username: &str) -> Result<Option<PresenceAccount>> {
        self.roster
            .presence_service()
            .find_enabled_user(username)
            .await
    }

    async fn is_blocked_for_account(
        &self,
        account_id: Uuid,
        account_bare: &str,
        from: &str,
    ) -> Result<bool> {
        self.roster
            .presence_service()
            .is_blocked_for_account(account_id, account_bare, from)
            .await
    }

    async fn allows_presence(&self, account_id: Uuid, requester_bare: &str) -> Result<bool> {
        self.roster
            .s2s_roster_authorization_service()
            .allows_presence(account_id, requester_bare)
            .await
    }

    async fn handle_federated_caps_response(
        &self,
        id: &str,
        kind: &str,
        root: Node<'_, '_>,
        raw: &str,
    ) -> bool {
        northstar_stream::protocol::caps::handle_federated_caps_response(self, id, kind, root, raw)
            .await
    }

    async fn handle_push_delivery_response(
        &self,
        id: &str,
        kind: &str,
        from: &str,
    ) -> Result<bool> {
        northstar_stream::protocol::misc::handle_push_delivery_response(self, id, kind, from).await
    }

    fn cached_disco_result(&self, id: &str, to: &str, node: Option<&str>) -> Option<String> {
        northstar_stream::protocol::caps::cached_disco_result(self, id, to, node)
    }

    fn sessions_for(&self, jid: &str) -> Vec<OnlineSession> {
        self.sessions.sessions_for(jid)
    }

    fn session_entries_for(&self, jid: &str) -> Vec<(String, OnlineSession)> {
        self.sessions.session_entries_for(jid)
    }

    async fn privacy_allows_iq(&self, session: &OnlineSession, from: &str) -> Result<bool> {
        self.privacy_allows_session(session, from, crate::db::PrivacyStanzaKind::Iq)
            .await
    }

    async fn route_s2s_iq_response_to_remote_resource(&self, to: &str, raw: &str) {
        self.cluster
            .route_s2s_iq_response_to_remote_resource(to, raw)
            .await;
    }

    async fn s2s_remote_recipient_route_exists(&self, to: &str) -> bool {
        self.cluster.s2s_remote_recipient_route_exists(to).await
    }

    async fn route_s2s_iq_request_remote(&self, to: &str, raw: &str, bare_target: bool) -> bool {
        self.cluster
            .route_s2s_iq_request_remote(to, raw, bare_target)
            .await
    }

    async fn public_vcard(&self, username: &str) -> Result<PublicVCard> {
        self.pubsub.profile_service().public_vcard(username).await
    }

    async fn find_enabled_pubsub_user(&self, username: &str) -> Result<Option<PubSubAccount>> {
        self.pubsub
            .pubsub_service()
            .find_enabled_user(username)
            .await
    }

    async fn handle_pubsub_request(
        &self,
        from: &str,
        kind: &str,
        child: Node<'_, '_>,
    ) -> Result<PubSubReply> {
        northstar_pubsub_xmpp::pubsub::handle_request(self, from, kind, child)
            .await
            .map(inbound_pubsub_reply)
    }

    async fn pubsub_disco_info(&self, from: &str, node: Option<&str>) -> Result<PubSubReply> {
        northstar_pubsub_xmpp::pubsub::federated_disco_info(self, from, node)
            .await
            .map(inbound_pubsub_reply)
    }

    async fn pubsub_disco_items(&self, from: &str, child: Node<'_, '_>) -> Result<PubSubReply> {
        northstar_pubsub_xmpp::pubsub::federated_disco_items(self, from, child)
            .await
            .map(inbound_pubsub_reply)
    }

    async fn federated_pep_items(&self, request: InboundPepRequest<'_, '_>) -> Result<String> {
        northstar_pubsub_xmpp::federated_pep::federated_pep_items(
            self,
            request.owner_name,
            request.full_target,
            request.child,
            request.id,
            request.to,
            request.from,
        )
        .await
    }

    async fn federated_pep_subscription(
        &self,
        request: InboundPepRequest<'_, '_>,
    ) -> Result<String> {
        northstar_pubsub_xmpp::federated_pep::federated_pep_subscription(
            self,
            request.owner_name,
            request.full_target,
            request.child,
            request.id,
            request.to,
            request.from,
        )
        .await
    }

    async fn pep_disco_info(
        &self,
        owner: &PubSubAccount,
        from: &str,
        node: Option<&str>,
    ) -> Result<Option<String>> {
        northstar_pubsub_xmpp::pep::federated_pep_disco_info(self, owner, from, node).await
    }

    async fn pep_disco_items(
        &self,
        owner: &PubSubAccount,
        from: &str,
        node: Option<&str>,
    ) -> Result<Option<String>> {
        northstar_pubsub_xmpp::pep::federated_pep_disco_items(self, owner, from, node).await
    }
}

fn inbound_pubsub_reply(reply: northstar_pubsub_xmpp::pubsub::PubSubReply) -> PubSubReply {
    use northstar_pubsub_xmpp::pubsub::PubSubReply as Reply;

    match reply {
        Reply::Result(payload) => PubSubReply::Result(payload),
        Reply::Error(condition) => PubSubReply::Error(condition),
        Reply::ExtendedError(error) => PubSubReply::ExtendedError(error),
    }
}

#[cfg(test)]
#[path = "s2s_inbound_tests.rs"]
mod tests;
