//! The application and local/cluster routing ports used after an inbound stream authenticates.

use anyhow::Result;
use northstar_pubsub_application::profile::PublicVCard;
use northstar_roster_core::PresenceAccount;
use northstar_stream::local_routes::session::OnlineSession;
use roxmltree::Node;
use std::{future::Future, sync::Arc};
use uuid::Uuid;

/// The protocol outcome of a PubSub service request, independent of its XMPP adapter.
pub enum PubSubReply {
    Result(String),
    Error(&'static str),
    ExtendedError(northstar_xep_0060::PubSubError),
}

/// A federated PEP request with its reply addresses and account/resource scope intact.
pub struct InboundPepRequest<'a, 'input> {
    pub owner_name: Option<&'a str>,
    pub full_target: bool,
    pub child: Node<'a, 'input>,
    pub id: &'a str,
    pub to: &'a str,
    pub from: &'a str,
}

/// Narrow bindings supplied by the composition root. Authorization and dispatch order live in
/// `inbound`; context adapters and persistence implementations stay behind these operations.
pub trait InboundHost:
    northstar_stream::protocol::iq_visibility::IqVisibilityHost + Send + Sync + 'static
{
    fn local_domain(&self) -> &str;
    fn island_mode_enabled(&self) -> bool;
    fn federation_entity_allowed(&self, entity: &str) -> bool;
    fn s2s_component_domain_configured(&self, domain: &str) -> bool;
    fn s2s_ping_route_enabled(&self) -> bool;
    fn s2s_ping_feature_enabled(&self) -> bool;

    fn send_to_component(&self, domain: &str, stanza: String) -> impl Future<Output = bool> + Send;

    fn federated_mix_iq(
        self: Arc<Self>,
        authenticated_domain: &str,
        raw: String,
    ) -> impl Future<Output = Result<bool>> + Send;
    fn federated_mix_message(
        self: Arc<Self>,
        authenticated_domain: &str,
        raw: String,
    ) -> impl Future<Output = Result<bool>> + Send;
    fn federated_mix_presence(
        self: Arc<Self>,
        authenticated_domain: &str,
        raw: String,
    ) -> impl Future<Output = Result<bool>> + Send;

    fn federated_muc_presence(
        &self,
        authenticated_domain: &str,
        connection_id: Uuid,
        root: Node<'_, '_>,
        raw: &str,
    ) -> impl Future<Output = Result<Option<String>>> + Send;
    fn federated_muc_message(
        &self,
        authenticated_domain: &str,
        connection_id: Uuid,
        root: Node<'_, '_>,
        raw: &str,
    ) -> impl Future<Output = Result<Option<String>>> + Send;
    fn federated_muc_iq(
        &self,
        authenticated_domain: &str,
        connection_id: Uuid,
        root: Node<'_, '_>,
        raw: &str,
    ) -> impl Future<Output = Result<Option<String>>> + Send;

    fn handle_pubsub_authorization_response(
        &self,
        from: &str,
        root: Node<'_, '_>,
    ) -> impl Future<Output = Result<()>> + Send;
    fn route_inbound_message(
        &self,
        root: Node<'_, '_>,
        raw: &str,
        from: &str,
        to: &str,
        authenticated_domain: &str,
    ) -> impl Future<Output = Result<Option<String>>> + Send;
    fn route_inbound_presence(
        &self,
        root: Node<'_, '_>,
        raw: &str,
        from: &str,
        to: &str,
        connection_id: Uuid,
        verified_peer: &str,
    ) -> impl Future<Output = Result<Option<String>>> + Send;

    fn find_enabled_presence_user(
        &self,
        username: &str,
    ) -> impl Future<Output = Result<Option<PresenceAccount>>> + Send;
    fn is_blocked_for_account(
        &self,
        account_id: Uuid,
        account_bare: &str,
        from: &str,
    ) -> impl Future<Output = Result<bool>> + Send;
    fn allows_presence(
        &self,
        account_id: Uuid,
        requester_bare: &str,
    ) -> impl Future<Output = Result<bool>> + Send;

    fn handle_federated_caps_response(
        &self,
        id: &str,
        kind: &str,
        root: Node<'_, '_>,
        raw: &str,
    ) -> impl Future<Output = bool> + Send;
    fn handle_push_delivery_response(
        &self,
        id: &str,
        kind: &str,
        from: &str,
    ) -> impl Future<Output = Result<bool>> + Send;
    fn cached_disco_result(&self, id: &str, to: &str, node: Option<&str>) -> Option<String>;

    fn sessions_for(&self, jid: &str) -> Vec<OnlineSession>;
    fn session_entries_for(&self, jid: &str) -> Vec<(String, OnlineSession)>;
    fn privacy_allows_iq(
        &self,
        session: &OnlineSession,
        from: &str,
    ) -> impl Future<Output = Result<bool>> + Send;
    fn route_s2s_iq_response_to_remote_resource(
        &self,
        to: &str,
        raw: &str,
    ) -> impl Future<Output = ()> + Send;
    fn s2s_remote_recipient_route_exists(&self, to: &str) -> impl Future<Output = bool> + Send;
    fn route_s2s_iq_request_remote(
        &self,
        to: &str,
        raw: &str,
        bare_target: bool,
    ) -> impl Future<Output = bool> + Send;

    fn public_vcard(&self, username: &str) -> impl Future<Output = Result<PublicVCard>> + Send;
    fn handle_pubsub_request(
        &self,
        from: &str,
        kind: &str,
        child: Node<'_, '_>,
    ) -> impl Future<Output = Result<PubSubReply>> + Send;
    fn pubsub_disco_info(
        &self,
        from: &str,
        node: Option<&str>,
    ) -> impl Future<Output = Result<PubSubReply>> + Send;
    fn pubsub_disco_items(
        &self,
        from: &str,
        child: Node<'_, '_>,
    ) -> impl Future<Output = Result<PubSubReply>> + Send;
    fn federated_pep_items(
        &self,
        request: InboundPepRequest<'_, '_>,
    ) -> impl Future<Output = Result<String>> + Send;
    fn federated_pep_subscription(
        &self,
        request: InboundPepRequest<'_, '_>,
    ) -> impl Future<Output = Result<String>> + Send;
    fn pep_disco_info(
        &self,
        owner_username: &str,
        from: &str,
        node: Option<&str>,
    ) -> impl Future<Output = Result<Option<String>>> + Send;
    fn pep_disco_items(
        &self,
        owner_username: &str,
        from: &str,
        node: Option<&str>,
    ) -> impl Future<Output = Result<Option<String>>> + Send;
}
