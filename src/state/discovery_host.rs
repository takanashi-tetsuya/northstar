//! The node's service bindings and context adapters for client discovery.

use super::AppState;
use anyhow::Result;
use northstar_pubsub_application::PubSubService;
use northstar_pubsub_core::{PubSubAccount, PubSubNode};
use northstar_room_application::muc_service::{MucService, SerializableMucOccupant};
use northstar_stream::protocol::discovery::{DiscoveryHost, PubSubDiscoItemsReply};
use northstar_stream::protocol::ProtocolSession;
use roxmltree::Node;

impl DiscoveryHost for AppState {
    type MucStore = northstar_workflows::room_effects::PostgresMucRepository;
    type PubSubStore = northstar_workflows::pubsub_repository::PostgresPubSubRepository;

    fn muc_service(&self) -> &MucService<Self::MucStore> {
        AppState::muc_service(self)
    }

    fn pubsub_service(&self) -> &PubSubService<Self::PubSubStore> {
        AppState::pubsub_service(self)
    }

    fn server_name(&self) -> &str {
        AppState::server_name(self)
    }

    fn mix_muc_mirror_enabled(&self) -> bool {
        AppState::mix_muc_mirror_enabled(self)
    }

    fn upload_max_file_bytes(&self) -> u64 {
        self.upload_slot_limits().max_file_bytes
    }

    fn server_disco_features(&self) -> Vec<&'static str> {
        AppState::server_disco_features(self)
    }

    fn external_service_discovery_available(&self) -> bool {
        AppState::external_service_discovery_available(self)
    }

    fn server_info_addresses(&self) -> [(&'static str, &[String]); 6] {
        AppState::server_info_addresses(self)
    }

    fn configured_component_domains(&self) -> Vec<String> {
        AppState::configured_component_domains(self)
    }

    async fn discovery_room_occupants(
        &self,
        room_jid: &str,
    ) -> Result<Vec<SerializableMucOccupant>> {
        AppState::discovery_room_occupants(self, room_jid).await
    }

    fn mix_service_disco_info_payload(server_name: &str, mirror: &str) -> Result<String> {
        northstar_mix_xmpp::mix_service_disco_info_payload(server_name, mirror)
    }

    fn mix_channel_disco_info_payload(
        name: &str,
        supports_retraction: bool,
        supports_private_messages: bool,
        supports_mam: bool,
        mirror: &str,
    ) -> Result<String> {
        northstar_mix_xmpp::mix_channel_disco_info_payload(
            name,
            supports_retraction,
            supports_private_messages,
            supports_mam,
            mirror,
        )
    }

    async fn pubsub_node_metadata_form(&self, node: &PubSubNode) -> Result<String> {
        northstar_pubsub_xmpp::pubsub::node_metadata_form(self, node).await
    }

    fn pubsub_service_disco_payload(&self) -> String {
        northstar_pubsub_xmpp::pubsub::service_disco_payload(self)
    }

    async fn pubsub_disco_items(
        &self,
        requester: &str,
        request: Node<'_, '_>,
    ) -> Result<PubSubDiscoItemsReply> {
        use northstar_pubsub_xmpp::pubsub::{error_condition, federated_disco_items, PubSubReply};

        Ok(
            match federated_disco_items(self, requester, request).await? {
                PubSubReply::Result(payload) => PubSubDiscoItemsReply::Result(payload),
                error => PubSubDiscoItemsReply::Error(
                    error_condition(&error).unwrap_or("undefined-condition"),
                ),
            },
        )
    }

    async fn pep_access_allowed(
        &self,
        owner: &PubSubAccount,
        domain: &str,
        node: &str,
        requester: &str,
    ) -> Result<bool> {
        northstar_pubsub_xmpp::pep::pep_access_allowed(
            self.pubsub_service(),
            owner,
            domain,
            node,
            requester,
        )
        .await
    }

    fn is_command(node: &str) -> bool {
        northstar_operations_xmpp::commands::is_command(node)
    }

    async fn commands_available_to(session: &ProtocolSession<Self>) -> Result<bool> {
        northstar_operations_xmpp::commands::available_to(session).await
    }

    async fn command_disco_info(
        session: &ProtocolSession<Self>,
        id: &str,
        from: &str,
        node: &str,
    ) -> Result<Option<String>> {
        northstar_operations_xmpp::commands::disco_info(session, id, from, node).await
    }

    async fn command_disco_items(
        session: &ProtocolSession<Self>,
        id: &str,
        from: &str,
        node: &str,
    ) -> Result<Option<String>> {
        northstar_operations_xmpp::commands::disco_items(session, id, from, node).await
    }
}
