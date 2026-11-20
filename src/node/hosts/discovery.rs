//! The node's service bindings and context adapters for client discovery.

use crate::node::ServerNode;
use anyhow::Result;
use northstar_pubsub_application::PubSubService;
use northstar_pubsub_core::{PubSubNode, PubSubNodeMetadata};
use northstar_room_application::muc_service::{MucService, SerializableMucOccupant};
use northstar_stream::protocol::discovery::{DiscoveryHost, PubSubDiscoItemsReply};
use northstar_stream::protocol::ProtocolSession;
use roxmltree::Node;

impl DiscoveryHost for ServerNode {
    type MucStore = northstar_workflows::room_effects::PostgresMucRepository;
    type PubSubStore = northstar_workflows::pubsub_repository::PostgresPubSubRepository;

    fn muc_service(&self) -> &MucService<Self::MucStore> {
        self.room.muc_service()
    }

    fn pubsub_service(&self) -> &PubSubService<Self::PubSubStore> {
        self.pubsub.pubsub_service()
    }

    fn server_name(&self) -> &str {
        &self.config.server_name
    }

    fn mix_muc_mirror_enabled(&self) -> bool {
        self.config.mix_muc_mirror_enabled
    }

    fn upload_max_file_bytes(&self) -> u64 {
        self.config.upload_max_bytes
    }

    fn server_disco_features(&self) -> Vec<&'static str> {
        self.config.server_disco_features()
    }

    fn external_service_discovery_available(&self) -> bool {
        self.config.external_service_discovery_available()
    }

    fn server_info_addresses(&self) -> [(&'static str, &[String]); 6] {
        self.config.server_info_addresses()
    }

    fn configured_component_domains(&self) -> Vec<String> {
        ServerNode::configured_component_domains(self)
    }

    async fn discovery_room_occupants(
        &self,
        room_jid: &str,
    ) -> Result<Vec<SerializableMucOccupant>> {
        ServerNode::discovery_room_occupants(self, room_jid).await
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

    fn pubsub_node_metadata_form(node: &PubSubNode, metadata: &PubSubNodeMetadata) -> String {
        northstar_pubsub_xmpp::pubsub::node_metadata_form(node, metadata)
    }

    fn pubsub_service_disco_payload(&self) -> String {
        northstar_pubsub_xmpp::pubsub::service_disco_payload(self)
    }

    async fn pubsub_disco_items(
        &self,
        requester: &str,
        request: Node<'_, '_>,
    ) -> Result<PubSubDiscoItemsReply> {
        northstar_pubsub_xmpp::pubsub::disco_items_reply(self, requester, request).await
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
