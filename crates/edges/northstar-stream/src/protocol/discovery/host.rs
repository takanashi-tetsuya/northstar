//! The services, discovery configuration and context adapters supplied by the node.

use crate::protocol::{ProtocolSession, SessionHost};
use anyhow::Result;
use northstar_pubsub_application::{
    PepNodeQueryRepository, PepSnapshotRepository, PubSubDiscoverySnapshotRepository, PubSubService,
};
use northstar_pubsub_core::{PubSubNode, PubSubNodeMetadata};
use northstar_room_application::muc_service::{MucRepository, MucRoomView, MucService};
use roxmltree::Node;
use std::future::Future;

/// The PubSub adapter's discovery payload or stanza error condition.
pub enum PubSubDiscoItemsReply {
    Result(String),
    Error(&'static str),
}

/// What service discovery needs beyond the core session host. Context XMPP
/// adapters depend on stream, so the composition root binds their calls here.
pub trait DiscoveryHost: SessionHost {
    type MucStore: MucRepository;
    type PubSubStore: PubSubDiscoverySnapshotRepository
        + PepNodeQueryRepository
        + PepSnapshotRepository;

    fn muc_service(&self) -> &MucService<Self::MucStore>;
    fn pubsub_service(&self) -> &PubSubService<Self::PubSubStore>;
    fn server_name(&self) -> &str;
    fn mix_muc_mirror_enabled(&self) -> bool;
    fn upload_max_file_bytes(&self) -> u64;
    fn server_disco_features(&self) -> Vec<&'static str>;
    fn external_service_discovery_available(&self) -> bool;
    fn server_info_addresses(&self) -> [(&'static str, &[String]); 6];
    fn configured_component_domains(&self) -> Vec<String>;
    fn discovery_room_occupants(
        &self,
        localpart: &str,
        viewer_full_jid: Option<&str>,
    ) -> impl Future<Output = Result<MucRoomView>> + Send;

    fn mix_service_disco_info_payload(server_name: &str, mirror: &str) -> Result<String>;
    fn mix_channel_disco_info_payload(
        name: &str,
        supports_retraction: bool,
        supports_private_messages: bool,
        supports_mam: bool,
        mirror: &str,
    ) -> Result<String>;

    fn pubsub_node_metadata_form(node: &PubSubNode, metadata: &PubSubNodeMetadata) -> String;
    fn pubsub_service_disco_payload(&self) -> String;
    fn pubsub_disco_items(
        &self,
        requester: &str,
        request: Node<'_, '_>,
    ) -> impl Future<Output = Result<PubSubDiscoItemsReply>> + Send;
    fn is_command(node: &str) -> bool;
    fn commands_available_to(
        session: &ProtocolSession<Self>,
    ) -> impl Future<Output = Result<bool>> + Send;
    fn command_disco_info(
        session: &ProtocolSession<Self>,
        id: &str,
        from: &str,
        node: &str,
    ) -> impl Future<Output = Result<Option<String>>> + Send;
    fn command_disco_items(
        session: &ProtocolSession<Self>,
        id: &str,
        from: &str,
        node: &str,
    ) -> impl Future<Output = Result<Option<String>>> + Send;
}
