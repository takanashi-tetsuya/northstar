//! PubSub node, item, and discovery types.

use northstar_time::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

#[derive(Clone, Debug, Serialize)]
pub struct PubSubNode {
    pub id: Uuid,
    pub node: String,
    pub creator_jid: String,
    pub access_model: String,
    pub publish_model: String,
    pub max_items: i32,
    pub title: Option<String>,
    pub description: Option<String>,
    pub deliver_payloads: bool,
    pub notify_delete: bool,
    pub notify_retract: bool,
    pub persist_items: bool,
    pub send_last_published_item: String,
    pub node_type: String,
    pub deliver_notifications: bool,
    pub notify_config: bool,
    pub notify_sub: bool,
    pub language: Option<String>,
    pub payload_type: Option<String>,
    pub max_payload_size: i32,
    pub children_max: i32,
    pub children_association_policy: String,
    pub children_association_whitelist: Vec<String>,
    pub created_at: DateTime<Utc>,
}

impl PubSubNode {
    pub fn config(&self) -> PubSubNodeConfig {
        PubSubNodeConfig {
            access_model: self.access_model.clone(),
            publish_model: self.publish_model.clone(),
            max_items: self.max_items,
            title: self.title.clone(),
            description: self.description.clone(),
            deliver_payloads: self.deliver_payloads,
            notify_delete: self.notify_delete,
            notify_retract: self.notify_retract,
            persist_items: self.persist_items,
            send_last_published_item: self.send_last_published_item.clone(),
            node_type: self.node_type.clone(),
            deliver_notifications: self.deliver_notifications,
            notify_config: self.notify_config,
            notify_sub: self.notify_sub,
            language: self.language.clone(),
            payload_type: self.payload_type.clone(),
            max_payload_size: self.max_payload_size,
            children_max: self.children_max,
            children_association_policy: self.children_association_policy.clone(),
            children_association_whitelist: self.children_association_whitelist.clone(),
            collections: Vec::new(),
            children: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PubSubNodeConfig {
    pub access_model: String,
    pub publish_model: String,
    pub max_items: i32,
    pub title: Option<String>,
    pub description: Option<String>,
    pub deliver_payloads: bool,
    pub notify_delete: bool,
    pub notify_retract: bool,
    pub persist_items: bool,
    pub send_last_published_item: String,
    pub node_type: String,
    pub deliver_notifications: bool,
    pub notify_config: bool,
    pub notify_sub: bool,
    pub language: Option<String>,
    pub payload_type: Option<String>,
    pub max_payload_size: i32,
    pub children_max: i32,
    pub children_association_policy: String,
    pub children_association_whitelist: Vec<String>,
    pub collections: Vec<String>,
    pub children: Vec<String>,
}

impl Default for PubSubNodeConfig {
    fn default() -> Self {
        Self {
            access_model: "open".to_owned(),
            publish_model: "publishers".to_owned(),
            max_items: 100,
            title: None,
            description: None,
            deliver_payloads: true,
            notify_delete: true,
            notify_retract: true,
            persist_items: true,
            send_last_published_item: "on_sub_and_presence".to_owned(),
            node_type: "leaf".to_owned(),
            deliver_notifications: true,
            notify_config: true,
            notify_sub: true,
            language: None,
            payload_type: None,
            max_payload_size: 1_048_576,
            children_max: 1_000,
            children_association_policy: "owner".to_owned(),
            children_association_whitelist: Vec::new(),
            collections: Vec::new(),
            children: Vec::new(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct PubSubItem {
    pub item_id: String,
    pub xml_payload: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct CollectionVisibleItem {
    pub node: String,
    pub xml_payload: String,
}

#[derive(Clone, Debug)]
pub struct PubSubAffiliation {
    pub node: String,
    pub jid: String,
    pub affiliation: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PubSubNodeMetadata {
    pub owners: Vec<String>,
    pub publishers: Vec<String>,
    pub active_subscribers: i64,
}

#[derive(Clone, Debug)]
pub struct PubSubRootDiscoNode {
    pub node: String,
    pub title: Option<String>,
    pub index: i64,
}

#[derive(Clone, Debug)]
pub struct PubSubRootDiscoPage {
    pub total: i64,
    pub cursor_exists: bool,
    pub nodes: Vec<PubSubRootDiscoNode>,
}
