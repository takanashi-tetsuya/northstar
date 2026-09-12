//! XEP-0060 Publish-Subscribe microservice.
//!
//! Defined per `northstar_microservices_deep_audit_2026-09-03.md` (Sections 6, 7, 8, 19.2).

use foundation_contracts::adapters::common::ErrorDetail;
use foundation_eventing::memory::InMemoryOutbox;
use foundation_eventing::OutboxEvent;
use std::collections::{HashMap, HashSet};
use std::sync::RwLock;

pub struct PubSubNode {
    pub node_id: String,
    pub creator_jid: String,
    pub items: HashMap<String, Vec<u8>>,
    pub subscribers: HashSet<String>,
}

pub struct PubSubService {
    nodes: RwLock<HashMap<String, PubSubNode>>,
    outbox: InMemoryOutbox,
}

impl Default for PubSubService {
    fn default() -> Self {
        Self::new()
    }
}

impl PubSubService {
    pub fn new() -> Self {
        Self {
            nodes: RwLock::new(HashMap::new()),
            outbox: InMemoryOutbox::new(),
        }
    }

    pub fn create_node(&self, node_id: &str, creator_jid: &str) -> Result<(), ErrorDetail> {
        let mut nodes = self.nodes.write().unwrap();
        if nodes.contains_key(node_id) {
            return Err(ErrorDetail::new("CONFLICT", "Node already exists"));
        }

        let node = PubSubNode {
            node_id: node_id.to_string(),
            creator_jid: creator_jid.to_string(),
            items: HashMap::new(),
            subscribers: HashSet::new(),
        };

        nodes.insert(node_id.to_string(), node);
        Ok(())
    }

    pub fn publish_item(
        &self,
        node_id: &str,
        item_id: &str,
        payload: Vec<u8>,
    ) -> Result<(), ErrorDetail> {
        let mut nodes = self.nodes.write().unwrap();
        let Some(node) = nodes.get_mut(node_id) else {
            return Err(ErrorDetail::new("ITEM_NOT_FOUND", "Node does not exist"));
        };

        node.items.insert(item_id.to_string(), payload.clone());

        // Stage publication event in Outbox
        let event = OutboxEvent::new("node", node_id, 1, "pubsub.event.published.v1", payload);
        self.outbox.stage(event);

        Ok(())
    }

    pub fn subscribe(&self, node_id: &str, subscriber_jid: &str) -> Result<(), ErrorDetail> {
        let mut nodes = self.nodes.write().unwrap();
        let Some(node) = nodes.get_mut(node_id) else {
            return Err(ErrorDetail::new("ITEM_NOT_FOUND", "Node does not exist"));
        };

        node.subscribers.insert(subscriber_jid.to_string());
        Ok(())
    }

    pub fn subscribers(&self, node_id: &str) -> Vec<String> {
        self.nodes
            .read()
            .unwrap()
            .get(node_id)
            .map(|n| n.subscribers.iter().cloned().collect())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pubsub_node_create_publish_subscribe_lifecycle() {
        let pubsub = PubSubService::new();
        let node = "weather-news";

        assert!(pubsub.create_node(node, "admin@example.com").is_ok());
        assert!(pubsub.create_node(node, "admin@example.com").is_err()); // Duplicate fails

        assert!(pubsub.subscribe(node, "user1@example.com").is_ok());
        assert_eq!(pubsub.subscribers(node).len(), 1);

        assert!(pubsub
            .publish_item(node, "item-1", b"<weather temp='25'/>".to_vec())
            .is_ok());
    }
}
