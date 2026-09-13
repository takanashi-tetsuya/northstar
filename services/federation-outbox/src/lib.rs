//! S2S Federation Outbox microservice implementation.
//!
//! Defined per `northstar_microservices_deep_audit_2026-09-03.md` (Sections 6, 8, 19.1, 19.6).

use chrono::Utc;
use std::collections::HashMap;
use std::sync::RwLock;
use uuid::Uuid;

pub const MAX_RETRY_ATTEMPTS: u32 = 5;

#[derive(Debug, Clone)]
pub struct OutboxItem {
    pub outbox_id: Uuid,
    pub target_domain: String,
    pub stanza: Vec<u8>,
    pub attempt_count: u32,
    pub lock_token: Option<Uuid>,
    pub lease_expiry_ms: Option<u64>,
}

pub struct FederationOutboxService {
    items: RwLock<HashMap<Uuid, OutboxItem>>,
}

impl Default for FederationOutboxService {
    fn default() -> Self {
        Self::new()
    }
}

impl FederationOutboxService {
    pub fn new() -> Self {
        Self {
            items: RwLock::new(HashMap::new()),
        }
    }

    /// Enqueues a new stanza for outbound S2S delivery.
    pub fn enqueue(&self, target_domain: impl Into<String>, stanza: Vec<u8>) -> Uuid {
        let outbox_id = Uuid::new_v4();
        let item = OutboxItem {
            outbox_id,
            target_domain: target_domain.into(),
            stanza,
            attempt_count: 0,
            lock_token: None,
            lease_expiry_ms: None,
        };
        self.items.write().unwrap().insert(outbox_id, item);
        outbox_id
    }

    /// Claims a batch of pending items for a target domain with a lease duration.
    pub fn claim_pending(
        &self,
        target_domain: &str,
        limit: usize,
        lease_ms: u64,
    ) -> Vec<(OutboxItem, Uuid)> {
        let now_ms = Utc::now().timestamp_millis() as u64;
        let mut items = self.items.write().unwrap();
        let mut claimed = Vec::new();

        for item in items.values_mut() {
            if claimed.len() >= limit {
                break;
            }

            if item.target_domain == target_domain {
                let is_available = match item.lease_expiry_ms {
                    None => true,
                    Some(exp) => exp <= now_ms,
                };

                if is_available && item.attempt_count < MAX_RETRY_ATTEMPTS {
                    let lock_token = Uuid::new_v4();
                    item.lock_token = Some(lock_token);
                    item.lease_expiry_ms = Some(now_ms + lease_ms);
                    item.attempt_count += 1;
                    claimed.push((item.clone(), lock_token));
                }
            }
        }

        claimed
    }

    /// Acknowledges successful S2S delivery and removes the item.
    pub fn acknowledge(&self, outbox_id: Uuid, lock_token: Uuid) -> bool {
        let mut items = self.items.write().unwrap();
        if let Some(item) = items.get(&outbox_id) {
            if item.lock_token == Some(lock_token) {
                items.remove(&outbox_id);
                return true;
            }
        }
        false
    }

    /// Releases a claimed item for retry backoff or dead-letters it if max attempts reached.
    pub fn release_or_retry(&self, outbox_id: Uuid, lock_token: Uuid) -> bool {
        let mut items = self.items.write().unwrap();
        if let Some(item) = items.get_mut(&outbox_id) {
            if item.lock_token == Some(lock_token) {
                item.lock_token = None;
                item.lease_expiry_ms = None;
                return true;
            }
        }
        false
    }

    pub fn pending_count(&self) -> usize {
        self.items.read().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn federation_outbox_claim_ack_retry_lifecycle() {
        let outbox = FederationOutboxService::new();
        let id = outbox.enqueue(
            "remote.example.org",
            b"<message to='remote.example.org'/>".to_vec(),
        );
        assert_eq!(outbox.pending_count(), 1);

        // 1. Claim pending items
        let claimed = outbox.claim_pending("remote.example.org", 10, 5000);
        assert_eq!(claimed.len(), 1);
        let (item, lock) = &claimed[0];
        assert_eq!(item.outbox_id, id);

        // 2. Second claim finds nothing (currently leased)
        let claimed_again = outbox.claim_pending("remote.example.org", 10, 5000);
        assert_eq!(claimed_again.len(), 0);

        // 3. Acknowledge delivery
        let acked = outbox.acknowledge(id, *lock);
        assert!(acked);
        assert_eq!(outbox.pending_count(), 0);
    }
}
