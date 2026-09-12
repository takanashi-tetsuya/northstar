//! XEP-0191 Blocking Command microservice.
//!
//! Defined per `northstar_microservices_deep_audit_2026-09-03.md` (Sections 6, 7, 8, 19.2).

use foundation_eventing::memory::InMemoryOutbox;
use foundation_eventing::OutboxEvent;
use std::collections::{HashMap, HashSet};
use std::sync::RwLock;

pub struct BlockingService {
    blocked: RwLock<HashMap<String, HashSet<String>>>, // owner_bare_jid -> set of blocked JIDs
    outbox: InMemoryOutbox,
}

impl Default for BlockingService {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockingService {
    pub fn new() -> Self {
        Self {
            blocked: RwLock::new(HashMap::new()),
            outbox: InMemoryOutbox::new(),
        }
    }

    pub fn block_jids(&self, owner_bare_jid: &str, jids: &[String]) {
        let mut map = self.blocked.write().unwrap();
        let set = map.entry(owner_bare_jid.to_string()).or_default();
        for jid in jids {
            set.insert(jid.clone());
        }

        let event = OutboxEvent::new(
            "blocking",
            owner_bare_jid,
            1,
            "blocking.list.updated.v1",
            serde_json::to_vec(jids).unwrap_or_default(),
        );
        self.outbox.stage(event);
    }

    pub fn unblock_jids(&self, owner_bare_jid: &str, jids: &[String]) {
        let mut map = self.blocked.write().unwrap();
        if let Some(set) = map.get_mut(owner_bare_jid) {
            for jid in jids {
                set.remove(jid);
            }
        }

        let event = OutboxEvent::new(
            "blocking",
            owner_bare_jid,
            2,
            "blocking.list.updated.v1",
            serde_json::to_vec(jids).unwrap_or_default(),
        );
        self.outbox.stage(event);
    }

    pub fn get_blocklist(&self, owner_bare_jid: &str) -> Vec<String> {
        self.blocked
            .read()
            .unwrap()
            .get(owner_bare_jid)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn is_blocked(&self, owner_bare_jid: &str, target_jid: &str) -> bool {
        let target_bare = target_jid.split('/').next().unwrap_or(target_jid);
        self.blocked
            .read()
            .unwrap()
            .get(owner_bare_jid)
            .map(|s| s.contains(target_jid) || s.contains(target_bare))
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocking_unblocking_and_check() {
        let blocking = BlockingService::new();
        let user = "alice@example.com";

        assert!(!blocking.is_blocked(user, "spammer@bad.org"));

        // Block spammer
        blocking.block_jids(user, &["spammer@bad.org".to_string()]);
        assert!(blocking.is_blocked(user, "spammer@bad.org"));
        assert!(blocking.is_blocked(user, "spammer@bad.org/resource")); // Bare JID blocks full JID

        // Unblock
        blocking.unblock_jids(user, &["spammer@bad.org".to_string()]);
        assert!(!blocking.is_blocked(user, "spammer@bad.org"));
    }
}
