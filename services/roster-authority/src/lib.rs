//! Roster Authority microservice implementation.
//!
//! Defined per `northstar_microservices_deep_audit_2026-09-03.md` (Sections 6, 7, 8, 19.2).

use foundation_eventing::memory::InMemoryOutbox;
use foundation_eventing::OutboxEvent;
use std::collections::HashMap;
use std::sync::RwLock;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RosterItem {
    pub jid: String,
    pub name: Option<String>,
    pub subscription: String,
    pub groups: Vec<String>,
}

#[derive(Default)]
pub struct UserRoster {
    pub version: u64,
    pub items: HashMap<String, RosterItem>, // contact_jid -> RosterItem
}

pub struct RosterAuthorityService {
    rosters: RwLock<HashMap<String, UserRoster>>, // owner_bare_jid -> UserRoster
    outbox: InMemoryOutbox,
}

impl Default for RosterAuthorityService {
    fn default() -> Self {
        Self::new()
    }
}

impl RosterAuthorityService {
    pub fn new() -> Self {
        Self {
            rosters: RwLock::new(HashMap::new()),
            outbox: InMemoryOutbox::new(),
        }
    }

    pub fn get_roster(&self, owner_bare_jid: &str) -> (u64, Vec<RosterItem>) {
        let rosters = self.rosters.read().unwrap();
        if let Some(roster) = rosters.get(owner_bare_jid) {
            (roster.version, roster.items.values().cloned().collect())
        } else {
            (0, Vec::new())
        }
    }

    pub fn upsert_item(
        &self,
        owner_bare_jid: &str,
        contact_jid: &str,
        name: Option<String>,
        groups: Vec<String>,
    ) -> u64 {
        let mut rosters = self.rosters.write().unwrap();
        let roster = rosters.entry(owner_bare_jid.to_string()).or_default();
        roster.version += 1;
        let ver = roster.version;

        let sub = roster
            .items
            .get(contact_jid)
            .map(|i| i.subscription.clone())
            .unwrap_or_else(|| "none".to_string());

        let item = RosterItem {
            jid: contact_jid.to_string(),
            name,
            subscription: sub,
            groups,
        };

        roster.items.insert(contact_jid.to_string(), item);

        let event = OutboxEvent::new(
            "roster",
            owner_bare_jid,
            ver,
            "roster.changed.v1",
            contact_jid.as_bytes().to_vec(),
        );
        self.outbox.stage(event);

        ver
    }

    pub fn remove_item(&self, owner_bare_jid: &str, contact_jid: &str) -> Option<u64> {
        let mut rosters = self.rosters.write().unwrap();
        let roster = rosters.get_mut(owner_bare_jid)?;
        if roster.items.remove(contact_jid).is_some() {
            roster.version += 1;
            let ver = roster.version;

            let event = OutboxEvent::new(
                "roster",
                owner_bare_jid,
                ver,
                "roster.item_removed.v1",
                contact_jid.as_bytes().to_vec(),
            );
            self.outbox.stage(event);
            Some(ver)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roster_crud_and_version_bumping() {
        let service = RosterAuthorityService::new();
        let owner = "alice@example.com";

        // Initial empty roster
        let (ver0, items0) = service.get_roster(owner);
        assert_eq!(ver0, 0);
        assert!(items0.is_empty());

        // Upsert item
        let ver1 = service.upsert_item(
            owner,
            "bob@example.com",
            Some("Bobby".to_string()),
            vec!["Friends".to_string()],
        );
        assert_eq!(ver1, 1);

        let (ver_curr, items_curr) = service.get_roster(owner);
        assert_eq!(ver_curr, 1);
        assert_eq!(items_curr.len(), 1);
        assert_eq!(items_curr[0].name.as_deref(), Some("Bobby"));

        // Remove item
        let ver2 = service.remove_item(owner, "bob@example.com").unwrap();
        assert_eq!(ver2, 2);

        let (ver_final, items_final) = service.get_roster(owner);
        assert_eq!(ver_final, 2);
        assert!(items_final.is_empty());
    }
}
