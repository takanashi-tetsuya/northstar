use super::{CapsKey, CapsObservationOwner, PendingCaps};
use dashmap::DashMap;
use northstar_session_core::LocalCapsEpoch;
use std::sync::Mutex;
use std::time::Instant;

pub struct PendingCapsIndex {
    pub entries: DashMap<String, PendingCaps>,
    pub admission: Mutex<()>,
}

impl Default for PendingCapsIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl PendingCapsIndex {
    pub fn new() -> Self {
        Self {
            entries: DashMap::new(),
            admission: Mutex::new(()),
        }
    }

    pub fn insert(
        &self,
        id: String,
        full_jid: String,
        key: CapsKey,
        owner: CapsObservationOwner,
        expires_at: Instant,
    ) -> bool {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if self.entries.contains_key(&id) {
            return false;
        }
        self.entries
            .retain(|_, pending| pending.full_jid != full_jid || pending.owner != owner);
        if self.entries.iter().any(|pending| pending.key == key) {
            return false;
        }
        self.entries.insert(
            id,
            PendingCaps {
                full_jid,
                key,
                owner,
                expires_at,
            },
        );
        true
    }

    pub fn take(&self, id: &str) -> Option<PendingCaps> {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.entries.remove(id).map(|(_, pending)| pending)
    }

    pub fn federated_resource(&self, id: &str) -> Option<String> {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.entries
            .get(id)
            .filter(|pending| matches!(pending.owner, CapsObservationOwner::Federated { .. }))
            .map(|pending| pending.full_jid.clone())
    }

    pub fn remove(&self, id: &str) {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.entries.remove(id);
    }

    pub fn remove_resource(&self, full_jid: &str) {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.entries
            .retain(|_, pending| pending.full_jid != full_jid);
    }

    pub fn remove_local_resource(&self, full_jid: &str, connection_id: uuid::Uuid) {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.entries.retain(|_, pending| {
            pending.full_jid != full_jid
                || !matches!(pending.owner, CapsObservationOwner::Local(epoch) if epoch.connection_id == connection_id)
        });
    }

    pub fn remove_local_epoch(&self, full_jid: &str, epoch: LocalCapsEpoch) {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.entries.retain(|_, pending| {
            pending.full_jid != full_jid || pending.owner != CapsObservationOwner::Local(epoch)
        });
    }

    pub fn remove_federated_connection(&self, connection_id: uuid::Uuid) {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.entries.retain(|_, pending| {
            !matches!(pending.owner, CapsObservationOwner::Federated { connection_id: owner, .. } if owner == connection_id)
        });
    }

    pub fn remove_federated_resource_if_connection(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
    ) {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.entries.retain(|_, pending| {
            pending.full_jid != full_jid
                || pending.owner.federated_connection() != Some(connection_id)
        });
    }

    pub fn take_expired(&self, now: Instant) -> Vec<(String, PendingCaps)> {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let expired = self
            .entries
            .iter()
            .filter(|entry| entry.expires_at <= now)
            .map(|entry| entry.key().clone())
            .collect::<Vec<_>>();
        expired
            .into_iter()
            .filter_map(|id| self.entries.remove(&id).map(|(_, pending)| (id, pending)))
            .collect()
    }

    pub fn next_expiration(&self) -> Option<Instant> {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.entries.iter().map(|pending| pending.expires_at).min()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}
