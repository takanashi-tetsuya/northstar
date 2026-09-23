//! Expire locked rooms after the database commits their tombstones and outbox.

use super::{
    muc_delivery::MucDeliveryContext, remove_live_muc_membership_in,
    remove_local_muc_occupant_exact_from, AppState, MucOccupant, OnlineSession,
    SerializableMucOccupant,
};
use crate::{
    db::locked_muc_expiry_repository::PostgresLockedMucExpiryRepository,
    services::locked_muc_expiry::LockedMucExpiryService, workers::WorkerHeartbeat,
};
use dashmap::DashMap;
use std::{
    sync::{Arc, Weak},
    time::Duration,
};

pub(crate) struct LockedMucExpiryContext {
    service: LockedMucExpiryService<PostgresLockedMucExpiryRepository>,
    local: LockedMucExpiryLocal,
    delivery: MucDeliveryContext,
    domain: String,
    cluster_enabled: bool,
}

struct LockedMucExpiryLocal {
    sessions: Arc<DashMap<String, OnlineSession>>,
    occupants: Arc<DashMap<String, MucOccupant>>,
}

impl LockedMucExpiryContext {
    pub(crate) fn from_state(state: &AppState) -> Self {
        Self {
            service: state.locked_muc_expiry_service.clone(),
            local: LockedMucExpiryLocal {
                sessions: Arc::clone(&state.sessions),
                occupants: Arc::clone(&state.muc_occupants),
            },
            delivery: state.muc_delivery_context(),
            domain: state.config.domain.clone(),
            cluster_enabled: state.cluster.is_enabled(),
        }
    }

    async fn expire_once(&self, heartbeat: &WorkerHeartbeat) {
        // The service returns localparts only after the tombstone and terminal
        // outbox transaction commits. Never clean local routes on a DB error.
        let expired = match self.service.expire_locked_rooms(100).await {
            Ok(expired) => expired,
            Err(error) => {
                heartbeat.error(&error);
                tracing::error!(?error, "could not expire abandoned locked MUC rooms");
                return;
            }
        };
        heartbeat.ok();
        for localpart in expired {
            let room_jid = format!("{}@conference.{}", localpart, self.domain);
            for occupant in self.local.occupants_for(&room_jid) {
                let serializable = SerializableMucOccupant::from(&occupant);
                self.local.remove_exact(&occupant, &serializable);
                if !self.cluster_enabled {
                    let unavailable =
                        crate::xmpp::xml_util::muc_destroy_presence(&serializable, None, None);
                    let _ = self
                        .delivery
                        .deliver_to_muc_occupant(&occupant, unavailable)
                        .await;
                }
            }
            // Cluster nodes catch the committed outbox up from PostgreSQL.
            // A Redis destroy command would create a second execution authority.
        }
    }
}

impl LockedMucExpiryLocal {
    fn occupants_for(&self, room_jid: &str) -> Vec<MucOccupant> {
        let Ok(room_jid) = crate::jid::canonicalize_bare(room_jid) else {
            return Vec::new();
        };
        self.occupants
            .iter()
            .filter(|entry| entry.value().room_jid == room_jid)
            .map(|entry| entry.value().clone())
            .collect()
    }

    fn remove_exact(&self, occupant: &MucOccupant, serializable: &SerializableMucOccupant) {
        remove_live_muc_membership_in(&self.sessions, serializable);
        remove_local_muc_occupant_exact_from(&self.occupants, occupant.into());
    }
}

pub(crate) async fn run_locked_muc_expiry(
    weak: Weak<LockedMucExpiryContext>,
    heartbeat: WorkerHeartbeat,
) -> anyhow::Result<()> {
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        let Some(context) = weak.upgrade() else {
            return Ok(());
        };
        context.expire_once(&heartbeat).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{outbound::OutboundSender, state::MucOccupantEndpoint};

    fn occupant(full_jid: &str, connection_id: uuid::Uuid, epoch: uuid::Uuid) -> MucOccupant {
        let (sender, _receiver) = tokio::sync::mpsc::channel(1);
        MucOccupant {
            full_jid: full_jid.to_owned(),
            room_jid: "room@conference.example.test".to_owned(),
            nick: "Alice".to_owned(),
            endpoint: MucOccupantEndpoint::Local(OutboundSender::new(sender)),
            affiliation: "member".to_owned(),
            role: "participant".to_owned(),
            room_non_anonymous: true,
            occupant_id: "opaque".to_owned(),
            cluster_epoch: epoch,
            connection_id,
            sm_session_id: None,
            payload: String::new(),
        }
    }

    #[test]
    fn stale_expiry_snapshot_keeps_reused_nickname() {
        let occupants = Arc::new(DashMap::new());
        let local = LockedMucExpiryLocal {
            sessions: Arc::new(DashMap::new()),
            occupants: Arc::clone(&occupants),
        };
        let old = occupant(
            "alice@example.test/Phone",
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
        );
        let key = crate::xmpp::xml_util::muc_occupant_key(&old.room_jid, &old.nick);
        occupants.insert(key.clone(), old.clone());
        let snapshot = local.occupants_for(&old.room_jid);
        assert_eq!(snapshot.len(), 1);

        let replacement = occupant(
            "alice@example.test/Tablet",
            old.connection_id,
            old.cluster_epoch,
        );
        occupants.insert(key.clone(), replacement.clone());
        let serializable = SerializableMucOccupant::from(&snapshot[0]);
        local.remove_exact(&snapshot[0], &serializable);
        assert_eq!(occupants.get(&key).unwrap().full_jid, replacement.full_jid);
    }
}
