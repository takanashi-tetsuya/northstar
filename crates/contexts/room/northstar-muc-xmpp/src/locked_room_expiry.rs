//! Expire locked rooms after the database commits their tombstones and outbox.

use dashmap::DashMap;
use northstar_federation_core::FederationRoute;
use northstar_room_application::cluster_muc_receipt_claim::ClusterMucReceiptClaimRepository;
use northstar_room_application::locked_muc_expiry::{
    LockedMucExpiryRepository, LockedMucExpiryService,
};
use northstar_room_application::muc_delivery::MucDeliveryRepository;
use northstar_room_application::muc_service::SerializableMucOccupant;
use northstar_room_core::ClusterMucOutboxDelivery;
use northstar_runtime::workers::WorkerHeartbeat;
use northstar_stream::local_routes::muc::MucOccupant;
use northstar_stream::local_routes::muc_table::{
    remove_live_muc_membership_in, remove_local_muc_occupant_exact_from,
};
use northstar_stream::local_routes::session::OnlineSession;
use northstar_stream::muc_delivery::MucDeliveryContext;
use std::{
    sync::{Arc, Weak},
    time::Duration,
};

pub struct LockedMucExpiryContext<E, R, C, F> {
    pub service: LockedMucExpiryService<E>,
    pub local: LockedMucExpiryLocal,
    pub delivery: MucDeliveryContext<R, C, F>,
    pub domain: String,
    pub cluster_enabled: bool,
}

pub struct LockedMucExpiryLocal {
    pub sessions: Arc<DashMap<String, OnlineSession>>,
    pub occupants: Arc<DashMap<String, MucOccupant>>,
}

impl<E, R, C, F> LockedMucExpiryContext<E, R, C, F>
where
    E: LockedMucExpiryRepository,
    R: MucDeliveryRepository,
    C: ClusterMucReceiptClaimRepository<Delivery = ClusterMucOutboxDelivery>,
    F: FederationRoute,
{
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
                    let unavailable = northstar_room_core::stanza::muc_destroy_presence(
                        &serializable,
                        None,
                        None,
                    );
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
        let Ok(room_jid) = northstar_xmpp_types::jid::canonicalize_bare(room_jid) else {
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

pub async fn run_locked_muc_expiry<E, R, C, F>(
    weak: Weak<LockedMucExpiryContext<E, R, C, F>>,
    heartbeat: WorkerHeartbeat,
) -> anyhow::Result<()>
where
    E: LockedMucExpiryRepository,
    R: MucDeliveryRepository,
    C: ClusterMucReceiptClaimRepository<Delivery = ClusterMucOutboxDelivery>,
    F: FederationRoute,
{
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
    use northstar_stream::local_routes::muc::MucOccupantEndpoint;
    use northstar_stream::outbound::OutboundSender;

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
        let key = northstar_room_core::stanza::muc_occupant_key(&old.room_jid, &old.nick);
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
