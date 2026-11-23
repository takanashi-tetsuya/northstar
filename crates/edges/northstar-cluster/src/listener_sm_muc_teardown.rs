//! Exact suspended-MUC teardown after durable session authority is established.

use crate::{ClusterAdapters, ClusterSmMucTeardownProjection};
use northstar_room_application::muc_service::{
    CommittedRoomRetirement, LocalMucOccupantIdentity, SerializableMucOccupant,
};
use northstar_room_application::sm_teardown_muc::SmTeardownMucService;
use northstar_room_core::occupancy::MucOccupantRoute;
use northstar_stream::local_routes::muc_table::{
    remove_live_muc_membership_in, remove_local_muc_occupant_exact_from,
    with_local_muc_occupant_exact,
};
use northstar_stream::local_routes::sm_teardown::SmTeardownLocalEffects;
use northstar_xmpp_types::jid_text::localpart;

pub struct ClusterListenerSmMucTeardown<A: ClusterAdapters> {
    pub local: SmTeardownLocalEffects,
    pub redis: ClusterSmMucTeardownProjection,
    pub rooms: SmTeardownMucService<A::SmTeardownMuc>,
    pub delivery: super::ClusterMucDelivery<A>,
    pub local_domain: String,
}

impl<A: ClusterAdapters> ClusterListenerSmMucTeardown<A> {
    pub async fn teardown_exact(
        &self,
        sm_session_id: uuid::Uuid,
        occupant: &SerializableMucOccupant,
    ) -> anyhow::Result<usize> {
        if self
            .local
            .remove_exact_suspended_occupant(sm_session_id, occupant)
        {
            self.redis
                .unregister_muc_occupant_epoch(
                    &occupant.room_jid,
                    &occupant.nick,
                    occupant.cluster_epoch,
                    occupant.connection_id,
                )
                .await?;
        }
        let route = MucOccupantRoute::from(LocalMucOccupantIdentity::from(occupant));
        let Some(room) = self
            .rooms
            .departed_room(localpart(&occupant.room_jid), &route, sm_session_id)
            .await?
        else {
            return Ok(0);
        };
        let remaining: Vec<_> = self
            .rooms
            .departure_observers(room, &occupant.nick)
            .await?
            .into_iter()
            .filter(|route| {
                with_local_muc_occupant_exact(
                    &self.local.occupants,
                    route.identity(&occupant.room_jid),
                    |_| (),
                )
                .is_some()
            })
            .collect();
        let occupant_jids = remaining
            .iter()
            .map(|route| route.full_jid.clone())
            .collect::<Vec<_>>();
        let visible_sender = format!("{}/{}", occupant.room_jid, occupant.nick);
        let blocked = self
            .rooms
            .blocked_local_audience(
                &self.local_domain,
                &occupant_jids,
                &[visible_sender, occupant.full_jid.clone()],
            )
            .await?;
        let mut delivered = 0;
        for route in &remaining {
            if northstar_xmpp_types::jid::canonical_bare_key(&route.full_jid)
                .is_ok_and(|owner| blocked.contains(&owner))
            {
                continue;
            }
            let Some(target) = with_local_muc_occupant_exact(
                &self.local.occupants,
                route.identity(&occupant.room_jid),
                |target| target.clone(),
            ) else {
                continue;
            };
            let presence = northstar_room_core::stanza::muc_presence_stanza(
                occupant,
                &target.full_jid,
                true,
                false,
                false,
                None,
                occupant.room_non_anonymous || target.role == "moderator",
            );
            delivered += usize::from(
                self.delivery
                    .deliver_to_muc_occupant_unchecked_result(&target, presence)
                    .await?,
            );
        }
        if remaining.is_empty() {
            self.redis.leave_muc(&occupant.room_jid).await?;
        }
        let globally_empty = self.redis.room_is_empty(&occupant.room_jid).await?;
        let retirement = if globally_empty && remaining.is_empty() {
            self.rooms.retire_empty_temporary_room(room).await?
        } else {
            None
        };
        if let Some(retirement) = retirement {
            remove_retirement(
                &self.local,
                &self.delivery.sessions,
                &occupant.room_jid,
                &retirement,
            );
        }
        Ok(delivered)
    }
}

fn remove_retirement(
    local: &SmTeardownLocalEffects,
    sessions: &dashmap::DashMap<String, northstar_stream::local_routes::session::OnlineSession>,
    room_jid: &str,
    retirement: &CommittedRoomRetirement,
) {
    for occupant in &retirement.occupants {
        if let Some(removed) = remove_local_muc_occupant_exact_from(
            &local.occupants,
            occupant.route.identity(room_jid),
        ) {
            remove_live_muc_membership_in(sessions, &SerializableMucOccupant::from(&removed));
        }
    }
}

#[cfg(test)]
mod retirement_tests;
