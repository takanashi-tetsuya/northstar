//! Exact suspended-MUC teardown after durable session authority is established.

use super::{
    localpart, sm_teardown_local::SmTeardownLocalEffects, AppState, SerializableMucOccupant,
};
use crate::{
    cluster::ClusterSmMucTeardownProjection,
    db::sm_teardown_muc_repository::PostgresSmTeardownMucRepository,
    services::sm_teardown_muc::SmTeardownMucService,
};

pub(crate) struct ClusterListenerSmMucTeardown {
    local: SmTeardownLocalEffects,
    redis: ClusterSmMucTeardownProjection,
    rooms: SmTeardownMucService<PostgresSmTeardownMucRepository>,
    delivery: super::muc_delivery::MucDeliveryContext,
    local_domain: String,
}

impl AppState {
    pub(crate) fn cluster_listener_sm_muc_teardown(&self) -> ClusterListenerSmMucTeardown {
        ClusterListenerSmMucTeardown {
            local: self.sm_teardown_local_effects(),
            redis: self.cluster.sm_muc_teardown_projection(),
            rooms: self.sm_teardown_muc_service(),
            delivery: self.muc_delivery_context(),
            local_domain: self.config.domain.clone(),
        }
    }
}

impl ClusterListenerSmMucTeardown {
    pub(crate) async fn teardown_exact(
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
        let remaining = self.local.room_occupants(&occupant.room_jid);
        let occupant_jids = remaining
            .iter()
            .map(|(_, target)| target.full_jid.clone())
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
        for (_, target) in &remaining {
            if crate::jid::canonical_bare_key(&target.full_jid)
                .is_ok_and(|owner| blocked.contains(&owner))
            {
                continue;
            }
            let presence = crate::xmpp::xml_util::muc_presence_stanza(
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
                    .deliver_to_muc_occupant_unchecked_result(target, presence)
                    .await?,
            );
        }
        if remaining.is_empty() {
            self.redis.leave_muc(&occupant.room_jid).await?;
        }
        let globally_empty = self.redis.room_is_empty(&occupant.room_jid).await?;
        if globally_empty && remaining.is_empty() {
            self.rooms
                .retire_empty_temporary_room(localpart(&occupant.room_jid))
                .await?;
        }
        Ok(delivered)
    }
}
