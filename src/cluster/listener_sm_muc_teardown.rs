//! Exact suspended-MUC teardown after durable session authority is established.

use crate::platform::jid_text::localpart;
use crate::services::muc::SerializableMucOccupant;
use crate::xmpp::local_routes::sm_teardown::SmTeardownLocalEffects;
use crate::{
    cluster::ClusterSmMucTeardownProjection,
    db::sm_teardown_muc_repository::PostgresSmTeardownMucRepository,
    services::sm_teardown_muc::SmTeardownMucService,
};

pub(crate) struct ClusterListenerSmMucTeardown {
    pub(crate) local: SmTeardownLocalEffects,
    pub(crate) redis: ClusterSmMucTeardownProjection,
    pub(crate) rooms: SmTeardownMucService<PostgresSmTeardownMucRepository>,
    pub(crate) delivery: crate::xmpp::muc_delivery::MucDeliveryContext,
    pub(crate) local_domain: String,
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
            if northstar_xmpp_types::jid::canonical_bare_key(&target.full_jid)
                .is_ok_and(|owner| blocked.contains(&owner))
            {
                continue;
            }
            let presence = crate::services::xml_util::muc_presence_stanza(
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
