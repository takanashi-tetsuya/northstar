use super::*;
use northstar_mix_xmpp::{
    channel_delivery::ChannelStanzaDatabaseLane, ports::MixChannelPolicyReader,
};
use northstar_room_application::room_delivery_policy::{
    MixRelayPolicyReader, RoomDeliveryDecision, RoomDeliveryPolicyQuery, RoomDeliveryPolicyReader,
    RoomPolicyLiveSession, RoomPolicyRoute,
};
use northstar_room_core::{mix::MixChannelAddress, mix_iq_relay::RelayPamIncarnation};
use northstar_workflows::muc_delivery_repository::PostgresRoomDeliveryPolicy;

impl MixChannelPolicyReader for MixOutboxContext {
    fn channel_policy_route_is_current(&self, full_jid: &str, route: RoomPolicyRoute) -> bool {
        self.sessions.get(full_jid).is_some_and(|current| {
            current.routable.load(std::sync::atomic::Ordering::Acquire)
                && current.room_policy_route() == route
        })
    }

    async fn read_channel_delivery_policies(
        &self,
        queries: &[RoomDeliveryPolicyQuery<'_>],
        lane: ChannelStanzaDatabaseLane,
    ) -> Result<Vec<RoomDeliveryDecision>> {
        match lane {
            ChannelStanzaDatabaseLane::LiveIngress => {
                self.room_policy.read_room_delivery_policies(queries).await
            }
            ChannelStanzaDatabaseLane::DurableOutbox => {
                self.service
                    .outbox_room_delivery_policies(&self.room_policy, queries)
                    .await
            }
        }
    }
}

impl MixRelayPolicyReader for ServerNode {
    async fn read_remote_mix_relay(
        &self,
        policy: &RoomDeliveryPolicyQuery<'_>,
        channel: &MixChannelAddress,
    ) -> Result<Option<RelayPamIncarnation>> {
        PostgresRoomDeliveryPolicy::new(self.pool.clone())
            .read_remote_mix_relay(policy, channel)
            .await
    }
}
