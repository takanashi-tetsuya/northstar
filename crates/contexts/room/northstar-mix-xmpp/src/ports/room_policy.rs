use crate::channel_delivery::ChannelStanzaDatabaseLane;
use anyhow::Result;
use northstar_room_application::room_delivery_policy::{
    RoomDeliveryDecision, RoomDeliveryPolicyQuery, RoomPolicyRoute,
};
use std::future::Future;

pub trait MixChannelPolicyReader: Send + Sync {
    fn channel_policy_route_is_current(&self, full_jid: &str, route: RoomPolicyRoute) -> bool;

    fn read_channel_delivery_policies(
        &self,
        queries: &[RoomDeliveryPolicyQuery<'_>],
        lane: ChannelStanzaDatabaseLane,
    ) -> impl Future<Output = Result<Vec<RoomDeliveryDecision>>> + Send;
}
