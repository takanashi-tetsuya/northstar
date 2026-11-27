use super::*;
use northstar_room_application::room_delivery_policy::{
    MixRelayPolicyReader, RoomDeliveryDecision, RoomDeliveryPolicyQuery, RoomDeliveryPolicyReader,
};
use northstar_room_core::{mix::MixChannelAddress, mix_iq_relay::RelayPamIncarnation};

impl RoomDeliveryPolicyReader for Host {
    async fn read_room_delivery_policies(
        &self,
        _: &[RoomDeliveryPolicyQuery<'_>],
    ) -> Result<Vec<RoomDeliveryDecision>> {
        panic!("unexpected MIX user-resource policy")
    }
}

impl MixRelayPolicyReader for Host {
    async fn read_remote_mix_relay(
        &self,
        _: &RoomDeliveryPolicyQuery<'_>,
        _: &MixChannelAddress,
    ) -> Result<Option<RelayPamIncarnation>> {
        panic!("unexpected MIX relay policy")
    }
}
