use super::*;
use northstar_muc_xmpp::ports::MucOccupantPolicyDelivery;
use northstar_room_application::room_delivery_policy::{
    RoomDeliveryDecision, RoomDeliveryPolicyQuery, RoomDeliveryPolicyReader,
};
use northstar_stream::{
    local_routes::muc::{MucOccupant, SuspendedMucEndpoint},
    outbound::OutboundSender,
};
use northstar_workflows::muc_delivery_repository::PostgresRoomDeliveryPolicy;

impl RoomDeliveryPolicyReader for ServerNode {
    async fn read_room_delivery_policies(
        &self,
        queries: &[RoomDeliveryPolicyQuery<'_>],
    ) -> anyhow::Result<Vec<RoomDeliveryDecision>> {
        PostgresRoomDeliveryPolicy::new(self.pool.clone())
            .read_room_delivery_policies(queries)
            .await
    }
}

impl MucOccupantPolicyDelivery<OutboundSender, SuspendedMucEndpoint> for ServerNode {
    async fn deliver_muc_from(
        &self,
        occupant: &MucOccupant,
        stanza: String,
        visible_peer: Option<&str>,
        real_peer: &str,
    ) -> bool {
        self.muc_delivery_context()
            .deliver_to_muc_occupant_from(occupant, stanza, visible_peer, Some(real_peer))
            .await
    }
}
