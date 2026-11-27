use super::*;
use northstar_room_application::room_delivery_policy::{
    RoomDeliveryDecision, RoomDeliveryPolicyQuery, RoomDeliveryPolicyReader,
};

impl RoomDeliveryPolicyReader for Host {
    async fn read_room_delivery_policies(
        &self,
        queries: &[RoomDeliveryPolicyQuery<'_>],
    ) -> Result<Vec<RoomDeliveryDecision>> {
        Ok(vec![RoomDeliveryDecision::Allow; queries.len()])
    }
}

impl crate::ports::MucOccupantPolicyDelivery<OutboundSender, ()> for Host {
    async fn deliver_muc_from(
        &self,
        recipient: &Occupant<Self>,
        stanza: String,
        visible_peer: Option<&str>,
        real_peer: &str,
    ) -> bool {
        assert!(!real_peer.is_empty());
        if let Some(visible_peer) = visible_peer {
            let mut peers = vec![visible_peer.to_owned()];
            if visible_peer != ROOM_JID {
                peers.push(real_peer.to_owned());
            }
            assert!(self
                .blocked_muc_recipient_accounts(std::slice::from_ref(recipient), &peers)
                .await
                .is_empty());
        }
        self.deliver_to_muc_occupant_unchecked(recipient, stanza)
            .await
    }
}
