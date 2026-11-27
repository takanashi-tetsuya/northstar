use northstar_room_core::occupancy::MucOccupant;
use std::future::Future;

pub trait MucOccupantPolicyDelivery<L, S>: Send + Sync {
    fn deliver_muc_from(
        &self,
        occupant: &MucOccupant<L, S>,
        stanza: String,
        visible_peer: Option<&str>,
        real_peer: &str,
    ) -> impl Future<Output = bool> + Send;
}
