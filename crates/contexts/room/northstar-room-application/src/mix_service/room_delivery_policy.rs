use super::MixService;
use crate::room_delivery_policy::{
    RoomDeliveryDecision, RoomDeliveryPolicyQuery, RoomDeliveryPolicyReader,
};
use anyhow::Result;

impl<R> MixService<R> {
    pub async fn outbox_room_delivery_policies(
        &self,
        reader: &impl RoomDeliveryPolicyReader,
        queries: &[RoomDeliveryPolicyQuery<'_>],
    ) -> Result<Vec<RoomDeliveryDecision>> {
        let _outbox_db_admission = self.outbox_db_admission_guard().await;
        reader.read_room_delivery_policies(queries).await
    }
}
