use super::*;

impl<E: RoomEffects> MixPamDeliveryRepository for PostgresMixRepository<E> {
    async fn pam_delivery_view(
        &self,
        query: PamDeliveryQuery<'_>,
    ) -> Result<Option<PamDeliveryAuthority>> {
        crate::mix::pam_delivery_view(&self.pool, query).await
    }
}
