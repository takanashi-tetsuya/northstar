use super::*;

impl MixPamDeliveryRepository for ControlledRepository {
    async fn pam_delivery_view(
        &self,
        _query: PamDeliveryQuery<'_>,
    ) -> Result<Option<PamDeliveryAuthority>> {
        Err(self.unused("pam_delivery_view"))
    }
}
