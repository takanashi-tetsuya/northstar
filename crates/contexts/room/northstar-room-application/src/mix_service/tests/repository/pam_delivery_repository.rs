use super::Repository;
use crate::mix_service::{MixPamDeliveryRepository, PamDeliveryAuthority, PamDeliveryQuery};
use anyhow::Result;

impl MixPamDeliveryRepository for Repository {
    async fn pam_delivery_view(
        &self,
        _query: PamDeliveryQuery<'_>,
    ) -> Result<Option<PamDeliveryAuthority>> {
        panic!("unexpected port call: pam_delivery_view")
    }
}
