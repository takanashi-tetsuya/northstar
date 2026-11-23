use super::UnusedRepository;
use anyhow::Result;
use northstar_room_application::mix_service::{
    MixPamDeliveryRepository, PamDeliveryAuthority, PamDeliveryQuery,
};

impl MixPamDeliveryRepository for UnusedRepository {
    async fn pam_delivery_view(
        &self,
        _query: PamDeliveryQuery<'_>,
    ) -> Result<Option<PamDeliveryAuthority>> {
        panic!("unexpected port call: pam_delivery_view")
    }
}
