use super::UnusedRepository;
use anyhow::Result;
use northstar_message_application::push::{PushDelivery, PushHandoffAuthority};
use uuid::Uuid;

impl PushHandoffAuthority for UnusedRepository {
    async fn validate_handoff(&self, _: Uuid, _: &PushDelivery) -> Result<bool> {
        panic!("unexpected port call: validate_handoff")
    }
}
