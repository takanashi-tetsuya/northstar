use super::*;

impl PushHandoffAuthority for StubRepository {
    async fn validate_handoff(&self, _: Uuid, _: &PushDelivery) -> Result<bool> {
        unreachable!()
    }
}

#[tokio::test]
async fn a_stale_claim_is_neither_a_queue_attempt_nor_a_provider_failure() {
    let (result, trace) = dispatch(Failure::Stale).await;
    result.unwrap();
    assert_eq!(trace, ["claim", "route", "route", "routed", "attempted"]);
}
