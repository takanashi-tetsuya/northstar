use super::UnusedRepository;
use northstar_roster_application::{
    CommunicationDecision, CommunicationPolicyQuery, CommunicationPolicyReader,
};

impl CommunicationPolicyReader for UnusedRepository {
    async fn read_communication_policies(
        &self,
        _queries: &[CommunicationPolicyQuery],
    ) -> anyhow::Result<Vec<CommunicationDecision>> {
        panic!("unexpected communication policy read")
    }
}
