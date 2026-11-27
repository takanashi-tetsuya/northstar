use super::UnusedPorts;
use northstar_roster_application::{
    CommunicationDecision, CommunicationPolicyQuery, CommunicationPolicyReader,
};

impl CommunicationPolicyReader for UnusedPorts {
    async fn read_communication_policies(
        &self,
        _queries: &[CommunicationPolicyQuery],
    ) -> anyhow::Result<Vec<CommunicationDecision>> {
        panic!("unused communication policy read")
    }
}
