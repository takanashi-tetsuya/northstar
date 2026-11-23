use super::UnusedPorts;
use northstar_message_application::messaging::invitation_admission::{
    DirectInvitation, DirectInvitationGrant, DirectInvitationOutcome, DirectInvitationRepository,
};

impl DirectInvitationRepository for UnusedPorts {
    async fn admit_direct_invitation(
        &self,
        _: &DirectInvitation<'_>,
        _: Option<DirectInvitationGrant<'_>>,
    ) -> anyhow::Result<DirectInvitationOutcome> {
        panic!("unused direct invitation admission port")
    }
}
