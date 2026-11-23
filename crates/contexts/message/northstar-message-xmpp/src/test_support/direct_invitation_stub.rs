use super::Repository;
use northstar_message_application::messaging::invitation_admission::{
    DirectInvitation, DirectInvitationGrant, DirectInvitationOutcome, DirectInvitationRepository,
};

impl DirectInvitationRepository for Repository {
    async fn admit_direct_invitation(
        &self,
        _: &DirectInvitation<'_>,
        _: Option<DirectInvitationGrant<'_>>,
    ) -> anyhow::Result<DirectInvitationOutcome> {
        panic!("unexpected direct invitation admission")
    }
}
