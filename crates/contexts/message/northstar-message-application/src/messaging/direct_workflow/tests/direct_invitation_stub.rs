use super::RecordingCommit;
use crate::messaging::invitation_admission::{
    DirectInvitation, DirectInvitationGrant, DirectInvitationOutcome, DirectInvitationRepository,
};

impl DirectInvitationRepository for RecordingCommit {
    async fn admit_direct_invitation(
        &self,
        _: &DirectInvitation<'_>,
        _: Option<DirectInvitationGrant<'_>>,
    ) -> anyhow::Result<DirectInvitationOutcome> {
        panic!("unexpected direct invitation admission")
    }
}
