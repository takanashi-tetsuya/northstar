use super::Repository;
use anyhow::Result;
use northstar_room_application::mix_service::{
    FederatedMixMutation, IssueMixInvitation, MixInvitationRepository, PreparedMixInvitationToken,
};

impl MixInvitationRepository for Repository {
    async fn execute_mix_invitation(
        &self,
        _command: &IssueMixInvitation,
        _token: &PreparedMixInvitationToken,
        _federated: Option<&FederatedMixMutation>,
    ) -> Result<bool> {
        panic!("unexpected repository call: execute_mix_invitation")
    }
}
