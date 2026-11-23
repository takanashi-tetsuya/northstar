use super::Repository;
use crate::mix_service::{
    FederatedMixMutation, IssueMixInvitation, MixInvitationRepository, PreparedMixInvitationToken,
};
use anyhow::Result;

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
