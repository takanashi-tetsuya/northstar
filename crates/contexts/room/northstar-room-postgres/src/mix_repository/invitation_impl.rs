use super::*;

impl<E: RoomEffects> MixInvitationRepository for PostgresMixRepository<E> {
    async fn execute_mix_invitation(
        &self,
        command: &IssueMixInvitation,
        token: &PreparedMixInvitationToken,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<bool> {
        crate::mix::execute_mix_invitation(
            &self.effects,
            &self.pool,
            command,
            token,
            &MixPayloads,
            federated,
        )
        .await
    }
}
