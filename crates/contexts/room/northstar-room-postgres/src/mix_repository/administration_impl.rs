use super::*;

impl<E: RoomEffects> MixAdministrationRepository for PostgresMixRepository<E> {
    async fn update_preference(
        &self,
        channel_id: MixChannelId,
        actor: &MixRealJid,
        patch: PreferencePatch,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<Option<CommittedPreference>> {
        crate::mix::apply_preference_patch(
            &self.effects,
            &self.pool,
            channel_id,
            actor,
            patch,
            &MixPayloads,
            federated,
        )
        .await
    }

    async fn update_info(
        &self,
        channel_id: MixChannelId,
        actor: &MixRealJid,
        patch: InfoPatch,
        item_id: String,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<MixMutationOutcome> {
        Ok(map_outcome(
            crate::mix::apply_info_patch(
                &self.effects,
                &self.pool,
                channel_id,
                actor,
                &patch,
                &item_id,
                &MixPayloads,
                federated,
            )
            .await?,
        ))
    }

    async fn update_config(
        &self,
        channel_id: MixChannelId,
        actor: &MixRealJid,
        patch: ConfigPatch,
        item_id: String,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<MixMutationOutcome> {
        Ok(map_outcome(
            crate::mix::apply_config_patch(
                &self.effects,
                &self.pool,
                channel_id,
                actor,
                &patch,
                &item_id,
                &MixPayloads,
                federated,
            )
            .await?,
        ))
    }
}

fn map_outcome(outcome: crate::mix::MixMutationOutcome) -> MixMutationOutcome {
    match outcome {
        crate::mix::MixMutationOutcome::Applied(admission) => {
            MixMutationOutcome::Applied(Box::new(mutation_admission(*admission)))
        }
        crate::mix::MixMutationOutcome::Conflict => MixMutationOutcome::Conflict,
        crate::mix::MixMutationOutcome::Forbidden => MixMutationOutcome::Forbidden,
        crate::mix::MixMutationOutcome::NotFound => MixMutationOutcome::NotFound,
    }
}
