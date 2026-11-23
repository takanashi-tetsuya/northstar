use super::*;
use northstar_room_core::mix::{MixChannelId, MixRealJid};

impl<E: RoomEffects> MixPamProjectionRepository for PostgresMixRepository<E> {
    async fn destroy_mix_channel_committed(
        &self,
        channel: &MixChannelId,
        actor: &MixRealJid,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<CommittedMixChange<bool>> {
        crate::mix::destroy_mix_channel(
            &self.effects,
            &self.pool,
            channel.as_uuid(),
            actor.as_str(),
            &MixPayloads,
            federated,
        )
        .await
    }

    async fn leave_mix_channel_committed(
        &self,
        channel: &MixChannelId,
        actor: &MixRealJid,
        pam_user: Option<Uuid>,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<CommittedMixChange<Option<LeaveMixOutcome>>> {
        let committed = crate::mix::leave_mix_channel(
            &self.effects,
            &self.pool,
            channel.as_uuid(),
            actor.as_str(),
            pam_user,
            &MixPayloads,
            federated,
        )
        .await?;
        Ok(CommittedMixChange {
            outcome: committed.outcome.map(|left| LeaveMixOutcome {
                participant: left.participant,
                presence_items: left.presence_items.into_iter().map(presence_item).collect(),
                roster_change: left.roster_change,
            }),
            roster: committed.roster,
        })
    }

    async fn set_mix_access_entry_committed(
        &self,
        channel: &MixChannelId,
        actor: &MixRealJid,
        pattern: &str,
        list: MixAccessList,
        operation: MixAccessEntryOperation<'_>,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<CommittedMixChange<Option<AccessChangeOutcome>>> {
        let list = match list {
            MixAccessList::Allowed => crate::mix::MixAccessList::Allowed,
            MixAccessList::Banned => crate::mix::MixAccessList::Banned,
        };
        let operation = match operation {
            MixAccessEntryOperation::Publish { reason } => {
                crate::mix::MixAccessEntryOperation::Publish { reason }
            }
            MixAccessEntryOperation::Retract => crate::mix::MixAccessEntryOperation::Retract,
        };
        let committed = crate::mix::set_mix_access_entry(
            &self.effects,
            &self.pool,
            crate::mix::MixAccessEntryUpdate {
                channel_id: channel.as_uuid(),
                actor: actor.as_str(),
                pattern,
                list,
                operation,
            },
            &MixPayloads,
            federated,
        )
        .await?;
        Ok(committed.map_or_else(
            || CommittedMixChange {
                outcome: None,
                roster: Vec::new(),
            },
            |committed| CommittedMixChange {
                outcome: Some(access_change_outcome(committed.outcome)),
                roster: committed.roster,
            },
        ))
    }

    async fn complete_remote_pam_success_committed(
        &self,
        response: RemotePamResponse<'_>,
        join: Option<RemotePamJoinEvidence<'_>>,
    ) -> Result<CommittedMixChange<RemotePamCompletionOutcome>> {
        let committed = crate::mix::complete_remote_pam_success(
            &self.effects,
            &self.pool,
            response,
            join,
            &MixPayloads,
        )
        .await?;
        Ok(CommittedMixChange {
            outcome: map_pam_completion(committed.outcome),
            roster: committed.roster,
        })
    }
}
