use crate::muc_delivery_repository::{read_room_delivery_policies_on, PostgresRoomDeliveryPolicy};
use anyhow::Result;
use northstar_room_application::room_delivery_policy::{
    MixRelayPolicyReader, RoomDeliveryPolicyQuery, RoomPolicySubject,
};
use northstar_room_core::mix::{MixChannelAddress, MixParticipantId};
use northstar_room_core::mix_iq_relay::RelayPamIncarnation;

impl MixRelayPolicyReader for PostgresRoomDeliveryPolicy {
    async fn read_remote_mix_relay(
        &self,
        policy: &RoomDeliveryPolicyQuery<'_>,
        channel: &MixChannelAddress,
    ) -> Result<Option<RelayPamIncarnation>> {
        if !matches!(policy.route.subject, RoomPolicySubject::Connection { .. })
            || policy.real_peer != Some(channel.as_str())
        {
            return Ok(None);
        }
        let mut transaction = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *transaction)
            .await?;
        let decisions =
            read_room_delivery_policies_on(&mut *transaction, std::slice::from_ref(policy)).await?;
        let incarnation = if matches!(decisions.as_slice(), [decision] if decision.allows()) {
            sqlx::query_as::<_, (uuid::Uuid, Option<String>)>(
                "SELECT id, participant_id FROM mix_pam_memberships
                  WHERE user_id = $1 AND channel_jid = $2 AND state = 'joined'",
            )
            .bind(policy.route.account_id)
            .bind(channel.as_str())
            .fetch_optional(&mut *transaction)
            .await?
            .map(|(membership, participant)| {
                Ok::<_, anyhow::Error>(RelayPamIncarnation {
                    membership,
                    participant: participant
                        .as_deref()
                        .map(MixParticipantId::parse_remote)
                        .transpose()?,
                })
            })
            .transpose()?
        } else {
            None
        };
        transaction.commit().await?;
        Ok(incarnation)
    }
}
