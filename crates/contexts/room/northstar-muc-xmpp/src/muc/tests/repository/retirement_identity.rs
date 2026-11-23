use super::*;

impl MucRetirementIdentityRepository for Repository {
    async fn commit_retirement(
        &self,
        _operation_id: Uuid,
        retirement: MucRetirement<'_>,
    ) -> Result<Option<CommittedRoomRetirement>> {
        match retirement {
            MucRetirement::Expire(room_id) => self.expire_locked_room_exact(room_id).await,
            MucRetirement::Cancel {
                room_id,
                actor_full_jid,
            } => self.cancel_locked_room_exact(room_id, actor_full_jid).await,
            MucRetirement::Destroy(room_id) => self.retire_room(room_id).await,
            MucRetirement::Temporary {
                room,
                config_version,
            } => self.retire_empty_temporary_room(room, config_version).await,
        }
    }
}
