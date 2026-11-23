use super::{PostgresMucRepository, RoomEffects};
use anyhow::Result;
use northstar_room_application::muc_service::{
    CommittedRoomRetirement, MucRetirement, MucRetirementIdentityRepository,
};
use sqlx::PgPool;
use uuid::Uuid;

impl<E: RoomEffects> MucRetirementIdentityRepository for PostgresMucRepository<E> {
    async fn commit_retirement(
        &self,
        operation_id: Uuid,
        retirement: MucRetirement<'_>,
    ) -> Result<Option<CommittedRoomRetirement>> {
        commit_muc_retirement(&self.pool, operation_id, retirement).await
    }
}

pub async fn commit_muc_retirement(
    pool: &PgPool,
    operation_id: Uuid,
    retirement: MucRetirement<'_>,
) -> Result<Option<CommittedRoomRetirement>> {
    match retirement {
        MucRetirement::Expire(room_id) => {
            crate::muc::expire_locked_muc_room_with_id(pool, room_id, operation_id).await
        }
        MucRetirement::Cancel {
            room_id,
            actor_full_jid,
        } => {
            crate::muc::cancel_locked_muc_room_with_id(pool, room_id, actor_full_jid, operation_id)
                .await
        }
        MucRetirement::Destroy(room_id) => {
            crate::muc::delete_muc_room_with_id(pool, room_id, operation_id).await
        }
        MucRetirement::Temporary {
            room,
            config_version,
        } => {
            crate::muc::delete_temporary_muc_room_with_id(pool, room, config_version, operation_id)
                .await
        }
    }
}
