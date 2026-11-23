use super::*;

impl MucRoomDeadlineRepository for Repository {
    async fn room_for_command(&self, localpart: &str) -> Result<Option<MucRoomRead>> {
        Ok(self
            .local_room_snapshot(localpart)
            .await?
            .map(test_room_read))
    }

    async fn reserve_local_room(
        &self,
        _room_id: Uuid,
        localpart: &str,
        creator_id: Uuid,
        creator_full_jid: &str,
    ) -> Result<(MucRoomRead, bool)> {
        let (room, created) = self
            .get_or_create_local_room(localpart, creator_id, creator_full_jid)
            .await?;
        Ok((test_room_read(room), created))
    }

    async fn reserve_federated_room(
        &self,
        _room_id: Uuid,
        localpart: &str,
        creator_full_jid: &str,
    ) -> Result<(MucRoomRead, bool)> {
        let (room, created) = self
            .get_or_create_federated_room(localpart, creator_full_jid)
            .await?;
        Ok((test_room_read(room), created))
    }
}

fn test_room_read(room: MucRoom) -> MucRoomRead {
    MucRoomRead {
        occupant_id_secret_state: if room.occupant_id_secret.is_empty() {
            MucOccupantIdSecretState::AbsentLegacy
        } else {
            MucOccupantIdSecretState::Present
        },
        room,
        configuration_expired: false,
    }
}
