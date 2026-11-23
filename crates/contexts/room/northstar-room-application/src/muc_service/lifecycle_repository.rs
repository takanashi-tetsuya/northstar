use anyhow::Result;
use northstar_room_core::occupancy::MucOccupantRoute;
use std::future::Future;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MucRoomIncarnation {
    pub room_id: Uuid,
    pub room_epoch: Uuid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetiredMucOccupant {
    pub route: MucOccupantRoute,
    pub status_codes: &'static [u16],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommittedRoomRetirement {
    pub room: MucRoomIncarnation,
    pub localpart: String,
    pub operation_id: Uuid,
    pub occupants: Vec<RetiredMucOccupant>,
}

pub trait MucLifecycleRepository: Send + Sync {
    fn expire_locked_room_exact(
        &self,
        room_id: Uuid,
    ) -> impl Future<Output = Result<Option<CommittedRoomRetirement>>> + Send;

    fn cancel_locked_room_exact(
        &self,
        room_id: Uuid,
        actor_full_jid: &str,
    ) -> impl Future<Output = Result<Option<CommittedRoomRetirement>>> + Send;

    fn retire_room(
        &self,
        room_id: Uuid,
    ) -> impl Future<Output = Result<Option<CommittedRoomRetirement>>> + Send;

    fn retire_empty_temporary_room(
        &self,
        room: MucRoomIncarnation,
        expected_config_version: Option<i64>,
    ) -> impl Future<Output = Result<Option<CommittedRoomRetirement>>> + Send;

    fn departed_room(
        &self,
        localpart: &str,
        route: &MucOccupantRoute,
    ) -> impl Future<Output = Result<Option<MucRoomIncarnation>>> + Send;
}
