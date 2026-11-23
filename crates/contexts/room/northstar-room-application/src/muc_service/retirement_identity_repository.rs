use super::{CommittedRoomRetirement, MucRoomIncarnation};
use anyhow::Result;
use std::future::Future;
use uuid::Uuid;

pub enum MucRetirement<'a> {
    Expire(Uuid),
    Cancel {
        room_id: Uuid,
        actor_full_jid: &'a str,
    },
    Destroy(Uuid),
    Temporary {
        room: MucRoomIncarnation,
        config_version: Option<i64>,
    },
}

/// Commit a lifecycle operation whose identity was allocated by the caller.
pub trait MucRetirementIdentityRepository {
    fn commit_retirement(
        &self,
        operation_id: Uuid,
        retirement: MucRetirement<'_>,
    ) -> impl Future<Output = Result<Option<CommittedRoomRetirement>>> + Send;
}
