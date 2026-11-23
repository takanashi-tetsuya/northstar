//! Expire abandoned locked rooms through one committed database use case.

use crate::muc_service::CommittedRoomRetirement;
use anyhow::Result;
use std::future::Future;

pub trait LockedMucExpiryRepository: Send + Sync {
    /// Return exact retirements only after the tombstones and terminal outbox
    /// records have committed together.
    fn expire_locked_rooms(
        &self,
        limit: i64,
    ) -> impl Future<Output = Result<Vec<CommittedRoomRetirement>>> + Send;
}

#[derive(Clone)]
pub struct LockedMucExpiryService<R> {
    repository: R,
}

impl<R: LockedMucExpiryRepository> LockedMucExpiryService<R> {
    pub fn new(repository: R) -> Self {
        Self { repository }
    }

    pub async fn expire_locked_rooms(&self, limit: i64) -> Result<Vec<CommittedRoomRetirement>> {
        self.repository.expire_locked_rooms(limit).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::muc_service::MucRoomIncarnation;
    use std::sync::Mutex;
    use uuid::Uuid;

    struct StubRepository {
        result: Mutex<Option<Result<Vec<CommittedRoomRetirement>>>>,
        limits: Mutex<Vec<i64>>,
    }

    impl LockedMucExpiryRepository for &StubRepository {
        async fn expire_locked_rooms(&self, limit: i64) -> Result<Vec<CommittedRoomRetirement>> {
            self.limits.lock().unwrap().push(limit);
            self.result.lock().unwrap().take().unwrap()
        }
    }

    #[tokio::test]
    async fn returns_only_committed_room_localparts_in_repository_order() {
        let committed = ["first", "second"].map(|localpart| CommittedRoomRetirement {
            room: MucRoomIncarnation {
                room_id: Uuid::new_v4(),
                room_epoch: Uuid::new_v4(),
            },
            localpart: localpart.to_owned(),
            operation_id: Uuid::new_v4(),
            occupants: Vec::new(),
        });
        let repository = StubRepository {
            result: Mutex::new(Some(Ok(committed.to_vec()))),
            limits: Mutex::new(Vec::new()),
        };
        let service = LockedMucExpiryService::new(&repository);
        assert_eq!(
            service.expire_locked_rooms(100).await.unwrap(),
            committed.to_vec()
        );
        assert_eq!(*repository.limits.lock().unwrap(), vec![100]);
    }

    #[tokio::test]
    async fn propagates_repository_failure_without_room_localparts() {
        let repository = StubRepository {
            result: Mutex::new(Some(Err(anyhow::anyhow!("expiry transaction rolled back")))),
            limits: Mutex::new(Vec::new()),
        };
        let service = LockedMucExpiryService::new(&repository);
        let error = service.expire_locked_rooms(100).await.unwrap_err();
        assert!(error.to_string().contains("transaction rolled back"));
        assert_eq!(*repository.limits.lock().unwrap(), vec![100]);
    }
}
