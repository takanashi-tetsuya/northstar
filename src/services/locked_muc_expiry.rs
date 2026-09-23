//! Expire abandoned locked rooms through one committed database use case.

use anyhow::Result;
use std::future::Future;

pub(crate) trait LockedMucExpiryRepository: Send + Sync {
    /// Return room localparts only after the tombstones and terminal outbox
    /// records have committed together.
    fn expire_locked_rooms(&self, limit: i64) -> impl Future<Output = Result<Vec<String>>> + Send;
}

pub(crate) struct LockedMucExpiryService<R> {
    repository: R,
}

impl<R: LockedMucExpiryRepository> LockedMucExpiryService<R> {
    pub(crate) fn new(repository: R) -> Self {
        Self { repository }
    }

    pub(crate) async fn expire_locked_rooms(&self, limit: i64) -> Result<Vec<String>> {
        self.repository.expire_locked_rooms(limit).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct StubRepository {
        result: Mutex<Option<Result<Vec<String>>>>,
        limits: Mutex<Vec<i64>>,
    }

    impl LockedMucExpiryRepository for &StubRepository {
        async fn expire_locked_rooms(&self, limit: i64) -> Result<Vec<String>> {
            self.limits.lock().unwrap().push(limit);
            self.result.lock().unwrap().take().unwrap()
        }
    }

    #[tokio::test]
    async fn returns_only_committed_room_localparts_in_repository_order() {
        let repository = StubRepository {
            result: Mutex::new(Some(Ok(vec!["first".into(), "second".into()]))),
            limits: Mutex::new(Vec::new()),
        };
        let service = LockedMucExpiryService::new(&repository);
        assert_eq!(
            service.expire_locked_rooms(100).await.unwrap(),
            vec!["first".to_owned(), "second".to_owned()]
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
