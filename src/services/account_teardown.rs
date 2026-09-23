//! Read the committed authorization generation before cross-node teardown.

use anyhow::Result;
use std::future::Future;
use uuid::Uuid;

pub(crate) trait AccountGenerationRepository: Send + Sync {
    fn generation(&self, user_id: Uuid) -> impl Future<Output = Result<Option<i64>>> + Send;
}

pub(crate) struct AccountGenerationService<R> {
    repository: R,
}

impl<R: AccountGenerationRepository> AccountGenerationService<R> {
    pub(crate) fn new(repository: R) -> Self {
        Self { repository }
    }

    pub(crate) async fn committed_generation(&self, user_id: Uuid) -> Result<i64> {
        Ok(self
            .repository
            .generation(user_id)
            .await?
            .unwrap_or(i64::MAX))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Stub(Option<i64>);

    impl AccountGenerationRepository for Stub {
        async fn generation(&self, _user_id: Uuid) -> Result<Option<i64>> {
            Ok(self.0)
        }
    }

    #[tokio::test]
    async fn deleted_account_uses_full_revocation_fence() {
        let service = AccountGenerationService::new(Stub(None));
        assert_eq!(
            service.committed_generation(Uuid::new_v4()).await.unwrap(),
            i64::MAX
        );
    }
}
