//! Durable claim authority for S2S stream-management replay and acknowledgements.
//! The protocol retains its pending queue; this service checks each fenced
//! database claim before that queue may advance.

use anyhow::{ensure, Result};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SmOutboxClaim {
    pub(crate) id: Uuid,
    pub(crate) lock_token: Uuid,
}

pub(crate) trait SmOutboxRepository: Send + Sync {
    async fn renew(&self, claim: SmOutboxClaim, lease_seconds: u64) -> Result<bool>;
    async fn complete(&self, claim: SmOutboxClaim) -> Result<bool>;
}

pub(crate) struct SmOutboxService<R> {
    repository: R,
}

impl<R: SmOutboxRepository> SmOutboxService<R> {
    pub(crate) fn new(repository: R) -> Self {
        Self { repository }
    }

    /// Renew in stream order, failing at the first lost lease. The caller's
    /// existing deadline bounds the complete batch, not each individual row.
    pub(crate) async fn renew_pending(
        &self,
        claims: &[SmOutboxClaim],
        lease_seconds: u64,
    ) -> Result<()> {
        for &claim in claims {
            ensure!(
                self.repository.renew(claim, lease_seconds).await?,
                "S2S replay lost its outbox lease"
            );
        }
        Ok(())
    }

    /// A successful fenced delete permits exactly one pending queue item to
    /// advance; failure leaves it in place for the existing retry path.
    pub(crate) async fn complete_acknowledged(&self, claim: SmOutboxClaim) -> Result<()> {
        ensure!(
            self.repository.complete(claim).await?,
            "S2S outbox lease was lost before acknowledgement"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct StubRepository {
        renewed: Mutex<Vec<SmOutboxClaim>>,
        completed: Mutex<Vec<SmOutboxClaim>>,
        fail_renew_at: Option<usize>,
        fail_complete: bool,
    }

    impl SmOutboxRepository for StubRepository {
        async fn renew(&self, claim: SmOutboxClaim, lease_seconds: u64) -> Result<bool> {
            assert_eq!(lease_seconds, 150);
            let mut renewed = self.renewed.lock().unwrap();
            renewed.push(claim);
            Ok(self.fail_renew_at != Some(renewed.len()))
        }

        async fn complete(&self, claim: SmOutboxClaim) -> Result<bool> {
            self.completed.lock().unwrap().push(claim);
            Ok(!self.fail_complete)
        }
    }

    fn claim(id: u128) -> SmOutboxClaim {
        SmOutboxClaim {
            id: Uuid::from_u128(id),
            lock_token: Uuid::from_u128(id + 100),
        }
    }

    #[tokio::test]
    async fn renewal_preserves_stream_order_and_stops_at_lost_claim() {
        let service = SmOutboxService::new(StubRepository {
            fail_renew_at: Some(2),
            ..StubRepository::default()
        });
        let claims = [claim(1), claim(2), claim(3)];
        let error = service.renew_pending(&claims, 150).await.unwrap_err();
        assert!(error
            .to_string()
            .contains("S2S replay lost its outbox lease"));
        assert_eq!(*service.repository.renewed.lock().unwrap(), claims[..2]);
    }

    #[tokio::test]
    async fn acknowledgement_requires_fenced_delete() {
        let service = SmOutboxService::new(StubRepository {
            fail_complete: true,
            ..StubRepository::default()
        });
        let error = service.complete_acknowledged(claim(7)).await.unwrap_err();
        assert!(error
            .to_string()
            .contains("S2S outbox lease was lost before acknowledgement"));
        assert_eq!(*service.repository.completed.lock().unwrap(), [claim(7)]);
    }

    #[tokio::test]
    async fn valid_claims_are_renewed_and_completed_with_original_tokens() {
        let service = SmOutboxService::new(StubRepository::default());
        let claims = [claim(11), claim(12)];
        service.renew_pending(&claims, 150).await.unwrap();
        service.complete_acknowledged(claims[0]).await.unwrap();
        assert_eq!(
            service.repository.renewed.lock().unwrap().as_slice(),
            claims
        );
        assert_eq!(
            service.repository.completed.lock().unwrap().as_slice(),
            [claims[0]]
        );
    }
}
