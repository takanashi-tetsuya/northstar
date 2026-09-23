//! Exact process-instance lease release after signed publication has quiesced.
//! The caller owns the publication fence; this service owns only one database
//! release command and never receives cluster transport or signing authority.

use anyhow::Result;
use std::future::Future;
use uuid::Uuid;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ClusterInstanceReleaseIdentity {
    pub(crate) xmpp_domain: String,
    pub(crate) node_id: String,
    pub(crate) instance_uuid: Uuid,
    pub(crate) instance_epoch: i64,
    pub(crate) signing_key_id: String,
    pub(crate) signing_key_epoch: i64,
}

pub(crate) trait ClusterInstanceReleaseRepository: Send + Sync {
    fn release(
        &self,
        identity: &ClusterInstanceReleaseIdentity,
    ) -> impl Future<Output = Result<bool>> + Send;
}

pub(crate) struct ClusterInstanceReleaseService<R> {
    repository: R,
}

impl<R: ClusterInstanceReleaseRepository> ClusterInstanceReleaseService<R> {
    pub(crate) fn new(repository: R) -> Self {
        Self { repository }
    }

    /// Preserve the repository's exact committed / absent / error outcome.
    pub(crate) async fn release(&self, identity: &ClusterInstanceReleaseIdentity) -> Result<bool> {
        self.repository.release(identity).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct RecordingRepository {
        calls: Mutex<Vec<ClusterInstanceReleaseIdentity>>,
        result: std::result::Result<bool, &'static str>,
    }

    impl ClusterInstanceReleaseRepository for &RecordingRepository {
        async fn release(&self, identity: &ClusterInstanceReleaseIdentity) -> Result<bool> {
            self.calls.lock().unwrap().push(identity.clone());
            self.result.map_err(anyhow::Error::msg)
        }
    }

    #[tokio::test]
    async fn exact_identity_is_released_once_and_false_or_error_is_not_promoted() {
        let identity = ClusterInstanceReleaseIdentity {
            xmpp_domain: "example.test".into(),
            node_id: "node-a".into(),
            instance_uuid: Uuid::from_u128(7),
            instance_epoch: 12,
            signing_key_id: "signing-key".into(),
            signing_key_epoch: 3,
        };
        for expected in [Ok(true), Ok(false), Err("lease release failed")] {
            let repository = RecordingRepository {
                calls: Mutex::new(Vec::new()),
                result: expected,
            };
            let service = ClusterInstanceReleaseService::new(&repository);
            let actual = service.release(&identity).await;
            match expected {
                Ok(value) => assert_eq!(actual.unwrap(), value),
                Err(message) => assert_eq!(actual.unwrap_err().to_string(), message),
            }
            assert_eq!(
                repository.calls.lock().unwrap().as_slice(),
                std::slice::from_ref(&identity)
            );
        }
    }
}
