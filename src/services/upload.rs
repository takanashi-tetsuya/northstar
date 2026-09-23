//! Application boundary for XEP-0363 slot admission.
//!
//! The protocol layer validates XML and renders URLs. This service validates
//! the reservation and safety gate, creates the bearer, and commits only its
//! hash through the atomic reservation port.

use crate::auth;
use crate::services::upload_maintenance::CommittedUploadIdentity;
pub(crate) use crate::services::upload_maintenance::PromotedUploadProjection;
use crate::services::upload_safety::UploadSafetyGate;
use anyhow::Result;
use northstar_upload_application::{validate_upload_slot_request, UploadRepository};
pub(crate) use northstar_upload_application::{
    UploadIoClass, UploadSlotAdmission, UploadSlotRequest, UploadSlotRequestCommand,
};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct UploadSlot {
    pub id: Uuid,
    pub content_type: String,
    pub size: i64,
    pub remaining_seconds: u64,
    pub storage_backend: String,
    pub storage_object_key: Option<String>,
    pub storage_object_version: Option<String>,
}

#[derive(Debug)]
pub struct UploadLease {
    pub slot: UploadSlot,
    pub claim_token: Uuid,
    /// Monotonic database fence for this exact attempt.
    pub storage_fence: i64,
    /// Bounded by PostgreSQL's clock, not the application host clock.
    pub remaining_seconds: u64,
}

#[derive(Debug)]
pub enum UploadClaimOutcome {
    Acquired(UploadLease),
    Replay {
        slot: UploadSlot,
        content_sha256: [u8; 32],
    },
    InProgress {
        retry_after_seconds: u64,
    },
    Rejected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UploadRenewOutcome {
    Renewed,
    Busy,
    Lost,
}

pub struct UploadStageProjection<'a> {
    pub id: Uuid,
    pub claim_token: Uuid,
    pub storage_backend: &'a str,
    pub stage_key: &'a str,
    pub stage_version: Option<&'a str>,
    pub object_key: &'a str,
    pub content_sha256: &'a [u8; 32],
    pub size: u64,
    pub storage_fence: i64,
}

#[derive(Clone, Copy)]
pub(crate) struct PromotionClaim {
    pub id: Uuid,
    pub storage_attempt: Uuid,
    pub storage_fence: i64,
    pub promotion_claim_token: Uuid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AcquirePromotionOutcome {
    Busy,
    Ready(Uuid),
    Retired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FinalizePromotionOutcome {
    Committed,
    ConcurrentlyCommitted,
    Retired,
    Indeterminate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserUploadDeleteOutcome {
    Accepted,
    Unauthorized,
}

/// Upload request lease and replay authority; each operation owns its SQL
/// connection and completes before the caller can touch object storage.
pub(crate) trait UploadLifecycleRepository: Send + Sync {
    fn claim_slot(
        &self,
        id: Uuid,
        token_hash: &[u8],
        lease_seconds: i64,
    ) -> impl std::future::Future<Output = Result<UploadClaimOutcome>> + Send;

    fn record_replay(
        &self,
        id: Uuid,
        token_hash: &[u8],
        content_sha256: &[u8; 32],
    ) -> impl std::future::Future<Output = Result<bool>> + Send;

    fn renew_claim(
        &self,
        id: Uuid,
        claim_token: Uuid,
        lease_seconds: i64,
    ) -> impl std::future::Future<Output = Result<UploadRenewOutcome>> + Send;

    fn release_claim(
        &self,
        id: Uuid,
        claim_token: Uuid,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;

    fn record_stage(
        &self,
        projection: UploadStageProjection<'_>,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;

    fn claim_promotion(
        &self,
        id: Uuid,
        storage_attempt: Uuid,
        storage_fence: i64,
    ) -> impl std::future::Future<Output = Result<Option<Uuid>>> + Send;

    fn begin_promotion(
        &self,
        claim: PromotionClaim,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;

    fn retire_promotion(
        &self,
        claim: PromotionClaim,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;

    fn defer_promotion(
        &self,
        claim: PromotionClaim,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;

    fn complete_promotion(
        &self,
        projection: PromotedUploadProjection<'_>,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;

    fn attempt_committed(
        &self,
        identity: CommittedUploadIdentity<'_>,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;

    fn public_file(
        &self,
        id: Uuid,
    ) -> impl std::future::Future<Output = Result<Option<UploadSlot>>> + Send;

    fn delete_authorized(
        &self,
        user_id: Uuid,
        auth_generation: i64,
        session_token: &str,
        id: Uuid,
        request_id: Uuid,
    ) -> impl std::future::Future<Output = Result<UserUploadDeleteOutcome>> + Send;
}

#[derive(Clone)]
pub(crate) struct UploadService<R> {
    repository: R,
    safety_gate: Arc<UploadSafetyGate>,
    max_upload_bytes: u64,
}

impl<R: UploadRepository<Error = anyhow::Error>> UploadService<R> {
    pub(crate) fn new(
        repository: R,
        safety_gate: Arc<UploadSafetyGate>,
        max_upload_bytes: u64,
    ) -> Self {
        Self {
            repository,
            safety_gate,
            max_upload_bytes,
        }
    }

    pub(crate) async fn execute_upload_slot_reservation(
        &self,
        command: UploadSlotRequestCommand<'_>,
    ) -> Result<UploadSlotAdmission> {
        if let Err(err) = validate_upload_slot_request(&command, self.max_upload_bytes) {
            anyhow::bail!("invalid upload slot request: {:?}", err);
        }
        self.reserve_slot(command).await
    }

    async fn reserve_slot(&self, request: UploadSlotRequest<'_>) -> Result<UploadSlotAdmission> {
        self.safety_gate.permit(UploadIoClass::NewWrite)?;
        let bearer_token = auth::new_session_token();
        let token_hash = auth::token_hash(&bearer_token);
        let id = self.repository.reserve_slot(&request, &token_hash).await?;
        Ok(match id {
            Some(id) => UploadSlotAdmission::Reserved { id, bearer_token },
            None => UploadSlotAdmission::CapacityExceeded,
        })
    }
}

impl<R: UploadLifecycleRepository> UploadService<R> {
    pub(crate) async fn claim_slot(
        &self,
        id: Uuid,
        token_hash: &[u8],
        lease_seconds: i64,
    ) -> Result<UploadClaimOutcome> {
        self.repository
            .claim_slot(id, token_hash, lease_seconds)
            .await
    }

    pub(crate) async fn record_replay(
        &self,
        id: Uuid,
        token_hash: &[u8],
        content_sha256: &[u8; 32],
    ) -> Result<bool> {
        self.repository
            .record_replay(id, token_hash, content_sha256)
            .await
    }

    pub(crate) async fn renew_claim(
        &self,
        id: Uuid,
        claim_token: Uuid,
        lease_seconds: i64,
    ) -> Result<UploadRenewOutcome> {
        self.repository
            .renew_claim(id, claim_token, lease_seconds)
            .await
    }

    pub(crate) async fn release_claim(&self, id: Uuid, claim_token: Uuid) -> Result<bool> {
        self.repository.release_claim(id, claim_token).await
    }

    pub(crate) async fn record_stage(&self, projection: UploadStageProjection<'_>) -> Result<bool> {
        self.repository.record_stage(projection).await
    }

    pub(crate) async fn acquire_promotion(
        &self,
        id: Uuid,
        storage_attempt: Uuid,
        storage_fence: i64,
    ) -> Result<AcquirePromotionOutcome> {
        let Some(promotion_claim_token) = self
            .repository
            .claim_promotion(id, storage_attempt, storage_fence)
            .await?
        else {
            return Ok(AcquirePromotionOutcome::Busy);
        };
        let claim = PromotionClaim {
            id,
            storage_attempt,
            storage_fence,
            promotion_claim_token,
        };
        if self.repository.begin_promotion(claim).await? {
            Ok(AcquirePromotionOutcome::Ready(promotion_claim_token))
        } else if self.repository.retire_promotion(claim).await? {
            Ok(AcquirePromotionOutcome::Retired)
        } else {
            Ok(AcquirePromotionOutcome::Busy)
        }
    }

    pub(crate) async fn defer_promotion(&self, claim: PromotionClaim) -> Result<bool> {
        self.repository.defer_promotion(claim).await
    }

    pub(crate) async fn finalize_promotion(
        &self,
        projection: PromotedUploadProjection<'_>,
    ) -> Result<FinalizePromotionOutcome> {
        let claim = PromotionClaim {
            id: projection.id,
            storage_attempt: projection.claim_token,
            storage_fence: projection.storage_fence,
            promotion_claim_token: projection.promotion_claim_token,
        };
        let identity = CommittedUploadIdentity {
            id: projection.id,
            storage_attempt: projection.claim_token,
            storage_backend: projection.storage_backend,
            object_key: projection.object_key,
            object_version: projection.object_version,
            content_sha256: projection.content_sha256,
            size: projection.size,
            storage_fence: projection.storage_fence,
        };
        if self.repository.complete_promotion(projection).await? {
            Ok(FinalizePromotionOutcome::Committed)
        } else if self.repository.attempt_committed(identity).await? {
            Ok(FinalizePromotionOutcome::ConcurrentlyCommitted)
        } else if self.repository.retire_promotion(claim).await? {
            Ok(FinalizePromotionOutcome::Retired)
        } else {
            Ok(FinalizePromotionOutcome::Indeterminate)
        }
    }

    pub(crate) async fn public_file(&self, id: Uuid) -> Result<Option<UploadSlot>> {
        self.repository.public_file(id).await
    }

    pub(crate) async fn delete_authorized(
        &self,
        user_id: Uuid,
        auth_generation: i64,
        session_token: &str,
        id: Uuid,
        request_id: Uuid,
    ) -> Result<UserUploadDeleteOutcome> {
        self.repository
            .delete_authorized(user_id, auth_generation, session_token, id, request_id)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use northstar_upload_application::UploadAuthorityGeneration;
    use std::sync::Mutex;
    use uuid::Uuid;

    #[derive(Default)]
    struct LifecycleRepository {
        claim: Option<Uuid>,
        begin: bool,
        retire: bool,
        complete: bool,
        committed: bool,
        calls: Mutex<Vec<&'static str>>,
    }

    impl UploadLifecycleRepository for LifecycleRepository {
        async fn claim_slot(&self, _: Uuid, _: &[u8], _: i64) -> Result<UploadClaimOutcome> {
            unreachable!("not used by this promotion test")
        }

        async fn record_replay(&self, _: Uuid, _: &[u8], _: &[u8; 32]) -> Result<bool> {
            unreachable!("not used by this promotion test")
        }

        async fn renew_claim(&self, _: Uuid, _: Uuid, _: i64) -> Result<UploadRenewOutcome> {
            unreachable!("not used by this promotion test")
        }

        async fn release_claim(&self, _: Uuid, _: Uuid) -> Result<bool> {
            unreachable!("not used by this promotion test")
        }

        async fn record_stage(&self, _: UploadStageProjection<'_>) -> Result<bool> {
            unreachable!("not used by this promotion test")
        }

        async fn claim_promotion(&self, _: Uuid, _: Uuid, _: i64) -> Result<Option<Uuid>> {
            self.calls.lock().unwrap().push("claim");
            Ok(self.claim)
        }

        async fn begin_promotion(&self, _: PromotionClaim) -> Result<bool> {
            self.calls.lock().unwrap().push("begin");
            Ok(self.begin)
        }

        async fn retire_promotion(&self, _: PromotionClaim) -> Result<bool> {
            self.calls.lock().unwrap().push("retire");
            Ok(self.retire)
        }

        async fn defer_promotion(&self, _: PromotionClaim) -> Result<bool> {
            unreachable!("not used by this promotion test")
        }

        async fn complete_promotion(&self, _: PromotedUploadProjection<'_>) -> Result<bool> {
            self.calls.lock().unwrap().push("complete");
            Ok(self.complete)
        }

        async fn attempt_committed(&self, _: CommittedUploadIdentity<'_>) -> Result<bool> {
            self.calls.lock().unwrap().push("committed");
            Ok(self.committed)
        }

        async fn public_file(&self, _: Uuid) -> Result<Option<UploadSlot>> {
            unreachable!("not used by this promotion test")
        }

        async fn delete_authorized(
            &self,
            _: Uuid,
            _: i64,
            _: &str,
            _: Uuid,
            _: Uuid,
        ) -> Result<UserUploadDeleteOutcome> {
            unreachable!("not used by this promotion test")
        }
    }

    fn lifecycle_service(repository: LifecycleRepository) -> UploadService<LifecycleRepository> {
        UploadService {
            repository,
            safety_gate: UploadSafetyGate::new(),
            max_upload_bytes: 1024,
        }
    }

    #[tokio::test]
    async fn promotion_only_retires_after_a_failed_exact_begin_or_commit() {
        let id = Uuid::new_v4();
        let storage_attempt = Uuid::new_v4();
        let promotion_claim_token = Uuid::new_v4();
        let service = lifecycle_service(LifecycleRepository {
            claim: Some(promotion_claim_token),
            begin: false,
            retire: true,
            ..Default::default()
        });
        assert_eq!(
            service
                .acquire_promotion(id, storage_attempt, 7)
                .await
                .unwrap(),
            AcquirePromotionOutcome::Retired
        );
        assert_eq!(
            *service.repository.calls.lock().unwrap(),
            ["claim", "begin", "retire"]
        );

        let service = lifecycle_service(LifecycleRepository {
            complete: false,
            committed: true,
            retire: true,
            ..Default::default()
        });
        let digest = [7_u8; 32];
        let projection = PromotedUploadProjection {
            id,
            claim_token: storage_attempt,
            promotion_claim_token,
            storage_backend: "local",
            object_key: "object",
            object_version: None,
            content_sha256: &digest,
            size: 12,
            retention_seconds: 60,
            storage_fence: 7,
        };
        assert_eq!(
            service.finalize_promotion(projection).await.unwrap(),
            FinalizePromotionOutcome::ConcurrentlyCommitted
        );
        assert_eq!(
            *service.repository.calls.lock().unwrap(),
            ["complete", "committed"],
            "a committed retry must never retire its promoted object"
        );
    }

    #[derive(Default)]
    struct Repository {
        hashes: Mutex<Vec<Vec<u8>>>,
        outcome: Mutex<u8>,
    }

    impl UploadRepository for Repository {
        type Error = anyhow::Error;

        async fn reserve_slot(
            &self,
            request: &UploadSlotRequest<'_>,
            token_hash: &[u8],
        ) -> Result<Option<Uuid>> {
            assert_eq!(request.max_pending_jobs, 128);
            self.hashes.lock().unwrap().push(token_hash.to_vec());
            match *self.outcome.lock().unwrap() {
                0 => Ok(Some(request.user_id)),
                1 => Ok(None),
                _ => anyhow::bail!("reservation interrupted"),
            }
        }
    }

    #[tokio::test]
    async fn reservation_preserves_safety_denial_and_token_ownership() {
        let safety = UploadSafetyGate::new();
        let service = UploadService::new(Repository::default(), safety.clone(), 1024);
        let request = UploadSlotRequest {
            user_id: Uuid::new_v4(),
            filename: "image.png",
            content_type: "image/png",
            size: 64,
            max_files_per_user: 10,
            max_bytes_per_user: 1024,
            storage_backend: "local",
            max_retained_files: 100,
            max_retained_bytes: 10240,
            max_pending_jobs: 128,
        };
        assert!(service
            .execute_upload_slot_reservation(request)
            .await
            .is_err());
        assert!(service.repository.hashes.lock().unwrap().is_empty());
        safety.establish(UploadAuthorityGeneration::new(1, 1), false);
        assert!(service
            .execute_upload_slot_reservation(UploadSlotRequest {
                filename: "../escape",
                ..request
            })
            .await
            .is_err());
        assert!(service.repository.hashes.lock().unwrap().is_empty());
        let UploadSlotAdmission::Reserved { id, bearer_token } = service
            .execute_upload_slot_reservation(request)
            .await
            .unwrap()
        else {
            panic!("expected reservation");
        };
        assert_eq!(id, request.user_id);
        assert_eq!(
            service.repository.hashes.lock().unwrap()[0],
            auth::token_hash(&bearer_token)
        );
        *service.repository.outcome.lock().unwrap() = 1;
        assert_eq!(
            service
                .execute_upload_slot_reservation(request)
                .await
                .unwrap(),
            UploadSlotAdmission::CapacityExceeded
        );
        *service.repository.outcome.lock().unwrap() = 2;
        assert_eq!(
            service
                .execute_upload_slot_reservation(request)
                .await
                .unwrap_err()
                .to_string(),
            "reservation interrupted"
        );
        assert_eq!(service.repository.hashes.lock().unwrap().len(), 3);
    }
}
