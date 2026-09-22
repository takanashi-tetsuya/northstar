//! Application boundary for XEP-0363 slot admission.
//!
//! The protocol layer validates XML and renders URLs. This service validates
//! the reservation and safety gate, creates the bearer, and commits only its
//! hash through the atomic reservation port.

use crate::auth;
use crate::services::upload_safety::UploadSafetyGate;
use anyhow::Result;
use northstar_upload_application::{validate_upload_slot_request, UploadRepository};
pub(crate) use northstar_upload_application::{
    UploadIoClass, UploadSlotAdmission, UploadSlotRequest, UploadSlotRequestCommand,
};
use std::sync::Arc;

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

#[cfg(test)]
mod tests {
    use super::*;
    use northstar_upload_application::UploadAuthorityGeneration;
    use std::sync::Mutex;
    use uuid::Uuid;

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
