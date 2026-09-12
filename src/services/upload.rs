//! Application boundary for XEP-0363 slot admission.
//!
//! The protocol layer validates XML and renders URLs. This service owns the
//! database capability, bearer-token creation and all logical/physical quota
//! inputs so a handler cannot persist a partially specified reservation.

use crate::services::upload_safety::UploadSafetyGate;
use crate::{auth, db};
use anyhow::Result;
use northstar_upload_application::validate_upload_slot_request;
pub(crate) use northstar_upload_application::{
    UploadIoClass, UploadSlotAdmission, UploadSlotRequest, UploadSlotRequestCommand,
};
use sqlx::PgPool;
use std::sync::Arc;

#[derive(Clone)]
pub(crate) struct UploadService {
    pool: PgPool,
    safety_gate: Arc<UploadSafetyGate>,
    max_upload_bytes: u64,
}

impl UploadService {
    pub(crate) fn new(
        pool: PgPool,
        safety_gate: Arc<UploadSafetyGate>,
        max_upload_bytes: u64,
    ) -> Self {
        Self {
            pool,
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

    pub(crate) async fn reserve_slot(
        &self,
        request: UploadSlotRequest<'_>,
    ) -> Result<UploadSlotAdmission> {
        self.safety_gate.permit(UploadIoClass::NewWrite)?;
        let size = i64::try_from(request.size)
            .map_err(|_| anyhow::anyhow!("upload reservation exceeds PostgreSQL BIGINT"))?;
        let bearer_token = auth::new_session_token();
        let token_hash = auth::token_hash(&bearer_token);
        let id = db::create_upload_slot_bounded(
            &self.pool,
            db::UploadReservation {
                user_id: request.user_id,
                filename: request.filename,
                content_type: request.content_type,
                size,
                token_hash: &token_hash,
                max_files_per_user: request.max_files_per_user,
                max_bytes_per_user: request.max_bytes_per_user,
                storage_backend: request.storage_backend,
            },
            request.max_retained_files,
            request.max_retained_bytes,
            request.max_pending_jobs,
        )
        .await?;
        Ok(match id {
            Some(id) => UploadSlotAdmission::Reserved { id, bearer_token },
            None => UploadSlotAdmission::CapacityExceeded,
        })
    }
}
