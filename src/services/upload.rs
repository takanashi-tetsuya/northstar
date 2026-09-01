//! Application boundary for XEP-0363 slot admission.
//!
//! The protocol layer validates XML and renders URLs. This service owns the
//! database capability, bearer-token creation and all logical/physical quota
//! inputs so a handler cannot persist a partially specified reservation.

use crate::services::upload_safety::{UploadIoClass, UploadSafetyGate};
use crate::{auth, db};
use anyhow::Result;
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

pub(crate) struct UploadSlotRequest<'a> {
    pub(crate) user_id: Uuid,
    pub(crate) filename: &'a str,
    pub(crate) content_type: &'a str,
    pub(crate) size: u64,
    pub(crate) max_files_per_user: i64,
    pub(crate) max_bytes_per_user: i64,
    pub(crate) storage_backend: &'a str,
    pub(crate) max_retained_files: i64,
    pub(crate) max_retained_bytes: i64,
    pub(crate) max_pending_jobs: i64,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum UploadSlotAdmission {
    Reserved { id: Uuid, bearer_token: String },
    CapacityExceeded,
}

#[derive(Clone)]
pub(crate) struct UploadService {
    pool: PgPool,
    safety_gate: Arc<UploadSafetyGate>,
}

impl UploadService {
    pub(crate) fn new(pool: PgPool, safety_gate: Arc<UploadSafetyGate>) -> Self {
        Self { pool, safety_gate }
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
