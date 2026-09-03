//! Capability-injected HTTP upload application boundary, typed commands,
//! and validation rules.

#![forbid(unsafe_code)]

pub use northstar_upload_core::*;
pub mod repository;
pub use repository::*;
use uuid::Uuid;

/// Typed request for reserving an upload slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UploadSlotRequest<'a> {
    pub user_id: Uuid,
    pub filename: &'a str,
    pub content_type: &'a str,
    pub size: u64,
    pub max_files_per_user: i64,
    pub max_bytes_per_user: i64,
    pub storage_backend: &'a str,
    pub max_retained_files: i64,
    pub max_retained_bytes: i64,
    pub max_pending_jobs: i64,
}

pub type UploadSlotRequestCommand<'a> = UploadSlotRequest<'a>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UploadCommandValidationError {
    InvalidFilename,
    ZeroOrExcessiveSize,
    EmptyContentType,
    InvalidQuotaLimits,
}

/// Pure validation of an upload slot reservation command.
pub fn validate_upload_slot_request(
    request: &UploadSlotRequest<'_>,
    max_configured_bytes: u64,
) -> Result<(), UploadCommandValidationError> {
    if !is_valid_upload_filename(request.filename) {
        return Err(UploadCommandValidationError::InvalidFilename);
    }
    if !validate_upload_size(request.size, max_configured_bytes) {
        return Err(UploadCommandValidationError::ZeroOrExcessiveSize);
    }
    if request.content_type.trim().is_empty() {
        return Err(UploadCommandValidationError::EmptyContentType);
    }
    if request.max_files_per_user < 0 || request.max_bytes_per_user < 0 {
        return Err(UploadCommandValidationError::InvalidQuotaLimits);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_request_success() {
        let req = UploadSlotRequest {
            user_id: Uuid::new_v4(),
            filename: "avatar.png",
            content_type: "image/png",
            size: 1024,
            max_files_per_user: 100,
            max_bytes_per_user: 10_000_000,
            storage_backend: "local",
            max_retained_files: 1000,
            max_retained_bytes: 100_000_000,
            max_pending_jobs: 10,
        };
        assert!(validate_upload_slot_request(&req, 5_000_000).is_ok());
    }

    #[test]
    fn validate_request_invalid_filename() {
        let req = UploadSlotRequest {
            user_id: Uuid::new_v4(),
            filename: "../bad.png",
            content_type: "image/png",
            size: 1024,
            max_files_per_user: 100,
            max_bytes_per_user: 10_000_000,
            storage_backend: "local",
            max_retained_files: 1000,
            max_retained_bytes: 100_000_000,
            max_pending_jobs: 10,
        };
        assert_eq!(
            validate_upload_slot_request(&req, 5_000_000),
            Err(UploadCommandValidationError::InvalidFilename)
        );
    }

    #[test]
    fn validate_request_excessive_size() {
        let req = UploadSlotRequest {
            user_id: Uuid::new_v4(),
            filename: "large.bin",
            content_type: "application/octet-stream",
            size: 10_000_000,
            max_files_per_user: 100,
            max_bytes_per_user: 10_000_000,
            storage_backend: "local",
            max_retained_files: 1000,
            max_retained_bytes: 100_000_000,
            max_pending_jobs: 10,
        };
        assert_eq!(
            validate_upload_slot_request(&req, 5_000_000),
            Err(UploadCommandValidationError::ZeroOrExcessiveSize)
        );
    }
}
