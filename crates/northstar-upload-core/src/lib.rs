//! Capability-free XEP-0363 HTTP File Upload domain models, safety classifications,
//! and admission outcomes.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Outcome of reserving an upload slot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum UploadSlotAdmission {
    Reserved { id: Uuid, bearer_token: String },
    CapacityExceeded,
}

/// Generation proof for upload physical namespace and capacity authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct UploadAuthorityGeneration {
    pub namespace: i64,
    pub capacity_policy: i64,
}

impl UploadAuthorityGeneration {
    pub fn new(namespace: i64, capacity_policy: i64) -> Self {
        Self {
            namespace,
            capacity_policy,
        }
    }
}

/// Process-wide upload safety gate state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum UploadSafetyState {
    /// Upload capability is absent by configuration.
    Disabled,
    Unproven,
    Healthy,
    NamespaceUnsafe,
    CapacityAuthorityUnsafe,
    LedgerMismatch,
    RecoveryDraining,
}

/// Classification of upload object store I/O operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum UploadIoClass {
    /// Read an already-committed exact object/version.
    Read,
    /// Admit bytes which do not yet exist in the physical namespace.
    NewWrite,
    /// Verify/promote an already-accounted exact stage.
    Promotion,
    /// Delete or inspect an exact durable recovery projection.
    Recovery,
    /// Refresh the client used by subsequent guarded operations.
    CredentialRefresh,
}

/// Pure validation to check if a requested upload size is positive and within configured limits.
pub fn validate_upload_size(size: u64, max_allowed: u64) -> bool {
    size > 0 && size <= max_allowed
}

/// Pure validation to ensure a filename is non-empty, contains no path separators or null bytes.
pub fn is_valid_upload_filename(filename: &str) -> bool {
    let trimmed = filename.trim();
    !trimmed.is_empty()
        && !trimmed.contains('/')
        && !trimmed.contains('\\')
        && !trimmed.contains('\0')
        && trimmed.len() <= 1024
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_validation() {
        assert!(validate_upload_size(1, 100));
        assert!(validate_upload_size(100, 100));
        assert!(!validate_upload_size(0, 100));
        assert!(!validate_upload_size(101, 100));
    }

    #[test]
    fn filename_validation() {
        assert!(is_valid_upload_filename("photo.jpg"));
        assert!(is_valid_upload_filename("document.pdf"));
        assert!(!is_valid_upload_filename(""));
        assert!(!is_valid_upload_filename("   "));
        assert!(!is_valid_upload_filename("../photo.jpg"));
        assert!(!is_valid_upload_filename("sub/photo.jpg"));
        assert!(!is_valid_upload_filename("sub\\photo.jpg"));
        assert!(!is_valid_upload_filename("photo\0.jpg"));
    }

    #[test]
    fn authority_generation_roundtrip() {
        let gen = UploadAuthorityGeneration::new(42, 100);
        assert_eq!(gen.namespace, 42);
        assert_eq!(gen.capacity_policy, 100);
    }
}
