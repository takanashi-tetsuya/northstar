//! Offline upload migration journal port and canonical manifest.

use anyhow::{ensure, Result};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const MANIFEST_DOMAIN: &[u8] = b"northstar-upload-migration-manifest-v1\0";

#[derive(Clone, Debug)]
pub struct BeginRun {
    pub run_id: Uuid,
    pub source_backend: String,
    pub target_backend: String,
    pub source_namespace_sha256: [u8; 32],
    pub target_namespace_sha256: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct MigrationRun {
    pub run_id: Uuid,
    pub source_backend: String,
    pub target_backend: String,
    pub source_namespace_sha256: [u8; 32],
    pub target_namespace_sha256: [u8; 32],
    pub source_generation: i64,
    pub source_slot_count: i64,
    pub state: String,
    pub manifest_sha256: Option<[u8; 32]>,
}

#[derive(Clone, Debug)]
pub struct MigrationItem {
    pub run_id: Uuid,
    pub object_id: Uuid,
    pub source_backend: String,
    pub source_key: String,
    pub source_version: Option<String>,
    pub source_fence: i64,
    pub source_size: i64,
    pub source_sha256: Option<[u8; 32]>,
    pub dest_attempt: Uuid,
    pub dest_key: String,
    pub claim_token: Uuid,
}

#[derive(Clone, Debug)]
pub struct VerifiedItem {
    pub item: MigrationItem,
    pub source_sha256: [u8; 32],
    pub dest_version: Option<String>,
    pub dest_size: i64,
    pub dest_sha256: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct VerifiedManifestItem {
    pub object_id: Uuid,
    pub source_backend: String,
    pub source_key: String,
    pub source_version: Option<String>,
    pub source_fence: i64,
    pub source_size: i64,
    pub source_catalog_sha256: Option<[u8; 32]>,
    pub source_sha256: [u8; 32],
    pub dest_attempt: Uuid,
    pub dest_key: String,
    pub dest_version: Option<String>,
    pub dest_size: i64,
    pub dest_sha256: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct Cutover {
    pub run_id: Uuid,
    pub generation: i64,
    pub manifest_sha256: [u8; 32],
}

/// Migrator-only journal port. Claims journal a fresh destination attempt before
/// object I/O. An uncertain write keeps its claim until lease expiry; a later
/// claim retires that attempt before issuing another identity.
pub trait StorageMigrationRepository: Send + Sync {
    fn find_active_run(
        &self,
    ) -> impl std::future::Future<Output = Result<Option<MigrationRun>>> + Send;

    fn get_run(
        &self,
        run_id: Uuid,
    ) -> impl std::future::Future<Output = Result<Option<MigrationRun>>> + Send;

    fn begin_offline_run(
        &self,
        input: BeginRun,
    ) -> impl std::future::Future<Output = Result<MigrationRun>> + Send;

    fn claim_items(
        &self,
        run_id: Uuid,
        limit: i64,
        lease_seconds: i64,
    ) -> impl std::future::Future<Output = Result<Vec<MigrationItem>>> + Send;

    fn release_or_retry_claim(
        &self,
        run_id: Uuid,
        object_id: Uuid,
        claim_token: Uuid,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;

    fn mark_verified(
        &self,
        verified: &VerifiedItem,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;

    fn has_unverified_items(
        &self,
        run_id: Uuid,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;

    fn list_verified_items(
        &self,
        run_id: Uuid,
        after_object_id: Option<Uuid>,
        limit: i64,
    ) -> impl std::future::Future<Output = Result<Vec<VerifiedManifestItem>>> + Send;

    fn final_cutover(
        &self,
        run_id: Uuid,
        manifest_sha256: [u8; 32],
        operator_confirmation: &str,
    ) -> impl std::future::Future<Output = Result<Cutover>> + Send;

    fn abort_run(&self, run_id: Uuid) -> impl std::future::Future<Output = Result<()>> + Send;
}

fn put_bytes(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u32).to_be_bytes());
    hasher.update(value);
}

fn put_optional(hasher: &mut Sha256, value: Option<&[u8]>) {
    match value {
        Some(bytes) => {
            hasher.update([1]);
            put_bytes(hasher, bytes);
        }
        None => hasher.update([0]),
    }
}

/// Canonical manifest v1 is domain-separated SHA-256 over length-prefixed
/// UTF-8 fields, UUID bytes, big-endian i64 values, and tagged optionals.
/// Rows must be supplied in ascending PostgreSQL UUID order, exactly once.
pub struct CanonicalManifestHasher {
    hasher: Sha256,
    last_id: Option<Uuid>,
    count: i64,
}

impl CanonicalManifestHasher {
    pub fn new(run: &MigrationRun) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_DOMAIN);
        hasher.update(run.run_id.as_bytes());
        put_bytes(&mut hasher, run.source_backend.as_bytes());
        put_bytes(&mut hasher, run.target_backend.as_bytes());
        hasher.update(run.source_namespace_sha256);
        hasher.update(run.target_namespace_sha256);
        hasher.update(run.source_generation.to_be_bytes());
        hasher.update(run.source_slot_count.to_be_bytes());
        Self {
            hasher,
            last_id: None,
            count: 0,
        }
    }

    pub fn update(&mut self, item: &VerifiedManifestItem) -> Result<()> {
        ensure!(
            self.last_id.is_none_or(|last| last < item.object_id),
            "manifest item order or identity is invalid"
        );
        self.last_id = Some(item.object_id);
        self.count += 1;
        self.hasher.update(item.object_id.as_bytes());
        put_bytes(&mut self.hasher, item.source_backend.as_bytes());
        put_bytes(&mut self.hasher, item.source_key.as_bytes());
        put_optional(
            &mut self.hasher,
            item.source_version.as_deref().map(str::as_bytes),
        );
        self.hasher.update(item.source_fence.to_be_bytes());
        self.hasher.update(item.source_size.to_be_bytes());
        put_optional(
            &mut self.hasher,
            item.source_catalog_sha256.as_ref().map(|v| v.as_slice()),
        );
        self.hasher.update(item.source_sha256);
        self.hasher.update(item.dest_attempt.as_bytes());
        put_bytes(&mut self.hasher, item.dest_key.as_bytes());
        put_optional(
            &mut self.hasher,
            item.dest_version.as_deref().map(str::as_bytes),
        );
        self.hasher.update(item.dest_size.to_be_bytes());
        self.hasher.update(item.dest_sha256);
        Ok(())
    }

    pub fn finish(self, expected_count: i64) -> Result<[u8; 32]> {
        ensure!(
            self.count == expected_count,
            "manifest does not cover every source slot"
        );
        Ok(self.hasher.finalize().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_manifest_rejects_duplicate_or_unsorted_items() {
        let run = MigrationRun {
            run_id: Uuid::new_v4(),
            source_backend: "local".into(),
            target_backend: "s3".into(),
            source_namespace_sha256: [1; 32],
            target_namespace_sha256: [2; 32],
            source_generation: 1,
            source_slot_count: 1,
            state: "copying".into(),
            manifest_sha256: None,
        };
        let id = Uuid::new_v4();
        let item = VerifiedManifestItem {
            object_id: id,
            source_backend: "local".into(),
            source_key: id.to_string(),
            source_version: None,
            source_fence: 0,
            source_size: 4,
            source_catalog_sha256: Some([3; 32]),
            source_sha256: [3; 32],
            dest_attempt: Uuid::new_v4(),
            dest_key: "objects/key".into(),
            dest_version: Some("version".into()),
            dest_size: 4,
            dest_sha256: [3; 32],
        };
        let mut hasher = CanonicalManifestHasher::new(&run);
        hasher.update(&item).unwrap();
        assert!(hasher.update(&item).is_err());
        assert_ne!(hasher.finish(1).unwrap(), [0; 32]);
    }
}
