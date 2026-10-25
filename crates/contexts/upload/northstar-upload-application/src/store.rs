//! The upload object store port: the store trait and its staged, stored and
//! readable objects, the integrity error, and the guard that admits every store
//! operation through the upload safety gate.

use std::{future::Future, pin::Pin, sync::Arc, task::Poll};

use anyhow::Result;
use tokio::io::AsyncRead;

use crate::safety::{UploadIoPermit, UploadSafetyError, UploadSafetyGate};
use crate::{UploadAuthorityGeneration, UploadIoClass};

#[derive(Debug, thiserror::Error)]
#[error("upload object integrity verification failed: {0}")]
pub struct UploadIntegrityError(&'static str);

impl UploadIntegrityError {
    pub fn new(kind: &'static str) -> Self {
        Self(kind)
    }
}

pub fn is_upload_integrity_error(error: &anyhow::Error) -> bool {
    error.downcast_ref::<UploadIntegrityError>().is_some()
}

pub fn is_upload_safety_error(error: &anyhow::Error) -> bool {
    error.downcast_ref::<UploadSafetyError>().is_some()
}

pub type StoreFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

/// Removes a staged object that was never durably recorded. A store gives each stage that owns bytes its
/// own cleanup, and `StagedUpload` runs it when it is dropped.
pub trait StageCleanup: Send + Sync {
    /// Runs from `Drop` after the bound upload authority, if any, still permits recovery I/O, so it must
    /// not block. `authority` is the gate and generation the stage was bound to.
    fn cleanup(
        self: Box<Self>,
        authority: Option<(Arc<UploadSafetyGate>, UploadAuthorityGeneration)>,
    );
}

/// Lease-owned staged bytes. Dropping a completed stage before its database-
/// fenced promotion schedules cleanup of its provider object, including when
/// an HTTP future is canceled between ingestion and the DB handoff. Versioned
/// S3 cleanup names an exact version; key-only cleanup requires an explicit
/// qualified unversioned mode and a fresh provider-state proof.
pub struct StagedUpload {
    bytes_written: u64,
    sha256: Option<[u8; 32]>,
    stage_key: String,
    object_key: String,
    stage_version: Option<String>,
    cleanup: Option<Box<dyn StageCleanup>>,
    cleanup_authority: Option<(Arc<UploadSafetyGate>, UploadAuthorityGeneration)>,
}

impl std::fmt::Debug for StagedUpload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StagedUpload")
            .field("bytes_written", &self.bytes_written)
            .field("sha256_present", &self.sha256.is_some())
            .field("stage_key", &self.stage_key)
            .field("object_key", &self.object_key)
            .field("stage_version", &self.stage_version)
            .finish_non_exhaustive()
    }
}

impl StagedUpload {
    /// A stage of `bytes_written` bytes; `cleanup` removes its bytes if it is dropped before it is durably
    /// recorded.
    pub fn new(
        bytes_written: u64,
        sha256: Option<[u8; 32]>,
        stage_key: String,
        object_key: String,
        stage_version: Option<String>,
        cleanup: Option<Box<dyn StageCleanup>>,
    ) -> Self {
        Self {
            bytes_written,
            sha256,
            stage_key,
            object_key,
            stage_version,
            cleanup,
            cleanup_authority: None,
        }
    }

    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    pub fn stage_key(&self) -> &str {
        &self.stage_key
    }

    /// Digest of the exact byte sequence accepted by the storage backend.
    /// Mismatched-length stages are aborted and deliberately have no digest.
    pub fn sha256(&self) -> Option<&[u8; 32]> {
        self.sha256.as_ref()
    }

    pub fn object_key(&self) -> &str {
        &self.object_key
    }

    pub fn stage_version(&self) -> Option<&str> {
        self.stage_version.as_deref()
    }

    /// PostgreSQL now owns reconciliation for this exact stage. From this
    /// point onward cancellation must not race the durable promotion worker.
    pub fn durably_recorded(&mut self) {
        self.cleanup = None;
        self.cleanup_authority = None;
    }

    /// Binds the stage's cleanup to the upload authority generation that admitted its write: once that
    /// generation no longer permits recovery I/O, dropping the stage leaves its bytes to durable
    /// reconciliation.
    pub fn bind_cleanup_authority(
        &mut self,
        gate: Arc<UploadSafetyGate>,
        generation: UploadAuthorityGeneration,
    ) {
        self.cleanup_authority = Some((gate, generation));
    }
}

impl Drop for StagedUpload {
    fn drop(&mut self) {
        let authority = self.cleanup_authority.take();
        if let Some((gate, generation)) = &authority {
            if !gate.permits_generation(UploadIoClass::Recovery, *generation) {
                tracing::warn!(
                    stage_key = %self.stage_key,
                    "upload authority changed; durable reconciliation retains staged bytes"
                );
                return;
            }
        }
        if let Some(cleanup) = self.cleanup.take() {
            cleanup.cleanup(authority);
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredUpload {
    pub backend: String,
    pub object_key: String,
    pub object_version: Option<String>,
    pub size: u64,
}

pub struct StoredUploadReader {
    pub reader: Box<dyn AsyncRead + Send + Unpin + 'static>,
    pub size: u64,
    pub object_version: Option<String>,
}

pub trait UploadStore: Send + Sync {
    fn backend(&self) -> &'static str;

    fn put<'a>(
        &'a self,
        key: &'a str,
        attempt: &'a str,
        stream: Box<dyn AsyncRead + Send + Unpin + 'a>,
        max_size: u64,
    ) -> StoreFuture<'a, StagedUpload>;

    /// Verify/promote outside a PostgreSQL transaction. S3 writes directly to
    /// its private attempt-qualified final key and this method performs an
    /// exact-version readback only; local storage promotes its private stage
    /// to the historical bare-UUID destination with a create-only hard link.
    fn commit<'a>(
        &'a self,
        key: &'a str,
        attempt: &'a str,
        expected_stage_version: Option<&'a str>,
        expected_size: u64,
        expected_sha256: &'a [u8; 32],
    ) -> StoreFuture<'a, StoredUpload>;

    /// Remove only one lease-owned staging object.
    fn abort<'a>(
        &'a self,
        key: &'a str,
        attempt: &'a str,
        stage_version: Option<&'a str>,
    ) -> StoreFuture<'a, bool>;

    fn get<'a>(
        &'a self,
        object_key: &'a str,
        object_version: Option<&'a str>,
    ) -> StoreFuture<'a, Option<StoredUploadReader>>;

    fn delete<'a>(
        &'a self,
        object_key: &'a str,
        object_version: Option<&'a str>,
    ) -> StoreFuture<'a, bool>;

    /// Rebuild a client from protected credential files. Provider-chain
    /// clients may use this as a no-op because they refresh internally.
    fn reload_credentials<'a>(&'a self) -> StoreFuture<'a, bool> {
        Box::pin(async { Ok(false) })
    }

    /// Delete only objects owned by this store. Implementations must not
    /// recursively remove an operator-supplied root directory.
    #[cfg_attr(not(test), allow(dead_code))]
    fn clear<'a>(&'a self) -> StoreFuture<'a, u64>;
}

/// The only production-facing upload-store capability. Every operation is
/// checked against the process-wide generation-bound gate before it starts,
/// canceled when the proof changes, and checked again before its result is
/// released. Returned readers and staged-upload Drop cleanup remain guarded
/// after the initial future has completed.
pub struct GuardedUploadStore {
    inner: Arc<dyn UploadStore>,
    gate: Arc<UploadSafetyGate>,
}

impl GuardedUploadStore {
    pub fn new(inner: Arc<dyn UploadStore>, gate: Arc<UploadSafetyGate>) -> Self {
        Self { inner, gate }
    }

    async fn run<T>(mut permit: UploadIoPermit, operation: StoreFuture<'_, T>) -> Result<T> {
        tokio::select! {
            biased;
            _ = permit.invalidated() => {
                Err(permit.authority_changed_error().into())
            }
            result = operation => {
                let result = result?;
                permit.ensure_current()?;
                Ok(result)
            }
        }
    }
}

struct GuardedUploadReader {
    inner: Box<dyn AsyncRead + Send + Unpin + 'static>,
    gate: Arc<UploadSafetyGate>,
    generation: UploadAuthorityGeneration,
    invalidated: Pin<Box<dyn Future<Output = ()> + Send + 'static>>,
}

impl AsyncRead for GuardedUploadReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if !self
            .gate
            .permits_generation(UploadIoClass::Read, self.generation)
        {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "upload namespace authority changed while streaming",
            )));
        }
        if self.invalidated.as_mut().poll(context).is_ready() {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "upload namespace authority changed while streaming",
            )));
        }
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl UploadStore for GuardedUploadStore {
    fn backend(&self) -> &'static str {
        self.inner.backend()
    }

    fn put<'a>(
        &'a self,
        key: &'a str,
        attempt: &'a str,
        stream: Box<dyn AsyncRead + Send + Unpin + 'a>,
        max_size: u64,
    ) -> StoreFuture<'a, StagedUpload> {
        let permit = match self.gate.permit(UploadIoClass::NewWrite) {
            Ok(permit) => permit,
            Err(error) => return Box::pin(async move { Err(error.into()) }),
        };
        let generation = permit.generation();
        let gate = Arc::clone(&self.gate);
        let operation = self.inner.put(key, attempt, stream, max_size);
        Box::pin(async move {
            let mut permit = permit;
            tokio::select! {
                biased;
                _ = permit.invalidated() => {
                    Err(permit.authority_changed_error().into())
                }
                result = operation => {
                    let mut staged = result?;
                    // Bind the durable generation before the final recheck.
                    // If authority flipped after the provider completed, the
                    // error path drops this value without deleting bytes that
                    // now belong to database recovery.
                    staged.bind_cleanup_authority(gate, generation);
                    permit.ensure_current()?;
                    Ok(staged)
                }
            }
        })
    }

    fn commit<'a>(
        &'a self,
        key: &'a str,
        attempt: &'a str,
        expected_stage_version: Option<&'a str>,
        expected_size: u64,
        expected_sha256: &'a [u8; 32],
    ) -> StoreFuture<'a, StoredUpload> {
        let permit = match self.gate.permit(UploadIoClass::Promotion) {
            Ok(permit) => permit,
            Err(error) => return Box::pin(async move { Err(error.into()) }),
        };
        let operation = self.inner.commit(
            key,
            attempt,
            expected_stage_version,
            expected_size,
            expected_sha256,
        );
        Box::pin(Self::run(permit, operation))
    }

    fn abort<'a>(
        &'a self,
        key: &'a str,
        attempt: &'a str,
        stage_version: Option<&'a str>,
    ) -> StoreFuture<'a, bool> {
        let permit = match self.gate.permit(UploadIoClass::Recovery) {
            Ok(permit) => permit,
            Err(error) => return Box::pin(async move { Err(error.into()) }),
        };
        let operation = self.inner.abort(key, attempt, stage_version);
        Box::pin(Self::run(permit, operation))
    }

    fn get<'a>(
        &'a self,
        object_key: &'a str,
        object_version: Option<&'a str>,
    ) -> StoreFuture<'a, Option<StoredUploadReader>> {
        let permit = match self.gate.permit(UploadIoClass::Read) {
            Ok(permit) => permit,
            Err(error) => return Box::pin(async move { Err(error.into()) }),
        };
        let generation = permit.generation();
        let gate = Arc::clone(&self.gate);
        let invalidated = gate.invalidation_future(UploadIoClass::Read, generation);
        let operation = self.inner.get(object_key, object_version);
        Box::pin(async move {
            Ok(Self::run(permit, operation)
                .await?
                .map(|stored| StoredUploadReader {
                    reader: Box::new(GuardedUploadReader {
                        inner: stored.reader,
                        gate,
                        generation,
                        invalidated,
                    }),
                    size: stored.size,
                    object_version: stored.object_version,
                }))
        })
    }

    fn delete<'a>(
        &'a self,
        object_key: &'a str,
        object_version: Option<&'a str>,
    ) -> StoreFuture<'a, bool> {
        let permit = match self.gate.permit(UploadIoClass::Recovery) {
            Ok(permit) => permit,
            Err(error) => return Box::pin(async move { Err(error.into()) }),
        };
        let operation = self.inner.delete(object_key, object_version);
        Box::pin(Self::run(permit, operation))
    }

    fn reload_credentials<'a>(&'a self) -> StoreFuture<'a, bool> {
        let permit = match self.gate.permit(UploadIoClass::CredentialRefresh) {
            Ok(permit) => permit,
            Err(error) => return Box::pin(async move { Err(error.into()) }),
        };
        let operation = self.inner.reload_credentials();
        Box::pin(Self::run(permit, operation))
    }

    fn clear<'a>(&'a self) -> StoreFuture<'a, u64> {
        let permit = match self.gate.permit(UploadIoClass::Recovery) {
            Ok(permit) => permit,
            Err(error) => return Box::pin(async move { Err(error.into()) }),
        };
        let operation = self.inner.clear();
        Box::pin(Self::run(permit, operation))
    }
}
