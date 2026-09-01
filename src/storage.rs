use anyhow::{Context, Result};
use object_store::ObjectStoreExt as _;
use sha2::{Digest, Sha256};
use std::{future::Future, path::PathBuf, pin::Pin, sync::Arc, task::Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

use crate::services::upload_safety::{
    UploadAuthorityGeneration, UploadIoClass, UploadIoPermit, UploadSafetyError, UploadSafetyGate,
};

#[derive(Debug, thiserror::Error)]
#[error("upload object integrity verification failed: {0}")]
pub struct UploadIntegrityError(&'static str);

impl UploadIntegrityError {
    pub(crate) fn new(kind: &'static str) -> Self {
        Self(kind)
    }
}

pub fn is_upload_integrity_error(error: &anyhow::Error) -> bool {
    error.downcast_ref::<UploadIntegrityError>().is_some()
}

pub fn is_upload_safety_error(error: &anyhow::Error) -> bool {
    error.downcast_ref::<UploadSafetyError>().is_some()
}

mod s3;

pub use s3::{S3UploadSettings, S3UploadStore};

pub type StoreFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

const MAX_STARTUP_DIRECTORY_ENTRIES: usize = 16_384;
const MAX_STARTUP_STAGING_ATTEMPTS: usize = 4_096;

fn push_startup_staging_attempt(
    attempts: &mut Vec<(uuid::Uuid, uuid::Uuid)>,
    object: uuid::Uuid,
    attempt: uuid::Uuid,
) -> Result<()> {
    anyhow::ensure!(
        attempts.len() < MAX_STARTUP_STAGING_ATTEMPTS,
        "upload staging scan exceeded the hard recoverable-attempt limit"
    );
    attempts.push((object, attempt));
    Ok(())
}

/// Lease-owned staged bytes. Dropping a completed stage before its database-
/// fenced promotion removes only that attempt, including when an HTTP future
/// is canceled between body ingestion and the completion transaction.
pub struct StagedUpload {
    bytes_written: u64,
    sha256: Option<[u8; 32]>,
    stage_key: String,
    object_key: String,
    stage_version: Option<String>,
    cleanup_path: Option<PathBuf>,
    remote_cleanup: Option<(Arc<dyn object_store::ObjectStore>, object_store::path::Path)>,
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
        self.cleanup_path = None;
        self.remote_cleanup = None;
        self.cleanup_authority = None;
    }

    fn bind_cleanup_authority(
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
        let Some(path) = self.cleanup_path.take() else {
            if let Some((store, path)) = self.remote_cleanup.take() {
                // A completed multipart stage is a normal object. If the HTTP
                // future is cancelled before PostgreSQL records it, schedule
                // attempt-scoped cleanup. Incomplete multipart parts remain
                // subject to the mandatory bucket lifecycle policy.
                if let Ok(handle) = tokio::runtime::Handle::try_current() {
                    let authority = authority.clone();
                    handle.spawn(async move {
                        let deleted = if let Some((gate, generation)) = authority {
                            let Ok(mut permit) = gate.permit(UploadIoClass::Recovery) else {
                                return;
                            };
                            if permit.generation() != generation {
                                return;
                            }
                            tokio::select! {
                                biased;
                                _ = permit.invalidated() => return,
                                deleted = store.delete(&path) => deleted,
                            }
                        } else {
                            store.delete(&path).await
                        };
                        if let Err(error) = deleted {
                            tracing::warn!(stage_key = %path, ?error, "failed to remove abandoned remote upload stage");
                        }
                    });
                }
            }
            return;
        };
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => tracing::warn!(
                path = %path.display(),
                %error,
                "failed to remove abandoned staged upload"
            ),
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
pub(crate) struct GuardedUploadStore {
    inner: Arc<dyn UploadStore>,
    gate: Arc<UploadSafetyGate>,
}

impl GuardedUploadStore {
    pub(crate) fn new(inner: Arc<dyn UploadStore>, gate: Arc<UploadSafetyGate>) -> Self {
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

pub struct LocalUploadStore {
    root: PathBuf,
    safety_gate: Option<Arc<UploadSafetyGate>>,
}

fn parse_object_key(key: &str) -> Result<(uuid::Uuid, uuid::Uuid)> {
    let mut parts = key.split('/');
    let (Some("objects"), Some(id), Some(attempt), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        anyhow::bail!("upload object key is not canonical");
    };
    Ok((
        uuid::Uuid::parse_str(id).context("upload object key has an invalid UUID")?,
        uuid::Uuid::parse_str(attempt).context("upload object key has an invalid attempt UUID")?,
    ))
}

async fn digest_local_file(path: &std::path::Path) -> Result<(u64, [u8; 32])> {
    let mut file = tokio::fs::File::open(path).await?;
    let mut digest = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        size = size
            .checked_add(read as u64)
            .context("upload object size overflow")?;
        digest.update(&buffer[..read]);
    }
    Ok((size, digest.finalize().into()))
}

/// Removes an incomplete object even when the async write future is cancelled.
/// Async cleanup code does not run when a handler future is dropped, so the
/// small synchronous unlink in `Drop` closes that otherwise persistent leak.
struct TemporaryObject {
    path: PathBuf,
    armed: bool,
    cleanup_authority: Option<(Arc<UploadSafetyGate>, UploadAuthorityGeneration)>,
}

impl TemporaryObject {
    fn new(
        path: PathBuf,
        cleanup_authority: Option<(Arc<UploadSafetyGate>, UploadAuthorityGeneration)>,
    ) -> Self {
        Self {
            path,
            armed: true,
            cleanup_authority,
        }
    }

    fn commit(&mut self) {
        self.armed = false;
    }
}

impl Drop for TemporaryObject {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Some((gate, generation)) = &self.cleanup_authority {
            if !gate.permits_generation(UploadIoClass::Recovery, *generation) {
                tracing::warn!(
                    path = %self.path.display(),
                    "upload authority changed; retaining incomplete upload for reconciliation"
                );
                return;
            }
        }
        match std::fs::remove_file(&self.path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => tracing::warn!(
                path = %self.path.display(),
                %error,
                "failed to remove incomplete upload"
            ),
        }
    }
}

impl LocalUploadStore {
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            safety_gate: None,
        }
    }

    pub(crate) fn with_safety_gate(mut self, gate: Arc<UploadSafetyGate>) -> Self {
        self.safety_gate = Some(gate);
        self
    }

    fn cleanup_authority(
        &self,
    ) -> Result<Option<(Arc<UploadSafetyGate>, UploadAuthorityGeneration)>> {
        let Some(gate) = &self.safety_gate else {
            return Ok(None);
        };
        let permit = gate.permit(UploadIoClass::NewWrite)?;
        Ok(Some((Arc::clone(gate), permit.generation())))
    }

    fn path(&self, key: &str) -> Result<PathBuf> {
        // Legacy committed rows used the bare upload UUID. New rows use an
        // immutable attempt-qualified key while retaining a flat local layout
        // so no untrusted directory traversal or symlink component is needed.
        if let Ok(id) = uuid::Uuid::parse_str(key) {
            return Ok(self.root.join(id.to_string()));
        }
        let (id, attempt) = parse_object_key(key)?;
        Ok(self.root.join(format!("{id}.{attempt}.object")))
    }

    fn temporary_path(&self, key: &str, attempt: &str) -> Result<PathBuf> {
        let id = uuid::Uuid::parse_str(key).context("upload object key is not a UUID")?;
        let attempt = uuid::Uuid::parse_str(attempt).context("upload attempt key is not a UUID")?;
        Ok(self.root.join(format!("{id}.{attempt}.part")))
    }

    async fn ensure_private_root(&self) -> Result<()> {
        tokio::fs::create_dir_all(&self.root)
            .await
            .with_context(|| {
                format!("could not create upload directory {}", self.root.display())
            })?;
        let metadata = tokio::fs::symlink_metadata(&self.root).await?;
        anyhow::ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "upload root must be a real directory, not a symbolic link"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                tokio::fs::set_permissions(&self.root, std::fs::Permissions::from_mode(0o700))
                    .await
                    .with_context(|| {
                        format!(
                            "could not restrict upload directory {} to mode 0700",
                            self.root.display()
                        )
                    })?;
            }
        }
        Ok(())
    }

    /// Enumerate only a bounded set of staging names owned by this backend.
    /// Exceeding either limit aborts the scan before the caller can delete
    /// anything; operators must then quarantine/reconcile the directory
    /// offline instead of letting crash debris consume unbounded memory.
    /// The caller must
    /// compare each `(object_id, claim_token)` with PostgreSQL before removal:
    /// during a rolling restart another process may still own a live lease in
    /// the same shared upload directory.
    pub async fn staging_attempts(&self) -> Result<Vec<(uuid::Uuid, uuid::Uuid)>> {
        let permit = self
            .safety_gate
            .as_ref()
            .map(|gate| gate.permit(UploadIoClass::Recovery))
            .transpose()?;
        self.ensure_private_root().await?;
        if let Some(permit) = &permit {
            permit.ensure_current()?;
        }
        let mut entries = match tokio::fs::read_dir(&self.root).await {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };
        let mut attempts = Vec::new();
        let mut inspected = 0_usize;
        while let Some(entry) = entries.next_entry().await? {
            inspected = inspected.saturating_add(1);
            anyhow::ensure!(
                inspected <= MAX_STARTUP_DIRECTORY_ENTRIES,
                "upload staging scan exceeded the hard directory-entry limit"
            );
            if let Some(permit) = &permit {
                permit.ensure_current()?;
            }
            if !entry.file_type().await?.is_file() {
                continue;
            }
            let name = entry.file_name();
            let Some(staged) = name.to_str().and_then(|name| name.strip_suffix(".part")) else {
                continue;
            };
            let mut parts = staged.split('.');
            let (Some(object), Some(attempt), None) = (parts.next(), parts.next(), parts.next())
            else {
                continue;
            };
            let (Ok(object), Ok(attempt)) = (
                uuid::Uuid::parse_str(object),
                uuid::Uuid::parse_str(attempt),
            ) else {
                continue;
            };
            push_startup_staging_attempt(&mut attempts, object, attempt)?;
        }
        if let Some(permit) = &permit {
            permit.ensure_current()?;
        }
        Ok(attempts)
    }
}

impl UploadStore for LocalUploadStore {
    fn backend(&self) -> &'static str {
        "local"
    }

    fn put<'a>(
        &'a self,
        key: &'a str,
        attempt: &'a str,
        stream: Box<dyn AsyncRead + Send + Unpin + 'a>,
        max_size: u64,
    ) -> StoreFuture<'a, StagedUpload> {
        Box::pin(async move {
            self.ensure_private_root().await?;
            let id = uuid::Uuid::parse_str(key).context("upload object key is not a UUID")?;
            let attempt_id =
                uuid::Uuid::parse_str(attempt).context("upload attempt key is not a UUID")?;
            // Every durable database lease owns a distinct staging file. A
            // worker that is canceled after losing its lease can therefore
            // remove only its own bytes, never those of the replacement.
            let temporary = self.temporary_path(key, attempt)?;
            let cleanup_authority = self.cleanup_authority()?;
            // `create_new` refuses pre-existing files and symlinks instead of
            // following or truncating them. A stale partial is removed by the
            // expiry maintenance path before the slot metadata is deleted.
            let mut options = tokio::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                options.mode(0o600);
            }
            let mut file = options
                .open(&temporary)
                .await
                .with_context(|| format!("could not create upload file {}", temporary.display()))?;
            let mut temporary_object = TemporaryObject::new(temporary.clone(), cleanup_authority);
            let mut stream = stream.take(max_size.saturating_add(1));
            let mut digest = Sha256::new();
            let mut bytes_written = 0_u64;
            let mut buffer = [0_u8; 64 * 1024];
            loop {
                let read = stream.read(&mut buffer).await.with_context(|| {
                    format!("could not read upload body for {}", temporary.display())
                })?;
                if read == 0 {
                    break;
                }
                bytes_written = bytes_written
                    .checked_add(read as u64)
                    .context("upload size overflow")?;
                if bytes_written > max_size {
                    break;
                }
                digest.update(&buffer[..read]);
                file.write_all(&buffer[..read])
                    .await
                    .with_context(|| format!("could not write upload {}", temporary.display()))?;
            }
            file.flush()
                .await
                .with_context(|| format!("could not flush upload {}", temporary.display()))?;
            file.sync_all()
                .await
                .with_context(|| format!("could not sync upload {}", temporary.display()))?;
            drop(file);
            if bytes_written != max_size {
                Ok(StagedUpload {
                    bytes_written,
                    sha256: None,
                    stage_key: format!("staging/{id}/{attempt_id}"),
                    object_key: id.to_string(),
                    stage_version: None,
                    cleanup_path: None,
                    remote_cleanup: None,
                    cleanup_authority: None,
                })
            } else {
                // Exact-size bytes remain staged until the caller locks the
                // authoritative database row and invokes `commit`.
                temporary_object.commit();
                Ok(StagedUpload {
                    bytes_written,
                    sha256: Some(digest.finalize().into()),
                    stage_key: format!("staging/{id}/{attempt_id}"),
                    object_key: id.to_string(),
                    stage_version: None,
                    cleanup_path: Some(temporary),
                    remote_cleanup: None,
                    cleanup_authority: None,
                })
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
        Box::pin(async move {
            anyhow::ensure!(
                expected_stage_version.is_none(),
                "local upload stages do not have provider versions"
            );
            let id = uuid::Uuid::parse_str(key).context("upload object key is not a UUID")?;
            let _attempt_id =
                uuid::Uuid::parse_str(attempt).context("upload attempt key is not a UUID")?;
            // Local storage retains the historical bare-UUID namespace used
            // by backup/restore. A hard-link is the portable create-only
            // promotion primitive: it is atomic on this single filesystem and
            // cannot overwrite a destination created by another attempt.
            let object_key = id.to_string();
            let path = self.path(&object_key)?;
            let temporary = self.temporary_path(key, attempt)?;
            if let Err(error) = tokio::fs::hard_link(&temporary, &path).await {
                // A retry after a crash between storage promotion and database
                // completion sees the same create-only UUID destination.
                // Never delete or replace it: verify its bytes below instead.
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::AlreadyExists | std::io::ErrorKind::NotFound
                ) {
                    anyhow::ensure!(
                        tokio::fs::try_exists(&path).await?,
                        "upload stage and immutable destination are both missing"
                    );
                } else {
                    return Err(error)
                        .with_context(|| format!("could not commit upload {}", path.display()));
                }
            }
            #[cfg(unix)]
            std::fs::File::open(&self.root)
                .and_then(|directory| directory.sync_all())
                .with_context(|| {
                    format!(
                        "could not durably sync upload directory {}",
                        self.root.display()
                    )
                })?;
            let (size, digest) = digest_local_file(&path).await?;
            if size != expected_size {
                return Err(UploadIntegrityError::new("promoted size mismatch").into());
            }
            if &digest != expected_sha256 {
                return Err(UploadIntegrityError::new("promoted digest mismatch").into());
            }
            // Keep the stage until PostgreSQL commits the promoted locator.
            // `complete_promoted_upload` admits an exact delete-stage job in
            // the same transaction; removing it here would violate that
            // recovery boundary if the process exited before the DB commit.
            Ok(StoredUpload {
                backend: "local".to_owned(),
                object_key,
                object_version: None,
                size,
            })
        })
    }

    fn abort<'a>(
        &'a self,
        key: &'a str,
        attempt: &'a str,
        stage_version: Option<&'a str>,
    ) -> StoreFuture<'a, bool> {
        Box::pin(async move {
            anyhow::ensure!(
                stage_version.is_none(),
                "local upload stages do not have versions"
            );
            match tokio::fs::remove_file(self.temporary_path(key, attempt)?).await {
                Ok(()) => Ok(true),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
                Err(error) => Err(error.into()),
            }
        })
    }

    fn get<'a>(
        &'a self,
        object_key: &'a str,
        object_version: Option<&'a str>,
    ) -> StoreFuture<'a, Option<StoredUploadReader>> {
        Box::pin(async move {
            anyhow::ensure!(
                object_version.is_none(),
                "local upload objects do not have versions"
            );
            match tokio::fs::File::open(self.path(object_key)?).await {
                Ok(file) => {
                    let metadata = file.metadata().await?;
                    let size = metadata.len();
                    Ok(Some(StoredUploadReader {
                        reader: Box::new(file) as Box<dyn AsyncRead + Send + Unpin + 'static>,
                        size,
                        object_version: None,
                    }))
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(error.into()),
            }
        })
    }

    fn delete<'a>(
        &'a self,
        object_key: &'a str,
        object_version: Option<&'a str>,
    ) -> StoreFuture<'a, bool> {
        Box::pin(async move {
            anyhow::ensure!(
                object_version.is_none(),
                "local upload objects do not have versions"
            );
            let path = self.path(object_key)?;
            match tokio::fs::remove_file(&path).await {
                Ok(()) => Ok(true),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
                Err(error) => Err(error.into()),
            }
        })
    }

    fn clear<'a>(&'a self) -> StoreFuture<'a, u64> {
        Box::pin(async move {
            let mut removed = 0_u64;
            let mut entries = match tokio::fs::read_dir(&self.root).await {
                Ok(entries) => entries,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
                Err(error) => return Err(error.into()),
            };
            while let Some(entry) = entries.next_entry().await? {
                if !entry.file_type().await?.is_file() {
                    continue;
                }
                let file_name = entry.file_name();
                let Some(file_name) = file_name.to_str() else {
                    continue;
                };
                let owned = if let Some(staged) = file_name.strip_suffix(".part") {
                    let mut parts = staged.split('.');
                    matches!(
                        (parts.next(), parts.next(), parts.next()),
                        (Some(object), Some(attempt), None)
                            if uuid::Uuid::parse_str(object).is_ok()
                                && uuid::Uuid::parse_str(attempt).is_ok()
                    )
                } else if let Some(committed) = file_name.strip_suffix(".object") {
                    let mut parts = committed.split('.');
                    matches!(
                        (parts.next(), parts.next(), parts.next()),
                        (Some(object), Some(attempt), None)
                            if uuid::Uuid::parse_str(object).is_ok()
                                && uuid::Uuid::parse_str(attempt).is_ok()
                    )
                } else {
                    uuid::Uuid::parse_str(file_name).is_ok()
                };
                if !owned {
                    continue;
                }
                tokio::fs::remove_file(entry.path()).await?;
                removed += 1;
            }
            Ok(removed)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        push_startup_staging_attempt, GuardedUploadStore, LocalUploadStore,
        UploadAuthorityGeneration, UploadSafetyGate, UploadStore, MAX_STARTUP_STAGING_ATTEMPTS,
    };
    use sha2::Digest;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf};

    struct FailingReader;

    impl AsyncRead for FailingReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Err(std::io::Error::other("intentional read failure")))
        }
    }

    fn test_root() -> std::path::PathBuf {
        std::env::temp_dir().join(format!("northstar-upload-store-{}", uuid::Uuid::new_v4()))
    }

    #[tokio::test]
    async fn short_and_oversized_writes_leave_no_object_or_partial() {
        for (body, expected) in [(b"abc".as_slice(), 4_u64), (b"abcde".as_slice(), 4_u64)] {
            let root = test_root();
            let id = uuid::Uuid::new_v4();
            let attempt = uuid::Uuid::new_v4();
            let store = LocalUploadStore::new(root.clone());
            let written = store
                .put(
                    &id.to_string(),
                    &attempt.to_string(),
                    Box::new(std::io::Cursor::new(body.to_vec())),
                    expected,
                )
                .await
                .unwrap();
            assert_ne!(written.bytes_written(), expected);
            assert!(!tokio::fs::try_exists(root.join(id.to_string()))
                .await
                .unwrap());
            assert!(
                !tokio::fs::try_exists(root.join(format!("{id}.{attempt}.part")))
                    .await
                    .unwrap()
            );
            if tokio::fs::try_exists(&root).await.unwrap() {
                tokio::fs::remove_dir_all(root).await.unwrap();
            }
        }
    }

    #[tokio::test]
    async fn exact_write_is_committed_and_readable_without_partial() {
        let root = test_root();
        let id = uuid::Uuid::new_v4();
        let key = id.to_string();
        let attempt = uuid::Uuid::new_v4().to_string();
        let store = LocalUploadStore::new(root.clone());
        let mut staged = store
            .put(
                &key,
                &attempt,
                Box::new(std::io::Cursor::new(b"test".to_vec())),
                4,
            )
            .await
            .unwrap();
        assert_eq!(staged.bytes_written(), 4);
        assert!(
            tokio::fs::try_exists(root.join(format!("{id}.{attempt}.part")))
                .await
                .unwrap()
        );
        assert!(store.get(&key, None).await.unwrap().is_none());
        let digest: [u8; 32] = sha2::Sha256::digest(b"test").into();
        let promoted = store
            .commit(&key, &attempt, None, 4, &digest)
            .await
            .unwrap();
        let duplicate = store
            .commit(&key, &attempt, None, 4, &digest)
            .await
            .unwrap();
        assert_eq!(promoted, duplicate);
        staged.durably_recorded();
        assert!(
            tokio::fs::try_exists(root.join(format!("{id}.{attempt}.part")))
                .await
                .unwrap()
        );
        assert!(store.abort(&key, &attempt, None).await.unwrap());
        assert!(
            !tokio::fs::try_exists(root.join(format!("{id}.{attempt}.part")))
                .await
                .unwrap()
        );
        let stored = store
            .get(&promoted.object_key, None)
            .await
            .unwrap()
            .unwrap();
        let mut reader = stored.reader;
        let mut body = Vec::new();
        reader.read_to_end(&mut body).await.unwrap();
        assert_eq!(stored.size, 4);
        assert_eq!(body, b"test");
        tokio::fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn dropping_an_unpromoted_exact_stage_removes_only_that_attempt() {
        let root = test_root();
        let id = uuid::Uuid::new_v4();
        let stale_attempt = uuid::Uuid::new_v4();
        let replacement_attempt = uuid::Uuid::new_v4();
        let store = LocalUploadStore::new(root.clone());

        let stale = store
            .put(
                &id.to_string(),
                &stale_attempt.to_string(),
                Box::new(std::io::Cursor::new(b"old!".to_vec())),
                4,
            )
            .await
            .unwrap();
        let replacement = store
            .put(
                &id.to_string(),
                &replacement_attempt.to_string(),
                Box::new(std::io::Cursor::new(b"new!".to_vec())),
                4,
            )
            .await
            .unwrap();

        drop(stale);
        assert!(
            !tokio::fs::try_exists(root.join(format!("{id}.{stale_attempt}.part")))
                .await
                .unwrap()
        );
        assert!(
            tokio::fs::try_exists(root.join(format!("{id}.{replacement_attempt}.part")))
                .await
                .unwrap()
        );
        drop(replacement);
        assert!(
            !tokio::fs::try_exists(root.join(format!("{id}.{replacement_attempt}.part")))
                .await
                .unwrap()
        );
        assert!(store.get(&id.to_string(), None).await.unwrap().is_none());

        tokio::fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn startup_scan_and_cleanup_target_only_well_formed_abandoned_stages() {
        let root = test_root();
        tokio::fs::create_dir_all(&root).await.unwrap();
        let object = uuid::Uuid::new_v4();
        let attempt = uuid::Uuid::new_v4();
        let owned = root.join(format!("{object}.{attempt}.part"));
        let operator_file = root.join("operator-data.part");
        let malformed = root.join(format!("{object}.not-a-uuid.part"));
        tokio::fs::write(&owned, b"abandoned").await.unwrap();
        tokio::fs::write(&operator_file, b"keep").await.unwrap();
        tokio::fs::write(&malformed, b"keep").await.unwrap();

        let store = LocalUploadStore::new(root.clone());
        assert_eq!(
            store.staging_attempts().await.unwrap(),
            vec![(object, attempt)]
        );
        assert!(store
            .abort(&object.to_string(), &attempt.to_string(), None)
            .await
            .unwrap());
        assert!(!tokio::fs::try_exists(owned).await.unwrap());
        assert!(tokio::fs::try_exists(operator_file).await.unwrap());
        assert!(tokio::fs::try_exists(malformed).await.unwrap());

        tokio::fs::remove_dir_all(root).await.unwrap();
    }

    #[test]
    fn startup_scan_rejects_stage_overflow_before_growing_the_result() {
        let object = uuid::Uuid::new_v4();
        let attempt = uuid::Uuid::new_v4();
        let mut attempts = vec![(object, attempt); MAX_STARTUP_STAGING_ATTEMPTS];
        assert!(push_startup_staging_attempt(&mut attempts, object, attempt).is_err());
        assert_eq!(attempts.len(), MAX_STARTUP_STAGING_ATTEMPTS);
    }

    #[tokio::test]
    async fn guarded_stage_drop_quarantines_bytes_after_generation_invalidation() {
        let root = test_root();
        let gate = UploadSafetyGate::new();
        let generation = UploadAuthorityGeneration {
            namespace: 17,
            capacity_policy: 23,
        };
        gate.establish(generation, false);
        let local =
            Arc::new(LocalUploadStore::new(root.clone()).with_safety_gate(Arc::clone(&gate)));
        let guarded = GuardedUploadStore::new(local, Arc::clone(&gate));
        let object = uuid::Uuid::new_v4();
        let attempt = uuid::Uuid::new_v4();
        let staged = guarded
            .put(
                &object.to_string(),
                &attempt.to_string(),
                Box::new(std::io::Cursor::new(b"safe".to_vec())),
                4,
            )
            .await
            .unwrap();
        let path = root.join(format!("{object}.{attempt}.part"));
        assert!(tokio::fs::try_exists(&path).await.unwrap());
        gate.mark_ledger_mismatch("injected post-write mismatch");
        drop(staged);
        assert!(tokio::fs::try_exists(&path).await.unwrap());
        tokio::fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn stream_failure_removes_partial() {
        let root = test_root();
        let id = uuid::Uuid::new_v4();
        let attempt = uuid::Uuid::new_v4();
        let store = LocalUploadStore::new(root.clone());
        assert!(store
            .put(
                &id.to_string(),
                &attempt.to_string(),
                Box::new(FailingReader),
                4,
            )
            .await
            .is_err());
        assert!(!tokio::fs::try_exists(root.join(id.to_string()))
            .await
            .unwrap());
        assert!(
            !tokio::fs::try_exists(root.join(format!("{id}.{attempt}.part")))
                .await
                .unwrap()
        );
        if tokio::fs::try_exists(&root).await.unwrap() {
            tokio::fs::remove_dir_all(root).await.unwrap();
        }
    }

    #[tokio::test]
    async fn cancelled_write_removes_partial_and_is_not_gettable() {
        let root = test_root();
        let id = uuid::Uuid::new_v4();
        let key = id.to_string();
        let attempt = uuid::Uuid::new_v4().to_string();
        let store = Arc::new(LocalUploadStore::new(root.clone()));
        let (mut writer, reader) = tokio::io::duplex(64);
        writer.write_all(b"partial").await.unwrap();

        let task_store = store.clone();
        let task_key = key.clone();
        let task_attempt = attempt.clone();
        let task = tokio::spawn(async move {
            task_store
                .put(&task_key, &task_attempt, Box::new(reader), 1024)
                .await
                .unwrap()
        });
        let partial = root.join(format!("{id}.{attempt}.part"));
        for _ in 0..100 {
            if tokio::fs::try_exists(&partial).await.unwrap() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(tokio::fs::try_exists(&partial).await.unwrap());
        assert!(store.get(&key, None).await.unwrap().is_none());
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(!tokio::fs::try_exists(&partial).await.unwrap());
        assert!(store.get(&key, None).await.unwrap().is_none());

        drop(writer);
        tokio::fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn delete_removes_final_and_partial_but_rejects_non_uuid_keys() {
        let root = test_root();
        tokio::fs::create_dir_all(&root).await.unwrap();
        let id = uuid::Uuid::new_v4();
        let attempt = uuid::Uuid::new_v4();
        tokio::fs::write(root.join(id.to_string()), b"object")
            .await
            .unwrap();
        tokio::fs::write(root.join(format!("{id}.{attempt}.part")), b"partial")
            .await
            .unwrap();
        let store = LocalUploadStore::new(root.clone());
        assert!(store.delete(&id.to_string(), None).await.unwrap());
        assert!(!store.delete(&id.to_string(), None).await.unwrap());
        assert!(store.get("../operator-secret", None).await.is_err());
        assert!(store.delete("../operator-secret", None).await.is_err());
        tokio::fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn clear_removes_only_owned_uuid_objects() {
        let root = test_root();
        tokio::fs::create_dir_all(root.join("operator-directory"))
            .await
            .unwrap();
        let id = uuid::Uuid::new_v4();
        let attempt = uuid::Uuid::new_v4();
        tokio::fs::write(root.join(id.to_string()), b"object")
            .await
            .unwrap();
        tokio::fs::write(root.join(format!("{id}.{attempt}.part")), b"partial")
            .await
            .unwrap();
        tokio::fs::write(root.join("keep.txt"), b"operator data")
            .await
            .unwrap();

        let store = LocalUploadStore::new(root.clone());
        assert_eq!(store.clear().await.unwrap(), 2);
        assert!(tokio::fs::try_exists(root.join("keep.txt")).await.unwrap());
        assert!(tokio::fs::try_exists(root.join("operator-directory"))
            .await
            .unwrap());

        tokio::fs::remove_dir_all(root).await.unwrap();
    }
}
