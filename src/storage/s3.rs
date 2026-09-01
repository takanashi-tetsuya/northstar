use super::{
    StagedUpload, StoreFuture, StoredUpload, StoredUploadReader, UploadIntegrityError, UploadStore,
};
use crate::services::upload_safety::{UploadAuthorityGeneration, UploadIoClass, UploadSafetyGate};
use anyhow::{Context, Result};
use bytes::BytesMut;
use futures::TryStreamExt;
use object_store::{
    aws::{AmazonS3Builder, AmazonS3ConfigKey},
    path::Path,
    GetOptions, ObjectStore, ObjectStoreExt, WriteMultipart,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};
use tokio::io::{AsyncRead, AsyncReadExt};
use zeroize::{Zeroize, Zeroizing};

/// Non-secret S3 connection settings plus protected credential-file paths.
/// `ambient_credentials` enables the maintained client's web-identity,
/// container and IMDSv2 providers; long-lived environment credentials are
/// rejected by configuration validation before this type is constructed.
#[derive(Clone)]
pub struct S3UploadSettings {
    pub endpoint: Option<String>,
    pub region: String,
    pub bucket: String,
    pub prefix: String,
    pub path_style: bool,
    pub allow_http: bool,
    pub ambient_credentials: bool,
    pub credential_bundle_file: Option<PathBuf>,
    pub access_key_id_file: Option<PathBuf>,
    pub secret_access_key_file: Option<PathBuf>,
    pub session_token_file: Option<PathBuf>,
    pub sse_kms_key_id_file: Option<PathBuf>,
}

impl std::fmt::Debug for S3UploadSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3UploadSettings")
            .field("region", &self.region)
            .field("bucket", &self.bucket)
            .field("prefix", &self.prefix)
            .field("path_style", &self.path_style)
            .field("allow_http", &self.allow_http)
            .field("ambient_credentials", &self.ambient_credentials)
            .field("custom_endpoint", &self.endpoint.is_some())
            .field(
                "file_credentials",
                &(self.credential_bundle_file.is_some() || self.access_key_id_file.is_some()),
            )
            .field("session_token_file", &self.session_token_file.is_some())
            .field("sse_kms_key_file", &self.sse_kms_key_id_file.is_some())
            .finish()
    }
}

pub struct S3UploadStore {
    settings: S3UploadSettings,
    client: std::sync::RwLock<Arc<dyn ObjectStore>>,
    credential_generation: AtomicU64,
    safety_gate: Option<Arc<UploadSafetyGate>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialBundle {
    generation: u64,
    access_key_id: String,
    secret_access_key: String,
    #[serde(default)]
    session_token: Option<String>,
}

impl Drop for CredentialBundle {
    fn drop(&mut self) {
        self.access_key_id.zeroize();
        self.secret_access_key.zeroize();
        if let Some(token) = &mut self.session_token {
            token.zeroize();
        }
    }
}

/// Covers cancellation after multipart completion but before `StagedUpload`
/// reaches the caller. Incomplete multipart parts still require the documented
/// bucket lifecycle rule because deleting an object key cannot address an
/// upload id hidden inside the provider client.
struct RemoteTemporaryObject {
    client: Arc<dyn ObjectStore>,
    path: Path,
    armed: bool,
    cleanup_authority: Option<(Arc<UploadSafetyGate>, UploadAuthorityGeneration)>,
}

impl RemoteTemporaryObject {
    fn new(
        client: Arc<dyn ObjectStore>,
        path: Path,
        cleanup_authority: Option<(Arc<UploadSafetyGate>, UploadAuthorityGeneration)>,
    ) -> Self {
        Self {
            client,
            path,
            armed: true,
            cleanup_authority,
        }
    }

    fn commit(&mut self) {
        self.armed = false;
    }
}

impl Drop for RemoteTemporaryObject {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let client = Arc::clone(&self.client);
        let path = self.path.clone();
        let authority = self.cleanup_authority.clone();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
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
                        deleted = client.delete(&path) => deleted,
                    }
                } else {
                    client.delete(&path).await
                };
                if let Err(error) = deleted {
                    tracing::warn!(stage_key=%path, ?error, "failed to remove canceled remote upload stage");
                }
            });
        }
    }
}

impl std::fmt::Debug for S3UploadStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3UploadStore")
            .field("region", &self.settings.region)
            .field("bucket", &self.settings.bucket)
            .field("prefix", &self.settings.prefix)
            .field("path_style", &self.settings.path_style)
            .finish_non_exhaustive()
    }
}

impl S3UploadStore {
    pub fn new(settings: S3UploadSettings) -> Result<Self> {
        let (client, generation) = build_client(&settings)?;
        Ok(Self {
            settings,
            client: std::sync::RwLock::new(client),
            credential_generation: AtomicU64::new(generation),
            safety_gate: None,
        })
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

    fn client(&self) -> Arc<dyn ObjectStore> {
        self.client
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    #[cfg(test)]
    fn with_client_for_test(client: Arc<dyn ObjectStore>) -> Self {
        Self {
            settings: S3UploadSettings {
                endpoint: None,
                region: "test-1".to_owned(),
                bucket: "test-bucket".to_owned(),
                prefix: "northstar-test".to_owned(),
                path_style: true,
                allow_http: false,
                ambient_credentials: false,
                credential_bundle_file: None,
                access_key_id_file: None,
                secret_access_key_file: None,
                session_token_file: None,
                sse_kms_key_id_file: None,
            },
            client: std::sync::RwLock::new(client),
            credential_generation: AtomicU64::new(0),
            safety_gate: None,
        }
    }

    #[cfg(test)]
    fn swap_client_for_test(&self, replacement: Arc<dyn ObjectStore>) {
        *self
            .client
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = replacement;
    }

    fn path(&self, relative: &str) -> Result<Path> {
        validate_relative_key(relative)?;
        let key = if self.settings.prefix.is_empty() {
            relative.to_owned()
        } else {
            format!("{}/{}", self.settings.prefix, relative)
        };
        Path::parse(key).context("upload object key is not a canonical object-store path")
    }

    async fn verified_object(
        &self,
        key: &str,
        expected_version: Option<&str>,
        expected_size: u64,
        expected_sha256: &[u8; 32],
    ) -> Result<Option<StoredUpload>> {
        let client = self.client();
        let path = self.path(key)?;
        let options = GetOptions::new().with_version(expected_version.map(str::to_owned));
        let result = match client.get_opts(&path, options).await {
            Ok(result) => result,
            Err(object_store::Error::NotFound { .. }) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if result.meta.version.as_deref() != expected_version {
            return Err(UploadIntegrityError::new(
                "object-store version differs from the staged database projection",
            )
            .into());
        }
        if result.meta.size != expected_size {
            return Err(UploadIntegrityError::new("object-store metadata size mismatch").into());
        }
        let version = result.meta.version.clone();
        let mut stream = result.into_stream();
        let mut size = 0_u64;
        let mut digest = Sha256::new();
        while let Some(chunk) = stream.try_next().await? {
            size = size
                .checked_add(chunk.len() as u64)
                .context("object-store size overflow")?;
            if size > expected_size {
                return Err(UploadIntegrityError::new("object-store object is oversized").into());
            }
            digest.update(&chunk);
        }
        if size != expected_size {
            return Err(UploadIntegrityError::new("object-store object is truncated").into());
        }
        let actual: [u8; 32] = digest.finalize().into();
        if &actual != expected_sha256 {
            return Err(UploadIntegrityError::new("object-store digest mismatch").into());
        }
        Ok(Some(StoredUpload {
            backend: "s3".to_owned(),
            object_key: key.to_owned(),
            object_version: version,
            size,
        }))
    }
}

impl UploadStore for S3UploadStore {
    fn backend(&self) -> &'static str {
        "s3"
    }

    fn put<'a>(
        &'a self,
        key: &'a str,
        attempt: &'a str,
        mut stream: Box<dyn AsyncRead + Send + Unpin + 'a>,
        max_size: u64,
    ) -> StoreFuture<'a, StagedUpload> {
        Box::pin(async move {
            let id = uuid::Uuid::parse_str(key).context("upload object key is not a UUID")?;
            let attempt =
                uuid::Uuid::parse_str(attempt).context("upload attempt key is not a UUID")?;
            // The attempt-qualified key is private until PostgreSQL changes
            // the slot to `committed`; no provider-side copy is necessary.
            // Using one immutable key also removes the ambiguous CopyObject
            // completion window after a timeout or process crash.
            let object_key = format!("objects/{id}/{attempt}");
            let stage_key = object_key.clone();
            let path = self.path(&stage_key)?;
            let client = self.client();
            let mut temporary = RemoteTemporaryObject::new(
                Arc::clone(&client),
                path.clone(),
                self.cleanup_authority()?,
            );
            let upload = client
                .put_multipart(&path)
                .await
                .context("could not initiate multipart upload stage")?;
            let mut writer = WriteMultipart::new(upload);
            let mut bytes_written = 0_u64;
            let mut digest = Sha256::new();
            let mut buffer = BytesMut::zeroed(128 * 1024);
            loop {
                let read = match stream.read(&mut buffer[..]).await {
                    Ok(read) => read,
                    Err(error) => {
                        writer.abort().await.ok();
                        return Err(error).context("could not read multipart upload body");
                    }
                };
                if read == 0 {
                    break;
                }
                bytes_written = bytes_written
                    .checked_add(read as u64)
                    .context("upload stage size overflow")?;
                if bytes_written > max_size {
                    writer.abort().await.ok();
                    return Ok(StagedUpload {
                        bytes_written,
                        sha256: None,
                        stage_key,
                        object_key,
                        stage_version: None,
                        cleanup_path: None,
                        remote_cleanup: None,
                        cleanup_authority: None,
                    });
                }
                writer.wait_for_capacity(4).await?;
                writer.write(&buffer[..read]);
                digest.update(&buffer[..read]);
            }
            if bytes_written != max_size {
                writer.abort().await.ok();
                return Ok(StagedUpload {
                    bytes_written,
                    sha256: None,
                    stage_key,
                    object_key,
                    stage_version: None,
                    cleanup_path: None,
                    remote_cleanup: None,
                    cleanup_authority: None,
                });
            }
            let result = writer
                .finish()
                .await
                .context("could not complete multipart upload stage")?;
            temporary.commit();
            Ok(StagedUpload {
                bytes_written,
                sha256: Some(digest.finalize().into()),
                stage_key,
                object_key,
                stage_version: result.version,
                cleanup_path: None,
                remote_cleanup: Some((client, path)),
                cleanup_authority: None,
            })
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
            let id = uuid::Uuid::parse_str(key).context("upload object key is not a UUID")?;
            let attempt =
                uuid::Uuid::parse_str(attempt).context("upload attempt key is not a UUID")?;
            let object_key = format!("objects/{id}/{attempt}");
            self.verified_object(
                &object_key,
                expected_stage_version,
                expected_size,
                expected_sha256,
            )
            .await?
            .context("staged object is missing during committed-gate verification")
        })
    }

    fn abort<'a>(
        &'a self,
        key: &'a str,
        attempt: &'a str,
        stage_version: Option<&'a str>,
    ) -> StoreFuture<'a, bool> {
        Box::pin(async move {
            let id = uuid::Uuid::parse_str(key).context("upload object key is not a UUID")?;
            let attempt =
                uuid::Uuid::parse_str(attempt).context("upload attempt key is not a UUID")?;
            let path = self.path(&format!("objects/{id}/{attempt}"))?;
            let client = self.client();
            let current = match client.head(&path).await {
                Ok(current) => current,
                Err(object_store::Error::NotFound { .. }) => return Ok(false),
                Err(error) => return Err(error.into()),
            };
            if let Some(expected) = stage_version {
                anyhow::ensure!(
                    current.version.as_deref() == Some(expected),
                    "refusing to delete an upload stage version not named by PostgreSQL"
                );
            }
            match client.delete(&path).await {
                Ok(()) => match client.head(&path).await {
                    Err(object_store::Error::NotFound { .. }) => Ok(true),
                    Ok(_) => anyhow::bail!("upload stage remains visible after delete"),
                    Err(error) => Err(error.into()),
                },
                Err(object_store::Error::NotFound { .. }) => Ok(false),
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
            let path = self.path(object_key)?;
            let client = self.client();
            let options = GetOptions::new().with_version(object_version.map(str::to_owned));
            let result = match client.get_opts(&path, options).await {
                Ok(result) => result,
                Err(object_store::Error::NotFound { .. }) => return Ok(None),
                Err(error) => return Err(error.into()),
            };
            if let Some(expected) = object_version {
                anyhow::ensure!(
                    result.meta.version.as_deref() == Some(expected),
                    "object-store version differs from committed metadata"
                );
            }
            let size = result.meta.size;
            let version = result.meta.version.clone();
            let stream = result.into_stream().map_err(std::io::Error::other);
            Ok(Some(StoredUploadReader {
                reader: Box::new(tokio_util::io::StreamReader::new(stream)),
                size,
                object_version: version,
            }))
        })
    }

    fn delete<'a>(
        &'a self,
        object_key: &'a str,
        object_version: Option<&'a str>,
    ) -> StoreFuture<'a, bool> {
        Box::pin(async move {
            let path = self.path(object_key)?;
            let client = self.client();
            let current = match client.head(&path).await {
                Ok(current) => current,
                Err(object_store::Error::NotFound { .. }) => return Ok(false),
                Err(error) => return Err(error.into()),
            };
            if let Some(expected) = object_version {
                anyhow::ensure!(
                    current.version.as_deref() == Some(expected),
                    "refusing to delete an object-store version not named by PostgreSQL"
                );
            }
            match client.delete(&path).await {
                Ok(()) => match client.head(&path).await {
                    Err(object_store::Error::NotFound { .. }) => Ok(true),
                    Ok(_) => anyhow::bail!("object remains visible after delete"),
                    Err(error) => Err(error.into()),
                },
                Err(object_store::Error::NotFound { .. }) => Ok(false),
                Err(error) => Err(error.into()),
            }
        })
    }

    fn reload_credentials<'a>(&'a self) -> StoreFuture<'a, bool> {
        Box::pin(async move {
            if self.settings.credential_bundle_file.is_none()
                && self.settings.access_key_id_file.is_some()
            {
                // Multiple legacy files cannot be sampled atomically. They
                // are development-only and deliberately have a restart
                // boundary instead of risking a torn access/secret pair.
                return Ok(false);
            }
            let (replacement, generation) = build_client(&self.settings)?;
            let mut client = self
                .client
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let current = self.credential_generation.load(Ordering::Acquire);
            if self.settings.credential_bundle_file.is_some() && generation <= current {
                return Ok(false);
            }
            *client = replacement;
            // Generation and client are published under the same write-side
            // critical section. Concurrent reloads therefore cannot let an
            // older parsed bundle overwrite a newer client.
            self.credential_generation
                .store(generation, Ordering::Release);
            Ok(true)
        })
    }

    fn clear<'a>(&'a self) -> StoreFuture<'a, u64> {
        Box::pin(async {
            anyhow::bail!(
                "bulk object-store clearing is deliberately unsupported; use the bounded database reconciliation queue"
            )
        })
    }
}

fn build_client(settings: &S3UploadSettings) -> Result<(Arc<dyn ObjectStore>, u64)> {
    // Start from a clean builder. `from_env` also accepts endpoint, proxy,
    // unsigned-payload and HTTP overrides, which would bypass Northstar's
    // SSRF/TLS validation. Copy only credential-provider inputs with bounded
    // semantics; absent inputs deliberately fall back to IMDSv2 (never v1).
    let has_file_credentials = settings.credential_bundle_file.is_some()
        || settings.access_key_id_file.is_some() && settings.secret_access_key_file.is_some();
    anyhow::ensure!(
        settings.ambient_credentials || has_file_credentials,
        "S3 upload storage has no authorized credential source"
    );
    let mut builder = AmazonS3Builder::new()
        .with_bucket_name(&settings.bucket)
        .with_region(&settings.region)
        .with_virtual_hosted_style_request(!settings.path_style)
        .with_allow_http(settings.allow_http);

    if settings.ambient_credentials {
        if let (Some(token_file), Some(role_arn)) = (
            std::env::var_os("AWS_WEB_IDENTITY_TOKEN_FILE"),
            std::env::var_os("AWS_ROLE_ARN"),
        ) {
            builder = builder
                .with_config(
                    AmazonS3ConfigKey::WebIdentityTokenFile,
                    token_file.to_string_lossy(),
                )
                .with_config(AmazonS3ConfigKey::RoleArn, role_arn.to_string_lossy());
            if let Some(name) = std::env::var_os("AWS_ROLE_SESSION_NAME") {
                builder =
                    builder.with_config(AmazonS3ConfigKey::RoleSessionName, name.to_string_lossy());
            }
        } else if let Some(relative) = std::env::var_os("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI") {
            let relative = relative.to_string_lossy();
            anyhow::ensure!(
                relative.starts_with('/')
                    && relative.len() <= 2048
                    && !relative.contains("..")
                    && !relative.chars().any(char::is_control),
                "AWS container credential relative URI is invalid"
            );
            builder =
                builder.with_config(AmazonS3ConfigKey::ContainerCredentialsRelativeUri, relative);
        }
    }

    if let Some(endpoint) = &settings.endpoint {
        builder = builder.with_endpoint(endpoint);
    }

    let mut generation = 0;
    if let Some(bundle_file) = settings.credential_bundle_file.as_deref() {
        anyhow::ensure!(
            settings.access_key_id_file.is_none()
                && settings.secret_access_key_file.is_none()
                && settings.session_token_file.is_none(),
            "the atomic S3 credential bundle cannot be combined with legacy credential files"
        );
        let bundle_json = Zeroizing::new(crate::config::read_secret_file(
            bundle_file,
            "UPLOAD_S3_CREDENTIAL_BUNDLE_FILE",
        )?);
        let bundle: CredentialBundle =
            serde_json::from_str(&bundle_json).context("S3 credential bundle is not valid JSON")?;
        anyhow::ensure!(
            bundle.generation > 0,
            "S3 credential bundle generation must be positive"
        );
        anyhow::ensure!(
            !bundle.access_key_id.is_empty() && !bundle.secret_access_key.is_empty(),
            "S3 credential bundle keys must not be empty"
        );
        builder = builder
            .with_access_key_id(bundle.access_key_id.as_str())
            .with_secret_access_key(bundle.secret_access_key.as_str());
        if let Some(token) = bundle.session_token.as_deref() {
            builder = builder.with_token(token);
        }
        generation = bundle.generation;
    } else {
        match (
            settings.access_key_id_file.as_deref(),
            settings.secret_access_key_file.as_deref(),
        ) {
            (Some(access_file), Some(secret_file)) => {
                let mut access = Zeroizing::new(crate::config::read_secret_file(
                    access_file,
                    "UPLOAD_S3_ACCESS_KEY_ID_FILE",
                )?);
                let mut secret = Zeroizing::new(crate::config::read_secret_file(
                    secret_file,
                    "UPLOAD_S3_SECRET_ACCESS_KEY_FILE",
                )?);
                builder = builder
                    .with_access_key_id(access.as_str())
                    .with_secret_access_key(secret.as_str());
                access.zeroize();
                secret.zeroize();
            }
            (None, None) => {}
            _ => anyhow::bail!("S3 access-key files must be configured together"),
        }
    }
    if settings.credential_bundle_file.is_none() {
        if let Some(token_file) = settings.session_token_file.as_deref() {
            let mut token = Zeroizing::new(crate::config::read_secret_file(
                token_file,
                "UPLOAD_S3_SESSION_TOKEN_FILE",
            )?);
            builder = builder.with_token(token.as_str());
            token.zeroize();
        }
    }
    if let Some(kms_file) = settings.sse_kms_key_id_file.as_deref() {
        let mut kms_key = Zeroizing::new(crate::config::read_secret_file(
            kms_file,
            "UPLOAD_S3_SSE_KMS_KEY_ID_FILE",
        )?);
        builder = builder.with_sse_kms_encryption(kms_key.as_str());
        kms_key.zeroize();
    }
    Ok((
        Arc::new(
            builder
                .build()
                .context("could not build S3 upload client")?,
        ),
        generation,
    ))
}

fn validate_relative_key(key: &str) -> Result<()> {
    let mut parts = key.split('/');
    let (Some(kind @ ("objects" | "staging")), Some(id), Some(attempt), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        anyhow::bail!("upload object key is not canonical");
    };
    let _ = kind;
    uuid::Uuid::parse_str(id).context("upload object key has an invalid UUID")?;
    uuid::Uuid::parse_str(attempt).context("upload object key has an invalid attempt UUID")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{validate_relative_key, S3UploadSettings, S3UploadStore};
    use crate::storage::UploadStore;
    use object_store::{memory::InMemory, ObjectStore};
    use sha2::{Digest, Sha256};
    use std::sync::Arc;
    use tokio::io::AsyncReadExt;

    #[test]
    fn keys_are_uuid_qualified_and_cannot_traverse() {
        let id = uuid::Uuid::new_v4();
        let attempt = uuid::Uuid::new_v4();
        assert!(validate_relative_key(&format!("objects/{id}/{attempt}")).is_ok());
        assert!(validate_relative_key(&format!("staging/{id}/{attempt}")).is_ok());
        for invalid in [
            "../secret",
            "objects/not-a-uuid/not-a-uuid",
            "objects/a/b/c",
            "/objects/a/b",
        ] {
            assert!(validate_relative_key(invalid).is_err());
        }
    }

    #[test]
    fn nonambient_store_requires_protected_file_credentials_and_debug_is_redacted() {
        let settings = S3UploadSettings {
            endpoint: Some("https://objects.example.test".to_owned()),
            region: "test-1".to_owned(),
            bucket: "test-bucket".to_owned(),
            prefix: "northstar-test".to_owned(),
            path_style: true,
            allow_http: false,
            ambient_credentials: false,
            credential_bundle_file: None,
            access_key_id_file: None,
            secret_access_key_file: None,
            session_token_file: Some("do-not-print/session-token".into()),
            sse_kms_key_id_file: Some("do-not-print/kms-key".into()),
        };
        let rendered = format!("{settings:?}");
        assert!(!rendered.contains("objects.example.test"));
        assert!(!rendered.contains("do-not-print"));
        assert!(S3UploadStore::new(settings).is_err());
    }

    #[tokio::test]
    async fn shared_fake_store_verifies_same_attempt_across_nodes_and_deletes() {
        let shared: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let node_a = S3UploadStore::with_client_for_test(Arc::clone(&shared));
        let node_b = S3UploadStore::with_client_for_test(shared);
        let id = uuid::Uuid::new_v4();
        let attempt = uuid::Uuid::new_v4();
        let body = b"node-a-to-node-b";
        let expected: [u8; 32] = Sha256::digest(body).into();

        let mut staged = node_a
            .put(
                &id.to_string(),
                &attempt.to_string(),
                Box::new(std::io::Cursor::new(body.to_vec())),
                body.len() as u64,
            )
            .await
            .unwrap();
        assert_eq!(staged.sha256(), Some(&expected));
        assert_eq!(staged.stage_key(), staged.object_key());
        let stage_version = staged.stage_version().map(str::to_owned);
        staged.durably_recorded();
        let first = node_a
            .commit(
                &id.to_string(),
                &attempt.to_string(),
                stage_version.as_deref(),
                body.len() as u64,
                &expected,
            )
            .await
            .unwrap();
        let duplicate = node_b
            .commit(
                &id.to_string(),
                &attempt.to_string(),
                stage_version.as_deref(),
                body.len() as u64,
                &expected,
            )
            .await
            .unwrap();
        assert_eq!(first.object_key, duplicate.object_key);

        let stored = node_b
            .get(&first.object_key, first.object_version.as_deref())
            .await
            .unwrap()
            .unwrap();
        let mut reader = stored.reader;
        let mut downloaded = Vec::new();
        reader.read_to_end(&mut downloaded).await.unwrap();
        assert_eq!(downloaded, body);

        assert!(node_b
            .delete(&first.object_key, first.object_version.as_deref())
            .await
            .unwrap());
        assert!(node_a
            .get(&first.object_key, first.object_version.as_deref())
            .await
            .unwrap()
            .is_none());
        assert!(!node_a
            .delete(&first.object_key, first.object_version.as_deref())
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn client_swap_is_atomic_and_old_client_remains_valid_for_in_flight_work() {
        let old: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let replacement: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let store = S3UploadStore::with_client_for_test(Arc::clone(&old));
        let in_flight = store.client();
        store.swap_client_for_test(replacement);
        assert!(Arc::ptr_eq(&old, &in_flight));
        assert!(!Arc::ptr_eq(&store.client(), &in_flight));
    }

    #[tokio::test]
    async fn late_attempt_appearance_is_removed_by_a_retained_cleanup_tombstone() {
        let shared: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let store = S3UploadStore::with_client_for_test(shared);
        let id = uuid::Uuid::new_v4();
        let attempt = uuid::Uuid::new_v4();
        assert!(!store
            .abort(&id.to_string(), &attempt.to_string(), None)
            .await
            .unwrap());

        // Model a provider completing a previously timed-out multipart after
        // the first absence observation. The durable DB tombstone is retained
        // for a quiet interval, so its next pass names the same attempt key.
        let mut late = store
            .put(
                &id.to_string(),
                &attempt.to_string(),
                Box::new(std::io::Cursor::new(b"late".to_vec())),
                4,
            )
            .await
            .unwrap();
        let version = late.stage_version().map(str::to_owned);
        late.durably_recorded();
        assert!(store
            .abort(&id.to_string(), &attempt.to_string(), version.as_deref())
            .await
            .unwrap());
        assert!(!store
            .abort(&id.to_string(), &attempt.to_string(), version.as_deref())
            .await
            .unwrap());
    }

    #[tokio::test]
    #[ignore = "requires the explicit loopback MinIO fixture and a pre-created bucket"]
    async fn minio_compatible_round_trip_harness() {
        let endpoint = std::env::var("NORTHSTAR_MINIO_TEST_ENDPOINT")
            .expect("set NORTHSTAR_MINIO_TEST_ENDPOINT, normally http://127.0.0.1:19000");
        let bucket = std::env::var("NORTHSTAR_MINIO_TEST_BUCKET")
            .expect("set NORTHSTAR_MINIO_TEST_BUCKET after creating the fixture bucket");
        let access_key_id_file = std::env::var_os("NORTHSTAR_MINIO_TEST_ACCESS_KEY_FILE")
            .map(std::path::PathBuf::from)
            .expect("set NORTHSTAR_MINIO_TEST_ACCESS_KEY_FILE");
        let secret_access_key_file = std::env::var_os("NORTHSTAR_MINIO_TEST_SECRET_KEY_FILE")
            .map(std::path::PathBuf::from)
            .expect("set NORTHSTAR_MINIO_TEST_SECRET_KEY_FILE");
        let store = S3UploadStore::new(super::S3UploadSettings {
            endpoint: Some(endpoint),
            region: "us-east-1".to_owned(),
            bucket,
            prefix: format!("northstar-manual-test/{}", uuid::Uuid::new_v4()),
            path_style: true,
            allow_http: true,
            ambient_credentials: false,
            credential_bundle_file: None,
            access_key_id_file: Some(access_key_id_file),
            secret_access_key_file: Some(secret_access_key_file),
            session_token_file: None,
            sse_kms_key_id_file: None,
        })
        .unwrap();
        let id = uuid::Uuid::new_v4();
        let attempt = uuid::Uuid::new_v4();
        let body = b"minio-compatibility";
        let digest: [u8; 32] = Sha256::digest(body).into();
        let mut stage = store
            .put(
                &id.to_string(),
                &attempt.to_string(),
                Box::new(std::io::Cursor::new(body.to_vec())),
                body.len() as u64,
            )
            .await
            .unwrap();
        let stage_version = stage.stage_version().map(str::to_owned);
        stage.durably_recorded();
        let object = store
            .commit(
                &id.to_string(),
                &attempt.to_string(),
                stage_version.as_deref(),
                body.len() as u64,
                &digest,
            )
            .await
            .unwrap();
        assert!(store
            .get(&object.object_key, object.object_version.as_deref())
            .await
            .unwrap()
            .is_some());
        store
            .delete(&object.object_key, object.object_version.as_deref())
            .await
            .unwrap();
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Projection {
        Writing,
        Staged,
        Promoting,
        Committed,
    }

    #[derive(Clone, Copy)]
    enum FailurePoint {
        StageBeforeMetadata,
        StagedMetadata,
        PromotingMetadata,
        VerifyBeforeCommit,
        CommitBeforeResponse,
    }

    #[derive(Default)]
    struct FakeLifecycleStore {
        attempt_key: bool,
    }

    /// Pure crash model for the production transition order. Every injected
    /// stop is resumed from durable state; promotion is create-only and
    /// successful commit never removes the immutable attempt key.
    fn recover_after_failure(fail_after: FailurePoint) -> (Projection, FakeLifecycleStore) {
        let mut transitions = vec![Projection::Writing];
        let mut store = FakeLifecycleStore { attempt_key: true };
        // The process can stop after stage creation while PostgreSQL is still
        // `writing`; the expired writing intent owns the exact cleanup key.
        if matches!(fail_after, FailurePoint::StageBeforeMetadata) {
            assert_eq!(transitions.last(), Some(&Projection::Writing));
            store.attempt_key = false;
            // A replacement claim recreates an isolated stage key.
            store.attempt_key = true;
        }
        transitions.push(Projection::Staged);
        if matches!(fail_after, FailurePoint::StagedMetadata) {
            // Durable promote job restarts from `staged`.
        }
        transitions.push(Projection::Promoting);
        if matches!(fail_after, FailurePoint::PromotingMetadata) {
            // Durable promote job restarts from `promoting`.
        }
        if matches!(fail_after, FailurePoint::VerifyBeforeCommit) {
            // PostgreSQL remains `promoting`; retry performs another read-only
            // exact-version verification of the same key.
            assert_eq!(transitions.last(), Some(&Projection::Promoting));
        }
        transitions.push(Projection::Committed);
        if matches!(fail_after, FailurePoint::CommitBeforeResponse) {
            // A retried request observes the committed DB projection and must
            // not abort the key which is both stage and destination.
            assert!(store.attempt_key);
        }
        (*transitions.last().expect("at least one projection"), store)
    }

    #[test]
    fn every_durable_transition_recovers_monotonically() {
        for fail_after in [
            FailurePoint::StageBeforeMetadata,
            FailurePoint::StagedMetadata,
            FailurePoint::PromotingMetadata,
            FailurePoint::VerifyBeforeCommit,
            FailurePoint::CommitBeforeResponse,
        ] {
            let (projection, store) = recover_after_failure(fail_after);
            assert_eq!(projection, Projection::Committed);
            assert!(store.attempt_key);
        }
    }
}
