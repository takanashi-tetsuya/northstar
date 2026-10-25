use super::{
    StageCleanup, StagedUpload, StoreFuture, StoredUpload, StoredUploadReader,
    UploadIntegrityError, UploadStore,
};
use anyhow::{Context, Result};
use axum::http::{Method, Request, StatusCode};
use bytes::BytesMut;
use futures::TryStreamExt;
use northstar_upload_application::safety::UploadSafetyGate;
use northstar_upload_application::{UploadAuthorityGeneration, UploadIoClass};
use object_store::{
    aws::{AmazonS3, AmazonS3Builder, AmazonS3ConfigKey, AwsAuthorizer},
    client::{ClientOptions, HttpClient, HttpConnector, HttpRequestBody, ReqwestConnector},
    path::Path,
    signer::Signer,
    GetOptions, ObjectStore, ObjectStoreExt, PutMode, WriteMultipart,
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum S3CleanupMode {
    ExactVersion,
    QualifiedUnversioned,
}

impl S3CleanupMode {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "exact-version" => Ok(Self::ExactVersion),
            "qualified-unversioned" => Ok(Self::QualifiedUnversioned),
            _ => anyhow::bail!(
                "UPLOAD_S3_CLEANUP_MODE must be exact-version or qualified-unversioned"
            ),
        }
    }
}

#[derive(Clone)]
pub struct S3UploadSettings {
    pub endpoint: Option<String>,
    pub region: String,
    pub bucket: String,
    pub prefix: String,
    pub path_style: bool,
    pub allow_http: bool,
    pub ambient_credentials: bool,
    pub cleanup_mode: S3CleanupMode,
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
            .field("cleanup_mode", &self.cleanup_mode)
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
    client: std::sync::RwLock<Arc<S3ClientSnapshot>>,
    credential_generation: AtomicU64,
    safety_gate: Option<Arc<UploadSafetyGate>>,
    #[cfg(test)]
    exact_delete_gate: Option<(Arc<tokio::sync::Barrier>, Arc<tokio::sync::Barrier>)>,
}

/// Keep the object-store operations, URL construction, and credential provider
/// on one immutable client generation while a version-qualified delete runs.
struct S3ClientSnapshot {
    store: Arc<dyn ObjectStore>,
    s3: Option<Arc<AmazonS3>>,
    delete_http: Option<HttpClient>,
    region: String,
    cleanup_mode: S3CleanupMode,
}

type ExactDeleteGate = (Arc<tokio::sync::Barrier>, Arc<tokio::sync::Barrier>);

/// An unrecorded completed stage retains the same client generation used for
/// its write. Exact-version cleanup is the default; qualified unversioned
/// cleanup requires a fresh bucket-state proof. The outer `StagedUpload` Drop
/// still owns the recovery-generation check.
struct RemoteS3Cleanup {
    snapshot: Arc<S3ClientSnapshot>,
    path: Path,
    version: Option<String>,
}

impl RemoteS3Cleanup {
    fn path(&self) -> &Path {
        &self.path
    }

    async fn delete(self) -> Result<bool> {
        delete_with_snapshot(&self.snapshot, &self.path, self.version.as_deref(), None).await
    }
}

impl StageCleanup for RemoteS3Cleanup {
    fn cleanup(
        self: Box<Self>,
        authority: Option<(Arc<UploadSafetyGate>, UploadAuthorityGeneration)>,
    ) {
        // A completed multipart stage is a normal object. If the HTTP
        // future is cancelled before PostgreSQL records it, schedule
        // guarded cleanup. Incomplete multipart parts remain
        // subject to the mandatory bucket lifecycle policy.
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let cleanup = *self;
            let stage_key = cleanup.path().to_string();
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
                        deleted = cleanup.delete() => deleted,
                    }
                } else {
                    cleanup.delete().await
                };
                if let Err(error) = deleted {
                    tracing::warn!(
                        stage_key = %stage_key,
                        ?error,
                        "failed to remove abandoned remote upload stage"
                    );
                }
            });
        }
    }
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
    path: Path,
    armed: bool,
}

impl RemoteTemporaryObject {
    fn new(path: Path) -> Self {
        Self { path, armed: true }
    }

    fn commit(&mut self) {
        self.armed = false;
    }
}

impl Drop for RemoteTemporaryObject {
    fn drop(&mut self) {
        if self.armed {
            // Completion may have succeeded even when its response was lost;
            // without that version ID, a key-level DELETE could hide a newer
            // stage. Provider lifecycle or an operational orphan sweep must
            // handle any completed object whose version response was lost.
            tracing::warn!(stage_key=%self.path, "canceled S3 stage has no known version; retaining provider bytes for orphan cleanup");
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
            #[cfg(test)]
            exact_delete_gate: None,
        })
    }

    pub fn with_safety_gate(mut self, gate: Arc<UploadSafetyGate>) -> Self {
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

    fn client_snapshot(&self) -> Arc<S3ClientSnapshot> {
        self.client
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn client(&self) -> Arc<dyn ObjectStore> {
        self.client_snapshot().store.clone()
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
                cleanup_mode: S3CleanupMode::ExactVersion,
                credential_bundle_file: None,
                access_key_id_file: None,
                secret_access_key_file: None,
                session_token_file: None,
                sse_kms_key_id_file: None,
            },
            client: std::sync::RwLock::new(Arc::new(S3ClientSnapshot {
                store: client,
                s3: None,
                delete_http: None,
                region: "test-1".to_owned(),
                cleanup_mode: S3CleanupMode::ExactVersion,
            })),
            credential_generation: AtomicU64::new(0),
            safety_gate: None,
            exact_delete_gate: None,
        }
    }

    #[cfg(test)]
    fn swap_client_for_test(&self, replacement: Arc<dyn ObjectStore>) {
        *self
            .client
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Arc::new(S3ClientSnapshot {
            store: replacement,
            s3: None,
            delete_http: None,
            region: "test-1".to_owned(),
            cleanup_mode: S3CleanupMode::ExactVersion,
        });
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

    async fn delete_expected_version(&self, path: &Path, version: Option<&str>) -> Result<bool> {
        let snapshot = self.client_snapshot();
        let gate = {
            #[cfg(test)]
            {
                self.exact_delete_gate.as_ref()
            }
            #[cfg(not(test))]
            {
                None
            }
        };
        delete_with_snapshot(&snapshot, path, version, gate).await
    }
}

async fn delete_with_snapshot(
    snapshot: &S3ClientSnapshot,
    path: &Path,
    version: Option<&str>,
    gate: Option<&ExactDeleteGate>,
) -> Result<bool> {
    match version {
        Some(version) => delete_exact_version_with_snapshot(snapshot, path, version, gate).await,
        None => delete_qualified_unversioned_with_snapshot(snapshot, path, gate).await,
    }
}

async fn signed_provider_request(
    snapshot: &S3ClientSnapshot,
    method: Method,
    path: &Path,
    query: Option<(&str, &str)>,
    if_match: Option<&str>,
) -> Result<Request<HttpRequestBody>> {
    let s3 = snapshot
        .s3
        .as_ref()
        .context("S3 provider client is unavailable")?;
    let mut url = s3
        .signed_url(method.clone(), path, std::time::Duration::from_secs(60))
        .await?;
    anyhow::ensure!(
        url.query_pairs()
            .all(|(name, _)| name.starts_with("X-Amz-") || name == "x-amz-request-payer"),
        "S3 signer returned an unexpected resource query"
    );
    url.set_query(None);
    if let Some((name, value)) = query {
        url.query_pairs_mut().append_pair(name, value);
    }
    let mut builder = Request::builder().method(method).uri(url.as_str());
    if let Some(etag) = if_match {
        builder = builder.header(axum::http::header::IF_MATCH, etag);
    }
    let mut request = builder.body(HttpRequestBody::empty())?;
    let credential = s3.credentials().get_credential().await?;
    AwsAuthorizer::new(&credential, "s3", &snapshot.region).try_authorize(&mut request, None)?;
    Ok(request)
}

async fn ensure_bucket_never_versioned(snapshot: &S3ClientSnapshot) -> Result<()> {
    anyhow::ensure!(
        snapshot.cleanup_mode == S3CleanupMode::QualifiedUnversioned,
        "S3 key-only cleanup requires qualified-unversioned opt-in"
    );
    let http = snapshot
        .delete_http
        .as_ref()
        .context("S3 bucket versioning probe needs its bounded HTTP transport")?;
    let request = signed_provider_request(
        snapshot,
        Method::GET,
        &Path::default(),
        Some(("versioning", "")),
        None,
    )
    .await?;
    let response = http.execute(request).await?;
    anyhow::ensure!(
        response.status() == StatusCode::OK,
        "S3 bucket versioning state could not be verified: HTTP {}",
        response.status()
    );
    let mut chunks = response.into_body().bytes_stream();
    let mut body = Vec::new();
    while let Some(chunk) = chunks.try_next().await? {
        anyhow::ensure!(
            body.len().saturating_add(chunk.len()) <= 8192,
            "S3 bucket versioning response exceeds the allowed size"
        );
        body.extend_from_slice(&chunk);
    }
    let xml = std::str::from_utf8(&body).context("S3 bucket versioning response is not UTF-8")?;
    let document =
        roxmltree::Document::parse(xml).context("S3 bucket versioning response is not XML")?;
    let root = document.root_element();
    anyhow::ensure!(
        root.tag_name().name() == "VersioningConfiguration"
            && root.tag_name().namespace() == Some("http://s3.amazonaws.com/doc/2006-03-01/")
            && root
                .children()
                .all(|child| child.is_text()
                    && child.text().is_some_and(|text| text.trim().is_empty())),
        "S3 bucket versioning is enabled, suspended, or unverifiable"
    );
    Ok(())
}

fn conditional_delete_canary_path(target: &Path) -> Result<Path> {
    let (parent, _) = target
        .as_ref()
        .rsplit_once('/')
        .context("S3 cleanup target has no attempt component")?;
    let (objects_root, _) = parent
        .rsplit_once('/')
        .context("S3 cleanup target has no object component")?;
    anyhow::ensure!(
        objects_root == "objects" || objects_root.ends_with("/objects"),
        "S3 cleanup target is outside the upload object namespace"
    );
    Path::parse(format!(
        "{objects_root}/{}/{}",
        uuid::Uuid::new_v4(),
        uuid::Uuid::new_v4()
    ))
    .context("could not construct S3 conditional-delete canary key")
}

/// The recovery authority may cancel a Drop cleanup during canary creation.
/// Log the exact key even then; doing provider I/O from Drop would bypass the
/// generation fence that canceled the operation.
struct ConditionalDeleteCanaryGuard {
    key: String,
    armed: bool,
}

impl Drop for ConditionalDeleteCanaryGuard {
    fn drop(&mut self) {
        if self.armed {
            tracing::warn!(canary_key = %self.key, "conditional-delete canary may need operational orphan cleanup");
        }
    }
}

async fn cleanup_conditional_delete_canary(snapshot: &S3ClientSnapshot, path: &Path) -> Result<()> {
    let current = match snapshot.store.head(path).await {
        Ok(current) => current,
        Err(object_store::Error::NotFound { .. }) => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if let Some(version) = current.version.as_deref() {
        anyhow::ensure!(
            !version.eq_ignore_ascii_case("null") && !version.is_empty(),
            "conditional-delete canary has an unsafe null provider version"
        );
        let _ = delete_exact_version_with_snapshot(snapshot, path, version, None).await?;
        return match snapshot.store.head(path).await {
            Err(object_store::Error::NotFound { .. }) => Ok(()),
            Ok(_) => anyhow::bail!("conditional-delete canary remains after exact cleanup"),
            Err(error) => Err(error.into()),
        };
    }
    ensure_bucket_never_versioned(snapshot).await?;
    let etag = current
        .e_tag
        .as_deref()
        .filter(|etag| !etag.is_empty())
        .context("conditional-delete canary has no ETag")?;
    let request = signed_provider_request(snapshot, Method::DELETE, path, None, Some(etag)).await?;
    let http = snapshot
        .delete_http
        .as_ref()
        .context("S3 conditional-delete canary needs its bounded HTTP transport")?;
    let response = http.execute(request).await?;
    anyhow::ensure!(
        response.status() == StatusCode::NO_CONTENT
            && response
                .headers()
                .get("x-amz-delete-marker")
                .is_none_or(|value| !value.as_bytes().eq_ignore_ascii_case(b"true")),
        "conditional-delete canary cleanup failed with HTTP {} or created a marker",
        response.status()
    );
    match snapshot.store.head(path).await {
        Err(object_store::Error::NotFound { .. }) => Ok(()),
        Ok(_) => anyhow::bail!("conditional-delete canary remains visible after cleanup"),
        Err(error) => Err(error.into()),
    }
}

async fn probe_conditional_delete(snapshot: &S3ClientSnapshot, target: &Path) -> Result<()> {
    let canary = conditional_delete_canary_path(target)?;
    let canary_key = canary.to_string();
    let mut guard = ConditionalDeleteCanaryGuard {
        key: canary_key.clone(),
        armed: true,
    };
    let payload = format!(
        "northstar-conditional-delete-canary:{}",
        uuid::Uuid::new_v4()
    );
    let probe = tokio::time::timeout(std::time::Duration::from_secs(20), async {
        let result = snapshot
            .store
            .put_opts(
                &canary,
                payload.as_bytes().to_vec().into(),
                PutMode::Create.into(),
            )
            .await
            .context("could not create an isolated conditional-delete canary")?;
        anyhow::ensure!(
            result.version.is_none(),
            "conditional-delete canary returned a provider version"
        );
        let before = snapshot.store.head(&canary).await?;
        anyhow::ensure!(
            before.version.is_none(),
            "conditional-delete canary HEAD returned a provider version"
        );
        let etag = before
            .e_tag
            .as_deref()
            .filter(|etag| !etag.is_empty())
            .context("conditional-delete canary has no ETag")?;
        let deliberately_wrong = format!("\"northstar-invalid-{}\"", uuid::Uuid::new_v4());
        anyhow::ensure!(
            etag != deliberately_wrong,
            "conditional-delete canary ETag collided"
        );
        let request = signed_provider_request(
            snapshot,
            Method::DELETE,
            &canary,
            None,
            Some(&deliberately_wrong),
        )
        .await?;
        let http = snapshot
            .delete_http
            .as_ref()
            .context("S3 conditional-delete probe needs its bounded HTTP transport")?;
        let response = http.execute(request).await?;
        anyhow::ensure!(
            response.status() == StatusCode::PRECONDITION_FAILED,
            "S3 provider did not enforce conditional DELETE: HTTP {}",
            response.status()
        );
        let after = snapshot.store.head(&canary).await?;
        anyhow::ensure!(
            after.version.is_none() && after.e_tag == before.e_tag,
            "S3 conditional-delete canary changed after rejected DELETE"
        );
        let bytes = snapshot.store.get(&canary).await?.bytes().await?;
        anyhow::ensure!(
            bytes.as_ref() == payload.as_bytes(),
            "S3 conditional-delete canary bytes changed after rejected DELETE"
        );
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("S3 conditional-delete canary probe timed out")
    .and_then(|result| result);

    let cleanup = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        cleanup_conditional_delete_canary(snapshot, &canary),
    )
    .await
    .context("S3 conditional-delete canary cleanup timed out")
    .and_then(|result| result);
    if cleanup.is_ok() {
        guard.armed = false;
    } else if let Err(error) = &cleanup {
        tracing::warn!(canary_key = %canary_key, ?error, "conditional-delete canary cleanup failed");
    }
    if let Err(error) = probe {
        tracing::warn!(canary_key = %canary_key, ?error, "S3 conditional-delete capability probe rejected provider");
        return Err(error);
    }
    cleanup?;
    Ok(())
}

async fn delete_qualified_unversioned_with_snapshot(
    snapshot: &S3ClientSnapshot,
    path: &Path,
    gate: Option<&ExactDeleteGate>,
) -> Result<bool> {
    ensure_bucket_never_versioned(snapshot).await?;
    probe_conditional_delete(snapshot, path).await?;
    let current = match snapshot.store.head(path).await {
        Ok(current) => current,
        Err(object_store::Error::NotFound { .. }) => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    anyhow::ensure!(
        current.version.is_none(),
        "S3 qualified-unversioned object returned a provider version"
    );
    let etag = current
        .e_tag
        .as_deref()
        .filter(|etag| !etag.is_empty())
        .context("S3 qualified-unversioned object has no ETag for conditional deletion")?;
    if let Some((entered, resume)) = gate {
        entered.wait().await;
        resume.wait().await;
    }
    let http = snapshot
        .delete_http
        .as_ref()
        .context("S3 conditional deletion needs its bounded HTTP transport")?;
    let request = signed_provider_request(snapshot, Method::DELETE, path, None, Some(etag)).await?;
    let response = http.execute(request).await?;
    anyhow::ensure!(
        response.status() == StatusCode::NO_CONTENT,
        "S3 conditional unversioned deletion failed with HTTP {}",
        response.status()
    );
    anyhow::ensure!(
        response
            .headers()
            .get("x-amz-delete-marker")
            .is_none_or(|value| !value.as_bytes().eq_ignore_ascii_case(b"true")),
        "S3 conditional unversioned deletion unexpectedly created a marker"
    );
    match snapshot.store.head(path).await {
        Err(object_store::Error::NotFound { .. }) => Ok(true),
        Ok(_) => anyhow::bail!("S3 qualified-unversioned object remains after deletion"),
        Err(error) => Err(error.into()),
    }
}

async fn delete_exact_version_with_snapshot(
    snapshot: &S3ClientSnapshot,
    path: &Path,
    version: &str,
    gate: Option<&ExactDeleteGate>,
) -> Result<bool> {
    anyhow::ensure!(
        !version.is_empty() && !version.eq_ignore_ascii_case("null"),
        "S3 cleanup requires a non-null exact object version"
    );
    let s3 = snapshot
        .s3
        .as_ref()
        .context("S3 exact-version deletion needs the provider client")?;
    let delete_http = snapshot
        .delete_http
        .as_ref()
        .context("S3 exact-version deletion needs its bounded HTTP transport")?;
    let mut head_options = GetOptions::new().with_version(Some(version.to_owned()));
    head_options.head = true;
    let before_version = match snapshot.store.get_opts(path, head_options.clone()).await {
        Ok(result) => result.meta.version,
        Err(object_store::Error::NotFound { .. }) => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    anyhow::ensure!(
        before_version.as_deref() == Some(version),
        "S3 provider did not identify the requested cleanup version"
    );

    if let Some((entered, resume)) = gate {
        entered.wait().await;
        resume.wait().await;
    }

    // object_store 0.14.1 exposes exact-version GET but only key-level
    // DELETE. Its public signer supplies the same client's canonical
    // endpoint and encoded path; discard the *entire* presign query, add
    // only versionId, then use its public SigV4 authorizer for this request.
    let mut url = s3
        .signed_url(Method::DELETE, path, std::time::Duration::from_secs(60))
        .await?;
    anyhow::ensure!(
        url.query_pairs()
            .all(|(name, _)| name.starts_with("X-Amz-") || name == "x-amz-request-payer"),
        "S3 signer returned an unexpected resource query"
    );
    url.set_query(None);
    url.query_pairs_mut().append_pair("versionId", version);
    let mut request = Request::builder()
        .method(Method::DELETE)
        .uri(url.as_str())
        .body(HttpRequestBody::empty())?;
    let credential = s3.credentials().get_credential().await?;
    AwsAuthorizer::new(&credential, "s3", &snapshot.region).try_authorize(&mut request, None)?;
    let response = delete_http.execute(request).await?;
    anyhow::ensure!(
        response.status() == StatusCode::NO_CONTENT,
        "S3 exact-version deletion failed with HTTP {}",
        response.status()
    );
    anyhow::ensure!(
        response
            .headers()
            .get("x-amz-delete-marker")
            .is_none_or(|value| value.as_bytes() != b"true"),
        "S3 cleanup unexpectedly deleted a marker"
    );
    match snapshot.store.get_opts(path, head_options).await {
        Err(object_store::Error::NotFound { .. }) => Ok(true),
        Ok(_) => anyhow::bail!("S3 exact object version remains after deletion"),
        Err(error) => Err(error.into()),
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
            let cleanup_authority = self.cleanup_authority()?;
            let snapshot = self.client_snapshot();
            let client = Arc::clone(&snapshot.store);
            let upload = client
                .put_multipart(&path)
                .await
                .context("could not initiate multipart upload stage")?;
            let mut temporary = RemoteTemporaryObject::new(path.clone());
            let mut writer = WriteMultipart::new(upload);
            let mut bytes_written = 0_u64;
            let mut digest = Sha256::new();
            let mut buffer = BytesMut::zeroed(128 * 1024);
            loop {
                let read = match stream.read(&mut buffer[..]).await {
                    Ok(read) => read,
                    Err(error) => {
                        if writer.abort().await.is_ok() {
                            temporary.commit();
                        }
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
                    if writer.abort().await.is_ok() {
                        temporary.commit();
                    }
                    return Ok(StagedUpload::new(
                        bytes_written,
                        None,
                        stage_key,
                        object_key,
                        None,
                        None,
                    ));
                }
                writer.wait_for_capacity(4).await?;
                writer.write(&buffer[..read]);
                digest.update(&buffer[..read]);
            }
            if bytes_written != max_size {
                if writer.abort().await.is_ok() {
                    temporary.commit();
                }
                return Ok(StagedUpload::new(
                    bytes_written,
                    None,
                    stage_key,
                    object_key,
                    None,
                    None,
                ));
            }
            let result = writer
                .finish()
                .await
                .context("could not complete multipart upload stage")?;
            temporary.commit();
            let version = result.version;
            let mut staged = StagedUpload::new(
                bytes_written,
                Some(digest.finalize().into()),
                stage_key,
                object_key,
                version.clone(),
                Some(Box::new(RemoteS3Cleanup {
                    snapshot,
                    path,
                    version,
                })),
            );
            if let Some((gate, generation)) = cleanup_authority {
                staged.bind_cleanup_authority(gate, generation);
            }
            Ok(staged)
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
            self.delete_expected_version(&path, stage_version).await
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
            self.delete_expected_version(&path, object_version).await
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

fn build_client(settings: &S3UploadSettings) -> Result<(Arc<S3ClientSnapshot>, u64)> {
    // Start from a clean builder. `from_env` also accepts explicit endpoint,
    // proxy, unsigned-payload and HTTP overrides outside this configuration.
    // Copy only credential-provider inputs with bounded semantics; absent
    // inputs deliberately fall back to IMDSv2 (never v1). Reqwest may still
    // honor the process's system proxy environment in both S3 transports.
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
        let bundle_json = Zeroizing::new(northstar_security::secret_files::read_secret_file(
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
                let mut access =
                    Zeroizing::new(northstar_security::secret_files::read_secret_file(
                        access_file,
                        "UPLOAD_S3_ACCESS_KEY_ID_FILE",
                    )?);
                let mut secret =
                    Zeroizing::new(northstar_security::secret_files::read_secret_file(
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
            let mut token = Zeroizing::new(northstar_security::secret_files::read_secret_file(
                token_file,
                "UPLOAD_S3_SESSION_TOKEN_FILE",
            )?);
            builder = builder.with_token(token.as_str());
            token.zeroize();
        }
    }
    if let Some(kms_file) = settings.sse_kms_key_id_file.as_deref() {
        let mut kms_key = Zeroizing::new(northstar_security::secret_files::read_secret_file(
            kms_file,
            "UPLOAD_S3_SSE_KMS_KEY_ID_FILE",
        )?);
        builder = builder.with_sse_kms_encryption(kms_key.as_str());
        kms_key.zeroize();
    }
    let s3 = Arc::new(
        builder
            .build()
            .context("could not build S3 upload client")?,
    );
    let delete_http = ReqwestConnector::default().connect(
        &ClientOptions::new()
            .with_allow_http(settings.allow_http)
            .with_connect_timeout(std::time::Duration::from_secs(5))
            .with_timeout(std::time::Duration::from_secs(30)),
    )?;
    Ok((
        Arc::new(S3ClientSnapshot {
            store: s3.clone(),
            s3: Some(s3),
            delete_http: Some(delete_http),
            region: settings.region.clone(),
            cleanup_mode: settings.cleanup_mode,
        }),
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
mod tests;
