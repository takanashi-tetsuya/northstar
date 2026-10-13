//! Upload storage namespace, request admission and storage runtime selection.

use super::*;

/// Stable, non-secret identity for the physical upload namespace shared by
/// every node. PostgreSQL stores this digest so a node configured for a
/// different bucket/prefix cannot serve or delete another node's objects.
/// Credential material is deliberately excluded: rotating credentials must
/// not change storage authority.
pub(super) fn upload_storage_namespace_id(config: &Config) -> anyhow::Result<[u8; 32]> {
    let s3 = (config.upload_storage_backend == "s3")
        .then(|| -> anyhow::Result<S3UploadSettings> {
            Ok(S3UploadSettings {
                endpoint: config.upload_s3_endpoint.clone(),
                region: config.upload_s3_region.clone(),
                bucket: config.upload_s3_bucket.clone().unwrap_or_default(),
                prefix: config.upload_s3_prefix.clone(),
                path_style: config.upload_s3_path_style,
                allow_http: config.upload_s3_allow_http,
                ambient_credentials: config.upload_s3_credential_mode == "ambient",
                cleanup_mode: crate::storage::S3CleanupMode::parse(&config.upload_s3_cleanup_mode)?,
                credential_bundle_file: config.upload_s3_credential_bundle_file.clone(),
                access_key_id_file: config.upload_s3_access_key_id_file.clone(),
                secret_access_key_file: config.upload_s3_secret_access_key_file.clone(),
                session_token_file: config.upload_s3_session_token_file.clone(),
                sse_kms_key_id_file: config.upload_s3_sse_kms_key_id_file.clone(),
            })
        })
        .transpose()?;
    crate::storage::upload_storage_namespace_id(
        &config.upload_storage_backend,
        &config.upload_dir,
        s3.as_ref(),
    )
}

#[derive(Clone)]
pub(super) struct UploadAdmission {
    pub(super) semaphore: Arc<Semaphore>,
    pub(super) by_ip: Arc<DashMap<std::net::IpAddr, usize>>,
    pub(super) max_per_ip: usize,
}

impl UploadAdmission {
    pub(super) fn try_acquire_download(&self, ip: std::net::IpAddr) -> Option<UploadDownloadGuard> {
        let permit = Arc::clone(&self.semaphore).try_acquire_owned().ok()?;
        let mut count = self.by_ip.entry(ip).or_insert(0);
        if *count >= self.max_per_ip {
            let remove_zero = *count == 0;
            drop(count);
            if remove_zero {
                self.by_ip.remove(&ip);
            }
            return None;
        }
        *count += 1;
        drop(count);
        Some(UploadDownloadGuard {
            counts: Arc::clone(&self.by_ip),
            ip,
            _permit: permit,
        })
    }
}

pub(super) enum UploadRuntime {
    Enabled {
        requests: UploadAdmission,
        downloads: UploadAdmission,
    },
    DrainReadOnly {
        downloads: UploadAdmission,
    },
    Disabled,
}

impl UploadRuntime {
    pub(super) fn from_config(config: &crate::platform::config::Config) -> Self {
        let downloads = || UploadAdmission {
            semaphore: Arc::new(Semaphore::new(config.upload_download_max_concurrent)),
            by_ip: Arc::new(DashMap::new()),
            max_per_ip: config.upload_download_max_per_ip,
        };
        match config.upload_mode {
            crate::platform::config::UploadMode::Enabled => Self::Enabled {
                requests: UploadAdmission {
                    semaphore: Arc::new(Semaphore::new(32)),
                    by_ip: Arc::new(DashMap::new()),
                    max_per_ip: 4,
                },
                downloads: downloads(),
            },
            crate::platform::config::UploadMode::DrainReadOnly => Self::DrainReadOnly {
                downloads: downloads(),
            },
            crate::platform::config::UploadMode::Disabled => Self::Disabled,
        }
    }

    pub(super) fn request_admission(&self) -> Option<&UploadAdmission> {
        match self {
            Self::Enabled { requests, .. } => Some(requests),
            Self::DrainReadOnly { .. } | Self::Disabled => None,
        }
    }

    pub(super) fn download_admission(&self) -> Option<&UploadAdmission> {
        match self {
            Self::Enabled { downloads, .. } | Self::DrainReadOnly { downloads } => Some(downloads),
            Self::Disabled => None,
        }
    }
}
