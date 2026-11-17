//! Upload backend settings and store selection from the server configuration.

use std::sync::Arc;

use anyhow::Context;
use northstar_config::{Config, RawConfig};
use northstar_upload_application::safety::UploadSafetyGate;
use northstar_upload_application::startup::{reconcile_abandoned_stages, UploadStartupRepository};
use northstar_upload_application::store::{GuardedUploadStore, UploadStore};

use crate::{LocalUploadStore, S3CleanupMode, S3UploadSettings, S3UploadStore};

pub fn s3_settings(config: &Config) -> anyhow::Result<S3UploadSettings> {
    s3_settings_from_raw(config)
}

fn s3_settings_from_raw(config: &RawConfig) -> anyhow::Result<S3UploadSettings> {
    Ok(S3UploadSettings {
        endpoint: config.upload_s3_endpoint.clone(),
        region: config.upload_s3_region.clone(),
        bucket: config
            .upload_s3_bucket
            .clone()
            .context("S3 upload bucket is missing after validation")?,
        prefix: config.upload_s3_prefix.clone(),
        path_style: config.upload_s3_path_style,
        allow_http: config.upload_s3_allow_http,
        ambient_credentials: config.upload_s3_credential_mode == "ambient",
        cleanup_mode: S3CleanupMode::parse(&config.upload_s3_cleanup_mode)?,
        credential_bundle_file: config.upload_s3_credential_bundle_file.clone(),
        access_key_id_file: config.upload_s3_access_key_id_file.clone(),
        secret_access_key_file: config.upload_s3_secret_access_key_file.clone(),
        session_token_file: config.upload_s3_session_token_file.clone(),
        sse_kms_key_id_file: config.upload_s3_sse_kms_key_id_file.clone(),
    })
}

/// Stable, non-secret identity for the physical upload namespace shared by
/// every node. PostgreSQL stores this digest so a node configured for a
/// different bucket/prefix cannot serve or delete another node's objects.
/// Credential material is deliberately excluded: rotating credentials must
/// not change storage authority.
pub fn namespace_id_from_config(config: &Config) -> anyhow::Result<[u8; 32]> {
    namespace_id_from_raw(config)
}

fn namespace_id_from_raw(config: &RawConfig) -> anyhow::Result<[u8; 32]> {
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
                cleanup_mode: S3CleanupMode::parse(&config.upload_s3_cleanup_mode)?,
                credential_bundle_file: config.upload_s3_credential_bundle_file.clone(),
                access_key_id_file: config.upload_s3_access_key_id_file.clone(),
                secret_access_key_file: config.upload_s3_secret_access_key_file.clone(),
                session_token_file: config.upload_s3_session_token_file.clone(),
                sse_kms_key_id_file: config.upload_s3_sse_kms_key_id_file.clone(),
            })
        })
        .transpose()?;
    crate::upload_storage_namespace_id(
        &config.upload_storage_backend,
        &config.upload_dir,
        s3.as_ref(),
    )
}

pub async fn start_upload_store<R: UploadStartupRepository>(
    config: &Config,
    startup: &R,
    gate: &Arc<UploadSafetyGate>,
) -> anyhow::Result<Arc<dyn UploadStore>> {
    let upload_store: Arc<dyn UploadStore> = match config.upload_storage_backend.as_str() {
        "local" => {
            let local = Arc::new(
                LocalUploadStore::new(config.upload_dir.clone()).with_safety_gate(Arc::clone(gate)),
            );
            let guarded = Arc::new(GuardedUploadStore::new(local.clone(), Arc::clone(gate)));
            reconcile_abandoned_stages(startup, guarded.as_ref(), local.staging_attempts()).await?;
            guarded
        }
        "s3" => {
            let inner: Arc<dyn UploadStore> = Arc::new(
                S3UploadStore::new(s3_settings(config)?)?.with_safety_gate(Arc::clone(gate)),
            );
            Arc::new(GuardedUploadStore::new(inner, Arc::clone(gate)))
        }
        _ => unreachable!("upload backend was validated by Config"),
    };
    Ok(upload_store)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> RawConfig {
        serde_json::from_str("{}").expect("RawConfig defaults must deserialize")
    }

    #[test]
    fn s3_settings_requires_a_bucket() {
        let mut config = config();
        config.upload_s3_bucket = None;
        assert_eq!(
            s3_settings_from_raw(&config).unwrap_err().to_string(),
            "S3 upload bucket is missing after validation"
        );
        config.upload_s3_bucket = Some("uploads".to_owned());
        assert_eq!(s3_settings_from_raw(&config).unwrap().bucket, "uploads");
    }

    #[test]
    fn namespace_id_ignores_credentials() {
        let mut config = config();
        config.upload_storage_backend = "s3".to_owned();
        config.upload_s3_bucket = Some("uploads".to_owned());
        let original = namespace_id_from_raw(&config).unwrap();
        config.upload_s3_credential_mode = "ambient".to_owned();
        config.upload_s3_credential_bundle_file = Some("rotated-bundle".into());
        config.upload_s3_access_key_id_file = Some("rotated-access-key".into());
        config.upload_s3_secret_access_key_file = Some("rotated-secret-key".into());
        config.upload_s3_session_token_file = Some("rotated-session-token".into());
        assert_eq!(namespace_id_from_raw(&config).unwrap(), original);
        config.upload_s3_prefix.push_str("/other");
        assert_ne!(namespace_id_from_raw(&config).unwrap(), original);
    }

    #[test]
    fn namespace_id_allows_a_missing_bucket_but_returns_cleanup_mode_errors() {
        let mut config = config();
        config.upload_storage_backend = "s3".to_owned();
        config.upload_s3_bucket = None;
        assert!(namespace_id_from_raw(&config).is_ok());
        config.upload_s3_cleanup_mode = "invalid".to_owned();
        assert_eq!(
            namespace_id_from_raw(&config).unwrap_err().to_string(),
            "UPLOAD_S3_CLEANUP_MODE must be exact-version or qualified-unversioned"
        );
    }
}
