//! Loading the validated configuration from the environment (Config::from_env).

use super::*;

impl Config {
    pub fn from_env() -> Result<Self> {
        // `envy` applies serde defaults before exposing whether an environment
        // variable was supplied. Retain that fact so test activation replaces
        // only inherited production listener defaults.
        let test_listener_bind_explicitness = TestListenerBindExplicitness::from_environment();
        let mut raw: RawConfig =
            envy::from_env().context("Failed to parse config from environment")?;
        apply_test_listener_defaults(&mut raw, test_listener_bind_explicitness);
        let xmpp_extensions = Arc::new(crate::platform::extensions::ExtensionRuntime::resolve(
            crate::platform::extensions::ExtensionSwitches {
                xep_0016: raw.xep_0016_enabled,
                xep_0045: raw.xep_0045_enabled,
                xep_0059: raw.xep_0059_enabled,
                xep_0085: raw.xep_0085_enabled,
                xep_0092: raw.xep_0092_enabled,
                xep_0115: raw.xep_0115_enabled,
                xep_0060: raw.xep_0060_enabled,
                xep_0184: raw.xep_0184_enabled,
                xep_0191: raw.xep_0191_enabled,
                xep_0198: raw.xep_0198_enabled,
                xep_0199: raw.xep_0199_enabled,
                xep_0202: raw.xep_0202_enabled,
                xep_0215: raw.xep_0215_enabled,
                xep_0280: raw.xep_0280_enabled,
                xep_0313: raw.xep_0313_enabled,
                xep_0352: raw.xep_0352_enabled,
                xep_0357: raw.xep_0357_enabled,
                xep_0359: raw.xep_0359_enabled,
                xep_0363: raw.xep_0363_enabled,
                xep_0308: raw.xep_0308_enabled,
                xep_0333: raw.xep_0333_enabled,
                xep_0380: raw.xep_0380_enabled,
                xep_0444: raw.xep_0444_enabled,
                xep_0461: raw.xep_0461_enabled,
            },
        ));
        let web_capabilities = Arc::new(resolve_web_capability_plan(&raw)?);
        let invitation_policy_disabled_with_web_client = matches!(
            web_capabilities.registration.lock,
            RegistrationDependencyLock::LockedWebClientDisabled
        );
        raw.open_registration = !web_capabilities.registration.mode.is_closed();
        raw.invitation_required = web_capabilities.registration.mode.is_invitation_only();
        raw.upload_mode = web_capabilities.upload_mode;
        raw.database_url_file = non_empty_path(raw.database_url_file.take());
        if let Some(path) = &raw.database_url_file {
            if !raw.database_url.trim().is_empty() {
                anyhow::bail!("set only one of DATABASE_URL and DATABASE_URL_FILE");
            }
            raw.database_url = read_secret_file(path, "DATABASE_URL_FILE")?;
        }
        raw.admin_command_database_url_file =
            non_empty_path(raw.admin_command_database_url_file.take());
        if let Some(path) = &raw.admin_command_database_url_file {
            if !raw.admin_command_database_url.trim().is_empty() {
                anyhow::bail!(
                    "set only one of ADMIN_COMMAND_DATABASE_URL and ADMIN_COMMAND_DATABASE_URL_FILE"
                );
            }
            raw.admin_command_database_url =
                read_secret_file(path, "ADMIN_COMMAND_DATABASE_URL_FILE")?;
        }
        raw.storage_database_url_file = non_empty_path(raw.storage_database_url_file.take());
        if let Some(path) = &raw.storage_database_url_file {
            if !raw.storage_database_url.trim().is_empty() {
                anyhow::bail!("set only one of STORAGE_DATABASE_URL and STORAGE_DATABASE_URL_FILE");
            }
            raw.storage_database_url = read_secret_file(path, "STORAGE_DATABASE_URL_FILE")?;
        }
        raw.bootstrap_admin_username = raw
            .bootstrap_admin_username
            .take()
            .filter(|value| !value.trim().is_empty());
        raw.bootstrap_admin_password = raw
            .bootstrap_admin_password
            .take()
            .filter(|value| !value.is_empty());
        raw.bootstrap_admin_password_file =
            non_empty_path(raw.bootstrap_admin_password_file.take());
        if let Some(path) = &raw.bootstrap_admin_password_file {
            if raw.bootstrap_admin_password.is_some() {
                anyhow::bail!(
                    "set only one of BOOTSTRAP_ADMIN_PASSWORD and BOOTSTRAP_ADMIN_PASSWORD_FILE"
                );
            }
            raw.bootstrap_admin_password =
                Some(read_secret_file(path, "BOOTSTRAP_ADMIN_PASSWORD_FILE")?);
        }
        raw.turn_shared_secret = raw
            .turn_shared_secret
            .take()
            .filter(|value| !value.is_empty());
        raw.turn_shared_secret_file = non_empty_path(raw.turn_shared_secret_file.take());
        if let Some(path) = &raw.turn_shared_secret_file {
            if raw.turn_shared_secret.is_some() {
                anyhow::bail!("set only one of TURN_SHARED_SECRET and TURN_SHARED_SECRET_FILE");
            }
            raw.turn_shared_secret = Some(read_secret_file(path, "TURN_SHARED_SECRET_FILE")?);
        }
        raw.dialback_secret = raw.dialback_secret.take().filter(|value| !value.is_empty());
        raw.dialback_secret_file = non_empty_path(raw.dialback_secret_file.take());
        if let Some(path) = &raw.dialback_secret_file {
            if raw.dialback_secret.is_some() {
                anyhow::bail!("set only one of DIALBACK_SECRET and DIALBACK_SECRET_FILE");
            }
            raw.dialback_secret = Some(read_secret_file(path, "DIALBACK_SECRET_FILE")?);
        }
        raw.fast_token_secret = raw
            .fast_token_secret
            .take()
            .filter(|value| !value.is_empty());
        raw.fast_token_secret_file = non_empty_path(raw.fast_token_secret_file.take());
        if let Some(path) = &raw.fast_token_secret_file {
            if raw.fast_token_secret.is_some() {
                anyhow::bail!("set only one of FAST_TOKEN_SECRET and FAST_TOKEN_SECRET_FILE");
            }
            raw.fast_token_secret = Some(read_secret_file(path, "FAST_TOKEN_SECRET_FILE")?);
        }
        raw.dummy_scram_secret_file = non_empty_path(raw.dummy_scram_secret_file.take());
        let dummy_scram_secret = raw
            .dummy_scram_secret_file
            .as_deref()
            .map(|path| read_secret_file(path, "DUMMY_SCRAM_SECRET_FILE"))
            .transpose()?
            .map(Zeroizing::new);
        raw.abuse_state_hmac_key = raw
            .abuse_state_hmac_key
            .take()
            .filter(|value| !value.is_empty());
        raw.abuse_state_hmac_key_file = non_empty_path(raw.abuse_state_hmac_key_file.take());
        if let Some(path) = &raw.abuse_state_hmac_key_file {
            if raw.abuse_state_hmac_key.is_some() {
                anyhow::bail!("set only one of ABUSE_STATE_HMAC_KEY or ABUSE_STATE_HMAC_KEY_FILE");
            }
            raw.abuse_state_hmac_key = Some(read_secret_file(path, "ABUSE_STATE_HMAC_KEY_FILE")?);
        }
        raw.abuse_state_hmac_previous_key = raw
            .abuse_state_hmac_previous_key
            .take()
            .filter(|value| !value.is_empty());
        raw.abuse_state_hmac_previous_key_file =
            non_empty_path(raw.abuse_state_hmac_previous_key_file.take());
        if let Some(path) = &raw.abuse_state_hmac_previous_key_file {
            if raw.abuse_state_hmac_previous_key.is_some() {
                anyhow::bail!("set only one of ABUSE_STATE_HMAC_PREVIOUS_KEY or ABUSE_STATE_HMAC_PREVIOUS_KEY_FILE");
            }
            raw.abuse_state_hmac_previous_key = Some(read_secret_file(
                path,
                "ABUSE_STATE_HMAC_PREVIOUS_KEY_FILE",
            )?);
        }
        raw.api_control_secret_file = non_empty_path(raw.api_control_secret_file.take());
        raw.api_control_previous_secret_file =
            non_empty_path(raw.api_control_previous_secret_file.take());
        let api_control_secret = raw
            .api_control_secret_file
            .as_ref()
            .map(|path| read_secret_file(path, "API_CONTROL_SECRET_FILE"))
            .transpose()?;
        let api_control_previous_secret = raw
            .api_control_previous_secret_file
            .as_ref()
            .map(|path| read_secret_file(path, "API_CONTROL_PREVIOUS_SECRET_FILE"))
            .transpose()?;
        raw.metrics_bearer_token_file = non_empty_path(raw.metrics_bearer_token_file.take());
        let metrics_bearer_token = raw
            .metrics_bearer_token_file
            .as_ref()
            .map(|path| read_secret_file(path, "METRICS_BEARER_TOKEN_FILE"))
            .transpose()?;
        if metrics_bearer_token
            .as_ref()
            .is_some_and(|token| !valid_http_bearer_secret(token))
        {
            anyhow::bail!(
                "METRICS_BEARER_TOKEN_FILE must contain 32 to 4096 visible ASCII bytes without whitespace"
            );
        }
        if !raw.metrics_bind.ip().is_loopback() && metrics_bearer_token.is_none() {
            anyhow::bail!("a non-loopback METRICS_BIND requires METRICS_BEARER_TOKEN_FILE");
        }
        raw.web_admin_gateway_token_file = non_empty_path(raw.web_admin_gateway_token_file.take());
        let web_admin_gateway_token = if raw.web_admin_enabled {
            raw.web_admin_gateway_token_file
                .as_ref()
                .map(|path| read_secret_file(path, "WEB_ADMIN_GATEWAY_TOKEN_FILE"))
                .transpose()?
        } else {
            // A disabled capability owns no key material and performs no
            // filesystem I/O.  This also permits staged secret rotation while
            // the administration surface is intentionally off.
            None
        };
        if web_admin_gateway_token
            .as_ref()
            .is_some_and(|token| !valid_http_bearer_secret(token))
        {
            anyhow::bail!(
                "WEB_ADMIN_GATEWAY_TOKEN_FILE must contain 32 to 4096 visible ASCII bytes without whitespace"
            );
        }
        if let Some(gateway) = web_admin_gateway_token.as_deref() {
            for (name, other) in [
                ("METRICS_BEARER_TOKEN_FILE", metrics_bearer_token.as_deref()),
                ("API_CONTROL_SECRET_FILE", api_control_secret.as_deref()),
                (
                    "API_CONTROL_PREVIOUS_SECRET_FILE",
                    api_control_previous_secret.as_deref(),
                ),
                ("FAST_TOKEN_SECRET_FILE", raw.fast_token_secret.as_deref()),
                ("DIALBACK_SECRET_FILE", raw.dialback_secret.as_deref()),
                ("TURN_SHARED_SECRET_FILE", raw.turn_shared_secret.as_deref()),
                (
                    "ABUSE_STATE_HMAC_KEY_FILE",
                    raw.abuse_state_hmac_key.as_deref(),
                ),
                (
                    "ABUSE_STATE_HMAC_PREVIOUS_KEY_FILE",
                    raw.abuse_state_hmac_previous_key.as_deref(),
                ),
                (
                    "BOOTSTRAP_ADMIN_PASSWORD_FILE",
                    raw.bootstrap_admin_password.as_deref(),
                ),
            ] {
                if other.is_some_and(|other| {
                    crate::auth::constant_time_bytes_eq(gateway.as_bytes(), other.as_bytes())
                }) {
                    anyhow::bail!(
                        "WEB_ADMIN_GATEWAY_TOKEN_FILE must not reuse {name} key material"
                    );
                }
            }
        }
        raw.public_url = raw
            .public_url
            .take()
            .filter(|value| !value.trim().is_empty());
        raw.redis_url_file = non_empty_path(raw.redis_url_file.take());
        if let Some(path) = &raw.redis_url_file {
            if raw
                .redis_url
                .as_ref()
                .is_some_and(|value| !value.trim().is_empty())
            {
                anyhow::bail!("set only one of REDIS_URL and REDIS_URL_FILE");
            }
            raw.redis_url = Some(read_secret_file(path, "REDIS_URL_FILE")?);
        }
        raw.redis_url = raw
            .redis_url
            .take()
            .filter(|value| !value.trim().is_empty());
        raw.redis_tls_ca_cert_path = non_empty_path(raw.redis_tls_ca_cert_path.take());
        raw.redis_tls_client_cert_path = non_empty_path(raw.redis_tls_client_cert_path.take());
        raw.redis_tls_client_key_path = non_empty_path(raw.redis_tls_client_key_path.take());
        raw.cluster_signing_private_key_file =
            non_empty_path(raw.cluster_signing_private_key_file.take());
        raw.cluster_signing_previous_public_key_file =
            non_empty_path(raw.cluster_signing_previous_public_key_file.take());
        raw.cluster_signing_staged_next_public_key_file =
            non_empty_path(raw.cluster_signing_staged_next_public_key_file.take());
        raw.cluster_peer_keys_file = non_empty_path(raw.cluster_peer_keys_file.take());
        validate_redis_transport(
            raw.redis_url.as_deref(),
            raw.redis_tls_ca_cert_path.as_deref(),
            raw.redis_tls_client_cert_path.as_deref(),
            raw.redis_tls_client_key_path.as_deref(),
        )?;
        raw.federation_extra_root_cert_path = raw
            .federation_extra_root_cert_path
            .take()
            .filter(|path| !path.as_os_str().is_empty());
        raw.federation_crl_path = non_empty_path(raw.federation_crl_path.take());
        raw.tls_ocsp_response_path = non_empty_path(raw.tls_ocsp_response_path.take());
        raw.c2s_client_trust_root_cert_path = raw
            .c2s_client_trust_root_cert_path
            .take()
            .filter(|path| !path.as_os_str().is_empty());
        raw.c2s_client_crl_path = non_empty_path(raw.c2s_client_crl_path.take());
        raw.components_config_file = non_empty_path(raw.components_config_file.take());
        raw.upload_s3_access_key_id_file = non_empty_path(raw.upload_s3_access_key_id_file.take());
        raw.upload_s3_credential_bundle_file =
            non_empty_path(raw.upload_s3_credential_bundle_file.take());
        raw.upload_s3_secret_access_key_file =
            non_empty_path(raw.upload_s3_secret_access_key_file.take());
        raw.upload_s3_session_token_file = non_empty_path(raw.upload_s3_session_token_file.take());
        raw.upload_s3_sse_kms_key_id_file =
            non_empty_path(raw.upload_s3_sse_kms_key_id_file.take());
        raw.upload_s3_endpoint = raw
            .upload_s3_endpoint
            .take()
            .filter(|value| !value.trim().is_empty());
        raw.upload_s3_bucket = raw
            .upload_s3_bucket
            .take()
            .filter(|value| !value.trim().is_empty());

        let domain = crate::jid::prepare_domainpart(raw.xmpp_domain.trim())
            .context("XMPP_DOMAIN is invalid")?;
        let cluster_fields_present = raw
            .cluster_node_id
            .as_ref()
            .is_some_and(|v| !v.trim().is_empty())
            || raw.cluster_signing_private_key_file.is_some()
            || raw.cluster_signing_previous_public_key_file.is_some()
            || raw.cluster_signing_staged_next_public_key_file.is_some()
            || raw.cluster_peer_keys_file.is_some();
        if raw.redis_url.is_none() && cluster_fields_present {
            anyhow::bail!("cluster signing configuration requires REDIS_URL or REDIS_URL_FILE");
        }
        let cluster_security = raw
            .redis_url
            .as_ref()
            .map(|_| {
                crate::cluster::security::load_configuration(
                    crate::cluster::security::ClusterSecurityConfiguration {
                        namespace: &domain,
                        node_id: raw
                            .cluster_node_id
                            .as_deref()
                            .map(str::trim)
                            .filter(|v| !v.is_empty()),
                        private_key_file: raw.cluster_signing_private_key_file.as_deref(),
                        previous_public_key_file: raw
                            .cluster_signing_previous_public_key_file
                            .as_deref(),
                        staged_next_public_key_file: raw
                            .cluster_signing_staged_next_public_key_file
                            .as_deref(),
                        peer_keys_file: raw.cluster_peer_keys_file.as_deref(),
                        key_epoch: raw.cluster_signing_key_epoch,
                        failure_policy: &raw.cluster_failure_policy,
                        safety_lease_seconds: raw.cluster_safety_lease_seconds,
                    },
                )
            })
            .transpose()?;
        let listeners_are_loopback = [
            raw.xmpp_bind,
            raw.xmpps_bind,
            raw.http_bind,
            raw.metrics_bind,
            raw.s2s_bind,
            raw.s2s_tls_bind,
            raw.component_bind,
        ]
        .iter()
        .all(|address| address.ip().is_loopback())
            && (!raw.web_admin_enabled || raw.web_admin_bind.ip().is_loopback());
        let reserved_development_domain =
            domain == "localhost" || domain.ends_with(".localhost") || domain.ends_with(".test");
        validate_test_listener_activation(
            &raw,
            listeners_are_loopback,
            reserved_development_domain,
        )?;
        let development_redis_is_local = redis_endpoint_is_local(raw.redis_url.as_deref())?;
        let ephemeral_abuse_state_is_allowed = raw.abuse_state_allow_ephemeral
            && raw.redis_url.is_none()
            && listeners_are_loopback
            && reserved_development_domain;
        let ephemeral_fast_is_allowed = ephemeral_development_secret_allowed(
            raw.fast_token_allow_ephemeral_for_development,
            raw.redis_url.is_some(),
            listeners_are_loopback,
            reserved_development_domain,
        );
        let ephemeral_dummy_scram_is_allowed = ephemeral_development_secret_allowed(
            raw.dummy_scram_allow_ephemeral_for_development,
            raw.redis_url.is_some(),
            listeners_are_loopback,
            reserved_development_domain,
        );
        if raw.fast_token_allow_ephemeral_for_development && !ephemeral_fast_is_allowed {
            anyhow::bail!(
                "FAST_TOKEN_ALLOW_EPHEMERAL_FOR_DEVELOPMENT is allowed only for a single-node loopback reserved-domain deployment"
            );
        }
        if !ephemeral_fast_is_allowed && raw.fast_token_secret_file.is_none() {
            anyhow::bail!(
                "production FAST requires FAST_TOKEN_SECRET_FILE; inline or process-local keys are permitted only by explicit loopback development opt-in"
            );
        }
        if raw.dummy_scram_allow_ephemeral_for_development && !ephemeral_dummy_scram_is_allowed {
            anyhow::bail!(
                "DUMMY_SCRAM_ALLOW_EPHEMERAL_FOR_DEVELOPMENT is allowed only for a single-node loopback reserved-domain deployment"
            );
        }
        if !ephemeral_dummy_scram_is_allowed && raw.dummy_scram_secret_file.is_none() {
            anyhow::bail!(
                "production dummy SCRAM requires DUMMY_SCRAM_SECRET_FILE; process-local keys are permitted only by explicit loopback development opt-in"
            );
        }
        if raw.database_allow_unsafe_role_for_development
            && !(development_redis_is_local
                && listeners_are_loopback
                && reserved_development_domain)
        {
            anyhow::bail!(
                "DATABASE_ALLOW_UNSAFE_ROLE_FOR_DEVELOPMENT is allowed only for a loopback reserved-domain deployment with absent or loopback Redis"
            );
        }
        let admin_command_pool_mode = resolve_admin_command_pool_mode(
            raw.database_allow_unsafe_role_for_development,
            &raw.admin_command_database_url,
        )?;
        let storage_pool_mode = resolve_storage_pool_mode(
            raw.database_allow_unsafe_role_for_development,
            raw.upload_mode.keeps_storage_runtime(),
            &raw.storage_database_url,
        )?;
        raw.upload_storage_backend = raw.upload_storage_backend.trim().to_ascii_lowercase();
        raw.upload_s3_credential_mode = raw.upload_s3_credential_mode.trim().to_ascii_lowercase();
        raw.upload_s3_cleanup_mode = raw.upload_s3_cleanup_mode.trim().to_ascii_lowercase();
        raw.upload_s3_region = raw.upload_s3_region.trim().to_owned();
        raw.upload_s3_prefix = raw.upload_s3_prefix.trim().trim_matches('/').to_owned();
        if raw.upload_mode.keeps_storage_runtime() {
            if !matches!(raw.upload_storage_backend.as_str(), "local" | "s3") {
                anyhow::bail!("UPLOAD_STORAGE_BACKEND must be local or s3");
            }
            if raw.redis_url.is_some()
                && raw.upload_storage_backend != "s3"
                && !(listeners_are_loopback
                    && (domain == "localhost"
                        || domain.ends_with(".localhost")
                        || domain.ends_with(".test")))
            {
                anyhow::bail!(
                    "public Redis cluster mode requires shared UPLOAD_STORAGE_BACKEND=s3"
                );
            }
            if raw.upload_storage_backend == "s3" {
                if !matches!(
                    raw.upload_s3_cleanup_mode.as_str(),
                    "exact-version" | "qualified-unversioned"
                ) {
                    anyhow::bail!(
                        "UPLOAD_S3_CLEANUP_MODE must be exact-version or qualified-unversioned"
                    );
                }
                let bucket = raw
                    .upload_s3_bucket
                    .as_deref()
                    .context("UPLOAD_S3_BUCKET is required for the s3 upload backend")?;
                if !(3..=63).contains(&bucket.len())
                    || bucket.starts_with('.')
                    || bucket.starts_with('-')
                    || bucket.ends_with('.')
                    || bucket.ends_with('-')
                    || bucket.contains("..")
                    || bucket.bytes().any(|byte| {
                        !(byte.is_ascii_lowercase()
                            || byte.is_ascii_digit()
                            || byte == b'.'
                            || byte == b'-')
                    })
                {
                    anyhow::bail!(
                        "UPLOAD_S3_BUCKET must be a canonical lowercase DNS-style bucket name"
                    );
                }
                if raw.upload_s3_region.is_empty()
                    || raw.upload_s3_region.len() > 128
                    || raw
                        .upload_s3_region
                        .chars()
                        .any(|c| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_')))
                {
                    anyhow::bail!("UPLOAD_S3_REGION is invalid");
                }
                if raw.upload_s3_prefix.len() > 512
                    || (!raw.upload_s3_prefix.is_empty()
                        && raw.upload_s3_prefix.split('/').any(|segment| {
                            segment.is_empty()
                                || matches!(segment, "." | "..")
                                || segment.len() > 128
                                || segment.chars().any(|c| {
                                    !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
                                })
                        }))
                {
                    anyhow::bail!("UPLOAD_S3_PREFIX must be a bounded canonical relative prefix");
                }
                let development_storage = listeners_are_loopback
                    && raw.redis_url.is_none()
                    && (domain == "localhost"
                        || domain.ends_with(".localhost")
                        || domain.ends_with(".test"));
                if let Some(endpoint) = raw.upload_s3_endpoint.as_deref() {
                    let uri = endpoint
                        .parse::<axum::http::Uri>()
                        .context("UPLOAD_S3_ENDPOINT must be an absolute HTTP(S) URI")?;
                    let scheme = uri
                        .scheme_str()
                        .context("UPLOAD_S3_ENDPOINT needs a scheme")?;
                    let authority = uri.authority().context("UPLOAD_S3_ENDPOINT needs a host")?;
                    if authority.as_str().contains('@')
                        || uri
                            .path_and_query()
                            .is_some_and(|value| value.as_str() != "/")
                    {
                        anyhow::bail!(
                        "UPLOAD_S3_ENDPOINT cannot contain credentials, a path, query, or fragment"
                    );
                    }
                    match scheme {
                    "https" if !raw.upload_s3_allow_http => {}
                    "http" if raw.upload_s3_allow_http && development_storage => {}
                    "http" => anyhow::bail!("HTTP object storage is allowed only by explicit opt-in in a loopback test deployment"),
                    "https" => anyhow::bail!("UPLOAD_S3_ALLOW_HTTP must be false for an HTTPS endpoint"),
                    _ => anyhow::bail!("UPLOAD_S3_ENDPOINT must use HTTPS"),
                }
                } else if raw.upload_s3_allow_http {
                    anyhow::bail!("UPLOAD_S3_ALLOW_HTTP requires an explicit development endpoint");
                }
                if !development_storage
                    && [
                        "AWS_ACCESS_KEY_ID",
                        "AWS_SECRET_ACCESS_KEY",
                        "AWS_SESSION_TOKEN",
                    ]
                    .iter()
                    .any(|name| std::env::var_os(name).is_some())
                {
                    anyhow::bail!("long-lived inline AWS credential environment variables are forbidden in production; use protected *_FILE mounts or workload credentials");
                }
                match raw.upload_s3_credential_mode.as_str() {
                    "files" => {
                        let bundle = raw.upload_s3_credential_bundle_file.is_some();
                        let legacy_pair = raw.upload_s3_access_key_id_file.is_some()
                            && raw.upload_s3_secret_access_key_file.is_some();
                        let any_legacy = raw.upload_s3_access_key_id_file.is_some()
                            || raw.upload_s3_secret_access_key_file.is_some()
                            || raw.upload_s3_session_token_file.is_some();
                        if bundle == legacy_pair
                            || (bundle && any_legacy)
                            || (!bundle && any_legacy && !legacy_pair)
                        {
                            anyhow::bail!("file S3 credentials require exactly one atomic UPLOAD_S3_CREDENTIAL_BUNDLE_FILE or the legacy access/secret file pair");
                        }
                        if !development_storage && !bundle {
                            anyhow::bail!("production S3 file credentials require the atomically replaced UPLOAD_S3_CREDENTIAL_BUNDLE_FILE");
                        }
                    }
                    "ambient" => {
                        if raw.upload_s3_credential_bundle_file.is_some()
                            || raw.upload_s3_access_key_id_file.is_some()
                            || raw.upload_s3_secret_access_key_file.is_some()
                            || raw.upload_s3_session_token_file.is_some()
                        {
                            anyhow::bail!("ambient S3 credentials cannot be combined with Northstar credential files");
                        }
                        for forbidden in [
                            "AWS_ENDPOINT",
                            "AWS_ENDPOINT_URL_S3",
                            "AWS_ALLOW_HTTP",
                            "AWS_SKIP_SIGNATURE",
                            "AWS_METADATA_ENDPOINT",
                            "AWS_EC2_METADATA_SERVICE_ENDPOINT",
                            "AWS_CONTAINER_CREDENTIALS_FULL_URI",
                        ] {
                            if std::env::var_os(forbidden).is_some() {
                                anyhow::bail!(
                                "{forbidden} is not accepted by the constrained S3 provider chain"
                            );
                            }
                        }
                    }
                    _ => anyhow::bail!("UPLOAD_S3_CREDENTIAL_MODE must be files or ambient"),
                }
                if raw.upload_s3_session_token_file.is_some()
                    && raw.upload_s3_credential_mode != "files"
                {
                    anyhow::bail!("UPLOAD_S3_SESSION_TOKEN_FILE requires file credential mode");
                }
            } else if raw.upload_s3_endpoint.is_some()
                || raw.upload_s3_cleanup_mode != "exact-version"
                || raw.upload_s3_bucket.is_some()
                || raw.upload_s3_access_key_id_file.is_some()
                || raw.upload_s3_credential_bundle_file.is_some()
                || raw.upload_s3_secret_access_key_file.is_some()
                || raw.upload_s3_session_token_file.is_some()
                || raw.upload_s3_sse_kms_key_id_file.is_some()
                || raw.upload_s3_allow_http
            {
                anyhow::bail!("UPLOAD_S3_* settings require UPLOAD_STORAGE_BACKEND=s3");
            }
        }
        if !ephemeral_abuse_state_is_allowed && raw.abuse_state_hmac_key_file.is_none() {
            anyhow::bail!(
                "production abuse state requires ABUSE_STATE_HMAC_KEY_FILE; inline or process-local keys are permitted only in explicit loopback development mode"
            );
        }
        if !ephemeral_abuse_state_is_allowed
            && raw.abuse_state_hmac_previous_key.is_some()
            && raw.abuse_state_hmac_previous_key_file.is_none()
        {
            anyhow::bail!(
                "production abuse-state rotation requires ABUSE_STATE_HMAC_PREVIOUS_KEY_FILE"
            );
        }
        if raw.server_name.trim().is_empty()
            || raw.server_name.len() > 128
            || raw.server_name.chars().any(char::is_control)
        {
            anyhow::bail!("SERVER_NAME must contain 1 to 128 characters without controls");
        }
        raw.server_name = raw.server_name.trim().to_owned();
        if raw.database_url.trim().is_empty() {
            anyhow::bail!("DATABASE_URL must not be empty");
        }
        for (name, addresses) in [
            ("ADMIN_ADDRESSES", &raw.admin_addresses),
            ("ABUSE_ADDRESSES", &raw.abuse_addresses),
            ("SUPPORT_ADDRESSES", &raw.support_addresses),
            ("FEEDBACK_ADDRESSES", &raw.feedback_addresses),
            ("SALES_ADDRESSES", &raw.sales_addresses),
            ("SECURITY_ADDRESSES", &raw.security_addresses),
        ] {
            if addresses.iter().any(|address| {
                address.is_empty()
                    || address.len() > 2_048
                    || !address.contains(':')
                    || address.chars().any(char::is_whitespace)
                    || address.chars().any(char::is_control)
            }) {
                anyhow::bail!("{name} must contain comma-separated URI values without whitespace");
            }
        }
        validate_runtime_pool_budget(raw.database_max_connections, raw.database_min_connections)?;
        if !(crate::auth::MIN_SCRAM_ITERATIONS..=crate::auth::MAX_SCRAM_ITERATIONS)
            .contains(&raw.scram_iterations)
        {
            anyhow::bail!(
                "SCRAM_ITERATIONS must be between {} and {}",
                crate::auth::MIN_SCRAM_ITERATIONS,
                crate::auth::MAX_SCRAM_ITERATIONS
            );
        }
        validate_shared_runtime_secret("FAST_TOKEN_SECRET", raw.fast_token_secret.as_deref())?;
        validate_shared_runtime_secret(
            "DUMMY_SCRAM_SECRET",
            dummy_scram_secret.as_deref().map(String::as_str),
        )?;
        if !authentication_master_secrets_are_independent(
            raw.fast_token_secret.as_deref(),
            dummy_scram_secret.as_deref().map(String::as_str),
        ) {
            anyhow::bail!(
                "DUMMY_SCRAM_SECRET_FILE must contain a key independent from FAST_TOKEN_SECRET_FILE"
            );
        }
        for (name, secret) in [
            ("ABUSE_STATE_HMAC_KEY", raw.abuse_state_hmac_key.as_ref()),
            (
                "ABUSE_STATE_HMAC_PREVIOUS_KEY",
                raw.abuse_state_hmac_previous_key.as_ref(),
            ),
        ] {
            if secret.is_some_and(|secret| {
                secret.len() < 32 || secret.len() > 4096 || secret.contains('\0')
            }) {
                anyhow::bail!("{name} must contain 32 to 4096 bytes without NUL");
            }
        }
        if raw.abuse_state_hmac_key.is_none() && raw.abuse_state_hmac_previous_key.is_some() {
            anyhow::bail!("ABUSE_STATE_HMAC_PREVIOUS_KEY requires ABUSE_STATE_HMAC_KEY");
        }
        if raw.abuse_state_hmac_key_epoch < 1 {
            anyhow::bail!("ABUSE_STATE_HMAC_KEY_EPOCH must be a positive integer");
        }
        if raw.abuse_state_hmac_retire_previous && raw.abuse_state_hmac_previous_key.is_none() {
            anyhow::bail!(
                "ABUSE_STATE_HMAC_RETIRE_PREVIOUS requires ABUSE_STATE_HMAC_PREVIOUS_KEY_FILE"
            );
        }
        if raw.abuse_state_hmac_retire_previous
            && (raw.abuse_state_hmac_key_file.is_none()
                || raw.abuse_state_hmac_previous_key_file.is_none())
        {
            anyhow::bail!(
                "ABUSE_STATE_HMAC_RETIRE_PREVIOUS requires mounted current and previous key files"
            );
        }
        if raw.abuse_state_hmac_previous_key.as_deref() == raw.abuse_state_hmac_key.as_deref()
            && raw.abuse_state_hmac_previous_key.is_some()
        {
            anyhow::bail!("ABUSE_STATE_HMAC_PREVIOUS_KEY must differ from the current key");
        }
        for (name, secret) in [
            ("API_CONTROL_SECRET_FILE", api_control_secret.as_ref()),
            (
                "API_CONTROL_PREVIOUS_SECRET_FILE",
                api_control_previous_secret.as_ref(),
            ),
        ] {
            if secret.is_some_and(|secret| {
                secret.len() < 32 || secret.len() > 4096 || secret.contains('\0')
            }) {
                anyhow::bail!("{name} must contain 32 to 4096 bytes without NUL");
            }
        }
        if api_control_secret.is_none() && api_control_previous_secret.is_some() {
            anyhow::bail!("API_CONTROL_PREVIOUS_SECRET_FILE requires API_CONTROL_SECRET_FILE");
        }
        if !(1..=3650).contains(&raw.fast_token_ttl_days)
            || !(1..=3650).contains(&raw.fast_token_rotation_days)
            || raw.fast_token_rotation_days > raw.fast_token_ttl_days
        {
            anyhow::bail!(
                "FAST token TTL and rotation must be 1..3650 days and rotation must not exceed TTL"
            );
        }
        if !(1..=3650).contains(&raw.fast_strong_reauth_max_days)
            || raw.fast_strong_reauth_max_days < raw.fast_token_ttl_days
        {
            anyhow::bail!(
                "FAST_STRONG_REAUTH_MAX_DAYS must be between FAST_TOKEN_TTL_DAYS and 3650"
            );
        }
        if !(1..=86_400).contains(&raw.sm_resume_timeout_seconds) {
            anyhow::bail!("SM_RESUME_TIMEOUT_SECONDS must be between 1 and 86400");
        }
        if !(5..=300).contains(&raw.sm_live_lease_seconds)
            || !(5..=300).contains(&raw.sm_claim_lease_seconds)
        {
            anyhow::bail!("SM live and claim leases must be between 5 and 300 seconds");
        }
        if !(1..=16_384).contains(&raw.sm_max_unacked_stanzas)
            || !(64 * 1024..=64 * 1024 * 1024).contains(&raw.sm_max_unacked_bytes)
            || !(64 * 1024..=256 * 1024 * 1024).contains(&raw.sm_max_snapshot_bytes)
            || !(64 * 1024..=64 * 1024 * 1024 * 1024).contains(&raw.sm_memory_budget_bytes)
            || !(64 * 1024..=64 * 1024 * 1024 * 1024).contains(&raw.sm_recovery_max_bytes)
            || !(1..=1_000_000).contains(&raw.sm_recovery_max_jobs)
            || !(1..=1_000_000).contains(&raw.sm_max_resumable_sessions)
        {
            anyhow::bail!("SM durable queue/session limits are outside their safe ranges");
        }
        if raw.sm_max_snapshot_bytes < raw.sm_max_unacked_bytes
            || raw.sm_memory_budget_bytes < raw.sm_max_snapshot_bytes
            || raw.sm_recovery_max_bytes < raw.sm_max_snapshot_bytes
        {
            anyhow::bail!(
                "SM snapshot, process-memory, and recovery-queue byte limits are inconsistent"
            );
        }
        if crate::db::SmIpPolicy::parse(&raw.sm_ip_binding).is_none() {
            anyhow::bail!("SM_IP_BINDING must be one of: none, exact, subnet");
        }
        if !(60..=86_400).contains(&raw.turn_credentials_ttl_seconds) {
            anyhow::bail!("TURN_CREDENTIALS_TTL_SECONDS must be between 60 and 86400");
        }
        if !(1..=600).contains(&raw.turn_credential_requests_per_minute) {
            anyhow::bail!("TURN_CREDENTIAL_REQUESTS_PER_MINUTE must be between 1 and 600");
        }
        if !(0..=3650).contains(&raw.offline_message_ttl_days)
            || !(0..=36_500).contains(&raw.mam_retention_days)
            || !(0..=36_500).contains(&raw.muc_mam_retention_days)
            || !(0..=36_500).contains(&raw.moderation_retention_days)
        {
            anyhow::bail!(
                "retention days must be zero (disabled) or within the documented maximum"
            );
        }
        if !(30..=36_500).contains(&raw.audit_log_retention_days) {
            anyhow::bail!("AUDIT_LOG_RETENTION_DAYS must be between 30 and 36500");
        }
        if !(1..=10_000).contains(&raw.retention_cleanup_batch_size)
            || !(60..=86_400).contains(&raw.retention_cleanup_interval_seconds)
        {
            anyhow::bail!(
                "retention cleanup batch size must be 1..10000 and interval 60..86400 seconds"
            );
        }
        if !(1..=100_000).contains(&raw.offline_max_messages_per_account)
            || !(1024 * 1024..=10 * 1024 * 1024 * 1024).contains(&raw.offline_max_bytes_per_account)
        {
            anyhow::bail!("offline queue limits must be 1..100000 messages and 1 MiB..10 GiB");
        }
        if !(1..=8760).contains(&raw.session_ttl_hours) {
            anyhow::bail!("SESSION_TTL_HOURS must be between 1 and 8760");
        }
        if !(100..=1_000_000).contains(&raw.max_client_connections) {
            anyhow::bail!("MAX_CLIENT_CONNECTIONS must be between 100 and 1000000");
        }
        if raw.max_connections_per_ip == 0
            || raw.max_connections_per_ip > raw.max_client_connections
        {
            anyhow::bail!(
                "MAX_CONNECTIONS_PER_IP must be positive and no larger than MAX_CLIENT_CONNECTIONS"
            );
        }
        if !(1..=10_000).contains(&raw.max_sessions_per_account) {
            anyhow::bail!("MAX_SESSIONS_PER_ACCOUNT must be between 1 and 10000");
        }
        if raw.deployment_capacity_epoch < 1 {
            anyhow::bail!("DEPLOYMENT_CAPACITY_EPOCH must be a positive integer");
        }
        if !(1..=100_000_000).contains(&raw.max_accounts_total)
            || !(1..=10_000_000).contains(&raw.max_muc_rooms_total)
            || !(1..=100_000).contains(&raw.max_muc_rooms_per_owner)
            || !(100..=10_000_000).contains(&raw.max_live_sessions_total)
        {
            anyhow::bail!("deployment account, MUC-room, owner-room, or live-session capacity is outside its safe range");
        }
        if raw.max_muc_rooms_per_owner > raw.max_muc_rooms_total {
            anyhow::bail!("MAX_MUC_ROOMS_PER_OWNER cannot exceed MAX_MUC_ROOMS_TOTAL");
        }
        if !(30..=600).contains(&raw.capacity_session_lease_seconds)
            || !(5..=120).contains(&raw.capacity_session_heartbeat_seconds)
            || raw.capacity_session_heartbeat_seconds.saturating_mul(3)
                > raw.capacity_session_lease_seconds
        {
            anyhow::bail!("capacity session lease must be 30..600 seconds and at least three times its 5..120 second heartbeat");
        }
        if !(16..=100_000).contains(&raw.max_s2s_connections) {
            anyhow::bail!("MAX_S2S_CONNECTIONS must be between 16 and 100000");
        }
        if raw.max_component_connections > 10_000
            || !(5..=120).contains(&raw.component_handshake_timeout_seconds)
            || !(16..=10_000).contains(&raw.component_queue_capacity)
        {
            anyhow::bail!("component connection, handshake, or queue limit is invalid");
        }
        if !(60..=30 * 24 * 60 * 60).contains(&raw.s2s_outbox_ttl_seconds) {
            anyhow::bail!("S2S_OUTBOX_TTL_SECONDS must be between 60 and 2592000");
        }
        if !(1..=10_000_000).contains(&raw.s2s_outbox_max_rows)
            || !(1024 * 1024..=1024_i64 * 1024 * 1024 * 1024).contains(&raw.s2s_outbox_max_bytes)
            || !(1..=1_000_000).contains(&raw.s2s_outbox_max_per_domain)
            || raw.s2s_outbox_max_per_domain > raw.s2s_outbox_max_rows
        {
            anyhow::bail!("S2S outbox row, byte, or per-domain capacity is invalid");
        }
        if !(1..=3600).contains(&raw.s2s_outbox_retry_base_seconds)
            || raw.s2s_outbox_retry_max_seconds < raw.s2s_outbox_retry_base_seconds
            || raw.s2s_outbox_retry_max_seconds > 86_400
            || !(1..=10_000).contains(&raw.s2s_outbox_max_attempts)
            || !(1..=10_000).contains(&raw.s2s_outbox_claim_batch)
            || !(30..=3600).contains(&raw.s2s_outbox_lease_seconds)
        {
            anyhow::bail!("S2S outbox retry, batch, attempts, or lease setting is invalid");
        }
        if !(5..=600).contains(&raw.unauthenticated_timeout_seconds) {
            anyhow::bail!("UNAUTHENTICATED_TIMEOUT_SECONDS must be between 5 and 600");
        }
        if !(5..=600).contains(&raw.resource_bind_timeout_seconds) {
            anyhow::bail!("RESOURCE_BIND_TIMEOUT_SECONDS must be between 5 and 600");
        }
        if !(60..=86_400).contains(&raw.admin_idle_seconds) {
            anyhow::bail!("ADMIN_IDLE_SECONDS must be between 60 and 86400");
        }
        if !(1..=10_000).contains(&raw.pubsub_max_nodes_per_owner)
            || !(1..=10_000).contains(&raw.pep_max_nodes_per_account)
        {
            anyhow::bail!("PubSub and PEP node quotas must be between 1 and 10000");
        }
        const MAX_ACCOUNT_STORAGE: i64 = 100 * 1024 * 1024 * 1024;
        if !(1024 * 1024..=MAX_ACCOUNT_STORAGE).contains(&raw.pubsub_max_storage_bytes_per_owner)
            || !(1024 * 1024..=MAX_ACCOUNT_STORAGE).contains(&raw.pep_max_storage_bytes_per_account)
        {
            anyhow::bail!("PubSub and PEP storage quotas must be between 1 MiB and 100 GiB");
        }
        if raw.upload_mode.admits_new_uploads() {
            if raw.upload_max_bytes == 0 || raw.upload_max_bytes > i64::MAX as u64 {
                anyhow::bail!("UPLOAD_MAX_BYTES must be between 1 and i64::MAX");
            }
            if !(1..=1_000_000).contains(&raw.upload_max_files_per_user) {
                anyhow::bail!("UPLOAD_MAX_FILES_PER_USER must be between 1 and 1000000");
            }
            if raw.upload_max_bytes_per_user < raw.upload_max_bytes as i64
                || raw.upload_max_bytes_per_user > MAX_ACCOUNT_STORAGE
            {
                anyhow::bail!(
                "UPLOAD_MAX_BYTES_PER_USER must be at least UPLOAD_MAX_BYTES and at most 100 GiB"
            );
            }
        }
        if raw.upload_mode.keeps_storage_runtime() {
            if raw.upload_download_max_bytes == 0
                || raw.upload_download_max_bytes > i64::MAX as u64
                || (raw.upload_mode.admits_new_uploads()
                    && raw.upload_download_max_bytes < raw.upload_max_bytes)
            {
                anyhow::bail!(
                    "UPLOAD_DOWNLOAD_MAX_BYTES must be positive, at most i64::MAX, and no smaller than UPLOAD_MAX_BYTES while admission is enabled"
                );
            }
            if !(1..=10_000).contains(&raw.upload_download_max_concurrent)
                || !(1..=256).contains(&raw.upload_download_max_per_ip)
                || raw.upload_download_max_per_ip > raw.upload_download_max_concurrent
                || !(5..=300).contains(&raw.upload_download_read_timeout_seconds)
                || !(30..=3600).contains(&raw.upload_download_max_seconds)
            {
                anyhow::bail!("upload download concurrency or read timeout is invalid");
            }
            if !(128..=100_000).contains(&raw.upload_storage_max_pending_jobs)
                || !(1_000..=100_000_000).contains(&raw.upload_storage_max_retained_files)
                || (raw.upload_mode.admits_new_uploads()
                    && raw.upload_storage_max_retained_bytes < raw.upload_max_bytes as i64)
                || raw.upload_storage_max_retained_bytes <= 0
                || raw.upload_storage_max_retained_bytes > 1024_i64 * 1024 * 1024 * 1024 * 1024
            {
                anyhow::bail!("upload physical-retention or reconciliation bounds are invalid");
            }
            if !(60..=10 * 365 * 24 * 60 * 60).contains(&raw.upload_retention_seconds) {
                anyhow::bail!("UPLOAD_RETENTION_SECONDS must be between 60 seconds and 10 years");
            }
        }
        if raw.pow_base_work_factor == 0 || raw.pow_max_work_factor < raw.pow_base_work_factor {
            anyhow::bail!("PoW maximum work factor must be at least the positive base factor");
        }
        raw.pow_v1_compatibility_until = raw
            .pow_v1_compatibility_until
            .take()
            .filter(|value| !value.trim().is_empty());
        let pow_v1_compatibility_until =
            parse_pow_v1_compatibility_until(raw.pow_v1_compatibility_until.as_deref())?;
        if !(10..=10_000).contains(&raw.abuse_message_free_burst)
            || !(1..=30).contains(&raw.pow_max_device_seconds)
        {
            anyhow::bail!("ABUSE_MESSAGE_FREE_BURST must be 10..10000 and POW_MAX_DEVICE_SECONDS must be 1..30");
        }
        if raw.abuse_window_seconds == 0
            || raw.abuse_cooldown_seconds == 0
            || raw.abuse_max_wait_seconds == 0
        {
            anyhow::bail!("anti-abuse window, cooldown and maximum wait must be positive");
        }
        if raw.log_retention_files == 0
            || !matches!(
                raw.log_rotation.to_ascii_lowercase().as_str(),
                "daily" | "hourly" | "minutely" | "never"
            )
        {
            anyhow::bail!("LOG_ROTATION or LOG_RETENTION_FILES is invalid");
        }
        if !matches!(
            raw.log_format.to_ascii_lowercase().as_str(),
            "text" | "json"
        ) {
            anyhow::bail!("LOG_FORMAT must be text or json");
        }
        if raw.bootstrap_admin_username.is_some() != raw.bootstrap_admin_password.is_some() {
            anyhow::bail!(
                "BOOTSTRAP_ADMIN_USERNAME and BOOTSTRAP_ADMIN_PASSWORD must be set together"
            );
        }

        let public_url = resolve_public_url(&raw, &domain, !test_listener_bind_explicitness.http)?;
        if !(1..=100_000).contains(&raw.bosh_max_sessions)
            || !(1..=4_096).contains(&raw.bosh_max_concurrent_body_reads)
            || !(1..=120).contains(&raw.bosh_body_read_timeout_seconds)
            || !(1..=120).contains(&raw.bosh_max_wait_seconds)
            || !(5..=3_600).contains(&raw.bosh_inactivity_seconds)
            || !(1..=60).contains(&raw.bosh_polling_seconds)
            || raw.bosh_max_pause_seconds < raw.bosh_inactivity_seconds
            || raw.bosh_max_pause_seconds > 86_400
            || !(16 * 1024..=4 * 1024 * 1024).contains(&raw.bosh_max_request_bytes)
            || !(16 * 1024..=4 * 1024 * 1024).contains(&raw.bosh_max_response_bytes)
            || !(1..=256).contains(&raw.bosh_max_stanzas_per_request)
            || !(2..=2_048).contains(&raw.bosh_max_output_stanzas)
            || !(64 * 1024..=64 * 1024 * 1024).contains(&raw.bosh_max_output_bytes)
        {
            anyhow::bail!("BOSH session, timer, request, response, stanza, or output bounds are outside their safe ranges");
        }
        if raw.bosh_enabled && !public_url.starts_with("https://") {
            anyhow::bail!("BOSH_ENABLED requires an HTTPS PUBLIC_URL");
        }
        let mut websocket_allowed_origins = Vec::new();
        let mut seen_websocket_origins = HashSet::new();
        for origin in raw.websocket_allowed_origins.split(',') {
            let origin = origin.trim();
            if origin.is_empty() {
                continue;
            }
            let canonical = canonical_web_origin(origin).with_context(|| {
                format!("WEBSOCKET_ALLOWED_ORIGINS contains an invalid origin: {origin}")
            })?;
            if seen_websocket_origins.insert(canonical.clone()) {
                websocket_allowed_origins.push(canonical);
            }
        }
        if websocket_allowed_origins.len() > 64 {
            anyhow::bail!("WEBSOCKET_ALLOWED_ORIGINS may contain at most 64 origins");
        }
        if !(1..=604_800).contains(&raw.xep_0487_ttl_seconds) {
            anyhow::bail!("XEP_0487_TTL_SECONDS must be between 1 and 604800");
        }

        if !(1..=1_000_000).contains(&raw.registration_rate_per_hour) {
            anyhow::bail!("REGISTRATION_RATE_PER_HOUR must be between 1 and 1000000");
        }

        let trusted_proxy_ips = raw
            .trusted_proxy_ips
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.parse())
            .collect::<Result<Vec<IpAddr>, _>>()
            .context("invalid trusted proxy IPs")?;
        validate_web_admin_exposure(raw.web_admin_enabled, raw.web_admin_bind)?;
        if raw.bosh_enabled && trusted_proxy_ips.is_empty() {
            anyhow::bail!("BOSH_ENABLED requires at least one TRUSTED_PROXY_IPS entry");
        }
        let xep_0487_ips = parse_xep_0487_ips(&raw.xep_0487_ips)?;
        let public_http_active =
            web_capabilities.listeners.public.is_some() || !xep_0487_ips.is_empty();
        validate_listener_plan(&raw, public_http_active)?;

        let federation_allowlist = domain_list(&raw.federation_allowlist)
            .context("federation allowlist contains an invalid domain pattern")?;
        let federation_denylist = domain_list(&raw.federation_denylist)
            .context("federation denylist contains an invalid domain pattern")?;
        let federation_dane_mode = crate::s2s::dane::DaneMode::parse(&raw.federation_dane_mode)?;
        raw.federation_dane_mode = match federation_dane_mode {
            crate::s2s::dane::DaneMode::Off => "off",
            crate::s2s::dane::DaneMode::Opportunistic => "opportunistic",
            crate::s2s::dane::DaneMode::Required => "required",
        }
        .to_owned();
        if raw.c2s_client_crl_path.is_some() && raw.c2s_client_trust_root_cert_path.is_none() {
            anyhow::bail!("C2S_CLIENT_CRL_PATH requires C2S_CLIENT_TRUST_ROOT_CERT_PATH");
        }

        let mut federation_dns_overrides = Vec::new();
        for entry in raw.federation_dns_overrides.split(',') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            let (d, endpoint) = entry.split_once('=').context("invalid DNS override")?;
            let d = crate::jid::prepare_domainpart(d.trim())
                .context("invalid domain in DNS override")?;
            let endpoint = endpoint.trim();
            let (endpoint, direct_tls) = endpoint
                .strip_prefix("xmpps://")
                .map(|endpoint| (endpoint, true))
                .or_else(|| {
                    endpoint
                        .strip_prefix("starttls://")
                        .map(|endpoint| (endpoint, false))
                })
                .unwrap_or((endpoint, false));
            federation_dns_overrides.push((
                d,
                endpoint.parse().context("invalid override address")?,
                direct_tls,
            ));
        }
        crate::s2s::lab_dnssec::validate_settings(
            raw.federation_dnssec_lab_trust_anchor_path.as_deref(),
            federation_dane_mode,
            &domain,
            raw.federation_enabled,
            raw.federation_allow_private_ips,
            &federation_allowlist,
            federation_dns_overrides.len(),
        )?;
        let stun_service = raw
            .stun_server
            .as_deref()
            .map(parse_external_service)
            .transpose()
            .context("STUN_SERVER is invalid")?;
        let turn_service = raw
            .turn_server
            .as_deref()
            .map(parse_external_service)
            .transpose()
            .context("TURN_SERVER is invalid")?;
        if raw.turn_shared_secret.is_some() && turn_service.is_none() {
            anyhow::bail!("TURN_SHARED_SECRET requires TURN_SERVER");
        }
        if raw
            .turn_shared_secret
            .as_ref()
            .is_some_and(|secret| secret.len() < 32 || secret.len() > 4096 || secret.contains('\0'))
        {
            anyhow::bail!("TURN_SHARED_SECRET must contain 32 to 4096 bytes without NUL");
        }
        validate_shared_runtime_secret("DIALBACK_SECRET", raw.dialback_secret.as_deref())?;
        validate_cluster_dialback_secret(
            raw.redis_url.is_some(),
            raw.dialback_enabled,
            raw.dialback_secret_file.as_deref(),
        )?;
        validate_cluster_fast_secret(
            raw.redis_url.is_some(),
            raw.fast_token_secret_file.as_deref(),
        )?;
        if raw.federation_enabled && !raw.s2s_sasl_external_enabled && !raw.dialback_enabled {
            anyhow::bail!("federation requires S2S_SASL_EXTERNAL_ENABLED or DIALBACK_ENABLED");
        }

        let components = if raw.components_enabled {
            let path = raw
                .components_config_file
                .as_deref()
                .context("COMPONENTS_ENABLED requires COMPONENTS_CONFIG_FILE")?;
            load_component_credentials(path, &domain)?
        } else {
            Vec::new()
        };
        if raw.components_enabled && components.is_empty() {
            anyhow::bail!(
                "component support is enabled but no component credentials are configured"
            );
        }
        validate_component_transport(raw.component_bind, &components)?;
        validate_component_capacity(raw.max_component_connections, &components)?;

        let fast_token_enabled = raw.fast_token_secret.is_some() || ephemeral_fast_is_allowed;
        Ok(Self {
            raw,
            admin_command_pool_mode,
            storage_pool_mode,
            domain,
            public_url,
            websocket_allowed_origins,
            trusted_proxy_ips,
            xep_0487_ips,
            xmpp_extensions,
            federation_allowlist,
            federation_denylist,
            federation_dns_overrides,
            federation_dane_mode,
            stun_service,
            turn_service,
            components,
            cluster_security: cluster_security.map(Arc::new),
            fast_token_enabled,
            dummy_scram_secret,
            api_control_secret,
            api_control_previous_secret,
            metrics_bearer_token: metrics_bearer_token.map(|token| Arc::new(Zeroizing::new(token))),
            web_admin_gateway_token: web_admin_gateway_token
                .map(|token| Arc::new(Zeroizing::new(token))),
            web_capabilities,
            invitation_policy_disabled_with_web_client,
            pow_v1_compatibility_until,
        })
    }
}
