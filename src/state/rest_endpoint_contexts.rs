//! Composition-root constructors for the REST endpoint and upload contexts in api::contexts.

use super::AppState;
use crate::api::contexts::{
    api_session_http::ApiSessionHttpContext,
    http_challenge_endpoint::HttpChallengeEndpointContext,
    http_login_endpoint::HttpLoginEndpointCounters,
    http_registration_endpoint::HttpRegistrationEndpointContext,
    omemo_recovery_http::OmemoRecoveryHttpContext,
    passkey_http::{PasskeyAccountHttpContext, PasskeyStartHttpContext},
    password_change_http::PasswordChangeHttpContext,
    upload_http_delete::UploadHttpDeleteContext,
    upload_http_write::UploadHttpWriteContext,
    HttpLoginEndpointContext, OmemoRecoveryPollContext, PasskeyLoginFinishContext,
    UploadHttpReadContext, UploadHttpReplayReadContext,
};
use std::sync::Arc;
use std::time::Duration;

impl axum::extract::FromRef<Arc<AppState>> for ApiSessionHttpContext {
    fn from_ref(state: &Arc<AppState>) -> Self {
        Self {
            service: Arc::new(state.api_session_service()),
        }
    }
}

impl axum::extract::FromRef<Arc<AppState>> for HttpChallengeEndpointContext {
    fn from_ref(state: &Arc<AppState>) -> Self {
        Self {
            service: state.abuse.challenge_issue_service.clone(),
            trusted_proxies: state.config.trusted_proxy_ips.clone(),
            requested: Arc::clone(&state.metrics.anti_abuse_challenges_total),
            rate_limited: Arc::clone(&state.metrics.rate_limited_total),
        }
    }
}

impl axum::extract::FromRef<Arc<AppState>> for HttpRegistrationEndpointContext {
    fn from_ref(state: &Arc<AppState>) -> Self {
        Self {
            service: state.auth.account_service.clone(),
            availability: state.http_registration_availability(),
            trusted_proxies: state.config.trusted_proxy_ips.clone(),
            registrations: Arc::clone(&state.metrics.registrations_total),
            rate_limited: Arc::clone(&state.metrics.rate_limited_total),
            capacity_rejected: Arc::clone(&state.metrics.capacity_reservations_rejected_total),
        }
    }
}

impl axum::extract::FromRef<Arc<AppState>> for HttpLoginEndpointContext {
    fn from_ref(state: &Arc<AppState>) -> Self {
        HttpLoginEndpointContext {
            service: state.auth.login_service.clone(),
            trusted_proxies: state.config.trusted_proxy_ips.clone(),
            counters: HttpLoginEndpointCounters {
                rate_limited: Arc::clone(&state.metrics.rate_limited_total),
                backend_failures: Arc::clone(&state.metrics.authentication_backend_failures_total),
            },
        }
    }
}

impl axum::extract::FromRef<Arc<AppState>> for OmemoRecoveryHttpContext {
    fn from_ref(state: &Arc<AppState>) -> Self {
        Self {
            queries: state.api_query_service().clone(),
            recovery: state.omemo_recovery_service().clone(),
            domain: state.public_discovery_context().policy().domain.clone(),
            metrics: Arc::clone(&state.metrics),
        }
    }
}

impl axum::extract::FromRef<Arc<AppState>> for PasswordChangeHttpContext {
    fn from_ref(state: &Arc<AppState>) -> Self {
        Self {
            service: state.auth.password_change_service.clone(),
            trusted_proxies: state.config.trusted_proxy_ips.clone(),
            domain: state.local_domain().to_owned(),
            rate_limited: Arc::clone(&state.metrics.rate_limited_total),
            backend_failures: Arc::clone(&state.metrics.authentication_backend_failures_total),
        }
    }
}

impl axum::extract::FromRef<Arc<AppState>> for PasskeyAccountHttpContext {
    fn from_ref(state: &Arc<AppState>) -> Self {
        Self {
            service: Arc::clone(&state.auth.passkey_service),
        }
    }
}

impl axum::extract::FromRef<Arc<AppState>> for PasskeyStartHttpContext {
    fn from_ref(state: &Arc<AppState>) -> Self {
        Self {
            service: Arc::clone(&state.auth.passkey_service),
            abuse: Arc::clone(&state.abuse.passkey_login_abuse_service),
            trusted_proxies: state
                .http_transport_policy()
                .trusted_proxies()
                .to_vec()
                .into(),
        }
    }
}

impl axum::extract::FromRef<Arc<AppState>> for PasskeyLoginFinishContext {
    fn from_ref(state: &Arc<AppState>) -> Self {
        Self::new(Arc::clone(&state.auth.passkey_service))
    }
}

impl axum::extract::FromRef<Arc<AppState>> for OmemoRecoveryPollContext {
    fn from_ref(state: &Arc<AppState>) -> Self {
        state.omemo_recovery_poll_context()
    }
}

impl axum::extract::FromRef<Arc<AppState>> for UploadHttpReadContext {
    fn from_ref(state: &Arc<AppState>) -> Self {
        UploadHttpReadContext {
            service: state.upload.service.clone(),
            // AppState stores only GuardedUploadStore implementations here.
            guarded_store: state.upload.store.as_ref().map(Arc::clone),
            admission: state.upload.runtime.download_admission().cloned(),
            trusted_proxies: state.config.trusted_proxy_ips.clone().into(),
            operation_duration: Arc::clone(&state.metrics.upload_operation_duration_seconds),
            read_timeout: Duration::from_secs(state.config.upload_download_read_timeout_seconds),
            max_duration: Duration::from_secs(state.config.upload_download_max_seconds),
        }
    }
}

impl axum::extract::FromRef<Arc<AppState>> for UploadHttpReplayReadContext {
    fn from_ref(state: &Arc<AppState>) -> Self {
        Self {
            // AppState stores only GuardedUploadStore implementations here.
            guarded_store: state.upload.store.as_ref().map(Arc::clone),
            read_timeout: Duration::from_secs(state.config.upload_download_read_timeout_seconds),
            max_duration: Duration::from_secs(state.config.upload_download_max_seconds),
        }
    }
}

impl axum::extract::FromRef<Arc<AppState>> for UploadHttpWriteContext {
    fn from_ref(state: &Arc<AppState>) -> Self {
        Self {
            service: state.upload.service.clone(),
            // AppState stores only GuardedUploadStore implementations here.
            guarded_store: state.upload.store.as_ref().map(Arc::clone),
            admission: state.upload.runtime.request_admission().cloned(),
            safety_gate: Arc::clone(&state.upload.safety_gate),
            trusted_proxies: state.config.trusted_proxy_ips.clone().into(),
            operation_duration: Arc::clone(&state.metrics.upload_operation_duration_seconds),
            retention_seconds: state.config.upload_retention_seconds,
        }
    }
}

impl axum::extract::FromRef<Arc<AppState>> for UploadHttpDeleteContext {
    fn from_ref(state: &Arc<AppState>) -> Self {
        Self {
            service: state.upload.service.clone(),
            operation_duration: Arc::clone(&state.metrics.upload_operation_duration_seconds),
        }
    }
}
