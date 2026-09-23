//! Public discovery data and HTTP entry policies without application authority.
use crate::{
    config::{RegistrationMode, UploadMode},
    metrics::Metrics,
};
use std::{
    net::IpAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub(crate) struct PublicDiscoveryPolicy {
    pub(crate) domain: String,
    pub(crate) public_url: String,
    pub(crate) trusted_proxy_ips: Vec<IpAddr>,
    pub(crate) websocket_allowed_origins: Vec<String>,
    pub(super) configured_registration_mode: RegistrationMode,
    pub(super) registration_dependency_locked: bool,
    pub(crate) require_encrypted_archive: bool,
    pub(super) federation_configured: bool,
    pub(crate) rest_api_enabled: bool,
    pub(crate) websocket_enabled: bool,
    pub(crate) bosh_enabled: bool,
    pub(crate) web_client_enabled: bool,
    pub(crate) passkeys_enabled: bool,
    pub(crate) web_admin_enabled: bool,
    pub(crate) upload_mode: UploadMode,
    pub(crate) upload_max_bytes: u64,
    pub(crate) upload_download_max_bytes: u64,
    pub(crate) pow_max_work_factor: u64,
    pub(crate) pow_max_device_seconds: u64,
    pub(crate) xep_0487_ips: Vec<IpAddr>,
    pub(crate) xep_0487_ttl_seconds: u64,
    pub(crate) xep_0487_priority: u16,
    pub(crate) xep_0487_weight: u16,
    pub(crate) xmpps_port: u16,
    pub(crate) s2s_tls_port: u16,
}

#[derive(Clone)]
pub(crate) struct PublicDiscoveryContext {
    policy: Arc<PublicDiscoveryPolicy>,
    registration_closed: Arc<AtomicBool>,
    island_mode: Arc<AtomicBool>,
}

impl PublicDiscoveryContext {
    pub(super) fn new(
        policy: PublicDiscoveryPolicy,
        registration_closed: Arc<AtomicBool>,
        island_mode: Arc<AtomicBool>,
    ) -> Self {
        Self {
            policy: Arc::new(policy),
            registration_closed,
            island_mode,
        }
    }

    pub(crate) fn policy(&self) -> &PublicDiscoveryPolicy {
        &self.policy
    }

    pub(crate) fn registration_mode(&self) -> RegistrationMode {
        if self.policy.registration_dependency_locked
            || self.registration_closed.load(Ordering::Acquire)
        {
            RegistrationMode::Closed
        } else {
            self.policy.configured_registration_mode
        }
    }

    pub(crate) fn registration_requires_invitation(&self) -> bool {
        self.registration_mode() == RegistrationMode::InvitationOnly
    }

    pub(crate) fn registration_opening_is_dependency_locked(&self) -> bool {
        self.policy.registration_dependency_locked
    }

    pub(crate) fn federation_enabled(&self) -> bool {
        self.policy.federation_configured && !self.island_mode.load(Ordering::Acquire)
    }
}

#[derive(Clone)]
pub(crate) struct HttpTransportPolicy {
    trusted_proxies: Arc<[IpAddr]>,
    metrics: Arc<Metrics>,
}

impl HttpTransportPolicy {
    pub(super) fn new(trusted_proxies: Vec<IpAddr>, metrics: Arc<Metrics>) -> Self {
        Self {
            trusted_proxies: trusted_proxies.into(),
            metrics,
        }
    }

    pub(crate) fn trusted_proxies(&self) -> &[IpAddr] {
        &self.trusted_proxies
    }

    pub(crate) fn record_insecure_rejection(&self) -> u64 {
        self.metrics
            .http_insecure_requests_rejected_total
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1)
    }
}

#[derive(Clone)]
pub(crate) struct AdminGatewayVerifier {
    expected: Option<Arc<Zeroizing<String>>>,
}

impl AdminGatewayVerifier {
    pub(crate) fn new(expected: Option<Arc<Zeroizing<String>>>) -> Self {
        Self { expected }
    }

    pub(crate) fn authorized(&self, candidate: Option<&str>) -> bool {
        let Some(expected) = self.expected.as_deref() else {
            return true;
        };
        candidate.is_some_and(|candidate| {
            candidate.len() == expected.len()
                && bool::from(candidate.as_bytes().ct_eq(expected.as_bytes()))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn discovery_policy() -> PublicDiscoveryPolicy {
        PublicDiscoveryPolicy {
            domain: "chat.example.test".into(),
            public_url: "https://chat.example.test".into(),
            trusted_proxy_ips: vec!["127.0.0.1".parse().unwrap()],
            websocket_allowed_origins: vec!["https://chat.example.test".into()],
            configured_registration_mode: RegistrationMode::InvitationOnly,
            registration_dependency_locked: false,
            require_encrypted_archive: true,
            federation_configured: true,
            rest_api_enabled: true,
            websocket_enabled: true,
            bosh_enabled: true,
            web_client_enabled: true,
            passkeys_enabled: true,
            web_admin_enabled: false,
            upload_mode: UploadMode::Enabled,
            upload_max_bytes: 100,
            upload_download_max_bytes: 200,
            pow_max_work_factor: 1000,
            pow_max_device_seconds: 30,
            xep_0487_ips: vec![],
            xep_0487_ttl_seconds: 300,
            xep_0487_priority: 0,
            xep_0487_weight: 0,
            xmpps_port: 5223,
            s2s_tls_port: 5270,
        }
    }

    #[tokio::test]
    async fn discovery_reads_current_registration_and_federation_authority() {
        let closed = Arc::new(AtomicBool::new(false));
        let island = Arc::new(AtomicBool::new(false));
        let context = PublicDiscoveryContext::new(
            discovery_policy(),
            Arc::clone(&closed),
            Arc::clone(&island),
        );
        let cloned = context.clone();
        assert!(cloned.registration_requires_invitation());
        assert!(cloned.federation_enabled());
        let axum::Json(initial) =
            crate::api::public_config(axum::extract::State(cloned.clone())).await;
        assert_eq!(initial["registration_mode"], "invitation");
        assert_eq!(initial["invitation_required"], true);
        assert_eq!(initial["federation_enabled"], true);
        closed.store(true, Ordering::Release);
        island.store(true, Ordering::Release);
        assert_eq!(cloned.registration_mode(), RegistrationMode::Closed);
        assert!(!cloned.registration_requires_invitation());
        assert!(!cloned.federation_enabled());
        let axum::Json(closed_document) =
            crate::api::public_config(axum::extract::State(cloned)).await;
        assert_eq!(closed_document["registration_mode"], "closed");
        assert_eq!(closed_document["open_registration"], false);
        assert_eq!(closed_document["invitation_required"], false);
        assert_eq!(closed_document["federation_enabled"], false);
        closed.store(false, Ordering::Release);
        island.store(false, Ordering::Release);
        assert!(context.registration_requires_invitation());
        assert!(context.federation_enabled());
    }

    #[test]
    fn configured_limits_cannot_be_opened_by_runtime_flags() {
        let mut policy = discovery_policy();
        policy.registration_dependency_locked = true;
        policy.federation_configured = false;
        let context = PublicDiscoveryContext::new(
            policy,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        );
        assert_eq!(context.registration_mode(), RegistrationMode::Closed);
        assert!(context.registration_opening_is_dependency_locked());
        assert!(!context.federation_enabled());
    }

    #[test]
    fn transport_rejections_use_the_original_process_counter() {
        let metrics = Arc::new(Metrics::default());
        metrics
            .http_insecure_requests_rejected_total
            .store(7, Ordering::Relaxed);
        let proxy: IpAddr = "127.0.0.1".parse().unwrap();
        let policy = HttpTransportPolicy::new(vec![proxy], Arc::clone(&metrics));
        assert_eq!(policy.trusted_proxies(), &[proxy]);
        assert_eq!(policy.clone().record_insecure_rejection(), 8);
        assert_eq!(policy.record_insecure_rejection(), 9);
        assert_eq!(
            metrics
                .http_insecure_requests_rejected_total
                .load(Ordering::Relaxed),
            9
        );
    }

    #[test]
    fn gateway_verifier_retains_the_original_secret_and_optional_mode() {
        let secret = Arc::new(Zeroizing::new(uuid::Uuid::new_v4().simple().to_string()));
        let verifier = AdminGatewayVerifier::new(Some(Arc::clone(&secret)));
        assert!(verifier.clone().authorized(Some(secret.as_str())));
        assert!(!verifier.authorized(None));
        assert!(!verifier.authorized(Some("")));
        let incorrect = format!("{}x", &secret[..secret.len() - 1]);
        assert!(!verifier.authorized(Some(&incorrect)));
        assert!(AdminGatewayVerifier::new(None).authorized(None));
        assert!(AdminGatewayVerifier::new(None).authorized(Some(&incorrect)));
    }
}
