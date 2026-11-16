//! Derived runtime policies over the validated process configuration.

use crate::Config;
use std::time::Duration;

#[derive(Clone, Copy)]
pub struct RuntimeListenerPolicy {
    pub xmpp: std::net::SocketAddr,
    pub xmpps: std::net::SocketAddr,
    pub http: std::net::SocketAddr,
    pub metrics: std::net::SocketAddr,
    pub admin: Option<std::net::SocketAddr>,
    pub s2s: Option<std::net::SocketAddr>,
    pub s2s_tls: Option<std::net::SocketAddr>,
    pub component: std::net::SocketAddr,
}

impl Config {
    pub fn server_info_addresses(&self) -> [(&'static str, &[String]); 6] {
        [
            ("admin-addresses", &self.admin_addresses),
            ("abuse-addresses", &self.abuse_addresses),
            ("support-addresses", &self.support_addresses),
            ("feedback-addresses", &self.feedback_addresses),
            ("sales-addresses", &self.sales_addresses),
            ("security-addresses", &self.security_addresses),
        ]
    }

    pub fn external_service_discovery_available(&self) -> bool {
        self.stun_service.is_some() || self.turn_service.is_some()
    }

    pub fn s2s_dane_required(&self) -> bool {
        self.federation_dane_mode == northstar_security::dane::DaneMode::Required
    }

    pub fn s2s_ping_route_enabled(&self) -> bool {
        self.xmpp_extensions.route_enabled(
            northstar_xep_core::StanzaKind::IqGet,
            northstar_xep_0199::NAMESPACE,
            "ping",
        )
    }

    pub fn xmpp_route_enabled(
        &self,
        stanza: northstar_xep_core::StanzaKind,
        namespace: &str,
        local_name: &str,
    ) -> bool {
        self.xmpp_extensions
            .route_enabled(stanza, namespace, local_name)
    }

    pub fn xmpp_extension_enabled(&self, id: northstar_xep_core::XepId) -> bool {
        self.xmpp_extensions.enabled(id)
    }

    pub fn server_disco_features(&self) -> Vec<&'static str> {
        self.xmpp_extensions.server_disco_features().collect()
    }

    pub fn unauthenticated_timeout(&self) -> Duration {
        Duration::from_secs(self.unauthenticated_timeout_seconds)
    }

    pub fn runtime_listener_policy(&self) -> RuntimeListenerPolicy {
        RuntimeListenerPolicy {
            xmpp: self.xmpp_bind,
            xmpps: self.xmpps_bind,
            http: self.http_bind,
            metrics: self.metrics_bind,
            admin: self.web_admin_enabled.then_some(self.web_admin_bind),
            s2s: self.federation_enabled.then_some(self.s2s_bind),
            s2s_tls: self.federation_enabled.then_some(self.s2s_tls_bind),
            component: self.component_bind,
        }
    }

    pub fn xmpp_http_upload_enabled(&self) -> bool {
        self.upload_mode.admits_new_uploads()
            && self.xmpp_extension_enabled(northstar_xep_0363::XEP_ID)
    }

    /// The caller combines the dependency lock with the live registration switch.
    pub fn registration_mode(&self, registration_is_closed: bool) -> crate::RegistrationMode {
        if registration_is_closed {
            crate::RegistrationMode::Closed
        } else {
            self.configured_registration_mode()
        }
    }

    pub fn registration_requires_invitation(&self, registration_is_closed: bool) -> bool {
        self.registration_mode(registration_is_closed) == crate::RegistrationMode::InvitationOnly
    }
}
