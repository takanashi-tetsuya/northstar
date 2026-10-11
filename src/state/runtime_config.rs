//! Runtime configuration views: readiness context, policy value types and configuration accessors.

use super::*;

/// Private observability capability. It contains only read-only live probes
/// and the existing typed persistence service, never AppState or a mutable
/// cluster, worker, connection, upload, or SM owner.
pub(crate) struct ReadinessContext {
    pub(super) connection: crate::connection_actors::ConnectionAdmissionReadiness,
    pub(super) sm: crate::services::sm_capacity::SmMemoryReadiness,
    pub(super) upload: crate::services::upload_safety::UploadSafetyReadiness,
    pub(super) cluster: crate::cluster::ClusterReadinessProbe,
    pub(super) workers: crate::workers::WorkerReadinessProbe,
    pub(super) abuse_key_deployment: Option<db::AbuseKeyDeploymentIdentity>,
    pub(super) persistence: crate::services::readiness::ReadinessService<
        db::readiness_repository::PostgresReadinessRepository,
    >,
}

impl ReadinessContext {
    pub(crate) fn connection_accepting(&self) -> bool {
        self.connection.is_accepting()
    }

    pub(crate) fn sm_ready(&self) -> bool {
        self.sm.is_ready()
    }

    pub(crate) fn upload_state(&self) -> crate::services::upload_safety::UploadSafetyState {
        self.upload.state()
    }

    pub(crate) fn cluster_error(&self) -> Option<String> {
        self.cluster.readiness_error()
    }

    pub(crate) fn worker_error(&self) -> Option<String> {
        self.workers.readiness_error()
    }

    pub(crate) fn cluster_authority_snapshot(
        &self,
    ) -> Option<crate::cluster::ClusterReadinessAuthority> {
        self.cluster.authority_snapshot()
    }

    pub(crate) async fn validate_persistence(
        &self,
        cluster_authority: Option<&crate::cluster::ClusterReadinessAuthority>,
    ) -> anyhow::Result<()> {
        self.persistence
            .validate_persistence(self.abuse_key_deployment.as_ref(), cluster_authority)
            .await
    }
}

#[derive(Clone, Copy)]
pub(crate) struct OfflineDeliveryLimits {
    pub(crate) max_messages: i64,
    pub(crate) max_bytes: i64,
    pub(crate) ttl_days: i64,
}

#[derive(Clone, Copy)]
pub(crate) struct SmBufferLimits {
    pub(crate) max_unacked_stanzas: usize,
    pub(crate) max_unacked_bytes: usize,
    pub(crate) max_snapshot_bytes: usize,
}

#[derive(Clone, Copy)]
pub(crate) struct SmSessionPolicy {
    pub(crate) require_same_device: bool,
    pub(crate) resume_timeout_seconds: u64,
    pub(crate) live_lease_seconds: u64,
    pub(crate) claim_lease_seconds: u64,
    pub(crate) max_per_account: usize,
    pub(crate) max_global: usize,
}

#[derive(Clone, Copy)]
pub(crate) struct BoshPolicy {
    pub(crate) max_wait_seconds: u64,
    pub(crate) inactivity_seconds: u64,
    pub(crate) polling_seconds: u64,
    pub(crate) max_pause_seconds: u64,
    pub(crate) body_read_timeout_seconds: u64,
    pub(crate) max_request_bytes: usize,
    pub(crate) max_response_bytes: usize,
    pub(crate) max_stanzas_per_request: usize,
    pub(crate) max_output_stanzas: usize,
    pub(crate) max_output_bytes: usize,
}

#[derive(Clone, Copy)]
pub(crate) struct ComponentRuntimePolicy {
    pub(crate) enabled: bool,
    pub(crate) max_connections: usize,
    pub(crate) handshake_timeout: Duration,
    pub(crate) queue_capacity: usize,
}

#[derive(Clone, Copy)]
pub(crate) struct RuntimeListenerPolicy {
    pub(crate) xmpp: std::net::SocketAddr,
    pub(crate) xmpps: std::net::SocketAddr,
    pub(crate) http: std::net::SocketAddr,
    pub(crate) metrics: std::net::SocketAddr,
    pub(crate) admin: Option<std::net::SocketAddr>,
    pub(crate) s2s: Option<std::net::SocketAddr>,
    pub(crate) s2s_tls: Option<std::net::SocketAddr>,
    pub(crate) component: std::net::SocketAddr,
}

#[derive(Clone, Copy)]
pub(crate) struct PubSubOwnerLimits {
    pub(crate) max_nodes: i64,
    pub(crate) max_storage_bytes: i64,
}

#[derive(Clone, Copy)]
pub(crate) struct Sasl2FastTokenPolicy {
    pub(crate) enabled: bool,
    pub(crate) rotation_days: i64,
    pub(crate) ttl_days: i64,
    pub(crate) strong_reauth_max_days: i64,
}

#[derive(Clone, Copy)]
pub(crate) struct AdminScramPolicy {
    pub(crate) iterations: u32,
    pub(crate) sha1_enabled: bool,
}

#[derive(Clone, Copy)]
pub(crate) struct UploadSlotLimits {
    pub(crate) max_file_bytes: u64,
    pub(crate) max_files_per_user: i64,
    pub(crate) max_bytes_per_user: i64,
    pub(crate) max_retained_files: i64,
    pub(crate) max_retained_bytes: i64,
    pub(crate) max_pending_jobs: i64,
}

impl AppState {
    pub(crate) fn tls_context(&self) -> &crate::tls::TlsContext {
        &self.tls_context
    }

    /// Validated local identity for protocol routing without exposing Config.
    pub(crate) fn local_domain(&self) -> &str {
        &self.config.domain
    }

    pub(crate) fn server_name(&self) -> &str {
        &self.config.server_name
    }

    pub(crate) fn server_info_addresses(&self) -> [(&'static str, &[String]); 6] {
        [
            ("admin-addresses", &self.config.admin_addresses),
            ("abuse-addresses", &self.config.abuse_addresses),
            ("support-addresses", &self.config.support_addresses),
            ("feedback-addresses", &self.config.feedback_addresses),
            ("sales-addresses", &self.config.sales_addresses),
            ("security-addresses", &self.config.security_addresses),
        ]
    }

    pub(crate) fn external_service_discovery_available(&self) -> bool {
        self.config.stun_service.is_some() || self.config.turn_service.is_some()
    }

    pub(crate) fn upload_public_url(&self) -> &str {
        &self.config.public_url
    }

    pub(crate) fn xmpp_external_route_domain_allowed(&self, domain: &str) -> bool {
        self.config.external_route_domain_allowed(domain)
    }

    pub(crate) fn xmpp_component_domain_configured(&self, domain: &str) -> bool {
        self.config.component_domain_configured(domain)
    }

    pub(crate) fn s2s_federation_enabled(&self) -> bool {
        self.config.federation_enabled
    }

    pub(crate) fn s2s_sasl_external_enabled(&self) -> bool {
        self.config.s2s_sasl_external_enabled
    }

    pub(crate) fn s2s_dialback_enabled(&self) -> bool {
        self.config.dialback_enabled
    }

    pub(crate) fn s2s_dane_required(&self) -> bool {
        self.config.federation_dane_mode == crate::s2s::dane::DaneMode::Required
    }

    pub(crate) fn s2s_dane_mode(&self) -> crate::s2s::dane::DaneMode {
        self.config.federation_dane_mode
    }

    pub(crate) fn s2s_ocsp_staple_required(&self) -> bool {
        self.config.federation_ocsp_staple_required
    }

    pub(crate) fn s2s_dns_override(&self, domain: &str) -> Option<(std::net::SocketAddr, bool)> {
        self.config
            .federation_dns_overrides
            .iter()
            .find(|(candidate, _, _)| {
                crate::jid::prepare_domainpart(candidate).is_ok_and(|candidate| candidate == domain)
            })
            .map(|(_, address, direct_tls)| (*address, *direct_tls))
    }

    pub(crate) fn s2s_private_addresses_allowed(&self) -> bool {
        self.config.federation_allow_private_ips
    }

    pub(crate) fn s2s_component_domain_configured(&self, domain: &str) -> bool {
        self.config.component_domain_configured(domain)
    }

    pub(crate) fn s2s_ping_route_enabled(&self) -> bool {
        self.config.xmpp_extensions.route_enabled(
            northstar_xep_core::StanzaKind::IqGet,
            northstar_xep_0199::NAMESPACE,
            "ping",
        )
    }

    pub(crate) fn xmpp_route_enabled(
        &self,
        stanza: northstar_xep_core::StanzaKind,
        namespace: &str,
        local_name: &str,
    ) -> bool {
        self.config
            .xmpp_extensions
            .route_enabled(stanza, namespace, local_name)
    }

    pub(crate) fn xmpp_extension_enabled(&self, id: northstar_xep_core::XepId) -> bool {
        self.config.xmpp_extensions.enabled(id)
    }

    pub(crate) fn server_disco_features(&self) -> Vec<&'static str> {
        self.config
            .xmpp_extensions
            .server_disco_features()
            .collect()
    }

    pub(crate) fn xmpp_version_includes_os(&self) -> bool {
        self.config.xep_0092_include_os
    }

    pub(crate) fn sm_buffer_limits(&self) -> SmBufferLimits {
        SmBufferLimits {
            max_unacked_stanzas: self.config.sm_max_unacked_stanzas,
            max_unacked_bytes: self.config.sm_max_unacked_bytes,
            max_snapshot_bytes: self.config.sm_max_snapshot_bytes,
        }
    }

    pub(crate) fn bosh_policy(&self) -> BoshPolicy {
        BoshPolicy {
            max_wait_seconds: self.config.bosh_max_wait_seconds,
            inactivity_seconds: self.config.bosh_inactivity_seconds,
            polling_seconds: self.config.bosh_polling_seconds,
            max_pause_seconds: self.config.bosh_max_pause_seconds,
            body_read_timeout_seconds: self.config.bosh_body_read_timeout_seconds,
            max_request_bytes: self.config.bosh_max_request_bytes,
            max_response_bytes: self.config.bosh_max_response_bytes,
            max_stanzas_per_request: self.config.bosh_max_stanzas_per_request,
            max_output_stanzas: self.config.bosh_max_output_stanzas,
            max_output_bytes: self.config.bosh_max_output_bytes,
        }
    }

    pub(crate) fn unauthenticated_timeout(&self) -> Duration {
        Duration::from_secs(self.config.unauthenticated_timeout_seconds)
    }

    pub(crate) fn trusted_proxy_ips(&self) -> &[std::net::IpAddr] {
        &self.config.trusted_proxy_ips
    }

    pub(crate) fn runtime_listener_policy(&self) -> RuntimeListenerPolicy {
        RuntimeListenerPolicy {
            xmpp: self.config.xmpp_bind,
            xmpps: self.config.xmpps_bind,
            http: self.config.http_bind,
            metrics: self.config.metrics_bind,
            admin: self
                .config
                .web_admin_enabled
                .then_some(self.config.web_admin_bind),
            s2s: self
                .config
                .federation_enabled
                .then_some(self.config.s2s_bind),
            s2s_tls: self
                .config
                .federation_enabled
                .then_some(self.config.s2s_tls_bind),
            component: self.config.component_bind,
        }
    }

    pub(crate) fn cluster_workers_enabled(&self) -> bool {
        self.cluster.is_enabled()
    }

    pub(crate) fn cluster_pubsub_listener_transport(
        &self,
    ) -> crate::cluster::ClusterPubsubListenerTransport {
        self.cluster.pubsub_listener_transport()
    }

    pub(crate) fn test_listener_activation_policy(
        &self,
    ) -> crate::test_activation::TestActivationPolicy<'_> {
        crate::test_activation::TestActivationPolicy {
            enabled: self.config.test_listener_activation,
            destination: self.config.test_readiness_file.as_deref(),
            nonce: self.config.test_readiness_nonce.as_deref(),
        }
    }

    pub(crate) fn sm_session_policy(&self) -> SmSessionPolicy {
        SmSessionPolicy {
            require_same_device: self.config.sm_require_same_device,
            resume_timeout_seconds: self.config.sm_resume_timeout_seconds,
            live_lease_seconds: self.config.sm_live_lease_seconds,
            claim_lease_seconds: self.config.sm_claim_lease_seconds,
            max_per_account: self.config.max_sessions_per_account,
            max_global: self.config.sm_max_resumable_sessions,
        }
    }

    pub(crate) fn sm_ip_binding(&self) -> &str {
        &self.config.sm_ip_binding
    }

    pub(crate) fn c2s_resource_bind_timeout_seconds(&self) -> u64 {
        self.config.resource_bind_timeout_seconds
    }

    pub(crate) fn c2s_scram_sha1_enabled(&self) -> bool {
        self.config.scram_sha1_enabled
    }

    pub(crate) fn admin_scram_policy(&self) -> AdminScramPolicy {
        AdminScramPolicy {
            iterations: self.config.scram_iterations,
            sha1_enabled: self.config.scram_sha1_enabled,
        }
    }

    pub(crate) fn admin_activity_idle_seconds(&self) -> u64 {
        self.config.admin_idle_seconds
    }

    pub(crate) fn xmpp_service_control_enabled(&self) -> bool {
        self.config.enable_xmpp_service_control
    }

    pub(crate) fn mix_muc_mirror_enabled(&self) -> bool {
        self.config.mix_muc_mirror_enabled
    }

    pub(crate) fn xmpp_http_upload_enabled(&self) -> bool {
        self.config.upload_mode.admits_new_uploads()
            && self.xmpp_extension_enabled(northstar_xep_0363::XEP_ID)
    }

    pub(crate) fn upload_slot_limits(&self) -> UploadSlotLimits {
        UploadSlotLimits {
            max_file_bytes: self.config.upload_max_bytes,
            max_files_per_user: self.config.upload_max_files_per_user,
            max_bytes_per_user: self.config.upload_max_bytes_per_user,
            max_retained_files: self.config.upload_storage_max_retained_files,
            max_retained_bytes: self.config.upload_storage_max_retained_bytes,
            max_pending_jobs: self.config.upload_storage_max_pending_jobs,
        }
    }

    pub(crate) fn sasl2_fast_token_policy(&self) -> Sasl2FastTokenPolicy {
        Sasl2FastTokenPolicy {
            enabled: self.config.fast_token_enabled,
            rotation_days: self.config.fast_token_rotation_days,
            ttl_days: self.config.fast_token_ttl_days,
            strong_reauth_max_days: self.config.fast_strong_reauth_max_days,
        }
    }

    pub(crate) fn capacity_session_lease_seconds(&self) -> u64 {
        self.config.capacity_session_lease_seconds
    }

    pub(crate) fn pubsub_owner_limits(&self) -> PubSubOwnerLimits {
        PubSubOwnerLimits {
            max_nodes: self.config.pubsub_max_nodes_per_owner,
            max_storage_bytes: self.config.pubsub_max_storage_bytes_per_owner,
        }
    }

    pub(crate) fn pep_account_quotas(&self) -> crate::services::pubsub::PepQuotas {
        crate::services::pubsub::PepQuotas {
            max_nodes: self.config.pep_max_nodes_per_account,
            max_storage_bytes: self.config.pep_max_storage_bytes_per_account,
        }
    }

    pub(crate) fn validate_routed_message(
        &self,
        root: roxmltree::Node<'_, '_>,
    ) -> Result<(), &'static str> {
        crate::xmpp::xml_util::validate_routed_message(root, &self.config.xmpp_extensions)
    }

    pub(crate) fn archive_requires_encryption(&self) -> bool {
        self.config.require_encrypted_archive
    }

    pub(crate) fn muc_mam_retention_days(&self) -> i64 {
        self.config.muc_mam_retention_days
    }

    pub(crate) fn offline_delivery_limits(&self) -> OfflineDeliveryLimits {
        OfflineDeliveryLimits {
            max_messages: self.config.offline_max_messages_per_account,
            max_bytes: self.config.offline_max_bytes_per_account,
            ttl_days: self.config.offline_message_ttl_days,
        }
    }
}
