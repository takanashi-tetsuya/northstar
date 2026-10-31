//! AppState worker contexts, connection admission, component credentials and runtime registries.

use super::*;
use crate::api::contexts::ReadinessContext;

impl AppState {
    pub(crate) fn background_housekeeping_counters(
        &self,
    ) -> crate::services::background_housekeeping::BackgroundHousekeepingCounters {
        crate::services::background_housekeeping::BackgroundHousekeepingCounters::new(
            Arc::clone(&self.metrics.retention_moderation_cases_deleted_total),
            Arc::clone(&self.metrics.background_maintenance_failures_total),
        )
    }

    pub(crate) fn background_housekeeping_context(
        &self,
        counters: crate::services::background_housekeeping::BackgroundHousekeepingCounters,
    ) -> crate::services::background_housekeeping::BackgroundHousekeepingContext<
        db::background_housekeeping_repository::PostgresBackgroundHousekeepingRepository,
    > {
        crate::services::background_housekeeping::BackgroundHousekeepingContext::new(
            db::background_housekeeping_repository::PostgresBackgroundHousekeepingRepository::new(
                self.pool.clone(),
            ),
            self.config.moderation_retention_days,
            self.config.retention_cleanup_batch_size,
            counters,
        )
    }

    pub(crate) fn retention_context(
        &self,
    ) -> crate::runtime::retention::RetentionContext<db::retention::PostgresMaintenanceRepository>
    {
        crate::runtime::retention::RetentionContext::new(
            db::retention::PostgresMaintenanceRepository::new(self.pool.clone()),
            crate::runtime::retention::RetentionPolicy::from_config(&self.config),
            crate::runtime::retention::RetentionCounters::from_metrics(&self.metrics),
        )
    }

    pub(crate) fn retention_worker_max_silence(&self) -> Duration {
        Duration::from_secs(
            self.config
                .retention_cleanup_interval_seconds
                .saturating_mul(2)
                .saturating_add(60),
        )
    }

    pub(crate) fn subscription_cleanup_context(
        &self,
    ) -> crate::runtime::subscription_cleanup::SubscriptionCleanupContext<
        db::retention::PostgresMaintenanceRepository,
    > {
        crate::runtime::subscription_cleanup::SubscriptionCleanupContext::new(
            db::retention::PostgresMaintenanceRepository::new(self.pool.clone()),
            Arc::clone(&self.metrics.subscription_cleanup),
        )
    }

    pub(crate) fn abuse_key_authority_probe(
        &self,
    ) -> crate::services::readiness::AbuseKeyAuthorityProbe<
        db::readiness_repository::PostgresReadinessRepository,
    > {
        self.readiness_service.abuse_key_authority_probe()
    }

    pub(crate) fn readiness_context(&self) -> ReadinessContext {
        ReadinessContext {
            connection: self.connection_actors.readiness_probe(),
            sm: self.sm_memory_governor.readiness_probe(),
            upload: self.upload.safety_gate.readiness_probe(),
            cluster: self.cluster.readiness_probe(),
            workers: self.workers.readiness_probe(),
            abuse_key_deployment: self.abuse.abuse_key_deployment.clone(),
            persistence: self.readiness_service.clone(),
        }
    }

    pub(crate) fn http_transport_policy(&self) -> HttpTransportPolicy {
        HttpTransportPolicy::new(
            self.config.trusted_proxy_ips.clone(),
            Arc::clone(&self.metrics.http_insecure_requests_rejected_total),
            Arc::clone(&self.http_body_admission),
        )
    }

    pub(crate) fn admin_gateway_verifier(&self) -> AdminGatewayVerifier {
        AdminGatewayVerifier::new(self.web_admin_gateway_token.clone())
    }

    pub(crate) fn capacity_lease_renewal_context(&self) -> CapacityLeaseRenewalContext {
        capacity_maintenance::CapacityLeaseRenewalContext::new(
            crate::services::capacity_maintenance::CapacityMaintenanceService::new(
                db::capacity_maintenance_repository::PostgresCapacityMaintenanceRepository::new(
                    self.pool.clone(),
                ),
            ),
            Arc::clone(&self.sessions),
            Arc::clone(&self.metrics),
            Duration::from_secs(self.config.capacity_session_heartbeat_seconds),
            self.config.capacity_session_lease_seconds,
        )
    }

    /// Process-local XEP-0124/XEP-0206 session authority. Transport handlers
    /// may submit bounded manager operations but cannot replace the manager.
    pub(crate) fn bosh_manager(&self) -> &crate::bosh::BoshManager {
        self.bosh
            .as_ref()
            .expect("BOSH routes exist only when the capability runtime is enabled")
    }

    /// Cached ordinary DNS resolver used only by the federation discovery
    /// layer. Keeping it private prevents unrelated code from bypassing the
    /// S2S endpoint-validation path.
    pub(crate) fn s2s_dns_resolver(&self) -> &TokioResolver {
        &self.s2s_dns_resolver
    }

    /// Locally validating resolver dedicated to DANE policy construction.
    pub(crate) fn s2s_dnssec_resolver(&self) -> Option<&TokioResolver> {
        self.s2s_dnssec_resolver.as_ref()
    }

    /// Admit one bounded authoritative dialback verification without exposing
    /// or allowing replacement of the underlying global semaphore.
    pub(crate) fn try_acquire_dialback_verification(
        &self,
    ) -> std::result::Result<OwnedSemaphorePermit, tokio::sync::TryAcquireError> {
        Arc::clone(&self.dialback_verifications).try_acquire_owned()
    }

    /// Admit one process-local federation connection while keeping the global
    /// capacity semaphore replace-proof and unavailable to unrelated code.
    pub(crate) fn try_acquire_s2s_connection(
        &self,
    ) -> std::result::Result<OwnedSemaphorePermit, tokio::sync::TryAcquireError> {
        Arc::clone(&self.s2s_connections).try_acquire_owned()
    }

    /// Wait for one bounded outbound federation dial attempt. Returning the
    /// original acquire error preserves the caller's existing timeout and
    /// closed-semaphore diagnostics.
    pub(crate) async fn acquire_s2s_connection_attempt(
        &self,
    ) -> std::result::Result<OwnedSemaphorePermit, tokio::sync::AcquireError> {
        Arc::clone(&self.s2s_connection_attempts)
            .acquire_owned()
            .await
    }

    /// Owner-fenced process-local S2S route registry. Its API returns cloned
    /// senders and value snapshots only; callers cannot obtain DashMap guards.
    pub(crate) fn s2s_connection_registry(&self) -> &crate::s2s::S2sConnectionRegistry {
        &self.s2s_connection_registry
    }

    /// Admit an inbound component socket without exposing the semaphore as a
    /// generally clonable capability.
    pub(crate) fn try_acquire_component_connection(
        &self,
    ) -> std::result::Result<OwnedSemaphorePermit, tokio::sync::TryAcquireError> {
        Arc::clone(&self.component_connections).try_acquire_owned()
    }

    /// Wait for a component slot while preserving cancellation through the
    /// caller's `select!` and the original closed-semaphore error.
    pub(crate) async fn acquire_component_connection(
        &self,
    ) -> std::result::Result<OwnedSemaphorePermit, tokio::sync::AcquireError> {
        Arc::clone(&self.component_connections)
            .acquire_owned()
            .await
    }

    /// Read the federation kill switch with acquire ordering so a caller that
    /// observes an applied value also observes the preceding policy update.
    pub(crate) fn island_mode_enabled(&self) -> bool {
        self.federation_write_policy.enabled()
    }

    /// Acquire the application-stanza write boundary and revalidate island
    /// mode after route admission. The caller holds the returned guard over
    /// the socket write, making a completed policy transition linearizable.
    pub(crate) async fn federation_delivery_permit(
        &self,
    ) -> Option<tokio::sync::RwLockReadGuard<'_, ()>> {
        self.federation_write_policy.permit().await
    }

    /// Read the public-registration kill switch with acquire ordering.
    pub(crate) fn registration_is_closed(&self) -> bool {
        self.config.registration_dependency_locked()
            || self.registration_closed.load(Ordering::Acquire)
    }

    pub(crate) fn registration_mode(&self) -> northstar_config::RegistrationMode {
        if self.registration_is_closed() {
            northstar_config::RegistrationMode::Closed
        } else {
            self.config.configured_registration_mode()
        }
    }

    pub(crate) fn registration_requires_invitation(&self) -> bool {
        self.registration_mode() == northstar_config::RegistrationMode::InvitationOnly
    }

    pub(crate) fn http_registration_availability(
        &self,
    ) -> northstar_auth_application::account::HttpRegistrationAvailability {
        northstar_auth_application::account::HttpRegistrationAvailability::new(
            Arc::clone(&self.registration_closed),
            self.config.registration_dependency_locked(),
            self.config.configured_registration_mode()
                == northstar_config::RegistrationMode::InvitationOnly,
        )
    }

    pub(crate) fn worker_registry(&self) -> &Arc<northstar_runtime::workers::WorkerRegistry> {
        &self.workers
    }

    pub(crate) fn sm_suspension_context(
        &self,
    ) -> suspension::SmSuspensionContext<db::sm_suspension::PostgresSmSuspensionRepository> {
        suspension::SmSuspensionContext::new(
            db::sm_suspension::PostgresSmSuspensionRepository::new(self.pool.clone()),
            crate::services::sm_suspension::SmSuspensionLimits {
                max_stanzas: self.config.sm_max_unacked_stanzas,
                max_bytes: self.config.sm_max_unacked_bytes,
            },
            Arc::clone(&self.muc_occupants),
            self.cluster.sm_suspension(),
        )
    }

    pub(crate) fn sm_suspension_recovery_queue(
        &self,
    ) -> &Arc<crate::state::session_cleanup::SmSuspensionRecoveryQueue> {
        &self.sm_suspension_recovery
    }

    pub(crate) fn sm_memory_governor(
        &self,
    ) -> &Arc<crate::services::sm_capacity::SmMemoryGovernor> {
        &self.sm_memory_governor
    }

    pub(crate) fn connection_actors(
        &self,
    ) -> &northstar_runtime::connection_actors::ConnectionActorRegistry {
        &self.connection_actors
    }

    pub(crate) fn caps_effect_dispatcher(
        &self,
    ) -> &Arc<northstar_protocol_runtime::caps::CapsEffectDispatcher> {
        &self.caps_effect_dispatcher
    }

    pub(crate) fn pending_mix_iq(&self) -> &northstar_protocol_runtime::mix::MixIqRelayIndex {
        self.pending_mix_iq.as_ref()
    }

    pub(crate) fn caps_cache(&self) -> &northstar_protocol_runtime::caps::CapsCacheIndex {
        &self.caps_cache
    }

    pub(crate) fn caps_by_jid(&self) -> &northstar_protocol_runtime::caps::CapsResourceIndex {
        &self.caps_by_jid
    }

    pub(crate) fn pending_caps(&self) -> &northstar_protocol_runtime::caps::PendingCapsIndex {
        &self.pending_caps
    }

    pub(crate) fn federated_caps_gates(
        &self,
    ) -> &northstar_protocol_runtime::caps::FederatedCapsGateIndex {
        &self.federated_caps_gates
    }

    pub(crate) fn abuse_key_deployment(
        &self,
    ) -> Option<&northstar_abuse_application::guard::records::AbuseKeyDeploymentIdentity> {
        self.abuse.abuse_key_deployment.as_ref()
    }

    pub(crate) fn upload_store(&self) -> &dyn UploadStore {
        self.upload
            .store
            .as_deref()
            .expect("upload routes and workers require an enabled or draining runtime")
    }

    pub(crate) fn admin_gateway_authentication_enabled(&self) -> bool {
        self.web_admin_gateway_token.is_some()
    }

    pub(crate) fn public_http_bind_address(&self) -> std::net::SocketAddr {
        self.config.http_bind
    }

    pub(crate) fn admin_http_bind_address(&self) -> std::net::SocketAddr {
        self.config.web_admin_bind
    }

    pub(crate) fn has_component_credentials(&self) -> bool {
        !self.component_credentials.is_empty()
    }

    pub(crate) fn component_runtime_policy(&self) -> ComponentRuntimePolicy {
        ComponentRuntimePolicy {
            enabled: self.config.components_enabled,
            max_connections: self.config.max_component_connections,
            handshake_timeout: Duration::from_secs(self.config.component_handshake_timeout_seconds),
            queue_capacity: self.config.component_queue_capacity,
        }
    }

    /// Authenticated external-component ownership and wake-up authority.
    /// The registry exposes only owner-fenced operations; its concurrent map
    /// remains encapsulated inside the component subsystem.
    pub(crate) fn component_registry(&self) -> &crate::s2s::components::ComponentRegistry {
        &self.components
    }

    /// Redacted configured routing domains used by observability and the S2S
    /// outbox exclusion query. Preserve the original Vec semantics, including
    /// configuration order and any duplicates across credentials.
    pub(crate) fn configured_component_domains(&self) -> Vec<String> {
        self.config
            .components
            .iter()
            .flat_map(|credential| credential.allowed_domains.iter().cloned())
            .collect()
    }

    pub(crate) fn component_connect_credentials(
        &self,
    ) -> Vec<northstar_config::ComponentCredential> {
        self.component_credentials
            .iter()
            .filter(|credential| {
                credential.connection == northstar_config::ComponentConnectionMode::Connect
            })
            .cloned()
            .collect()
    }

    pub(crate) fn accepts_component_connections(&self) -> bool {
        self.component_credentials.iter().any(|credential| {
            credential.connection == northstar_config::ComponentConnectionMode::Accept
        })
    }

    pub(crate) fn component_authentication_credential(
        &self,
        domain: &str,
    ) -> Option<northstar_config::ComponentCredential> {
        let domain = northstar_xmpp_types::jid::prepare_domainpart(domain).ok()?;
        self.component_credentials
            .iter()
            .find(|credential| {
                credential
                    .allowed_domains
                    .iter()
                    .any(|allowed| allowed == &domain)
            })
            .cloned()
    }

    pub(crate) fn upload_maintenance_context(
        &self,
    ) -> Option<
        northstar_upload_application::worker::UploadMaintenanceContext<
            northstar_upload_postgres::maintenance::PostgresUploadMaintenanceRepository,
        >,
    > {
        Some(
            northstar_upload_application::worker::UploadMaintenanceContext::new(
                northstar_upload_postgres::maintenance::PostgresUploadMaintenanceRepository::new(
                    self.upload.storage_pool.as_ref()?.clone(),
                ),
                Arc::clone(self.upload.store.as_ref()?),
                northstar_upload_application::worker::UploadMaintenancePolicy {
                    max_pending_jobs: self.config.upload_storage_max_pending_jobs,
                    max_retained_files: self.config.upload_storage_max_retained_files,
                    max_retained_bytes: self.config.upload_storage_max_retained_bytes,
                    retention_seconds: self.config.upload_retention_seconds,
                    namespace_sha256: self.upload.namespace_sha256,
                    generation: self.upload.authority_generation,
                },
                Arc::clone(&self.upload.safety_gate),
                Arc::clone(&self.upload.startup_audits),
                Arc::clone(&self.metrics),
            ),
        )
    }
}
