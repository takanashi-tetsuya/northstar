//! The session context as the composition root builds it: stream management, offline replay, the SM
//! memory governor and the supervised SM suspension recovery queue.

use crate::node::*;

/// The session context's live state, built once at startup.
pub(in crate::node) struct SessionLiveState {
    bosh: Option<northstar_bosh::BoshManager>,
    sessions: LocalSessionTable,
    /// XEP-0115 entries are inserted only after the advertised verification
    /// string has been recomputed successfully. Unverified payloads never
    /// enter this shared cache.
    caps_cache: Arc<northstar_protocol_runtime::caps::CapsCacheIndex>,
    caps_by_jid: Arc<northstar_protocol_runtime::caps::CapsResourceIndex>,
    pending_caps: Arc<northstar_protocol_runtime::caps::PendingCapsIndex>,
    /// Cross-stream ordering authority for one authenticated federated full
    /// JID's capability lifecycle. Weak, self-cleaning entries exist only
    /// while an observer or response owns or waits for the resource.
    federated_caps_gates: Arc<northstar_protocol_runtime::caps::FederatedCapsGateIndex>,
    /// Bounded, per-full-JID single-flight boundary for XEP-0115-triggered
    /// PEP last-item delivery and verified MIX presence publication.
    caps_effect_dispatcher: Arc<northstar_protocol_runtime::caps::CapsEffectDispatcher>,
    /// Shared client connection admission authority.
    client_admission: Arc<northstar_stream::client_admission::ClientAdmission>,
    connection_actors: northstar_runtime::connection_actors::ConnectionActorRegistry,
}

/// Already-constructed values owned by the session context.
pub(in crate::node) struct SessionLiveParts {
    pub(in crate::node) bosh: Option<northstar_bosh::BoshManager>,
    pub(in crate::node) sessions: LocalSessionTable,
    pub(in crate::node) caps_cache: Arc<northstar_protocol_runtime::caps::CapsCacheIndex>,
    pub(in crate::node) caps_by_jid: Arc<northstar_protocol_runtime::caps::CapsResourceIndex>,
    pub(in crate::node) pending_caps: Arc<northstar_protocol_runtime::caps::PendingCapsIndex>,
    pub(in crate::node) federated_caps_gates:
        Arc<northstar_protocol_runtime::caps::FederatedCapsGateIndex>,
    pub(in crate::node) caps_effect_dispatcher:
        Arc<northstar_protocol_runtime::caps::CapsEffectDispatcher>,
    pub(in crate::node) client_admission: Arc<northstar_stream::client_admission::ClientAdmission>,
    pub(in crate::node) connection_actors:
        northstar_runtime::connection_actors::ConnectionActorRegistry,
}

impl SessionLiveState {
    pub(in crate::node) fn new(parts: SessionLiveParts) -> Self {
        Self {
            bosh: parts.bosh,
            sessions: parts.sessions,
            caps_cache: parts.caps_cache,
            caps_by_jid: parts.caps_by_jid,
            pending_caps: parts.pending_caps,
            federated_caps_gates: parts.federated_caps_gates,
            caps_effect_dispatcher: parts.caps_effect_dispatcher,
            client_admission: parts.client_admission,
            connection_actors: parts.connection_actors,
        }
    }

    pub(in crate::node) fn bosh(&self) -> Option<&northstar_bosh::BoshManager> {
        self.bosh.as_ref()
    }

    pub(in crate::node) fn sessions(&self) -> &LocalSessionTable {
        &self.sessions
    }

    pub(in crate::node) fn caps_cache(
        &self,
    ) -> &Arc<northstar_protocol_runtime::caps::CapsCacheIndex> {
        &self.caps_cache
    }

    pub(in crate::node) fn caps_by_jid(
        &self,
    ) -> &Arc<northstar_protocol_runtime::caps::CapsResourceIndex> {
        &self.caps_by_jid
    }

    pub(in crate::node) fn pending_caps(
        &self,
    ) -> &Arc<northstar_protocol_runtime::caps::PendingCapsIndex> {
        &self.pending_caps
    }

    pub(in crate::node) fn federated_caps_gates(
        &self,
    ) -> &Arc<northstar_protocol_runtime::caps::FederatedCapsGateIndex> {
        &self.federated_caps_gates
    }

    pub(in crate::node) fn caps_effect_dispatcher(
        &self,
    ) -> &Arc<northstar_protocol_runtime::caps::CapsEffectDispatcher> {
        &self.caps_effect_dispatcher
    }

    pub(in crate::node) fn client_admission(
        &self,
    ) -> &Arc<northstar_stream::client_admission::ClientAdmission> {
        &self.client_admission
    }

    pub(in crate::node) fn connection_actors(
        &self,
    ) -> &northstar_runtime::connection_actors::ConnectionActorRegistry {
        &self.connection_actors
    }
}

/// The session context's services, built once at startup.
pub(in crate::node) struct SessionModule {
    live: SessionLiveState,
    pub(in crate::node) sm_teardown_presence_service: northstar_session_application::sm_teardown_presence::SmTeardownPresenceService<
        northstar_workflows::sm_teardown_presence_repository::PostgresSmTeardownPresenceRepository,
    >,
    pub(in crate::node) cluster_instance_release_service: northstar_session_application::cluster_instance_release::ClusterInstanceReleaseService<
        northstar_session_postgres::cluster_instance_release_repository::PostgresClusterInstanceReleaseRepository,
    >,
    pub(in crate::node) cluster_authority_service: northstar_session_application::cluster_authority::ClusterAuthorityService<
        northstar_session_postgres::cluster_authority_repository::PostgresClusterAuthorityRepository,
    >,
    pub(in crate::node) sm_service: northstar_session_application::sm::SmService<
        northstar_workflows::sm_repository::PostgresSmRepository,
    >,
    pub(in crate::node) replay_service: northstar_session_application::replay::ReplayService<
        northstar_session_postgres::replay_repository::PostgresReplayRepository,
    >,
    /// Supervised retry ownership for an exact SM suspension whose database
    /// outcome was an error or timeout. The corresponding MUC FIFO remains
    /// sealed until this queue proves a durable handoff.
    pub(in crate::node) sm_suspension_recovery:
        Arc<northstar_stream::session_cleanup::recovery::SmSuspensionRecoveryQueue>,
    pub(in crate::node) sm_memory_governor:
        Arc<northstar_session_application::sm_capacity::SmMemoryGovernor>,
}

/// What the session context is built from.
pub(in crate::node) struct SessionModuleParts<'a> {
    pub(in crate::node) live: SessionLiveState,
    pub(in crate::node) config: &'a Config,
    pub(in crate::node) pool: &'a PgPool,
    pub(in crate::node) fast_token_secret: &'a Arc<Zeroizing<Vec<u8>>>,
    pub(in crate::node) sm_authority_schema: String,
}

impl SessionModule {
    pub(in crate::node) fn live(&self) -> &SessionLiveState {
        &self.live
    }

    pub(in crate::node) fn sm_teardown_presence_service(
        &self,
    ) -> &northstar_session_application::sm_teardown_presence::SmTeardownPresenceService<
        northstar_workflows::sm_teardown_presence_repository::PostgresSmTeardownPresenceRepository,
    > {
        &self.sm_teardown_presence_service
    }

    pub(crate) fn sm_service(
        &self,
    ) -> &northstar_session_application::sm::SmService<
        northstar_workflows::sm_repository::PostgresSmRepository,
    > {
        &self.sm_service
    }

    pub(crate) fn replay_service(
        &self,
    ) -> &northstar_session_application::replay::ReplayService<
        northstar_session_postgres::replay_repository::PostgresReplayRepository,
    > {
        &self.replay_service
    }

    pub(crate) fn cluster_authority_service(
        &self,
    ) -> &northstar_session_application::cluster_authority::ClusterAuthorityService<
        northstar_session_postgres::cluster_authority_repository::PostgresClusterAuthorityRepository,
    >{
        &self.cluster_authority_service
    }

    pub(crate) fn cluster_instance_release_service(
        &self,
    ) -> &northstar_session_application::cluster_instance_release::ClusterInstanceReleaseService<
        northstar_session_postgres::cluster_instance_release_repository::PostgresClusterInstanceReleaseRepository,
    >{
        &self.cluster_instance_release_service
    }

    /// Builds the services over the primary pool, with one capacity metrics sink shared by the
    /// memory governor and the recovery queue.
    pub(in crate::node) fn new(parts: SessionModuleParts<'_>) -> anyhow::Result<Self> {
        let SessionModuleParts {
            live,
            config,
            pool,
            fast_token_secret,
            sm_authority_schema,
        } = parts;
        let sm_capacity_metrics =
            Arc::new(northstar_session_application::sm_capacity::SmCapacityMetrics::default());
        let sm_memory_governor = northstar_session_application::sm_capacity::SmMemoryGovernor::new(
            config.sm_memory_budget_bytes,
            config.sm_recovery_max_bytes,
            config.sm_recovery_max_jobs,
            config.sm_max_snapshot_bytes,
            Arc::clone(&sm_capacity_metrics),
        )?;
        Ok(Self {
            live,
            sm_teardown_presence_service: northstar_session_application::sm_teardown_presence::SmTeardownPresenceService::new(
                northstar_workflows::sm_teardown_presence_repository::PostgresSmTeardownPresenceRepository::new(
                    pool.clone(),
                ),
            ),
            cluster_instance_release_service: northstar_session_application::cluster_instance_release::ClusterInstanceReleaseService::new(
                northstar_session_postgres::cluster_instance_release_repository::PostgresClusterInstanceReleaseRepository::new(
                    pool.clone(),
                ),
            ),
            cluster_authority_service: northstar_session_application::cluster_authority::ClusterAuthorityService::new(
                northstar_session_postgres::cluster_authority_repository::PostgresClusterAuthorityRepository::new(
                    pool.clone(),
                ),
            ),
            sm_service: northstar_session_application::sm::SmService::new(
                northstar_workflows::sm_repository::PostgresSmRepository::new(
                    pool.clone(),
                    Arc::clone(fast_token_secret),
                ),
                sm_authority_schema,
            )?,
            replay_service: northstar_session_application::replay::ReplayService::new(
                northstar_session_postgres::replay_repository::PostgresReplayRepository::new(
                    pool.clone(),
                ),
                &config.domain,
                config.offline_message_ttl_days,
            ),
            sm_suspension_recovery:
                northstar_stream::session_cleanup::recovery::SmSuspensionRecoveryQueue::new(
                    config.sm_recovery_max_jobs,
                    config.sm_recovery_max_bytes,
                    sm_capacity_metrics,
                    Arc::clone(&sm_memory_governor),
                ),
            sm_memory_governor,
        })
    }
}
