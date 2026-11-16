//! The room context as the composition root builds it: the MUC and MIX services over their
//! PostgreSQL repositories, the live occupant tables and the locked-room expiry worker's state.

use super::*;
use anyhow::Result;
use northstar_abuse_policy::content_identity::{
    MixMessageContentKeyring, MixRetractionContentKeyring,
};
use northstar_runtime::durable_outbox::DurableOutboxDatabaseAdmission;

/// The room context's services and live tables, built once at startup.
pub(super) struct RoomModule {
    pub(super) sm_teardown_muc_service: northstar_room_application::sm_teardown_muc::SmTeardownMucService<
        northstar_workflows::sm_teardown_muc_repository::PostgresSmTeardownMucRepository,
    >,
    pub(super) cluster_muc_occupancy_maintenance_service: northstar_room_application::muc_service::ClusterMucOccupancyMaintenanceService<
        northstar_room_postgres::room::PostgresClusterMucOccupancyMaintenanceRepository,
    >,
    /// PostgreSQL-authoritative MUC application service. Redis capabilities
    /// deliberately do not cross this boundary.
    pub(super) muc_service: northstar_room_application::muc_service::MucService<northstar_workflows::room_effects::PostgresMucRepository>,
    pub(super) mix_service: northstar_room_application::mix_service::MixService<northstar_workflows::room_effects::PostgresMixRepository>,
    pub(super) muc_occupants: LocalMucOccupantTable,
    /// Exactly one process-local suspension/resume FIFO per durable SM
    /// session.  Every room occupancy for the same client points at this Arc,
    /// preserving cross-room arrival order and enforcing one shared budget.
    pub(super) suspended_muc_sessions: Arc<DashMap<uuid::Uuid, Arc<SuspendedMucEndpoint>>>,
    /// XEP-0403 IQ relay correlations. Keys are server-generated opaque IQ
    /// ids, never client-controlled ids; entries are bounded and short-lived.
    pub(super) pending_mix_iq: Arc<northstar_room_core::mix_iq_relay::MixIqRelayIndex>,
    pub(super) locked_muc_expiry_service: northstar_room_application::locked_muc_expiry::LockedMucExpiryService<
        northstar_room_postgres::locked_muc_expiry_repository::PostgresLockedMucExpiryRepository,
    >,
    pub(super) locked_muc_expiry_context: std::sync::OnceLock<Arc<locked_muc_expiry::LockedMucExpiryContext>>,
}

/// What the room context's services are built from.
pub(super) struct RoomModuleParts<'a> {
    pub(super) config: &'a Config,
    pub(super) pool: &'a PgPool,
    pub(super) mix_message_content_identity: MixMessageContentKeyring,
    pub(super) mix_retraction_content_identity: MixRetractionContentKeyring,
    pub(super) durable_outbox_database_admission: &'a DurableOutboxDatabaseAdmission,
    pub(super) sm_authority_schema: String,
}

impl RoomModule {
    pub(super) fn sm_teardown_muc_service(
        &self,
    ) -> &northstar_room_application::sm_teardown_muc::SmTeardownMucService<
        northstar_workflows::sm_teardown_muc_repository::PostgresSmTeardownMucRepository,
    > {
        &self.sm_teardown_muc_service
    }

    pub(crate) fn mix_service(
        &self,
    ) -> &northstar_room_application::mix_service::MixService<
        northstar_workflows::room_effects::PostgresMixRepository,
    > {
        &self.mix_service
    }

    pub(crate) fn muc_service(
        &self,
    ) -> &northstar_room_application::muc_service::MucService<
        northstar_workflows::room_effects::PostgresMucRepository,
    > {
        &self.muc_service
    }

    pub(crate) fn cluster_muc_occupancy_maintenance_service(
        &self,
    ) -> &northstar_room_application::muc_service::ClusterMucOccupancyMaintenanceService<
        northstar_room_postgres::room::PostgresClusterMucOccupancyMaintenanceRepository,
    > {
        &self.cluster_muc_occupancy_maintenance_service
    }

    /// Builds the services and empty live tables over the primary pool.
    pub(super) fn new(parts: RoomModuleParts<'_>) -> Result<Self> {
        let RoomModuleParts {
            config,
            pool,
            mix_message_content_identity,
            mix_retraction_content_identity,
            durable_outbox_database_admission,
            sm_authority_schema,
        } = parts;
        Ok(Self {
            sm_teardown_muc_service: northstar_room_application::sm_teardown_muc::SmTeardownMucService::new(
                northstar_workflows::sm_teardown_muc_repository::PostgresSmTeardownMucRepository::new(
                    pool.clone(),
                ),
            ),
            cluster_muc_occupancy_maintenance_service: northstar_room_application::muc_service::ClusterMucOccupancyMaintenanceService::new(
                northstar_room_postgres::room::PostgresClusterMucOccupancyMaintenanceRepository::new(
                    pool.clone(),
                ),
            ),
            muc_service: northstar_room_application::muc_service::MucService::new(
                northstar_workflows::room_effects::PostgresMucRepository::new(pool.clone()),
                config.domain.clone(),
            ),
            // The MIX wake broker validates the same schema identity that the
            // dedicated PostgreSQL listener attests.  It never trusts a
            // notification as delivery authority; schema matching only prevents
            // a shared database's unrelated schema from creating local scan load.
            mix_service:
                northstar_room_application::mix_service::MixService::new_with_outbox_database_admission(
                    northstar_workflows::room_effects::PostgresMixRepository::new(pool.clone()),
                    config.domain.clone(),
                    mix_message_content_identity,
                    mix_retraction_content_identity,
                    durable_outbox_database_admission.clone(),
                    sm_authority_schema,
                )?,
            muc_occupants: LocalMucOccupantTable::default(),
            suspended_muc_sessions: Arc::new(DashMap::new()),
            pending_mix_iq: Arc::new(northstar_room_core::mix_iq_relay::MixIqRelayIndex::new()),
            locked_muc_expiry_service:
                northstar_room_application::locked_muc_expiry::LockedMucExpiryService::new(
                    northstar_room_postgres::locked_muc_expiry_repository::PostgresLockedMucExpiryRepository::new(
                        pool.clone(),
                    ),
                ),
            locked_muc_expiry_context: std::sync::OnceLock::new(),
        })
    }
}
