//! The PostgreSQL repositories the cluster's workers and listener run on.

pub(crate) struct PostgresClusterAdapters;

impl crate::cluster::ClusterAdapters for PostgresClusterAdapters {
    type ClusterAuthority =
        northstar_session_postgres::cluster_authority_repository::PostgresClusterAuthorityRepository;
    type ReplayMaintenance =
        northstar_session_postgres::cluster_replay_maintenance_repository::PostgresClusterReplayMaintenanceRepository;
    type RouteMaintenance =
        northstar_session_postgres::cluster_session_route_maintenance_repository::PostgresClusterSessionRouteMaintenanceRepository;
    type SessionAuthoritySweep =
        northstar_workflows::session_authority_sweep_repository::PostgresSessionAuthoritySweepRepository;
    type NodeMessageProjection =
        northstar_session_postgres::node_message_projection_repository::PostgresNodeMessageProjectionRepository;
    type SessionTermination =
        northstar_session_postgres::session_termination_authority_repository::PostgresSessionTerminationAuthorityRepository;
    type Replay = northstar_session_postgres::replay_repository::PostgresReplayRepository;
    type RecoveryReplay =
        northstar_session_postgres::replay_repository::PostgresRecoveryReplayStore;
    type MucOccupancyMaintenance =
        northstar_room_postgres::room::PostgresClusterMucOccupancyMaintenanceRepository;
    type MucOutboxPreclaim =
        northstar_room_postgres::cluster_muc_outbox_preclaim_repository::PostgresClusterMucOutboxPreclaimRepository;
    type MucOutboxClaim =
        northstar_room_postgres::cluster_muc_outbox_claim_repository::PostgresClusterMucOutboxClaimRepository;
    type MucOutboxSettlement =
        northstar_room_postgres::cluster_muc_outbox_settlement_repository::PostgresClusterMucOutboxSettlementRepository;
    type MucOutboxHousekeeping =
        northstar_room_postgres::cluster_muc_outbox_housekeeping_repository::PostgresClusterMucOutboxHousekeepingRepository;
    type MucDeliveryRead =
        northstar_room_postgres::cluster_muc_delivery_read_repository::PostgresClusterMucDeliveryReadRepository;
    type MucDeliveryItem =
        northstar_room_postgres::cluster_muc_delivery_item_repository::PostgresClusterMucDeliveryItemRepository;
    type Mix = northstar_workflows::room_effects::PostgresMixRepository;
    type SmTeardownMuc =
        northstar_workflows::sm_teardown_muc_repository::PostgresSmTeardownMucRepository;
    type Message = northstar_workflows::message_repository::PostgresMessageRepository;
    type DirectSpoolWake =
        northstar_message_postgres::direct_spool_wake::PostgresDirectSpoolWakeRepository;
    type Presence = crate::db::presence_repository::PostgresPresenceRepository;
}
