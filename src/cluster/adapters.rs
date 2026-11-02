//! The repositories the cluster's workers and listener run on, as one family of types. The
//! composition root names the PostgreSQL family; the cluster code sees only the application ports.

use northstar_message_application::{
    direct_spool_wake::DirectSpoolWakeRepository, messaging::MessageRepository,
};
use northstar_room_application::{
    cluster_muc_delivery_item::ClusterMucDeliveryItemRepository,
    cluster_muc_delivery_read::ClusterMucDeliveryReadRepository,
    cluster_muc_outbox_claim::ClusterMucOutboxClaimRepository,
    cluster_muc_outbox_housekeeping::ClusterMucOutboxHousekeepingRepository,
    cluster_muc_outbox_preclaim::ClusterMucOutboxPreclaimRepository,
    cluster_muc_outbox_settlement::ClusterMucOutboxSettlementRepository,
    mix_service::MixRepository, muc_service::ClusterMucOccupancyMaintenanceRepository,
    sm_teardown_muc::SmTeardownMucRepository,
};
use northstar_room_core::{
    ClusterMucAudienceSnapshot, ClusterMucEventContext, ClusterMucOutboxDelivery,
};
use northstar_roster_application::presence::PresenceRepository;
use northstar_session_application::{
    cluster_authority::ClusterAuthorityRepository,
    cluster_replay_maintenance::ClusterReplayMaintenanceRepository,
    cluster_session_route_maintenance::ClusterSessionRouteMaintenanceRepository,
    node_message_contract_verifier::NodeMessageProjectionRepository,
    replay::{RecoveryReplayStore, ReplayRepository},
    session_authority_sweep::SessionAuthoritySweepRepository,
    session_termination_authority::SessionTerminationAuthorityRepository,
};

pub trait ClusterAdapters: Send + Sync + 'static {
    type ClusterAuthority: ClusterAuthorityRepository + 'static;
    type ReplayMaintenance: ClusterReplayMaintenanceRepository + 'static;
    type RouteMaintenance: ClusterSessionRouteMaintenanceRepository + 'static;
    type SessionAuthoritySweep: SessionAuthoritySweepRepository + 'static;
    type NodeMessageProjection: NodeMessageProjectionRepository + 'static;
    type SessionTermination: SessionTerminationAuthorityRepository + 'static;
    type Replay: ReplayRepository + Clone + 'static;
    type RecoveryReplay: RecoveryReplayStore + Clone + 'static;
    type MucOccupancyMaintenance: ClusterMucOccupancyMaintenanceRepository + 'static;
    type MucOutboxPreclaim: ClusterMucOutboxPreclaimRepository + 'static;
    type MucOutboxClaim: ClusterMucOutboxClaimRepository<Delivery = ClusterMucOutboxDelivery>
        + 'static;
    type MucOutboxSettlement: ClusterMucOutboxSettlementRepository<Delivery = ClusterMucOutboxDelivery>
        + 'static;
    type MucOutboxHousekeeping: ClusterMucOutboxHousekeepingRepository + 'static;
    type MucDeliveryRead: ClusterMucDeliveryReadRepository<
            Delivery = ClusterMucOutboxDelivery,
            EventContext = ClusterMucEventContext,
            AudienceSnapshot = ClusterMucAudienceSnapshot,
        > + 'static;
    type MucDeliveryItem: ClusterMucDeliveryItemRepository<Delivery = ClusterMucOutboxDelivery>
        + 'static;
    type Mix: MixRepository + 'static;
    type SmTeardownMuc: SmTeardownMucRepository + 'static;
    type Message: MessageRepository + 'static;
    type DirectSpoolWake: DirectSpoolWakeRepository + 'static;
    type Presence: PresenceRepository + 'static;
}
