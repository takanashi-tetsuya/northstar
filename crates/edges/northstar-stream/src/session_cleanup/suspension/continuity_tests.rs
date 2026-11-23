use super::*;
use northstar_room_application::muc_service::{ClusterMucOccupancy, ClusterMucWakeDescriptor};
use std::sync::atomic::{AtomicBool, Ordering};
use uuid::Uuid;

struct Standalone;

impl MucWakePort for Standalone {
    async fn wake(&self, _: &ClusterMucWakeDescriptor) -> Result<()> {
        panic!("no wake descriptor was returned");
    }

    fn record_failure(&self, _: &anyhow::Error) {}
}

impl SmSuspensionCluster for Standalone {
    fn is_enabled(&self) -> bool {
        false
    }
    fn muc_pg_authority(&self) -> bool {
        true
    }
    fn node_id(&self) -> &str {
        "standalone-node"
    }

    async fn register_suspended_muc_occupant(
        &self,
        _: &str,
        _: &str,
        _: Uuid,
        _: &str,
    ) -> Result<bool> {
        panic!("standalone must not project to Redis");
    }
}

struct Repository<'a>(&'a AtomicBool);

impl SmSuspensionRepository for Repository<'_> {
    async fn suspend_exact_session(
        &self,
        _: SmSuspensionRequest<'_>,
        _: SmSuspensionLimits,
    ) -> Result<bool> {
        panic!("the fixture already has a durable SM session");
    }

    async fn append_suspended_stanza(
        &self,
        _: Uuid,
        _: Uuid,
        _: &str,
        _: usize,
        _: usize,
    ) -> Result<bool> {
        panic!("there is no volatile suffix to promote");
    }

    async fn suspend_muc_occupant(
        &self,
        request: MucSuspensionRequest<'_>,
    ) -> Result<Option<ClusterMucOccupancy>> {
        assert!(!self.0.swap(true, Ordering::Relaxed));
        assert_eq!(request.room_localpart, "room");
        assert_eq!(request.node_id, "standalone-node");
        assert_eq!(request.occupant.connection_id, Uuid::from_u128(1));
        assert_eq!(request.occupant.cluster_epoch, Uuid::from_u128(2));
        assert_eq!(request.sm_session_id, Uuid::from_u128(3));
        Ok(None)
    }

    async fn committed_muc_wake(&self, _: Uuid) -> Result<Option<ClusterMucWakeDescriptor>> {
        panic!("failed PG transitions must not wake an operation");
    }
}

#[tokio::test]
async fn standalone_durable_promotion_runs_the_postgres_transition() {
    let called = AtomicBool::new(false);
    let session = Uuid::from_u128(3);
    let endpoint = Arc::new(SuspendedMucEndpoint::new_durable(session));
    let occupants = Arc::new(DashMap::new());
    occupants.insert(
        "room/Alice".to_owned(),
        MucOccupant {
            full_jid: "alice@local.test/phone".to_owned(),
            room_jid: "room@conference.local.test".to_owned(),
            nick: "Alice".to_owned(),
            endpoint: MucOccupantEndpoint::Suspended(Arc::clone(&endpoint)),
            affiliation: "owner".to_owned(),
            role: "moderator".to_owned(),
            room_non_anonymous: true,
            occupant_id: "id".to_owned(),
            cluster_epoch: Uuid::from_u128(2),
            connection_id: Uuid::from_u128(1),
            sm_session_id: Some(session),
            payload: String::new(),
        },
    );
    let context = SmSuspensionContext::new(
        Repository(&called),
        SmSuspensionLimits {
            max_stanzas: 8,
            max_bytes: 4096,
        },
        occupants,
        Standalone,
    );
    assert!(!context.mark_suspended_muc_durable(vec![endpoint]).await);
    assert!(called.load(Ordering::Relaxed));
}
