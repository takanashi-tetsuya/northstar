use super::*;
use std::sync::Mutex;

struct StubRepository {
    target: ClusterMucOccupancyTarget,
    leaves: Mutex<Vec<Uuid>>,
}

impl ClusterMucOccupancyDepartureRepository for &StubRepository {
    async fn find_exact_for_disconnect(
        &self,
        room_localpart: &str,
        full_jid: &str,
        nick: &str,
        occupant_incarnation: Uuid,
        connection_uuid: Uuid,
        owner_node_id: &str,
    ) -> Result<Option<ClusterMucOccupancyTarget>> {
        assert_eq!(room_localpart, "room");
        assert_eq!(owner_node_id, "node-1");
        Ok((full_jid == self.target.full_jid
            && nick == self.target.nick
            && occupant_incarnation == self.target.occupant_incarnation
            && connection_uuid == self.target.connection_uuid)
            .then(|| self.target.clone()))
    }

    async fn leave_exact(
        &self,
        operation_id: Uuid,
        target: &ClusterMucOccupancyTarget,
        owner_node_id: &str,
        lease: Duration,
    ) -> Result<ClusterMucTransitionOutcome> {
        assert_eq!(target, &self.target);
        assert_eq!(owner_node_id, "node-1");
        assert_eq!(lease, Duration::from_secs(90));
        self.leaves.lock().unwrap().push(operation_id);
        Ok(ClusterMucTransitionOutcome::Applied)
    }
}

#[tokio::test]
async fn disconnect_leave_is_bound_to_one_stream_and_one_stable_operation() {
    let target = ClusterMucOccupancyTarget {
        room_id: Uuid::new_v4(),
        room_epoch: Uuid::new_v4(),
        occupant_incarnation: Uuid::new_v4(),
        occupancy_epoch: 1,
        full_jid: "alice@example.test/Phone".to_owned(),
        nick: "Alice".to_owned(),
        connection_uuid: Uuid::new_v4(),
        connection_epoch: 1,
    };
    let repository = StubRepository {
        target: target.clone(),
        leaves: Mutex::new(Vec::new()),
    };
    let service = ClusterMucOccupancyDepartureService::new(&repository);
    let resolved = service
        .find_exact_for_disconnect(
            "room@muc.example.test",
            &target.full_jid,
            &target.nick,
            target.occupant_incarnation,
            target.connection_uuid,
            "node-1",
        )
        .await
        .unwrap();
    assert_eq!(resolved, Some(target.clone()));
    assert!(service
        .leave_exact_for_disconnect(Uuid::new_v4(), &target, "node-1")
        .await
        .is_err());
    let first = service
        .leave_exact_for_disconnect(target.connection_uuid, &target, "node-1")
        .await
        .unwrap();
    let replay = service
        .leave_exact_for_disconnect(target.connection_uuid, &target, "node-1")
        .await
        .unwrap();
    assert_eq!(first.operation_id, replay.operation_id);
    assert_eq!(
        repository.leaves.lock().unwrap().as_slice(),
        &[first.operation_id; 2]
    );
}
