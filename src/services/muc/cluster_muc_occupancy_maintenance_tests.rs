use super::*;
use std::sync::Mutex;

struct StubRepository {
    target: ClusterMucOccupancyTarget,
    renewal: Mutex<Option<(ClusterMucOccupancyTarget, String, Duration)>>,
}

impl ClusterMucOccupancyMaintenanceRepository for &StubRepository {
    async fn authoritative_for_node(
        &self,
        node_id: &str,
    ) -> Result<Vec<ClusterMucOccupancyTarget>> {
        assert_eq!(node_id, "node-1");
        Ok(vec![self.target.clone()])
    }

    async fn resolve_exact_batch(
        &self,
        candidates: &[MucOccupancyLookup],
        owner_node_id: &str,
    ) -> Result<Vec<MucResolvedOccupancy>> {
        assert_eq!(owner_node_id, "node-1");
        Ok(candidates
            .iter()
            .filter(|candidate| {
                candidate.full_jid == self.target.full_jid
                    && candidate.nick == self.target.nick
                    && candidate.occupant_incarnation == self.target.occupant_incarnation
                    && candidate.connection_uuid == self.target.connection_uuid
            })
            .map(|candidate| MucResolvedOccupancy {
                room_localpart: candidate.room_localpart.clone(),
                target: self.target.clone(),
            })
            .collect())
    }

    async fn committed_terminal_exact_batch(
        &self,
        _candidates: &[MucOccupancyLookup],
        owner_node_id: &str,
    ) -> Result<Vec<MucOccupancyLookup>> {
        assert_eq!(owner_node_id, "node-1");
        Ok(Vec::new())
    }

    async fn renew_exact(
        &self,
        target: &ClusterMucOccupancyTarget,
        owner_node_id: &str,
        lease: Duration,
    ) -> Result<bool> {
        *self.renewal.lock().unwrap() = Some((target.clone(), owner_node_id.to_owned(), lease));
        Ok(true)
    }

    async fn renew_exact_batch(
        &self,
        targets: &[ClusterMucOccupancyTarget],
        owner_node_id: &str,
        lease: Duration,
    ) -> Result<Vec<ClusterMucOccupancyTarget>> {
        assert_eq!(targets, std::slice::from_ref(&self.target));
        *self.renewal.lock().unwrap() = Some((targets[0].clone(), owner_node_id.to_owned(), lease));
        Ok(targets.to_vec())
    }
}

#[tokio::test]
async fn maintenance_renews_the_snapshot_target_with_the_fixed_lease() {
    let target = ClusterMucOccupancyTarget {
        room_id: Uuid::new_v4(),
        room_epoch: Uuid::new_v4(),
        occupant_incarnation: Uuid::new_v4(),
        occupancy_epoch: 7,
        full_jid: "alice@example.test/Phone".to_owned(),
        nick: "Alice".to_owned(),
        connection_uuid: Uuid::new_v4(),
        connection_epoch: 9,
    };
    let repository = StubRepository {
        target: target.clone(),
        renewal: Mutex::new(None),
    };
    let service = ClusterMucOccupancyMaintenanceService::new(&repository);
    let snapshot = service.authoritative_for_node("node-1").await.unwrap();
    assert_eq!(snapshot, vec![target.clone()]);
    let lookup = MucOccupancyLookup::new(
        "room@muc.example.test",
        &target.full_jid,
        &target.nick,
        target.occupant_incarnation,
        target.connection_uuid,
    )
    .unwrap();
    assert_eq!(
        service
            .resolve_exact_batch(std::slice::from_ref(&lookup), "node-1")
            .await
            .unwrap(),
        vec![MucResolvedOccupancy {
            room_localpart: "room".to_owned(),
            target: target.clone(),
        }]
    );
    assert!(service.renew_exact(&snapshot[0], "node-1").await.unwrap());
    assert_eq!(
        *repository.renewal.lock().unwrap(),
        Some((
            snapshot[0].clone(),
            "node-1".to_owned(),
            Duration::from_secs(90)
        ))
    );
    assert_eq!(
        service
            .renew_exact_batch(std::slice::from_ref(&target), "node-1")
            .await
            .unwrap(),
        vec![target.clone()]
    );
    assert!(service
        .renew_exact_batch(&[target.clone(), target.clone()], "node-1")
        .await
        .is_err());
    assert!(service
        .renew_exact_batch(&vec![target; MAX_MUC_OCCUPANCY_RENEW_BATCH + 1], "node-1")
        .await
        .is_err());
}
