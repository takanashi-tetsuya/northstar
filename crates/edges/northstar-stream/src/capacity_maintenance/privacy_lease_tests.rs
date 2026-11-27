use super::*;
use std::collections::HashSet;
use uuid::Uuid;

struct ExactLiveRenewal(Uuid);

impl CapacityMaintenanceRepository for ExactLiveRenewal {
    async fn renew_live_connections(&self, ids: &[Uuid], _: u64) -> Result<HashSet<Uuid>> {
        assert_eq!(ids, &[self.0]);
        Ok(HashSet::from([self.0]))
    }

    async fn try_reap_expired(&self, _: i64) -> Result<Option<u64>> {
        panic!("renewal must not run the reaper")
    }
}

#[tokio::test]
async fn only_published_uncancelled_connection_ids_reach_renewal() {
    let live = Uuid::new_v4();
    let sessions = Arc::new(DashMap::new());
    sessions.insert("one@example.test/live".into(), tests::session(live, true));
    sessions.insert(
        "one@example.test/staged".into(),
        tests::session(Uuid::new_v4(), false),
    );
    let cancelled = tests::session(Uuid::new_v4(), true);
    cancelled.disconnect.cancel();
    sessions.insert("one@example.test/cancelled".into(), cancelled);
    let quiescing = tests::session(Uuid::new_v4(), true);
    quiescing.lifecycle.store(1, Ordering::Release);
    sessions.insert("one@example.test/quiescing".into(), quiescing);
    let context = CapacityLeaseRenewalContext::new(
        CapacityMaintenanceService::new(ExactLiveRenewal(live)),
        sessions,
        Arc::new(Metrics::default()),
        Duration::from_secs(30),
        120,
    );
    assert!(context.renew_once(&CancellationToken::new()).await.unwrap());
}
