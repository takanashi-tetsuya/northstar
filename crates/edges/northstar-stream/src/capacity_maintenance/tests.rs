use super::*;
use northstar_session_application::RouteIncarnationSignal;
use std::{
    collections::HashSet,
    sync::{atomic::AtomicBool, Mutex},
    time::Instant,
};
use tokio::sync::Notify;
use tokio_util::task::AbortOnDropHandle;
use uuid::Uuid;

const TEST_START_TIMEOUT: Duration = Duration::from_secs(5);
const TEST_JOIN_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone)]
struct ControlledRepository {
    started: Arc<Notify>,
    release: Arc<Notify>,
    block: bool,
    fail: bool,
    calls: Arc<Mutex<Vec<Vec<Uuid>>>>,
    future_dropped: Arc<AtomicBool>,
    refreshed: HashSet<Uuid>,
}

struct DropWitness(Arc<AtomicBool>);
impl Drop for DropWitness {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

impl ControlledRepository {
    fn new(block: bool, fail: bool) -> Self {
        Self {
            started: Arc::new(Notify::new()),
            release: Arc::new(Notify::new()),
            block,
            fail,
            calls: Arc::new(Mutex::new(Vec::new())),
            future_dropped: Arc::new(AtomicBool::new(false)),
            refreshed: HashSet::new(),
        }
    }
}

impl CapacityMaintenanceRepository for ControlledRepository {
    async fn renew_live_connections(
        &self,
        connection_ids: &[Uuid],
        lease_seconds: u64,
    ) -> Result<HashSet<Uuid>> {
        assert_eq!(lease_seconds, 120);
        let _witness = DropWitness(Arc::clone(&self.future_dropped));
        self.calls.lock().unwrap().push(connection_ids.to_vec());
        self.started.notify_one();
        if self.block {
            self.release.notified().await;
        }
        if self.fail {
            anyhow::bail!("fixture database unavailable");
        }
        Ok(self.refreshed.clone())
    }

    async fn try_reap_expired(&self, _: i64) -> Result<Option<u64>> {
        panic!("renewal must not run deployment-wide cleanup");
    }
}

pub(crate) fn session(connection_id: Uuid, routable: bool) -> OnlineSession {
    let (sender, _receiver) = tokio::sync::mpsc::channel(1);
    OnlineSession {
        user_id: Uuid::new_v4(),
        auth_generation: 0,
        user_agent_epoch: None,
        connection_id,
        route_incarnation: RouteIncarnationSignal::new(connection_id),
        lifecycle: Arc::default(),
        metrics_counted: Arc::default(),
        routable: Arc::new(AtomicBool::new(routable)),
        sender: crate::outbound::OutboundSender::new(sender),
        available: Arc::default(),
        availability_generation: Arc::default(),
        post_actions: northstar_session_application::post_actions::PostActionHandle::default(),
        recovery_replay_inflight_epoch: Arc::default(),
        recovery_replay_completed_epoch: Arc::default(),
        bind2_mam_catchup: false,
        mix_presence_gate: Arc::default(),
        mix_presence_fallback_suppressed: Arc::default(),
        caps_observation_generation: Arc::default(),
        carbons: Arc::default(),
        priority: Arc::default(),
        show: Arc::default(),
        blocklist_requested: Arc::default(),
        roster_requested: Arc::default(),
        roster_sync: Arc::default(),
        mix_roster_annotations: Arc::default(),
        privacy_active: Arc::default(),
        privacy_requested: Arc::default(),
        directed_presence: Arc::default(),
        last_presence: Arc::default(),
        ip: None,
        resource: "fixture".into(),
        user_agent_id: None,
        sm_session_id: Arc::default(),
        muc_memberships: Arc::default(),
        connected_at: Instant::now(),
        last_activity: Arc::new(std::sync::RwLock::new(Instant::now())),
        disconnect: CancellationToken::new(),
        pending_subscription_delivery: Arc::default(),
    }
}

fn context(repository: ControlledRepository) -> CapacityLeaseRenewalContext<ControlledRepository> {
    CapacityLeaseRenewalContext::new(
        CapacityMaintenanceService::new(repository),
        Arc::new(DashMap::new()),
        Arc::new(Metrics::default()),
        Duration::from_secs(30),
        120,
    )
}

#[tokio::test]
async fn database_failure_does_not_disconnect_a_live_connection() {
    let repository = ControlledRepository::new(false, true);
    let context = context(repository);
    let live = session(Uuid::new_v4(), true);
    let disconnect = live.disconnect.clone();
    context
        .sessions
        .insert("alice@example.test/fixture".into(), live);
    let error = context
        .renew_once(&CancellationToken::new())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("could not refresh"));
    assert!(!disconnect.is_cancelled());
    assert_eq!(
        context
            .metrics
            .capacity_session_lease_losses_total
            .load(Ordering::Relaxed),
        0
    );
}

#[tokio::test]
async fn delayed_lease_loss_disconnects_only_the_snapshotted_connection() {
    let mut repository = ControlledRepository::new(true, false);
    let kept_id = Uuid::new_v4();
    repository.refreshed.insert(kept_id);
    let context = context(repository.clone());
    let kept = session(kept_id, true);
    let kept_disconnect = kept.disconnect.clone();
    context
        .sessions
        .insert("kept@example.test/fixture".into(), kept);
    let old_id = Uuid::new_v4();
    let old = session(old_id, true);
    let old_disconnect = old.disconnect.clone();
    context
        .sessions
        .insert("alice@example.test/fixture".into(), old);
    let pending = session(Uuid::new_v4(), false);
    let pending_disconnect = pending.disconnect.clone();
    context
        .sessions
        .insert("pending@example.test/fixture".into(), pending);
    let turn_context = context.clone();
    let turn = AbortOnDropHandle::new(tokio::spawn(async move {
        turn_context.renew_once(&CancellationToken::new()).await
    }));
    tokio::time::timeout(TEST_START_TIMEOUT, repository.started.notified())
        .await
        .expect("renewal did not reach the controlled repository");
    let replacement = session(Uuid::new_v4(), true);
    let replacement_disconnect = replacement.disconnect.clone();
    context
        .sessions
        .insert("alice@example.test/fixture".into(), replacement);
    repository.release.notify_one();
    assert!(tokio::time::timeout(TEST_JOIN_TIMEOUT, turn)
        .await
        .expect("renewal did not finish after the repository was released")
        .unwrap()
        .unwrap());
    assert!(old_disconnect.is_cancelled());
    assert!(!kept_disconnect.is_cancelled());
    assert!(!replacement_disconnect.is_cancelled());
    assert!(!pending_disconnect.is_cancelled());
    let calls = repository.calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(
        calls[0].iter().copied().collect::<HashSet<_>>(),
        HashSet::from([old_id, kept_id])
    );
    assert_eq!(
        context
            .metrics
            .capacity_session_lease_losses_total
            .load(Ordering::Relaxed),
        1
    );
}

#[tokio::test]
async fn cancellation_drops_the_database_future_without_disconnect() {
    let repository = ControlledRepository::new(true, false);
    let context = context(repository.clone());
    let live = session(Uuid::new_v4(), true);
    let disconnect = live.disconnect.clone();
    context
        .sessions
        .insert("alice@example.test/fixture".into(), live);
    let cancel = CancellationToken::new();
    let turn_cancel = cancel.clone();
    let turn_context = context.clone();
    let turn = AbortOnDropHandle::new(tokio::spawn(async move {
        turn_context.renew_once(&turn_cancel).await
    }));
    tokio::time::timeout(TEST_START_TIMEOUT, repository.started.notified())
        .await
        .expect("renewal did not reach the controlled repository");
    cancel.cancel();
    assert!(!tokio::time::timeout(TEST_JOIN_TIMEOUT, turn)
        .await
        .expect("renewal did not stop after cancellation")
        .unwrap()
        .unwrap());
    assert!(repository.future_dropped.load(Ordering::Acquire));
    assert!(!disconnect.is_cancelled());
    assert_eq!(
        context
            .metrics
            .capacity_session_lease_losses_total
            .load(Ordering::Relaxed),
        0
    );
}

#[tokio::test]
async fn timeout_drops_the_database_future_without_disconnect() {
    let repository = ControlledRepository::new(true, false);
    let context = context(repository.clone());
    let live = session(Uuid::new_v4(), true);
    let disconnect = live.disconnect.clone();
    context
        .sessions
        .insert("alice@example.test/fixture".into(), live);
    let error = tokio::time::timeout(
        TEST_JOIN_TIMEOUT,
        context.renew_with_timeout(&CancellationToken::new(), Duration::from_millis(5)),
    )
    .await
    .expect("renewal ignored its database deadline")
    .unwrap_err();
    assert!(error.to_string().contains("refresh timed out"));
    assert!(repository.future_dropped.load(Ordering::Acquire));
    assert!(!disconnect.is_cancelled());
    assert_eq!(
        context
            .metrics
            .capacity_session_lease_losses_total
            .load(Ordering::Relaxed),
        0
    );
}

#[tokio::test]
async fn idle_or_pending_only_node_does_not_query_the_database() {
    let repository = ControlledRepository::new(false, true);
    let context = context(repository.clone());
    assert!(context.renew_once(&CancellationToken::new()).await.unwrap());
    context.sessions.insert(
        "alice@example.test/pending".into(),
        session(Uuid::new_v4(), false),
    );
    assert!(context.renew_once(&CancellationToken::new()).await.unwrap());
    assert!(repository.calls.lock().unwrap().is_empty());
}
