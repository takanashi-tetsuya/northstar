use super::*;
use crate::state::RouteIncarnationSignal;
use std::time::Instant;
use tokio_util::sync::CancellationToken;

fn session(connection_id: Uuid, routable: bool) -> OnlineSession {
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
    }
}

#[test]
fn registration_cache_updates_the_original_flag_and_preserves_dependency_lock() {
    let shared = Arc::new(AtomicBool::new(true));
    let cache = LocalRegistrationCache::new(false, Arc::clone(&shared));
    cache.apply_current_closed(false);
    assert!(!shared.load(Ordering::Acquire));
    cache.apply_current_closed(true);
    assert!(shared.load(Ordering::Acquire));
    let locked = LocalRegistrationCache::new(true, Arc::clone(&shared));
    locked.apply_current_closed(false);
    assert!(shared.load(Ordering::Acquire));
}

#[test]
fn snapshot_uses_shared_sessions_including_pending_and_survives_route_replacement() {
    let shared = Arc::new(DashMap::new());
    let lookup = LocalAdminSessions::new(Arc::clone(&shared));
    let old_id = Uuid::new_v4();
    let mut pending = session(old_id, false);
    pending.auth_generation = 17;
    let expected_user = pending.user_id;
    let old_cancel = pending.disconnect.clone();
    shared.insert("alice@example.test/fixture".into(), pending);
    let old = lookup.exact_connection(old_id).unwrap();
    assert_eq!(
        old,
        SessionKickSnapshot {
            user_id: expected_user,
            auth_generation: 17,
            connection_id: old_id
        }
    );
    let new_id = Uuid::new_v4();
    let replacement = session(new_id, true);
    let new_cancel = replacement.disconnect.clone();
    // This write uses the same map shard; the snapshot must not own its guard.
    shared.insert("alice@example.test/fixture".into(), replacement);
    assert!(lookup.exact_connection(old_id).is_none());
    assert_eq!(
        lookup.exact_connection(new_id).unwrap().connection_id,
        new_id
    );
    assert_eq!(old.connection_id, old_id);
    assert_eq!(old.auth_generation, 17);
    assert!(!old_cancel.is_cancelled());
    assert!(!new_cancel.is_cancelled());
}
