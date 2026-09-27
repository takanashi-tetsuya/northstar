//! Exact local C2S wake capability after cluster authority is reconciled.
//! Maintenance may request work, but the owning protocol session controls
//! when that work can start relative to its current transport action.

use super::{AppState, OnlineSession};
use crate::{
    cluster::{ClusterAdmission, ClusterReadinessAuthority, DirectPostCommitMode},
    db,
    metrics::Metrics,
    services::replay::{RecoveryReplayAuthority, ReplayService},
    xmpp::{capabilities::PostActionTelemetry, protocol::replay},
};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use sqlx::PgPool;
use std::{
    collections::BinaryHeap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};
use tokio::sync::Semaphore;
use uuid::Uuid;

const MAX_CONCURRENT_RECOVERY_REPLAYS: usize = 8;
const MAX_RECOVERY_ROUTE_PAGE: usize = 256;

#[derive(Clone)]
pub(crate) struct ClusterRecoveryReplayWake {
    sessions: Arc<DashMap<String, OnlineSession>>,
    replay: ReplayService<db::replay_repository::PostgresReplayRepository>,
    admission: ClusterAdmission,
    pool: PgPool,
    metrics: Arc<Metrics>,
    permits: Arc<Semaphore>,
}

struct PendingRecoveryReplay {
    epoch: u64,
    inflight_epoch: Arc<AtomicU64>,
    completed_epoch: Arc<AtomicU64>,
    completed: bool,
}

impl Drop for PendingRecoveryReplay {
    fn drop(&mut self) {
        if self.completed {
            self.completed_epoch.store(self.epoch, Ordering::Release);
        }
        let _ = self.inflight_epoch.compare_exchange(
            self.epoch,
            0,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RecoveryReplayStatus {
    Complete,
    InFlight,
    Retryable,
    AwaitEligibility,
    Ineligible,
    Stale,
}

fn recovery_epoch_status(session: &OnlineSession, recovery_epoch: u64) -> RecoveryReplayStatus {
    if recovery_epoch != 0
        && session
            .recovery_replay_completed_epoch
            .load(Ordering::Acquire)
            == recovery_epoch
    {
        RecoveryReplayStatus::Complete
    } else if recovery_epoch != 0
        && session
            .recovery_replay_inflight_epoch
            .load(Ordering::Acquire)
            == recovery_epoch
    {
        RecoveryReplayStatus::InFlight
    } else {
        RecoveryReplayStatus::Retryable
    }
}

fn exact_replay_route_is_current(
    sessions: &DashMap<String, OnlineSession>,
    full_jid: &str,
    connection_id: Uuid,
    expected: &OnlineSession,
    expected_generation: u64,
    live: bool,
) -> bool {
    if !live {
        return false;
    }
    sessions.get(full_jid).is_some_and(|current| {
        current.connection_id == connection_id
            && Arc::ptr_eq(&current.route_incarnation, &expected.route_incarnation)
            && current.user_id == expected.user_id
            && current.auth_generation == expected.auth_generation
            && current.routable.load(Ordering::Acquire)
            && current.lifecycle.load(Ordering::Acquire) == 0
            && !current.disconnect.is_cancelled()
            && current.available.load(Ordering::Acquire)
            && current.priority.load(Ordering::Acquire) >= 0
            && current.availability_generation.load(Ordering::Acquire) == expected_generation
    })
}

fn recovery_route_page_after(
    sessions: &DashMap<String, OnlineSession>,
    cursor: Option<&str>,
    limit: usize,
) -> Vec<(String, Uuid)> {
    let limit = limit.min(MAX_RECOVERY_ROUTE_PAGE);
    if limit == 0 {
        return Vec::new();
    }
    // The live session table has no ordered index. Scan it without retaining
    // a map guard or an unbounded copy; the max-heap keeps only the lexical
    // next page even when the node owns many resources.
    let mut next = BinaryHeap::with_capacity(limit);
    for route in sessions.iter() {
        if cursor.is_some_and(|after| route.key().as_str() <= after) {
            continue;
        }
        if !route.routable.load(Ordering::Acquire)
            || route.lifecycle.load(Ordering::Acquire) != 0
            || route.disconnect.is_cancelled()
        {
            continue;
        }
        // Ordinary presence replays an ineligible resource when it later
        // becomes available/nonnegative. Bind2 MAM catch-up deliberately
        // skips that replay, so retain its exact route for a bounded future
        // recovery sweep even while it cannot accept delivery today.
        if (!route.available.load(Ordering::Acquire) || route.priority.load(Ordering::Acquire) < 0)
            && !route.bind2_mam_catchup
        {
            continue;
        }
        next.push((route.key().clone(), route.connection_id));
        if next.len() > limit {
            next.pop();
        }
    }
    let mut page = next.into_vec();
    page.sort_unstable();
    page
}

impl ClusterRecoveryReplayWake {
    pub(crate) fn direct_mode(&self) -> DirectPostCommitMode {
        self.admission.direct_mode()
    }

    /// A database route candidate is not itself a delivery capability. Match
    /// its recipient to the exact local session before interpreting an epoch.
    pub(crate) fn recipient_completion_state(
        &self,
        recipient_id: Uuid,
        full_jid: &str,
        connection_id: Uuid,
        recovery_epoch: u64,
    ) -> RecoveryReplayStatus {
        self.completion_state_checked(full_jid, connection_id, recovery_epoch, Some(recipient_id))
    }

    pub(crate) fn request_for_recipient(
        &self,
        recipient_id: Uuid,
        full_jid: &str,
        connection_id: Uuid,
        cutoff: DateTime<Utc>,
        recovery_epoch: u64,
    ) -> bool {
        self.request_checked(
            full_jid,
            connection_id,
            cutoff,
            recovery_epoch,
            Some(recipient_id),
        )
    }

    /// Observe one exact route after a prior `request`. Maintenance retains
    /// InFlight/Retryable entries. An exact unavailable/negative-priority
    /// Bind2 route awaits a bounded future sweep; other such routes use their
    /// ordinary future presence replay.
    pub(crate) fn completion_state(
        &self,
        full_jid: &str,
        connection_id: Uuid,
        recovery_epoch: u64,
    ) -> RecoveryReplayStatus {
        self.completion_state_checked(full_jid, connection_id, recovery_epoch, None)
    }

    fn completion_state_checked(
        &self,
        full_jid: &str,
        connection_id: Uuid,
        recovery_epoch: u64,
        recipient_id: Option<Uuid>,
    ) -> RecoveryReplayStatus {
        let Some(session) = self.sessions.get(full_jid) else {
            return RecoveryReplayStatus::Stale;
        };
        if session.connection_id != connection_id
            || recipient_id.is_some_and(|recipient_id| session.user_id != recipient_id)
        {
            return RecoveryReplayStatus::Stale;
        }
        let epoch = recovery_epoch_status(&session, recovery_epoch);
        if epoch != RecoveryReplayStatus::Retryable {
            return epoch;
        }
        if !session.routable.load(Ordering::Acquire)
            || session.lifecycle.load(Ordering::Acquire) != 0
            || session.disconnect.is_cancelled()
        {
            RecoveryReplayStatus::Stale
        } else if !session.available.load(Ordering::Acquire)
            || session.priority.load(Ordering::Acquire) < 0
        {
            if session.bind2_mam_catchup {
                RecoveryReplayStatus::AwaitEligibility
            } else {
                RecoveryReplayStatus::Ineligible
            }
        } else {
            RecoveryReplayStatus::Retryable
        }
    }

    /// Return at most 256 exact local route identities in lexical key order.
    /// The caller advances `cursor` only after retaining this bounded page;
    /// a replacement under an earlier key has its own bind/presence replay.
    pub(crate) fn routes_page_after(
        &self,
        cursor: Option<&str>,
        limit: usize,
    ) -> Vec<(String, Uuid)> {
        recovery_route_page_after(&self.sessions, cursor, limit)
    }

    /// Capture one PostgreSQL-clock high-water mark only after all direct
    /// admission transactions holding the exact key/instance rows have
    /// committed. A timeout leaves recovery wake retryable by maintenance.
    pub(crate) async fn barrier(
        &self,
        authority: &ClusterReadinessAuthority,
    ) -> anyhow::Result<DateTime<Utc>> {
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            db::recovery_replay_cutoff_after_direct_commits(&self.pool, authority),
        )
        .await
        .map_err(|_| anyhow::anyhow!("cluster recovery replay cutoff barrier timed out"))?
    }

    fn telemetry(&self) -> PostActionTelemetry<'_> {
        PostActionTelemetry::new(
            &self.metrics.post_action_tasks_started_total,
            &self.metrics.post_action_tasks_completed_total,
            &self.metrics.post_action_tasks_panicked_total,
            &self.metrics.post_action_tasks_aborted_total,
            &self.metrics.post_action_capacity_rejections_total,
        )
    }

    /// Attempt one resource-scoped wake. `false` means the route is stale or
    /// ineligible, or bounded capacity is busy; maintenance may retry on a
    /// later healthy pass. `true` means one task was admitted, or the same
    /// recovery epoch already has an exact task pending for this resource.
    pub(crate) fn request(
        &self,
        full_jid: &str,
        connection_id: Uuid,
        cutoff: DateTime<Utc>,
        recovery_epoch: u64,
    ) -> bool {
        self.request_checked(full_jid, connection_id, cutoff, recovery_epoch, None)
    }

    fn request_checked(
        &self,
        full_jid: &str,
        connection_id: Uuid,
        cutoff: DateTime<Utc>,
        recovery_epoch: u64,
        recipient_id: Option<Uuid>,
    ) -> bool {
        if recovery_epoch == 0 || self.admission.direct_mode() != DirectPostCommitMode::Live {
            return false;
        }
        let Some(session) = self
            .sessions
            .get(full_jid)
            .map(|entry| entry.value().clone())
        else {
            return false;
        };
        if recipient_id.is_some_and(|recipient_id| session.user_id != recipient_id) {
            return false;
        }
        let generation = session.availability_generation.load(Ordering::Acquire);
        if !exact_replay_route_is_current(
            &self.sessions,
            full_jid,
            connection_id,
            &session,
            generation,
            true,
        ) {
            return false;
        }
        match recovery_epoch_status(&session, recovery_epoch) {
            RecoveryReplayStatus::Complete | RecoveryReplayStatus::InFlight => return true,
            RecoveryReplayStatus::Retryable
            | RecoveryReplayStatus::AwaitEligibility
            | RecoveryReplayStatus::Ineligible
            | RecoveryReplayStatus::Stale => {}
        }
        let Ok(permit) = Arc::clone(&self.permits).try_acquire_owned() else {
            return false;
        };
        match session.recovery_replay_inflight_epoch.compare_exchange(
            0,
            recovery_epoch,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {}
            Err(current) => return current == recovery_epoch,
        }
        if session
            .recovery_replay_completed_epoch
            .load(Ordering::Acquire)
            == recovery_epoch
        {
            let _ = session.recovery_replay_inflight_epoch.compare_exchange(
                recovery_epoch,
                0,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            return true;
        }

        let sessions = Arc::clone(&self.sessions);
        let admission = self.admission.clone();
        let route_key = full_jid.to_owned();
        let route = session.clone();
        let replay_key = full_jid.to_owned();
        let current_route = Arc::new(move || {
            exact_replay_route_is_current(
                &sessions,
                &route_key,
                connection_id,
                &route,
                generation,
                admission.direct_mode() == DirectPostCommitMode::Live,
            )
        });
        let inflight_epoch = Arc::clone(&session.recovery_replay_inflight_epoch);
        let completed_epoch = Arc::clone(&session.recovery_replay_completed_epoch);
        let replay_service = self.replay.clone();
        let replay_session = session.clone();
        let recovery_authority =
            RecoveryReplayAuthority::new(db::replay_repository::RecoveryReplayAuthority::new(
                self.pool.clone(),
                session.user_id,
                session.auth_generation,
            ));
        let result = session.post_actions.defer_recovery(
            "cluster-recovered-offline-replay",
            async move {
                let mut pending = PendingRecoveryReplay {
                    epoch: recovery_epoch,
                    inflight_epoch,
                    completed_epoch,
                    completed: false,
                };
                let _permit = permit;
                pending.completed = replay::replay_after_cluster_reconciliation(
                    replay_service,
                    replay_session.sender,
                    replay_session.user_id,
                    replay_key,
                    replay_session.privacy_active,
                    replay_session.bind2_mam_catchup,
                    replay_session.available,
                    replay_session.availability_generation,
                    generation,
                    cutoff,
                    current_route,
                    recovery_authority,
                )
                .await;
            },
            &self.telemetry(),
        );
        if result.is_err() {
            let _ = session.recovery_replay_inflight_epoch.compare_exchange(
                recovery_epoch,
                0,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            return false;
        }
        true
    }
}

impl AppState {
    pub(crate) fn cluster_recovery_replay_wake(&self) -> ClusterRecoveryReplayWake {
        ClusterRecoveryReplayWake {
            sessions: Arc::clone(&self.sessions),
            replay: self.replay_service.clone(),
            admission: self.cluster.admission(),
            pool: self.pool.clone(),
            metrics: Arc::clone(&self.metrics),
            permits: Arc::new(Semaphore::new(MAX_CONCURRENT_RECOVERY_REPLAYS)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::RouteIncarnationSignal;
    use std::sync::atomic::{AtomicBool, AtomicI16};
    use tokio_util::sync::CancellationToken;

    fn session(connection_id: Uuid) -> OnlineSession {
        let (sender, _receiver) = tokio::sync::mpsc::channel(1);
        OnlineSession {
            user_id: Uuid::new_v4(),
            auth_generation: 1,
            user_agent_epoch: None,
            connection_id,
            route_incarnation: RouteIncarnationSignal::new(connection_id),
            lifecycle: Arc::default(),
            metrics_counted: Arc::default(),
            routable: Arc::new(AtomicBool::new(true)),
            sender: crate::outbound::OutboundSender::new(sender),
            available: Arc::new(AtomicBool::new(true)),
            availability_generation: Arc::new(AtomicU64::new(3)),
            post_actions: crate::xmpp::protocol::PostActionHandle::default(),
            recovery_replay_inflight_epoch: Arc::default(),
            recovery_replay_completed_epoch: Arc::default(),
            bind2_mam_catchup: false,
            mix_presence_gate: Arc::default(),
            mix_presence_fallback_suppressed: Arc::default(),
            caps_observation_generation: Arc::default(),
            carbons: Arc::default(),
            priority: Arc::new(AtomicI16::new(0)),
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
            resource: "Phone".to_owned(),
            user_agent_id: None,
            sm_session_id: Arc::default(),
            muc_memberships: Arc::default(),
            connected_at: std::time::Instant::now(),
            last_activity: Arc::new(std::sync::RwLock::new(std::time::Instant::now())),
            disconnect: CancellationToken::new(),
        }
    }

    #[test]
    fn recovery_replay_fences_exact_route_availability_and_priority() {
        let sessions = DashMap::new();
        let full_jid = "alice@example.test/Phone";
        let connection_id = Uuid::new_v4();
        let original = session(connection_id);
        sessions.insert(full_jid.to_owned(), original.clone());
        let current = || {
            exact_replay_route_is_current(&sessions, full_jid, connection_id, &original, 3, true)
        };
        assert!(current());
        assert!(!exact_replay_route_is_current(
            &sessions,
            full_jid,
            connection_id,
            &original,
            3,
            false,
        ));

        original.priority.store(-1, Ordering::Release);
        assert!(!current());
        original.priority.store(0, Ordering::Release);
        original.available.store(false, Ordering::Release);
        assert!(!current());
        original.available.store(true, Ordering::Release);
        original.availability_generation.store(4, Ordering::Release);
        assert!(
            !current(),
            "same-connection availability ABA invalidates old wake"
        );

        original.availability_generation.store(3, Ordering::Release);
        let replacement = session(Uuid::new_v4());
        sessions.insert(full_jid.to_owned(), replacement);
        assert!(!current(), "full-JID replacement cannot inherit old wake");
    }

    #[test]
    fn recovery_route_pages_are_bounded_and_lexically_contiguous() {
        let sessions = DashMap::new();
        for index in (0..300).rev() {
            sessions.insert(
                format!("user{index:03}@example.test/Phone"),
                session(Uuid::new_v4()),
            );
        }
        let first = recovery_route_page_after(&sessions, None, 1_000);
        assert_eq!(first.len(), MAX_RECOVERY_ROUTE_PAGE);
        assert_eq!(first.first().unwrap().0, "user000@example.test/Phone");
        assert_eq!(first.last().unwrap().0, "user255@example.test/Phone");
        let second = recovery_route_page_after(&sessions, Some(&first[255].0), 1_000);
        assert_eq!(second.len(), 44);
        assert_eq!(second.first().unwrap().0, "user256@example.test/Phone");
        assert_eq!(second.last().unwrap().0, "user299@example.test/Phone");
        assert!(recovery_route_page_after(&sessions, Some(&second[43].0), 2).is_empty());
        assert!(recovery_route_page_after(&sessions, None, 0).is_empty());
    }

    #[test]
    fn recovery_route_page_skips_ineligible_entries_before_capacity() {
        let sessions = DashMap::new();
        for index in 0..300 {
            let route = session(Uuid::new_v4());
            route.priority.store(-1, Ordering::Release);
            sessions.insert(format!("a{index:03}@example.test/Phone"), route);
        }
        let eligible = session(Uuid::new_v4());
        sessions.insert("z@example.test/Phone".to_owned(), eligible.clone());
        let page = recovery_route_page_after(&sessions, None, MAX_RECOVERY_ROUTE_PAGE);
        assert_eq!(
            page,
            vec![("z@example.test/Phone".to_owned(), eligible.connection_id)]
        );
        eligible.available.store(false, Ordering::Release);
        assert!(recovery_route_page_after(&sessions, None, MAX_RECOVERY_ROUTE_PAGE).is_empty());
    }

    #[test]
    fn recovery_route_page_retains_ineligible_bind2_for_future_sweep() {
        let sessions = DashMap::new();
        let mut bind2 = session(Uuid::new_v4());
        bind2.bind2_mam_catchup = true;
        bind2.available.store(false, Ordering::Release);
        let connection_id = bind2.connection_id;
        sessions.insert("bind2@example.test/Phone".to_owned(), bind2);
        let page = recovery_route_page_after(&sessions, None, MAX_RECOVERY_ROUTE_PAGE);
        assert_eq!(
            page,
            vec![("bind2@example.test/Phone".to_owned(), connection_id)]
        );
    }

    #[test]
    fn completed_recovery_epoch_does_not_block_next_epoch() {
        let route = session(Uuid::new_v4());
        assert_eq!(
            recovery_epoch_status(&route, 7),
            RecoveryReplayStatus::Retryable
        );
        route
            .recovery_replay_inflight_epoch
            .compare_exchange(0, 7, Ordering::AcqRel, Ordering::Acquire)
            .unwrap();
        assert_eq!(
            recovery_epoch_status(&route, 7),
            RecoveryReplayStatus::InFlight
        );
        assert_eq!(
            recovery_epoch_status(&route, 8),
            RecoveryReplayStatus::Retryable
        );
        assert!(route
            .recovery_replay_inflight_epoch
            .compare_exchange(0, 8, Ordering::AcqRel, Ordering::Acquire)
            .is_err());
        drop(PendingRecoveryReplay {
            epoch: 7,
            inflight_epoch: Arc::clone(&route.recovery_replay_inflight_epoch),
            completed_epoch: Arc::clone(&route.recovery_replay_completed_epoch),
            completed: true,
        });
        assert_eq!(
            recovery_epoch_status(&route, 7),
            RecoveryReplayStatus::Complete
        );
        assert_eq!(
            recovery_epoch_status(&route, 8),
            RecoveryReplayStatus::Retryable
        );
        route
            .recovery_replay_inflight_epoch
            .compare_exchange(0, 8, Ordering::AcqRel, Ordering::Acquire)
            .unwrap();
        drop(PendingRecoveryReplay {
            epoch: 8,
            inflight_epoch: Arc::clone(&route.recovery_replay_inflight_epoch),
            completed_epoch: Arc::clone(&route.recovery_replay_completed_epoch),
            completed: false,
        });
        assert_eq!(
            recovery_epoch_status(&route, 8),
            RecoveryReplayStatus::Retryable
        );
    }

    #[tokio::test]
    async fn recovery_request_rejects_busy_global_capacity_without_marking_epoch() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://unused:unused@127.0.0.1/unused")
            .unwrap();
        let cluster =
            crate::cluster::ClusterManager::new(None, "example.test", None, None, None, None)
                .await
                .unwrap();
        let sessions = Arc::new(DashMap::new());
        let full_jid = "alice@example.test/Phone";
        let route = session(Uuid::new_v4());
        sessions.insert(full_jid.to_owned(), route.clone());
        let wake = ClusterRecoveryReplayWake {
            sessions,
            replay: ReplayService::new(
                db::replay_repository::PostgresReplayRepository::new(pool.clone()),
                "example.test",
                30,
            ),
            admission: cluster.admission(),
            pool,
            metrics: Arc::default(),
            permits: Arc::new(Semaphore::new(0)),
        };
        let wrong_recipient = Uuid::new_v4();
        assert_eq!(
            wake.recipient_completion_state(wrong_recipient, full_jid, route.connection_id, 7),
            RecoveryReplayStatus::Stale
        );
        assert!(!wake.request_for_recipient(
            wrong_recipient,
            full_jid,
            route.connection_id,
            Utc::now(),
            7
        ));
        assert!(!wake.request(full_jid, route.connection_id, Utc::now(), 7));
        assert_eq!(
            route.recovery_replay_inflight_epoch.load(Ordering::Acquire),
            0
        );
        assert_eq!(
            wake.completion_state(full_jid, route.connection_id, 7),
            RecoveryReplayStatus::Retryable
        );
        route.priority.store(-1, Ordering::Release);
        assert_eq!(
            wake.completion_state(full_jid, route.connection_id, 7),
            RecoveryReplayStatus::Ineligible
        );
        wake.sessions.get_mut(full_jid).unwrap().bind2_mam_catchup = true;
        assert_eq!(
            wake.completion_state(full_jid, route.connection_id, 7),
            RecoveryReplayStatus::AwaitEligibility
        );
    }
}
