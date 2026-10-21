//! Recovery replay plans: page bounds, route progress, retention and retry.

use super::*;

pub(super) const RECOVERY_REPLAY_PAGE: usize = 256;
pub(super) const RECOVERY_REPLAY_REQUESTS_PER_PASS: usize = 256;
pub(super) const RECOVERY_REPLAY_RETRY_MAX: Duration = Duration::from_secs(300);
pub(super) const RECOVERY_REPLAY_OBSERVATIONS_PER_SWEEP: u8 = 4;
pub(super) const RECOVERY_REPLAY_INCOMPLETE_DELAY: Duration = Duration::from_secs(300);

pub(super) struct RecoveryReplayRoute {
    pub(super) full_jid: String,
    pub(super) connection_id: uuid::Uuid,
    pub(super) attempts: u8,
    pub(super) observations: u8,
    pub(super) retry_after: Instant,
}

pub(super) struct RecoveryReplayPlan {
    pub(super) health_epoch: u64,
    pub(super) wake_epoch: u64,
    pub(super) cutoff: Option<chrono::DateTime<chrono::Utc>>,
    pub(super) cursor: Option<String>,
    pub(super) pending: VecDeque<RecoveryReplayRoute>,
    pub(super) barrier_attempts: u8,
    pub(super) barrier_retry_after: Instant,
    pub(super) incomplete: bool,
    pub(super) exhausted: bool,
    pub(super) next_sweep_at: Option<Instant>,
}

impl RecoveryReplayPlan {
    pub(super) fn new(health_epoch: u64, wake_epoch: u64) -> Self {
        Self {
            health_epoch,
            wake_epoch,
            cutoff: None,
            cursor: None,
            pending: VecDeque::new(),
            barrier_attempts: 0,
            barrier_retry_after: Instant::now(),
            incomplete: false,
            exhausted: false,
            next_sweep_at: None,
        }
    }

    pub(super) fn begin_next_sweep(&mut self, wake_epoch: u64) {
        self.wake_epoch = wake_epoch;
        self.cutoff = None;
        self.cursor = None;
        self.pending.clear();
        self.barrier_attempts = 0;
        self.barrier_retry_after = Instant::now();
        self.incomplete = false;
        self.exhausted = false;
        self.next_sweep_at = None;
    }

    pub(super) fn queue_page(&mut self, page: Vec<(String, uuid::Uuid)>) {
        debug_assert!(self.pending.is_empty() && page.len() <= RECOVERY_REPLAY_PAGE);
        if page.is_empty() {
            self.exhausted = true;
            return;
        }
        self.cursor = page.last().map(|(full_jid, _)| full_jid.clone());
        self.pending
            .extend(
                page.into_iter()
                    .map(|(full_jid, connection_id)| RecoveryReplayRoute {
                        full_jid,
                        connection_id,
                        attempts: 0,
                        observations: 0,
                        retry_after: Instant::now(),
                    }),
            );
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RecoveryRouteProgress {
    Done,
    Pending,
    DeferredToNextSweep,
}

pub(super) fn recovery_route_progress(
    route: &mut RecoveryReplayRoute,
    status: super::recovery_replay_wake::RecoveryReplayStatus,
    now: Instant,
    schedule: impl FnOnce(),
) -> RecoveryRouteProgress {
    use super::recovery_replay_wake::RecoveryReplayStatus;
    match status {
        RecoveryReplayStatus::Complete
        | RecoveryReplayStatus::Ineligible
        | RecoveryReplayStatus::Stale => RecoveryRouteProgress::Done,
        RecoveryReplayStatus::AwaitEligibility => RecoveryRouteProgress::DeferredToNextSweep,
        RecoveryReplayStatus::InFlight | RecoveryReplayStatus::Retryable => {
            route.observations = route.observations.saturating_add(1);
            if route.observations >= RECOVERY_REPLAY_OBSERVATIONS_PER_SWEEP {
                return RecoveryRouteProgress::DeferredToNextSweep;
            }
            if status == RecoveryReplayStatus::Retryable && now >= route.retry_after {
                schedule();
                route.attempts = route.attempts.saturating_add(1);
                route.retry_after = now + recovery_retry_delay(route.attempts);
            }
            RecoveryRouteProgress::Pending
        }
    }
}

pub(super) fn retain_recovery_replay_plan(health: &ClusterHealth, plan: RecoveryReplayPlan) {
    let mut slot = health
        .recovery_replay_plan
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if slot.as_ref().is_none_or(|current| {
        (current.health_epoch, current.wake_epoch) <= (plan.health_epoch, plan.wake_epoch)
    }) {
        *slot = Some(plan);
    }
}

pub(super) fn recovery_retry_delay(attempts: u8) -> Duration {
    Duration::from_secs(
        (30_u64 << attempts.saturating_sub(1).min(4)).min(RECOVERY_REPLAY_RETRY_MAX.as_secs()),
    )
}

pub(super) async fn drive_recovery_replay_plan(
    context: &super::maintenance_context::ClusterMaintenanceContext,
) {
    let control = &context.control;
    let Some(mut plan) = control
        .health
        .recovery_replay_plan
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take()
    else {
        return;
    };
    if control
        .health
        .listener_rotation_epoch
        .load(Ordering::Acquire)
        != plan.health_epoch
    {
        // The next successful recovery gets a newer cutoff and supersedes
        // this resource-scoped wake plan.
        return;
    }
    if control.readiness_error().is_some() {
        retain_recovery_replay_plan(&control.health, plan);
        return;
    }
    if let Some(next_sweep_at) = plan.next_sweep_at {
        if Instant::now() < next_sweep_at {
            retain_recovery_replay_plan(&control.health, plan);
            return;
        }
        let wake_epoch = control
            .health
            .recovery_wake_sequence
            .fetch_add(1, Ordering::AcqRel)
            .saturating_add(1);
        plan.begin_next_sweep(wake_epoch);
    }
    if plan.cutoff.is_none() {
        let Some(authority) = control.peer_authority.readiness_snapshot() else {
            tracing::warn!("cluster recovery replay lacks exact local authority");
            plan.barrier_attempts = plan.barrier_attempts.saturating_add(1);
            plan.barrier_retry_after = Instant::now() + recovery_retry_delay(plan.barrier_attempts);
            retain_recovery_replay_plan(&control.health, plan);
            return;
        };
        if Instant::now() < plan.barrier_retry_after {
            retain_recovery_replay_plan(&control.health, plan);
            return;
        }
        match context.replay_wake.barrier(&authority).await {
            Ok(cutoff) => plan.cutoff = Some(cutoff),
            Err(error) => {
                plan.barrier_attempts = plan.barrier_attempts.saturating_add(1);
                plan.barrier_retry_after =
                    Instant::now() + recovery_retry_delay(plan.barrier_attempts);
                context.locals.record_background_failure();
                if plan.barrier_attempts == 1
                    || plan.barrier_attempts.is_power_of_two()
                    || plan.barrier_attempts == u8::MAX
                {
                    tracing::warn!(?error, health_epoch = plan.health_epoch, attempts = plan.barrier_attempts,
                        "cluster recovery replay cutoff was not established; retrying while healthy");
                }
                retain_recovery_replay_plan(&control.health, plan);
                return;
            }
        }
    }
    if control
        .health
        .listener_rotation_epoch
        .load(Ordering::Acquire)
        != plan.health_epoch
    {
        return;
    }
    if control.readiness_error().is_some() {
        retain_recovery_replay_plan(&control.health, plan);
        return;
    }
    let cutoff = plan.cutoff.expect("successful recovery barrier set cutoff");
    let mut budget = RECOVERY_REPLAY_REQUESTS_PER_PASS;
    while budget != 0 {
        if plan.pending.is_empty() {
            if plan.exhausted {
                break;
            }
            let page = context
                .replay_wake
                .routes_page_after(plan.cursor.as_deref(), RECOVERY_REPLAY_PAGE);
            plan.queue_page(page);
            if plan.exhausted {
                break;
            }
        }
        let batch = plan.pending.len().min(budget);
        let mut stalled_routes = 0_usize;
        for _ in 0..batch {
            if control
                .health
                .listener_rotation_epoch
                .load(Ordering::Acquire)
                != plan.health_epoch
            {
                return;
            }
            if control.readiness_error().is_some() {
                retain_recovery_replay_plan(&control.health, plan);
                return;
            }
            let mut route = plan.pending.pop_front().expect("bounded page has route");
            budget -= 1;
            let status = context.replay_wake.completion_state(
                &route.full_jid,
                route.connection_id,
                plan.wake_epoch,
            );
            let full_jid = route.full_jid.clone();
            let connection_id = route.connection_id;
            let wake_epoch = plan.wake_epoch;
            let progress = recovery_route_progress(&mut route, status, Instant::now(), || {
                let _scheduled =
                    context
                        .replay_wake
                        .request(&full_jid, connection_id, cutoff, wake_epoch);
            });
            match progress {
                RecoveryRouteProgress::Done => {}
                RecoveryRouteProgress::Pending => plan.pending.push_back(route),
                RecoveryRouteProgress::DeferredToNextSweep => {
                    plan.incomplete = true;
                    stalled_routes += 1;
                }
            }
        }
        if stalled_routes != 0 {
            tracing::warn!(health_epoch = plan.health_epoch, wake_epoch = plan.wake_epoch, stalled_routes,
                pending_routes = plan.pending.len(), cursor = ?plan.cursor,
                "cluster recovery replay page advanced with incomplete exact routes; next bounded sweep will retry them");
        }
        if !plan.pending.is_empty() {
            break;
        }
    }
    if plan.exhausted && plan.pending.is_empty() && plan.incomplete {
        tracing::warn!(
            health_epoch = plan.health_epoch,
            wake_epoch = plan.wake_epoch,
            "cluster recovery replay sweep incomplete; retrying with a fresh cutoff after backoff"
        );
        plan.next_sweep_at = Some(Instant::now() + RECOVERY_REPLAY_INCOMPLETE_DELAY);
    }
    if !plan.exhausted || !plan.pending.is_empty() || plan.incomplete {
        retain_recovery_replay_plan(&control.health, plan);
    }
}
