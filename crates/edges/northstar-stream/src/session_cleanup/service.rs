//! Explicit C2S session-finalization boundary.
//!
//! A transport first calls [`SessionCleanupService::quiesce`] synchronously so
//! no new local route can observe a connection whose socket has gone away.
//! The returned work item is then completed with bounded, independently
//! observed database and network steps.  Every durable mutation uses the
//! exact connection/SM/MUC epoch captured by the protocol actor; a late
//! cleanup can therefore never remove a replacement session.

use super::local::SessionCleanupLocal;
use super::{
    CleanupRecovery, CleanupReport, SessionCleanupPlan, SessionSmCleanup, CLEANUP_STEP_BUDGET,
};
use crate::local_routes::muc::{MucOccupant, SuspendedMucEndpoint};
use anyhow::Result;
use northstar_room_application::muc_service::{
    ClusterMucTransitionOutcome, CommittedRoomRetirement, LocalMucOccupantIdentity,
    MucRoomIncarnation,
};
use northstar_room_core::occupancy::MucOccupantRoute;
use northstar_session_application::sm_teardown_presence::{
    TerminalOwner, TerminalPresenceAudience, TerminalPresenceRequest,
};
use northstar_session_application::SessionCleanupAccount;
use std::{
    future::Future,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::time::Instant;
use uuid::Uuid;

mod terminal;
pub use terminal::TerminalPresenceCleanup;

/// The node services one session finalization drives besides the
/// process-local routes it fences itself.
pub trait SessionCleanupPorts: TerminalPresenceCleanup {
    fn snapshot_suspended_muc_for_disconnect(
        &self,
        endpoints: &[Arc<SuspendedMucEndpoint>],
        snapshot: &mut northstar_session_application::sm::SmSessionSnapshot,
    ) -> impl Future<Output = Result<()>> + Send;
    fn seal_suspended_muc_endpoints(
        &self,
        endpoints: &[Arc<SuspendedMucEndpoint>],
    ) -> impl Future<Output = ()> + Send;
    fn mark_memory_invariant_failure(&self);
    fn suspend_exact_session(
        &self,
        session_id: Uuid,
        connection_id: Uuid,
        account: &SessionCleanupAccount,
        snapshot: &northstar_session_application::sm::SmSessionSnapshot,
        ttl_seconds: u64,
    ) -> impl Future<Output = Result<bool>> + Send;
    fn mark_suspended_muc_durable(
        &self,
        endpoints: Vec<Arc<SuspendedMucEndpoint>>,
    ) -> impl Future<Output = bool> + Send;
    fn queue_promotion(
        &self,
        connection_id: Uuid,
        session_id: Uuid,
        endpoints: Vec<Arc<SuspendedMucEndpoint>>,
        capacity: northstar_session_application::sm_capacity::SmCapacityLease,
    ) -> bool;
    #[allow(clippy::too_many_arguments)]
    fn queue_suspension(
        &self,
        account: SessionCleanupAccount,
        connection_id: Uuid,
        session_id: Uuid,
        snapshot: northstar_session_application::sm::SmSessionSnapshot,
        ttl_seconds: u64,
        endpoints: Vec<Arc<SuspendedMucEndpoint>>,
        capacity: northstar_session_application::sm_capacity::SmCapacityLease,
    ) -> bool;
    fn revoke_session(&self, session_id: Uuid) -> impl Future<Output = Result<()>> + Send;
    fn revoke_session_with_teardown(
        &self,
        session_id: Uuid,
    ) -> impl Future<Output = Result<()>> + Send;
    fn release_live_session(
        &self,
        connection_id: Uuid,
    ) -> impl Future<Output = Result<bool>> + Send;
    fn release_exact_local_session_route(
        &self,
        full_jid: &str,
        connection_id: Uuid,
    ) -> impl Future<Output = Result<()>> + Send;
    fn actor_bare_jid(&self, username: &str) -> String;
    fn disconnect_mix_presence(
        &self,
        user_id: Uuid,
        actor_bare: &str,
        actor_full: &str,
    ) -> impl Future<Output = Result<()>> + Send;
    /// Whether PostgreSQL owns MUC occupancy, so departures leave it exactly
    /// instead of publishing a cluster projection.
    fn pg_muc_authoritative(&self) -> bool;
    fn leave_pg_muc_exact(
        &self,
        room_jid: &str,
        departed: &MucOccupant,
    ) -> impl Future<Output = Result<Option<ClusterMucTransitionOutcome>>> + Send;
    fn publish_local_muc_departure(
        &self,
        departed: &MucOccupant,
        was_last: bool,
    ) -> impl Future<Output = Result<()>> + Send;
    fn deliver_to_muc_occupant(
        &self,
        occupant: &MucOccupant,
        stanza: String,
    ) -> impl Future<Output = bool> + Send;
    fn departed_room(
        &self,
        room_jid: &str,
        route: &MucOccupantRoute,
    ) -> impl Future<Output = Result<Option<MucRoomIncarnation>>> + Send;
    fn delete_temporary_room(
        &self,
        room: MucRoomIncarnation,
    ) -> impl Future<Output = Result<Option<CommittedRoomRetirement>>> + Send;
    fn clear_active_privacy_session(
        &self,
        user_id: Uuid,
        connection_id: Uuid,
    ) -> impl Future<Output = Result<()>> + Send;
    fn finalization_started(&self);
    fn finalization_failed(&self, failures: usize);
    fn worker_registry(&self) -> &northstar_runtime::workers::WorkerRegistry;
}

const CLEANUP_TOTAL_BUDGET: Duration = Duration::from_secs(10);

struct MucDeparture {
    room_jid: String,
    departed: MucOccupant,
    remaining: Vec<(String, MucOccupant)>,
}

struct DurableSuspension {
    session_id: Uuid,
    snapshot: northstar_session_application::sm::SmSessionSnapshot,
    ttl_seconds: u64,
    endpoints: Vec<Arc<SuspendedMucEndpoint>>,
    capacity: northstar_session_application::sm_capacity::SmCapacityLease,
}

pub struct QuiescedSessionCleanup {
    connection_id: Uuid,
    may_own_live_session: bool,
    mix_presence_gate: Arc<tokio::sync::Mutex<()>>,
    account: Option<SessionCleanupAccount>,
    registered_key: Option<String>,
    full_jid: Option<String>,
    available: Option<Arc<AtomicBool>>,
    active_privacy_list: Option<String>,
    directed_presence: Vec<String>,
    route_removed: bool,
    departures: Vec<MucDeparture>,
    durable_suspension: Option<DurableSuspension>,
    revoke_sm_session: Option<Uuid>,
}

/// Keep the exact release future completely unpolled for transports that
/// never attempted a lease, and for streams whose lease was suspended.
async fn finish_live_session_release(
    may_own: bool,
    suspended: bool,
    release: impl std::future::Future<Output = ()>,
) {
    if may_own && !suspended {
        release.await;
    }
}

async fn run_cleanup_step<T>(
    deadline: Instant,
    operation: &'static str,
    recovery: CleanupRecovery,
    future: impl std::future::Future<Output = Result<T>>,
    report: &mut CleanupReport,
) -> Option<T> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        report.failed(operation, recovery);
        tracing::warn!(
            operation,
            ?recovery,
            "session cleanup total budget exhausted"
        );
        return None;
    }
    match tokio::time::timeout(remaining.min(CLEANUP_STEP_BUDGET), future).await {
        Ok(Ok(value)) => {
            report.completed();
            Some(value)
        }
        Ok(Err(error)) => {
            report.failed(operation, recovery);
            tracing::warn!(?error, operation, ?recovery, "session cleanup step failed");
            None
        }
        Err(_) => {
            report.failed(operation, recovery);
            tracing::warn!(operation, ?recovery, "session cleanup step timed out");
            None
        }
    }
}

pub struct SessionCleanupService<P> {
    local: SessionCleanupLocal,
    ports: P,
}

impl<P: SessionCleanupPorts> SessionCleanupService<P> {
    pub fn new(local: SessionCleanupLocal, ports: P) -> Self {
        Self { local, ports }
    }

    /// Remove exact process-local ownership before any asynchronous cleanup.
    /// This method performs no database or network I/O and is also the model
    /// used by the synchronous `Drop` fallback.
    pub fn quiesce(&self, plan: SessionCleanupPlan) -> QuiescedSessionCleanup {
        let local = &self.local;
        let full_jid = plan.full_jid.as_deref().unwrap_or_default();
        let (durable_suspension, revoke_sm_session) = match plan.sm {
            SessionSmCleanup::Suspend {
                session_id,
                snapshot,
                ttl_seconds,
                capacity,
            } => {
                let base_stanzas = snapshot.unacked.len();
                let base_bytes = snapshot
                    .unacked
                    .iter()
                    .map(|entry| entry.stanza.len())
                    .sum();
                let endpoints = local.suspend_local_muc_occupants(
                    full_jid,
                    plan.connection_id,
                    session_id,
                    &plan.joined_rooms,
                    base_stanzas,
                    base_bytes,
                );
                // Transfer the live session's actual-byte reservation at the
                // same synchronous ownership boundary as the route fence.
                // From this point every volatile MUC suffix append must grow
                // this shared lease before retaining another stanza.
                crate::local_routes::suspended_muc::retain_suspended_sm_capacity(
                    &endpoints,
                    capacity.clone(),
                );
                plan.joined_rooms.clear();
                (
                    Some(DurableSuspension {
                        session_id,
                        snapshot,
                        ttl_seconds,
                        endpoints,
                        capacity,
                    }),
                    None,
                )
            }
            SessionSmCleanup::Revoke { session_id } => (None, Some(session_id)),
            SessionSmCleanup::None => (None, None),
        };

        let mut departures = Vec::new();
        if durable_suspension.is_none() {
            let memberships = plan
                .joined_rooms
                .iter()
                .map(|membership| (membership.key().clone(), membership.value().clone()))
                .collect::<Vec<_>>();
            for (room_jid, membership) in memberships {
                plan.joined_rooms
                    .remove_if(&room_jid, |_, current| current == &membership);
                let Some(departed) = local.remove_local_muc_occupant_exact(
                    northstar_room_application::muc_service::LocalMucOccupantIdentity {
                        room_jid: &room_jid,
                        nick: &membership.nick,
                        full_jid,
                        connection_id: plan.connection_id,
                        cluster_epoch: membership.cluster_epoch,
                    },
                ) else {
                    continue;
                };
                let remaining = local.muc_occupants_for(&room_jid);
                departures.push(MucDeparture {
                    room_jid,
                    departed,
                    remaining,
                });
            }
        }

        let route_removed = plan.registered_key.as_deref().is_some_and(|key| {
            local
                .remove_session_if_connection(key, plan.connection_id)
                .is_some()
        });
        if route_removed && durable_suspension.is_none() {
            if let Some(available) = &plan.available {
                available.store(false, Ordering::Release);
            }
        }

        QuiescedSessionCleanup {
            connection_id: plan.connection_id,
            may_own_live_session: plan.may_own_live_session,
            mix_presence_gate: plan.mix_presence_gate,
            account: plan.account,
            registered_key: plan.registered_key,
            full_jid: plan.full_jid,
            available: plan.available,
            active_privacy_list: plan.active_privacy_list,
            directed_presence: plan.directed_presence,
            route_removed,
            departures,
            durable_suspension,
            revoke_sm_session,
        }
    }

    /// Complete every independent cleanup step within one finite connection
    /// budget. Failure never short-circuits later security/capacity cleanup.
    /// The report names the durable recovery mechanism for each missed step.
    pub async fn finish(&self, work: QuiescedSessionCleanup) -> CleanupReport {
        let deadline = Instant::now() + CLEANUP_TOTAL_BUDGET;
        let mut report = CleanupReport::default();
        self.ports.finalization_started();
        // The route is already fenced. Sample policy before any asynchronous
        // cleanup can retire the source's active-list lease.
        let audience = self.capture_unavailable(deadline, &work, &mut report).await;

        // Cross the exact resource epoch after `quiesce` removes the route.
        // A caps worker that already entered finishes before this barrier;
        // one that wakes afterwards must re-read the route and observe that
        // it is gone. Do not retain the gate across database/cluster cleanup:
        // finalization has a finite budget and the epoch protects only the
        // route-to-MIX ordering boundary.
        let mix_presence_epoch = Arc::clone(&work.mix_presence_gate).lock_owned().await;
        drop(mix_presence_epoch);

        let mut suspended = false;
        if let Some(suspension) = work.durable_suspension {
            let DurableSuspension {
                session_id,
                snapshot,
                ttl_seconds,
                endpoints,
                capacity,
            } = suspension;
            let mut capacity = Some(capacity);
            if let Some(account) = &work.account {
                let mut exact_snapshot = snapshot;
                let snapshot_backed = self
                    .step(
                        deadline,
                        "snapshot-suspended-muc",
                        CleanupRecovery::LeaseOrEpoch,
                        self.ports
                            .snapshot_suspended_muc_for_disconnect(&endpoints, &mut exact_snapshot),
                        &mut report,
                    )
                    .await
                    .is_some();
                if !snapshot_backed {
                    // The endpoint still owns its original FIFO because the
                    // snapshot helper validates before changing phase. Keep
                    // the legacy two-step durable fallback available for this
                    // invariant/error path rather than dropping either owner.
                    self.ports.seal_suspended_muc_endpoints(&endpoints).await;
                }
                let snapshot_bytes = exact_snapshot.resident_bytes().unwrap_or(usize::MAX);
                if capacity
                    .as_ref()
                    .is_none_or(|lease| lease.try_grow_to(snapshot_bytes).is_err())
                {
                    report.failed("suspend-sm-memory-admission", CleanupRecovery::LeaseOrEpoch);
                    self.ports.mark_memory_invariant_failure();
                    self.ports.seal_suspended_muc_endpoints(&endpoints).await;
                    let _ = self
                        .step(
                            deadline,
                            "revoke-sm-after-memory-rejection",
                            CleanupRecovery::LeaseOrEpoch,
                            self.ports.revoke_session_with_teardown(session_id),
                            &mut report,
                        )
                        .await;
                    capacity.take();
                } else {
                    match self
                        .step(
                            deadline,
                            "suspend-sm",
                            CleanupRecovery::LeaseOrEpoch,
                            self.ports.suspend_exact_session(
                                session_id,
                                work.connection_id,
                                account,
                                &exact_snapshot,
                                ttl_seconds,
                            ),
                            &mut report,
                        )
                        .await
                    {
                        Some(true) => {
                            // PostgreSQL now owns the resumable stream and its
                            // deployment-capacity lease even if MUC soft-state
                            // promotion below needs reconciliation.
                            suspended = true;
                            let promotion_endpoints = endpoints.clone();
                            let promotion_ports = &self.ports;
                            let promotion = self
                            .step(
                                deadline,
                                "activate-suspended-muc",
                                CleanupRecovery::LeaseOrEpoch,
                                async move {
                                    anyhow::ensure!(
                                        promotion_ports.mark_suspended_muc_durable(promotion_endpoints).await,
                                        "one or more suspended MUC projections require reconciliation"
                                    );
                                    Ok(())
                                },
                                &mut report,
                            )
                            .await;
                            if promotion.is_none() {
                                let queued = self.ports.queue_promotion(
                                    work.connection_id,
                                    session_id,
                                    endpoints.clone(),
                                    capacity
                                        .take()
                                        .expect("SM suspension owns its capacity lease"),
                                );
                                if !queued {
                                    suspended = false;
                                    report.failed(
                                        "queue-sm-promotion",
                                        CleanupRecovery::LeaseOrEpoch,
                                    );
                                    let _ = self
                                        .step(
                                            deadline,
                                            "revoke-sm-after-recovery-capacity",
                                            CleanupRecovery::LeaseOrEpoch,
                                            self.ports.revoke_session_with_teardown(session_id),
                                            &mut report,
                                        )
                                        .await;
                                }
                            } else if let Some(capacity) = capacity.take() {
                                crate::local_routes::suspended_muc::retain_suspended_sm_capacity(
                                    &endpoints, capacity,
                                );
                            }
                            // The SM row is already durable. If promotion times
                            // out or PostgreSQL rejects a MUC suffix, state keeps
                            // the exact bounded endpoint fail-closed for retry or
                            // same-process resume. Removing it here would turn a
                            // recoverable cleanup failure into silent message
                            // loss. Expiry/revocation remains the terminal owner.
                        }
                        Some(false) => {
                            self.ports.seal_suspended_muc_endpoints(&endpoints).await;
                            if !report
                                .failures
                                .iter()
                                .any(|failure| failure.operation == "suspend-sm")
                            {
                                report.failed("suspend-sm", CleanupRecovery::LeaseOrEpoch);
                            }
                        }
                        None => {
                            self.ports.seal_suspended_muc_endpoints(&endpoints).await;
                            let queued = self.ports.queue_suspension(
                                account.clone(),
                                work.connection_id,
                                session_id,
                                exact_snapshot,
                                ttl_seconds,
                                endpoints.clone(),
                                capacity
                                    .take()
                                    .expect("SM suspension owns its capacity lease"),
                            );
                            if !queued {
                                report.failed("queue-sm-suspension", CleanupRecovery::LeaseOrEpoch);
                                let _ = self
                                    .step(
                                        deadline,
                                        "revoke-sm-after-recovery-capacity",
                                        CleanupRecovery::LeaseOrEpoch,
                                        self.ports.revoke_session_with_teardown(session_id),
                                        &mut report,
                                    )
                                    .await;
                            }
                        }
                    }
                }
            } else {
                report.failed("suspend-sm-missing-account", CleanupRecovery::LeaseOrEpoch);
                self.ports.seal_suspended_muc_endpoints(&endpoints).await;
            }
        }

        if let Some(session_id) = work.revoke_sm_session {
            let _ = self
                .step(
                    deadline,
                    "revoke-sm",
                    CleanupRecovery::LeaseOrEpoch,
                    self.ports.revoke_session(session_id),
                    &mut report,
                )
                .await;
        }

        if let Some(account) = &work.account {
            let _ = self
                .step(
                    deadline,
                    "clear-active-privacy",
                    CleanupRecovery::LeaseOrEpoch,
                    self.ports
                        .clear_active_privacy_session(account.user_id, work.connection_id),
                    &mut report,
                )
                .await;
        }

        if work.route_removed {
            if let Some(key) = &work.registered_key {
                let _ = self
                    .step(
                        deadline,
                        "unregister-cluster-session",
                        CleanupRecovery::ClusterReconciliation,
                        self.ports
                            .release_exact_local_session_route(key, work.connection_id),
                        &mut report,
                    )
                    .await;
            }
        }

        self.cleanup_muc_departures(deadline, work.departures, &mut report)
            .await;

        if work.route_removed && !suspended {
            if let Some(available) = &work.available {
                available.store(false, Ordering::Release);
            }
            if let (Some(account), Some(full_jid)) = (&work.account, &work.full_jid) {
                let future = self.publish_unavailable(account, full_jid, audience);
                let _ = self
                    .step(
                        deadline,
                        "publish-unavailable",
                        CleanupRecovery::PresenceRefresh,
                        future,
                        &mut report,
                    )
                    .await;
            }
        }

        // A successfully suspended stream retains its deployment capacity
        // lease across resume. On every terminal path, keep the exact resource
        // lease until its unavailable projection has completed (or entered
        // the documented recovery path), so a new bind cannot be followed by
        // stale cleanup from the connection it replaced.
        finish_live_session_release(work.may_own_live_session, suspended, async {
            let _ = self
                .step(
                    deadline,
                    "release-live-session",
                    CleanupRecovery::LeaseOrEpoch,
                    self.ports.release_live_session(work.connection_id),
                    &mut report,
                )
                .await;
        })
        .await;

        self.complete_report(report)
    }

    /// A superseding XEP-0198 connection owns route/SM/MUC cleanup, but the
    /// old connection's privacy selection remains connection-scoped and must
    /// still be removed explicitly.
    pub async fn clear_transferred_privacy(
        &self,
        account: Option<&SessionCleanupAccount>,
        connection_id: Uuid,
    ) -> CleanupReport {
        let mut report = CleanupReport::default();
        self.ports.finalization_started();
        if let Some(account) = account {
            let deadline = Instant::now() + CLEANUP_STEP_BUDGET;
            let _ = self
                .step(
                    deadline,
                    "clear-transferred-privacy",
                    CleanupRecovery::LeaseOrEpoch,
                    self.ports
                        .clear_active_privacy_session(account.user_id, connection_id),
                    &mut report,
                )
                .await;
        }
        self.complete_report(report)
    }

    fn complete_report(&self, report: CleanupReport) -> CleanupReport {
        if !report.is_clean() {
            self.ports.finalization_failed(report.failures.len());
            tracing::error!(
                connection_cleanup_failures = report.failures.len(),
                failures = ?report.failures,
                "C2S session cleanup completed with recoverable debt"
            );
        }
        report.observe(self.ports.worker_registry());
        report
    }

    async fn step<T>(
        &self,
        deadline: Instant,
        operation: &'static str,
        recovery: CleanupRecovery,
        future: impl std::future::Future<Output = Result<T>>,
        report: &mut CleanupReport,
    ) -> Option<T> {
        run_cleanup_step(deadline, operation, recovery, future, report).await
    }

    async fn cleanup_muc_departures(
        &self,
        deadline: Instant,
        departures: Vec<MucDeparture>,
        report: &mut CleanupReport,
    ) {
        for departure in departures {
            let was_last = departure.remaining.is_empty();
            let pg_authoritative = self.ports.pg_muc_authoritative();
            let departed_in_authority = if pg_authoritative {
                self.step(
                    deadline,
                    "leave-pg-muc-occupancy",
                    CleanupRecovery::LeaseOrEpoch,
                    async {
                        let Some(outcome) = self
                            .ports
                            .leave_pg_muc_exact(&departure.room_jid, &departure.departed)
                            .await?
                        else {
                            // A concurrent exact transition or lease expiry
                            // already removed this incarnation.
                            return Ok(());
                        };
                        anyhow::ensure!(
                            matches!(
                                outcome,
                                ClusterMucTransitionOutcome::Applied
                                    | ClusterMucTransitionOutcome::Replay
                                    | ClusterMucTransitionOutcome::Stale
                                    | ClusterMucTransitionOutcome::Destroyed
                            ),
                            "exact PostgreSQL MUC departure was rejected: {:?}",
                            outcome
                        );
                        Ok(())
                    },
                    report,
                )
                .await
                .is_some()
            } else {
                let _ = self
                    .step(
                        deadline,
                        "unregister-muc-occupant",
                        CleanupRecovery::ClusterReconciliation,
                        self.ports
                            .publish_local_muc_departure(&departure.departed, was_last),
                        report,
                    )
                    .await;
                false
            };

            // A PostgreSQL leave commits one immutable audience/outbox event;
            // sending these local presences as well would duplicate delivery.
            if !pg_authoritative {
                for (_, target) in &departure.remaining {
                    let presence = northstar_room_core::stanza::muc_presence_stanza(
                        &northstar_room_application::muc_service::SerializableMucOccupant::from(
                            &departure.departed,
                        ),
                        &target.full_jid,
                        true,
                        false,
                        false,
                        None,
                        departure.departed.room_non_anonymous || target.role == "moderator",
                    );
                    let _ = self
                        .step(
                            deadline,
                            "deliver-muc-unavailable",
                            CleanupRecovery::PresenceRefresh,
                            async {
                                anyhow::ensure!(
                                    self.ports.deliver_to_muc_occupant(target, presence).await,
                                    "MUC departure target was unavailable"
                                );
                                Ok(())
                            },
                            report,
                        )
                        .await;
                }
            }

            if departure.remaining.is_empty() && (!pg_authoritative || departed_in_authority) {
                let route =
                    MucOccupantRoute::from(LocalMucOccupantIdentity::from(&departure.departed));
                let retirement = self
                    .step(
                        deadline,
                        "delete-temporary-muc",
                        CleanupRecovery::LeaseOrEpoch,
                        retire_departed_room(
                            self.ports.departed_room(&departure.room_jid, &route),
                            |room| self.ports.delete_temporary_room(room),
                        ),
                        report,
                    )
                    .await
                    .flatten();
                if let Some(retirement) = retirement {
                    for occupant in retirement.occupants {
                        self.local
                            .remove_retired_muc_route(occupant.route.identity(&departure.room_jid));
                    }
                }
            }
        }
    }

    async fn capture_unavailable(
        &self,
        deadline: Instant,
        work: &QuiescedSessionCleanup,
        report: &mut CleanupReport,
    ) -> Option<TerminalPresenceAudience> {
        let account = work.account.as_ref()?;
        let full_jid = work.full_jid.as_deref()?;
        if !work.route_removed {
            return None;
        }
        self.step(
            deadline,
            "capture-unavailable",
            CleanupRecovery::PresenceRefresh,
            self.ports
                .capture_terminal_presence(TerminalPresenceRequest {
                    owner_id: account.user_id,
                    owner: TerminalOwner::Live {
                        auth_generation: account.auth_generation,
                        connection_id: work.connection_id,
                    },
                    full_jid,
                    active_privacy_list: work.active_privacy_list.as_deref(),
                    available: true,
                    directed: &work.directed_presence,
                    local_domain: "",
                }),
            report,
        )
        .await
        .flatten()
    }

    async fn publish_unavailable(
        &self,
        account: &SessionCleanupAccount,
        full_jid: &str,
        audience: Option<TerminalPresenceAudience>,
    ) -> Result<()> {
        let actor_bare = self.ports.actor_bare_jid(&account.username);
        let (presence, mix) = tokio::join!(
            async {
                match audience {
                    Some(audience) => self.ports.publish_terminal_presence(audience).await,
                    None => Ok(()),
                }
            },
            self.ports
                .disconnect_mix_presence(account.user_id, &actor_bare, full_jid),
        );
        presence.and(mix)
    }
}

async fn retire_departed_room<F>(
    resolve: impl Future<Output = Result<Option<MucRoomIncarnation>>>,
    retire: impl FnOnce(MucRoomIncarnation) -> F,
) -> Result<Option<CommittedRoomRetirement>>
where
    F: Future<Output = Result<Option<CommittedRoomRetirement>>>,
{
    let Some(room) = resolve.await? else {
        return Ok(None);
    };
    retire(room).await
}

impl<P: SessionCleanupPorts> super::SessionCleanup for SessionCleanupService<P> {
    type Quiesced = QuiescedSessionCleanup;

    fn quiesce(&self, plan: SessionCleanupPlan) -> QuiescedSessionCleanup {
        SessionCleanupService::quiesce(self, plan)
    }

    async fn finish(&self, work: QuiescedSessionCleanup) -> CleanupReport {
        SessionCleanupService::finish(self, work).await
    }

    async fn clear_transferred_privacy(
        &self,
        account: Option<&SessionCleanupAccount>,
        connection_id: Uuid,
    ) -> CleanupReport {
        SessionCleanupService::clear_transferred_privacy(self, account, connection_id).await
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod temporary_room_tests;
