use super::*;

// Main grants background workers 15 seconds to join. Stop admission first and
// let bounded claims and owned deliveries drain for 14 seconds. The supervisor
// then drops unfinished work; an uncertain lease recovers only through expiry.
pub(super) const MIX_OUTBOX_DRAIN_GRACE: Duration = Duration::from_secs(14);
/// A claimed delivery may have already crossed a process or network boundary,
/// so its lease is the recovery authority.  Keep the entire local attempt —
/// effect, lease renewal, and final durable transition — within one absolute
/// deadline.  A later worker can safely recover a fenced row after its lease
/// expires; this worker must never retain its lane indefinitely.
pub(super) const MIX_OUTBOX_ATTEMPT_DEADLINE: Duration = Duration::from_secs(20);
/// Bound claim and maintenance turns separately so a pool acquire or database
/// wait cannot make a worker appear healthy while progress has stopped. A
/// claim whose commit response is lost may still own a lease in PostgreSQL.
pub(super) const MIX_OUTBOX_UNCLAIMED_DB_TURN_DEADLINE: Duration = Duration::from_secs(5);
/// Retention has a fixed deadline owned by the worker lifecycle, rather than
/// by individual delivery wakes.  Recreating this deadline after every claim
/// would let sustained traffic starve bounded maintenance forever.
pub(super) const MIX_OUTBOX_MAINTENANCE_INTERVAL: Duration = Duration::from_secs(60);
/// Renew well before the durable lease expires, but never immediately after a
/// claim.  Tokio intervals tick immediately, which used to let a renewal wait
/// on the same admission permit as the still-running effect.
pub(super) const MIX_OUTBOX_LEASE_RENEWAL_INTERVAL: Duration = Duration::from_secs(10);
/// An unavailable or not-yet-verified local route is not a failed delivery.
/// Keep its durable projection parked for a bounded recovery interval.  The
/// service layer reactivates it immediately when capability verification
/// completes; this timer is only the fallback for a missed wake-up.
pub(super) const MIX_DELIVERY_ROUTE_RECOVERY_DELAY_SECS: i64 = 30;
// PAM results include peer-facing correlation/acknowledgement work.  Keep the
// historical narrow window even when ordinary MIX delivery has a larger
// capacity budget, so a burst cannot crowd out the remote listener's exact
// response path.
pub(super) const PAM_RESULT_MAX_CONCURRENCY: usize = 2;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum MixOutboxQueue {
    Delivery,
    PamResult,
}

/// Only delivery has a retained commit/reconnect wake. Its empty recovery
/// scans may back off to one second; PAM retains the fixed 250 ms cadence.
pub(super) struct MixClaimSchedule {
    pub(super) next_claim: tokio::time::Instant,
    pub(super) empty_delay: Duration,
    pub(super) max_empty_delay: Duration,
}

impl MixClaimSchedule {
    pub(super) const BASE_DELAY: Duration = Duration::from_millis(250);

    pub(super) fn starting_at(queue: MixOutboxQueue, now: tokio::time::Instant) -> Self {
        Self {
            next_claim: now,
            empty_delay: Self::BASE_DELAY,
            max_empty_delay: match queue {
                MixOutboxQueue::Delivery => Duration::from_secs(1),
                MixOutboxQueue::PamResult => Self::BASE_DELAY,
            },
        }
    }

    pub(super) fn record_claim(&mut self, now: tokio::time::Instant, has_work: bool) {
        if has_work {
            self.empty_delay = Self::BASE_DELAY;
        }
        self.next_claim = now + self.empty_delay;
        if !has_work {
            self.empty_delay = (self.empty_delay * 2).min(self.max_empty_delay);
        }
    }

    pub(super) fn record_progress(&mut self, now: tokio::time::Instant) {
        self.empty_delay = Self::BASE_DELAY;
        self.next_claim = now;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct MixMaintenanceSchedule {
    pub(super) next_deadline: tokio::time::Instant,
}

impl MixMaintenanceSchedule {
    pub(super) fn starting_at(now: tokio::time::Instant) -> Self {
        Self {
            next_deadline: now + MIX_OUTBOX_MAINTENANCE_INTERVAL,
        }
    }

    pub(super) fn due(self, now: tokio::time::Instant) -> bool {
        now >= self.next_deadline
    }

    pub(super) fn record_completed_page(&mut self, completed_at: tokio::time::Instant) {
        // Schedule one future page from the actual completion point. This is
        // intentionally skip-like: delayed workers never burst an arbitrary
        // number of maintenance pages ahead of delivery work.
        self.next_deadline = completed_at + MIX_OUTBOX_MAINTENANCE_INTERVAL;
    }
}

/// External delivery can wait on a remote peer without holding a database
/// connection.  Keep one independently startable PAM lane, capped at its
/// protocol-safe window; MixService separately limits each short database
/// round to the configured background budget.
pub(super) const fn mix_outbox_lane_budgets(background_budget: usize) -> (usize, usize) {
    let pam_budget = if background_budget < PAM_RESULT_MAX_CONCURRENCY {
        background_budget
    } else {
        PAM_RESULT_MAX_CONCURRENCY
    };
    (background_budget, pam_budget)
}

pub(super) enum MixOutboxWork {
    Delivery(crate::services::mix::ClaimedMixDelivery),
    PamResult(ClaimedPamResult),
}

/// Claim only one protocol lane at a time.  The caller runs the delivery and
/// PAM lanes concurrently, while the service serializes their short database
/// turns.  A slow external delivery therefore never holds the start slot of a
/// correlated PAM reply.
pub(super) async fn claim_mix_outbox_work(
    context: &MixOutboxContext,
    stop_claiming: &tokio_util::sync::CancellationToken,
    cancel: &tokio_util::sync::CancellationToken,
    queue: MixOutboxQueue,
    budget: usize,
) -> Result<Vec<MixOutboxWork>> {
    let claim_limit = i64::try_from(budget)
        .expect("MIX outbox background budget is bounded by its fixed maximum");
    match queue {
        MixOutboxQueue::Delivery => {
            let deliveries = drainable_mix_outbox_claim(
                stop_claiming,
                cancel,
                context
                    .service()
                    .claim_mix_deliveries(claim_limit, 8 * 1024 * 1024),
            )
            .await?;
            Ok(deliveries
                .into_iter()
                .map(MixOutboxWork::Delivery)
                .collect())
        }
        MixOutboxQueue::PamResult => Ok(drainable_mix_outbox_claim(
            stop_claiming,
            cancel,
            context.service().claim_pam_results(claim_limit),
        )
        .await?
        .into_iter()
        .map(MixOutboxWork::PamResult)
        .collect()),
    }
}

pub(super) type MixOutboxTask = BoxFuture<'static, (MixOutboxQueue, Result<()>)>;
pub(super) type MixOutboxClaimTask = BoxFuture<'static, Result<Vec<MixOutboxWork>>>;
pub(super) type MixOutboxMaintenanceTask = BoxFuture<'static, Result<()>>;

pub(super) fn process_mix_outbox_work(
    context: Arc<MixOutboxContext>,
    work: MixOutboxWork,
    cancel: tokio_util::sync::CancellationToken,
) -> MixOutboxTask {
    Box::pin(async move {
        match work {
            MixOutboxWork::Delivery(delivery) => (
                MixOutboxQueue::Delivery,
                process_claimed_mix_delivery(context, delivery, cancel).await,
            ),
            MixOutboxWork::PamResult(result) => (
                MixOutboxQueue::PamResult,
                process_claimed_pam_result(context, result, cancel).await,
            ),
        }
    })
}

/// Keep the bounded claim in the same progress set as already-claimed work.
/// It may commit a lease before returning its token, so ordinary admission
/// shutdown must keep polling it; only hard cancellation or its deadline can
/// leave that unknown token for lease recovery.
pub(super) fn process_mix_outbox_claim(
    context: Arc<MixOutboxContext>,
    stop_claiming: tokio_util::sync::CancellationToken,
    cancel: tokio_util::sync::CancellationToken,
    queue: MixOutboxQueue,
    available: usize,
) -> MixOutboxClaimTask {
    Box::pin(async move {
        claim_mix_outbox_work(&context, &stop_claiming, &cancel, queue, available).await
    })
}

/// Start one bounded maintenance page without parking already-claimed work.
/// The event loop polls this future beside `in_flight`; retaining it as a
/// separate task prevents a pool/gate wait in retention from becoming a point
/// at which a claimed delivery can no longer make the progress needed to
/// release that same resource.
pub(super) fn process_mix_outbox_maintenance(
    context: Arc<MixOutboxContext>,
    cancel: tokio_util::sync::CancellationToken,
) -> MixOutboxMaintenanceTask {
    Box::pin(async move {
        cancellable_mix_outbox_turn(&cancel, async {
            context.service().maintain_mix_delivery_retention().await?;
            context
                .service()
                .prune_expired_business_intents(512)
                .await?;
            context
                .service()
                .prune_expired_federated_iq_results(512)
                .await?;
            context.service().reconcile_expired_remote_pam(128).await?;
            context
                .service()
                .prune_expired_pam_results(512)
                .await
                .map(|_| ())
        })
        .await
    })
}

pub(super) enum MixOutboxProgress {
    InFlight(MixOutboxQueue, Result<()>),
    Claim(Result<Vec<MixOutboxWork>>),
    Maintenance(Result<()>),
}

/// Poll claimed delivery work, a pending claim, and maintenance together.
/// Either unclaimed database future may wait on a bounded gate whose owner is
/// released only when an already-claimed future is polled. Keeping all three
/// in one select prevents either foreground claim or retention from becoming
/// an accidental progress barrier for the delivery lane.
pub(super) async fn next_mix_outbox_progress(
    in_flight: &mut FuturesUnordered<MixOutboxTask>,
    claim: &mut Option<MixOutboxClaimTask>,
    maintenance: &mut Option<MixOutboxMaintenanceTask>,
) -> MixOutboxProgress {
    debug_assert!(!in_flight.is_empty() || claim.is_some() || maintenance.is_some());
    tokio::select! {
        biased;
        Some((kind, outcome)) = in_flight.next(), if !in_flight.is_empty() => {
            MixOutboxProgress::InFlight(kind, outcome)
        }
        outcome = async {
            claim
                .as_mut()
                .expect("claim branch requires a task")
                .await
        }, if claim.is_some() => {
            claim.take();
            MixOutboxProgress::Claim(outcome)
        }
        outcome = async {
            maintenance
                .as_mut()
                .expect("maintenance branch requires a task")
                .await
        }, if maintenance.is_some() => {
            maintenance.take();
            MixOutboxProgress::Maintenance(outcome)
        }
    }
}

/// Wait for the typed delivery wake without giving MIX-PAM a generic shared
/// signal.  PAM has a different eligibility projection and continues to use
/// its bounded recovery scan until it gains a dedicated authority channel.
///
/// A `watch` receiver retains an unseen generation, so this future resolves
/// immediately if PostgreSQL committed a recipient row while the lane was
/// claiming or delivering its previous batch.  The `None` branch is pending
/// forever and is used only by the separate PAM lane.
pub(super) async fn wait_for_mix_delivery_wake(
    subscription: &mut Option<crate::services::mix::MixDeliveryWakeSubscription>,
) -> bool {
    match subscription {
        Some(subscription) => subscription.changed().await,
        None => std::future::pending().await,
    }
}

pub(super) async fn run_mix_outbox_lane(
    context: Arc<MixOutboxContext>,
    stop_claiming: tokio_util::sync::CancellationToken,
    cancel: tokio_util::sync::CancellationToken,
    queue: MixOutboxQueue,
    concurrency: usize,
    maintain: bool,
    heartbeat: crate::workers::WorkerHeartbeat,
) -> Result<()> {
    debug_assert!(concurrency > 0);
    let mut in_flight = FuturesUnordered::<MixOutboxTask>::new();
    // Install the retained receiver before the first claim.  Any committed
    // recipient INSERT/DELETE that races a later wait remains observable, and
    // the delivery lane therefore does not rely on Tokio timer scheduling for
    // prompt progress. Empty delivery scans back off from 250 ms to at most
    // one second, retaining durable recovery across listener outages, expired
    // leases and retry deadlines. PAM has no such wake and stays at 250 ms.
    let mut delivery_wake = matches!(queue, MixOutboxQueue::Delivery)
        .then(|| context.service().subscribe_delivery_wake());
    let mut claim_schedule = MixClaimSchedule::starting_at(queue, tokio::time::Instant::now());
    // Startup must first make already-committed user delivery eligible.
    // Retention work is important but cannot be allowed to put a maintenance
    // page ahead of the first claimed live MIX event on a small pool.
    let mut maintenance_schedule = MixMaintenanceSchedule::starting_at(tokio::time::Instant::now());
    let mut claim_task: Option<MixOutboxClaimTask> = None;
    let mut maintenance_task: Option<MixOutboxMaintenanceTask> = None;
    let mut accepting = true;
    let mut terminal_error = None;

    loop {
        // Heartbeat only after a real state-machine boundary.  Merely having
        // an in-flight future is not evidence of liveness: a future waiting
        // on an admission gate or pool acquire makes no forward progress.
        let mut healthy_progress = false;
        let mut failed_attempt_progress = false;
        if accepting && (stop_claiming.is_cancelled() || cancel.is_cancelled()) {
            accepting = false;
        }
        if !accepting {
            // Maintenance owns no external delivery handoff. Drop its wait
            // to leave database admission available to the draining work.
            maintenance_task.take();
        }
        if accepting
            && maintain
            && maintenance_task.is_none()
            && maintenance_schedule.due(tokio::time::Instant::now())
        {
            maintenance_task = Some(process_mix_outbox_maintenance(
                Arc::clone(&context),
                cancel.clone(),
            ));
        }

        if accepting
            && claim_task.is_none()
            && maintenance_task.is_none()
            && in_flight.len() < concurrency
            && tokio::time::Instant::now() >= claim_schedule.next_claim
        {
            let available = concurrency - in_flight.len();
            claim_task = Some(process_mix_outbox_claim(
                Arc::clone(&context),
                stop_claiming.clone(),
                cancel.clone(),
                queue,
                available,
            ));
        }

        // A pending claim can have acquired rows at the same instant
        // cancellation was requested. Drain its result into cancellation-aware
        // claimed work before returning; otherwise a just-committed lease
        // would wait for expiry without a local defer/retry attempt.
        if !accepting && in_flight.is_empty() && claim_task.is_none() {
            return match terminal_error {
                Some(error) => Err(error),
                None => Ok(()),
            };
        }

        tokio::select! {
            biased;
            _ = stop_claiming.cancelled(), if accepting => {
                accepting = false;
            }
            _ = cancel.cancelled(), if accepting => {
                accepting = false;
            }
            progress = next_mix_outbox_progress(&mut in_flight, &mut claim_task, &mut maintenance_task), if !in_flight.is_empty() || claim_task.is_some() || maintenance_task.is_some() => {
                match progress {
                    MixOutboxProgress::InFlight(kind, outcome) => {
                        // A finished row has released one lane slot. Claim again
                        // in the next loop turn instead of imposing the idle
                        // recovery cadence on an already-known backlog.
                        claim_schedule.record_progress(tokio::time::Instant::now());
                        if let Err(error) = outcome {
                            // A claimed row retains its fenced lease and is retried
                            // by the row-level completion path; one recipient must
                            // not restart either lane or starve PAM results.
                            tracing::warn!(?error, ?kind, "MIX outbox work attempt failed before completion");
                            heartbeat.error(&error);
                            failed_attempt_progress = true;
                        } else {
                            healthy_progress = true;
                        }
                    }
                    MixOutboxProgress::Claim(outcome) => {
                        match outcome {
                            Ok(claimed) => {
                                claim_schedule.record_claim(tokio::time::Instant::now(), !claimed.is_empty());
                                for work in claimed {
                                    in_flight.push(process_mix_outbox_work(
                                        Arc::clone(&context),
                                        work,
                                        cancel.clone(),
                                    ));
                                }
                                debug_assert!(in_flight.len() <= concurrency);
                                // An empty claim still completed one bounded,
                                // authoritative database turn.
                                healthy_progress = true;
                            }
                            Err(error) if mix_outbox_is_shutting_down(&error) => {
                                accepting = false;
                            }
                            Err(error) => {
                                terminal_error = Some(error);
                                accepting = false;
                                cancel.cancel();
                            }
                        }
                    }
                    MixOutboxProgress::Maintenance(outcome) => {
                        maintenance_schedule.record_completed_page(tokio::time::Instant::now());
                        match outcome {
                            Ok(_) => healthy_progress = true,
                            Err(error) if mix_outbox_is_shutting_down(&error) => {
                                accepting = false;
                            }
                            Err(error) => {
                                // Do not drop already-claimed rows. Cancel the local
                                // lanes so their operations defer/retry through their
                                // normal lease paths before surfacing the error.
                                terminal_error = Some(error);
                                accepting = false;
                                cancel.cancel();
                            }
                        }
                    }
                }
            }
            wake_open = wait_for_mix_delivery_wake(&mut delivery_wake), if accepting && claim_task.is_none() && maintenance_task.is_none() && in_flight.len() < concurrency => {
                if wake_open {
                    // The wake carries no delivery authority.  It merely
                    // asks the lane to run the normal fenced PostgreSQL
                    // claim immediately instead of waiting for its recovery
                    // scan.
                    claim_schedule.record_progress(tokio::time::Instant::now());
                } else {
                    terminal_error = Some(anyhow::anyhow!(
                        "MIX delivery wake broker unexpectedly closed"
                    ));
                    accepting = false;
                    cancel.cancel();
                }
            }
            _ = tokio::time::sleep_until(claim_schedule.next_claim), if accepting && claim_task.is_none() && maintenance_task.is_none() && in_flight.len() < concurrency => {}
        }
        if healthy_progress {
            heartbeat.ok();
        } else if failed_attempt_progress {
            // The worker completed a unit of work but it was not a healthy
            // boundary.  Keep its error history while preventing a completed
            // retry attempt from being mistaken for a deadlock.
            heartbeat.pulse();
        }
    }
}

/// Wait for the two independent durable-MIX lanes as one supervised worker.
///
/// Both lanes are intentionally continuous.  A plain `join` therefore turns a
/// failure in either lane into a silent hang: the failed future completes, but
/// the healthy peer continues polling forever and the supervisor never sees
/// the failure. An error or unexpected early return hard-cancels the peer.
/// During ordinary admission shutdown, however, an empty lane must let its
/// peer finish already-issued claims and owned work inside the supervisor's
/// existing drain budget. Unknown or transferred tokens are never released
/// by the joiner.
pub(super) async fn join_mix_outbox_lanes<D, P>(
    stop_claiming: tokio_util::sync::CancellationToken,
    lane_cancel: tokio_util::sync::CancellationToken,
    delivery: D,
    pam: P,
) -> Result<()>
where
    D: std::future::Future<Output = Result<()>>,
    P: std::future::Future<Output = Result<()>>,
{
    tokio::pin!(delivery);
    tokio::pin!(pam);
    tokio::select! {
        delivery_result = &mut delivery => {
            if delivery_result.is_err() || !stop_claiming.is_cancelled() {
                lane_cancel.cancel();
            }
            let pam_result = pam.await;
            delivery_result?;
            pam_result
        }
        pam_result = &mut pam => {
            if pam_result.is_err() || !stop_claiming.is_cancelled() {
                lane_cancel.cancel();
            }
            let delivery_result = delivery.await;
            pam_result?;
            delivery_result
        }
    }
}

pub(crate) fn start_mix_delivery_outbox(
    context: Arc<MixOutboxContext>,
    registry: Arc<crate::workers::WorkerRegistry>,
    cancel: tokio_util::sync::CancellationToken,
) {
    registry.supervise_draining(
        "mix-delivery-outbox",
        crate::workers::WorkerCriticality::Restartable,
        crate::workers::WorkerMode::Continuous,
        Some(Duration::from_secs(30)),
        MIX_OUTBOX_DRAIN_GRACE,
        cancel.clone(),
        move |heartbeat| {
            let context = Arc::clone(&context);
            let cancel = cancel.clone();
            async move {
                let (delivery_budget, pam_budget) =
                    mix_outbox_lane_budgets(context.service().outbox_background_budget());
                // Server shutdown stops admission without discarding an
                // in-progress claim response or delivery. Lane failures use
                // a fresh, independent hard-cancel token for this attempt;
                // the supervisor still bounds the whole drain to 14 seconds.
                let lane_cancel = tokio_util::sync::CancellationToken::new();
                let delivery = run_mix_outbox_lane(
                    Arc::clone(&context),
                    cancel.clone(),
                    lane_cancel.clone(),
                    MixOutboxQueue::Delivery,
                    delivery_budget,
                    true,
                    heartbeat.clone(),
                );
                let pam = run_mix_outbox_lane(
                    context,
                    cancel.clone(),
                    lane_cancel.clone(),
                    MixOutboxQueue::PamResult,
                    pam_budget,
                    false,
                    heartbeat,
                );
                // Both protocol lanes may wait on external I/O concurrently,
                // but MixService serializes their database turns. The joiner
                // preserves normal draining and surfaces an abnormal lane
                // exit to the restartable supervisor.
                join_mix_outbox_lanes(cancel, lane_cancel, delivery, pam).await
            }
        },
    );
}
