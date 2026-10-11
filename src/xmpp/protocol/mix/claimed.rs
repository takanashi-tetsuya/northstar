//! Claimed MIX outbox effects: turn deadlines, shutdown, lease-bounded claims and the claimed delivery and PAM result processing.

use super::*;

#[derive(Debug)]
pub(super) struct MixOutboxShutdown;

impl std::fmt::Display for MixOutboxShutdown {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MIX outbox worker is shutting down")
    }
}

impl std::error::Error for MixOutboxShutdown {}

pub(super) fn mix_outbox_is_shutting_down(error: &anyhow::Error) -> bool {
    error.downcast_ref::<MixOutboxShutdown>().is_some()
}

/// The caller reached its explicit durable-work deadline.  This is distinct
/// from shutdown: the row remains fenced and lease expiry is the authoritative
/// recovery path, rather than attempting another state change after ownership
/// may have become uncertain.
#[derive(Debug)]
pub(super) struct MixOutboxDeadlineElapsed;

impl std::fmt::Display for MixOutboxDeadlineElapsed {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MIX outbox durable-work deadline elapsed")
    }
}

impl std::error::Error for MixOutboxDeadlineElapsed {}

pub(super) fn mix_outbox_deadline_elapsed(error: &anyhow::Error) -> bool {
    error.downcast_ref::<MixOutboxDeadlineElapsed>().is_some()
}

/// Await one database turn while continuing to honor cancellation and one
/// caller-owned absolute deadline.  Dropping the pending future also drops a
/// pending semaphore/pool acquisition, so no detached task retains a worker
/// lane after the caller has stopped owning the attempt.
pub(super) async fn bounded_mix_outbox_turn<T>(
    cancel: &tokio_util::sync::CancellationToken,
    deadline: tokio::time::Instant,
    turn: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    if cancel.is_cancelled() {
        return Err(MixOutboxShutdown.into());
    }
    if tokio::time::Instant::now() >= deadline {
        return Err(MixOutboxDeadlineElapsed.into());
    }
    tokio::select! {
        biased;
        _ = cancel.cancelled() => Err(MixOutboxShutdown.into()),
        _ = tokio::time::sleep_until(deadline) => Err(MixOutboxDeadlineElapsed.into()),
        result = turn => result,
    }
}

/// Unclaimed polling and maintenance work has no row-specific attempt
/// deadline.  Give each database turn a short, explicit progress budget;
/// claimed effects use their shared attempt deadline through
/// [`bounded_mix_outbox_turn`] directly.
pub(super) async fn cancellable_mix_outbox_turn<T>(
    cancel: &tokio_util::sync::CancellationToken,
    turn: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    bounded_mix_outbox_turn(
        cancel,
        tokio::time::Instant::now() + MIX_OUTBOX_UNCLAIMED_DB_TURN_DEADLINE,
        turn,
    )
    .await
}

/// Do not issue a new claim once admission closes. An already-polled claim
/// keeps the same five-second database budget and returns its exact tokens
/// during graceful shutdown. Hard cancellation still leaves any uncertain
/// commit fenced for lease expiry; no token is guessed or released in Drop.
pub(super) async fn drainable_mix_outbox_claim<T>(
    stop_claiming: &tokio_util::sync::CancellationToken,
    cancel: &tokio_util::sync::CancellationToken,
    claim: impl std::future::Future<Output = Result<Vec<T>>>,
) -> Result<Vec<T>> {
    if stop_claiming.is_cancelled() {
        return Ok(Vec::new());
    }
    cancellable_mix_outbox_turn(cancel, claim).await
}

/// Drive the externally visible part of one claimed durable row while keeping
/// its effect, cancellation, absolute deadline, and at most one lease renewal
/// concurrently pollable.  In particular, renewal is *not* awaited inside a
/// timer branch: an effect can hold the only outbox database admission permit,
/// and pausing it while renewal waits for that same permit would self-deadlock.
///
/// `Ok(None)` means the lease was no longer ours.  The caller must not attempt
/// an acknowledgement or retry in that case.
pub(super) async fn run_claimed_mix_effect_with_lease<T>(
    cancel: tokio_util::sync::CancellationToken,
    deadline: tokio::time::Instant,
    renewal_interval: Duration,
    effect: impl std::future::Future<Output = Result<T>> + Send,
    mut renew: impl FnMut() -> BoxFuture<'static, Result<bool>>,
) -> Result<Option<T>> {
    let mut effect = Box::pin(effect);
    let mut next_renewal = tokio::time::Instant::now() + renewal_interval;

    loop {
        if tokio::time::Instant::now() >= deadline {
            return Err(MixOutboxDeadlineElapsed.into());
        }

        tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err(MixOutboxShutdown.into()),
            _ = tokio::time::sleep_until(deadline) => return Err(MixOutboxDeadlineElapsed.into()),
            result = &mut effect => return result.map(Some),
            _ = tokio::time::sleep_until(next_renewal) => {}
        }

        // Do not start a renewal that cannot finish before the shared attempt
        // deadline.  The deadline branch above will fence this worker instead.
        if tokio::time::Instant::now() >= deadline {
            return Err(MixOutboxDeadlineElapsed.into());
        }

        let mut renewal = Box::pin(bounded_mix_outbox_turn(&cancel, deadline, renew()));
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err(MixOutboxShutdown.into()),
            _ = tokio::time::sleep_until(deadline) => return Err(MixOutboxDeadlineElapsed.into()),
            result = &mut effect => return result.map(Some),
            renewed = &mut renewal => {
                if !renewed? {
                    return Ok(None);
                }
                next_renewal = tokio::time::Instant::now() + renewal_interval;
            }
        }
    }
}

/// Only the route and observed durable turns vary between worker environments.
/// The shared policy owns deadlines, renewal scope, and settlement selection.
pub(super) trait ClaimedMixDeliveryPort: Clone + Send + Sync + 'static {
    fn route(
        &self,
        request: &mix_worker::RouteRequest,
    ) -> impl std::future::Future<Output = Result<ChannelStanzaDeliveryOutcome>> + Send;

    fn renew(
        &self,
        request: &mix_worker::RenewalRequest,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;

    fn settle(
        &self,
        request: &mix_worker::SettlementRequest,
    ) -> impl std::future::Future<Output = Result<mix_worker::SettlementResult>> + Send;
}

#[derive(Clone)]
pub(super) struct MixOutboxDeliveryPort {
    pub(super) context: Arc<MixOutboxContext>,
}

impl ClaimedMixDeliveryPort for MixOutboxDeliveryPort {
    async fn route(
        &self,
        request: &mix_worker::RouteRequest,
    ) -> Result<ChannelStanzaDeliveryOutcome> {
        deliver_claimed_channel_stanza(&self.context, request).await
    }

    async fn renew(&self, request: &mix_worker::RenewalRequest) -> Result<bool> {
        self.context
            .service()
            .renew_mix_delivery_lease_observed(request)
            .await
    }

    async fn settle(
        &self,
        request: &mix_worker::SettlementRequest,
    ) -> Result<mix_worker::SettlementResult> {
        self.context
            .service()
            .settle_mix_delivery_observed(request)
            .await
    }
}

pub(super) async fn process_claimed_mix_delivery(
    context: Arc<MixOutboxContext>,
    attempt: mix_worker::Attempt,
    handle: outbox::AttemptHandle,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<()> {
    process_claimed_mix_delivery_with_port(
        MixOutboxDeliveryPort { context },
        attempt,
        handle,
        cancel,
    )
    .await
}

pub(super) async fn process_claimed_mix_delivery_with_port<P: ClaimedMixDeliveryPort>(
    port: P,
    attempt: mix_worker::Attempt,
    handle: outbox::AttemptHandle,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<()> {
    let attempt_deadline = tokio::time::Instant::now() + MIX_OUTBOX_ATTEMPT_DEADLINE;
    let source = attempt.row().source;
    let event_id = attempt.row().event_id;
    let channel_id = attempt.row().channel_id;
    let stanza = match addressed_mix_delivery(&attempt.row().stanza, &attempt.row().recipient_jid) {
        Ok(stanza) => stanza,
        Err(error) => {
            let request = attempt.invalid_template(error.to_string())?;
            let moved = match bounded_mix_outbox_turn(
                &cancel,
                attempt_deadline,
                port.settle(&request),
            )
            .await
            {
                Ok(mix_worker::SettlementResult::DeadLetter(moved)) => moved,
                Ok(_) => anyhow::bail!("invalid-template settlement result kind mismatch"),
                Err(wait) if mix_outbox_is_shutting_down(&wait) => {
                    handle.finish_as(mix_worker::TerminalReason::Cancelled);
                    return Ok(());
                }
                Err(wait) if mix_outbox_deadline_elapsed(&wait) => {
                    handle.finish_as(mix_worker::TerminalReason::TimedOut);
                    tracing::warn!(delivery_id=%source.delivery_id, event_id=%event_id, channel_id=%channel_id, "MIX invalid-template handling exceeded its claimed delivery deadline; retaining fenced row for lease recovery");
                    return Ok(());
                }
                Err(wait) => return Err(wait),
            };
            if !moved {
                tracing::warn!(delivery_id=%source.delivery_id, event_id=%event_id, channel_id=%channel_id, "MIX invalid-template dead-letter result was NotMoved");
            }
            return Ok(());
        }
    };
    let request = attempt.route(stanza)?;
    let renewal_port = port.clone();
    let renewal_owner = handle.observation.clone();
    let result = run_claimed_mix_effect_with_lease(
        cancel.clone(),
        attempt_deadline,
        MIX_OUTBOX_LEASE_RENEWAL_INTERVAL,
        async { Ok(port.route(&request).await) },
        move || -> BoxFuture<'static, Result<bool>> {
            let port = renewal_port.clone();
            let owner = renewal_owner.clone();
            Box::pin(async move {
                let renewal = owner.renewal_request()?;
                port.renew(&renewal).await
            })
        },
    )
    .await;
    // The existing helper has returned and destroyed its routing/renewal
    // children. This token records that boundary without inventing a result
    // for an in-flight renewal dropped because routing completed.
    let closed = handle.observation.close_renewal_scope()?;
    let result = match result {
        Ok(Some(result)) => result,
        Ok(None) => {
            tracing::warn!(delivery_id=%source.delivery_id, event_id=%event_id, channel_id=%channel_id, "MIX renewal no longer matched the active exact source while an external side effect was in flight");
            return Ok(());
        }
        Err(error) if mix_outbox_is_shutting_down(&error) => {
            handle.finish_as(mix_worker::TerminalReason::Cancelled);
            return Ok(());
        }
        Err(error) if mix_outbox_deadline_elapsed(&error) => {
            handle.finish_as(mix_worker::TerminalReason::TimedOut);
            tracing::warn!(delivery_id=%source.delivery_id, event_id=%event_id, channel_id=%channel_id, "MIX delivery attempt exceeded its claimed deadline; retaining fenced row for lease recovery");
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    let (outcome, command) = match result {
        Ok(ChannelStanzaDeliveryOutcome::TransferredToRecoverableTransport) => {
            request
                .returned(mix_worker::RouteResult::Transferred)?
                .transferred(closed)?;
            return Ok(());
        }
        Ok(ChannelStanzaDeliveryOutcome::CompletedByClaimingWorker) => (
            mix_worker::RouteResult::CompletedByWorker,
            mix_worker::SettlementCommand::Ack,
        ),
        Err(error) => {
            if mix_outbox_is_shutting_down(&error) {
                handle.finish_as(mix_worker::TerminalReason::Cancelled);
                return Ok(());
            } else if error.downcast_ref::<MixDeliveryRoutePending>().is_some() {
                (
                    mix_worker::RouteResult::Pending,
                    mix_worker::SettlementCommand::Defer {
                        delay_seconds: MIX_DELIVERY_ROUTE_RECOVERY_DELAY_SECS,
                    },
                )
            } else if let Some(permanent) = error.downcast_ref::<PermanentMixDeliveryError>() {
                (
                    mix_worker::RouteResult::Permanent,
                    mix_worker::SettlementCommand::DeadLetter {
                        reason: permanent.reason.to_owned(),
                        error: permanent.detail.clone(),
                    },
                )
            } else {
                (
                    mix_worker::RouteResult::Retry,
                    mix_worker::SettlementCommand::Retry {
                        error: error.to_string(),
                    },
                )
            }
        }
    };
    let completion = request.returned(outcome)?;
    let settlement = completion
        .settlement(command, closed)?
        .context("worker-owned route requires its exclusive settlement")?;
    let completion =
        bounded_mix_outbox_turn(&cancel, attempt_deadline, port.settle(&settlement)).await;
    let result = match completion {
        Ok(result) => result,
        Err(error) if mix_outbox_is_shutting_down(&error) => {
            handle.finish_as(mix_worker::TerminalReason::Cancelled);
            return Ok(());
        }
        Err(error) if mix_outbox_deadline_elapsed(&error) => {
            handle.finish_as(mix_worker::TerminalReason::TimedOut);
            tracing::warn!(delivery_id=%source.delivery_id, event_id=%event_id, channel_id=%channel_id, "MIX delivery finalization exceeded its claimed deadline; retaining fenced row for lease recovery");
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    match result {
        mix_worker::SettlementResult::DeadLetter(false) => {
            tracing::warn!(delivery_id=%source.delivery_id, event_id=%event_id, channel_id=%channel_id, "MIX delivery dead-letter result was NotMoved");
        }
        mix_worker::SettlementResult::Ack(false)
        | mix_worker::SettlementResult::Defer(false)
        | mix_worker::SettlementResult::Retry(mix_worker::RetryResult::LeaseLost) => {
            tracing::warn!(delivery_id=%source.delivery_id, event_id=%event_id, channel_id=%channel_id, "MIX delivery completion did not match its exact source fence");
        }
        _ => {}
    }
    Ok(())
}

pub(super) enum PamResultRoute {
    Accepted,
    Offline,
}

pub(super) async fn deliver_claimed_pam_result(
    context: &MixOutboxContext,
    result: &ClaimedPamResult,
) -> Result<PamResultRoute> {
    let target = CanonicalJid::parse(&result.requester_full_jid)?;
    anyhow::ensure!(
        target.resourcepart().is_some(),
        "PAM result target is not a full JID"
    );
    for (jid, session) in context.session_entries_for(&result.requester_full_jid) {
        if jid != result.requester_full_jid || session.user_id != result.user_id {
            continue;
        }
        let (receipt_tx, mut receipt_rx) = tokio::sync::mpsc::unbounded_channel();
        if let Err(error) = session
            .sender
            .try_send_with_transport_receipt(result.response_xml.clone(), receipt_tx)
        {
            if matches!(&error, tokio::sync::mpsc::error::TrySendError::Full(_)) {
                session.sender.disconnect_backpressured_transport();
                session.disconnect.cancel();
            }
            anyhow::bail!("PAM result resource rejected durable delivery: {error}");
        }
        match tokio::time::timeout(Duration::from_secs(5), receipt_rx.recv()).await {
            Ok(Some(())) => return Ok(PamResultRoute::Accepted),
            Ok(None) => anyhow::bail!("PAM result transport closed before taking ownership"),
            Err(_) => {
                // The stanza may still be sitting in the ordered socket
                // queue. Close that transport before a retry can overtake it;
                // the journal remains authoritative for reconnect/retry.
                session.sender.disconnect_backpressured_transport();
                session.disconnect.cancel();
                anyhow::bail!("PAM result transport ownership timed out");
            }
        }
    }
    let nodes = context
        .outbox_lookup_cluster_nodes(&result.requester_full_jid)
        .await?;
    for node in nodes {
        if context
            .send_cluster_pam_result(
                &node,
                &result.requester_full_jid,
                &result.response_xml,
                result.user_id,
            )
            .await?
        {
            return Ok(PamResultRoute::Accepted);
        }
    }
    Ok(PamResultRoute::Offline)
}

pub(super) async fn process_claimed_pam_result(
    context: Arc<MixOutboxContext>,
    result: ClaimedPamResult,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<()> {
    let attempt_deadline = tokio::time::Instant::now() + MIX_OUTBOX_ATTEMPT_DEADLINE;
    let renewal_context = Arc::clone(&context);
    let routed = match run_claimed_mix_effect_with_lease(
        cancel.clone(),
        attempt_deadline,
        MIX_OUTBOX_LEASE_RENEWAL_INTERVAL,
        async { Ok(deliver_claimed_pam_result(&context, &result).await) },
        move || -> BoxFuture<'static, Result<bool>> {
            let context = Arc::clone(&renewal_context);
            let operation_id = result.operation_id;
            let lease_token = result.lease_token;
            Box::pin(async move {
                context
                    .service()
                    .renew_pam_result_lease(operation_id, lease_token)
                    .await
            })
        },
    )
    .await
    {
        Ok(Some(routed)) => routed,
        Ok(None) => {
            tracing::warn!(operation_id=%result.operation_id, "lost PAM result lease during delivery");
            return Ok(());
        }
        Err(error) if mix_outbox_is_shutting_down(&error) => return Ok(()),
        Err(error) if mix_outbox_deadline_elapsed(&error) => {
            tracing::warn!(operation_id=%result.operation_id, "PAM result delivery exceeded its claimed deadline; retaining fenced row for lease recovery");
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    let completion = match routed {
        Ok(PamResultRoute::Accepted) => {
            bounded_mix_outbox_turn(
                &cancel,
                attempt_deadline,
                context
                    .service()
                    .acknowledge_pam_result(result.operation_id, result.lease_token),
            )
            .await
        }
        Ok(PamResultRoute::Offline) => {
            // Being offline is not a failed business attempt. Preserve the
            // exact response and retry without escalating the attempt count.
            bounded_mix_outbox_turn(
                &cancel,
                attempt_deadline,
                context
                    .service()
                    .defer_pam_result(result.operation_id, result.lease_token, 5),
            )
            .await
        }
        Err(error) if mix_outbox_is_shutting_down(&error) => {
            // See the delivery-side shutdown branch above: the durable
            // result remains fenced and lease expiry recovers it without
            // making the process wait for an unavailable database turn.
            return Ok(());
        }
        Err(error) if mix_outbox_deadline_elapsed(&error) => {
            tracing::warn!(operation_id=%result.operation_id, "PAM result route exceeded its claimed deadline; retaining fenced row for lease recovery");
            return Ok(());
        }
        Err(error) => {
            bounded_mix_outbox_turn(
                &cancel,
                attempt_deadline,
                context.service().retry_pam_result(
                    result.operation_id,
                    result.lease_token,
                    result.attempt_count,
                    &error.to_string(),
                ),
            )
            .await
        }
    };
    let completed = match completion {
        Ok(completed) => completed,
        Err(error) if mix_outbox_is_shutting_down(&error) => return Ok(()),
        Err(error) if mix_outbox_deadline_elapsed(&error) => {
            tracing::warn!(operation_id=%result.operation_id, "PAM result finalization exceeded its claimed deadline; retaining fenced row for lease recovery");
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    if !completed {
        tracing::warn!(operation_id=%result.operation_id, "PAM result completion lost its lease fence");
    }
    Ok(())
}

pub(super) fn record_mix_post_commit_failure(
    context: &MixOutboxContext,
    channel_jid: &str,
    recipient: &str,
    stage: &str,
    error: &dyn std::fmt::Display,
) {
    context.record_post_commit_failure();
    tracing::warn!(
        channel = channel_jid,
        recipient,
        stage,
        error = %error,
        "post-commit MIX delivery was not admitted"
    );
}
