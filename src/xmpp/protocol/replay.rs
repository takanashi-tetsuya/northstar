use crate::{
    services::replay::{
        ReplayBusyUntil, ReplayPageOutcome, ReplayService, ReplaySession, ReplayStartOutcome,
    },
    state::{attr_escape, AppState},
};
use anyhow::{Context, Result};
use rand::Rng;
use std::{
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use uuid::Uuid;

const OUTBOUND_BACKPRESSURE_TIMEOUT: Duration = Duration::from_secs(5);
const REPLAY_RECOVERY_DEADLINE: Duration = Duration::from_secs(120);
// Leave a bounded tail for releasing an exact page claim and the resource
// owner lease. Recovery work never starts inside this reserve, so every
// database/socket await remains below the same end-to-end deadline.
const REPLAY_CLEANUP_RESERVE: Duration = Duration::from_secs(2);
const BUSY_RETRY_MIN_DELAY: Duration = Duration::from_millis(40);
const BUSY_RETRY_BASE_MAX_DELAY: Duration = Duration::from_millis(450);
const BUSY_RETRY_JITTER_MAX_MILLIS: u64 = 50;
const AVAILABILITY_POLL_INTERVAL: Duration = Duration::from_millis(50);

#[derive(Clone)]
struct AvailabilityFence {
    available: Arc<AtomicBool>,
    generation: Arc<AtomicU64>,
    expected_generation: u64,
}

impl AvailabilityFence {
    fn current(&self) -> bool {
        is_current_availability(&self.available, &self.generation, self.expected_generation)
    }
}

fn jittered_busy_retry_delay(retry_after: Duration) -> Duration {
    let base = retry_after
        .max(BUSY_RETRY_MIN_DELAY)
        .min(BUSY_RETRY_BASE_MAX_DELAY);
    let jitter =
        Duration::from_millis(rand::thread_rng().gen_range(0..=BUSY_RETRY_JITTER_MAX_MILLIS));
    base.saturating_add(jitter)
}

async fn wait_for_replay_retry(
    busy: &ReplayBusyUntil,
    outbound: &crate::outbound::OutboundSender,
    availability: Option<&AvailabilityFence>,
    recovery_deadline: tokio::time::Instant,
) -> bool {
    if availability.is_some_and(|fence| !fence.current()) {
        return false;
    }
    let now = tokio::time::Instant::now();
    if now >= recovery_deadline {
        return false;
    }
    let delay = jittered_busy_retry_delay(busy.retry_after)
        .min(recovery_deadline.saturating_duration_since(now));
    let retry_at = now + delay;
    // OutboundSender exposes its shared backpressure-disconnect latch, but not
    // raw mpsc receiver closure. Session teardown aborts this supervised
    // post-action task; the absolute recovery deadline is the final bound for
    // Bind 2 reconciliation, whose pre-presence lifecycle intentionally has
    // no availability fence.
    let transport_cancelled = outbound.backpressure_disconnect();
    loop {
        if availability.is_some_and(|fence| !fence.current()) {
            return false;
        }
        let now = tokio::time::Instant::now();
        if now >= recovery_deadline {
            return false;
        }
        if now >= retry_at {
            return true;
        }
        let sleep_for = retry_at
            .saturating_duration_since(now)
            .min(AVAILABILITY_POLL_INTERVAL);
        tokio::select! {
            _ = tokio::time::sleep(sleep_for) => {}
            _ = transport_cancelled.cancelled() => return false,
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn acquire_replay_session(
    service: &ReplayService,
    outbound: &crate::outbound::OutboundSender,
    recipient_id: Uuid,
    current_full_jid: &str,
    explicit_cutoff: Option<chrono::DateTime<chrono::Utc>>,
    availability: Option<&AvailabilityFence>,
    recovery_deadline: tokio::time::Instant,
) -> Result<Option<ReplaySession>> {
    loop {
        if availability.is_some_and(|fence| !fence.current()) {
            return Ok(None);
        }
        if tokio::time::Instant::now() >= recovery_deadline {
            return Ok(None);
        }
        let started = match tokio::time::timeout_at(
            recovery_deadline,
            service.start(recipient_id, current_full_jid, explicit_cutoff),
        )
        .await
        {
            Ok(started) => started?,
            Err(_) => return Ok(None),
        };
        match started {
            ReplayStartOutcome::Acquired(session) => return Ok(Some(session)),
            ReplayStartOutcome::BusyUntil(busy) => {
                tracing::debug!(
                    %recipient_id,
                    resource = %current_full_jid,
                    expires_at = %busy.expires_at,
                    "offline replay resource lease is busy; scheduling a bounded retry"
                );
                if !wait_for_replay_retry(&busy, outbound, availability, recovery_deadline).await {
                    return Ok(None);
                }
            }
        }
    }
}

async fn release_unsent_suffix(
    service: &ReplayService,
    session: &ReplaySession,
    page_claim_token: Uuid,
    ids: &[Uuid],
    recovery_deadline: tokio::time::Instant,
) {
    if ids.is_empty() {
        return;
    }
    match tokio::time::timeout_at(
        recovery_deadline,
        service.release_unsent(session, page_claim_token, ids),
    )
    .await
    {
        Ok(Ok(_)) => {}
        Ok(Err(error)) => {
            tracing::warn!(
                ?error,
                recipient_id = %session.recipient_id(),
                %page_claim_token,
                "failed to release an untransferred offline replay suffix; claims remain crash-recoverable"
            );
        }
        Err(_) => {
            tracing::warn!(
                recipient_id = %session.recipient_id(),
                %page_claim_token,
                "offline replay deadline elapsed while releasing an untransferred suffix; claims remain crash-recoverable"
            );
        }
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "the replay entry point keeps recipient authority, privacy, cutoff, and availability fences explicit"
)]
async fn drain_offline(
    state: &Arc<AppState>,
    outbound: &crate::outbound::OutboundSender,
    recipient_id: Uuid,
    current_full_jid: &str,
    active_privacy_list: Option<&str>,
    bind2_mam_catchup: bool,
    explicit_cutoff: Option<chrono::DateTime<chrono::Utc>>,
    availability: Option<&AvailabilityFence>,
) -> Result<usize> {
    let service = state.replay_service().clone();
    let recovery_deadline = tokio::time::Instant::now() + REPLAY_RECOVERY_DEADLINE;
    let work_deadline = recovery_deadline
        .checked_sub(REPLAY_CLEANUP_RESERVE)
        .unwrap_or(recovery_deadline);
    let Some(session) = acquire_replay_session(
        &service,
        outbound,
        recipient_id,
        current_full_jid,
        explicit_cutoff,
        availability,
        work_deadline,
    )
    .await?
    else {
        return Ok(0);
    };
    let result = drain_owned_offline(
        &service,
        &session,
        outbound,
        active_privacy_list,
        bind2_mam_catchup,
        availability,
        work_deadline,
        recovery_deadline,
    )
    .await;
    let released = match tokio::time::timeout_at(recovery_deadline, service.finish(&session)).await
    {
        Ok(released) => released,
        Err(_) => Err(anyhow::anyhow!(
            "offline replay owner lease release exceeded the recovery deadline"
        )),
    };
    match (result, released) {
        (Ok(delivered), Ok(true)) => Ok(delivered),
        (Ok(_), Ok(false)) => anyhow::bail!("offline replay owner lease was lost before release"),
        (Ok(_), Err(error)) => Err(error).context("failed to release offline replay owner lease"),
        (Err(error), Ok(_)) => Err(error),
        (Err(error), Err(release_error)) => {
            tracing::warn!(
                ?release_error,
                recipient_id = %session.recipient_id(),
                "offline replay failed and its owner lease could not be released; expiry will recover it"
            );
            Err(error)
        }
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "the owned replay loop must carry both lease deadlines and the exact policy/availability fences"
)]
async fn drain_owned_offline(
    service: &ReplayService,
    session: &ReplaySession,
    outbound: &crate::outbound::OutboundSender,
    active_privacy_list: Option<&str>,
    bind2_mam_catchup: bool,
    availability: Option<&AvailabilityFence>,
    work_deadline: tokio::time::Instant,
    recovery_deadline: tokio::time::Instant,
) -> Result<usize> {
    let mut delivered = 0usize;
    loop {
        if tokio::time::Instant::now() >= work_deadline {
            return Ok(delivered);
        }
        if availability.is_some_and(|fence| !fence.current()) {
            return Ok(delivered);
        }
        let claimed = match tokio::time::timeout_at(
            work_deadline,
            service.claim_page(session, active_privacy_list, bind2_mam_catchup),
        )
        .await
        {
            Ok(claimed) => claimed?,
            Err(_) => return Ok(delivered),
        };
        let page = match claimed {
            ReplayPageOutcome::Claimed(page) => page,
            ReplayPageOutcome::Empty => return Ok(delivered),
            ReplayPageOutcome::LeaseLost => {
                anyhow::bail!("offline replay owner lease expired before page claim")
            }
        };
        if page.messages.is_empty() {
            continue;
        }
        for (index, message) in page.messages.iter().enumerate() {
            let suffix = page.messages[index..]
                .iter()
                .map(|message| message.id)
                .collect::<Vec<_>>();
            if tokio::time::Instant::now() >= work_deadline {
                release_unsent_suffix(
                    service,
                    session,
                    page.claim_token,
                    &suffix,
                    recovery_deadline,
                )
                .await;
                return Ok(delivered);
            }
            if availability.is_some_and(|fence| !fence.current()) {
                release_unsent_suffix(
                    service,
                    session,
                    page.claim_token,
                    &suffix,
                    recovery_deadline,
                )
                .await;
                return Ok(delivered);
            }
            let renewed = match tokio::time::timeout_at(
                work_deadline,
                service.renew_before_send(session, page.claim_token, &suffix),
            )
            .await
            {
                Ok(Ok(renewed)) => renewed,
                Ok(Err(error)) => {
                    release_unsent_suffix(
                        service,
                        session,
                        page.claim_token,
                        &suffix,
                        recovery_deadline,
                    )
                    .await;
                    return Err(error).context("offline replay fence renewal failed");
                }
                Err(_) => {
                    release_unsent_suffix(
                        service,
                        session,
                        page.claim_token,
                        &suffix,
                        recovery_deadline,
                    )
                    .await;
                    return Ok(delivered);
                }
            };
            if !renewed {
                release_unsent_suffix(
                    service,
                    session,
                    page.claim_token,
                    &suffix,
                    recovery_deadline,
                )
                .await;
                anyhow::bail!("offline replay ownership was lost before transport send");
            }
            // Renewal can wait on PostgreSQL. Revalidate availability after
            // that await so an unavailable transition cannot leak one final
            // stanza into the old resource.
            if availability.is_some_and(|fence| !fence.current())
                || tokio::time::Instant::now() >= work_deadline
            {
                release_unsent_suffix(
                    service,
                    session,
                    page.claim_token,
                    &suffix,
                    recovery_deadline,
                )
                .await;
                return Ok(delivered);
            }
            let send_deadline = work_deadline.min(
                tokio::time::Instant::now()
                    .checked_add(OUTBOUND_BACKPRESSURE_TIMEOUT)
                    .unwrap_or(work_deadline),
            );
            match tokio::time::timeout_at(
                send_deadline,
                outbound.send_durable_if_current(
                    message.stanza.clone(),
                    crate::outbound::DurableDelivery {
                        recipient_id: session.recipient_id(),
                        message_id: message.id,
                        claim_id: Some(page.claim_token),
                    },
                    || availability.is_none_or(AvailabilityFence::current),
                ),
            )
            .await
            {
                Ok(Ok(true)) => delivered += 1,
                Ok(Ok(false)) => {
                    release_unsent_suffix(
                        service,
                        session,
                        page.claim_token,
                        &suffix,
                        recovery_deadline,
                    )
                    .await;
                    return Ok(delivered);
                }
                Ok(Err(_)) => {
                    release_unsent_suffix(
                        service,
                        session,
                        page.claim_token,
                        &suffix,
                        recovery_deadline,
                    )
                    .await;
                    return Ok(delivered);
                }
                Err(_) => {
                    outbound.disconnect_backpressured_transport();
                    release_unsent_suffix(
                        service,
                        session,
                        page.claim_token,
                        &suffix,
                        recovery_deadline,
                    )
                    .await;
                    return Ok(delivered);
                }
            }
        }
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "the post-presence replay task captures one immutable availability generation and its complete policy snapshot"
)]
pub(crate) async fn replay_newly_available_resource(
    state: Arc<AppState>,
    outbound: crate::outbound::OutboundSender,
    recipient_id: Uuid,
    account: String,
    full_jid: String,
    active_privacy_list: Option<String>,
    bind2_mam_catchup: bool,
    include_offline: bool,
    available: Arc<AtomicBool>,
    availability_generation: Arc<AtomicU64>,
    expected_generation: u64,
    offline_replay_cutoff: Option<chrono::DateTime<chrono::Utc>>,
) {
    let availability = AvailabilityFence {
        available,
        generation: availability_generation,
        expected_generation,
    };
    if !availability.current() {
        return;
    }
    if include_offline {
        if let Err(error) = drain_offline(
            &state,
            &outbound,
            recipient_id,
            &full_jid,
            active_privacy_list.as_deref(),
            bind2_mam_catchup,
            offline_replay_cutoff,
            Some(&availability),
        )
        .await
        {
            tracing::warn!(?error, %recipient_id, "durable offline replay stopped; unacknowledged rows remain retryable");
            return;
        }
    }

    let service = state.replay_service().clone();
    let mut cursor = None;
    loop {
        if !availability.current() {
            return;
        }
        let page = match service
            .pending_presence_page(
                recipient_id,
                &account,
                active_privacy_list.as_deref(),
                cursor.as_ref(),
            )
            .await
        {
            Ok(page) => page,
            Err(error) => {
                tracing::warn!(?error, %recipient_id, "pending subscription replay policy snapshot failed closed");
                return;
            }
        };
        cursor = page.next_cursor;
        for pending in page.items {
            if !availability.current() {
                return;
            }
            let candidate = pending.requester;
            let request = pending.stanza.map_or_else(
                || {
                    format!(
                        "<presence xmlns='jabber:client' from='{}' to='{}' type='subscribe'/>",
                        attr_escape(&candidate),
                        attr_escape(&full_jid),
                    )
                },
                |stanza| crate::xmpp::xml_util::set_to(&stanza, &full_jid),
            );
            if outbound.send(request).await.is_err() {
                return;
            }
        }
        if page.complete {
            return;
        }
        if cursor.is_none() {
            tracing::warn!(%recipient_id, "pending subscription replay returned an incomplete page without a cursor");
            return;
        }
    }
}

pub(crate) async fn replay_bind2_offline(
    state: Arc<AppState>,
    outbound: crate::outbound::OutboundSender,
    recipient_id: Uuid,
    full_jid: String,
) {
    if let Err(error) = drain_offline(
        &state,
        &outbound,
        recipient_id,
        &full_jid,
        None,
        true,
        None,
        None,
    )
    .await
    {
        tracing::warn!(?error, %recipient_id, "deferred Bind 2 offline reconciliation failed; durable rows remain retryable");
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "the resumed replay task carries one immutable availability generation and privacy snapshot"
)]
pub(crate) async fn replay_resumed_offline(
    state: Arc<AppState>,
    outbound: crate::outbound::OutboundSender,
    recipient_id: Uuid,
    full_jid: String,
    active_privacy_list: Option<String>,
    available: Arc<AtomicBool>,
    availability_generation: Arc<AtomicU64>,
    expected_generation: u64,
) {
    let availability = AvailabilityFence {
        available,
        generation: availability_generation,
        expected_generation,
    };
    if !availability.current() {
        return;
    }
    if let Err(error) = drain_offline(
        &state,
        &outbound,
        recipient_id,
        &full_jid,
        active_privacy_list.as_deref(),
        false,
        None,
        Some(&availability),
    )
    .await
    {
        tracing::warn!(?error, %recipient_id, "offline delivery failed after SM resume; durable rows remain retryable");
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "the priority-transition replay task carries one immutable availability generation and cutoff"
)]
pub(crate) async fn replay_newly_nonnegative_resource(
    state: Arc<AppState>,
    outbound: crate::outbound::OutboundSender,
    recipient_id: Uuid,
    full_jid: String,
    active_privacy_list: Option<String>,
    available: Arc<AtomicBool>,
    availability_generation: Arc<AtomicU64>,
    expected_generation: u64,
    offline_replay_cutoff: chrono::DateTime<chrono::Utc>,
) {
    let availability = AvailabilityFence {
        available,
        generation: availability_generation,
        expected_generation,
    };
    if !availability.current() {
        return;
    }
    if let Err(error) = drain_offline(
        &state,
        &outbound,
        recipient_id,
        &full_jid,
        active_privacy_list.as_deref(),
        false,
        Some(offline_replay_cutoff),
        Some(&availability),
    )
    .await
    {
        tracing::warn!(?error, %recipient_id, "offline delivery failed after priority became nonnegative; durable rows remain retryable");
    }
}

fn is_current_availability(
    available: &AtomicBool,
    generation: &AtomicU64,
    expected_generation: u64,
) -> bool {
    available.load(Ordering::Acquire) && generation.load(Ordering::Acquire) == expected_generation
}

#[cfg(test)]
#[path = "replay_tests.rs"]
mod tests;
