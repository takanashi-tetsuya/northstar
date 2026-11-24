//! XEP-0160 offline replay and pending subscription replay onto one stream's
//! outbound queue, fenced by that resource's availability generation.

use anyhow::{Context, Result};
use northstar_session_application::replay::{
    AuthorizedReplayClaim, ReplayAuthorityRepository, ReplayBusyUntil, ReplayMessageAuthority,
    ReplayPageAuthority, ReplayRepository, ReplayRoute, ReplayService, ReplaySession,
    ReplayStartOutcome,
};
use northstar_xml_builder::escape::attr_escape;
use rand::Rng;
use std::{
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use uuid::Uuid;

mod authority;
pub use authority::ReplayTarget;
use authority::{handoff, ReplayHandoff};

const OUTBOUND_BACKPRESSURE_TIMEOUT: Duration = Duration::from_secs(5);
const RECOVERY_AUTHORITY_HOLD_TIMEOUT: Duration = Duration::from_millis(750);
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
    is_current: &(dyn Fn() -> bool + Sync),
    recovery_deadline: tokio::time::Instant,
) -> bool {
    if !is_current() {
        return false;
    }
    let now = tokio::time::Instant::now();
    if now >= recovery_deadline {
        return false;
    }
    let delay = jittered_busy_retry_delay(busy.retry_after)
        .min(recovery_deadline.saturating_duration_since(now));
    let retry_at = now + delay;
    let transport_cancelled = outbound.backpressure_disconnect();
    loop {
        if !is_current() {
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

async fn acquire_replay_session(
    service: &ReplayService<impl ReplayRepository>,
    outbound: &crate::outbound::OutboundSender,
    route: &ReplayRoute,
    explicit_cutoff: Option<northstar_time::DateTime<northstar_time::Utc>>,
    is_current: &(dyn Fn() -> bool + Sync),
    recovery_deadline: tokio::time::Instant,
) -> Result<Option<ReplaySession>> {
    loop {
        if !is_current() {
            return Ok(None);
        }
        if tokio::time::Instant::now() >= recovery_deadline {
            return Ok(None);
        }
        let started = match tokio::time::timeout_at(
            recovery_deadline,
            service.start(route.clone(), explicit_cutoff),
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
                    recipient_id = %route.recipient_id,
                    resource = %route.full_jid,
                    expires_at = %busy.expires_at,
                    "offline replay resource lease is busy; scheduling a bounded retry"
                );
                if !wait_for_replay_retry(&busy, outbound, is_current, recovery_deadline).await {
                    return Ok(None);
                }
            }
        }
    }
}

async fn release_unsent_suffix(
    service: &ReplayService<impl ReplayRepository>,
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

async fn drain_offline(
    service: &ReplayService<impl ReplayAuthorityRepository>,
    outbound: &crate::outbound::OutboundSender,
    target: &ReplayTarget,
    bind2_mam_catchup: bool,
    explicit_cutoff: Option<northstar_time::DateTime<northstar_time::Utc>>,
    availability: Option<&AvailabilityFence>,
    recovery: bool,
) -> Result<(usize, bool)> {
    let recovery_deadline = tokio::time::Instant::now() + REPLAY_RECOVERY_DEADLINE;
    let work_deadline = recovery_deadline
        .checked_sub(REPLAY_CLEANUP_RESERVE)
        .unwrap_or(recovery_deadline);
    let disconnected = outbound.backpressure_disconnect();
    let is_current = || {
        !disconnected.is_cancelled()
            && target.current()
            && availability.is_none_or(AvailabilityFence::current)
    };
    let Some(session) = acquire_replay_session(
        service,
        outbound,
        &target.route,
        explicit_cutoff,
        &is_current,
        work_deadline,
    )
    .await?
    else {
        return Ok((0, false));
    };
    let result = drain_owned_offline(
        service,
        &session,
        outbound,
        target,
        bind2_mam_catchup,
        &is_current,
        recovery,
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
    reason = "one owned replay pass carries its route, cutoff budget and policy mode"
)]
async fn drain_owned_offline(
    service: &ReplayService<impl ReplayAuthorityRepository>,
    session: &ReplaySession,
    outbound: &crate::outbound::OutboundSender,
    target: &ReplayTarget,
    bind2_mam_catchup: bool,
    is_current: &(dyn Fn() -> bool + Send + Sync),
    recovery: bool,
    recovery_deadline: tokio::time::Instant,
) -> Result<(usize, bool)> {
    let work_deadline = recovery_deadline - REPLAY_CLEANUP_RESERVE;
    let budget = if recovery {
        RECOVERY_AUTHORITY_HOLD_TIMEOUT
    } else {
        OUTBOUND_BACKPRESSURE_TIMEOUT
    };
    let mut delivered = 0;
    'pages: while is_current() && tokio::time::Instant::now() < work_deadline {
        let selected_privacy = target.selected_privacy();
        let page_current = || is_current() && target.selection_is(&selected_privacy);
        let page_authority = ReplayPageAuthority {
            active_privacy_list: selected_privacy.as_deref(),
            is_current: &page_current,
        };
        let claim_deadline = if recovery {
            work_deadline.min(tokio::time::Instant::now() + budget)
        } else {
            work_deadline
        };
        let claimed = tokio::time::timeout_at(
            claim_deadline,
            service.claim_current_page(session, page_authority, bind2_mam_catchup),
        )
        .await;
        let page = match claimed {
            Ok(Ok(AuthorizedReplayClaim::Claimed(page))) => page,
            Ok(Ok(AuthorizedReplayClaim::Empty)) if is_current() && !page_current() => continue,
            Ok(Ok(AuthorizedReplayClaim::Empty)) => return Ok((delivered, page_current())),
            Ok(Ok(AuthorizedReplayClaim::StaleRoute)) if is_current() && !page_current() => {
                continue
            }
            Ok(Ok(AuthorizedReplayClaim::StaleRoute | AuthorizedReplayClaim::PendingClaims))
            | Err(_) => return Ok((delivered, false)),
            Ok(Ok(AuthorizedReplayClaim::LeaseLost)) => {
                anyhow::bail!("offline replay owner lease expired before page claim")
            }
            Ok(Err(error)) => return Err(error),
        };
        let ids: Vec<_> = page
            .messages
            .iter()
            .map(|(message, _)| message.id)
            .collect();
        for (index, (message, disposition)) in page.messages.into_iter().enumerate() {
            let suffix = &ids[index..];
            let result = if !page_current() {
                Ok(ReplayHandoff::RetryPage)
            } else {
                match tokio::time::timeout_at(
                    work_deadline,
                    service.renew_before_send(session, page.claim_token, suffix),
                )
                .await
                {
                    Ok(Ok(true)) => {
                        handoff(
                            service,
                            session,
                            outbound,
                            message,
                            ReplayMessageAuthority {
                                route: page_authority,
                                policy_version: &page.policy_version,
                                claim_token: page.claim_token,
                                message_id: suffix[0],
                                disposition,
                            },
                            work_deadline.min(tokio::time::Instant::now() + budget),
                        )
                        .await
                    }
                    Ok(Ok(false)) => Err(anyhow::anyhow!(
                        "offline replay ownership was lost before transport send"
                    )),
                    Ok(Err(error)) => Err(error).context("offline replay fence renewal failed"),
                    Err(_) => Ok(ReplayHandoff::Stopped),
                }
            };
            match result {
                Ok(ReplayHandoff::Queued) => delivered += 1,
                Ok(ReplayHandoff::Suppressed) => {}
                outcome => {
                    release_unsent_suffix(
                        service,
                        session,
                        page.claim_token,
                        suffix,
                        recovery_deadline,
                    )
                    .await;
                    match outcome? {
                        ReplayHandoff::RetryPage => continue 'pages,
                        ReplayHandoff::Backpressured if !recovery => {
                            outbound.disconnect_backpressured_transport()
                        }
                        ReplayHandoff::Stopped | ReplayHandoff::Backpressured => {}
                        ReplayHandoff::Queued | ReplayHandoff::Suppressed => unreachable!(),
                    }
                    return Ok((delivered, false));
                }
            }
        }
    }
    Ok((delivered, false))
}

#[expect(
    clippy::too_many_arguments,
    reason = "the post-presence replay task captures one immutable availability generation and its complete policy snapshot"
)]
pub async fn replay_newly_available_resource(
    service: ReplayService<impl ReplayAuthorityRepository>,
    outbound: crate::outbound::OutboundSender,
    target: ReplayTarget,
    account: String,
    bind2_mam_catchup: bool,
    include_offline: bool,
    available: Arc<AtomicBool>,
    availability_generation: Arc<AtomicU64>,
    expected_generation: u64,
    offline_replay_cutoff: Option<northstar_time::DateTime<northstar_time::Utc>>,
) {
    let availability = AvailabilityFence {
        available,
        generation: availability_generation,
        expected_generation,
    };
    let recipient_id = target.route.recipient_id;
    let full_jid = &target.route.full_jid;
    if !target.current() || !availability.current() {
        return;
    }
    if include_offline {
        if let Err(error) = drain_offline(
            &service,
            &outbound,
            &target,
            bind2_mam_catchup,
            offline_replay_cutoff,
            Some(&availability),
            false,
        )
        .await
        {
            tracing::warn!(?error, %recipient_id, "durable offline replay stopped; unacknowledged rows remain retryable");
            return;
        }
    }

    let mut cursor = None;
    loop {
        if !target.current() || !availability.current() {
            return;
        }
        let active_privacy_list = target.selected_privacy();
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
            if !target.current()
                || !availability.current()
                || !target.selection_is(&active_privacy_list)
            {
                return;
            }
            let candidate = pending.requester;
            let request = pending.stanza.map_or_else(
                || {
                    format!(
                        "<presence xmlns='jabber:client' from='{}' to='{}' type='subscribe'/>",
                        attr_escape(&candidate),
                        attr_escape(full_jid),
                    )
                },
                |stanza| northstar_xml_builder::rewrite::set_to(&stanza, full_jid),
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
    service: ReplayService<impl ReplayAuthorityRepository>,
    outbound: crate::outbound::OutboundSender,
    target: ReplayTarget,
) {
    if let Err(error) = drain_offline(&service, &outbound, &target, true, None, None, false).await {
        tracing::warn!(?error, recipient_id = %target.route.recipient_id, "deferred Bind 2 offline reconciliation failed; durable rows remain retryable");
    }
}

pub(crate) async fn replay_resumed_offline(
    service: ReplayService<impl ReplayAuthorityRepository>,
    outbound: crate::outbound::OutboundSender,
    target: ReplayTarget,
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
        &service,
        &outbound,
        &target,
        false,
        None,
        Some(&availability),
        false,
    )
    .await
    {
        tracing::warn!(?error, recipient_id = %target.route.recipient_id, "offline delivery failed after SM resume; durable rows remain retryable");
    }
}

pub async fn replay_newly_nonnegative_resource(
    service: ReplayService<impl ReplayAuthorityRepository>,
    outbound: crate::outbound::OutboundSender,
    target: ReplayTarget,
    available: Arc<AtomicBool>,
    availability_generation: Arc<AtomicU64>,
    expected_generation: u64,
    offline_replay_cutoff: northstar_time::DateTime<northstar_time::Utc>,
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
        &service,
        &outbound,
        &target,
        false,
        Some(offline_replay_cutoff),
        Some(&availability),
        false,
    )
    .await
    {
        tracing::warn!(?error, recipient_id = %target.route.recipient_id, "offline delivery failed after priority became nonnegative; durable rows remain retryable");
    }
}

/// Redis recovery does not create a new RFC 6121 presence transition. Replay
/// only the durable offline queue for this exact, already-available resource;
/// pending subscription presence and XEP-0198 resume stanzas have independent
/// owners. The caller's route predicate is rechecked across every PG await
/// and immediately before the bounded outbound queue accepts a stanza.
#[expect(
    clippy::too_many_arguments,
    reason = "recovery carries the exact route, availability epoch, privacy selection, and PG cutoff"
)]
pub async fn replay_after_cluster_reconciliation(
    service: ReplayService<impl ReplayAuthorityRepository>,
    outbound: crate::outbound::OutboundSender,
    target: ReplayTarget,
    bind2_mam_catchup: bool,
    available: Arc<AtomicBool>,
    availability_generation: Arc<AtomicU64>,
    expected_generation: u64,
    cutoff: northstar_time::DateTime<northstar_time::Utc>,
) -> bool {
    let availability = AvailabilityFence {
        available,
        generation: availability_generation,
        expected_generation,
    };
    if !availability.current() {
        return false;
    }
    match drain_offline(
        &service,
        &outbound,
        &target,
        bind2_mam_catchup,
        Some(cutoff),
        Some(&availability),
        true,
    )
    .await
    {
        Ok((_, completed)) => completed,
        Err(error) => {
            tracing::warn!(?error, recipient_id = %target.route.recipient_id, full_jid = %target.route.full_jid,
                "cluster recovery offline replay stopped; durable rows remain retryable");
            false
        }
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
