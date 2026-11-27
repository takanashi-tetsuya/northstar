use super::*;
use crate::local_routes::{
    pending_subscription::deliver_pending_subscription, session::OnlineSession,
};
use northstar_session_application::replay::{
    pending_presence::PendingPresenceAuthority, PendingPresenceReplay, ReplayMessage,
    ReplayPreparation,
};
use std::{
    future::Future,
    sync::RwLock,
    task::{Context as TaskContext, Poll, Wake, Waker},
};

/// The exact transport and live privacy selection of one replay entry.
pub struct ReplayTarget {
    pub(super) route: ReplayRoute,
    privacy_active: Arc<RwLock<Option<String>>>,
    is_current: Arc<dyn Fn() -> bool + Send + Sync>,
    pub(super) pending_route: Option<OnlineSession>,
}

impl ReplayTarget {
    pub fn new(
        route: ReplayRoute,
        privacy_active: Arc<RwLock<Option<String>>>,
        is_current: Arc<dyn Fn() -> bool + Send + Sync>,
    ) -> Self {
        Self {
            route,
            privacy_active,
            is_current,
            pending_route: None,
        }
    }

    pub fn for_session<H: crate::protocol::host::SessionHost>(
        session: &crate::protocol::ProtocolSession<H>,
        account: &northstar_auth_application::authentication::AuthenticatedAccount,
        full_jid: &str,
    ) -> Self {
        let route = ReplayRoute {
            recipient_id: account.id,
            auth_generation: account.auth_generation,
            connection_id: session.connection_id,
            full_jid: full_jid.to_owned(),
        };
        let expected = route.clone();
        let host = Arc::downgrade(session.host());
        let disconnect = session.disconnect.clone();
        let pending_route = crate::protocol::host::SessionRoutesHost::session_entries_for(
            &**session.host(),
            full_jid,
        )
        .into_iter()
        .find(|(jid, entry)| jid == full_jid && matches_route(&route, entry))
        .map(|(_, entry)| entry);
        let mut target = Self::new(
            route,
            session.privacy_active.clone(),
            Arc::new(move || {
                !disconnect.is_cancelled()
                    && host.upgrade().is_some_and(|host| {
                        crate::protocol::host::SessionRoutesHost::session_entries_for(
                            &*host,
                            &expected.full_jid,
                        )
                        .iter()
                        .any(|(jid, entry)| {
                            jid == &expected.full_jid
                                && matches_route(&expected, entry)
                                && entry.routable.load(Ordering::Acquire)
                                && entry.lifecycle.load(Ordering::Acquire) == 0
                                && !entry.disconnect.is_cancelled()
                        })
                    })
            }),
        );
        target.pending_route = pending_route;
        target
    }

    pub(super) fn current(&self) -> bool {
        (self.is_current)()
    }

    pub(super) fn selected_privacy(&self) -> Option<String> {
        self.privacy_active
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub(super) fn selection_is(&self, expected: &Option<String>) -> bool {
        self.privacy_active
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .eq(expected)
    }
}

fn matches_route(route: &ReplayRoute, session: &OnlineSession) -> bool {
    session.connection_id == route.connection_id
        && session.user_id == route.recipient_id
        && session.auth_generation == route.auth_generation
}

pub(super) async fn handoff_pending(
    service: &ReplayService<impl ReplayAuthorityRepository>,
    outbound: &crate::outbound::OutboundSender,
    target: &ReplayTarget,
    availability: &AvailabilityFence,
    selection: &Option<String>,
    pending: &PendingPresenceReplay,
    stanza: String,
) -> Result<()> {
    let Some(session) = &target.pending_route else {
        return Ok(());
    };
    let current = || target.current() && availability.current() && target.selection_is(selection);
    let mut policy_result = Ok(());
    let send = outbound.send_if_current_and(
        stanza,
        current,
        async {
            let authority = PendingPresenceAuthority {
                route: &target.route,
                expects_active: selection.is_some(),
            };
            match service
                .pending_presence_is_current(authority, pending)
                .await
            {
                Ok(allowed) => allowed,
                Err(error) => {
                    policy_result = Err(error);
                    false
                }
            }
        },
        || {
            // The sink already owns the queue permit and sends synchronously.
            deliver_pending_subscription(
                session,
                availability.expected_generation,
                (&pending.cursor).into(),
                || true,
            )
        },
    );
    tokio::select! {
        biased;
        _ = session.disconnect.cancelled() => return Ok(()),
        result = send => {
            result.map_err(|_| anyhow::anyhow!("pending subscription replay queue closed"))?;
        }
    }
    policy_result
}

pub(super) enum ReplayHandoff {
    Queued,
    Suppressed,
    RetryPage,
    Stopped,
    Backpressured,
}

struct QueueWake(tokio::sync::Notify);

impl Wake for QueueWake {
    fn wake(self: Arc<Self>) {
        self.0.notify_one();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.notify_one();
    }
}

/// The outbound future reserves capacity on first poll. Poll it under the
/// checked database fence, but if it needs to wait, release the fence before
/// listening for capacity. The same queued reservation is polled only after
/// a fresh authority check, including after a capacity wake.
pub(super) async fn handoff(
    service: &ReplayService<impl ReplayAuthorityRepository>,
    session: &ReplaySession,
    outbound: &crate::outbound::OutboundSender,
    message: ReplayMessage,
    authority: ReplayMessageAuthority<'_>,
    deadline: tokio::time::Instant,
) -> Result<ReplayHandoff> {
    let current = authority.route.is_current;
    let wake = Arc::new(QueueWake(tokio::sync::Notify::new()));
    let waker = Waker::from(wake.clone());
    let mut send = std::pin::pin!(outbound.send_durable_if_current(
        message.stanza,
        crate::outbound::DurableDelivery {
            recipient_id: session.recipient_id(),
            message_id: message.id,
            claim_id: Some(authority.claim_token),
        },
        || current() && tokio::time::Instant::now() < deadline,
    ));
    loop {
        if !current() {
            return Ok(ReplayHandoff::RetryPage);
        }
        let guard = match tokio::time::timeout_at(
            deadline,
            service.prepare_current_message(session, authority),
        )
        .await
        {
            Ok(result) => match result? {
                ReplayPreparation::Ready(guard) => guard,
                ReplayPreparation::Suppressed => return Ok(ReplayHandoff::Suppressed),
                ReplayPreparation::RetryPage => return Ok(ReplayHandoff::RetryPage),
                ReplayPreparation::StaleRoute => return Ok(ReplayHandoff::Stopped),
            },
            Err(_) => return Ok(ReplayHandoff::Stopped),
        };
        let queued = send.as_mut().poll(&mut TaskContext::from_waker(&waker));
        if let Ok(Err(error)) = tokio::time::timeout_at(deadline, guard.release()).await {
            tracing::warn!(?error, recipient_id = %session.recipient_id(), "offline replay authority release failed");
        }
        match queued {
            Poll::Ready(Ok(true)) => return Ok(ReplayHandoff::Queued),
            Poll::Ready(Ok(false)) if !current() => return Ok(ReplayHandoff::RetryPage),
            Poll::Ready(_) => return Ok(ReplayHandoff::Stopped),
            Poll::Pending => {}
        }
        while current() {
            tokio::select! {
                _ = tokio::time::sleep_until(deadline) => return Ok(ReplayHandoff::Backpressured),
                _ = wake.0.notified() => break,
                _ = tokio::time::sleep(AVAILABILITY_POLL_INTERVAL) => {},
            }
        }
    }
}
