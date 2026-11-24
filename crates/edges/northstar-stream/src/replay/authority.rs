use super::*;
use northstar_session_application::replay::{ReplayMessage, ReplayPreparation};
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
        Self::new(
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
                                && entry.connection_id == expected.connection_id
                                && entry.user_id == expected.recipient_id
                                && entry.auth_generation == expected.auth_generation
                                && entry.routable.load(Ordering::Acquire)
                                && entry.lifecycle.load(Ordering::Acquire) == 0
                                && !entry.disconnect.is_cancelled()
                        })
                    })
            }),
        )
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
