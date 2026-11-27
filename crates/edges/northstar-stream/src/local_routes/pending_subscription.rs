use super::session::OnlineSession;
use northstar_session_application::replay::PendingPresenceCursor;
use std::{
    collections::HashSet,
    sync::{atomic::Ordering, Mutex},
};
use uuid::Uuid;

#[derive(Clone, Eq, Hash, PartialEq)]
pub struct PendingSubscriptionKey {
    source: i16,
    requester: String,
    created_at_micros: i64,
}

impl PendingSubscriptionKey {
    pub fn local(requester: Uuid, created_at_micros: i64) -> Self {
        Self {
            source: 0,
            requester: requester.to_string(),
            created_at_micros,
        }
    }

    pub fn federated(requester: String, created_at_micros: i64) -> Self {
        Self {
            source: 1,
            requester,
            created_at_micros,
        }
    }
}

impl From<&PendingPresenceCursor> for PendingSubscriptionKey {
    fn from(cursor: &PendingPresenceCursor) -> Self {
        Self {
            source: cursor.source,
            requester: cursor.key.clone(),
            created_at_micros: cursor.created_at.timestamp_micros(),
        }
    }
}

/// Accepted subscription requests in one availability epoch of one resource.
#[derive(Default)]
pub struct PendingSubscriptionDelivery {
    accepted: Mutex<(u64, HashSet<PendingSubscriptionKey>)>,
}

/// Admit an exact pending subscription at the synchronous queue boundary.
/// A refused enqueue leaves the request eligible for replay.
pub fn deliver_pending_subscription(
    session: &OnlineSession,
    availability_epoch: u64,
    key: PendingSubscriptionKey,
    enqueue: impl FnOnce() -> bool,
) -> bool {
    let mut accepted = session
        .pending_subscription_delivery
        .accepted
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if !session.routable.load(Ordering::Acquire)
        || session.lifecycle.load(Ordering::Acquire) != 0
        || session.disconnect.is_cancelled()
        || !session.available.load(Ordering::Acquire)
        || session.availability_generation.load(Ordering::Acquire) != availability_epoch
    {
        return false;
    }
    if accepted.0 != availability_epoch {
        *accepted = (availability_epoch, HashSet::new());
    }
    if accepted.1.contains(&key) || !enqueue() {
        return false;
    }
    accepted.1.insert(key);
    true
}
