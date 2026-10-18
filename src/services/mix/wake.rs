//! Provides lossless local observation of committed durable MIX delivery wakes.

use super::*;

/// Process-local observation of a durable MIX-outbox change.
///
/// PostgreSQL rows remain the sole delivery authority.  This value is only a
/// monotonic wake generation: `watch` retains it until every receiver has
/// observed it, so a database notification that arrives between a worker's
/// claim and its next wait cannot be lost.  The dedicated PostgreSQL listener
/// advances the same generation after reconnecting, forcing a fresh durable
/// probe for notifications that may have been missed during that gap.
#[derive(Debug)]
pub(crate) struct MixDeliveryWakeBroker {
    pub(super) schema: String,
    pub(super) sender: watch::Sender<u64>,
}

impl MixDeliveryWakeBroker {
    pub(super) fn new(schema: String) -> Result<Arc<Self>> {
        anyhow::ensure!(
            !schema.is_empty()
                && schema.len() <= 63
                && !schema.contains('\0')
                && schema != "pg_catalog"
                && schema != "information_schema",
            "invalid PostgreSQL schema for MIX outbox wake listener"
        );
        let (sender, _) = watch::channel(0_u64);
        Ok(Arc::new(Self { schema, sender }))
    }

    pub(super) fn advance(&self) {
        // A u64 wrap would require more than 5.8e11 committed outbox changes
        // per second for a year.  `watch` also records its own change version,
        // so a theoretical numeric wrap cannot erase an already published
        // edge for a live receiver.
        // `send_modify` serializes the read/advance/publish operation inside
        // the watch state. A separate atomic increment followed by
        // `send_replace` could publish generations out of numeric order under
        // concurrent local commits and listener notifications.
        self.sender
            .send_modify(|generation| *generation = generation.wrapping_add(1));
    }

    /// Record a local mutation only after its transaction-returning service
    /// call has completed successfully.  The database trigger publishes the
    /// same committed fact to other processes; this direct edge avoids making
    /// the writer wait for its own listener under CPU pressure.
    pub(crate) fn publish_local_commit(&self) {
        self.advance();
    }

    /// A listener start, transparent reconnect, or terminal receive error
    /// may have missed a PostgreSQL notification.  Wake every lane so it
    /// performs an authoritative claim; the periodic scan remains the final
    /// recovery path if PostgreSQL itself is unavailable.
    pub(crate) fn publish_listener_transition(&self) {
        self.advance();
    }

    /// Accept the bounded, non-secret schema payload emitted by migration
    /// 0133.  An unexpected payload has no authority and must not generate
    /// unrelated cross-schema load.
    pub(crate) fn accept_committed_notification(&self, schema: &str) -> bool {
        if schema != self.schema {
            return false;
        }
        self.advance();
        true
    }

    pub(crate) fn subscribe(&self) -> MixDeliveryWakeSubscription {
        MixDeliveryWakeSubscription {
            receiver: self.sender.subscribe(),
        }
    }
}

/// One MIX outbox lane's lossless local wake receiver.
pub(crate) struct MixDeliveryWakeSubscription {
    pub(super) receiver: watch::Receiver<u64>,
}

impl MixDeliveryWakeSubscription {
    /// `watch` retains an unseen value.  Therefore this resolves immediately
    /// for a notification that happened before a lane installed its next
    /// wait, rather than relying on an edge-triggered `Notify` permit.
    pub(crate) async fn changed(&mut self) -> bool {
        self.receiver.changed().await.is_ok()
    }
}

impl<R: MixRepository> MixService<R> {
    /// Expose the broker only to the existing dedicated PostgreSQL listener.
    /// Protocol handlers receive subscriptions, never a raw notification
    /// sender, so they cannot turn uncommitted input into a wake fact.
    pub(crate) fn delivery_wake_broker(&self) -> Arc<MixDeliveryWakeBroker> {
        Arc::clone(&self.delivery_wake)
    }
}
