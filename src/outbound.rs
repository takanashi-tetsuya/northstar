use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// A database-backed C2S delivery which must not be acknowledged merely
/// because it entered an in-memory channel. The transport removes the exact
/// durable row only after the transport's recoverable acknowledgement
/// boundary (XEP-0198 h, BOSH response ack, or the explicit non-SM socket
/// write fallback).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurableDelivery {
    pub recipient_id: Uuid,
    pub message_id: Uuid,
    /// Offline replay enters routing with a fenced claim. Live routing starts
    /// without one; non-SM TCP/WebSocket takes an exact short claim at the
    /// write boundary, while SM/BOSH transfers the row to its protocol owner.
    pub claim_id: Option<Uuid>,
}

/// One XEP-0198 outbound sequence entry.  A durable delivery fence travels
/// with the exact stanza until the client advances `h`; persisting only the
/// XML would recreate the socket-write/database-complete ambiguity after a
/// stream resume.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SmUnackedStanza {
    pub stanza: String,
    pub durable_delivery: Option<DurableDelivery>,
}

impl SmUnackedStanza {
    #[cfg(test)]
    pub fn plain(stanza: String) -> Self {
        Self {
            stanza,
            durable_delivery: None,
        }
    }

    pub fn with_delivery(stanza: String, durable_delivery: Option<DurableDelivery>) -> Self {
        Self {
            stanza,
            durable_delivery,
        }
    }
}

#[derive(Clone, Debug)]
pub struct OutboundItem {
    pub stanza: String,
    pub durable_delivery: Option<DurableDelivery>,
    /// Completion signal for a clustered MUC policy outbox item. It is fired
    /// at durable SM/BOSH ownership or after a non-SM socket write, never when
    /// the stanza merely enters the bounded process channel.
    pub transport_receipt: Option<mpsc::UnboundedSender<()>>,
    /// Process-wide transient SM replay reservation. BOSH attaches the same
    /// shared hold to every control/replay fragment until the corresponding
    /// HTTP response body is completed or discarded. Ordinary routed stanzas
    /// never set this field.
    pub(crate) transient_sm_capacity:
        Option<std::sync::Arc<Vec<crate::services::sm_capacity::SmCapacityLease>>>,
}

impl OutboundItem {
    pub fn plain(stanza: String) -> Self {
        Self {
            stanza,
            durable_delivery: None,
            transport_receipt: None,
            transient_sm_capacity: None,
        }
    }

    pub fn durable(stanza: String, delivery: DurableDelivery) -> Self {
        Self {
            stanza,
            durable_delivery: Some(delivery),
            transport_receipt: None,
            transient_sm_capacity: None,
        }
    }

    pub fn with_transport_receipt(stanza: String, receipt: mpsc::UnboundedSender<()>) -> Self {
        Self {
            stanza,
            durable_delivery: None,
            transport_receipt: Some(receipt),
            transient_sm_capacity: None,
        }
    }

    pub(crate) fn resume_fragment(
        stanza: String,
        capacity: std::sync::Arc<Vec<crate::services::sm_capacity::SmCapacityLease>>,
    ) -> Self {
        Self {
            stanza,
            durable_delivery: None,
            transport_receipt: None,
            transient_sm_capacity: Some(capacity),
        }
    }

    pub fn confirm_transport_ownership(&self) {
        if let Some(receipt) = &self.transport_receipt {
            let _ = receipt.send(());
        }
    }
}

/// Compatibility wrapper around Tokio's bounded sender. Most protocol paths
/// intentionally enqueue ordinary strings; message delivery paths opt into
/// `*_durable` and carry their database acknowledgement fence to the socket.
#[derive(Clone, Debug)]
pub struct OutboundSender {
    inner: mpsc::Sender<OutboundItem>,
    /// A full durable queue is a transport failure, not an offline-routing
    /// decision.  Every clone shares this latch so the owning transport is
    /// torn down before a later stanza can cross the delivery gap.
    backpressure_disconnect: CancellationToken,
}

impl OutboundSender {
    pub fn new(inner: mpsc::Sender<OutboundItem>) -> Self {
        Self {
            inner,
            backpressure_disconnect: CancellationToken::new(),
        }
    }

    pub fn backpressure_disconnect(&self) -> CancellationToken {
        self.backpressure_disconnect.clone()
    }

    pub fn disconnect_backpressured_transport(&self) {
        self.backpressure_disconnect.cancel();
    }

    pub fn try_send(&self, stanza: String) -> Result<(), mpsc::error::TrySendError<String>> {
        self.try_send_item(OutboundItem::plain(stanza))
            .map_err(map_try_send_error)
    }

    pub fn try_send_durable(
        &self,
        stanza: String,
        delivery: DurableDelivery,
    ) -> Result<(), mpsc::error::TrySendError<String>> {
        match self.try_send_item(OutboundItem::durable(stanza, delivery)) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(item)) => {
                self.backpressure_disconnect.cancel();
                Err(mpsc::error::TrySendError::Full(item.stanza))
            }
            Err(mpsc::error::TrySendError::Closed(item)) => {
                Err(mpsc::error::TrySendError::Closed(item.stanza))
            }
        }
    }

    pub async fn send(&self, stanza: String) -> Result<(), mpsc::error::SendError<String>> {
        self.send_item(OutboundItem::plain(stanza))
            .await
            .map_err(|error| mpsc::error::SendError(error.0.stanza))
    }

    #[cfg(test)]
    pub async fn send_durable(
        &self,
        stanza: String,
        delivery: DurableDelivery,
    ) -> Result<(), mpsc::error::SendError<String>> {
        self.send_item(OutboundItem::durable(stanza, delivery))
            .await
            .map_err(|error| mpsc::error::SendError(error.0.stanza))
    }

    /// Queue one durable delivery only while its caller-owned routing fence is
    /// still current. The predicate is evaluated before waiting for channel
    /// capacity and again after capacity is reserved, immediately before the
    /// item crosses the in-memory transport boundary.
    ///
    /// `Ok(false)` means the routing fence changed and the item was not queued;
    /// the caller still owns its durable database projection and must release
    /// or retry that projection. A transport closure remains an error.
    pub async fn send_durable_if_current<F>(
        &self,
        stanza: String,
        delivery: DurableDelivery,
        is_current: F,
    ) -> Result<bool, mpsc::error::SendError<String>>
    where
        F: Fn() -> bool,
    {
        self.send_item_if_current(OutboundItem::durable(stanza, delivery), is_current)
            .await
            .map_err(|error| mpsc::error::SendError(error.0.stanza))
    }

    pub fn try_send_with_transport_receipt(
        &self,
        stanza: String,
        receipt: mpsc::UnboundedSender<()>,
    ) -> Result<(), mpsc::error::TrySendError<String>> {
        match self.try_send_item(OutboundItem::with_transport_receipt(stanza, receipt)) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(item)) => {
                // A transport receipt represents a durable policy/outbox
                // boundary just like `DurableDelivery`: the database item is
                // still pending until this exact stanza becomes recoverable
                // or reaches the socket.  If the bounded queue is full, a
                // later stanza must not overtake that pending item on the same
                // stream.  Latch the transport closed and let reconnect/replay
                // restore the authoritative order.
                self.backpressure_disconnect.cancel();
                Err(mpsc::error::TrySendError::Full(item.stanza))
            }
            Err(mpsc::error::TrySendError::Closed(item)) => {
                Err(mpsc::error::TrySendError::Closed(item.stanza))
            }
        }
    }

    fn try_send_item(
        &self,
        item: OutboundItem,
    ) -> Result<(), mpsc::error::TrySendError<OutboundItem>> {
        if self.backpressure_disconnect.is_cancelled() {
            return Err(mpsc::error::TrySendError::Closed(item));
        }
        self.inner.try_send(item)
    }

    async fn send_item(
        &self,
        item: OutboundItem,
    ) -> Result<(), mpsc::error::SendError<OutboundItem>> {
        let sent = self.send_item_if_current(item, || true).await?;
        debug_assert!(sent, "an unconditional outbound send cannot lose its guard");
        Ok(())
    }

    async fn send_item_if_current<F>(
        &self,
        item: OutboundItem,
        is_current: F,
    ) -> Result<bool, mpsc::error::SendError<OutboundItem>>
    where
        F: Fn() -> bool,
    {
        if !is_current() {
            return Ok(false);
        }
        let permit = tokio::select! {
            biased;
            _ = self.backpressure_disconnect.cancelled() => {
                return Err(mpsc::error::SendError(item));
            }
            result = self.inner.reserve() => match result {
                Ok(permit) => permit,
                Err(_) => return Err(mpsc::error::SendError(item)),
            },
        };
        if self.backpressure_disconnect.is_cancelled() {
            return Err(mpsc::error::SendError(item));
        }
        if !is_current() {
            return Ok(false);
        }
        permit.send(item);
        Ok(true)
    }
}

fn map_try_send_error(
    error: mpsc::error::TrySendError<OutboundItem>,
) -> mpsc::error::TrySendError<String> {
    match error {
        mpsc::error::TrySendError::Full(item) => mpsc::error::TrySendError::Full(item.stanza),
        mpsc::error::TrySendError::Closed(item) => mpsc::error::TrySendError::Closed(item.stanza),
    }
}

/// The recipient-authoritative identity carried by a message stanza.  Cluster
/// protocol v6 inferred durable delivery from this value; v7 carries the
/// actual PostgreSQL fence explicitly because not every durable projection
/// uses the stanza-id as its row key (for example, a durable MUC invitation).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecipientDeliveryIdentity {
    Missing,
    Exact(Uuid),
    Invalid,
}

pub fn recipient_delivery_identity(
    stanza: &str,
    expected_recipient: &str,
) -> RecipientDeliveryIdentity {
    let Ok(recipient) = crate::jid::CanonicalJid::parse(expected_recipient) else {
        return RecipientDeliveryIdentity::Invalid;
    };
    let expected_by = recipient.bare();
    let Ok(document) = roxmltree::Document::parse(stanza) else {
        return RecipientDeliveryIdentity::Invalid;
    };
    let root = document.root_element();
    if root.tag_name().name() != "message" {
        return RecipientDeliveryIdentity::Invalid;
    }
    let mut identities = root.children().filter_map(|child| {
        if !child.is_element()
            || child.tag_name().name() != "stanza-id"
            || child.tag_name().namespace() != Some("urn:xmpp:sid:0")
        {
            return None;
        }
        let by = crate::jid::CanonicalJid::parse(child.attribute("by")?).ok()?;
        (by.bare() == expected_by).then_some(child.attribute("id"))
    });
    let Some(first) = identities.next() else {
        return RecipientDeliveryIdentity::Missing;
    };
    if identities.next().is_some() {
        return RecipientDeliveryIdentity::Invalid;
    }
    first.and_then(|value| Uuid::parse_str(value).ok()).map_or(
        RecipientDeliveryIdentity::Invalid,
        RecipientDeliveryIdentity::Exact,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovers_only_the_recipient_authoritative_identity() {
        let message_id = Uuid::from_u128(2);
        let stanza = format!(
            "<message to='Bob@Example.COM/Phone'><stanza-id xmlns='urn:xmpp:sid:0' by='sender.test' id='ignored'/><stanza-id xmlns='urn:xmpp:sid:0' by='bob@example.com' id='{message_id}'/></message>"
        );
        assert_eq!(
            recipient_delivery_identity(&stanza, "bob@example.com/OtherResource"),
            RecipientDeliveryIdentity::Exact(message_id)
        );
    }

    #[test]
    fn rejects_ambiguous_or_unrelated_identities() {
        let first = Uuid::from_u128(3);
        let second = Uuid::from_u128(4);
        let ambiguous = format!(
            "<message><stanza-id xmlns='urn:xmpp:sid:0' by='bob@example.com' id='{first}'/><stanza-id xmlns='urn:xmpp:sid:0' by='Bob@Example.COM' id='{second}'/></message>"
        );
        assert_eq!(
            recipient_delivery_identity(&ambiguous, "bob@example.com"),
            RecipientDeliveryIdentity::Invalid
        );

        let unrelated = format!(
            "<message><stanza-id xmlns='urn:xmpp:sid:0' by='mallory.example' id='{first}'/></message>"
        );
        assert_eq!(
            recipient_delivery_identity(&unrelated, "bob@example.com"),
            RecipientDeliveryIdentity::Missing
        );

        let malformed = "<message><stanza-id xmlns='urn:xmpp:sid:0' by='bob@example.com' id='not-a-uuid'/></message>";
        assert_eq!(
            recipient_delivery_identity(malformed, "bob@example.com"),
            RecipientDeliveryIdentity::Invalid
        );
    }

    #[tokio::test]
    async fn durable_queue_saturation_latches_the_transport_closed() {
        let (inner, mut receiver) = mpsc::channel(1);
        let sender = OutboundSender::new(inner);
        let disconnect = sender.backpressure_disconnect();
        sender.try_send("older".to_owned()).unwrap();

        let delivery = DurableDelivery {
            recipient_id: Uuid::from_u128(10),
            message_id: Uuid::from_u128(11),
            claim_id: None,
        };
        assert!(matches!(
            sender.try_send_durable("gap".to_owned(), delivery),
            Err(mpsc::error::TrySendError::Full(stanza)) if stanza == "gap"
        ));
        assert!(disconnect.is_cancelled());

        // Even if capacity later becomes available, no newer stanza can pass
        // the durable gap on this connection.
        assert_eq!(receiver.recv().await.unwrap().stanza, "older");
        assert!(matches!(
            sender.try_send("newer".to_owned()),
            Err(mpsc::error::TrySendError::Closed(stanza)) if stanza == "newer"
        ));
    }

    #[tokio::test]
    async fn volatile_queue_saturation_does_not_latch_the_transport_closed() {
        let (inner, _receiver) = mpsc::channel(1);
        let sender = OutboundSender::new(inner);
        sender.try_send("first".to_owned()).unwrap();
        assert!(matches!(
            sender.try_send("second".to_owned()),
            Err(mpsc::error::TrySendError::Full(stanza)) if stanza == "second"
        ));
        assert!(!sender.backpressure_disconnect().is_cancelled());
    }

    #[tokio::test]
    async fn guarded_durable_send_rechecks_after_waiting_for_capacity() {
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        };

        let (inner, mut receiver) = mpsc::channel(1);
        let sender = OutboundSender::new(inner);
        sender.try_send("older".to_owned()).unwrap();
        let current = Arc::new(AtomicBool::new(true));
        let first_check = Arc::new(tokio::sync::Notify::new());
        let delivery = DurableDelivery {
            recipient_id: Uuid::from_u128(12),
            message_id: Uuid::from_u128(13),
            claim_id: Some(Uuid::from_u128(14)),
        };

        let guarded_send = sender.send_durable_if_current("guarded".to_owned(), delivery, {
            let current = Arc::clone(&current);
            let first_check = Arc::clone(&first_check);
            move || {
                first_check.notify_one();
                current.load(Ordering::Acquire)
            }
        });
        let invalidate_after_wait_started = async {
            first_check.notified().await;
            current.store(false, Ordering::Release);
            assert_eq!(receiver.recv().await.unwrap().stanza, "older");
        };
        let (sent, ()) = tokio::join!(guarded_send, invalidate_after_wait_started);

        assert!(!sent.unwrap());
        assert!(receiver.try_recv().is_err());
        assert!(!sender.backpressure_disconnect().is_cancelled());
    }

    #[tokio::test]
    async fn receipt_queue_saturation_latches_the_transport_closed() {
        let (inner, mut receiver) = mpsc::channel(1);
        let sender = OutboundSender::new(inner);
        let disconnect = sender.backpressure_disconnect();
        sender.try_send("older".to_owned()).unwrap();

        let (receipt, mut receipt_rx) = mpsc::unbounded_channel();
        assert!(matches!(
            sender.try_send_with_transport_receipt("policy-gap".to_owned(), receipt),
            Err(mpsc::error::TrySendError::Full(stanza)) if stanza == "policy-gap"
        ));
        assert!(disconnect.is_cancelled());
        assert!(receipt_rx.recv().await.is_none());

        assert_eq!(receiver.recv().await.unwrap().stanza, "older");
        assert!(matches!(
            sender.try_send("newer".to_owned()),
            Err(mpsc::error::TrySendError::Closed(stanza)) if stanza == "newer"
        ));
    }
}
