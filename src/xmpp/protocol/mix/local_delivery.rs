//! Durable MIX delivery errors, route classification and the local transport hand-off.

use super::*;

#[derive(Debug)]
pub(super) struct PermanentMixDeliveryError {
    pub(super) reason: &'static str,
    pub(super) detail: String,
}

impl std::fmt::Display for PermanentMixDeliveryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.reason, self.detail)
    }
}

impl std::error::Error for PermanentMixDeliveryError {}

#[derive(Debug)]
pub(super) struct MixDeliveryRoutePending;

impl std::fmt::Display for MixDeliveryRoutePending {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("waiting for an eligible MIX delivery route")
    }
}

impl std::error::Error for MixDeliveryRoutePending {}

/// The durable recipient projection remains authoritative until an eligible
/// resource actually accepts it, an explicit permanent policy/account failure
/// occurs, or its database retention window expires.  A successful personal
/// archive write is deliberately not a live-delivery acknowledgement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DurableMixRouteAvailability {
    NoTarget,
    UnknownCapability,
    Unsupported,
    Deliverable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DurableMixRouteDisposition {
    Accepted,
    Park,
    RetryCluster,
    RetryDeliverable,
}

/// Classify only the live-routing outcome after any archive projection has
/// completed.  `_archive_projection_present` is deliberately explicit: it
/// documents and tests that a MAM projection cannot turn an unavailable route
/// into an acknowledged durable delivery.  There is intentionally no delivery
/// age input; elapsed capability discovery is not a terminal state.
pub(super) fn classify_durable_mix_route(
    _archive_projection_present: bool,
    accepted: bool,
    availability: DurableMixRouteAvailability,
    cluster_delivery_failed: bool,
) -> DurableMixRouteDisposition {
    if accepted {
        DurableMixRouteDisposition::Accepted
    } else if cluster_delivery_failed {
        DurableMixRouteDisposition::RetryCluster
    } else if availability == DurableMixRouteAvailability::Deliverable {
        DurableMixRouteDisposition::RetryDeliverable
    } else {
        DurableMixRouteDisposition::Park
    }
}

/// The precise reason one local ordered transport could not take a durable
/// MIX source. Queue admission is deliberately absent: the recipient row is
/// authoritative until the transport either writes it or persists a typed
/// hand-off to XEP-0198/BOSH.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum MixLocalTransportFailure {
    QueueFull,
    QueueClosed,
    HandoffClosed,
    Observation(mix_worker::Rejected),
}

impl std::fmt::Display for MixLocalTransportFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let detail = match self {
            Self::QueueFull => "local session queue is full",
            Self::QueueClosed => "local session queue is closed",
            Self::HandoffClosed => "local transport closed before durable hand-off",
            Self::Observation(error) => {
                return write!(
                    formatter,
                    "MIX attempt rejected a local hand-off observation: {error}"
                )
            }
        };
        formatter.write_str(detail)
    }
}

/// Cancels an exact session if a waiting caller is dropped before the item has
/// crossed a recoverability boundary. This is the crucial replacement for the
/// old 500 ms receipt timeout: the normal path waits for the actual durable
/// hand-off, while cancellation, shutdown, or the outbox attempt deadline
/// closes the one transport that could otherwise later expose a stale item.
pub(super) struct PendingMixLocalHandoff {
    pub(super) sender: crate::outbound::OutboundSender,
    pub(super) disconnect: tokio_util::sync::CancellationToken,
    pub(super) completed: bool,
}

impl PendingMixLocalHandoff {
    pub(super) fn new(
        sender: crate::outbound::OutboundSender,
        disconnect: tokio_util::sync::CancellationToken,
    ) -> Self {
        Self {
            sender,
            disconnect,
            completed: false,
        }
    }

    pub(super) fn mark_completed(&mut self) {
        self.completed = true;
    }
}

impl Drop for PendingMixLocalHandoff {
    fn drop(&mut self) {
        if !self.completed {
            self.sender.disconnect_backpressured_transport();
            self.disconnect.cancel();
        }
    }
}

/// Try one already MIX-qualified local resource for a durable recipient row.
///
/// On every failure — including cancellation while awaiting a durable
/// boundary — this closes *that exact* C2S transport. The queued item may
/// otherwise still become visible after its source row is retried, which
/// would violate in-order delivery on the old stream. A caller may safely try
/// another qualified resource; only a typed hand-off lets it transfer or
/// consume the source.
pub(super) async fn try_send_local_durable_mix(
    sender: &crate::outbound::OutboundSender,
    disconnect: &tokio_util::sync::CancellationToken,
    stanza: String,
    source: crate::outbound::MixDelivery,
) -> std::result::Result<crate::outbound::MixTransportCompletion, MixLocalTransportFailure> {
    try_send_local_durable_mix_inner(sender, disconnect, stanza, source, None).await
}

pub(super) async fn try_send_local_durable_mix_observed(
    sender: &crate::outbound::OutboundSender,
    disconnect: &tokio_util::sync::CancellationToken,
    request: &mix_worker::LocalRequest,
) -> std::result::Result<crate::outbound::MixTransportCompletion, MixLocalTransportFailure> {
    try_send_local_durable_mix_inner(
        sender,
        disconnect,
        request.stanza().to_owned(),
        request.source(),
        Some(request),
    )
    .await
}

pub(super) async fn try_send_local_durable_mix_inner(
    sender: &crate::outbound::OutboundSender,
    disconnect: &tokio_util::sync::CancellationToken,
    stanza: String,
    source: crate::outbound::MixDelivery,
    observation: Option<&mix_worker::LocalRequest>,
) -> std::result::Result<crate::outbound::MixTransportCompletion, MixLocalTransportFailure> {
    if let Some(request) = observation {
        request
            .start()
            .map_err(MixLocalTransportFailure::Observation)?;
    }
    let receiver = match sender.try_send_durable_mix(stanza, source) {
        Ok(receiver) => receiver,
        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
            sender.disconnect_backpressured_transport();
            disconnect.cancel();
            if let Some(request) = observation {
                request
                    .returned(mix_worker::LocalResult::QueueFull)
                    .map_err(MixLocalTransportFailure::Observation)?;
            }
            return Err(MixLocalTransportFailure::QueueFull);
        }
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
            sender.disconnect_backpressured_transport();
            disconnect.cancel();
            if let Some(request) = observation {
                request
                    .returned(mix_worker::LocalResult::QueueClosed)
                    .map_err(MixLocalTransportFailure::Observation)?;
            }
            return Err(MixLocalTransportFailure::QueueClosed);
        }
    };
    let mut pending = PendingMixLocalHandoff::new(sender.clone(), disconnect.clone());
    if let Some(request) = observation {
        request
            .enqueued()
            .map_err(MixLocalTransportFailure::Observation)?;
    }
    let completion = match receiver.await {
        Ok(completion) => completion,
        Err(_) => {
            if let Some(request) = observation {
                request
                    .returned(mix_worker::LocalResult::HandoffClosed)
                    .map_err(MixLocalTransportFailure::Observation)?;
            }
            return Err(MixLocalTransportFailure::HandoffClosed);
        }
    };
    pending.mark_completed();
    if let Some(request) = observation {
        let boundary = match completion {
            crate::outbound::MixTransportCompletion::SocketFenced { connection_id } => {
                mix_worker::TransferBoundary::SocketFenced(connection_id)
            }
            crate::outbound::MixTransportCompletion::SmPersisted { session_id } => {
                mix_worker::TransferBoundary::SmPersisted(session_id)
            }
            crate::outbound::MixTransportCompletion::BoshPersisted { session_id } => {
                mix_worker::TransferBoundary::BoshPersisted(session_id)
            }
        };
        request
            .returned(mix_worker::LocalResult::Transferred(boundary))
            .map_err(MixLocalTransportFailure::Observation)?;
    }
    Ok(completion)
}

pub(super) fn permanent_mix_delivery_error(
    reason: &'static str,
    detail: impl Into<String>,
) -> anyhow::Error {
    PermanentMixDeliveryError {
        reason,
        detail: detail.into(),
    }
    .into()
}
