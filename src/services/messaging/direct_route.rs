//! The live handoff between durable admission and protocol-owned follow-up.
//!
//! Queue acceptance is not transport completion. This owner can relinquish an
//! unaccepted initial claim, but cannot acknowledge a delivery or perform a
//! second admission. XML, PoW finalization, Push and Carbons stay with callers.

use super::{
    committed_live_delivery_has_fence, FullJidFallback, FullJidFallbackPlan, FullJidFallbackPort,
    FullJidFallbackResult, OnlineMessageRouter, OnlineRouteResult, RoutePayload,
};
use crate::{cluster::DirectPostCommitMode, outbound::DurableDelivery};
use northstar_message_core::{bare_message_route, BareMessageRoute};
use std::future::Future;
use uuid::Uuid;

pub(crate) trait DirectMessageRoutePort: FullJidFallbackPort {
    fn direct_route_mode(&self) -> DirectPostCommitMode;
    fn clustered_direct_routes(&self) -> bool;
    /// Relinquish only this initial exact claim. A later transport fence wins
    /// the repository CAS; failure leaves the row recoverable by lease expiry.
    fn rearm_direct_route(&self, delivery: DurableDelivery) -> impl Future<Output = ()> + Send;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DirectRouteDelivery {
    Volatile,
    Committed(DurableDelivery),
}

impl DirectRouteDelivery {
    fn durable(self) -> Option<DurableDelivery> {
        match self {
            Self::Volatile => None,
            Self::Committed(delivery) => Some(delivery),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum DirectRouteTarget<'a> {
    Bare(&'a str),
    Full { jid: &'a str, bare: &'a str },
}

impl<'a> DirectRouteTarget<'a> {
    pub(super) fn jid(self) -> &'a str {
        match self {
            Self::Bare(jid) | Self::Full { jid, .. } => jid,
        }
    }
}

pub(crate) struct DirectRouteRequest<'a, S> {
    pub(crate) message_type: &'a str,
    pub(crate) target: DirectRouteTarget<'a>,
    pub(crate) sender: &'a str,
    pub(crate) recipient_id: Uuid,
    pub(crate) stanza: &'a str,
    pub(crate) delivery: DirectRouteDelivery,
    pub(crate) approved_targets: &'a [(String, S)],
    /// Internal service addresses retain their existing non-direct behavior.
    pub(crate) enforce_direct_health: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DirectRouteStage {
    LiveReservation,
    HandoffBinding,
    PrimaryRoute,
    PrimaryRemote,
    FullJidFallback,
    FallbackLocal,
    FallbackRemote,
    AfterRouting,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DirectRouteRecoveryReason {
    MissingLiveReservation,
    InvalidHandoff,
    HealthChanged,
    FallbackFailed,
    FallbackRejected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DirectRouteRejection {
    Unavailable,
    NoMatchingResource,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum DirectRouteOutcome {
    /// An ordered queue accepted the item, not necessarily a socket write.
    Routed {
        accepted_full_jid: Option<String>,
    },
    /// No route accepted. The protocol may now apply its offline policy.
    Unrouted,
    /// Prior durable admission/history remains accepted. Suppress further live
    /// effects, even when a concurrent transport may already own the exact row.
    AcceptedForRecovery {
        stage: DirectRouteStage,
        reason: DirectRouteRecoveryReason,
    },
    /// A volatile queue accepted before health changed. Do not invite retry.
    AcceptedBeforeDegradation,
    Dropped,
    Rejected(DirectRouteRejection),
}

#[derive(Debug)]
pub(crate) struct DirectRouteError {
    pub(crate) stage: DirectRouteStage,
    source: anyhow::Error,
}

impl std::fmt::Display for DirectRouteError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "direct route failed at {:?}: {}",
            self.stage, self.source
        )
    }
}

impl std::error::Error for DirectRouteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

/// Consuming this capability makes repeated recovery branches idempotent in
/// one route attempt. It never represents a transport acknowledgement.
struct UnroutedClaim {
    source: Option<DurableDelivery>,
    witness: Option<northstar_message_application::direct_handoff::HandoffHandle>,
}

impl UnroutedClaim {
    async fn rearm<P: DirectMessageRoutePort>(&mut self, port: &P) {
        if let Some(delivery) = self
            .source
            .take()
            .filter(|delivery| delivery.claim_id.is_some())
        {
            let permit = match &self.witness {
                Some(witness) => match witness.rearm_permit(delivery) {
                    Ok(Some(permit)) => Some(permit),
                    Ok(None) | Err(_) => return,
                },
                None => None,
            };
            port.rearm_direct_route(delivery).await;
            if let Some(permit) = permit {
                permit.returned();
            }
        }
    }
}

pub(crate) struct DirectMessageRouter;

impl DirectMessageRouter {
    pub(crate) async fn route<P: DirectMessageRoutePort>(
        port: &P,
        request: DirectRouteRequest<'_, P::Session>,
    ) -> Result<DirectRouteOutcome, DirectRouteError> {
        let mut payload = RoutePayload::new(request.stanza, request.delivery.durable());
        let result = Self::route_owned(port, request, &mut payload).await;
        payload.returned();
        result
    }

    pub(crate) async fn route_prepared<P: DirectMessageRoutePort>(
        port: &P,
        request: DirectRouteRequest<'_, P::Session>,
        prepared: super::direct_workflow::PreparedDirectHandoff<'_>,
    ) -> Result<DirectRouteOutcome, DirectRouteError> {
        let (item, witness) = match prepared.bind_route(&request) {
            Ok(bound) => bound,
            Err(_) => {
                port.post_accept_failed();
                return Ok(DirectRouteOutcome::AcceptedForRecovery {
                    stage: DirectRouteStage::HandoffBinding,
                    reason: DirectRouteRecoveryReason::InvalidHandoff,
                });
            }
        };
        let mut payload = RoutePayload::prepared(request.stanza, item, witness);
        let result = Self::route_owned(port, request, &mut payload).await;
        payload.returned();
        result
    }

    pub(crate) async fn recover_prepared<P: DirectMessageRoutePort>(
        port: &P,
        prepared: super::direct_workflow::PreparedDirectRecovery,
    ) {
        let mut payload = RoutePayload::new("", Some(prepared.source));
        payload.witness = Some(prepared.witness);
        let mut claim = UnroutedClaim {
            source: Some(prepared.source),
            witness: payload.witness.clone(),
        };
        claim.rearm(port).await;
        payload.returned();
    }

    async fn route_owned<P: DirectMessageRoutePort>(
        port: &P,
        request: DirectRouteRequest<'_, P::Session>,
        payload: &mut RoutePayload<'_>,
    ) -> Result<DirectRouteOutcome, DirectRouteError> {
        let delivery = request.delivery.durable();
        let mut claim = UnroutedClaim {
            source: delivery,
            witness: payload.witness.clone(),
        };
        if let Some(outcome) = Self::reservation_gate(port, delivery) {
            return Ok(outcome);
        }
        if let Some(outcome) = Self::health_gate(
            port,
            &request,
            &mut claim,
            DirectRouteStage::PrimaryRoute,
            false,
        )
        .await
        {
            return Ok(outcome);
        }
        let mut routed = OnlineMessageRouter::dispatch_owned(
            port,
            request.target.jid(),
            payload,
            matches!(request.target, DirectRouteTarget::Bare(_))
                && bare_message_route(request.message_type) == BareMessageRoute::All,
            request.approved_targets,
        )
        .await;
        if !routed.delivered {
            if let DirectRouteTarget::Full { jid, bare } = request.target {
                if let Some(outcome) = Self::health_gate(
                    port,
                    &request,
                    &mut claim,
                    DirectRouteStage::FullJidFallback,
                    false,
                )
                .await
                {
                    return Ok(outcome);
                }
                let fallback = OnlineMessageRouter::full_jid_fallback_owned(
                    port,
                    FullJidFallback {
                        message_type: request.message_type,
                        full_target: jid,
                        bare_target: bare,
                        sender: request.sender,
                        recipient_id: request.recipient_id,
                        delivery,
                    },
                    payload,
                )
                .await;
                if let Some(outcome) =
                    Self::finish_fallback(port, delivery, &mut claim, &mut routed, fallback).await?
                {
                    return Ok(outcome);
                }
            }
        }
        if !routed.delivered {
            claim.rearm(port).await;
        }
        if let Some(outcome) = Self::health_gate(
            port,
            &request,
            &mut claim,
            DirectRouteStage::AfterRouting,
            routed.delivered,
        )
        .await
        {
            return Ok(outcome);
        }
        Ok(if routed.delivered {
            DirectRouteOutcome::Routed {
                accepted_full_jid: routed.accepted_full_jid,
            }
        } else {
            DirectRouteOutcome::Unrouted
        })
    }

    /// Federation preserves its historical health checks between local and
    /// remote handoffs and after fallback privacy. An unrouted result returns
    /// to the protocol's headline/no-store/offline policy without a new final
    /// health read. C2S deliberately keeps its different checkpoint sequence.
    pub(crate) async fn route_federated<P: DirectMessageRoutePort>(
        port: &P,
        request: DirectRouteRequest<'_, P::Session>,
        history_committed: bool,
    ) -> Result<DirectRouteOutcome, DirectRouteError> {
        let mut payload = RoutePayload::new(request.stanza, request.delivery.durable());
        let delivery = request.delivery.durable();
        let mut claim = UnroutedClaim {
            source: delivery,
            witness: None,
        };
        if let Some(outcome) = Self::reservation_gate(port, delivery) {
            return Ok(outcome);
        }
        // Only this checkpoint historically treats already committed history
        // as acceptance. It must not manufacture a delivery/claim capability.
        if let Some(outcome) = Self::health_gate_with_history(
            port,
            &request,
            &mut claim,
            DirectRouteStage::PrimaryRoute,
            false,
            history_committed,
        )
        .await
        {
            return Ok(outcome);
        }
        let deliver_all = matches!(request.target, DirectRouteTarget::Bare(_))
            && bare_message_route(request.message_type) == BareMessageRoute::All;
        let local = OnlineMessageRouter::dispatch_local_owned(
            port,
            &mut payload,
            deliver_all,
            request.approved_targets,
        );
        // This check also runs after a local acceptance: a degraded node must
        // suppress remote headline fanout and all subsequent live follow-up.
        if let Some(outcome) = Self::health_gate(
            port,
            &request,
            &mut claim,
            DirectRouteStage::PrimaryRemote,
            local.delivered,
        )
        .await
        {
            return Ok(outcome);
        }
        let mut routed = OnlineMessageRouter::dispatch_remote_owned(
            port,
            request.target.jid(),
            &mut payload,
            deliver_all,
            local,
        )
        .await;
        if !routed.delivered {
            if let DirectRouteTarget::Full { jid, bare } = request.target {
                if let Some(outcome) = Self::health_gate(
                    port,
                    &request,
                    &mut claim,
                    DirectRouteStage::FullJidFallback,
                    false,
                )
                .await
                {
                    return Ok(outcome);
                }
                let prepared = OnlineMessageRouter::prepare_full_jid_fallback(
                    port,
                    FullJidFallback {
                        message_type: request.message_type,
                        full_target: jid,
                        bare_target: bare,
                        sender: request.sender,
                        recipient_id: request.recipient_id,
                        delivery,
                    },
                )
                .await;
                let fallback = match prepared {
                    Ok(FullJidFallbackPlan::Finished(result)) => Ok(result),
                    Err(error) => Err(error),
                    Ok(FullJidFallbackPlan::Targets(allowed)) => {
                        if let Some(outcome) = Self::health_gate(
                            port,
                            &request,
                            &mut claim,
                            DirectRouteStage::FallbackLocal,
                            false,
                        )
                        .await
                        {
                            return Ok(outcome);
                        }
                        let local = OnlineMessageRouter::dispatch_local_owned(
                            port,
                            &mut payload,
                            false,
                            &allowed,
                        );
                        let fallback = if local.delivered {
                            local
                        } else {
                            if let Some(outcome) = Self::health_gate(
                                port,
                                &request,
                                &mut claim,
                                DirectRouteStage::FallbackRemote,
                                false,
                            )
                            .await
                            {
                                return Ok(outcome);
                            }
                            OnlineMessageRouter::dispatch_remote_owned(
                                port,
                                bare,
                                &mut payload,
                                false,
                                local,
                            )
                            .await
                        };
                        Ok(if fallback.delivered {
                            FullJidFallbackResult::Delivered(fallback.accepted_full_jid)
                        } else {
                            FullJidFallbackResult::Undelivered
                        })
                    }
                };
                if let Some(outcome) =
                    Self::finish_fallback(port, delivery, &mut claim, &mut routed, fallback).await?
                {
                    return Ok(outcome);
                }
            }
        }
        if !routed.delivered {
            claim.rearm(port).await;
            return Ok(DirectRouteOutcome::Unrouted);
        }
        if let Some(outcome) = Self::health_gate(
            port,
            &request,
            &mut claim,
            DirectRouteStage::AfterRouting,
            true,
        )
        .await
        {
            return Ok(outcome);
        }
        Ok(DirectRouteOutcome::Routed {
            accepted_full_jid: routed.accepted_full_jid,
        })
    }

    fn reservation_gate<P: DirectMessageRoutePort>(
        port: &P,
        delivery: Option<DurableDelivery>,
    ) -> Option<DirectRouteOutcome> {
        if let Some(delivery) = delivery {
            if !committed_live_delivery_has_fence(
                port.clustered_direct_routes(),
                delivery.message_id,
                delivery.claim_id,
            ) {
                port.post_accept_failed();
                tracing::error!(stage = ?DirectRouteStage::LiveReservation,
                    reason = ?DirectRouteRecoveryReason::MissingLiveReservation,
                    "clustered durable direct admission lacked live reservation");
                return Some(DirectRouteOutcome::AcceptedForRecovery {
                    stage: DirectRouteStage::LiveReservation,
                    reason: DirectRouteRecoveryReason::MissingLiveReservation,
                });
            }
        }
        None
    }

    async fn finish_fallback<P: DirectMessageRoutePort>(
        port: &P,
        delivery: Option<DurableDelivery>,
        claim: &mut UnroutedClaim,
        routed: &mut OnlineRouteResult,
        fallback: anyhow::Result<FullJidFallbackResult>,
    ) -> Result<Option<DirectRouteOutcome>, DirectRouteError> {
        match fallback {
            Ok(FullJidFallbackResult::Delivered(key)) => {
                routed.delivered = true;
                routed.accepted_full_jid = key;
            }
            Ok(FullJidFallbackResult::Undelivered) => {}
            Ok(FullJidFallbackResult::Dropped) => {
                claim.rearm(port).await;
                return Ok(Some(DirectRouteOutcome::Dropped));
            }
            Ok(FullJidFallbackResult::Rejected) if delivery.is_none() => {
                return Ok(Some(DirectRouteOutcome::Rejected(
                    DirectRouteRejection::NoMatchingResource,
                )));
            }
            Err(source) if delivery.is_none() => {
                return Err(DirectRouteError {
                    stage: DirectRouteStage::FullJidFallback,
                    source,
                });
            }
            failed => {
                claim.rearm(port).await;
                port.post_accept_failed();
                let reason = match failed {
                    Err(_error) => {
                        tracing::warn!(stage = ?DirectRouteStage::FullJidFallback,
                                    reason = ?DirectRouteRecoveryReason::FallbackFailed,
                                    "full-JID fallback failed after durable admission; row remains recoverable");
                        DirectRouteRecoveryReason::FallbackFailed
                    }
                    _ => DirectRouteRecoveryReason::FallbackRejected,
                };
                return Ok(Some(DirectRouteOutcome::AcceptedForRecovery {
                    stage: DirectRouteStage::FullJidFallback,
                    reason,
                }));
            }
        }
        Ok(None)
    }

    async fn health_gate<P: DirectMessageRoutePort>(
        port: &P,
        request: &DirectRouteRequest<'_, P::Session>,
        claim: &mut UnroutedClaim,
        stage: DirectRouteStage,
        queue_accepted: bool,
    ) -> Option<DirectRouteOutcome> {
        Self::health_gate_with_history(port, request, claim, stage, queue_accepted, false).await
    }

    async fn health_gate_with_history<P: DirectMessageRoutePort>(
        port: &P,
        request: &DirectRouteRequest<'_, P::Session>,
        claim: &mut UnroutedClaim,
        stage: DirectRouteStage,
        queue_accepted: bool,
        history_committed: bool,
    ) -> Option<DirectRouteOutcome> {
        use northstar_message_application::direct_handoff::{health_decision, HealthDecision};
        // Keep the original disabled-health short circuit and each caller's
        // checkpoint; the shared decision owns no clock or health read.
        if !request.enforce_direct_health {
            return None;
        }
        match health_decision(
            true,
            port.direct_route_mode(),
            request.delivery.durable().is_some(),
            history_committed,
            queue_accepted,
        ) {
            HealthDecision::Continue => None,
            HealthDecision::Recover => {
                if !queue_accepted {
                    claim.rearm(port).await;
                }
                Some(DirectRouteOutcome::AcceptedForRecovery {
                    stage,
                    reason: DirectRouteRecoveryReason::HealthChanged,
                })
            }
            HealthDecision::AcceptedBeforeDegradation => {
                Some(DirectRouteOutcome::AcceptedBeforeDegradation)
            }
            HealthDecision::Reject => Some(DirectRouteOutcome::Rejected(
                DirectRouteRejection::Unavailable,
            )),
        }
    }
}

#[cfg(test)]
#[path = "direct_route_tests.rs"]
mod tests;
