//! CAPS effect scheduling, exact local routes, and disco transport authority.

use super::{
    local_caps_route_epoch_matches, mix_presence_recovery::MixPresenceRecoveryContext,
    pep_last_items::PepLastItemsContext, AppState, OnlineSession,
};
use crate::s2s::FederationRouter;
use crate::xmpp::protocol::caps::*;
use dashmap::DashMap;
use futures::{stream::FuturesUnordered, StreamExt};
use northstar_protocol_runtime::caps::{
    CapsCacheIndex, CapsEffectDispatcher, CapsResourceIndex, FederatedCapsGateIndex,
    FederatedCapsGuard, PendingCapsIndex,
};
use northstar_session_application::telemetry::CapsEffectTelemetry;
use northstar_session_core::LocalCapsEpoch;
use northstar_stream::outbound::OutboundSender;
use northstar_telemetry::metrics::DurationHistogram;
use northstar_xml_builder::stream::stream_id;
use northstar_xml_builder::XmlElement;
use std::future::Future;
use std::pin::Pin;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

/// The supervised task owns only CAPS state, exact route fences, and PEP/MIX
/// effect capabilities. It never retains the application state or a raw pool.
pub(crate) struct CapsEffectDispatchContext {
    pub(crate) observations: Arc<CapsResourceIndex>,
    pub(crate) pending: Arc<PendingCapsIndex>,
    pub(crate) cache: Arc<CapsCacheIndex>,
    pub(crate) dispatcher: Arc<CapsEffectDispatcher>,
    counters: CapsEffectCounters,
    federated_gates: Arc<FederatedCapsGateIndex>,
    sessions: Arc<DashMap<String, OnlineSession>>,
    federation_outbox: FederationRouter,
    local_domain: String,
    pep: PepLastItemsContext,
    mix: MixPresenceRecoveryContext,
}

struct CapsEffectCounters {
    coalesced: Arc<AtomicU64>,
    queue_saturated: Arc<AtomicU64>,
    failures: Arc<AtomicU64>,
    latency: Arc<DurationHistogram>,
}

impl AppState {
    pub(crate) fn caps_effect_dispatch_context(&self) -> CapsEffectDispatchContext {
        CapsEffectDispatchContext {
            observations: Arc::clone(&self.caps_by_jid),
            pending: Arc::clone(&self.pending_caps),
            cache: Arc::clone(&self.caps_cache),
            dispatcher: Arc::clone(&self.caps_effect_dispatcher),
            counters: CapsEffectCounters {
                coalesced: Arc::clone(&self.metrics.caps_effect_coalesced_total),
                queue_saturated: Arc::clone(&self.metrics.caps_effect_queue_saturated_total),
                failures: Arc::clone(&self.metrics.caps_effect_failures_total),
                latency: Arc::clone(&self.metrics.caps_effect_latency_seconds),
            },
            federated_gates: Arc::clone(&self.federated_caps_gates),
            sessions: Arc::clone(&self.sessions),
            federation_outbox: self.federation.federation_outbox.clone(),
            local_domain: self.config.domain.clone(),
            pep: self.pep_last_items_context(),
            mix: self.mix_presence_recovery_context(),
        }
    }
}

impl CapsEffectDispatchContext {
    pub(crate) fn telemetry(&self) -> CapsEffectTelemetry<'_> {
        CapsEffectTelemetry::new(
            &self.counters.coalesced,
            &self.counters.queue_saturated,
            &self.counters.failures,
            &self.counters.latency,
        )
    }

    pub(crate) fn pep(&self) -> &PepLastItemsContext {
        &self.pep
    }

    pub(crate) fn mix(&self) -> &MixPresenceRecoveryContext {
        &self.mix
    }

    pub(crate) fn local_domain(&self) -> &str {
        &self.local_domain
    }

    pub(crate) fn local_epoch_is_current(&self, full_jid: &str, epoch: LocalCapsEpoch) -> bool {
        self.sessions.get(full_jid).is_some_and(|session| {
            local_caps_route_epoch_matches(
                session.connection_id,
                session.caps_observation_generation.load(Ordering::Acquire),
                session.routable.load(Ordering::Acquire),
                session.disconnect.is_cancelled(),
                session.lifecycle.load(Ordering::Acquire),
                true,
                epoch,
            )
        })
    }

    pub(crate) fn local_sender_if_current(
        &self,
        full_jid: &str,
        epoch: LocalCapsEpoch,
    ) -> Option<OutboundSender> {
        self.sessions.get(full_jid).and_then(|session| {
            local_caps_route_epoch_matches(
                session.connection_id,
                session.caps_observation_generation.load(Ordering::Acquire),
                session.routable.load(Ordering::Acquire),
                session.disconnect.is_cancelled(),
                session.lifecycle.load(Ordering::Acquire),
                true,
                epoch,
            )
            .then(|| session.sender.clone())
        })
    }

    pub(crate) async fn lock_federated_resource(&self, full_jid: &str) -> FederatedCapsGuard<'_> {
        self.federated_gates.lock(full_jid).await
    }

    pub(crate) async fn send_federated_disco(&self, domain: &str, query: String) -> bool {
        self.federation_outbox
            .send(domain, query, Some(self.local_domain.to_owned()))
            .await
    }
}

pub(crate) struct CapsEffectRunGuard<'a> {
    pub(crate) observations: &'a CapsResourceIndex,
    pub(crate) dispatcher: &'a CapsEffectDispatcher,
}

impl Drop for CapsEffectRunGuard<'_> {
    fn drop(&mut self) {
        self.observations.recover_interrupted(Instant::now());
        self.dispatcher.request_rescan();
    }
}

type CapsEffectFuture =
    Pin<Box<dyn Future<Output = (CapsEffectJob, CapsEffects)> + Send + 'static>>;

fn caps_owner_is_current(context: &CapsEffectDispatchContext, job: &CapsEffectJob) -> bool {
    context.observations.current_owner(&job.full_jid, job.owner)
        && match job.owner {
            CapsObservationOwner::Local(epoch) => {
                context.local_epoch_is_current(&job.full_jid, epoch)
            }
            CapsObservationOwner::Federated { .. } => true,
        }
}

async fn send_caps_disco_query(
    context: &CapsEffectDispatchContext,
    job: &CapsEffectJob,
) -> anyhow::Result<()> {
    let key = job
        .key
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("caps disco work has no advertised key"))?;
    // Re-check verified knowledge at dispatch time. Observations can be
    // admitted together before the first response arrives; the pending index
    // single-flights that first request, and followers resolve from this same
    // Arc on their event-driven retry instead of emitting duplicate IQs.
    if let Some(summary) = context.cache.query(key, Instant::now()) {
        return match context.observations.mark_cached_verified(
            &job.full_jid,
            job.owner,
            key,
            summary,
        ) {
            CapsVerificationCommit::Applied => Ok(()),
            CapsVerificationCommit::Stale => {
                anyhow::bail!("caps observation no longer needs cached verification")
            }
            CapsVerificationCommit::ResourceLimited => {
                anyhow::bail!("caps semantic memory budget is exhausted")
            }
        };
    }
    let id = format!("caps-{}", stream_id());
    let expires_at = Instant::now() + PENDING_TTL;
    if !context
        .observations
        .begin_query(&job.full_jid, job.owner, key, id.clone())
    {
        anyhow::bail!("caps observation no longer needs this disco query");
    }
    if !context.pending.insert(
        id.clone(),
        job.full_jid.clone(),
        key.clone(),
        job.owner,
        expires_at,
    ) {
        context
            .observations
            .mark_query_failed(&job.full_jid, job.owner, &id);
        anyhow::bail!("caps IQ correlation ID or semantic key is already in flight");
    }
    let query = caps_disco_request(
        context.local_domain(),
        &job.full_jid,
        &id,
        &key.node,
        &key.version,
    );
    let sent = match job.owner {
        CapsObservationOwner::Local(epoch) => {
            let sender = context.local_sender_if_current(&job.full_jid, epoch);
            match sender {
                Some(sender) => match sender.try_send(query) {
                    Ok(()) => true,
                    Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                        // This sender belongs to the exact epoch validated above.
                        // Queue saturation is a transport failure, never a
                        // successful disco dispatch.
                        sender.disconnect_backpressured_transport();
                        false
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => false,
                },
                None => false,
            }
        }
        CapsObservationOwner::Federated { .. } => {
            let domain = northstar_xmpp_types::jid::CanonicalJid::parse(&job.full_jid)?
                .domainpart()
                .to_owned();
            context.send_federated_disco(&domain, query).await
        }
    };
    if sent {
        Ok(())
    } else {
        context.pending.remove(&id);
        context
            .observations
            .mark_query_failed(&job.full_jid, job.owner, &id);
        anyhow::bail!("caps disco query was not accepted by its exact transport")
    }
}

async fn execute_caps_effects_inner(
    context: &CapsEffectDispatchContext,
    job: &CapsEffectJob,
) -> CapsEffects {
    if !caps_owner_is_current(context, job) {
        return CapsEffects::default();
    }
    let mut failed = CapsEffects::default();
    if job.effects.contains(CapsEffects::DISCO_QUERY) {
        if let Err(error) = send_caps_disco_query(context, job).await {
            failed.0 |= CapsEffects::DISCO_QUERY.0;
            tracing::warn!(?error, resource = %job.full_jid, "failed to dispatch capability disco query");
        }
    }
    if job.effects.contains(CapsEffects::EXPLICIT_PEP_LAST_ITEMS) {
        let local_epoch = match job.owner {
            CapsObservationOwner::Local(epoch) => Some(epoch),
            CapsObservationOwner::Federated { .. } => None,
        };
        if let Err(error) =
            northstar_pubsub_xmpp::pep::deliver_explicit_pep_last_items_for_resource(
                context.pep(),
                &job.full_jid,
                local_epoch,
            )
            .await
        {
            failed.0 |= CapsEffects::EXPLICIT_PEP_LAST_ITEMS.0;
            tracing::warn!(?error, resource = %job.full_jid, "failed to deliver explicit PEP last items");
        }
    }
    if job.effects.contains(CapsEffects::AUTOMATIC_PEP_LAST_ITEMS) {
        let result = match job.owner {
            CapsObservationOwner::Local(epoch) => {
                northstar_pubsub_xmpp::pep::deliver_pep_last_items_for_resource(
                    context.pep(),
                    &job.full_jid,
                    epoch,
                )
                .await
            }
            CapsObservationOwner::Federated { .. } => {
                northstar_pubsub_xmpp::pep::deliver_pep_last_items_for_federated_resource(
                    context.pep(),
                    &job.full_jid,
                )
                .await
            }
        };
        if let Err(error) = result {
            failed.0 |= CapsEffects::AUTOMATIC_PEP_LAST_ITEMS.0;
            tracing::warn!(?error, resource = %job.full_jid, "failed to deliver capability-selected PEP last items");
        }
    }
    if job.effects.contains(CapsEffects::VERIFIED_MIX_PRESENCE) {
        let result = match job.owner {
            CapsObservationOwner::Local(epoch) => {
                northstar_mix_xmpp::publish_verified_mix_presence_with(
                    context.mix(),
                    &job.full_jid,
                    epoch.connection_id,
                    epoch.generation,
                )
                .await
            }
            CapsObservationOwner::Federated { .. } => Ok(()),
        };
        if let Err(error) = result {
            failed.0 |= CapsEffects::VERIFIED_MIX_PRESENCE.0;
            tracing::warn!(?error, resource = %job.full_jid, "failed to publish verified MIX presence");
        }
    }
    failed
}

async fn execute_caps_effects(
    context: Arc<CapsEffectDispatchContext>,
    job: &CapsEffectJob,
) -> CapsEffects {
    match job.owner {
        CapsObservationOwner::Local(_) => execute_caps_effects_inner(&context, job).await,
        CapsObservationOwner::Federated { .. } => {
            let _resource_epoch = context.lock_federated_resource(&job.full_jid).await;
            execute_caps_effects_inner(&context, job).await
        }
    }
}

async fn run_caps_effect_dispatcher(
    context: Arc<CapsEffectDispatchContext>,
    cancel: CancellationToken,
    heartbeat: northstar_runtime::workers::WorkerHeartbeat,
) -> anyhow::Result<()> {
    let dispatcher = context.dispatcher.as_ref();
    context.observations.recover_interrupted(Instant::now());
    // A restart performs one authoritative reconstruction. Thereafter new
    // work, saturation, completions and exact retry/expiry deadlines are the
    // only wake sources; correctness does not depend on fixed polling.
    dispatcher.request_rescan();
    let _recovery = CapsEffectRunGuard {
        observations: &context.observations,
        dispatcher,
    };
    let mut running = FuturesUnordered::<CapsEffectFuture>::new();
    let mut draining = false;
    let mut liveness = tokio::time::interval(Duration::from_secs(15));
    liveness.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        if cancel.is_cancelled() && !draining {
            draining = true;
            dispatcher.close();
        }

        loop {
            let Ok(permit) = Arc::clone(&dispatcher.execution_slots).try_acquire_owned() else {
                break;
            };
            let Some(full_jid) = dispatcher.take_hint() else {
                drop(permit);
                break;
            };
            let Some(job) = context
                .observations
                .claim_effects(&full_jid, Instant::now())
            else {
                drop(permit);
                continue;
            };
            let effect_context = Arc::clone(&context);
            running.push(Box::pin(async move {
                let _permit = permit;
                let failed = execute_caps_effects(effect_context, &job).await;
                (job, failed)
            }));
        }

        if !draining
            && dispatcher.execution_slots.available_permits() > 0
            && dispatcher.begin_rescan()
        {
            let now = Instant::now();
            for (full_jid, local) in context.observations.ready_observations(now) {
                let _ = dispatcher.hint(full_jid, local, &context.telemetry());
            }
            // Schedule reconstructed hints before sleeping. If a class filled,
            // `hint` left rescan_required set; freeing a slot wakes the next
            // reconstruction without a lost-notify window.
            continue;
        }

        if draining && running.is_empty() {
            heartbeat.ok();
            return Ok(());
        }

        let now = Instant::now();
        let next_deadline = if draining {
            None
        } else {
            match (
                context.observations.next_retry_deadline(now),
                context.pending.next_expiration(),
            ) {
                (Some(left), Some(right)) => Some(left.min(right)),
                (Some(deadline), None) | (None, Some(deadline)) => Some(deadline),
                (None, None) => None,
            }
        };
        let deadline_wait = async move {
            match next_deadline {
                Some(deadline) => tokio::time::sleep_until(deadline.into()).await,
                None => futures::future::pending::<()>().await,
            }
        };
        tokio::pin!(deadline_wait);

        tokio::select! {
            _ = cancel.cancelled(), if !draining => {
                draining = true;
                dispatcher.close();
            }
            Some((job, failed)) = running.next(), if !running.is_empty() => {
                if matches!(job.owner, CapsObservationOwner::Local(epoch) if !context.local_epoch_is_current(&job.full_jid, epoch)) {
                    if let CapsObservationOwner::Local(epoch) = job.owner {
                        context.pending.remove_local_epoch(&job.full_jid, epoch);
                        context.observations.remove_local_epoch(&job.full_jid, epoch);
                    }
                } else if context.observations.complete_effects(&job, failed, Instant::now()) {
                    let _ = dispatcher.hint(
                        job.full_jid.clone(),
                        job.owner.is_local(),
                        &context.telemetry(),
                    );
                }
                context.telemetry().completed_after(job.queued_at.elapsed());
                let failures = failed.0.count_ones() as u64;
                if failures == 0 {
                    heartbeat.ok();
                } else {
                    context.telemetry().failed(failures);
                    heartbeat.error(format!("{failures} caps side effects failed"));
                }
            }
            _ = dispatcher.wake.notified() => {}
            _ = &mut deadline_wait, if !draining => {
                let now = Instant::now();
                for (id, pending) in context.pending.take_expired(now) {
                    if context.observations.rearm_expired(&id, &pending, now) {
                        let _ = dispatcher.hint(
                            pending.full_jid,
                            pending.owner.is_local(),
                            &context.telemetry(),
                        );
                    }
                }
                dispatcher.request_rescan();
            }
            _ = liveness.tick() => {
                context.cache.sweep(Instant::now());
                heartbeat.pulse();
            }
        }
    }
}

pub(crate) fn start_caps_effect_dispatcher(
    context: Arc<CapsEffectDispatchContext>,
    worker_registry: Arc<northstar_runtime::workers::WorkerRegistry>,
    cancel: CancellationToken,
) {
    worker_registry.supervise_draining(
        "caps-side-effects",
        northstar_runtime::workers::WorkerCriticality::Restartable,
        northstar_runtime::workers::WorkerMode::Continuous,
        Some(Duration::from_secs(60)),
        CAPS_EFFECT_DRAIN_GRACE,
        cancel.clone(),
        move |heartbeat| {
            let context = Arc::clone(&context);
            let cancel = cancel.clone();
            async move { run_caps_effect_dispatcher(context, cancel, heartbeat).await }
        },
    );
}

fn caps_disco_request(domain: &str, full_jid: &str, id: &str, node: &str, version: &str) -> String {
    XmlElement::namespaced("iq", "jabber:client")
        .attr("type", "get")
        .attr("from", domain)
        .attr("to", full_jid)
        .attr("id", id)
        .child(
            XmlElement::namespaced("query", DISCO_INFO_NS)
                .attr("node", format!("{node}#{version}")),
        )
        .finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatcher_drop_rearms_claimed_effects_and_requests_rescan() {
        let observations = CapsResourceIndex::with_limits(4, 4);
        let dispatcher = CapsEffectDispatcher::with_limits(1, 1);
        let resource = "alice@remote.test/Phone";
        observations
            .observe_federated(
                resource.to_owned(),
                uuid::Uuid::new_v4(),
                "remote.test".to_owned(),
                None,
                None,
                Instant::now(),
            )
            .unwrap();
        let claimed = observations
            .claim_effects(resource, Instant::now())
            .unwrap();
        assert!(observations
            .claim_effects(resource, Instant::now())
            .is_none());
        assert!(!dispatcher.begin_rescan());

        drop(CapsEffectRunGuard {
            observations: &observations,
            dispatcher: dispatcher.as_ref(),
        });

        assert!(dispatcher.begin_rescan());
        let retry = observations
            .claim_effects(resource, Instant::now())
            .unwrap();
        assert_eq!(retry.owner, claimed.owner);
        assert_eq!(retry.effects, claimed.effects);
    }
}
