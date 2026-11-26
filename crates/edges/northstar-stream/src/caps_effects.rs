//! CAPS effect scheduling, exact local routes, and disco transport authority.

use crate::local_routes::session::OnlineSession;
use crate::local_routes::session_table::local_caps_route_epoch_matches;
use crate::outbound::OutboundSender;
use crate::protocol::caps::{CapsEffectDispatcherExt, DISCO_INFO_NS};
use dashmap::DashMap;
use futures::{stream::FuturesUnordered, StreamExt};
use northstar_protocol_runtime::caps::{
    CapsCacheIndex, CapsEffectDispatcher, CapsEffectJob, CapsEffects, CapsObservationOwner,
    CapsResourceIndex, CapsVerificationCommit, FederatedCapsGateIndex, FederatedCapsGuard,
    PendingCapsIndex, CAPS_EFFECT_DRAIN_GRACE, PENDING_TTL,
};
use northstar_session_application::telemetry::CapsEffectTelemetry;
use northstar_session_core::LocalCapsEpoch;
use northstar_telemetry::metrics::DurationHistogram;
use northstar_xml_builder::XmlElement;
use std::future::Future;
use std::pin::Pin;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// Monotonic time and protocol IDs used by CAPS observations and disco queries.
pub trait CapsEventSource: Send + Sync {
    fn caps_now(&self) -> Instant {
        SystemCapsEvents.caps_now()
    }

    fn new_caps_protocol_id(&self) -> Uuid {
        SystemCapsEvents.new_caps_protocol_id()
    }
}

struct SystemCapsEvents;

impl CapsEventSource for SystemCapsEvents {
    fn caps_now(&self) -> Instant {
        Instant::now()
    }

    fn new_caps_protocol_id(&self) -> Uuid {
        Uuid::new_v4()
    }
}

/// The node services capability effects drive beyond process-local routes.
pub trait CapsEffectPorts: CapsEventSource + 'static {
    fn send_federated_disco(
        &self,
        domain: &str,
        query: String,
        local_domain: &str,
    ) -> impl Future<Output = bool> + Send;
    fn deliver_explicit_pep_last_items_for_resource(
        &self,
        full_jid: &str,
        local_epoch: Option<LocalCapsEpoch>,
    ) -> impl Future<Output = anyhow::Result<()>> + Send;
    fn deliver_pep_last_items_for_resource(
        &self,
        full_jid: &str,
        epoch: LocalCapsEpoch,
    ) -> impl Future<Output = anyhow::Result<()>> + Send;
    fn deliver_pep_last_items_for_federated_resource(
        &self,
        full_jid: &str,
    ) -> impl Future<Output = anyhow::Result<()>> + Send;
    fn publish_verified_mix_presence(
        &self,
        full_jid: &str,
        epoch: LocalCapsEpoch,
    ) -> impl Future<Output = anyhow::Result<()>> + Send;
}

/// The supervised task owns only CAPS state, exact route fences, and PEP/MIX
/// effect capabilities. It never retains the application state or a raw pool.
pub struct CapsEffectDispatchContext<P> {
    pub observations: Arc<CapsResourceIndex>,
    pub pending: Arc<PendingCapsIndex>,
    pub cache: Arc<CapsCacheIndex>,
    pub dispatcher: Arc<CapsEffectDispatcher>,
    pub counters: CapsEffectCounters,
    pub federated_gates: Arc<FederatedCapsGateIndex>,
    pub sessions: Arc<DashMap<String, OnlineSession>>,
    pub local_domain: String,
    pub ports: P,
}

pub struct CapsEffectCounters {
    pub coalesced: Arc<AtomicU64>,
    pub queue_saturated: Arc<AtomicU64>,
    pub failures: Arc<AtomicU64>,
    pub latency: Arc<DurationHistogram>,
}

impl<P: CapsEffectPorts> CapsEffectDispatchContext<P> {
    fn telemetry(&self) -> CapsEffectTelemetry<'_> {
        CapsEffectTelemetry::new(
            &self.counters.coalesced,
            &self.counters.queue_saturated,
            &self.counters.failures,
            &self.counters.latency,
        )
    }

    fn local_domain(&self) -> &str {
        &self.local_domain
    }

    fn local_epoch_is_current(&self, full_jid: &str, epoch: LocalCapsEpoch) -> bool {
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

    fn local_sender_if_current(
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

    async fn lock_federated_resource(&self, full_jid: &str) -> FederatedCapsGuard<'_> {
        self.federated_gates.lock(full_jid).await
    }
}

pub(crate) struct CapsEffectRunGuard<'a> {
    pub(crate) observations: &'a CapsResourceIndex,
    pub(crate) dispatcher: &'a CapsEffectDispatcher,
    events: &'a dyn CapsEventSource,
}

impl Drop for CapsEffectRunGuard<'_> {
    fn drop(&mut self) {
        self.observations
            .recover_interrupted(self.events.caps_now());
        self.dispatcher.request_rescan();
    }
}

type CapsEffectFuture =
    Pin<Box<dyn Future<Output = (CapsEffectJob, CapsEffects)> + Send + 'static>>;

fn caps_owner_is_current<P: CapsEffectPorts>(
    context: &CapsEffectDispatchContext<P>,
    job: &CapsEffectJob,
) -> bool {
    context.observations.current_owner(&job.full_jid, job.owner)
        && match job.owner {
            CapsObservationOwner::Local(epoch) => {
                context.local_epoch_is_current(&job.full_jid, epoch)
            }
            CapsObservationOwner::Federated { .. } => true,
        }
}

async fn send_caps_disco_query<P: CapsEffectPorts>(
    context: &CapsEffectDispatchContext<P>,
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
    if let Some(summary) = context.cache.query(key, context.ports.caps_now()) {
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
    let (id, expires_at) = caps_query_correlation(&context.ports);
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
            context
                .ports
                .send_federated_disco(&domain, query, context.local_domain())
                .await
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

fn caps_query_correlation(events: &impl CapsEventSource) -> (String, Instant) {
    let id = format!("caps-{}", events.new_caps_protocol_id().as_u128());
    let expires_at = events.caps_now() + PENDING_TTL;
    (id, expires_at)
}

async fn execute_caps_effects_inner<P: CapsEffectPorts>(
    context: &CapsEffectDispatchContext<P>,
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
        if let Err(error) = context
            .ports
            .deliver_explicit_pep_last_items_for_resource(&job.full_jid, local_epoch)
            .await
        {
            failed.0 |= CapsEffects::EXPLICIT_PEP_LAST_ITEMS.0;
            tracing::warn!(?error, resource = %job.full_jid, "failed to deliver explicit PEP last items");
        }
    }
    if job.effects.contains(CapsEffects::AUTOMATIC_PEP_LAST_ITEMS) {
        let result = match job.owner {
            CapsObservationOwner::Local(epoch) => {
                context
                    .ports
                    .deliver_pep_last_items_for_resource(&job.full_jid, epoch)
                    .await
            }
            CapsObservationOwner::Federated { .. } => {
                context
                    .ports
                    .deliver_pep_last_items_for_federated_resource(&job.full_jid)
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
                context
                    .ports
                    .publish_verified_mix_presence(&job.full_jid, epoch)
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

async fn execute_caps_effects<P: CapsEffectPorts>(
    context: Arc<CapsEffectDispatchContext<P>>,
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

async fn run_caps_effect_dispatcher<P: CapsEffectPorts>(
    context: Arc<CapsEffectDispatchContext<P>>,
    cancel: CancellationToken,
    heartbeat: northstar_runtime::workers::WorkerHeartbeat,
) -> anyhow::Result<()> {
    let dispatcher = context.dispatcher.as_ref();
    context
        .observations
        .recover_interrupted(context.ports.caps_now());
    // A restart performs one authoritative reconstruction. Thereafter new
    // work, saturation, completions and exact retry/expiry deadlines are the
    // only wake sources; correctness does not depend on fixed polling.
    dispatcher.request_rescan();
    let _recovery = CapsEffectRunGuard {
        observations: &context.observations,
        dispatcher,
        events: &context.ports,
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
                .claim_effects(&full_jid, context.ports.caps_now())
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
            let now = context.ports.caps_now();
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

        let now = context.ports.caps_now();
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
                } else if context.observations.complete_effects(&job, failed, context.ports.caps_now()) {
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
                let now = context.ports.caps_now();
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
                context.cache.sweep(context.ports.caps_now());
                heartbeat.pulse();
            }
        }
    }
}

pub fn start_caps_effect_dispatcher<P: CapsEffectPorts>(
    context: Arc<CapsEffectDispatchContext<P>>,
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
            events: &SystemCapsEvents,
        });

        assert!(dispatcher.begin_rescan());
        let retry = observations
            .claim_effects(resource, Instant::now())
            .unwrap();
        assert_eq!(retry.owner, claimed.owner);
        assert_eq!(retry.effects, claimed.effects);
    }

    struct RecordingCapsPorts(Arc<std::sync::Mutex<Vec<String>>>);
    impl CapsEffectPorts for RecordingCapsPorts {
        async fn send_federated_disco(&self, _: &str, _: String, _: &str) -> bool {
            panic!("retry fixture has no disco work")
        }
        async fn deliver_explicit_pep_last_items_for_resource(
            &self,
            full_jid: &str,
            epoch: Option<LocalCapsEpoch>,
        ) -> anyhow::Result<()> {
            assert_eq!(epoch, None);
            self.0.lock().unwrap().push(full_jid.to_owned());
            Ok(())
        }
        async fn deliver_pep_last_items_for_resource(
            &self,
            _: &str,
            _: LocalCapsEpoch,
        ) -> anyhow::Result<()> {
            panic!("retry fixture has no local PEP work")
        }
        async fn deliver_pep_last_items_for_federated_resource(
            &self,
            _: &str,
        ) -> anyhow::Result<()> {
            panic!("retry fixture has no automatic PEP work")
        }
        async fn publish_verified_mix_presence(
            &self,
            _: &str,
            _: LocalCapsEpoch,
        ) -> anyhow::Result<()> {
            panic!("retry fixture has no MIX work")
        }
    }

    #[tokio::test(start_paused = true)]
    async fn caps_dispatcher_wakes_at_the_earlier_retry_or_pending_expiration() {
        use northstar_protocol_runtime::caps::CapsKey;
        use northstar_runtime::workers::{WorkerCriticality, WorkerMode, WorkerRegistry};
        let resource = "alice@remote.test/Phone";
        for label in ["retry first", "expiration first"] {
            let registry = WorkerRegistry::new();
            let worker_cancel = CancellationToken::new();
            let (sender, receiver) = tokio::sync::oneshot::channel();
            let sender = Arc::new(std::sync::Mutex::new(Some(sender)));
            let factory_cancel = worker_cancel.clone();
            registry.supervise(
                "caps-deadline-fixture",
                WorkerCriticality::Restartable,
                WorkerMode::Continuous,
                None,
                worker_cancel.clone(),
                move |heartbeat| {
                    let _ = sender.lock().unwrap().take().unwrap().send(heartbeat);
                    let cancel = factory_cancel.clone();
                    async move {
                        cancel.cancelled().await;
                        Ok(())
                    }
                },
            );
            let heartbeat = receiver.await.unwrap();
            let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
            let context = Arc::new(CapsEffectDispatchContext {
                observations: Arc::new(CapsResourceIndex::with_limits(4, 4)),
                pending: Arc::new(PendingCapsIndex::new()),
                cache: Arc::new(CapsCacheIndex::new()),
                dispatcher: CapsEffectDispatcher::with_limits(4, 2),
                counters: CapsEffectCounters {
                    coalesced: Arc::new(AtomicU64::new(0)),
                    queue_saturated: Arc::new(AtomicU64::new(0)),
                    failures: Arc::new(AtomicU64::new(0)),
                    latency: Arc::new(DurationHistogram::default()),
                },
                federated_gates: Arc::new(FederatedCapsGateIndex::new()),
                sessions: Arc::new(DashMap::new()),
                local_domain: "example.test".to_owned(),
                ports: RecordingCapsPorts(Arc::clone(&calls)),
            });
            let now = tokio::time::Instant::now().into_std();
            let early = now + Duration::from_secs(1);
            let late = now + Duration::from_secs(2);
            let owner = context
                .observations
                .observe_federated(
                    resource.to_owned(),
                    uuid::Uuid::from_u128(901),
                    "remote.test".to_owned(),
                    None,
                    None,
                    now,
                )
                .unwrap();
            {
                let mut observation = context.observations.entries.get_mut(resource).unwrap();
                observation.pending_effects = CapsEffects::EXPLICIT_PEP_LAST_ITEMS.0;
                observation.retry_at = if label == "retry first" { early } else { late };
            }
            assert!(context.pending.insert(
                "expiry".to_owned(),
                "other@remote.test/Phone".to_owned(),
                CapsKey {
                    algorithm: "sha-1".to_owned(),
                    node: "test-node".to_owned(),
                    version: "test-version".to_owned()
                },
                owner,
                if label == "expiration first" {
                    early
                } else {
                    late
                },
            ));
            let cancel = CancellationToken::new();
            let mut running = Box::pin(run_caps_effect_dispatcher(
                Arc::clone(&context),
                cancel.clone(),
                heartbeat,
            ));
            assert!(futures::poll!(&mut running).is_pending(), "{label}");
            // The authoritative indexes use std::Instant. Make the selected
            // work due without sending a hint; paused Tokio time then proves
            // that the already-armed dispatcher timer supplies the wake.
            let due = Instant::now()
                .checked_sub(Duration::from_millis(1))
                .unwrap();
            if label == "retry first" {
                context
                    .observations
                    .entries
                    .get_mut(resource)
                    .unwrap()
                    .retry_at = due;
            } else {
                context
                    .pending
                    .entries
                    .get_mut("expiry")
                    .unwrap()
                    .expires_at = due;
            }
            let before = tokio::time::Instant::from_std(early) - Duration::from_millis(1);
            tokio::time::advance(before.saturating_duration_since(tokio::time::Instant::now()))
                .await;
            assert!(futures::poll!(&mut running).is_pending(), "{label}");
            assert!(
                calls.lock().unwrap().is_empty(),
                "{label}: work ran before its timer"
            );
            assert_eq!(context.pending.len(), 1, "{label}");
            tokio::time::advance(Duration::from_millis(1)).await;
            assert!(futures::poll!(&mut running).is_pending(), "{label}");
            assert_eq!(
                calls.lock().unwrap().len(),
                usize::from(label == "retry first"),
                "{label}: earliest retry was missed"
            );
            assert_eq!(
                context.pending.len(),
                usize::from(label == "retry first"),
                "{label}: earliest expiration was missed"
            );
            if label == "retry first" {
                assert_eq!(calls.lock().unwrap().as_slice(), [resource]);
            }
            cancel.cancel();
            running.await.unwrap();
            assert!(registry
                .shutdown_and_join(&worker_cancel, Duration::from_secs(1))
                .await
                .is_clean());
        }
    }

    mod events;
}
