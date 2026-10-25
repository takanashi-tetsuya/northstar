use std::{
    future::Future,
    sync::{atomic::Ordering, Arc},
    time::Duration,
};

use anyhow::{Context, Result};
use serde_json::{json, Value};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::services::admin_session_cleanup_worker::{
    AdminSessionCleanupKind, AdminSessionCleanupLease, AdminSessionCleanupRepository,
    AdminSessionCleanupWorkerService,
};
use crate::services::operation_effect_fence::FencedEffect;
use crate::services::operation_journal_worker::{
    ClaimedOperation, LeaseRenewal, NextTarget, TargetSeed, TargetSettlement,
};
use crate::{
    db,
    services::muc::LocalMucOccupantIdentity,
    services::operation_muc_destroy::MucDestroyCommit,
    state::{
        AdminSessionCleanupContext, AppState, OperationIslandEffects, OperationMucDestroyEffects,
        OperationPanicEffects, OperationSessionEffects, OperationTlsReloadEffects,
        OperationWorkerControl,
    },
};

const LEASE_SECONDS: i64 = 60;

/// The durable worker owns only the authorities needed to execute a committed
/// operation. Every handle refers to the same live state as protocol traffic.
pub(crate) struct OperationWorkerRuntime {
    control: Arc<OperationWorkerControl>,
    session_effects: OperationSessionEffects,
    tls_reload_effects: OperationTlsReloadEffects,
    island_effects: OperationIslandEffects,
    muc_destroy_effects: OperationMucDestroyEffects,
    panic_effects: OperationPanicEffects,
}

impl OperationWorkerRuntime {
    pub(crate) fn from_state(state: &AppState) -> Self {
        Self {
            control: Arc::new(state.operation_worker_control()),
            session_effects: state.operation_session_effects(),
            tls_reload_effects: state.operation_tls_reload_effects(),
            island_effects: state.operation_island_effects(),
            muc_destroy_effects: state.operation_muc_destroy_effects(),
            panic_effects: state.operation_panic_effects(),
        }
    }
}

pub(crate) async fn serve(
    runtime: OperationWorkerRuntime,
    cancel: CancellationToken,
) -> Result<()> {
    let worker_id = Uuid::new_v4();
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            result = run_one(&runtime, worker_id) => match result {
                Ok(true) => {},
                Ok(false) => tokio::time::sleep(Duration::from_millis(250)).await,
                Err(error) => {
                    tracing::error!(?error, worker_id=%worker_id, "durable operation worker iteration failed");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }
}

/// Run the security-sensitive XEP-0133 cleanup outbox independently from
/// ordinary administrator operations. A broadcast operation may own thousands
/// of target transitions and `run_one` intentionally retains its parent lease
/// until all of them reach a terminal state. Sharing that loop would therefore
/// allow an unrelated long broadcast to delay a committed credential or exact
/// connection revocation.
pub async fn serve_admin_session_cleanup(
    context: Arc<AdminSessionCleanupContext>,
    cancel: CancellationToken,
    health: northstar_runtime::workers::WorkerHeartbeat,
) -> Result<()> {
    let worker_id = Uuid::new_v4();
    loop {
        health.pulse();
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            result = run_one_admin_session_cleanup(&context, worker_id) => match result {
                Ok(true) => health.ok(),
                Ok(false) => {
                    health.ok();
                    tokio::select! {
                        _ = cancel.cancelled() => return Ok(()),
                        _ = tokio::time::sleep(Duration::from_millis(250)) => {}
                    }
                },
                Err(error) => {
                    health.error(&error);
                    tracing::error!(?error, worker_id=%worker_id, "administrator session-cleanup worker iteration failed");
                    tokio::select! {
                        _ = cancel.cancelled() => return Ok(()),
                        _ = tokio::time::sleep(Duration::from_secs(1)) => {}
                    }
                }
            }
        }
    }
}

async fn run_one_admin_session_cleanup(
    context: &AdminSessionCleanupContext,
    worker_id: Uuid,
) -> Result<bool> {
    let Some(lease) = context.service().claim(worker_id).await? else {
        return Ok(false);
    };
    // Keep the renewal future in this attempt's structured-concurrency scope.
    // WorkerRegistry may drop an attempt immediately during shutdown or after
    // a terminal health transition. A detached Tokio task would survive that
    // drop and could continue renewing a lease after its effect owner ceased
    // to exist.
    let effect = execute_with_lease_renewal(
        execute_admin_session_cleanup(context, &lease, worker_id),
        |heartbeat_stop| {
            admin_session_cleanup_heartbeat(
                context.service(),
                lease.clone(),
                worker_id,
                heartbeat_stop,
            )
        },
    )
    .await;

    match effect {
        Ok(true) => {
            if !context.service().complete(&lease, worker_id).await? {
                tracing::debug!(effect_id=%lease.id, "administrator session-cleanup lease changed before completion");
            }
        }
        Ok(false) => {
            if !context
                .service()
                .retry(&lease, worker_id, "target_still_current")
                .await?
            {
                tracing::debug!(effect_id=%lease.id, "administrator session-cleanup lease changed before retry");
            }
        }
        Err(error) => {
            tracing::warn!(
                ?error,
                effect_id=%lease.id,
                command_operation_id=%lease.command_operation_id,
                attempts=lease.attempts,
                "durable administrator session cleanup will be retried"
            );
            if !context
                .service()
                .retry(&lease, worker_id, "delivery_failed")
                .await?
            {
                tracing::debug!(effect_id=%lease.id, "administrator session-cleanup lease changed after delivery failure");
            }
        }
    }
    Ok(true)
}

/// Run an ordinary operation effect while a spawned task renews its lease
/// fence. The heartbeat is stopped when the effect completes and also when
/// this future is dropped (for example when `serve` is cancelled during
/// shutdown), so an abandoned target is never renewed by an orphaned task. A
/// heartbeat failure is reported after the effect returns, as before.
async fn execute_with_spawned_heartbeat<T, Effect, Heartbeat, HeartbeatFactory>(
    effect: Effect,
    heartbeat_factory: HeartbeatFactory,
) -> Result<T>
where
    Effect: Future<Output = T>,
    Heartbeat: Future<Output = Result<()>> + Send + 'static,
    HeartbeatFactory: FnOnce(CancellationToken) -> Heartbeat,
{
    let heartbeat_stop = CancellationToken::new();
    let _stop_heartbeat_on_drop = heartbeat_stop.clone().drop_guard();
    let heartbeat = tokio::spawn(heartbeat_factory(heartbeat_stop.clone()));
    let output = effect.await;
    heartbeat_stop.cancel();
    heartbeat
        .await
        .context("operation lease heartbeat panicked")??;
    Ok(output)
}

/// Run one effect and its lease renewal in a single cancellation scope.
///
/// The renewal is deliberately a child future rather than a spawned task:
/// dropping this future drops both children synchronously. When the effect
/// completes (successfully or with an error), renewal is cancelled and then
/// driven to completion before the effect result is returned. If renewal
/// fails first, the effect is dropped and must not continue under a lost
/// fence.
async fn execute_with_lease_renewal<T, Effect, Renewal, RenewalFactory>(
    effect: Effect,
    renewal_factory: RenewalFactory,
) -> Result<T>
where
    Effect: Future<Output = Result<T>>,
    Renewal: Future<Output = Result<()>>,
    RenewalFactory: FnOnce(CancellationToken) -> Renewal,
{
    let renewal_stop = CancellationToken::new();
    let effect = effect;
    let renewal = renewal_factory(renewal_stop.clone());
    tokio::pin!(effect);
    tokio::pin!(renewal);

    let effect_result = tokio::select! {
        biased;
        result = &mut effect => result,
        result = &mut renewal => {
            renewal_stop.cancel();
            result.context("administrator session-cleanup lease renewal failed")?;
            anyhow::bail!("administrator session-cleanup lease renewal stopped before its effect completed");
        }
    };

    renewal_stop.cancel();
    renewal
        .await
        .context("administrator session-cleanup lease renewal failed")?;
    effect_result
}

async fn admin_session_cleanup_heartbeat<R: AdminSessionCleanupRepository>(
    service: &AdminSessionCleanupWorkerService<R>,
    lease: AdminSessionCleanupLease,
    worker_id: Uuid,
    stop: CancellationToken,
) -> Result<()> {
    loop {
        tokio::select! {
            _ = stop.cancelled() => return Ok(()),
            _ = tokio::time::sleep(Duration::from_secs(15)) => {
                service.renew_or_fail(&lease, worker_id).await?;
            }
        }
    }
}

async fn execute_admin_session_cleanup(
    context: &AdminSessionCleanupContext,
    lease: &AdminSessionCleanupLease,
    worker_id: Uuid,
) -> Result<bool> {
    match lease.kind {
        AdminSessionCleanupKind::AccountGeneration => {
            let bare_jid = lease
                .bare_jid
                .as_deref()
                .context("generation cleanup has no bare JID")?;
            let bare_jid = northstar_xmpp_types::jid::CanonicalJid::parse_bare(bare_jid)
                .context("generation cleanup has an invalid bare JID")?;
            anyhow::ensure!(
                bare_jid.localpart().is_some() && bare_jid.domainpart() == context.local_domain(),
                "generation cleanup must target an account on the local XMPP domain"
            );
            context.revoke_generation_routes(
                lease.user_id,
                &bare_jid.to_string(),
                lease.auth_generation,
            );
            context
                .notifier()
                .send_account_generation_teardown(
                    &bare_jid.to_string(),
                    lease.user_id,
                    lease.auth_generation,
                )
                .await?;
            Ok(true)
        }
        AdminSessionCleanupKind::ExactConnection => {
            let full_jid = lease
                .full_jid
                .as_deref()
                .context("exact cleanup has no full JID")?;
            let full_jid = northstar_xmpp_types::jid::CanonicalJid::parse(full_jid)
                .context("exact cleanup has an invalid full JID")?;
            anyhow::ensure!(
                full_jid.localpart().is_some()
                    && full_jid.resourcepart().is_some()
                    && full_jid.domainpart() == context.local_domain(),
                "exact cleanup must target a full account JID on the local XMPP domain"
            );
            let full_jid = full_jid.to_string();
            let connection_id = lease
                .connection_id
                .context("exact cleanup has no connection identity")?;
            context.fence_exact_session(
                &full_jid,
                lease.user_id,
                lease.auth_generation,
                connection_id,
            );
            context
                .notifier()
                .send_session_instance_termination(&full_jid, connection_id)
                .await?;
            Ok(!context.service().target_current(lease, worker_id).await?)
        }
    }
}

async fn run_one(runtime: &OperationWorkerRuntime, worker_id: Uuid) -> Result<bool> {
    let control = &runtime.control;
    let Some(lease) = control
        .claim_parent_with_targets(worker_id, LEASE_SECONDS)
        .await?
    else {
        return Ok(false);
    };

    loop {
        let target = match control
            .journal()
            .next_target(&lease, worker_id, LEASE_SECONDS)
            .await?
        {
            NextTarget::LeaseLost | NextTarget::Cancelled => return Ok(true),
            NextTarget::Exhausted => break,
            NextTarget::Claimed(target) => target,
        };

        let fenced = control
            .effects()
            .execute_after_commit(&lease, &target, || async {
                execute_with_spawned_heartbeat(
                    execute_effect(
                        &runtime.session_effects,
                        &runtime.tls_reload_effects,
                        &runtime.island_effects,
                        &runtime.muc_destroy_effects,
                        &runtime.panic_effects,
                        &lease.operation,
                        &target.target.payload,
                    ),
                    |stop| {
                        lease_heartbeat(Arc::clone(control), lease.clone(), target.clone(), stop)
                    },
                )
                .await
            })
            .await?;
        let FencedEffect::Executed(effect) = fenced else {
            return Ok(true);
        };
        match control
            .journal()
            .settle_target(
                &lease,
                &target,
                lease.operation.id,
                target.target.id,
                effect,
            )
            .await?
        {
            TargetSettlement::Succeeded => {}
            TargetSettlement::Indeterminate | TargetSettlement::NotApplied => return Ok(true),
        }
    }

    let _ = control.journal().terminalize_parent(&lease).await?;
    Ok(true)
}

async fn lease_heartbeat(
    control: Arc<OperationWorkerControl>,
    parent: db::OperationLease,
    target: db::OperationTargetLease,
    stop: CancellationToken,
) -> Result<()> {
    loop {
        tokio::select! {
            _ = stop.cancelled() => return Ok(()),
            _ = tokio::time::sleep(Duration::from_secs(15)) => {
                if control.journal()
                    .renew_effect_leases(&parent, &target, LEASE_SECONDS)
                    .await? == LeaseRenewal::Lost
                {
                    anyhow::bail!("operation lease fencing was lost");
                }
            }
        }
    }
}

/// Only the local route snapshot and exact best-effort delivery authority
/// needed by the administrator broadcast operation. Its methods never expose
/// the underlying session map to callers.
#[derive(Clone)]
pub(crate) struct LocalBroadcastRoutes {
    sessions: Arc<dashmap::DashMap<String, crate::xmpp::local_routes::session::OnlineSession>>,
    domain: String,
    node_id: String,
}

/// Claim-time route snapshot only; it cannot deliver an administrator message.
pub(crate) struct LocalBroadcastTargetSnapshot {
    sessions: Arc<dashmap::DashMap<String, crate::xmpp::local_routes::session::OnlineSession>>,
    node_id: String,
}

impl LocalBroadcastRoutes {
    pub(crate) fn new(
        sessions: Arc<dashmap::DashMap<String, crate::xmpp::local_routes::session::OnlineSession>>,
        domain: String,
        node_id: String,
    ) -> Self {
        Self {
            sessions,
            domain,
            node_id,
        }
    }

    pub(crate) fn target_snapshot(&self) -> LocalBroadcastTargetSnapshot {
        LocalBroadcastTargetSnapshot {
            sessions: Arc::clone(&self.sessions),
            node_id: self.node_id.clone(),
        }
    }

    pub(crate) fn send_exact(&self, payload: &Value) -> Result<Value> {
        let Some(key) = payload.get("session_key").and_then(Value::as_str) else {
            return Ok(json!({"sent":false,"reason":"empty_snapshot"}));
        };
        let user_id = uuid_field(payload, "user_id")?;
        let connection_id = uuid_field(payload, "connection_id")?;
        let generation = payload
            .get("auth_generation")
            .and_then(Value::as_i64)
            .context("auth generation is missing")?;
        let text = payload
            .get("message")
            .and_then(Value::as_str)
            .context("message is missing")?;
        let stanza = format!(
            "<message from='{}' type='headline' id='{}'><body>{}</body></message>",
            northstar_xml_builder::escape::attr_escape(&self.domain),
            Uuid::new_v4(),
            northstar_xml_builder::escape::attr_escape(text)
        );
        let sent = self.sessions.get(key).is_some_and(|session| {
            session.user_id == user_id
                && session.auth_generation == generation
                && session.connection_id == connection_id
                && session.routable.load(Ordering::Acquire)
                && session.sender.try_send(stanza).is_ok()
        });
        Ok(json!({"sent":sent,"connection_id":connection_id}))
    }
}

impl LocalBroadcastTargetSnapshot {
    pub(crate) fn target_seeds(&self, operation: ClaimedOperation<'_>) -> Result<Vec<TargetSeed>> {
        let routes = self.sessions.iter().filter_map(|entry| {
            let session = entry.value();
            session
                .routable
                .load(Ordering::Acquire)
                .then(|| BroadcastRoute {
                    session_key: entry.key().clone(),
                    user_id: session.user_id,
                    auth_generation: session.auth_generation,
                    connection_id: session.connection_id,
                })
        });
        target_seeds_for_operation(operation, &self.node_id, routes)
    }
}

/// An administrator operation may cancel only a session with the exact
/// committed user, credential generation, and connection incarnation.
pub(crate) struct LocalSessionKickRoutes {
    sessions: Arc<dashmap::DashMap<String, crate::xmpp::local_routes::session::OnlineSession>>,
}

impl LocalSessionKickRoutes {
    pub(crate) fn new(
        sessions: Arc<dashmap::DashMap<String, crate::xmpp::local_routes::session::OnlineSession>>,
    ) -> Self {
        Self { sessions }
    }

    pub(crate) fn kick_exact(
        &self,
        user_id: Uuid,
        auth_generation: i64,
        connection_id: Uuid,
    ) -> bool {
        self.sessions
            .iter()
            .find(|entry| {
                let session = entry.value();
                session.connection_id == connection_id
                    && session.user_id == user_id
                    && session.auth_generation == auth_generation
            })
            .is_some_and(|session| {
                session.disconnect.cancel();
                true
            })
    }
}

/// Committed account cleanup can disconnect every resource of one exact
/// credential generation, without gaining route admission or removal access.
pub(crate) struct LocalGenerationCleanupRoutes {
    sessions: Arc<dashmap::DashMap<String, crate::xmpp::local_routes::session::OnlineSession>>,
}

impl LocalGenerationCleanupRoutes {
    pub(crate) fn new(
        sessions: Arc<dashmap::DashMap<String, crate::xmpp::local_routes::session::OnlineSession>>,
    ) -> Self {
        Self { sessions }
    }

    pub(crate) fn cancel_exact_generation(&self, user_id: Uuid, auth_generation: i64) -> u64 {
        let mut disconnected = 0_u64;
        for session in self.sessions.iter() {
            if session.user_id == user_id && session.auth_generation == auth_generation {
                session.disconnect.cancel();
                disconnected += 1;
            }
        }
        disconnected
    }
}

/// Process-wide emergency cancellation. This handle only signals local
/// transports; durable SM teardown remains a separate, ordered effect.
pub(crate) struct LocalPanicDisconnectRoutes {
    sessions: Arc<dashmap::DashMap<String, crate::xmpp::local_routes::session::OnlineSession>>,
}

impl LocalPanicDisconnectRoutes {
    pub(crate) fn new(
        sessions: Arc<dashmap::DashMap<String, crate::xmpp::local_routes::session::OnlineSession>>,
    ) -> Self {
        Self { sessions }
    }

    pub(crate) fn cancel_all(&self) -> u64 {
        let mut disconnected = 0_u64;
        for session in self.sessions.iter() {
            session.disconnect.cancel();
            disconnected += 1;
        }
        disconnected
    }
}

pub(crate) async fn panic_disconnect_with<Teardown, TeardownFuture>(
    routes: &LocalPanicDisconnectRoutes,
    teardown: Teardown,
) -> Result<Value>
where
    Teardown: FnOnce() -> TeardownFuture,
    TeardownFuture: Future<Output = Result<usize>>,
{
    let disconnected = routes.cancel_all();
    teardown().await?;
    Ok(json!({"sessions_disconnected":disconnected}))
}

struct BroadcastRoute {
    session_key: String,
    user_id: Uuid,
    auth_generation: i64,
    connection_id: Uuid,
}

fn target_seeds_for_operation(
    operation: ClaimedOperation<'_>,
    node_id: &str,
    routes: impl Iterator<Item = BroadcastRoute>,
) -> Result<Vec<TargetSeed>> {
    if operation.kind == "admin.broadcast" {
        let message = operation
            .payload
            .get("message")
            .and_then(Value::as_str)
            .context("broadcast message is missing")?;
        let mut seeds = Vec::new();
        for (ordinal, route) in routes.enumerate() {
            let payload = json!({"message":message,"session_key":route.session_key,"user_id":route.user_id,
                "auth_generation":route.auth_generation,"connection_id":route.connection_id});
            seeds.push(TargetSeed {
                target_key: format!("connection:{}", route.connection_id),
                ordinal: ordinal as i64,
                payload,
            });
        }
        if !seeds.is_empty() {
            return Ok(seeds);
        }
    }
    let target_key = if operation.kind == "admin.session_kick" {
        format!(
            "connection:{}",
            operation
                .payload
                .get("connection_id")
                .and_then(Value::as_str)
                .context("connection id is missing")?
        )
    } else {
        format!("node:{node_id}")
    };
    Ok(vec![TargetSeed {
        target_key,
        ordinal: 0,
        payload: operation.payload.clone(),
    }])
}

async fn execute_effect(
    session_effects: &OperationSessionEffects,
    tls_reload_effects: &OperationTlsReloadEffects,
    island_effects: &OperationIslandEffects,
    muc_destroy_effects: &OperationMucDestroyEffects,
    panic_effects: &OperationPanicEffects,
    operation: &db::OperationRecord,
    payload: &Value,
) -> Result<Value> {
    match operation.kind.as_str() {
        "admin.tls_reload" => {
            let outcome = tls_reload_effects.reload().await?;
            for session in &outcome.drained_sessions {
                tracing::warn!(
                    operation_id = %operation.id,
                    connection_id = %session.connection_id,
                    session_kind = session.kind.label(),
                    certificate_issuer = %session.certificate_issuer,
                    certificate_serial = %session.certificate_serial,
                    certificate_sha256 = %session.certificate_sha256,
                    handshake_tls_generation = session.handshake_tls_generation,
                    activated_tls_generation = outcome.generation,
                    "draining an explicitly revoked certificate-authenticated session"
                );
            }
            if outcome.inconclusive_rechecks > 0 {
                tracing::warn!(
                    operation_id = %operation.id,
                    activated_tls_generation = outcome.generation,
                    inconclusive_rechecks = outcome.inconclusive_rechecks,
                    "some live certificate chains could not be conclusively classified by the new CRL snapshot; they were not disconnected"
                );
            }
            Ok(json!({
                "reloaded":true,
                "previous_generation":outcome.previous_generation,
                "generation":outcome.generation,
                "evaluated_certificate_sessions":outcome.evaluated_sessions,
                "certificate_sessions_without_applicable_crl":outcome.sessions_without_applicable_crl,
                "inconclusive_revocation_rechecks":outcome.inconclusive_rechecks,
                "active_certificate_sessions_after_signal":outcome.active_sessions_after_signal,
                "drained_sessions":outcome.drained_total(),
                "drained_c2s_external":outcome.drained_c2s_external,
                "drained_inbound_s2s_external":outcome.drained_inbound_s2s_external,
                "drained_outbound_s2s_external":outcome.drained_outbound_s2s_external
            }))
        }
        "admin.panic_disconnect" => panic_effects.execute().await,
        "admin.session_kick" => {
            let (user_id, connection_id, generation) = session_kick_identity(payload)?;
            let kicked = session_effects.kick_exact(user_id, generation, connection_id);
            Ok(json!({"kicked":kicked,"connection_id":connection_id}))
        }
        "admin.broadcast" => session_effects.send_broadcast_exact(payload),
        "admin.island_converge" => {
            let enabled = match payload.get("mode").and_then(Value::as_str) {
                Some("enabled") => true,
                Some("disabled") => false,
                _ => anyhow::bail!("invalid island mode"),
            };
            island_effects.converge(enabled).await;
            Ok(json!({"island_mode":enabled}))
        }
        "admin.user_session_cleanup" => {
            let (user_id, generation) = generation_cleanup_identity(payload)?;
            let disconnected = session_effects.cancel_exact_generation(user_id, generation);
            Ok(json!({"sessions_disconnected":disconnected,"user_id":user_id}))
        }
        "admin.muc_destroy" => {
            let committed = muc_destroy_effects
                .commit(crate::services::operation_muc_destroy::MucDestroyEffect {
                    operation_id: operation.id,
                    request_id: operation.request_id,
                    actor_id: operation.actor_id,
                    payload,
                })
                .await?;
            muc_destroy_effects.notify_committed(operation.id).await;
            remove_committed_muc_audience(&committed, |identity| {
                muc_destroy_effects.remove_local_occupant_exact(identity)
            });
            Ok(json!({"destroyed":committed.destroyed,"room_jid":committed.room_jid}))
        }
        kind => anyhow::bail!("operation executor is unavailable for {kind}"),
    }
}

/// The room JID may already belong to a new room when a delayed operation
/// worker reaches this cleanup. Only the occupancies captured by the committed
/// tombstone may be removed from the local projection.
fn remove_committed_muc_audience<'a>(
    committed: &'a MucDestroyCommit,
    mut remove_exact: impl FnMut(LocalMucOccupantIdentity<'a>) -> bool,
) -> usize {
    if !committed.destroyed {
        return 0;
    }
    committed
        .audience
        .iter()
        .filter(|expected| {
            if expected.occupant_incarnation.is_nil() || expected.connection_id.is_nil() {
                return false;
            }
            remove_exact(LocalMucOccupantIdentity {
                room_jid: &committed.room_jid,
                nick: &expected.nick,
                full_jid: &expected.full_jid,
                connection_id: expected.connection_id,
                cluster_epoch: expected.occupant_incarnation,
            })
        })
        .count()
}

fn uuid_field(payload: &Value, name: &str) -> Result<Uuid> {
    let value = payload
        .get(name)
        .and_then(Value::as_str)
        .with_context(|| format!("{name} is missing"))?;
    let id = Uuid::parse_str(value).with_context(|| format!("{name} is invalid"))?;
    anyhow::ensure!(!id.is_nil(), "{name} must not be nil");
    Ok(id)
}

fn session_kick_identity(payload: &Value) -> Result<(Uuid, Uuid, i64)> {
    let user_id = uuid_field(payload, "user_id")?;
    let connection_id = uuid_field(payload, "connection_id")?;
    let generation = payload
        .get("auth_generation")
        .and_then(Value::as_i64)
        .context("auth generation is missing")?;
    Ok((user_id, connection_id, generation))
}

fn generation_cleanup_identity(payload: &Value) -> Result<(Uuid, i64)> {
    let user_id = uuid_field(payload, "user_id")?;
    let generation = payload
        .get("auth_generation")
        .and_then(Value::as_i64)
        .context("auth generation is missing")?;
    Ok((user_id, generation))
}

#[cfg(test)]
mod tests;
