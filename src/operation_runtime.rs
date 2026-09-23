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
use crate::{db, state::AppState};

const LEASE_SECONDS: i64 = 60;

pub async fn serve(state: Arc<AppState>, cancel: CancellationToken) -> Result<()> {
    let worker_id = Uuid::new_v4();
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            result = run_one(&state, worker_id) => match result {
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
    state: Arc<AppState>,
    cancel: CancellationToken,
    health: crate::workers::WorkerHeartbeat,
) -> Result<()> {
    let worker_id = Uuid::new_v4();
    loop {
        health.pulse();
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            result = run_one_admin_session_cleanup(&state, worker_id) => match result {
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

async fn run_one_admin_session_cleanup(state: &Arc<AppState>, worker_id: Uuid) -> Result<bool> {
    let Some(lease) = state
        .admin_session_cleanup_worker_service()
        .claim(worker_id)
        .await?
    else {
        return Ok(false);
    };
    // Keep the renewal future in this attempt's structured-concurrency scope.
    // WorkerRegistry may drop an attempt immediately during shutdown or after
    // a terminal health transition. A detached Tokio task would survive that
    // drop and could continue renewing a lease after its effect owner ceased
    // to exist.
    let effect = execute_with_lease_renewal(
        execute_admin_session_cleanup(state, &lease, worker_id),
        |heartbeat_stop| {
            admin_session_cleanup_heartbeat(
                state.admin_session_cleanup_worker_service(),
                lease.clone(),
                worker_id,
                heartbeat_stop,
            )
        },
    )
    .await;

    match effect {
        Ok(true) => {
            if !state
                .admin_session_cleanup_worker_service()
                .complete(&lease, worker_id)
                .await?
            {
                tracing::debug!(effect_id=%lease.id, "administrator session-cleanup lease changed before completion");
            }
        }
        Ok(false) => {
            if !state
                .admin_session_cleanup_worker_service()
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
            if !state
                .admin_session_cleanup_worker_service()
                .retry(&lease, worker_id, "delivery_failed")
                .await?
            {
                tracing::debug!(effect_id=%lease.id, "administrator session-cleanup lease changed after delivery failure");
            }
        }
    }
    Ok(true)
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
    state: &AppState,
    lease: &AdminSessionCleanupLease,
    worker_id: Uuid,
) -> Result<bool> {
    match lease.kind {
        AdminSessionCleanupKind::AccountGeneration => {
            let bare_jid = lease
                .bare_jid
                .as_deref()
                .context("generation cleanup has no bare JID")?;
            let bare_jid = crate::jid::CanonicalJid::parse_bare(bare_jid)
                .context("generation cleanup has an invalid bare JID")?;
            anyhow::ensure!(
                bare_jid.localpart().is_some() && bare_jid.domainpart() == state.config.domain,
                "generation cleanup must target an account on the local XMPP domain"
            );
            state.revoke_local_account_routes(
                lease.user_id,
                &bare_jid.to_string(),
                Some(lease.auth_generation),
            );
            state
                .cluster
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
            let full_jid = crate::jid::CanonicalJid::parse(full_jid)
                .context("exact cleanup has an invalid full JID")?;
            anyhow::ensure!(
                full_jid.localpart().is_some()
                    && full_jid.resourcepart().is_some()
                    && full_jid.domainpart() == state.config.domain,
                "exact cleanup must target a full account JID on the local XMPP domain"
            );
            let full_jid = full_jid.to_string();
            let connection_id = lease
                .connection_id
                .context("exact cleanup has no connection identity")?;
            if let Some(session) = state.sessions.get_mut(&full_jid) {
                if session.user_id == lease.user_id
                    && session.auth_generation == lease.auth_generation
                    && session.connection_id == connection_id
                {
                    session.routable.store(false, Ordering::Release);
                    session.disconnect.cancel();
                }
            }
            state
                .cluster
                .send_session_instance_termination(&full_jid, connection_id)
                .await?;
            Ok(!state
                .admin_session_cleanup_worker_service()
                .target_current(lease, worker_id)
                .await?)
        }
    }
}

async fn run_one(state: &Arc<AppState>, worker_id: Uuid) -> Result<bool> {
    let Some(lease) = state
        .operation_journal_worker_service()
        .claim_parent_with_targets(worker_id, LEASE_SECONDS, |operation| {
            state.broadcast_routes().target_seeds(operation)
        })
        .await?
    else {
        return Ok(false);
    };

    loop {
        let target = match state
            .operation_journal_worker_service()
            .next_target(&lease, worker_id, LEASE_SECONDS)
            .await?
        {
            NextTarget::LeaseLost | NextTarget::Cancelled => return Ok(true),
            NextTarget::Exhausted => break,
            NextTarget::Claimed(target) => target,
        };

        let fenced = state
            .operation_effect_fence_service()
            .execute_after_commit(&lease, &target, || async {
                let heartbeat_stop = CancellationToken::new();
                let heartbeat = tokio::spawn(lease_heartbeat(
                    Arc::clone(state),
                    lease.clone(),
                    target.clone(),
                    heartbeat_stop.clone(),
                ));
                let effect = execute_effect(state, &lease.operation, &target.target.payload).await;
                heartbeat_stop.cancel();
                heartbeat
                    .await
                    .context("operation lease heartbeat panicked")??;
                Ok(effect)
            })
            .await?;
        let FencedEffect::Executed(effect) = fenced else {
            return Ok(true);
        };
        match state
            .operation_journal_worker_service()
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

    let _ = state
        .operation_journal_worker_service()
        .terminalize_parent(&lease)
        .await?;
    Ok(true)
}

async fn lease_heartbeat(
    state: Arc<AppState>,
    parent: db::OperationLease,
    target: db::OperationTargetLease,
    stop: CancellationToken,
) -> Result<()> {
    loop {
        tokio::select! {
            _ = stop.cancelled() => return Ok(()),
            _ = tokio::time::sleep(Duration::from_secs(15)) => {
                if state.operation_journal_worker_service()
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
    sessions: Arc<dashmap::DashMap<String, crate::state::OnlineSession>>,
    domain: String,
    node_id: String,
}

impl LocalBroadcastRoutes {
    pub(crate) fn new(
        sessions: Arc<dashmap::DashMap<String, crate::state::OnlineSession>>,
        domain: String,
        node_id: String,
    ) -> Self {
        Self {
            sessions,
            domain,
            node_id,
        }
    }

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
            crate::state::attr_escape(&self.domain),
            Uuid::new_v4(),
            crate::state::attr_escape(text)
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

/// An administrator operation may cancel only a session with the exact
/// committed user, credential generation, and connection incarnation.
pub(crate) struct LocalSessionKickRoutes {
    sessions: Arc<dashmap::DashMap<String, crate::state::OnlineSession>>,
}

impl LocalSessionKickRoutes {
    pub(crate) fn new(
        sessions: Arc<dashmap::DashMap<String, crate::state::OnlineSession>>,
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
    sessions: Arc<dashmap::DashMap<String, crate::state::OnlineSession>>,
}

impl LocalGenerationCleanupRoutes {
    pub(crate) fn new(
        sessions: Arc<dashmap::DashMap<String, crate::state::OnlineSession>>,
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
    sessions: Arc<dashmap::DashMap<String, crate::state::OnlineSession>>,
}

impl LocalPanicDisconnectRoutes {
    pub(crate) fn new(
        sessions: Arc<dashmap::DashMap<String, crate::state::OnlineSession>>,
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

async fn panic_disconnect_with<Teardown, TeardownFuture>(
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
    state: &AppState,
    operation: &db::OperationRecord,
    payload: &Value,
) -> Result<Value> {
    match operation.kind.as_str() {
        "admin.tls_reload" => {
            let tls = state.tls_context().clone();
            let outcome = match tokio::task::spawn_blocking(move || tls.reload()).await {
                Ok(Ok(outcome)) => outcome,
                Ok(Err(error)) => {
                    state
                        .metrics
                        .tls_reload_failures_total
                        .fetch_add(1, Ordering::Relaxed);
                    return Err(error);
                }
                Err(error) => {
                    state
                        .metrics
                        .tls_reload_failures_total
                        .fetch_add(1, Ordering::Relaxed);
                    return Err(error.into());
                }
            };
            state
                .metrics
                .tls_revocation_rechecks_total
                .fetch_add(outcome.evaluated_sessions, Ordering::Relaxed);
            state
                .metrics
                .tls_revocation_recheck_inconclusive_total
                .fetch_add(outcome.inconclusive_rechecks, Ordering::Relaxed);
            state
                .metrics
                .tls_revoked_sessions_drained_total
                .fetch_add(outcome.drained_total(), Ordering::Relaxed);
            state
                .metrics
                .tls_revoked_c2s_external_sessions_drained_total
                .fetch_add(outcome.drained_c2s_external, Ordering::Relaxed);
            state
                .metrics
                .tls_revoked_inbound_s2s_external_sessions_drained_total
                .fetch_add(outcome.drained_inbound_s2s_external, Ordering::Relaxed);
            state
                .metrics
                .tls_revoked_outbound_s2s_external_sessions_drained_total
                .fetch_add(outcome.drained_outbound_s2s_external, Ordering::Relaxed);
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
        "admin.panic_disconnect" => {
            panic_disconnect_with(&state.panic_disconnect_routes(), || {
                state.revoke_all_sm_sessions_with_teardown()
            })
            .await
        }
        "admin.session_kick" => {
            let (user_id, connection_id, generation) = session_kick_identity(payload)?;
            let kicked = state
                .session_kick_routes()
                .kick_exact(user_id, generation, connection_id);
            Ok(json!({"kicked":kicked,"connection_id":connection_id}))
        }
        "admin.broadcast" => state.broadcast_routes().send_exact(payload),
        "admin.island_converge" => {
            let enabled = match payload.get("mode").and_then(Value::as_str) {
                Some("enabled") => true,
                Some("disabled") => false,
                _ => anyhow::bail!("invalid island mode"),
            };
            state.apply_island_mode(enabled).await;
            if enabled {
                state
                    .s2s_connection_registry()
                    .clear_outbound_for_island_mode();
            }
            Ok(json!({"island_mode":enabled}))
        }
        "admin.user_session_cleanup" => {
            let (user_id, generation) = generation_cleanup_identity(payload)?;
            let disconnected = state
                .generation_cleanup_routes()
                .cancel_exact_generation(user_id, generation);
            Ok(json!({"sessions_disconnected":disconnected,"user_id":user_id}))
        }
        "admin.muc_destroy" => {
            let committed = state
                .operation_muc_destroy_service()
                .execute(crate::services::operation_muc_destroy::MucDestroyEffect {
                    operation_id: operation.id,
                    request_id: operation.request_id,
                    actor_id: operation.actor_id,
                    payload,
                    local_domain: &state.config.domain,
                })
                .await?;
            if let Err(error) = state
                .muc_service()
                .wake_committed_operation(&state.cluster, operation.id)
                .await
            {
                tracing::warn!(?error, operation_id=%operation.id,
                    "admin MUC destroy committed; signed wake failed and PostgreSQL polling will catch up");
            }
            state
                .muc_occupants
                .retain(|_, occupant| occupant.room_jid != committed.room_jid);
            Ok(json!({"destroyed":committed.destroyed,"room_jid":committed.room_jid}))
        }
        kind => anyhow::bail!("operation executor is unavailable for {kind}"),
    }
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
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Instant;
    use tokio::sync::Notify;

    fn session(
        user_id: Uuid,
        generation: i64,
        connection_id: Uuid,
        sender: tokio::sync::mpsc::Sender<crate::outbound::OutboundItem>,
    ) -> crate::state::OnlineSession {
        crate::state::OnlineSession {
            user_id,
            auth_generation: generation,
            user_agent_epoch: None,
            connection_id,
            route_incarnation: crate::state::RouteIncarnationSignal::new(connection_id),
            lifecycle: Arc::default(),
            metrics_counted: Arc::default(),
            routable: Arc::new(AtomicBool::new(true)),
            sender: crate::outbound::OutboundSender::new(sender),
            available: Arc::default(),
            mix_presence_gate: Arc::default(),
            mix_presence_fallback_suppressed: Arc::default(),
            caps_observation_generation: Arc::default(),
            carbons: Arc::default(),
            priority: Arc::default(),
            show: Arc::default(),
            blocklist_requested: Arc::default(),
            roster_requested: Arc::default(),
            roster_sync: Arc::default(),
            mix_roster_annotations: Arc::default(),
            privacy_active: Arc::default(),
            privacy_requested: Arc::default(),
            directed_presence: Arc::default(),
            last_presence: Arc::default(),
            ip: None,
            resource: "fixture".into(),
            user_agent_id: None,
            sm_session_id: Arc::default(),
            muc_memberships: Arc::default(),
            connected_at: Instant::now(),
            last_activity: Arc::new(std::sync::RwLock::new(Instant::now())),
            disconnect: CancellationToken::new(),
        }
    }

    #[tokio::test]
    async fn panic_disconnect_cancels_every_local_route_before_sm_teardown() {
        let sessions = Arc::new(dashmap::DashMap::new());
        let routes = LocalPanicDisconnectRoutes::new(Arc::clone(&sessions));
        let add = |key: &str, routable: bool| {
            let (sender, _receiver) = tokio::sync::mpsc::channel(1);
            let session = session(Uuid::new_v4(), 3, Uuid::new_v4(), sender);
            session.routable.store(routable, Ordering::Release);
            let cancelled = session.disconnect.clone();
            sessions.insert(key.to_owned(), session);
            cancelled
        };
        let active = add("alice@example.test/phone", true);
        let pending = add("alice@example.test/pending", false);
        let previously_cancelled = add("bob@example.test/device", true);
        previously_cancelled.cancel();

        let result = panic_disconnect_with(&routes, || {
            assert!(active.is_cancelled());
            assert!(pending.is_cancelled());
            assert!(previously_cancelled.is_cancelled());
            async { Ok(12) }
        })
        .await
        .unwrap();
        assert_eq!(result, json!({"sessions_disconnected":3}));
        assert!(sessions
            .get("alice@example.test/phone")
            .unwrap()
            .routable
            .load(Ordering::Acquire));
        assert!(!sessions
            .get("alice@example.test/pending")
            .unwrap()
            .routable
            .load(Ordering::Acquire));

        let error = panic_disconnect_with(&routes, || {
            assert!(active.is_cancelled());
            async { anyhow::bail!("durable SM teardown failed") }
        })
        .await
        .unwrap_err();
        assert_eq!(error.to_string(), "durable SM teardown failed");
        assert_eq!(routes.cancel_all(), 3);
    }

    #[test]
    fn exact_session_kick_cancels_pending_route_without_touching_replacements() {
        let sessions = Arc::new(dashmap::DashMap::new());
        let routes = LocalSessionKickRoutes::new(Arc::clone(&sessions));
        let user_id = Uuid::new_v4();
        let old_connection = Uuid::new_v4();
        let (old_sender, _old_receiver) = tokio::sync::mpsc::channel(1);
        let old = session(user_id, 4, old_connection, old_sender);
        old.routable.store(false, Ordering::Release);
        let old_disconnect = old.disconnect.clone();
        sessions.insert("alice@example.test/phone".into(), old);

        assert!(!routes.kick_exact(Uuid::new_v4(), 4, old_connection));
        assert!(!routes.kick_exact(user_id, 5, old_connection));
        assert!(!routes.kick_exact(user_id, 4, Uuid::new_v4()));
        assert!(!old_disconnect.is_cancelled());

        assert!(routes.kick_exact(user_id, 4, old_connection));
        assert!(old_disconnect.is_cancelled());
        assert!(routes.kick_exact(user_id, 4, old_connection));
        assert!(!sessions
            .get("alice@example.test/phone")
            .unwrap()
            .routable
            .load(Ordering::Acquire));

        let new_connection = Uuid::new_v4();
        let (new_sender, _new_receiver) = tokio::sync::mpsc::channel(1);
        let replacement = session(user_id, 5, new_connection, new_sender);
        let new_disconnect = replacement.disconnect.clone();
        sessions.insert("alice@example.test/phone".into(), replacement);
        assert!(!routes.kick_exact(user_id, 4, old_connection));
        assert!(!new_disconnect.is_cancelled());
        assert!(routes.kick_exact(user_id, 5, new_connection));
        assert!(new_disconnect.is_cancelled());
    }

    #[test]
    fn session_kick_payload_errors_remain_at_effect_decoding() {
        let user_id = Uuid::new_v4();
        let connection_id = Uuid::new_v4();
        for (payload, expected) in [
            (json!({}), "user_id is missing"),
            (json!({"user_id":"not-a-uuid"}), "user_id is invalid"),
            (json!({"user_id":Uuid::nil()}), "user_id must not be nil"),
            (json!({"user_id":user_id}), "connection_id is missing"),
            (
                json!({"user_id":user_id,"connection_id":"not-a-uuid"}),
                "connection_id is invalid",
            ),
            (
                json!({"user_id":user_id,"connection_id":Uuid::nil()}),
                "connection_id must not be nil",
            ),
            (
                json!({"user_id":user_id,"connection_id":connection_id}),
                "auth generation is missing",
            ),
        ] {
            assert_eq!(
                session_kick_identity(&payload).unwrap_err().to_string(),
                expected
            );
        }
        assert_eq!(
            session_kick_identity(&json!({
                "user_id":user_id,
                "connection_id":connection_id,
                "auth_generation":7
            }))
            .unwrap(),
            (user_id, connection_id, 7)
        );
    }

    #[test]
    fn generation_cleanup_counts_all_exact_resources_including_pending_on_retry() {
        let sessions = Arc::new(dashmap::DashMap::new());
        let routes = LocalGenerationCleanupRoutes::new(Arc::clone(&sessions));
        let user_id = Uuid::new_v4();
        let other_user = Uuid::new_v4();
        let add = |key: &str, owner: Uuid, generation: i64, routable: bool| {
            let (sender, _receiver) = tokio::sync::mpsc::channel(1);
            let session = session(owner, generation, Uuid::new_v4(), sender);
            session.routable.store(routable, Ordering::Release);
            let cancelled = session.disconnect.clone();
            sessions.insert(key.to_owned(), session);
            cancelled
        };
        let phone = add("alice@example.test/phone", user_id, 3, true);
        let pending = add("alice@example.test/pending", user_id, 3, false);
        let older = add("alice@example.test/older", user_id, 2, true);
        let newer = add("alice@example.test/newer", user_id, 4, true);
        let recreated = add("alice@example.test/recreated", other_user, 3, true);

        assert_eq!(routes.cancel_exact_generation(user_id, 3), 2);
        assert!(phone.is_cancelled());
        assert!(pending.is_cancelled());
        assert!(!older.is_cancelled());
        assert!(!newer.is_cancelled());
        assert!(!recreated.is_cancelled());
        assert!(!sessions
            .get("alice@example.test/pending")
            .unwrap()
            .routable
            .load(Ordering::Acquire));
        assert!(sessions
            .get("alice@example.test/phone")
            .unwrap()
            .routable
            .load(Ordering::Acquire));
        assert_eq!(routes.cancel_exact_generation(user_id, 3), 2);
        assert!(!older.is_cancelled());
        assert!(!newer.is_cancelled());
        assert!(!recreated.is_cancelled());
    }

    #[test]
    fn generation_cleanup_payload_errors_match_effect_decoding() {
        let user_id = Uuid::new_v4();
        for (payload, expected) in [
            (json!({}), "user_id is missing"),
            (json!({"user_id":"not-a-uuid"}), "user_id is invalid"),
            (json!({"user_id":Uuid::nil()}), "user_id must not be nil"),
            (json!({"user_id":user_id}), "auth generation is missing"),
        ] {
            assert_eq!(
                generation_cleanup_identity(&payload)
                    .unwrap_err()
                    .to_string(),
                expected
            );
        }
        assert_eq!(
            generation_cleanup_identity(&json!({"user_id":user_id,"auth_generation":3})).unwrap(),
            (user_id, 3)
        );
    }

    #[test]
    fn broadcast_effect_rechecks_snapshot_identity_and_does_not_send_to_replacement() {
        let sessions = Arc::new(dashmap::DashMap::new());
        let routes = LocalBroadcastRoutes::new(
            Arc::clone(&sessions),
            "example.test".into(),
            "node-1".into(),
        );
        let key = "alice@example.test/phone";
        let user_id = Uuid::new_v4();
        let old_connection = Uuid::new_v4();
        let (old_sender, mut old_receiver) = tokio::sync::mpsc::channel(1);
        sessions.insert(key.into(), session(user_id, 3, old_connection, old_sender));
        let operation_payload = json!({"message":"<&>'\""});
        let old_seed = routes
            .target_seeds(ClaimedOperation {
                kind: "admin.broadcast",
                payload: &operation_payload,
            })
            .unwrap()
            .pop()
            .unwrap();

        let new_connection = Uuid::new_v4();
        let (new_sender, mut new_receiver) = tokio::sync::mpsc::channel(1);
        sessions.insert(key.into(), session(user_id, 4, new_connection, new_sender));
        assert_eq!(
            routes.send_exact(&old_seed.payload).unwrap(),
            json!({"sent":false,"connection_id":old_connection})
        );
        assert!(old_receiver.try_recv().is_err());
        assert!(new_receiver.try_recv().is_err());

        let new_seed = routes
            .target_seeds(ClaimedOperation {
                kind: "admin.broadcast",
                payload: &operation_payload,
            })
            .unwrap()
            .pop()
            .unwrap();
        for (field, replacement) in [
            ("user_id", json!(Uuid::new_v4())),
            ("auth_generation", json!(3)),
            ("connection_id", json!(old_connection)),
        ] {
            let mut stale = new_seed.payload.clone();
            stale[field] = replacement;
            assert_eq!(
                stale.get("session_key"),
                new_seed.payload.get("session_key")
            );
            assert_eq!(routes.send_exact(&stale).unwrap()["sent"], false);
        }
        assert!(new_receiver.try_recv().is_err());
        sessions
            .get(key)
            .unwrap()
            .routable
            .store(false, Ordering::Release);
        assert_eq!(routes.send_exact(&new_seed.payload).unwrap()["sent"], false);
        sessions
            .get(key)
            .unwrap()
            .routable
            .store(true, Ordering::Release);

        assert_eq!(
            routes.send_exact(&new_seed.payload).unwrap(),
            json!({"sent":true,"connection_id":new_connection})
        );
        let stanza = new_receiver.try_recv().unwrap().stanza;
        assert!(stanza.contains("from='example.test' type='headline' id='"));
        assert!(stanza.contains("<body>&lt;&amp;&gt;&apos;&quot;</body>"));
    }

    #[test]
    fn broadcast_effect_reports_full_queue_and_empty_snapshot_without_delivery() {
        let sessions = Arc::new(dashmap::DashMap::new());
        let routes = LocalBroadcastRoutes::new(
            Arc::clone(&sessions),
            "example.test".into(),
            "node-1".into(),
        );
        let operation_payload = json!({"message":"maintenance"});
        let empty = routes
            .target_seeds(ClaimedOperation {
                kind: "admin.broadcast",
                payload: &operation_payload,
            })
            .unwrap();
        assert_eq!(empty[0].target_key, "node:node-1");
        assert_eq!(empty[0].ordinal, 0);
        assert_eq!(
            routes.send_exact(&empty[0].payload).unwrap(),
            json!({"sent":false,"reason":"empty_snapshot"})
        );

        let key = "alice@example.test/phone";
        let connection_id = Uuid::new_v4();
        let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
        sessions.insert(
            key.into(),
            session(Uuid::new_v4(), 3, connection_id, sender),
        );
        let seed = routes
            .target_seeds(ClaimedOperation {
                kind: "admin.broadcast",
                payload: &operation_payload,
            })
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(routes.send_exact(&seed.payload).unwrap()["sent"], true);
        assert_eq!(routes.send_exact(&seed.payload).unwrap()["sent"], false);
        assert!(receiver
            .try_recv()
            .unwrap()
            .stanza
            .contains("<body>maintenance</body>"));
        assert!(receiver.try_recv().is_err());
    }

    #[test]
    fn broadcast_target_snapshot_preserves_connection_order_and_payload() {
        let alice = Uuid::new_v4();
        let bob = Uuid::new_v4();
        let alice_connection = Uuid::new_v4();
        let bob_connection = Uuid::new_v4();
        let operation_payload = json!({"message":"maintenance"});
        let seeds = target_seeds_for_operation(
            ClaimedOperation {
                kind: "admin.broadcast",
                payload: &operation_payload,
            },
            "node-1",
            [
                BroadcastRoute {
                    session_key: "alice@example.test/phone".to_owned(),
                    user_id: alice,
                    auth_generation: 3,
                    connection_id: alice_connection,
                },
                BroadcastRoute {
                    session_key: "bob@example.test/laptop".to_owned(),
                    user_id: bob,
                    auth_generation: 5,
                    connection_id: bob_connection,
                },
            ]
            .into_iter(),
        )
        .unwrap();
        assert_eq!(seeds.len(), 2);
        assert_eq!(
            seeds[0].target_key,
            format!("connection:{alice_connection}")
        );
        assert_eq!(seeds[0].ordinal, 0);
        assert_eq!(
            seeds[0].payload,
            json!({
                "message":"maintenance",
                "session_key":"alice@example.test/phone",
                "user_id":alice,
                "auth_generation":3,
                "connection_id":alice_connection,
            })
        );
        assert_eq!(seeds[1].target_key, format!("connection:{bob_connection}"));
        assert_eq!(seeds[1].ordinal, 1);
        assert_eq!(
            seeds[1].payload,
            json!({
                "message":"maintenance",
                "session_key":"bob@example.test/laptop",
                "user_id":bob,
                "auth_generation":5,
                "connection_id":bob_connection,
            })
        );
    }

    #[test]
    fn empty_broadcast_and_nonbroadcast_target_fallbacks_are_exact() {
        for (kind, payload, expected_key) in [
            (
                "admin.broadcast",
                json!({"message":"maintenance"}),
                "node:node-1",
            ),
            ("admin.tls_reload", json!({}), "node:node-1"),
            (
                "admin.session_kick",
                json!({"connection_id":"exact-connection"}),
                "connection:exact-connection",
            ),
        ] {
            let seeds = target_seeds_for_operation(
                ClaimedOperation {
                    kind,
                    payload: &payload,
                },
                "node-1",
                std::iter::empty(),
            )
            .unwrap();
            assert_eq!(seeds.len(), 1);
            assert_eq!(seeds[0].target_key, expected_key);
            assert_eq!(seeds[0].ordinal, 0);
            assert_eq!(seeds[0].payload, payload);
        }
    }

    struct DropSignal(Arc<AtomicBool>);

    impl Drop for DropSignal {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    #[tokio::test]
    async fn cleanup_effect_success_cancels_and_reaps_renewal() {
        let renewal_stopped = Arc::new(AtomicBool::new(false));
        let renewal_stopped_in_task = Arc::clone(&renewal_stopped);

        let value = execute_with_lease_renewal(async { Ok(42_u8) }, move |stop| async move {
            stop.cancelled().await;
            renewal_stopped_in_task.store(true, Ordering::Release);
            Ok(())
        })
        .await
        .expect("the cleanup effect must succeed");

        assert_eq!(value, 42);
        assert!(
            renewal_stopped.load(Ordering::Acquire),
            "the effect result must not escape before renewal observes cancellation"
        );
    }

    #[tokio::test]
    async fn cleanup_effect_error_cancels_and_reaps_renewal() {
        let renewal_stopped = Arc::new(AtomicBool::new(false));
        let renewal_stopped_in_task = Arc::clone(&renewal_stopped);

        let error = execute_with_lease_renewal(
            async { Err::<(), anyhow::Error>(anyhow::anyhow!("injected cleanup effect failure")) },
            move |stop| async move {
                stop.cancelled().await;
                renewal_stopped_in_task.store(true, Ordering::Release);
                Ok(())
            },
        )
        .await
        .expect_err("the cleanup effect must preserve its failure");

        assert!(error
            .to_string()
            .contains("injected cleanup effect failure"));
        assert!(
            renewal_stopped.load(Ordering::Acquire),
            "the effect result must not escape before renewal observes cancellation"
        );
    }

    #[tokio::test]
    async fn cleanup_attempt_cancellation_cannot_detach_renewal() {
        let renewal_started = Arc::new(Notify::new());
        let renewal_started_in_task = Arc::clone(&renewal_started);
        let renewal_dropped = Arc::new(AtomicBool::new(false));
        let renewal_dropped_in_task = Arc::clone(&renewal_dropped);

        let attempt = tokio::spawn(execute_with_lease_renewal(
            std::future::pending::<Result<()>>(),
            move |_stop| async move {
                let _drop_signal = DropSignal(renewal_dropped_in_task);
                renewal_started_in_task.notify_one();
                std::future::pending::<Result<()>>().await
            },
        ));
        tokio::time::timeout(Duration::from_secs(1), renewal_started.notified())
            .await
            .expect("renewal did not enter its structured scope");

        attempt.abort();
        let join_error = attempt
            .await
            .expect_err("the injected attempt cancellation must abort its parent future");
        assert!(join_error.is_cancelled());
        assert!(
            renewal_dropped.load(Ordering::Acquire),
            "dropping the parent attempt must synchronously drop its renewal child"
        );
    }

    #[tokio::test]
    async fn renewal_failure_stops_the_cleanup_effect() {
        let effect_dropped = Arc::new(AtomicBool::new(false));
        let effect_dropped_in_task = Arc::clone(&effect_dropped);

        let error = execute_with_lease_renewal(
            async move {
                let _drop_signal = DropSignal(effect_dropped_in_task);
                std::future::pending::<Result<()>>().await
            },
            |_stop| async { anyhow::bail!("injected renewal failure") },
        )
        .await
        .expect_err("renewal failure must fence the cleanup effect");

        assert!(error.to_string().contains("lease renewal failed"));
        assert!(
            effect_dropped.load(Ordering::Acquire),
            "an effect must not outlive its failed renewal fence"
        );
    }
}
