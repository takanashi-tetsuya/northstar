use std::{
    sync::{atomic::Ordering, Arc},
    time::Duration,
};

use anyhow::{Context, Result};
use serde_json::{json, Value};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

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
    let Some(lease) = db::claim_admin_session_cleanup(
        &state.pool,
        worker_id,
        i32::try_from(LEASE_SECONDS).expect("operation lease seconds fit i32"),
    )
    .await?
    else {
        return Ok(false);
    };
    let heartbeat_stop = CancellationToken::new();
    let heartbeat = tokio::spawn(admin_session_cleanup_heartbeat(
        Arc::clone(state),
        lease.clone(),
        worker_id,
        heartbeat_stop.clone(),
    ));
    let effect = execute_admin_session_cleanup(state, &lease, worker_id).await;
    heartbeat_stop.cancel();
    heartbeat
        .await
        .context("administrator session-cleanup heartbeat panicked")??;

    match effect {
        Ok(true) => {
            if !db::complete_admin_session_cleanup(&state.pool, &lease, worker_id).await? {
                tracing::debug!(effect_id=%lease.id, "administrator session-cleanup lease changed before completion");
            }
        }
        Ok(false) => {
            if !db::retry_admin_session_cleanup(
                &state.pool,
                &lease,
                worker_id,
                "target_still_current",
            )
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
            if !db::retry_admin_session_cleanup(&state.pool, &lease, worker_id, "delivery_failed")
                .await?
            {
                tracing::debug!(effect_id=%lease.id, "administrator session-cleanup lease changed after delivery failure");
            }
        }
    }
    Ok(true)
}

async fn admin_session_cleanup_heartbeat(
    state: Arc<AppState>,
    lease: db::AdminSessionCleanupLease,
    worker_id: Uuid,
    stop: CancellationToken,
) -> Result<()> {
    loop {
        tokio::select! {
            _ = stop.cancelled() => return Ok(()),
            _ = tokio::time::sleep(Duration::from_secs(15)) => {
                if !db::renew_admin_session_cleanup(
                    &state.pool,
                    &lease,
                    worker_id,
                    i32::try_from(LEASE_SECONDS).expect("operation lease seconds fit i32"),
                ).await? {
                    anyhow::bail!("administrator session-cleanup lease fencing was lost");
                }
            }
        }
    }
}

async fn execute_admin_session_cleanup(
    state: &AppState,
    lease: &db::AdminSessionCleanupLease,
    worker_id: Uuid,
) -> Result<bool> {
    match lease.kind {
        db::AdminSessionCleanupKind::AccountGeneration => {
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
        db::AdminSessionCleanupKind::ExactConnection => {
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
            Ok(!db::admin_session_cleanup_target_current(&state.pool, lease, worker_id).await?)
        }
    }
}

async fn run_one(state: &Arc<AppState>, worker_id: Uuid) -> Result<bool> {
    let mut tx = state.pool.begin().await?;
    let Some(lease) = db::claim_operation_in_tx(&mut tx, worker_id, LEASE_SECONDS).await? else {
        tx.commit().await?;
        return Ok(false);
    };
    ensure_targets(state, &mut tx, &lease.operation).await?;
    tx.commit().await?;

    loop {
        let mut claim = state.pool.begin().await?;
        if !db::renew_operation_lease_in_tx(&mut claim, &lease, LEASE_SECONDS).await? {
            claim.rollback().await?;
            return Ok(true);
        }
        let target = db::claim_operation_target_in_tx(
            &mut claim,
            lease.operation.id,
            worker_id,
            LEASE_SECONDS,
        )
        .await?;
        claim.commit().await?;
        let Some(target) = target else {
            let mut cancel_tx = state.pool.begin().await?;
            if db::acknowledge_operation_cancel_in_tx(&mut cancel_tx, &lease).await? {
                cancel_tx.commit().await?;
                return Ok(true);
            }
            cancel_tx.rollback().await?;
            break;
        };

        let mut fence = state.pool.begin().await?;
        if db::authorize_operation_effect_in_tx(&mut fence, &lease).await?
            != db::EffectAuthorizationOutcome::Authorized
            || !db::mark_operation_target_point_of_no_return_in_tx(&mut fence, &target).await?
        {
            let _ = db::acknowledge_operation_target_cancel_in_tx(&mut fence, &target).await?;
            let _ = db::acknowledge_operation_cancel_in_tx(&mut fence, &lease).await?;
            fence.commit().await?;
            return Ok(true);
        }
        fence.commit().await?;

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
        let mut finish = state.pool.begin().await?;
        match effect {
            Ok(result) => {
                if !db::succeed_operation_target_in_tx(&mut finish, &target, &result).await? {
                    finish.rollback().await?;
                    return Ok(true);
                }
            }
            Err(error) => {
                tracing::warn!(operation_id=%lease.operation.id, target_id=%target.target.id, ?error, "durable operation effect failed after PONR");
                let details = json!({"message": error.to_string()});
                if !db::mark_operation_target_indeterminate_in_tx(
                    &mut finish,
                    &lease,
                    &target,
                    "effect_outcome_unprovable",
                    Some(&details),
                )
                .await?
                {
                    finish.rollback().await?;
                    return Ok(true);
                }
                finish.commit().await?;
                return Ok(true);
            }
        }
        finish.commit().await?;
    }

    let mut finish = state.pool.begin().await?;
    if !db::succeed_operation_in_tx(&mut finish, &lease, &json!({"completed":true})).await? {
        if db::fail_operation_in_tx(&mut finish, &lease, "target_incomplete", None).await? {
            finish.commit().await?;
        } else {
            finish.rollback().await?;
        }
        return Ok(true);
    }
    finish.commit().await?;
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
                let mut tx = state.pool.begin().await?;
                let parent_ok = db::renew_operation_lease_in_tx(&mut tx, &parent, LEASE_SECONDS).await?;
                let target_ok = db::renew_operation_target_lease_in_tx(&mut tx, &target, LEASE_SECONDS).await?;
                if !parent_ok || !target_ok {
                    tx.rollback().await?;
                    anyhow::bail!("operation lease fencing was lost");
                }
                tx.commit().await?;
            }
        }
    }
}

async fn ensure_targets(
    state: &AppState,
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    operation: &db::OperationRecord,
) -> Result<()> {
    if operation.kind == "admin.broadcast" {
        let message = operation
            .payload
            .get("message")
            .and_then(Value::as_str)
            .context("broadcast message is missing")?;
        let mut ordinal = 0_i64;
        for entry in state.sessions.iter() {
            let session = entry.value();
            if !session.routable.load(Ordering::Acquire) {
                continue;
            }
            let payload = json!({"message":message,"session_key":entry.key(),"user_id":session.user_id,
                "auth_generation":session.auth_generation,"connection_id":session.connection_id});
            db::enqueue_operation_target_in_tx(
                tx,
                &db::EnqueueOperationTarget {
                    operation_id: operation.id,
                    target_key: &format!("connection:{}", session.connection_id),
                    ordinal,
                    payload: &payload,
                    max_attempts: operation.max_attempts,
                    deadline_seconds: 24 * 60 * 60,
                },
            )
            .await?;
            ordinal += 1;
        }
        if ordinal > 0 {
            return Ok(());
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
        format!("node:{}", state.cluster.node_id)
    };
    db::enqueue_operation_target_in_tx(
        tx,
        &db::EnqueueOperationTarget {
            operation_id: operation.id,
            target_key: &target_key,
            ordinal: 0,
            payload: &operation.payload,
            max_attempts: operation.max_attempts,
            deadline_seconds: 24 * 60 * 60,
        },
    )
    .await?;
    Ok(())
}

async fn execute_effect(
    state: &AppState,
    operation: &db::OperationRecord,
    payload: &Value,
) -> Result<Value> {
    match operation.kind.as_str() {
        "admin.tls_reload" => {
            let tls = Arc::clone(&state.tls);
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
            let mut disconnected = 0_u64;
            for session in state.sessions.iter() {
                session.disconnect.cancel();
                disconnected += 1;
            }
            state.revoke_all_sm_sessions_with_teardown().await?;
            Ok(json!({"sessions_disconnected":disconnected}))
        }
        "admin.session_kick" => {
            let user_id = uuid_field(payload, "user_id")?;
            let connection_id = uuid_field(payload, "connection_id")?;
            let generation = payload
                .get("auth_generation")
                .and_then(Value::as_i64)
                .context("auth generation is missing")?;
            let kicked = state
                .sessions
                .iter()
                .find(|entry| {
                    let session = entry.value();
                    session.connection_id == connection_id
                        && session.user_id == user_id
                        && session.auth_generation == generation
                })
                .is_some_and(|session| {
                    session.disconnect.cancel();
                    true
                });
            Ok(json!({"kicked":kicked,"connection_id":connection_id}))
        }
        "admin.broadcast" => {
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
                crate::state::attr_escape(&state.config.domain),
                Uuid::new_v4(),
                crate::state::attr_escape(text)
            );
            let sent = state.sessions.get(key).is_some_and(|session| {
                session.user_id == user_id
                    && session.auth_generation == generation
                    && session.connection_id == connection_id
                    && session.routable.load(Ordering::Acquire)
                    && session.sender.try_send(stanza).is_ok()
            });
            Ok(json!({"sent":sent,"connection_id":connection_id}))
        }
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
            let user_id = uuid_field(payload, "user_id")?;
            let generation = payload
                .get("auth_generation")
                .and_then(Value::as_i64)
                .context("auth generation is missing")?;
            let mut disconnected = 0_u64;
            for session in state.sessions.iter() {
                if session.user_id == user_id && session.auth_generation == generation {
                    session.disconnect.cancel();
                    disconnected += 1;
                }
            }
            Ok(json!({"sessions_disconnected":disconnected,"user_id":user_id}))
        }
        "admin.muc_destroy" => {
            let room_jid = payload
                .get("room_jid")
                .and_then(Value::as_str)
                .context("room JID is missing")?;
            let jid = crate::jid::CanonicalJid::parse(room_jid).context("room JID is invalid")?;
            anyhow::ensure!(jid.resourcepart().is_none(), "room JID must be bare");
            let localpart = jid.localpart().context("room JID has no localpart")?;
            anyhow::ensure!(
                jid.domainpart() == format!("conference.{}", state.config.domain),
                "room JID is outside this MUC service"
            );
            let mut tx = state.pool.begin().await?;
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
                .bind(format!("northstar:muc-room:{localpart}"))
                .execute(&mut *tx)
                .await?;
            let intent_matches = sqlx::query_scalar::<_, Uuid>(
                "SELECT operation_id FROM api_muc_destroy_intents WHERE room_jid=$1 AND localpart=$2 AND operation_id=$3 FOR UPDATE",
            )
            .bind(room_jid).bind(localpart).bind(operation.id)
            .fetch_optional(&mut *tx).await?.is_some();
            anyhow::ensure!(intent_matches, "durable MUC destroy intent is absent");
            let room_id: Option<Uuid> = sqlx::query_scalar(
                "SELECT id FROM muc_rooms
                  WHERE localpart=$1 AND destroyed_at IS NULL FOR UPDATE",
            )
            .bind(localpart)
            .fetch_optional(&mut *tx)
            .await?;
            let actor_id = operation
                .actor_id
                .context("admin MUC destroy operation has no actor")?;
            let actor_label = actor_id.to_string();
            let alternate_jid = payload.get("alternate_jid").and_then(Value::as_str);
            let reason = payload.get("reason").and_then(Value::as_str);
            let destroyed = if let Some(room_id) = room_id {
                db::admin_destroy_cluster_muc_room_in_tx(
                    &mut tx,
                    operation.id,
                    room_id,
                    actor_id,
                    &actor_label,
                    alternate_jid,
                    reason,
                )
                .await?
            } else {
                false
            };
            sqlx::query("DELETE FROM api_muc_destroy_intents WHERE operation_id=$1")
                .bind(operation.id)
                .execute(&mut *tx)
                .await?;
            sqlx::query("INSERT INTO audit_log(actor_id,action,target,details,request_id,operation_id) VALUES($1,'admin.muc_room.destroy',$2,$3,$4,$5)")
                .bind(operation.actor_id).bind(room_jid).bind(json!({"destroyed":destroyed}))
                .bind(operation.request_id).bind(operation.id).execute(&mut *tx).await?;
            tx.commit().await?;
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
                .retain(|_, occupant| occupant.room_jid != room_jid);
            Ok(json!({"destroyed":destroyed,"room_jid":room_jid}))
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
