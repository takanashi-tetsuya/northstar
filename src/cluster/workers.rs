//! Cluster maintenance, account revocation, direct spool wake, pubsub listener and failure supervisor loops.

use super::*;

/// Read committed account fences independently of Redis and cluster maintenance.
/// Notifications reduce latency; polling recovers missed notifications.
pub(crate) async fn run_account_revocations<
    R: crate::services::account_revocation_consumer::AccountRevocationRepository,
>(
    context: Arc<AccountRevocationWorkerContext<R>>,
    cancel: CancellationToken,
    heartbeat: crate::platform::workers::WorkerHeartbeat,
) -> Result<()> {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut cleanup_interval = tokio::time::interval(Duration::from_secs(30));
    let notify = Arc::clone(&context.authority.notify);
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return Ok(()),
            _ = notify.notified() => {},
            _ = interval.tick() => {},
            _ = cleanup_interval.tick() => {
                // A replaced process cannot host live sessions. Its queue can
                // be removed, but an expired lease alone is not replacement.
                match tokio::time::timeout(Duration::from_secs(2),
                    context.service.cleanup()).await {
                    Ok(Ok(())) => {},
                    error => tracing::warn!(?error, "account revocation queue cleanup deferred"),
                }
                continue;
            }
        }
        let consume = async {
            let identity = context.authority.identity();
            let more = context
                .service
                .consume_batch(&identity, |user_id, bare_jid, before_generation| {
                    context.routes.revoke(user_id, bare_jid, before_generation);
                })
                .await?;
            if more {
                notify.notify_one();
            }
            Ok::<(), anyhow::Error>(())
        };
        let result = tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            result = tokio::time::timeout(Duration::from_secs(2), consume) =>
                result.context("account revocation read exceeded its time budget")
                    .and_then(std::convert::identity),
        };
        match result {
            Ok(()) => heartbeat.ok(),
            Err(error) => {
                context.authority.record_failure(&error);
                heartbeat.error(&error);
                // An unreachable authority cannot confirm that existing
                // credentials are still valid. Fence routes before retrying.
                context.routes.fence_all();
                tracing::warn!(
                    ?error,
                    "account revocation authority unavailable; local routes fenced"
                );
            }
        }
        tokio::task::yield_now().await;
    }
}

pub(crate) async fn run_maintenance(
    context: Arc<crate::state::cluster_maintenance_context::ClusterMaintenanceContext>,
    cancel: CancellationToken,
    heartbeat: crate::platform::workers::WorkerHeartbeat,
) -> Result<()> {
    let wake_context = Arc::clone(&context);
    let wake_cancel = cancel.clone();
    tokio::try_join!(
        run_maintenance_passes(context, cancel, heartbeat),
        run_direct_spool_wake_loop(wake_context, wake_cancel),
    )?;
    Ok(())
}

pub(super) async fn run_direct_spool_wake_loop(
    context: Arc<crate::state::cluster_maintenance_context::ClusterMaintenanceContext>,
    cancel: CancellationToken,
) -> Result<()> {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut cleanup = tokio::time::interval(Duration::from_secs(300));
    cleanup.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let control = &context.control;
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return Ok(()),
            _ = cleanup.tick() => {
                match tokio::time::timeout(Duration::from_secs(5), context.direct_spool_wake.cleanup()).await {
                    Ok(Ok(_)) => {},
                    error => {
                        context.locals.record_background_failure();
                        tracing::warn!(?error, "direct spool wake cleanup deferred");
                    }
                }
                continue;
            },
            _ = interval.tick() => {},
            _ = control.direct_spool_notify.notified() => {},
        }
        // Notifications are hints only. A missed LISTEN event or a process
        // restart is covered by the one-second indexed PostgreSQL poll.
        if control.readiness_error().is_some() {
            continue;
        }
        let Some(authority) = control.peer_authority.readiness_snapshot() else {
            continue;
        };
        let attempt = tokio::time::timeout(
            Duration::from_secs(10),
            context.direct_spool_wake.drive_once(&authority, || {
                control
                    .health
                    .recovery_wake_sequence
                    .fetch_add(1, Ordering::AcqRel)
                    .saturating_add(1)
            }),
        )
        .await;
        let failure = match attempt {
            Ok(Ok(())) => None,
            Ok(Err(error)) => Some(error),
            Err(_) => Some(anyhow::anyhow!(
                "direct spool wake pass exceeded its time budget"
            )),
        };
        if let Some(error) = failure {
            control.record_control_plane_failure(&error);
            context.locals.record_background_failure();
            tracing::warn!(?error, "direct spool wake will retry from PostgreSQL");
        }
    }
}

pub(super) async fn run_maintenance_passes(
    context: Arc<crate::state::cluster_maintenance_context::ClusterMaintenanceContext>,
    cancel: CancellationToken,
    heartbeat: crate::platform::workers::WorkerHeartbeat,
) -> Result<()> {
    let control = &context.control;
    let locals = &context.locals;
    let mut interval =
        tokio::time::interval(Duration::from_secs(CLUSTER_MAINTENANCE_INTERVAL_SECONDS));
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            _ = interval.tick() => {
                let maintenance = tokio::select! {
                    _ = cancel.cancelled() => return Ok(()),
                    result = tokio::time::timeout(
                        CLUSTER_MAINTENANCE_BUDGET,
                        maintenance_once(&context),
                    ) => result
                        .context("cluster maintenance pass exceeded its time budget")
                        .and_then(std::convert::identity),
                };
                if let Err(error) = maintenance {
                    control.record_control_plane_failure(&error);
                    heartbeat.error(&error);
                    locals.record_background_failure();
                    tracing::warn!(?error, "session authorization/cluster lease maintenance failed; it will be retried");
                } else {
                    heartbeat.ok();
                }
            }
        }
    }
}

pub(super) async fn maintenance_once(
    context: &crate::state::cluster_maintenance_context::ClusterMaintenanceContext,
) -> Result<()> {
    let control = &context.control;
    let redis = &context.redis;
    let locals = &context.locals;
    // PostgreSQL is authoritative for credential generations.  One bounded
    // batch query provides a Redis-independent safety net for lost controls,
    // node restarts and rolling upgrades.
    let snapshots = locals.session_authority_snapshots();
    let authority_snapshots = snapshots
        .iter()
        .map(|snapshot| snapshot.authority)
        .collect::<Vec<_>>();
    let stale_generations = context
        .session_authority
        .stale_generations(&authority_snapshots)
        .await?;
    for (snapshot, stale) in snapshots.iter().zip(stale_generations) {
        if stale {
            let full_jid = &snapshot.full_jid;
            let user_id = snapshot.authority.user_id;
            let generation = snapshot.authority.auth_generation;
            tracing::warn!(%full_jid, %user_id, auth_generation = generation, "disconnecting credential-stale live session");
            snapshot.disconnect.cancel();
        }
    }
    let stale_device_epochs = context
        .session_authority
        .stale_device_epochs(&authority_snapshots)
        .await?;
    for (snapshot, stale) in snapshots.iter().zip(stale_device_epochs) {
        if let Some((device_id, epoch)) = snapshot
            .authority
            .device_id
            .zip(snapshot.authority.device_epoch)
        {
            if stale {
                let full_jid = &snapshot.full_jid;
                let user_id = snapshot.authority.user_id;
                tracing::warn!(%full_jid, %user_id, %device_id, epoch, "disconnecting replaced user-agent session");
                snapshot.disconnect.cancel();
            }
        }
    }
    if !control.enabled {
        return Ok(());
    }
    let reconciliation_epoch = if control.readiness_error().is_some() {
        match control.begin_reconciliation()? {
            Some(epoch) => Some(epoch),
            // A direct COMMIT still owns the old health decision. Leave Redis
            // reconciliation to the next maintenance pass after it drains.
            None => return Ok(()),
        }
    } else {
        None
    };
    // PostgreSQL instance authority is refreshed before Redis ownership. A
    // recovered listener cannot make this node ready while its view of peer
    // process epochs is stale.
    control
        .refresh_peers_with(&context.cluster_authority)
        .await?;
    let _redis_timer = locals.redis_operation_timer();
    redis.touch_node().await?;
    let sessions = locals
        .session_lease_snapshots()
        .into_iter()
        .map(
            |snapshot| crate::services::session_route_maintenance::SessionRouteLease {
                full_jid: snapshot.full_jid,
                activity_age_seconds: snapshot.activity_age_seconds,
                connection_id: snapshot.connection_id,
                disconnect: snapshot.disconnect,
            },
        )
        .collect();
    context.session_routes.renew_all(sessions).await?;
    // PostgreSQL, not Redis, owns clustered MUC occupancy. Refresh the
    // complete node snapshot once, then require each local actor to match its
    // exact incarnation and connection fence. Redis is repopulated only as a
    // disposable fan-out cache after the authoritative check succeeds.
    let occupancy_maintenance = &context.muc_occupancy;
    let authoritative_muc = occupancy_maintenance
        .authoritative_for_node(&control.node_id)
        .await?;
    locals.record_muc_reconciliation();
    let authoritative_muc = authoritative_muc
        .into_iter()
        .map(|occupancy| {
            (
                (occupancy.occupant_incarnation, occupancy.connection_uuid),
                occupancy,
            )
        })
        .collect::<std::collections::HashMap<_, _>>();
    let occupants = locals.muc_occupant_snapshots();
    let mut unrenewed_muc = Vec::new();
    let mut renewed_muc = Vec::new();
    for occupant in occupants {
        let authoritative =
            authoritative_muc.get(&(occupant.cluster_epoch, occupant.connection_id));
        let exact = authoritative.is_some_and(|authority| {
            authority.full_jid == occupant.full_jid && authority.nick == occupant.nick
        });
        let renewed = if let Some(authority) = authoritative.filter(|_| exact) {
            occupancy_maintenance
                .renew_exact(authority, &control.node_id)
                .await?
        } else {
            false
        };
        if !renewed {
            unrenewed_muc.push(occupant);
            continue;
        }
        renewed_muc.push(occupant);
    }
    for chunk in unrenewed_muc.chunks(crate::services::muc::MAX_MUC_OCCUPANCY_RENEW_BATCH) {
        let mut candidates = Vec::with_capacity(chunk.len());
        for occupant in chunk {
            match crate::services::muc::MucOccupancyLookup::new(
                &occupant.room_jid,
                &occupant.full_jid,
                &occupant.nick,
                occupant.cluster_epoch,
                occupant.connection_id,
            ) {
                Ok(lookup) => candidates.push((occupant, lookup)),
                Err(_) => locals.remove_stale_muc_actor(occupant),
            }
        }
        let lookups = candidates
            .iter()
            .map(|(_, lookup)| lookup.clone())
            .collect::<Vec<_>>();
        let terminal = match occupancy_maintenance
            .committed_terminal_exact_batch(&lookups, &control.node_id)
            .await
        {
            Ok(terminal) => terminal.into_iter().collect::<HashSet<_>>(),
            Err(error) => {
                for (occupant, _) in candidates {
                    locals.remove_stale_muc_actor(occupant);
                }
                return Err(error);
            }
        };
        for (occupant, lookup) in candidates {
            if terminal.contains(&lookup) {
                locals.remove_committed_terminal_muc_actor(occupant);
            } else {
                locals.remove_stale_muc_actor(occupant);
                tracing::warn!(
                    room = %occupant.room_jid,
                    nick = %occupant.nick,
                    epoch = %occupant.cluster_epoch,
                    "removed local MUC actor that lost its PostgreSQL occupancy authority"
                );
            }
        }
    }
    // Clear lost authority before any Redis network wait can postpone its
    // route fence. Redis remains a disposable projection of renewed actors.
    let soft_state = crate::services::muc::MucSoftStateProjectionService::new(redis);
    let mut muc_soft_state_errors = 0_u64;
    let mut active_muc_rooms = HashSet::new();
    for occupant in renewed_muc {
        let serializable = crate::services::muc::SerializableMucOccupant::from(&occupant);
        let json = serde_json::to_string(&serializable)?;
        if let Err(error) = soft_state
            .refresh(&occupant.room_jid, &occupant.nick, &json)
            .await
        {
            let error = control.record_muc_projection_failure(error);
            muc_soft_state_errors = muc_soft_state_errors.saturating_add(1);
            // scripts/cluster-wsl.py observes this refusal under the cluster target.
            tracing::warn!(target: "rust_xmpp_server::cluster",
                ?error, room=%occupant.room_jid, nick=%occupant.nick,
                "could not refresh disposable Redis MUC soft-state");
        } else {
            active_muc_rooms.insert(occupant.room_jid.clone());
        }
    }
    // Sweep each active room once, irrespective of its occupant count. This
    // removes crashed-node members while another live node keeps renewing the
    // room lease, without imposing O(occupants²) maintenance work.
    for room in active_muc_rooms {
        if let Err(error) = soft_state.reconcile_room(&room).await {
            let error = control.record_muc_projection_failure(error);
            muc_soft_state_errors = muc_soft_state_errors.saturating_add(1);
            tracing::warn!(?error, %room, "could not reconcile Redis MUC room soft-state");
        }
    }
    if let Some(rotation_epoch) = reconciliation_epoch {
        anyhow::ensure!(
            muc_soft_state_errors == 0,
            "Redis MUC soft-state reconciliation failed for {muc_soft_state_errors} authoritative occupancies"
        );
        match control.complete_reconciliation(rotation_epoch)? {
            ReconciliationOutcome::WaitingForInitialListener => {
                // Every database/Redis operation above succeeded. The independent
                // cluster readiness gate stays closed until the first self-loop.
                tracing::debug!(
                    "cluster authority reconciled; awaiting initial listener self-loop"
                );
            }
            ReconciliationOutcome::DeferredForDirectCommits => {
                tracing::debug!("cluster reconciliation deferred until direct commits drain");
            }
            ReconciliationOutcome::Complete => {
                if rotation_epoch != 0 {
                    let mut slot = control
                        .health
                        .recovery_replay_plan
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    if slot
                        .as_ref()
                        .is_none_or(|plan| plan.health_epoch <= rotation_epoch)
                    {
                        let wake_epoch = control
                            .health
                            .recovery_wake_sequence
                            .fetch_add(1, Ordering::AcqRel)
                            .saturating_add(1);
                        *slot = Some(RecoveryReplayPlan::new(rotation_epoch, wake_epoch));
                    }
                }
            }
        }
    }
    drive_recovery_replay_plan(context).await;
    Ok(())
}

/// Listener capabilities are assembled once; the receive loop never retains
/// the application state or a general cluster manager.
pub(super) struct ClusterListenerRuntime {
    pub(super) message_policy:
        Arc<crate::state::cluster_listener_message::ClusterListenerMessagePolicy>,
    pub(super) dispatch: crate::state::cluster_listener_dispatch::ClusterListenerDispatch,
    pub(super) muc_endpoints:
        crate::state::cluster_muc_delivery_endpoints::ClusterMucDeliveryEndpoints,
    pub(super) muc_delivery: crate::state::muc_delivery::MucDeliveryContext,
    pub(super) mix_caps: crate::state::cluster_listener_mix_caps::ClusterListenerMixCaps,
    pub(super) blocking: crate::state::cluster_listener_blocking::ClusterListenerBlocking,
    pub(super) sm_muc_teardown:
        crate::state::cluster_listener_sm_muc_teardown::ClusterListenerSmMucTeardown,
    pub(super) presence_sender: Arc<ClusterNodeDelivery>,
    pub(super) security: Arc<ClusterListenerSecurity>,
}

impl ClusterListenerRuntime {
    pub(super) fn from_state(state: &AppState) -> Self {
        Self {
            message_policy: Arc::new(state.cluster_listener_message_policy()),
            dispatch: state.cluster_listener_dispatch(),
            muc_endpoints: state.cluster_muc_delivery_endpoints(),
            muc_delivery: state.muc_delivery_context(),
            mix_caps: state.cluster_listener_mix_caps(),
            blocking: state.cluster_listener_blocking(),
            sm_muc_teardown: state.cluster_listener_sm_muc_teardown(),
            presence_sender: Arc::new(state.cluster_listener_presence_sender()),
            security: Arc::new(state.cluster_listener_security()),
        }
    }
}

pub(crate) async fn run_pubsub_listener(
    transport: Arc<ClusterPubsubListenerTransport>,
    admission: Arc<ClusterListenerAdmission>,
    state: Arc<AppState>,
    cancel: CancellationToken,
    heartbeat: crate::platform::workers::WorkerHeartbeat,
) -> Result<()> {
    if !transport.is_enabled() {
        return Ok(());
    }
    let runtime = ClusterListenerRuntime::from_state(&state);
    drop(state);
    let result = listen_once(
        Arc::clone(&transport),
        Arc::clone(&admission),
        runtime,
        cancel.clone(),
        heartbeat,
    )
    .await;
    if cancel.is_cancelled() {
        return result;
    }
    let error = match result {
        Ok(()) => anyhow::anyhow!("Redis PubSub stream ended unexpectedly"),
        Err(error) => error,
    };
    if !transport.rotation_already_required() {
        transport.record_listener_failure(&error);
    }
    Err(error)
}

/// Supervise the PostgreSQL half of cluster identity fencing and the bounded
/// degraded-mode shutdown deadline. This worker never makes Redis healthy;
/// only full lease/occupant/listener reconciliation in maintenance can do so.
pub async fn run_failure_supervisor(
    context: Arc<crate::state::cluster_failure_supervisor::ClusterFailureSupervisorContext>,
    cancel: CancellationToken,
    heartbeat: crate::platform::workers::WorkerHeartbeat,
) -> Result<()> {
    let authority = &context.authority;
    if !authority.is_enabled() {
        return Ok(());
    }
    let identity = authority
        .key_identity()
        .context("cluster signing-key authority is missing")?;
    let authority_service = &context.authority_service;
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut heartbeat_tick = 0_u8;
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            _ = interval.tick() => {
                heartbeat_tick = heartbeat_tick.wrapping_add(1);
                let validation = async {
                    authority_service.validate_cluster_key(identity).await?;
                    let instance = authority.readiness_snapshot()
                        .context("cluster signing identity is missing")?;
                    authority_service.validate_local_instance(&instance).await?;
                    if heartbeat_tick % 6 == 1 {
                        let instance = authority.readiness_snapshot()
                            .context("cluster signing identity is missing")?;
                        authority_service.heartbeat_local_instance(
                            &instance,
                            Duration::from_secs(NODE_TTL_SECONDS),
                        ).await?;
                        context.replay_maintenance
                            .cleanup_and_validate(4096)
                            .await?;
                        context.route_maintenance
                            .cleanup_and_validate(4096)
                            .await?;
                    }
                    authority.refresh_peers_with(authority_service).await?;
                    Ok::<_, anyhow::Error>(())
                }.await;
                match validation {
                    Ok(()) => heartbeat.ok(),
                    Err(error) => {
                        heartbeat.error(&error);
                        authority.record_authority_failure(&error);
                        if degraded_shutdown_required(
                            authority.failure_policy(),
                            false,
                            false,
                        ) {
                            authority.require_shutdown();
                            // The critical-worker supervisor owns process-wide
                            // cancellation. Return the authority error first so
                            // it can persist the terminal cause before waking
                            // the main shutdown path; cancelling this shared
                            // token here would make the same exit look like an
                            // operator-requested shutdown.
                            anyhow::bail!(
                                "PostgreSQL cluster key/instance authority was lost; refusing unfenced degraded operation: {error:#}"
                            );
                        }
                    }
                }
                let policy = authority.failure_policy();
                if degraded_shutdown_required(policy, true, authority.safety_lease_expired()) {
                    authority.require_shutdown();
                    tracing::error!(
                        ?policy,
                        "cluster safety lease expired; requesting supervised shutdown"
                    );
                    // As above, the retained critical-worker supervisor must
                    // record this exact terminal cause before it cancels the
                    // service token.
                    anyhow::bail!("cluster safety lease expired before full reconciliation");
                }
            }
        }
    }
}
