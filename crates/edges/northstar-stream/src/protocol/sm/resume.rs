//! Stream resumption, claim ownership, and replay.

use super::sm_resume_token_hash;
use crate::local_routes::muc::RestoredMucOccupancy as _;
use crate::protocol::{Action, ProtocolSession, SessionHost};
use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use northstar_session_application::sm::{
    SmResumeClaimOutcome, SmResumeClaimRequest, SmResumeFinalizationOutcome,
    SmResumeFinalizationRequest, SmSessionSnapshot,
};
use northstar_xep_0198::build_failed_str as sm_failed;
use northstar_xep_0198::{acknowledgement_delta, resumed_offline_replay_eligible};
use northstar_xml_builder::XmlElement;
use roxmltree::Node;
use std::{
    collections::VecDeque,
    sync::{atomic::Ordering, Arc},
};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SmRouteTakeover {
    Acquired,
    Dropping,
    Conflict,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RouteRemovalWait {
    Removed,
    ConnectionCancelled,
    ClaimLeaseExpired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ClaimBoundWaitAbort {
    ConnectionCancelled,
    ClaimLeaseExpired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PendingAuthorityWait {
    AuthorityChanged,
    RouteRemoved,
    ConnectionCancelled,
    RetryBoundary,
}

async fn wait_for_route_removed(mut removed: tokio::sync::watch::Receiver<bool>) {
    while !*removed.borrow() {
        if removed.changed().await.is_err() {
            break;
        }
    }
}

async fn wait_for_pending_authority(
    subscription: &mut northstar_session_application::sm::SmAuthoritySubscription,
    route_removed: Option<tokio::sync::watch::Receiver<bool>>,
    disconnect: &tokio_util::sync::CancellationToken,
    retry_at: tokio::time::Instant,
) -> PendingAuthorityWait {
    let route = async move {
        match route_removed {
            Some(removed) => wait_for_route_removed(removed).await,
            None => std::future::pending::<()>().await,
        }
    };
    tokio::pin!(route);
    tokio::select! {
        biased;
        _ = subscription.changed() => PendingAuthorityWait::AuthorityChanged,
        _ = &mut route => PendingAuthorityWait::RouteRemoved,
        _ = disconnect.cancelled() => PendingAuthorityWait::ConnectionCancelled,
        _ = tokio::time::sleep_until(retry_at) => PendingAuthorityWait::RetryBoundary,
    }
}

pub(super) async fn lock_mix_presence_gate_for_claim(
    gate: Arc<tokio::sync::Mutex<()>>,
    disconnect: &tokio_util::sync::CancellationToken,
    claim_deadline: tokio::time::Instant,
) -> std::result::Result<tokio::sync::OwnedMutexGuard<()>, ClaimBoundWaitAbort> {
    if tokio::time::Instant::now() >= claim_deadline {
        return Err(ClaimBoundWaitAbort::ClaimLeaseExpired);
    }
    let guard = tokio::select! {
        biased;
        _ = disconnect.cancelled() => return Err(ClaimBoundWaitAbort::ConnectionCancelled),
        _ = tokio::time::sleep_until(claim_deadline) => return Err(ClaimBoundWaitAbort::ClaimLeaseExpired),
        guard = gate.lock_owned() => guard,
    };
    if tokio::time::Instant::now() >= claim_deadline {
        drop(guard);
        return Err(ClaimBoundWaitAbort::ClaimLeaseExpired);
    }
    Ok(guard)
}

/// Wait for the terminal notification of one exact route incarnation.
///
/// `watch` retains the terminal value, which closes the subscribe-after-remove
/// lost-wakeup window. Callers must still re-read the route map after
/// `Removed`: another connection may already have installed the same full JID.
pub(super) async fn wait_for_exact_route_removal(
    mut removed: tokio::sync::watch::Receiver<bool>,
    disconnect: &tokio_util::sync::CancellationToken,
    claim_deadline: tokio::time::Instant,
) -> RouteRemovalWait {
    loop {
        if *removed.borrow() {
            return RouteRemovalWait::Removed;
        }
        tokio::select! {
            biased;
            changed = removed.changed() => {
                if changed.is_err() || *removed.borrow() {
                    return RouteRemovalWait::Removed;
                }
            }
            _ = disconnect.cancelled() => {
                // Prefer a concurrently committed removal over abandoning the
                // claim; either result is safe, but this preserves progress.
                return if *removed.borrow() {
                    RouteRemovalWait::Removed
                } else {
                    RouteRemovalWait::ConnectionCancelled
                };
            }
            _ = tokio::time::sleep_until(claim_deadline) => {
                return if *removed.borrow() {
                    RouteRemovalWait::Removed
                } else {
                    RouteRemovalWait::ClaimLeaseExpired
                };
            }
        }
    }
}

pub(super) fn claim_sm_route_lifecycle(lifecycle: &std::sync::atomic::AtomicU8) -> SmRouteTakeover {
    match lifecycle.compare_exchange(0, 2, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => SmRouteTakeover::Acquired,
        Err(1) => SmRouteTakeover::Dropping,
        Err(_) => SmRouteTakeover::Conflict,
    }
}

impl<H: SessionHost> ProtocolSession<H> {
    pub(crate) async fn resume(&mut self, root: Node<'_, '_>) -> Result<Action> {
        let resume = match northstar_xep_0198::parse_resume(root) {
            Ok(resume) => resume,
            Err(_) => {
                return Ok(Action::Send(sm_failed("bad-request")));
            }
        };
        let previd = resume.previd;
        if !URL_SAFE_NO_PAD
            .decode(&previd)
            .is_ok_and(|decoded| decoded.len() == 32)
        {
            return Ok(Action::Send(sm_failed("bad-request")));
        }
        self.resume_values(&previd, resume.h.get()).await
    }

    /// Shared resumption engine for ordinary top-level SM and XEP-0388
    /// inline resumption. Callers decide whether `<resumed/>` is a top-level
    /// control or a child of SASL2 `<success/>`.
    pub(crate) async fn resume_values(&mut self, previd: &str, client_h: u32) -> Result<Action> {
        self.resume_values_with_fast(previd, client_h, None, false)
            .await
            .map(|(action, _)| action)
    }

    pub(crate) async fn resume_values_with_fast(
        &mut self,
        previd: &str,
        client_h: u32,
        fast_plan: Option<&northstar_auth_application::authentication::FastCommitPlan>,
        defer_visibility: bool,
    ) -> Result<(
        Action,
        Option<northstar_auth_application::authentication::IssuedFastToken>,
    )> {
        if self.sm.enabled || self.full_jid.is_some() {
            return Ok((Action::Send(sm_failed("unexpected-request")), None));
        }
        let Some(current_user) = self.authenticated.clone() else {
            return Ok((Action::Send(sm_failed("not-authorized")), None));
        };
        let previd = Zeroizing::new(previd.to_owned());
        let token_hash = sm_resume_token_hash(previd.as_str());
        let mut pending_subscription: Option<(
            uuid::Uuid,
            northstar_session_application::sm::SmAuthoritySubscription,
        )> = None;
        // The first database-owned retry boundary is also this attempt's
        // terminal ownership horizon. A healthy old stream may extend its
        // lease after that point; following every extension would let one
        // resume request wait forever. This is not an application timeout: it
        // is the exact lease/expiry boundary returned under the authority row
        // lock by the first valid Pending decision.
        let mut pending_ownership_horizon: Option<std::time::Instant> = None;
        let (claim, claim_ownership_deadline, claim_capacity) = loop {
            // Only an actual authority probe reserves the maximum possible
            // materialized snapshot. A Pending response drops this RAII lease
            // before waiting, so valid contention cannot pin the process-wide
            // SM memory budget for a live lease's entire duration.
            let claim_capacity = match self.host.sm_memory_governor().try_reserve_claim() {
                Ok(capacity) => capacity,
                Err(_) => {
                    self.host.sm_session_telemetry().capacity_rejected();
                    return Ok((Action::Send(sm_failed("resource-constraint")), None));
                }
            };
            let before_probe = pending_subscription
                .as_ref()
                .map(|(_, subscription)| subscription.probe_stamp());
            match self
                .live_session_ownership
                .attempt(self.host.sm_service().claim_resume(SmResumeClaimRequest {
                    token_hash: &token_hash,
                    user_id: current_user.id,
                    peer_ip: self.peer_ip,
                    user_agent_id: self.user_agent_id,
                    ip_binding: self.sm_runtime_policy.ip_binding.as_str(),
                    require_same_device: self.sm_runtime_policy.session.require_same_device,
                    claim_lease_seconds: self.sm_runtime_policy.session.claim_lease_seconds,
                }))
                .await?
            {
                SmResumeClaimOutcome::Claimed(claim) => {
                    let claim_deadline = tokio::time::Instant::from_std(claim.claim_deadline);
                    break (*claim, claim_deadline, claim_capacity);
                }
                SmResumeClaimOutcome::Rejected => {
                    return Ok((Action::Send(sm_failed("item-not-found")), None));
                }
                SmResumeClaimOutcome::Pending(pending) => {
                    drop(claim_capacity);
                    let ownership_horizon =
                        *pending_ownership_horizon.get_or_insert(pending.retry_at);
                    if std::time::Instant::now() >= ownership_horizon {
                        tracing::debug!(
                            session_id = %pending.session_id,
                            old_connection_id = %pending.old_connection_id,
                            reason = ?pending.reason,
                            "durable SM owner remained authoritative through the initial lease boundary"
                        );
                        return Ok((Action::Send(sm_failed("item-not-found")), None));
                    }
                    let needs_subscription = pending_subscription
                        .as_ref()
                        .is_none_or(|(session_id, _)| *session_id != pending.session_id);
                    if needs_subscription {
                        // Subscribe first and immediately re-probe. A commit
                        // between the first query and LISTEN/watch registration
                        // is therefore observed by the second authoritative
                        // statement instead of becoming a lost wakeup.
                        pending_subscription = Some((
                            pending.session_id,
                            self.host
                                .sm_service()
                                .subscribe_authority(pending.session_id),
                        ));
                        continue;
                    }
                    let (_, subscription) = pending_subscription
                        .as_mut()
                        .expect("pending SM subscription was installed above");
                    if subscription.acknowledge_probe(
                        pending.state_version,
                        before_probe.expect("existing subscription has a pre-probe stamp"),
                    ) {
                        continue;
                    }
                    // A valid resume bearer may supersede only the exact
                    // local incarnation named by PostgreSQL. Cancellation
                    // starts normal cleanup; route removal remains the wake.
                    let route_removed = self.host.sm_pending_route_removal_signal(
                        &pending.full_jid,
                        pending.old_connection_id,
                        current_user.id,
                        pending.session_id,
                        matches!(
                            pending.reason,
                            northstar_session_application::sm::SmPendingReason::Live
                                | northstar_session_application::sm::SmPendingReason::LiveAndClaim
                        ),
                    );
                    let retry_at =
                        tokio::time::Instant::from_std(pending.retry_at.min(ownership_horizon));
                    let wait = wait_for_pending_authority(
                        subscription,
                        route_removed,
                        &self.disconnect,
                        retry_at,
                    )
                    .await;
                    if wait == PendingAuthorityWait::ConnectionCancelled {
                        return Ok((Action::Send(sm_failed("item-not-found")), None));
                    }
                    tracing::trace!(
                        session_id = %pending.session_id,
                        old_connection_id = %pending.old_connection_id,
                        ?wait,
                        reason = ?pending.reason,
                        "rechecking durable SM resume authority after an exact wake boundary"
                    );
                }
            }
        };

        let claimed_bytes = claim.resident_bytes().unwrap_or(usize::MAX);
        if claimed_bytes > self.sm_runtime_policy.buffer.max_snapshot_bytes
            || claim_capacity.shrink_to(claimed_bytes).is_err()
        {
            self.host.sm_session_telemetry().capacity_rejected();
            self.host
                .revoke_sm_session_with_teardown(claim.session_id)
                .await?;
            return Ok((Action::Send(sm_failed("resource-constraint")), None));
        }

        let Some(delta) = acknowledgement_delta(claim.acked_h, client_h, claim.unacked.len())
        else {
            self.host
                .revoke_sm_session_with_teardown(claim.session_id)
                .await?;
            return Ok((Action::Send(sm_failed("undefined-condition")), None));
        };
        let account = format!("{}@{}", current_user.username, self.host.local_domain());
        let key = match validated_sm_session_key(&claim.full_jid, &claim.resource, &account) {
            Some(key) => key,
            _ => {
                self.host
                    .revoke_sm_session_with_teardown(claim.session_id)
                    .await?;
                return Ok((Action::Send(sm_failed("item-not-found")), None));
            }
        };
        // A live exact-route replacement inherits the old resource's MIX
        // presence epoch. A suspended route has already published its durable
        // resume authority while holding that same gate, so a fresh gate is
        // safe once no live entry remains.
        let (
            mut mix_presence_gate,
            mut mix_presence_fallback_suppressed,
            mut caps_observation_generation,
        ) = self
            .host
            .sm_presence_epoch(&key)
            .map(|epoch| (epoch.gate, epoch.fallback_suppressed, epoch.caps_generation))
            .unwrap_or_else(|| {
                // A durable resume restores the last projected presence. Do
                // not let a later caps completion infer a new item until the
                // resumed client sends a new broadcast available. Directed
                // available remains authoritative for its addressed channel,
                // but deliberately does not re-enable fallback elsewhere.
                (
                    Arc::clone(&self.presence.mix_presence_gate),
                    {
                        let suppressed = Arc::new(dashmap::DashSet::new());
                        suppressed.insert("*".to_owned());
                        suppressed
                    },
                    Arc::clone(&self.presence.caps_observation_generation),
                )
            });
        let mut mix_presence_epoch = match lock_mix_presence_gate_for_claim(
            Arc::clone(&mix_presence_gate),
            &self.disconnect,
            claim_ownership_deadline,
        )
        .await
        {
            Ok(guard) => guard,
            Err(reason) => {
                self.host
                    .sm_service()
                    .release_claim(claim.session_id, claim.claim_token)
                    .await?;
                tracing::debug!(
                    ?reason,
                    connection_id = %self.connection_id,
                    sm_session_id = %claim.session_id,
                    "SM resume abandoned while waiting for the resource presence epoch"
                );
                return Ok((Action::Send(sm_failed("item-not-found")), None));
            }
        };
        let available = Arc::new(std::sync::atomic::AtomicBool::new(claim.available));
        let carbons = Arc::new(std::sync::atomic::AtomicBool::new(claim.carbons));
        let priority = Arc::new(std::sync::atomic::AtomicI16::new(claim.priority));
        let show = Arc::new(std::sync::atomic::AtomicU8::new(if claim.available {
            1
        } else {
            0
        }));
        let blocklist = Arc::new(std::sync::atomic::AtomicBool::new(
            claim.blocklist_requested,
        ));
        let roster_requested = Arc::new(std::sync::atomic::AtomicBool::new(claim.roster_requested));
        let roster_sync = Arc::new(northstar_roster_core::RosterSyncGate::default());
        let privacy_active = Arc::new(std::sync::RwLock::new(claim.active_privacy_list.clone()));
        let privacy_requested =
            Arc::new(std::sync::atomic::AtomicBool::new(claim.privacy_requested));
        // MIX roster annotations are negotiated by a roster get on each live
        // resource and are never inherited account-wide. A resumed client can
        // opt in again with its next roster request.
        let mix_roster_annotations = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let directed_presence = Arc::new(dashmap::DashSet::new());
        for jid in &claim.directed_presence {
            directed_presence.insert(jid.clone());
        }
        let last_presence = Arc::new(std::sync::RwLock::new(claim.last_presence.clone()));
        let sm_session_id_shared = Arc::new(std::sync::RwLock::new(Some(claim.session_id)));
        let effective_user_agent = self.user_agent_id.or(claim.user_agent_id);
        loop {
            match self.host.stage_sm_resumed_session(
                key.clone(),
                crate::local_routes::session::OnlineSession {
                    user_id: current_user.id,
                    auth_generation: current_user.auth_generation,
                    route_incarnation: northstar_session_application::RouteIncarnationSignal::new(
                        self.connection_id,
                    ),
                    sender: self.outbound.clone(),
                    available: Arc::clone(&available),
                    availability_generation: Arc::clone(&self.presence.availability_generation),
                    post_actions: self.post_actions.clone(),
                    recovery_replay_inflight_epoch: Arc::new(std::sync::atomic::AtomicU64::new(0)),
                    recovery_replay_completed_epoch: Arc::new(std::sync::atomic::AtomicU64::new(0)),
                    bind2_mam_catchup: false,
                    mix_presence_gate: Arc::clone(&mix_presence_gate),
                    mix_presence_fallback_suppressed: Arc::clone(&mix_presence_fallback_suppressed),
                    caps_observation_generation: Arc::clone(&caps_observation_generation),
                    carbons: Arc::clone(&carbons),
                    priority: Arc::clone(&priority),
                    show: Arc::clone(&show),
                    blocklist_requested: Arc::clone(&blocklist),
                    roster_requested: Arc::clone(&roster_requested),
                    roster_sync: Arc::clone(&roster_sync),
                    mix_roster_annotations: Arc::clone(&mix_roster_annotations),
                    privacy_active: Arc::clone(&privacy_active),
                    privacy_requested: Arc::clone(&privacy_requested),
                    directed_presence: Arc::clone(&directed_presence),
                    last_presence: Arc::clone(&last_presence),
                    user_agent_id: effective_user_agent,
                    user_agent_epoch: None,
                    connection_id: self.connection_id,
                    lifecycle: Arc::clone(&self.route_lifecycle),
                    metrics_counted: Arc::new(std::sync::atomic::AtomicBool::new(true)),
                    routable: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                    sm_session_id: Arc::clone(&sm_session_id_shared),
                    muc_memberships: Arc::clone(&self.joined_rooms),
                    ip: Some(self.peer_ip),
                    resource: claim.resource.clone(),
                    connected_at: std::time::Instant::now(),
                    last_activity: Arc::clone(&self.last_activity),
                    disconnect: self.disconnect.clone(),
                    pending_subscription_delivery: Arc::default(),
                },
                current_user.id,
                claim.session_id,
                &mix_presence_gate,
            ) {
                crate::local_routes::session::SmStagedRouteClaim::Inserted => {
                    self.host.sm_session_telemetry().staged_route_installed();
                    break;
                }
                crate::local_routes::session::SmStagedRouteClaim::Conflict => {
                    self.host
                        .sm_service()
                        .release_claim(claim.session_id, claim.claim_token)
                        .await?;
                    return Ok((Action::Send(sm_failed("conflict")), None));
                }
                crate::local_routes::session::SmStagedRouteClaim::AdoptPresenceEpoch(epoch) => {
                    drop(mix_presence_epoch);
                    mix_presence_gate = epoch.gate;
                    mix_presence_fallback_suppressed = epoch.fallback_suppressed;
                    caps_observation_generation = epoch.caps_generation;
                    mix_presence_epoch = match lock_mix_presence_gate_for_claim(
                        Arc::clone(&mix_presence_gate),
                        &self.disconnect,
                        claim_ownership_deadline,
                    )
                    .await
                    {
                        Ok(guard) => guard,
                        Err(reason) => {
                            self.host
                                .sm_service()
                                .release_claim(claim.session_id, claim.claim_token)
                                .await?;
                            tracing::debug!(
                                ?reason,
                                connection_id = %self.connection_id,
                                sm_session_id = %claim.session_id,
                                "SM route takeover lost its claim while adopting the current presence epoch"
                            );
                            return Ok((Action::Send(sm_failed("item-not-found")), None));
                        }
                    };
                    continue;
                }
                crate::local_routes::session::SmStagedRouteClaim::Replace {
                    connection_id: old_connection_id,
                    lifecycle: old_lifecycle,
                    disconnect: old_disconnect,
                    route_incarnation: old_route_incarnation,
                } => {
                    match claim_sm_route_lifecycle(&old_lifecycle) {
                        SmRouteTakeover::Acquired => {
                            old_disconnect.cancel();
                            self.host
                                .remove_session_if_connection(&key, old_connection_id);
                            if let Err(error) = self
                                .host
                                .release_exact_local_session_route(&key, old_connection_id)
                                .await
                            {
                                let _ = self
                                    .host
                                    .sm_service()
                                    .release_claim(claim.session_id, claim.claim_token)
                                    .await;
                                return Err(error);
                            }
                        }
                        SmRouteTakeover::Dropping => {
                            debug_assert_eq!(
                                old_route_incarnation.connection_id(),
                                old_connection_id
                            );
                            match wait_for_exact_route_removal(
                                old_route_incarnation.subscribe(),
                                &self.disconnect,
                                claim_ownership_deadline,
                            )
                            .await
                            {
                                RouteRemovalWait::Removed => {
                                    // Re-enter the DashMap and validate the
                                    // current incarnation. It may be vacant,
                                    // or an ABA replacement may already own the
                                    // full JID; neither conclusion is inferred
                                    // from the old signal alone.
                                }
                                RouteRemovalWait::ConnectionCancelled => {
                                    self.host
                                        .sm_service()
                                        .release_claim(claim.session_id, claim.claim_token)
                                        .await?;
                                    return Ok((Action::Send(sm_failed("item-not-found")), None));
                                }
                                RouteRemovalWait::ClaimLeaseExpired => {
                                    self.host
                                        .sm_service()
                                        .release_claim(claim.session_id, claim.claim_token)
                                        .await?;
                                    tracing::debug!(
                                        user_id = %current_user.id,
                                        connection_id = %self.connection_id,
                                        sm_session_id = %claim.session_id,
                                        "SM route takeover did not quiesce before its exact claim lease expired"
                                    );
                                    return Ok((Action::Send(sm_failed("item-not-found")), None));
                                }
                            }
                        }
                        SmRouteTakeover::Conflict => {
                            self.host
                                .sm_service()
                                .release_claim(claim.session_id, claim.claim_token)
                                .await?;
                            return Ok((Action::Send(sm_failed("conflict")), None));
                        }
                    }
                }
            }
        }
        // The old route has been replaced atomically by a staged, non-routable
        // route carrying this same gate and suppression state. No MIX effect
        // can now target the old connection, so release before cluster/SM/MUC
        // database work rather than making teardown wait on that work.
        drop(mix_presence_epoch);
        match self
            .host
            .claim_sm_resume_route(
                &key,
                self.connection_id,
                claim.session_id,
                claim.claim_token,
            )
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                self.host
                    .remove_session_if_connection(&key, self.connection_id);
                self.host
                    .sm_service()
                    .release_claim(claim.session_id, claim.claim_token)
                    .await?;
                return Ok((Action::Send(sm_failed("conflict")), None));
            }
            Err(error) => {
                self.host
                    .remove_session_if_connection(&key, self.connection_id);
                let _ = self
                    .host
                    .sm_service()
                    .release_claim(claim.session_id, claim.claim_token)
                    .await;
                return Err(error);
            }
        }

        let paused_muc = self
            .host
            .pause_suspended_muc_delivery(claim.session_id)
            .await;
        let credential_attempt = self.prepare_credential_attempt(
            northstar_auth_application::authentication::publication::CredentialKind::Resume,
        )?;
        let finalized = self
            .host
            .finalize_sm_resume(
                SmResumeFinalizationRequest {
                    session_id: claim.session_id,
                    claim_token: claim.claim_token,
                    connection_id: self.connection_id,
                    user_id: current_user.id,
                    expected_auth_generation: current_user.auth_generation,
                    client_h,
                    acknowledged_count: delta,
                    peer_ip: self.peer_ip,
                    user_agent_id: effective_user_agent,
                    active_privacy_list: claim.active_privacy_list.as_deref(),
                    ttl_seconds: claim.resume_timeout_seconds,
                    live_lease_seconds: self.sm_runtime_policy.session.live_lease_seconds,
                    max_stanzas: self.sm_runtime_policy.buffer.max_unacked_stanzas,
                    max_bytes: self.sm_runtime_policy.buffer.max_unacked_bytes,
                    fast_plan,
                },
                credential_attempt.prepared(),
            )
            .await;
        let (activated, mut receipt) = match finalized {
            Ok(SmResumeFinalizationOutcome::Committed(committed)) => {
                (committed.activated, committed.receipt)
            }
            Ok(
                SmResumeFinalizationOutcome::CredentialsExpired
                | SmResumeFinalizationOutcome::ClaimLost
                | SmResumeFinalizationOutcome::PrivacySelectionMissing,
            ) => {
                self.host
                    .remove_session_if_connection(&key, self.connection_id);
                let _ = self
                    .host
                    .release_exact_local_session_route(&key, self.connection_id)
                    .await;
                if !self
                    .host
                    .mark_suspended_muc_durable(paused_muc.clone())
                    .await
                {
                    let queued = self.host.enqueue_sm_promote_recovery(
                        self.connection_id,
                        claim.session_id,
                        paused_muc,
                        claim_capacity.clone(),
                    );
                    if !queued {
                        self.host.sm_memory_governor().mark_invariant_failure();
                        let _ = self
                            .host
                            .revoke_sm_session_with_teardown(claim.session_id)
                            .await;
                    }
                }
                let _ = self
                    .host
                    .sm_service()
                    .release_claim(claim.session_id, claim.claim_token)
                    .await;
                return Ok((Action::Send(sm_failed("item-not-found")), None));
            }
            Err(error) => {
                self.host
                    .remove_session_if_connection(&key, self.connection_id);
                let _ = self
                    .host
                    .release_exact_local_session_route(&key, self.connection_id)
                    .await;
                if !self
                    .host
                    .mark_suspended_muc_durable(paused_muc.clone())
                    .await
                {
                    let queued = self.host.enqueue_sm_promote_recovery(
                        self.connection_id,
                        claim.session_id,
                        paused_muc,
                        claim_capacity.clone(),
                    );
                    if !queued {
                        self.host.sm_memory_governor().mark_invariant_failure();
                        let _ = self
                            .host
                            .revoke_sm_session_with_teardown(claim.session_id)
                            .await;
                    }
                }
                let _ = self
                    .host
                    .sm_service()
                    .release_claim(claim.session_id, claim.claim_token)
                    .await;
                return Err(error);
            }
        };
        let issued_fast = receipt.take_issued_fast();
        self.retain_credential_commit(receipt, credential_attempt)?;
        let remaining: VecDeque<crate::outbound::SmUnackedStanza> = activated.unacked.into();
        let exact_base_bytes = remaining.iter().map(|entry| entry.stanza.len()).sum();
        let muc_resume_ready = self
            .host
            .begin_suspended_muc_resume(&paused_muc, remaining.len(), exact_base_bytes)
            .await;
        let route_is_current = self.host.staged_session_is_current(
            &key,
            self.connection_id,
            current_user.id,
            current_user.auth_generation,
            &self.route_lifecycle,
        );
        if !route_is_current || !muc_resume_ready {
            tracing::warn!(
                sm_session_id = %claim.session_id,
                connection_id = %self.connection_id,
                route_is_current,
                muc_resume_ready,
                "committed SM resume lost its staged local route before transport publication"
            );
            self.host
                .remove_session_if_connection(&key, self.connection_id);
            let abort_snapshot = SmSessionSnapshot {
                inbound_h: claim.inbound_h,
                outbound_h: activated.outbound_h,
                acked_h: client_h,
                available: claim.available,
                carbons: claim.carbons,
                priority: claim.priority,
                blocklist_requested: claim.blocklist_requested,
                roster_requested: claim.roster_requested,
                active_privacy_list: claim.active_privacy_list.clone(),
                privacy_requested: claim.privacy_requested,
                peer_ip: self.peer_ip,
                user_agent_id: effective_user_agent,
                joined_rooms: claim.joined_rooms.clone(),
                directed_presence: claim.directed_presence.clone(),
                last_presence: claim.last_presence.clone(),
                unacked: remaining.iter().cloned().collect(),
            };
            match self
                .host
                .sm_service()
                .suspend_exact_session(
                    claim.session_id,
                    self.connection_id,
                    current_user.id,
                    current_user.auth_generation,
                    &abort_snapshot,
                    claim.resume_timeout_seconds,
                    self.sm_runtime_policy.buffer.max_unacked_stanzas,
                    self.sm_runtime_policy.buffer.max_unacked_bytes,
                )
                .await
            {
                Ok(true) => {
                    if !self
                        .host
                        .mark_suspended_muc_durable(paused_muc.clone())
                        .await
                    {
                        let queued = self.host.enqueue_sm_promote_recovery(
                            self.connection_id,
                            claim.session_id,
                            paused_muc,
                            claim_capacity.clone(),
                        );
                        if !queued {
                            self.host.sm_memory_governor().mark_invariant_failure();
                            let _ = self
                                .host
                                .revoke_sm_session_with_teardown(claim.session_id)
                                .await;
                        }
                    }
                }
                Ok(false) => {
                    self.host.seal_suspended_muc_endpoints(&paused_muc).await;
                }
                Err(error) => {
                    self.host.seal_suspended_muc_endpoints(&paused_muc).await;
                    let queued = self.host.enqueue_sm_suspension_recovery(
                        northstar_session_application::SessionCleanupAccount {
                            user_id: current_user.id,
                            username: current_user.username.clone(),
                            auth_generation: current_user.auth_generation,
                        },
                        self.connection_id,
                        claim.session_id,
                        abort_snapshot.clone(),
                        claim.resume_timeout_seconds,
                        paused_muc.clone(),
                        claim_capacity.clone(),
                    );
                    if !queued {
                        self.host.sm_memory_governor().mark_invariant_failure();
                        let _ = self
                            .host
                            .revoke_sm_session_with_teardown(claim.session_id)
                            .await;
                    }
                    let _ = self
                        .host
                        .release_exact_local_session_route(&key, self.connection_id)
                        .await;
                    tracing::error!(
                        ?error,
                        sm_session_id = %claim.session_id,
                        connection_id = %self.connection_id,
                        "failed to compensate a committed SM resume whose route was revoked"
                    );
                    return Err(error);
                }
            }
            let _ = self
                .host
                .release_exact_local_session_route(&key, self.connection_id)
                .await;
            // Credential/SM finalization already committed. Never emit a
            // contradictory ordinary resume failure or re-run an unbound FAST
            // commit; close and let the client retry with the still-valid
            // two-slot credential state.
            return Ok((Action::Close, None));
        }

        self.full_jid = Some(key.clone());
        self.registered_key = Some(key.clone());
        self.available = Some(available);
        self.presence.mix_presence_gate = mix_presence_gate;
        self.presence.mix_presence_fallback_suppressed = mix_presence_fallback_suppressed;
        self.presence.caps_observation_generation = caps_observation_generation;
        self.presence.resumed_caps_presence = claim
            .available
            .then(|| claim.last_presence.clone())
            .flatten();
        self.carbons = carbons;
        self.priority = priority;
        self.show = show;
        self.blocklist_requested = blocklist;
        self.roster_requested = roster_requested;
        self.roster_sync = roster_sync;
        self.mix_roster_annotations = mix_roster_annotations;
        self.privacy_active = privacy_active;
        self.privacy_requested = privacy_requested;
        self.directed_presence = directed_presence;
        self.last_presence = last_presence;
        // The staged route owns the same gate as the replaced route. It
        // remains non-routable until the later transport-success publication,
        // so caps effects must recheck and will skip it.
        self.user_agent_id = effective_user_agent;
        self.user_agent_epoch = None;
        self.sm.enabled = true;
        self.sm.db_id = Some(claim.session_id);
        self.sm.session_id_shared = sm_session_id_shared;
        self.sm.resume_allowed = true;
        self.sm.capacity = Some(claim_capacity.clone());
        self.sm.resume_timeout_seconds = claim.resume_timeout_seconds;
        self.sm.inbound_h = claim.inbound_h;
        self.sm.outbound_h = activated.outbound_h;
        self.sm.acked_h = client_h;
        self.sm.unacked = remaining;
        let restored_muc = self
            .host
            .restore_local_muc_occupants(
                crate::local_routes::muc::RestoreLocalMucOccupantsRequest {
                    user: &current_user,
                    full_jid: &key,
                    connection_id: self.connection_id,
                    sm_session_id: claim.session_id,
                    memberships: &claim.joined_rooms,
                    base_stanzas: self.sm.unacked.len(),
                    base_bytes: self.sm.unacked.iter().map(|entry| entry.stanza.len()).sum(),
                },
            )
            .await;
        let planned_muc = restored_muc.planned_memberships();
        let planned_joined_rooms = restored_muc.planned_joined_rooms();
        let announced_failures = restored_muc.failures().to_vec();
        self.joined_rooms.clear();
        for (room_jid, membership) in &planned_joined_rooms {
            self.joined_rooms
                .insert(room_jid.clone(), membership.clone());
        }
        let mut muc_replay_suffix = restored_muc.replay_suffix().to_vec();
        muc_replay_suffix.extend(
            announced_failures
                .iter()
                .map(|membership| muc_resume_failure_stanza(&key, membership)),
        );
        let suffix_growth = muc_replay_suffix.iter().try_fold(0usize, |bytes, stanza| {
            bytes
                .checked_add(std::mem::size_of::<crate::outbound::SmUnackedStanza>())
                .and_then(|bytes| bytes.checked_add(stanza.len()))
        });
        let projected = self
            .sm_resident_bytes()
            .and_then(|bytes| suffix_growth.and_then(|growth| bytes.checked_add(growth)));
        if projected.is_none_or(|bytes| {
            bytes > self.sm_runtime_policy.buffer.max_snapshot_bytes
                || claim_capacity.try_grow_to(bytes).is_err()
        }) {
            self.sm.resume_allowed = false;
            self.host.abort_local_muc_resume(&restored_muc, false).await;
            anyhow::bail!("resumed MUC traffic exceeds process SM memory capacity");
        }
        let Some((staged_unacked, staged_outbound_h)) = stage_muc_replay_suffix(
            &self.sm.unacked,
            self.sm.outbound_h,
            muc_replay_suffix,
            self.sm_runtime_policy.buffer.max_unacked_stanzas,
            self.sm_runtime_policy.buffer.max_unacked_bytes,
        ) else {
            self.host.abort_local_muc_resume(&restored_muc, false).await;
            anyhow::bail!("resumed MUC traffic exceeds the global SM replay budget");
        };
        self.sm.unacked = staged_unacked;
        self.sm.outbound_h = staged_outbound_h;
        // Reserve the process-wide transient budget before cloning the replay
        // FIFO for the transport action. This action can otherwise coexist for
        // every concurrently resuming stream and bypass the live snapshot
        // lease by another full replay copy per connection.
        let resume_control =
            northstar_xep_0198::build_resumed(previd.as_str(), self.sm.inbound_h, None);
        let mut resume_payload = match super::super::ResumePayload::from_sm_unacked(
            self.host.sm_memory_governor(),
            resume_control,
            Vec::new(),
            &self.sm.unacked,
            !defer_visibility,
        ) {
            Ok(payload) => payload,
            Err(error) => {
                self.sm.resume_allowed = false;
                self.host.abort_local_muc_resume(&restored_muc, false).await;
                return Err(error);
            }
        };
        let staged_live_bytes = self
            .sm_resident_bytes()
            .ok_or_else(|| anyhow::anyhow!("resumed SM resident-size overflow"))?;
        let _staged_snapshot_clone_capacity = self
            .host
            .sm_memory_governor()
            .try_reserve_live(staged_live_bytes)
            .context("resumed SM transient snapshot capacity reached")?;
        let staged_snapshot = self.sm_snapshot();
        let staged_bytes = staged_snapshot
            .resident_bytes()
            .ok_or_else(|| anyhow::anyhow!("resumed SM resident-size overflow"))?;
        claim_capacity.shrink_to(staged_bytes)?;
        let checkpointed = self
            .host
            .sm_service()
            .checkpoint_session(
                claim.session_id,
                self.connection_id,
                &staged_snapshot,
                self.sm.resume_timeout_seconds,
                self.sm_runtime_policy.session.live_lease_seconds,
                self.sm_runtime_policy.buffer.max_unacked_stanzas,
                self.sm_runtime_policy.buffer.max_unacked_bytes,
                None,
            )
            .await;
        match checkpointed {
            Ok(outcome) if outcome.updated => {
                self.apply_sm_ownership_resolution(&outcome.ownership);
            }
            Ok(_) => {
                self.host.abort_local_muc_resume(&restored_muc, true).await;
                anyhow::bail!("durable XEP-0198 stream lease was lost before MUC replay");
            }
            Err(error) => {
                self.host.abort_local_muc_resume(&restored_muc, true).await;
                return Err(error);
            }
        }
        if !self.host.checkpoint_local_muc_resume(&restored_muc).await {
            self.host.abort_local_muc_resume(&restored_muc, true).await;
            anyhow::bail!("MUC resume suffix ownership changed during checkpoint");
        }
        // The new live claim lease now owns the exact replay FIFO; release the
        // old suspended endpoint's clone only after the durable checkpoint.
        self.host.clear_suspended_sm_capacity(&paused_muc);

        // Do not expose the MUC endpoints to their new transport until the
        // transport driver has emitted `<resumed/>` and the complete replay.
        // The post-action task performs exact-actor swaps under the shared gate
        // and repairs only memberships which lost an ABA race; its targeted DB
        // update cannot overwrite a concurrent acknowledgement or later join.
        let resume_state = Arc::clone(&self.host);
        let resume_sender = self.outbound.clone();
        let resume_joined_rooms = Arc::clone(&self.joined_rooms);
        let resume_disconnect = self.disconnect.clone();
        let resume_session_id = claim.session_id;
        let resume_connection_id = self.connection_id;
        let resume_full_jid = key.clone();
        let resume_capacity = claim_capacity.clone();
        let restored_muc = Arc::new(std::sync::Mutex::new(Some(restored_muc)));
        let deferred_restored_muc = Arc::clone(&restored_muc);
        let defer_result = self.defer_after_transport("sm-muc-resume-activate", async move {
            let restored_muc = deferred_restored_muc
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take()
                .expect("one post-transport task owns the MUC resume plan");
            let committed = resume_state
                .commit_local_muc_resume(restored_muc, &resume_sender, resume_capacity)
                .await;
            let actual = committed
                .joined_rooms
                .iter()
                .map(
                    |(room_jid, membership)| northstar_session_application::sm::SmMucMembership {
                        room_jid: room_jid.clone(),
                        nick: membership.nick.clone(),
                    },
                )
                .collect::<Vec<_>>();
            let lost = planned_muc
                .iter()
                .filter(|membership| !actual.contains(membership))
                .cloned()
                .collect::<Vec<_>>();
            debug_assert!(lost
                .iter()
                .all(|membership| committed.failures.contains(membership)));
            for membership in &lost {
                if let Some(expected) = planned_joined_rooms
                    .iter()
                    .find(|(room_jid, _)| room_jid == &membership.room_jid)
                    .map(|(_, expected)| expected)
                {
                    resume_joined_rooms
                        .remove_if(&membership.room_jid, |_, current| current == expected);
                }
            }
            if !lost.is_empty() {
                match resume_state
                    .sm_service()
                    .remove_live_muc_memberships(resume_session_id, resume_connection_id, &lost)
                    .await
                {
                    Ok(true) => {}
                    Ok(false) => {
                        resume_disconnect.cancel();
                        return;
                    }
                    Err(error) => {
                        tracing::error!(?error, %resume_session_id,
                            "failed to reconcile SM memberships after an exact MUC resume race");
                        resume_disconnect.cancel();
                        return;
                    }
                }
                for membership in lost {
                    if !announced_failures.contains(&membership) {
                        let _ = resume_sender
                            .send(muc_resume_failure_stanza(&resume_full_jid, &membership))
                            .await;
                    }
                }
            }
        });
        if let Err(error) = defer_result {
            let restored_muc = restored_muc
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take()
                .expect("rejected post-action returns the MUC resume plan");
            self.host.abort_local_muc_resume(&restored_muc, true).await;
            return Err(error);
        }

        // A resumed stream keeps its RFC 6121 availability and priority.
        // XEP-0160 must not drain the account queue into an unavailable or
        // negative-priority resource merely because XEP-0198 resumed it.
        // The ordinary presence transition will start replay later if this
        // resource becomes eligible.
        if resumed_offline_replay_eligible(claim.available, claim.priority) {
            let replay_service = self.host.replay_service().clone();
            let replay_outbound = self.outbound.clone();
            let replay_target = crate::replay::ReplayTarget::for_session(self, &current_user, &key);
            let replay_available = self
                .available
                .as_ref()
                .expect("a resumed bound resource has availability state")
                .clone();
            let replay_availability_generation = self.presence.availability_generation.clone();
            let replay_expected_generation = replay_availability_generation.load(Ordering::Acquire);
            self.defer_after_transport("resumed-offline-replay", async move {
                crate::replay::replay_resumed_offline(
                    replay_service,
                    replay_outbound,
                    replay_target,
                    replay_available,
                    replay_availability_generation,
                    replay_expected_generation,
                )
                .await;
            })?;
        }
        if !defer_visibility {
            self.seal_resume_authentication(&mut resume_payload)?;
        }
        Ok((Action::Resume(resume_payload), issued_fast))
    }
}

/// Stage the complete session FIFO without taking ownership from the suspended
/// endpoint. Capacity and byte accounting include the durable unacked prefix,
/// so one disconnect cannot obtain an independent per-room overflow budget.
pub(super) fn stage_muc_replay_suffix(
    unacked: &VecDeque<crate::outbound::SmUnackedStanza>,
    outbound_h: u32,
    suffix: Vec<String>,
    max_stanzas: usize,
    max_bytes: usize,
) -> Option<(VecDeque<crate::outbound::SmUnackedStanza>, u32)> {
    let total_stanzas = unacked.len().checked_add(suffix.len())?;
    let existing_bytes = unacked
        .iter()
        .try_fold(0usize, |total, entry| total.checked_add(entry.stanza.len()))?;
    let total_bytes = suffix.iter().try_fold(existing_bytes, |total, stanza| {
        total.checked_add(stanza.len())
    })?;
    if total_stanzas > max_stanzas || total_bytes > max_bytes {
        return None;
    }
    let mut staged = unacked.clone();
    let mut staged_h = outbound_h;
    for stanza in suffix {
        staged_h = staged_h.wrapping_add(1);
        staged.push_back(crate::outbound::SmUnackedStanza {
            stanza,
            source: None,
        });
    }
    Some((staged, staged_h))
}

pub(super) fn muc_resume_failure_stanza(
    full_jid: &str,
    membership: &northstar_session_application::sm::SmMucMembership,
) -> String {
    XmlElement::namespaced("presence", "jabber:client")
        .attr(
            "from",
            format!("{}/{}", membership.room_jid, membership.nick),
        )
        .attr("to", full_jid)
        .attr("type", "unavailable")
        .child(
            XmlElement::namespaced("x", "http://jabber.org/protocol/muc#user")
                .child(XmlElement::new("status").attr("code", "332")),
        )
        .finish()
}

pub(super) fn validated_sm_session_key(
    full_jid: &str,
    resource: &str,
    account: &str,
) -> Option<String> {
    let key = northstar_xmpp_types::jid::canonical_session_key(full_jid).ok()?;
    let jid = northstar_xmpp_types::jid::CanonicalJid::parse(&key).ok()?;
    (jid.bare() == northstar_xmpp_types::jid::canonical_bare_key(account).ok()?
        && jid.resourcepart() == Some(resource))
    .then_some(key)
}
