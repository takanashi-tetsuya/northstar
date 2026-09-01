use super::{Action, ProtocolSession};
use crate::services::sm::{
    SmResumeClaimOutcome, SmResumeClaimRequest, SmResumeFinalizationOutcome,
    SmResumeFinalizationRequest, SmSessionCreationOutcome, SmSessionCreationRequest,
    SmSessionSnapshot,
};
use crate::xmpp::sm_counter::acknowledgement_delta;
use crate::xmpp::xml_builder::XmlElement;
use crate::xmpp::xml_util::*;
use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use dashmap::mapref::entry::Entry;
use rand::RngCore;
use roxmltree::Node;
use sha2::{Digest, Sha256};
use std::{
    collections::VecDeque,
    sync::{atomic::Ordering, Arc},
};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SmRouteTakeover {
    Acquired,
    Dropping,
    Conflict,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RouteRemovalWait {
    Removed,
    ConnectionCancelled,
    ClaimLeaseExpired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClaimBoundWaitAbort {
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
    subscription: &mut crate::services::sm::SmAuthoritySubscription,
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

async fn lock_mix_presence_gate_for_claim(
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
async fn wait_for_exact_route_removal(
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

fn matching_sm_route(
    existing_user: uuid::Uuid,
    existing_sm_id: Option<uuid::Uuid>,
    claimant_user: uuid::Uuid,
    claimed_sm_id: uuid::Uuid,
) -> bool {
    existing_user == claimant_user && existing_sm_id == Some(claimed_sm_id)
}

fn claim_sm_route_lifecycle(lifecycle: &std::sync::atomic::AtomicU8) -> SmRouteTakeover {
    match lifecycle.compare_exchange(0, 2, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => SmRouteTakeover::Acquired,
        Err(1) => SmRouteTakeover::Dropping,
        Err(_) => SmRouteTakeover::Conflict,
    }
}

fn sm_resume_token_hash(emitted_bearer: &str) -> [u8; 32] {
    Sha256::digest(emitted_bearer.as_bytes()).into()
}

fn resumability_allowed(
    requested: bool,
    require_same_device: bool,
    user_agent_id: Option<uuid::Uuid>,
) -> bool {
    requested && (!require_same_device || user_agent_id.is_some())
}

impl ProtocolSession {
    /// Enables XEP-0198 as an inline Bind 2 feature and returns the exact XML
    /// that belongs inside `<bound/>`. Resume tokens are 256-bit random
    /// bearers; PostgreSQL receives only SHA-256(token).
    pub(crate) async fn enable_sm_inline(
        &mut self,
        resume: bool,
        requested_max: Option<u64>,
    ) -> std::result::Result<String, &'static str> {
        if self.full_jid.is_none() || self.sm_enabled {
            return Err("unexpected-request");
        }
        // XEP-0388 supplies a stable user-agent UUID, while legacy SASL has no
        // standard way to prove device continuity.  Under the strict policy,
        // negotiate ordinary stream management for an unidentifiable legacy
        // client instead of issuing a bearer that the claim authority must
        // later reject.  Operators can explicitly disable the policy when
        // legacy resumption is an intended compatibility boundary.
        let resume = resumability_allowed(
            resume,
            self.state.config.sm_require_same_device,
            self.user_agent_id,
        );
        self.sm_enabled = true;
        self.sm_resume_allowed = resume;
        self.sm_inbound_h = 0;
        self.sm_outbound_h = 0;
        self.sm_acked_h = 0;
        self.sm_unacked.clear();
        self.sm_db_id = None;

        let Some(user) = self.authenticated.as_ref() else {
            self.reset_sm();
            return Err("not-authorized");
        };
        let full_jid = self.full_jid.clone().expect("checked above");
        let Ok(parsed_full_jid) = crate::jid::CanonicalJid::parse(&full_jid) else {
            self.reset_sm();
            return Err("unexpected-request");
        };
        let Some(resource) = parsed_full_jid.resourcepart() else {
            self.reset_sm();
            return Err("unexpected-request");
        };
        let server_max = self.state.config.sm_resume_timeout_seconds;
        let negotiated_max = if resume {
            requested_max.unwrap_or(server_max).min(server_max).max(1)
        } else {
            // Non-resumable SM still needs a database owner for durable
            // delivery fences until the client advances `h`.  Its random
            // bearer is never emitted, and Drop revokes the row immediately;
            // this TTL is only a crash-recovery ceiling.
            server_max.max(1)
        };
        let mut token = Zeroizing::new([0_u8; 32]);
        rand::thread_rng().fill_bytes(&mut *token);
        let resume_id = Zeroizing::new(URL_SAFE_NO_PAD.encode(token.as_ref()));
        // The client proves the exact base64url text emitted in `id`. Hashing
        // the pre-encoding random bytes would create an unreachable row: no
        // conforming wire client ever sends those raw bytes back.
        let token_hash = sm_resume_token_hash(resume_id.as_str());
        let snapshot = self.sm_snapshot();
        let snapshot_bytes = snapshot.resident_bytes().ok_or("resource-constraint")?;
        if snapshot_bytes > self.state.config.sm_max_snapshot_bytes {
            self.reset_sm();
            return Err("resource-constraint");
        }
        let capacity = match self
            .state
            .sm_memory_governor()
            .try_reserve_live(snapshot_bytes)
        {
            Ok(capacity) => capacity,
            Err(_) => {
                self.state
                    .metrics
                    .capacity_reservations_rejected_total
                    .fetch_add(1, Ordering::Relaxed);
                self.reset_sm();
                return Err("resource-constraint");
            }
        };
        self.sm_capacity = Some(capacity);
        match self
            .state
            .sm_service()
            .create_session(SmSessionCreationRequest {
                token_hash: &token_hash,
                user_id: user.id,
                auth_generation: user.auth_generation,
                full_jid: &full_jid,
                resource,
                server_domain: &self.state.config.domain,
                connection_id: self.connection_id,
                snapshot: &snapshot,
                ttl_seconds: negotiated_max,
                live_lease_seconds: self.state.config.sm_live_lease_seconds,
                max_per_account: self.state.config.max_sessions_per_account,
                max_global: self.state.config.sm_max_resumable_sessions,
            })
            .await
        {
            Ok(SmSessionCreationOutcome::Created(id)) => {
                self.sm_db_id = Some(id);
                *self
                    .sm_session_id_shared
                    .write()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(id);
                self.state
                    .associate_local_muc_sm_session(
                        &full_jid,
                        self.connection_id,
                        id,
                        &self.joined_rooms,
                    )
                    .await;
                self.sm_resume_timeout_seconds = negotiated_max;
                if resume {
                    Ok(XmlElement::namespaced("enabled", "urn:xmpp:sm:3")
                        .attr("id", resume_id.as_str())
                        .attr("resume", "true")
                        .attr("max", negotiated_max)
                        .finish())
                } else {
                    Ok(XmlElement::namespaced("enabled", "urn:xmpp:sm:3")
                        .attr("resume", "false")
                        .finish())
                }
            }
            Ok(SmSessionCreationOutcome::CapacityExhausted) => {
                self.state
                    .metrics
                    .capacity_reservations_rejected_total
                    .fetch_add(1, Ordering::Relaxed);
                self.reset_sm();
                Err("resource-constraint")
            }
            Err(error) => {
                tracing::error!(?error, "could not create durable XEP-0198 resume state");
                self.reset_sm();
                Err("resource-constraint")
            }
        }
    }

    pub(crate) async fn stream_management(&mut self, root: Node<'_, '_>) -> Result<Action> {
        match root.tag_name().name() {
            "enable" => {
                if !valid_sm_control(root, &["resume", "max"]) {
                    return Ok(Action::Send(sm_failed("bad-request")));
                }
                let resume = match root.attribute("resume") {
                    None | Some("false" | "0") => false,
                    Some("true" | "1") => true,
                    Some(_) => return Ok(Action::Send(sm_failed("bad-request"))),
                };
                let max = match root.attribute("max") {
                    None => None,
                    Some(value) => match value.parse::<u64>() {
                        Ok(value) if value > 0 && resume => Some(value),
                        _ => return Ok(Action::Send(sm_failed("bad-request"))),
                    },
                };
                Ok(Action::Send(
                    self.enable_sm_inline(resume, max)
                        .await
                        .unwrap_or_else(sm_failed),
                ))
            }
            "r" if self.sm_enabled => {
                if !valid_sm_control(root, &[]) {
                    return Ok(Action::Send(sm_failed("bad-request")));
                }
                Ok(Action::Send(
                    XmlElement::namespaced("a", "urn:xmpp:sm:3")
                        .attr("h", self.sm_inbound_h)
                        .finish(),
                ))
            }
            "a" if self.sm_enabled => {
                if !valid_sm_control(root, &["h"]) {
                    return Ok(Action::Send(sm_failed("bad-request")));
                }
                let Some(h) = root
                    .attribute("h")
                    .and_then(|value| value.parse::<u32>().ok())
                else {
                    return Ok(Action::Send(sm_failed("bad-request")));
                };
                if !self.acknowledge(h).await? {
                    self.sm_resume_allowed = false;
                    if let Some(id) = self.sm_db_id.take() {
                        // Preserve and durably lease the availability/MUC
                        // snapshot until teardown completes. A direct DELETE
                        // here creates a process-crash window with permanent
                        // ghost presence or occupants.
                        self.state.revoke_sm_session_with_teardown(id).await?;
                        *self
                            .sm_session_id_shared
                            .write()
                            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
                    }
                    return Ok(Action::CloseWith(handled_count_too_high_stream_error(
                        h,
                        self.sm_outbound_h,
                    )));
                }
                Ok(Action::None)
            }
            "resume" => self.resume(root).await,
            _ => Ok(Action::Send(sm_failed("unexpected-request"))),
        }
    }

    pub(crate) async fn resume(&mut self, root: Node<'_, '_>) -> Result<Action> {
        if !valid_sm_control(root, &["previd", "h"]) {
            return Ok(Action::Send(sm_failed("bad-request")));
        }
        let Some(previd) = root.attribute("previd").filter(|value| {
            URL_SAFE_NO_PAD
                .decode(value)
                .is_ok_and(|decoded| decoded.len() == 32)
        }) else {
            return Ok(Action::Send(sm_failed("bad-request")));
        };
        let Some(client_h) = root
            .attribute("h")
            .and_then(|value| value.parse::<u32>().ok())
        else {
            return Ok(Action::Send(sm_failed("bad-request")));
        };
        self.resume_values(previd, client_h).await
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
        fast_plan: Option<&crate::services::authentication::FastCommitPlan>,
        defer_visibility: bool,
    ) -> Result<(
        Action,
        Option<crate::services::authentication::IssuedFastToken>,
    )> {
        if self.sm_enabled || self.full_jid.is_some() {
            return Ok((Action::Send(sm_failed("unexpected-request")), None));
        }
        let Some(current_user) = self.authenticated.clone() else {
            return Ok((Action::Send(sm_failed("not-authorized")), None));
        };
        let previd = Zeroizing::new(previd.to_owned());
        let token_hash = sm_resume_token_hash(previd.as_str());
        let mut pending_subscription: Option<(
            uuid::Uuid,
            crate::services::sm::SmAuthoritySubscription,
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
            let claim_capacity = match self.state.sm_memory_governor().try_reserve_claim() {
                Ok(capacity) => capacity,
                Err(_) => {
                    self.state
                        .metrics
                        .capacity_reservations_rejected_total
                        .fetch_add(1, Ordering::Relaxed);
                    return Ok((Action::Send(sm_failed("resource-constraint")), None));
                }
            };
            let before_probe = pending_subscription
                .as_ref()
                .map(|(_, subscription)| subscription.probe_stamp());
            match self
                .state
                .sm_service()
                .claim_resume(SmResumeClaimRequest {
                    token_hash: &token_hash,
                    user_id: current_user.id,
                    peer_ip: self.peer_ip,
                    user_agent_id: self.user_agent_id,
                    ip_binding: &self.state.config.sm_ip_binding,
                    require_same_device: self.state.config.sm_require_same_device,
                    claim_lease_seconds: self.state.config.sm_claim_lease_seconds,
                })
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
                            self.state
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
                    let route_removed =
                        self.state
                            .sessions
                            .get(&pending.full_jid)
                            .and_then(|session| {
                                let exact_sm = session
                                    .sm_session_id
                                    .read()
                                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                                    .is_some_and(|session_id| session_id == pending.session_id);
                                let exact_route = session.connection_id
                                    == pending.old_connection_id
                                    && session.user_id == current_user.id
                                    && exact_sm;
                                if exact_route
                                    && matches!(
                                        pending.reason,
                                        crate::services::sm::SmPendingReason::Live
                                            | crate::services::sm::SmPendingReason::LiveAndClaim
                                    )
                                {
                                    // A valid resume bearer may supersede only the
                                    // exact local incarnation named by PostgreSQL.
                                    // Cancellation starts normal cleanup/snapshot
                                    // persistence; it never fabricates claim
                                    // completion. Cross-node owners converge only
                                    // through their committed DB transition or the
                                    // authoritative lease boundary.
                                    session.disconnect.cancel();
                                }
                                exact_route.then(|| session.route_incarnation.subscribe())
                            });
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
        if claimed_bytes > self.state.config.sm_max_snapshot_bytes
            || claim_capacity.shrink_to(claimed_bytes).is_err()
        {
            self.state
                .metrics
                .capacity_reservations_rejected_total
                .fetch_add(1, Ordering::Relaxed);
            self.state
                .revoke_sm_session_with_teardown(claim.session_id)
                .await?;
            return Ok((Action::Send(sm_failed("resource-constraint")), None));
        }

        let Some(delta) = acknowledgement_delta(claim.acked_h, client_h, claim.unacked.len())
        else {
            self.state
                .revoke_sm_session_with_teardown(claim.session_id)
                .await?;
            return Ok((Action::Send(sm_failed("undefined-condition")), None));
        };
        let account = format!("{}@{}", current_user.username, self.state.config.domain);
        let key = match validated_sm_session_key(&claim.full_jid, &claim.resource, &account) {
            Some(key) => key,
            _ => {
                self.state
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
            .state
            .sessions
            .get(&key)
            .map(|session| {
                (
                    Arc::clone(&session.mix_presence_gate),
                    Arc::clone(&session.mix_presence_fallback_suppressed),
                    Arc::clone(&session.caps_observation_generation),
                )
            })
            .unwrap_or_else(|| {
                // A durable resume restores the last projected presence. Do
                // not let a later caps completion infer a new item until the
                // resumed client sends a new broadcast available. Directed
                // available remains authoritative for its addressed channel,
                // but deliberately does not re-enable fallback elsewhere.
                (
                    Arc::clone(&self.mix_presence_gate),
                    {
                        let suppressed = Arc::new(dashmap::DashSet::new());
                        suppressed.insert("*".to_owned());
                        suppressed
                    },
                    Arc::clone(&self.caps_observation_generation),
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
                self.state
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
        let roster_sync = Arc::new(crate::services::roster::RosterSyncGate::default());
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
            match self.state.sessions.entry(key.clone()) {
                Entry::Vacant(entry) => {
                    entry.insert(crate::state::OnlineSession {
                        user_id: current_user.id,
                        auth_generation: current_user.auth_generation,
                        route_incarnation: crate::state::RouteIncarnationSignal::new(
                            self.connection_id,
                        ),
                        sender: self.outbound.clone(),
                        available: Arc::clone(&available),
                        mix_presence_gate: Arc::clone(&mix_presence_gate),
                        mix_presence_fallback_suppressed: Arc::clone(
                            &mix_presence_fallback_suppressed,
                        ),
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
                    });
                    self.state
                        .metrics
                        .active_sessions
                        .fetch_add(1, Ordering::Relaxed);
                    break;
                }
                Entry::Occupied(entry) => {
                    let existing = entry.get();
                    let existing_sm_id = *existing
                        .sm_session_id
                        .read()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    if !matching_sm_route(
                        existing.user_id,
                        existing_sm_id,
                        current_user.id,
                        claim.session_id,
                    ) {
                        drop(entry);
                        self.state
                            .sm_service()
                            .release_claim(claim.session_id, claim.claim_token)
                            .await?;
                        return Ok((Action::Send(sm_failed("conflict")), None));
                    }
                    if !Arc::ptr_eq(&mix_presence_gate, &existing.mix_presence_gate) {
                        let replacement_gate = Arc::clone(&existing.mix_presence_gate);
                        let replacement_suppression =
                            Arc::clone(&existing.mix_presence_fallback_suppressed);
                        let replacement_caps_generation =
                            Arc::clone(&existing.caps_observation_generation);
                        drop(entry);
                        drop(mix_presence_epoch);
                        mix_presence_gate = replacement_gate;
                        mix_presence_fallback_suppressed = replacement_suppression;
                        caps_observation_generation = replacement_caps_generation;
                        mix_presence_epoch = match lock_mix_presence_gate_for_claim(
                            Arc::clone(&mix_presence_gate),
                            &self.disconnect,
                            claim_ownership_deadline,
                        )
                        .await
                        {
                            Ok(guard) => guard,
                            Err(reason) => {
                                self.state
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
                    let old_connection_id = existing.connection_id;
                    let old_lifecycle = Arc::clone(&existing.lifecycle);
                    let old_disconnect = existing.disconnect.clone();
                    let old_route_incarnation = Arc::clone(&existing.route_incarnation);
                    drop(entry);
                    match claim_sm_route_lifecycle(&old_lifecycle) {
                        SmRouteTakeover::Acquired => {
                            old_disconnect.cancel();
                            self.state
                                .remove_session_if_connection(&key, old_connection_id);
                            if let Err(error) = self
                                .state
                                .cluster
                                .unregister_session(&key, old_connection_id)
                                .await
                            {
                                let _ = self
                                    .state
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
                                    self.state
                                        .sm_service()
                                        .release_claim(claim.session_id, claim.claim_token)
                                        .await?;
                                    return Ok((Action::Send(sm_failed("item-not-found")), None));
                                }
                                RouteRemovalWait::ClaimLeaseExpired => {
                                    self.state
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
                            self.state
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
            .state
            .cluster
            .try_register_session(
                &key,
                self.connection_id,
                crate::services::sm::SessionRouteClaimProof::SmResume {
                    session_id: claim.session_id,
                    claim_token: claim.claim_token,
                },
            )
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                self.state
                    .remove_session_if_connection(&key, self.connection_id);
                self.state
                    .sm_service()
                    .release_claim(claim.session_id, claim.claim_token)
                    .await?;
                return Ok((Action::Send(sm_failed("conflict")), None));
            }
            Err(error) => {
                self.state
                    .remove_session_if_connection(&key, self.connection_id);
                let _ = self
                    .state
                    .sm_service()
                    .release_claim(claim.session_id, claim.claim_token)
                    .await;
                return Err(error);
            }
        }

        let paused_muc = self
            .state
            .pause_suspended_muc_delivery(claim.session_id)
            .await;
        let finalized = self
            .state
            .finalize_sm_resume(SmResumeFinalizationRequest {
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
                live_lease_seconds: self.state.config.sm_live_lease_seconds,
                max_stanzas: self.state.config.sm_max_unacked_stanzas,
                max_bytes: self.state.config.sm_max_unacked_bytes,
                fast_plan,
            })
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
                self.state
                    .remove_session_if_connection(&key, self.connection_id);
                let _ = self
                    .state
                    .cluster
                    .unregister_session(&key, self.connection_id)
                    .await;
                if !self
                    .state
                    .mark_suspended_muc_durable(paused_muc.clone())
                    .await
                {
                    let queued = self.state.sm_suspension_recovery_queue().enqueue_promote(
                        self.connection_id,
                        claim.session_id,
                        paused_muc,
                        claim_capacity.clone(),
                    );
                    if !queued {
                        self.state.sm_memory_governor().mark_invariant_failure();
                        let _ = self
                            .state
                            .revoke_sm_session_with_teardown(claim.session_id)
                            .await;
                    }
                }
                let _ = self
                    .state
                    .sm_service()
                    .release_claim(claim.session_id, claim.claim_token)
                    .await;
                return Ok((Action::Send(sm_failed("item-not-found")), None));
            }
            Err(error) => {
                self.state
                    .remove_session_if_connection(&key, self.connection_id);
                let _ = self
                    .state
                    .cluster
                    .unregister_session(&key, self.connection_id)
                    .await;
                if !self
                    .state
                    .mark_suspended_muc_durable(paused_muc.clone())
                    .await
                {
                    let queued = self.state.sm_suspension_recovery_queue().enqueue_promote(
                        self.connection_id,
                        claim.session_id,
                        paused_muc,
                        claim_capacity.clone(),
                    );
                    if !queued {
                        self.state.sm_memory_governor().mark_invariant_failure();
                        let _ = self
                            .state
                            .revoke_sm_session_with_teardown(claim.session_id)
                            .await;
                    }
                }
                let _ = self
                    .state
                    .sm_service()
                    .release_claim(claim.session_id, claim.claim_token)
                    .await;
                return Err(error);
            }
        };
        let issued_fast = receipt.take_issued_fast();
        self.pending_credential_commit = Some(receipt);
        let remaining: VecDeque<crate::outbound::SmUnackedStanza> = activated.unacked.into();
        let exact_base_bytes = remaining.iter().map(|entry| entry.stanza.len()).sum();
        let muc_resume_ready = self
            .state
            .begin_suspended_muc_resume(&paused_muc, remaining.len(), exact_base_bytes)
            .await;
        let route_state = self.state.sessions.get_mut(&key).map(|session| {
            (
                session.connection_id == self.connection_id,
                session.user_id == current_user.id,
                session.auth_generation == current_user.auth_generation,
                Arc::ptr_eq(&session.lifecycle, &self.route_lifecycle),
                session.disconnect.is_cancelled(),
                session.lifecycle.load(Ordering::Acquire),
            )
        });
        let route_is_current = route_state.is_some_and(
            |(
                same_connection,
                same_user,
                same_auth_generation,
                same_lifecycle,
                cancelled,
                state,
            )| {
                same_connection
                    && same_user
                    && same_auth_generation
                    && same_lifecycle
                    && !cancelled
                    && state == 0
            },
        );
        if !route_is_current || !muc_resume_ready {
            tracing::warn!(
                sm_session_id = %claim.session_id,
                connection_id = %self.connection_id,
                ?route_state,
                muc_resume_ready,
                "committed SM resume lost its staged local route before transport publication"
            );
            self.state
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
                .state
                .sm_service()
                .suspend_exact_session(
                    claim.session_id,
                    self.connection_id,
                    current_user.id,
                    current_user.auth_generation,
                    &abort_snapshot,
                    claim.resume_timeout_seconds,
                    self.state.config.sm_max_unacked_stanzas,
                    self.state.config.sm_max_unacked_bytes,
                )
                .await
            {
                Ok(true) => {
                    if !self
                        .state
                        .mark_suspended_muc_durable(paused_muc.clone())
                        .await
                    {
                        let queued = self.state.sm_suspension_recovery_queue().enqueue_promote(
                            self.connection_id,
                            claim.session_id,
                            paused_muc,
                            claim_capacity.clone(),
                        );
                        if !queued {
                            self.state.sm_memory_governor().mark_invariant_failure();
                            let _ = self
                                .state
                                .revoke_sm_session_with_teardown(claim.session_id)
                                .await;
                        }
                    }
                }
                Ok(false) => {
                    self.state.seal_suspended_muc_endpoints(&paused_muc).await;
                }
                Err(error) => {
                    self.state.seal_suspended_muc_endpoints(&paused_muc).await;
                    let queued = self.state.sm_suspension_recovery_queue().enqueue(
                        crate::services::session_cleanup::SessionCleanupAccount {
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
                        self.state.sm_memory_governor().mark_invariant_failure();
                        let _ = self
                            .state
                            .revoke_sm_session_with_teardown(claim.session_id)
                            .await;
                    }
                    let _ = self
                        .state
                        .cluster
                        .unregister_session(&key, self.connection_id)
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
                .state
                .cluster
                .unregister_session(&key, self.connection_id)
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
        self.mix_presence_gate = mix_presence_gate;
        self.mix_presence_fallback_suppressed = mix_presence_fallback_suppressed;
        self.caps_observation_generation = caps_observation_generation;
        self.resumed_caps_presence = claim
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
        self.sm_enabled = true;
        self.sm_db_id = Some(claim.session_id);
        self.sm_session_id_shared = sm_session_id_shared;
        self.sm_resume_allowed = true;
        self.sm_capacity = Some(claim_capacity.clone());
        self.sm_resume_timeout_seconds = claim.resume_timeout_seconds;
        self.sm_inbound_h = claim.inbound_h;
        self.sm_outbound_h = activated.outbound_h;
        self.sm_acked_h = client_h;
        self.sm_unacked = remaining;
        let restored_muc = self
            .state
            .restore_local_muc_occupants(crate::state::RestoreLocalMucOccupantsRequest {
                user: &current_user,
                full_jid: &key,
                connection_id: self.connection_id,
                sm_session_id: claim.session_id,
                memberships: &claim.joined_rooms,
                base_stanzas: self.sm_unacked.len(),
                base_bytes: self.sm_unacked.iter().map(|entry| entry.stanza.len()).sum(),
            })
            .await;
        let planned_muc = restored_muc.planned_memberships();
        let planned_joined_rooms = restored_muc.planned_joined_rooms();
        let announced_failures = restored_muc.failures.clone();
        self.joined_rooms.clear();
        for (room_jid, membership) in &planned_joined_rooms {
            self.joined_rooms
                .insert(room_jid.clone(), membership.clone());
        }
        let mut muc_replay_suffix = restored_muc.replay_suffix.clone();
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
            bytes > self.state.config.sm_max_snapshot_bytes
                || claim_capacity.try_grow_to(bytes).is_err()
        }) {
            self.sm_resume_allowed = false;
            self.state
                .abort_local_muc_resume(&restored_muc, false)
                .await;
            anyhow::bail!("resumed MUC traffic exceeds process SM memory capacity");
        }
        let Some((staged_unacked, staged_outbound_h)) = stage_muc_replay_suffix(
            &self.sm_unacked,
            self.sm_outbound_h,
            muc_replay_suffix,
            self.state.config.sm_max_unacked_stanzas,
            self.state.config.sm_max_unacked_bytes,
        ) else {
            self.state
                .abort_local_muc_resume(&restored_muc, false)
                .await;
            anyhow::bail!("resumed MUC traffic exceeds the global SM replay budget");
        };
        self.sm_unacked = staged_unacked;
        self.sm_outbound_h = staged_outbound_h;
        // Reserve the process-wide transient budget before cloning the replay
        // FIFO for the transport action. This action can otherwise coexist for
        // every concurrently resuming stream and bypass the live snapshot
        // lease by another full replay copy per connection.
        let resume_control = XmlElement::namespaced("resumed", "urn:xmpp:sm:3")
            .attr("h", self.sm_inbound_h)
            .attr("previd", previd.as_str())
            .finish();
        let resume_payload = match super::ResumePayload::from_sm_unacked(
            self.state.sm_memory_governor(),
            resume_control,
            Vec::new(),
            &self.sm_unacked,
            !defer_visibility,
        ) {
            Ok(payload) => payload,
            Err(error) => {
                self.sm_resume_allowed = false;
                self.state
                    .abort_local_muc_resume(&restored_muc, false)
                    .await;
                return Err(error);
            }
        };
        let staged_live_bytes = self
            .sm_resident_bytes()
            .ok_or_else(|| anyhow::anyhow!("resumed SM resident-size overflow"))?;
        let _staged_snapshot_clone_capacity = self
            .state
            .sm_memory_governor()
            .try_reserve_live(staged_live_bytes)
            .context("resumed SM transient snapshot capacity reached")?;
        let staged_snapshot = self.sm_snapshot();
        let staged_bytes = staged_snapshot
            .resident_bytes()
            .ok_or_else(|| anyhow::anyhow!("resumed SM resident-size overflow"))?;
        claim_capacity.shrink_to(staged_bytes)?;
        let checkpointed = self
            .state
            .sm_service()
            .checkpoint_session(
                claim.session_id,
                self.connection_id,
                &staged_snapshot,
                self.sm_resume_timeout_seconds,
                self.state.config.sm_live_lease_seconds,
                self.state.config.sm_max_unacked_stanzas,
                self.state.config.sm_max_unacked_bytes,
            )
            .await;
        match checkpointed {
            Ok(true) => {}
            Ok(false) => {
                self.state.abort_local_muc_resume(&restored_muc, true).await;
                anyhow::bail!("durable XEP-0198 stream lease was lost before MUC replay");
            }
            Err(error) => {
                self.state.abort_local_muc_resume(&restored_muc, true).await;
                return Err(error);
            }
        }
        if !self.state.checkpoint_local_muc_resume(&restored_muc).await {
            self.state.abort_local_muc_resume(&restored_muc, true).await;
            anyhow::bail!("MUC resume suffix ownership changed during checkpoint");
        }
        // The new live claim lease now owns the exact replay FIFO; release the
        // old suspended endpoint's clone only after the durable checkpoint.
        self.state.clear_suspended_sm_capacity(&paused_muc);

        // Do not expose the MUC endpoints to their new transport until the
        // transport driver has emitted `<resumed/>` and the complete replay.
        // The post-action task performs exact-actor swaps under the shared gate
        // and repairs only memberships which lost an ABA race; its targeted DB
        // update cannot overwrite a concurrent acknowledgement or later join.
        let resume_state = Arc::clone(&self.state);
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
                    |(room_jid, membership)| crate::services::sm::SmMucMembership {
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
            self.state.abort_local_muc_resume(&restored_muc, true).await;
            return Err(error);
        }

        // A resumed stream keeps its RFC 6121 availability and priority.
        // XEP-0160 must not drain the account queue into an unavailable or
        // negative-priority resource merely because XEP-0198 resumed it.
        // The ordinary presence transition will start replay later if this
        // resource becomes eligible.
        if resumed_offline_replay_eligible(claim.available, claim.priority) {
            let active_privacy = self
                .privacy_active
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone();
            let replay_state = self.state.clone();
            let replay_outbound = self.outbound.clone();
            let replay_user_id = current_user.id;
            let replay_full_jid = key.clone();
            let replay_available = self
                .available
                .as_ref()
                .expect("a resumed bound resource has availability state")
                .clone();
            let replay_availability_generation = self.availability_generation.clone();
            let replay_expected_generation = replay_availability_generation.load(Ordering::Acquire);
            self.defer_after_transport("resumed-offline-replay", async move {
                super::replay::replay_resumed_offline(
                    replay_state,
                    replay_outbound,
                    replay_user_id,
                    replay_full_jid,
                    active_privacy,
                    replay_available,
                    replay_availability_generation,
                    replay_expected_generation,
                )
                .await;
            })?;
        }
        Ok((Action::Resume(resume_payload), issued_fast))
    }

    pub(crate) async fn acknowledge(&mut self, h: u32) -> Result<bool> {
        let Some(delta) = acknowledgement_delta(self.sm_acked_h, h, self.sm_unacked.len()) else {
            return Ok(false);
        };
        let acknowledged = self
            .sm_unacked
            .iter()
            .take(delta)
            .cloned()
            .collect::<Vec<_>>();
        let remaining = self
            .sm_unacked
            .iter()
            .skip(delta)
            .cloned()
            .collect::<VecDeque<_>>();
        if let Some(id) = self.sm_db_id {
            let clone_bytes = self
                .sm_resident_bytes()
                .ok_or_else(|| anyhow::anyhow!("XEP-0198 live resident-size overflow"))?;
            let _snapshot_clone_capacity = self
                .state
                .sm_memory_governor()
                .try_reserve_live(clone_bytes)?;
            let mut snapshot = self.sm_snapshot();
            snapshot.acked_h = h;
            snapshot.unacked = remaining.iter().cloned().collect();
            let updated = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                self.state.sm_service().checkpoint_and_acknowledge(
                    id,
                    self.connection_id,
                    &snapshot,
                    &acknowledged,
                    self.sm_resume_timeout_seconds,
                    self.state.config.sm_live_lease_seconds,
                    self.state.config.sm_max_unacked_stanzas,
                    self.state.config.sm_max_unacked_bytes,
                ),
            )
            .await
            .map_err(|_| {
                anyhow::anyhow!("XEP-0198 acknowledgement database operation timed out")
            })??;
            anyhow::ensure!(updated, "durable XEP-0198 stream lease was lost");
        } else {
            let deliveries = acknowledged
                .iter()
                .filter_map(|entry| entry.durable_delivery)
                .collect::<Vec<_>>();
            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                self.state
                    .sm_service()
                    .acknowledge_delivery_batch(&deliveries),
            )
            .await
            .map_err(|_| {
                anyhow::anyhow!("delivery acknowledgement database operation timed out")
            })??;
        }
        self.sm_unacked = remaining;
        self.sm_acked_h = h;
        let live_bytes = self
            .sm_resident_bytes()
            .ok_or_else(|| anyhow::anyhow!("XEP-0198 live resident-size overflow"))?;
        if let Some(capacity) = &self.sm_capacity {
            capacity.shrink_to(live_bytes)?;
        }
        Ok(true)
    }

    pub(crate) fn reset_sm(&mut self) {
        self.sm_enabled = false;
        self.resumed_caps_presence = None;
        self.sm_db_id = None;
        *self
            .sm_session_id_shared
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
        self.sm_resume_allowed = false;
        self.sm_resume_timeout_seconds = 0;
        self.sm_inbound_h = 0;
        self.sm_outbound_h = 0;
        self.sm_acked_h = 0;
        self.sm_unacked.clear();
        self.sm_capacity = None;
    }
}

fn valid_sm_control(root: Node<'_, '_>, allowed_attributes: &[&str]) -> bool {
    root.attributes().all(|attribute| {
        attribute.namespace().is_none() && allowed_attributes.contains(&attribute.name())
    }) && !root
        .children()
        .any(|child| child.is_element() || child.text().is_some_and(|text| !text.trim().is_empty()))
}

fn resumed_offline_replay_eligible(available: bool, priority: i16) -> bool {
    available && priority >= 0
}

/// Stage the complete session FIFO without taking ownership from the suspended
/// endpoint. Capacity and byte accounting include the durable unacked prefix,
/// so one disconnect cannot obtain an independent per-room overflow budget.
fn stage_muc_replay_suffix(
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
            durable_delivery: None,
        });
    }
    Some((staged, staged_h))
}

fn muc_resume_failure_stanza(
    full_jid: &str,
    membership: &crate::services::sm::SmMucMembership,
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

fn handled_count_too_high_stream_error(received: u32, sent: u32) -> String {
    XmlElement::new("stream:error")
        .attr("xmlns:stream", "http://etherx.jabber.org/streams")
        .child(XmlElement::namespaced(
            "undefined-condition",
            "urn:ietf:params:xml:ns:xmpp-streams",
        ))
        .child(
            XmlElement::namespaced("handled-count-too-high", "urn:xmpp:sm:3")
                .attr("h", received)
                .attr("send-count", sent),
        )
        .finish()
}

fn validated_sm_session_key(full_jid: &str, resource: &str, account: &str) -> Option<String> {
    let key = crate::jid::canonical_session_key(full_jid).ok()?;
    let jid = crate::jid::CanonicalJid::parse(&key).ok()?;
    (jid.bare() == crate::jid::canonical_bare_key(account).ok()?
        && jid.resourcepart() == Some(resource))
    .then_some(key)
}

#[cfg(test)]
mod tests {
    use super::{
        acknowledgement_delta, claim_sm_route_lifecycle, handled_count_too_high_stream_error,
        lock_mix_presence_gate_for_claim, matching_sm_route, muc_resume_failure_stanza,
        resumability_allowed, resumed_offline_replay_eligible, sm_resume_token_hash,
        stage_muc_replay_suffix, valid_sm_control, validated_sm_session_key,
        wait_for_exact_route_removal, ClaimBoundWaitAbort, RouteRemovalWait, SmRouteTakeover,
    };
    use roxmltree::Document;

    #[tokio::test]
    async fn ready_mix_gate_cannot_outlive_the_database_claim() {
        let gate = std::sync::Arc::new(tokio::sync::Mutex::new(()));
        let disconnect = tokio_util::sync::CancellationToken::new();
        let expired = tokio::time::Instant::now()
            .checked_sub(std::time::Duration::from_millis(1))
            .expect("a one millisecond earlier instant is representable");

        assert!(
            matches!(
                lock_mix_presence_gate_for_claim(gate, &disconnect, expired).await,
                Err(ClaimBoundWaitAbort::ClaimLeaseExpired)
            ),
            "an immediately ready mutex must not outrank an already-expired database lease"
        );
    }

    #[tokio::test]
    async fn route_removal_wait_rechecks_the_map_and_cannot_miss_an_aba_replacement() {
        let key = "alice@example.test/Phone".to_owned();
        let old_connection = uuid::Uuid::new_v4();
        let replacement_connection = uuid::Uuid::new_v4();
        let routes = std::sync::Arc::new(dashmap::DashMap::new());
        routes.insert(key.clone(), old_connection);
        let (removed, receiver) = tokio::sync::watch::channel(false);
        let disconnect = tokio_util::sync::CancellationToken::new();

        let writer_routes = std::sync::Arc::clone(&routes);
        let writer_key = key.clone();
        let writer = tokio::spawn(async move {
            tokio::task::yield_now().await;
            assert!(writer_routes
                .remove_if(&writer_key, |_, connection| *connection == old_connection)
                .is_some());
            // Deliberately install the ABA replacement before publishing the
            // old incarnation's terminal event.
            writer_routes.insert(writer_key, replacement_connection);
            removed.send_replace(true);
        });

        assert_eq!(
            wait_for_exact_route_removal(
                receiver,
                &disconnect,
                tokio::time::Instant::now() + std::time::Duration::from_secs(1),
            )
            .await,
            RouteRemovalWait::Removed
        );
        writer.await.expect("writer completes");
        assert_eq!(
            routes.get(&key).map(|route| *route),
            Some(replacement_connection),
            "the old event is only permission to re-read; it is not proof of vacancy"
        );
    }

    #[tokio::test]
    async fn route_removal_wait_observes_a_notification_published_before_subscribe() {
        let (removed, receiver) = tokio::sync::watch::channel(false);
        removed.send_replace(true);
        let disconnect = tokio_util::sync::CancellationToken::new();
        assert_eq!(
            wait_for_exact_route_removal(
                receiver,
                &disconnect,
                tokio::time::Instant::now() + std::time::Duration::from_secs(1),
            )
            .await,
            RouteRemovalWait::Removed
        );
    }

    #[tokio::test]
    async fn route_removal_wait_is_bounded_only_by_cancellation_or_the_claim_lease() {
        let (_removed, receiver) = tokio::sync::watch::channel(false);
        let disconnect = tokio_util::sync::CancellationToken::new();
        disconnect.cancel();
        assert_eq!(
            wait_for_exact_route_removal(
                receiver,
                &disconnect,
                tokio::time::Instant::now() + std::time::Duration::from_secs(1),
            )
            .await,
            RouteRemovalWait::ConnectionCancelled
        );

        let (_removed, receiver) = tokio::sync::watch::channel(false);
        let disconnect = tokio_util::sync::CancellationToken::new();
        assert_eq!(
            wait_for_exact_route_removal(receiver, &disconnect, tokio::time::Instant::now()).await,
            RouteRemovalWait::ClaimLeaseExpired
        );
    }

    #[test]
    fn resumed_muc_replay_suffix_is_tracked_after_the_unacked_prefix() {
        let unacked = std::collections::VecDeque::from([
            crate::outbound::SmUnackedStanza::plain("<queued-1/>".to_owned()),
            crate::outbound::SmUnackedStanza::plain("<queued-2/>".to_owned()),
        ]);
        let (unacked, outbound_h) = stage_muc_replay_suffix(
            &unacked,
            9_u32,
            vec!["<muc-newer/>".to_owned(), "<muc-newest/>".to_owned()],
            8,
            4_096,
        )
        .expect("the combined FIFO fits");
        let replay: Vec<&str> = unacked.iter().map(|entry| entry.stanza.as_str()).collect();
        assert_eq!(
            replay,
            [
                "<queued-1/>",
                "<queued-2/>",
                "<muc-newer/>",
                "<muc-newest/>"
            ]
        );
        assert_eq!(outbound_h, 11);
        assert!(
            unacked.iter().all(|entry| entry.durable_delivery.is_none()),
            "volatile MUC traffic carries no durable delivery fence"
        );
    }

    #[test]
    fn resumed_muc_suffix_cannot_open_a_second_sm_budget() {
        let unacked = std::collections::VecDeque::from([
            crate::outbound::SmUnackedStanza::plain("1234".to_owned()),
            crate::outbound::SmUnackedStanza::plain("5678".to_owned()),
        ]);
        assert!(stage_muc_replay_suffix(&unacked, 2, vec!["x".to_owned()], 2, 9,).is_none());
        assert!(stage_muc_replay_suffix(&unacked, 2, vec!["xx".to_owned()], 3, 9,).is_none());
    }

    #[test]
    fn resume_failure_presence_332_consumes_the_same_global_budget() {
        let membership = crate::services::sm::SmMucMembership {
            room_jid: "room@conference.example.test".to_owned(),
            nick: "alice".to_owned(),
        };
        let failure = muc_resume_failure_stanza("alice@example.test/Phone", &membership);
        let document = Document::parse(&failure).expect("failure presence is valid XML");
        assert!(document.root_element().descendants().any(|node| {
            node.is_element()
                && node.tag_name().name() == "status"
                && node.attribute("code") == Some("332")
        }));
        let unacked = std::collections::VecDeque::from([crate::outbound::SmUnackedStanza::plain(
            "old".to_owned(),
        )]);
        let exact_bytes = "old".len() + failure.len();
        let (staged, _) =
            stage_muc_replay_suffix(&unacked, 1, vec![failure.clone()], 2, exact_bytes)
                .expect("the final allowed 332 presence fits the shared budget");
        assert_eq!(staged.len(), 2);
        assert!(
            stage_muc_replay_suffix(&unacked, 1, vec![failure.clone()], 1, exact_bytes).is_none()
        );
        assert!(stage_muc_replay_suffix(&unacked, 1, vec![failure], 2, exact_bytes - 1).is_none());
    }

    #[test]
    fn acknowledgements_handle_wrap_and_reject_ahead_or_stale_values() {
        assert_eq!(acknowledgement_delta(u32::MAX - 1, 1, 3), Some(3));
        assert_eq!(acknowledgement_delta(10, 12, 2), Some(2));
        assert_eq!(acknowledgement_delta(10, 13, 2), None);
        assert_eq!(acknowledgement_delta(10, 9, 512), None);
    }

    #[test]
    fn duplicate_ack_is_idempotent() {
        assert_eq!(acknowledgement_delta(42, 42, 0), Some(0));
        assert_eq!(acknowledgement_delta(42, 42, 8), Some(0));
    }

    #[test]
    fn sm_resume_only_replays_offline_to_an_eligible_resource() {
        assert!(resumed_offline_replay_eligible(true, 0));
        assert!(resumed_offline_replay_eligible(true, i16::MAX));
        assert!(!resumed_offline_replay_eligible(false, 0));
        assert!(!resumed_offline_replay_eligible(true, -1));
    }

    #[test]
    fn strict_same_device_policy_does_not_issue_unclaimable_legacy_bearers() {
        let device = uuid::Uuid::new_v4();
        assert!(resumability_allowed(true, true, Some(device)));
        assert!(resumability_allowed(true, false, None));
        assert!(!resumability_allowed(true, true, None));
        assert!(!resumability_allowed(false, false, Some(device)));
    }

    #[test]
    fn impossible_ack_uses_the_required_terminal_stream_error() {
        let xml = handled_count_too_high_stream_error(10, 8);
        let document = Document::parse(&xml).unwrap();
        let root = document.root_element();
        assert_eq!(
            root.tag_name().namespace(),
            Some("http://etherx.jabber.org/streams")
        );
        let detail = root
            .children()
            .find(|child| {
                child.is_element()
                    && child.tag_name().namespace() == Some("urn:xmpp:sm:3")
                    && child.tag_name().name() == "handled-count-too-high"
            })
            .unwrap();
        assert_eq!(detail.attribute("h"), Some("10"));
        assert_eq!(detail.attribute("send-count"), Some("8"));
    }

    #[test]
    fn resume_identity_canonicalizes_account_but_matches_resource_exactly() {
        assert_eq!(
            validated_sm_session_key("ALICE@Example.test/Phone", "Phone", "alice@example.test"),
            Some("alice@example.test/Phone".to_owned())
        );
        assert_eq!(
            validated_sm_session_key("alice@example.test/Phone", "phone", "alice@example.test"),
            None
        );
        assert_eq!(
            validated_sm_session_key("mallory@example.test/Phone", "Phone", "alice@example.test"),
            None
        );
    }

    #[test]
    fn stream_management_controls_are_structurally_strict() {
        for (xml, allowed) in [
            (
                "<enable xmlns='urn:xmpp:sm:3' resume='true' max='60'/>",
                &["resume", "max"][..],
            ),
            ("<r xmlns='urn:xmpp:sm:3'/>", &[][..]),
            ("<a xmlns='urn:xmpp:sm:3' h='1'/>", &["h"][..]),
            (
                "<resume xmlns='urn:xmpp:sm:3' previd='token' h='1'/>",
                &["previd", "h"][..],
            ),
        ] {
            let document = Document::parse(xml).unwrap();
            assert!(valid_sm_control(document.root_element(), allowed));
        }
        for (xml, allowed) in [
            ("<r xmlns='urn:xmpp:sm:3' h='1'/>", &[][..]),
            ("<a xmlns='urn:xmpp:sm:3' h='1'><x/></a>", &["h"][..]),
            (
                "<resume xmlns='urn:xmpp:sm:3' previd='x' h='1'>junk</resume>",
                &["previd", "h"][..],
            ),
        ] {
            let document = Document::parse(xml).unwrap();
            assert!(!valid_sm_control(document.root_element(), allowed));
        }
    }

    #[test]
    fn immediate_takeover_is_exact_and_old_drop_cannot_win_afterward() {
        let user = uuid::Uuid::new_v4();
        let other = uuid::Uuid::new_v4();
        let stream = uuid::Uuid::new_v4();
        assert!(matching_sm_route(user, Some(stream), user, stream));
        assert!(!matching_sm_route(other, Some(stream), user, stream));
        assert!(!matching_sm_route(
            user,
            Some(uuid::Uuid::new_v4()),
            user,
            stream
        ));

        let lifecycle = std::sync::atomic::AtomicU8::new(0);
        assert_eq!(
            claim_sm_route_lifecycle(&lifecycle),
            SmRouteTakeover::Acquired
        );
        assert_eq!(lifecycle.load(std::sync::atomic::Ordering::Acquire), 2);
        assert!(lifecycle
            .compare_exchange(
                0,
                1,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire
            )
            .is_err());

        let dropping = std::sync::atomic::AtomicU8::new(1);
        assert_eq!(
            claim_sm_route_lifecycle(&dropping),
            SmRouteTakeover::Dropping
        );
    }

    #[test]
    fn emitted_resume_bearer_is_the_exact_persisted_and_claimed_hash_input() {
        use base64::Engine;
        use sha2::{Digest, Sha256};

        let raw = [0xA7_u8; 32];
        let emitted = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
        let persisted = sm_resume_token_hash(&emitted);
        let claim_input: [u8; 32] = Sha256::digest(emitted.as_bytes()).into();
        let unreachable_raw_hash: [u8; 32] = Sha256::digest(raw).into();
        assert_eq!(persisted, claim_input);
        assert_ne!(persisted, unreachable_raw_hash);
    }
}
