//! Operations on the live C2S session table: authority and lease snapshots, staged activation, SM route claims,
//! epoch predicates, fences and routable lookups. The composition root owns the table itself.

use super::session::{OnlineSession, SmPresenceEpoch, SmStagedRouteClaim};
use dashmap::{DashMap, DashSet};
use northstar_protocol_runtime::caps::{CapsObservationOwner, CapsResourceIndex, PendingCapsIndex};
use northstar_room_application::muc_service::SerializableMucOccupant;
use northstar_room_core::mix::{MixSessionCapability, CORE_NS, PAM_NS};
use northstar_session_core::{
    staged_route_activation_allowed, LocalCapsEpoch, StagedRouteActivationCheck,
    StagedRouteIdentity,
};
use northstar_xmpp_types::jid_text::bare_jid;
use std::sync::{
    atomic::{AtomicU8, Ordering},
    Arc,
};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// A detached view of a local route for PostgreSQL credential maintenance.
/// Pending bind and resume routes are included so they can be cancelled before
/// their final activation check; no map guard survives the database read.
pub struct LocalSessionAuthoritySnapshot {
    pub full_jid: String,
    pub authority: northstar_session_application::session_authority_sweep::SessionAuthoritySnapshot,
    pub disconnect: CancellationToken,
}

/// Captured only after instance authority is refreshed, immediately before
/// Redis route leases are renewed. This is deliberately a second snapshot.
pub struct LocalSessionLeaseSnapshot {
    pub full_jid: String,
    pub activity_age_seconds: u64,
    pub connection_id: uuid::Uuid,
    pub disconnect: CancellationToken,
}

pub fn local_session_authority_snapshots_in(
    sessions: &DashMap<String, OnlineSession>,
) -> Vec<LocalSessionAuthoritySnapshot> {
    sessions
        .iter()
        .map(|entry| LocalSessionAuthoritySnapshot {
            full_jid: entry.key().clone(),
            authority:
                northstar_session_application::session_authority_sweep::SessionAuthoritySnapshot {
                    user_id: entry.user_id,
                    auth_generation: entry.auth_generation,
                    device_id: entry.user_agent_id,
                    device_epoch: entry.user_agent_epoch,
                },
            disconnect: entry.disconnect.clone(),
        })
        .collect()
}

pub fn local_session_lease_snapshots_in(
    sessions: &DashMap<String, OnlineSession>,
) -> Vec<LocalSessionLeaseSnapshot> {
    sessions
        .iter()
        .map(|entry| {
            let activity_age_seconds = entry
                .last_activity
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .elapsed()
                .as_secs();
            LocalSessionLeaseSnapshot {
                full_jid: entry.key().clone(),
                activity_age_seconds,
                connection_id: entry.connection_id,
                disconnect: entry.disconnect.clone(),
            }
        })
        .collect()
}

pub fn try_stage_bound_session_in(
    sessions: &DashMap<String, OnlineSession>,
    key: String,
    session: OnlineSession,
) -> bool {
    debug_assert!(!session.routable.load(Ordering::Acquire));
    match sessions.entry(key) {
        dashmap::mapref::entry::Entry::Vacant(entry) => {
            entry.insert(session);
            true
        }
        dashmap::mapref::entry::Entry::Occupied(_) => false,
    }
}

pub fn publish_user_agent_epoch_if_current_in(
    sessions: &DashMap<String, OnlineSession>,
    key: &str,
    connection_id: uuid::Uuid,
    user_id: uuid::Uuid,
    auth_generation: i64,
    lifecycle: &Arc<AtomicU8>,
    user_agent_epoch: Option<i64>,
) -> bool {
    let Some(mut session) = sessions.get_mut(key) else {
        return false;
    };
    if session.connection_id != connection_id
        || session.user_id != user_id
        || session.auth_generation != auth_generation
        || !Arc::ptr_eq(&session.lifecycle, lifecycle)
        || session.disconnect.is_cancelled()
        || session.lifecycle.load(Ordering::Acquire) != 0
    {
        return false;
    }
    session.user_agent_epoch = user_agent_epoch;
    true
}

pub fn activate_session_if_current_in(
    sessions: &DashMap<String, OnlineSession>,
    full_jid: &str,
    connection_id: uuid::Uuid,
    user_id: uuid::Uuid,
    auth_generation: i64,
    lifecycle: &Arc<AtomicU8>,
    disconnect: &CancellationToken,
) -> bool {
    let Some(session) = sessions.get_mut(full_jid) else {
        return false;
    };
    if !staged_route_activation_allowed(StagedRouteActivationCheck {
        session: StagedRouteIdentity {
            connection_id: session.connection_id,
            user_id: session.user_id,
            auth_generation: session.auth_generation,
        },
        expected: StagedRouteIdentity {
            connection_id,
            user_id,
            auth_generation,
        },
        same_lifecycle: Arc::ptr_eq(&session.lifecycle, lifecycle),
        lifecycle_state: session.lifecycle.load(Ordering::Acquire),
        session_cancelled: session.disconnect.is_cancelled(),
        owner_cancelled: disconnect.is_cancelled(),
    }) {
        return false;
    }
    session.routable.store(true, Ordering::Release);
    if session.lifecycle.load(Ordering::Acquire) != 0
        || session.disconnect.is_cancelled()
        || disconnect.is_cancelled()
    {
        session.routable.store(false, Ordering::Release);
        return false;
    }
    true
}

pub fn stage_sm_resumed_session_in(
    sessions: &DashMap<String, OnlineSession>,
    key: String,
    candidate: OnlineSession,
    claimant_user: uuid::Uuid,
    claimed_sm_id: uuid::Uuid,
    expected_gate: &Arc<tokio::sync::Mutex<()>>,
) -> SmStagedRouteClaim {
    debug_assert!(!candidate.routable.load(Ordering::Acquire));
    match sessions.entry(key) {
        dashmap::mapref::entry::Entry::Vacant(entry) => {
            entry.insert(candidate);
            SmStagedRouteClaim::Inserted
        }
        dashmap::mapref::entry::Entry::Occupied(entry) => {
            let existing = entry.get();
            let existing_sm_id = *existing
                .sm_session_id
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if !matching_sm_route(
                existing.user_id,
                existing_sm_id,
                claimant_user,
                claimed_sm_id,
            ) {
                SmStagedRouteClaim::Conflict
            } else if !Arc::ptr_eq(expected_gate, &existing.mix_presence_gate) {
                SmStagedRouteClaim::AdoptPresenceEpoch(SmPresenceEpoch {
                    gate: Arc::clone(&existing.mix_presence_gate),
                    fallback_suppressed: Arc::clone(&existing.mix_presence_fallback_suppressed),
                    caps_generation: Arc::clone(&existing.caps_observation_generation),
                })
            } else {
                SmStagedRouteClaim::Replace {
                    connection_id: existing.connection_id,
                    lifecycle: Arc::clone(&existing.lifecycle),
                    disconnect: existing.disconnect.clone(),
                    route_incarnation: Arc::clone(&existing.route_incarnation),
                }
            }
        }
    }
}

pub enum LocalSessionFence {
    Instance(uuid::Uuid),
    Sm(uuid::Uuid),
    Admin {
        user_id: uuid::Uuid,
        auth_generation: i64,
        connection_id: uuid::Uuid,
    },
}

pub fn local_caps_route_epoch_matches(
    current_connection_id: uuid::Uuid,
    current_generation: u64,
    routable: bool,
    cancelled: bool,
    lifecycle: u8,
    same_gate: bool,
    expected: LocalCapsEpoch,
) -> bool {
    current_connection_id == expected.connection_id
        && current_generation == expected.generation
        && routable
        && !cancelled
        && lifecycle == 0
        && same_gate
}

/// The same verified observation and stale-local-epoch eviction used by
/// ordinary CAPS routing. An unknown observation keeps durable delivery
/// parked until verification or the recipient's next route wake.
pub fn session_mix_capability_in(
    sessions: &DashMap<String, OnlineSession>,
    caps_by_jid: &CapsResourceIndex,
    pending_caps: &PendingCapsIndex,
    full_jid: &str,
) -> MixSessionCapability {
    let Ok(full_jid) = northstar_xmpp_types::jid::canonical_session_key(full_jid) else {
        return MixSessionCapability::Unknown;
    };
    let Some(observation) = caps_by_jid.snapshot(&full_jid) else {
        return MixSessionCapability::Unknown;
    };
    if let CapsObservationOwner::Local(epoch) = observation.owner {
        let current = sessions.get(&full_jid).is_some_and(|session| {
            local_caps_route_epoch_matches(
                session.connection_id,
                session.caps_observation_generation.load(Ordering::Acquire),
                session.routable.load(Ordering::Acquire),
                session.disconnect.is_cancelled(),
                session.lifecycle.load(Ordering::Acquire),
                true,
                epoch,
            )
        });
        if !current {
            pending_caps.remove_local_epoch(&full_jid, epoch);
            caps_by_jid.remove_local_epoch(&full_jid, epoch);
            return MixSessionCapability::Unknown;
        }
    }
    match observation.summary {
        Some(summary) if summary.has_feature(CORE_NS) || summary.has_feature(PAM_NS) => {
            MixSessionCapability::Supported
        }
        Some(_) => MixSessionCapability::Unsupported,
        None => MixSessionCapability::Unknown,
    }
}

pub fn mix_presence_epoch_is_current(
    current_connection_id: uuid::Uuid,
    expected_connection_id: uuid::Uuid,
    current_caps_generation: u64,
    expected_caps_generation: u64,
    routable: bool,
    available: bool,
    same_gate: bool,
) -> bool {
    current_connection_id == expected_connection_id
        && current_caps_generation == expected_caps_generation
        && routable
        && available
        && same_gate
}

pub fn mix_presence_fallback_is_suppressed(
    suppressed: &DashSet<String>,
    channel_jid: &str,
) -> bool {
    suppressed.contains("*") || suppressed.contains(channel_jid)
}

pub(crate) fn matching_sm_route(
    existing_user: uuid::Uuid,
    existing_sm_id: Option<uuid::Uuid>,
    claimant_user: uuid::Uuid,
    claimed_sm_id: uuid::Uuid,
) -> bool {
    existing_user == claimant_user && existing_sm_id == Some(claimed_sm_id)
}

pub fn fence_local_session_in(
    sessions: &DashMap<String, OnlineSession>,
    full_jid: &str,
    fence: LocalSessionFence,
) -> bool {
    fence_local_session_if(sessions, full_jid, |session| match fence {
        LocalSessionFence::Instance(connection_id) => {
            !connection_id.is_nil() && session.connection_id == connection_id
        }
        LocalSessionFence::Sm(sm_session_id) => {
            *session
                .sm_session_id
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                == Some(sm_session_id)
        }
        LocalSessionFence::Admin {
            user_id,
            auth_generation,
            connection_id,
        } => {
            session.user_id == user_id
                && session.auth_generation == auth_generation
                && session.connection_id == connection_id
        }
    })
}

pub(crate) fn fence_local_session_if(
    sessions: &DashMap<String, OnlineSession>,
    full_jid: &str,
    matches: impl FnOnce(&OnlineSession) -> bool,
) -> bool {
    let Some(session) = sessions.get_mut(full_jid) else {
        return false;
    };
    if !matches(&session) {
        return false;
    }
    // Serialize the fence with two-phase route activation and revocation.
    session.routable.store(false, Ordering::Release);
    session.disconnect.cancel();
    true
}

#[cfg(any(test, feature = "test-support"))]
pub fn cancel_local_session_if_connection_in(
    sessions: &DashMap<String, OnlineSession>,
    full_jid: &str,
    connection_id: uuid::Uuid,
) -> bool {
    let Some(session) = sessions.get(full_jid) else {
        return false;
    };
    if session.connection_id != connection_id {
        return false;
    }
    session.disconnect.cancel();
    true
}

#[derive(Debug, Eq, PartialEq)]
pub enum SessionLookup {
    Bare(String),
    Full(String),
}

pub fn session_lookup(jid: &str) -> Option<SessionLookup> {
    let jid = northstar_xmpp_types::jid::CanonicalJid::parse(jid).ok()?;
    Some(if jid.resourcepart().is_some() {
        SessionLookup::Full(jid.to_string())
    } else {
        SessionLookup::Bare(jid.bare())
    })
}

pub fn session_entries_for_in(
    sessions: &DashMap<String, OnlineSession>,
    jid: &str,
) -> Vec<(String, OnlineSession)> {
    let Some(lookup) = session_lookup(jid) else {
        return Vec::new();
    };
    match lookup {
        SessionLookup::Full(full) => sessions
            .get(&full)
            .filter(|entry| entry.routable.load(Ordering::Acquire))
            .map(|entry| vec![(entry.key().clone(), entry.value().clone())])
            .unwrap_or_default(),
        SessionLookup::Bare(bare) => sessions
            .iter()
            .filter(|entry| {
                bare_jid(entry.key()) == bare.as_str() && entry.routable.load(Ordering::Acquire)
            })
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect(),
    }
}

pub fn try_send_to_entries_in(sessions: &DashMap<String, OnlineSession>, jid: &str, stanza: &str) {
    for (_, session) in session_entries_for_in(sessions, jid) {
        let _ = session.sender.try_send(stanza.to_owned());
    }
}

/// Clone routable sibling routes before sending; no DashMap guard is held
/// while a transport accepts the unavailable presence.
pub fn try_send_to_available_entries_in(
    sessions: &DashMap<String, OnlineSession>,
    jid: &str,
    stanza: &str,
) {
    for (jid, target) in session_entries_for_in(sessions, jid)
        .into_iter()
        .filter(|(_, target)| target.available.load(Ordering::Relaxed))
    {
        let _ = target
            .sender
            .try_send(northstar_xml_builder::rewrite::set_to(stanza, &jid));
    }
}

/// The live C2S session table, keyed by full JID. The composition root holds one; workers that need only the raw
/// routes take a clone of the shared map, which the table dereferences to.
#[derive(Clone, Default)]
pub struct LocalSessionTable(Arc<DashMap<String, OnlineSession>>);

impl LocalSessionTable {
    /// The table over the shared map `sessions`.
    pub fn new(sessions: Arc<DashMap<String, OnlineSession>>) -> Self {
        Self(sessions)
    }

    /// Revoke the exact live protocol actor membership represented by an
    /// occupant.  All four identities are required so a delayed kick or
    /// teardown cannot affect a later connection or a reused nickname.
    pub fn remove_live_muc_membership(&self, occupant: &SerializableMucOccupant) -> bool {
        super::muc_table::remove_live_muc_membership_in(&self.0, occupant)
    }

    /// Reserve a non-routable bind candidate under the same map entry guard
    /// that rejects a concurrent bind or resume for this full JID.
    pub fn try_stage_bound_session(&self, key: String, session: OnlineSession) -> bool {
        try_stage_bound_session_in(&self.0, key, session)
    }

    pub fn staged_session_is_current(
        &self,
        key: &str,
        connection_id: uuid::Uuid,
        user_id: uuid::Uuid,
        auth_generation: i64,
        lifecycle: &Arc<AtomicU8>,
    ) -> bool {
        self.0.get(key).is_some_and(|session| {
            session.connection_id == connection_id
                && session.user_id == user_id
                && session.auth_generation == auth_generation
                && Arc::ptr_eq(&session.lifecycle, lifecycle)
                && !session.disconnect.is_cancelled()
                && session.lifecycle.load(Ordering::Acquire) == 0
        })
    }

    pub fn publish_user_agent_epoch_if_current(
        &self,
        key: &str,
        connection_id: uuid::Uuid,
        user_id: uuid::Uuid,
        auth_generation: i64,
        lifecycle: &Arc<AtomicU8>,
        user_agent_epoch: Option<i64>,
    ) -> bool {
        publish_user_agent_epoch_if_current_in(
            &self.0,
            key,
            connection_id,
            user_id,
            auth_generation,
            lifecycle,
            user_agent_epoch,
        )
    }

    /// A carbon preference is session-local and must be visible to fan-out
    /// before its IQ result is sent to the same connection.
    pub fn set_local_carbons_for_connection(
        &self,
        key: &str,
        connection_id: uuid::Uuid,
        enabled: bool,
    ) -> bool {
        let Some(route) = self.0.get(key) else {
            return false;
        };
        if route.connection_id != connection_id {
            return false;
        }
        route.carbons.store(enabled, Ordering::Release);
        true
    }

    pub fn sm_pending_route_removal_signal(
        &self,
        key: &str,
        old_connection_id: uuid::Uuid,
        user_id: uuid::Uuid,
        sm_session_id: uuid::Uuid,
        cancel_live_route: bool,
    ) -> Option<tokio::sync::watch::Receiver<bool>> {
        let session = self.0.get(key)?;
        let exact_sm = session
            .sm_session_id
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_some_and(|current| current == sm_session_id);
        if session.connection_id != old_connection_id || session.user_id != user_id || !exact_sm {
            return None;
        }
        if cancel_live_route {
            session.disconnect.cancel();
        }
        Some(session.route_incarnation.subscribe())
    }

    pub fn sm_presence_epoch(&self, key: &str) -> Option<SmPresenceEpoch> {
        self.0.get(key).map(|session| SmPresenceEpoch {
            gate: Arc::clone(&session.mix_presence_gate),
            fallback_suppressed: Arc::clone(&session.mix_presence_fallback_suppressed),
            caps_generation: Arc::clone(&session.caps_observation_generation),
        })
    }

    /// Inspect/insert inside one DashMap entry operation. The caller owns the
    /// returned gate and route-incarnation handles before any async wait.
    pub fn stage_sm_resumed_session(
        &self,
        key: String,
        candidate: OnlineSession,
        claimant_user: uuid::Uuid,
        claimed_sm_id: uuid::Uuid,
        expected_gate: &Arc<tokio::sync::Mutex<()>>,
    ) -> SmStagedRouteClaim {
        stage_sm_resumed_session_in(
            &self.0,
            key,
            candidate,
            claimant_user,
            claimed_sm_id,
            expected_gate,
        )
    }

    /// The command protocol receives only the delivered account identities,
    /// not mutable access to the session table.
    pub fn send_local_announcement(&self, stanza: &str) -> std::collections::BTreeSet<String> {
        let mut recipients = std::collections::BTreeSet::new();
        for entry in self.0.iter() {
            if entry.routable.load(Ordering::Acquire)
                && entry.available.load(Ordering::Acquire)
                && entry.priority.load(Ordering::Acquire) >= 0
                && entry.sender.try_send(stanza.to_owned()).is_ok()
            {
                if let Ok(bare) = northstar_xmpp_types::jid::canonical_bare_key(entry.key()) {
                    recipients.insert(bare);
                }
            }
        }
        recipients
    }

    pub fn local_online_bare_jids(&self) -> std::collections::BTreeSet<String> {
        self.0
            .iter()
            .filter(|entry| entry.routable.load(Ordering::Acquire))
            .filter_map(|entry| northstar_xmpp_types::jid::canonical_bare_key(entry.key()).ok())
            .collect()
    }

    pub fn local_activity_bare_jids(
        &self,
        idle_after: Duration,
    ) -> (
        std::collections::BTreeSet<String>,
        std::collections::BTreeSet<String>,
    ) {
        let mut online = std::collections::BTreeSet::new();
        let mut active = std::collections::BTreeSet::new();
        for entry in self.0.iter() {
            if !entry.routable.load(Ordering::Acquire) {
                continue;
            }
            let Ok(bare) = northstar_xmpp_types::jid::canonical_bare_key(entry.key()) else {
                continue;
            };
            online.insert(bare.clone());
            if entry
                .last_activity
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .elapsed()
                < idle_after
            {
                active.insert(bare);
            }
        }
        (online, active)
    }

    /// Initial key snapshot for an account presence probe. The protocol then
    /// rechecks each incarnation after its privacy/database awaits.
    pub fn local_presence_owner_keys(&self) -> Vec<String> {
        self.0.iter().map(|entry| entry.key().clone()).collect()
    }

    pub fn local_presence_owner_candidate(
        &self,
        key: &str,
        user_id: uuid::Uuid,
        auth_generation: i64,
    ) -> Option<OnlineSession> {
        self.0.get(key).and_then(|session| {
            (session.routable.load(Ordering::Acquire)
                && session.user_id == user_id
                && session.auth_generation == auth_generation
                && session.available.load(Ordering::Relaxed))
            .then(|| session.value().clone())
        })
    }

    pub fn local_presence_owner_if_current(
        &self,
        key: &str,
        expected: &OnlineSession,
        user_id: uuid::Uuid,
        auth_generation: i64,
    ) -> Option<OnlineSession> {
        self.0.get(key).and_then(|current| {
            (current.connection_id == expected.connection_id
                && Arc::ptr_eq(&current.route_incarnation, &expected.route_incarnation)
                && current.user_id == user_id
                && current.auth_generation == auth_generation
                && current.routable.load(Ordering::Acquire)
                && current.available.load(Ordering::Relaxed))
            .then(|| current.value().clone())
        })
    }

    pub fn send_presence_if_owner_current(
        &self,
        key: &str,
        expected: &OnlineSession,
        user_id: uuid::Uuid,
        auth_generation: i64,
        recipient: &crate::outbound::OutboundSender,
        presence: &str,
    ) -> bool {
        let Some(current) = self.0.get(key) else {
            return false;
        };
        if current.connection_id != expected.connection_id
            || !Arc::ptr_eq(&current.route_incarnation, &expected.route_incarnation)
            || current.user_id != user_id
            || current.auth_generation != auth_generation
            || !current.routable.load(Ordering::Acquire)
            || !current.available.load(Ordering::Relaxed)
        {
            return false;
        }
        recipient.try_send(presence.to_owned()).is_ok()
    }

    pub fn local_caps_epoch_is_current(
        &self,
        full_jid: &str,
        epoch: LocalCapsEpoch,
        expected_gate: Option<&Arc<tokio::sync::Mutex<()>>>,
    ) -> bool {
        self.0.get(full_jid).is_some_and(|session| {
            local_caps_route_epoch_matches(
                session.connection_id,
                session.caps_observation_generation.load(Ordering::Acquire),
                session.routable.load(Ordering::Acquire),
                session.disconnect.is_cancelled(),
                session.lifecycle.load(Ordering::Acquire),
                expected_gate.is_none_or(|gate| Arc::ptr_eq(&session.mix_presence_gate, gate)),
                epoch,
            )
        })
    }

    pub fn local_caps_observer_connection_is_current(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
        expected_gate: &Arc<tokio::sync::Mutex<()>>,
    ) -> bool {
        self.0.get(full_jid).is_some_and(|session| {
            session.connection_id == connection_id
                && Arc::ptr_eq(&session.mix_presence_gate, expected_gate)
                && session.routable.load(Ordering::Acquire)
                && !session.disconnect.is_cancelled()
                && session.lifecycle.load(Ordering::Acquire) == 0
        })
    }

    pub fn local_mix_presence_route_is_current(
        &self,
        full_jid: &str,
        expected_connection_id: uuid::Uuid,
        expected_gate: &Arc<tokio::sync::Mutex<()>>,
        require_available: bool,
    ) -> bool {
        self.0.get(full_jid).is_some_and(|session| {
            session.connection_id == expected_connection_id
                && Arc::ptr_eq(&session.mix_presence_gate, expected_gate)
                && session.routable.load(Ordering::Acquire)
                && (!require_available || session.available.load(Ordering::Acquire))
                && !session.disconnect.is_cancelled()
                && session.lifecycle.load(Ordering::Acquire) == 0
        })
    }

    pub fn sessions_for(&self, jid: &str) -> Vec<OnlineSession> {
        let Some(lookup) = session_lookup(jid) else {
            return Vec::new();
        };
        match lookup {
            SessionLookup::Full(full) => self
                .0
                .get(&full)
                .filter(|entry| entry.routable.load(Ordering::Acquire))
                .map(|entry| vec![entry.value().clone()])
                .unwrap_or_default(),
            SessionLookup::Bare(bare) => self
                .0
                .iter()
                .filter(|entry| {
                    bare_jid(entry.key()) == bare.as_str() && entry.routable.load(Ordering::Acquire)
                })
                .map(|entry| entry.value().clone())
                .collect(),
        }
    }

    pub fn privacy_list_active_locally(&self, account: &str, name: &str) -> bool {
        self.sessions_for(account).iter().any(|session| {
            session
                .privacy_active
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .as_deref()
                == Some(name)
        })
    }

    pub fn session_entries_for(&self, jid: &str) -> Vec<(String, OnlineSession)> {
        session_entries_for_in(&self.0, jid)
    }

    /// Publish only the exact staged route incarnation that survived every
    /// authorization and lifecycle fence.  The DashMap write guard provides
    /// a local linearization point with account/session revocation helpers;
    /// the cancellation/lifecycle recheck after publication also closes a
    /// concurrent out-of-band transport cancellation window.
    pub fn activate_session_if_current(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
        user_id: uuid::Uuid,
        auth_generation: i64,
        lifecycle: &Arc<AtomicU8>,
        disconnect: &CancellationToken,
    ) -> bool {
        activate_session_if_current_in(
            &self.0,
            full_jid,
            connection_id,
            user_id,
            auth_generation,
            lifecycle,
            disconnect,
        )
    }
}

impl std::ops::Deref for LocalSessionTable {
    type Target = Arc<DashMap<String, OnlineSession>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use northstar_protocol_runtime::caps::{CapsKey, VerifiedCapsSummary};
    use std::time::{Duration, Instant};
    use uuid::Uuid;

    const KEY: &str = "alice@example.test/fixture";

    fn session(
        connection_id: uuid::Uuid,
        user_id: uuid::Uuid,
        routable: bool,
    ) -> (
        OnlineSession,
        tokio::sync::mpsc::Receiver<crate::outbound::OutboundItem>,
    ) {
        let (session, receiver) =
            super::super::session::test_online_session(user_id, 7, connection_id, "fixture", 1);
        session.routable.store(routable, Ordering::Relaxed);
        session
            .caps_observation_generation
            .store(11, Ordering::Relaxed);
        (session, receiver)
    }

    #[test]
    fn privacy_list_active_locally_matches_any_resource() {
        let table = LocalSessionTable::new(Arc::new(DashMap::new()));
        let (inactive, _inactive_receiver) = session(Uuid::new_v4(), Uuid::new_v4(), true);
        let (active, _active_receiver) = session(Uuid::new_v4(), Uuid::new_v4(), true);
        *active.privacy_active.write().unwrap() = Some("friends".to_owned());
        table.insert(KEY.to_owned(), inactive);
        table.insert("alice@example.test/active".to_owned(), active);

        assert!(table.privacy_list_active_locally("alice@example.test", "friends"));
    }

    #[test]
    fn privacy_list_active_locally_returns_false_without_a_match() {
        let table = LocalSessionTable::new(Arc::new(DashMap::new()));
        let (inactive, _inactive_receiver) = session(Uuid::new_v4(), Uuid::new_v4(), true);
        let (active, _active_receiver) = session(Uuid::new_v4(), Uuid::new_v4(), true);
        *active.privacy_active.write().unwrap() = Some("other".to_owned());
        table.insert(KEY.to_owned(), inactive);
        table.insert("alice@example.test/active".to_owned(), active);

        assert!(!table.privacy_list_active_locally("alice@example.test", "friends"));
        assert!(!table.privacy_list_active_locally("absent@example.test", "friends"));
    }

    #[test]
    fn privacy_list_active_locally_ignores_other_accounts() {
        let table = LocalSessionTable::new(Arc::new(DashMap::new()));
        let (inactive, _inactive_receiver) = session(Uuid::new_v4(), Uuid::new_v4(), true);
        let (active, _active_receiver) = session(Uuid::new_v4(), Uuid::new_v4(), true);
        *active.privacy_active.write().unwrap() = Some("friends".to_owned());
        table.insert(KEY.to_owned(), inactive);
        table.insert("bob@example.test/active".to_owned(), active);

        assert!(!table.privacy_list_active_locally("alice@example.test", "friends"));
    }

    #[test]
    fn privacy_list_active_locally_recovers_poisoned_lock() {
        let table = LocalSessionTable::new(Arc::new(DashMap::new()));
        let (active, _receiver) = session(Uuid::new_v4(), Uuid::new_v4(), true);
        let privacy_active = Arc::clone(&active.privacy_active);
        assert!(std::thread::spawn(move || {
            let mut guard = privacy_active.write().unwrap();
            *guard = Some("friends".to_owned());
            panic!("poison privacy_active");
        })
        .join()
        .is_err());
        assert!(active.privacy_active.is_poisoned());
        table.insert(KEY.to_owned(), active);

        assert!(table.privacy_list_active_locally("alice@example.test", "friends"));
        assert!(!table.privacy_list_active_locally("alice@example.test", "other"));
    }

    #[test]
    fn try_send_to_available_entries_skips_unavailable_sessions() {
        let sessions = DashMap::new();
        let mut receivers = Vec::new();
        for (key, routable, available) in [
            (KEY, true, true),
            ("alice@example.test/unavailable", true, false),
            ("alice@example.test/pending", false, true),
            ("bob@example.test/fixture", true, true),
        ] {
            let (route, receiver) = session(Uuid::new_v4(), Uuid::new_v4(), routable);
            route.available.store(available, Ordering::Relaxed);
            sessions.insert(key.to_owned(), route);
            receivers.push((key, receiver));
        }
        let stanza = "<presence from='alice@example.test/gone' type='unavailable'/>";

        try_send_to_available_entries_in(&sessions, "alice@example.test", stanza);

        for (key, mut receiver) in receivers {
            if key == KEY {
                assert_eq!(
                    receiver.try_recv().unwrap().stanza,
                    northstar_xml_builder::rewrite::set_to(stanza, KEY)
                );
            }
            assert!(matches!(
                receiver.try_recv(),
                Err(tokio::sync::mpsc::error::TryRecvError::Empty)
            ));
        }
    }

    #[test]
    fn try_send_to_entries_delivers_one_copy_to_each_matching_session() {
        for jid in ["alice@example.test", KEY] {
            let sessions = DashMap::new();
            let mut receivers = Vec::new();
            for (key, user_id, routable) in [
                (KEY, Uuid::from_u128(1), true),
                ("alice@example.test/other", Uuid::from_u128(1), true),
                ("alice@example.test/pending", Uuid::from_u128(1), false),
                ("bob@example.test/fixture", Uuid::from_u128(2), true),
            ] {
                let (route, receiver) = session(Uuid::new_v4(), user_id, routable);
                sessions.insert(key.to_owned(), route);
                receivers.push((key, receiver));
            }
            let expected = session_entries_for_in(&sessions, jid);
            assert_eq!(expected.len(), if jid == KEY { 1 } else { 2 });
            let stanza = "<presence/>";

            try_send_to_entries_in(&sessions, jid, stanza);

            for (key, mut receiver) in receivers {
                if expected.iter().any(|(full_jid, _)| full_jid == key) {
                    assert_eq!(receiver.try_recv().unwrap().stanza, stanza);
                }
                assert!(matches!(
                    receiver.try_recv(),
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty)
                ));
            }
        }
    }

    fn caps_key(version: &str) -> CapsKey {
        CapsKey {
            algorithm: "sha-1".to_owned(),
            node: "https://example.test/caps".to_owned(),
            version: version.to_owned(),
        }
    }

    fn supplied_summary(core: bool, pam: bool) -> Arc<VerifiedCapsSummary> {
        // Supplied verified environment; these tests do not run disco/hash verification.
        Arc::new(VerifiedCapsSummary::new(
            core,
            pam,
            String::new(),
            Vec::new(),
        ))
    }

    #[test]
    fn local_caps_classification_uses_the_current_canonical_route_and_summary() {
        for (features, expected) in [
            (Some((true, false)), MixSessionCapability::Supported),
            (Some((false, true)), MixSessionCapability::Supported),
            (Some((false, false)), MixSessionCapability::Unsupported),
            (None, MixSessionCapability::Unknown),
        ] {
            let sessions = DashMap::new();
            let (route, _receiver) = session(Uuid::from_u128(1), Uuid::from_u128(2), true);
            let epoch = LocalCapsEpoch {
                connection_id: route.connection_id,
                generation: route.caps_observation_generation.load(Ordering::Acquire),
            };
            sessions.insert(KEY.to_owned(), route);
            let caps = CapsResourceIndex::new();
            let pending = PendingCapsIndex::new();
            let now = Instant::now();
            caps.observe_local(
                KEY.to_owned(),
                epoch,
                Some(caps_key("current")),
                features.map(|(core, pam)| supplied_summary(core, pam)),
                now,
            );
            assert!(pending.insert(
                "current".to_owned(),
                KEY.to_owned(),
                caps_key("current"),
                CapsObservationOwner::Local(epoch),
                now + Duration::from_secs(30),
            ));
            assert_eq!(
                session_mix_capability_in(&sessions, &caps, &pending, "ALICE@EXAMPLE.TEST/fixture"),
                expected
            );
            assert_eq!(caps.owner(KEY), Some(CapsObservationOwner::Local(epoch)));
            assert_eq!(caps.len(), 1);
            assert_eq!(pending.len(), 1);
            assert_eq!(
                pending.entries.get("current").unwrap().owner,
                CapsObservationOwner::Local(epoch)
            );
        }
    }

    #[test]
    fn invalid_or_unobserved_caps_target_keeps_existing_indexes() {
        let sessions = DashMap::new();
        let (route, _receiver) = session(Uuid::from_u128(1), Uuid::from_u128(2), true);
        let epoch = LocalCapsEpoch {
            connection_id: route.connection_id,
            generation: route.caps_observation_generation.load(Ordering::Acquire),
        };
        sessions.insert(KEY.to_owned(), route);
        let caps = CapsResourceIndex::new();
        let pending = PendingCapsIndex::new();
        let now = Instant::now();
        caps.observe_local(
            KEY.to_owned(),
            epoch,
            Some(caps_key("current")),
            Some(supplied_summary(true, false)),
            now,
        );
        assert!(pending.insert(
            "current".to_owned(),
            KEY.to_owned(),
            caps_key("current"),
            CapsObservationOwner::Local(epoch),
            now + Duration::from_secs(30),
        ));
        for target in ["", "alice@example.test", "alice@example.test/missing"] {
            assert_eq!(
                session_mix_capability_in(&sessions, &caps, &pending, target),
                MixSessionCapability::Unknown,
                "{target}"
            );
            assert_eq!(caps.owner(KEY), Some(CapsObservationOwner::Local(epoch)));
            assert_eq!(caps.len(), 1);
            assert_eq!(pending.len(), 1);
        }
    }

    #[test]
    fn stale_local_caps_evict_only_the_queried_epoch_and_preserve_other_observations() {
        for case in [
            "missing session",
            "connection",
            "generation",
            "unroutable",
            "session cancelled",
            "lifecycle one",
            "lifecycle two",
        ] {
            let sessions = DashMap::new();
            let (mut route, _receiver) = session(Uuid::from_u128(1), Uuid::from_u128(2), true);
            let epoch = LocalCapsEpoch {
                connection_id: route.connection_id,
                generation: route.caps_observation_generation.load(Ordering::Acquire),
            };
            match case {
                "missing session" => {}
                "connection" => {
                    route.connection_id = Uuid::from_u128(3);
                    route.route_incarnation =
                        northstar_session_application::RouteIncarnationSignal::new(
                            route.connection_id,
                        );
                }
                "generation" => route
                    .caps_observation_generation
                    .store(12, Ordering::Release),
                "unroutable" => route.routable.store(false, Ordering::Release),
                "session cancelled" => route.disconnect.cancel(),
                "lifecycle one" => route.lifecycle.store(1, Ordering::Release),
                "lifecycle two" => route.lifecycle.store(2, Ordering::Release),
                _ => unreachable!(),
            }
            if case != "missing session" {
                sessions.insert(KEY.to_owned(), route);
            }
            let caps = CapsResourceIndex::new();
            let pending = PendingCapsIndex::new();
            let now = Instant::now();
            let summary = supplied_summary(true, false);
            for key in [KEY, "alice@example.test/other"] {
                caps.observe_local(
                    key.to_owned(),
                    epoch,
                    Some(caps_key("old")),
                    Some(Arc::clone(&summary)),
                    now,
                );
            }
            let newer_epoch = LocalCapsEpoch {
                connection_id: epoch.connection_id,
                generation: epoch.generation + 1,
            };
            for (id, owner) in [("old", epoch), ("newer", newer_epoch)] {
                assert!(pending.insert(
                    id.to_owned(),
                    KEY.to_owned(),
                    caps_key(id),
                    CapsObservationOwner::Local(owner),
                    now + Duration::from_secs(30),
                ));
            }
            assert_eq!(caps.len(), 2);
            assert_eq!(pending.len(), 2);
            assert_eq!(
                session_mix_capability_in(&sessions, &caps, &pending, "ALICE@EXAMPLE.TEST/fixture"),
                MixSessionCapability::Unknown,
                "{case}"
            );
            assert!(caps.owner(KEY).is_none(), "{case}");
            assert!(pending.entries.get("old").is_none(), "{case}");
            assert_eq!(
                pending.entries.get("newer").unwrap().owner,
                CapsObservationOwner::Local(newer_epoch),
                "{case}"
            );
            // The other target is also stale, but was never queried.
            assert_eq!(
                caps.owner("alice@example.test/other"),
                Some(CapsObservationOwner::Local(epoch)),
                "{case}"
            );
            assert_eq!(caps.len(), 1);
            assert_eq!(pending.len(), 1);
            assert_eq!(
                caps.admission.lock().unwrap().summary_bytes,
                summary.resident_charge()
            );
        }
    }

    #[test]
    fn federated_caps_classification_does_not_apply_local_route_fences() {
        for (features, expected) in [
            (Some((false, true)), MixSessionCapability::Supported),
            (Some((false, false)), MixSessionCapability::Unsupported),
            (None, MixSessionCapability::Unknown),
        ] {
            let sessions = DashMap::new();
            let (route, _receiver) = session(Uuid::from_u128(1), Uuid::from_u128(2), false);
            route.disconnect.cancel();
            route.lifecycle.store(2, Ordering::Release);
            sessions.insert(KEY.to_owned(), route);
            let caps = CapsResourceIndex::new();
            let pending = PendingCapsIndex::new();
            let now = Instant::now();
            let owner = caps
                .observe_federated(
                    KEY.to_owned(),
                    Uuid::from_u128(3),
                    "example.test".to_owned(),
                    Some(caps_key("federated")),
                    features.map(|(core, pam)| supplied_summary(core, pam)),
                    now,
                )
                .unwrap();
            assert!(pending.insert(
                "federated".to_owned(),
                KEY.to_owned(),
                caps_key("federated"),
                owner,
                now + Duration::from_secs(30),
            ));
            assert_eq!(
                session_mix_capability_in(&sessions, &caps, &pending, KEY),
                expected
            );
            assert_eq!(caps.owner(KEY), Some(owner));
            assert_eq!(pending.entries.get("federated").unwrap().owner, owner);
            assert_eq!(caps.len(), 1);
            assert_eq!(pending.len(), 1);
        }
    }

    #[test]
    fn epoch_publication_and_activation_fence_every_captured_route_argument() {
        for label in [
            "current",
            "missing key",
            "connection",
            "user",
            "generation",
            "lifecycle pointer",
            "finalizing",
            "superseded",
            "session cancelled",
            "owner cancelled",
            "replacement",
        ] {
            let sessions = Arc::new(DashMap::new());
            let table = LocalSessionTable::new(Arc::clone(&sessions));
            let (mut route, _receiver) = session(Uuid::from_u128(1), Uuid::from_u128(2), false);
            route.user_agent_epoch = Some(13);
            let mut key = KEY;
            let mut connection = route.connection_id;
            let mut user = route.user_id;
            let mut generation = route.auth_generation;
            let mut lifecycle = Arc::clone(&route.lifecycle);
            let owner_disconnect = CancellationToken::new();
            match label {
                "missing key" => key = "alice@example.test/missing",
                "connection" => connection = Uuid::from_u128(3),
                "user" => user = Uuid::from_u128(4),
                "generation" => generation += 1,
                "lifecycle pointer" => lifecycle = Arc::new(AtomicU8::new(0)),
                "finalizing" => route.lifecycle.store(1, Ordering::Release),
                "superseded" => route.lifecycle.store(2, Ordering::Release),
                "session cancelled" => route.disconnect.cancel(),
                "owner cancelled" => owner_disconnect.cancel(),
                "current" | "replacement" => {}
                _ => unreachable!(),
            }
            sessions.insert(KEY.to_owned(), route);
            if label == "replacement" {
                let (mut replacement, _replacement_receiver) =
                    session(Uuid::from_u128(5), user, false);
                replacement.user_agent_epoch = Some(13);
                sessions.insert(KEY.to_owned(), replacement);
            }
            let epoch_allowed = matches!(label, "current" | "owner cancelled");
            // The epoch helper has no owner-cancellation argument. Both its direct
            // entry point and the table facade must assign the supplied Option.
            for epoch in [Some(43), None] {
                assert_eq!(
                    publish_user_agent_epoch_if_current_in(
                        &sessions, key, connection, user, generation, &lifecycle, epoch
                    ),
                    epoch_allowed,
                    "{label}: direct epoch publication"
                );
                assert_eq!(
                    table.publish_user_agent_epoch_if_current(
                        key, connection, user, generation, &lifecycle, epoch
                    ),
                    epoch_allowed,
                    "{label}: table epoch publication"
                );
                let stored = sessions.get(KEY).unwrap();
                assert_eq!(
                    stored.user_agent_epoch,
                    if epoch_allowed { epoch } else { Some(13) },
                    "{label}"
                );
                assert!(
                    !stored.routable.load(Ordering::Acquire),
                    "{label}: epoch publication activated route"
                );
            }
            let activation_allowed = label == "current";
            assert_eq!(
                activate_session_if_current_in(
                    &sessions,
                    key,
                    connection,
                    user,
                    generation,
                    &lifecycle,
                    &owner_disconnect
                ),
                activation_allowed,
                "{label}: direct activation"
            );
            assert_eq!(
                table.activate_session_if_current(
                    key,
                    connection,
                    user,
                    generation,
                    &lifecycle,
                    &owner_disconnect
                ),
                activation_allowed,
                "{label}: table activation"
            );
            assert_eq!(
                sessions.get(KEY).unwrap().routable.load(Ordering::Acquire),
                activation_allowed,
                "{label}"
            );
            assert_eq!(sessions.len(), 1, "{label}");
            // Both calls must have released their map guards.
            assert!(sessions.remove(KEY).is_some(), "{label}");
        }
    }
}
