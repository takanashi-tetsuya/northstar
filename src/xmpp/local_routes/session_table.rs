//! Operations on the live C2S session table: authority and lease snapshots, staged activation, SM route claims,
//! epoch predicates, fences and routable lookups. The composition root owns the table itself.

use super::session::{OnlineSession, SmPresenceEpoch, SmStagedRouteClaim};
use crate::platform::jid_text::bare_jid;
use dashmap::{DashMap, DashSet};
use northstar_session_core::{
    staged_route_activation_allowed, LocalCapsEpoch, StagedRouteActivationCheck,
    StagedRouteIdentity,
};
use std::sync::{
    atomic::{AtomicU8, Ordering},
    Arc,
};
use tokio_util::sync::CancellationToken;

/// A detached view of a local route for PostgreSQL credential maintenance.
/// Pending bind and resume routes are included so they can be cancelled before
/// their final activation check; no map guard survives the database read.
pub(crate) struct LocalSessionAuthoritySnapshot {
    pub(crate) full_jid: String,
    pub(crate) authority: crate::services::session_authority_sweep::SessionAuthoritySnapshot,
    pub(crate) disconnect: CancellationToken,
}

/// Captured only after instance authority is refreshed, immediately before
/// Redis route leases are renewed. This is deliberately a second snapshot.
pub(crate) struct LocalSessionLeaseSnapshot {
    pub(crate) full_jid: String,
    pub(crate) activity_age_seconds: u64,
    pub(crate) connection_id: uuid::Uuid,
    pub(crate) disconnect: CancellationToken,
}

pub(crate) fn local_session_authority_snapshots_in(
    sessions: &DashMap<String, OnlineSession>,
) -> Vec<LocalSessionAuthoritySnapshot> {
    sessions
        .iter()
        .map(|entry| LocalSessionAuthoritySnapshot {
            full_jid: entry.key().clone(),
            authority: crate::services::session_authority_sweep::SessionAuthoritySnapshot {
                user_id: entry.user_id,
                auth_generation: entry.auth_generation,
                device_id: entry.user_agent_id,
                device_epoch: entry.user_agent_epoch,
            },
            disconnect: entry.disconnect.clone(),
        })
        .collect()
}

pub(crate) fn local_session_lease_snapshots_in(
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

pub(crate) fn try_stage_bound_session_in(
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

pub(crate) fn publish_user_agent_epoch_if_current_in(
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

pub(crate) fn activate_session_if_current_in(
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

pub(crate) fn stage_sm_resumed_session_in(
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

pub(crate) enum LocalSessionFence {
    Instance(uuid::Uuid),
    Sm(uuid::Uuid),
    Admin {
        user_id: uuid::Uuid,
        auth_generation: i64,
        connection_id: uuid::Uuid,
    },
}

pub(crate) fn local_caps_route_epoch_matches(
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

pub(crate) fn mix_presence_epoch_is_current(
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

pub(crate) fn mix_presence_fallback_is_suppressed(
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

pub(crate) fn fence_local_session_in(
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

#[cfg(test)]
pub(crate) fn cancel_local_session_if_connection_in(
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
pub(crate) enum SessionLookup {
    Bare(String),
    Full(String),
}

pub(crate) fn session_lookup(jid: &str) -> Option<SessionLookup> {
    let jid = northstar_xmpp_types::jid::CanonicalJid::parse(jid).ok()?;
    Some(if jid.resourcepart().is_some() {
        SessionLookup::Full(jid.to_string())
    } else {
        SessionLookup::Bare(jid.bare())
    })
}

pub(crate) fn session_entries_for_in(
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
