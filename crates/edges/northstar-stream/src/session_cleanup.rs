//! The session finalization contract. A protocol session gathers what it owns into a [`SessionCleanupPlan`]
//! and hands it to its host's [`SessionCleanup`] service, which fences the local routes synchronously, then
//! completes the bounded durable and network steps and reports what failed in a [`CleanupReport`].

use dashmap::DashMap;
use northstar_session_application::SessionCleanupAccount;
use std::future::Future;
use std::sync::{atomic::AtomicBool, Arc};
use uuid::Uuid;

#[derive(Debug)]
pub enum SessionSmCleanup {
    Suspend {
        session_id: Uuid,
        snapshot: northstar_session_application::sm::SmSessionSnapshot,
        ttl_seconds: u64,
        capacity: northstar_session_application::sm_capacity::SmCapacityLease,
    },
    Revoke {
        session_id: Uuid,
    },
    None,
}

pub struct SessionCleanupPlan {
    pub connection_id: Uuid,
    pub may_own_live_session: bool,
    pub mix_presence_gate: Arc<tokio::sync::Mutex<()>>,
    pub account: Option<SessionCleanupAccount>,
    pub registered_key: Option<String>,
    pub full_jid: Option<String>,
    pub available: Option<Arc<AtomicBool>>,
    pub active_privacy_list: Option<String>,
    pub directed_presence: Vec<String>,
    pub joined_rooms: Arc<DashMap<String, northstar_session_core::JoinedMucMembership>>,
    pub sm: SessionSmCleanup,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CleanupRecovery {
    /// An exact database lease or epoch makes a retry/expiry safe.
    LeaseOrEpoch,
    /// Periodic cluster reconciliation removes stale soft state.
    ClusterReconciliation,
    /// Presence is soft state and peers converge on reconnect/probe.
    PresenceRefresh,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CleanupFailure {
    pub operation: &'static str,
    pub recovery: CleanupRecovery,
}

#[derive(Debug, Default)]
pub struct CleanupReport {
    pub failures: Vec<CleanupFailure>,
    completed_steps: usize,
}

impl CleanupReport {
    pub fn is_clean(&self) -> bool {
        self.failures.is_empty()
    }

    /// The bounded steps that completed.
    pub fn completed_steps(&self) -> usize {
        self.completed_steps
    }

    pub fn failed(&mut self, operation: &'static str, recovery: CleanupRecovery) {
        self.failures.push(CleanupFailure {
            operation,
            recovery,
        });
    }

    pub fn completed(&mut self) {
        self.completed_steps += 1;
    }

    pub fn observe(&self, registry: &northstar_runtime::workers::WorkerRegistry) {
        if !self.is_clean() {
            registry.observer_error(
                "session-cleanup",
                format!("{} bounded cleanup steps failed", self.failures.len()),
            );
        } else if self.completed_steps > 0 {
            // Closing a transport that owned no durable or projected state
            // cannot demonstrate recovery from an earlier cleanup failure.
            registry.observer_ok("session-cleanup");
        }
    }
}

/// The finalization service a session hands its cleanup plan to.
pub trait SessionCleanup: Send + Sync {
    /// The synchronously quiesced half of one finalization.
    type Quiesced: Send;

    /// Fences the session's local routes and MUC ownership before any await.
    fn quiesce(&self, plan: SessionCleanupPlan) -> Self::Quiesced;

    /// Completes the bounded durable and network steps of a quiesced finalization.
    fn finish(&self, work: Self::Quiesced) -> impl Future<Output = CleanupReport> + Send;

    /// Removes the connection-scoped privacy selection of a session that a resumed connection superseded.
    fn clear_transferred_privacy(
        &self,
        account: Option<&SessionCleanupAccount>,
        connection_id: Uuid,
    ) -> impl Future<Output = CleanupReport> + Send;
}
