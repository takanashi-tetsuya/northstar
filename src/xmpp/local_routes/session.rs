//! Local C2S session records, the SM route-claim result and the account revocation route handle.

use crate::platform::jid_text::bare_jid;
use dashmap::{DashMap, DashSet};
use northstar_session_application::RouteIncarnationSignal;
use northstar_session_core::JoinedMucMembership;
use std::{
    sync::{
        atomic::{AtomicBool, AtomicI16, AtomicU64, AtomicU8, Ordering},
        Arc,
    },
    time::Instant,
};
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
pub struct OnlineSession {
    /// Stable database identity and credential epoch that authorized this
    /// transport.  Keeping both on the live route lets password changes and
    /// administrative disables revoke sessions across cluster nodes without
    /// accidentally terminating a newly recreated account with the same JID.
    pub user_id: uuid::Uuid,
    pub auth_generation: i64,
    pub user_agent_epoch: Option<i64>,
    pub connection_id: uuid::Uuid,
    /// Terminal, exact-incarnation route-removal notification. Every local
    /// compare-and-remove publishes through `AppState`, including rollback,
    /// cleanup and synchronous Drop paths.
    pub(crate) route_incarnation: Arc<RouteIncarnationSignal>,
    /// Shared with the owning protocol session. A successful SM takeover sets
    /// this before removing the old route so the old connection's Drop cannot
    /// suspend/revoke the replacement stream or remove its MUC/caps state.
    pub lifecycle: Arc<AtomicU8>,
    /// Prevents failure cleanup and an eventual Drop from decrementing the
    /// active-session gauge more than once.
    pub metrics_counted: Arc<AtomicBool>,
    /// False while authentication/bind or SM resumption is still committing.
    /// Pending routes may reserve a cluster key, but no stanza delivery path
    /// may expose the transport before the authoritative database commit.
    pub routable: Arc<AtomicBool>,
    pub sender: crate::xmpp::outbound::OutboundSender,
    pub available: Arc<AtomicBool>,
    /// The protocol actor's exact available/unavailable epoch. Recovery
    /// replay must reject an unavailable/available ABA on this same route.
    pub(crate) availability_generation: Arc<AtomicU64>,
    /// External replay requests join the owning actor's transport-ordered,
    /// bounded post-action supervisor rather than spawning detached work.
    pub(crate) post_actions: crate::xmpp::protocol::PostActionHandle,
    /// One recovery replay per exact route at a time; zero means idle.
    pub(crate) recovery_replay_inflight_epoch: Arc<AtomicU64>,
    /// A completed PG claim pass is coalesced only for its own recovery epoch.
    pub(crate) recovery_replay_completed_epoch: Arc<AtomicU64>,
    /// Bind 2 MAM catch-up suppresses MAM-backed offline projections.
    pub(crate) bind2_mam_catchup: bool,
    /// Per-account/resource linearization boundary for MIX presence. Explicit
    /// presence, verified-caps fallback, transport cleanup and an exact SM
    /// replacement all share this gate, so a delayed side effect cannot
    /// recreate presence after an unavailable/delete epoch. The Arc belongs
    /// to the session lifecycle; there is no process-global keyed lock table.
    pub mix_presence_gate: Arc<tokio::sync::Mutex<()>>,
    /// A successful directed MIX unavailable suppresses the conservative
    /// verified-caps fallback until a later explicit/broadcast available.
    /// Keeping this resource-scoped avoids a process-global tombstone map.
    pub mix_presence_fallback_suppressed: Arc<dashmap::DashSet<String>>,
    /// Monotonic local XEP-0115 observation epoch shared with the protocol
    /// actor and transferred only by an exact live SM replacement.
    pub caps_observation_generation: Arc<AtomicU64>,
    pub carbons: Arc<AtomicBool>,
    pub priority: Arc<AtomicI16>,
    /// Encoded XMPP `<show/>`: 0 unavailable, 1 online, 2 away, 3 chat,
    /// 4 dnd, 5 xa.  Kept per resource for PubSub subscription filtering.
    pub show: Arc<AtomicU8>,
    pub blocklist_requested: Arc<AtomicBool>,
    /// Whether this exact resource has successfully requested its roster.
    /// RFC 6121 roster pushes are sent only to interested resources, and the
    /// flag is retained across XEP-0198 session resumption.
    pub roster_requested: Arc<AtomicBool>,
    /// Per-resource initial roster synchronization fence. Committed pushes
    /// are version-buffered until the initial IQ result owns the transport.
    pub roster_sync: Arc<northstar_roster_application::RosterSyncGate>,
    /// Per-resource XEP-0405 roster annotation preference. It is deliberately
    /// not an account-wide flag: a roster get without `<annotate/>` resets it
    /// only for the requesting client.
    pub mix_roster_annotations: Arc<AtomicBool>,
    /// Session-local XEP-0016 list selection. An absent selection delegates
    /// to the durable account default.
    pub privacy_active: Arc<std::sync::RwLock<Option<String>>>,
    /// Set after this resource requests XEP-0016 state; only interested
    /// resources receive list-definition pushes.
    pub privacy_requested: Arc<AtomicBool>,
    /// RFC 6121 directed-presence recipients authorized by this exact
    /// resource for the lifetime of its presence session.
    pub directed_presence: Arc<DashSet<String>>,
    /// Last authoritative broadcast presence for RFC 6121 probes. The stanza
    /// has a server asserted `from` and no recipient-specific `to`.
    pub last_presence: Arc<std::sync::RwLock<Option<String>>>,
    pub ip: Option<std::net::IpAddr>,
    pub resource: String,
    pub user_agent_id: Option<uuid::Uuid>,
    /// Exact durable XEP-0198 epoch currently owning this transport.
    pub sm_session_id: Arc<std::sync::RwLock<Option<uuid::Uuid>>>,
    /// Exact MUC occupancies owned by this connection.  Moderation and
    /// clustered control paths share this map with the protocol actor so a
    /// kick can revoke membership immediately without waiting for the target
    /// socket to send another stanza.
    pub muc_memberships: Arc<DashMap<String, JoinedMucMembership>>,
    pub connected_at: Instant,
    pub last_activity: Arc<std::sync::RwLock<Instant>>,
    pub disconnect: CancellationToken,
}

/// Only the state needed to transfer a live SM resource's presence epoch.
pub(crate) struct SmPresenceEpoch {
    pub(crate) gate: Arc<tokio::sync::Mutex<()>>,
    pub(crate) fallback_suppressed: Arc<DashSet<String>>,
    pub(crate) caps_generation: Arc<AtomicU64>,
}

/// Result of one atomic local SM route-table inspection. Every value is owned
/// before the caller can wait on a gate, durable claim or route-removal signal.
pub(crate) enum SmStagedRouteClaim {
    Inserted,
    Conflict,
    AdoptPresenceEpoch(SmPresenceEpoch),
    Replace {
        connection_id: uuid::Uuid,
        lifecycle: Arc<AtomicU8>,
        disconnect: CancellationToken,
        route_incarnation: Arc<RouteIncarnationSignal>,
    },
}

/// The revocation worker can only fence local routes. It cannot admit,
/// replace, remove, or deliver through a session.
#[derive(Clone)]
pub(crate) struct AccountRevocationRoutes {
    pub(crate) sessions: Arc<DashMap<String, OnlineSession>>,
}

impl AccountRevocationRoutes {
    pub(crate) fn new(sessions: Arc<DashMap<String, OnlineSession>>) -> Self {
        Self { sessions }
    }

    pub(crate) fn revoke_in(
        sessions: &DashMap<String, OnlineSession>,
        user_id: uuid::Uuid,
        bare_account_jid: &str,
        auth_generation_exclusive: Option<i64>,
    ) -> usize {
        let Ok(bare_account_jid) = crate::jid::canonicalize_bare(bare_account_jid) else {
            return 0;
        };
        let mut revoked = 0;
        for entry in sessions.iter_mut() {
            if bare_jid(entry.key()) == bare_account_jid
                && entry.user_id == user_id
                && auth_generation_exclusive
                    .is_none_or(|generation| entry.auth_generation < generation)
            {
                entry.routable.store(false, Ordering::Release);
                entry.disconnect.cancel();
                revoked += 1;
            }
        }
        revoked
    }

    pub(crate) fn revoke(
        &self,
        user_id: uuid::Uuid,
        bare_account_jid: &str,
        auth_generation_exclusive: Option<i64>,
    ) -> usize {
        Self::revoke_in(
            &self.sessions,
            user_id,
            bare_account_jid,
            auth_generation_exclusive,
        )
    }

    pub(crate) fn fence_all(&self) {
        for session in self.sessions.iter_mut() {
            session.routable.store(false, Ordering::Release);
            session.disconnect.cancel();
        }
    }
}
