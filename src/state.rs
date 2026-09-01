use crate::{
    abuse::{AbuseConfig, AbuseGuard},
    config::Config,
    db,
    metrics::Metrics,
    s2s::FederationRouter,
    services::upload_safety::{UploadAuthorityGeneration, UploadSafetyGate},
    storage::{GuardedUploadStore, LocalUploadStore, S3UploadSettings, S3UploadStore, UploadStore},
};
use anyhow::Context;
use dashmap::{DashMap, DashSet};
use hickory_resolver::{
    config::{ResolveHosts, ServerOrderingStrategy},
    net::runtime::TokioRuntimeProvider,
    system_conf::read_system_conf,
    TokioResolver,
};
use sha2::{Digest, Sha256};
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions},
    PgPool,
};
use std::{
    collections::{HashSet, VecDeque},
    sync::{
        atomic::{AtomicBool, AtomicI16, AtomicU64, AtomicU8, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use tokio::sync::OwnedSemaphorePermit;
use tokio::sync::RwLock;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use zeroize::{Zeroize, Zeroizing};

const OMEMO_POLL_CONCURRENCY: usize = 4;
const OMEMO_POLL_IP_REQUESTS_PER_MINUTE: usize = 30;
const OMEMO_POLL_MAX_ACTIVE_IPS: usize = 65_536;

fn admit_omemo_poll_ip_window(window: &mut VecDeque<Instant>, now: Instant) -> bool {
    let cutoff = now.checked_sub(Duration::from_secs(60)).unwrap_or(now);
    while window.front().is_some_and(|seen| *seen <= cutoff) {
        window.pop_front();
    }
    if window.len() >= OMEMO_POLL_IP_REQUESTS_PER_MINUTE {
        return false;
    }
    window.push_back(now);
    true
}

fn admit_bounded_omemo_poll_ip(
    windows: &DashMap<std::net::IpAddr, VecDeque<Instant>>,
    admission: &std::sync::Mutex<()>,
    ip: std::net::IpAddr,
    now: Instant,
    sweep: bool,
    max_active_ips: usize,
) -> bool {
    let _admission = admission
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if sweep {
        let cutoff = now.checked_sub(Duration::from_secs(60)).unwrap_or(now);
        windows.retain(|_, window| {
            while window.front().is_some_and(|seen| *seen <= cutoff) {
                window.pop_front();
            }
            !window.is_empty()
        });
    }
    if !windows.contains_key(&ip) && windows.len() >= max_active_ips {
        return false;
    }
    let mut window = windows.entry(ip).or_default();
    admit_omemo_poll_ip_window(&mut window, now)
}

/// Stable, non-secret identity for the physical upload namespace shared by
/// every node. PostgreSQL stores this digest so a node configured for a
/// different bucket/prefix cannot serve or delete another node's objects.
/// Credential material is deliberately excluded: rotating credentials must
/// not change storage authority.
fn upload_storage_namespace_id(config: &Config) -> anyhow::Result<[u8; 32]> {
    fn field(digest: &mut Sha256, value: &str) {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value.as_bytes());
    }

    let mut digest = Sha256::new();
    digest.update(b"northstar/upload-storage-namespace/v2\0");
    field(&mut digest, &config.upload_storage_backend);
    if config.upload_storage_backend == "local" {
        std::fs::create_dir_all(&config.upload_dir)
            .context("could not prepare UPLOAD_DIR for storage authority")?;
        let canonical = std::fs::canonicalize(&config.upload_dir)
            .context("could not canonicalize UPLOAD_DIR for storage authority")?;
        field(&mut digest, &canonical.to_string_lossy());
    } else {
        field(
            &mut digest,
            config
                .upload_s3_endpoint
                .as_deref()
                .unwrap_or("<aws-default-endpoint>"),
        );
        field(&mut digest, &config.upload_s3_region);
        field(
            &mut digest,
            config.upload_s3_bucket.as_deref().unwrap_or_default(),
        );
        field(&mut digest, &config.upload_s3_prefix);
        digest.update([
            u8::from(config.upload_s3_path_style),
            u8::from(config.upload_s3_allow_http),
        ]);
        if let Some(kms_file) = config.upload_s3_sse_kms_key_id_file.as_deref() {
            digest.update([1]);
            let mut kms = Zeroizing::new(crate::config::read_secret_file(
                kms_file,
                "UPLOAD_S3_SSE_KMS_KEY_ID_FILE",
            )?);
            field(&mut digest, kms.as_str());
            kms.zeroize();
        } else {
            digest.update([0]);
        }
    }
    Ok(digest.finalize().into())
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CapsKey {
    pub algorithm: String,
    pub node: String,
    pub version: String,
}

/// Exact authority for one local XEP-0115 observation. The connection fence
/// prevents full-JID ABA after bind/resume, while the generation fence prevents
/// an older response or running side effect from surviving a newer presence on
/// the same transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalCapsEpoch {
    pub connection_id: uuid::Uuid,
    pub generation: u64,
}

/// Lossless lifecycle signal for one exact local route incarnation.
///
/// The sender retains the terminal state, so a waiter which subscribes after
/// the compare-and-remove has committed still observes `Removed`.  Binding the
/// signal to the connection UUID prevents a full-JID ABA replacement from
/// satisfying a waiter for the previous transport.
#[derive(Debug)]
pub(crate) struct RouteIncarnationSignal {
    connection_id: uuid::Uuid,
    removed: tokio::sync::watch::Sender<bool>,
}

impl RouteIncarnationSignal {
    pub(crate) fn new(connection_id: uuid::Uuid) -> Arc<Self> {
        let (removed, _) = tokio::sync::watch::channel(false);
        Arc::new(Self {
            connection_id,
            removed,
        })
    }

    pub(crate) fn connection_id(&self) -> uuid::Uuid {
        self.connection_id
    }

    pub(crate) fn subscribe(&self) -> tokio::sync::watch::Receiver<bool> {
        self.removed.subscribe()
    }

    fn publish_removed(&self) {
        self.removed.send_replace(true);
    }
}

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
    pub sender: crate::outbound::OutboundSender,
    pub available: Arc<AtomicBool>,
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
    pub roster_sync: Arc<crate::services::roster::RosterSyncGate>,
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

#[derive(Clone, Copy)]
struct StagedRouteIdentity {
    connection_id: uuid::Uuid,
    user_id: uuid::Uuid,
    auth_generation: i64,
}

#[derive(Clone, Copy)]
struct StagedRouteActivationCheck {
    session: StagedRouteIdentity,
    expected: StagedRouteIdentity,
    same_lifecycle: bool,
    lifecycle_state: u8,
    session_cancelled: bool,
    owner_cancelled: bool,
}

fn staged_route_activation_allowed(check: StagedRouteActivationCheck) -> bool {
    check.session.connection_id == check.expected.connection_id
        && check.session.user_id == check.expected.user_id
        && check.session.auth_generation == check.expected.auth_generation
        && check.same_lifecycle
        && check.lifecycle_state == 0
        && !check.session_cancelled
        && !check.owner_cancelled
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JoinedMucMembership {
    pub nick: String,
    pub cluster_epoch: uuid::Uuid,
}

pub(crate) fn muc_actor_identity_matches(
    occupant: &MucOccupant,
    full_jid: &str,
    connection_id: uuid::Uuid,
    room_jid: &str,
    membership: &JoinedMucMembership,
) -> bool {
    muc_actor_epoch_matches(occupant, full_jid, connection_id, room_jid, membership)
        && matches!(occupant.endpoint, MucOccupantEndpoint::Local(_))
}

fn muc_actor_epoch_matches(
    occupant: &MucOccupant,
    full_jid: &str,
    connection_id: uuid::Uuid,
    room_jid: &str,
    membership: &JoinedMucMembership,
) -> bool {
    !connection_id.is_nil()
        && !membership.cluster_epoch.is_nil()
        && occupant.full_jid == full_jid
        && occupant.room_jid == room_jid
        && occupant.nick == membership.nick
        && occupant.connection_id == connection_id
        && occupant.cluster_epoch == membership.cluster_epoch
}

pub(crate) fn muc_departure_identity_matches(
    occupant: &MucOccupant,
    full_jid: &str,
    connection_id: uuid::Uuid,
    cluster_epoch: uuid::Uuid,
) -> bool {
    !connection_id.is_nil()
        && !cluster_epoch.is_nil()
        && occupant.full_jid == full_jid
        && occupant.connection_id == connection_id
        && occupant.cluster_epoch == cluster_epoch
}

/// Exact-identity removal guard for a suspended occupancy created by the
/// calling restore: a failure path may only ever remove the endpoint it just
/// created, never a concurrent joiner's or a winning resume's occupant.
fn suspended_occupant_is_created(
    occupant: &MucOccupant,
    created: &Arc<SuspendedMucEndpoint>,
) -> bool {
    matches!(
        &occupant.endpoint,
        MucOccupantEndpoint::Suspended(endpoint) if Arc::ptr_eq(endpoint, created)
    )
}

fn suspended_muc_resume_actor_matches(
    current: &MucOccupant,
    endpoint: &Arc<SuspendedMucEndpoint>,
    full_jid: &str,
    connection_id: uuid::Uuid,
    cluster_epoch: uuid::Uuid,
    sm_session_id: uuid::Uuid,
) -> bool {
    !connection_id.is_nil()
        && !cluster_epoch.is_nil()
        && current.full_jid == full_jid
        && current.connection_id == connection_id
        && current.cluster_epoch == cluster_epoch
        && current.sm_session_id == Some(sm_session_id)
        && matches!(
            &current.endpoint,
            MucOccupantEndpoint::Suspended(current_endpoint)
                if Arc::ptr_eq(current_endpoint, endpoint)
                    && current_endpoint.sm_session_id == sm_session_id
        )
}

pub(crate) fn muc_suspended_teardown_identity_matches(
    current: &MucOccupant,
    sm_session_id: uuid::Uuid,
    expected: &SerializableMucOccupant,
) -> bool {
    !expected.cluster_epoch.is_nil()
        && !expected.connection_id.is_nil()
        && current.sm_session_id == Some(sm_session_id)
        && current.full_jid == expected.full_jid
        && current.room_jid == expected.room_jid
        && current.nick == expected.nick
        && current.cluster_epoch == expected.cluster_epoch
        && current.connection_id == expected.connection_id
        && matches!(
            &current.endpoint,
            MucOccupantEndpoint::Suspended(endpoint)
                if endpoint.sm_session_id == sm_session_id
        )
}

#[derive(Clone)]
pub enum MixIqRelayStage {
    /// A local client sent an IQ through a remote channel.  The remote MIX
    /// service must return exactly the encoded participant and requester that
    /// were registered here before the client id is restored.
    Participant {
        requester_full_jid: String,
        original_id: String,
        expected_from: String,
        channel_jid: String,
    },
    /// A locally hosted channel relayed a whitelisted read to a remote
    /// participant.  Responses are accepted only from the exact real target
    /// and are rewritten back to the encoded channel identity.
    Channel {
        requester_full_jid: String,
        requester_encoded_jid: String,
        original_id: String,
        target_real_jid: String,
        target_encoded_jid: String,
        channel_jid: String,
    },
}

#[derive(Clone)]
pub struct PendingMixIqRelay {
    pub stage: MixIqRelayStage,
    pub expires_at: Instant,
}

#[derive(Clone)]
pub enum MucOccupantEndpoint {
    Local(crate::outbound::OutboundSender),
    /// A local occupant whose transport disappeared while a durable XEP-0198
    /// resume window is open.  Traffic is bounded and moved into PostgreSQL;
    /// it is never sent into the dead transport channel.
    Suspended(Arc<SuspendedMucEndpoint>),
    Federated {
        authenticated_domain: String,
        connection_id: uuid::Uuid,
    },
}

pub struct SuspendedMucEndpoint {
    pub sm_session_id: uuid::Uuid,
    /// The synchronous route fence is present for the complete lifetime of an
    /// SM-associated resource, including while it is live.  A delivery holds
    /// this mutex through `try_send`, while disconnect changes Live to
    /// Transitioning under the same mutex.  Consequently no sender can observe
    /// the old transport after suspension has begun.
    route: std::sync::Mutex<SuspendedMucRoute>,
    buffer: tokio::sync::Mutex<SuspendedMucBuffer>,
    changed: tokio::sync::Notify,
    /// Shared actual-byte lease for the durable stream plus its process-local
    /// MUC suffix. Clones across room occupants reference one reservation.
    sm_capacity: std::sync::Mutex<Option<crate::services::sm_capacity::SmCapacityLease>>,
}

#[derive(Clone)]
enum SuspendedMucRoute {
    Live(crate::outbound::OutboundSender),
    /// A short synchronous hand-off. Deliveries wait rather than falling back
    /// to a stale occupant-local sender.
    Transitioning,
    Suspended,
}

struct SuspendedMucBuffer {
    phase: SuspendedMucPhase,
    /// True only when the exact snapshot used by a committed-or-ambiguous SM
    /// transaction already contains this buffer's suffix. Keeping ownership
    /// separate from the delivery phase preserves it across Sealed->Waiting
    /// resume races without making an error state writable.
    snapshot_owned: bool,
    /// Already-sequenced SM traffic consumes the same stanza and byte budget
    /// as this volatile suffix.  Charging it here prevents a disconnect with
    /// a nearly-full unacked queue from opening a second independent queue.
    base_stanzas: usize,
    base_bytes: usize,
    bytes: usize,
    stanzas: VecDeque<SuspendedMucStanza>,
}

#[derive(Clone)]
struct SuspendedMucStanza {
    source_id: uuid::Uuid,
    xml: String,
}

#[derive(Clone, Debug)]
enum SuspendedMucPhase {
    /// The route mutex owns the live sender; the suspended queue is empty.
    Dormant,
    /// Short synchronous hand-off from the old live route to the durable SM
    /// row.  Volatile admission is bounded by the complete SM budget.
    Collecting,
    /// PostgreSQL owns subsequent delivery and the process-local suffix is
    /// empty.
    Durable,
    /// Resume has fenced durable appends but has not yet received the current
    /// queue size from PostgreSQL. New delivery waits for the exact base.
    Waiting,
    /// One exact resume claim is collecting the final globally-ordered suffix.
    Resuming,
    /// A process-restart restore reserved the nickname but must reject traffic
    /// until its PostgreSQL CAS and SM checkpoint have both committed.
    Reserved,
    /// The suffix has been snapshotted for an atomic SM checkpoint.  No new
    /// traffic is acknowledged while the checkpoint is in flight.
    Committing,
    /// PostgreSQL owns the complete replay queue. The buffer is empty, but the
    /// route stays suspended until `<resumed/>` and replay reach the socket.
    CheckpointOwned,
    /// Fail-closed terminal/intermediate state.  Retained traffic remains
    /// available for durable promotion, but new volatile traffic is rejected.
    Sealed,
}

impl SuspendedMucBuffer {
    fn enqueue_volatile(&mut self, stanza: String, max_stanzas: usize, max_bytes: usize) -> bool {
        if !matches!(
            &self.phase,
            SuspendedMucPhase::Collecting | SuspendedMucPhase::Resuming
        ) {
            return false;
        }
        let Some(next_bytes) = self.bytes.checked_add(stanza.len()) else {
            return false;
        };
        let Some(total_stanzas) = self.base_stanzas.checked_add(self.stanzas.len() + 1) else {
            return false;
        };
        let Some(total_bytes) = self.base_bytes.checked_add(next_bytes) else {
            return false;
        };
        if total_stanzas > max_stanzas || total_bytes > max_bytes {
            return false;
        }
        self.bytes = next_bytes;
        self.stanzas.push_back(SuspendedMucStanza {
            source_id: uuid::Uuid::new_v4(),
            xml: stanza,
        });
        true
    }

    /// Remove only a stanza whose next owner has already accepted it.  Using
    /// the actual front length (rather than clearing/saturating the counter)
    /// keeps the byte bound exact after a first or mid-drain failure.
    fn commit_front(&mut self) {
        let stanza = self
            .stanzas
            .pop_front()
            .expect("a suspended MUC drain can commit only its current front");
        self.bytes = self
            .bytes
            .checked_sub(stanza.xml.len())
            .expect("suspended MUC byte accounting must match its queue");
    }
}

/// Promote the process-local suspension prefix to PostgreSQL in strict FIFO
/// order.  The caller owns the endpoint mutex for the complete operation, so
/// a concurrently arriving stanza can neither overtake this prefix nor race a
/// resume claim. A failed append leaves that exact stanza and every successor
/// in the buffer; only successfully committed rows are removed.
async fn promote_suspended_muc_buffer<F, Fut>(
    buffer: &mut SuspendedMucBuffer,
    mut append: F,
) -> bool
where
    F: FnMut(uuid::Uuid, String) -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    buffer.phase = SuspendedMucPhase::Sealed;
    while let Some(stanza) = buffer.stanzas.front().cloned() {
        if !append(stanza.source_id, stanza.xml).await {
            return false;
        }
        buffer.commit_front();
    }
    buffer.base_stanzas = 0;
    buffer.base_bytes = 0;
    buffer.snapshot_owned = false;
    buffer.phase = SuspendedMucPhase::Durable;
    true
}

/// Seal one session-global FIFO and clone its exact suffix for a prospective
/// SM checkpoint.  Ownership is deliberately not transferred here: if the
/// checkpoint or capacity validation fails, the original endpoint still owns
/// every byte and cleanup can promote it durably.
async fn snapshot_suspended_muc_buffer_for_resume(
    endpoint: &SuspendedMucEndpoint,
) -> Option<Vec<String>> {
    let mut buffer = endpoint.buffer.lock().await;
    if !matches!(
        &buffer.phase,
        SuspendedMucPhase::Resuming | SuspendedMucPhase::Reserved | SuspendedMucPhase::Sealed
    ) {
        return None;
    }
    buffer.phase = SuspendedMucPhase::Committing;
    Some(if buffer.snapshot_owned {
        Vec::new()
    } else {
        buffer
            .stanzas
            .iter()
            .map(|stanza| stanza.xml.clone())
            .collect()
    })
}

async fn seal_suspended_muc_buffer(endpoint: &SuspendedMucEndpoint) {
    let mut buffer = endpoint.buffer.lock().await;
    if !matches!(&buffer.phase, SuspendedMucPhase::Dormant) {
        buffer.phase = SuspendedMucPhase::Sealed;
    }
    drop(buffer);
    finalize_suspended_muc_route_transition(endpoint);
    endpoint.changed.notify_waiters();
}

fn finalize_suspended_muc_route_transition(endpoint: &SuspendedMucEndpoint) {
    let mut route = endpoint
        .route
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if matches!(&*route, SuspendedMucRoute::Transitioning) {
        *route = SuspendedMucRoute::Suspended;
    }
}

fn begin_suspended_muc_route_transition(
    endpoint: &SuspendedMucEndpoint,
    base_stanzas: usize,
    base_bytes: usize,
) {
    let transition_from_live = {
        let mut route = endpoint
            .route
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if matches!(&*route, SuspendedMucRoute::Live(_)) {
            *route = SuspendedMucRoute::Transitioning;
            true
        } else {
            false
        }
    };
    if !transition_from_live {
        return;
    }
    // The ordinary live state has an idle buffer. If a post-replay commit
    // currently owns it, keep the route fenced as Transitioning; that commit
    // observes the fence and refuses Live publication, while async cleanup
    // seals/finalizes the transition after the mutex is released.
    if let Ok(mut buffer) = endpoint.buffer.try_lock() {
        buffer.phase = SuspendedMucPhase::Collecting;
        buffer.base_stanzas = base_stanzas;
        buffer.base_bytes = base_bytes;
        buffer.bytes = 0;
        buffer.stanzas.clear();
        buffer.snapshot_owned = false;
        drop(buffer);
        finalize_suspended_muc_route_transition(endpoint);
        endpoint.changed.notify_waiters();
    }
}

fn transfer_muc_suffix_to_checkpoint(buffer: &mut SuspendedMucBuffer) -> bool {
    if !matches!(&buffer.phase, SuspendedMucPhase::Committing) {
        return false;
    }
    buffer.stanzas.clear();
    buffer.bytes = 0;
    buffer.base_stanzas = 0;
    buffer.base_bytes = 0;
    buffer.snapshot_owned = true;
    buffer.phase = SuspendedMucPhase::CheckpointOwned;
    true
}

fn complete_snapshot_owned_handoff(buffer: &mut SuspendedMucBuffer) -> bool {
    if !buffer.snapshot_owned {
        return false;
    }
    buffer.stanzas.clear();
    buffer.bytes = 0;
    buffer.base_stanzas = 0;
    buffer.base_bytes = 0;
    buffer.snapshot_owned = false;
    buffer.phase = SuspendedMucPhase::Durable;
    true
}

/// Add the volatile MUC suffix to the exact XEP-0198 snapshot which will be
/// committed by the same suspension transaction.  Validation is completed
/// before either counter or queue is mutated, so an invariant failure leaves
/// the caller's original snapshot intact and the endpoint remains its owner.
fn append_suspended_muc_suffix_to_snapshot(
    snapshot: &mut crate::services::sm::SmSessionSnapshot,
    suffix: &VecDeque<SuspendedMucStanza>,
    max_stanzas: usize,
    max_bytes: usize,
) -> anyhow::Result<()> {
    let total_stanzas = snapshot
        .unacked
        .len()
        .checked_add(suffix.len())
        .context("SM stanza count overflow while fencing a MUC disconnect")?;
    let existing_bytes = snapshot
        .unacked
        .iter()
        .try_fold(0usize, |total, entry| total.checked_add(entry.stanza.len()))
        .context("SM byte count overflow while fencing a MUC disconnect")?;
    let total_bytes = suffix.iter().try_fold(existing_bytes, |total, stanza| {
        total.checked_add(stanza.xml.len())
    });
    let total_bytes =
        total_bytes.context("MUC suffix byte count overflow while fencing a disconnect")?;
    anyhow::ensure!(
        total_stanzas <= max_stanzas && total_bytes <= max_bytes,
        "MUC disconnect suffix exceeds the global SM replay budget"
    );

    for stanza in suffix {
        snapshot.outbound_h = snapshot.outbound_h.wrapping_add(1);
        snapshot
            .unacked
            .push(crate::outbound::SmUnackedStanza::with_delivery(
                stanza.xml.clone(),
                None,
            ));
    }
    Ok(())
}

impl SuspendedMucEndpoint {
    #[cfg(test)]
    pub fn new(sm_session_id: uuid::Uuid) -> Self {
        Self::new_collecting(sm_session_id, 0, 0)
    }

    fn new_live(sm_session_id: uuid::Uuid, sender: crate::outbound::OutboundSender) -> Self {
        Self {
            sm_session_id,
            route: std::sync::Mutex::new(SuspendedMucRoute::Live(sender)),
            buffer: tokio::sync::Mutex::new(SuspendedMucBuffer {
                phase: SuspendedMucPhase::Dormant,
                snapshot_owned: false,
                base_stanzas: 0,
                base_bytes: 0,
                bytes: 0,
                stanzas: VecDeque::new(),
            }),
            changed: tokio::sync::Notify::new(),
            sm_capacity: std::sync::Mutex::new(None),
        }
    }

    fn new_collecting(sm_session_id: uuid::Uuid, base_stanzas: usize, base_bytes: usize) -> Self {
        Self {
            sm_session_id,
            route: std::sync::Mutex::new(SuspendedMucRoute::Suspended),
            buffer: tokio::sync::Mutex::new(SuspendedMucBuffer {
                phase: SuspendedMucPhase::Collecting,
                snapshot_owned: false,
                base_stanzas,
                base_bytes,
                bytes: 0,
                stanzas: VecDeque::new(),
            }),
            changed: tokio::sync::Notify::new(),
            sm_capacity: std::sync::Mutex::new(None),
        }
    }

    fn new_reserved(sm_session_id: uuid::Uuid, base_stanzas: usize, base_bytes: usize) -> Self {
        Self {
            sm_session_id,
            route: std::sync::Mutex::new(SuspendedMucRoute::Suspended),
            buffer: tokio::sync::Mutex::new(SuspendedMucBuffer {
                phase: SuspendedMucPhase::Reserved,
                snapshot_owned: false,
                base_stanzas,
                base_bytes,
                bytes: 0,
                stanzas: VecDeque::new(),
            }),
            changed: tokio::sync::Notify::new(),
            sm_capacity: std::sync::Mutex::new(None),
        }
    }

    fn new_durable(sm_session_id: uuid::Uuid) -> Self {
        Self {
            sm_session_id,
            route: std::sync::Mutex::new(SuspendedMucRoute::Suspended),
            buffer: tokio::sync::Mutex::new(SuspendedMucBuffer {
                phase: SuspendedMucPhase::Durable,
                snapshot_owned: false,
                base_stanzas: 0,
                base_bytes: 0,
                bytes: 0,
                stanzas: VecDeque::new(),
            }),
            changed: tokio::sync::Notify::new(),
            sm_capacity: std::sync::Mutex::new(None),
        }
    }
}

/// Publish or adopt the one process-local route gate for an exact SM epoch.
/// Callers may have observed a miss before asynchronous database work; the
/// entry operation is the only publication point and can never replace a gate
/// installed by a concurrent join, disconnect, or winning resume.
fn canonical_suspended_muc_endpoint(
    registry: &DashMap<uuid::Uuid, Arc<SuspendedMucEndpoint>>,
    sm_session_id: uuid::Uuid,
    proposed: Arc<SuspendedMucEndpoint>,
) -> Arc<SuspendedMucEndpoint> {
    match registry.entry(sm_session_id) {
        dashmap::mapref::entry::Entry::Vacant(slot) => {
            slot.insert(Arc::clone(&proposed));
            proposed
        }
        dashmap::mapref::entry::Entry::Occupied(slot) => Arc::clone(slot.get()),
    }
}

/// Restore publication is insert-only. A joiner or another exact resume that
/// won while this task awaited PostgreSQL remains authoritative.
fn insert_restored_muc_occupant(
    occupants: &DashMap<String, MucOccupant>,
    key: String,
    occupant: MucOccupant,
) -> bool {
    match occupants.entry(key) {
        dashmap::mapref::entry::Entry::Vacant(slot) => {
            slot.insert(occupant);
            true
        }
        dashmap::mapref::entry::Entry::Occupied(_) => false,
    }
}

/// Result of reattaching one resumed XEP-0198 stream's local MUC occupancies:
/// the memberships which could not be proven valid, plus the volatile
/// suspension FIFO in exact order. The caller must emit the suffix strictly
/// after `<resumed/>` and the durable unacked replay so suspended-room
/// traffic never overtakes older sequenced stanzas.
pub struct RestoredLocalMucOccupants {
    pub failures: Vec<crate::services::sm::SmMucMembership>,
    pub replay_suffix: Vec<String>,
    resume_gate: Option<Arc<SuspendedMucEndpoint>>,
    actors: Vec<RestoredMucActor>,
}

pub(crate) struct RestoreLocalMucOccupantsRequest<'a> {
    pub(crate) user: &'a crate::services::authentication::AuthenticatedAccount,
    pub(crate) full_jid: &'a str,
    pub(crate) connection_id: uuid::Uuid,
    pub(crate) sm_session_id: uuid::Uuid,
    pub(crate) memberships: &'a [crate::services::sm::SmMucMembership],
    pub(crate) base_stanzas: usize,
    pub(crate) base_bytes: usize,
}

#[derive(Clone)]
struct RestoredMucActor {
    key: String,
    full_jid: String,
    connection_id: uuid::Uuid,
    cluster_epoch: uuid::Uuid,
    sm_session_id: uuid::Uuid,
    endpoint: Arc<SuspendedMucEndpoint>,
    membership: crate::services::sm::SmMucMembership,
    resumed_cluster_target: Option<db::ClusterMucOccupancyTarget>,
}

impl RestoredLocalMucOccupants {
    pub(crate) fn planned_memberships(&self) -> Vec<crate::services::sm::SmMucMembership> {
        self.actors
            .iter()
            .map(|actor| actor.membership.clone())
            .collect()
    }

    pub(crate) fn planned_joined_rooms(&self) -> Vec<(String, JoinedMucMembership)> {
        self.actors
            .iter()
            .map(|actor| {
                (
                    actor.membership.room_jid.clone(),
                    JoinedMucMembership {
                        nick: actor.membership.nick.clone(),
                        cluster_epoch: actor.cluster_epoch,
                    },
                )
            })
            .collect()
    }
}

pub(crate) struct CommittedLocalMucResume {
    pub(crate) joined_rooms: Vec<(String, JoinedMucMembership)>,
    pub(crate) failures: Vec<crate::services::sm::SmMucMembership>,
}

#[derive(Clone)]
pub struct MucOccupant {
    pub full_jid: String,
    pub room_jid: String,
    pub nick: String,
    pub endpoint: MucOccupantEndpoint,
    pub affiliation: String,
    pub role: String,
    pub room_non_anonymous: bool,
    pub occupant_id: String,
    /// Per-occupancy ABA guard used for atomic nickname changes in Redis.
    /// This value is internal and is never exposed in XMPP stanzas.
    pub cluster_epoch: uuid::Uuid,
    /// Exact transport incarnation which owns this occupancy.  A resumed SM
    /// stream updates this value while preserving the occupancy epoch; a
    /// recreated post-crash occupancy receives a fresh epoch.
    pub connection_id: uuid::Uuid,
    /// Durable stream epoch owning this local occupant, when XEP-0198
    /// resumption is enabled.
    pub sm_session_id: Option<uuid::Uuid>,
    pub payload: String,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct SerializableMucOccupant {
    pub full_jid: String,
    pub room_jid: String,
    pub nick: String,
    pub affiliation: String,
    pub role: String,
    pub room_non_anonymous: bool,
    #[serde(default)]
    pub occupant_id: String,
    #[serde(default)]
    pub cluster_epoch: uuid::Uuid,
    #[serde(default)]
    pub connection_id: uuid::Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub federated_domain: Option<String>,
    /// Internal cluster ownership epoch for a suspended XEP-0198 actor. It is
    /// never rendered into an XMPP stanza.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sm_session_id: Option<uuid::Uuid>,
    pub payload: String,
}

impl From<&MucOccupant> for SerializableMucOccupant {
    fn from(occ: &MucOccupant) -> Self {
        Self {
            full_jid: occ.full_jid.clone(),
            room_jid: occ.room_jid.clone(),
            nick: occ.nick.clone(),
            affiliation: occ.affiliation.clone(),
            role: occ.role.clone(),
            room_non_anonymous: occ.room_non_anonymous,
            occupant_id: occ.occupant_id.clone(),
            cluster_epoch: occ.cluster_epoch,
            connection_id: occ.connection_id,
            federated_domain: match &occ.endpoint {
                MucOccupantEndpoint::Local(_) | MucOccupantEndpoint::Suspended(_) => None,
                MucOccupantEndpoint::Federated {
                    authenticated_domain,
                    ..
                } => Some(authenticated_domain.clone()),
            },
            sm_session_id: occ.sm_session_id,
            payload: occ.payload.clone(),
        }
    }
}

struct FederationWritePolicy {
    gate: RwLock<()>,
    island_mode: AtomicBool,
}

impl FederationWritePolicy {
    fn new(island_mode: bool) -> Self {
        Self {
            gate: RwLock::new(()),
            island_mode: AtomicBool::new(island_mode),
        }
    }

    fn enabled(&self) -> bool {
        self.island_mode.load(Ordering::Acquire)
    }

    async fn apply(&self, enabled: bool) {
        let _write_guard = self.gate.write().await;
        self.island_mode.store(enabled, Ordering::Release);
    }

    async fn permit(&self) -> Option<tokio::sync::RwLockReadGuard<'_, ()>> {
        let guard = self.gate.read().await;
        (!self.island_mode.load(Ordering::Acquire)).then_some(guard)
    }

    async fn refresh(&self, enabled: bool) -> bool {
        let _write_guard = self.gate.write().await;
        self.island_mode.swap(enabled, Ordering::AcqRel)
    }
}

pub struct AppState {
    pub config: Config,
    pub pool: PgPool,
    /// Narrow persistence/orchestration capability for XEP-0060 and PEP.
    /// Protocol handlers receive this service rather than database authority.
    pubsub_service: crate::services::pubsub::PubSubService,
    /// Account-scoped vCard/vCard4/avatar mutation and public-profile read
    /// boundary. Profile transactions and authorization never cross into the
    /// XMPP protocol layer.
    profile_service: crate::services::profile::ProfileService,
    /// XEP-0215 TURN credential authority. Long-lived key material and its
    /// bounded rate windows never cross into protocol or public state.
    extdisco_service: crate::services::extdisco::ExtDiscoService,
    /// PostgreSQL-authoritative MUC application service. Redis capabilities
    /// deliberately do not cross this boundary.
    muc_service: crate::services::muc::MucService,
    /// Personal-message authorization and durable admission boundary. The
    /// protocol layer must not compose its own archive/outbox/offline writes.
    message_service: crate::services::messaging::MessageService,
    /// XEP-0424/XEP-0444 tombstone, action archive and federation admission
    /// transaction boundary.
    retraction_service: crate::services::retractions::RetractionService,
    mam_service: crate::services::mam::MamService,
    mix_service: crate::services::mix::MixService,
    sm_service: crate::services::sm::SmService,
    blocking_service: crate::services::blocking::BlockingService,
    presence_service: crate::services::presence::PresenceService,
    replay_service: crate::services::replay::ReplayService,
    roster_service: crate::services::roster::RosterService,
    privacy_service: crate::services::privacy::PrivacyService,
    private_storage_service: crate::services::private_storage::PrivateStorageService,
    account_service: crate::services::account::AccountService,
    /// Credential lookup, verification and XEP-0484 mutation authority. The
    /// protocol layer receives typed outcomes but neither PgPool nor the FAST
    /// derivation key.
    authentication_service: crate::services::authentication::AuthenticationService,
    /// XEP-0050/XEP-0133 session and execution authority. Protocol handlers
    /// never receive the backing PostgreSQL pool through this capability.
    admin_command_service: crate::services::admin_commands::AdminCommandService,
    push_service: crate::services::push::PushService,
    pub cluster: crate::cluster::ClusterManager,
    bosh: crate::bosh::BoshManager,
    pub sessions: DashMap<String, OnlineSession>,
    pub muc_occupants: DashMap<String, MucOccupant>,
    /// Exactly one process-local suspension/resume FIFO per durable SM
    /// session.  Every room occupancy for the same client points at this Arc,
    /// preserving cross-room arrival order and enforcing one shared budget.
    suspended_muc_sessions: DashMap<uuid::Uuid, Arc<SuspendedMucEndpoint>>,
    /// Supervised retry ownership for an exact SM suspension whose database
    /// outcome was an error or timeout. The corresponding MUC FIFO remains
    /// sealed until this queue proves a durable handoff.
    sm_suspension_recovery: Arc<crate::services::session_cleanup::SmSuspensionRecoveryQueue>,
    sm_memory_governor: Arc<crate::services::sm_capacity::SmMemoryGovernor>,
    pub metrics: Metrics,
    /// Optional credential for the dedicated observability listener. Callers
    /// can ask for an authorization decision but cannot read the token.
    metrics_bearer_token: Option<Arc<Zeroizing<String>>>,
    /// A fail-closed, read-only-sized pool for the unauthenticated poll
    /// capability. It cannot consume the primary 32-connection application
    /// pool during a capability flood.
    omemo_recovery_poll_pool: PgPool,
    api_control: db::ApiControlKeyring,
    /// Opaque REST pagination cursors use purpose-separated subkeys derived
    /// from the same current/previous process secrets as API idempotency.
    /// Keeping both keyrings on the state makes rotation atomic at startup:
    /// cursors issued with the previous secret remain valid only for the
    /// configured overlap window enforced by the cursor token lifetime.
    api_cursor: crate::api::cursor::CursorKeyring,
    /// XEP-0363 bearer-token and capacity admission authority. Protocol code
    /// receives typed slot outcomes, never the PostgreSQL pool.
    upload_service: crate::services::upload::UploadService,
    upload_store: Arc<dyn UploadStore>,
    upload_storage_namespace_sha256: [u8; 32],
    upload_authority_generation: UploadAuthorityGeneration,
    upload_safety_gate: Arc<UploadSafetyGate>,
    pub federation: FederationRouter,
    /// Full XEP-0114/XEP-0225 authentication records. `config.components`
    /// retains only redacted routing/discovery metadata after construction.
    component_credentials: Arc<[crate::config::ComponentCredential]>,
    components: crate::components::ComponentRegistry,
    s2s_connection_registry: crate::s2s::S2sConnectionRegistry,
    /// Shared TTL-aware resolver for SRV, CNAME, A and AAAA federation lookups.
    s2s_dns_resolver: TokioResolver,
    /// Separate locally validating DNSSEC resolver for RFC 7712. It never
    /// consults the hosts file and is absent when DANE is disabled, ensuring
    /// that an ordinary resolver answer can never be mistaken for secure
    /// TLSA material.
    s2s_dnssec_resolver: Option<TokioResolver>,
    /// XEP-0403 IQ relay correlations. Keys are server-generated opaque IQ
    /// ids, never client-controlled ids; entries are bounded and short-lived.
    pending_mix_iq: crate::xmpp::protocol::mix::MixIqRelayIndex,
    /// XEP-0115 entries are inserted only after the advertised verification
    /// string has been recomputed successfully. Unverified payloads never
    /// enter this shared cache.
    caps_cache: crate::xmpp::protocol::caps::CapsCacheIndex,
    caps_by_jid: crate::xmpp::protocol::caps::CapsResourceIndex,
    pending_caps: crate::xmpp::protocol::caps::PendingCapsIndex,
    /// Cross-stream ordering authority for one authenticated federated full
    /// JID's capability lifecycle. Weak, self-cleaning entries exist only
    /// while an observer or response owns or waits for the resource.
    federated_caps_gates: crate::xmpp::protocol::caps::FederatedCapsGateIndex,
    /// Bounded, per-full-JID single-flight boundary for XEP-0115-triggered
    /// PEP last-item delivery and verified MIX presence publication.
    caps_effect_dispatcher: Arc<crate::xmpp::protocol::caps::CapsEffectDispatcher>,
    dialback_secret: Zeroizing<Vec<u8>>,
    /// XEP-0484 token derivation key. PostgreSQL contains only derived token
    /// hashes and public diversification data.
    fast_token_secret: Arc<Zeroizing<Vec<u8>>>,
    dialback_verifications: Arc<Semaphore>,
    client_connections: Arc<Semaphore>,
    client_connections_by_ip: DashMap<std::net::IpAddr, usize>,
    /// HTTP upload hashing and local-file I/O are bounded independently from
    /// sockets so a valid capability cannot monopolize CPU or disk bandwidth.
    upload_requests: Arc<Semaphore>,
    upload_requests_by_ip: DashMap<std::net::IpAddr, usize>,
    upload_downloads: Arc<Semaphore>,
    upload_downloads_by_ip: DashMap<std::net::IpAddr, usize>,
    /// The unauthenticated OMEMO source completion capability is bounded
    /// independently from the general API and database pool. Keys are trusted-
    /// proxy-resolved IP addresses and expire from the one-minute window.
    omemo_recovery_poll_requests: Arc<Semaphore>,
    omemo_recovery_poll_requests_by_ip: DashMap<std::net::IpAddr, VecDeque<Instant>>,
    omemo_recovery_poll_ip_admission: std::sync::Mutex<()>,
    omemo_recovery_poll_request_checks: AtomicU64,
    s2s_connections: Arc<Semaphore>,
    s2s_connection_attempts: Arc<Semaphore>,
    component_connections: Arc<Semaphore>,
    connection_actors: crate::connection_actors::ConnectionActorRegistry,
    pub abuse: AbuseGuard,
    /// Public, irreversible key IDs and the configured generation used by the
    /// readiness path to detect a node that drifted from PostgreSQL authority.
    abuse_key_deployment: Option<db::AbuseKeyDeploymentIdentity>,
    started_at: Instant,
    process_started_at: chrono::DateTime<chrono::Utc>,
    pub tls: std::sync::Arc<crate::tls::ReloadableTlsConfig>,
    /// Linearization gate for the federation kill switch. Application
    /// stanza writes hold a read guard only across the socket write; island
    /// mode transitions take the exclusive guard.
    federation_write_policy: FederationWritePolicy,
    registration_closed: AtomicBool,
    /// Durable XEP-0133 federation policy overlay. Static environment policy
    /// remains the outer ceiling; runtime rules may only restrict it further.
    federation_runtime_policy: arc_swap::ArcSwap<RuntimeFederationPolicy>,
    service_shutdown: std::sync::OnceLock<CancellationToken>,
    workers: Arc<crate::workers::WorkerRegistry>,
}

#[derive(Default)]
struct RuntimeFederationPolicy {
    blacklist: std::collections::HashSet<String>,
    whitelist: std::collections::HashSet<String>,
}

fn federation_rule_matches(rule: &str, entity: &crate::jid::CanonicalJid) -> bool {
    crate::jid::CanonicalJid::parse(rule).is_ok_and(|rule| {
        if rule.domainpart() != entity.domainpart() {
            false
        } else if rule.localpart().is_none() {
            true
        } else if rule.resourcepart().is_none() {
            rule.bare() == entity.bare()
        } else {
            rule == *entity
        }
    })
}

fn service_control_applies(
    process_started_at: chrono::DateTime<chrono::Utc>,
    control: &db::DurableServiceControl,
) -> bool {
    control
        .fired_at
        .is_some_and(|fired_at| process_started_at < fired_at)
}

#[derive(Debug, Eq, PartialEq)]
enum SessionLookup {
    Bare(String),
    Full(String),
}

fn session_lookup(jid: &str) -> Option<SessionLookup> {
    let jid = crate::jid::CanonicalJid::parse(jid).ok()?;
    Some(if jid.resourcepart().is_some() {
        SessionLookup::Full(jid.to_string())
    } else {
        SessionLookup::Bare(jid.bare())
    })
}

fn api_keyrings(
    current_secret: &[u8],
    previous_secret: Option<&[u8]>,
) -> anyhow::Result<(db::ApiControlKeyring, crate::api::cursor::CursorKeyring)> {
    let api_control = db::ApiControlKeyring::new(current_secret, previous_secret)
        .context("failed to derive API control keys")?;
    let api_cursor = crate::api::cursor::CursorKeyring::new(current_secret, previous_secret)
        .context("failed to derive API cursor keys")?;
    Ok((api_control, api_cursor))
}

fn encode_api_control_entropy(mut entropy: [u8; 32]) -> [u8; 64] {
    const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = [0_u8; 64];
    for (index, byte) in entropy.iter().copied().enumerate() {
        encoded[index * 2] = LOWER_HEX[usize::from(byte >> 4)];
        encoded[index * 2 + 1] = LOWER_HEX[usize::from(byte & 0x0f)];
    }
    entropy.zeroize();
    encoded
}

fn ephemeral_api_control_secret() -> [u8; 64] {
    use rand::RngCore;

    let mut entropy = [0_u8; 32];
    rand::thread_rng().fill_bytes(&mut entropy);
    encode_api_control_entropy(entropy)
}

impl AppState {
    /// Process-local XEP-0124/XEP-0206 session authority. Transport handlers
    /// may submit bounded manager operations but cannot replace the manager.
    pub(crate) fn bosh_manager(&self) -> &crate::bosh::BoshManager {
        &self.bosh
    }

    /// Cached ordinary DNS resolver used only by the federation discovery
    /// layer. Keeping it private prevents unrelated code from bypassing the
    /// S2S endpoint-validation path.
    pub(crate) fn s2s_dns_resolver(&self) -> &TokioResolver {
        &self.s2s_dns_resolver
    }

    /// Locally validating resolver dedicated to DANE policy construction.
    pub(crate) fn s2s_dnssec_resolver(&self) -> Option<&TokioResolver> {
        self.s2s_dnssec_resolver.as_ref()
    }

    /// Admit one bounded authoritative dialback verification without exposing
    /// or allowing replacement of the underlying global semaphore.
    pub(crate) fn try_acquire_dialback_verification(
        &self,
    ) -> std::result::Result<OwnedSemaphorePermit, tokio::sync::TryAcquireError> {
        Arc::clone(&self.dialback_verifications).try_acquire_owned()
    }

    /// Admit one process-local federation connection while keeping the global
    /// capacity semaphore replace-proof and unavailable to unrelated code.
    pub(crate) fn try_acquire_s2s_connection(
        &self,
    ) -> std::result::Result<OwnedSemaphorePermit, tokio::sync::TryAcquireError> {
        Arc::clone(&self.s2s_connections).try_acquire_owned()
    }

    /// Wait for one bounded outbound federation dial attempt. Returning the
    /// original acquire error preserves the caller's existing timeout and
    /// closed-semaphore diagnostics.
    pub(crate) async fn acquire_s2s_connection_attempt(
        &self,
    ) -> std::result::Result<OwnedSemaphorePermit, tokio::sync::AcquireError> {
        Arc::clone(&self.s2s_connection_attempts)
            .acquire_owned()
            .await
    }

    /// Owner-fenced process-local S2S route registry. Its API returns cloned
    /// senders and value snapshots only; callers cannot obtain DashMap guards.
    pub(crate) fn s2s_connection_registry(&self) -> &crate::s2s::S2sConnectionRegistry {
        &self.s2s_connection_registry
    }

    /// Admit an inbound component socket without exposing the semaphore as a
    /// generally clonable capability.
    pub(crate) fn try_acquire_component_connection(
        &self,
    ) -> std::result::Result<OwnedSemaphorePermit, tokio::sync::TryAcquireError> {
        Arc::clone(&self.component_connections).try_acquire_owned()
    }

    /// Wait for a component slot while preserving cancellation through the
    /// caller's `select!` and the original closed-semaphore error.
    pub(crate) async fn acquire_component_connection(
        &self,
    ) -> std::result::Result<OwnedSemaphorePermit, tokio::sync::AcquireError> {
        Arc::clone(&self.component_connections)
            .acquire_owned()
            .await
    }

    /// Monotonic process uptime. Callers cannot observe or replace the raw
    /// start instant, which keeps wall-clock and lifecycle concerns separate.
    pub(crate) fn uptime(&self) -> Duration {
        self.started_at.elapsed()
    }

    /// Read the federation kill switch with acquire ordering so a caller that
    /// observes an applied value also observes the preceding policy update.
    pub(crate) fn island_mode_enabled(&self) -> bool {
        self.federation_write_policy.enabled()
    }

    /// Apply an authoritative island-mode value with the release ordering used
    /// by runtime administration.
    pub(crate) async fn apply_island_mode(&self, enabled: bool) {
        self.federation_write_policy.apply(enabled).await;
    }

    /// Acquire the application-stanza write boundary and revalidate island
    /// mode after route admission. The caller holds the returned guard over
    /// the socket write, making a completed policy transition linearizable.
    pub(crate) async fn federation_delivery_permit(
        &self,
    ) -> Option<tokio::sync::RwLockReadGuard<'_, ()>> {
        self.federation_write_policy.permit().await
    }

    /// Refresh the cached island-mode value and return the previous value.
    /// The exclusive delivery guard waits for any in-flight stanza write and
    /// blocks queued writers until they can observe the new policy.
    async fn refresh_island_mode(&self, enabled: bool) -> bool {
        self.federation_write_policy.refresh(enabled).await
    }

    /// Read the public-registration kill switch with acquire ordering.
    pub(crate) fn registration_is_closed(&self) -> bool {
        self.registration_closed.load(Ordering::Acquire)
    }

    /// Apply the authoritative registration setting with release ordering.
    pub(crate) fn apply_registration_closed(&self, closed: bool) {
        self.registration_closed.store(closed, Ordering::Release);
    }

    /// Evaluate one resource's session-local XEP-0016 selection (or the
    /// account default when no active list is selected). Callers must apply
    /// XEP-0191 first; a blocking hit is never overridden by an allow rule.
    /// Stanza paths that still hold a storage-level kind convert it at this
    /// boundary; the service layer owns the mapping.
    pub async fn privacy_allows_session(
        &self,
        session: &OnlineSession,
        peer: &str,
        kind: impl Into<crate::services::privacy::PrivacyStanzaKind>,
    ) -> anyhow::Result<bool> {
        let active = session
            .privacy_active
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        self.message_service
            .privacy_allows_session(
                session.user_id,
                session.connection_id,
                active.as_deref(),
                peer,
                kind.into(),
            )
            .await
    }

    pub async fn new(
        mut config: Config,
        pool: PgPool,
        federation: FederationRouter,
        components: crate::components::ComponentRegistry,
        worker_cancel: CancellationToken,
    ) -> anyhow::Result<Arc<Self>> {
        // This one-shot credential was consumed by ensure_bootstrap_admin
        // before AppState construction. Never retain it on shared state.
        if let Some(mut password) = config.raw.bootstrap_admin_password.take() {
            password.zeroize();
        }
        let metrics_bearer_token = config.metrics_bearer_token.take();
        let component_credentials: Arc<[crate::config::ComponentCredential]> =
            std::mem::take(&mut config.components).into();
        config.components = component_credentials
            .iter()
            .cloned()
            .map(|mut credential| {
                credential.secret_value = None;
                credential.secret_file = None;
                credential.secret_sha256.zeroize();
                credential
            })
            .collect();
        let mut previous_api_control_secret = config.api_control_previous_secret.take();
        let (api_control, api_cursor) = if let Some(mut current_secret) =
            config.api_control_secret.take()
        {
            let keyrings = api_keyrings(
                current_secret.as_bytes(),
                previous_api_control_secret.as_deref().map(str::as_bytes),
            );
            current_secret.zeroize();
            if let Some(previous_secret) = &mut previous_api_control_secret {
                previous_secret.zeroize();
            }
            keyrings?
        } else {
            anyhow::ensure!(
                config.api_control_allow_ephemeral
                    && config.redis_url.is_none()
                    && config.http_bind.ip().is_loopback()
                    && (config.domain == "localhost"
                        || config.domain.ends_with(".localhost")
                        || config.domain.ends_with(".test")),
                "API_CONTROL_SECRET_FILE is required outside an explicitly opted-in single-node loopback development deployment"
            );
            tracing::warn!(
                "API_CONTROL_SECRET_FILE is unset; REST idempotency and pagination cursors use a process-local key, so encrypted replays and issued cursors will not survive restart"
            );
            // Generate exactly one process-local root secret, then derive the
            // independent API-control and cursor subkeys from it. Generating
            // inside either keyring would make their lifetimes diverge. Encode
            // the 256-bit entropy as lowercase hex because mounted text
            // secrets and both keyrings deliberately reject NUL bytes.
            let mut process_secret = ephemeral_api_control_secret();
            let keyrings = api_keyrings(&process_secret, None);
            process_secret.zeroize();
            keyrings?
        };
        db::audit_mix_delivery_capacity_ledger(&pool)
            .await
            .context("MIX delivery capacity ledger failed startup reconciliation")?;
        db::audit_mix_pam_operation_capacity(&pool)
            .await
            .context("MIX-PAM operation capacity authority failed startup audit")?;
        let upload_safety_gate = UploadSafetyGate::new();
        let upload_namespace = upload_storage_namespace_id(&config)?;
        let namespace_generation = db::validate_upload_storage_backend(
            &pool,
            &config.upload_storage_backend,
            &upload_namespace,
        )
        .await
        .context("upload storage backend does not match durable metadata")?;
        let (capacity_policy_generation, recovery_draining) = db::validate_upload_capacity_policy(
            &pool,
            config.upload_storage_max_pending_jobs,
            config.upload_storage_max_retained_files,
            config.upload_storage_max_retained_bytes,
        )
        .await
        .context("upload capacity policy does not match durable deployment authority")?;
        let upload_authority_generation = UploadAuthorityGeneration {
            namespace: namespace_generation,
            capacity_policy: capacity_policy_generation,
        };
        let authority_audit = db::audit_upload_capacity_authority(
            &pool,
            config.upload_storage_max_pending_jobs,
            config.upload_storage_max_retained_files,
            config.upload_storage_max_retained_bytes,
        )
        .await
        .context("could not prove upload authority catalog and ACL invariants")?;
        if authority_audit.violation_count() != 0 {
            upload_safety_gate.mark_capacity_authority_unsafe(Arc::<str>::from(format!(
                "upload authority catalog/ACL audit found {} violations",
                authority_audit.violation_count()
            )));
            anyhow::bail!(
                "upload authority catalog/ACL audit found {} violations",
                authority_audit.violation_count()
            );
        }
        let capacity_reconciliation = db::reconcile_upload_capacity_ledger(&pool)
            .await
            .context("could not reconcile upload capacity facts before storage startup")?;
        if capacity_reconciliation.mismatch_count() != 0 {
            upload_safety_gate.mark_ledger_mismatch(Arc::<str>::from(format!(
                "upload capacity ledger differs from {} durable facts",
                capacity_reconciliation.mismatch_count()
            )));
            anyhow::bail!(
                "upload capacity ledger differs from {} durable facts",
                capacity_reconciliation.mismatch_count()
            );
        }
        upload_safety_gate.establish(upload_authority_generation, recovery_draining);
        let upload_store: Arc<dyn UploadStore> = match config.upload_storage_backend.as_str() {
            "local" => {
                let local = Arc::new(
                    LocalUploadStore::new(config.upload_dir.clone())
                        .with_safety_gate(Arc::clone(&upload_safety_gate)),
                );
                let guarded = Arc::new(GuardedUploadStore::new(
                    local.clone(),
                    Arc::clone(&upload_safety_gate),
                ));
                // This bounded local enumeration is retained only for legacy
                // pre-0091 partials. S3 reconciliation never lists a bucket;
                // every stage is represented by a PostgreSQL job.
                let mut abandoned_stages = 0_u64;
                let startup_stages =
                    tokio::time::timeout(Duration::from_secs(10), local.staging_attempts())
                        .await
                        .context("upload staging scan exceeded its startup time budget")?
                        .context("failed to enumerate upload staging files")?;
                // Enumeration is bounded above, but every candidate still
                // needs an authoritative lease lookup and may need one exact
                // unlink. Keep the complete reconciliation phase under one
                // wall-clock budget so thousands of crash remnants cannot
                // hold readiness indefinitely through sequential queries.
                let startup_cleanup_deadline =
                    tokio::time::Instant::now() + Duration::from_secs(30);
                for (object_id, claim_token) in startup_stages {
                    let remaining = startup_cleanup_deadline
                        .checked_duration_since(tokio::time::Instant::now())
                        .context(
                            "upload staging reconciliation exceeded its startup time budget",
                        )?;
                    if tokio::time::timeout(
                        remaining,
                        db::upload_claim_is_live(&pool, object_id, claim_token),
                    )
                    .await
                    .context("upload staging lease verification exceeded its startup time budget")?
                    .context("failed to verify an upload staging lease")?
                    {
                        continue;
                    }
                    let remaining = startup_cleanup_deadline
                        .checked_duration_since(tokio::time::Instant::now())
                        .context(
                            "upload staging reconciliation exceeded its startup time budget",
                        )?;
                    if tokio::time::timeout(
                        remaining,
                        guarded.abort(&object_id.to_string(), &claim_token.to_string(), None),
                    )
                    .await
                    .context("upload staging deletion exceeded its startup time budget")?
                    .context("failed to remove an abandoned upload stage")?
                    {
                        abandoned_stages = abandoned_stages.saturating_add(1);
                    }
                }
                if abandoned_stages > 0 {
                    tracing::warn!(
                        abandoned_stages,
                        "removed upload stages left by a previous process"
                    );
                }
                guarded
            }
            "s3" => {
                let inner: Arc<dyn UploadStore> = Arc::new(
                    S3UploadStore::new(S3UploadSettings {
                        endpoint: config.upload_s3_endpoint.clone(),
                        region: config.upload_s3_region.clone(),
                        bucket: config
                            .upload_s3_bucket
                            .clone()
                            .context("S3 upload bucket is missing after validation")?,
                        prefix: config.upload_s3_prefix.clone(),
                        path_style: config.upload_s3_path_style,
                        allow_http: config.upload_s3_allow_http,
                        ambient_credentials: config.upload_s3_credential_mode == "ambient",
                        credential_bundle_file: config.upload_s3_credential_bundle_file.clone(),
                        access_key_id_file: config.upload_s3_access_key_id_file.clone(),
                        secret_access_key_file: config.upload_s3_secret_access_key_file.clone(),
                        session_token_file: config.upload_s3_session_token_file.clone(),
                        sse_kms_key_id_file: config.upload_s3_sse_kms_key_id_file.clone(),
                    })?
                    .with_safety_gate(Arc::clone(&upload_safety_gate)),
                );
                Arc::new(GuardedUploadStore::new(
                    inner,
                    Arc::clone(&upload_safety_gate),
                ))
            }
            _ => unreachable!("upload backend was validated by Config"),
        };
        let extdisco_service = crate::services::extdisco::ExtDiscoService::new(
            config.raw.turn_shared_secret.take(),
            config.turn_credentials_ttl_seconds,
            config.turn_credential_requests_per_minute,
        );
        let abuse_state_hmac_key = config.raw.abuse_state_hmac_key.take().map(Zeroizing::new);
        let abuse_state_hmac_previous_key = config
            .raw
            .abuse_state_hmac_previous_key
            .take()
            .map(Zeroizing::new);
        if abuse_state_hmac_key.is_none() {
            let listeners_are_loopback = [
                config.xmpp_bind,
                config.xmpps_bind,
                config.http_bind,
                config.metrics_bind,
                config.s2s_bind,
                config.s2s_tls_bind,
                config.component_bind,
            ]
            .iter()
            .all(|address| address.ip().is_loopback());
            anyhow::ensure!(
                config.abuse_state_allow_ephemeral
                    && config.redis_url.is_none()
                    && listeners_are_loopback
                    && (config.domain == "localhost"
                        || config.domain.ends_with(".localhost")
                        || config.domain.ends_with(".test")),
                "ABUSE_STATE_HMAC_KEY_FILE is required unless every listener is loopback-only and ABUSE_STATE_ALLOW_EPHEMERAL=true explicitly enables single-node development mode"
            );
        }
        // The overlap phase deliberately keeps the previous generation as the
        // primary durable writer so old-only nodes can verify challenges and
        // deduplicate admissions.  `retire_previous` is the DB-authorized
        // fence after which every node switches its primary to the new key.
        let write_abuse_artifacts_with_previous =
            abuse_state_hmac_previous_key.is_some() && !config.abuse_state_hmac_retire_previous;
        let abuse = AbuseGuard::new_persistent_for_deployment(
            AbuseConfig {
                base_work_factor: config.pow_base_work_factor,
                max_work_factor: config.pow_max_work_factor,
                window: Duration::from_secs(config.abuse_window_seconds),
                cooldown_step: Duration::from_secs(config.abuse_cooldown_seconds),
                max_wait: Duration::from_secs(config.abuse_max_wait_seconds),
                message_free_burst: config.abuse_message_free_burst,
                approximate_max_device_seconds: config.pow_max_device_seconds,
            },
            pool.clone(),
            abuse_state_hmac_key
                .as_ref()
                .map(|secret| secret.as_bytes()),
            abuse_state_hmac_previous_key
                .as_ref()
                .map(|secret| secret.as_bytes()),
            write_abuse_artifacts_with_previous,
            config.pow_v1_compatibility_until,
        );
        // Inline key material is accepted only by the explicit disposable
        // loopback development profile. Mounted persistent keys, including
        // every Redis/non-loopback deployment, participate in DB authority.
        let abuse_key_deployment = config.abuse_state_hmac_key_file.as_ref().map(|_| {
            let (current_key_id, previous_key_id) = abuse.deployment_key_ids();
            db::AbuseKeyDeploymentIdentity {
                xmpp_domain: config.domain.clone(),
                epoch: config.abuse_state_hmac_key_epoch,
                current_key_id: current_key_id.to_owned(),
                previous_key_id: previous_key_id.map(str::to_owned),
                retire_previous: config.abuse_state_hmac_retire_previous,
                minimum_overlap: abuse.minimum_key_rotation_overlap(),
            }
        });
        let tls = crate::tls::ReloadableTlsConfig::new(
            &config.tls_cert_path,
            &config.tls_key_path,
            &config.domain,
            config.federation_extra_root_cert_path.as_deref(),
            config.c2s_client_trust_root_cert_path.as_deref(),
            config.federation_crl_path.as_deref(),
            config.c2s_client_crl_path.as_deref(),
        )
        .context("failed to load and validate TLS identity")?;
        let open_registration = config.open_registration;
        let dialback_secret = if let Some(secret) =
            config.raw.dialback_secret.take().map(Zeroizing::new)
        {
            Zeroizing::new(secret.as_bytes().to_vec())
        } else {
            use rand::RngCore;
            let mut secret = Zeroizing::new(vec![0_u8; 32]);
            rand::thread_rng().fill_bytes(&mut secret);
            if config.dialback_enabled {
                tracing::warn!(
                    "DIALBACK_SECRET is unset; using a process-local secret (set a mounted secret for deterministic multi-node operation)"
                );
            }
            secret
        };
        let fast_token_secret = Arc::new(
            if let Some(secret) = config.raw.fast_token_secret.take().map(Zeroizing::new) {
                Zeroizing::new(secret.as_bytes().to_vec())
            } else {
                anyhow::ensure!(
                    config.fast_token_enabled
                        && config.raw.fast_token_allow_ephemeral_for_development,
                    "FAST key is unavailable after configuration validation"
                );
                use rand::RngCore;
                let mut secret = Zeroizing::new(vec![0_u8; 32]);
                rand::thread_rng().fill_bytes(&mut secret);
                tracing::warn!(
                    "explicit loopback development mode is using an ephemeral FAST key; XEP-0484 tokens change on restart"
                );
                secret
            },
        );
        let dummy_scram_secret = Arc::new(if let Some(secret) = config.dummy_scram_secret.take() {
            Zeroizing::new(secret.as_bytes().to_vec())
        } else {
            anyhow::ensure!(
                config.raw.dummy_scram_allow_ephemeral_for_development,
                "dummy SCRAM key is unavailable after configuration validation"
            );
            use rand::RngCore;
            let mut secret = Zeroizing::new(vec![0_u8; 32]);
            rand::thread_rng().fill_bytes(&mut secret);
            tracing::warn!(
                "explicit loopback development mode is using an independent ephemeral dummy SCRAM key; unknown-account challenge material changes on restart"
            );
            secret
        });
        anyhow::ensure!(
            !crate::auth::constant_time_bytes_eq(
                fast_token_secret.as_slice(),
                dummy_scram_secret.as_slice(),
            ),
            "FAST and dummy SCRAM master keys must be independent"
        );
        let client_connections = Arc::new(Semaphore::new(config.max_client_connections));
        let s2s_connections = Arc::new(Semaphore::new(config.max_s2s_connections));
        let s2s_connection_attempts = Arc::new(Semaphore::new(config.max_s2s_connections));
        let component_connections = Arc::new(Semaphore::new(config.max_component_connections));
        let connection_actors =
            crate::connection_actors::ConnectionActorRegistry::for_transport_limits(
                config.max_client_connections,
                config.max_s2s_connections,
                config.max_component_connections,
            )
            .context("configured connection actor capacity is invalid")?;
        let sm_capacity_metrics =
            Arc::new(crate::services::sm_capacity::SmCapacityMetrics::default());
        let sm_memory_governor = crate::services::sm_capacity::SmMemoryGovernor::new(
            config.sm_memory_budget_bytes,
            config.sm_recovery_max_bytes,
            config.sm_recovery_max_jobs,
            config.sm_max_snapshot_bytes,
            Arc::clone(&sm_capacity_metrics),
        )?;
        let (resolver_config, mut resolver_options) =
            read_system_conf().context("failed to read the system DNS resolver configuration")?;
        resolver_options.try_tcp_on_error = true;
        resolver_options.server_ordering_strategy = ServerOrderingStrategy::RoundRobin;
        resolver_options.cache_size = 1024;
        let mut dnssec_options = resolver_options.clone();
        dnssec_options.validate = true;
        dnssec_options.use_hosts_file = ResolveHosts::Never;
        dnssec_options.preserve_intermediates = true;
        dnssec_options.positive_max_ttl = Some(Duration::from_secs(24 * 60 * 60));
        dnssec_options.negative_max_ttl = Some(Duration::from_secs(5 * 60));
        let s2s_dns_resolver = TokioResolver::builder_with_config(
            resolver_config.clone(),
            TokioRuntimeProvider::default(),
        )
        .with_options(resolver_options)
        .build()
        .context("failed to initialize the asynchronous DNS resolver")?;
        let s2s_dnssec_resolver = (config.federation_dane_mode != crate::s2s::dane::DaneMode::Off)
            .then(|| {
                TokioResolver::builder_with_config(resolver_config, TokioRuntimeProvider::default())
                    .with_options(dnssec_options)
                    .build()
                    .context("failed to initialize the locally validating DNSSEC resolver")
            })
            .transpose()?;

        // Transfer the Redis endpoint and signing capability out of the
        // broadly shared Config before constructing AppState.  ClusterManager
        // is their sole runtime owner; keeping a second copy in `state.config`
        // would let unrelated protocol code regain a long-lived secret by
        // reaching through configuration.
        let mut redis_url = config.raw.redis_url.take();
        let cluster_security = config.cluster_security.take();
        let cluster = crate::cluster::ClusterManager::new(
            redis_url.as_deref(),
            &config.domain,
            config.raw.redis_tls_ca_cert_path.as_deref(),
            config.raw.redis_tls_client_cert_path.as_deref(),
            config.raw.redis_tls_client_key_path.as_deref(),
            cluster_security,
        )
        .await
        .context("failed to connect to Redis for cluster manager")?;
        if let Some(redis_url) = &mut redis_url {
            redis_url.zeroize();
            redis_url.clear();
        }
        cluster.configure_authority_pool(&pool)?;
        if let Some(identity) = cluster.key_authority_identity() {
            db::reconcile_cluster_key_deployment_before_instance_claim(&pool, &identity)
                .await
                .context("cluster signing-key authority preparation failed")?;
            for peer in cluster.peer_key_authority_identities() {
                db::reconcile_cluster_peer_key_deployment(&pool, &peer)
                    .await
                    .with_context(|| {
                        format!(
                            "configured cluster peer {} key authority is inconsistent",
                            peer.node_id
                        )
                    })?;
            }
            cluster
                .claim_instance_authority(&pool)
                .await
                .context("cluster node ID is already owned by another live process")?;
            db::reconcile_cluster_key_deployment(&pool, &identity)
                .await
                .context("cluster signing-key authority finalization failed")?;
            cluster
                .refresh_instance_authority(&pool)
                .await
                .context("could not load peer cluster instance authority")?;
        }
        cluster
            .activate()
            .await
            .context("failed to publish the initial signed cluster node lease")?;
        db::initialize_admin_runtime_settings(&pool, false, !open_registration).await?;
        let (island_mode, registration_closed) = db::admin_runtime_settings(&pool).await?;
        let process_started_at: chrono::DateTime<chrono::Utc> =
            sqlx::query_scalar("SELECT clock_timestamp()")
                .fetch_one(&pool)
                .await?;
        let (runtime_blacklist, runtime_whitelist) = db::federation_runtime_rules(&pool).await?;

        db::recover_remote_pam_after_restart(&pool)
            .await
            .context("failed to recover pending MIX-PAM federation operations")?;
        let mix_presence_recovery = db::prepare_mix_presence_after_restart(&pool, &config.domain)
            .await
            .context("failed to prepare XEP-0403 presence recovery")?;
        if config.mix_muc_mirror_enabled {
            let mix_domain = format!("mix.{}", config.domain);
            let linked = db::reconcile_mix_muc_mirrors(&pool, &mix_domain, &config.domain)
                .await
                .context("failed to reconcile XEP-0408 MIX/MUC mirror associations")?;
            tracing::info!(linked, "XEP-0408 partial MIX/MUC mirror mode enabled");
        }

        if let Some(identity) = &abuse_key_deployment {
            db::reconcile_abuse_key_deployment(&pool, identity)
                .await
                .context("anti-abuse HMAC deployment consistency check failed")?;
        }

        let bosh = crate::bosh::BoshManager::new(
            config.bosh_max_sessions,
            config.bosh_max_concurrent_body_reads,
        );
        let upload_download_max_concurrent = config.upload_download_max_concurrent;
        let sm_recovery_max_jobs = config.sm_recovery_max_jobs;
        let sm_recovery_max_bytes = config.sm_recovery_max_bytes;
        let message_content_identity = abuse.personal_message_content_keyring();
        let retraction_content_identity = abuse.personal_retraction_content_keyring();
        let mix_message_content_identity = abuse.mix_message_content_keyring();
        let mix_retraction_content_identity = abuse.mix_retraction_content_keyring();
        let message_service = crate::services::messaging::MessageService::new(
            pool.clone(),
            message_content_identity,
            config.domain.clone(),
            config.require_encrypted_archive,
            config.offline_max_messages_per_account,
            config.offline_max_bytes_per_account,
            config.offline_message_ttl_days,
        );
        let retraction_service = crate::services::retractions::RetractionService::new(
            pool.clone(),
            retraction_content_identity,
            config.domain.clone(),
        );
        let account_service = crate::services::account::AccountService::new(
            pool.clone(),
            config.domain.clone(),
            config.invitation_required,
            config.registration_rate_per_hour,
            config.scram_iterations,
            config.scram_sha1_enabled,
        );
        let dummy_scram_iteration_profiles =
            crate::db::scram_iteration_profiles(&pool, config.scram_iterations)
                .await
                .context("failed to load dummy SCRAM iteration profiles")?;
        let authentication_service = crate::services::authentication::AuthenticationService::new_with_dummy_scram_iteration_profiles(
                pool.clone(),
                Arc::clone(&fast_token_secret),
                dummy_scram_secret,
                config.scram_iterations,
                dummy_scram_iteration_profiles,
                config.scram_sha1_enabled,
            );
        let pubsub_service =
            crate::services::pubsub::PubSubService::new(pool.clone(), &config.domain);
        let profile_service = crate::services::profile::ProfileService::with_mutation_admission(
            pool.clone(),
            config.domain.clone(),
            pubsub_service.mutation_admission(),
        );
        let mam_service = crate::services::mam::MamService::new(pool.clone());
        let upload_service = crate::services::upload::UploadService::new(
            pool.clone(),
            Arc::clone(&upload_safety_gate),
        );
        let privacy_service = crate::services::privacy::PrivacyService::new(pool.clone());
        let replay_service = crate::services::replay::ReplayService::new(
            pool.clone(),
            &config.domain,
            config.offline_message_ttl_days,
        );
        let roster_service = crate::services::roster::RosterService::new(pool.clone());
        let private_storage_service = crate::services::private_storage::PrivateStorageService::new(
            pool.clone(),
            config.pep_max_nodes_per_account,
            config.pep_max_storage_bytes_per_account,
        );
        let command_pool_options = PgPoolOptions::new()
            .max_connections(4)
            .min_connections(0)
            .acquire_timeout(Duration::from_secs(2));
        let command_pool_options = if config.database_allow_unsafe_role_for_development {
            command_pool_options
        } else {
            crate::db::pin_public_application_schema(command_pool_options)
        };
        let command_pool = command_pool_options
            .connect(&config.admin_command_database_url)
            .await
            .context("could not create bounded XEP-0133 command database pool")?;
        if config.database_allow_unsafe_role_for_development {
            crate::db::attest_development_database_is_loopback(&command_pool).await?;
        } else {
            crate::db::attest_admin_command_role(&command_pool).await?;
        }
        let omemo_recovery_pool_options = PgPoolOptions::new()
            .max_connections(2)
            .min_connections(0)
            .acquire_timeout(Duration::from_secs(2));
        let omemo_recovery_pool_options = if config.database_allow_unsafe_role_for_development {
            omemo_recovery_pool_options
        } else {
            crate::db::pin_public_application_schema(omemo_recovery_pool_options)
        };
        let omemo_recovery_poll_pool = omemo_recovery_pool_options
            .connect(&config.database_url)
            .await
            .context("could not create isolated OMEMO recovery poll database pool")?;
        let sm_authority_schema: String = sqlx::query_scalar("SELECT current_schema()")
            .fetch_one(&pool)
            .await
            .context("could not determine the SM authority schema")?;
        let mut sm_authority_connect_options = config
            .database_url
            .parse::<PgConnectOptions>()
            .context("could not parse the SM authority listener database URL")?;
        if !config.database_allow_unsafe_role_for_development {
            sm_authority_connect_options =
                sm_authority_connect_options.options([("search_path", "public")]);
        }
        let sm_service = crate::services::sm::SmService::new(pool.clone(), sm_authority_schema)?;
        config.raw.database_url.zeroize();
        config.raw.database_url.clear();
        config.raw.admin_command_database_url.zeroize();
        config.raw.admin_command_database_url.clear();
        let muc_service =
            crate::services::muc::MucService::new(pool.clone(), config.domain.clone());
        let state = Arc::new(Self {
            config,
            pubsub_service,
            profile_service,
            extdisco_service,
            muc_service,
            message_service,
            retraction_service,
            mam_service,
            mix_service: crate::services::mix::MixService::new(
                pool.clone(),
                mix_message_content_identity,
                mix_retraction_content_identity,
            ),
            sm_service,
            blocking_service: crate::services::blocking::BlockingService::new(pool.clone()),
            presence_service: crate::services::presence::PresenceService::new(pool.clone()),
            replay_service,
            roster_service,
            privacy_service,
            private_storage_service,
            account_service,
            authentication_service,
            admin_command_service: crate::services::admin_commands::AdminCommandService::new(
                pool.clone(),
                command_pool,
            ),
            push_service: crate::services::push::PushService::new(pool.clone()),
            pool,
            cluster,
            bosh,
            sessions: DashMap::new(),
            muc_occupants: DashMap::new(),
            suspended_muc_sessions: DashMap::new(),
            sm_suspension_recovery:
                crate::services::session_cleanup::SmSuspensionRecoveryQueue::new(
                    sm_recovery_max_jobs,
                    sm_recovery_max_bytes,
                    Arc::clone(&sm_capacity_metrics),
                    Arc::clone(&sm_memory_governor),
                ),
            sm_memory_governor,
            metrics: Metrics::default(),
            metrics_bearer_token,
            omemo_recovery_poll_pool,
            api_control,
            api_cursor,
            upload_service,
            upload_store,
            upload_storage_namespace_sha256: upload_namespace,
            upload_authority_generation,
            upload_safety_gate,
            federation,
            component_credentials,
            components,
            s2s_connection_registry: crate::s2s::S2sConnectionRegistry::default(),
            s2s_dns_resolver,
            s2s_dnssec_resolver,
            pending_mix_iq: crate::xmpp::protocol::mix::MixIqRelayIndex::new(),
            caps_cache: crate::xmpp::protocol::caps::CapsCacheIndex::new(),
            caps_by_jid: crate::xmpp::protocol::caps::CapsResourceIndex::new(),
            pending_caps: crate::xmpp::protocol::caps::PendingCapsIndex::new(),
            federated_caps_gates: crate::xmpp::protocol::caps::FederatedCapsGateIndex::new(),
            caps_effect_dispatcher: crate::xmpp::protocol::caps::CapsEffectDispatcher::new(),
            dialback_secret,
            fast_token_secret,
            dialback_verifications: Arc::new(Semaphore::new(64)),
            client_connections,
            client_connections_by_ip: DashMap::new(),
            upload_requests: Arc::new(Semaphore::new(32)),
            upload_requests_by_ip: DashMap::new(),
            upload_downloads: Arc::new(Semaphore::new(upload_download_max_concurrent)),
            upload_downloads_by_ip: DashMap::new(),
            omemo_recovery_poll_requests: Arc::new(Semaphore::new(OMEMO_POLL_CONCURRENCY)),
            omemo_recovery_poll_requests_by_ip: DashMap::new(),
            omemo_recovery_poll_ip_admission: std::sync::Mutex::new(()),
            omemo_recovery_poll_request_checks: AtomicU64::new(0),
            s2s_connections,
            s2s_connection_attempts,
            component_connections,
            connection_actors,
            abuse,
            abuse_key_deployment,
            started_at: Instant::now(),
            process_started_at,
            tls,
            federation_write_policy: FederationWritePolicy::new(island_mode),
            registration_closed: AtomicBool::new(registration_closed),
            federation_runtime_policy: arc_swap::ArcSwap::from_pointee(RuntimeFederationPolicy {
                blacklist: runtime_blacklist.into_iter().collect(),
                whitelist: runtime_whitelist.into_iter().collect(),
            }),
            service_shutdown: std::sync::OnceLock::new(),
            workers: crate::workers::WorkerRegistry::new(),
        });
        state.worker_registry().register_observer(
            "session-cleanup",
            crate::workers::WorkerCriticality::Restartable,
        );
        crate::services::sm::start_sm_authority_listener(
            state.sm_service().clone(),
            sm_authority_connect_options,
            Arc::clone(state.worker_registry()),
            worker_cancel.clone(),
        );
        crate::xmpp::protocol::caps::start_caps_effect_dispatcher(
            Arc::clone(&state),
            worker_cancel.clone(),
        );
        crate::services::session_cleanup::start_sm_suspension_recovery(
            Arc::clone(&state),
            Arc::clone(&state.sm_suspension_recovery),
            worker_cancel.clone(),
        );
        crate::xmpp::protocol::mix::start_mix_presence_recovery(
            Arc::clone(&state),
            mix_presence_recovery.0,
            mix_presence_recovery.1,
            worker_cancel.clone(),
        );
        crate::xmpp::protocol::mix::start_mix_iq_relay_expiry(
            Arc::clone(&state),
            worker_cancel.clone(),
        );
        crate::xmpp::protocol::mix::start_mix_delivery_outbox(
            Arc::clone(&state),
            worker_cancel.clone(),
        );
        crate::xmpp::protocol::pubsub::start_pubsub_digest_delivery(
            Arc::clone(&state),
            worker_cancel.clone(),
        );
        crate::xmpp::protocol::pubsub::start_pubsub_event_outbox_delivery(
            Arc::clone(&state),
            worker_cancel.clone(),
        );
        crate::cluster::start_muc_outbox_delivery(Arc::clone(&state), worker_cancel.clone());
        Self::start_locked_muc_expiry(Arc::clone(&state), worker_cancel.clone());
        Self::start_runtime_federation_policy_refresh(Arc::clone(&state), worker_cancel.clone());
        Self::start_runtime_admin_setting_refresh(Arc::clone(&state), worker_cancel);
        Ok(state)
    }

    pub(crate) fn worker_registry(&self) -> &Arc<crate::workers::WorkerRegistry> {
        &self.workers
    }

    pub(crate) fn sm_suspension_recovery_queue(
        &self,
    ) -> &Arc<crate::services::session_cleanup::SmSuspensionRecoveryQueue> {
        &self.sm_suspension_recovery
    }

    pub(crate) fn sm_memory_governor(
        &self,
    ) -> &Arc<crate::services::sm_capacity::SmMemoryGovernor> {
        &self.sm_memory_governor
    }

    pub(crate) fn connection_actors(&self) -> &crate::connection_actors::ConnectionActorRegistry {
        &self.connection_actors
    }

    pub(crate) fn caps_effect_dispatcher(
        &self,
    ) -> &Arc<crate::xmpp::protocol::caps::CapsEffectDispatcher> {
        &self.caps_effect_dispatcher
    }

    pub(crate) fn pending_mix_iq(&self) -> &crate::xmpp::protocol::mix::MixIqRelayIndex {
        &self.pending_mix_iq
    }

    pub(crate) fn caps_cache(&self) -> &crate::xmpp::protocol::caps::CapsCacheIndex {
        &self.caps_cache
    }

    pub(crate) fn caps_by_jid(&self) -> &crate::xmpp::protocol::caps::CapsResourceIndex {
        &self.caps_by_jid
    }

    pub(crate) fn pending_caps(&self) -> &crate::xmpp::protocol::caps::PendingCapsIndex {
        &self.pending_caps
    }

    pub(crate) fn federated_caps_gates(
        &self,
    ) -> &crate::xmpp::protocol::caps::FederatedCapsGateIndex {
        &self.federated_caps_gates
    }

    pub(crate) fn abuse_key_deployment(&self) -> Option<&db::AbuseKeyDeploymentIdentity> {
        self.abuse_key_deployment.as_ref()
    }

    pub(crate) fn api_control(&self) -> &db::ApiControlKeyring {
        &self.api_control
    }

    pub(crate) fn api_cursor(&self) -> &crate::api::cursor::CursorKeyring {
        &self.api_cursor
    }

    pub(crate) fn upload_store(&self) -> &dyn UploadStore {
        self.upload_store.as_ref()
    }

    pub(crate) fn metrics_request_authorized(
        &self,
        peer: std::net::IpAddr,
        candidate: Option<&str>,
    ) -> bool {
        let Some(expected) = self.metrics_bearer_token.as_deref() else {
            return peer.is_loopback();
        };
        candidate.is_some_and(|candidate| {
            candidate.len() == expected.len()
                && bool::from(candidate.as_bytes().ct_eq(expected.as_bytes()))
        })
    }

    pub(crate) fn has_component_credentials(&self) -> bool {
        !self.component_credentials.is_empty()
    }

    /// Authenticated external-component ownership and wake-up authority.
    /// The registry exposes only owner-fenced operations; its concurrent map
    /// remains encapsulated inside the component subsystem.
    pub(crate) fn component_registry(&self) -> &crate::components::ComponentRegistry {
        &self.components
    }

    /// Redacted configured routing domains used by observability and the S2S
    /// outbox exclusion query. Preserve the original Vec semantics, including
    /// configuration order and any duplicates across credentials.
    pub(crate) fn configured_component_domains(&self) -> Vec<String> {
        self.config
            .components
            .iter()
            .flat_map(|credential| credential.allowed_domains.iter().cloned())
            .collect()
    }

    pub(crate) fn component_connect_credentials(&self) -> Vec<crate::config::ComponentCredential> {
        self.component_credentials
            .iter()
            .filter(|credential| {
                credential.connection == crate::config::ComponentConnectionMode::Connect
            })
            .cloned()
            .collect()
    }

    pub(crate) fn accepts_component_connections(&self) -> bool {
        self.component_credentials.iter().any(|credential| {
            credential.connection == crate::config::ComponentConnectionMode::Accept
        })
    }

    pub(crate) fn component_authentication_credential(
        &self,
        domain: &str,
    ) -> Option<crate::config::ComponentCredential> {
        let domain = crate::jid::prepare_domainpart(domain).ok()?;
        self.component_credentials
            .iter()
            .find(|credential| {
                credential
                    .allowed_domains
                    .iter()
                    .any(|allowed| allowed == &domain)
            })
            .cloned()
    }

    pub(crate) fn upload_storage_namespace_sha256(&self) -> &[u8; 32] {
        &self.upload_storage_namespace_sha256
    }

    pub(crate) fn upload_authority_generation(&self) -> UploadAuthorityGeneration {
        self.upload_authority_generation
    }

    pub(crate) fn upload_safety_gate(&self) -> &Arc<UploadSafetyGate> {
        &self.upload_safety_gate
    }

    pub(crate) fn upload_service(&self) -> &crate::services::upload::UploadService {
        &self.upload_service
    }

    pub(crate) fn pubsub_service(&self) -> &crate::services::pubsub::PubSubService {
        &self.pubsub_service
    }

    pub(crate) fn profile_service(&self) -> &crate::services::profile::ProfileService {
        &self.profile_service
    }

    pub(crate) fn mix_service(&self) -> &crate::services::mix::MixService {
        &self.mix_service
    }

    pub(crate) fn extdisco_service(&self) -> &crate::services::extdisco::ExtDiscoService {
        &self.extdisco_service
    }

    pub(crate) fn muc_service(&self) -> &crate::services::muc::MucService {
        &self.muc_service
    }

    pub(crate) fn message_service(&self) -> &crate::services::messaging::MessageService {
        &self.message_service
    }

    pub(crate) fn retraction_service(&self) -> &crate::services::retractions::RetractionService {
        &self.retraction_service
    }

    pub(crate) fn mam_service(&self) -> &crate::services::mam::MamService {
        &self.mam_service
    }

    pub(crate) fn sm_service(&self) -> &crate::services::sm::SmService {
        &self.sm_service
    }

    pub(crate) fn blocking_service(&self) -> &crate::services::blocking::BlockingService {
        &self.blocking_service
    }

    pub(crate) fn presence_service(&self) -> &crate::services::presence::PresenceService {
        &self.presence_service
    }

    pub(crate) fn replay_service(&self) -> &crate::services::replay::ReplayService {
        &self.replay_service
    }

    pub(crate) fn roster_service(&self) -> &crate::services::roster::RosterService {
        &self.roster_service
    }

    pub(crate) fn privacy_service(&self) -> &crate::services::privacy::PrivacyService {
        &self.privacy_service
    }

    pub(crate) fn private_storage_service(
        &self,
    ) -> &crate::services::private_storage::PrivateStorageService {
        &self.private_storage_service
    }

    pub(crate) fn account_service(&self) -> &crate::services::account::AccountService {
        &self.account_service
    }

    pub(crate) fn authentication_service(
        &self,
    ) -> &crate::services::authentication::AuthenticationService {
        &self.authentication_service
    }

    pub(crate) fn admin_command_service(
        &self,
    ) -> &crate::services::admin_commands::AdminCommandService {
        &self.admin_command_service
    }

    pub(crate) fn push_service(&self) -> &crate::services::push::PushService {
        &self.push_service
    }

    pub(crate) fn derive_dialback_key(
        &self,
        receiving_domain: &str,
        originating_domain: &str,
        stream_id: &str,
    ) -> String {
        crate::s2s::dialback::key(
            self.dialback_secret.as_slice(),
            receiving_domain,
            originating_domain,
            stream_id,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn finalize_resource_binding(
        &self,
        connection_id: uuid::Uuid,
        user_id: uuid::Uuid,
        expected_auth_generation: i64,
        full_jid: &str,
        device_id: Option<uuid::Uuid>,
        fast_plan: Option<&crate::services::authentication::FastCommitPlan>,
    ) -> anyhow::Result<crate::services::sm::BindingFinalizationOutcome> {
        self.sm_service
            .finalize_binding(
                self.fast_token_secret.as_slice(),
                connection_id,
                user_id,
                expected_auth_generation,
                full_jid,
                self.config.capacity_session_lease_seconds,
                device_id,
                fast_plan,
            )
            .await
    }

    pub(crate) async fn finalize_sm_resume(
        &self,
        request: crate::services::sm::SmResumeFinalizationRequest<'_>,
    ) -> anyhow::Result<crate::services::sm::SmResumeFinalizationOutcome> {
        self.sm_service
            .finalize_resume(self.fast_token_secret.as_slice(), request)
            .await
    }

    fn start_locked_muc_expiry(state: Arc<Self>, cancel: CancellationToken) {
        let weak = Arc::downgrade(&state);
        state.worker_registry().supervise(
            "locked-muc-expiry",
            crate::workers::WorkerCriticality::Restartable,
            crate::workers::WorkerMode::Continuous,
            Some(Duration::from_secs(20)),
            cancel,
            move |heartbeat| {
                let weak = weak.clone();
                async move {
                    let mut interval = tokio::time::interval(Duration::from_secs(5));
                    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                    loop {
                        interval.tick().await;
                        let Some(state) = weak.upgrade() else {
                            return Ok(());
                        };
                        let expired =
                            match db::delete_expired_locked_muc_rooms(&state.pool, 100).await {
                                Ok(expired) => expired,
                                Err(error) => {
                                    heartbeat.error(&error);
                                    tracing::error!(
                                        ?error,
                                        "could not expire abandoned locked MUC rooms"
                                    );
                                    continue;
                                }
                            };
                        heartbeat.ok();
                        for localpart in expired {
                            let room_jid =
                                format!("{}@conference.{}", localpart, state.config.domain);
                            for (key, occupant) in state.muc_occupants_for(&room_jid) {
                                let serializable = SerializableMucOccupant::from(&occupant);
                                state.remove_live_muc_membership(&serializable);
                                state.muc_occupants.remove_if(&key, |_, current| {
                                    current.cluster_epoch == occupant.cluster_epoch
                                        && current.connection_id == occupant.connection_id
                                });
                                if !state.cluster.is_enabled() {
                                    let unavailable = crate::xmpp::xml_util::muc_destroy_presence(
                                        &serializable,
                                        None,
                                        None,
                                    );
                                    let _ =
                                        state.deliver_to_muc_occupant(&occupant, unavailable).await;
                                }
                            }
                            // delete_expired_locked_muc_rooms committed the
                            // tombstone plus terminal outbox. Cluster nodes
                            // catch it up from PostgreSQL; emitting the legacy
                            // Redis destroy command would reintroduce a second
                            // executable authority.
                        }
                    }
                }
            },
        );
    }

    fn start_runtime_federation_policy_refresh(state: Arc<Self>, cancel: CancellationToken) {
        let weak = Arc::downgrade(&state);
        state.worker_registry().supervise(
            "federation-policy-refresh",
            crate::workers::WorkerCriticality::Critical,
            crate::workers::WorkerMode::Continuous,
            Some(Duration::from_secs(10)),
            cancel,
            move |heartbeat| {
                let weak = weak.clone();
                async move {
                    let mut interval = tokio::time::interval(Duration::from_secs(2));
                    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                    loop {
                        interval.tick().await;
                        let Some(state) = weak.upgrade() else {
                            return Ok(());
                        };
                        match db::federation_runtime_rules(&state.pool).await {
                            Ok((blacklist, whitelist)) => {
                                state.replace_runtime_federation_cache(blacklist, whitelist);
                                heartbeat.ok();
                            }
                            Err(error) => {
                                heartbeat.error(&error);
                                tracing::error!(
                                    ?error,
                                    "could not refresh durable federation policy"
                                );
                            }
                        }
                    }
                }
            },
        );
    }

    pub fn federation_domain_allowed(&self, domain: &str) -> bool {
        let Ok(domain) = crate::jid::prepare_domainpart(domain) else {
            return false;
        };
        let policy = self.federation_runtime_policy.load();
        let domain_denied = policy.blacklist.iter().any(|entry| {
            crate::jid::CanonicalJid::parse(entry)
                .is_ok_and(|jid| jid.localpart().is_none() && jid.domainpart() == domain)
        });
        let domain_admitted = policy.whitelist.is_empty()
            || policy.whitelist.iter().any(|entry| {
                crate::jid::CanonicalJid::parse(entry).is_ok_and(|jid| jid.domainpart() == domain)
            });
        self.config.federation_domain_allowed(&domain) && !domain_denied && domain_admitted
    }

    /// Apply XEP-0133 entity rules using XEP-0016-style JID specificity: a
    /// domain rule matches the whole domain, a bare JID matches all of its
    /// resources, and a full JID matches exactly one resource.
    pub fn federation_entity_allowed(&self, entity: &str) -> bool {
        let Ok(entity) = crate::jid::CanonicalJid::parse(entity) else {
            return false;
        };
        if !self.config.federation_domain_allowed(entity.domainpart()) {
            return false;
        }
        let policy = self.federation_runtime_policy.load();
        let matches = |rule: &str| federation_rule_matches(rule, &entity);
        !policy.blacklist.iter().any(|entry| matches(entry))
            && (policy.whitelist.is_empty() || policy.whitelist.iter().any(|entry| matches(entry)))
    }

    pub fn replace_runtime_federation_cache(&self, blacklist: Vec<String>, whitelist: Vec<String>) {
        self.federation_runtime_policy
            .store(Arc::new(RuntimeFederationPolicy {
                blacklist: blacklist.into_iter().collect(),
                whitelist: whitelist.into_iter().collect(),
            }));
    }

    fn start_runtime_admin_setting_refresh(state: Arc<Self>, cancel: CancellationToken) {
        let weak = Arc::downgrade(&state);
        state.worker_registry().supervise(
            "administration-setting-refresh",
            crate::workers::WorkerCriticality::Critical,
            crate::workers::WorkerMode::Continuous,
            Some(Duration::from_secs(5)),
            cancel,
            move |heartbeat| {
                let weak = weak.clone();
                async move {
                    let mut interval = tokio::time::interval(Duration::from_secs(1));
                    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                    loop {
                        interval.tick().await;
                        let Some(state) = weak.upgrade() else {
                            return Ok(());
                        };
                        match db::admin_runtime_settings(&state.pool).await {
                            Ok((island_mode, registration_closed)) => {
                                let was_island = state.refresh_island_mode(island_mode).await;
                                state.apply_registration_closed(registration_closed);
                                if island_mode && !was_island {
                                    state
                                        .s2s_connection_registry()
                                        .clear_outbound_for_island_mode();
                                }
                                heartbeat.ok();
                            }
                            Err(error) => {
                                heartbeat.error(&error);
                                tracing::error!(
                                    ?error,
                                    "could not refresh durable administration settings"
                                );
                            }
                        }
                    }
                }
            },
        );
    }

    pub fn install_service_shutdown(
        self: &Arc<Self>,
        cancel: CancellationToken,
    ) -> anyhow::Result<()> {
        self.service_shutdown
            .set(cancel)
            .map_err(|_| anyhow::anyhow!("service shutdown control was already installed"))?;
        Self::start_service_control_watcher(Arc::clone(self));
        Ok(())
    }

    pub fn service_control_available(&self) -> bool {
        self.service_shutdown.get().is_some()
    }

    fn start_service_control_watcher(state: Arc<Self>) {
        let weak = Arc::downgrade(&state);
        let cancel = state
            .service_shutdown
            .get()
            .expect("service shutdown installed before watcher")
            .clone();
        state.worker_registry().supervise(
            "service-control-watcher",
            crate::workers::WorkerCriticality::Critical,
            crate::workers::WorkerMode::Continuous,
            Some(Duration::from_secs(3)),
            cancel,
            move |heartbeat| {
                let weak = weak.clone();
                async move {
                    let mut interval = tokio::time::interval(Duration::from_millis(500));
                    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                    let mut acted = None;
                    loop {
                        interval.tick().await;
                        let Some(state) = weak.upgrade() else {
                            return Ok(());
                        };
                        match db::poll_admin_service_control(&state.pool).await {
                            Ok(Some(control))
                                if service_control_applies(state.process_started_at, &control)
                                    && acted != Some(control.generation) =>
                            {
                                acted = Some(control.generation);
                                tracing::warn!(
                                    operation = %control.action,
                                    generation = %control.generation,
                                    execute_at = %control.execute_at,
                                    expires_at = %control.expires_at,
                                    "executing durable cluster-wide service control"
                                );
                                if let Some(shutdown) = state.service_shutdown.get() {
                                    shutdown.cancel();
                                }
                                heartbeat.ok();
                            }
                            Ok(_) => heartbeat.ok(),
                            Err(error) => {
                                heartbeat.error(&error);
                                tracing::error!(
                                    ?error,
                                    "could not poll durable cluster-wide service control"
                                );
                            }
                        }
                    }
                }
            },
        );
    }

    pub fn sessions_for(&self, jid: &str) -> Vec<OnlineSession> {
        let Some(lookup) = session_lookup(jid) else {
            return Vec::new();
        };
        match lookup {
            SessionLookup::Full(full) => self
                .sessions
                .get(&full)
                .filter(|entry| entry.routable.load(Ordering::Acquire))
                .map(|entry| vec![entry.value().clone()])
                .unwrap_or_default(),
            SessionLookup::Bare(bare) => self
                .sessions
                .iter()
                .filter(|entry| {
                    bare_jid(entry.key()) == bare.as_str() && entry.routable.load(Ordering::Acquire)
                })
                .map(|entry| entry.value().clone())
                .collect(),
        }
    }

    pub fn session_entries_for(&self, jid: &str) -> Vec<(String, OnlineSession)> {
        let Some(lookup) = session_lookup(jid) else {
            return Vec::new();
        };
        match lookup {
            SessionLookup::Full(full) => self
                .sessions
                .get(&full)
                .filter(|entry| entry.routable.load(Ordering::Acquire))
                .map(|entry| vec![(entry.key().clone(), entry.value().clone())])
                .unwrap_or_default(),
            SessionLookup::Bare(bare) => self
                .sessions
                .iter()
                .filter(|entry| {
                    bare_jid(entry.key()) == bare.as_str() && entry.routable.load(Ordering::Acquire)
                })
                .map(|entry| (entry.key().clone(), entry.value().clone()))
                .collect(),
        }
    }

    /// Publish only the exact staged route incarnation that survived every
    /// authorization and lifecycle fence.  The DashMap write guard provides
    /// a local linearization point with account/session revocation helpers;
    /// the cancellation/lifecycle recheck after publication also closes a
    /// concurrent out-of-band transport cancellation window.
    pub(crate) fn activate_session_if_current(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
        user_id: uuid::Uuid,
        auth_generation: i64,
        lifecycle: &Arc<AtomicU8>,
        disconnect: &CancellationToken,
    ) -> bool {
        let Some(session) = self.sessions.get_mut(full_jid) else {
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

    /// Cancel local account routes, including non-routable two-phase bind or
    /// resume candidates.  Public lookup helpers intentionally hide those
    /// candidates, so authorization revocation must iterate the authority map
    /// itself and set `routable=false` under the same per-entry write guard
    /// used by activation.
    pub(crate) fn revoke_local_account_routes(
        &self,
        user_id: uuid::Uuid,
        bare_account_jid: &str,
        auth_generation_exclusive: Option<i64>,
    ) -> usize {
        let Ok(bare_account_jid) = crate::jid::canonicalize_bare(bare_account_jid) else {
            return 0;
        };
        let mut revoked = 0;
        for entry in self.sessions.iter_mut() {
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

    /// Remove exactly one local route incarnation. Every rollback and Drop
    /// path must use this instead of an unconditional DashMap removal: a late
    /// old connection must never delete a newly bound/resumed replacement.
    pub fn remove_session_if_connection(
        &self,
        key: &str,
        connection_id: uuid::Uuid,
    ) -> Option<OnlineSession> {
        let (_, removed) = self
            .sessions
            .remove_if(key, |_, session| session.connection_id == connection_id)?;
        debug_assert_eq!(removed.route_incarnation.connection_id(), connection_id);
        // Publish immediately after the exact compare-and-remove.  Any route
        // inserted between removal and this notification is a new incarnation;
        // waiters re-read `sessions` and must not mistake that ABA for vacancy.
        removed.route_incarnation.publish_removed();
        self.caps_effect_dispatcher
            .cancel_local(key, removed.connection_id);
        self.caps_by_jid
            .remove_local_resource(key, removed.connection_id);
        self.pending_caps
            .remove_local_resource(key, removed.connection_id);
        if removed.metrics_counted.swap(false, Ordering::AcqRel) {
            self.metrics.active_sessions.fetch_sub(1, Ordering::Relaxed);
        }
        Some(removed)
    }

    pub fn muc_occupants_for(&self, room_jid: &str) -> Vec<(String, MucOccupant)> {
        let Ok(room_jid) = crate::jid::canonicalize_bare(room_jid) else {
            return Vec::new();
        };
        self.muc_occupants
            .iter()
            .filter(|entry| entry.value().room_jid == room_jid)
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect()
    }

    /// Revoke the exact live protocol actor membership represented by an
    /// occupant.  All four identities are required so a delayed kick or
    /// teardown cannot affect a later connection or a reused nickname.
    pub fn remove_live_muc_membership(&self, occupant: &SerializableMucOccupant) -> bool {
        let Ok(full_jid) = crate::jid::canonical_session_key(&occupant.full_jid) else {
            return false;
        };
        let Some(session) = self.sessions.get(&full_jid) else {
            return false;
        };
        if occupant.connection_id.is_nil() || session.connection_id != occupant.connection_id {
            return false;
        }
        session
            .muc_memberships
            .remove_if(&occupant.room_jid, |_, membership| {
                membership.nick == occupant.nick
                    && membership.cluster_epoch == occupant.cluster_epoch
                    && !membership.cluster_epoch.is_nil()
            })
            .is_some()
    }

    /// Resolve a room membership only when it is still owned by the exact
    /// live transport and occupancy incarnation.  A room/nickname pair is
    /// deliberately insufficient because both values can be reused after a
    /// kick, disconnect, or resume race.
    pub fn validated_local_muc_occupant(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
        room_jid: &str,
        membership: &JoinedMucMembership,
    ) -> Option<MucOccupant> {
        if connection_id.is_nil() || membership.cluster_epoch.is_nil() {
            return None;
        }
        let full_jid = crate::jid::canonical_session_key(full_jid).ok()?;
        let room_jid = crate::jid::canonicalize_bare(room_jid).ok()?;
        let session = self.sessions.get(&full_jid)?;
        if session.connection_id != connection_id
            || !session
                .muc_memberships
                .get(&room_jid)
                .is_some_and(|current| current.value() == membership)
        {
            return None;
        }
        drop(session);
        let key = crate::xmpp::xml_util::muc_occupant_key(&room_jid, &membership.nick);
        self.muc_occupants
            .get(&key)
            .filter(|occupant| {
                muc_actor_identity_matches(
                    occupant,
                    &full_jid,
                    connection_id,
                    &room_jid,
                    membership,
                )
            })
            .map(|occupant| occupant.value().clone())
    }

    pub async fn deliver_to_muc_occupant(&self, occupant: &MucOccupant, stanza: String) -> bool {
        self.deliver_to_muc_occupant_inner(occupant, stanza, None)
            .await
    }

    /// Deliver one durable clustered policy event and wait until the endpoint
    /// owns it recoverably (SM/BOSH/suspended storage) or its socket write has
    /// completed. A successful `try_send` alone is deliberately insufficient.
    pub(crate) async fn deliver_to_muc_occupant_with_receipt(
        &self,
        occupant: &MucOccupant,
        stanza: String,
        delivery: &db::ClusterMucOutboxDelivery,
    ) -> anyhow::Result<bool> {
        let (receipt, mut received) = tokio::sync::mpsc::unbounded_channel();
        let accepted = self
            .deliver_to_muc_occupant_inner(occupant, stanza, Some(receipt))
            .await;
        if !accepted {
            return Ok(false);
        }
        let mut renew = tokio::time::interval(Duration::from_secs(10));
        renew.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                result = received.recv() => return Ok(result.is_some()),
                _ = renew.tick() => {
                    anyhow::ensure!(
                        db::renew_cluster_muc_outbox_claim(
                            &self.pool, delivery, Duration::from_secs(30)
                        ).await?,
                        "cluster MUC transport receipt lost its exact outbox claim"
                    );
                }
            }
        }
    }

    async fn deliver_to_muc_occupant_inner(
        &self,
        occupant: &MucOccupant,
        stanza: String,
        receipt: Option<tokio::sync::mpsc::UnboundedSender<()>>,
    ) -> bool {
        let senders = roxmltree::Document::parse(&stanza)
            .ok()
            .map(|document| {
                let root = document.root_element();
                let mut senders = root
                    .attribute("from")
                    .and_then(|sender| crate::jid::canonicalize(sender).ok())
                    .into_iter()
                    .collect::<Vec<_>>();
                if root.tag_name().name() == "presence" {
                    senders.extend(root.descendants().filter_map(|node| {
                        (node.is_element()
                            && node.tag_name().name() == "item"
                            && node.tag_name().namespace()
                                == Some("http://jabber.org/protocol/muc#user"))
                        .then(|| node.attribute("jid"))
                        .flatten()
                        .and_then(|jid| crate::jid::canonicalize(jid).ok())
                    }));
                }
                senders.sort_unstable();
                senders.dedup();
                senders
            })
            .unwrap_or_default();
        if !senders.is_empty() {
            let blocked = self
                .blocked_muc_recipient_accounts(std::slice::from_ref(occupant), &senders)
                .await;
            if crate::jid::canonical_bare_key(&occupant.full_jid)
                .is_ok_and(|owner| blocked.contains(&owner))
            {
                return false;
            }
        }
        self.deliver_to_muc_occupant_unchecked_result_with_receipt(occupant, stanza, receipt)
            .await
            .unwrap_or_else(|error| {
                tracing::warn!(?error, "failed to deliver a MUC stanza");
                false
            })
    }

    /// Rebuild only the delivery endpoint for an immutable clustered MUC
    /// audience row. This never restores membership in the live maps and
    /// never grants authorization: it exists so a committed terminal event
    /// (kick/ban/destroy/policy eviction) remains deliverable after a process
    /// crash even though PostgreSQL has already revoked the occupancy.
    pub(crate) fn cluster_muc_recipient_from_snapshot(
        &self,
        snapshot: &db::ClusterMucAudienceSnapshot,
        room_jid: &str,
        room_non_anonymous: bool,
        occupant_id: String,
    ) -> Option<MucOccupant> {
        let endpoint = match snapshot.identity_kind.as_str() {
            "local" => {
                if let Some(session) = self.sessions.get(&snapshot.full_jid) {
                    if session.connection_id == snapshot.connection_uuid
                        && snapshot.local_user_id == Some(session.user_id)
                    {
                        MucOccupantEndpoint::Local(session.sender.clone())
                    } else {
                        drop(session);
                        let sm_session_id = snapshot.sm_session_id?;
                        MucOccupantEndpoint::Suspended(Arc::new(SuspendedMucEndpoint::new_durable(
                            sm_session_id,
                        )))
                    }
                } else {
                    let sm_session_id = snapshot.sm_session_id?;
                    MucOccupantEndpoint::Suspended(Arc::new(SuspendedMucEndpoint::new_durable(
                        sm_session_id,
                    )))
                }
            }
            "federated" => MucOccupantEndpoint::Federated {
                authenticated_domain: snapshot.authenticated_domain.clone()?,
                connection_id: snapshot.connection_uuid,
            },
            _ => return None,
        };
        Some(MucOccupant {
            full_jid: snapshot.full_jid.clone(),
            room_jid: room_jid.to_owned(),
            nick: snapshot.nick.clone(),
            endpoint,
            affiliation: snapshot.affiliation.clone(),
            role: snapshot.role.clone(),
            room_non_anonymous,
            occupant_id,
            cluster_epoch: snapshot.occupant_incarnation,
            connection_id: snapshot.connection_uuid,
            sm_session_id: snapshot.sm_session_id,
            // Audience snapshots intentionally omit the recipient's previous
            // presence payload; endpoint reconstruction is delivery-only and
            // must not recreate advertised soft state.
            payload: String::new(),
        })
    }

    /// Batch XEP-0191 filter for MUC fan-out. Database failure is fail-closed
    /// for local occupants so a transient outage cannot leak a blocked room or
    /// real sender; remote occupants remain the responsibility of their home
    /// server.
    pub async fn blocked_muc_recipient_accounts(
        &self,
        occupants: &[MucOccupant],
        stanza_senders: &[String],
    ) -> std::collections::HashSet<String> {
        let occupant_jids = occupants
            .iter()
            .map(|occupant| occupant.full_jid.clone())
            .collect::<Vec<_>>();
        match db::blocked_local_accounts_for_candidates(
            &self.pool,
            &self.config.domain,
            &occupant_jids,
            stanza_senders,
        )
        .await
        {
            Ok(blocked) => blocked,
            Err(error) => {
                tracing::warn!(
                    ?error,
                    "failed MUC recipient blocklist lookup; denying local delivery"
                );
                occupant_jids
                    .iter()
                    .filter_map(|jid| crate::jid::CanonicalJid::parse(jid).ok())
                    .filter(|jid| jid.domainpart() == self.config.domain)
                    .map(|jid| jid.bare())
                    .collect()
            }
        }
    }

    /// Use only after `blocked_muc_recipient_accounts` covered the exact
    /// visible and real senders for this fan-out batch.
    pub async fn deliver_to_muc_occupant_unchecked(
        &self,
        occupant: &MucOccupant,
        stanza: String,
    ) -> bool {
        self.deliver_to_muc_occupant_unchecked_result(occupant, stanza)
            .await
            .unwrap_or_else(|error| {
                tracing::warn!(?error, "failed to deliver a MUC stanza");
                false
            })
    }

    async fn deliver_to_muc_occupant_unchecked_result(
        &self,
        occupant: &MucOccupant,
        stanza: String,
    ) -> anyhow::Result<bool> {
        self.deliver_to_muc_occupant_unchecked_result_with_receipt(occupant, stanza, None)
            .await
    }

    async fn deliver_to_muc_occupant_unchecked_result_with_receipt(
        &self,
        occupant: &MucOccupant,
        stanza: String,
        receipt: Option<tokio::sync::mpsc::UnboundedSender<()>>,
    ) -> anyhow::Result<bool> {
        // Installing the session gate precedes the per-room endpoint swaps.
        // Consulting it first makes that multi-entry transition atomic from
        // every delivery path's point of view and preserves one cross-room
        // FIFO from the first quiesced stanza onward.
        let session_gate = if matches!(
            &occupant.endpoint,
            MucOccupantEndpoint::Local(_) | MucOccupantEndpoint::Suspended(_)
        ) {
            let sm_session_id = occupant.sm_session_id.or_else(|| {
                self.sessions.get(&occupant.full_jid).and_then(|session| {
                    if session.connection_id != occupant.connection_id {
                        return None;
                    }
                    let sm_session_id = *session
                        .sm_session_id
                        .read()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    sm_session_id
                })
            });
            sm_session_id.and_then(|sm_session_id| {
                self.suspended_muc_sessions
                    .get(&sm_session_id)
                    .map(|endpoint| Arc::clone(&endpoint))
            })
        } else {
            None
        };
        let privacy_peer_kind = roxmltree::Document::parse(&stanza)
            .ok()
            .and_then(|document| {
                let root = document.root_element();
                let kind = match root.tag_name().name() {
                    "message" => db::PrivacyStanzaKind::Message,
                    "iq" => db::PrivacyStanzaKind::Iq,
                    "presence" => db::PrivacyStanzaKind::PresenceIn,
                    _ => return None,
                };
                let peer = root
                    .attribute("from")
                    .and_then(|from| crate::jid::canonicalize(from).ok())?;
                Some((peer, kind))
            });
        if let Some((peer, kind)) = privacy_peer_kind.as_ref() {
            if let Some(suspended) = &session_gate {
                if db::privacy_denies_for_sm_session(
                    &self.pool,
                    suspended.sm_session_id,
                    peer,
                    *kind,
                )
                .await?
                .unwrap_or(true)
                {
                    return Ok(false);
                }
            } else {
                match &occupant.endpoint {
                    MucOccupantEndpoint::Local(_) => {
                        let Some(session) =
                            self.sessions_for(&occupant.full_jid).into_iter().next()
                        else {
                            return Ok(false);
                        };
                        if !self.privacy_allows_session(&session, peer, *kind).await? {
                            return Ok(false);
                        }
                    }
                    MucOccupantEndpoint::Suspended(suspended) => {
                        if db::privacy_denies_for_sm_session(
                            &self.pool,
                            suspended.sm_session_id,
                            peer,
                            *kind,
                        )
                        .await?
                        .unwrap_or(true)
                        {
                            return Ok(false);
                        }
                    }
                    MucOccupantEndpoint::Federated { .. } => {}
                }
            }
        }
        if let Some(suspended) = session_gate {
            return self
                .deliver_to_suspended_muc_endpoint(&suspended, stanza, receipt)
                .await;
        }
        match &occupant.endpoint {
            MucOccupantEndpoint::Local(sender) => match receipt {
                Some(receipt) => match sender.try_send_with_transport_receipt(stanza, receipt) {
                    Ok(()) => Ok(true),
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => Ok(false),
                    Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                        anyhow::bail!("local MUC recipient queue is full")
                    }
                },
                None => match sender.try_send(stanza) {
                    Ok(()) => Ok(true),
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => Ok(false),
                    Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                        anyhow::bail!("local MUC recipient queue is full")
                    }
                },
            },
            MucOccupantEndpoint::Suspended(suspended) => {
                self.deliver_to_suspended_muc_endpoint(suspended, stanza, receipt)
                    .await
            }
            MucOccupantEndpoint::Federated {
                authenticated_domain,
                ..
            } => {
                anyhow::ensure!(
                    self.federation
                        .send(authenticated_domain, stanza, None)
                        .await,
                    "federation queue rejected MUC stanza"
                );
                if let Some(receipt) = receipt {
                    let _ = receipt.send(());
                }
                Ok(true)
            }
        }
    }

    async fn deliver_to_suspended_muc_endpoint(
        &self,
        suspended: &Arc<SuspendedMucEndpoint>,
        stanza: String,
        receipt: Option<tokio::sync::mpsc::UnboundedSender<()>>,
    ) -> anyhow::Result<bool> {
        let mut stanza = Some(stanza);
        let mut receipt = receipt;
        let volatile_source_id = uuid::Uuid::new_v4();
        loop {
            // Live delivery and Live->Transitioning use this exact synchronous
            // mutex. There is no check/send window in which cleanup can install
            // a fence behind an already-approved old transport write.
            let wait_for_route = {
                let route = suspended
                    .route
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                match &*route {
                    SuspendedMucRoute::Live(sender) => {
                        let stanza = stanza.take().expect("MUC delivery owns one stanza");
                        return match receipt.take() {
                            Some(receipt) => sender
                                .try_send_with_transport_receipt(stanza, receipt)
                                .map(|_| true)
                                .map_err(|error| {
                                    anyhow::anyhow!(
                                        "resuming MUC recipient queue rejected stanza: {error}"
                                    )
                                }),
                            None => match sender.try_send(stanza) {
                                Ok(()) => Ok(true),
                                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => Ok(false),
                                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                                    anyhow::bail!("resuming MUC recipient queue is full")
                                }
                            },
                        };
                    }
                    SuspendedMucRoute::Transitioning => true,
                    SuspendedMucRoute::Suspended => false,
                }
            };
            if wait_for_route {
                // Transitioning is a synchronous critical section; yielding is
                // sufficient and avoids a lost-wakeup window around Notify.
                tokio::task::yield_now().await;
                continue;
            }

            let mut buffer = suspended.buffer.lock().await;
            match buffer.phase.clone() {
                SuspendedMucPhase::Dormant => {
                    // Commit publishes Dormant before switching the synchronous
                    // route to Live. Loop through the route fence once more.
                    drop(buffer);
                }
                SuspendedMucPhase::Collecting | SuspendedMucPhase::Resuming => {
                    anyhow::ensure!(
                        receipt.is_none(),
                        "cluster MUC outbox cannot transfer ownership to a volatile suspended buffer"
                    );
                    let stanza_ref = stanza.as_deref().expect("MUC delivery owns one stanza");
                    let next_bytes = buffer
                        .bytes
                        .checked_add(stanza_ref.len())
                        .ok_or_else(|| anyhow::anyhow!("suspended MUC byte count overflow"))?;
                    let total_stanzas = buffer
                        .base_stanzas
                        .checked_add(buffer.stanzas.len() + 1)
                        .ok_or_else(|| {
                        anyhow::anyhow!("suspended MUC stanza count overflow")
                    })?;
                    let total_bytes = buffer
                        .base_bytes
                        .checked_add(next_bytes)
                        .ok_or_else(|| anyhow::anyhow!("suspended MUC byte count overflow"))?;
                    anyhow::ensure!(
                        total_stanzas <= self.config.sm_max_unacked_stanzas
                            && total_bytes <= self.config.sm_max_unacked_bytes,
                        "suspended MUC recipient queue is unavailable or full"
                    );
                    let capacity = suspended
                        .sm_capacity
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .clone()
                        .ok_or_else(|| {
                            self.sm_memory_governor.mark_invariant_failure();
                            anyhow::anyhow!("suspended MUC route has no SM memory reservation")
                        })?;
                    let growth = std::mem::size_of::<SuspendedMucStanza>()
                        .checked_add(stanza_ref.len())
                        .ok_or_else(|| anyhow::anyhow!("suspended MUC allocation overflow"))?;
                    capacity.try_grow_by(growth).map_err(|error| {
                        anyhow::anyhow!("suspended MUC memory admission rejected: {error}")
                    })?;
                    anyhow::ensure!(
                        buffer.enqueue_volatile(
                            stanza.take().expect("MUC delivery owns one stanza"),
                            self.config.sm_max_unacked_stanzas,
                            self.config.sm_max_unacked_bytes,
                        ),
                        "suspended MUC recipient queue is unavailable or full"
                    );
                    return Ok(true);
                }
                SuspendedMucPhase::Durable => {
                    // Keep the session-global endpoint mutex across the append.
                    // A resume claim cannot overtake this stanza, and every room
                    // shares the same SM sequence owner.
                    let stored = db::append_suspended_sm_stanza(
                        &self.pool,
                        suspended.sm_session_id,
                        volatile_source_id,
                        stanza.as_deref().expect("MUC delivery owns one stanza"),
                        self.config.sm_max_unacked_stanzas,
                        self.config.sm_max_unacked_bytes,
                    )
                    .await?;
                    if stored {
                        stanza.take();
                        if let Some(receipt) = receipt.take() {
                            let _ = receipt.send(());
                        }
                    }
                    return Ok(stored);
                }
                SuspendedMucPhase::Waiting
                | SuspendedMucPhase::Reserved
                | SuspendedMucPhase::Committing
                | SuspendedMucPhase::CheckpointOwned
                | SuspendedMucPhase::Sealed => {
                    // These are ownership transitions, not delivery failures.
                    // Register the waiter while the phase mutex is still held
                    // so a concurrent notification cannot be missed.
                    let notified = suspended.changed.notified();
                    tokio::pin!(notified);
                    notified.as_mut().enable();
                    drop(buffer);
                    notified.await;
                }
            }
        }
    }

    pub fn acquire_client_connection(
        self: &Arc<Self>,
        ip: std::net::IpAddr,
    ) -> Option<ClientConnectionGuard> {
        let permit = Arc::clone(&self.client_connections)
            .try_acquire_owned()
            .ok()?;
        {
            let mut count = self.client_connections_by_ip.entry(ip).or_insert(0);
            if *count >= self.config.max_connections_per_ip {
                let remove_zero = *count == 0;
                drop(count);
                if remove_zero {
                    self.client_connections_by_ip.remove(&ip);
                }
                return None;
            }
            *count += 1;
        }
        Some(ClientConnectionGuard {
            state: Arc::clone(self),
            ip,
            _permit: permit,
        })
    }

    pub fn acquire_upload_request(
        self: &Arc<Self>,
        ip: std::net::IpAddr,
    ) -> Option<UploadRequestGuard> {
        let permit = Arc::clone(&self.upload_requests).try_acquire_owned().ok()?;
        {
            let mut count = self.upload_requests_by_ip.entry(ip).or_insert(0);
            if *count >= 4 {
                let remove_zero = *count == 0;
                drop(count);
                if remove_zero {
                    self.upload_requests_by_ip.remove(&ip);
                }
                return None;
            }
            *count += 1;
        }
        Some(UploadRequestGuard {
            state: Arc::clone(self),
            ip,
            _permit: permit,
        })
    }

    pub fn acquire_upload_download(
        self: &Arc<Self>,
        ip: std::net::IpAddr,
    ) -> Option<UploadDownloadGuard> {
        let permit = Arc::clone(&self.upload_downloads)
            .try_acquire_owned()
            .ok()?;
        let mut count = self.upload_downloads_by_ip.entry(ip).or_insert(0);
        if *count >= self.config.upload_download_max_per_ip {
            let remove_zero = *count == 0;
            drop(count);
            if remove_zero {
                self.upload_downloads_by_ip.remove(&ip);
            }
            return None;
        }
        *count += 1;
        drop(count);
        Some(UploadDownloadGuard {
            state: Arc::clone(self),
            ip,
            _permit: permit,
        })
    }

    pub fn acquire_omemo_recovery_poll(
        &self,
        ip: std::net::IpAddr,
    ) -> Option<OwnedSemaphorePermit> {
        let now = Instant::now();
        let check = self
            .omemo_recovery_poll_request_checks
            .fetch_add(1, Ordering::Relaxed);
        if !admit_bounded_omemo_poll_ip(
            &self.omemo_recovery_poll_requests_by_ip,
            &self.omemo_recovery_poll_ip_admission,
            ip,
            now,
            check.is_multiple_of(256),
            OMEMO_POLL_MAX_ACTIVE_IPS,
        ) {
            self.metrics
                .omemo_recovery_poll_rate_limited_total
                .fetch_add(1, Ordering::Relaxed);
            return None;
        }
        match Arc::clone(&self.omemo_recovery_poll_requests).try_acquire_owned() {
            Ok(permit) => Some(permit),
            Err(_) => {
                self.metrics
                    .omemo_recovery_poll_concurrency_rejected_total
                    .fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    pub fn omemo_recovery_poll_pool(&self) -> &PgPool {
        &self.omemo_recovery_poll_pool
    }

    /// Revoke every local live route and every durable resumable XMPP session
    /// for an account before returning.  Other nodes receive the committed
    /// authorization-generation fence over Redis; if that control path is
    /// unavailable, their 30-second PostgreSQL maintenance sweep provides the
    /// bounded fallback rather than pretending remote socket teardown was
    /// synchronously acknowledged.
    pub async fn disconnect_account(&self, user_id: uuid::Uuid, bare_account_jid: &str) {
        self.revoke_local_account_routes(user_id, bare_account_jid, None);
        if let Err(error) = self.revoke_user_sm_sessions_with_teardown(user_id).await {
            tracing::error!(?error, %user_id, "failed to revoke durable SM sessions");
        }
        // The credential mutation has already committed at this point.  A
        // failed Redis control must therefore be reported and retried by the
        // generation maintenance sweep, never surfaced as a fake mutation
        // failure to the client.
        let generation = match db::find_user_by_id(&self.pool, user_id).await {
            Ok(Some(user)) => user.auth_generation,
            Ok(None) => i64::MAX,
            Err(error) => {
                tracing::error!(?error, %user_id, "could not load the post-mutation auth generation");
                return;
            }
        };
        if let Err(error) = self
            .cluster
            .send_account_generation_teardown(bare_account_jid, user_id, generation)
            .await
        {
            tracing::error!(
                ?error,
                %user_id,
                auth_generation = generation,
                "cross-node account revocation was not acknowledged; maintenance will retry"
            );
        }
    }

    /// Revoke only transports authenticated before a committed authorization
    /// fence.  Unlike `disconnect_account`, this remains safe when the control
    /// is delayed or replayed after the replacement browser has logged in.
    pub async fn disconnect_account_before_auth_generation(
        &self,
        user_id: uuid::Uuid,
        bare_account_jid: &str,
        auth_generation_exclusive: i64,
    ) {
        if auth_generation_exclusive <= 0 {
            tracing::error!(
                %user_id,
                auth_generation = auth_generation_exclusive,
                "refused invalid account authorization teardown fence"
            );
            return;
        }
        self.revoke_local_account_routes(
            user_id,
            bare_account_jid,
            Some(auth_generation_exclusive),
        );
        if let Err(error) = self
            .revoke_user_sm_sessions_before_auth_generation_with_teardown(
                user_id,
                auth_generation_exclusive,
            )
            .await
        {
            tracing::error!(
                ?error,
                %user_id,
                auth_generation = auth_generation_exclusive,
                "failed to revoke generation-fenced durable SM sessions"
            );
        }
        if let Err(error) = self
            .cluster
            .send_account_generation_teardown(bare_account_jid, user_id, auth_generation_exclusive)
            .await
        {
            tracing::error!(
                ?error,
                %user_id,
                auth_generation = auth_generation_exclusive,
                "generation-fenced cross-node account revocation was not acknowledged"
            );
        }
    }

    pub async fn revoke_user_sm_sessions_with_teardown(
        &self,
        user_id: uuid::Uuid,
    ) -> anyhow::Result<usize> {
        let lease = self.config.sm_claim_lease_seconds.max(1);
        let deadline =
            tokio::time::Instant::now() + std::time::Duration::from_secs(lease.saturating_add(2));
        let mut total = 0usize;
        loop {
            let batch = db::take_user_sm_sessions_for_teardown(&self.pool, user_id, lease).await?;
            total = total.saturating_add(batch.snapshots.len());
            for snapshot in batch.snapshots {
                self.perform_and_finalize_sm_teardown(snapshot).await?;
            }
            if batch.pending == 0 && db::count_user_sm_rows(&self.pool, user_id).await? == 0 {
                return Ok(total);
            }
            anyhow::ensure!(
                tokio::time::Instant::now() < deadline,
                "durable SM account teardown claims did not quiesce before the deadline"
            );
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    }

    async fn revoke_user_sm_sessions_before_auth_generation_with_teardown(
        &self,
        user_id: uuid::Uuid,
        auth_generation_exclusive: i64,
    ) -> anyhow::Result<usize> {
        let lease = self.config.sm_claim_lease_seconds.max(1);
        let deadline =
            tokio::time::Instant::now() + std::time::Duration::from_secs(lease.saturating_add(2));
        let mut total = 0usize;
        loop {
            let batch = db::take_user_sm_sessions_before_auth_generation_for_teardown(
                &self.pool,
                user_id,
                auth_generation_exclusive,
                lease,
            )
            .await?;
            total = total.saturating_add(batch.snapshots.len());
            for snapshot in batch.snapshots {
                self.perform_and_finalize_sm_teardown(snapshot).await?;
            }
            if batch.pending == 0
                && db::count_user_sm_rows_before_auth_generation(
                    &self.pool,
                    user_id,
                    auth_generation_exclusive,
                )
                .await?
                    == 0
            {
                return Ok(total);
            }
            anyhow::ensure!(
                tokio::time::Instant::now() < deadline,
                "generation-fenced SM teardown claims did not quiesce before the deadline"
            );
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    }

    /// Atomically acquire and tear down every expired durable SM stream.
    /// PostgreSQL skips a still-live resume claim, ensuring that activation
    /// and expiry can never both own the same presence session.
    pub async fn cleanup_expired_sm_sessions(&self) -> anyhow::Result<usize> {
        let mut total = 0usize;
        let mut first_error = None;
        loop {
            let snapshots = db::cleanup_expired_sm_sessions(
                &self.pool,
                self.config.sm_claim_lease_seconds.max(1),
            )
            .await?;
            let batch = snapshots.len();
            total = total.saturating_add(batch);
            for snapshot in snapshots {
                // An unclean process/transport failure can leave `resumable`
                // false until the live lease expires. Expiry is final in
                // either representation and therefore owns teardown.
                if let Err(error) = self.perform_and_finalize_sm_teardown(snapshot).await {
                    tracing::warn!(
                        ?error,
                        "expired SM teardown will be retried after its lease"
                    );
                    first_error.get_or_insert(error);
                }
            }
            if batch < 256 {
                break;
            }
            tokio::task::yield_now().await;
        }
        if let Some(error) = first_error {
            return Err(error);
        }
        Ok(total)
    }

    pub async fn revoke_sm_session_with_teardown(&self, id: uuid::Uuid) -> anyhow::Result<()> {
        if let Some(snapshot) = db::take_sm_session_for_teardown(
            &self.pool,
            id,
            self.config.sm_claim_lease_seconds.max(1),
        )
        .await?
        {
            self.perform_and_finalize_sm_teardown(snapshot).await?;
        }
        Ok(())
    }

    pub async fn revoke_all_sm_sessions_with_teardown(&self) -> anyhow::Result<usize> {
        let lease = self.config.sm_claim_lease_seconds.max(1);
        let deadline =
            tokio::time::Instant::now() + std::time::Duration::from_secs(lease.saturating_add(2));
        let mut total = 0usize;
        loop {
            let batch = db::take_all_sm_sessions_for_teardown(&self.pool, lease).await?;
            total = total.saturating_add(batch.snapshots.len());
            for snapshot in batch.snapshots {
                self.perform_and_finalize_sm_teardown(snapshot).await?;
            }
            if batch.pending == 0 && db::count_all_sm_rows(&self.pool).await? == 0 {
                return Ok(total);
            }
            anyhow::ensure!(
                tokio::time::Instant::now() < deadline,
                "global durable SM teardown claims did not quiesce before the deadline"
            );
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    }

    async fn perform_and_finalize_sm_teardown(
        &self,
        snapshot: db::SmTeardownSnapshot,
    ) -> anyhow::Result<()> {
        self.teardown_sm_snapshot(&snapshot).await?;
        anyhow::ensure!(
            db::finalize_sm_teardown(&self.pool, snapshot.session_id, snapshot.teardown_token)
                .await?,
            "durable SM teardown lease was lost before finalization"
        );
        Ok(())
    }

    async fn teardown_sm_snapshot(&self, snapshot: &db::SmTeardownSnapshot) -> anyhow::Result<()> {
        let Ok(full_jid) = crate::jid::canonical_session_key(&snapshot.full_jid) else {
            tracing::warn!(sm_session_id = %snapshot.session_id, "discarded invalid durable SM teardown JID");
            anyhow::bail!("invalid durable SM teardown JID");
        };
        let actor_bare = bare_jid(&full_jid).to_owned();

        if let Some(session) = self.sessions.get_mut(&full_jid) {
            let matches = *session
                .sm_session_id
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                == Some(snapshot.session_id);
            if matches {
                session.routable.store(false, Ordering::Release);
                session.disconnect.cancel();
            }
        }
        self.cluster
            .send_sm_session_teardown(&full_jid, snapshot.session_id)
            .await?;

        let mut first_error = None;

        if snapshot.available {
            let unavailable = format!(
                "<presence xmlns='jabber:client' from='{}' type='unavailable'/>",
                attr_escape(&full_jid)
            );
            let mut routed = HashSet::new();
            let roster = db::roster(&self.pool, snapshot.user_id).await?;
            for (jid, _, subscription, _) in roster {
                if matches!(subscription.as_str(), "from" | "both") && routed.insert(jid.clone()) {
                    if let Err(error) = self
                        .route_unavailable_with_policy(
                            snapshot.user_id,
                            snapshot.active_privacy_list.as_deref(),
                            &full_jid,
                            &unavailable,
                            &jid,
                        )
                        .await
                    {
                        first_error.get_or_insert(error);
                    }
                }
            }

            // Other resources of the same account are part of the same
            // presence session audience, independent of roster privacy.
            if let Err(error) = self
                .route_sm_unavailable_unchecked(&full_jid, &unavailable, &actor_bare, false)
                .await
            {
                first_error.get_or_insert(error);
            }

            for target in &snapshot.directed_presence {
                if routed.insert(target.clone()) {
                    if let Err(error) = self
                        .route_unavailable_with_policy(
                            snapshot.user_id,
                            snapshot.active_privacy_list.as_deref(),
                            &full_jid,
                            &unavailable,
                            target,
                        )
                        .await
                    {
                        first_error.get_or_insert(error);
                    }
                }
            }
        }

        let mut memberships = HashSet::new();
        for membership in &snapshot.joined_rooms {
            let Ok(room_jid) = crate::jid::canonicalize_bare(&membership.room_jid) else {
                continue;
            };
            let Ok(nick) = crate::xmpp::xml_util::prepare_muc_nick(&membership.nick) else {
                continue;
            };
            if !memberships.insert((room_jid.clone(), nick.clone())) {
                continue;
            }
            let occupant = self
                .sm_teardown_muc_occupant(
                    snapshot.session_id,
                    snapshot.user_id,
                    &full_jid,
                    &room_jid,
                    &nick,
                )
                .await?;
            if let Err(error) = self
                .cluster
                .send_sm_muc_teardown(&room_jid, snapshot.session_id, &occupant)
                .await
            {
                tracing::warn!(?error, %room_jid, "failed to publish clustered SM MUC teardown");
                first_error.get_or_insert(error);
            }
            if let Err(error) = self
                .teardown_suspended_muc_membership(snapshot.session_id, &occupant)
                .await
            {
                first_error.get_or_insert(error);
            }
        }
        if let Some(error) = first_error {
            return Err(error);
        }
        self.suspended_muc_sessions.remove(&snapshot.session_id);
        Ok(())
    }

    pub(crate) async fn route_unavailable_with_policy(
        &self,
        owner_id: uuid::Uuid,
        active_privacy_list: Option<&str>,
        from: &str,
        unavailable: &str,
        target: &str,
    ) -> anyhow::Result<()> {
        if db::is_blocked_for_account(&self.pool, owner_id, bare_jid(from), target).await? {
            return Ok(());
        }
        if db::privacy_denies(
            &self.pool,
            owner_id,
            active_privacy_list,
            target,
            db::PrivacyStanzaKind::PresenceOut,
        )
        .await?
        {
            return Ok(());
        }
        let Ok(target_jid) = crate::jid::CanonicalJid::parse(target) else {
            anyhow::bail!("invalid SM teardown presence target");
        };
        if target_jid.domainpart() == self.config.domain {
            if let Some(username) = target_jid.localpart() {
                match db::find_enabled_user(&self.pool, username).await? {
                    Some(recipient) => {
                        if db::is_blocked_for_account(
                            &self.pool,
                            recipient.id,
                            &target_jid.bare(),
                            from,
                        )
                        .await?
                        {
                            return Ok(());
                        }
                    }
                    None => return Ok(()),
                }
            }
        }
        self.route_sm_unavailable_unchecked(from, unavailable, target, true)
            .await
    }

    async fn route_sm_unavailable_unchecked(
        &self,
        from: &str,
        unavailable: &str,
        target: &str,
        recipient_privacy: bool,
    ) -> anyhow::Result<()> {
        let Ok(target_jid) = crate::jid::CanonicalJid::parse(target) else {
            anyhow::bail!("invalid SM teardown presence target");
        };
        let canonical_target = target_jid.to_string();
        let delivery = crate::xmpp::xml_util::set_to(unavailable, &canonical_target);
        if target_jid.domainpart() == self.config.domain {
            let mut recipients = self.session_entries_for(&canonical_target);
            if target_jid.resourcepart().is_none() {
                recipients.retain(|(_, session)| {
                    session.available.load(std::sync::atomic::Ordering::Relaxed)
                });
            }
            recipients.retain(|(jid, _)| jid != from);
            for (jid, recipient) in recipients {
                if recipient_privacy
                    && !self
                        .privacy_allows_session(&recipient, from, db::PrivacyStanzaKind::PresenceIn)
                        .await?
                {
                    continue;
                }
                if let Err(tokio::sync::mpsc::error::TrySendError::Full(_)) = recipient
                    .sender
                    .try_send(crate::xmpp::xml_util::set_to(unavailable, &jid))
                {
                    anyhow::bail!("local SM unavailable recipient queue is full");
                }
            }
            for node_id in self.cluster.lookup_nodes(&canonical_target).await? {
                if node_id == self.cluster.node_id {
                    continue;
                }
                if target_jid.resourcepart().is_none() {
                    self.cluster
                        .send_to_node_available_presence_confirmed_excluding(
                            &node_id,
                            &canonical_target,
                            &delivery,
                            Some(from),
                        )
                        .await?;
                } else {
                    self.cluster
                        .send_to_node_confirmed(&node_id, &canonical_target, &delivery, Some(from))
                        .await?;
                }
            }
        } else if self
            .config
            .external_route_domain_allowed(target_jid.domainpart())
        {
            anyhow::ensure!(
                self.federation
                    .send(target_jid.domainpart(), delivery, Some(from.to_owned()))
                    .await,
                "federation queue rejected SM unavailable presence"
            );
        }
        Ok(())
    }

    async fn sm_teardown_muc_occupant(
        &self,
        sm_session_id: uuid::Uuid,
        user_id: uuid::Uuid,
        full_jid: &str,
        room_jid: &str,
        nick: &str,
    ) -> anyhow::Result<SerializableMucOccupant> {
        let key = crate::xmpp::xml_util::muc_occupant_key(room_jid, nick);
        if let Some(occupant) = self.muc_occupants.get(&key).filter(|occupant| {
            occupant.full_jid == full_jid
                && occupant.room_jid == room_jid
                && occupant.nick == nick
                && !occupant.cluster_epoch.is_nil()
                && !occupant.connection_id.is_nil()
                && matches!(
                    &occupant.endpoint,
                    MucOccupantEndpoint::Suspended(endpoint)
                        if endpoint.sm_session_id == sm_session_id
                )
        }) {
            return Ok(SerializableMucOccupant::from(&*occupant));
        }
        let room = db::muc_room(&self.pool, localpart(room_jid)).await?;
        let affiliation = if let Some(room) = &room {
            db::muc_affiliation(&self.pool, room.id, user_id)
                .await?
                .unwrap_or_else(|| "none".to_owned())
        } else {
            "none".to_owned()
        };
        let role = if matches!(affiliation.as_str(), "owner" | "admin") {
            "moderator"
        } else {
            "participant"
        };
        Ok(SerializableMucOccupant {
            full_jid: full_jid.to_owned(),
            room_jid: room_jid.to_owned(),
            nick: nick.to_owned(),
            affiliation,
            role: role.to_owned(),
            room_non_anonymous: room.as_ref().is_none_or(|room| room.non_anonymous),
            occupant_id: room
                .as_ref()
                .map(|room| {
                    crate::xmpp::xml_util::muc_occupant_id(
                        &room.occupant_id_secret,
                        bare_jid(full_jid),
                    )
                })
                .unwrap_or_default(),
            cluster_epoch: uuid::Uuid::new_v4(),
            connection_id: uuid::Uuid::nil(),
            federated_domain: None,
            sm_session_id: Some(sm_session_id),
            payload: String::new(),
        })
    }

    /// Remove one exact suspended actor and publish the already-authorized
    /// unavailable event to this node's room occupants. Called both by the DB
    /// teardown owner and by authenticated Redis cluster fanout.
    pub async fn teardown_suspended_muc_membership(
        &self,
        sm_session_id: uuid::Uuid,
        occupant: &SerializableMucOccupant,
    ) -> anyhow::Result<usize> {
        let key = crate::xmpp::xml_util::muc_occupant_key(&occupant.room_jid, &occupant.nick);
        let removed = self.muc_occupants.remove_if(&key, |_, current| {
            muc_suspended_teardown_identity_matches(current, sm_session_id, occupant)
        });
        if removed.is_some() {
            self.cluster
                .unregister_muc_occupant_epoch(
                    &occupant.room_jid,
                    &occupant.nick,
                    occupant.cluster_epoch,
                    occupant.connection_id,
                )
                .await?;
        }
        let remaining = self.muc_occupants_for(&occupant.room_jid);
        let occupant_jids = remaining
            .iter()
            .map(|(_, target)| target.full_jid.clone())
            .collect::<Vec<_>>();
        let visible_sender = format!("{}/{}", occupant.room_jid, occupant.nick);
        let blocked = db::blocked_local_accounts_for_candidates(
            &self.pool,
            &self.config.domain,
            &occupant_jids,
            &[visible_sender, occupant.full_jid.clone()],
        )
        .await?;
        let mut delivered = 0;
        for (_, target) in &remaining {
            if crate::jid::canonical_bare_key(&target.full_jid)
                .is_ok_and(|owner| blocked.contains(&owner))
            {
                continue;
            }
            let presence = crate::xmpp::xml_util::muc_presence_stanza(
                occupant,
                &target.full_jid,
                true,
                false,
                false,
                None,
                occupant.room_non_anonymous || target.role == "moderator",
            );
            delivered += usize::from(
                self.deliver_to_muc_occupant_unchecked_result(target, presence)
                    .await?,
            );
        }
        if remaining.is_empty() {
            self.cluster.leave_muc(&occupant.room_jid).await?;
        }
        let globally_empty = self
            .cluster
            .get_muc_occupants(&occupant.room_jid)
            .await?
            .is_empty();
        if globally_empty && remaining.is_empty() {
            if let Some(room) = db::muc_room(&self.pool, localpart(&occupant.room_jid)).await? {
                db::delete_temporary_muc_room(
                    &self.pool,
                    room.id,
                    room.room_epoch,
                    room.config_version,
                )
                .await?;
            }
        }
        Ok(delivered)
    }

    /// Give every locally-owned MUC endpoint the XEP-0045 system-shutdown
    /// status before listener cancellation tears transports down. One self
    /// unavailable per occupancy avoids an O(n²) room broadcast during the
    /// bounded graceful-shutdown window.
    pub async fn notify_muc_system_shutdown(&self) -> usize {
        let occupants = self
            .muc_occupants
            .iter()
            .map(|entry| entry.value().clone())
            .collect::<Vec<_>>();
        let mut delivered = 0;
        for occupant in occupants {
            let serialized = SerializableMucOccupant::from(&occupant);
            let stanza = crate::xmpp::xml_util::muc_presence_stanza_with_status(
                &serialized,
                &occupant.full_jid,
                true,
                true,
                false,
                None,
                true,
                Some(332),
                None,
                None,
            );
            delivered += usize::from(self.deliver_to_muc_occupant(&occupant, stanza).await);
        }
        delivered
    }

    pub fn suspend_local_muc_occupants(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
        sm_session_id: uuid::Uuid,
        memberships: &DashMap<String, JoinedMucMembership>,
        base_stanzas: usize,
        base_bytes: usize,
    ) -> Vec<Arc<SuspendedMucEndpoint>> {
        // Publish the session fence before walking independent room entries.
        // Delivery consults this registry ahead of each endpoint, so no room
        // can continue accepting into the disappearing transport while a
        // later room has already switched to the suspension FIFO.
        let proposed = Arc::new(SuspendedMucEndpoint::new_collecting(
            sm_session_id,
            base_stanzas,
            base_bytes,
        ));
        let endpoint =
            canonical_suspended_muc_endpoint(&self.suspended_muc_sessions, sm_session_id, proposed);
        begin_suspended_muc_route_transition(&endpoint, base_stanzas, base_bytes);
        for membership in memberships {
            let room_jid = membership.key();
            let membership = membership.value();
            let key = crate::xmpp::xml_util::muc_occupant_key(room_jid, &membership.nick);
            let Some(mut occupant) = self.muc_occupants.get_mut(&key) else {
                continue;
            };
            if !muc_actor_epoch_matches(&occupant, full_jid, connection_id, room_jid, membership)
                || occupant.sm_session_id != Some(sm_session_id)
            {
                continue;
            }
            match &occupant.endpoint {
                MucOccupantEndpoint::Local(_) => {
                    occupant.endpoint = MucOccupantEndpoint::Suspended(Arc::clone(&endpoint));
                }
                MucOccupantEndpoint::Suspended(current)
                    if Arc::ptr_eq(current, &endpoint)
                        && current.sm_session_id == sm_session_id => {}
                MucOccupantEndpoint::Suspended(_) | MucOccupantEndpoint::Federated { .. } => {}
            }
        }
        // Even a stale membership plan returns the published fence: an
        // in-flight delivery may already hold its Arc and must be promoted (or
        // remain visibly sealed) instead of being acknowledged into a dropped
        // buffer.
        vec![endpoint]
    }

    /// Associate MUC occupants which were joined before SM enable with the
    /// newly-created durable stream epoch and update their Redis control
    /// records. This also makes active-session revocation exact and immune to
    /// nick reuse races.
    pub async fn associate_local_muc_sm_session(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
        sm_session_id: uuid::Uuid,
        memberships: &DashMap<String, JoinedMucMembership>,
    ) {
        // Install the session-global gate even when the resource has not joined
        // a room yet. Future joins carry `sm_session_id` and therefore route
        // through this same Arc from their first stanza onward.
        let Some(live_sender) = self.sessions.get(full_jid).and_then(|session| {
            (session.connection_id == connection_id).then(|| session.sender.clone())
        }) else {
            tracing::warn!(%full_jid, %connection_id, %sm_session_id,
                "could not install the live SM MUC route gate");
            return;
        };
        let proposed = Arc::new(SuspendedMucEndpoint::new_live(sm_session_id, live_sender));
        let _endpoint =
            canonical_suspended_muc_endpoint(&self.suspended_muc_sessions, sm_session_id, proposed);
        for membership in memberships {
            let room_jid = membership.key();
            let membership = membership.value();
            let key = crate::xmpp::xml_util::muc_occupant_key(room_jid, &membership.nick);
            let serializable = {
                let Some(mut occupant) = self.muc_occupants.get_mut(&key) else {
                    continue;
                };
                if !muc_actor_identity_matches(
                    &occupant,
                    full_jid,
                    connection_id,
                    room_jid,
                    membership,
                ) {
                    continue;
                }
                occupant.sm_session_id = Some(sm_session_id);
                SerializableMucOccupant::from(&*occupant)
            };
            let encoded = serde_json::to_string(&serializable).unwrap_or_default();
            if self.cluster.is_enabled() {
                let association = async {
                    let room =
                        db::muc_room(&self.pool, crate::state::localpart(&serializable.room_jid))
                            .await?
                            .context("SM association references a missing MUC room")?;
                    let target = db::cluster_muc_occupancy_target(
                        &self.pool,
                        room.id,
                        serializable.cluster_epoch,
                        serializable.connection_id,
                    )
                    .await?
                    .context("SM association lost its exact MUC occupancy")?;
                    anyhow::ensure!(
                        db::associate_cluster_muc_sm_session(
                            &self.pool,
                            &target,
                            &self.cluster.node_id,
                            sm_session_id,
                        )
                        .await?,
                        "SM association lost its PG occupancy fence"
                    );
                    Ok::<_, anyhow::Error>(())
                }
                .await;
                if let Err(error) = association {
                    tracing::warn!(?error, room=%serializable.room_jid, nick=%serializable.nick,
                        "failed to associate PG-authoritative MUC occupancy with SM epoch");
                }
            }
            if let Err(error) = self
                .cluster
                .register_suspended_muc_occupant(
                    &serializable.room_jid,
                    &serializable.nick,
                    sm_session_id,
                    &encoded,
                )
                .await
            {
                tracing::warn!(?error, room = %serializable.room_jid, nick = %serializable.nick, "failed to associate clustered MUC occupant with SM epoch");
            }
        }
    }

    pub async fn mark_suspended_muc_durable(
        &self,
        endpoints: Vec<Arc<SuspendedMucEndpoint>>,
    ) -> bool {
        let mut complete = true;
        let mut seen = HashSet::new();
        for endpoint in endpoints {
            if !seen.insert(Arc::as_ptr(&endpoint) as usize) {
                continue;
            }
            let route_is_live = {
                let route = endpoint
                    .route
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                matches!(&*route, SuspendedMucRoute::Live(_))
            };
            if route_is_live {
                continue;
            }
            let mut buffer = endpoint.buffer.lock().await;
            let sm_session_id = endpoint.sm_session_id;
            let pool = &self.pool;
            let max_stanzas = self.config.sm_max_unacked_stanzas;
            let max_bytes = self.config.sm_max_unacked_bytes;
            let promoted = match buffer.phase.clone() {
                SuspendedMucPhase::Durable => true,
                // The caller invokes this method only after the exact SM
                // suspension CAS succeeded. Snapshot ownership is orthogonal
                // to Sealed/Waiting/CheckpointOwned so a lost COMMIT response
                // followed by an immediate claim cannot erase the fact that
                // PostgreSQL already contains this suffix.
                _ if buffer.snapshot_owned => complete_snapshot_owned_handoff(&mut buffer),
                SuspendedMucPhase::Dormant => {
                    buffer.phase = SuspendedMucPhase::Sealed;
                    false
                }
                _ => {
                    promote_suspended_muc_buffer(&mut buffer, |source_id, stanza| async move {
                        match db::append_suspended_sm_stanza(
                            pool,
                            sm_session_id,
                            source_id,
                            &stanza,
                            max_stanzas,
                            max_bytes,
                        )
                        .await
                        {
                            Ok(stored) => stored,
                            Err(error) => {
                                tracing::warn!(
                                    ?error,
                                    %sm_session_id,
                                    "could not append the suspended MUC queue to durable SM storage"
                                );
                                false
                            }
                        }
                    })
                    .await
                }
            };
            if promoted {
                endpoint.changed.notify_waiters();
            }
            drop(buffer);
            if !promoted {
                complete = false;
                tracing::warn!(
                    sm_session_id = %endpoint.sm_session_id,
                    "retained bounded MUC traffic because durable SM storage is unavailable"
                );
            }
            // Replace the Redis occupant value with the exact suspended SM
            // epoch. Any node that later wins PostgreSQL expiry can now
            // remove the cluster record immediately without risking a newly
            // resumed/rejoined occupant which reused the same nick.
            let occupants = self
                .muc_occupants
                .iter()
                .filter_map(|occupant| match &occupant.endpoint {
                    MucOccupantEndpoint::Suspended(current) if Arc::ptr_eq(current, &endpoint) => {
                        Some(SerializableMucOccupant::from(&*occupant))
                    }
                    _ => None,
                })
                .collect::<Vec<_>>();
            for occupant in occupants {
                let encoded = serde_json::to_string(&occupant).unwrap_or_default();
                if self.cluster.is_enabled() {
                    let suspend = async {
                        let room = db::muc_room(&self.pool, localpart(&occupant.room_jid))
                            .await?
                            .context("SM suspension references a missing MUC room")?;
                        let target = db::cluster_muc_occupancy_target(
                            &self.pool,
                            room.id,
                            occupant.cluster_epoch,
                            occupant.connection_id,
                        )
                        .await?
                        .context("SM suspension lost its exact MUC occupancy")?;
                        let operation_id = uuid::Uuid::new_v4();
                        let outcome = db::transition_cluster_muc_occupancy(
                            &self.pool,
                            operation_id,
                            &target,
                            "suspend",
                            &self.cluster.node_id,
                            None,
                            None,
                            Some(endpoint.sm_session_id),
                            Duration::from_secs(90),
                        )
                        .await?;
                        anyhow::ensure!(
                            matches!(
                                outcome,
                                db::ClusterMucTransitionOutcome::Applied
                                    | db::ClusterMucTransitionOutcome::Replay
                            ),
                            "PG MUC suspension rejected stale occupancy: {outcome:?}"
                        );
                        self.muc_service()
                            .wake_committed_operation(&self.cluster, operation_id)
                            .await?;
                        Ok::<_, anyhow::Error>(())
                    }
                    .await;
                    if let Err(error) = suspend {
                        complete = false;
                        tracing::warn!(?error, room=%occupant.room_jid, nick=%occupant.nick,
                            "could not commit PG-authoritative MUC suspension");
                        continue;
                    }
                }
                if let Err(error) = self
                    .cluster
                    .register_suspended_muc_occupant(
                        &occupant.room_jid,
                        &occupant.nick,
                        endpoint.sm_session_id,
                        &encoded,
                    )
                    .await
                {
                    complete = false;
                    tracing::warn!(?error, room = %occupant.room_jid, nick = %occupant.nick, "failed to mark clustered MUC occupant as SM-suspended");
                }
            }
        }
        complete
    }

    pub async fn pause_suspended_muc_delivery(
        &self,
        sm_session_id: uuid::Uuid,
    ) -> Vec<Arc<SuspendedMucEndpoint>> {
        let mut endpoints = self
            .muc_occupants
            .iter()
            .filter_map(|occupant| match &occupant.endpoint {
                MucOccupantEndpoint::Suspended(endpoint)
                    if endpoint.sm_session_id == sm_session_id =>
                {
                    Some(Arc::clone(endpoint))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        if let Some(endpoint) = self.suspended_muc_sessions.get(&sm_session_id) {
            endpoints.push(Arc::clone(&endpoint));
        }
        let mut seen = HashSet::new();
        endpoints.retain(|endpoint| seen.insert(Arc::as_ptr(endpoint) as usize));
        if let Some(endpoint) = endpoints.first() {
            match self.suspended_muc_sessions.entry(sm_session_id) {
                dashmap::mapref::entry::Entry::Vacant(slot) => {
                    slot.insert(Arc::clone(endpoint));
                }
                dashmap::mapref::entry::Entry::Occupied(_) => {}
            }
        }
        for endpoint in &endpoints {
            let transition_from_live = {
                let mut route = endpoint
                    .route
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if matches!(&*route, SuspendedMucRoute::Live(_)) {
                    *route = SuspendedMucRoute::Transitioning;
                    true
                } else {
                    false
                }
            };
            let mut buffer = endpoint.buffer.lock().await;
            buffer.phase = match buffer.phase.clone() {
                SuspendedMucPhase::Durable
                | SuspendedMucPhase::Collecting
                | SuspendedMucPhase::Resuming
                | SuspendedMucPhase::Sealed => SuspendedMucPhase::Waiting,
                SuspendedMucPhase::Reserved => SuspendedMucPhase::Reserved,
                SuspendedMucPhase::Dormant => SuspendedMucPhase::Waiting,
                SuspendedMucPhase::Waiting
                | SuspendedMucPhase::Committing
                | SuspendedMucPhase::CheckpointOwned => SuspendedMucPhase::Sealed,
            };
            drop(buffer);
            if transition_from_live {
                *endpoint
                    .route
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) =
                    SuspendedMucRoute::Suspended;
            }
            endpoint.changed.notify_waiters();
        }
        endpoints
    }

    /// Install the exact post-finalization replay base. `claim_resume` is only
    /// a preliminary snapshot: acknowledgements may advance before the
    /// PostgreSQL activation CAS returns. Keeping the endpoint in `Waiting`
    /// until this method prevents that stale claim size from opening excess
    /// stanza or byte budget.
    pub async fn begin_suspended_muc_resume(
        &self,
        endpoints: &[Arc<SuspendedMucEndpoint>],
        base_stanzas: usize,
        base_bytes: usize,
    ) -> bool {
        let mut complete = true;
        let mut seen = HashSet::new();
        for endpoint in endpoints {
            if !seen.insert(Arc::as_ptr(endpoint) as usize) {
                continue;
            }
            let mut buffer = endpoint.buffer.lock().await;
            match buffer.phase.clone() {
                SuspendedMucPhase::Waiting | SuspendedMucPhase::Sealed => {
                    buffer.base_stanzas = base_stanzas;
                    buffer.base_bytes = base_bytes;
                    buffer.phase = SuspendedMucPhase::Resuming;
                }
                SuspendedMucPhase::Reserved => {
                    buffer.base_stanzas = base_stanzas;
                    buffer.base_bytes = base_bytes;
                }
                _ => complete = false,
            }
            drop(buffer);
            endpoint.changed.notify_waiters();
        }
        complete
    }

    pub async fn seal_suspended_muc_endpoints(&self, endpoints: &[Arc<SuspendedMucEndpoint>]) {
        let mut seen = HashSet::new();
        for endpoint in endpoints {
            if seen.insert(Arc::as_ptr(endpoint) as usize) {
                seal_suspended_muc_buffer(endpoint).await;
            }
        }
    }

    pub(crate) fn retain_suspended_sm_capacity(
        &self,
        endpoints: &[Arc<SuspendedMucEndpoint>],
        capacity: crate::services::sm_capacity::SmCapacityLease,
    ) {
        for endpoint in endpoints {
            *endpoint
                .sm_capacity
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(capacity.clone());
        }
    }

    pub(crate) fn clear_suspended_sm_capacity(&self, endpoints: &[Arc<SuspendedMucEndpoint>]) {
        for endpoint in endpoints {
            endpoint
                .sm_capacity
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
        }
    }

    /// Freeze the one session-global disconnect suffix before the exact SM
    /// suspension transaction and append it directly to that transaction's
    /// snapshot while holding the endpoint mutex. The endpoint retains its
    /// byte-for-byte backup until PostgreSQL confirms ownership. New delivery
    /// waits instead of creating an uncommitted process-crash window.
    pub async fn snapshot_suspended_muc_for_disconnect(
        &self,
        endpoints: &[Arc<SuspendedMucEndpoint>],
        snapshot: &mut crate::services::sm::SmSessionSnapshot,
    ) -> anyhow::Result<()> {
        let mut unique = Vec::new();
        let mut seen = HashSet::new();
        for endpoint in endpoints {
            if seen.insert(Arc::as_ptr(endpoint) as usize) {
                unique.push(endpoint);
            }
        }
        anyhow::ensure!(
            unique.len() <= 1,
            "one SM epoch exposed multiple process-local MUC FIFOs"
        );
        let Some(endpoint) = unique.into_iter().next() else {
            return Ok(());
        };
        let mut buffer = endpoint.buffer.lock().await;
        match buffer.phase.clone() {
            SuspendedMucPhase::Collecting
            | SuspendedMucPhase::Waiting
            | SuspendedMucPhase::Resuming
            | SuspendedMucPhase::Reserved
            | SuspendedMucPhase::Sealed => {
                if !buffer.snapshot_owned {
                    append_suspended_muc_suffix_to_snapshot(
                        snapshot,
                        &buffer.stanzas,
                        self.config.sm_max_unacked_stanzas,
                        self.config.sm_max_unacked_bytes,
                    )?;
                }
            }
            // These phases already correspond to the current ProtocolSession
            // snapshot. Re-appending their backup would duplicate replay.
            SuspendedMucPhase::Committing
            | SuspendedMucPhase::CheckpointOwned
            | SuspendedMucPhase::Durable => {}
            SuspendedMucPhase::Dormant => {
                anyhow::bail!("live MUC route was not fenced before SM suspension")
            }
        }
        buffer.snapshot_owned = true;
        buffer.phase = SuspendedMucPhase::Sealed;
        drop(buffer);
        finalize_suspended_muc_route_transition(endpoint);
        endpoint.changed.notify_waiters();
        Ok(())
    }

    /// Reattach only memberships that can still be proven valid. Existing
    /// suspended actors are swapped in place; after a process restart a new
    /// actor is recreated without join broadcast or history replay. The
    /// volatile suspension FIFO moves into the returned replay suffix so the
    /// resumed stream emits it strictly after `<resumed/>` and the durable
    /// unacked replay.
    pub async fn restore_local_muc_occupants(
        &self,
        request: RestoreLocalMucOccupantsRequest<'_>,
    ) -> RestoredLocalMucOccupants {
        let RestoreLocalMucOccupantsRequest {
            user,
            full_jid,
            connection_id,
            sm_session_id,
            memberships,
            base_stanzas,
            base_bytes,
        } = request;
        let Ok(full_jid) = crate::jid::canonical_session_key(full_jid) else {
            return RestoredLocalMucOccupants {
                failures: memberships.to_vec(),
                replay_suffix: Vec::new(),
                resume_gate: None,
                actors: Vec::new(),
            };
        };
        if connection_id.is_nil() {
            return RestoredLocalMucOccupants {
                failures: memberships.to_vec(),
                replay_suffix: Vec::new(),
                resume_gate: None,
                actors: Vec::new(),
            };
        }
        let muc_domain =
            crate::jid::prepare_domainpart(&format!("conference.{}", self.config.domain))
                .expect("configured XMPP domain must form a valid MUC domain");
        let mut failures = Vec::new();
        let mut actors = Vec::new();
        let mut resume_gate = self
            .suspended_muc_sessions
            .get(&sm_session_id)
            .map(|endpoint| Arc::clone(&endpoint));
        for membership in memberships {
            let (Ok(room_jid), Ok(nick)) = (
                crate::jid::canonicalize_bare(&membership.room_jid),
                crate::xmpp::xml_util::prepare_muc_nick(&membership.nick),
            ) else {
                failures.push(membership.clone());
                continue;
            };
            if jid_domain(&room_jid) != Some(muc_domain.as_str()) {
                failures.push(membership.clone());
                continue;
            }
            let Ok(Some(initial_room)) = self
                .muc_service()
                .local_room_snapshot(localpart(&room_jid))
                .await
            else {
                failures.push(membership.clone());
                continue;
            };
            let key = crate::xmpp::xml_util::muc_occupant_key(&room_jid, &nick);
            // Single-node join, rename and SM restore publish into the same
            // room-local map. Existing suspended actors already own a slot
            // and bypass the new-admission capacity check; a post-restart
            // recreation must compete under the same gate as a fresh join so
            // delayed resumes cannot overfill the room.
            let _local_resume_guard = if self.cluster.is_enabled() {
                None
            } else {
                Some(self.muc_service().lock_local_join(initial_room.id).await)
            };
            let Ok(Some(room)) = self
                .muc_service()
                .local_room_snapshot(localpart(&room_jid))
                .await
            else {
                failures.push(membership.clone());
                continue;
            };
            if room.id != initial_room.id
                || room.room_epoch != initial_room.room_epoch
                || room.config_version != initial_room.config_version
            {
                failures.push(membership.clone());
                continue;
            }
            let affiliation = match self.muc_service().local_affiliation(room.id, user.id).await {
                Ok(value) => value.unwrap_or_else(|| "none".to_owned()),
                Err(error) => {
                    tracing::warn!(?error, "failed to reauthorize resumed MUC membership");
                    failures.push(membership.clone());
                    continue;
                }
            };
            if affiliation == "outcast" || (room.members_only && affiliation == "none") {
                failures.push(membership.clone());
                continue;
            }
            match self
                .muc_service()
                .local_nick_reserved_for_other(room.id, user.id, &nick)
                .await
            {
                Ok(false) => {}
                Ok(true) => {
                    failures.push(membership.clone());
                    continue;
                }
                Err(error) => {
                    tracing::warn!(?error, room=%room_jid, %nick,
                        "failed to revalidate a reserved nickname during SM resume");
                    failures.push(membership.clone());
                    continue;
                }
            }
            let role = if matches!(affiliation.as_str(), "owner" | "admin") {
                "moderator"
            } else if room.moderated && affiliation == "none" {
                "visitor"
            } else {
                "participant"
            }
            .to_owned();

            // From here through the final Entry publication the single-node
            // room gate remains held, so the exact room policy, nickname and
            // capacity decision cannot be invalidated by join/rename/config.
            if room.configuration_is_expired(chrono::Utc::now()) {
                failures.push(membership.clone());
                continue;
            };
            if let Some(occupant) = self.muc_occupants.get(&key) {
                let previous = SerializableMucOccupant::from(&*occupant);
                let endpoint = match &occupant.endpoint {
                    MucOccupantEndpoint::Suspended(endpoint)
                        if endpoint.sm_session_id == sm_session_id =>
                    {
                        Some(Arc::clone(endpoint))
                    }
                    _ => None,
                };
                let owned = occupant.full_jid == full_jid && endpoint.is_some();
                if !owned {
                    failures.push(membership.clone());
                    continue;
                }
                let endpoint = endpoint.expect("checked above");
                drop(occupant);
                let canonical_endpoint = canonical_suspended_muc_endpoint(
                    &self.suspended_muc_sessions,
                    sm_session_id,
                    Arc::clone(&endpoint),
                );
                if !Arc::ptr_eq(&canonical_endpoint, &endpoint)
                    || resume_gate
                        .as_ref()
                        .is_some_and(|current| !Arc::ptr_eq(current, &endpoint))
                {
                    failures.push(membership.clone());
                    continue;
                }
                resume_gate = Some(Arc::clone(&endpoint));

                let resumed_cluster_target = if self.cluster.is_enabled() {
                    let resume = async {
                        let target = db::cluster_muc_occupancy_target(
                            &self.pool,
                            room.id,
                            previous.cluster_epoch,
                            previous.connection_id,
                        )
                        .await?
                        .context("SM resume lost its exact suspended MUC occupancy")?;
                        let next_epoch = target
                            .connection_epoch
                            .checked_add(1)
                            .context("MUC connection epoch overflow")?;
                        let operation_id = uuid::Uuid::new_v4();
                        let outcome = db::transition_cluster_muc_occupancy(
                            &self.pool,
                            operation_id,
                            &target,
                            "resume",
                            &self.cluster.node_id,
                            Some(connection_id),
                            Some(next_epoch),
                            Some(sm_session_id),
                            Duration::from_secs(90),
                        )
                        .await?;
                        anyhow::ensure!(
                            matches!(
                                outcome,
                                db::ClusterMucTransitionOutcome::Applied
                                    | db::ClusterMucTransitionOutcome::Replay
                            ),
                            "PG MUC resume rejected stale occupancy: {outcome:?}"
                        );
                        if let Err(error) = self
                            .muc_service()
                            .wake_committed_operation(&self.cluster, operation_id)
                            .await
                        {
                            tracing::warn!(?error, %operation_id, room=%room_jid,
                                "MUC resume wake failed; PG outbox polling will catch up");
                        }
                        let mut resumed = target;
                        resumed.connection_uuid = connection_id;
                        resumed.connection_epoch = next_epoch;
                        Ok::<_, anyhow::Error>(resumed)
                    }
                    .await;
                    match resume {
                        Ok(target) => Some(target),
                        Err(error) => {
                            tracing::warn!(?error, room=%room_jid, nick=%nick,
                                "could not commit PG-authoritative MUC resume");
                            failures.push(membership.clone());
                            continue;
                        }
                    }
                } else {
                    None
                };
                let Some(mut occupant) = self.muc_occupants.get_mut(&key) else {
                    if let Some(target) = &resumed_cluster_target {
                        self.compensate_resumed_muc_target(target, sm_session_id)
                            .await;
                    }
                    failures.push(membership.clone());
                    continue;
                };
                if !matches!(
                    &occupant.endpoint,
                    MucOccupantEndpoint::Suspended(current)
                        if Arc::ptr_eq(current, &endpoint)
                            && current.sm_session_id == sm_session_id
                ) || occupant.full_jid != full_jid
                    || occupant.connection_id != previous.connection_id
                    || occupant.cluster_epoch != previous.cluster_epoch
                    || occupant.sm_session_id != Some(sm_session_id)
                {
                    drop(occupant);
                    if let Some(target) = &resumed_cluster_target {
                        self.compensate_resumed_muc_target(target, sm_session_id)
                            .await;
                    }
                    failures.push(membership.clone());
                    continue;
                }
                occupant.connection_id = connection_id;
                occupant.sm_session_id = Some(sm_session_id);
                occupant.affiliation = affiliation;
                occupant.role = role;
                occupant.room_non_anonymous = room.non_anonymous;
                let serializable = SerializableMucOccupant::from(&*occupant);
                drop(occupant);
                match self
                    .cluster
                    .resume_muc_occupant(&previous, &serializable)
                    .await
                {
                    Ok(true) => {}
                    Ok(false) | Err(_) if !self.cluster.is_enabled() => {
                        self.muc_occupants.remove_if(&key, |_, current| {
                            current.full_jid == full_jid
                                && current.cluster_epoch == serializable.cluster_epoch
                                && current.connection_id == connection_id
                                && matches!(
                                    &current.endpoint,
                                    MucOccupantEndpoint::Suspended(current)
                                        if Arc::ptr_eq(current, &endpoint)
                                )
                        });
                        if let Some(target) = &resumed_cluster_target {
                            self.compensate_resumed_muc_target(target, sm_session_id)
                                .await;
                        }
                        failures.push(membership.clone());
                        continue;
                    }
                    Ok(false) | Err(_) => {
                        tracing::warn!(room=%room_jid, nick=%nick,
                            "PG MUC resume committed but Redis soft-state refresh failed");
                    }
                }
                actors.push(RestoredMucActor {
                    key,
                    full_jid: full_jid.clone(),
                    connection_id,
                    cluster_epoch: serializable.cluster_epoch,
                    sm_session_id,
                    endpoint,
                    membership: crate::services::sm::SmMucMembership { room_jid, nick },
                    resumed_cluster_target,
                });
                continue;
            }

            if !self.cluster.is_enabled() {
                let privileged = matches!(affiliation.as_str(), "owner" | "admin");
                let effective_capacity = room.max_occupants as usize + usize::from(privileged) * 10;
                if self.muc_occupants_for(&room_jid).len() >= effective_capacity {
                    failures.push(membership.clone());
                    continue;
                }
            }

            let cluster_authority = if self.cluster.is_enabled() {
                let authority = match db::suspended_cluster_muc_occupancy(
                    &self.pool,
                    room.id,
                    room.room_epoch,
                    sm_session_id,
                    &full_jid,
                    &nick,
                )
                .await
                {
                    Ok(Some(authority)) => authority,
                    Ok(None) | Err(_) => {
                        failures.push(membership.clone());
                        continue;
                    }
                };
                Some(authority)
            } else {
                None
            };

            let proposed_endpoint = resume_gate.clone().unwrap_or_else(|| {
                Arc::new(SuspendedMucEndpoint::new_reserved(
                    sm_session_id,
                    base_stanzas,
                    base_bytes,
                ))
            });
            let created_endpoint = canonical_suspended_muc_endpoint(
                &self.suspended_muc_sessions,
                sm_session_id,
                proposed_endpoint,
            );
            if resume_gate
                .as_ref()
                .is_some_and(|current| !Arc::ptr_eq(current, &created_endpoint))
            {
                failures.push(membership.clone());
                continue;
            }
            resume_gate = Some(Arc::clone(&created_endpoint));

            let occupant = MucOccupant {
                full_jid: full_jid.clone(),
                room_jid: room_jid.clone(),
                nick: nick.clone(),
                endpoint: MucOccupantEndpoint::Suspended(Arc::clone(&created_endpoint)),
                affiliation,
                role,
                room_non_anonymous: room.non_anonymous,
                occupant_id: crate::xmpp::xml_util::muc_occupant_id(
                    &room.occupant_id_secret,
                    bare_jid(&full_jid),
                ),
                cluster_epoch: cluster_authority
                    .as_ref()
                    .map(|authority| authority.occupant_incarnation)
                    .unwrap_or_else(uuid::Uuid::new_v4),
                connection_id,
                sm_session_id: Some(sm_session_id),
                payload: cluster_authority
                    .as_ref()
                    .map(|authority| authority.presence_payload.clone())
                    .unwrap_or_default(),
            };
            let serializable = SerializableMucOccupant::from(&occupant);
            // A concurrent join or a winning resume may have created the same
            // (room, nick) occupancy while the restore awaited PostgreSQL.
            if !insert_restored_muc_occupant(&self.muc_occupants, key.clone(), occupant) {
                failures.push(membership.clone());
                continue;
            }

            let resumed_cluster_target = if let Some(authority) = cluster_authority.as_ref() {
                let target = db::ClusterMucOccupancyTarget::from(authority);
                let Some(next_epoch) = target.connection_epoch.checked_add(1) else {
                    self.muc_occupants.remove_if(&key, |_, occupant| {
                        suspended_occupant_is_created(occupant, &created_endpoint)
                            && occupant.full_jid == full_jid
                            && occupant.connection_id == connection_id
                    });
                    failures.push(membership.clone());
                    continue;
                };
                let operation_id = uuid::Uuid::new_v4();
                match db::transition_cluster_muc_occupancy(
                    &self.pool,
                    operation_id,
                    &target,
                    "resume",
                    &self.cluster.node_id,
                    Some(connection_id),
                    Some(next_epoch),
                    Some(sm_session_id),
                    Duration::from_secs(90),
                )
                .await
                {
                    Ok(db::ClusterMucTransitionOutcome::Applied)
                    | Ok(db::ClusterMucTransitionOutcome::Replay) => {
                        if let Err(error) = self
                            .muc_service()
                            .wake_committed_operation(&self.cluster, operation_id)
                            .await
                        {
                            tracing::warn!(?error, %operation_id, room=%room_jid,
                                "MUC resume wake failed; PG outbox polling will catch up");
                        }
                        let mut resumed = target;
                        resumed.connection_uuid = connection_id;
                        resumed.connection_epoch = next_epoch;
                        Some(resumed)
                    }
                    Ok(outcome) => {
                        tracing::warn!(?outcome, room=%room_jid, nick=%nick,
                            "PG MUC restart resume rejected the reserved local actor");
                        self.muc_occupants.remove_if(&key, |_, occupant| {
                            suspended_occupant_is_created(occupant, &created_endpoint)
                                && occupant.full_jid == full_jid
                                && occupant.connection_id == connection_id
                        });
                        failures.push(membership.clone());
                        continue;
                    }
                    Err(error) => {
                        tracing::warn!(?error, room=%room_jid, nick=%nick,
                            "PG MUC restart resume failed after local reservation");
                        self.muc_occupants.remove_if(&key, |_, occupant| {
                            suspended_occupant_is_created(occupant, &created_endpoint)
                                && occupant.full_jid == full_jid
                                && occupant.connection_id == connection_id
                        });
                        failures.push(membership.clone());
                        continue;
                    }
                }
            } else {
                None
            };

            let refresh = if let Some(authority) = cluster_authority.as_ref() {
                let previous = SerializableMucOccupant {
                    full_jid: authority.full_jid.clone(),
                    room_jid: room_jid.clone(),
                    nick: authority.nick.clone(),
                    affiliation: authority.affiliation.clone(),
                    role: authority.role.clone(),
                    room_non_anonymous: room.non_anonymous,
                    occupant_id: crate::xmpp::xml_util::muc_occupant_id(
                        &room.occupant_id_secret,
                        bare_jid(&authority.full_jid),
                    ),
                    cluster_epoch: authority.occupant_incarnation,
                    connection_id: authority.connection_uuid,
                    federated_domain: None,
                    sm_session_id: authority.sm_session_id,
                    payload: authority.presence_payload.clone(),
                };
                self.cluster
                    .resume_muc_occupant(&previous, &serializable)
                    .await
            } else {
                Ok(true)
            };
            if !matches!(refresh, Ok(true)) {
                tracing::warn!(room=%room_jid, nick=%nick,
                    "PG MUC restart resume committed but Redis soft-state refresh failed");
            }
            actors.push(RestoredMucActor {
                key,
                full_jid: full_jid.clone(),
                connection_id,
                cluster_epoch: serializable.cluster_epoch,
                sm_session_id,
                endpoint: created_endpoint,
                membership: crate::services::sm::SmMucMembership { room_jid, nick },
                resumed_cluster_target,
            });
        }

        let replay_suffix = if let Some(endpoint) = &resume_gate {
            match snapshot_suspended_muc_buffer_for_resume(endpoint).await {
                Some(stanzas) => stanzas,
                None => {
                    for actor in &actors {
                        if let Some(target) = &actor.resumed_cluster_target {
                            self.compensate_resumed_muc_target(target, actor.sm_session_id)
                                .await;
                        }
                        self.muc_occupants.remove_if(&actor.key, |_, current| {
                            current.full_jid == actor.full_jid
                                && current.connection_id == actor.connection_id
                                && current.cluster_epoch == actor.cluster_epoch
                                && current.sm_session_id == Some(actor.sm_session_id)
                                && matches!(
                                    &current.endpoint,
                                    MucOccupantEndpoint::Suspended(current_endpoint)
                                        if Arc::ptr_eq(current_endpoint, &actor.endpoint)
                                )
                        });
                    }
                    failures.extend(actors.iter().map(|actor| actor.membership.clone()));
                    actors.clear();
                    Vec::new()
                }
            }
        } else {
            Vec::new()
        };
        RestoredLocalMucOccupants {
            failures,
            replay_suffix,
            resume_gate,
            actors,
        }
    }

    async fn compensate_resumed_muc_target(
        &self,
        target: &db::ClusterMucOccupancyTarget,
        sm_session_id: uuid::Uuid,
    ) {
        if !self.cluster.is_enabled() {
            return;
        }
        let operation_id = uuid::Uuid::new_v4();
        match db::transition_cluster_muc_occupancy(
            &self.pool,
            operation_id,
            target,
            "suspend",
            &self.cluster.node_id,
            None,
            None,
            Some(sm_session_id),
            Duration::from_secs(90),
        )
        .await
        {
            Ok(db::ClusterMucTransitionOutcome::Applied)
            | Ok(db::ClusterMucTransitionOutcome::Replay) => {
                if let Err(error) = self
                    .muc_service()
                    .wake_committed_operation(&self.cluster, operation_id)
                    .await
                {
                    tracing::warn!(?error, %operation_id,
                        "MUC resume compensation wake failed; PG polling will converge");
                }
            }
            Ok(outcome) => tracing::warn!(?outcome, room_id=%target.room_id,
                "MUC resume compensation no longer owned the exact PG actor"),
            Err(error) => tracing::error!(?error, room_id=%target.room_id,
                "failed to re-suspend a PG MUC actor after local resume failure"),
        }
    }

    /// Transfer the volatile suffix to the exact live SM checkpoint. The
    /// queue is cleared only after PostgreSQL accepted that checkpoint, while
    /// the endpoint mutex still excludes both delivery and transport
    /// publication. A later socket failure therefore re-suspends the snapshot
    /// without appending a duplicate copy of the suffix.
    pub async fn checkpoint_local_muc_resume(&self, restored: &RestoredLocalMucOccupants) -> bool {
        let Some(endpoint) = restored.resume_gate.as_ref() else {
            return true;
        };
        let mut buffer = endpoint.buffer.lock().await;
        if !transfer_muc_suffix_to_checkpoint(&mut buffer) {
            buffer.phase = SuspendedMucPhase::Sealed;
            endpoint.changed.notify_waiters();
            return false;
        }
        endpoint.changed.notify_waiters();
        true
    }

    /// Publish a restore plan only after the `<resumed/>` control and complete
    /// replay have reached the transport. The endpoint mutex is held while all
    /// exact actors are swapped, so an arriving stanza observes either the
    /// sealed gate or the final live route, never a partially transferred FIFO.
    pub async fn commit_local_muc_resume(
        &self,
        restored: RestoredLocalMucOccupants,
        sender: &crate::outbound::OutboundSender,
        capacity: crate::services::sm_capacity::SmCapacityLease,
    ) -> CommittedLocalMucResume {
        let RestoredLocalMucOccupants {
            mut failures,
            replay_suffix: _,
            resume_gate,
            actors,
        } = restored;
        let Some(endpoint) = resume_gate else {
            return CommittedLocalMucResume {
                joined_rooms: Vec::new(),
                failures,
            };
        };
        let recovery_connection_id = actors
            .first()
            .map(|actor| actor.connection_id)
            .unwrap_or_else(uuid::Uuid::nil);

        let mut committed = Vec::new();
        let mut failed_actors = Vec::new();
        let mut stale_suspended = Vec::new();
        let mut published = false;
        {
            // Keep both publication fences in a lexical scope that ends
            // before any compensation I/O. In particular, a std mutex guard
            // must never become part of the Send future used by deferred SM
            // resume completion.
            let mut buffer = endpoint.buffer.lock().await;
            let mut route = endpoint
                .route
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if matches!(&buffer.phase, SuspendedMucPhase::CheckpointOwned)
                && matches!(&*route, SuspendedMucRoute::Suspended)
            {
                for actor in actors {
                    let activated =
                        self.muc_occupants
                            .get_mut(&actor.key)
                            .is_some_and(|mut current| {
                                if suspended_muc_resume_actor_matches(
                                    &current,
                                    &actor.endpoint,
                                    &actor.full_jid,
                                    actor.connection_id,
                                    actor.cluster_epoch,
                                    actor.sm_session_id,
                                ) {
                                    current.endpoint = MucOccupantEndpoint::Local(sender.clone());
                                    true
                                } else {
                                    false
                                }
                            });
                    if activated {
                        committed.push((
                            actor.membership.room_jid.clone(),
                            JoinedMucMembership {
                                nick: actor.membership.nick.clone(),
                                cluster_epoch: actor.cluster_epoch,
                            },
                        ));
                    } else {
                        failures.push(actor.membership.clone());
                        failed_actors.push(actor);
                    }
                }

                stale_suspended = self
                    .muc_occupants
                    .iter()
                    .filter_map(|current| match &current.endpoint {
                        MucOccupantEndpoint::Suspended(current_endpoint)
                            if Arc::ptr_eq(current_endpoint, &endpoint) =>
                        {
                            Some((
                                current.key().clone(),
                                SerializableMucOccupant::from(&*current),
                            ))
                        }
                        _ => None,
                    })
                    .collect();
                for (key, expected) in &stale_suspended {
                    self.muc_occupants.remove_if(key, |_, current| {
                        muc_suspended_teardown_identity_matches(
                            current,
                            endpoint.sm_session_id,
                            expected,
                        ) && matches!(
                            &current.endpoint,
                            MucOccupantEndpoint::Suspended(current_endpoint)
                                if Arc::ptr_eq(current_endpoint, &endpoint)
                        )
                    });
                }
                buffer.stanzas.clear();
                buffer.bytes = 0;
                buffer.base_stanzas = 0;
                buffer.base_bytes = 0;
                buffer.snapshot_owned = false;
                buffer.phase = SuspendedMucPhase::Dormant;
                *route = SuspendedMucRoute::Live(sender.clone());
                published = true;
                // Keep the route fence locked until the async buffer mutex is
                // released. A concurrent disconnect can then observe Live only
                // after `try_lock()` is guaranteed to succeed; no publication
                // window can panic or reset a partially committed FIFO.
                drop(buffer);
                drop(route);
                endpoint.changed.notify_waiters();
            } else {
                failures.extend(actors.iter().map(|actor| actor.membership.clone()));
                failed_actors = actors;
                if !matches!(&buffer.phase, SuspendedMucPhase::Dormant) {
                    buffer.phase = SuspendedMucPhase::Sealed;
                }
                endpoint.changed.notify_waiters();
                drop(buffer);
                drop(route);
            }
        }
        for actor in failed_actors {
            if let Some(target) = actor.resumed_cluster_target {
                self.compensate_resumed_muc_target(&target, actor.sm_session_id)
                    .await;
            }
        }
        for (_, expected) in stale_suspended {
            if let Err(error) = self
                .cluster
                .unregister_muc_occupant_epoch(
                    &expected.room_jid,
                    &expected.nick,
                    expected.cluster_epoch,
                    expected.connection_id,
                )
                .await
            {
                tracing::warn!(?error, room=%expected.room_jid, nick=%expected.nick,
                    "failed to remove stale suspended MUC soft state after resume");
            }
        }
        if !published
            && !self
                .mark_suspended_muc_durable(vec![Arc::clone(&endpoint)])
                .await
        {
            let queued = self.sm_suspension_recovery_queue().enqueue_promote(
                recovery_connection_id,
                endpoint.sm_session_id,
                vec![Arc::clone(&endpoint)],
                capacity,
            );
            if !queued {
                self.sm_memory_governor().mark_invariant_failure();
                seal_suspended_muc_buffer(&endpoint).await;
                let _ = self
                    .revoke_sm_session_with_teardown(endpoint.sm_session_id)
                    .await;
            }
        }
        failures.sort_by(|left, right| {
            (&left.room_jid, &left.nick).cmp(&(&right.room_jid, &right.nick))
        });
        failures.dedup();
        CommittedLocalMucResume {
            joined_rooms: committed,
            failures,
        }
    }

    /// Roll a failed restore back to a suspended actor without taking suffix
    /// ownership away from its sole durable source. `snapshot_backed` is true
    /// only after the protocol session itself contains the staged suffix; in
    /// that case successful connection cleanup clears this backup instead of
    /// appending it again.
    pub async fn abort_local_muc_resume(
        &self,
        restored: &RestoredLocalMucOccupants,
        snapshot_backed: bool,
    ) {
        let Some(endpoint) = restored.resume_gate.as_ref() else {
            return;
        };
        {
            let mut buffer = endpoint.buffer.lock().await;
            buffer.snapshot_owned |= snapshot_backed;
            buffer.phase = SuspendedMucPhase::Sealed;
        }
        endpoint.changed.notify_waiters();

        for actor in &restored.actors {
            if let Some(target) = &actor.resumed_cluster_target {
                self.compensate_resumed_muc_target(target, actor.sm_session_id)
                    .await;
            }
            let suspended = self.muc_occupants.get(&actor.key).and_then(|current| {
                suspended_muc_resume_actor_matches(
                    &current,
                    &actor.endpoint,
                    &actor.full_jid,
                    actor.connection_id,
                    actor.cluster_epoch,
                    actor.sm_session_id,
                )
                .then(|| SerializableMucOccupant::from(&*current))
            });
            if let Some(suspended) = suspended {
                let encoded = serde_json::to_string(&suspended).unwrap_or_default();
                if let Err(error) = self
                    .cluster
                    .register_suspended_muc_occupant(
                        &suspended.room_jid,
                        &suspended.nick,
                        actor.sm_session_id,
                        &encoded,
                    )
                    .await
                {
                    tracing::warn!(?error, room=%suspended.room_jid, nick=%suspended.nick,
                        "failed to restore suspended MUC soft state after resume rollback");
                }
            }
        }
    }
}

pub struct ClientConnectionGuard {
    state: Arc<AppState>,
    ip: std::net::IpAddr,
    _permit: OwnedSemaphorePermit,
}

pub struct UploadRequestGuard {
    state: Arc<AppState>,
    ip: std::net::IpAddr,
    _permit: OwnedSemaphorePermit,
}

pub struct UploadDownloadGuard {
    state: Arc<AppState>,
    ip: std::net::IpAddr,
    _permit: OwnedSemaphorePermit,
}

impl Drop for UploadDownloadGuard {
    fn drop(&mut self) {
        if let Some(mut count) = self.state.upload_downloads_by_ip.get_mut(&self.ip) {
            *count = count.saturating_sub(1);
            drop(count);
            self.state
                .upload_downloads_by_ip
                .remove_if(&self.ip, |_, count| *count == 0);
        }
    }
}

impl Drop for UploadRequestGuard {
    fn drop(&mut self) {
        if let Some(mut count) = self.state.upload_requests_by_ip.get_mut(&self.ip) {
            *count = count.saturating_sub(1);
            drop(count);
            self.state
                .upload_requests_by_ip
                .remove_if(&self.ip, |_, count| *count == 0);
        }
    }
}

impl Drop for ClientConnectionGuard {
    fn drop(&mut self) {
        if let Some(mut count) = self.state.client_connections_by_ip.get_mut(&self.ip) {
            *count = count.saturating_sub(1);
            drop(count);
            self.state
                .client_connections_by_ip
                .remove_if(&self.ip, |_, count| *count == 0);
        }
    }
}

pub fn bare_jid(jid: &str) -> &str {
    jid.split('/').next().unwrap_or(jid)
}

pub fn localpart(jid: &str) -> &str {
    bare_jid(jid).split('@').next().unwrap_or(jid)
}

pub fn jid_domain(jid: &str) -> Option<&str> {
    bare_jid(jid).split_once('@').map(|(_, domain)| domain)
}

pub fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

pub fn attr_escape(value: &str) -> String {
    xml_escape(value)
}

#[cfg(test)]
mod session_key_tests {
    use super::{
        admit_bounded_omemo_poll_ip, admit_omemo_poll_ip_window, api_keyrings,
        append_suspended_muc_suffix_to_snapshot, begin_suspended_muc_route_transition,
        canonical_suspended_muc_endpoint, complete_snapshot_owned_handoff,
        encode_api_control_entropy, ephemeral_api_control_secret, federation_rule_matches,
        insert_restored_muc_occupant, muc_actor_identity_matches, muc_departure_identity_matches,
        muc_suspended_teardown_identity_matches, promote_suspended_muc_buffer,
        seal_suspended_muc_buffer, service_control_applies, session_lookup,
        snapshot_suspended_muc_buffer_for_resume, staged_route_activation_allowed,
        suspended_muc_resume_actor_matches, suspended_occupant_is_created,
        transfer_muc_suffix_to_checkpoint, FederationWritePolicy, JoinedMucMembership, MucOccupant,
        MucOccupantEndpoint, RouteIncarnationSignal, SerializableMucOccupant, SessionLookup,
        StagedRouteActivationCheck, StagedRouteIdentity, SuspendedMucBuffer, SuspendedMucEndpoint,
        SuspendedMucPhase, SuspendedMucRoute,
    };
    use std::collections::VecDeque;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    };
    use std::time::{Duration, Instant};

    #[test]
    fn route_removal_signal_retains_the_exact_terminal_state_for_late_subscribers() {
        let connection_id = uuid::Uuid::new_v4();
        let signal = RouteIncarnationSignal::new(connection_id);
        signal.publish_removed();

        let late = signal.subscribe();
        assert_eq!(signal.connection_id(), connection_id);
        assert!(
            *late.borrow(),
            "subscribing after compare-and-remove must not lose the terminal event"
        );
    }

    #[tokio::test]
    async fn island_mode_transition_waits_for_and_fences_federation_writes() {
        let policy = Arc::new(FederationWritePolicy::new(false));
        let permit = policy.permit().await.expect("federation starts enabled");
        let transition_policy = Arc::clone(&policy);
        let transition = tokio::spawn(async move {
            transition_policy.apply(true).await;
        });

        tokio::task::yield_now().await;
        assert!(
            !transition.is_finished(),
            "the kill switch must wait for an in-flight socket-write boundary"
        );
        drop(permit);
        tokio::time::timeout(Duration::from_secs(1), transition)
            .await
            .expect("island transition completes after the write boundary")
            .expect("island transition task succeeds");
        assert!(policy.enabled());
        assert!(
            policy.permit().await.is_none(),
            "queued writers must observe island mode after the transition"
        );

        policy.apply(false).await;
        assert!(policy.permit().await.is_some());
    }

    #[test]
    fn omemo_poll_active_ip_cap_is_linearizable() {
        let windows = Arc::new(dashmap::DashMap::new());
        let admission = Arc::new(std::sync::Mutex::new(()));
        let barrier = Arc::new(std::sync::Barrier::new(33));
        let now = Instant::now();
        let accepted = std::thread::scope(|scope| {
            let mut workers = Vec::new();
            for suffix in 1_u8..=32 {
                let windows = Arc::clone(&windows);
                let admission = Arc::clone(&admission);
                let barrier = Arc::clone(&barrier);
                workers.push(scope.spawn(move || {
                    barrier.wait();
                    admit_bounded_omemo_poll_ip(
                        &windows,
                        &admission,
                        std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, suffix)),
                        now,
                        false,
                        4,
                    )
                }));
            }
            barrier.wait();
            workers
                .into_iter()
                .map(|worker| worker.join().expect("poll admission thread completes"))
                .filter(|accepted| *accepted)
                .count()
        });
        assert_eq!(accepted, 4);
        assert_eq!(windows.len(), 4);
    }

    fn suspended_buffer(stanzas: &[&str]) -> SuspendedMucBuffer {
        let mut buffer = SuspendedMucBuffer {
            phase: SuspendedMucPhase::Collecting,
            snapshot_owned: false,
            base_stanzas: 0,
            base_bytes: 0,
            bytes: 0,
            stanzas: VecDeque::new(),
        };
        for stanza in stanzas {
            assert!(buffer.enqueue_volatile((*stanza).to_owned(), 32, 4096));
        }
        buffer
    }

    fn queued(buffer: &SuspendedMucBuffer) -> Vec<&str> {
        buffer
            .stanzas
            .iter()
            .map(|stanza| stanza.xml.as_str())
            .collect()
    }

    fn sm_snapshot(outbound_h: u32, unacked: &[&str]) -> crate::services::sm::SmSessionSnapshot {
        crate::services::sm::SmSessionSnapshot {
            inbound_h: 0,
            outbound_h,
            acked_h: 0,
            available: true,
            carbons: false,
            priority: 0,
            blocklist_requested: false,
            roster_requested: false,
            active_privacy_list: None,
            privacy_requested: false,
            peer_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            user_agent_id: None,
            joined_rooms: Vec::new(),
            directed_presence: Vec::new(),
            last_presence: None,
            unacked: unacked
                .iter()
                .map(|stanza| crate::outbound::SmUnackedStanza::plain((*stanza).to_owned()))
                .collect(),
        }
    }

    #[test]
    fn disconnect_snapshot_preserves_fifo_budget_and_counter_wrap() {
        let mut snapshot = sm_snapshot(u32::MAX, &["old"]);
        let mut suffix = VecDeque::new();
        suffix.push_back(super::SuspendedMucStanza {
            source_id: uuid::Uuid::new_v4(),
            xml: "room-a".to_owned(),
        });
        suffix.push_back(super::SuspendedMucStanza {
            source_id: uuid::Uuid::new_v4(),
            xml: "room-b".to_owned(),
        });
        append_suspended_muc_suffix_to_snapshot(&mut snapshot, &suffix, 3, "oldroom-aroom-b".len())
            .expect("the complete session FIFO fits exactly");
        assert_eq!(snapshot.outbound_h, 1);
        assert_eq!(
            snapshot
                .unacked
                .iter()
                .map(|entry| entry.stanza.as_str())
                .collect::<Vec<_>>(),
            vec!["old", "room-a", "room-b"]
        );
        assert!(snapshot
            .unacked
            .iter()
            .all(|entry| entry.durable_delivery.is_none()));

        let before_h = snapshot.outbound_h;
        let before = snapshot.unacked.clone();
        assert!(
            append_suspended_muc_suffix_to_snapshot(&mut snapshot, &suffix, 4, usize::MAX).is_err()
        );
        assert_eq!(snapshot.outbound_h, before_h);
        assert_eq!(snapshot.unacked, before);
    }

    #[tokio::test]
    async fn suspended_muc_durable_promotion_retains_first_and_mid_failure_exactly() {
        let mut first_failure = suspended_buffer(&["first", "second"]);
        let expected_bytes = "first".len() + "second".len();
        let mut outcomes = VecDeque::from([false]);
        let mut attempted = Vec::new();
        assert!(
            !promote_suspended_muc_buffer(&mut first_failure, |_source_id, stanza| {
                attempted.push(stanza);
                std::future::ready(outcomes.pop_front().unwrap())
            })
            .await
        );
        assert_eq!(attempted, vec!["first".to_owned()]);
        assert_eq!(queued(&first_failure), vec!["first", "second"]);
        assert_eq!(first_failure.bytes, expected_bytes);
        assert!(matches!(&first_failure.phase, SuspendedMucPhase::Sealed));
        assert!(!first_failure.enqueue_volatile("newer".to_owned(), 32, 4096));

        let mut mid_failure = suspended_buffer(&["first", "middle", "last"]);
        let mut outcomes = VecDeque::from([true, false]);
        let mut attempted = Vec::new();
        assert!(
            !promote_suspended_muc_buffer(&mut mid_failure, |source_id, stanza| {
                attempted.push((source_id, stanza));
                std::future::ready(outcomes.pop_front().unwrap())
            })
            .await
        );
        assert_eq!(
            attempted
                .iter()
                .map(|(_, stanza)| stanza.as_str())
                .collect::<Vec<_>>(),
            vec!["first", "middle"]
        );
        let ambiguous_source_id = attempted[1].0;
        assert_eq!(queued(&mid_failure), vec!["middle", "last"]);
        assert_eq!(mid_failure.bytes, "middle".len() + "last".len());
        assert!(matches!(&mid_failure.phase, SuspendedMucPhase::Sealed));

        let mut outcomes = VecDeque::from([true, true]);
        let mut retried = Vec::new();
        assert!(
            promote_suspended_muc_buffer(&mut mid_failure, |source_id, stanza| {
                retried.push((source_id, stanza));
                std::future::ready(outcomes.pop_front().unwrap())
            })
            .await
        );
        assert_eq!(retried[0].0, ambiguous_source_id);
        assert_eq!(
            retried
                .iter()
                .map(|(_, stanza)| stanza.as_str())
                .collect::<Vec<_>>(),
            vec!["middle", "last"]
        );
        assert!(mid_failure.stanzas.is_empty());
        assert_eq!(mid_failure.bytes, 0);
        assert!(matches!(&mid_failure.phase, SuspendedMucPhase::Durable));
    }

    #[tokio::test]
    async fn suspended_muc_checkpoint_snapshot_keeps_ownership_until_commit() {
        let endpoint = Arc::new(SuspendedMucEndpoint::new(uuid::Uuid::new_v4()));
        {
            let mut buffer = endpoint.buffer.lock().await;
            assert!(buffer.enqueue_volatile("older-1".to_owned(), 8, 4096));
            assert!(buffer.enqueue_volatile("older-2".to_owned(), 8, 4096));
            buffer.phase = SuspendedMucPhase::Resuming;
        }
        let snapshot = snapshot_suspended_muc_buffer_for_resume(&endpoint)
            .await
            .expect("resuming gate can be checkpointed");
        assert_eq!(snapshot, vec!["older-1".to_owned(), "older-2".to_owned()]);
        {
            let mut buffer = endpoint.buffer.lock().await;
            assert_eq!(queued(&buffer), vec!["older-1", "older-2"]);
            assert!(matches!(&buffer.phase, SuspendedMucPhase::Committing));
            assert!(!buffer.enqueue_volatile("racing".to_owned(), 8, 4096));
        }
        // A failed durable checkpoint seals the original owner without taking
        // or clearing a byte, so cleanup can still promote the exact FIFO.
        seal_suspended_muc_buffer(&endpoint).await;
        {
            let buffer = endpoint.buffer.lock().await;
            assert!(matches!(&buffer.phase, SuspendedMucPhase::Sealed));
            assert_eq!(queued(&buffer), vec!["older-1", "older-2"]);
        }
    }

    #[tokio::test]
    async fn checkpoint_owned_suffix_is_cleared_once_and_never_promoted_again() {
        let endpoint = Arc::new(SuspendedMucEndpoint::new(uuid::Uuid::new_v4()));
        {
            let mut buffer = endpoint.buffer.lock().await;
            assert!(buffer.enqueue_volatile("one".to_owned(), 8, 4096));
            assert!(buffer.enqueue_volatile("two".to_owned(), 8, 4096));
            buffer.phase = SuspendedMucPhase::Resuming;
        }
        assert_eq!(
            snapshot_suspended_muc_buffer_for_resume(&endpoint).await,
            Some(vec!["one".to_owned(), "two".to_owned()])
        );
        {
            let mut buffer = endpoint.buffer.lock().await;
            assert!(transfer_muc_suffix_to_checkpoint(&mut buffer));
            assert!(buffer.stanzas.is_empty());
            assert_eq!(buffer.bytes, 0);
            assert!(matches!(&buffer.phase, SuspendedMucPhase::CheckpointOwned));
            assert!(complete_snapshot_owned_handoff(&mut buffer));
            assert!(buffer.stanzas.is_empty());
            assert!(matches!(&buffer.phase, SuspendedMucPhase::Durable));
            assert!(!complete_snapshot_owned_handoff(&mut buffer));
        }
    }

    #[tokio::test]
    async fn ambiguous_suspend_commit_can_be_claimed_without_replaying_backup_twice() {
        let endpoint = Arc::new(SuspendedMucEndpoint::new(uuid::Uuid::new_v4()));
        {
            let mut buffer = endpoint.buffer.lock().await;
            assert!(buffer.enqueue_volatile("already-in-db".to_owned(), 8, 4096));
            buffer.snapshot_owned = true;
            buffer.phase = SuspendedMucPhase::Resuming;
        }
        assert_eq!(
            snapshot_suspended_muc_buffer_for_resume(&endpoint).await,
            Some(Vec::new()),
            "the claimed PostgreSQL queue, not its retained backup, is replayed"
        );
        {
            let mut buffer = endpoint.buffer.lock().await;
            assert!(buffer.snapshot_owned);
            assert_eq!(queued(&buffer), vec!["already-in-db"]);
            assert!(transfer_muc_suffix_to_checkpoint(&mut buffer));
            assert!(buffer.stanzas.is_empty());
            assert!(complete_snapshot_owned_handoff(&mut buffer));
            assert!(!buffer.snapshot_owned);
            assert!(matches!(&buffer.phase, SuspendedMucPhase::Durable));
        }
    }

    #[tokio::test]
    async fn disconnect_fence_survives_a_busy_checkpoint_buffer_without_clearing_it() {
        let (raw_sender, _receiver) = tokio::sync::mpsc::channel(2);
        let endpoint = Arc::new(SuspendedMucEndpoint::new_live(
            uuid::Uuid::new_v4(),
            crate::outbound::OutboundSender::new(raw_sender),
        ));
        let mut buffer = endpoint.buffer.lock().await;
        buffer.phase = SuspendedMucPhase::CheckpointOwned;
        buffer.snapshot_owned = true;
        begin_suspended_muc_route_transition(&endpoint, 7, 700);
        {
            let route = endpoint
                .route
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            assert!(matches!(&*route, SuspendedMucRoute::Transitioning));
        }
        assert!(buffer.snapshot_owned);
        assert!(matches!(&buffer.phase, SuspendedMucPhase::CheckpointOwned));
        drop(buffer);

        seal_suspended_muc_buffer(&endpoint).await;
        let buffer = endpoint.buffer.lock().await;
        assert!(buffer.snapshot_owned);
        assert!(matches!(&buffer.phase, SuspendedMucPhase::Sealed));
        let route = endpoint
            .route
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(matches!(&*route, SuspendedMucRoute::Suspended));
    }

    #[test]
    fn live_route_send_and_transition_share_one_linearization_fence() {
        let (raw_sender, mut receiver) = tokio::sync::mpsc::channel(2);
        let endpoint = Arc::new(SuspendedMucEndpoint::new_live(
            uuid::Uuid::new_v4(),
            crate::outbound::OutboundSender::new(raw_sender),
        ));
        let barrier = Arc::new(std::sync::Barrier::new(2));
        std::thread::scope(|scope| {
            let live = endpoint
                .route
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let transition_endpoint = Arc::clone(&endpoint);
            let transition_barrier = Arc::clone(&barrier);
            let transition = scope.spawn(move || {
                transition_barrier.wait();
                let mut route = transition_endpoint
                    .route
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                *route = SuspendedMucRoute::Transitioning;
            });
            barrier.wait();
            let SuspendedMucRoute::Live(sender) = &*live else {
                panic!("the route starts live");
            };
            sender
                .try_send("before-fence".to_owned())
                .expect("the write linearizes before transition");
            drop(live);
            transition.join().expect("transition thread completes");
        });
        let delivered = receiver.try_recv().expect("pre-fence stanza is delivered");
        assert_eq!(delivered.stanza, "before-fence");
        let route = endpoint
            .route
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(matches!(&*route, SuspendedMucRoute::Transitioning));
    }

    #[tokio::test]
    async fn one_sm_gate_preserves_cross_room_fifo_and_global_budget() {
        let endpoint = Arc::new(SuspendedMucEndpoint::new_collecting(
            uuid::Uuid::new_v4(),
            2,
            8,
        ));
        {
            let mut buffer = endpoint.buffer.lock().await;
            assert!(buffer.enqueue_volatile("A".to_owned(), 3, 9));
            assert!(!buffer.enqueue_volatile("B".to_owned(), 4, 9));
            buffer.base_stanzas = 0;
            buffer.base_bytes = 0;
            assert!(buffer.enqueue_volatile("room-b:1".to_owned(), 8, 4096));
            assert!(buffer.enqueue_volatile("room-a:2".to_owned(), 8, 4096));
            buffer.phase = SuspendedMucPhase::Resuming;
        }
        assert_eq!(
            snapshot_suspended_muc_buffer_for_resume(&endpoint)
                .await
                .unwrap(),
            vec!["A".to_owned(), "room-b:1".to_owned(), "room-a:2".to_owned()]
        );
    }

    #[test]
    fn suspended_removal_matches_only_the_exact_created_endpoint() {
        let session = uuid::Uuid::new_v4();
        let created = Arc::new(SuspendedMucEndpoint::new(session));
        let same_session_other_endpoint = Arc::new(SuspendedMucEndpoint::new(session));
        let mut occupant = test_muc_occupant(
            "alice@example.test/Phone",
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
        );
        occupant.endpoint = MucOccupantEndpoint::Suspended(same_session_other_endpoint);
        // Two distinct endpoints may share one SM session id; only the exact
        // Arc this restore created may ever be removed by its failure path.
        assert!(!suspended_occupant_is_created(&occupant, &created));
        occupant.endpoint = MucOccupantEndpoint::Suspended(Arc::clone(&created));
        assert!(suspended_occupant_is_created(&occupant, &created));
    }

    #[test]
    fn stale_registry_miss_adopts_the_concurrent_canonical_resume_gate() {
        let registry = Arc::new(dashmap::DashMap::new());
        let session_id = uuid::Uuid::new_v4();
        assert!(registry.get(&session_id).is_none());
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let endpoints = std::thread::scope(|scope| {
            let mut workers = Vec::new();
            for _ in 0..2 {
                let registry = Arc::clone(&registry);
                let barrier = Arc::clone(&barrier);
                workers.push(scope.spawn(move || {
                    let proposed = Arc::new(SuspendedMucEndpoint::new_reserved(session_id, 0, 0));
                    barrier.wait();
                    canonical_suspended_muc_endpoint(&registry, session_id, proposed)
                }));
            }
            barrier.wait();
            workers
                .into_iter()
                .map(|worker| worker.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert!(Arc::ptr_eq(&endpoints[0], &endpoints[1]));
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn stale_restore_miss_never_overwrites_a_concurrent_joiner() {
        let occupants = dashmap::DashMap::new();
        let key = "room@example.test\0nick".to_owned();
        assert!(occupants.get(&key).is_none());
        let joiner_connection = uuid::Uuid::new_v4();
        occupants.insert(
            key.clone(),
            test_muc_occupant(
                "alice@example.test/Joiner",
                joiner_connection,
                uuid::Uuid::new_v4(),
            ),
        );
        let restored = test_muc_occupant(
            "alice@example.test/Restored",
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
        );
        assert!(!insert_restored_muc_occupant(
            &occupants,
            key.clone(),
            restored
        ));
        assert_eq!(
            occupants.get(&key).unwrap().connection_id,
            joiner_connection
        );
    }

    #[tokio::test]
    async fn restart_reserved_and_checkpoint_owned_gates_accept_no_volatile_suffix() {
        let endpoint = SuspendedMucEndpoint::new_reserved(uuid::Uuid::new_v4(), 0, 0);
        let mut buffer = endpoint.buffer.lock().await;
        assert!(matches!(&buffer.phase, SuspendedMucPhase::Reserved));
        assert!(!buffer.enqueue_volatile("during-db-await".to_owned(), 8, 4096));
        buffer.phase = SuspendedMucPhase::CheckpointOwned;
        assert!(!buffer.enqueue_volatile("before-resumed".to_owned(), 8, 4096));
        let route = endpoint
            .route
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(matches!(&*route, SuspendedMucRoute::Suspended));
    }

    #[test]
    fn resumed_muc_actor_swap_rejects_every_aba_identity_change() {
        let sm_session_id = uuid::Uuid::new_v4();
        let connection_id = uuid::Uuid::new_v4();
        let cluster_epoch = uuid::Uuid::new_v4();
        let endpoint = Arc::new(SuspendedMucEndpoint::new(sm_session_id));
        let mut occupant =
            test_muc_occupant("alice@example.test/Phone", connection_id, cluster_epoch);
        occupant.sm_session_id = Some(sm_session_id);
        occupant.endpoint = MucOccupantEndpoint::Suspended(Arc::clone(&endpoint));
        let matches = |endpoint, full_jid, connection_id, cluster_epoch| {
            suspended_muc_resume_actor_matches(
                &occupant,
                endpoint,
                full_jid,
                connection_id,
                cluster_epoch,
                sm_session_id,
            )
        };
        assert!(matches(
            &endpoint,
            "alice@example.test/Phone",
            connection_id,
            cluster_epoch
        ));
        let unrelated_endpoint = Arc::new(SuspendedMucEndpoint::new(sm_session_id));
        assert!(!matches(
            &unrelated_endpoint,
            "alice@example.test/Phone",
            connection_id,
            cluster_epoch
        ));
        assert!(!matches(
            &endpoint,
            "alice@example.test/Other",
            connection_id,
            cluster_epoch
        ));
        assert!(!matches(
            &endpoint,
            "alice@example.test/Phone",
            uuid::Uuid::new_v4(),
            cluster_epoch
        ));
        assert!(!matches(
            &endpoint,
            "alice@example.test/Phone",
            connection_id,
            uuid::Uuid::new_v4()
        ));
    }

    #[tokio::test]
    async fn suspended_muc_promotion_mutex_orders_concurrent_admission_after_the_prefix() {
        let endpoint = Arc::new(SuspendedMucEndpoint::new(uuid::Uuid::new_v4()));
        {
            let mut buffer = endpoint.buffer.lock().await;
            assert!(buffer.enqueue_volatile("older-1".to_owned(), 8, 4096));
            assert!(buffer.enqueue_volatile("older-2".to_owned(), 8, 4096));
        }
        let started = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let order = Arc::new(Mutex::new(Vec::new()));
        let calls = Arc::new(AtomicUsize::new(0));
        let promote_endpoint = Arc::clone(&endpoint);
        let promote_started = Arc::clone(&started);
        let promote_release = Arc::clone(&release);
        let promote_order = Arc::clone(&order);
        let promote_calls = Arc::clone(&calls);
        let promotion = tokio::spawn(async move {
            let mut buffer = promote_endpoint.buffer.lock().await;
            promote_suspended_muc_buffer(&mut buffer, move |_source_id, stanza| {
                let started = Arc::clone(&promote_started);
                let release = Arc::clone(&promote_release);
                let order = Arc::clone(&promote_order);
                let call = promote_calls.fetch_add(1, Ordering::SeqCst);
                async move {
                    order.lock().unwrap().push(stanza);
                    if call == 0 {
                        started.notify_one();
                        release.notified().await;
                    }
                    true
                }
            })
            .await
        });
        started.notified().await;
        assert!(endpoint.buffer.try_lock().is_err());

        let writer_endpoint = Arc::clone(&endpoint);
        let writer_order = Arc::clone(&order);
        let writer = tokio::spawn(async move {
            let buffer = writer_endpoint.buffer.lock().await;
            assert!(matches!(&buffer.phase, SuspendedMucPhase::Durable));
            writer_order.lock().unwrap().push("newer".to_owned());
        });
        release.notify_one();
        assert!(promotion.await.unwrap());
        writer.await.unwrap();
        assert_eq!(
            *order.lock().unwrap(),
            vec![
                "older-1".to_owned(),
                "older-2".to_owned(),
                "newer".to_owned()
            ]
        );
    }

    #[test]
    fn staged_route_cannot_reactivate_after_identity_or_revocation_fence_changes() {
        let connection = uuid::Uuid::new_v4();
        let user = uuid::Uuid::new_v4();
        let allowed = |actual_connection,
                       actual_user,
                       actual_generation,
                       same_lifecycle,
                       lifecycle_state,
                       session_cancelled,
                       owner_cancelled| {
            staged_route_activation_allowed(StagedRouteActivationCheck {
                session: StagedRouteIdentity {
                    connection_id: actual_connection,
                    user_id: actual_user,
                    auth_generation: actual_generation,
                },
                expected: StagedRouteIdentity {
                    connection_id: connection,
                    user_id: user,
                    auth_generation: 7,
                },
                same_lifecycle,
                lifecycle_state,
                session_cancelled,
                owner_cancelled,
            })
        };
        assert!(allowed(connection, user, 7, true, 0, false, false));
        assert!(!allowed(
            uuid::Uuid::new_v4(),
            user,
            7,
            true,
            0,
            false,
            false
        ));
        assert!(!allowed(connection, user, 6, true, 0, false, false));
        assert!(!allowed(connection, user, 7, false, 0, false, false));
        assert!(!allowed(connection, user, 7, true, 1, false, false));
        assert!(!allowed(connection, user, 7, true, 0, true, false));
        assert!(!allowed(connection, user, 7, true, 0, false, true));
    }

    #[test]
    fn omemo_poll_ip_window_is_sliding_and_bounded() {
        let started = Instant::now();
        let mut window = VecDeque::new();
        for offset in 0..super::OMEMO_POLL_IP_REQUESTS_PER_MINUTE {
            assert!(admit_omemo_poll_ip_window(
                &mut window,
                started + Duration::from_millis(offset as u64),
            ));
        }
        assert!(!admit_omemo_poll_ip_window(
            &mut window,
            started + Duration::from_secs(1),
        ));
        assert!(admit_omemo_poll_ip_window(
            &mut window,
            started + Duration::from_secs(61),
        ));
        assert_eq!(window.len(), 1);
    }

    fn test_muc_occupant(
        full_jid: &str,
        connection_id: uuid::Uuid,
        cluster_epoch: uuid::Uuid,
    ) -> MucOccupant {
        let (sender, _receiver) = tokio::sync::mpsc::channel(1);
        MucOccupant {
            full_jid: full_jid.to_owned(),
            room_jid: "room@conference.example.test".to_owned(),
            nick: "Alice".to_owned(),
            endpoint: MucOccupantEndpoint::Local(crate::outbound::OutboundSender::new(sender)),
            affiliation: "member".to_owned(),
            role: "participant".to_owned(),
            room_non_anonymous: true,
            occupant_id: "opaque".to_owned(),
            cluster_epoch,
            connection_id,
            sm_session_id: None,
            payload: String::new(),
        }
    }

    #[test]
    fn kicked_session_without_occupant_cannot_authorize_a_message() {
        let connection_id = uuid::Uuid::new_v4();
        let membership = JoinedMucMembership {
            nick: "Alice".to_owned(),
            cluster_epoch: uuid::Uuid::new_v4(),
        };
        let occupant: Option<&MucOccupant> = None;
        assert!(!occupant.is_some_and(|occupant| {
            muc_actor_identity_matches(
                occupant,
                "alice@example.test/Phone",
                connection_id,
                "room@conference.example.test",
                &membership,
            )
        }));
    }

    #[test]
    fn reused_nickname_does_not_authorize_the_old_session() {
        let old_connection = uuid::Uuid::new_v4();
        let old_membership = JoinedMucMembership {
            nick: "Alice".to_owned(),
            cluster_epoch: uuid::Uuid::new_v4(),
        };
        let replacement = test_muc_occupant(
            "bob@example.test/Laptop",
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
        );
        assert!(!muc_actor_identity_matches(
            &replacement,
            "alice@example.test/Phone",
            old_connection,
            "room@conference.example.test",
            &old_membership,
        ));
    }

    #[test]
    fn delayed_old_drop_cannot_remove_a_reused_nickname() {
        let old_connection = uuid::Uuid::new_v4();
        let old_epoch = uuid::Uuid::new_v4();
        let replacement = test_muc_occupant(
            "alice@example.test/Phone",
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
        );
        assert!(!muc_departure_identity_matches(
            &replacement,
            "alice@example.test/Phone",
            old_connection,
            old_epoch,
        ));
    }

    #[test]
    fn delayed_suspended_teardown_cannot_remove_resumed_connection() {
        let sm_session_id = uuid::Uuid::new_v4();
        let old_connection_id = uuid::Uuid::new_v4();
        let new_connection_id = uuid::Uuid::new_v4();
        let cluster_epoch = uuid::Uuid::new_v4();
        let mut current =
            test_muc_occupant("alice@example.test/Phone", old_connection_id, cluster_epoch);
        current.sm_session_id = Some(sm_session_id);
        current.endpoint =
            MucOccupantEndpoint::Suspended(Arc::new(SuspendedMucEndpoint::new(sm_session_id)));
        let stale_teardown = SerializableMucOccupant::from(&current);
        assert!(muc_suspended_teardown_identity_matches(
            &current,
            sm_session_id,
            &stale_teardown,
        ));

        let (sender, _receiver) = tokio::sync::mpsc::channel(1);
        current.endpoint = MucOccupantEndpoint::Local(crate::outbound::OutboundSender::new(sender));
        current.connection_id = new_connection_id;
        assert_eq!(current.cluster_epoch, stale_teardown.cluster_epoch);
        assert!(!muc_suspended_teardown_identity_matches(
            &current,
            sm_session_id,
            &stale_teardown,
        ));
    }

    #[test]
    fn full_session_lookup_is_exact_while_bare_lookup_is_canonical() {
        assert_eq!(
            session_lookup("ALICE@Example.test/Phone"),
            Some(SessionLookup::Full("alice@example.test/Phone".to_owned()))
        );
        assert_eq!(
            session_lookup("alice@example.test/phone"),
            Some(SessionLookup::Full("alice@example.test/phone".to_owned()))
        );
        assert_ne!(
            session_lookup("alice@example.test/Phone"),
            session_lookup("alice@example.test/phone")
        );
        assert_eq!(
            session_lookup("ALICE@Example.test"),
            Some(SessionLookup::Bare("alice@example.test".to_owned()))
        );
        assert_eq!(
            session_lookup("A\u{30a}LICE@B\u{fc}CHER.Example./DeviceA\u{30a}"),
            Some(SessionLookup::Full(
                "\u{e5}lice@b\u{fc}cher.example/Device\u{c5}".to_owned()
            ))
        );
        assert_eq!(session_lookup("alice@example.test/\u{0007}"), None);
        assert_eq!(session_lookup("alice@@example.test/Phone"), None);
    }

    #[test]
    fn cluster_muc_epoch_is_backward_compatible_and_exact() {
        let legacy = serde_json::json!({
            "full_jid": "alice@example.test/Phone",
            "room_jid": "room@conference.example.test",
            "nick": "Alice",
            "affiliation": "member",
            "role": "participant",
            "room_non_anonymous": true,
            "occupant_id": "opaque",
            "payload": ""
        });
        let legacy: SerializableMucOccupant = serde_json::from_value(legacy).unwrap();
        assert_eq!(legacy.sm_session_id, None);
        assert!(legacy.cluster_epoch.is_nil());

        let id = uuid::Uuid::new_v4();
        let current = SerializableMucOccupant {
            sm_session_id: Some(id),
            ..legacy
        };
        let round_trip: SerializableMucOccupant =
            serde_json::from_str(&serde_json::to_string(&current).unwrap()).unwrap();
        assert_eq!(round_trip.sm_session_id, Some(id));
    }

    #[test]
    fn federation_entity_rules_follow_domain_bare_and_full_jid_specificity() {
        let phone = crate::jid::CanonicalJid::parse("alice@remote.example/Phone").unwrap();
        let laptop = crate::jid::CanonicalJid::parse("alice@remote.example/Laptop").unwrap();
        let bob = crate::jid::CanonicalJid::parse("bob@remote.example/Phone").unwrap();
        assert!(federation_rule_matches("remote.example", &phone));
        assert!(federation_rule_matches("alice@remote.example", &phone));
        assert!(federation_rule_matches(
            "alice@remote.example/Phone",
            &phone
        ));
        assert!(!federation_rule_matches(
            "alice@remote.example/Phone",
            &laptop
        ));
        assert!(!federation_rule_matches("alice@remote.example", &bob));
        assert!(!federation_rule_matches("other.example", &phone));
    }

    #[test]
    fn service_control_only_stops_processes_started_before_the_fire_epoch() {
        let fired_at = chrono::Utc::now();
        let control = crate::db::DurableServiceControl {
            generation: uuid::Uuid::new_v4(),
            action: "restart".to_owned(),
            execute_at: fired_at - chrono::Duration::seconds(1),
            fired_at: Some(fired_at),
            expires_at: fired_at + chrono::Duration::minutes(5),
        };
        assert!(service_control_applies(
            fired_at - chrono::Duration::seconds(1),
            &control
        ));
        assert!(!service_control_applies(fired_at, &control));
        assert!(!service_control_applies(
            fired_at + chrono::Duration::seconds(1),
            &control
        ));
        let pending = crate::db::DurableServiceControl {
            fired_at: None,
            ..control
        };
        assert!(!service_control_applies(
            fired_at - chrono::Duration::seconds(1),
            &pending
        ));
    }

    #[test]
    fn api_cursor_rotation_uses_the_shared_api_secret_overlap() {
        use crate::api::cursor::{CursorBinding, CursorDirection, CursorPosition, CursorValue};

        let old_secret = b"old-shared-api-secret-000000000001";
        let current_secret = b"new-shared-api-secret-000000000002";
        let (_old_control, old_cursor) = api_keyrings(old_secret, None).unwrap();
        let binding = CursorBinding {
            endpoint: "admin/users",
            principal_scope: b"admin-account-id",
            filter_scope: b"enabled=true",
            sort: "created_at-id",
            direction: CursorDirection::Forward,
            node_incarnation: uuid::Uuid::nil(),
        };
        let position = CursorPosition {
            last: vec![CursorValue::I64(7)],
        };
        let token = old_cursor.issue(&binding, &position, 1_000, 300).unwrap();

        let (_rotating_control, rotating_cursor) =
            api_keyrings(current_secret, Some(old_secret)).unwrap();
        assert_eq!(
            rotating_cursor.verify(&token, &binding, 1_100).unwrap(),
            position
        );

        let (_current_control, current_cursor) = api_keyrings(current_secret, None).unwrap();
        assert!(current_cursor.verify(&token, &binding, 1_100).is_err());
    }

    #[test]
    fn ephemeral_api_control_secret_is_fixed_lowercase_hex() {
        let secret = ephemeral_api_control_secret();
        assert_eq!(secret.len(), 64);
        assert!(secret
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)));
        assert!(!secret.contains(&0));
        assert!(api_keyrings(&secret, None).is_ok());
    }

    #[test]
    fn nul_containing_entropy_is_encoded_before_keyring_validation() {
        let mut entropy = [0_u8; 32];
        entropy[1] = 0xff;
        entropy[31] = 0x80;
        assert!(api_keyrings(&entropy, None).is_err());

        let encoded = encode_api_control_entropy(entropy);
        assert_eq!(&encoded[..4], b"00ff");
        assert_eq!(&encoded[62..], b"80");
        assert!(!encoded.contains(&0));
        assert!(api_keyrings(&encoded, None).is_ok());
    }
}
