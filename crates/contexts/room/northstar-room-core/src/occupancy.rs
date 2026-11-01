//! Occupant records shared by the room service, the MUC protocol adapters and cluster replication.

/// The process-local identity needed to remove one occupancy without touching
/// a connection that later reused its room nickname.
#[derive(Clone, Copy)]
pub struct LocalMucOccupantIdentity<'a> {
    pub room_jid: &'a str,
    pub nick: &'a str,
    pub full_jid: &'a str,
    pub connection_id: uuid::Uuid,
    pub cluster_epoch: uuid::Uuid,
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

impl<'a> From<&'a SerializableMucOccupant> for LocalMucOccupantIdentity<'a> {
    fn from(occupant: &'a SerializableMucOccupant) -> Self {
        Self {
            room_jid: &occupant.room_jid,
            nick: &occupant.nick,
            full_jid: &occupant.full_jid,
            connection_id: occupant.connection_id,
            cluster_epoch: occupant.cluster_epoch,
        }
    }
}

/// One room occupancy. `L` is a live transport sender and `S` a suspended
/// stream endpoint: both belong to the session runtime, so a room sees them
/// only as parameters.
pub struct MucOccupant<L, S> {
    pub full_jid: String,
    pub room_jid: String,
    pub nick: String,
    pub endpoint: MucOccupantEndpoint<L, S>,
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

impl<L: Clone, S> Clone for MucOccupant<L, S> {
    fn clone(&self) -> Self {
        Self {
            full_jid: self.full_jid.clone(),
            room_jid: self.room_jid.clone(),
            nick: self.nick.clone(),
            endpoint: self.endpoint.clone(),
            affiliation: self.affiliation.clone(),
            role: self.role.clone(),
            room_non_anonymous: self.room_non_anonymous,
            occupant_id: self.occupant_id.clone(),
            cluster_epoch: self.cluster_epoch,
            connection_id: self.connection_id,
            sm_session_id: self.sm_session_id,
            payload: self.payload.clone(),
        }
    }
}

impl<'a, L, S> From<&'a MucOccupant<L, S>> for LocalMucOccupantIdentity<'a> {
    fn from(occupant: &'a MucOccupant<L, S>) -> Self {
        Self {
            room_jid: &occupant.room_jid,
            nick: &occupant.nick,
            full_jid: &occupant.full_jid,
            connection_id: occupant.connection_id,
            cluster_epoch: occupant.cluster_epoch,
        }
    }
}

impl<L, S> From<&MucOccupant<L, S>> for SerializableMucOccupant {
    fn from(occ: &MucOccupant<L, S>) -> Self {
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

pub enum MucOccupantEndpoint<L, S> {
    Local(L),
    /// A local occupant whose transport disappeared while a durable XEP-0198
    /// resume window is open.  Traffic is bounded and moved into PostgreSQL;
    /// it is never sent into the dead transport channel.
    Suspended(std::sync::Arc<S>),
    Federated {
        authenticated_domain: String,
        connection_id: uuid::Uuid,
    },
}

impl<L: Clone, S> Clone for MucOccupantEndpoint<L, S> {
    fn clone(&self) -> Self {
        match self {
            Self::Local(sender) => Self::Local(sender.clone()),
            Self::Suspended(endpoint) => Self::Suspended(std::sync::Arc::clone(endpoint)),
            Self::Federated {
                authenticated_domain,
                connection_id,
            } => Self::Federated {
                authenticated_domain: authenticated_domain.clone(),
                connection_id: *connection_id,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalMucNicknameMove {
    Published,
    AlreadyPublished,
    DeferredToReconciliation,
    OldMissing,
    CollisionRestored,
    CollisionRestoreFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalMucJoinPublication {
    Published,
    AlreadyPublished,
    Occupied,
}

pub fn muc_departure_identity_matches<L, S>(
    occupant: &MucOccupant<L, S>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MucRegistration {
    Joined,
    Conflict,
    Full,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MucRename {
    Renamed,
    Conflict,
    Stale,
}

#[derive(Clone)]
pub enum MucRoleChange {
    Changed(Box<SerializableMucOccupant>),
    Stale,
}

pub struct MucPresencePublication<'a> {
    pub room: &'a str,
    pub occupant: &'a SerializableMucOccupant,
    pub unavailable: bool,
    pub created: bool,
    pub removal_status: Option<u16>,
    pub actor_nick: Option<&'a str>,
    pub reason: Option<&'a str>,
}

/// What a committed join did to the disposable routing cache.
pub struct MucJoinCacheAttempt {
    pub refresh: anyhow::Result<()>,
    pub registration: anyhow::Result<MucRegistration>,
}

/// The node that accepted a room's account message.
pub struct FederatedMucAccountRoute {
    pub accepted_full_jid: Option<String>,
}
