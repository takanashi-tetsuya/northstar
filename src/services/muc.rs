//! Application-service boundary for XEP-0045 and clustered MUC authority.
//!
//! XML handlers supply already-authenticated principals and exact occupancy
//! identities. This service owns the PostgreSQL capability and delegates to
//! the repositories which enforce transaction, fencing and outbox invariants.
//! Keeping the pool private prevents a protocol handler from accidentally
//! composing an authoritative mutation with a best-effort Redis side effect.

use crate::db;
use anyhow::Result;
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::{sync::Arc, time::Duration};
use uuid::Uuid;

const LOCAL_JOIN_GATE_SHARDS: usize = 256;

#[derive(Clone)]
pub(crate) struct MucService {
    pool: PgPool,
    /// Server-owned domain authority.  Protocol commands cannot substitute a
    /// self-reported domain for this value.
    configured_domain: Arc<str>,
    /// Single-node MUC occupancy has no PostgreSQL lease row. Serialize the
    /// final nickname/capacity check and in-memory publication per room using
    /// a fixed number of shards, so adversarial room churn cannot grow a lock
    /// registry without bound.
    local_join_gates: Arc<[Arc<tokio::sync::Mutex<()>>]>,
}

/// Minimal local-account identity needed by MUC routing. Password verifiers,
/// administrative status and profile fields never cross this boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MucLocalAccount {
    pub(crate) id: Uuid,
}

#[derive(Clone, Debug)]
pub(crate) struct MucRoom {
    pub(crate) id: Uuid,
    pub(crate) room_epoch: Uuid,
    pub(crate) config_version: i64,
    pub(crate) localpart: String,
    pub(crate) title: Option<String>,
    pub(crate) description: Option<String>,
    pub(crate) persistent: bool,
    pub(crate) members_only: bool,
    pub(crate) public: bool,
    pub(crate) moderated: bool,
    pub(crate) non_anonymous: bool,
    pub(crate) max_occupants: i32,
    pub(crate) subject: Option<String>,
    pub(crate) subject_changed_at: Option<DateTime<Utc>>,
    pub(crate) allow_subject_change: bool,
    pub(crate) allow_invites: bool,
    pub(crate) allow_private_messages: bool,
    pub(crate) logging_enabled: bool,
    pub(crate) allow_registration: bool,
    pub(crate) password_hash: Option<String>,
    pub(crate) occupant_id_secret: Vec<u8>,
    pub(crate) configuration_owner_jid: Option<String>,
    pub(crate) configuration_expires_at: Option<DateTime<Utc>>,
}

impl MucRoom {
    pub(crate) fn is_locked(&self) -> bool {
        self.configuration_owner_jid.is_some()
    }

    pub(crate) fn configuration_is_expired(&self, now: DateTime<Utc>) -> bool {
        self.configuration_expires_at
            .is_some_and(|expires_at| expires_at <= now)
    }

    pub(crate) fn can_configure_locked_room(
        &self,
        actor_full_jid: &str,
        now: DateTime<Utc>,
    ) -> bool {
        self.configuration_owner_jid.as_deref() == Some(actor_full_jid)
            && !self.configuration_is_expired(now)
    }
}

impl From<db::MucRoom> for MucRoom {
    fn from(room: db::MucRoom) -> Self {
        Self {
            id: room.id,
            room_epoch: room.room_epoch,
            config_version: room.config_version,
            localpart: room.localpart,
            title: room.title,
            description: room.description,
            persistent: room.persistent,
            members_only: room.members_only,
            public: room.public,
            moderated: room.moderated,
            non_anonymous: room.non_anonymous,
            max_occupants: room.max_occupants,
            subject: room.subject,
            subject_changed_at: room.subject_changed_at,
            allow_subject_change: room.allow_subject_change,
            allow_invites: room.allow_invites,
            allow_private_messages: room.allow_private_messages,
            logging_enabled: room.logging_enabled,
            allow_registration: room.allow_registration,
            password_hash: room.password_hash,
            occupant_id_secret: room.occupant_id_secret,
            configuration_owner_jid: room.configuration_owner_jid,
            configuration_expires_at: room.configuration_expires_at,
        }
    }
}

#[derive(Debug)]
pub(crate) struct MucMessage {
    pub(crate) sender_jid: String,
    pub(crate) stanza: String,
    pub(crate) created_at: DateTime<Utc>,
}

impl From<db::MucMessage> for MucMessage {
    fn from(message: db::MucMessage) -> Self {
        Self {
            sender_jid: message.sender_jid,
            stanza: message.stanza,
            created_at: message.created_at,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct MucDiscoPage {
    pub(crate) rooms: Vec<MucRoom>,
    pub(crate) total: i64,
    pub(crate) first_index: i64,
}

impl From<db::MucDiscoPage> for MucDiscoPage {
    fn from(page: db::MucDiscoPage) -> Self {
        Self {
            rooms: page.rooms.into_iter().map(Into::into).collect(),
            total: page.total,
            first_index: page.first_index,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OfflineStoreOutcome {
    Stored,
    Replay,
    QuotaExceeded,
    RecipientUnavailable,
}

impl From<db::OfflineStoreOutcome> for OfflineStoreOutcome {
    fn from(outcome: db::OfflineStoreOutcome) -> Self {
        match outcome {
            db::OfflineStoreOutcome::Stored => Self::Stored,
            db::OfflineStoreOutcome::Replay => Self::Replay,
            db::OfflineStoreOutcome::QuotaExceeded => Self::QuotaExceeded,
            db::OfflineStoreOutcome::RecipientUnavailable => Self::RecipientUnavailable,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct OfflineStorePolicy {
    pub(crate) max_messages: i64,
    pub(crate) max_bytes: i64,
    pub(crate) ttl_days: i64,
    pub(crate) mam_backed: bool,
}

impl From<OfflineStorePolicy> for db::OfflineStorePolicy {
    fn from(policy: OfflineStorePolicy) -> Self {
        Self {
            max_messages: policy.max_messages,
            max_bytes: policy.max_bytes,
            ttl_days: policy.ttl_days,
            mam_backed: policy.mam_backed,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct FederatedInvitePolicy {
    pub(crate) ttl_seconds: u64,
    pub(crate) max_rows: i64,
    pub(crate) max_bytes: i64,
    pub(crate) max_per_domain: i64,
}

impl From<db::S2sOutboxPolicy> for FederatedInvitePolicy {
    fn from(policy: db::S2sOutboxPolicy) -> Self {
        Self {
            ttl_seconds: policy.ttl_seconds,
            max_rows: policy.max_rows,
            max_bytes: policy.max_bytes,
            max_per_domain: policy.max_per_domain,
        }
    }
}

impl From<FederatedInvitePolicy> for db::S2sOutboxPolicy {
    fn from(policy: FederatedInvitePolicy) -> Self {
        Self {
            ttl_seconds: policy.ttl_seconds,
            max_rows: policy.max_rows,
            max_bytes: policy.max_bytes,
            max_per_domain: policy.max_per_domain,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum ClusterMucPrincipal {
    Local {
        user_id: Uuid,
        bare_jid: String,
    },
    Federated {
        bare_jid: String,
        authenticated_domain: String,
    },
}

impl From<&ClusterMucPrincipal> for db::ClusterMucPrincipal {
    fn from(principal: &ClusterMucPrincipal) -> Self {
        match principal {
            ClusterMucPrincipal::Local { user_id, bare_jid } => Self::Local {
                user_id: *user_id,
                bare_jid: bare_jid.clone(),
            },
            ClusterMucPrincipal::Federated {
                bare_jid,
                authenticated_domain,
            } => Self::Federated {
                bare_jid: bare_jid.clone(),
                authenticated_domain: authenticated_domain.clone(),
            },
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum ClusterMucAffiliationSubject {
    Local { user_id: Uuid, bare_jid: String },
    Federated { bare_jid: String },
}

impl From<&ClusterMucAffiliationSubject> for db::ClusterMucAffiliationSubject {
    fn from(subject: &ClusterMucAffiliationSubject) -> Self {
        match subject {
            ClusterMucAffiliationSubject::Local { user_id, bare_jid } => Self::Local {
                user_id: *user_id,
                bare_jid: bare_jid.clone(),
            },
            ClusterMucAffiliationSubject::Federated { bare_jid } => Self::Federated {
                bare_jid: bare_jid.clone(),
            },
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub(crate) struct ClusterMucOccupancyTarget {
    pub(crate) room_id: Uuid,
    pub(crate) room_epoch: Uuid,
    pub(crate) occupant_incarnation: Uuid,
    pub(crate) occupancy_epoch: i64,
    pub(crate) full_jid: String,
    pub(crate) nick: String,
    pub(crate) connection_uuid: Uuid,
    pub(crate) connection_epoch: i64,
}

impl From<db::ClusterMucOccupancyTarget> for ClusterMucOccupancyTarget {
    fn from(target: db::ClusterMucOccupancyTarget) -> Self {
        Self {
            room_id: target.room_id,
            room_epoch: target.room_epoch,
            occupant_incarnation: target.occupant_incarnation,
            occupancy_epoch: target.occupancy_epoch,
            full_jid: target.full_jid,
            nick: target.nick,
            connection_uuid: target.connection_uuid,
            connection_epoch: target.connection_epoch,
        }
    }
}

impl From<&ClusterMucOccupancyTarget> for db::ClusterMucOccupancyTarget {
    fn from(target: &ClusterMucOccupancyTarget) -> Self {
        Self {
            room_id: target.room_id,
            room_epoch: target.room_epoch,
            occupant_incarnation: target.occupant_incarnation,
            occupancy_epoch: target.occupancy_epoch,
            full_jid: target.full_jid.clone(),
            nick: target.nick.clone(),
            connection_uuid: target.connection_uuid,
            connection_epoch: target.connection_epoch,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ClusterMucInviteAuthority {
    pub(crate) operation_id: Uuid,
    pub(crate) expected_room_epoch: Uuid,
    pub(crate) expected_config_version: i64,
    pub(crate) actor: ClusterMucPrincipal,
    pub(crate) actor_full_jid: String,
    pub(crate) actor_target: Option<ClusterMucOccupancyTarget>,
    pub(crate) subject: ClusterMucAffiliationSubject,
    pub(crate) reason: Option<String>,
}

impl From<&ClusterMucInviteAuthority> for db::ClusterMucInviteAuthority {
    fn from(authority: &ClusterMucInviteAuthority) -> Self {
        Self {
            operation_id: authority.operation_id,
            expected_room_epoch: authority.expected_room_epoch,
            expected_config_version: authority.expected_config_version,
            actor: (&authority.actor).into(),
            actor_full_jid: authority.actor_full_jid.clone(),
            actor_target: authority.actor_target.as_ref().map(Into::into),
            subject: (&authority.subject).into(),
            reason: authority.reason.clone(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MucRegistrationOutcome {
    Registered { affiliation_changed: bool },
    Conflict,
    Outcast,
}

impl From<db::MucRegistrationOutcome> for MucRegistrationOutcome {
    fn from(outcome: db::MucRegistrationOutcome) -> Self {
        match outcome {
            db::MucRegistrationOutcome::Registered {
                affiliation_changed,
            } => Self::Registered {
                affiliation_changed,
            },
            db::MucRegistrationOutcome::Conflict => Self::Conflict,
            db::MucRegistrationOutcome::Outcast => Self::Outcast,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ClusterMucRegistrationOutcome {
    Applied { affiliation_changed: bool },
    Replay { affiliation_changed: bool },
    Conflict,
    Outcast,
    NotAllowed,
    Stale,
    Destroyed,
}

impl From<db::ClusterMucRegistrationOutcome> for ClusterMucRegistrationOutcome {
    fn from(outcome: db::ClusterMucRegistrationOutcome) -> Self {
        match outcome {
            db::ClusterMucRegistrationOutcome::Applied {
                affiliation_changed,
            } => Self::Applied {
                affiliation_changed,
            },
            db::ClusterMucRegistrationOutcome::Replay {
                affiliation_changed,
            } => Self::Replay {
                affiliation_changed,
            },
            db::ClusterMucRegistrationOutcome::Conflict => Self::Conflict,
            db::ClusterMucRegistrationOutcome::Outcast => Self::Outcast,
            db::ClusterMucRegistrationOutcome::NotAllowed => Self::NotAllowed,
            db::ClusterMucRegistrationOutcome::Stale => Self::Stale,
            db::ClusterMucRegistrationOutcome::Destroyed => Self::Destroyed,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DurableMucInviteOutcome {
    Stored { id: Uuid, affiliation_changed: bool },
    Replay { id: Uuid },
    QuotaExceeded,
    RecipientUnavailable,
    Outcast,
    AuthorityRejected,
    Stale,
}

impl From<db::DurableMucInviteOutcome> for DurableMucInviteOutcome {
    fn from(outcome: db::DurableMucInviteOutcome) -> Self {
        match outcome {
            db::DurableMucInviteOutcome::Stored {
                id,
                affiliation_changed,
            } => Self::Stored {
                id,
                affiliation_changed,
            },
            db::DurableMucInviteOutcome::Replay { id } => Self::Replay { id },
            db::DurableMucInviteOutcome::QuotaExceeded => Self::QuotaExceeded,
            db::DurableMucInviteOutcome::RecipientUnavailable => Self::RecipientUnavailable,
            db::DurableMucInviteOutcome::Outcast => Self::Outcast,
            db::DurableMucInviteOutcome::AuthorityRejected => Self::AuthorityRejected,
            db::DurableMucInviteOutcome::Stale => Self::Stale,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ClusterMucTransitionOutcome {
    Applied,
    Replay,
    Stale,
    Destroyed,
    Conflict,
    Unauthorized,
}

impl From<db::ClusterMucTransitionOutcome> for ClusterMucTransitionOutcome {
    fn from(outcome: db::ClusterMucTransitionOutcome) -> Self {
        match outcome {
            db::ClusterMucTransitionOutcome::Applied => Self::Applied,
            db::ClusterMucTransitionOutcome::Replay => Self::Replay,
            db::ClusterMucTransitionOutcome::Stale => Self::Stale,
            db::ClusterMucTransitionOutcome::Destroyed => Self::Destroyed,
            db::ClusterMucTransitionOutcome::Conflict => Self::Conflict,
            db::ClusterMucTransitionOutcome::Unauthorized => Self::Unauthorized,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MucConfigurationOutcome {
    Applied,
    LockedByAnother,
    Expired,
    Missing,
}

impl From<db::MucConfigurationOutcome> for MucConfigurationOutcome {
    fn from(outcome: db::MucConfigurationOutcome) -> Self {
        match outcome {
            db::MucConfigurationOutcome::Applied => Self::Applied,
            db::MucConfigurationOutcome::LockedByAnother => Self::LockedByAnother,
            db::MucConfigurationOutcome::Expired => Self::Expired,
            db::MucConfigurationOutcome::Missing => Self::Missing,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ClusterMucConfigurationOutcome {
    Applied,
    Replay,
    LockedByAnother,
    Expired,
    Missing,
    Stale,
    Unauthorized,
    Destroyed,
}

impl From<db::ClusterMucConfigurationOutcome> for ClusterMucConfigurationOutcome {
    fn from(outcome: db::ClusterMucConfigurationOutcome) -> Self {
        match outcome {
            db::ClusterMucConfigurationOutcome::Applied => Self::Applied,
            db::ClusterMucConfigurationOutcome::Replay => Self::Replay,
            db::ClusterMucConfigurationOutcome::LockedByAnother => Self::LockedByAnother,
            db::ClusterMucConfigurationOutcome::Expired => Self::Expired,
            db::ClusterMucConfigurationOutcome::Missing => Self::Missing,
            db::ClusterMucConfigurationOutcome::Stale => Self::Stale,
            db::ClusterMucConfigurationOutcome::Unauthorized => Self::Unauthorized,
            db::ClusterMucConfigurationOutcome::Destroyed => Self::Destroyed,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MucAffiliationBatchOutcome {
    Applied,
    DuplicateTarget,
    LastOwner,
    MissingTarget,
    Unauthorized,
    Stale,
    Destroyed,
}

impl From<db::MucAffiliationBatchOutcome> for MucAffiliationBatchOutcome {
    fn from(outcome: db::MucAffiliationBatchOutcome) -> Self {
        match outcome {
            db::MucAffiliationBatchOutcome::Applied => Self::Applied,
            db::MucAffiliationBatchOutcome::DuplicateTarget => Self::DuplicateTarget,
            db::MucAffiliationBatchOutcome::LastOwner => Self::LastOwner,
            db::MucAffiliationBatchOutcome::MissingTarget => Self::MissingTarget,
            db::MucAffiliationBatchOutcome::Unauthorized => Self::Unauthorized,
            db::MucAffiliationBatchOutcome::Stale => Self::Stale,
            db::MucAffiliationBatchOutcome::Destroyed => Self::Destroyed,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub(crate) enum MucAffiliationTarget {
    LocalUsername(String),
    FederatedBareJid(String),
}

impl From<&MucAffiliationTarget> for db::MucAffiliationTarget {
    fn from(target: &MucAffiliationTarget) -> Self {
        match target {
            MucAffiliationTarget::LocalUsername(username) => Self::LocalUsername(username.clone()),
            MucAffiliationTarget::FederatedBareJid(jid) => Self::FederatedBareJid(jid.clone()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub(crate) struct MucAffiliationChange {
    pub(crate) target: MucAffiliationTarget,
    pub(crate) affiliation: String,
}

impl From<&MucAffiliationChange> for db::MucAffiliationChange {
    fn from(change: &MucAffiliationChange) -> Self {
        Self {
            target: (&change.target).into(),
            affiliation: change.affiliation.clone(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MucDiscussionAdmission {
    Stored(Uuid),
    Replay(Uuid),
    Unauthorized,
    Stale,
}

impl From<db::MucDiscussionAdmission> for MucDiscussionAdmission {
    fn from(admission: db::MucDiscussionAdmission) -> Self {
        match admission {
            db::MucDiscussionAdmission::Stored(id) => Self::Stored(id),
            db::MucDiscussionAdmission::Replay(id) => Self::Replay(id),
            db::MucDiscussionAdmission::Unauthorized => Self::Unauthorized,
            db::MucDiscussionAdmission::Stale => Self::Stale,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) enum MucActorPrincipal<'a> {
    Local {
        user_id: Uuid,
        local_domain: &'a str,
    },
    Federated {
        bare_jid: &'a str,
        authenticated_domain: &'a str,
    },
}

impl<'a> From<&MucActorPrincipal<'a>> for db::MucActorPrincipal<'a> {
    fn from(principal: &MucActorPrincipal<'a>) -> Self {
        match principal {
            MucActorPrincipal::Local {
                user_id,
                local_domain,
            } => Self::Local {
                user_id: *user_id,
                local_domain,
            },
            MucActorPrincipal::Federated {
                bare_jid,
                authenticated_domain,
            } => Self::Federated {
                bare_jid,
                authenticated_domain,
            },
        }
    }
}

impl MucActorAuthority<'_> {
    /// Reject a forged foreign-domain JID before a local command crosses the
    /// application-service boundary.  The repository repeats this check under
    /// its transaction locks so this is defense in depth, not the authority
    /// decision itself.
    fn local_scope_matches_configured_domain(&self, configured_domain: &str) -> bool {
        let MucActorPrincipal::Local { local_domain, .. } = &self.principal else {
            return true;
        };
        let (Ok(local_domain), Ok(configured_domain)) = (
            crate::jid::prepare_domainpart(local_domain),
            crate::jid::prepare_domainpart(configured_domain),
        ) else {
            return false;
        };
        if local_domain != configured_domain {
            return false;
        }
        crate::jid::CanonicalJid::parse_bare(self.actor_scope).is_ok_and(|actor| {
            actor.resourcepart().is_none()
                && actor.domainpart() == local_domain
                && actor.to_string() == self.actor_scope
        })
    }
}

#[derive(Clone, Debug)]
pub(crate) struct MucActorAuthority<'a> {
    pub(crate) clustered: bool,
    pub(crate) expected_room_epoch: Uuid,
    pub(crate) principal: MucActorPrincipal<'a>,
    pub(crate) actor_scope: &'a str,
    pub(crate) full_jid: &'a str,
    pub(crate) nick: &'a str,
    pub(crate) occupant_incarnation: Uuid,
    pub(crate) connection_uuid: Uuid,
    pub(crate) expected_role: &'a str,
    pub(crate) expected_affiliation: &'a str,
    pub(crate) cluster_target: Option<ClusterMucOccupancyTarget>,
}

pub(crate) struct MucDiscussion<'a> {
    pub(crate) id: Uuid,
    pub(crate) room_id: Uuid,
    pub(crate) actor_scope: &'a str,
    pub(crate) origin_id: Option<&'a str>,
    pub(crate) sender_jid: &'a str,
    pub(crate) nick: &'a str,
    pub(crate) stanza: &'a str,
    pub(crate) encrypted: bool,
    pub(crate) archive: bool,
    pub(crate) retention_days: i64,
    pub(crate) authority: MucActorAuthority<'a>,
}

impl<'a> MucDiscussion<'a> {
    fn into_db(self) -> db::MucDiscussion<'a> {
        let cluster_target = self.authority.cluster_target.as_ref().map(Into::into);
        let authority = db::MucActorAuthority {
            clustered: self.authority.clustered,
            expected_room_epoch: self.authority.expected_room_epoch,
            principal: (&self.authority.principal).into(),
            actor_scope: self.authority.actor_scope,
            full_jid: self.authority.full_jid,
            nick: self.authority.nick,
            occupant_incarnation: self.authority.occupant_incarnation,
            connection_uuid: self.authority.connection_uuid,
            expected_role: self.authority.expected_role,
            expected_affiliation: self.authority.expected_affiliation,
            cluster_target,
        };
        db::MucDiscussion {
            id: self.id,
            room_id: self.room_id,
            actor_scope: self.actor_scope,
            origin_id: self.origin_id,
            sender_jid: self.sender_jid,
            nick: self.nick,
            stanza: self.stanza,
            encrypted: self.encrypted,
            archive: self.archive,
            retention_days: self.retention_days,
            authority,
        }
    }
}

pub(crate) struct MucSubjectMutation<'a> {
    pub(crate) stanza_id: Uuid,
    pub(crate) room_id: Uuid,
    pub(crate) actor_scope: &'a str,
    pub(crate) sender_jid: &'a str,
    pub(crate) nick: &'a str,
    pub(crate) subject: &'a str,
    pub(crate) stanza: &'a str,
    pub(crate) encrypted: bool,
}

impl<'a> MucSubjectMutation<'a> {
    fn into_db(self) -> db::MucSubjectMutation<'a> {
        db::MucSubjectMutation {
            stanza_id: self.stanza_id,
            room_id: self.room_id,
            actor_scope: self.actor_scope,
            sender_jid: self.sender_jid,
            nick: self.nick,
            subject: self.subject,
            stanza: self.stanza,
            encrypted: self.encrypted,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MucRetractionKind {
    Author,
    Moderator,
}

impl From<MucRetractionKind> for db::MucRetractionKind {
    fn from(kind: MucRetractionKind) -> Self {
        match kind {
            MucRetractionKind::Author => Self::Author,
            MucRetractionKind::Moderator => Self::Moderator,
        }
    }
}

pub(crate) struct MucRetractionMutation<'a> {
    pub(crate) action_id: Uuid,
    pub(crate) room_id: Uuid,
    pub(crate) target_id: Uuid,
    pub(crate) expected_stanza: &'a str,
    pub(crate) actor_scope: &'a str,
    pub(crate) sender_jid: &'a str,
    pub(crate) nick: &'a str,
    pub(crate) tombstone: &'a str,
    pub(crate) action_stanza: &'a str,
    pub(crate) reason: Option<&'a str>,
    pub(crate) kind: MucRetractionKind,
    pub(crate) authority: MucActorAuthority<'a>,
}

impl<'a> MucRetractionMutation<'a> {
    fn into_db(self) -> db::MucRetractionMutation<'a> {
        let cluster_target = self.authority.cluster_target.as_ref().map(Into::into);
        db::MucRetractionMutation {
            action_id: self.action_id,
            room_id: self.room_id,
            target_id: self.target_id,
            expected_stanza: self.expected_stanza,
            actor_scope: self.actor_scope,
            sender_jid: self.sender_jid,
            nick: self.nick,
            tombstone: self.tombstone,
            action_stanza: self.action_stanza,
            reason: self.reason,
            kind: self.kind.into(),
            authority: db::MucActorAuthority {
                clustered: self.authority.clustered,
                expected_room_epoch: self.authority.expected_room_epoch,
                principal: (&self.authority.principal).into(),
                actor_scope: self.authority.actor_scope,
                full_jid: self.authority.full_jid,
                nick: self.authority.nick,
                occupant_incarnation: self.authority.occupant_incarnation,
                connection_uuid: self.authority.connection_uuid,
                expected_role: self.authority.expected_role,
                expected_affiliation: self.authority.expected_affiliation,
                cluster_target,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MucRetractionOutcome {
    Applied,
    Conflict,
    Unauthorized,
    Stale,
}

impl From<db::MucRetractionOutcome> for MucRetractionOutcome {
    fn from(outcome: db::MucRetractionOutcome) -> Self {
        match outcome {
            db::MucRetractionOutcome::Applied => Self::Applied,
            db::MucRetractionOutcome::Conflict => Self::Conflict,
            db::MucRetractionOutcome::Unauthorized => Self::Unauthorized,
            db::MucRetractionOutcome::Stale => Self::Stale,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MucAdminRoleEntry {
    pub(crate) nick: String,
    pub(crate) role: String,
    pub(crate) bare_jid: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MucAdminRoleList {
    pub(crate) requester_role: String,
    pub(crate) non_anonymous: bool,
    pub(crate) entries: Vec<MucAdminRoleEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MucAdminAffiliationEntry {
    pub(crate) bare_jid: String,
    pub(crate) affiliation: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MucAdminSnapshot<T> {
    Authorized(T),
    Unauthorized,
    Stale,
}

impl From<db::MucAdminRoleList> for MucAdminRoleList {
    fn from(list: db::MucAdminRoleList) -> Self {
        Self {
            requester_role: list.requester_role,
            non_anonymous: list.non_anonymous,
            entries: list
                .entries
                .into_iter()
                .map(|entry| MucAdminRoleEntry {
                    nick: entry.nick,
                    role: entry.role,
                    bare_jid: entry.bare_jid,
                })
                .collect(),
        }
    }
}

fn map_admin_snapshot<T, U>(
    snapshot: db::MucAdminSnapshot<T>,
    map: impl FnOnce(T) -> U,
) -> MucAdminSnapshot<U> {
    match snapshot {
        db::MucAdminSnapshot::Authorized(value) => MucAdminSnapshot::Authorized(map(value)),
        db::MucAdminSnapshot::Unauthorized => MucAdminSnapshot::Unauthorized,
        db::MucAdminSnapshot::Stale => MucAdminSnapshot::Stale,
    }
}

pub(crate) struct MucConfigUpdate<'a> {
    pub(crate) title: Option<&'a str>,
    pub(crate) description: Option<&'a str>,
    pub(crate) persistent: bool,
    pub(crate) members_only: bool,
    pub(crate) public: bool,
    pub(crate) moderated: bool,
    pub(crate) non_anonymous: bool,
    pub(crate) max_occupants: i32,
    pub(crate) password_hash: Option<&'a str>,
    pub(crate) allow_subject_change: bool,
    pub(crate) allow_invites: bool,
    pub(crate) allow_private_messages: bool,
    pub(crate) logging_enabled: bool,
    pub(crate) allow_registration: bool,
}

impl<'a> MucConfigUpdate<'a> {
    fn into_db(self) -> db::MucConfigUpdate<'a> {
        db::MucConfigUpdate {
            title: self.title,
            description: self.description,
            persistent: self.persistent,
            members_only: self.members_only,
            public: self.public,
            moderated: self.moderated,
            non_anonymous: self.non_anonymous,
            max_occupants: self.max_occupants,
            password_hash: self.password_hash,
            allow_subject_change: self.allow_subject_change,
            allow_invites: self.allow_invites,
            allow_private_messages: self.allow_private_messages,
            logging_enabled: self.logging_enabled,
            allow_registration: self.allow_registration,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ClusterMucOccupancy {
    pub(crate) room_id: Uuid,
    pub(crate) room_epoch: Uuid,
    pub(crate) occupant_incarnation: Uuid,
    pub(crate) occupancy_epoch: i64,
    pub(crate) config_version: i64,
    pub(crate) identity_kind: String,
    pub(crate) local_user_id: Option<Uuid>,
    pub(crate) bare_jid: String,
    pub(crate) full_jid: String,
    pub(crate) nick: String,
    pub(crate) authenticated_domain: Option<String>,
    pub(crate) owner_node_id: String,
    pub(crate) connection_uuid: Uuid,
    pub(crate) connection_epoch: i64,
    pub(crate) sm_session_id: Option<Uuid>,
    pub(crate) role: String,
    pub(crate) affiliation: String,
    pub(crate) state: String,
    pub(crate) presence_payload: String,
    pub(crate) lease_until: DateTime<Utc>,
}

impl From<db::ClusterMucOccupancy> for ClusterMucOccupancy {
    fn from(occupancy: db::ClusterMucOccupancy) -> Self {
        Self {
            room_id: occupancy.room_id,
            room_epoch: occupancy.room_epoch,
            occupant_incarnation: occupancy.occupant_incarnation,
            occupancy_epoch: occupancy.occupancy_epoch,
            config_version: occupancy.config_version,
            identity_kind: occupancy.identity_kind,
            local_user_id: occupancy.local_user_id,
            bare_jid: occupancy.bare_jid,
            full_jid: occupancy.full_jid,
            nick: occupancy.nick,
            authenticated_domain: occupancy.authenticated_domain,
            owner_node_id: occupancy.owner_node_id,
            connection_uuid: occupancy.connection_uuid,
            connection_epoch: occupancy.connection_epoch,
            sm_session_id: occupancy.sm_session_id,
            role: occupancy.role,
            affiliation: occupancy.affiliation,
            state: occupancy.state,
            presence_payload: occupancy.presence_payload,
            lease_until: occupancy.lease_until,
        }
    }
}

pub(crate) struct ClusterMucJoin<'a> {
    pub(crate) operation_id: Uuid,
    pub(crate) room_id: Uuid,
    pub(crate) expected_room_epoch: Uuid,
    pub(crate) expected_config_version: i64,
    pub(crate) principal: ClusterMucPrincipal,
    pub(crate) full_jid: &'a str,
    pub(crate) nick: &'a str,
    pub(crate) owner_node_id: &'a str,
    pub(crate) connection_uuid: Uuid,
    pub(crate) connection_epoch: i64,
    pub(crate) sm_session_id: Option<Uuid>,
    pub(crate) occupant_incarnation: Uuid,
    pub(crate) presence_payload: &'a str,
    pub(crate) lease: Duration,
}

impl<'a> ClusterMucJoin<'a> {
    fn into_db(self) -> db::ClusterMucJoin<'a> {
        db::ClusterMucJoin {
            operation_id: self.operation_id,
            room_id: self.room_id,
            expected_room_epoch: self.expected_room_epoch,
            expected_config_version: self.expected_config_version,
            principal: (&self.principal).into(),
            full_jid: self.full_jid,
            nick: self.nick,
            owner_node_id: self.owner_node_id,
            connection_uuid: self.connection_uuid,
            connection_epoch: self.connection_epoch,
            sm_session_id: self.sm_session_id,
            occupant_incarnation: self.occupant_incarnation,
            presence_payload: self.presence_payload,
            lease: self.lease,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ClusterMucJoinOutcome {
    Joined(ClusterMucOccupancy),
    Replay(ClusterMucOccupancy),
    RoomMissing,
    RoomDestroyed,
    RoomLocked,
    StaleRoom,
    Outcast,
    MembershipRequired,
    ReservedNickname,
    NicknameConflict,
    FullJidConflict,
    Full,
}

impl From<db::ClusterMucJoinOutcome> for ClusterMucJoinOutcome {
    fn from(outcome: db::ClusterMucJoinOutcome) -> Self {
        match outcome {
            db::ClusterMucJoinOutcome::Joined(occupancy) => Self::Joined(occupancy.into()),
            db::ClusterMucJoinOutcome::Replay(occupancy) => Self::Replay(occupancy.into()),
            db::ClusterMucJoinOutcome::RoomMissing => Self::RoomMissing,
            db::ClusterMucJoinOutcome::RoomDestroyed => Self::RoomDestroyed,
            db::ClusterMucJoinOutcome::RoomLocked => Self::RoomLocked,
            db::ClusterMucJoinOutcome::StaleRoom => Self::StaleRoom,
            db::ClusterMucJoinOutcome::Outcast => Self::Outcast,
            db::ClusterMucJoinOutcome::MembershipRequired => Self::MembershipRequired,
            db::ClusterMucJoinOutcome::ReservedNickname => Self::ReservedNickname,
            db::ClusterMucJoinOutcome::NicknameConflict => Self::NicknameConflict,
            db::ClusterMucJoinOutcome::FullJidConflict => Self::FullJidConflict,
            db::ClusterMucJoinOutcome::Full => Self::Full,
        }
    }
}

impl MucService {
    pub(crate) fn new(pool: PgPool, configured_domain: impl AsRef<str>) -> Self {
        let local_join_gates: Arc<[Arc<tokio::sync::Mutex<()>>]> = (0..LOCAL_JOIN_GATE_SHARDS)
            .map(|_| Arc::new(tokio::sync::Mutex::new(())))
            .collect::<Vec<_>>()
            .into();
        Self {
            pool,
            configured_domain: Arc::from(configured_domain.as_ref()),
            local_join_gates,
        }
    }

    /// Serialize every process-local authoritative mutation for one MUC room.
    ///
    /// Cluster mode uses PostgreSQL occupancy/configuration transactions as
    /// its authority and only uses the in-memory registry as a soft cache.
    /// Single-node mode has no durable occupancy row, so local C2S actors,
    /// federated S2S actors, owner/admin commands and SM restoration must all
    /// share this gate before changing the room's occupant registry.
    pub(crate) async fn lock_local_room_mutation(
        &self,
        room_id: Uuid,
    ) -> tokio::sync::OwnedMutexGuard<()> {
        let mut prefix = [0_u8; 8];
        prefix.copy_from_slice(&room_id.as_bytes()[..8]);
        let shard = u64::from_le_bytes(prefix) as usize % self.local_join_gates.len();
        Arc::clone(&self.local_join_gates[shard]).lock_owned().await
    }

    /// Compatibility name retained for the SM restoration path while the
    /// room registry is being consolidated behind this service boundary.
    pub(crate) async fn lock_local_join(&self, room_id: Uuid) -> tokio::sync::OwnedMutexGuard<()> {
        self.lock_local_room_mutation(room_id).await
    }

    /// Stable protocol retry identity. The caller supplies canonical semantic
    /// fields (including the authenticated stream/connection and stanza id);
    /// changing the payload therefore produces a different UUID while an
    /// exact retry reaches the repository's idempotency record.
    pub(crate) fn operation_id(identity: &serde_json::Value) -> Result<Uuid> {
        let bytes = serde_json::to_vec(identity)?;
        let digest = Sha256::digest(bytes);
        let mut id = [0_u8; 16];
        id.copy_from_slice(&digest[..16]);
        id[6] = (id[6] & 0x0f) | 0x50;
        id[8] = (id[8] & 0x3f) | 0x80;
        Ok(Uuid::from_bytes(id))
    }

    pub(crate) fn is_capacity_exhausted(error: &anyhow::Error) -> bool {
        db::is_capacity_exhausted(error)
    }

    pub(crate) fn hash_room_password(password: &str) -> Result<String> {
        db::hash_muc_password(password)
    }

    pub(crate) fn verify_room_password(password_hash: &str, candidate: &str) -> bool {
        db::verify_muc_password(password_hash, candidate)
    }

    #[cfg(test)]
    pub(crate) fn archive_page_is_last(page: &db::MamRsmPage) -> bool {
        matches!(page, db::MamRsmPage::Last)
    }

    /// Notify the cluster dispatcher only after PostgreSQL has committed the
    /// authoritative MUC operation. Keeping the pool inside this service stops
    /// protocol handlers from coupling a Redis wake-up to an arbitrary query.
    pub(crate) async fn wake_committed_operation(
        &self,
        cluster: &crate::cluster::ClusterManager,
        operation_id: Uuid,
    ) -> Result<()> {
        cluster
            .wake_committed_muc_operation(&self.pool, operation_id)
            .await
    }

    // Read-side and durable delivery capabilities used by XMPP handlers.

    pub(crate) async fn local_room_snapshot(&self, localpart: &str) -> Result<Option<MucRoom>> {
        Ok(db::muc_room(&self.pool, localpart).await?.map(Into::into))
    }

    pub(crate) async fn federated_room_snapshot(&self, localpart: &str) -> Result<Option<MucRoom>> {
        self.local_room_snapshot(localpart).await
    }

    pub(crate) async fn local_affiliation(
        &self,
        room_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<String>> {
        db::muc_affiliation(&self.pool, room_id, user_id).await
    }

    pub(crate) async fn federated_affiliation(
        &self,
        room_id: Uuid,
        bare_jid: &str,
    ) -> Result<Option<String>> {
        db::federated_muc_affiliation(&self.pool, room_id, bare_jid).await
    }

    pub(crate) async fn enabled_local_account(
        &self,
        username: &str,
    ) -> Result<Option<MucLocalAccount>> {
        Ok(db::enabled_user_id(&self.pool, username)
            .await?
            .map(|id| MucLocalAccount { id }))
    }

    pub(crate) async fn is_blocked_for_account(
        &self,
        owner_id: Uuid,
        owner_bare_jid: &str,
        candidate: &str,
    ) -> Result<bool> {
        db::is_blocked_for_account(&self.pool, owner_id, owner_bare_jid, candidate).await
    }

    pub(crate) async fn blocked_jids(&self, user_id: Uuid) -> Result<Vec<String>> {
        db::blocked_jids(&self.pool, user_id).await
    }

    pub(crate) async fn store_local_muc_offline(
        &self,
        recipient_id: Uuid,
        sender_jid: &str,
        stanza: &str,
        encrypted: bool,
        policy: OfflineStorePolicy,
    ) -> Result<OfflineStoreOutcome> {
        let recipient = db::find_enabled_user_by_id(&self.pool, recipient_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("MUC offline recipient account is unavailable"))?;
        let recipient_bare_jid = crate::jid::canonicalize_bare(&format!(
            "{}@{}",
            recipient.username, self.configured_domain
        ))?;
        Ok(db::store_offline_for_recipient(
            &self.pool,
            recipient_id,
            &recipient_bare_jid,
            sender_jid,
            stanza,
            encrypted,
            policy.into(),
        )
        .await?
        .into())
    }

    pub(crate) async fn store_federated_muc_offline(
        &self,
        recipient_id: Uuid,
        sender_jid: &str,
        stanza: &str,
        encrypted: bool,
        policy: OfflineStorePolicy,
    ) -> Result<OfflineStoreOutcome> {
        self.store_local_muc_offline(recipient_id, sender_jid, stanza, encrypted, policy)
            .await
    }

    pub(crate) async fn local_message_by_id(
        &self,
        room_id: Uuid,
        message_id: Uuid,
    ) -> Result<Option<MucMessage>> {
        Ok(db::muc_message_by_id(&self.pool, room_id, message_id)
            .await?
            .map(Into::into))
    }

    pub(crate) async fn federated_message_by_id(
        &self,
        room_id: Uuid,
        message_id: Uuid,
    ) -> Result<Option<MucMessage>> {
        self.local_message_by_id(room_id, message_id).await
    }

    pub(crate) async fn local_history_since(
        &self,
        room_id: Uuid,
        limit: i64,
        since: Option<DateTime<Utc>>,
    ) -> Result<Vec<MucMessage>> {
        Ok(db::muc_history_since(&self.pool, room_id, limit, since)
            .await?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    pub(crate) async fn federated_history_since(
        &self,
        room_id: Uuid,
        limit: i64,
        since: Option<DateTime<Utc>>,
    ) -> Result<Vec<MucMessage>> {
        self.local_history_since(room_id, limit, since).await
    }

    pub(crate) async fn delete_expired_locked_room(&self, room_id: Uuid) -> Result<bool> {
        db::delete_expired_locked_muc_room(&self.pool, room_id).await
    }

    pub(crate) async fn delete_temporary_room(
        &self,
        room_id: Uuid,
        room_epoch: Uuid,
        config_version: i64,
    ) -> Result<bool> {
        db::delete_temporary_muc_room(&self.pool, room_id, room_epoch, config_version).await
    }

    pub(crate) async fn local_reserved_nick(
        &self,
        room_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<String>> {
        db::muc_reserved_nick(&self.pool, room_id, user_id).await
    }

    pub(crate) async fn local_nick_reserved_for_other(
        &self,
        room_id: Uuid,
        user_id: Uuid,
        nick: &str,
    ) -> Result<bool> {
        db::muc_nick_reserved_for_other(&self.pool, room_id, user_id, nick).await
    }

    pub(crate) async fn federated_reserved_nick(
        &self,
        room_id: Uuid,
        bare_jid: &str,
    ) -> Result<Option<String>> {
        db::federated_muc_reserved_nick(&self.pool, room_id, bare_jid).await
    }

    pub(crate) async fn federated_nick_reserved_for_other(
        &self,
        room_id: Uuid,
        bare_jid: &str,
        nick: &str,
    ) -> Result<bool> {
        db::federated_muc_nick_reserved_for_other(&self.pool, room_id, bare_jid, nick).await
    }

    pub(crate) async fn get_or_create_local_room(
        &self,
        localpart: &str,
        creator_id: Uuid,
        creator_full_jid: &str,
    ) -> Result<(MucRoom, bool)> {
        let (room, created) =
            db::get_or_create_muc_room(&self.pool, localpart, creator_id, creator_full_jid).await?;
        Ok((room.into(), created))
    }

    pub(crate) async fn get_or_create_federated_room(
        &self,
        localpart: &str,
        creator_full_jid: &str,
    ) -> Result<(MucRoom, bool)> {
        let (room, created) =
            db::get_or_create_federated_muc_room(&self.pool, localpart, creator_full_jid).await?;
        Ok((room.into(), created))
    }

    pub(crate) async fn public_room_page(
        &self,
        after: Option<&str>,
        before: Option<Option<&str>>,
        max: i64,
    ) -> Result<Option<db::MucDiscoPage>> {
        db::public_muc_room_page(&self.pool, after, before, max).await
    }

    pub(crate) async fn federated_public_room_page(
        &self,
        after: Option<&str>,
        before: Option<Option<&str>>,
        max: i64,
    ) -> Result<Option<MucDiscoPage>> {
        Ok(db::public_muc_room_page(&self.pool, after, before, max)
            .await?
            .map(Into::into))
    }

    pub(crate) async fn register_local_member(
        &self,
        room_id: Uuid,
        user_id: Uuid,
        nick: &str,
    ) -> Result<MucRegistrationOutcome> {
        Ok(
            db::register_local_muc_member(&self.pool, room_id, user_id, nick)
                .await?
                .into(),
        )
    }

    pub(crate) async fn unregister_local_member(
        &self,
        room_id: Uuid,
        user_id: Uuid,
    ) -> Result<bool> {
        db::unregister_local_muc_member(&self.pool, room_id, user_id).await
    }

    pub(crate) async fn register_federated_member(
        &self,
        room_id: Uuid,
        bare_jid: &str,
        nick: &str,
    ) -> Result<MucRegistrationOutcome> {
        Ok(
            db::register_federated_muc_member(&self.pool, room_id, bare_jid, nick)
                .await?
                .into(),
        )
    }

    pub(crate) async fn unregister_federated_member(
        &self,
        room_id: Uuid,
        bare_jid: &str,
    ) -> Result<bool> {
        db::unregister_federated_muc_member(&self.pool, room_id, bare_jid).await
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn mutate_local_cluster_registration(
        &self,
        operation_id: Uuid,
        room_id: Uuid,
        expected_room_epoch: Uuid,
        expected_config_version: i64,
        principal: &ClusterMucPrincipal,
        actor_full_jid: &str,
        reserved_nick: Option<&str>,
    ) -> Result<ClusterMucRegistrationOutcome> {
        let principal = principal.into();
        Ok(db::mutate_cluster_muc_registration(
            &self.pool,
            operation_id,
            room_id,
            expected_room_epoch,
            expected_config_version,
            &principal,
            actor_full_jid,
            reserved_nick,
        )
        .await?
        .into())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn admit_local_invite_command(
        &self,
        id: Uuid,
        room_id: Uuid,
        recipient_id: Uuid,
        sender_jid: &str,
        stanza: &str,
        encrypted: bool,
        policy: OfflineStorePolicy,
        cluster_authority: Option<&ClusterMucInviteAuthority>,
    ) -> Result<DurableMucInviteOutcome> {
        let recipient = db::find_enabled_user_by_id(&self.pool, recipient_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("local MUC invite recipient account is unavailable"))?;
        let recipient_bare_jid = crate::jid::canonicalize_bare(&format!(
            "{}@{}",
            recipient.username, self.configured_domain
        ))?;
        let cluster_authority = cluster_authority.map(Into::into);
        Ok(db::admit_local_muc_invite(
            &self.pool,
            id,
            room_id,
            recipient_id,
            &recipient_bare_jid,
            sender_jid,
            stanza,
            encrypted,
            policy.into(),
            cluster_authority.as_ref(),
        )
        .await?
        .into())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn admit_federated_invite_command(
        &self,
        room_id: Uuid,
        invitee_bare_jid: &str,
        target_domain: &str,
        stanza: &str,
        bounce_to: Option<&str>,
        policy: FederatedInvitePolicy,
        cluster_authority: Option<&ClusterMucInviteAuthority>,
    ) -> Result<bool> {
        let cluster_authority = cluster_authority.map(Into::into);
        db::admit_federated_muc_invite(
            &self.pool,
            room_id,
            invitee_bare_jid,
            target_domain,
            stanza,
            bounce_to,
            policy.into(),
            cluster_authority.as_ref(),
        )
        .await
    }

    pub(crate) async fn admit_local_discussion(
        &self,
        message: MucDiscussion<'_>,
    ) -> Result<MucDiscussionAdmission> {
        if !message
            .authority
            .local_scope_matches_configured_domain(&self.configured_domain)
        {
            return Ok(MucDiscussionAdmission::Unauthorized);
        }
        Ok(db::admit_muc_discussion(&self.pool, message.into_db())
            .await?
            .into())
    }

    pub(crate) async fn set_local_cluster_subject(
        &self,
        operation_id: Uuid,
        expected_room_epoch: Uuid,
        expected_config_version: i64,
        actor: &ClusterMucOccupancyTarget,
        mutation: MucSubjectMutation<'_>,
        archive: bool,
    ) -> Result<ClusterMucTransitionOutcome> {
        let actor = actor.into();
        Ok(db::set_cluster_muc_subject(
            &self.pool,
            operation_id,
            expected_room_epoch,
            expected_config_version,
            &actor,
            mutation.into_db(),
            archive,
        )
        .await?
        .into())
    }

    pub(crate) async fn retract_local_message_and_archive_action(
        &self,
        mutation: MucRetractionMutation<'_>,
    ) -> Result<MucRetractionOutcome> {
        if !mutation
            .authority
            .local_scope_matches_configured_domain(&self.configured_domain)
        {
            return Ok(MucRetractionOutcome::Unauthorized);
        }
        Ok(
            db::retract_muc_message_and_archive_action(&self.pool, mutation.into_db())
                .await?
                .into(),
        )
    }

    pub(crate) async fn update_local_legacy_config(
        &self,
        room_id: Uuid,
        actor_full_jid: &str,
        config: MucConfigUpdate<'_>,
    ) -> Result<MucConfigurationOutcome> {
        Ok(
            db::update_muc_config(&self.pool, room_id, actor_full_jid, config.into_db())
                .await?
                .into(),
        )
    }

    pub(crate) async fn cancel_locked_room(
        &self,
        room_id: Uuid,
        actor_full_jid: &str,
    ) -> Result<bool> {
        db::cancel_locked_muc_room(&self.pool, room_id, actor_full_jid).await
    }

    pub(crate) async fn delete_room(&self, room_id: Uuid) -> Result<()> {
        db::delete_muc_room(&self.pool, room_id).await
    }

    pub(crate) async fn set_local_legacy_affiliations_batch(
        &self,
        room_id: Uuid,
        changes: &[MucAffiliationChange],
    ) -> Result<MucAffiliationBatchOutcome> {
        let changes = changes.iter().map(Into::into).collect::<Vec<_>>();
        Ok(
            db::set_muc_affiliations_batch(&self.pool, room_id, &changes)
                .await?
                .into(),
        )
    }

    pub(crate) async fn local_affiliations(
        &self,
        room_id: Uuid,
        affiliation: &str,
    ) -> Result<Vec<String>> {
        db::get_muc_affiliations(&self.pool, room_id, affiliation).await
    }

    pub(crate) async fn federated_affiliations(
        &self,
        room_id: Uuid,
        affiliation: &str,
    ) -> Result<Vec<String>> {
        db::get_federated_muc_affiliations(&self.pool, room_id, affiliation).await
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn authorized_admin_role_list(
        &self,
        room_id: Uuid,
        expected_room_epoch: Uuid,
        user_id: Uuid,
        actor_scope: &str,
        asserted_local_role: &str,
        actor_target: Option<&ClusterMucOccupancyTarget>,
        clustered: bool,
        requested_role: &str,
    ) -> Result<MucAdminSnapshot<MucAdminRoleList>> {
        let actor_target = actor_target.map(Into::into);
        let snapshot = db::authorized_muc_admin_role_list(
            &self.pool,
            room_id,
            expected_room_epoch,
            user_id,
            actor_scope,
            &self.configured_domain,
            asserted_local_role,
            actor_target.as_ref(),
            clustered,
            requested_role,
        )
        .await?;
        Ok(map_admin_snapshot(snapshot, Into::into))
    }

    pub(crate) async fn authorized_admin_affiliation_list(
        &self,
        room_id: Uuid,
        expected_room_epoch: Uuid,
        user_id: Uuid,
        actor_scope: &str,
        requested_affiliation: &str,
    ) -> Result<MucAdminSnapshot<Vec<MucAdminAffiliationEntry>>> {
        let snapshot = db::authorized_muc_admin_affiliation_list(
            &self.pool,
            room_id,
            expected_room_epoch,
            user_id,
            actor_scope,
            requested_affiliation,
            &self.configured_domain,
        )
        .await?;
        Ok(map_admin_snapshot(snapshot, |entries| {
            entries
                .into_iter()
                .map(|entry| MucAdminAffiliationEntry {
                    bare_jid: entry.bare_jid,
                    affiliation: entry.affiliation,
                })
                .collect()
        }))
    }

    // PostgreSQL-authoritative clustered occupancy and control mutations.

    pub(crate) async fn claim_local_cluster_occupancy(
        &self,
        request: ClusterMucJoin<'_>,
    ) -> Result<ClusterMucJoinOutcome> {
        Ok(
            db::claim_cluster_muc_occupancy(&self.pool, request.into_db())
                .await?
                .into(),
        )
    }

    pub(crate) async fn renew_local_cluster_occupancy(
        &self,
        target: &ClusterMucOccupancyTarget,
        owner_node_id: &str,
        lease: Duration,
    ) -> Result<bool> {
        let target = target.into();
        db::renew_cluster_muc_occupancy(&self.pool, &target, owner_node_id, lease).await
    }

    pub(crate) async fn refresh_local_cluster_presence(
        &self,
        target: &ClusterMucOccupancyTarget,
        owner_node_id: &str,
        presence_payload: &str,
        lease: Duration,
    ) -> Result<bool> {
        let target = target.into();
        db::refresh_cluster_muc_presence(
            &self.pool,
            &target,
            owner_node_id,
            presence_payload,
            lease,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn transition_local_cluster_occupancy(
        &self,
        operation_id: Uuid,
        target: &ClusterMucOccupancyTarget,
        transition: &str,
        owner_node_id: &str,
        new_connection_uuid: Option<Uuid>,
        new_connection_epoch: Option<i64>,
        sm_session_id: Option<Uuid>,
        lease: Duration,
    ) -> Result<ClusterMucTransitionOutcome> {
        let target = target.into();
        Ok(db::transition_cluster_muc_occupancy(
            &self.pool,
            operation_id,
            &target,
            transition,
            owner_node_id,
            new_connection_uuid,
            new_connection_epoch,
            sm_session_id,
            lease,
        )
        .await?
        .into())
    }

    pub(crate) async fn rename_local_cluster_occupancy(
        &self,
        operation_id: Uuid,
        target: &ClusterMucOccupancyTarget,
        owner_node_id: &str,
        new_nick: &str,
    ) -> Result<ClusterMucTransitionOutcome> {
        let target = target.into();
        Ok(db::rename_cluster_muc_occupancy(
            &self.pool,
            operation_id,
            &target,
            owner_node_id,
            new_nick,
        )
        .await?
        .into())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn update_local_cluster_config(
        &self,
        operation_id: Uuid,
        room_id: Uuid,
        expected_room_epoch: Uuid,
        expected_config_version: i64,
        actor_target: &ClusterMucOccupancyTarget,
        principal: &ClusterMucPrincipal,
        actor_full_jid: &str,
        config: MucConfigUpdate<'_>,
    ) -> Result<ClusterMucConfigurationOutcome> {
        let actor_target = actor_target.into();
        let principal = principal.into();
        Ok(db::update_cluster_muc_config(
            &self.pool,
            operation_id,
            room_id,
            expected_room_epoch,
            expected_config_version,
            &actor_target,
            &principal,
            actor_full_jid,
            config.into_db(),
        )
        .await?
        .into())
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "application-service boundary mirrors the authenticated XEP-0045 batch command"
    )]
    pub(crate) async fn apply_local_cluster_affiliations_batch(
        &self,
        operation_id: Uuid,
        room_id: Uuid,
        expected_room_epoch: Uuid,
        expected_config_version: i64,
        actor_target: &ClusterMucOccupancyTarget,
        actor: &ClusterMucPrincipal,
        actor_full_jid: &str,
        changes: &[MucAffiliationChange],
    ) -> Result<MucAffiliationBatchOutcome> {
        let actor_target = actor_target.into();
        let actor = actor.into();
        let changes = changes.iter().map(Into::into).collect::<Vec<_>>();
        Ok(db::apply_cluster_muc_affiliations_batch(
            &self.pool,
            db::ClusterMucAffiliationBatch {
                operation_id,
                room_id,
                expected_room_epoch,
                expected_config_version,
                actor_target: &actor_target,
                actor: &actor,
                actor_full_jid,
                changes: &changes,
            },
        )
        .await?
        .into())
    }

    pub(crate) async fn kick_local_cluster_occupancy(
        &self,
        operation_id: Uuid,
        actor: &ClusterMucOccupancyTarget,
        target: &ClusterMucOccupancyTarget,
        reason: Option<&str>,
    ) -> Result<ClusterMucTransitionOutcome> {
        let actor = actor.into();
        let target = target.into();
        Ok(
            db::kick_cluster_muc_occupancy(&self.pool, operation_id, &actor, &target, reason)
                .await?
                .into(),
        )
    }

    pub(crate) async fn change_local_cluster_role(
        &self,
        operation_id: Uuid,
        actor: &ClusterMucOccupancyTarget,
        target: &ClusterMucOccupancyTarget,
        new_role: &str,
        reason: Option<&str>,
    ) -> Result<ClusterMucTransitionOutcome> {
        let actor = actor.into();
        let target = target.into();
        Ok(
            db::change_cluster_muc_role(
                &self.pool,
                operation_id,
                &actor,
                &target,
                new_role,
                reason,
            )
            .await?
            .into(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn destroy_local_cluster_room(
        &self,
        operation_id: Uuid,
        room_id: Uuid,
        expected_room_epoch: Uuid,
        actor: Option<&ClusterMucOccupancyTarget>,
        authorization_source: &str,
        actor_jid: Option<&str>,
        alternate_jid: Option<&str>,
        reason: Option<&str>,
    ) -> Result<ClusterMucTransitionOutcome> {
        let actor = actor.map(Into::into);
        Ok(db::destroy_cluster_muc_room(
            &self.pool,
            operation_id,
            room_id,
            expected_room_epoch,
            actor.as_ref(),
            authorization_source,
            actor_jid,
            alternate_jid,
            reason,
        )
        .await?
        .into())
    }

    pub(crate) async fn local_cluster_occupancy_target(
        &self,
        room_id: Uuid,
        occupant_incarnation: Uuid,
        connection_uuid: Uuid,
    ) -> Result<Option<ClusterMucOccupancyTarget>> {
        Ok(db::cluster_muc_occupancy_target(
            &self.pool,
            room_id,
            occupant_incarnation,
            connection_uuid,
        )
        .await?
        .map(Into::into))
    }

    pub(crate) async fn local_cluster_occupancy_target_by_nick(
        &self,
        room_id: Uuid,
        expected_room_epoch: Uuid,
        nick: &str,
    ) -> Result<Option<ClusterMucOccupancyTarget>> {
        Ok(
            db::cluster_muc_occupancy_target_by_nick(
                &self.pool,
                room_id,
                expected_room_epoch,
                nick,
            )
            .await?
            .map(Into::into),
        )
    }

    pub(crate) async fn exact_local_cluster_occupancy_snapshot(
        &self,
        target: &ClusterMucOccupancyTarget,
    ) -> Result<Option<ClusterMucOccupancy>> {
        let target = target.into();
        Ok(
            db::cluster_muc_exact_occupancy_snapshot(&self.pool, &target)
                .await?
                .map(Into::into),
        )
    }

    pub(crate) async fn cluster_room_is_empty(&self, room_id: Uuid) -> Result<bool> {
        db::cluster_muc_room_is_empty(&self.pool, room_id).await
    }
}

// Transitional compatibility surface for discovery. Both MUC protocol slices
// use only the service-owned DTOs above; this remaining call site belongs to a
// separately-owned service-boundary slice.
impl MucService {
    pub(crate) async fn room(&self, localpart: &str) -> Result<Option<db::MucRoom>> {
        db::muc_room(&self.pool, localpart).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn local_room_mutation_gate_serializes_one_room_without_a_growing_registry() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://northstar@localhost/northstar")
            .expect("lazy test pool");
        let service = MucService::new(pool, "local.test");
        let room_id = Uuid::from_u128(7);
        let first = service.lock_local_room_mutation(room_id).await;
        assert!(tokio::time::timeout(
            Duration::from_millis(10),
            service.lock_local_room_mutation(room_id)
        )
        .await
        .is_err());
        drop(first);
        tokio::time::timeout(
            Duration::from_millis(100),
            service.lock_local_room_mutation(room_id),
        )
        .await
        .expect("room gate released");
        assert_eq!(service.local_join_gates.len(), LOCAL_JOIN_GATE_SHARDS);
    }

    #[tokio::test]
    async fn local_room_mutation_gate_does_not_serialize_different_fixed_shards() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://northstar@localhost/northstar")
            .expect("lazy test pool");
        let service = MucService::new(pool, "local.test");
        let first_room = Uuid::from_bytes([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        // The shard is derived from the first little-endian u64. These two
        // UUIDs therefore select different fixed gates deterministically.
        let other_room = Uuid::from_bytes([2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let first = service.lock_local_room_mutation(first_room).await;
        tokio::time::timeout(
            Duration::from_millis(100),
            service.lock_local_room_mutation(other_room),
        )
        .await
        .expect("an unrelated room shard must remain independently writable");
        drop(first);
    }

    #[test]
    fn registration_outcomes_preserve_authorization_distinctions() {
        assert_eq!(
            MucRegistrationOutcome::from(db::MucRegistrationOutcome::Registered {
                affiliation_changed: true,
            }),
            MucRegistrationOutcome::Registered {
                affiliation_changed: true,
            }
        );
        assert_eq!(
            ClusterMucRegistrationOutcome::from(db::ClusterMucRegistrationOutcome::NotAllowed),
            ClusterMucRegistrationOutcome::NotAllowed
        );
        assert_eq!(
            ClusterMucRegistrationOutcome::from(db::ClusterMucRegistrationOutcome::Stale),
            ClusterMucRegistrationOutcome::Stale
        );
    }

    #[tokio::test]
    async fn local_actor_scope_requires_the_configured_domain_at_the_service_boundary() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://northstar@localhost/northstar")
            .expect("lazy test pool");
        let service = MucService::new(pool, "local.test");
        let admission = service
            .admit_local_discussion(MucDiscussion {
                id: Uuid::nil(),
                room_id: Uuid::nil(),
                actor_scope: "alice@evil.test",
                origin_id: None,
                sender_jid: "alice@evil.test/Phone",
                nick: "Alice",
                stanza: "<message/>",
                encrypted: false,
                archive: false,
                retention_days: 0,
                authority: MucActorAuthority {
                    clustered: false,
                    expected_room_epoch: Uuid::nil(),
                    principal: MucActorPrincipal::Local {
                        user_id: Uuid::nil(),
                        // Attacker-controlled command fields agree with each
                        // other, but not with MucService's server-owned domain.
                        local_domain: "evil.test",
                    },
                    actor_scope: "alice@evil.test",
                    full_jid: "alice@evil.test/Phone",
                    nick: "Alice",
                    occupant_incarnation: Uuid::nil(),
                    connection_uuid: Uuid::nil(),
                    expected_role: "participant",
                    expected_affiliation: "none",
                    cluster_target: None,
                },
            })
            .await
            .expect("forged domain is rejected before the lazy pool connects");
        assert_eq!(admission, MucDiscussionAdmission::Unauthorized);
    }

    #[test]
    fn durable_delivery_outcomes_do_not_collapse_security_failures() {
        assert_eq!(
            DurableMucInviteOutcome::from(db::DurableMucInviteOutcome::RecipientUnavailable),
            DurableMucInviteOutcome::RecipientUnavailable
        );
        assert_eq!(
            DurableMucInviteOutcome::from(db::DurableMucInviteOutcome::AuthorityRejected),
            DurableMucInviteOutcome::AuthorityRejected
        );
        assert_eq!(
            OfflineStoreOutcome::from(db::OfflineStoreOutcome::QuotaExceeded),
            OfflineStoreOutcome::QuotaExceeded
        );
    }

    #[test]
    fn cluster_transition_mapping_keeps_stale_and_unauthorized_separate() {
        assert_eq!(
            ClusterMucTransitionOutcome::from(db::ClusterMucTransitionOutcome::Stale),
            ClusterMucTransitionOutcome::Stale
        );
        assert_eq!(
            ClusterMucTransitionOutcome::from(db::ClusterMucTransitionOutcome::Unauthorized),
            ClusterMucTransitionOutcome::Unauthorized
        );
        assert_eq!(
            ClusterMucConfigurationOutcome::from(
                db::ClusterMucConfigurationOutcome::LockedByAnother
            ),
            ClusterMucConfigurationOutcome::LockedByAnother
        );
    }

    #[test]
    fn occupancy_target_conversion_preserves_all_fencing_fields() {
        let target = ClusterMucOccupancyTarget {
            room_id: Uuid::new_v4(),
            room_epoch: Uuid::new_v4(),
            occupant_incarnation: Uuid::new_v4(),
            occupancy_epoch: 37,
            full_jid: "alice@example.test/desktop".to_owned(),
            nick: "Alice".to_owned(),
            connection_uuid: Uuid::new_v4(),
            connection_epoch: 19,
        };
        let repository: db::ClusterMucOccupancyTarget = (&target).into();
        assert_eq!(ClusterMucOccupancyTarget::from(repository), target);
    }

    #[test]
    fn federated_authority_conversion_preserves_domain_and_outbox_limits() {
        let principal = ClusterMucPrincipal::Federated {
            bare_jid: "alice@remote.test".to_owned(),
            authenticated_domain: "remote.test".to_owned(),
        };
        assert_eq!(
            db::ClusterMucPrincipal::from(&principal),
            db::ClusterMucPrincipal::Federated {
                bare_jid: "alice@remote.test".to_owned(),
                authenticated_domain: "remote.test".to_owned(),
            }
        );

        let policy = FederatedInvitePolicy {
            ttl_seconds: 3600,
            max_rows: 100,
            max_bytes: 1_048_576,
            max_per_domain: 10,
        };
        let repository: db::S2sOutboxPolicy = policy.into();
        assert_eq!(repository.ttl_seconds, 3600);
        assert_eq!(repository.max_rows, 100);
        assert_eq!(repository.max_bytes, 1_048_576);
        assert_eq!(repository.max_per_domain, 10);
    }
}
