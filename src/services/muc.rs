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
pub(crate) use northstar_room_application::{
    validate_muc_affiliation_batch_command, validate_muc_configuration_command,
    validate_muc_registration_command, validate_muc_retraction_command,
    validate_muc_subject_command, MucAffiliationBatchCommand, MucAffiliationBatchResult,
    MucConfigurationCommand, MucConfigurationResult, MucDiscussionRepository,
    MucRegistrationCommand, MucRegistrationResult, MucRetractionCommand, MucRetractionResult,
    MucSubjectCommand, MucSubjectResult, RepositoryFuture, RoomApplication,
};
pub(crate) use northstar_room_core::{
    ClusterMucAffiliationSubject, ClusterMucConfigurationOutcome, ClusterMucInviteAuthority,
    ClusterMucJoin, ClusterMucJoinOutcome, ClusterMucOccupancy, ClusterMucOccupancyTarget,
    ClusterMucPrincipal, ClusterMucRegistrationOutcome, ClusterMucTransitionOutcome,
    DurableMucInviteOutcome, FederatedInvitePolicy, MucActorAuthority, MucActorPrincipal,
    MucAdminAffiliationEntry, MucAdminRoleEntry, MucAdminRoleList, MucAdminSnapshot,
    MucAffiliationBatchOutcome, MucAffiliationBatchWrite, MucAffiliationChange,
    MucAffiliationTarget, MucConfigUpdate, MucConfigurationOutcome, MucConfigurationWrite,
    MucDiscoPage, MucDiscussion, MucDiscussionAdmission, MucLocalAccount, MucMessage,
    MucRegistrationOutcome, MucRegistrationTarget, MucRegistrationWrite, MucRetractionKind,
    MucRetractionMutation, MucRetractionOutcome, MucRoom, MucSubjectMutation, MucSubjectOutcome,
    OfflineStoreOutcome, OfflineStorePolicy,
};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::{sync::Arc, time::Duration};
use uuid::Uuid;

const LOCAL_JOIN_GATE_SHARDS: usize = 256;

#[derive(Clone)]
pub(crate) struct MucService {
    pool: PgPool,
    discussion_application: RoomApplication<PostgresMucDiscussionRepository>,
    /// Server-owned domain authority.  Protocol commands cannot substitute a
    /// self-reported domain for this value.
    configured_domain: Arc<str>,
    /// Single-node MUC occupancy has no PostgreSQL lease row. Serialize the
    /// final nickname/capacity check and in-memory publication per room using
    /// a fixed number of shards, so adversarial room churn cannot grow a lock
    /// registry without bound.
    local_join_gates: Arc<[Arc<tokio::sync::Mutex<()>>]>,
}

#[derive(Clone)]
struct PostgresMucDiscussionRepository {
    pool: PgPool,
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

impl From<db::MucMessage> for MucMessage {
    fn from(message: db::MucMessage) -> Self {
        Self {
            sender_jid: message.sender_jid,
            stanza: message.stanza,
            created_at: message.created_at,
        }
    }
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

fn occupancy_target_from_db(target: db::ClusterMucOccupancyTarget) -> ClusterMucOccupancyTarget {
    ClusterMucOccupancyTarget {
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

fn actor_principal_to_db(principal: &MucActorPrincipal) -> db::MucActorPrincipal<'_> {
    match principal {
        MucActorPrincipal::Local {
            user_id,
            local_domain,
        } => db::MucActorPrincipal::Local {
            user_id: *user_id,
            local_domain,
        },
        MucActorPrincipal::Federated {
            bare_jid,
            authenticated_domain,
        } => db::MucActorPrincipal::Federated {
            bare_jid,
            authenticated_domain,
        },
    }
}

fn actor_authority_to_db(authority: &MucActorAuthority) -> db::MucActorAuthority<'_> {
    db::MucActorAuthority {
        clustered: authority.clustered,
        expected_room_epoch: authority.expected_room_epoch,
        principal: actor_principal_to_db(&authority.principal),
        actor_scope: &authority.actor_scope,
        full_jid: &authority.full_jid,
        nick: &authority.nick,
        occupant_incarnation: authority.occupant_incarnation,
        connection_uuid: authority.connection_uuid,
        expected_role: &authority.expected_role,
        expected_affiliation: &authority.expected_affiliation,
        cluster_target: authority.cluster_target.as_ref().map(Into::into),
    }
}

fn discussion_to_db(command: &MucDiscussion) -> db::MucDiscussion<'_> {
    db::MucDiscussion {
        id: command.id,
        room_id: command.room_id,
        actor_scope: &command.actor_scope,
        origin_id: command.origin_id.as_deref(),
        sender_jid: &command.sender_jid,
        nick: &command.nick,
        stanza: &command.stanza,
        encrypted: command.encrypted,
        archive: command.archive,
        retention_days: command.retention_days,
        authority: actor_authority_to_db(&command.authority),
    }
}

impl MucDiscussionRepository for PostgresMucDiscussionRepository {
    type Error = anyhow::Error;

    fn admit_discussion<'a>(
        &'a self,
        command: &'a MucDiscussion,
    ) -> RepositoryFuture<'a, Self::Error> {
        Box::pin(async move {
            Ok(
                match db::admit_muc_discussion(&self.pool, discussion_to_db(command)).await? {
                    db::MucDiscussionAdmission::Stored(id) => MucDiscussionAdmission::Stored(id),
                    db::MucDiscussionAdmission::Replay(id) => MucDiscussionAdmission::Replay(id),
                    db::MucDiscussionAdmission::Unauthorized => {
                        MucDiscussionAdmission::Unauthorized
                    }
                    db::MucDiscussionAdmission::Stale => MucDiscussionAdmission::Stale,
                },
            )
        })
    }
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

impl From<&MucAffiliationTarget> for db::MucAffiliationTarget {
    fn from(target: &MucAffiliationTarget) -> Self {
        match target {
            MucAffiliationTarget::LocalUsername(username) => Self::LocalUsername(username.clone()),
            MucAffiliationTarget::FederatedBareJid(jid) => Self::FederatedBareJid(jid.clone()),
        }
    }
}

impl From<&MucAffiliationChange> for db::MucAffiliationChange {
    fn from(change: &MucAffiliationChange) -> Self {
        Self {
            target: (&change.target).into(),
            affiliation: change.affiliation.clone(),
        }
    }
}

impl From<db::MucSubjectOutcome> for MucSubjectOutcome {
    fn from(outcome: db::MucSubjectOutcome) -> Self {
        match outcome {
            db::MucSubjectOutcome::Applied => Self::Applied,
            db::MucSubjectOutcome::Unauthorized => Self::Unauthorized,
            db::MucSubjectOutcome::Stale => Self::Stale,
        }
    }
}

fn subject_mutation_into_db<'a>(m: MucSubjectMutation<'a>) -> db::MucSubjectMutation<'a> {
    db::MucSubjectMutation {
        stanza_id: m.stanza_id,
        room_id: m.room_id,
        actor_scope: m.actor_scope,
        sender_jid: m.sender_jid,
        nick: m.nick,
        subject: m.subject,
        stanza: m.stanza,
        encrypted: m.encrypted,
    }
}

impl From<MucRetractionKind> for db::MucRetractionKind {
    fn from(kind: MucRetractionKind) -> Self {
        match kind {
            MucRetractionKind::Author => Self::Author,
            MucRetractionKind::Moderator => Self::Moderator,
        }
    }
}

fn retraction_mutation_as_db<'a>(
    m: &'a MucRetractionMutation<'a>,
) -> db::MucRetractionMutation<'a> {
    db::MucRetractionMutation {
        action_id: m.action_id,
        room_id: m.room_id,
        target_id: m.target_id,
        expected_stanza: m.expected_stanza,
        actor_scope: m.actor_scope,
        sender_jid: m.sender_jid,
        nick: m.nick,
        tombstone: m.tombstone,
        action_stanza: m.action_stanza,
        reason: m.reason,
        kind: m.kind.into(),
        authority: actor_authority_to_db(&m.authority),
    }
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

fn config_update_into_db<'a>(c: MucConfigUpdate<'a>) -> db::MucConfigUpdate<'a> {
    db::MucConfigUpdate {
        title: c.title,
        description: c.description,
        persistent: c.persistent,
        members_only: c.members_only,
        public: c.public,
        moderated: c.moderated,
        non_anonymous: c.non_anonymous,
        max_occupants: c.max_occupants,
        password_hash: c.password_hash,
        allow_subject_change: c.allow_subject_change,
        allow_invites: c.allow_invites,
        allow_private_messages: c.allow_private_messages,
        logging_enabled: c.logging_enabled,
        allow_registration: c.allow_registration,
    }
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

fn cluster_join_into_db<'a>(j: ClusterMucJoin<'a>) -> db::ClusterMucJoin<'a> {
    db::ClusterMucJoin {
        operation_id: j.operation_id,
        room_id: j.room_id,
        expected_room_epoch: j.expected_room_epoch,
        expected_config_version: j.expected_config_version,
        principal: (&j.principal).into(),
        full_jid: j.full_jid,
        nick: j.nick,
        owner_node_id: j.owner_node_id,
        connection_uuid: j.connection_uuid,
        connection_epoch: j.connection_epoch,
        sm_session_id: j.sm_session_id,
        occupant_incarnation: j.occupant_incarnation,
        presence_payload: j.presence_payload,
        lease: j.lease,
    }
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
        let configured_domain: Arc<str> = Arc::from(configured_domain.as_ref());
        let local_join_gates: Arc<[Arc<tokio::sync::Mutex<()>>]> = (0..LOCAL_JOIN_GATE_SHARDS)
            .map(|_| Arc::new(tokio::sync::Mutex::new(())))
            .collect::<Vec<_>>()
            .into();
        Self {
            discussion_application: RoomApplication::new(
                PostgresMucDiscussionRepository { pool: pool.clone() },
                configured_domain.to_string(),
            ),
            pool,
            configured_domain,
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

    pub(crate) async fn execute_muc_discussion(
        &self,
        command: &MucDiscussion,
    ) -> Result<MucDiscussionAdmission> {
        self.admit_local_discussion(command.clone()).await
    }

    pub(crate) async fn execute_muc_subject(
        &self,
        command: MucSubjectCommand<'_>,
    ) -> Result<MucSubjectResult> {
        if let Err(_err) = validate_muc_subject_command(&command) {
            return Ok(MucSubjectResult {
                outcome: MucSubjectOutcome::Unauthorized,
            });
        }
        let outcome = self
            .set_local_subject(command.mutation, command.archive, command.authority)
            .await?;
        Ok(MucSubjectResult { outcome })
    }

    pub(crate) async fn execute_muc_retraction(
        &self,
        command: MucRetractionCommand<'_>,
    ) -> Result<MucRetractionResult> {
        if let Err(_err) = validate_muc_retraction_command(&command) {
            return Ok(MucRetractionResult {
                outcome: MucRetractionOutcome::Unauthorized,
            });
        }
        let outcome = self
            .retract_local_message_and_archive_action(command.mutation)
            .await?;
        Ok(MucRetractionResult { outcome })
    }

    pub(crate) async fn execute_muc_affiliation_batch(
        &self,
        command: MucAffiliationBatchCommand<'_>,
    ) -> Result<MucAffiliationBatchResult> {
        if let Err(_err) = validate_muc_affiliation_batch_command(&command) {
            return Ok(MucAffiliationBatchResult {
                outcome: MucAffiliationBatchOutcome::DuplicateTarget,
            });
        }
        let outcome = self
            .set_local_legacy_affiliations_batch(command.write.room_id, command.write.changes)
            .await?;
        Ok(MucAffiliationBatchResult { outcome })
    }

    pub(crate) async fn execute_muc_configuration(
        &self,
        command: MucConfigurationCommand<'_>,
    ) -> Result<MucConfigurationResult> {
        if let Err(_err) = validate_muc_configuration_command(&command) {
            return Ok(MucConfigurationResult {
                outcome: MucConfigurationOutcome::Missing,
            });
        }
        let outcome = self
            .update_local_legacy_config(
                command.write.room_id,
                command.write.actor_full_jid,
                command.write.config,
            )
            .await?;
        Ok(MucConfigurationResult { outcome })
    }

    pub(crate) async fn execute_muc_registration(
        &self,
        command: MucRegistrationCommand<'_>,
    ) -> Result<MucRegistrationResult> {
        if let Err(_err) = validate_muc_registration_command(&command) {
            return Ok(MucRegistrationResult {
                outcome: MucRegistrationOutcome::Conflict,
            });
        }
        let outcome = match command.write.target {
            MucRegistrationTarget::Local { user_id } => {
                self.register_local_member(command.write.room_id, user_id, command.write.nick)
                    .await?
            }
            MucRegistrationTarget::Federated { bare_jid } => {
                self.register_federated_member(command.write.room_id, bare_jid, command.write.nick)
                    .await?
            }
        };
        Ok(MucRegistrationResult { outcome })
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
            policy,
            cluster_authority.as_ref(),
        )
        .await
    }

    pub(crate) async fn admit_local_discussion(
        &self,
        message: MucDiscussion,
    ) -> Result<MucDiscussionAdmission> {
        self.discussion_application.admit_discussion(&message).await
    }

    pub(crate) async fn set_local_subject(
        &self,
        mutation: MucSubjectMutation<'_>,
        archive: bool,
        authority: MucActorAuthority,
    ) -> Result<MucSubjectOutcome> {
        if !authority.matches_authenticated_scope(&self.configured_domain) {
            return Ok(MucSubjectOutcome::Unauthorized);
        }
        let authority = actor_authority_to_db(&authority);
        Ok(db::set_local_muc_subject(
            &self.pool,
            subject_mutation_into_db(mutation),
            archive,
            authority,
        )
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
            subject_mutation_into_db(mutation),
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
            .matches_authenticated_scope(&self.configured_domain)
        {
            return Ok(MucRetractionOutcome::Unauthorized);
        }
        Ok(db::retract_muc_message_and_archive_action(
            &self.pool,
            retraction_mutation_as_db(&mutation),
        )
        .await?
        .into())
    }

    pub(crate) async fn update_local_legacy_config(
        &self,
        room_id: Uuid,
        actor_full_jid: &str,
        config: MucConfigUpdate<'_>,
    ) -> Result<MucConfigurationOutcome> {
        Ok(db::update_muc_config(
            &self.pool,
            room_id,
            actor_full_jid,
            config_update_into_db(config),
        )
        .await?
        .into())
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
            db::claim_cluster_muc_occupancy(&self.pool, cluster_join_into_db(request))
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
            config_update_into_db(config),
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
        .map(occupancy_target_from_db))
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
            .map(occupancy_target_from_db),
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
                actor_scope: "alice@evil.test".to_owned(),
                origin_id: None,
                sender_jid: "alice@evil.test/Phone".to_owned(),
                nick: "Alice".to_owned(),
                stanza: "<message/>".to_owned(),
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
                        local_domain: "evil.test".to_owned(),
                    },
                    actor_scope: "alice@evil.test".to_owned(),
                    full_jid: "alice@evil.test/Phone".to_owned(),
                    nick: "Alice".to_owned(),
                    occupant_incarnation: Uuid::nil(),
                    connection_uuid: Uuid::nil(),
                    expected_role: "participant".to_owned(),
                    expected_affiliation: "none".to_owned(),
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
        assert_eq!(occupancy_target_from_db(repository), target);
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
        let repository: db::S2sOutboxPolicy = policy;
        assert_eq!(repository.ttl_seconds, 3600);
        assert_eq!(repository.max_rows, 100);
        assert_eq!(repository.max_bytes, 1_048_576);
        assert_eq!(repository.max_per_domain, 10);
    }
}
