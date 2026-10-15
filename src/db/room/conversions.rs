//! Conversions between database records and room application values.

use super::*;

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

pub(super) fn occupancy_target_from_db(
    target: db::ClusterMucOccupancyTarget,
) -> ClusterMucOccupancyTarget {
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

pub(super) fn actor_principal_to_db(principal: &MucActorPrincipal) -> db::MucActorPrincipal<'_> {
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

pub(super) fn actor_authority_to_db(authority: &MucActorAuthority) -> db::MucActorAuthority<'_> {
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
                live_claim_id,
            } => Self::Stored {
                id,
                affiliation_changed,
                live_claim_id,
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

impl From<&MucAdminBatchChange> for db::ClusterMucAdminChange {
    fn from(change: &MucAdminBatchChange) -> Self {
        match change {
            MucAdminBatchChange::Affiliation {
                target,
                affiliation,
                reason,
            } => Self::Affiliation {
                target: target.into(),
                affiliation: affiliation.clone(),
                reason: reason.clone(),
            },
            MucAdminBatchChange::Role {
                target_nick,
                role,
                reason,
            } => Self::Role {
                target_nick: target_nick.clone(),
                role: role.clone(),
                reason: reason.clone(),
            },
        }
    }
}

impl From<db::ClusterMucAdminBatchOutcome> for MucAdminBatchOutcome {
    fn from(outcome: db::ClusterMucAdminBatchOutcome) -> Self {
        match outcome {
            db::ClusterMucAdminBatchOutcome::Applied => Self::Applied,
            db::ClusterMucAdminBatchOutcome::Replay => Self::Replay,
            db::ClusterMucAdminBatchOutcome::DuplicateTarget => Self::DuplicateTarget,
            db::ClusterMucAdminBatchOutcome::LastOwner => Self::LastOwner,
            db::ClusterMucAdminBatchOutcome::MissingTarget => Self::MissingTarget,
            db::ClusterMucAdminBatchOutcome::Unauthorized => Self::Unauthorized,
            db::ClusterMucAdminBatchOutcome::Stale => Self::Stale,
            db::ClusterMucAdminBatchOutcome::Destroyed => Self::Destroyed,
            db::ClusterMucAdminBatchOutcome::Conflict => Self::Conflict,
            db::ClusterMucAdminBatchOutcome::TooManyProjections => Self::TooManyProjections,
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

pub(super) fn subject_mutation_into_db<'a>(
    m: MucSubjectMutation<'a>,
) -> db::MucSubjectMutation<'a> {
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

pub(super) fn retraction_mutation_as_db<'a>(
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

pub(super) fn map_admin_snapshot<T, U>(
    snapshot: db::MucAdminSnapshot<T>,
    map: impl FnOnce(T) -> U,
) -> MucAdminSnapshot<U> {
    match snapshot {
        db::MucAdminSnapshot::Authorized(value) => MucAdminSnapshot::Authorized(map(value)),
        db::MucAdminSnapshot::Unauthorized => MucAdminSnapshot::Unauthorized,
        db::MucAdminSnapshot::Stale => MucAdminSnapshot::Stale,
    }
}

pub(super) fn config_update_into_db<'a>(c: MucConfigUpdate<'a>) -> db::MucConfigUpdate<'a> {
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

pub(super) fn cluster_join_into_db<'a>(j: ClusterMucJoin<'a>) -> db::ClusterMucJoin<'a> {
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
