//! Conversions between database records and room application values.

use super::*;

impl From<crate::muc::MucRoom> for MucRoom {
    fn from(room: crate::muc::MucRoom) -> Self {
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

impl From<crate::muc::MucMessage> for MucMessage {
    fn from(message: crate::muc::MucMessage) -> Self {
        Self {
            sender_jid: message.sender_jid,
            stanza: message.stanza,
            created_at: message.created_at,
        }
    }
}

impl From<crate::muc::MucDiscoPage> for MucDiscoPage {
    fn from(page: crate::muc::MucDiscoPage) -> Self {
        Self {
            rooms: page.rooms.into_iter().map(Into::into).collect(),
            total: page.total,
            first_index: page.first_index,
        }
    }
}

impl From<&ClusterMucPrincipal> for crate::cluster_muc::ClusterMucPrincipal {
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

impl From<&ClusterMucAffiliationSubject> for crate::cluster_muc::ClusterMucAffiliationSubject {
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

pub fn actor_principal_to_db(principal: &MucActorPrincipal) -> crate::muc::MucActorPrincipal<'_> {
    match principal {
        MucActorPrincipal::Local {
            user_id,
            local_domain,
        } => crate::muc::MucActorPrincipal::Local {
            user_id: *user_id,
            local_domain,
        },
        MucActorPrincipal::Federated {
            bare_jid,
            authenticated_domain,
        } => crate::muc::MucActorPrincipal::Federated {
            bare_jid,
            authenticated_domain,
        },
    }
}

pub fn actor_authority_to_db(authority: &MucActorAuthority) -> crate::muc::MucActorAuthority<'_> {
    crate::muc::MucActorAuthority {
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

impl From<&ClusterMucInviteAuthority> for crate::cluster_muc::ClusterMucInviteAuthority {
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

impl From<crate::muc::MucRegistrationOutcome> for MucRegistrationOutcome {
    fn from(outcome: crate::muc::MucRegistrationOutcome) -> Self {
        match outcome {
            crate::muc::MucRegistrationOutcome::Registered {
                affiliation_changed,
            } => Self::Registered {
                affiliation_changed,
            },
            crate::muc::MucRegistrationOutcome::Conflict => Self::Conflict,
            crate::muc::MucRegistrationOutcome::Outcast => Self::Outcast,
        }
    }
}

impl From<crate::cluster_muc::ClusterMucRegistrationOutcome> for ClusterMucRegistrationOutcome {
    fn from(outcome: crate::cluster_muc::ClusterMucRegistrationOutcome) -> Self {
        match outcome {
            crate::cluster_muc::ClusterMucRegistrationOutcome::Applied {
                affiliation_changed,
            } => Self::Applied {
                affiliation_changed,
            },
            crate::cluster_muc::ClusterMucRegistrationOutcome::Replay {
                affiliation_changed,
            } => Self::Replay {
                affiliation_changed,
            },
            crate::cluster_muc::ClusterMucRegistrationOutcome::Conflict => Self::Conflict,
            crate::cluster_muc::ClusterMucRegistrationOutcome::Outcast => Self::Outcast,
            crate::cluster_muc::ClusterMucRegistrationOutcome::NotAllowed => Self::NotAllowed,
            crate::cluster_muc::ClusterMucRegistrationOutcome::Stale => Self::Stale,
            crate::cluster_muc::ClusterMucRegistrationOutcome::Destroyed => Self::Destroyed,
        }
    }
}

impl From<crate::muc::DurableMucInviteOutcome> for DurableMucInviteOutcome {
    fn from(outcome: crate::muc::DurableMucInviteOutcome) -> Self {
        match outcome {
            crate::muc::DurableMucInviteOutcome::Stored {
                id,
                affiliation_changed,
                live_claim_id,
            } => Self::Stored {
                id,
                affiliation_changed,
                live_claim_id,
            },
            crate::muc::DurableMucInviteOutcome::Replay { id } => Self::Replay { id },
            crate::muc::DurableMucInviteOutcome::QuotaExceeded => Self::QuotaExceeded,
            crate::muc::DurableMucInviteOutcome::RecipientUnavailable => Self::RecipientUnavailable,
            crate::muc::DurableMucInviteOutcome::Outcast => Self::Outcast,
            crate::muc::DurableMucInviteOutcome::AuthorityRejected => Self::AuthorityRejected,
            crate::muc::DurableMucInviteOutcome::Stale => Self::Stale,
        }
    }
}

impl From<crate::cluster_muc::ClusterMucTransitionOutcome> for ClusterMucTransitionOutcome {
    fn from(outcome: crate::cluster_muc::ClusterMucTransitionOutcome) -> Self {
        match outcome {
            crate::cluster_muc::ClusterMucTransitionOutcome::Applied => Self::Applied,
            crate::cluster_muc::ClusterMucTransitionOutcome::Replay => Self::Replay,
            crate::cluster_muc::ClusterMucTransitionOutcome::Stale => Self::Stale,
            crate::cluster_muc::ClusterMucTransitionOutcome::Destroyed => Self::Destroyed,
            crate::cluster_muc::ClusterMucTransitionOutcome::Conflict => Self::Conflict,
            crate::cluster_muc::ClusterMucTransitionOutcome::Unauthorized => Self::Unauthorized,
        }
    }
}

impl From<crate::muc::MucConfigurationOutcome> for MucConfigurationOutcome {
    fn from(outcome: crate::muc::MucConfigurationOutcome) -> Self {
        match outcome {
            crate::muc::MucConfigurationOutcome::Applied => Self::Applied,
            crate::muc::MucConfigurationOutcome::LockedByAnother => Self::LockedByAnother,
            crate::muc::MucConfigurationOutcome::Expired => Self::Expired,
            crate::muc::MucConfigurationOutcome::Missing => Self::Missing,
        }
    }
}

impl From<crate::cluster_muc::ClusterMucConfigurationOutcome> for ClusterMucConfigurationOutcome {
    fn from(outcome: crate::cluster_muc::ClusterMucConfigurationOutcome) -> Self {
        match outcome {
            crate::cluster_muc::ClusterMucConfigurationOutcome::Applied => Self::Applied,
            crate::cluster_muc::ClusterMucConfigurationOutcome::Replay => Self::Replay,
            crate::cluster_muc::ClusterMucConfigurationOutcome::LockedByAnother => {
                Self::LockedByAnother
            }
            crate::cluster_muc::ClusterMucConfigurationOutcome::Expired => Self::Expired,
            crate::cluster_muc::ClusterMucConfigurationOutcome::Missing => Self::Missing,
            crate::cluster_muc::ClusterMucConfigurationOutcome::Stale => Self::Stale,
            crate::cluster_muc::ClusterMucConfigurationOutcome::Unauthorized => Self::Unauthorized,
            crate::cluster_muc::ClusterMucConfigurationOutcome::Destroyed => Self::Destroyed,
        }
    }
}

impl From<crate::muc::MucAffiliationBatchOutcome> for MucAffiliationBatchOutcome {
    fn from(outcome: crate::muc::MucAffiliationBatchOutcome) -> Self {
        match outcome {
            crate::muc::MucAffiliationBatchOutcome::Applied => Self::Applied,
            crate::muc::MucAffiliationBatchOutcome::DuplicateTarget => Self::DuplicateTarget,
            crate::muc::MucAffiliationBatchOutcome::LastOwner => Self::LastOwner,
            crate::muc::MucAffiliationBatchOutcome::MissingTarget => Self::MissingTarget,
            crate::muc::MucAffiliationBatchOutcome::Unauthorized => Self::Unauthorized,
            crate::muc::MucAffiliationBatchOutcome::Stale => Self::Stale,
            crate::muc::MucAffiliationBatchOutcome::Destroyed => Self::Destroyed,
        }
    }
}

impl From<&MucAffiliationTarget> for crate::muc::MucAffiliationTarget {
    fn from(target: &MucAffiliationTarget) -> Self {
        match target {
            MucAffiliationTarget::LocalUsername(username) => Self::LocalUsername(username.clone()),
            MucAffiliationTarget::FederatedBareJid(jid) => Self::FederatedBareJid(jid.clone()),
        }
    }
}

impl From<&MucAffiliationChange> for crate::muc::MucAffiliationChange {
    fn from(change: &MucAffiliationChange) -> Self {
        Self {
            target: (&change.target).into(),
            affiliation: change.affiliation.clone(),
        }
    }
}

impl From<&MucAdminBatchChange> for crate::cluster_muc::ClusterMucAdminChange {
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

impl From<crate::cluster_muc::ClusterMucAdminBatchOutcome> for MucAdminBatchOutcome {
    fn from(outcome: crate::cluster_muc::ClusterMucAdminBatchOutcome) -> Self {
        match outcome {
            crate::cluster_muc::ClusterMucAdminBatchOutcome::Applied => Self::Applied,
            crate::cluster_muc::ClusterMucAdminBatchOutcome::Replay => Self::Replay,
            crate::cluster_muc::ClusterMucAdminBatchOutcome::DuplicateTarget => {
                Self::DuplicateTarget
            }
            crate::cluster_muc::ClusterMucAdminBatchOutcome::LastOwner => Self::LastOwner,
            crate::cluster_muc::ClusterMucAdminBatchOutcome::MissingTarget => Self::MissingTarget,
            crate::cluster_muc::ClusterMucAdminBatchOutcome::Unauthorized => Self::Unauthorized,
            crate::cluster_muc::ClusterMucAdminBatchOutcome::Stale => Self::Stale,
            crate::cluster_muc::ClusterMucAdminBatchOutcome::Destroyed => Self::Destroyed,
            crate::cluster_muc::ClusterMucAdminBatchOutcome::Conflict => Self::Conflict,
            crate::cluster_muc::ClusterMucAdminBatchOutcome::TooManyProjections => {
                Self::TooManyProjections
            }
        }
    }
}

impl From<crate::muc::MucSubjectOutcome> for MucSubjectOutcome {
    fn from(outcome: crate::muc::MucSubjectOutcome) -> Self {
        match outcome {
            crate::muc::MucSubjectOutcome::Applied => Self::Applied,
            crate::muc::MucSubjectOutcome::Unauthorized => Self::Unauthorized,
            crate::muc::MucSubjectOutcome::Stale => Self::Stale,
        }
    }
}

pub fn subject_mutation_into_db<'a>(
    m: MucSubjectMutation<'a>,
) -> crate::muc::MucSubjectMutation<'a> {
    crate::muc::MucSubjectMutation {
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

impl From<MucRetractionKind> for crate::muc::MucRetractionKind {
    fn from(kind: MucRetractionKind) -> Self {
        match kind {
            MucRetractionKind::Author => Self::Author,
            MucRetractionKind::Moderator => Self::Moderator,
        }
    }
}

pub fn retraction_mutation_as_db<'a>(
    m: &'a MucRetractionMutation<'a>,
) -> crate::muc::MucRetractionMutation<'a> {
    crate::muc::MucRetractionMutation {
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

impl From<crate::muc::MucRetractionOutcome> for MucRetractionOutcome {
    fn from(outcome: crate::muc::MucRetractionOutcome) -> Self {
        match outcome {
            crate::muc::MucRetractionOutcome::Applied => Self::Applied,
            crate::muc::MucRetractionOutcome::Conflict => Self::Conflict,
            crate::muc::MucRetractionOutcome::Unauthorized => Self::Unauthorized,
            crate::muc::MucRetractionOutcome::Stale => Self::Stale,
        }
    }
}

impl From<crate::muc::MucAdminRoleList> for MucAdminRoleList {
    fn from(list: crate::muc::MucAdminRoleList) -> Self {
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

pub fn map_admin_snapshot<T, U>(
    snapshot: crate::muc::MucAdminSnapshot<T>,
    map: impl FnOnce(T) -> U,
) -> MucAdminSnapshot<U> {
    match snapshot {
        crate::muc::MucAdminSnapshot::Authorized(value) => MucAdminSnapshot::Authorized(map(value)),
        crate::muc::MucAdminSnapshot::Unauthorized => MucAdminSnapshot::Unauthorized,
        crate::muc::MucAdminSnapshot::Stale => MucAdminSnapshot::Stale,
    }
}

pub fn config_update_into_db<'a>(c: MucConfigUpdate<'a>) -> crate::muc::MucConfigUpdate<'a> {
    crate::muc::MucConfigUpdate {
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

impl From<crate::cluster_muc::ClusterMucOccupancy> for ClusterMucOccupancy {
    fn from(occupancy: crate::cluster_muc::ClusterMucOccupancy) -> Self {
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

pub fn cluster_join_into_db<'a>(j: ClusterMucJoin<'a>) -> crate::cluster_muc::ClusterMucJoin<'a> {
    crate::cluster_muc::ClusterMucJoin {
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

impl From<crate::cluster_muc::ClusterMucJoinOutcome> for ClusterMucJoinOutcome {
    fn from(outcome: crate::cluster_muc::ClusterMucJoinOutcome) -> Self {
        match outcome {
            crate::cluster_muc::ClusterMucJoinOutcome::Joined(occupancy) => {
                Self::Joined(occupancy.into())
            }
            crate::cluster_muc::ClusterMucJoinOutcome::Replay(occupancy) => {
                Self::Replay(occupancy.into())
            }
            crate::cluster_muc::ClusterMucJoinOutcome::RoomMissing => Self::RoomMissing,
            crate::cluster_muc::ClusterMucJoinOutcome::RoomDestroyed => Self::RoomDestroyed,
            crate::cluster_muc::ClusterMucJoinOutcome::RoomLocked => Self::RoomLocked,
            crate::cluster_muc::ClusterMucJoinOutcome::StaleRoom => Self::StaleRoom,
            crate::cluster_muc::ClusterMucJoinOutcome::Outcast => Self::Outcast,
            crate::cluster_muc::ClusterMucJoinOutcome::MembershipRequired => {
                Self::MembershipRequired
            }
            crate::cluster_muc::ClusterMucJoinOutcome::ReservedNickname => Self::ReservedNickname,
            crate::cluster_muc::ClusterMucJoinOutcome::NicknameConflict => Self::NicknameConflict,
            crate::cluster_muc::ClusterMucJoinOutcome::FullJidConflict => Self::FullJidConflict,
            crate::cluster_muc::ClusterMucJoinOutcome::Full => Self::Full,
        }
    }
}
