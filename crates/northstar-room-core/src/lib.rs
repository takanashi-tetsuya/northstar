//! Capability-free room command and authority values shared by local MUC and
//! federated room adapters.

#![forbid(unsafe_code)]

use northstar_xmpp_types::{prepare_domainpart, CanonicalJid};
use uuid::Uuid;

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct ClusterMucOccupancyTarget {
    pub room_id: Uuid,
    pub room_epoch: Uuid,
    pub occupant_incarnation: Uuid,
    pub occupancy_epoch: i64,
    pub full_jid: String,
    pub nick: String,
    pub connection_uuid: Uuid,
    pub connection_epoch: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub enum MucActorPrincipal {
    Local {
        user_id: Uuid,
        local_domain: String,
    },
    Federated {
        bare_jid: String,
        authenticated_domain: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct MucActorAuthority {
    pub clustered: bool,
    pub expected_room_epoch: Uuid,
    pub principal: MucActorPrincipal,
    pub actor_scope: String,
    pub full_jid: String,
    pub nick: String,
    pub occupant_incarnation: Uuid,
    pub connection_uuid: Uuid,
    pub expected_role: String,
    pub expected_affiliation: String,
    pub cluster_target: Option<ClusterMucOccupancyTarget>,
}

impl MucActorAuthority {
    /// Validate transport-proven identity before the repository acquires a
    /// connection. PostgreSQL repeats authorization under its room locks;
    /// this boundary prevents a malformed adapter command from reaching it.
    pub fn matches_authenticated_scope(&self, configured_domain: &str) -> bool {
        let Ok(actor) = CanonicalJid::parse(&self.actor_scope) else {
            return false;
        };
        if actor.resourcepart().is_some() || actor.to_string() != self.actor_scope {
            return false;
        }
        let Ok(full) = CanonicalJid::parse(&self.full_jid) else {
            return false;
        };
        if full.resourcepart().is_none()
            || full.to_string() != self.full_jid
            || full.bare() != self.actor_scope
        {
            return false;
        }
        match &self.principal {
            MucActorPrincipal::Local { local_domain, .. } => {
                let (Ok(local_domain), Ok(configured_domain)) = (
                    prepare_domainpart(local_domain),
                    prepare_domainpart(configured_domain),
                ) else {
                    return false;
                };
                local_domain == configured_domain && actor.domainpart() == local_domain
            }
            MucActorPrincipal::Federated {
                bare_jid,
                authenticated_domain,
            } => {
                let Ok(principal) = CanonicalJid::parse(bare_jid) else {
                    return false;
                };
                let Ok(authenticated_domain) = prepare_domainpart(authenticated_domain) else {
                    return false;
                };
                principal.resourcepart().is_none()
                    && principal.to_string() == *bare_jid
                    && principal.bare() == self.actor_scope
                    && principal.domainpart() == authenticated_domain
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MucDiscussion {
    pub id: Uuid,
    pub room_id: Uuid,
    pub actor_scope: String,
    pub origin_id: Option<String>,
    pub sender_jid: String,
    pub nick: String,
    pub stanza: String,
    pub encrypted: bool,
    pub archive: bool,
    pub retention_days: i64,
    pub authority: MucActorAuthority,
}

impl MucDiscussion {
    pub fn authority_is_consistent(&self, configured_domain: &str) -> bool {
        self.actor_scope == self.authority.actor_scope
            && self.sender_jid == self.authority.full_jid
            && self.nick == self.authority.nick
            && self
                .authority
                .matches_authenticated_scope(configured_domain)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MucDiscussionAdmission {
    Stored(Uuid),
    Replay(Uuid),
    Unauthorized,
    Stale,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MucLocalAccount {
    pub id: Uuid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MucRoom {
    pub id: Uuid,
    pub room_epoch: Uuid,
    pub config_version: i64,
    pub localpart: String,
    pub title: Option<String>,
    pub description: Option<String>,
    pub persistent: bool,
    pub members_only: bool,
    pub public: bool,
    pub moderated: bool,
    pub non_anonymous: bool,
    pub max_occupants: i32,
    pub subject: Option<String>,
    pub subject_changed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub allow_subject_change: bool,
    pub allow_invites: bool,
    pub allow_private_messages: bool,
    pub logging_enabled: bool,
    pub allow_registration: bool,
    pub password_hash: Option<String>,
    pub occupant_id_secret: Vec<u8>,
    pub configuration_owner_jid: Option<String>,
    pub configuration_expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl MucRoom {
    pub fn is_locked(&self) -> bool {
        self.configuration_owner_jid.is_some()
    }

    pub fn configuration_is_expired(&self, now: chrono::DateTime<chrono::Utc>) -> bool {
        self.configuration_expires_at
            .is_some_and(|expires_at| expires_at <= now)
    }

    pub fn can_configure_locked_room(
        &self,
        actor_full_jid: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        self.configuration_owner_jid.as_deref() == Some(actor_full_jid)
            && !self.configuration_is_expired(now)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MucMessage {
    pub sender_jid: String,
    pub stanza: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MucDiscoPage {
    pub rooms: Vec<MucRoom>,
    pub total: i64,
    pub first_index: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OfflineStoreOutcome {
    Stored,
    Replay,
    QuotaExceeded,
    RecipientUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OfflineStorePolicy {
    pub max_messages: i64,
    pub max_bytes: i64,
    pub ttl_days: i64,
    pub mam_backed: bool,
}

pub use northstar_federation_core::S2sOutboxPolicy as FederatedInvitePolicy;

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ClusterMucPrincipal {
    Local {
        user_id: Uuid,
        bare_jid: String,
    },
    Federated {
        bare_jid: String,
        authenticated_domain: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ClusterMucAffiliationSubject {
    Local { user_id: Uuid, bare_jid: String },
    Federated { bare_jid: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClusterMucInviteAuthority {
    pub operation_id: Uuid,
    pub expected_room_epoch: Uuid,
    pub expected_config_version: i64,
    pub actor: ClusterMucPrincipal,
    pub actor_full_jid: String,
    pub actor_target: Option<ClusterMucOccupancyTarget>,
    pub subject: ClusterMucAffiliationSubject,
    pub reason: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MucRegistrationOutcome {
    Registered { affiliation_changed: bool },
    Conflict,
    Outcast,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClusterMucRegistrationOutcome {
    Applied { affiliation_changed: bool },
    Replay { affiliation_changed: bool },
    Conflict,
    Outcast,
    NotAllowed,
    Stale,
    Destroyed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableMucInviteOutcome {
    Stored { id: Uuid, affiliation_changed: bool },
    Replay { id: Uuid },
    QuotaExceeded,
    RecipientUnavailable,
    Outcast,
    AuthorityRejected,
    Stale,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClusterMucTransitionOutcome {
    Applied,
    Replay,
    Stale,
    Destroyed,
    Conflict,
    Unauthorized,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MucConfigurationOutcome {
    Applied,
    LockedByAnother,
    Expired,
    Missing,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClusterMucConfigurationOutcome {
    Applied,
    Replay,
    LockedByAnother,
    Expired,
    Missing,
    Stale,
    Unauthorized,
    Destroyed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MucAffiliationBatchOutcome {
    Applied,
    DuplicateTarget,
    LastOwner,
    MissingTarget,
    Unauthorized,
    Stale,
    Destroyed,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum MucAffiliationTarget {
    LocalUsername(String),
    FederatedBareJid(String),
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct MucAffiliationChange {
    pub target: MucAffiliationTarget,
    pub affiliation: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MucSubjectOutcome {
    Applied,
    Unauthorized,
    Stale,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MucSubjectMutation<'a> {
    pub stanza_id: Uuid,
    pub room_id: Uuid,
    pub actor_scope: &'a str,
    pub sender_jid: &'a str,
    pub nick: &'a str,
    pub subject: &'a str,
    pub stanza: &'a str,
    pub encrypted: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MucRetractionKind {
    Author,
    Moderator,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MucRetractionMutation<'a> {
    pub action_id: Uuid,
    pub room_id: Uuid,
    pub target_id: Uuid,
    pub expected_stanza: &'a str,
    pub actor_scope: &'a str,
    pub sender_jid: &'a str,
    pub nick: &'a str,
    pub tombstone: &'a str,
    pub action_stanza: &'a str,
    pub reason: Option<&'a str>,
    pub kind: MucRetractionKind,
    pub authority: MucActorAuthority,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MucRetractionOutcome {
    Applied,
    Conflict,
    Unauthorized,
    Stale,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MucAdminRoleEntry {
    pub nick: String,
    pub role: String,
    pub bare_jid: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MucAdminRoleList {
    pub requester_role: String,
    pub non_anonymous: bool,
    pub entries: Vec<MucAdminRoleEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MucAdminAffiliationEntry {
    pub bare_jid: String,
    pub affiliation: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MucAdminSnapshot<T> {
    Authorized(T),
    Unauthorized,
    Stale,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MucConfigUpdate<'a> {
    pub title: Option<&'a str>,
    pub description: Option<&'a str>,
    pub persistent: bool,
    pub members_only: bool,
    pub public: bool,
    pub moderated: bool,
    pub non_anonymous: bool,
    pub max_occupants: i32,
    pub password_hash: Option<&'a str>,
    pub allow_subject_change: bool,
    pub allow_invites: bool,
    pub allow_private_messages: bool,
    pub logging_enabled: bool,
    pub allow_registration: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClusterMucOccupancy {
    pub room_id: Uuid,
    pub room_epoch: Uuid,
    pub occupant_incarnation: Uuid,
    pub occupancy_epoch: i64,
    pub config_version: i64,
    pub identity_kind: String,
    pub local_user_id: Option<Uuid>,
    pub bare_jid: String,
    pub full_jid: String,
    pub nick: String,
    pub authenticated_domain: Option<String>,
    pub owner_node_id: String,
    pub connection_uuid: Uuid,
    pub connection_epoch: i64,
    pub sm_session_id: Option<Uuid>,
    pub role: String,
    pub affiliation: String,
    pub state: String,
    pub presence_payload: String,
    pub lease_until: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClusterMucJoin<'a> {
    pub operation_id: Uuid,
    pub room_id: Uuid,
    pub expected_room_epoch: Uuid,
    pub expected_config_version: i64,
    pub principal: ClusterMucPrincipal,
    pub full_jid: &'a str,
    pub nick: &'a str,
    pub owner_node_id: &'a str,
    pub connection_uuid: Uuid,
    pub connection_epoch: i64,
    pub sm_session_id: Option<Uuid>,
    pub occupant_incarnation: Uuid,
    pub presence_payload: &'a str,
    pub lease: std::time::Duration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClusterMucJoinOutcome {
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MucAffiliationBatchWrite<'a> {
    pub room_id: Uuid,
    pub changes: &'a [MucAffiliationChange],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MucConfigurationWrite<'a> {
    pub room_id: Uuid,
    pub actor_full_jid: &'a str,
    pub config: MucConfigUpdate<'a>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MucRegistrationTarget<'a> {
    Local { user_id: Uuid },
    Federated { bare_jid: &'a str },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MucRegistrationWrite<'a> {
    pub room_id: Uuid,
    pub target: MucRegistrationTarget<'a>,
    pub nick: &'a str,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local_command() -> MucDiscussion {
        MucDiscussion {
            id: Uuid::from_u128(1),
            room_id: Uuid::from_u128(2),
            actor_scope: "alice@local.test".to_owned(),
            origin_id: Some("origin-1".to_owned()),
            sender_jid: "alice@local.test/phone".to_owned(),
            nick: "Alice".to_owned(),
            stanza: "<message/>".to_owned(),
            encrypted: false,
            archive: true,
            retention_days: 30,
            authority: MucActorAuthority {
                clustered: false,
                expected_room_epoch: Uuid::from_u128(3),
                principal: MucActorPrincipal::Local {
                    user_id: Uuid::from_u128(4),
                    local_domain: "local.test".to_owned(),
                },
                actor_scope: "alice@local.test".to_owned(),
                full_jid: "alice@local.test/phone".to_owned(),
                nick: "Alice".to_owned(),
                occupant_incarnation: Uuid::from_u128(5),
                connection_uuid: Uuid::from_u128(6),
                expected_role: "participant".to_owned(),
                expected_affiliation: "member".to_owned(),
                cluster_target: None,
            },
        }
    }

    #[test]
    fn local_authority_requires_the_configured_domain_and_exact_scope() {
        let command = local_command();
        assert!(command.authority_is_consistent("LOCAL.test"));
        assert!(!command.authority_is_consistent("evil.test"));

        let mut forged = command;
        forged.actor_scope = "alice@evil.test".to_owned();
        assert!(!forged.authority_is_consistent("local.test"));
    }

    #[test]
    fn federated_authority_is_bound_to_the_authenticated_domain() {
        let mut command = local_command();
        command.actor_scope = "bob@remote.test".to_owned();
        command.sender_jid = "bob@remote.test/desktop".to_owned();
        command.authority.actor_scope = command.actor_scope.clone();
        command.authority.full_jid = command.sender_jid.clone();
        command.authority.principal = MucActorPrincipal::Federated {
            bare_jid: command.actor_scope.clone(),
            authenticated_domain: "remote.test".to_owned(),
        };
        assert!(command.authority_is_consistent("local.test"));

        let MucActorPrincipal::Federated {
            authenticated_domain,
            ..
        } = &mut command.authority.principal
        else {
            unreachable!();
        };
        *authenticated_domain = "attacker.test".to_owned();
        assert!(!command.authority_is_consistent("local.test"));
    }

    #[test]
    fn command_identity_must_match_the_authority_snapshot() {
        let mut command = local_command();
        command.nick = "Impostor".to_owned();
        assert!(!command.authority_is_consistent("local.test"));
    }
}
