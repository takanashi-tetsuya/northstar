//! Room authorization, local ordering and committed-operation notifications.

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
    ClusterMucWakeDescriptor, DurableMucInviteOutcome, FederatedInvitePolicy, MucActorAuthority,
    MucActorPrincipal, MucAdminAffiliationEntry, MucAdminRoleEntry, MucAdminRoleList,
    MucAdminSnapshot, MucAffiliationBatchOutcome, MucAffiliationBatchWrite, MucAffiliationChange,
    MucAffiliationTarget, MucCapacityExceeded, MucConfigUpdate, MucConfigurationOutcome,
    MucConfigurationWrite, MucDiscoPage, MucDiscussion, MucDiscussionAdmission, MucLocalAccount,
    MucMessage, MucRegistrationOutcome, MucRegistrationTarget, MucRegistrationWrite,
    MucRetractionKind, MucRetractionMutation, MucRetractionOutcome, MucRoom, MucSubjectMutation,
    MucSubjectOutcome, OfflineStoreOutcome, OfflineStorePolicy,
};
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};
use uuid::Uuid;

/// One ordered item in an XEP-0045 administrative IQ. Target names have
/// already been canonicalized by the protocol parser; the repository checks
/// them again before taking any lock or applying any change.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub(crate) enum MucAdminBatchChange {
    Affiliation {
        target: MucAffiliationTarget,
        affiliation: String,
        reason: Option<String>,
    },
    Role {
        target_nick: String,
        role: String,
        reason: Option<String>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MucAdminBatchOutcome {
    Applied,
    Replay,
    DuplicateTarget,
    LastOwner,
    MissingTarget,
    Unauthorized,
    Stale,
    Destroyed,
    Conflict,
    TooManyProjections,
}

pub(crate) struct MucAdminBatchResult {
    pub operation_id: Uuid,
    pub outcome: MucAdminBatchOutcome,
}

pub(crate) const MAX_MUC_OCCUPANCY_RENEW_BATCH: usize = 128;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct MucOccupancyLookup {
    pub room_localpart: String,
    pub full_jid: String,
    pub nick: String,
    pub occupant_incarnation: Uuid,
    pub connection_uuid: Uuid,
}

impl MucOccupancyLookup {
    pub(crate) fn new(
        room_jid: &str,
        full_jid: &str,
        nick: &str,
        occupant_incarnation: Uuid,
        connection_uuid: Uuid,
    ) -> Result<Self> {
        let room = crate::jid::CanonicalJid::parse_bare(room_jid)?;
        anyhow::ensure!(room.to_string() == room_jid, "noncanonical MUC room JID");
        let room_localpart = room
            .localpart()
            .ok_or_else(|| anyhow::anyhow!("MUC room JID has no localpart"))?
            .to_owned();
        Ok(Self {
            room_localpart,
            full_jid: full_jid.to_owned(),
            nick: nick.to_owned(),
            occupant_incarnation,
            connection_uuid,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MucResolvedOccupancy {
    pub room_localpart: String,
    pub target: ClusterMucOccupancyTarget,
}

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};

/// Node-local MUC lease maintenance has no room mutation or outbox authority.
/// The snapshot contains only the exact target columns needed to fence renewals.
pub(crate) trait ClusterMucOccupancyMaintenanceRepository: Send + Sync {
    fn authoritative_for_node(
        &self,
        node_id: &str,
    ) -> impl std::future::Future<Output = Result<Vec<ClusterMucOccupancyTarget>>> + Send;

    fn resolve_exact_batch(
        &self,
        candidates: &[MucOccupancyLookup],
        owner_node_id: &str,
    ) -> impl std::future::Future<Output = Result<Vec<MucResolvedOccupancy>>> + Send;

    fn committed_terminal_exact_batch(
        &self,
        candidates: &[MucOccupancyLookup],
        owner_node_id: &str,
    ) -> impl std::future::Future<Output = Result<Vec<MucOccupancyLookup>>> + Send;

    fn renew_exact(
        &self,
        target: &ClusterMucOccupancyTarget,
        owner_node_id: &str,
        lease: Duration,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;

    fn renew_exact_batch(
        &self,
        targets: &[ClusterMucOccupancyTarget],
        owner_node_id: &str,
        lease: Duration,
    ) -> impl std::future::Future<Output = Result<Vec<ClusterMucOccupancyTarget>>> + Send;
}

pub(crate) struct ClusterMucOccupancyMaintenanceService<R> {
    repository: R,
}

impl<R: ClusterMucOccupancyMaintenanceRepository> ClusterMucOccupancyMaintenanceService<R> {
    pub(crate) fn new(repository: R) -> Self {
        Self { repository }
    }

    pub(crate) async fn authoritative_for_node(
        &self,
        node_id: &str,
    ) -> Result<Vec<ClusterMucOccupancyTarget>> {
        self.repository.authoritative_for_node(node_id).await
    }

    pub(crate) async fn resolve_exact_batch(
        &self,
        candidates: &[MucOccupancyLookup],
        owner_node_id: &str,
    ) -> Result<Vec<MucResolvedOccupancy>> {
        anyhow::ensure!(
            candidates.len() <= MAX_MUC_OCCUPANCY_RENEW_BATCH,
            "MUC occupancy lookup batch exceeds its limit"
        );
        let mut requested = std::collections::HashSet::with_capacity(candidates.len());
        anyhow::ensure!(
            candidates.iter().all(|candidate| {
                requested.insert((
                    candidate.room_localpart.as_str(),
                    candidate.occupant_incarnation,
                    candidate.connection_uuid,
                ))
            }),
            "MUC occupancy lookup batch contains a duplicate incarnation"
        );
        let resolved = self
            .repository
            .resolve_exact_batch(candidates, owner_node_id)
            .await?;
        let mut returned = std::collections::HashSet::with_capacity(resolved.len());
        anyhow::ensure!(
            resolved.iter().all(|item| {
                returned.insert((
                    item.room_localpart.as_str(),
                    item.target.occupant_incarnation,
                    item.target.connection_uuid,
                )) && candidates.iter().any(|candidate| {
                    candidate.room_localpart == item.room_localpart
                        && candidate.full_jid == item.target.full_jid
                        && candidate.nick == item.target.nick
                        && candidate.occupant_incarnation == item.target.occupant_incarnation
                        && candidate.connection_uuid == item.target.connection_uuid
                })
            }),
            "MUC occupancy lookup returned an unrequested or duplicate target"
        );
        Ok(resolved)
    }

    pub(crate) async fn renew_exact(
        &self,
        target: &ClusterMucOccupancyTarget,
        owner_node_id: &str,
    ) -> Result<bool> {
        self.repository
            .renew_exact(target, owner_node_id, Duration::from_secs(90))
            .await
    }

    /// A committed revocation ends only the room membership. An absent,
    /// expired or transferred occupancy still fences its C2S connection.
    pub(crate) async fn committed_terminal_exact_batch(
        &self,
        candidates: &[MucOccupancyLookup],
        owner_node_id: &str,
    ) -> Result<Vec<MucOccupancyLookup>> {
        anyhow::ensure!(
            candidates.len() <= MAX_MUC_OCCUPANCY_RENEW_BATCH,
            "MUC terminal lookup batch exceeds its limit"
        );
        let requested = candidates.iter().collect::<std::collections::HashSet<_>>();
        anyhow::ensure!(
            requested.len() == candidates.len(),
            "MUC terminal lookup batch contains a duplicate identity"
        );
        let terminal = self
            .repository
            .committed_terminal_exact_batch(candidates, owner_node_id)
            .await?;
        let returned = terminal.iter().collect::<std::collections::HashSet<_>>();
        anyhow::ensure!(
            returned.len() == terminal.len() && returned.is_subset(&requested),
            "MUC terminal lookup returned an unrequested or duplicate identity"
        );
        Ok(terminal)
    }

    pub(crate) async fn renew_exact_batch(
        &self,
        targets: &[ClusterMucOccupancyTarget],
        owner_node_id: &str,
    ) -> Result<Vec<ClusterMucOccupancyTarget>> {
        anyhow::ensure!(
            targets.len() <= MAX_MUC_OCCUPANCY_RENEW_BATCH,
            "MUC occupancy renewal batch exceeds its limit"
        );
        let mut requested = std::collections::HashSet::with_capacity(targets.len());
        anyhow::ensure!(
            targets
                .iter()
                .all(|target| requested.insert((target.room_id, target.occupant_incarnation))),
            "MUC occupancy renewal batch contains a duplicate incarnation"
        );
        let renewed = self
            .repository
            .renew_exact_batch(targets, owner_node_id, Duration::from_secs(90))
            .await?;
        let mut returned = std::collections::HashSet::with_capacity(renewed.len());
        anyhow::ensure!(
            renewed.iter().all(|target| {
                returned.insert((target.room_id, target.occupant_incarnation))
                    && targets.iter().any(|requested| requested == target)
            }),
            "MUC occupancy renewal returned an unrequested or duplicate target"
        );
        Ok(renewed)
    }
}

/// The disconnect path can only resolve and retire the precise local stream
/// incarnation it just quiesced. Resumable SM suspension uses its own path.
pub(crate) trait ClusterMucOccupancyDepartureRepository: Send + Sync {
    #[allow(clippy::too_many_arguments)]
    fn find_exact_for_disconnect(
        &self,
        room_localpart: &str,
        full_jid: &str,
        nick: &str,
        occupant_incarnation: Uuid,
        connection_uuid: Uuid,
        owner_node_id: &str,
    ) -> impl std::future::Future<Output = Result<Option<ClusterMucOccupancyTarget>>> + Send;

    fn leave_exact(
        &self,
        operation_id: Uuid,
        target: &ClusterMucOccupancyTarget,
        owner_node_id: &str,
        lease: Duration,
    ) -> impl std::future::Future<Output = Result<ClusterMucTransitionOutcome>> + Send;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MucDisconnectLeaveResult {
    pub operation_id: Uuid,
    pub outcome: ClusterMucTransitionOutcome,
}

#[derive(Clone)]
pub(crate) struct ClusterMucOccupancyDepartureService<R> {
    repository: R,
}

impl<R: ClusterMucOccupancyDepartureRepository> ClusterMucOccupancyDepartureService<R> {
    pub(crate) fn new(repository: R) -> Self {
        Self { repository }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn find_exact_for_disconnect(
        &self,
        room_jid: &str,
        full_jid: &str,
        nick: &str,
        occupant_incarnation: Uuid,
        connection_uuid: Uuid,
        owner_node_id: &str,
    ) -> Result<Option<ClusterMucOccupancyTarget>> {
        let room = crate::jid::CanonicalJid::parse_bare(room_jid)?;
        anyhow::ensure!(room.to_string() == room_jid, "noncanonical MUC room JID");
        let localpart = room
            .localpart()
            .ok_or_else(|| anyhow::anyhow!("MUC room JID has no localpart"))?;
        self.repository
            .find_exact_for_disconnect(
                localpart,
                full_jid,
                nick,
                occupant_incarnation,
                connection_uuid,
                owner_node_id,
            )
            .await
    }

    pub(crate) async fn leave_exact_for_disconnect(
        &self,
        connection_uuid: Uuid,
        target: &ClusterMucOccupancyTarget,
        owner_node_id: &str,
    ) -> Result<MucDisconnectLeaveResult> {
        anyhow::ensure!(
            !connection_uuid.is_nil() && target.connection_uuid == connection_uuid,
            "MUC disconnect cannot retire another connection's occupancy"
        );
        let operation_id = operation_id(&serde_json::json!({
            "kind":"muc_disconnect_leave",
            "target":target,
        }))?;
        let outcome = self
            .repository
            .leave_exact(operation_id, target, owner_node_id, Duration::from_secs(90))
            .await?;
        Ok(MucDisconnectLeaveResult {
            operation_id,
            outcome,
        })
    }
}

#[cfg(test)]
mod cluster_muc_occupancy_maintenance_tests {
    use super::*;
    use std::sync::Mutex;

    struct StubRepository {
        target: ClusterMucOccupancyTarget,
        renewal: Mutex<Option<(ClusterMucOccupancyTarget, String, Duration)>>,
    }

    impl ClusterMucOccupancyMaintenanceRepository for &StubRepository {
        async fn authoritative_for_node(
            &self,
            node_id: &str,
        ) -> Result<Vec<ClusterMucOccupancyTarget>> {
            assert_eq!(node_id, "node-1");
            Ok(vec![self.target.clone()])
        }

        async fn resolve_exact_batch(
            &self,
            candidates: &[MucOccupancyLookup],
            owner_node_id: &str,
        ) -> Result<Vec<MucResolvedOccupancy>> {
            assert_eq!(owner_node_id, "node-1");
            Ok(candidates
                .iter()
                .filter(|candidate| {
                    candidate.full_jid == self.target.full_jid
                        && candidate.nick == self.target.nick
                        && candidate.occupant_incarnation == self.target.occupant_incarnation
                        && candidate.connection_uuid == self.target.connection_uuid
                })
                .map(|candidate| MucResolvedOccupancy {
                    room_localpart: candidate.room_localpart.clone(),
                    target: self.target.clone(),
                })
                .collect())
        }

        async fn committed_terminal_exact_batch(
            &self,
            _candidates: &[MucOccupancyLookup],
            owner_node_id: &str,
        ) -> Result<Vec<MucOccupancyLookup>> {
            assert_eq!(owner_node_id, "node-1");
            Ok(Vec::new())
        }

        async fn renew_exact(
            &self,
            target: &ClusterMucOccupancyTarget,
            owner_node_id: &str,
            lease: Duration,
        ) -> Result<bool> {
            *self.renewal.lock().unwrap() = Some((target.clone(), owner_node_id.to_owned(), lease));
            Ok(true)
        }

        async fn renew_exact_batch(
            &self,
            targets: &[ClusterMucOccupancyTarget],
            owner_node_id: &str,
            lease: Duration,
        ) -> Result<Vec<ClusterMucOccupancyTarget>> {
            assert_eq!(targets, std::slice::from_ref(&self.target));
            *self.renewal.lock().unwrap() =
                Some((targets[0].clone(), owner_node_id.to_owned(), lease));
            Ok(targets.to_vec())
        }
    }

    #[tokio::test]
    async fn maintenance_renews_the_snapshot_target_with_the_fixed_lease() {
        let target = ClusterMucOccupancyTarget {
            room_id: Uuid::new_v4(),
            room_epoch: Uuid::new_v4(),
            occupant_incarnation: Uuid::new_v4(),
            occupancy_epoch: 7,
            full_jid: "alice@example.test/Phone".to_owned(),
            nick: "Alice".to_owned(),
            connection_uuid: Uuid::new_v4(),
            connection_epoch: 9,
        };
        let repository = StubRepository {
            target: target.clone(),
            renewal: Mutex::new(None),
        };
        let service = ClusterMucOccupancyMaintenanceService::new(&repository);
        let snapshot = service.authoritative_for_node("node-1").await.unwrap();
        assert_eq!(snapshot, vec![target.clone()]);
        let lookup = MucOccupancyLookup::new(
            "room@muc.example.test",
            &target.full_jid,
            &target.nick,
            target.occupant_incarnation,
            target.connection_uuid,
        )
        .unwrap();
        assert_eq!(
            service
                .resolve_exact_batch(std::slice::from_ref(&lookup), "node-1")
                .await
                .unwrap(),
            vec![MucResolvedOccupancy {
                room_localpart: "room".to_owned(),
                target: target.clone(),
            }]
        );
        assert!(service.renew_exact(&snapshot[0], "node-1").await.unwrap());
        assert_eq!(
            *repository.renewal.lock().unwrap(),
            Some((
                snapshot[0].clone(),
                "node-1".to_owned(),
                Duration::from_secs(90)
            ))
        );
        assert_eq!(
            service
                .renew_exact_batch(std::slice::from_ref(&target), "node-1")
                .await
                .unwrap(),
            vec![target.clone()]
        );
        assert!(service
            .renew_exact_batch(&[target.clone(), target.clone()], "node-1")
            .await
            .is_err());
        assert!(service
            .renew_exact_batch(&vec![target; MAX_MUC_OCCUPANCY_RENEW_BATCH + 1], "node-1")
            .await
            .is_err());
    }
}

#[cfg(test)]
mod cluster_muc_occupancy_departure_tests {
    use super::*;
    use std::sync::Mutex;

    struct StubRepository {
        target: ClusterMucOccupancyTarget,
        leaves: Mutex<Vec<Uuid>>,
    }

    impl ClusterMucOccupancyDepartureRepository for &StubRepository {
        async fn find_exact_for_disconnect(
            &self,
            room_localpart: &str,
            full_jid: &str,
            nick: &str,
            occupant_incarnation: Uuid,
            connection_uuid: Uuid,
            owner_node_id: &str,
        ) -> Result<Option<ClusterMucOccupancyTarget>> {
            assert_eq!(room_localpart, "room");
            assert_eq!(owner_node_id, "node-1");
            Ok((full_jid == self.target.full_jid
                && nick == self.target.nick
                && occupant_incarnation == self.target.occupant_incarnation
                && connection_uuid == self.target.connection_uuid)
                .then(|| self.target.clone()))
        }

        async fn leave_exact(
            &self,
            operation_id: Uuid,
            target: &ClusterMucOccupancyTarget,
            owner_node_id: &str,
            lease: Duration,
        ) -> Result<ClusterMucTransitionOutcome> {
            assert_eq!(target, &self.target);
            assert_eq!(owner_node_id, "node-1");
            assert_eq!(lease, Duration::from_secs(90));
            self.leaves.lock().unwrap().push(operation_id);
            Ok(ClusterMucTransitionOutcome::Applied)
        }
    }

    #[tokio::test]
    async fn disconnect_leave_is_bound_to_one_stream_and_one_stable_operation() {
        let target = ClusterMucOccupancyTarget {
            room_id: Uuid::new_v4(),
            room_epoch: Uuid::new_v4(),
            occupant_incarnation: Uuid::new_v4(),
            occupancy_epoch: 1,
            full_jid: "alice@example.test/Phone".to_owned(),
            nick: "Alice".to_owned(),
            connection_uuid: Uuid::new_v4(),
            connection_epoch: 1,
        };
        let repository = StubRepository {
            target: target.clone(),
            leaves: Mutex::new(Vec::new()),
        };
        let service = ClusterMucOccupancyDepartureService::new(&repository);
        let resolved = service
            .find_exact_for_disconnect(
                "room@muc.example.test",
                &target.full_jid,
                &target.nick,
                target.occupant_incarnation,
                target.connection_uuid,
                "node-1",
            )
            .await
            .unwrap();
        assert_eq!(resolved, Some(target.clone()));
        assert!(service
            .leave_exact_for_disconnect(Uuid::new_v4(), &target, "node-1")
            .await
            .is_err());
        let first = service
            .leave_exact_for_disconnect(target.connection_uuid, &target, "node-1")
            .await
            .unwrap();
        let replay = service
            .leave_exact_for_disconnect(target.connection_uuid, &target, "node-1")
            .await
            .unwrap();
        assert_eq!(first.operation_id, replay.operation_id);
        assert_eq!(
            repository.leaves.lock().unwrap().as_slice(),
            &[first.operation_id; 2]
        );
    }
}

/// Each mutation retains its account/room/occupant fences and its complete
/// outbox projection. The port never exposes a connection or an open transaction.
pub(crate) trait MucRepository:
    MucDiscussionRepository<Error = anyhow::Error> + Clone + Send + Sync
{
    fn local_room_snapshot(
        &self,
        localpart: &str,
    ) -> impl std::future::Future<Output = Result<Option<MucRoom>>> + Send;

    fn local_affiliation(
        &self,
        room_id: Uuid,
        user_id: Uuid,
    ) -> impl std::future::Future<Output = Result<Option<String>>> + Send;
    fn federated_affiliation(
        &self,
        room_id: Uuid,
        bare_jid: &str,
    ) -> impl std::future::Future<Output = Result<Option<String>>> + Send;
    fn enabled_local_account(
        &self,
        username: &str,
    ) -> impl std::future::Future<Output = Result<Option<MucLocalAccount>>> + Send;
    fn is_blocked_for_account(
        &self,
        owner_id: Uuid,
        owner_bare_jid: &str,
        candidate: &str,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn blocked_jids(
        &self,
        user_id: Uuid,
    ) -> impl std::future::Future<Output = Result<Vec<String>>> + Send;
    fn store_local_muc_offline(
        &self,
        configured_domain: &str,
        recipient_id: Uuid,
        sender_jid: &str,
        stanza: &str,
        encrypted: bool,
        policy: OfflineStorePolicy,
    ) -> impl std::future::Future<Output = Result<OfflineStoreOutcome>> + Send;

    fn local_message_by_id(
        &self,
        room_id: Uuid,
        message_id: Uuid,
    ) -> impl std::future::Future<Output = Result<Option<MucMessage>>> + Send;

    fn local_history_since(
        &self,
        room_id: Uuid,
        limit: i64,
        since: Option<DateTime<Utc>>,
    ) -> impl std::future::Future<Output = Result<Vec<MucMessage>>> + Send;

    fn delete_expired_locked_room(
        &self,
        room_id: Uuid,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn delete_temporary_room(
        &self,
        room_id: Uuid,
        room_epoch: Uuid,
        config_version: i64,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn local_reserved_nick(
        &self,
        room_id: Uuid,
        user_id: Uuid,
    ) -> impl std::future::Future<Output = Result<Option<String>>> + Send;
    fn local_nick_reserved_for_other(
        &self,
        room_id: Uuid,
        user_id: Uuid,
        nick: &str,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn federated_reserved_nick(
        &self,
        room_id: Uuid,
        bare_jid: &str,
    ) -> impl std::future::Future<Output = Result<Option<String>>> + Send;
    fn federated_nick_reserved_for_other(
        &self,
        room_id: Uuid,
        bare_jid: &str,
        nick: &str,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn get_or_create_local_room(
        &self,
        localpart: &str,
        creator_id: Uuid,
        creator_full_jid: &str,
    ) -> impl std::future::Future<Output = Result<(MucRoom, bool)>> + Send;
    fn get_or_create_federated_room(
        &self,
        localpart: &str,
        creator_full_jid: &str,
    ) -> impl std::future::Future<Output = Result<(MucRoom, bool)>> + Send;
    fn public_room_page(
        &self,
        after: Option<&str>,
        before: Option<Option<&str>>,
        max: i64,
    ) -> impl std::future::Future<Output = Result<Option<MucDiscoPage>>> + Send;

    fn register_local_member(
        &self,
        room_id: Uuid,
        user_id: Uuid,
        nick: &str,
    ) -> impl std::future::Future<Output = Result<MucRegistrationOutcome>> + Send;
    fn unregister_local_member(
        &self,
        room_id: Uuid,
        user_id: Uuid,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn register_federated_member(
        &self,
        room_id: Uuid,
        bare_jid: &str,
        nick: &str,
    ) -> impl std::future::Future<Output = Result<MucRegistrationOutcome>> + Send;
    fn unregister_federated_member(
        &self,
        room_id: Uuid,
        bare_jid: &str,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    #[allow(clippy::too_many_arguments)]
    fn mutate_local_cluster_registration(
        &self,
        operation_id: Uuid,
        room_id: Uuid,
        expected_room_epoch: Uuid,
        expected_config_version: i64,
        principal: &ClusterMucPrincipal,
        actor_full_jid: &str,
        reserved_nick: Option<&str>,
    ) -> impl std::future::Future<Output = Result<ClusterMucRegistrationOutcome>> + Send;
    #[allow(clippy::too_many_arguments)]
    fn admit_local_invite_command(
        &self,
        configured_domain: &str,
        id: Uuid,
        room_id: Uuid,
        recipient_id: Uuid,
        sender_jid: &str,
        stanza: &str,
        encrypted: bool,
        policy: OfflineStorePolicy,
        cluster_authority: Option<&ClusterMucInviteAuthority>,
    ) -> impl std::future::Future<Output = Result<DurableMucInviteOutcome>> + Send;
    #[allow(clippy::too_many_arguments)]
    fn admit_federated_invite_command(
        &self,
        room_id: Uuid,
        invitee_bare_jid: &str,
        target_domain: &str,
        stanza: &str,
        bounce_to: Option<&str>,
        policy: FederatedInvitePolicy,
        cluster_authority: Option<&ClusterMucInviteAuthority>,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn set_local_subject(
        &self,
        mutation: MucSubjectMutation<'_>,
        archive: bool,
        authority: MucActorAuthority,
    ) -> impl std::future::Future<Output = Result<MucSubjectOutcome>> + Send;
    fn set_local_cluster_subject(
        &self,
        operation_id: Uuid,
        expected_room_epoch: Uuid,
        expected_config_version: i64,
        actor: &ClusterMucOccupancyTarget,
        mutation: MucSubjectMutation<'_>,
        archive: bool,
    ) -> impl std::future::Future<Output = Result<ClusterMucTransitionOutcome>> + Send;
    fn retract_local_message_and_archive_action(
        &self,
        mutation: MucRetractionMutation<'_>,
    ) -> impl std::future::Future<Output = Result<MucRetractionOutcome>> + Send;
    fn update_local_legacy_config(
        &self,
        room_id: Uuid,
        actor_full_jid: &str,
        config: MucConfigUpdate<'_>,
    ) -> impl std::future::Future<Output = Result<MucConfigurationOutcome>> + Send;
    fn cancel_locked_room(
        &self,
        room_id: Uuid,
        actor_full_jid: &str,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn delete_room(&self, room_id: Uuid) -> impl std::future::Future<Output = Result<()>> + Send;
    fn set_local_legacy_affiliations_batch(
        &self,
        room_id: Uuid,
        changes: &[MucAffiliationChange],
    ) -> impl std::future::Future<Output = Result<MucAffiliationBatchOutcome>> + Send;
    fn local_affiliations(
        &self,
        room_id: Uuid,
        affiliation: &str,
    ) -> impl std::future::Future<Output = Result<Vec<String>>> + Send;
    fn federated_affiliations(
        &self,
        room_id: Uuid,
        affiliation: &str,
    ) -> impl std::future::Future<Output = Result<Vec<String>>> + Send;
    #[allow(clippy::too_many_arguments)]
    fn authorized_admin_role_list(
        &self,
        configured_domain: &str,
        room_id: Uuid,
        expected_room_epoch: Uuid,
        user_id: Uuid,
        actor_scope: &str,
        asserted_local_role: &str,
        actor_target: Option<&ClusterMucOccupancyTarget>,
        clustered: bool,
        requested_role: &str,
    ) -> impl std::future::Future<Output = Result<MucAdminSnapshot<MucAdminRoleList>>> + Send;
    fn authorized_admin_affiliation_list(
        &self,
        configured_domain: &str,
        room_id: Uuid,
        expected_room_epoch: Uuid,
        user_id: Uuid,
        actor_scope: &str,
        requested_affiliation: &str,
    ) -> impl std::future::Future<Output = Result<MucAdminSnapshot<Vec<MucAdminAffiliationEntry>>>> + Send;
    fn claim_local_cluster_occupancy(
        &self,
        request: ClusterMucJoin<'_>,
    ) -> impl std::future::Future<Output = Result<ClusterMucJoinOutcome>> + Send;
    fn renew_local_cluster_occupancy(
        &self,
        target: &ClusterMucOccupancyTarget,
        owner_node_id: &str,
        lease: Duration,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn refresh_local_cluster_presence(
        &self,
        target: &ClusterMucOccupancyTarget,
        owner_node_id: &str,
        presence_payload: &str,
        lease: Duration,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    #[allow(clippy::too_many_arguments)]
    fn transition_local_cluster_occupancy(
        &self,
        operation_id: Uuid,
        target: &ClusterMucOccupancyTarget,
        transition: &str,
        owner_node_id: &str,
        new_connection_uuid: Option<Uuid>,
        new_connection_epoch: Option<i64>,
        sm_session_id: Option<Uuid>,
        lease: Duration,
    ) -> impl std::future::Future<Output = Result<ClusterMucTransitionOutcome>> + Send;
    fn rebind_federated_cluster_occupancy(
        &self,
        operation_id: Uuid,
        target: &ClusterMucOccupancyTarget,
        owner_node_id: &str,
        authenticated_domain: &str,
        new_connection_uuid: Uuid,
        lease: Duration,
    ) -> impl std::future::Future<Output = Result<ClusterMucTransitionOutcome>> + Send;
    fn disconnect_local_cluster_occupancy(
        &self,
        operation_id: Uuid,
        target: &ClusterMucOccupancyTarget,
        owner_node_id: &str,
    ) -> impl std::future::Future<Output = Result<ClusterMucTransitionOutcome>> + Send;
    fn rename_local_cluster_occupancy(
        &self,
        operation_id: Uuid,
        target: &ClusterMucOccupancyTarget,
        owner_node_id: &str,
        new_nick: &str,
    ) -> impl std::future::Future<Output = Result<ClusterMucTransitionOutcome>> + Send;
    #[allow(clippy::too_many_arguments)]
    fn update_local_cluster_config(
        &self,
        operation_id: Uuid,
        room_id: Uuid,
        expected_room_epoch: Uuid,
        expected_config_version: i64,
        actor_target: &ClusterMucOccupancyTarget,
        principal: &ClusterMucPrincipal,
        actor_full_jid: &str,
        config: MucConfigUpdate<'_>,
    ) -> impl std::future::Future<Output = Result<ClusterMucConfigurationOutcome>> + Send;
    #[allow(clippy::too_many_arguments)]
    fn apply_local_cluster_affiliations_batch(
        &self,
        operation_id: Uuid,
        room_id: Uuid,
        expected_room_epoch: Uuid,
        expected_config_version: i64,
        actor_target: &ClusterMucOccupancyTarget,
        actor: &ClusterMucPrincipal,
        actor_full_jid: &str,
        changes: &[MucAffiliationChange],
    ) -> impl std::future::Future<Output = Result<MucAffiliationBatchOutcome>> + Send;
    #[allow(clippy::too_many_arguments)]
    fn apply_local_cluster_admin_batch(
        &self,
        operation_id: Uuid,
        room_id: Uuid,
        expected_room_epoch: Uuid,
        expected_config_version: i64,
        actor_target: Option<&ClusterMucOccupancyTarget>,
        actor: &ClusterMucPrincipal,
        actor_full_jid: &str,
        local_domain: &str,
        changes: &[MucAdminBatchChange],
    ) -> impl std::future::Future<Output = Result<MucAdminBatchOutcome>> + Send;
    fn kick_local_cluster_occupancy(
        &self,
        operation_id: Uuid,
        actor: &ClusterMucOccupancyTarget,
        target: &ClusterMucOccupancyTarget,
        reason: Option<&str>,
    ) -> impl std::future::Future<Output = Result<ClusterMucTransitionOutcome>> + Send;
    fn change_local_cluster_role(
        &self,
        operation_id: Uuid,
        actor: &ClusterMucOccupancyTarget,
        target: &ClusterMucOccupancyTarget,
        new_role: &str,
        reason: Option<&str>,
    ) -> impl std::future::Future<Output = Result<ClusterMucTransitionOutcome>> + Send;
    #[allow(clippy::too_many_arguments)]
    fn destroy_local_cluster_room(
        &self,
        operation_id: Uuid,
        room_id: Uuid,
        expected_room_epoch: Uuid,
        actor: Option<&ClusterMucOccupancyTarget>,
        authorization_source: &str,
        actor_jid: Option<&str>,
        alternate_jid: Option<&str>,
        reason: Option<&str>,
    ) -> impl std::future::Future<Output = Result<ClusterMucTransitionOutcome>> + Send;
    fn local_cluster_occupancy_target(
        &self,
        room_id: Uuid,
        occupant_incarnation: Uuid,
        connection_uuid: Uuid,
    ) -> impl std::future::Future<Output = Result<Option<ClusterMucOccupancyTarget>>> + Send;
    fn local_cluster_occupancy_target_by_nick(
        &self,
        room_id: Uuid,
        expected_room_epoch: Uuid,
        nick: &str,
    ) -> impl std::future::Future<Output = Result<Option<ClusterMucOccupancyTarget>>> + Send;
    fn exact_local_cluster_occupancy_snapshot(
        &self,
        target: &ClusterMucOccupancyTarget,
    ) -> impl std::future::Future<Output = Result<Option<ClusterMucOccupancy>>> + Send;
    fn cluster_room_is_empty(
        &self,
        room_id: Uuid,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn committed_wake(
        &self,
        operation_id: Uuid,
    ) -> impl std::future::Future<Output = Result<Option<ClusterMucWakeDescriptor>>> + Send;
}

pub(crate) trait MucWakePort: Send + Sync {
    fn wake(
        &self,
        descriptor: &ClusterMucWakeDescriptor,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
    fn record_failure(&self, error: &anyhow::Error);
}

/// Redis holds a disposable projection of a PostgreSQL-fenced MUC occupant.
/// It cannot grant room authority; a failed refresh prevents reconciliation
/// from declaring the projection healthy.
pub(crate) trait MucSoftStateProjectionPort: Send + Sync {
    fn join_room(&self, room_jid: &str) -> impl std::future::Future<Output = Result<()>> + Send;
    fn refresh_occupant(
        &self,
        room_jid: &str,
        nick: &str,
        exact_occupant_json: &str,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn reconcile_room(
        &self,
        room_jid: &str,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum MucSoftStateDegradation {
    #[error("MUC Redis room join failed")]
    Join(#[source] anyhow::Error),
    #[error("MUC Redis exact occupant refresh failed")]
    Refresh(#[source] anyhow::Error),
    #[error("MUC Redis rejected the exact PostgreSQL occupant")]
    IdentityRejected,
    #[error("MUC Redis room reconciliation failed")]
    Reconcile(#[source] anyhow::Error),
}

pub(crate) struct MucSoftStateProjectionService<P> {
    port: P,
}

impl<P: MucSoftStateProjectionPort> MucSoftStateProjectionService<P> {
    pub(crate) fn new(port: P) -> Self {
        Self { port }
    }

    /// The room index is published before its exact occupant value, matching
    /// the existing recovery order. A rejected identity never counts as a
    /// successful refresh.
    pub(crate) async fn refresh(
        &self,
        room_jid: &str,
        nick: &str,
        exact_occupant_json: &str,
    ) -> std::result::Result<(), MucSoftStateDegradation> {
        self.port
            .join_room(room_jid)
            .await
            .map_err(MucSoftStateDegradation::Join)?;
        let accepted = self
            .port
            .refresh_occupant(room_jid, nick, exact_occupant_json)
            .await
            .map_err(MucSoftStateDegradation::Refresh)?;
        if !accepted {
            return Err(MucSoftStateDegradation::IdentityRejected);
        }
        Ok(())
    }

    pub(crate) async fn reconcile_room(
        &self,
        room_jid: &str,
    ) -> std::result::Result<(), MucSoftStateDegradation> {
        self.port
            .reconcile_room(room_jid)
            .await
            .map_err(MucSoftStateDegradation::Reconcile)
    }
}

const LOCAL_JOIN_GATE_SHARDS: usize = 256;

#[derive(Clone)]
pub(crate) struct MucService<R> {
    repository: R,
    discussion_application: RoomApplication<R>,
    configured_domain: Arc<str>,
    local_join_gates: Arc<[Arc<tokio::sync::Mutex<()>>]>,
}

impl<R: MucRepository> MucService<R> {
    pub(crate) fn new(repository: R, configured_domain: impl AsRef<str>) -> Self {
        let configured_domain: Arc<str> = Arc::from(configured_domain.as_ref());
        let local_join_gates: Arc<[Arc<tokio::sync::Mutex<()>>]> = (0..LOCAL_JOIN_GATE_SHARDS)
            .map(|_| Arc::new(tokio::sync::Mutex::new(())))
            .collect::<Vec<_>>()
            .into();
        Self {
            discussion_application: RoomApplication::new(
                repository.clone(),
                configured_domain.to_string(),
            ),
            repository,
            configured_domain,
            local_join_gates,
        }
    }
    pub(crate) async fn lock_local_room_mutation(
        &self,
        room_id: Uuid,
    ) -> tokio::sync::OwnedMutexGuard<()> {
        let mut prefix = [0_u8; 8];
        prefix.copy_from_slice(&room_id.as_bytes()[..8]);
        let shard = u64::from_le_bytes(prefix) as usize % self.local_join_gates.len();
        Arc::clone(&self.local_join_gates[shard]).lock_owned().await
    }

    pub(crate) async fn lock_local_join(&self, room_id: Uuid) -> tokio::sync::OwnedMutexGuard<()> {
        self.lock_local_room_mutation(room_id).await
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

    pub(crate) async fn admit_local_discussion(
        &self,
        message: MucDiscussion,
    ) -> Result<MucDiscussionAdmission> {
        self.discussion_application.admit_discussion(&message).await
    }

    pub(crate) async fn local_room_snapshot(&self, localpart: &str) -> Result<Option<MucRoom>> {
        self.repository.local_room_snapshot(localpart).await
    }

    pub(crate) async fn federated_room_snapshot(&self, localpart: &str) -> Result<Option<MucRoom>> {
        self.local_room_snapshot(localpart).await
    }

    pub(crate) async fn local_affiliation(
        &self,
        room_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<String>> {
        self.repository.local_affiliation(room_id, user_id).await
    }

    pub(crate) async fn federated_affiliation(
        &self,
        room_id: Uuid,
        bare_jid: &str,
    ) -> Result<Option<String>> {
        self.repository
            .federated_affiliation(room_id, bare_jid)
            .await
    }

    pub(crate) async fn enabled_local_account(
        &self,
        username: &str,
    ) -> Result<Option<MucLocalAccount>> {
        self.repository.enabled_local_account(username).await
    }

    pub(crate) async fn is_blocked_for_account(
        &self,
        owner_id: Uuid,
        owner_bare_jid: &str,
        candidate: &str,
    ) -> Result<bool> {
        self.repository
            .is_blocked_for_account(owner_id, owner_bare_jid, candidate)
            .await
    }

    pub(crate) async fn blocked_jids(&self, user_id: Uuid) -> Result<Vec<String>> {
        self.repository.blocked_jids(user_id).await
    }

    pub(crate) async fn store_local_muc_offline(
        &self,
        recipient_id: Uuid,
        sender_jid: &str,
        stanza: &str,
        encrypted: bool,
        policy: OfflineStorePolicy,
    ) -> Result<OfflineStoreOutcome> {
        self.repository
            .store_local_muc_offline(
                &self.configured_domain,
                recipient_id,
                sender_jid,
                stanza,
                encrypted,
                policy,
            )
            .await
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
        self.repository
            .local_message_by_id(room_id, message_id)
            .await
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
        self.repository
            .local_history_since(room_id, limit, since)
            .await
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
        self.repository.delete_expired_locked_room(room_id).await
    }

    pub(crate) async fn delete_temporary_room(
        &self,
        room_id: Uuid,
        room_epoch: Uuid,
        config_version: i64,
    ) -> Result<bool> {
        self.repository
            .delete_temporary_room(room_id, room_epoch, config_version)
            .await
    }

    pub(crate) async fn local_reserved_nick(
        &self,
        room_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<String>> {
        self.repository.local_reserved_nick(room_id, user_id).await
    }

    pub(crate) async fn local_nick_reserved_for_other(
        &self,
        room_id: Uuid,
        user_id: Uuid,
        nick: &str,
    ) -> Result<bool> {
        self.repository
            .local_nick_reserved_for_other(room_id, user_id, nick)
            .await
    }

    pub(crate) async fn federated_reserved_nick(
        &self,
        room_id: Uuid,
        bare_jid: &str,
    ) -> Result<Option<String>> {
        self.repository
            .federated_reserved_nick(room_id, bare_jid)
            .await
    }

    pub(crate) async fn federated_nick_reserved_for_other(
        &self,
        room_id: Uuid,
        bare_jid: &str,
        nick: &str,
    ) -> Result<bool> {
        self.repository
            .federated_nick_reserved_for_other(room_id, bare_jid, nick)
            .await
    }

    pub(crate) async fn get_or_create_local_room(
        &self,
        localpart: &str,
        creator_id: Uuid,
        creator_full_jid: &str,
    ) -> Result<(MucRoom, bool)> {
        self.repository
            .get_or_create_local_room(localpart, creator_id, creator_full_jid)
            .await
    }

    pub(crate) async fn get_or_create_federated_room(
        &self,
        localpart: &str,
        creator_full_jid: &str,
    ) -> Result<(MucRoom, bool)> {
        self.repository
            .get_or_create_federated_room(localpart, creator_full_jid)
            .await
    }

    pub(crate) async fn public_room_page(
        &self,
        after: Option<&str>,
        before: Option<Option<&str>>,
        max: i64,
    ) -> Result<Option<MucDiscoPage>> {
        self.repository.public_room_page(after, before, max).await
    }

    pub(crate) async fn federated_public_room_page(
        &self,
        after: Option<&str>,
        before: Option<Option<&str>>,
        max: i64,
    ) -> Result<Option<MucDiscoPage>> {
        self.public_room_page(after, before, max).await
    }

    pub(crate) async fn register_local_member(
        &self,
        room_id: Uuid,
        user_id: Uuid,
        nick: &str,
    ) -> Result<MucRegistrationOutcome> {
        self.repository
            .register_local_member(room_id, user_id, nick)
            .await
    }

    pub(crate) async fn unregister_local_member(
        &self,
        room_id: Uuid,
        user_id: Uuid,
    ) -> Result<bool> {
        self.repository
            .unregister_local_member(room_id, user_id)
            .await
    }

    pub(crate) async fn register_federated_member(
        &self,
        room_id: Uuid,
        bare_jid: &str,
        nick: &str,
    ) -> Result<MucRegistrationOutcome> {
        self.repository
            .register_federated_member(room_id, bare_jid, nick)
            .await
    }

    pub(crate) async fn unregister_federated_member(
        &self,
        room_id: Uuid,
        bare_jid: &str,
    ) -> Result<bool> {
        self.repository
            .unregister_federated_member(room_id, bare_jid)
            .await
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
        self.repository
            .mutate_local_cluster_registration(
                operation_id,
                room_id,
                expected_room_epoch,
                expected_config_version,
                principal,
                actor_full_jid,
                reserved_nick,
            )
            .await
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
        self.repository
            .admit_local_invite_command(
                &self.configured_domain,
                id,
                room_id,
                recipient_id,
                sender_jid,
                stanza,
                encrypted,
                policy,
                cluster_authority,
            )
            .await
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
        self.repository
            .admit_federated_invite_command(
                room_id,
                invitee_bare_jid,
                target_domain,
                stanza,
                bounce_to,
                policy,
                cluster_authority,
            )
            .await
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

        self.repository
            .set_local_subject(mutation, archive, authority)
            .await
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
        self.repository
            .set_local_cluster_subject(
                operation_id,
                expected_room_epoch,
                expected_config_version,
                actor,
                mutation,
                archive,
            )
            .await
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

        self.repository
            .retract_local_message_and_archive_action(mutation)
            .await
    }

    pub(crate) async fn update_local_legacy_config(
        &self,
        room_id: Uuid,
        actor_full_jid: &str,
        config: MucConfigUpdate<'_>,
    ) -> Result<MucConfigurationOutcome> {
        self.repository
            .update_local_legacy_config(room_id, actor_full_jid, config)
            .await
    }

    pub(crate) async fn cancel_locked_room(
        &self,
        room_id: Uuid,
        actor_full_jid: &str,
    ) -> Result<bool> {
        self.repository
            .cancel_locked_room(room_id, actor_full_jid)
            .await
    }

    pub(crate) async fn delete_room(&self, room_id: Uuid) -> Result<()> {
        self.repository.delete_room(room_id).await
    }

    pub(crate) async fn set_local_legacy_affiliations_batch(
        &self,
        room_id: Uuid,
        changes: &[MucAffiliationChange],
    ) -> Result<MucAffiliationBatchOutcome> {
        self.repository
            .set_local_legacy_affiliations_batch(room_id, changes)
            .await
    }

    pub(crate) async fn local_affiliations(
        &self,
        room_id: Uuid,
        affiliation: &str,
    ) -> Result<Vec<String>> {
        self.repository
            .local_affiliations(room_id, affiliation)
            .await
    }

    pub(crate) async fn federated_affiliations(
        &self,
        room_id: Uuid,
        affiliation: &str,
    ) -> Result<Vec<String>> {
        self.repository
            .federated_affiliations(room_id, affiliation)
            .await
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
        self.repository
            .authorized_admin_role_list(
                &self.configured_domain,
                room_id,
                expected_room_epoch,
                user_id,
                actor_scope,
                asserted_local_role,
                actor_target,
                clustered,
                requested_role,
            )
            .await
    }

    pub(crate) async fn authorized_admin_affiliation_list(
        &self,
        room_id: Uuid,
        expected_room_epoch: Uuid,
        user_id: Uuid,
        actor_scope: &str,
        requested_affiliation: &str,
    ) -> Result<MucAdminSnapshot<Vec<MucAdminAffiliationEntry>>> {
        self.repository
            .authorized_admin_affiliation_list(
                &self.configured_domain,
                room_id,
                expected_room_epoch,
                user_id,
                actor_scope,
                requested_affiliation,
            )
            .await
    }

    pub(crate) async fn claim_local_cluster_occupancy(
        &self,
        request: ClusterMucJoin<'_>,
    ) -> Result<ClusterMucJoinOutcome> {
        self.repository.claim_local_cluster_occupancy(request).await
    }

    pub(crate) async fn renew_local_cluster_occupancy(
        &self,
        target: &ClusterMucOccupancyTarget,
        owner_node_id: &str,
        lease: Duration,
    ) -> Result<bool> {
        self.repository
            .renew_local_cluster_occupancy(target, owner_node_id, lease)
            .await
    }

    pub(crate) async fn refresh_local_cluster_presence(
        &self,
        target: &ClusterMucOccupancyTarget,
        owner_node_id: &str,
        presence_payload: &str,
        lease: Duration,
    ) -> Result<bool> {
        self.repository
            .refresh_local_cluster_presence(target, owner_node_id, presence_payload, lease)
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
        self.repository
            .transition_local_cluster_occupancy(
                operation_id,
                target,
                transition,
                owner_node_id,
                new_connection_uuid,
                new_connection_epoch,
                sm_session_id,
                lease,
            )
            .await
    }

    pub(crate) async fn rebind_federated_cluster_occupancy(
        &self,
        operation_id: Uuid,
        target: &ClusterMucOccupancyTarget,
        owner_node_id: &str,
        authenticated_domain: &str,
        new_connection_uuid: Uuid,
        lease: Duration,
    ) -> Result<ClusterMucTransitionOutcome> {
        self.repository
            .rebind_federated_cluster_occupancy(
                operation_id,
                target,
                owner_node_id,
                authenticated_domain,
                new_connection_uuid,
                lease,
            )
            .await
    }

    pub(crate) async fn disconnect_local_cluster_occupancy(
        &self,
        operation_id: Uuid,
        target: &ClusterMucOccupancyTarget,
        owner_node_id: &str,
    ) -> Result<ClusterMucTransitionOutcome> {
        self.repository
            .disconnect_local_cluster_occupancy(operation_id, target, owner_node_id)
            .await
    }

    pub(crate) async fn rename_local_cluster_occupancy(
        &self,
        operation_id: Uuid,
        target: &ClusterMucOccupancyTarget,
        owner_node_id: &str,
        new_nick: &str,
    ) -> Result<ClusterMucTransitionOutcome> {
        self.repository
            .rename_local_cluster_occupancy(operation_id, target, owner_node_id, new_nick)
            .await
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
        self.repository
            .update_local_cluster_config(
                operation_id,
                room_id,
                expected_room_epoch,
                expected_config_version,
                actor_target,
                principal,
                actor_full_jid,
                config,
            )
            .await
    }

    #[allow(clippy::too_many_arguments)]
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
        self.repository
            .apply_local_cluster_affiliations_batch(
                operation_id,
                room_id,
                expected_room_epoch,
                expected_config_version,
                actor_target,
                actor,
                actor_full_jid,
                changes,
            )
            .await
    }

    /// The IQ identity intentionally excludes its items. A changed retry on
    /// the same authenticated stream and IQ id must hit the stored digest and
    /// fail as a conflict, even if a target nick no longer exists.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn apply_local_cluster_admin_batch(
        &self,
        stream_id: Uuid,
        iq_id: &str,
        room_jid: &str,
        room_id: Uuid,
        expected_room_epoch: Uuid,
        expected_config_version: i64,
        actor_target: Option<&ClusterMucOccupancyTarget>,
        actor: &ClusterMucPrincipal,
        actor_full_jid: &str,
        changes: &[MucAdminBatchChange],
    ) -> Result<MucAdminBatchResult> {
        anyhow::ensure!(!iq_id.is_empty() && iq_id.len() <= 256, "invalid MUC IQ id");
        let canonical_room = crate::jid::CanonicalJid::parse_bare(room_jid)?;
        anyhow::ensure!(
            canonical_room.to_string() == room_jid,
            "noncanonical MUC room JID"
        );
        let operation_id = operation_id(&serde_json::json!({
            "kind":"admin_batch","stream":stream_id,"iq_id":iq_id,"room":room_jid,
        }))?;
        let outcome = self
            .repository
            .apply_local_cluster_admin_batch(
                operation_id,
                room_id,
                expected_room_epoch,
                expected_config_version,
                actor_target,
                actor,
                actor_full_jid,
                &self.configured_domain,
                changes,
            )
            .await?;
        Ok(MucAdminBatchResult {
            operation_id,
            outcome,
        })
    }

    pub(crate) async fn kick_local_cluster_occupancy(
        &self,
        operation_id: Uuid,
        actor: &ClusterMucOccupancyTarget,
        target: &ClusterMucOccupancyTarget,
        reason: Option<&str>,
    ) -> Result<ClusterMucTransitionOutcome> {
        self.repository
            .kick_local_cluster_occupancy(operation_id, actor, target, reason)
            .await
    }

    pub(crate) async fn change_local_cluster_role(
        &self,
        operation_id: Uuid,
        actor: &ClusterMucOccupancyTarget,
        target: &ClusterMucOccupancyTarget,
        new_role: &str,
        reason: Option<&str>,
    ) -> Result<ClusterMucTransitionOutcome> {
        self.repository
            .change_local_cluster_role(operation_id, actor, target, new_role, reason)
            .await
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
        self.repository
            .destroy_local_cluster_room(
                operation_id,
                room_id,
                expected_room_epoch,
                actor,
                authorization_source,
                actor_jid,
                alternate_jid,
                reason,
            )
            .await
    }

    pub(crate) async fn local_cluster_occupancy_target(
        &self,
        room_id: Uuid,
        occupant_incarnation: Uuid,
        connection_uuid: Uuid,
    ) -> Result<Option<ClusterMucOccupancyTarget>> {
        self.repository
            .local_cluster_occupancy_target(room_id, occupant_incarnation, connection_uuid)
            .await
    }

    pub(crate) async fn local_cluster_occupancy_target_by_nick(
        &self,
        room_id: Uuid,
        expected_room_epoch: Uuid,
        nick: &str,
    ) -> Result<Option<ClusterMucOccupancyTarget>> {
        self.repository
            .local_cluster_occupancy_target_by_nick(room_id, expected_room_epoch, nick)
            .await
    }

    pub(crate) async fn exact_local_cluster_occupancy_snapshot(
        &self,
        target: &ClusterMucOccupancyTarget,
    ) -> Result<Option<ClusterMucOccupancy>> {
        self.repository
            .exact_local_cluster_occupancy_snapshot(target)
            .await
    }

    pub(crate) async fn cluster_room_is_empty(&self, room_id: Uuid) -> Result<bool> {
        self.repository.cluster_room_is_empty(room_id).await
    }

    pub(crate) async fn wake_committed_operation<W: MucWakePort>(
        &self,
        wake: &W,
        operation_id: Uuid,
    ) -> Result<()> {
        notify_committed_operation(
            self.repository.committed_wake(operation_id),
            wake,
            operation_id,
        )
        .await;
        Ok(())
    }

    pub(crate) async fn room(&self, localpart: &str) -> Result<Option<MucRoom>> {
        self.local_room_snapshot(localpart).await
    }
}

pub(crate) async fn notify_committed_operation(
    descriptor: impl std::future::Future<Output = Result<Option<ClusterMucWakeDescriptor>>>,
    wake: &impl MucWakePort,
    operation_id: Uuid,
) {
    let result = async {
        if let Some(descriptor) = descriptor.await? {
            wake.wake(&descriptor).await?;
        }
        Ok::<_, anyhow::Error>(())
    }
    .await;
    if let Err(error) = result {
        // The durable operation has already committed. A failed accelerator
        // must not turn its success into a protocol retry.
        tracing::warn!(?error, %operation_id, "committed MUC operation wake failed; PostgreSQL poller will catch up");
        wake.record_failure(&error);
    }
}

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
    error.downcast_ref::<MucCapacityExceeded>().is_some()
}

#[cfg(test)]
pub(crate) fn archive_page_is_last(page: &crate::db::MamRsmPage) -> bool {
    matches!(page, crate::db::MamRsmPage::Last)
}

/// Hash a room password for storage. XEP-0045 transmits this value inside the
/// TLS-protected XMPP stream, but the server never stores the cleartext value.
pub(crate) fn hash_room_password(password: &str) -> Result<String> {
    if password.is_empty() || password.len() > 1024 {
        anyhow::bail!("room password must contain 1 to 1024 bytes");
    }
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|error| anyhow::anyhow!("room password hashing failed: {error}"))
}

pub(crate) fn verify_room_password(password_hash: &str, candidate: &str) -> bool {
    if candidate.len() > 1024 {
        return false;
    }
    PasswordHash::new(password_hash).ok().is_some_and(|parsed| {
        Argon2::default()
            .verify_password(candidate.as_bytes(), &parsed)
            .is_ok()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::room::PostgresMucRepository;

    #[tokio::test]
    async fn committed_wake_failures_preserve_success_and_record_degradation() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct Wake {
            calls: AtomicUsize,
            failures: AtomicUsize,
            operation_id: Uuid,
        }
        impl MucWakePort for Wake {
            async fn wake(&self, descriptor: &ClusterMucWakeDescriptor) -> Result<()> {
                assert_eq!(descriptor.operation_id, self.operation_id);
                self.calls.fetch_add(1, Ordering::SeqCst);
                anyhow::bail!("injected Redis failure")
            }
            fn record_failure(&self, _: &anyhow::Error) {
                self.failures.fetch_add(1, Ordering::SeqCst);
            }
        }
        let operation_id = Uuid::new_v4();
        let wake = Wake {
            calls: AtomicUsize::new(0),
            failures: AtomicUsize::new(0),
            operation_id,
        };
        notify_committed_operation(
            async { anyhow::bail!("descriptor lookup failed") },
            &wake,
            operation_id,
        )
        .await;
        assert_eq!(wake.calls.load(Ordering::SeqCst), 0);
        assert_eq!(wake.failures.load(Ordering::SeqCst), 1);
        notify_committed_operation(async { Ok(None) }, &wake, operation_id).await;
        assert_eq!(wake.calls.load(Ordering::SeqCst), 0);
        assert_eq!(wake.failures.load(Ordering::SeqCst), 1);
        let descriptor = ClusterMucWakeDescriptor {
            operation_id,
            room_id: Uuid::new_v4(),
            event_id: Uuid::new_v4(),
            event_sequence: 1,
            target_nodes: vec!["node-a".to_owned()],
        };
        notify_committed_operation(async { Ok(Some(descriptor)) }, &wake, operation_id).await;
        assert_eq!(wake.calls.load(Ordering::SeqCst), 1);
        assert_eq!(wake.failures.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn local_room_mutation_gate_serializes_one_room_without_a_growing_registry() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://northstar@localhost/northstar")
            .expect("lazy test pool");
        let service = MucService::new(PostgresMucRepository::new(pool), "local.test");
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
        let service = MucService::new(PostgresMucRepository::new(pool), "local.test");
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

    #[tokio::test]
    async fn local_actor_scope_requires_the_configured_domain_at_the_service_boundary() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://northstar@localhost/northstar")
            .expect("lazy test pool");
        let service = MucService::new(PostgresMucRepository::new(pool), "local.test");
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
}

#[cfg(test)]
mod muc_soft_state_projection_tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    };

    struct FaultPort {
        calls: Mutex<Vec<&'static str>>,
        joins: AtomicUsize,
        refreshes: AtomicUsize,
        reconciliations: AtomicUsize,
    }

    impl MucSoftStateProjectionPort for &FaultPort {
        async fn join_room(&self, room_jid: &str) -> Result<()> {
            assert_eq!(room_jid, "room@conference.local.test");
            self.calls.lock().unwrap().push("join");
            if self.joins.fetch_add(1, Ordering::SeqCst) == 0 {
                anyhow::bail!("injected Redis join outage");
            }
            Ok(())
        }

        async fn refresh_occupant(
            &self,
            room_jid: &str,
            nick: &str,
            exact_occupant_json: &str,
        ) -> Result<bool> {
            assert_eq!(room_jid, "room@conference.local.test");
            assert_eq!(nick, "Alice");
            assert_eq!(exact_occupant_json, "exact-PG-fenced-occupant");
            self.calls.lock().unwrap().push("refresh");
            match self.refreshes.fetch_add(1, Ordering::SeqCst) {
                0 => Ok(false),
                1 => anyhow::bail!("injected Redis refresh outage"),
                _ => Ok(true),
            }
        }

        async fn reconcile_room(&self, room_jid: &str) -> Result<()> {
            assert_eq!(room_jid, "room@conference.local.test");
            self.calls.lock().unwrap().push("reconcile");
            if self.reconciliations.fetch_add(1, Ordering::SeqCst) == 0 {
                anyhow::bail!("injected Redis reconciliation outage");
            }
            Ok(())
        }
    }

    #[tokio::test]
    async fn projection_failure_does_not_claim_success_and_recovery_retries_in_order() {
        let port = FaultPort {
            calls: Mutex::new(Vec::new()),
            joins: AtomicUsize::new(0),
            refreshes: AtomicUsize::new(0),
            reconciliations: AtomicUsize::new(0),
        };
        let service = MucSoftStateProjectionService::new(&port);
        let refresh = || {
            service.refresh(
                "room@conference.local.test",
                "Alice",
                "exact-PG-fenced-occupant",
            )
        };
        assert!(matches!(
            refresh().await,
            Err(MucSoftStateDegradation::Join(_))
        ));
        assert!(matches!(
            refresh().await,
            Err(MucSoftStateDegradation::IdentityRejected)
        ));
        assert!(matches!(
            refresh().await,
            Err(MucSoftStateDegradation::Refresh(_))
        ));
        refresh().await.unwrap();
        assert!(matches!(
            service.reconcile_room("room@conference.local.test").await,
            Err(MucSoftStateDegradation::Reconcile(_))
        ));
        service
            .reconcile_room("room@conference.local.test")
            .await
            .unwrap();
        assert_eq!(
            *port.calls.lock().unwrap(),
            [
                "join",
                "join",
                "refresh",
                "join",
                "refresh",
                "join",
                "refresh",
                "reconcile",
                "reconcile"
            ]
        );
    }
}
