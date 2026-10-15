//! PostgreSQL implementation of the room application port.

use crate::{db, services::muc::*};
use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use std::time::Duration;
use uuid::Uuid;

mod conversions;
mod occupancy;

use self::conversions::{
    actor_authority_to_db, cluster_join_into_db, config_update_into_db, map_admin_snapshot,
    occupancy_target_from_db, retraction_mutation_as_db, subject_mutation_into_db,
};

#[derive(Clone)]
pub(crate) struct PostgresMucRepository {
    pool: PgPool,
}

impl PostgresMucRepository {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

pub(crate) struct PostgresClusterMucOccupancyMaintenanceRepository {
    pool: PgPool,
}

impl PostgresClusterMucOccupancyMaintenanceRepository {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(Clone)]
pub(crate) struct PostgresClusterMucOccupancyDepartureRepository {
    pool: PgPool,
}

impl PostgresClusterMucOccupancyDepartureRepository {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

pub(super) fn discussion_to_db(command: &MucDiscussion) -> db::MucDiscussion<'_> {
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

impl MucDiscussionRepository for PostgresMucRepository {
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

    fn admit_discussion_observed<'a>(
        &'a self,
        request: &'a northstar_room_application::discussion::Request,
    ) -> RepositoryFuture<'a, Self::Error> {
        Box::pin(async move {
            Ok(
                match db::admit_muc_discussion_observed(&self.pool, request).await? {
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

impl MucRepository for PostgresMucRepository {
    async fn local_room_snapshot(&self, localpart: &str) -> Result<Option<MucRoom>> {
        Ok(db::muc_room(&self.pool, localpart).await?.map(Into::into))
    }

    async fn local_affiliation(&self, room_id: Uuid, user_id: Uuid) -> Result<Option<String>> {
        db::muc_affiliation(&self.pool, room_id, user_id).await
    }

    async fn federated_affiliation(&self, room_id: Uuid, bare_jid: &str) -> Result<Option<String>> {
        db::federated_muc_affiliation(&self.pool, room_id, bare_jid).await
    }

    async fn enabled_local_account(&self, username: &str) -> Result<Option<MucLocalAccount>> {
        Ok(db::enabled_user_id(&self.pool, username)
            .await?
            .map(|id| MucLocalAccount { id }))
    }

    async fn is_blocked_for_account(
        &self,
        owner_id: Uuid,
        owner_bare_jid: &str,
        candidate: &str,
    ) -> Result<bool> {
        db::is_blocked_for_account(&self.pool, owner_id, owner_bare_jid, candidate).await
    }

    async fn blocked_jids(&self, user_id: Uuid) -> Result<Vec<String>> {
        db::blocked_jids(&self.pool, user_id).await
    }

    async fn store_local_muc_offline(
        &self,
        configured_domain: &str,
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
            recipient.username, configured_domain
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

    async fn local_message_by_id(
        &self,
        room_id: Uuid,
        message_id: Uuid,
    ) -> Result<Option<MucMessage>> {
        Ok(db::muc_message_by_id(&self.pool, room_id, message_id)
            .await?
            .map(Into::into))
    }

    async fn local_history_since(
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

    async fn delete_expired_locked_room(&self, room_id: Uuid) -> Result<bool> {
        db::delete_expired_locked_muc_room(&self.pool, room_id).await
    }

    async fn delete_temporary_room(
        &self,
        room_id: Uuid,
        room_epoch: Uuid,
        config_version: i64,
    ) -> Result<bool> {
        db::delete_temporary_muc_room(&self.pool, room_id, room_epoch, config_version).await
    }

    async fn local_reserved_nick(&self, room_id: Uuid, user_id: Uuid) -> Result<Option<String>> {
        db::muc_reserved_nick(&self.pool, room_id, user_id).await
    }

    async fn local_nick_reserved_for_other(
        &self,
        room_id: Uuid,
        user_id: Uuid,
        nick: &str,
    ) -> Result<bool> {
        db::muc_nick_reserved_for_other(&self.pool, room_id, user_id, nick).await
    }

    async fn federated_reserved_nick(
        &self,
        room_id: Uuid,
        bare_jid: &str,
    ) -> Result<Option<String>> {
        db::federated_muc_reserved_nick(&self.pool, room_id, bare_jid).await
    }

    async fn federated_nick_reserved_for_other(
        &self,
        room_id: Uuid,
        bare_jid: &str,
        nick: &str,
    ) -> Result<bool> {
        db::federated_muc_nick_reserved_for_other(&self.pool, room_id, bare_jid, nick).await
    }

    async fn get_or_create_local_room(
        &self,
        localpart: &str,
        creator_id: Uuid,
        creator_full_jid: &str,
    ) -> Result<(MucRoom, bool)> {
        let (room, created) =
            db::get_or_create_muc_room(&self.pool, localpart, creator_id, creator_full_jid)
                .await
                .map_err(map_capacity_error)?;
        Ok((room.into(), created))
    }

    async fn get_or_create_federated_room(
        &self,
        localpart: &str,
        creator_full_jid: &str,
    ) -> Result<(MucRoom, bool)> {
        let (room, created) =
            db::get_or_create_federated_muc_room(&self.pool, localpart, creator_full_jid)
                .await
                .map_err(map_capacity_error)?;
        Ok((room.into(), created))
    }

    async fn public_room_page(
        &self,
        after: Option<&str>,
        before: Option<Option<&str>>,
        max: i64,
    ) -> Result<Option<MucDiscoPage>> {
        Ok(db::public_muc_room_page(&self.pool, after, before, max)
            .await?
            .map(Into::into))
    }

    async fn register_local_member(
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

    async fn unregister_local_member(&self, room_id: Uuid, user_id: Uuid) -> Result<bool> {
        db::unregister_local_muc_member(&self.pool, room_id, user_id).await
    }

    async fn register_federated_member(
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

    async fn unregister_federated_member(&self, room_id: Uuid, bare_jid: &str) -> Result<bool> {
        db::unregister_federated_muc_member(&self.pool, room_id, bare_jid).await
    }

    #[allow(clippy::too_many_arguments)]
    async fn mutate_local_cluster_registration(
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
    async fn admit_local_invite_command(
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
    ) -> Result<DurableMucInviteOutcome> {
        let recipient = db::find_enabled_user_by_id(&self.pool, recipient_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("local MUC invite recipient account is unavailable"))?;
        let recipient_bare_jid = crate::jid::canonicalize_bare(&format!(
            "{}@{}",
            recipient.username, configured_domain
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
    async fn admit_federated_invite_command(
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

    async fn set_local_subject(
        &self,
        mutation: MucSubjectMutation<'_>,
        archive: bool,
        authority: MucActorAuthority,
    ) -> Result<MucSubjectOutcome> {
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

    async fn set_local_cluster_subject(
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

    async fn retract_local_message_and_archive_action(
        &self,
        mutation: MucRetractionMutation<'_>,
    ) -> Result<MucRetractionOutcome> {
        Ok(db::retract_muc_message_and_archive_action(
            &self.pool,
            retraction_mutation_as_db(&mutation),
        )
        .await?
        .into())
    }

    async fn update_local_legacy_config(
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

    async fn cancel_locked_room(&self, room_id: Uuid, actor_full_jid: &str) -> Result<bool> {
        db::cancel_locked_muc_room(&self.pool, room_id, actor_full_jid).await
    }

    async fn delete_room(&self, room_id: Uuid) -> Result<()> {
        db::delete_muc_room(&self.pool, room_id).await
    }

    async fn set_local_legacy_affiliations_batch(
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

    async fn local_affiliations(&self, room_id: Uuid, affiliation: &str) -> Result<Vec<String>> {
        db::get_muc_affiliations(&self.pool, room_id, affiliation).await
    }

    async fn federated_affiliations(
        &self,
        room_id: Uuid,
        affiliation: &str,
    ) -> Result<Vec<String>> {
        db::get_federated_muc_affiliations(&self.pool, room_id, affiliation).await
    }

    #[allow(clippy::too_many_arguments)]
    async fn authorized_admin_role_list(
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
    ) -> Result<MucAdminSnapshot<MucAdminRoleList>> {
        let actor_target = actor_target.map(Into::into);
        let snapshot = db::authorized_muc_admin_role_list(
            &self.pool,
            room_id,
            expected_room_epoch,
            user_id,
            actor_scope,
            configured_domain,
            asserted_local_role,
            actor_target.as_ref(),
            clustered,
            requested_role,
        )
        .await?;
        Ok(map_admin_snapshot(snapshot, Into::into))
    }

    async fn authorized_admin_affiliation_list(
        &self,
        configured_domain: &str,
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
            configured_domain,
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

    async fn claim_local_cluster_occupancy(
        &self,
        request: ClusterMucJoin<'_>,
    ) -> Result<ClusterMucJoinOutcome> {
        Ok(
            db::claim_cluster_muc_occupancy(&self.pool, cluster_join_into_db(request))
                .await?
                .into(),
        )
    }

    async fn renew_local_cluster_occupancy(
        &self,
        target: &ClusterMucOccupancyTarget,
        owner_node_id: &str,
        lease: Duration,
    ) -> Result<bool> {
        let target = target.into();
        db::renew_cluster_muc_occupancy(&self.pool, &target, owner_node_id, lease).await
    }

    async fn refresh_local_cluster_presence(
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
    async fn transition_local_cluster_occupancy(
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

    async fn rebind_federated_cluster_occupancy(
        &self,
        operation_id: Uuid,
        target: &ClusterMucOccupancyTarget,
        owner_node_id: &str,
        authenticated_domain: &str,
        new_connection_uuid: Uuid,
        lease: Duration,
    ) -> Result<ClusterMucTransitionOutcome> {
        Ok(db::rebind_federated_cluster_muc_occupancy(
            &self.pool,
            operation_id,
            &target.into(),
            owner_node_id,
            authenticated_domain,
            new_connection_uuid,
            lease,
        )
        .await?
        .into())
    }

    async fn disconnect_local_cluster_occupancy(
        &self,
        operation_id: Uuid,
        target: &ClusterMucOccupancyTarget,
        owner_node_id: &str,
    ) -> Result<ClusterMucTransitionOutcome> {
        Ok(db::disconnect_cluster_muc_occupancy(
            &self.pool,
            operation_id,
            &target.into(),
            owner_node_id,
        )
        .await?
        .into())
    }

    async fn rename_local_cluster_occupancy(
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
    async fn update_local_cluster_config(
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

    #[allow(clippy::too_many_arguments)]
    async fn apply_local_cluster_affiliations_batch(
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

    #[allow(clippy::too_many_arguments)]
    async fn apply_local_cluster_admin_batch(
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
    ) -> Result<MucAdminBatchOutcome> {
        let actor_target = actor_target.map(Into::into);
        let actor = actor.into();
        let changes = changes.iter().map(Into::into).collect::<Vec<_>>();
        Ok(db::apply_cluster_muc_admin_batch(
            &self.pool,
            db::ClusterMucAdminBatch {
                operation_id,
                room_id,
                expected_room_epoch,
                expected_config_version,
                actor_target: actor_target.as_ref(),
                actor: &actor,
                actor_full_jid,
                local_domain,
                changes: &changes,
            },
        )
        .await?
        .into())
    }

    async fn kick_local_cluster_occupancy(
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

    async fn change_local_cluster_role(
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
    async fn destroy_local_cluster_room(
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

    async fn local_cluster_occupancy_target(
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

    async fn local_cluster_occupancy_target_by_nick(
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

    async fn exact_local_cluster_occupancy_snapshot(
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

    async fn cluster_room_is_empty(&self, room_id: Uuid) -> Result<bool> {
        db::cluster_muc_room_is_empty(&self.pool, room_id).await
    }

    async fn committed_wake(&self, operation_id: Uuid) -> Result<Option<ClusterMucWakeDescriptor>> {
        db::cluster_muc_wake_descriptor(&self.pool, operation_id).await
    }
}

fn map_capacity_error(error: anyhow::Error) -> anyhow::Error {
    if db::is_capacity_exhausted(&error) {
        error.context(MucCapacityExceeded)
    } else {
        error
    }
}

#[cfg(test)]
mod tests;
