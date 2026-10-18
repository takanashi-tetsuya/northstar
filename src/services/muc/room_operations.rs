//! Room queries, membership, invitations, discussion commands, and legacy administrative operations.

use super::*;

impl<R: MucRepository> MucService<R> {
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
}
