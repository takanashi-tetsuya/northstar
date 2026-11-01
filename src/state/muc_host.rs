//! The node's capabilities as the MUC handlers see them.

use super::*;
use crate::db::room_effects::{PostgresMixRepository, PostgresMucRepository};
use crate::xmpp::outbound::{DurableDelivery, OutboundSender};
use anyhow::Result;
use northstar_archive_core::{
    FederatedMamAdmissionOutcome, FederatedMamMetadataCommand, FederatedMamStreamPage,
    FederatedMamStreamRequest, MamMetadataResult, MamRoomAccessOutcome,
};
use northstar_delivery_core::node_delivery::NodeDeliveryReceipt;
use northstar_federation_core::S2sOutboxPolicy;
use northstar_message_core::DirectPostCommitMode;
use northstar_muc_xmpp::ports::MucHost;
use northstar_room_application::mix_service::MixService;
use northstar_room_application::muc_service::MucService;
use northstar_room_core::occupancy::{
    FederatedMucAccountRoute, LocalMucJoinPublication, LocalMucNicknameMove, MucJoinCacheAttempt,
    MucPresencePublication, MucRename, MucRoleChange,
};
use std::collections::HashMap;

impl MucHost for AppState {
    type Repository = PostgresMucRepository;
    type MixRepository = PostgresMixRepository;
    type Outbound = OutboundSender;
    type SuspendedEndpoint = SuspendedMucEndpoint;
    type Session = OnlineSession;

    fn muc_service(&self) -> &MucService<PostgresMucRepository> {
        AppState::muc_service(self)
    }

    fn mix_service(&self) -> &MixService<PostgresMixRepository> {
        AppState::mix_service(self)
    }

    fn session_entries_for(&self, jid: &str) -> Vec<(String, OnlineSession)> {
        AppState::session_entries_for(self, jid)
    }

    fn message_direct_mode(&self) -> DirectPostCommitMode {
        self.message_service().direct_mode()
    }

    async fn rearm_unrouted_live_direct(
        &self,
        recipient_id: uuid::Uuid,
        message_id: uuid::Uuid,
        claim_id: &mut Option<uuid::Uuid>,
    ) {
        self.message_service()
            .rearm_unrouted_live_direct(recipient_id, message_id, claim_id)
            .await;
    }

    async fn send_received_carbons(
        &self,
        recipient: &str,
        delivered: Option<&str>,
        forwarded: &str,
    ) {
        crate::services::message_carbons::send_received_carbons(
            self, recipient, delivered, forwarded,
        )
        .await;
    }

    fn federation_outbox_policy(&self) -> S2sOutboxPolicy {
        self.federation_outbox().outbox_policy()
    }

    fn wake_federation_outbox(&self) {
        self.federation_outbox().wake_outbox();
    }

    async fn send_federated(
        &self,
        target_domain: &str,
        stanza: String,
        bounce_to: Option<String>,
    ) -> bool {
        self.federation_outbox()
            .send(target_domain, stanza, bounce_to)
            .await
    }

    async fn authorize_federated_room(
        &self,
        localpart: &str,
        viewer_bare_jid: &str,
        currently_joined: bool,
    ) -> Result<MamRoomAccessOutcome> {
        self.mam_service()
            .authorize_federated_room(localpart, viewer_bare_jid, currently_joined)
            .await
    }

    async fn execute_federated_mam_metadata(
        &self,
        command: FederatedMamMetadataCommand,
    ) -> Result<MamMetadataResult> {
        self.mam_service()
            .execute_federated_mam_metadata(command)
            .await
    }

    async fn admit_federated_room_stream<F>(
        &self,
        request: FederatedMamStreamRequest<'_>,
        render: F,
    ) -> Result<FederatedMamAdmissionOutcome>
    where
        F: FnOnce(&FederatedMamStreamPage) -> Result<Vec<String>> + Send,
    {
        self.mam_service()
            .admit_federated_room_stream(request, render)
            .await
    }

    fn admit_muc_pg_mutation(&self) -> Result<()> {
        AppState::admit_muc_pg_mutation(self)
    }

    fn archive_requires_encryption(&self) -> bool {
        AppState::archive_requires_encryption(self)
    }

    async fn blocked_muc_recipient_accounts(
        &self,
        occupants: &[MucOccupant],
        stanza_senders: &[String],
    ) -> std::collections::HashSet<String> {
        AppState::blocked_muc_recipient_accounts(self, occupants, stanza_senders).await
    }

    async fn cache_committed_muc_join(
        &self,
        occupant: &SerializableMucOccupant,
        capacity: usize,
    ) -> Result<MucJoinCacheAttempt> {
        AppState::cache_committed_muc_join(self, occupant, capacity).await
    }

    async fn cached_muc_cluster_occupants(&self, room: &str) -> Result<HashMap<String, String>> {
        AppState::cached_muc_cluster_occupants(self, room).await
    }

    async fn change_cluster_muc_affiliation_exact(
        &self,
        room: &str,
        occupant: &SerializableMucOccupant,
        affiliation: &str,
        role: &str,
    ) -> Result<MucRoleChange> {
        AppState::change_cluster_muc_affiliation_exact(self, room, occupant, affiliation, role)
            .await
    }

    async fn change_cluster_muc_role_exact(
        &self,
        room: &str,
        occupant: &SerializableMucOccupant,
        role: &str,
    ) -> Result<MucRoleChange> {
        AppState::change_cluster_muc_role_exact(self, room, occupant, role).await
    }

    async fn deliver_muc_primary_to_remote_node(
        &self,
        target: &str,
        stanza: &str,
        durable: Option<DurableDelivery>,
    ) -> Option<NodeDeliveryReceipt> {
        AppState::deliver_muc_primary_to_remote_node(self, target, stanza, durable).await
    }

    async fn deliver_to_muc_occupant(&self, occupant: &MucOccupant, stanza: String) -> bool {
        AppState::deliver_to_muc_occupant(self, occupant, stanza).await
    }

    async fn deliver_to_muc_occupant_unchecked(
        &self,
        occupant: &MucOccupant,
        stanza: String,
    ) -> bool {
        AppState::deliver_to_muc_occupant_unchecked(self, occupant, stanza).await
    }

    async fn dispatch_push_notification(&self, recipient_id: uuid::Uuid) -> Result<()> {
        AppState::dispatch_push_notification(self, recipient_id).await
    }

    async fn evict_cluster_muc_occupant(
        &self,
        occupant: &SerializableMucOccupant,
        status: u16,
        actor_nick: Option<&str>,
        reason: Option<&str>,
    ) -> Result<()> {
        AppState::evict_cluster_muc_occupant(self, occupant, status, actor_nick, reason).await
    }

    fn federated_muc_admit_mutation(&self) -> Result<()> {
        AppState::federated_muc_admit_mutation(self)
    }

    async fn federated_muc_change_occupant_affiliation(
        &self,
        room_jid: &str,
        occupant: &SerializableMucOccupant,
        affiliation: &str,
        role: &str,
    ) -> Result<MucRoleChange> {
        AppState::federated_muc_change_occupant_affiliation(
            self,
            room_jid,
            occupant,
            affiliation,
            role,
        )
        .await
    }

    async fn federated_muc_change_occupant_policy(
        &self,
        room_jid: &str,
        occupant: &SerializableMucOccupant,
        role: &str,
        room_non_anonymous: bool,
    ) -> Result<MucRoleChange> {
        AppState::federated_muc_change_occupant_policy(
            self,
            room_jid,
            occupant,
            role,
            room_non_anonymous,
        )
        .await
    }

    async fn federated_muc_change_occupant_role(
        &self,
        room_jid: &str,
        occupant: &SerializableMucOccupant,
        role: &str,
    ) -> Result<MucRoleChange> {
        AppState::federated_muc_change_occupant_role(self, room_jid, occupant, role).await
    }

    async fn federated_muc_evict_occupant(
        &self,
        occupant: &SerializableMucOccupant,
        status: u16,
        actor_nick: Option<&str>,
        reason: Option<&str>,
    ) -> Result<bool> {
        AppState::federated_muc_evict_occupant(self, occupant, status, actor_nick, reason).await
    }

    async fn federated_muc_global_occupants(
        &self,
        room_jid: &str,
    ) -> Result<HashMap<String, String>> {
        AppState::federated_muc_global_occupants(self, room_jid).await
    }

    async fn federated_muc_join_room(&self, room_jid: &str) -> Result<()> {
        AppState::federated_muc_join_room(self, room_jid).await
    }

    async fn federated_muc_leave_room(&self, room_jid: &str) -> Result<()> {
        AppState::federated_muc_leave_room(self, room_jid).await
    }

    fn federated_muc_occupants_for_closed_connection(
        &self,
        authenticated_domain: &str,
        connection_id: uuid::Uuid,
    ) -> Vec<MucOccupant> {
        AppState::federated_muc_occupants_for_closed_connection(
            self,
            authenticated_domain,
            connection_id,
        )
    }

    fn federated_muc_owner_node_id(&self) -> &str {
        AppState::federated_muc_owner_node_id(self)
    }

    fn federated_muc_pg_authority_enabled(&self) -> bool {
        AppState::federated_muc_pg_authority_enabled(self)
    }

    async fn federated_muc_publish_nickname_change(
        &self,
        room_jid: &str,
        old_occupant: &SerializableMucOccupant,
        new_occupant: &SerializableMucOccupant,
        id: Option<&str>,
    ) -> Result<()> {
        AppState::federated_muc_publish_nickname_change(
            self,
            room_jid,
            old_occupant,
            new_occupant,
            id,
        )
        .await
    }

    async fn federated_muc_publish_presence(
        &self,
        room_jid: &str,
        occupant: &SerializableMucOccupant,
        unavailable: bool,
        created: bool,
        id: Option<&str>,
    ) -> Result<()> {
        AppState::federated_muc_publish_presence(self, room_jid, occupant, unavailable, created, id)
            .await
    }

    async fn federated_muc_publish_private_message(
        &self,
        room_jid: &str,
        target_nick: &str,
        stanza: &str,
        real_sender: &str,
    ) -> Result<()> {
        AppState::federated_muc_publish_private_message(
            self,
            room_jid,
            target_nick,
            stanza,
            real_sender,
        )
        .await
    }

    async fn federated_muc_publish_removal_presence(
        &self,
        room_jid: &str,
        occupant: &SerializableMucOccupant,
        status: Option<u16>,
        actor_nick: Option<&str>,
        reason: Option<&str>,
    ) -> Result<()> {
        AppState::federated_muc_publish_removal_presence(
            self, room_jid, occupant, status, actor_nick, reason,
        )
        .await
    }

    async fn federated_muc_publish_room_message(
        &self,
        room_jid: &str,
        stanza: &str,
        real_sender: Option<&str>,
    ) -> Result<()> {
        AppState::federated_muc_publish_room_message(self, room_jid, stanza, real_sender).await
    }

    fn federated_muc_redis_transport_enabled(&self) -> bool {
        AppState::federated_muc_redis_transport_enabled(self)
    }

    async fn federated_muc_register_occupant(
        &self,
        room_jid: &str,
        nick: &str,
        json: &str,
    ) -> Result<bool> {
        AppState::federated_muc_register_occupant(self, room_jid, nick, json).await
    }

    async fn federated_muc_rename_occupant(
        &self,
        room_jid: &str,
        old_nick: &str,
        new_nick: &str,
        expected_epoch: uuid::Uuid,
        old_json: &str,
        new_json: &str,
    ) -> Result<MucRename> {
        AppState::federated_muc_rename_occupant(
            self,
            room_jid,
            old_nick,
            new_nick,
            expected_epoch,
            old_json,
            new_json,
        )
        .await
    }

    fn federated_muc_telemetry(&self) -> northstar_room_core::telemetry::FederatedMucTelemetry<'_> {
        AppState::federated_muc_telemetry(self)
    }

    async fn join_cluster_muc_room(&self, room: &str) -> Result<()> {
        AppState::join_cluster_muc_room(self, room).await
    }

    async fn leave_cluster_muc_room(&self, room: &str) -> Result<()> {
        AppState::leave_cluster_muc_room(self, room).await
    }

    fn local_domain(&self) -> &str {
        AppState::local_domain(self)
    }

    fn local_muc_occupant_by_nick(&self, room_jid: &str, nick: &str) -> Option<MucOccupant> {
        AppState::local_muc_occupant_by_nick(self, room_jid, nick)
    }

    fn local_muc_occupant_exact(
        &self,
        identity: LocalMucOccupantIdentity<'_>,
    ) -> Option<MucOccupant> {
        AppState::local_muc_occupant_exact(self, identity)
    }

    fn mix_muc_mirror_enabled(&self) -> bool {
        AppState::mix_muc_mirror_enabled(self)
    }

    fn move_local_muc_nickname_exact(
        &self,
        old: LocalMucOccupantIdentity<'_>,
        renamed: &MucOccupant,
        cluster_committed: bool,
    ) -> LocalMucNicknameMove {
        AppState::move_local_muc_nickname_exact(self, old, renamed, cluster_committed)
    }

    fn muc_cluster_node_id(&self) -> &str {
        AppState::muc_cluster_node_id(self)
    }

    fn muc_mam_retention_days(&self) -> i64 {
        AppState::muc_mam_retention_days(self)
    }

    fn muc_occupants_for(&self, room_jid: &str) -> Vec<(String, MucOccupant)> {
        AppState::muc_occupants_for(self, room_jid)
    }

    fn muc_pg_authority_enabled(&self) -> bool {
        AppState::muc_pg_authority_enabled(self)
    }

    fn muc_redis_transport_enabled(&self) -> bool {
        AppState::muc_redis_transport_enabled(self)
    }

    fn muc_telemetry(&self) -> northstar_room_core::telemetry::MucTelemetry<'_> {
        AppState::muc_telemetry(self)
    }

    fn offline_delivery_limits(&self) -> OfflineDeliveryLimits {
        AppState::offline_delivery_limits(self)
    }

    fn publish_local_muc_join_if_vacant(&self, joining: &MucOccupant) -> LocalMucJoinPublication {
        AppState::publish_local_muc_join_if_vacant(self, joining)
    }

    async fn publish_muc_cluster_nickname_change(
        &self,
        room: &str,
        before: &SerializableMucOccupant,
        after: &SerializableMucOccupant,
        id: Option<&str>,
    ) -> Result<()> {
        AppState::publish_muc_cluster_nickname_change(self, room, before, after, id).await
    }

    async fn publish_muc_cluster_presence(
        &self,
        publication: MucPresencePublication<'_>,
    ) -> Result<()> {
        AppState::publish_muc_cluster_presence(self, publication).await
    }

    async fn publish_muc_cluster_presence_with_id(
        &self,
        room: &str,
        occupant: &SerializableMucOccupant,
        unavailable: bool,
        created: bool,
        id: Option<&str>,
    ) -> Result<()> {
        AppState::publish_muc_cluster_presence_with_id(
            self,
            room,
            occupant,
            unavailable,
            created,
            id,
        )
        .await
    }

    async fn publish_muc_cluster_private_message(
        &self,
        room: &str,
        nick: &str,
        stanza: &str,
        real_sender: &str,
    ) -> Result<()> {
        AppState::publish_muc_cluster_private_message(self, room, nick, stanza, real_sender).await
    }

    async fn publish_muc_cluster_stanza(
        &self,
        room: &str,
        stanza: &str,
        real_sender: Option<&str>,
    ) -> Result<()> {
        AppState::publish_muc_cluster_stanza(self, room, stanza, real_sender).await
    }

    fn rebind_local_federated_muc_occupant_exact(
        &self,
        old: &MucOccupant,
        new_connection_id: uuid::Uuid,
    ) -> Option<MucOccupant> {
        AppState::rebind_local_federated_muc_occupant_exact(self, old, new_connection_id)
    }

    fn record_muc_cluster_control_plane_failure(&self, error: &anyhow::Error) {
        AppState::record_muc_cluster_control_plane_failure(self, error)
    }

    fn refresh_local_muc_policy_exact(
        &self,
        identity: LocalMucOccupantIdentity<'_>,
        moderated: Option<bool>,
        non_anonymous: Option<bool>,
    ) -> Option<(MucOccupant, bool)> {
        AppState::refresh_local_muc_policy_exact(self, identity, moderated, non_anonymous)
    }

    fn refresh_local_muc_presence_exact(
        &self,
        prepared: &MucOccupant,
        apply_policy: bool,
    ) -> Option<MucOccupant> {
        AppState::refresh_local_muc_presence_exact(self, prepared, apply_policy)
    }

    async fn register_cluster_muc_occupant(
        &self,
        room: &str,
        nick: &str,
        json: &str,
    ) -> Result<bool> {
        AppState::register_cluster_muc_occupant(self, room, nick, json).await
    }

    async fn remove_exact_muc_soft_state(&self, occupant: &MucOccupant) -> Result<bool> {
        AppState::remove_exact_muc_soft_state(self, occupant).await
    }

    fn remove_live_muc_membership(&self, occupant: &SerializableMucOccupant) -> bool {
        AppState::remove_live_muc_membership(self, occupant)
    }

    fn remove_local_muc_occupant_exact(
        &self,
        identity: LocalMucOccupantIdentity<'_>,
    ) -> Option<MucOccupant> {
        AppState::remove_local_muc_occupant_exact(self, identity)
    }

    async fn rename_cluster_muc_occupant_exact(
        &self,
        room: &str,
        old_nick: &str,
        new_nick: &str,
        expected_epoch: uuid::Uuid,
        old_json: &str,
        new_json: &str,
    ) -> Result<MucRename> {
        AppState::rename_cluster_muc_occupant_exact(
            self,
            room,
            old_nick,
            new_nick,
            expected_epoch,
            old_json,
            new_json,
        )
        .await
    }

    async fn revoke_cluster_muc_occupant_exact(
        &self,
        occupant: &SerializableMucOccupant,
        status: u16,
        actor_nick: Option<&str>,
        reason: Option<&str>,
    ) -> Result<bool> {
        AppState::revoke_cluster_muc_occupant_exact(self, occupant, status, actor_nick, reason)
            .await
    }

    async fn route_federated_muc_account_message_remote(
        &self,
        target_jid: &str,
        stanza: &str,
        delivery: Option<DurableDelivery>,
    ) -> Option<FederatedMucAccountRoute> {
        AppState::route_federated_muc_account_message_remote(self, target_jid, stanza, delivery)
            .await
    }

    fn server_name(&self) -> &str {
        AppState::server_name(self)
    }

    fn set_local_muc_affiliation_exact(
        &self,
        identity: LocalMucOccupantIdentity<'_>,
        affiliation: &str,
        moderated: bool,
        only_if_none: bool,
        expected_affiliation: Option<&str>,
    ) -> Option<MucOccupant> {
        AppState::set_local_muc_affiliation_exact(
            self,
            identity,
            affiliation,
            moderated,
            only_if_none,
            expected_affiliation,
        )
    }

    fn set_local_muc_role_exact(
        &self,
        identity: LocalMucOccupantIdentity<'_>,
        expected_role: &str,
        role: &str,
        non_anonymous: Option<bool>,
    ) -> Option<MucOccupant> {
        AppState::set_local_muc_role_exact(self, identity, expected_role, role, non_anonymous)
    }

    fn validate_routed_message(&self, root: roxmltree::Node<'_, '_>) -> Result<(), &'static str> {
        AppState::validate_routed_message(self, root)
    }

    fn validated_local_muc_occupant(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
        room_jid: &str,
        membership: &JoinedMucMembership,
    ) -> Option<MucOccupant> {
        AppState::validated_local_muc_occupant(self, full_jid, connection_id, room_jid, membership)
    }

    async fn wake_committed_muc_operation(&self, operation_id: uuid::Uuid) -> anyhow::Result<()> {
        AppState::wake_committed_muc_operation(self, operation_id).await
    }

    fn xmpp_extension_enabled(&self, id: northstar_xep_core::XepId) -> bool {
        AppState::xmpp_extension_enabled(self, id)
    }

    fn xmpp_external_route_domain_allowed(&self, domain: &str) -> bool {
        AppState::xmpp_external_route_domain_allowed(self, domain)
    }
}
