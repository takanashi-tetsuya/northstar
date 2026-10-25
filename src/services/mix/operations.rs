//! Implements MIX application queries, control operations, query types, and input validation.

use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MixEvent {
    pub(crate) id: Uuid,
    pub(crate) item_id: String,
    pub(crate) payload: String,
    pub(crate) created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MixEventPage {
    pub(crate) events: Vec<MixEvent>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MixReadOutcome<T> {
    Found(T),
    Unauthorized,
    NotFound,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MixMamPage {
    pub(crate) events: Vec<MixEvent>,
    pub(crate) total: i64,
    pub(crate) first_index: i64,
    pub(crate) complete: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MixPresenceItem {
    pub(crate) item_id: String,
    pub(crate) payload: String,
    pub(crate) source_full_jid: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MixPresenceProbeTarget {
    pub(crate) channel_jid: String,
    pub(crate) participant_jid: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MixDiscoPage {
    pub(crate) channels: Vec<MixChannel>,
    pub(crate) total: i64,
    pub(crate) first_index: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ArchiveBoundary {
    pub(crate) id: Uuid,
    pub(crate) created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub(crate) struct VCardRecord {
    pub(crate) payload_vcard_temp: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PepNodeConfig {
    pub(crate) access_model: String,
    pub(crate) max_items: i32,
    pub(crate) persist_items: bool,
    pub(crate) send_last_published_item: String,
    pub(crate) deliver_notifications: bool,
    pub(crate) roster_groups_allowed: Vec<String>,
    pub(crate) access_whitelist: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MixMucMirror {
    pub(crate) mix_channel_id: Uuid,
    pub(crate) muc_room_id: Uuid,
    pub(crate) localpart: String,
    pub(crate) mix_domain: String,
}

/// MIX-owned XEP-0059 page selector. The MAM slice keeps its own vocabulary;
/// MIX parses the same forms into this boundary type so the repository never
/// receives a protocol-shaped query directly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MamRsmPage {
    First,
    Last,
    Before(Uuid),
    After(Uuid),
    /// XEP-0059 section 2.6 page retrieval by zero-based result index.
    /// The protocol parser applies a production bound before this reaches
    /// PostgreSQL; keeping it in the shared query type makes personal, MUC,
    /// federated-MUC and MIX archives use the same semantics.
    Index(i64),
}

/// MIX-owned archive query consumed by `mix_mam_page*`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MamArchiveQuery {
    pub(crate) with_jid: Option<String>,
    pub(crate) start: Option<DateTime<Utc>>,
    pub(crate) end: Option<DateTime<Utc>>,
    pub(crate) before_id: Option<Uuid>,
    pub(crate) after_id: Option<Uuid>,
    pub(crate) ids: Vec<Uuid>,
    pub(crate) page: MamRsmPage,
    pub(crate) max: i64,
}

/// Current cluster session-route ownership for a claimed durable MIX outbox row. The implementation reads
/// authority outside the claimed outbox transaction; it receives no publication or session-mutation authority.
pub(crate) trait MixClusterRouteLookup: Send + Sync {
    fn lookup_nodes<'a>(
        &'a self,
        jid: &'a str,
    ) -> impl std::future::Future<Output = Result<Vec<String>>> + Send + 'a;
}

impl<R: MixRepository> MixService<R> {
    /// Atomically link existing same-localpart MIX and MUC entities after the
    /// repository proves that the authenticated bare JID still owns both.
    /// The protocol receives only a typed business outcome, never the pool or
    /// the repository's cross-table mutation primitive.
    pub(crate) async fn link_local_muc_mirror(
        &self,
        mix_domain: &str,
        localpart: &str,
        actor_bare_jid: &str,
        local_domain: &str,
    ) -> Result<MixMucLinkOutcome> {
        self.repository
            .link_local_muc_mirror(mix_domain, localpart, actor_bare_jid, local_domain)
            .await
    }

    pub(crate) async fn create_mix_channel(
        &self,
        service_domain: &str,
        requested_localpart: Option<&str>,
        creator_jid: &str,
        max_channels_per_owner: i64,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<(CreateChannelOutcome, String)> {
        self.repository
            .create_mix_channel(
                service_domain,
                requested_localpart,
                creator_jid,
                max_channels_per_owner,
                federated,
            )
            .await
    }
    pub(crate) async fn mix_channel(
        &self,
        service_domain: &str,
        localpart: &str,
    ) -> Result<Option<MixChannel>> {
        self.repository.mix_channel(service_domain, localpart).await
    }
    pub(crate) async fn discoverable_mix_channel_page(
        &self,
        service_domain: &str,
        requester: &str,
        after: Option<&str>,
        before: Option<Option<&str>>,
        max: i64,
    ) -> Result<Option<MixDiscoPage>> {
        self.repository
            .discoverable_mix_channel_page(service_domain, requester, after, before, max)
            .await
    }
    pub(crate) async fn mix_role(&self, channel_id: Uuid, jid: &str) -> Result<Option<String>> {
        self.repository.mix_role(channel_id, jid).await
    }
    pub(crate) async fn mix_channel_discoverable_to(
        &self,
        channel: &MixChannel,
        actor: &str,
    ) -> Result<bool> {
        self.repository
            .mix_channel_discoverable_to(channel, actor)
            .await
    }

    pub(crate) async fn mix_participant(
        &self,
        channel_id: Uuid,
        jid: &str,
    ) -> Result<Option<MixParticipant>> {
        self.repository.mix_participant(channel_id, jid).await
    }
    pub(crate) async fn mix_participant_by_id(
        &self,
        channel_id: Uuid,
        participant_id: Uuid,
    ) -> Result<Option<MixParticipant>> {
        self.repository
            .mix_participant_by_id(channel_id, participant_id)
            .await
    }
    pub(crate) async fn mix_presence_source_jid(
        &self,
        channel_id: Uuid,
        item_id: &str,
    ) -> Result<Option<String>> {
        self.repository
            .mix_presence_source_jid(channel_id, item_id)
            .await
    }

    /// Consult the immutable replay commitment before any mutable participant
    /// or permission check. A miss never writes; first execution is still
    /// admitted only inside the channel transaction.
    pub(crate) async fn lookup_mix_message_replay(
        &self,
        channel_id: Uuid,
        actor: &str,
        identity: &MixReplayIdentity,
    ) -> Result<MixBusinessReplay> {
        let authenticators = self
            .message_identity
            .authenticators(&identity.canonical_semantics);
        self.repository
            .lookup_mix_message_replay(channel_id, actor, identity, &authenticators)
            .await
    }

    pub(crate) async fn lookup_mix_retraction_replay(
        &self,
        channel_id: Uuid,
        actor: &str,
        target_id: Uuid,
        identity: &MixReplayIdentity,
    ) -> Result<MixBusinessReplay> {
        let authenticators = self
            .retraction_identity
            .authenticators(&identity.canonical_semantics);
        self.repository
            .lookup_mix_retraction_replay(channel_id, actor, target_id, identity, &authenticators)
            .await
    }
    pub(crate) async fn authorized_mix_event_page(
        &self,
        channel_id: Uuid,
        actor: &str,
        node: &str,
        before: Option<(DateTime<Utc>, Uuid)>,
        limit: i64,
    ) -> Result<MixReadOutcome<MixEventPage>> {
        self.repository
            .authorized_mix_event_page(channel_id, actor, node, before, limit)
            .await
    }

    pub(crate) async fn authorized_mix_mam_page(
        &self,
        channel_id: Uuid,
        actor: &str,
        viewer_id: Option<Uuid>,
        query: &MamArchiveQuery,
    ) -> Result<MixReadOutcome<MixMamPage>> {
        self.repository
            .authorized_mix_mam_page(channel_id, actor, viewer_id, query)
            .await
    }
    pub(crate) async fn authorized_mix_mam_boundaries(
        &self,
        channel_id: Uuid,
        actor: &str,
        viewer_id: Option<Uuid>,
    ) -> Result<MixReadOutcome<(Option<ArchiveBoundary>, Option<ArchiveBoundary>)>> {
        self.repository
            .authorized_mix_mam_boundaries(channel_id, actor, viewer_id)
            .await
    }
    pub(crate) async fn authorized_mix_access_entries(
        &self,
        channel_id: Uuid,
        actor: &str,
        banned: bool,
        limit: i64,
    ) -> Result<MixReadOutcome<Vec<String>>> {
        self.repository
            .authorized_mix_access_entries(channel_id, actor, banned, limit)
            .await
    }

    pub(crate) async fn mix_participant_preference(
        &self,
        channel_id: Uuid,
        actor: &str,
    ) -> Result<Option<MixParticipantPreference>> {
        self.repository
            .mix_participant_preference(channel_id, actor)
            .await
    }

    pub(crate) async fn authorized_mix_jid_map_entries(
        &self,
        channel_id: Uuid,
        actor: &str,
        limit: i64,
    ) -> Result<MixReadOutcome<Vec<(String, String)>>> {
        self.repository
            .authorized_mix_jid_map_entries(channel_id, actor, limit)
            .await
    }
    pub(crate) async fn issue_mix_invitation(
        &self,
        channel_id: Uuid,
        inviter: &str,
        invitee: &str,
        token: &str,
        lifetime: chrono::Duration,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<bool> {
        self.repository
            .issue_mix_invitation(channel_id, inviter, invitee, token, lifetime, federated)
            .await
    }
    pub(crate) async fn mix_private_message_recipient(
        &self,
        channel_id: Uuid,
        sender: &str,
        recipient_id: Uuid,
    ) -> Result<Option<(MixParticipant, MixParticipant)>> {
        self.repository
            .mix_private_message_recipient(channel_id, sender, recipient_id)
            .await
    }

    pub(crate) async fn lookup_remote_pam_operation(
        &self,
        user_id: Uuid,
        requester_full_jid: &str,
        client_request_id: &str,
        request_digest: &[u8; 32],
    ) -> Result<PamOperationReplay> {
        self.repository
            .lookup_remote_pam_operation(
                user_id,
                requester_full_jid,
                client_request_id,
                request_digest,
            )
            .await
    }

    pub(crate) async fn complete_remote_pam_success(
        &self,
        authenticated_domain: &str,
        channel_jid: &str,
        recipient_bare: &str,
        request_id: &str,
        response_digest: &[u8; 32],
        join: Option<RemotePamJoin<'_>>,
    ) -> Result<RemotePamCompletionOutcome> {
        self.repository
            .complete_remote_pam_success(
                authenticated_domain,
                channel_jid,
                recipient_bare,
                request_id,
                response_digest,
                join,
            )
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn complete_remote_pam_error(
        &self,
        authenticated_domain: &str,
        channel_jid: &str,
        recipient_bare: &str,
        request_id: &str,
        response_digest: &[u8; 32],
        error_type: &str,
        condition: &str,
    ) -> Result<RemotePamCompletionOutcome> {
        self.repository
            .complete_remote_pam_error(
                authenticated_domain,
                channel_jid,
                recipient_bare,
                request_id,
                response_digest,
                error_type,
                condition,
            )
            .await
    }
    pub(crate) async fn pam_memberships(&self, user_id: Uuid) -> Result<Vec<PamMembership>> {
        self.repository.pam_memberships(user_id).await
    }
    pub(crate) async fn pam_membership(
        &self,
        user_id: Uuid,
        channel_jid: &str,
    ) -> Result<Option<PamMembership>> {
        self.repository.pam_membership(user_id, channel_jid).await
    }
    pub(crate) async fn local_pam_users_for_channel(&self, channel_jid: &str) -> Result<Vec<Uuid>> {
        self.repository
            .local_pam_users_for_channel(channel_jid)
            .await
    }

    pub(crate) async fn find_enabled_user(&self, username: &str) -> Result<Option<MixAccount>> {
        self.repository.find_enabled_user(username).await
    }

    pub(crate) async fn find_enabled_user_by_id(
        &self,
        user_id: Uuid,
    ) -> Result<Option<MixAccount>> {
        self.repository.find_enabled_user_by_id(user_id).await
    }
    pub(crate) async fn is_blocked(&self, owner_id: Uuid, candidate: &str) -> Result<bool> {
        self.repository.is_blocked(owner_id, candidate).await
    }

    /// Resolve the cluster authority route for a claimed durable outbox row.
    ///
    /// The route handle reads PostgreSQL's current session ownership outside
    /// the claimed outbox transaction. Do not retain a scarce outbox database
    /// admission permit while this separate authority read is pending.
    pub(crate) async fn outbox_lookup_cluster_nodes(
        &self,
        routes: &impl MixClusterRouteLookup,
        jid: &str,
    ) -> Result<Vec<String>> {
        routes.lookup_nodes(jid).await
    }

    pub(crate) async fn pep_node(
        &self,
        owner_id: Uuid,
        node: &str,
    ) -> Result<Option<PepNodeConfig>> {
        self.repository.pep_node(owner_id, node).await
    }
    pub(crate) async fn pep_items(
        &self,
        owner_id: Uuid,
        node: &str,
        item_id: Option<&str>,
        limit: i64,
    ) -> Result<Vec<(String, String)>> {
        self.repository
            .pep_items(owner_id, node, item_id, limit)
            .await
    }
    pub(crate) async fn get_vcard(&self, user_id: Uuid) -> Result<VCardRecord> {
        self.repository.get_vcard(user_id).await
    }
    pub(crate) async fn latest_roster_change_for_contact(
        &self,
        user_id: Uuid,
        contact_jid: &str,
    ) -> Result<Option<northstar_roster_core::RosterChange>> {
        self.repository
            .latest_roster_change_for_contact(user_id, contact_jid)
            .await
    }
    pub(crate) async fn mix_muc_mirror_for_mix(
        &self,
        mix_channel_id: Uuid,
    ) -> Result<Option<MixMucMirror>> {
        self.repository.mix_muc_mirror_for_mix(mix_channel_id).await
    }
    pub(crate) async fn mix_muc_mirror_for_muc(
        &self,
        muc_room_id: Uuid,
    ) -> Result<Option<MixMucMirror>> {
        self.repository.mix_muc_mirror_for_muc(muc_room_id).await
    }
    pub(crate) async fn mix_muc_mirror_service_complete(&self, mix_domain: &str) -> Result<bool> {
        self.repository
            .mix_muc_mirror_service_complete(mix_domain)
            .await
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn archive_mix_message_once(
        &self,
        personal_archive_id: Uuid,
        owner_id: Uuid,
        channel_jid: &str,
        authoritative_stanza_id: Uuid,
        stanza: &str,
        encrypted: bool,
        client_stanza_id: Option<&str>,
    ) -> Result<SourceArchiveAdmission> {
        self.repository
            .archive_mix_message_once(
                personal_archive_id,
                owner_id,
                channel_jid,
                authoritative_stanza_id,
                stanza,
                encrypted,
                client_stanza_id,
            )
            .await
    }

    /// Admit one ordered federation response stream atomically. A capacity or
    /// validation failure rolls the complete stream back, so the remote peer
    /// cannot observe a MAM prefix without its terminal result (or vice versa).
    pub(crate) async fn enqueue_s2s_response_batch(
        &self,
        target_domain: &str,
        responses: &[String],
        policy: S2sOutboxPolicy,
    ) -> Result<()> {
        self.repository
            .enqueue_s2s_response_batch(target_domain, responses, policy)
            .await
    }

    pub(crate) async fn federated_mix_iq_replay(
        &self,
        authenticated_domain: &str,
        actor_jid: &str,
        request_id: &str,
        request_digest: &[u8; 32],
    ) -> Result<FederatedMixIqReplay> {
        self.repository
            .federated_mix_iq_replay(authenticated_domain, actor_jid, request_id, request_digest)
            .await
    }

    pub(crate) async fn admit_federated_mix_iq_result(
        &self,
        authenticated_domain: &str,
        actor_jid: &str,
        request_id: &str,
        request_digest: &[u8; 32],
        response: &str,
        policy: S2sOutboxPolicy,
    ) -> Result<FederatedMixIqReplay> {
        self.repository
            .admit_federated_mix_iq_result(
                authenticated_domain,
                actor_jid,
                request_id,
                request_digest,
                response,
                policy,
            )
            .await
    }
}

pub(crate) fn valid_stable_participant_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1023
        && !value.contains('@')
        && !value.contains('/')
        && !value.contains('#')
}
pub(crate) fn mix_timestamp_item_id() -> String {
    Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)
}
pub(crate) fn valid_join_nodes(nodes: &[String]) -> Result<Vec<String>> {
    let mut unique = std::collections::BTreeSet::new();
    anyhow::ensure!(
        nodes.len() <= SUBSCRIBABLE_NODES.len(),
        "too many MIX subscriptions"
    );
    for node in nodes {
        anyhow::ensure!(
            SUBSCRIBABLE_NODES.contains(&node.as_str()),
            "unknown MIX subscription node"
        );
        unique.insert(node.clone());
    }
    Ok(unique.into_iter().collect())
}
pub(crate) fn prepare_mix_nick(nick: &str) -> Result<String> {
    northstar_xmpp_types::jid::prepare_resourcepart(nick)
}
pub(crate) fn canonical_mix_access_pattern(pattern: &str) -> Result<String> {
    northstar_xmpp_types::jid::CanonicalJid::parse_bare(pattern).map(|jid| jid.to_string())
}
pub(crate) fn participant_jid_visible(
    channel: &MixChannel,
    preference: &MixParticipantPreference,
) -> bool {
    match channel.jid_visibility.as_str() {
        "visible" => true,
        "hidden" => false,
        "maybe" => preference.jid_visibility == "always",
        _ => false,
    }
}
