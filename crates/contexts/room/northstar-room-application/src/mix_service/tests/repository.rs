use super::*;
use northstar_delivery_core::{bosh_ownership, native_write, MixDelivery};
use std::sync::Mutex as RecordingMutex;

#[derive(Clone, Copy, Default)]
pub(super) enum Reply {
    #[default]
    Error,
    Stored(bool),
    PendingCommit,
    ReturnedOnly,
    Bool(bool),
    Worker,
    Settlement(outbox::core::SettlementResult),
}

#[derive(Clone, Default)]
pub(super) struct Repository {
    pub calls: Arc<RecordingMutex<Vec<String>>>,
    pub reply: Reply,
    pub pause: Option<Arc<tokio::sync::Semaphore>>,
    pub request_address: Option<usize>,
}

impl Repository {
    pub fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }

    async fn record(&self, call: String) -> Result<()> {
        self.calls.lock().unwrap().push(call);
        if let Some(pause) = &self.pause {
            pause.acquire().await.unwrap().forget();
        }
        if matches!(self.reply, Reply::Error) {
            anyhow::bail!("recorded repository failure");
        }
        Ok(())
    }

    async fn reject<T>(&self, call: String) -> Result<T> {
        self.record(call).await?;
        anyhow::bail!("recorded repository failure")
    }

    fn same_request<T>(&self, request: &T) {
        assert_eq!(
            self.request_address,
            Some(std::ptr::from_ref(request) as usize)
        );
    }
}

// All unrelated ports fail loudly; the tested ports below record their inputs.
macro_rules! unused_ports {
    ($($name:ident($($arg:ident: $ty:ty),*) -> $result:ty;)*) => {
        $(#[allow(clippy::too_many_arguments)]
        async fn $name(&self, $($arg: $ty),*) -> Result<$result> {
            $(let _ = $arg;)*
            panic!("unused repository port: {}", stringify!($name));
        })*
    };
}

macro_rules! recording_ports {
    ($($name:ident($($arg:ident: $ty:ty),*) -> $result:ty;)*) => {
        $(async fn $name(&self, $($arg: $ty),*) -> Result<$result> {
            self.reject(format!("{}:{:?}", stringify!($name), ($($arg,)*))).await
        })*
    };
}

impl MixRepository for Repository {
    recording_ports! {
        destroy_mix_channel(channel_id: Uuid, actor: &str, federated: Option<&FederatedMixMutation>) -> bool;
        join_mix_channel(channel_id: Uuid, request: JoinMixRequest, federated: Option<&FederatedMixMutation>) -> JoinChannelOutcome;
        expire_unrefreshed_mix_presence(cutoff: DateTime<Utc>) -> Vec<ExpiredMixPresence>;
        update_mix_subscriptions(channel_id: Uuid, actor: &str, subscribe: &[String], unsubscribe: &[String], federated: Option<&FederatedMixMutation>) -> Option<UpdateSubscriptionsOutcome>;
        set_mix_nick(channel_id: Uuid, actor: &str, nick: &str, federated: Option<&FederatedMixMutation>) -> std::result::Result<MixParticipant, SetNickError>;
        leave_mix_channel(channel_id: Uuid, actor: &str, pam_user_id: Option<Uuid>, federated: Option<&FederatedMixMutation>) -> Option<LeaveMixOutcome>;
        store_mix_presence(channel_id: Uuid, actor_bare: &str, actor_full: &str, payload: &str, unavailable: bool) -> PresenceOutcome;
        ensure_mix_presence(channel_id: Uuid, actor_bare: &str, actor_full: &str, payload: &str) -> PresenceOutcome;
        publish_mix_avatar(channel_id: Uuid, actor: &str, node: &str, item_id: &str, payload: &str, federated: Option<&FederatedMixMutation>) -> bool;
        retract_mix_avatar(channel_id: Uuid, actor: &str, node: &str, item_id: &str, federated: Option<&FederatedMixMutation>) -> bool;
        update_mix_info(channel_id: Uuid, actor: &str, update: MixInfoUpdate, federated: Option<&FederatedMixMutation>) -> MixMutationOutcome;
        update_mix_config(channel_id: Uuid, actor: &str, update: MixConfigUpdate, roles: MixRoleUpdate, federated: Option<&FederatedMixMutation>) -> MixMutationOutcome;
        set_mix_access_entry(update: MixAccessEntryUpdate<'_>, federated: Option<&FederatedMixMutation>) -> Option<AccessChangeOutcome>;
        register_mix_nick(service_domain: &str, actor: &str, nick: &str, federated: Option<&FederatedMixMutation>) -> RegisterMixNickOutcome;
        update_mix_participant_preference(channel_id: Uuid, actor: &str, preference: &MixParticipantPreference, federated: Option<&FederatedMixMutation>) -> Option<MixParticipantPreferenceUpdateOutcome>;
        begin_remote_pam_join(request: BeginRemotePamJoin) -> PamOperationReplay;
        begin_remote_pam_leave(request: BeginRemotePamLeave) -> PamOperationReplay;
        prune_expired_pam_results(limit: i64) -> u64;
        requeue_mix_delivery_dead_letter(dead_letter_id: Uuid) -> bool;
    }

    async fn store_mix_message(
        &self,
        request: StoreMixMessageRequest<'_>,
        authenticators: Option<&northstar_abuse_policy::ContentIdentityAuthenticators>,
    ) -> Result<StoreMixMessageAdmission> {
        assert!(authenticators.is_none());
        self.reject(format!(
            "store_mix_message:{:?}",
            (
                request.channel_id,
                request.actor,
                request.item_id,
                request.payload,
                request.identity,
                request.delivery_payload,
                request.visible_jid,
                request.encrypted
            )
        ))
        .await
    }

    async fn retract_mix_message(
        &self,
        request: RetractMixMessageRequest<'_>,
        authenticators: Option<&northstar_abuse_policy::ContentIdentityAuthenticators>,
    ) -> Result<RetractMixMessageAdmission> {
        assert!(authenticators.is_none());
        self.reject(format!(
            "retract_mix_message:{:?}",
            (
                request.channel_id,
                request.actor,
                request.target_id,
                request.retraction_id,
                request.tombstone_payload,
                request.retraction_payload,
                request.identity,
                request.visible_jid
            )
        ))
        .await
    }

    async fn store_mix_message_observed(
        &self,
        request: &foreground::StoreRequest,
        authenticators: Option<&northstar_abuse_policy::ContentIdentityAuthenticators>,
    ) -> Result<StoreMixMessageAdmission> {
        self.same_request(request);
        assert!(authenticators.is_none());
        assert_eq!(request.command(), &foreground::fixture::command(false));
        self.record("observed_store".into()).await?;
        let audience = match self.reply {
            Reply::Stored(audience) => Some(audience),
            Reply::PendingCommit => Some(true),
            _ => None,
        };
        if let Some(audience) = audience {
            crate::mix::commit_observed(
                async {
                    if matches!(self.reply, Reply::PendingCommit) {
                        std::future::pending::<()>().await;
                    }
                    Ok::<(), anyhow::Error>(())
                },
                request,
                foreground::fixture::stored(audience),
            )
            .await
            .map_err(|error| match error {
                crate::mix::CommitError::Observation(error) => anyhow::Error::from(error),
                crate::mix::CommitError::Commit(error) => error,
            })?;
            Ok(foreground::fixture::returned(audience))
        } else {
            Ok(foreground::fixture::returned(true))
        }
    }

    async fn lookup_mix_message_replay_observed(
        &self,
        request: &foreground::ReplayRequest,
        _authenticators: &northstar_abuse_policy::ContentIdentityAuthenticators,
    ) -> Result<MixBusinessReplay> {
        self.same_request(request);
        assert_eq!(
            request.ingress(),
            foreground::fixture::prepared(true).ingress()
        );
        self.record("observed_replay".into()).await?;
        request.observed_miss()?;
        Ok(MixBusinessReplay::Miss)
    }

    async fn acknowledge_mix_delivery(
        &self,
        delivery_id: Uuid,
        lease_token: Uuid,
        observation: Option<&native_write::AckRequest>,
    ) -> Result<bool> {
        if let Some(request) = observation {
            self.same_request(request);
            assert_eq!(
                request.source(),
                northstar_delivery_core::TransportOwnershipSource::Mix(MixDelivery {
                    delivery_id,
                    lease_token
                })
            );
        } else {
            assert!(self.request_address.is_none());
        }
        self.record(format!(
            "ack:{delivery_id}:{lease_token}:{}",
            observation.is_some()
        ))
        .await?;
        let Reply::Bool(result) = self.reply else {
            panic!("ack reply")
        };
        Ok(result)
    }

    async fn transfer_mix_delivery_to_bosh(
        &self,
        request: &bosh_ownership::TransferRequest,
    ) -> Result<MixDelivery> {
        self.same_request(request);
        request.validate_for_io()?;
        self.record(format!(
            "bosh:{:?}:{}:{}",
            request.source(),
            request.session_id(),
            request.ttl_seconds()
        ))
        .await?;
        Ok(MixDelivery {
            lease_token: Uuid::from_u128(103),
            ..request.source()
        })
    }

    async fn claim_mix_deliveries_observed(
        &self,
        request: &outbox::core::ClaimRequest,
    ) -> Result<outbox::core::Rows> {
        self.same_request(request);
        self.record(format!("claim:{:?}", request.command()))
            .await?;
        let entered = request.enter_statement()?;
        let rows = outbox::fixture::claimed_rows(false);
        request.received(entered, rows.clone())?;
        Ok(rows)
    }

    async fn archive_mix_message_once_observed(
        &self,
        request: &outbox::core::ArchiveRequest,
    ) -> Result<outbox::core::ArchiveResult> {
        self.same_request(request);
        self.record(format!("archive:{:?}", request.command()))
            .await?;
        let result = outbox::core::ArchiveResult::Stored(request.command().personal_archive_id);
        let entered = request.enter_commit(result)?;
        request.received(entered)?;
        Ok(result)
    }

    async fn renew_mix_delivery_lease_observed(
        &self,
        request: &outbox::core::RenewalRequest,
    ) -> Result<bool> {
        self.same_request(request);
        self.record(format!("renew:{:?}", request.source())).await?;
        let entered = request.enter_statement()?;
        request.received(entered, true)?;
        Ok(true)
    }

    async fn settle_mix_delivery_observed(
        &self,
        request: &outbox::core::SettlementRequest,
    ) -> Result<outbox::core::SettlementResult> {
        self.same_request(request);
        self.record(format!(
            "settle:{:?}:{:?}",
            request.source(),
            request.command()
        ))
        .await?;
        let Reply::Settlement(result) = self.reply else {
            panic!("settlement reply")
        };
        let entered = if matches!(
            request.command(),
            outbox::core::SettlementCommand::Defer { .. }
        ) {
            request.enter_statement()?
        } else {
            request.enter_commit(result)?
        };
        request.received(entered, result)?;
        Ok(result)
    }

    unused_ports! {
        link_local_muc_mirror(mix_domain: &str, localpart: &str, actor_bare_jid: &str, local_domain: &str) -> MixMucLinkOutcome;
        create_mix_channel(service_domain: &str, requested_localpart: Option<&str>, creator_jid: &str, max_channels_per_owner: i64, federated: Option<&FederatedMixMutation>) -> (CreateChannelOutcome, String);
        mix_channel(service_domain: &str, localpart: &str) -> Option<MixChannel>;
        discoverable_mix_channel_page(service_domain: &str, requester: &str, after: Option<&str>, before: Option<Option<&str>>, max: i64) -> Option<MixDiscoPage>;
        mix_role(channel_id: Uuid, jid: &str) -> Option<String>;
        mix_channel_discoverable_to(channel: &MixChannel, actor: &str) -> bool;
        mix_participant(channel_id: Uuid, jid: &str) -> Option<MixParticipant>;
        mix_participant_by_id(channel_id: Uuid, participant_id: Uuid) -> Option<MixParticipant>;
        mix_presence_source_jid(channel_id: Uuid, item_id: &str) -> Option<String>;
        lookup_mix_message_replay(channel_id: Uuid, actor: &str, identity: &MixReplayIdentity, authenticators: &northstar_abuse_policy::ContentIdentityAuthenticators) -> MixBusinessReplay;
        lookup_mix_retraction_replay(channel_id: Uuid, actor: &str, target_id: Uuid, identity: &MixReplayIdentity, authenticators: &northstar_abuse_policy::ContentIdentityAuthenticators) -> MixBusinessReplay;
        authorized_mix_event_page(channel_id: Uuid, actor: &str, node: &str, before: Option<(DateTime<Utc>, Uuid)>, limit: i64) -> MixReadOutcome<MixEventPage>;
        authorized_mix_mam_page(channel_id: Uuid, actor: &str, viewer_id: Option<Uuid>, query: &MamArchiveQuery) -> MixReadOutcome<MixMamPage>;
        authorized_mix_mam_boundaries(channel_id: Uuid, actor: &str, viewer_id: Option<Uuid>) -> MixReadOutcome<(Option<ArchiveBoundary>, Option<ArchiveBoundary>)>;
        authorized_mix_access_entries(channel_id: Uuid, actor: &str, banned: bool, limit: i64) -> MixReadOutcome<Vec<String>>;
        mix_participant_preference(channel_id: Uuid, actor: &str) -> Option<MixParticipantPreference>;
        authorized_mix_jid_map_entries(channel_id: Uuid, actor: &str, limit: i64) -> MixReadOutcome<Vec<(String, String)>>;
        issue_mix_invitation(channel_id: Uuid, inviter: &str, invitee: &str, token: &str, lifetime: chrono::Duration, federated: Option<&FederatedMixMutation>) -> bool;
        mix_private_message_recipient(channel_id: Uuid, sender: &str, recipient_id: Uuid) -> Option<(MixParticipant, MixParticipant)>;
        lookup_remote_pam_operation(user_id: Uuid, requester_full_jid: &str, client_request_id: &str, request_digest: &[u8; 32]) -> PamOperationReplay;
        complete_remote_pam_success(authenticated_domain: &str, channel_jid: &str, recipient_bare: &str, request_id: &str, response_digest: &[u8; 32], join: Option<RemotePamJoin<'_>>) -> RemotePamCompletionOutcome;
        complete_remote_pam_error(authenticated_domain: &str, channel_jid: &str, recipient_bare: &str, request_id: &str, response_digest: &[u8; 32], error_type: &str, condition: &str) -> RemotePamCompletionOutcome;
        pam_memberships(user_id: Uuid) -> Vec<PamMembership>;
        pam_membership(user_id: Uuid, channel_jid: &str) -> Option<PamMembership>;
        local_pam_users_for_channel(channel_jid: &str) -> Vec<Uuid>;
        reconcile_expired_remote_pam(limit: i64) -> u64;
        claim_pam_results(limit: i64) -> Vec<ClaimedPamResult>;
        renew_pam_result_lease(operation_id: Uuid, lease_token: Uuid) -> bool;
        acknowledge_pam_result(operation_id: Uuid, lease_token: Uuid) -> bool;
        defer_pam_result(operation_id: Uuid, lease_token: Uuid, delay_seconds: i64) -> bool;
        retry_pam_result(operation_id: Uuid, lease_token: Uuid, attempt_count: i32, error: &str) -> bool;
        find_enabled_user(username: &str) -> Option<MixAccount>;
        find_enabled_user_by_id(user_id: Uuid) -> Option<MixAccount>;
        is_blocked(owner_id: Uuid, candidate: &str) -> bool;
        pep_node(owner_id: Uuid, node: &str) -> Option<PepNodeConfig>;
        pep_items(owner_id: Uuid, node: &str, item_id: Option<&str>, limit: i64) -> Vec<(String, String)>;
        get_vcard(user_id: Uuid) -> VCardRecord;
        latest_roster_change_for_contact(user_id: Uuid, contact_jid: &str) -> Option<northstar_roster_core::RosterChange>;
        mix_muc_mirror_for_mix(mix_channel_id: Uuid) -> Option<MixMucMirror>;
        mix_muc_mirror_for_muc(muc_room_id: Uuid) -> Option<MixMucMirror>;
        mix_muc_mirror_service_complete(mix_domain: &str) -> bool;
        archive_mix_message_once(personal_archive_id: Uuid, owner_id: Uuid, channel_jid: &str, authoritative_stanza_id: Uuid, stanza: &str, encrypted: bool, client_stanza_id: Option<&str>) -> SourceArchiveAdmission;
        enqueue_s2s_response_batch(target_domain: &str, responses: &[String], policy: S2sOutboxPolicy) -> ();
        federated_mix_iq_replay(authenticated_domain: &str, actor_jid: &str, request_id: &str, request_digest: &[u8; 32]) -> FederatedMixIqReplay;
        admit_federated_mix_iq_result(authenticated_domain: &str, actor_jid: &str, request_id: &str, request_digest: &[u8; 32], response: &str, policy: S2sOutboxPolicy) -> FederatedMixIqReplay;
        claim_mix_deliveries(limit: i64, max_bytes: i64) -> Vec<ClaimedMixDelivery>;
        maintain_mix_delivery_retention() -> ();
        prune_expired_business_intents(limit: i64) -> u64;
        prune_expired_federated_iq_results(limit: i64) -> u64;
        fence_mix_socket_write(source: MixDelivery) -> MixDelivery;
        transfer_mix_delivery_to_cluster(source: MixDelivery, node_id: &str, request_id: Uuid, ttl_seconds: u64) -> MixDelivery;
        release_mix_cluster_delivery(source: MixDelivery, node_id: &str, request_id: Uuid) -> bool;
        renew_mix_delivery_lease(delivery_id: Uuid, lease_token: Uuid) -> bool;
        dead_letter_mix_delivery(delivery_id: Uuid, lease_token: Uuid, terminal_reason: &str, error: &str) -> bool;
        retry_mix_delivery(delivery_id: Uuid, lease_token: Uuid, attempt_count: i32, route_wake_generation: i64, error: &str) -> MixDeliveryRetryOutcome;
        defer_mix_delivery(delivery_id: Uuid, lease_token: Uuid, route_wake_generation: i64, delay_seconds: i64) -> bool;
        wake_mix_delivery_recipient(recipient_jid: &str) -> u64;
        mix_delivery_dead_letters(before: Option<(DateTime<Utc>, Uuid)>, limit: i64) -> Vec<MixDeliveryDeadLetter>;
    }
}
