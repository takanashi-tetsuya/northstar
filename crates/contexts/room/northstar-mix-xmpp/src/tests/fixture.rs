use super::*;
use northstar_abuse_policy::ContentIdentityAuthenticators;
use northstar_federation_core::{FederationOutboxAdmission, S2sOutboxPolicy};
use northstar_room_application::mix_service::*;
use northstar_time::{DateTime, Utc};

mod pam_delivery_repository;

#[derive(Clone, Debug, PartialEq)]
pub enum Call {
    Claim(mix_worker::ClaimCommand),
    PamClaim(i64),
    User(String, usize),
    Block(Uuid, String, usize),
    Archive(mix_worker::ArchiveCommand, usize),
    ReflectedRetraction(Uuid, String, Uuid, Uuid, String),
    Nodes(bool, String, usize),
    Sessions(String),
    Capability(String),
    Cluster(String, String, String, Option<MixDelivery>, usize),
    Pam(String, String, String, Uuid),
    PamDefer(Uuid, Uuid, i64),
    PamAck(Uuid, Uuid),
    Settle(MixDelivery, i64, mix_worker::SettlementCommand),
    Renew(MixDelivery),
    Maintenance(&'static str, i64),
    Federation(bool, String, String, usize),
    Frame(MixFrameStage),
    Register,
    Replay(bool),
    Channel(String, String),
    Member(Uuid, String),
    Preference(Uuid, String),
    Store(bool),
    Retract(Uuid, String, Uuid),
    MamBatch(String, Vec<String>),
    MutationReplay(String),
}

pub struct DropFlag(pub Arc<AtomicBool>);
impl Drop for DropFlag {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

pub struct PublisherWrite {
    pub identity: MixPublisherIdentity,
    pub payload: String,
    pub tombstone: Option<String>,
}

pub struct State {
    pub calls: Mutex<Vec<Call>>,
    pub changed: tokio::sync::Notify,
    pub admission: northstar_runtime::durable_outbox::DurableOutboxDatabaseAdmission,
    pub rows: Mutex<VecDeque<mix_worker::Rows>>,
    pub pam: Mutex<VecDeque<Vec<ClaimedPamResult>>>,
    pub claim_gate: Mutex<Option<Arc<tokio::sync::Semaphore>>>,
    pub nodes_gate: Mutex<Option<Arc<tokio::sync::Semaphore>>>,
    pub maintenance_gate: Mutex<Option<Arc<tokio::sync::Semaphore>>>,
    pub claim_dropped: Arc<AtomicBool>,
    pub nodes_dropped: Arc<AtomicBool>,
    pub maintenance_dropped: Arc<AtomicBool>,
    pub receipt: Mutex<NodeDeliveryReceipt>,
    pub nodes: Mutex<Vec<String>>,
    pub sessions: Mutex<Vec<(String, LocalSession)>>,
    pub capability: Mutex<MixSessionCapability>,
    pub archive_mismatch: AtomicBool,
    pub archive_replay: AtomicBool,
    pub reflection_conflict: AtomicBool,
    pub reflection_blocked: AtomicBool,
    pub reflection_membership: Mutex<Option<PamMembership>>,
    pub replay: Mutex<MixBusinessReplay>,
    pub foreground_owner: Mutex<Option<foreground::Observation>>,
    pub mam_outcome: Mutex<Option<MixMamReadOutcome>>,
    pub mutation_iq: Mutex<Option<(String, [u8; 32])>>,
    pub reject_mam: AtomicBool,
    pub outbox_wakes: std::sync::atomic::AtomicUsize,
    pub publisher_visibility: Mutex<VecDeque<&'static str>>,
    pub publisher_mismatches: Mutex<VecDeque<bool>>,
    pub publisher_writes: Mutex<Vec<PublisherWrite>>,
}

impl State {
    pub fn record(&self, call: Call) {
        self.calls.lock().unwrap().push(call);
        self.changed.notify_one();
    }

    pub fn calls(&self) -> Vec<Call> {
        self.calls.lock().unwrap().clone()
    }

    fn publisher_mismatch(
        &self,
        identity: &MixPublisherIdentity,
        payload: &str,
        tombstone: Option<&str>,
    ) -> Option<bool> {
        let mismatch = self.publisher_mismatches.lock().unwrap().pop_front()?;
        self.publisher_writes.lock().unwrap().push(PublisherWrite {
            identity: identity.clone(),
            payload: payload.to_owned(),
            tombstone: tombstone.map(str::to_owned),
        });
        Some(mismatch)
    }

    pub async fn until(&self, predicate: impl Fn(&[Call]) -> bool) {
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let changed = self.changed.notified();
                if predicate(&self.calls()) {
                    return;
                }
                changed.await;
            }
        })
        .await
        .expect("recording port did not reach the expected boundary");
    }
}

pub async fn wait_gate(gate: &Mutex<Option<Arc<tokio::sync::Semaphore>>>) {
    let gate = gate.lock().unwrap().clone();
    if let Some(gate) = gate {
        let _permit = gate.acquire().await.unwrap();
    }
}

#[derive(Clone)]
pub struct Repository(pub Arc<State>);

// Unrelated operations deliberately panic: an accidental compatibility call
// or a call into the other protocol lane must fail at the actual port.
macro_rules! unused_repository_methods {
    ($($name:ident($($arg:ident: $ty:ty),* $(,)?) -> $result:ty;)*) => {
        $(#[allow(clippy::too_many_arguments)]
        async fn $name(&self, $($arg: $ty),*) -> Result<$result> {
            let _ = ($($arg,)*);
            panic!("unexpected repository call: {}", stringify!($name));
        })*
    };
}

impl MixMamReadRepository for Repository {
    async fn read_mix_mam(&self, _command: MixMamReadCommand) -> Result<MixMamReadOutcome> {
        panic!("unexpected repository call: read_mix_mam")
    }

    async fn admit_federated_mix_mam(
        &self,
        command: MixMamReadCommand,
        target_domain: &str,
        _policy: S2sOutboxPolicy,
        render: impl FnOnce(MixMamReadOutcome) -> Result<Vec<String>> + Send,
    ) -> Result<MixMamAdmissionOutcome> {
        assert!(matches!(&command.actor, MixMamReadActor::Federated { .. }));
        let outcome = self.0.mam_outcome.lock().unwrap().take().unwrap();
        let responses = render(outcome)?;
        if self.0.reject_mam.load(Ordering::SeqCst) {
            return Ok(MixMamAdmissionOutcome::OutboxRejected(
                northstar_federation_core::S2sOutboxCapacityExceeded::PerDomain.into(),
            ));
        }
        self.0
            .record(Call::MamBatch(target_domain.to_owned(), responses));
        Ok(MixMamAdmissionOutcome::Queued)
    }
}

impl MixRepository for Repository {
    async fn federated_mix_iq_replay(
        &self,
        _authenticated_domain: &str,
        _actor_jid: &str,
        request_id: &str,
        request_digest: &[u8; 32],
    ) -> Result<FederatedMixIqReplay> {
        self.0.record(Call::MutationReplay(request_id.to_owned()));
        let recorded = self.0.mutation_iq.lock().unwrap();
        let (id, digest) = recorded
            .as_ref()
            .expect("unexpected mutation replay lookup");
        assert_eq!(id, request_id);
        Ok(if digest == request_digest {
            FederatedMixIqReplay::Replay("<iq/>".to_owned())
        } else {
            FederatedMixIqReplay::Conflict
        })
    }

    async fn find_enabled_user(&self, username: &str) -> Result<Option<MixAccount>> {
        self.0.record(Call::User(
            username.into(),
            self.0.admission.available_permits(),
        ));
        Ok(Some(MixAccount {
            id: Uuid::from_u128(81),
            username: username.into(),
        }))
    }

    async fn is_blocked(&self, owner_id: Uuid, candidate: &str) -> Result<bool> {
        self.0.record(Call::Block(
            owner_id,
            candidate.into(),
            self.0.admission.available_permits(),
        ));
        Ok(self.0.reflection_blocked.load(Ordering::SeqCst))
    }

    async fn prune_expired_business_intents(&self, limit: i64) -> Result<u64> {
        self.0.record(Call::Maintenance("business", limit));
        Ok(0)
    }
    async fn prune_expired_federated_iq_results(&self, limit: i64) -> Result<u64> {
        self.0.record(Call::Maintenance("iq", limit));
        Ok(0)
    }
    async fn mix_channel(
        &self,
        service_domain: &str,
        localpart: &str,
    ) -> Result<Option<MixChannel>> {
        self.0
            .record(Call::Channel(service_domain.into(), localpart.into()));
        let mut channel = channel();
        if let Some(visibility) = self.0.publisher_visibility.lock().unwrap().pop_front() {
            channel.jid_visibility = visibility.into();
        }
        Ok(Some(channel))
    }
    async fn mix_participant(&self, channel_id: Uuid, jid: &str) -> Result<Option<MixParticipant>> {
        self.0.record(Call::Member(channel_id, jid.into()));
        Ok(Some(MixParticipant {
            participant_id: Uuid::from_u128(94),
            jid: jid.into(),
            nick: Some("Bob".into()),
        }))
    }
    async fn mix_participant_preference(
        &self,
        channel_id: Uuid,
        actor: &str,
    ) -> Result<Option<MixParticipantPreference>> {
        self.0.record(Call::Preference(channel_id, actor.into()));
        Ok(None)
    }
    async fn store_mix_message(
        &self,
        request: StoreMixMessageRequest<'_>,
        _authenticators: Option<&ContentIdentityAuthenticators>,
    ) -> Result<StoreMixMessageAdmission> {
        self.0.record(Call::Store(false));
        let outcome =
            match self
                .0
                .publisher_mismatch(request.publisher_identity, request.payload, None)
            {
                Some(true) => StoreEventOutcome::IdentityPolicyChanged,
                Some(false) => StoreEventOutcome::Stored(Uuid::parse_str(request.item_id)?),
                None => StoreEventOutcome::NotParticipant,
            };
        Ok(StoreMixMessageAdmission {
            outcome,
            recipients: vec![],
        })
    }
    async fn store_mix_message_observed(
        &self,
        request: &foreground::StoreRequest,
        _authenticators: Option<&ContentIdentityAuthenticators>,
    ) -> Result<StoreMixMessageAdmission> {
        {
            let original = self.0.foreground_owner.lock().unwrap();
            assert!(std::ptr::eq(
                request.observation().ingress(),
                original.as_ref().unwrap().ingress()
            ));
        }
        self.0.record(Call::Store(true));
        let command = request.command();
        let outcome =
            match self
                .0
                .publisher_mismatch(request.publisher_identity(), &command.payload, None)
            {
                Some(true) => StoreEventOutcome::IdentityPolicyChanged,
                Some(false) => {
                    let mut stored = foreground::fixture::stored(false);
                    stored.authoritative_id = command.item_id;
                    stored.channel_id = command.channel_id;
                    stored.channel_jid = request.observation().ingress().channel_jid.clone();
                    request.received(request.enter_commit(stored)?)?;
                    StoreEventOutcome::Stored(command.item_id)
                }
                None => anyhow::bail!("recorded observed store"),
            };
        Ok(StoreMixMessageAdmission {
            outcome,
            recipients: vec![],
        })
    }
    async fn lookup_mix_message_replay_observed(
        &self,
        request: &foreground::ReplayRequest,
        _authenticators: &ContentIdentityAuthenticators,
    ) -> Result<MixBusinessReplay> {
        self.0.record(Call::Replay(true));
        let original = self.0.foreground_owner.lock().unwrap();
        assert!(std::ptr::eq(
            request.ingress(),
            original.as_ref().unwrap().ingress()
        ));
        let replay = *self.0.replay.lock().unwrap();
        if replay == MixBusinessReplay::Miss {
            request.observed_miss()?;
        } else {
            let raw = foreground::fixture::existing();
            request.observed_existing(raw.clone())?;
            request.authenticated(&raw, replay)?;
        }
        Ok(replay)
    }
    async fn lookup_mix_message_replay(
        &self,
        _channel_id: Uuid,
        _actor: &str,
        _identity: &MixReplayIdentity,
        _authenticators: &ContentIdentityAuthenticators,
    ) -> Result<MixBusinessReplay> {
        self.0.record(Call::Replay(false));
        Ok(*self.0.replay.lock().unwrap())
    }
    async fn lookup_mix_retraction_replay(
        &self,
        _channel_id: Uuid,
        _actor: &str,
        _target_id: Uuid,
        _identity: &MixReplayIdentity,
        _authenticators: &ContentIdentityAuthenticators,
    ) -> Result<MixBusinessReplay> {
        Ok(MixBusinessReplay::Miss)
    }
    async fn retract_mix_message(
        &self,
        request: RetractMixMessageRequest<'_>,
        _authenticators: Option<&ContentIdentityAuthenticators>,
    ) -> Result<RetractMixMessageAdmission> {
        self.0.record(Call::Retract(
            request.channel_id,
            request.actor.into(),
            request.target_id,
        ));
        let outcome = match self.0.publisher_mismatch(
            request.publisher_identity,
            request.retraction_payload,
            Some(request.tombstone_payload),
        ) {
            Some(true) => RetractMixMessageOutcome::IdentityPolicyChanged,
            Some(false) => RetractMixMessageOutcome::Retracted,
            None => RetractMixMessageOutcome::NotFound,
        };
        Ok(RetractMixMessageAdmission {
            outcome,
            recipients: vec![],
        })
    }

    unused_repository_methods! {
        link_local_muc_mirror(mix_domain: &str, localpart: &str, actor_bare_jid: &str, local_domain: &str) -> MixMucLinkOutcome;
        create_mix_channel(service_domain: &str, requested_localpart: Option<&str>, creator_jid: &str, max_channels_per_owner: i64, federated: Option<&FederatedMixMutation>) -> (CreateChannelOutcome, String);
        discoverable_mix_channel_page(service_domain: &str, requester: &str, after: Option<&str>, before: Option<Option<&str>>, max: i64) -> Option<MixDiscoPage>;
        mix_role(channel_id: Uuid, jid: &str) -> Option<String>;
        mix_channel_discoverable_to(channel: &MixChannel, actor: &str) -> bool;
        destroy_mix_channel(channel_id: Uuid, actor: &str, federated: Option<&FederatedMixMutation>) -> bool;
        join_mix_channel(channel_id: Uuid, request: JoinMixRequest, federated: Option<&FederatedMixMutation>) -> JoinChannelOutcome;
        expire_unrefreshed_mix_presence(cutoff: DateTime<Utc>) -> Vec<ExpiredMixPresence>;
        update_mix_subscriptions(channel_id: Uuid, actor: &str, subscribe: &[String], unsubscribe: &[String], federated: Option<&FederatedMixMutation>) -> Option<UpdateSubscriptionsOutcome>;
        set_mix_nick(channel_id: Uuid, actor: &str, nick: &str, federated: Option<&FederatedMixMutation>) -> std::result::Result<MixParticipant, SetNickError>;
        leave_mix_channel(channel_id: Uuid, actor: &str, pam_user_id: Option<Uuid>, federated: Option<&FederatedMixMutation>) -> Option<LeaveMixOutcome>;
        store_mix_presence(channel_id: Uuid, actor_bare: &str, actor_full: &str, payload: &str, unavailable: bool) -> PresenceOutcome;
        ensure_mix_presence(channel_id: Uuid, actor_bare: &str, actor_full: &str, payload: &str) -> PresenceOutcome;
        authorized_mix_event_page(channel_id: Uuid, actor: &str, node: &str, before: Option<(DateTime<Utc>, Uuid)>, limit: i64) -> MixReadOutcome<MixEventPage>;
        publish_mix_avatar(channel_id: Uuid, actor: &str, node: &str, item_id: &str, payload: &str, federated: Option<&FederatedMixMutation>) -> bool;
        retract_mix_avatar(channel_id: Uuid, actor: &str, node: &str, item_id: &str, federated: Option<&FederatedMixMutation>) -> bool;
        authorized_mix_access_entries(channel_id: Uuid, actor: &str, banned: bool, limit: i64) -> MixReadOutcome<Vec<String>>;
        update_mix_info(channel_id: Uuid, actor: &str, update: MixInfoUpdate, federated: Option<&FederatedMixMutation>) -> MixMutationOutcome;
        update_mix_config(channel_id: Uuid, actor: &str, update: MixConfigUpdate, roles: MixRoleUpdate, federated: Option<&FederatedMixMutation>) -> MixMutationOutcome;
        set_mix_access_entry(update: MixAccessEntryUpdate<'_>, federated: Option<&FederatedMixMutation>) -> Option<AccessChangeOutcome>;
        register_mix_nick(service_domain: &str, actor: &str, nick: &str, federated: Option<&FederatedMixMutation>) -> RegisterMixNickOutcome;
        update_mix_participant_preference(channel_id: Uuid, actor: &str, preference: &MixParticipantPreference, federated: Option<&FederatedMixMutation>) -> Option<MixParticipantPreferenceUpdateOutcome>;
        authorized_mix_jid_map_entries(channel_id: Uuid, actor: &str, limit: i64) -> MixReadOutcome<Vec<(String, String)>>;
        issue_mix_invitation(channel_id: Uuid, inviter: &str, invitee: &str, token: &str, lifetime: northstar_time::Duration, federated: Option<&FederatedMixMutation>) -> bool;
        mix_private_message_recipient(channel_id: Uuid, sender: &str, recipient_id: Uuid) -> Option<(MixParticipant, MixParticipant)>;
        find_enabled_user_by_id(user_id: Uuid) -> Option<MixAccount>;
        relay_profile_snapshot(query: MixRelayProfileQuery) -> MixRelayProfileResult;
        latest_roster_change_for_contact(user_id: Uuid, contact_jid: &str) -> Option<northstar_roster_core::RosterChange>;
        mix_muc_mirror_for_mix(mix_channel_id: Uuid) -> Option<MixMucMirror>;
        mix_muc_mirror_for_muc(muc_room_id: Uuid) -> Option<MixMucMirror>;
        mix_muc_mirror_service_complete(mix_domain: &str) -> bool;
        enqueue_s2s_response_batch(target_domain: &str, responses: &[String], policy: S2sOutboxPolicy) -> ();
        admit_federated_mix_iq_result(authenticated_domain: &str, actor_jid: &str, request_id: &str, request_digest: &[u8; 32], response: &str, policy: S2sOutboxPolicy) -> FederatedMixIqReplay;
    }
}

impl MixPamRepository for Repository {
    async fn claim_pam_results(&self, limit: i64) -> Result<Vec<ClaimedPamResult>> {
        self.0.record(Call::PamClaim(limit));
        Ok(self.0.pam.lock().unwrap().pop_front().unwrap_or_default())
    }

    async fn defer_pam_result(
        &self,
        operation_id: Uuid,
        lease_token: Uuid,
        delay_seconds: i64,
    ) -> Result<bool> {
        self.0
            .record(Call::PamDefer(operation_id, lease_token, delay_seconds));
        Ok(true)
    }
    async fn acknowledge_pam_result(&self, operation_id: Uuid, lease_token: Uuid) -> Result<bool> {
        self.0.record(Call::PamAck(operation_id, lease_token));
        Ok(true)
    }

    async fn reconcile_expired_remote_pam(&self, limit: i64) -> Result<u64> {
        self.0.record(Call::Maintenance("remote-pam", limit));
        Ok(0)
    }
    async fn prune_expired_pam_results(&self, limit: i64) -> Result<u64> {
        self.0.record(Call::Maintenance("pam", limit));
        Ok(0)
    }

    async fn pam_membership(
        &self,
        _user_id: Uuid,
        _channel_jid: &str,
    ) -> Result<Option<PamMembership>> {
        Ok(self.0.reflection_membership.lock().unwrap().clone())
    }

    unused_repository_methods! {
        begin_remote_pam_join(request: BeginRemotePamJoin) -> PamOperationReplay;
        lookup_remote_pam_operation(user_id: Uuid, requester_full_jid: &str, client_request_id: &str, request_digest: &[u8; 32]) -> PamOperationReplay;
        begin_remote_pam_leave(request: BeginRemotePamLeave) -> PamOperationReplay;
        complete_remote_pam_success(authenticated_domain: &str, channel_jid: &str, recipient_bare: &str, request_id: &str, response_digest: &[u8; 32], join: Option<RemotePamJoin<'_>>) -> RemotePamCompletionOutcome;
        complete_remote_pam_error(authenticated_domain: &str, channel_jid: &str, recipient_bare: &str, request_id: &str, response_digest: &[u8; 32], error_type: &str, condition: &str) -> RemotePamCompletionOutcome;
        pam_memberships(user_id: Uuid) -> Vec<PamMembership>;
        local_pam_users_for_channel(channel_jid: &str) -> Vec<Uuid>;
        renew_pam_result_lease(operation_id: Uuid, lease_token: Uuid) -> bool;
        retry_pam_result(operation_id: Uuid, lease_token: Uuid, attempt_count: i32, error: &str) -> bool;
    }
}

impl MixDeliveryRepository for Repository {
    async fn archive_verified_mix_reflection(
        &self,
        request: VerifiedMixReflection<'_>,
    ) -> Result<ReflectedMixArchiveOutcome> {
        self.admit_archive_reflection(request).await
    }

    async fn claim_mix_deliveries_observed(
        &self,
        request: &mix_worker::ClaimRequest,
    ) -> Result<mix_worker::Rows> {
        let _drop = DropFlag(self.0.claim_dropped.clone());
        self.0.record(Call::Claim(request.command()));
        let rows = self
            .0
            .rows
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| Vec::new().into());
        let entered = request.enter_statement()?;
        request.received(entered, rows.clone())?;
        wait_gate(&self.0.claim_gate).await;
        Ok(rows)
    }

    async fn archive_mix_message_once_observed(
        &self,
        request: &mix_worker::ArchiveRequest,
    ) -> Result<mix_worker::ArchiveResult> {
        self.0.record(Call::Archive(
            request.command().clone(),
            self.0.admission.available_permits(),
        ));
        let result = if self.0.archive_replay.load(Ordering::SeqCst) {
            mix_worker::ArchiveResult::Replay(Uuid::from_u128(82))
        } else {
            mix_worker::ArchiveResult::Stored(request.command().personal_archive_id)
        };
        let entered = request.enter_commit(result)?;
        request.received(entered)?;
        Ok(if self.0.archive_mismatch.load(Ordering::SeqCst) {
            mix_worker::ArchiveResult::Replay(Uuid::from_u128(83))
        } else {
            result
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn archive_mix_message_once(
        &self,
        personal_archive_id: Uuid,
        owner_id: Uuid,
        channel_jid: &str,
        authoritative_stanza_id: Uuid,
        stanza: &str,
        encrypted: bool,
        client_stanza_id: Option<&str>,
    ) -> Result<SourceArchiveAdmission> {
        self.0.record(Call::Archive(
            mix_worker::ArchiveCommand {
                personal_archive_id,
                owner_id,
                channel_jid: channel_jid.into(),
                authoritative_stanza_id,
                stanza: stanza.into(),
                encrypted,
                client_stanza_id: client_stanza_id.map(str::to_owned),
            },
            self.0.admission.available_permits(),
        ));
        Ok(SourceArchiveAdmission::Stored(personal_archive_id))
    }

    async fn renew_mix_delivery_lease_observed(
        &self,
        request: &mix_worker::RenewalRequest,
    ) -> Result<bool> {
        self.0.record(Call::Renew(request.source()));
        let entered = request.enter_statement()?;
        request.received(entered, true)?;
        Ok(true)
    }

    async fn settle_mix_delivery_observed(
        &self,
        request: &mix_worker::SettlementRequest,
    ) -> Result<mix_worker::SettlementResult> {
        self.0.record(Call::Settle(
            request.source(),
            request.route_wake_generation(),
            request.command().clone(),
        ));
        let result = settlement_result(request.command(), true);
        settlement_receipt(request, result)?;
        Ok(result)
    }

    async fn maintain_mix_delivery_retention(&self) -> Result<()> {
        let _drop = DropFlag(self.0.maintenance_dropped.clone());
        self.0.record(Call::Maintenance("retention", 0));
        wait_gate(&self.0.maintenance_gate).await;
        Ok(())
    }

    unused_repository_methods! {
        claim_mix_deliveries(limit: i64, max_bytes: i64) -> Vec<ClaimedMixDelivery>;
        acknowledge_mix_delivery(delivery_id: Uuid, lease_token: Uuid, observation: Option<&northstar_delivery_core::native_write::AckRequest>) -> bool;
        fence_mix_socket_write(source: MixDelivery) -> MixDelivery;
        transfer_mix_delivery_to_cluster(source: MixDelivery, node_id: &str, request_id: Uuid, ttl_seconds: u64) -> MixDelivery;
        release_mix_cluster_delivery(source: MixDelivery, node_id: &str, request_id: Uuid) -> bool;
        transfer_mix_delivery_to_bosh(request: &northstar_delivery_core::bosh_ownership::TransferRequest) -> MixDelivery;
        renew_mix_delivery_lease(delivery_id: Uuid, lease_token: Uuid) -> bool;
        dead_letter_mix_delivery(delivery_id: Uuid, lease_token: Uuid, terminal_reason: &str, error: &str) -> bool;
        retry_mix_delivery(delivery_id: Uuid, lease_token: Uuid, claimed_attempt_count: i32, route_wake_generation: i64, error: &str) -> MixDeliveryRetryOutcome;
        defer_mix_delivery(delivery_id: Uuid, lease_token: Uuid, route_wake_generation: i64, delay_seconds: i64) -> bool;
        wake_mix_delivery_recipient(recipient_jid: &str) -> u64;
        mix_delivery_dead_letters(before: Option<(DateTime<Utc>, Uuid)>, limit: i64) -> Vec<MixDeliveryDeadLetter>;
        requeue_mix_delivery_dead_letter(dead_letter_id: Uuid) -> bool;
    }
}

pub fn settlement_result(
    command: &mix_worker::SettlementCommand,
    matched: bool,
) -> mix_worker::SettlementResult {
    match command {
        mix_worker::SettlementCommand::Ack => mix_worker::SettlementResult::Ack(matched),
        mix_worker::SettlementCommand::Defer { .. } => mix_worker::SettlementResult::Defer(matched),
        mix_worker::SettlementCommand::DeadLetter { .. } => {
            mix_worker::SettlementResult::DeadLetter(matched)
        }
        mix_worker::SettlementCommand::Retry { .. } => {
            mix_worker::SettlementResult::Retry(if matched {
                mix_worker::RetryResult::Retried
            } else {
                mix_worker::RetryResult::LeaseLost
            })
        }
    }
}

pub fn settlement_receipt(
    request: &mix_worker::SettlementRequest,
    result: mix_worker::SettlementResult,
) -> Result<()> {
    let entered = if matches!(result, mix_worker::SettlementResult::Defer(_)) {
        request.enter_statement()?
    } else {
        request.enter_commit(result)?
    };
    request.received(entered, result)?;
    Ok(())
}

#[derive(Clone)]
pub struct Federation(pub Arc<State>);
impl FederationOutboxAdmission for Federation {
    async fn admit<'a>(&'a self, target_domain: &'a str, stanza: String) -> bool {
        self.0.record(Call::Federation(
            true,
            target_domain.into(),
            stanza,
            self.0.admission.available_permits(),
        ));
        true
    }
}
impl FederationRoute for Federation {
    fn outbox_policy(&self) -> S2sOutboxPolicy {
        S2sOutboxPolicy::new(60, 100, 1_000_000, 100)
    }
    fn wake_outbox(&self) {
        self.0.outbox_wakes.fetch_add(1, Ordering::SeqCst);
    }
    async fn send(&self, target_domain: &str, stanza: String, bounce_to: Option<String>) -> bool {
        assert!(bounce_to.is_none());
        self.0.record(Call::Federation(
            false,
            target_domain.into(),
            stanza,
            self.0.admission.available_permits(),
        ));
        true
    }
}

#[derive(Clone)]
pub struct LocalSession {
    pub sender: northstar_stream::outbound::OutboundSender,
    pub disconnect: CancellationToken,
}
impl MixLocalSession for LocalSession {
    type Outbound = northstar_stream::outbound::OutboundSender;
    fn sender(&self) -> &Self::Outbound {
        &self.sender
    }
    fn disconnect(&self) -> &CancellationToken {
        &self.disconnect
    }
    fn user_id(&self) -> Uuid {
        Uuid::from_u128(81)
    }
    fn is_available(&self) -> bool {
        true
    }
}

#[derive(Clone)]
pub struct Context {
    pub state: Arc<State>,
    pub service: MixService<Repository>,
    pub federation: Federation,
}
impl Context {
    pub fn new(budget: u32) -> Arc<Self> {
        let admission =
            northstar_runtime::durable_outbox::DurableOutboxDatabaseAdmission::for_primary_pool(
                budget + 1,
            );
        let state = Arc::new(State {
            calls: Mutex::new(vec![]),
            changed: tokio::sync::Notify::new(),
            admission: admission.clone(),
            rows: Mutex::new(VecDeque::new()),
            pam: Mutex::new(VecDeque::new()),
            claim_gate: Mutex::new(None),
            nodes_gate: Mutex::new(None),
            maintenance_gate: Mutex::new(None),
            claim_dropped: Arc::new(AtomicBool::new(false)),
            nodes_dropped: Arc::new(AtomicBool::new(false)),
            maintenance_dropped: Arc::new(AtomicBool::new(false)),
            receipt: Mutex::new(NodeDeliveryReceipt::default()),
            nodes: Mutex::new(vec![]),
            sessions: Mutex::new(vec![]),
            capability: Mutex::new(MixSessionCapability::Supported),
            archive_mismatch: AtomicBool::new(false),
            archive_replay: AtomicBool::new(false),
            reflection_conflict: AtomicBool::new(false),
            reflection_blocked: AtomicBool::new(false),
            reflection_membership: Mutex::new(None),
            replay: Mutex::new(MixBusinessReplay::Miss),
            foreground_owner: Mutex::new(None),
            mam_outcome: Mutex::new(None),
            mutation_iq: Mutex::new(None),
            reject_mam: AtomicBool::new(false),
            outbox_wakes: std::sync::atomic::AtomicUsize::new(0),
            publisher_visibility: Mutex::new(VecDeque::new()),
            publisher_mismatches: Mutex::new(VecDeque::new()),
            publisher_writes: Mutex::new(Vec::new()),
        });
        let generations = Arc::new(Vec::new());
        let service = MixService::new_with_outbox_database_admission(
            Repository(state.clone()),
            "local.test".into(),
            northstar_abuse_policy::content_identity::MixMessageContentKeyring::new(
                generations.clone(),
            ),
            northstar_abuse_policy::content_identity::MixRetractionContentKeyring::new(generations),
            admission,
            "mix_owner_tests".into(),
        )
        .unwrap();
        Arc::new(Self {
            federation: Federation(state.clone()),
            state,
            service,
        })
    }
}
impl MixOutboxPort for Context {
    type Repository = Repository;
    type Session = LocalSession;
    type Federation = Federation;
    fn service(&self) -> &MixService<Repository> {
        &self.service
    }
    fn local_domain(&self) -> &str {
        "local.test"
    }
    fn federation_domain_allowed(&self, _domain: &str) -> bool {
        true
    }
    fn federation_outbox(&self) -> &Federation {
        &self.federation
    }
    fn session_entries_for(&self, jid: &str) -> Vec<(String, LocalSession)> {
        self.state.record(Call::Sessions(jid.into()));
        self.state.sessions.lock().unwrap().clone()
    }
    fn session_mix_capability(&self, full_jid: &str) -> MixSessionCapability {
        self.state.record(Call::Capability(full_jid.into()));
        *self.state.capability.lock().unwrap()
    }
    async fn lookup_nodes(&self, jid: &str) -> Result<Vec<String>> {
        self.state.record(Call::Nodes(
            false,
            jid.into(),
            self.state.admission.available_permits(),
        ));
        Ok(self.state.nodes.lock().unwrap().clone())
    }
    async fn outbox_lookup_cluster_nodes(&self, jid: &str) -> Result<Vec<String>> {
        let _drop = DropFlag(self.state.nodes_dropped.clone());
        self.state.record(Call::Nodes(
            true,
            jid.into(),
            self.state.admission.available_permits(),
        ));
        if !jid.contains('/') {
            wait_gate(&self.state.nodes_gate).await;
        }
        Ok(self.state.nodes.lock().unwrap().clone())
    }
    async fn send_cluster_mix(
        &self,
        node_id: &str,
        recipient: &str,
        stanza: &str,
        source: Option<MixDelivery>,
    ) -> Result<NodeDeliveryReceipt> {
        self.state.record(Call::Cluster(
            node_id.into(),
            recipient.into(),
            stanza.into(),
            source,
            self.state.admission.available_permits(),
        ));
        Ok(self.state.receipt.lock().unwrap().clone())
    }
    async fn send_cluster_pam_result(
        &self,
        node_id: &str,
        target_full_jid: &str,
        stanza: &str,
        expected_user_id: Uuid,
    ) -> Result<bool> {
        self.state.record(Call::Pam(
            node_id.into(),
            target_full_jid.into(),
            stanza.into(),
            expected_user_id,
        ));
        Ok(false)
    }
    fn record_post_commit_failure(&self) {}
}

pub fn channel() -> MixChannel {
    MixChannel {
        id: Uuid::from_u128(93),
        revision: 0,
        service_domain: "mix.local.test".into(),
        localpart: "room".into(),
        creator_jid: "bob@local.test".into(),
        name: None,
        description: None,
        contacts: vec![],
        access_model: "open".into(),
        jid_visibility: "visible".into(),
        nick_required: false,
        max_participants: 100,
        max_events: 100,
        allow_private_messages: true,
        allow_participant_invites: true,
        allow_user_message_retraction: true,
        administrator_retraction_rights: "administrators".into(),
        enforce_registered_nick: false,
    }
}

pub fn pam_result(index: u128) -> ClaimedPamResult {
    ClaimedPamResult {
        operation_id: Uuid::from_u128(200 + index),
        user_id: Uuid::from_u128(81),
        requester_full_jid: format!("bob@local.test/resource-{index}"),
        response_xml: "<iq type='result' id='pam'/>".into(),
        attempt_count: 3,
        lease_token: Uuid::from_u128(300 + index),
    }
}

mod pam_projection_repository;
#[cfg(test)]
mod presence_recovery;
