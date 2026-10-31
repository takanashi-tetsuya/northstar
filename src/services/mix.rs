//! Application-service boundary for XEP-0369/XEP-0405 MIX.
//!
//! The service owns replay proofs, admission limits and committed delivery wakes.
//! Repository operations preserve each cross-table transaction.

use crate::services::abuse::{MixMessageContentKeyring, MixRetractionContentKeyring};
use anyhow::Result;
use chrono::{DateTime, Utc};
use northstar_xml_builder::XmlElement;
use std::collections::BTreeSet;
use std::sync::Arc;
use tokio::sync::{watch, Mutex, MutexGuard, OwnedSemaphorePermit};
use uuid::Uuid;

mod contracts;
mod operations;
mod payloads;
mod wake;

pub(crate) use self::contracts::{
    AccessChangeOutcome, BeginRemotePamJoin, BeginRemotePamLeave, ClaimedMixDelivery,
    ClaimedPamResult, CreateChannelOutcome, ExpiredMixPresence, FederatedMixIqReplay,
    FederatedMixMutation, JoinChannelOutcome, JoinMixRequest, LeaveMixOutcome,
    MixAccessEntryOperation, MixAccessEntryUpdate, MixAccessList, MixAccount, MixChannel,
    MixConfigUpdate, MixDeliveryDeadLetter, MixInfoUpdate, MixInvitationProof, MixMucLinkOutcome,
    MixMutationAdmission, MixMutationOutcome, MixParticipantPreference,
    MixParticipantPreferenceUpdateOutcome, MixRepository, MixRoleUpdate, PamMembership,
    PamOperationReplay, PresenceOutcome, RegisterMixNickOutcome, RemotePamCompletion,
    RemotePamCompletionOutcome, RemotePamJoin, RetractMixMessageAdmission,
    RetractMixMessageOutcome, RetractMixMessageRequest, SetNickError, SourceArchiveAdmission,
    StoreMixMessageRequest, UpdateSubscriptionsOutcome,
};
pub(crate) use self::operations::{
    canonical_mix_access_pattern, mix_timestamp_item_id, participant_jid_visible, prepare_mix_nick,
    valid_join_nodes, valid_stable_participant_id, ArchiveBoundary, MamArchiveQuery, MamRsmPage,
    MixClusterRouteLookup, MixDiscoPage, MixEvent, MixEventPage, MixMamPage, MixMucMirror,
    MixPresenceItem, MixPresenceProbeTarget, MixReadOutcome, PepNodeConfig, VCardRecord,
};
#[cfg(test)]
use self::payloads::{
    render_access_payload, render_config_payload, render_info_payload, render_participant_payload,
};
pub(crate) use self::payloads::{
    FederatedMixSuccess, MixEventPayloadRenderer, MixPayloads, MixPresenceDelivery, PamJoinResult,
};
pub(crate) use self::wake::{MixDeliveryWakeBroker, MixDeliveryWakeSubscription};

pub(crate) mod foreground;
pub(crate) mod outbox;
pub(crate) use northstar_room_core::mix::{
    Admission as StoreMixMessageAdmission, Outcome as StoreEventOutcome,
    Participant as MixParticipant, Replay as MixBusinessReplay,
    ReplayIdentity as MixReplayIdentity,
};

// XEP-0369 node identifiers owned by the application boundary.  The repository
// keeps identically-valued storage constants; protocol code may only name
// these.
pub(crate) const NODE_MESSAGES: &str = "urn:xmpp:mix:nodes:messages";
pub(crate) const NODE_PRESENCE: &str = "urn:xmpp:mix:nodes:presence";
pub(crate) const NODE_PARTICIPANTS: &str = "urn:xmpp:mix:nodes:participants";
pub(crate) const NODE_INFO: &str = "urn:xmpp:mix:nodes:info";
pub(crate) const NODE_CONFIG: &str = "urn:xmpp:mix:nodes:config";
pub(crate) const NODE_ALLOWED: &str = "urn:xmpp:mix:nodes:allowed";
pub(crate) const NODE_BANNED: &str = "urn:xmpp:mix:nodes:banned";
pub(crate) const NODE_JIDMAP: &str = "urn:xmpp:mix:nodes:jidmap";
pub(crate) const NODE_AVATAR_DATA: &str = "urn:xmpp:avatar:data";
pub(crate) const NODE_AVATAR_METADATA: &str = "urn:xmpp:avatar:metadata";
/// Transaction-ordered PostgreSQL wake channel for durable MIX delivery.
///
/// The notification payload is only the database schema that committed the
/// row.  It is never authorization data: workers still claim the fenced row
/// from PostgreSQL before producing any externally visible effect.
pub(crate) const MIX_DELIVERY_WAKE_NOTIFICATION_CHANNEL: &str = "northstar_mix_delivery_v1";
pub(crate) const SUBSCRIBABLE_NODES: [&str; 6] = [
    NODE_MESSAGES,
    NODE_PRESENCE,
    NODE_PARTICIPANTS,
    NODE_INFO,
    NODE_AVATAR_DATA,
    NODE_AVATAR_METADATA,
];
pub(crate) const CORE_NODES: [&str; 4] =
    [NODE_MESSAGES, NODE_PRESENCE, NODE_PARTICIPANTS, NODE_INFO];
pub(crate) const ALL_NODES: [&str; 10] = [
    NODE_MESSAGES,
    NODE_PRESENCE,
    NODE_PARTICIPANTS,
    NODE_INFO,
    NODE_CONFIG,
    NODE_ALLOWED,
    NODE_BANNED,
    NODE_JIDMAP,
    NODE_AVATAR_DATA,
    NODE_AVATAR_METADATA,
];

/// Owned mirror of the federation admission policy the protocol reads from
/// the S2S router before batching a federated MAM response stream.
pub(crate) use northstar_federation_core::S2sOutboxPolicy;

impl MixDeliveryWakeBroker {
    #[cfg(test)]
    pub(crate) fn for_test() -> Arc<Self> {
        Self::new("public".to_owned()).expect("test wake schema is valid")
    }

    #[cfg(test)]
    fn generation(&self) -> u64 {
        *self.sender.borrow()
    }
}

#[derive(Clone)]
pub(crate) struct MixService<R> {
    repository: R,
    /// Receiving configuration, independent of any per-call claimed domain.
    configured_mix_domain: String,
    message_identity: MixMessageContentKeyring,
    retraction_identity: MixRetractionContentKeyring,
    /// The bounded durable MIX outbox budget derived once from the configured
    /// primary application-pool capacity.  Protocol code gets this typed
    /// scheduling limit rather than a raw database-pool capability.
    outbox_background_budget: usize,
    /// Fair, process-local admission gate. Every application operation that
    /// can add a durable MIX delivery acquires this before asking database connection for a
    /// transaction. PostgreSQL keeps the cross-process authority; this gate
    /// prevents ordinary same-process concurrency from occupying a pool of
    /// connections while queued behind that authority.
    delivery_admission: Arc<Mutex<()>>,
    /// Clone-shared FIFO gate for the durable MIX-PAM operation counter. It is
    /// acquired before repository code can check out a PostgreSQL connection,
    /// so one process contributes at most one waiter to the cross-process
    /// singleton authority while unrelated database work retains pool access.
    pam_capacity_admission: Arc<Mutex<()>>,
    /// Application-owned admission for short durable outbox database turns.
    /// The same capability is shared with PubSub and clustered MUC delivery;
    /// no individual XEP worker can independently consume the primary pool's
    /// foreground reserve.
    outbox_db_admission: northstar_runtime::durable_outbox::DurableOutboxDatabaseAdmission,
    /// Shared cross-process/listener wake broker for the durable delivery
    /// lane. It carries no stanza data and is not a second delivery authority.
    /// MIX-PAM has a distinct eligibility model and deliberately retains its
    /// own periodic recovery until it receives a typed wake.
    delivery_wake: Arc<MixDeliveryWakeBroker>,
}

impl<R: MixRepository> MixService<R> {
    #[cfg(test)]
    pub(crate) fn new(
        repository: R,
        message_identity: MixMessageContentKeyring,
        retraction_identity: MixRetractionContentKeyring,
        primary_pool_max_connections: u32,
        schema: String,
    ) -> Result<Self> {
        Self::new_with_outbox_database_admission(
            repository,
            "local.test".to_owned(),
            message_identity,
            retraction_identity,
            northstar_runtime::durable_outbox::DurableOutboxDatabaseAdmission::for_primary_pool(
                primary_pool_max_connections,
            ),
            schema,
        )
    }

    pub(crate) fn new_with_outbox_database_admission(
        repository: R,
        configured_domain: String,
        message_identity: MixMessageContentKeyring,
        retraction_identity: MixRetractionContentKeyring,
        outbox_db_admission: northstar_runtime::durable_outbox::DurableOutboxDatabaseAdmission,
        schema: String,
    ) -> Result<Self> {
        let outbox_background_budget = outbox_db_admission.capacity();
        let configured_mix_domain =
            northstar_xmpp_types::prepare_domainpart(&format!("mix.{configured_domain}"))?;
        Ok(Self {
            repository,
            configured_mix_domain,
            message_identity,
            retraction_identity,
            outbox_background_budget,
            delivery_admission: Arc::new(Mutex::new(())),
            pam_capacity_admission: Arc::new(Mutex::new(())),
            outbox_db_admission,
            delivery_wake: MixDeliveryWakeBroker::new(schema)?,
        })
    }

    /// Maximum concurrent durable MIX outbox operations permitted for this
    /// process.  The service owns the primary-pool capacity policy so callers
    /// cannot infer it by reaching into a `database connection`.
    pub(crate) const fn outbox_background_budget(&self) -> usize {
        self.outbox_background_budget
    }

    async fn delivery_admission_guard(&self) -> MutexGuard<'_, ()> {
        self.delivery_admission.lock().await
    }

    async fn pam_capacity_admission_guard(&self) -> MutexGuard<'_, ()> {
        self.pam_capacity_admission.lock().await
    }

    async fn outbox_db_admission_guard(&self) -> OwnedSemaphorePermit {
        self.outbox_db_admission.acquire().await
    }

    /// Subscribe one durable MIX worker lane before it evaluates its next
    /// wait.  A committed PostgreSQL wake arriving while the lane is busy is
    /// retained by the subscription and causes an immediate next claim.
    pub(crate) fn subscribe_delivery_wake(&self) -> MixDeliveryWakeSubscription {
        self.delivery_wake.subscribe()
    }

    fn publish_delivery_local_commit(&self) {
        self.delivery_wake.publish_local_commit();
    }

    pub(crate) async fn destroy_mix_channel(
        &self,
        channel_id: Uuid,
        actor: &str,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<bool> {
        let _admission = self.delivery_admission_guard().await;
        self.repository
            .destroy_mix_channel(channel_id, actor, federated)
            .await
    }
    pub(crate) async fn join_mix_channel(
        &self,
        channel_id: Uuid,
        request: JoinMixRequest,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<JoinChannelOutcome> {
        let _admission = self.delivery_admission_guard().await;
        self.repository
            .join_mix_channel(channel_id, request, federated)
            .await
    }
    pub(crate) async fn expire_unrefreshed_mix_presence(
        &self,
        cutoff: DateTime<Utc>,
    ) -> Result<Vec<ExpiredMixPresence>> {
        let _admission = self.delivery_admission_guard().await;
        self.repository
            .expire_unrefreshed_mix_presence(cutoff)
            .await
    }
    pub(crate) async fn update_mix_subscriptions(
        &self,
        channel_id: Uuid,
        actor: &str,
        subscribe: &[String],
        unsubscribe: &[String],
        federated: Option<&FederatedMixMutation>,
    ) -> Result<Option<UpdateSubscriptionsOutcome>> {
        let _admission = self.delivery_admission_guard().await;
        self.repository
            .update_mix_subscriptions(channel_id, actor, subscribe, unsubscribe, federated)
            .await
    }
    pub(crate) async fn set_mix_nick(
        &self,
        channel_id: Uuid,
        actor: &str,
        nick: &str,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<std::result::Result<MixParticipant, SetNickError>> {
        let _admission = self.delivery_admission_guard().await;
        self.repository
            .set_mix_nick(channel_id, actor, nick, federated)
            .await
    }
    pub(crate) async fn leave_mix_channel(
        &self,
        channel_id: Uuid,
        actor: &str,
        pam_user_id: Option<Uuid>,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<Option<LeaveMixOutcome>> {
        let _admission = self.delivery_admission_guard().await;
        self.repository
            .leave_mix_channel(channel_id, actor, pam_user_id, federated)
            .await
    }
    pub(crate) async fn store_mix_presence(
        &self,
        channel_id: Uuid,
        actor_bare: &str,
        actor_full: &str,
        payload: &str,
        unavailable: bool,
    ) -> Result<PresenceOutcome> {
        let _admission = self.delivery_admission_guard().await;
        self.repository
            .store_mix_presence(channel_id, actor_bare, actor_full, payload, unavailable)
            .await
    }
    pub(crate) async fn ensure_mix_presence(
        &self,
        channel_id: Uuid,
        actor_bare: &str,
        actor_full: &str,
        payload: &str,
    ) -> Result<PresenceOutcome> {
        let _admission = self.delivery_admission_guard().await;
        self.repository
            .ensure_mix_presence(channel_id, actor_bare, actor_full, payload)
            .await
    }
    pub(crate) async fn store_mix_message(
        &self,
        request: StoreMixMessageRequest<'_>,
    ) -> Result<StoreMixMessageAdmission> {
        let authenticators = request.identity.as_ref().map(|identity| {
            self.message_identity
                .authenticators(&identity.canonical_semantics)
        });
        let _admission = self.delivery_admission_guard().await;
        let result = self
            .repository
            .store_mix_message(request, authenticators.as_ref())
            .await?;
        if matches!(&result.outcome, StoreEventOutcome::Stored(_)) && !result.recipients.is_empty()
        {
            self.publish_delivery_local_commit();
        }
        Ok(result)
    }

    pub(crate) fn prepare_mix_foreground(
        &self,
        ingress: foreground::Ingress,
    ) -> std::result::Result<foreground::PreparedIngress, foreground::Rejected> {
        if !ingress.matches_receiving_domain(&self.configured_mix_domain) {
            return Err(foreground::Rejected::Input);
        }
        Ok(foreground::PreparedIngress::new(ingress))
    }

    pub(crate) async fn store_mix_message_observed(
        &self,
        request: &foreground::StoreRequest,
    ) -> Result<Arc<StoreMixMessageAdmission>> {
        let authenticators = request.command().identity.as_ref().map(|identity| {
            self.message_identity
                .authenticators(&identity.canonical_semantics)
        });
        let _admission = self.delivery_admission_guard().await;
        let completion = northstar_room_application::mix::admit_observed(
            request,
            &self.configured_mix_domain,
            self.repository
                .store_mix_message_observed(request, authenticators.as_ref()),
        )
        .await
        .map_err(foreground::effect_error)?;
        let (result, wake) = completion.into_wake(request.observation())?;
        if let Some(wake) = wake {
            wake.invoke(|| self.publish_delivery_local_commit())?;
        }
        Ok(result)
    }

    pub(crate) async fn lookup_mix_message_replay_observed(
        &self,
        request: &foreground::ReplayRequest,
    ) -> Result<MixBusinessReplay> {
        let identity = request
            .ingress()
            .identity
            .as_ref()
            .ok_or(foreground::Rejected::Input)?;
        let authenticators = self
            .message_identity
            .authenticators(&identity.canonical_semantics);
        northstar_room_application::mix::read_observed(
            request,
            &self.configured_mix_domain,
            self.repository
                .lookup_mix_message_replay_observed(request, &authenticators),
        )
        .await
        .map_err(foreground::effect_error)
    }

    pub(crate) async fn publish_mix_avatar(
        &self,
        channel_id: Uuid,
        actor: &str,
        node: &str,
        item_id: &str,
        payload: &str,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<bool> {
        let _admission = self.delivery_admission_guard().await;
        self.repository
            .publish_mix_avatar(channel_id, actor, node, item_id, payload, federated)
            .await
    }

    pub(crate) async fn retract_mix_avatar(
        &self,
        channel_id: Uuid,
        actor: &str,
        node: &str,
        item_id: &str,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<bool> {
        let _admission = self.delivery_admission_guard().await;
        self.repository
            .retract_mix_avatar(channel_id, actor, node, item_id, federated)
            .await
    }
    pub(crate) async fn update_mix_info(
        &self,
        channel_id: Uuid,
        actor: &str,
        update: MixInfoUpdate,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<MixMutationOutcome> {
        let _admission = self.delivery_admission_guard().await;
        self.repository
            .update_mix_info(channel_id, actor, update, federated)
            .await
    }

    pub(crate) async fn update_mix_config(
        &self,
        channel_id: Uuid,
        actor: &str,
        update: MixConfigUpdate,
        roles: MixRoleUpdate,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<MixMutationOutcome> {
        let _admission = self.delivery_admission_guard().await;
        self.repository
            .update_mix_config(channel_id, actor, update, roles, federated)
            .await
    }

    pub(crate) async fn set_mix_access_entry(
        &self,
        update: MixAccessEntryUpdate<'_>,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<Option<AccessChangeOutcome>> {
        let _admission = self.delivery_admission_guard().await;
        self.repository
            .set_mix_access_entry(update, federated)
            .await
    }
    pub(crate) async fn register_mix_nick(
        &self,
        service_domain: &str,
        actor: &str,
        nick: &str,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<RegisterMixNickOutcome> {
        let _admission = self.delivery_admission_guard().await;
        self.repository
            .register_mix_nick(service_domain, actor, nick, federated)
            .await
    }
    pub(crate) async fn update_mix_participant_preference(
        &self,
        channel_id: Uuid,
        actor: &str,
        preference: &MixParticipantPreference,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<Option<MixParticipantPreferenceUpdateOutcome>> {
        let _admission = self.delivery_admission_guard().await;
        self.repository
            .update_mix_participant_preference(channel_id, actor, preference, federated)
            .await
    }
    pub(crate) async fn retract_mix_message(
        &self,
        request: RetractMixMessageRequest<'_>,
    ) -> Result<RetractMixMessageAdmission> {
        let authenticators = request.identity.as_ref().map(|identity| {
            self.retraction_identity
                .authenticators(&identity.canonical_semantics)
        });
        let _admission = self.delivery_admission_guard().await;
        let result = self
            .repository
            .retract_mix_message(request, authenticators.as_ref())
            .await?;
        if matches!(&result.outcome, RetractMixMessageOutcome::Retracted)
            && !result.recipients.is_empty()
        {
            self.publish_delivery_local_commit();
        }
        Ok(result)
    }
    pub(crate) async fn begin_remote_pam_join(
        &self,
        request: BeginRemotePamJoin,
    ) -> Result<PamOperationReplay> {
        let _admission = self.pam_capacity_admission_guard().await;
        self.repository.begin_remote_pam_join(request).await
    }

    pub(crate) async fn begin_remote_pam_leave(
        &self,
        request: BeginRemotePamLeave,
    ) -> Result<PamOperationReplay> {
        let _admission = self.pam_capacity_admission_guard().await;
        self.repository.begin_remote_pam_leave(request).await
    }

    pub(crate) async fn reconcile_expired_remote_pam(&self, limit: i64) -> Result<u64> {
        let _outbox_db_admission = self.outbox_db_admission_guard().await;
        self.repository.reconcile_expired_remote_pam(limit).await
    }

    pub(crate) async fn claim_pam_results(&self, limit: i64) -> Result<Vec<ClaimedPamResult>> {
        tracing::debug!(
            available_permits = self.outbox_db_admission.available_permits(),
            "MIX PAM result claim waiting for database admission"
        );
        let _outbox_db_admission = self.outbox_db_admission_guard().await;
        self.repository.claim_pam_results(limit).await
    }

    pub(crate) async fn renew_pam_result_lease(
        &self,
        operation_id: Uuid,
        lease_token: Uuid,
    ) -> Result<bool> {
        let _outbox_db_admission = self.outbox_db_admission_guard().await;
        self.repository
            .renew_pam_result_lease(operation_id, lease_token)
            .await
    }

    pub(crate) async fn acknowledge_pam_result(
        &self,
        operation_id: Uuid,
        lease_token: Uuid,
    ) -> Result<bool> {
        let _outbox_db_admission = self.outbox_db_admission_guard().await;
        self.repository
            .acknowledge_pam_result(operation_id, lease_token)
            .await
    }

    pub(crate) async fn defer_pam_result(
        &self,
        operation_id: Uuid,
        lease_token: Uuid,
        delay_seconds: i64,
    ) -> Result<bool> {
        let _outbox_db_admission = self.outbox_db_admission_guard().await;
        self.repository
            .defer_pam_result(operation_id, lease_token, delay_seconds)
            .await
    }

    pub(crate) async fn retry_pam_result(
        &self,
        operation_id: Uuid,
        lease_token: Uuid,
        attempt_count: i32,
        error: &str,
    ) -> Result<bool> {
        let _outbox_db_admission = self.outbox_db_admission_guard().await;
        self.repository
            .retry_pam_result(operation_id, lease_token, attempt_count, error)
            .await
    }

    pub(crate) async fn prune_expired_pam_results(&self, limit: i64) -> Result<u64> {
        let _outbox_db_admission = self.outbox_db_admission_guard().await;
        let _admission = self.pam_capacity_admission_guard().await;
        self.repository.prune_expired_pam_results(limit).await
    }

    /// Read a local recipient while processing a claimed durable MIX outbox
    /// row.  This is deliberately separate from [`Self::find_enabled_user`]:
    /// live ingress must not wait behind background work, while a durable
    /// worker must leave the service-owned foreground connection reserve
    /// intact.  The permit is released before the caller performs any socket,
    /// cluster, or federation I/O.
    pub(crate) async fn outbox_find_enabled_user(
        &self,
        username: &str,
    ) -> Result<Option<MixAccount>> {
        tracing::debug!(
            available_permits = self.outbox_db_admission.available_permits(),
            "MIX durable local-account lookup waiting for database admission"
        );
        let _outbox_db_admission = self.outbox_db_admission_guard().await;
        self.repository.find_enabled_user(username).await
    }

    /// Outbox-only variant of the live privacy lookup.  Keep the permit
    /// scoped to this database await rather than to the enclosing durable
    /// delivery attempt, which can wait on a local transport or remote peer.
    pub(crate) async fn outbox_is_blocked(&self, owner_id: Uuid, candidate: &str) -> Result<bool> {
        let _outbox_db_admission = self.outbox_db_admission_guard().await;
        self.repository.is_blocked(owner_id, candidate).await
    }

    /// Durably admit a claimed MIX outbox stanza to federation.
    ///
    /// `FederationOutboxAdmission::admit` is an S2S outbox admission here:
    /// it performs one PostgreSQL enqueue/commit followed only by local,
    /// non-awaiting wake-ups. It does not open a peer connection or write a
    /// socket. The permit is consequently released before the S2S dispatcher
    /// performs any network work, while preserving component-route wake-up
    /// semantics owned by the outbox service.
    pub(crate) async fn outbox_admit_federated_stanza<
        F: crate::services::federation_outbox::FederationOutboxAdmission,
    >(
        &self,
        federation: &F,
        target_domain: &str,
        stanza: String,
    ) -> bool {
        let _outbox_db_admission = self.outbox_db_admission_guard().await;
        federation.admit(target_domain, stanza).await
    }

    /// Idempotently archive one claimed durable MIX delivery under the same
    /// bounded outbox database budget as its claim and completion fence.
    /// This preserves the normal archive/replay result exactly, but does not
    /// allow the caller to retain a database permit while routing the stanza.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn outbox_archive_mix_message_once(
        &self,
        personal_archive_id: Uuid,
        owner_id: Uuid,
        channel_jid: &str,
        authoritative_stanza_id: Uuid,
        stanza: &str,
        encrypted: bool,
        client_stanza_id: Option<&str>,
    ) -> Result<SourceArchiveAdmission> {
        let _outbox_db_admission = self.outbox_db_admission_guard().await;
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

    #[allow(dead_code)] // Explicit returned-only compatibility entry; observed workers use bound requests.
    pub(crate) async fn claim_mix_deliveries(
        &self,
        limit: i64,
        max_bytes: i64,
    ) -> Result<Vec<ClaimedMixDelivery>> {
        tracing::debug!(
            available_permits = self.outbox_db_admission.available_permits(),
            "MIX delivery claim waiting for database admission"
        );
        let _admission = self.outbox_db_admission_guard().await;
        self.repository.claim_mix_deliveries(limit, max_bytes).await
    }

    pub(crate) async fn claim_mix_deliveries_observed(
        &self,
        request: &outbox::core::ClaimRequest,
    ) -> Result<Vec<outbox::OwnedAttempt>> {
        let _admission = self.outbox_db_admission_guard().await;
        request.start()?;
        match self.repository.claim_mix_deliveries_observed(request).await {
            Ok(rows) => Ok(request
                .returned(rows)?
                .into_iter()
                .map(outbox::OwnedAttempt::new)
                .collect()),
            Err(error) => {
                request.failed()?;
                Err(error)
            }
        }
    }

    pub(crate) async fn outbox_archive_mix_message_once_observed(
        &self,
        request: &outbox::core::ArchiveRequest,
    ) -> Result<outbox::core::ArchiveResult> {
        let _admission = self.outbox_db_admission_guard().await;
        request.start()?;
        match self
            .repository
            .archive_mix_message_once_observed(request)
            .await
        {
            Ok(result) => Ok(request.returned(result)?),
            Err(error) => {
                request.failed()?;
                Err(error)
            }
        }
    }

    pub(crate) async fn renew_mix_delivery_lease_observed(
        &self,
        request: &outbox::core::RenewalRequest,
    ) -> Result<bool> {
        let _admission = self.outbox_db_admission_guard().await;
        request.start()?;
        match self
            .repository
            .renew_mix_delivery_lease_observed(request)
            .await
        {
            Ok(result) => Ok(request.returned(result)?),
            Err(error) => {
                request.failed()?;
                Err(error)
            }
        }
    }

    pub(crate) async fn settle_mix_delivery_observed(
        &self,
        request: &outbox::core::SettlementRequest,
    ) -> Result<outbox::core::SettlementResult> {
        let _admission = self.outbox_db_admission_guard().await;
        request.start()?;
        let result = match self.repository.settle_mix_delivery_observed(request).await {
            Ok(result) => request.returned(result)?,
            Err(error) => {
                request.failed()?;
                return Err(error);
            }
        };
        use outbox::core::{RetryResult, SettlementResult};
        if matches!(
            result,
            SettlementResult::Ack(true)
                | SettlementResult::DeadLetter(true)
                | SettlementResult::Retry(
                    RetryResult::RouteWokenAtAttemptLimit | RetryResult::DeadLettered
                )
        ) {
            self.publish_delivery_local_commit();
        }
        Ok(result)
    }

    /// Keep MIX retention bounded without putting cleanup ahead of a live
    /// recipient claim. This remains a short repository-only turn under the
    /// private outbox admission capability.
    pub(crate) async fn maintain_mix_delivery_retention(&self) -> Result<()> {
        let _admission = self.outbox_db_admission_guard().await;
        self.repository.maintain_mix_delivery_retention().await
    }

    pub(crate) async fn prune_expired_business_intents(&self, limit: i64) -> Result<u64> {
        let _admission = self.outbox_db_admission_guard().await;
        self.repository.prune_expired_business_intents(limit).await
    }

    pub(crate) async fn prune_expired_federated_iq_results(&self, limit: i64) -> Result<u64> {
        let _admission = self.outbox_db_admission_guard().await;
        self.repository
            .prune_expired_federated_iq_results(limit)
            .await
    }

    #[allow(dead_code)] // Compatibility ACK remains distinct from native and observed worker ownership.
    pub(crate) async fn acknowledge_mix_delivery(
        &self,
        delivery_id: Uuid,
        lease_token: Uuid,
    ) -> Result<bool> {
        self.acknowledge_mix_delivery_inner(delivery_id, lease_token, None)
            .await
    }

    pub(crate) async fn acknowledge_mix_socket_write(
        &self,
        request: &northstar_delivery_core::native_write::AckRequest,
    ) -> Result<bool> {
        let northstar_delivery_core::TransportOwnershipSource::Mix(source) = request.source()
        else {
            anyhow::bail!("native MIX acknowledgement source mismatch");
        };
        self.acknowledge_mix_delivery_inner(source.delivery_id, source.lease_token, Some(request))
            .await
    }

    async fn acknowledge_mix_delivery_inner(
        &self,
        delivery_id: Uuid,
        lease_token: Uuid,
        observation: Option<&northstar_delivery_core::native_write::AckRequest>,
    ) -> Result<bool> {
        let _admission = self.outbox_db_admission_guard().await;
        let result = self
            .repository
            .acknowledge_mix_delivery(delivery_id, lease_token, observation)
            .await?;
        if result {
            self.publish_delivery_local_commit();
        }
        Ok(result)
    }

    /// Give a direct C2S writer a rotated, bounded MIX source lease before
    /// it can place bytes on TCP/WebSocket. The protocol layer receives no
    /// SQL capability and must treat the returned token as writer-private.
    pub(crate) async fn fence_mix_socket_write(
        &self,
        source: northstar_delivery_core::MixDelivery,
    ) -> Result<northstar_delivery_core::MixDelivery> {
        let _admission = self.outbox_db_admission_guard().await;
        self.repository.fence_mix_socket_write(source).await
    }

    /// Persist a remote-node ownership fence before a signed cluster command
    /// is allowed to enqueue this exact MIX source on the destination node.
    pub(crate) async fn transfer_mix_delivery_to_cluster(
        &self,
        source: northstar_delivery_core::MixDelivery,
        node_id: &str,
        request_id: Uuid,
        ttl_seconds: u64,
    ) -> Result<northstar_delivery_core::MixDelivery> {
        let _admission = self.outbox_db_admission_guard().await;
        self.repository
            .transfer_mix_delivery_to_cluster(source, node_id, request_id, ttl_seconds)
            .await
    }

    /// Release only the exact remote-node MIX hand-off which never reached a
    /// local durable boundary. A later transfer is never overwritten.
    pub(crate) async fn release_mix_cluster_delivery(
        &self,
        source: northstar_delivery_core::MixDelivery,
        node_id: &str,
        request_id: Uuid,
    ) -> Result<bool> {
        let _admission = self.outbox_db_admission_guard().await;
        let result = self
            .repository
            .release_mix_cluster_delivery(source, node_id, request_id)
            .await?;
        if result {
            self.publish_delivery_local_commit();
        }
        Ok(result)
    }

    /// Persist a typed BOSH owner for a claimed MIX recipient row. This is a
    /// transport transfer, not a delivery acknowledgement: client BOSH ACK
    /// processing remains responsible for the final exact source deletion.
    pub(crate) async fn transfer_mix_delivery_to_bosh(
        &self,
        request: &northstar_delivery_core::bosh_ownership::TransferRequest,
    ) -> Result<northstar_delivery_core::MixDelivery> {
        let _admission = self.outbox_db_admission_guard().await;
        self.repository.transfer_mix_delivery_to_bosh(request).await
    }

    #[allow(dead_code)] // Compatibility source tuple does not construct an observed renewal request.
    pub(crate) async fn renew_mix_delivery_lease(
        &self,
        delivery_id: Uuid,
        lease_token: Uuid,
    ) -> Result<bool> {
        let _admission = self.outbox_db_admission_guard().await;
        self.repository
            .renew_mix_delivery_lease(delivery_id, lease_token)
            .await
    }

    #[allow(dead_code)] // Explicit compatibility result, including NotMoved.
    pub(crate) async fn dead_letter_mix_delivery(
        &self,
        delivery_id: Uuid,
        lease_token: Uuid,
        terminal_reason: &str,
        error: &str,
    ) -> Result<bool> {
        let _admission = self.outbox_db_admission_guard().await;
        let result = self
            .repository
            .dead_letter_mix_delivery(delivery_id, lease_token, terminal_reason, error)
            .await?;
        if result {
            self.publish_delivery_local_commit();
        }
        Ok(result)
    }

    #[allow(dead_code)] // Preserve the historical bool API separately from typed observed retry results.
    pub(crate) async fn retry_mix_delivery(
        &self,
        delivery_id: Uuid,
        lease_token: Uuid,
        _claimed_attempt_count: i32,
        route_wake_generation: i64,
        error: &str,
    ) -> Result<bool> {
        let _admission = self.outbox_db_admission_guard().await;
        let result = self
            .repository
            .retry_mix_delivery(
                delivery_id,
                lease_token,
                _claimed_attempt_count,
                route_wake_generation,
                error,
            )
            .await?;
        match result {
            MixDeliveryRetryOutcome::LeaseLost => Ok(false),
            MixDeliveryRetryOutcome::Retried => Ok(true),
            MixDeliveryRetryOutcome::RouteWokenAtAttemptLimit
            | MixDeliveryRetryOutcome::DeadLettered => {
                self.publish_delivery_local_commit();
                Ok(true)
            }
        }
    }

    #[allow(dead_code)] // Compatibility source tuple does not construct an observed settlement request.
    pub(crate) async fn defer_mix_delivery(
        &self,
        delivery_id: Uuid,
        lease_token: Uuid,
        route_wake_generation: i64,
        delay_seconds: i64,
    ) -> Result<bool> {
        let _admission = self.outbox_db_admission_guard().await;
        self.repository
            .defer_mix_delivery(
                delivery_id,
                lease_token,
                route_wake_generation,
                delay_seconds,
            )
            .await
    }

    /// A locally verified MIX-capable resource can make an already-persisted
    /// delivery head routable sooner than its timer recovery probe. The
    /// database row remains the delivery authority; this advances its durable
    /// route epoch and brings an unleased head's next claim forward.
    pub(crate) async fn wake_mix_delivery_recipient(&self, recipient_jid: &str) -> Result<u64> {
        let _admission = self.outbox_db_admission_guard().await;
        let result = self
            .repository
            .wake_mix_delivery_recipient(recipient_jid)
            .await?;
        if result > 0 {
            self.publish_delivery_local_commit();
        }
        Ok(result)
    }

    #[allow(dead_code)] // Exposed for the pending admin recovery endpoint wiring.
    pub(crate) async fn mix_delivery_dead_letters(
        &self,
        before: Option<(DateTime<Utc>, Uuid)>,
        limit: i64,
    ) -> Result<Vec<MixDeliveryDeadLetter>> {
        let _admission = self.outbox_db_admission_guard().await;
        self.repository
            .mix_delivery_dead_letters(before, limit)
            .await
    }

    #[allow(dead_code)] // Exposed for the pending admin recovery endpoint wiring.
    pub(crate) async fn requeue_mix_delivery_dead_letter(
        &self,
        dead_letter_id: Uuid,
    ) -> Result<bool> {
        let _admission = self.delivery_admission_guard().await;
        let _outbox_db_admission = self.outbox_db_admission_guard().await;
        let result = self
            .repository
            .requeue_mix_delivery_dead_letter(dead_letter_id)
            .await?;
        if result {
            self.publish_delivery_local_commit();
        }
        Ok(result)
    }
}

pub(crate) use northstar_delivery_core::mix_outbox::RetryResult as MixDeliveryRetryOutcome;

#[cfg(test)]
mod tests;
