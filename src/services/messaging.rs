//! Personal-message policy and atomic admission through a persistence port.

mod direct_route;
pub(crate) mod direct_workflow;
pub(crate) use direct_route::{
    DirectMessageRoutePort, DirectMessageRouter, DirectRouteDelivery, DirectRouteOutcome,
    DirectRouteRejection, DirectRouteRequest, DirectRouteTarget,
};

use super::{
    muc::{ClusterMucInviteAuthority, DurableMucInviteOutcome},
    privacy::PrivacyStanzaKind,
    retractions::FederationOutboxPolicy,
};
use crate::abuse::MessageDedupeIdentity;
use crate::cluster::{DirectPostCommitMode, DirectSpoolEligibility};
use crate::outbound::{DurableDelivery, OutboundItem, RouteEnqueue};
use anyhow::Result;
use northstar_message_application::direct_commit::{
    CommitError as DirectCommitError, DirectCommitRepository,
};
use northstar_message_application::direct_handoff::HandoffHandle;
use northstar_message_application::{
    CommitError, MessageApplication, PersonalMessageCommitRepository,
};
pub(crate) use northstar_message_core::{
    ArchiveProjection as ArchiveWrite, DirectPersonalMessageAdmission, FederationDelivery,
    IdentityAuthority, LocalDelivery, MessageCommit as DurableAdmissionOutcome, MessageIdentity,
    MessagePostCommit, PersonalMessageDestination, ValidatedPersonalMessage,
};
use std::future::Future;
use uuid::Uuid;

/// Communication policy retains distinct blocking and privacy denials.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OutboundPolicyDecision {
    Allowed,
    Blocked,
    PrivacyDenied,
}

#[derive(Debug)]
pub(crate) enum LocalRecipientDecision {
    Missing,
    Blocked,
    Deliver(LocalRecipient),
}

/// Minimum identity required by the personal-message pipeline. In particular,
/// password hashes and SCRAM verifiers from the persistence model never cross
/// into stanza parsing or live routing code.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LocalRecipient {
    pub(crate) id: Uuid,
    pub(crate) username: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OfflineAdmissionOutcome {
    Stored,
    Replay,
    QuotaExceeded,
    RecipientUnavailable,
}

/// A clustered committed C2S row may enter a live queue only with the exact
/// reservation committed beside it. Standalone delivery has no claim token.
pub(crate) fn committed_live_delivery_has_fence(
    clustered: bool,
    message_id: Uuid,
    claim_id: Option<Uuid>,
) -> bool {
    northstar_message_application::direct_handoff::live_reservation_valid(
        clustered, message_id, claim_id,
    )
}

/// The first accepted online resource, if any. Cluster v1 receipts may be
/// accepted without naming an exact full JID, so the key remains optional.
#[derive(Debug, Default, Eq, PartialEq)]
pub(crate) struct OnlineRouteResult {
    pub(crate) delivered: bool,
    pub(crate) accepted_full_jid: Option<String>,
}

/// Live queues and cluster routes remain transport details. Targets arrive
/// already privacy-filtered and ordered by the pre-admission protocol path.
pub(crate) trait OnlineRoutePort: Sync {
    type Session: Send + Sync;

    fn try_local(
        &self,
        session: &Self::Session,
        enqueue: RouteEnqueue,
    ) -> Result<(), crate::outbound::RouteSendError>;
    fn record_local_accept(&self, durable: bool);
    fn route_available_remote(
        &self,
        jid: &str,
        stanza: &str,
        delivery: Option<DurableDelivery>,
    ) -> impl Future<Output = bool> + Send;
    fn route_remote_primary(
        &self,
        jid: &str,
        stanza: &str,
        delivery: Option<DurableDelivery>,
    ) -> impl Future<Output = OnlineRouteResult> + Send;
}

/// The exact-resource route is already gone. Fallback snapshots are separate
/// because privacy failures after a durable commit cannot reject the stanza.
pub(crate) trait FullJidFallbackPort: OnlineRoutePort {
    fn fallback_sessions(&self, bare: &str) -> Vec<(String, Self::Session)>;
    fn available_priority(&self, session: &Self::Session) -> Option<i16>;
    fn priority(&self, session: &Self::Session) -> i16;
    fn privacy_allows_fallback(
        &self,
        session: &Self::Session,
        sender: &str,
    ) -> impl Future<Output = Result<bool>> + Send;
    fn post_accept_failed(&self);
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum FullJidFallbackResult {
    Dropped,
    Rejected,
    Undelivered,
    Delivered(Option<String>),
}

pub(crate) struct FullJidFallback<'a> {
    pub(crate) message_type: &'a str,
    pub(crate) full_target: &'a str,
    pub(crate) bare_target: &'a str,
    pub(crate) sender: &'a str,
    pub(crate) recipient_id: Uuid,
    pub(crate) delivery: Option<DurableDelivery>,
}

/// Policy/privacy preparation is separate from enqueue so protocol owners can
/// recheck live health after asynchronous privacy work, before any side effect.
enum FullJidFallbackPlan<S> {
    Finished(FullJidFallbackResult),
    Targets(Vec<(String, S)>),
}

/// One durable item survives every refused primary/fallback local attempt.
/// Volatile fanout deliberately creates distinct items. The queue never owns
/// this operation handle; accepted items can outlive the sending frame.
struct RoutePayload<'a> {
    stanza: &'a str,
    delivery: Option<DurableDelivery>,
    item: Option<OutboundItem>,
    witness: Option<HandoffHandle>,
    binding_rejected: bool,
}
impl<'a> RoutePayload<'a> {
    fn new(stanza: &'a str, delivery: Option<DurableDelivery>) -> Self {
        Self {
            stanza,
            delivery,
            item: None,
            witness: None,
            binding_rejected: false,
        }
    }
    fn prepared(stanza: &'a str, item: OutboundItem, witness: HandoffHandle) -> Self {
        Self {
            stanza,
            delivery: item.c2s_delivery(),
            item: Some(item),
            witness: Some(witness),
            binding_rejected: false,
        }
    }
    fn enqueue<P: OnlineRoutePort>(&mut self, port: &P, session: &P::Session) -> bool {
        if self.binding_rejected {
            return false;
        }
        let item = self.item.take().unwrap_or_else(|| match self.delivery {
            Some(delivery) => OutboundItem::durable(self.stanza.to_owned(), delivery),
            None => OutboundItem::plain(self.stanza.to_owned()),
        });
        if item.stanza != self.stanza
            || item.c2s_delivery() != self.delivery
            || !item.validate_durable_source_shape()
        {
            self.item = Some(item);
            self.binding_rejected = true;
            return false;
        }
        let permit = match (&self.witness, self.delivery) {
            (Some(witness), Some(source)) => match witness.local_permit(source) {
                Ok(permit) => Some(permit),
                Err(_) => {
                    self.item = Some(item);
                    return false;
                }
            },
            _ => None,
        };
        let enqueue = match RouteEnqueue::bind(item, permit, self.stanza) {
            Ok(enqueue) => enqueue,
            Err(rejected) => {
                self.item = Some(rejected.0);
                self.binding_rejected = true;
                return false;
            }
        };
        match port.try_local(session, enqueue) {
            Ok(()) => true,
            Err(crate::outbound::RouteSendError::Binding(rejected)) => {
                self.item = Some(rejected.0);
                self.binding_rejected = true;
                false
            }
            Err(
                crate::outbound::RouteSendError::Full(item)
                | crate::outbound::RouteSendError::Closed(item),
            ) => {
                self.item = Some(item);
                false
            }
        }
    }
    fn returned(&self) {
        if let Some(witness) = &self.witness {
            witness.returned();
        }
    }
}
impl Drop for RoutePayload<'_> {
    fn drop(&mut self) {
        if let Some(witness) = &self.witness {
            witness.dropped();
        }
    }
}

pub(crate) struct OnlineMessageRouter;

impl OnlineMessageRouter {
    /// Route an accepted stanza without touching its transaction owner. A
    /// durable delivery has one transport owner; headline fanout is volatile.
    #[cfg(test)]
    pub(crate) async fn dispatch<P: OnlineRoutePort>(
        port: &P,
        jid: &str,
        stanza: &str,
        delivery: Option<DurableDelivery>,
        deliver_all: bool,
        approved_targets: &[(String, P::Session)],
    ) -> OnlineRouteResult {
        let mut payload = RoutePayload::new(stanza, delivery);
        Self::dispatch_owned(port, jid, &mut payload, deliver_all, approved_targets).await
    }

    async fn dispatch_owned<P: OnlineRoutePort>(
        port: &P,
        jid: &str,
        payload: &mut RoutePayload<'_>,
        deliver_all: bool,
        approved_targets: &[(String, P::Session)],
    ) -> OnlineRouteResult {
        let local = Self::dispatch_local_owned(port, payload, deliver_all, approved_targets);
        Self::dispatch_remote_owned(port, jid, payload, deliver_all, local).await
    }

    fn dispatch_local_owned<P: OnlineRoutePort>(
        port: &P,
        payload: &mut RoutePayload<'_>,
        deliver_all: bool,
        approved_targets: &[(String, P::Session)],
    ) -> OnlineRouteResult {
        debug_assert!(
            !(payload.delivery.is_some() && deliver_all),
            "one durable C2S fence cannot be fanned out to multiple resources"
        );
        let mut result = OnlineRouteResult::default();
        for (key, session) in approved_targets {
            if payload.enqueue(port, session) {
                // The real sender consumed its prevalidated positive permit
                // synchronously before this telemetry or any later await.
                port.record_local_accept(payload.delivery.is_some());
                if result.accepted_full_jid.is_none() {
                    result.accepted_full_jid = Some(key.clone());
                }
                result.delivered = true;
                if !deliver_all {
                    break;
                }
            }
        }
        result
    }

    async fn dispatch_remote_owned<P: OnlineRoutePort>(
        port: &P,
        jid: &str,
        payload: &mut RoutePayload<'_>,
        deliver_all: bool,
        mut result: OnlineRouteResult,
    ) -> OnlineRouteResult {
        if payload.binding_rejected || (!deliver_all && result.delivered) {
            return result;
        }
        let permit = match (&payload.witness, payload.delivery) {
            (Some(witness), Some(source)) => match witness.remote_permit(source) {
                Ok(permit) => Some(permit),
                Err(_) => return result,
            },
            _ => None,
        };
        let positive = if deliver_all {
            let accepted = port
                .route_available_remote(jid, payload.stanza, payload.delivery)
                .await;
            result.delivered |= accepted;
            accepted
        } else {
            result = port
                .route_remote_primary(jid, payload.stanza, payload.delivery)
                .await;
            result.delivered
        };
        if let Some(permit) = permit {
            permit.returned(positive);
        }
        if positive {
            payload.item.take();
        }
        result
    }

    /// RFC 6121 full-JID mismatch handling using the same refused item.
    /// Privacy for every candidate is checked before any fallback enqueue.
    async fn full_jid_fallback_owned<P: FullJidFallbackPort>(
        port: &P,
        request: FullJidFallback<'_>,
        payload: &mut RoutePayload<'_>,
    ) -> Result<FullJidFallbackResult> {
        let bare_target = request.bare_target;
        let allowed = match Self::prepare_full_jid_fallback(port, request).await? {
            FullJidFallbackPlan::Finished(result) => return Ok(result),
            FullJidFallbackPlan::Targets(allowed) => allowed,
        };
        let local = Self::dispatch_local_owned(port, payload, false, &allowed);
        let result = Self::dispatch_remote_owned(port, bare_target, payload, false, local).await;
        Ok(if result.delivered {
            FullJidFallbackResult::Delivered(result.accepted_full_jid)
        } else {
            FullJidFallbackResult::Undelivered
        })
    }

    async fn prepare_full_jid_fallback<P: FullJidFallbackPort>(
        port: &P,
        request: FullJidFallback<'_>,
    ) -> Result<FullJidFallbackPlan<P::Session>> {
        use northstar_message_core::{
            durable_full_no_match_recovers, full_no_match_route, FullNoMatchRoute,
        };
        let FullJidFallback {
            message_type,
            full_target,
            bare_target,
            sender,
            recipient_id,
            delivery,
        } = request;

        match full_no_match_route(message_type) {
            FullNoMatchRoute::Ignore => {
                return Ok(FullJidFallbackPlan::Finished(
                    FullJidFallbackResult::Dropped,
                ))
            }
            FullNoMatchRoute::Reject
                if durable_full_no_match_recovers(message_type, delivery.is_some()) =>
            {
                port.post_accept_failed();
                tracing::warn!(
                    %recipient_id,
                    target = %full_target,
                    "exact full-JID route disappeared after durable admission; resource-affine row remains replayable"
                );
                return Ok(FullJidFallbackPlan::Finished(
                    FullJidFallbackResult::Undelivered,
                ));
            }
            FullNoMatchRoute::Reject => {
                return Ok(FullJidFallbackPlan::Finished(
                    FullJidFallbackResult::Rejected,
                ))
            }
            FullNoMatchRoute::FallbackChat => {}
        }

        let mut candidates = port.fallback_sessions(bare_target);
        candidates.retain(|(_, session)| port.available_priority(session).is_some());
        candidates.sort_by(|(left_jid, left), (right_jid, right)| {
            port.priority(right)
                .cmp(&port.priority(left))
                .then_with(|| left_jid.cmp(right_jid))
        });
        let mut allowed = Vec::with_capacity(candidates.len());
        for (key, session) in candidates {
            match port.privacy_allows_fallback(&session, sender).await {
                Ok(true) => allowed.push((key, session)),
                Ok(false) => {}
                Err(error) if delivery.is_some() => {
                    port.post_accept_failed();
                    tracing::warn!(
                        ?error,
                        target = %key,
                        %recipient_id,
                        "privacy policy failed closed during post-admission full-JID fallback"
                    );
                }
                Err(error) => return Err(error),
            }
        }
        Ok(FullJidFallbackPlan::Targets(allowed))
    }
}

pub(crate) struct OfflinePostCommitPush {
    pub(crate) admission: OfflineAdmissionOutcome,
    pub(crate) push_error: Option<anyhow::Error>,
}

/// An offline claim or its MAM recovery must commit before Push can call an
/// external provider. A replay is already accepted but must not notify twice.
pub(crate) async fn admit_offline_then_push<A, P>(
    admission: A,
    history_committed: bool,
    push: P,
) -> Result<OfflinePostCommitPush>
where
    A: Future<Output = Result<OfflineAdmissionOutcome>>,
    P: Future<Output = Result<()>>,
{
    let admission = admission.await?;
    let notify = matches!(admission, OfflineAdmissionOutcome::Stored)
        || (history_committed && matches!(admission, OfflineAdmissionOutcome::QuotaExceeded));
    let push_error = if notify { push.await.err() } else { None };
    Ok(OfflinePostCommitPush {
        admission,
        push_error,
    })
}

pub(crate) struct RemoteMucInviteAdmission<'a> {
    pub(crate) local_actor_id: Uuid,
    pub(crate) identity: Option<MessageIdentity<'a>>,
    pub(crate) archives: &'a [ArchiveWrite<'a>],
    pub(crate) room_id: Uuid,
    pub(crate) invitee_bare_jid: &'a str,
    pub(crate) target_domain: &'a str,
    pub(crate) stanza: &'a str,
    pub(crate) bounce_to: Option<&'a str>,
    pub(crate) outbox_policy: FederationOutboxPolicy,
    pub(crate) cluster_authority: Option<&'a ClusterMucInviteAuthority>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RemoteMucInviteAdmissionOutcome {
    Stored,
    Replay,
    AccountUnavailable,
    Rejected,
    Stale,
    Conflict,
}

pub(crate) struct OfflineMessageAdmission<'a> {
    pub(crate) recipient_id: Uuid,
    pub(crate) recipient_bare_jid: &'a str,
    pub(crate) sender_jid: &'a str,
    pub(crate) stanza: &'a str,
    pub(crate) encrypted: bool,
    pub(crate) mam_backed: bool,
    pub(crate) identity: Option<&'a MessageDedupeIdentity>,
}

/// One application-level members-only direct invitation admission. The
/// service owns the transaction spanning personal history, origin identity,
/// recoverable C2S delivery and MUC affiliation authorization.
pub(crate) struct LocalMucInviteAdmission<'a> {
    pub(crate) local_actor_id: Uuid,
    pub(crate) identity: Option<MessageIdentity<'a>>,
    pub(crate) archives: &'a [ArchiveWrite<'a>],
    pub(crate) delivery_id: Uuid,
    pub(crate) recipient_id: Uuid,
    pub(crate) recipient_bare_jid: &'a str,
    pub(crate) sender_jid: &'a str,
    pub(crate) stanza: &'a str,
    pub(crate) encrypted: bool,
    pub(crate) mam_backed: bool,
    pub(crate) room_id: Uuid,
    pub(crate) cluster_authority: Option<&'a ClusterMucInviteAuthority>,
}

/// Each admission commits all requested history, delivery and affiliation
/// changes atomically. An error after requesting COMMIT can leave its outcome
/// unknown; it is not evidence that an atomic admission rolled back.
pub(crate) trait MessageRepository:
    PersonalMessageCommitRepository<Error = anyhow::Error>
    + DirectCommitRepository<Error = anyhow::Error>
    + Clone
    + Send
    + Sync
{
    fn direct_mode(&self) -> DirectPostCommitMode;
    fn clustered_direct_admission_enabled(&self) -> bool;
    fn release_live_direct_claim(
        &self,
        recipient_id: Uuid,
        message_id: Uuid,
        claim_id: Uuid,
    ) -> impl Future<Output = Result<bool>> + Send;
    fn authorize_outbound_message(
        &self,
        owner_id: Uuid,
        owner_bare_jid: &str,
        active_privacy_list: Option<&str>,
        target: &str,
    ) -> impl Future<Output = Result<OutboundPolicyDecision>> + Send;
    fn resolve_local_recipient(
        &self,
        username: &str,
        local_domain: &str,
        sender_jid: &str,
    ) -> impl Future<Output = Result<LocalRecipientDecision>> + Send;
    fn default_recipient_privacy_denies(
        &self,
        recipient_id: Uuid,
        sender_jid: &str,
    ) -> impl Future<Output = Result<bool>> + Send;
    fn privacy_allows_session(
        &self,
        user_id: Uuid,
        connection_id: Uuid,
        active_privacy_list: Option<&str>,
        peer: &str,
        kind: PrivacyStanzaKind,
    ) -> impl Future<Output = Result<bool>> + Send;
    fn archive_allowed(
        &self,
        owner_id: Uuid,
        peer_jid: &str,
    ) -> impl Future<Output = Result<bool>> + Send;
    fn admit_remote_muc_invite(
        &self,
        request: &RemoteMucInviteAdmission<'_>,
    ) -> impl Future<Output = Result<RemoteMucInviteAdmissionOutcome>> + Send;
    fn admit_local_muc_invite(
        &self,
        request: &LocalMucInviteAdmission<'_>,
    ) -> impl Future<Output = Result<DurableMucInviteOutcome>> + Send;
    fn admit_history(&self, writes: &[ArchiveWrite<'_>])
        -> impl Future<Output = Result<()>> + Send;
    fn store_offline(
        &self,
        admission: OfflineMessageAdmission<'_>,
    ) -> impl Future<Output = Result<OfflineAdmissionOutcome>> + Send;
}

#[derive(Clone)]
pub(crate) struct MessageService<R> {
    personal: MessageApplication<R>,
    repository: R,
    require_encrypted_archive: bool,
}

impl<R: MessageRepository> MessageService<R> {
    pub(crate) fn new(repository: R, require_encrypted_archive: bool) -> Self {
        Self {
            personal: MessageApplication::new(repository.clone()),
            repository,
            require_encrypted_archive,
        }
    }

    pub(crate) fn direct_mode(&self) -> DirectPostCommitMode {
        self.repository.direct_mode()
    }

    pub(crate) fn clustered_direct_admission_enabled(&self) -> bool {
        self.repository.clustered_direct_admission_enabled()
    }

    pub(crate) async fn admit_personal_message_with_mode(
        &self,
        request: &ValidatedPersonalMessage<'_>,
        eligibility: DirectSpoolEligibility,
    ) -> Result<DirectPersonalMessageAdmission> {
        self.personal
            .commit_direct(request, eligibility, None)
            .await
            .map_err(direct_commit_error)
    }

    pub(crate) async fn admit_prepared_personal_message_with_mode(
        &self,
        prepared: &direct_workflow::PreparedLocalDirect<'_, '_>,
    ) -> Result<DirectPersonalMessageAdmission> {
        self.personal
            .commit_direct(prepared.command(), prepared.eligibility(), Some(prepared))
            .await
            .map_err(direct_commit_error)
    }

    /// Rearm recovery only when the initial live reservation still owns the
    /// exact row. A transport that already fenced the row wins the CAS.
    pub(crate) async fn release_live_direct_claim(
        &self,
        recipient_id: Uuid,
        message_id: Uuid,
        claim_id: Uuid,
    ) -> Result<bool> {
        self.repository
            .release_live_direct_claim(recipient_id, message_id, claim_id)
            .await
    }

    /// A committed stanza has no known transport owner. Relinquish only its
    /// initial reservation, allowing the durable wake to retry promptly. A
    /// concurrent socket/SM/BOSH ownership transfer makes the CAS lose safely.
    pub(crate) async fn rearm_unrouted_live_direct(
        &self,
        recipient_id: Uuid,
        message_id: Uuid,
        claim_id: &mut Option<Uuid>,
    ) {
        let Some(claim_id) = claim_id.take() else {
            return;
        };
        if let Err(error) = self
            .release_live_direct_claim(recipient_id, message_id, claim_id)
            .await
        {
            // PostgreSQL still has the row and its bounded claim lease. A
            // post-commit failure cannot turn accepted content into a stanza
            // error inviting a second admission.
            tracing::warn!(?error, %recipient_id, %message_id, %claim_id,
                "could not promptly rearm unrouted committed direct delivery");
        }
    }
    pub(crate) async fn authorize_outbound_message(
        &self,
        owner_id: Uuid,
        owner_bare_jid: &str,
        active_privacy_list: Option<&str>,
        target: &str,
    ) -> Result<OutboundPolicyDecision> {
        self.repository
            .authorize_outbound_message(owner_id, owner_bare_jid, active_privacy_list, target)
            .await
    }

    pub(crate) async fn resolve_local_recipient(
        &self,
        username: &str,
        local_domain: &str,
        sender_jid: &str,
    ) -> Result<LocalRecipientDecision> {
        self.repository
            .resolve_local_recipient(username, local_domain, sender_jid)
            .await
    }

    pub(crate) async fn default_recipient_privacy_denies(
        &self,
        recipient_id: Uuid,
        sender_jid: &str,
    ) -> Result<bool> {
        self.repository
            .default_recipient_privacy_denies(recipient_id, sender_jid)
            .await
    }

    pub(crate) async fn privacy_allows_session(
        &self,
        user_id: Uuid,
        connection_id: Uuid,
        active_privacy_list: Option<&str>,
        peer: &str,
        kind: PrivacyStanzaKind,
    ) -> Result<bool> {
        self.repository
            .privacy_allows_session(user_id, connection_id, active_privacy_list, peer, kind)
            .await
    }

    pub(crate) async fn admit_remote_muc_invite(
        &self,
        request: &RemoteMucInviteAdmission<'_>,
    ) -> Result<RemoteMucInviteAdmissionOutcome> {
        self.repository.admit_remote_muc_invite(request).await
    }

    pub(crate) async fn admit_local_muc_invite(
        &self,
        request: &LocalMucInviteAdmission<'_>,
    ) -> Result<DurableMucInviteOutcome> {
        self.repository.admit_local_muc_invite(request).await
    }

    pub(crate) async fn admit_history(&self, writes: &[ArchiveWrite<'_>]) -> Result<()> {
        self.repository.admit_history(writes).await
    }

    pub(crate) async fn store_offline(
        &self,
        admission: OfflineMessageAdmission<'_>,
    ) -> Result<OfflineAdmissionOutcome> {
        self.repository.store_offline(admission).await
    }

    /// Combine stanza storage semantics, deployment encryption policy and the
    /// account's MAM preference. Retractions are always history mutations and
    /// therefore bypass ordinary content-storage eligibility.
    pub(crate) async fn archive_enabled(
        &self,
        owner_id: Uuid,
        peer_jid: &str,
        stanza_storage_eligible: bool,
        encrypted: bool,
        retraction: bool,
    ) -> Result<bool> {
        if retraction {
            return Ok(true);
        }
        if !stanza_storage_eligible || (self.require_encrypted_archive && !encrypted) {
            return Ok(false);
        }
        self.repository.archive_allowed(owner_id, peer_jid).await
    }

    /// Commit one validated personal-message command through its authoritative
    /// local-delivery or federation-outbox transaction. Protocol origin does
    /// not select a repository function; the typed destination and identity
    /// authority do, preventing C2S and S2S adapters from drifting apart.
    pub(crate) async fn admit_personal_message(
        &self,
        request: &ValidatedPersonalMessage<'_>,
    ) -> Result<DurableAdmissionOutcome> {
        match self.personal.commit(request).await {
            Ok(commit) => Ok(commit),
            Err(CommitError::Invalid(error)) => {
                anyhow::bail!("invalid personal-message command: {error:?}")
            }
            Err(CommitError::Repository(error)) => Err(error),
        }
    }
}

fn direct_commit_error(error: DirectCommitError<anyhow::Error>) -> anyhow::Error {
    match error {
        DirectCommitError::Invalid(error) => {
            anyhow::anyhow!("invalid personal-message command: {error:?}")
        }
        DirectCommitError::Observation { error, outcome } => {
            direct_workflow::continuation_error(error.into(), outcome)
        }
        DirectCommitError::Repository { error, outcome } => {
            direct_workflow::continuation_error(error, outcome)
        }
    }
}

#[cfg(test)]
#[path = "messaging_tests.rs"]
mod post_commit_tests;
