//! Personal-message policy and atomic admission through a persistence port.

use super::{
    muc::{ClusterMucInviteAuthority, DurableMucInviteOutcome},
    privacy::PrivacyStanzaKind,
    retractions::FederationOutboxPolicy,
};
use crate::abuse::MessageDedupeIdentity;
use crate::outbound::DurableDelivery;
use anyhow::Result;
use northstar_message_application::{
    CommitError, MessageApplication, PersonalMessageCommitRepository,
};
pub(crate) use northstar_message_core::{
    ArchiveProjection as ArchiveWrite, FederationDelivery, IdentityAuthority, LocalDelivery,
    MessageCommit as DurableAdmissionOutcome, MessageIdentity, MessagePostCommit,
    PersonalMessageDestination, ValidatedPersonalMessage,
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
        stanza: String,
        delivery: Option<DurableDelivery>,
    ) -> bool;
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
    pub(crate) stanza: &'a str,
    pub(crate) delivery: Option<DurableDelivery>,
}

pub(crate) struct OnlineMessageRouter;

impl OnlineMessageRouter {
    /// Route an accepted stanza without touching its transaction owner. A
    /// durable delivery has one transport owner; headline fanout is volatile.
    pub(crate) async fn dispatch<P: OnlineRoutePort>(
        port: &P,
        jid: &str,
        stanza: &str,
        delivery: Option<DurableDelivery>,
        deliver_all: bool,
        approved_targets: &[(String, P::Session)],
    ) -> OnlineRouteResult {
        debug_assert!(
            !(delivery.is_some() && deliver_all),
            "one durable C2S fence cannot be fanned out to multiple resources"
        );
        let mut result = OnlineRouteResult::default();
        for (key, session) in approved_targets {
            if port.try_local(session, stanza.to_owned(), delivery) {
                port.record_local_accept(delivery.is_some());
                if result.accepted_full_jid.is_none() {
                    result.accepted_full_jid = Some(key.clone());
                }
                result.delivered = true;
                if !deliver_all {
                    break;
                }
            }
        }
        if deliver_all {
            result.delivered |= port.route_available_remote(jid, stanza, delivery).await;
        } else if !result.delivered {
            result = port.route_remote_primary(jid, stanza, delivery).await;
        }
        result
    }

    /// RFC 6121 full-JID mismatch handling after the exact route declined.
    /// Privacy for every candidate is checked before any fallback enqueue.
    pub(crate) async fn full_jid_fallback<P: FullJidFallbackPort>(
        port: &P,
        request: FullJidFallback<'_>,
    ) -> Result<FullJidFallbackResult> {
        use northstar_message_core::{
            durable_full_no_match_recovers, full_no_match_route, FullNoMatchRoute,
        };
        let FullJidFallback {
            message_type,
            full_target,
            bare_target,
            sender,
            recipient_id,
            stanza,
            delivery,
        } = request;

        match full_no_match_route(message_type) {
            FullNoMatchRoute::Ignore => return Ok(FullJidFallbackResult::Dropped),
            FullNoMatchRoute::Reject
                if durable_full_no_match_recovers(message_type, delivery.is_some()) =>
            {
                port.post_accept_failed();
                tracing::warn!(
                    %recipient_id,
                    target = %full_target,
                    "exact full-JID route disappeared after durable admission; resource-affine row remains replayable"
                );
                return Ok(FullJidFallbackResult::Undelivered);
            }
            FullNoMatchRoute::Reject => return Ok(FullJidFallbackResult::Rejected),
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
        for (key, session) in allowed {
            if port.try_local(&session, stanza.to_owned(), delivery) {
                port.record_local_accept(delivery.is_some());
                return Ok(FullJidFallbackResult::Delivered(Some(key)));
            }
        }
        let remote = port
            .route_remote_primary(bare_target, stanza, delivery)
            .await;
        if remote.delivered {
            Ok(FullJidFallbackResult::Delivered(remote.accepted_full_jid))
        } else {
            Ok(FullJidFallbackResult::Undelivered)
        }
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
/// changes together. A denial or error must leave no partial admission.
pub(crate) trait MessageRepository:
    PersonalMessageCommitRepository<Error = anyhow::Error> + Clone + Send + Sync
{
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

#[cfg(test)]
#[path = "messaging_tests.rs"]
mod post_commit_tests;
