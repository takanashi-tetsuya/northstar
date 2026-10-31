//! Application-service boundary for RFC 6121 presence and subscriptions.
//!
//! Protocol handlers own stanza validation, recipient fan-out and the
//! notification-before-roster-push ordering required by RFC 6121. This
//! service applies outbound policy and requests complete subscription
//! transitions through its repository port.

use anyhow::Result;
use chrono::{DateTime, Utc};
use uuid::Uuid;

pub use northstar_roster_core::{
    InboundRemotePresenceEffect, LocalPresenceEffect, PresenceAccount, PresencePolicyDenial,
    RosterChange,
};

/// An administrative notice with the revision, date and token needed to
/// acknowledge its exact delivery claim.
#[derive(Clone, Debug)]
pub struct ServiceMessageClaim {
    repository_claim: ServiceMessageDeliveryClaim,
}

impl ServiceMessageClaim {
    pub fn from_lease(repository_claim: ServiceMessageDeliveryClaim) -> Self {
        Self { repository_claim }
    }
    pub fn lease(&self) -> &ServiceMessageDeliveryClaim {
        &self.repository_claim
    }

    pub fn kind(&self) -> &str {
        &self.repository_claim.kind
    }

    pub fn body(&self) -> &str {
        &self.repository_claim.body
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum PresenceMutation<T> {
    Unauthorized,
    PolicyDenied(PresencePolicyDenial),
    Missing,
    Transition(T),
}

#[derive(Debug, Eq, PartialEq)]
pub struct LocalSubscriptionTransition {
    pub actor: PresenceAccount,
    pub target: PresenceAccount,
    pub effect: LocalPresenceEffect,
    pub actor_subscription: String,
    pub actor_change: Option<RosterChange>,
    pub target_change: Option<RosterChange>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct RemoteSubscriptionTransition {
    pub actor: PresenceAccount,
    pub subscription: String,
    pub change: Option<RosterChange>,
    pub routed: bool,
}

#[derive(Debug, Eq, PartialEq)]
pub struct InboundSubscriptionTransition {
    pub recipient: PresenceAccount,
    pub effect: InboundRemotePresenceEffect,
    pub subscription: String,
    pub change: Option<RosterChange>,
    pub auto_reply: Option<&'static str>,
    pub send_unavailable: bool,
}

/// The complete authority and stanza input for one local subscription
/// mutation. Keeping these values together prevents call sites from swapping
/// the two generations, identities, or domains in a positional argument list.
pub struct LocalSubscriptionRequest<'a> {
    pub actor_id: Uuid,
    pub expected_auth_generation: i64,
    pub connection_id: Uuid,
    pub local_domain: &'a str,
    pub target_username: &'a str,
    pub kind: &'a str,
    pub stanza: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceMessageDeliveryClaim {
    pub kind: String,
    pub body: String,
    pub revision: Uuid,
    pub delivery_date: chrono::NaiveDate,
    pub claim_id: Uuid,
}

pub trait PresenceRepository: Send + Sync {
    fn roster_subscriptions(
        &self,
        owner_id: Uuid,
    ) -> impl std::future::Future<Output = Result<Vec<(String, String)>>> + Send;

    fn is_blocked_for_account(
        &self,
        owner_id: Uuid,
        owner_bare_jid: &str,
        candidate: &str,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn privacy_denies(
        &self,
        owner_id: Uuid,
        active_list: Option<&str>,
        candidate: &str,
        kind: northstar_xep_0016::PrivacyStanzaKind,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn avatar_hash(
        &self,
        user_id: Uuid,
    ) -> impl std::future::Future<Output = Result<Option<String>>> + Send;
    fn find_enabled_user(
        &self,
        username: &str,
    ) -> impl std::future::Future<Output = Result<Option<PresenceAccount>>> + Send;
    fn roster_subscription(
        &self,
        owner_id: Uuid,
        contact: &str,
    ) -> impl std::future::Future<Output = Result<Option<String>>> + Send;
    fn replay_cutoff(&self) -> impl std::future::Future<Output = Result<DateTime<Utc>>> + Send;
    fn claim_service_messages(
        &self,
        user_id: Uuid,
    ) -> impl std::future::Future<Output = Result<Vec<ServiceMessageClaim>>> + Send;
    fn complete_service_message_claim(
        &self,
        user_id: Uuid,
        claim: &ServiceMessageClaim,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    #[allow(clippy::too_many_arguments)]
    fn transition_remote_with_outbox(
        &self,
        actor_id: Uuid,
        expected_auth_generation: i64,
        connection_id: Uuid,
        local_domain: &str,
        contact: &str,
        kind: &str,
        target_domain: &str,
        stanza: &str,
        bounce_to: Option<&str>,
        policy: crate::S2sOutboxPolicy,
    ) -> impl std::future::Future<Output = Result<PresenceMutation<RemoteSubscriptionTransition>>> + Send;
    fn transition_remote(
        &self,
        actor_id: Uuid,
        expected_auth_generation: i64,
        connection_id: Uuid,
        local_domain: &str,
        contact: &str,
        kind: &str,
    ) -> impl std::future::Future<Output = Result<PresenceMutation<RemoteSubscriptionTransition>>> + Send;
    fn transition_local(
        &self,
        request: LocalSubscriptionRequest<'_>,
    ) -> impl std::future::Future<Output = Result<PresenceMutation<LocalSubscriptionTransition>>> + Send;
    fn transition_inbound(
        &self,
        recipient_id: Uuid,
        local_domain: &str,
        contact: &str,
        kind: &str,
        stanza: &str,
    ) -> impl std::future::Future<Output = Result<PresenceMutation<InboundSubscriptionTransition>>> + Send;
    #[allow(clippy::too_many_arguments)]
    fn cluster_authority_is_current(
        &self,
        local_domain: &str,
        owner_jid: &str,
        owner_id: Uuid,
        owner_auth_generation: i64,
        recipient_jid: &str,
        recipient_id: Uuid,
        recipient_auth_generation: i64,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
}

#[derive(Clone)]
pub struct PresenceService<R> {
    repository: R,
}
impl<R: PresenceRepository> PresenceService<R> {
    /// Cleanup must notify existing subscribers even after credentials expire.
    /// Delivery still applies the recipient's current blocking/privacy policy.
    pub async fn unavailable_recipients(&self, owner_id: Uuid) -> Result<Vec<String>> {
        Ok(self
            .repository
            .roster_subscriptions(owner_id)
            .await?
            .into_iter()
            .filter_map(|(jid, subscription)| {
                matches!(subscription.as_str(), "from" | "both").then_some(jid)
            })
            .collect())
    }

    pub fn new(repository: R) -> Self {
        Self { repository }
    }
    pub async fn is_blocked_for_account(
        &self,
        owner_id: Uuid,
        owner_bare_jid: &str,
        candidate: &str,
    ) -> Result<bool> {
        self.repository
            .is_blocked_for_account(owner_id, owner_bare_jid, candidate)
            .await
    }

    pub async fn privacy_denies(
        &self,
        owner_id: Uuid,
        active_list: Option<&str>,
        candidate: &str,
        kind: northstar_xep_0016::PrivacyStanzaKind,
    ) -> Result<bool> {
        self.repository
            .privacy_denies(owner_id, active_list, candidate, kind)
            .await
    }

    /// Blocking takes precedence over the active/default privacy list.
    pub async fn outbound_denied(
        &self,
        owner_id: Uuid,
        owner_bare_jid: &str,
        active_list: Option<&str>,
        candidate: &str,
    ) -> Result<bool> {
        if self
            .is_blocked_for_account(owner_id, owner_bare_jid, candidate)
            .await?
        {
            return Ok(true);
        }
        self.privacy_denies(
            owner_id,
            active_list,
            candidate,
            northstar_xep_0016::PrivacyStanzaKind::PresenceOut,
        )
        .await
    }

    pub async fn avatar_hash(&self, user_id: Uuid) -> Result<Option<String>> {
        self.repository.avatar_hash(user_id).await
    }

    pub async fn find_enabled_user(&self, username: &str) -> Result<Option<PresenceAccount>> {
        self.repository.find_enabled_user(username).await
    }

    pub async fn roster_subscription(
        &self,
        owner_id: Uuid,
        contact: &str,
    ) -> Result<Option<String>> {
        self.repository.roster_subscription(owner_id, contact).await
    }

    /// Use the repository clock as the durable replay fence.
    pub async fn replay_cutoff(&self) -> Result<DateTime<Utc>> {
        self.repository.replay_cutoff().await
    }

    pub async fn claim_service_messages(&self, user_id: Uuid) -> Result<Vec<ServiceMessageClaim>> {
        self.repository.claim_service_messages(user_id).await
    }

    pub async fn complete_service_message_claim(
        &self,
        user_id: Uuid,
        claim: &ServiceMessageClaim,
    ) -> Result<bool> {
        self.repository
            .complete_service_message_claim(user_id, claim)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn transition_remote_with_outbox(
        &self,
        actor_id: Uuid,
        expected_auth_generation: i64,
        connection_id: Uuid,
        local_domain: &str,
        contact: &str,
        kind: &str,
        target_domain: &str,
        stanza: &str,
        bounce_to: Option<&str>,
        policy: crate::S2sOutboxPolicy,
    ) -> Result<PresenceMutation<RemoteSubscriptionTransition>> {
        self.repository
            .transition_remote_with_outbox(
                actor_id,
                expected_auth_generation,
                connection_id,
                local_domain,
                contact,
                kind,
                target_domain,
                stanza,
                bounce_to,
                policy,
            )
            .await
    }

    pub async fn transition_remote(
        &self,
        actor_id: Uuid,
        expected_auth_generation: i64,
        connection_id: Uuid,
        local_domain: &str,
        contact: &str,
        kind: &str,
    ) -> Result<PresenceMutation<RemoteSubscriptionTransition>> {
        self.repository
            .transition_remote(
                actor_id,
                expected_auth_generation,
                connection_id,
                local_domain,
                contact,
                kind,
            )
            .await
    }

    pub async fn transition_local(
        &self,
        request: LocalSubscriptionRequest<'_>,
    ) -> Result<PresenceMutation<LocalSubscriptionTransition>> {
        self.repository.transition_local(request).await
    }

    pub async fn transition_inbound(
        &self,
        recipient_id: Uuid,
        local_domain: &str,
        contact: &str,
        kind: &str,
        stanza: &str,
    ) -> Result<PresenceMutation<InboundSubscriptionTransition>> {
        self.repository
            .transition_inbound(recipient_id, local_domain, contact, kind, stanza)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn cluster_authority_is_current(
        &self,
        local_domain: &str,
        owner_jid: &str,
        owner_id: Uuid,
        owner_auth_generation: i64,
        recipient_jid: &str,
        recipient_id: Uuid,
        recipient_auth_generation: i64,
    ) -> Result<bool> {
        self.repository
            .cluster_authority_is_current(
                local_domain,
                owner_jid,
                owner_id,
                owner_auth_generation,
                recipient_jid,
                recipient_id,
                recipient_auth_generation,
            )
            .await
    }
}
