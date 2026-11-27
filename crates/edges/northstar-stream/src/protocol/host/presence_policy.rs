use crate::local_routes::session::OnlineSession;

/// Presence services and per-session privacy policy.
pub trait SessionPresencePolicyHost: Send + Sync + 'static {
    /// The repository behind [`SessionPresencePolicyHost::presence_service`].
    type PresenceStore: northstar_roster_application::presence::PresenceRepository
        + northstar_roster_application::subscription_retry::SubscriptionRetryRepository
        + 'static;
    /// The repository behind [`SessionPresencePolicyHost::privacy_service`].
    type PrivacyStore: northstar_roster_application::privacy::PrivacyRepository + 'static;
    /// See `ServerNode::presence_service`.
    fn presence_service(
        &self,
    ) -> &northstar_roster_application::presence::PresenceService<Self::PresenceStore>;
    /// Evaluate one resource's session-local XEP-0016 selection (or the
    /// account default when no active list is selected). Callers must apply
    /// XEP-0191 first; a blocking hit is never overridden by an allow rule.
    /// Stanza paths that still hold a storage-level kind convert it at this
    /// boundary; the service layer owns the mapping.
    fn privacy_allows_session(
        &self,
        session: &OnlineSession,
        peer: &str,
        kind: impl Into<northstar_roster_application::privacy::PrivacyStanzaKind> + Send,
    ) -> impl std::future::Future<Output = anyhow::Result<bool>> + Send;
    /// See `ServerNode::privacy_service`.
    fn privacy_service(
        &self,
    ) -> &northstar_roster_application::privacy::PrivacyService<Self::PrivacyStore>;
}
