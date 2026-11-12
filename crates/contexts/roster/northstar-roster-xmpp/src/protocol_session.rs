//! The protocol session as this context sees it: the impls of this crate's session ports for
//! `northstar_stream::protocol::ProtocolSession`.

use crate::RosterSessionHost;
use anyhow::Result;
use northstar_federation_core::FederationRoute as _;
use northstar_roster_application::blocking::{BlockingRepository, BlockingService};
use northstar_roster_application::presence::{PresenceRepository, PresenceService};
use northstar_roster_application::privacy::{PrivacyRepository, PrivacyService};
use northstar_roster_application::{
    BeginRosterSyncError, RosterRepository, RosterService, RosterSyncPermit, S2sOutboxPolicy,
};
use northstar_roster_core::PresenceAccount;
use northstar_roster_core::{LocalRosterContact, RosterChange};
use northstar_stream::protocol::{ProtocolSession, SessionHost};
use std::sync::atomic::Ordering;

// From src/xmpp/protocol/roster_identity.rs.
impl<H: SessionHost> crate::SessionIdentity for ProtocolSession<H> {
    fn session_account(&self) -> Option<PresenceAccount> {
        self.authenticated.as_ref().map(|user| PresenceAccount {
            id: user.id,
            username: user.username.clone(),
            auth_generation: user.auth_generation,
        })
    }

    fn session_local_domain(&self) -> &str {
        self.host().local_domain()
    }
}

// From src/xmpp/protocol/blocking.rs.
impl<H: SessionHost + RosterSessionHost> crate::blocking::BlockingSession for ProtocolSession<H> {
    fn blocking_service(&self) -> &BlockingService<impl BlockingRepository> {
        self.host().blocking_service()
    }

    fn blocking_mark_requested(&self) {
        self.blocklist_requested.store(true, Ordering::Release);
    }

    async fn blocking_push_change(&self, owner: &str, payload: &str) {
        self.host().push_blocklist_change(owner, payload).await;
    }

    async fn blocking_presence_change(
        &self,
        owner: &str,
        targets: &[String],
        changed_patterns: &[String],
        available: bool,
    ) {
        self.host()
            .deliver_blocking_presence_change(owner, targets, changed_patterns, available)
            .await;
    }
}

// From src/xmpp/protocol/privacy.rs.
impl<H: SessionHost + RosterSessionHost> crate::privacy::PrivacySession for ProtocolSession<H> {
    fn privacy_full_jid(&self) -> Option<&str> {
        self.full_jid.as_deref()
    }

    fn privacy_connection_id(&self) -> uuid::Uuid {
        self.connection_id
    }

    fn privacy_service(&self) -> &PrivacyService<impl PrivacyRepository> {
        self.host().privacy_service()
    }

    fn privacy_mark_requested(&self) {
        self.privacy_requested.store(true, Ordering::Release);
    }

    fn privacy_active_list(&self) -> Option<String> {
        self.privacy_active
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn privacy_set_active_list(&self, name: Option<String>) {
        *self
            .privacy_active
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = name;
    }

    fn privacy_local_resources(&self, account: &str) -> usize {
        self.host().local_resource_count(account)
    }

    async fn privacy_has_remote_resources(&self, account: &str) -> Result<bool> {
        self.host().account_has_remote_resources(account).await
    }

    fn privacy_list_active_locally(&self, account: &str, name: &str) -> bool {
        self.host().privacy_list_active_locally(account, name)
    }

    async fn privacy_push_change(&self, account: &str, name: &str, base: &str) -> Option<String> {
        self.host()
            .push_privacy_change(account, name, base, self.connection_id)
            .await
    }
}

// From src/xmpp/protocol/presence/session.rs.
impl<H: SessionHost + RosterSessionHost> crate::presence::PresenceSession for ProtocolSession<H> {
    fn presence_service(&self) -> &PresenceService<impl PresenceRepository> {
        self.host().presence_service()
    }

    fn presence_is_available(&self) -> bool {
        self.available
            .as_ref()
            .is_some_and(|available| available.load(Ordering::Relaxed))
    }

    fn presence_set_last(&self, presence: Option<String>) {
        *self
            .last_presence
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = presence;
    }

    fn presence_try_send(&self, stanza: String) {
        let _ = self.outbound.try_send(stanza);
    }

    async fn presence_send(&self, stanza: String) -> Result<()> {
        self.outbound
            .send(stanza)
            .await
            .map_err(|_| anyhow::anyhow!("client delivery queue closed"))
    }

    fn presence_directed_contains(&self, target: &str) -> bool {
        self.directed_presence.contains(target)
    }

    fn presence_directed_count(&self) -> usize {
        self.directed_presence.len()
    }

    fn presence_directed_insert(&self, target: String) {
        self.directed_presence.insert(target);
    }

    fn presence_directed_remove(&self, target: &str) {
        self.directed_presence.remove(target);
    }

    fn presence_directed_retain(&self, keep: impl Fn(&str) -> bool) {
        self.directed_presence.retain(|target| keep(target));
    }

    fn presence_directed_take(&self) -> Vec<String> {
        let targets = self
            .directed_presence
            .iter()
            .map(|target| target.key().clone())
            .collect::<Vec<_>>();
        self.directed_presence.clear();
        targets
    }

    fn presence_route_allowed(&self, domain: &str) -> bool {
        self.host().xmpp_external_route_domain_allowed(domain)
    }

    fn presence_is_component_domain(&self, domain: &str) -> bool {
        self.host().presence_component_domain(domain)
    }

    async fn presence_send_federated(
        &self,
        domain: &str,
        stanza: String,
        bounce_to: Option<String>,
    ) -> bool {
        self.host()
            .federation_outbox()
            .send(domain, stanza, bounce_to)
            .await
    }

    async fn presence_deliver_directed(
        &self,
        to: &str,
        canonical_to: &str,
        from: &str,
        stanza: &str,
        bare_target: bool,
    ) -> Result<bool> {
        self.host()
            .deliver_directed_presence(to, canonical_to, from, stanza, bare_target)
            .await
    }

    async fn presence_deliver_subscription(
        &self,
        owner: &PresenceAccount,
        recipient: &PresenceAccount,
        owner_bare: &str,
        recipient_bare: &str,
        stanza: &str,
    ) -> Result<()> {
        self.host()
            .deliver_subscription_presence(owner, recipient, owner_bare, recipient_bare, stanza)
            .await
    }

    async fn presence_deliver_approval(
        &self,
        owner: &PresenceAccount,
        recipient: &PresenceAccount,
        owner_bare: &str,
        recipient_bare: &str,
        approved: &str,
    ) -> Result<()> {
        self.host()
            .deliver_subscription_approval(
                owner,
                recipient,
                owner_bare,
                recipient_bare,
                approved,
                self.full_jid.as_deref(),
            )
            .await
    }

    async fn presence_deliver_to_contact(
        &self,
        contact: &str,
        from: &str,
        stanza: &str,
    ) -> Result<()> {
        self.host()
            .deliver_contact_presence(contact, from, stanza)
            .await
    }

    async fn presence_echo_to_account(&self, account: &str, from: &str, stanza: &str) {
        self.host()
            .echo_account_presence(account, from, stanza)
            .await;
    }

    async fn presence_deliver_directed_unavailable(
        &self,
        target: &str,
        bare_target: bool,
        from: &str,
        stanza: &str,
    ) {
        self.host()
            .deliver_directed_unavailable(target, bare_target, from, stanza)
            .await;
    }

    fn presence_has_available_resource(&self, bare: &str) -> bool {
        self.host().account_has_available_resource(bare)
    }

    async fn presence_probe_has_remote_owner(&self, bare: &str) -> Result<bool> {
        self.host().probe_has_remote_owner(bare).await
    }

    fn presence_directed_recipient(&self, owner_full: &str, requester: &str) -> bool {
        self.host()
            .directed_presence_recipient(owner_full, requester)
    }

    async fn presence_answer_full_probe(
        &self,
        owner_full: &str,
        owner_bare: &str,
        requester: &str,
        probe_id: Option<&str>,
    ) -> Result<()> {
        if let Some(reply) = self
            .host()
            .answer_full_presence_probe(owner_full, owner_bare, requester, probe_id)
            .await?
        {
            let _ = self.outbound.try_send(reply);
        }
        Ok(())
    }

    async fn presence_send_current(&self, owner: &str, recipient: &str) {
        self.host().send_current_presence(owner, recipient).await;
    }

    async fn presence_send_current_exact(
        &self,
        owner: &PresenceAccount,
        recipient: &PresenceAccount,
        owner_bare: &str,
        recipient_bare: &str,
    ) {
        self.host()
            .send_current_presence_exact(owner, recipient, owner_bare, recipient_bare)
            .await;
    }

    async fn presence_full_target_routed(&self, full_jid: &str) -> bool {
        self.host().full_presence_target_routed(full_jid).await
    }

    async fn presence_notify_offline(&self, user_id: uuid::Uuid) -> Result<()> {
        self.host().notify_offline_account(user_id).await
    }
}

// From src/xmpp/protocol/roster.rs.
impl<H: SessionHost + RosterSessionHost> crate::roster::RosterSession for ProtocolSession<H> {
    fn roster_service(&self) -> &RosterService<impl RosterRepository<Error = anyhow::Error>> {
        self.host().roster_service()
    }

    fn roster_full_jid(&self) -> Option<&str> {
        self.full_jid.as_deref()
    }

    fn roster_begin_sync(
        &self,
        annotations_requested: bool,
    ) -> std::result::Result<RosterSyncPermit, BeginRosterSyncError> {
        self.roster_sync.begin(
            &self.roster_requested,
            &self.mix_roster_annotations,
            annotations_requested,
        )
    }

    fn roster_fail_sync(&self, permit: RosterSyncPermit) {
        self.roster_sync.fail(permit);
    }

    fn roster_disconnect(&self) {
        self.disconnect.cancel();
    }

    fn roster_is_hosted_domain(&self, domain: &str) -> bool {
        domain == self.host().muc_domain()
            || domain == self.host().upload_domain()
            || domain == self.host().pubsub_domain()
    }

    fn roster_outbox_policy(&self) -> S2sOutboxPolicy {
        self.host().roster_outbox_policy()
    }

    fn roster_wake_outbox(&self) {
        self.host().roster_wake_outbox();
    }

    async fn roster_deliver_removal_presence(
        &self,
        owner: &PresenceAccount,
        recipient: &LocalRosterContact,
        target_bare: &str,
        stanza: &str,
    ) {
        self.host()
            .deliver_roster_removal_presence(owner, recipient, target_bare, stanza)
            .await;
    }

    async fn roster_push_change(
        &self,
        owner_id: uuid::Uuid,
        owner: &str,
        change: &RosterChange,
    ) -> Result<()> {
        self.host()
            .deliver_committed_roster_change(owner_id, owner, change, None)
            .await
    }
}
