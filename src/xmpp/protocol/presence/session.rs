//! The client session as the presence handlers see it. The fan-out over online sessions stays here
//! until the session context moves.

use super::*;
use northstar_federation_core::FederationRoute as _;
use northstar_roster_xmpp::RosterSessionHost;

impl<H: SessionHost + RosterSessionHost> northstar_roster_xmpp::presence::PresenceSession
    for ProtocolSession<H>
{
    fn presence_service(&self) -> &PresenceService<impl PresenceRepository> {
        self.host.presence_service()
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
        self.host.xmpp_external_route_domain_allowed(domain)
    }

    fn presence_is_component_domain(&self, domain: &str) -> bool {
        self.host.presence_component_domain(domain)
    }

    async fn presence_send_federated(
        &self,
        domain: &str,
        stanza: String,
        bounce_to: Option<String>,
    ) -> bool {
        self.host
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
        self.host
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
        self.host
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
        self.host
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
        self.host
            .deliver_contact_presence(contact, from, stanza)
            .await
    }

    async fn presence_echo_to_account(&self, account: &str, from: &str, stanza: &str) {
        self.host.echo_account_presence(account, from, stanza).await;
    }

    async fn presence_deliver_directed_unavailable(
        &self,
        target: &str,
        bare_target: bool,
        from: &str,
        stanza: &str,
    ) {
        self.host
            .deliver_directed_unavailable(target, bare_target, from, stanza)
            .await;
    }

    fn presence_has_available_resource(&self, bare: &str) -> bool {
        self.host.account_has_available_resource(bare)
    }

    async fn presence_probe_has_remote_owner(&self, bare: &str) -> Result<bool> {
        self.host.probe_has_remote_owner(bare).await
    }

    fn presence_directed_recipient(&self, owner_full: &str, requester: &str) -> bool {
        self.host.directed_presence_recipient(owner_full, requester)
    }

    async fn presence_answer_full_probe(
        &self,
        owner_full: &str,
        owner_bare: &str,
        requester: &str,
        probe_id: Option<&str>,
    ) -> Result<()> {
        if let Some(reply) = self
            .host
            .answer_full_presence_probe(owner_full, owner_bare, requester, probe_id)
            .await?
        {
            let _ = self.outbound.try_send(reply);
        }
        Ok(())
    }

    async fn presence_send_current(&self, owner: &str, recipient: &str) {
        self.host.send_current_presence(owner, recipient).await;
    }

    async fn presence_send_current_exact(
        &self,
        owner: &PresenceAccount,
        recipient: &PresenceAccount,
        owner_bare: &str,
        recipient_bare: &str,
    ) {
        self.host
            .send_current_presence_exact(owner, recipient, owner_bare, recipient_bare)
            .await;
    }

    async fn presence_full_target_routed(&self, full_jid: &str) -> bool {
        self.host.full_presence_target_routed(full_jid).await
    }

    async fn presence_notify_offline(&self, user_id: uuid::Uuid) -> Result<()> {
        self.host.notify_offline_account(user_id).await
    }
}
