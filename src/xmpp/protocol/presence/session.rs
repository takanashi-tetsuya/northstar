//! The client session as the presence handlers see it. The fan-out over online sessions stays here
//! until the session context moves.

use super::*;

fn cluster_authority(
    owner: &PresenceAccount,
    recipient: &PresenceAccount,
) -> crate::cluster::ClusterPresenceAuthority {
    crate::cluster::ClusterPresenceAuthority {
        owner_id: owner.id,
        owner_auth_generation: owner.auth_generation,
        recipient_id: recipient.id,
        recipient_auth_generation: recipient.auth_generation,
    }
}

impl northstar_roster_xmpp::presence::PresenceSession for ProtocolSession {
    fn presence_service(&self) -> &PresenceService<impl PresenceRepository> {
        self.state.presence_service()
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
        self.state.xmpp_external_route_domain_allowed(domain)
    }

    fn presence_is_component_domain(&self, domain: &str) -> bool {
        self.state.xmpp_component_domain_configured(domain)
    }

    async fn presence_send_federated(
        &self,
        domain: &str,
        stanza: String,
        bounce_to: Option<String>,
    ) -> bool {
        self.state
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
        let mut targets = self.state.session_entries_for(to);
        if bare_target {
            targets.retain(|(_, target)| target.available.load(Ordering::Relaxed));
        }
        let mut delivered = false;
        for (_, target) in targets {
            if self
                .state
                .privacy_allows_session(&target, from, PrivacyStanzaKind::PresenceIn)
                .await?
                && target.sender.try_send(stanza.to_owned()).is_ok()
            {
                delivered = true;
            }
        }
        delivered |= self
            .state
            .route_directed_presence_remote(canonical_to, stanza, bare_target)
            .await;
        Ok(delivered)
    }

    async fn presence_deliver_subscription(
        &self,
        owner: &PresenceAccount,
        recipient: &PresenceAccount,
        owner_bare: &str,
        recipient_bare: &str,
        stanza: &str,
    ) -> Result<()> {
        let mut targets = self.state.session_entries_for(recipient_bare);
        // RFC 6121 subscription-related presence is delivered to
        // available resources independently of roster interest.
        // `roster_requested` gates roster pushes only; using it here
        // can drop the approval on the exact resource that just sent
        // the subscription request after reconnecting.
        targets.retain(|(_, session)| {
            session.user_id == recipient.id
                && session.auth_generation == recipient.auth_generation
                && session.available.load(Ordering::Acquire)
        });
        for (target_full, session) in targets {
            if self
                .state
                .privacy_allows_session(&session, owner_bare, PrivacyStanzaKind::PresenceIn)
                .await?
            {
                let _ = session.sender.try_send(set_to(stanza, &target_full));
            }
        }
        self.state
            .route_presence_subscription_remote(
                recipient_bare,
                stanza,
                cluster_authority(owner, recipient),
            )
            .await;
        Ok(())
    }

    async fn presence_deliver_approval(
        &self,
        owner: &PresenceAccount,
        recipient: &PresenceAccount,
        owner_bare: &str,
        recipient_bare: &str,
        approved: &str,
    ) -> Result<()> {
        let current = self.full_jid.as_deref();
        for (jid, session) in self
            .state
            .session_entries_for(recipient_bare)
            .into_iter()
            .filter(|(_, session)| {
                session.user_id == recipient.id
                    && session.auth_generation == recipient.auth_generation
                    && session.available.load(Ordering::Acquire)
            })
        {
            if current != Some(jid.as_str())
                && self
                    .state
                    .privacy_allows_session(&session, owner_bare, PrivacyStanzaKind::PresenceIn)
                    .await?
            {
                let _ = session.sender.try_send(approved.to_owned());
            }
        }
        self.state
            .route_presence_subscription_remote(
                recipient_bare,
                approved,
                cluster_authority(owner, recipient),
            )
            .await;
        Ok(())
    }

    async fn presence_deliver_to_contact(
        &self,
        contact: &str,
        from: &str,
        stanza: &str,
    ) -> Result<()> {
        for (_, target) in self
            .state
            .session_entries_for(contact)
            .into_iter()
            .filter(|(_, target)| target.available.load(Ordering::Relaxed))
        {
            if self
                .state
                .privacy_allows_session(&target, from, PrivacyStanzaKind::PresenceIn)
                .await?
            {
                let _ = target.sender.try_send(stanza.to_owned());
            }
        }
        self.state
            .broadcast_available_presence_remote(contact, stanza)
            .await;
        Ok(())
    }

    async fn presence_echo_to_account(&self, account: &str, from: &str, stanza: &str) {
        for (jid, target) in self.state.session_entries_for(account) {
            if target.available.load(Ordering::Relaxed) || jid == from {
                let _ = target.sender.try_send(set_to(stanza, &jid));
            }
        }
        let account_delivery = set_to(stanza, account);
        self.state
            .broadcast_available_presence_remote(account, &account_delivery)
            .await;
    }

    async fn presence_deliver_directed_unavailable(
        &self,
        target: &str,
        bare_target: bool,
        from: &str,
        stanza: &str,
    ) {
        let mut recipients = self.state.session_entries_for(target);
        if bare_target {
            recipients.retain(|(_, session)| session.available.load(Ordering::Relaxed));
        }
        for (_, recipient) in recipients {
            if self
                .state
                .privacy_allows_session(&recipient, from, PrivacyStanzaKind::PresenceIn)
                .await
                .unwrap_or(false)
            {
                let _ = recipient.sender.try_send(stanza.to_owned());
            }
        }
    }

    fn presence_has_available_resource(&self, bare: &str) -> bool {
        self.state
            .session_entries_for(bare)
            .into_iter()
            .any(|(_, session)| session.available.load(Ordering::Acquire))
    }

    async fn presence_probe_has_remote_owner(&self, bare: &str) -> Result<bool> {
        self.state.presence_probe_has_remote_owner(bare).await
    }

    fn presence_directed_recipient(&self, owner_full: &str, requester: &str) -> bool {
        self.state
            .session_entries_for(owner_full)
            .into_iter()
            .any(|(_, owner)| {
                owner
                    .directed_presence
                    .iter()
                    .any(|target| directed_recipient_matches(target.key(), requester))
            })
    }

    async fn presence_answer_full_probe(
        &self,
        owner_full: &str,
        owner_bare: &str,
        requester: &str,
        probe_id: Option<&str>,
    ) -> Result<()> {
        self.answer_authorized_full_presence_probe(owner_full, owner_bare, requester, probe_id)
            .await
    }

    async fn presence_send_current(&self, owner: &str, recipient: &str) {
        self.send_current_availability(owner, recipient).await;
    }

    async fn presence_send_current_exact(
        &self,
        owner: &PresenceAccount,
        recipient: &PresenceAccount,
        owner_bare: &str,
        recipient_bare: &str,
    ) {
        self.send_current_availability_exact(
            owner_bare,
            owner.id,
            owner.auth_generation,
            recipient_bare,
            recipient.id,
            recipient.auth_generation,
        )
        .await;
    }

    async fn presence_full_target_routed(&self, full_jid: &str) -> bool {
        self.state
            .subscription_full_target_has_route(full_jid)
            .await
    }

    async fn presence_notify_offline(&self, user_id: uuid::Uuid) -> Result<()> {
        self.state.dispatch_push_notification(user_id).await
    }
}
