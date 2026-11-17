//! The node's side of the roster context's session handlers.

use crate::node::{ClientSession, ServerNode};
use anyhow::Result;
use northstar_mix_xmpp::MixHandlers;
use northstar_muc_xmpp::MucHandlers;
use northstar_pubsub_xmpp::PubSubHandlers;
use northstar_roster_application::blocking::{BlockingRepository, BlockingService};
use northstar_roster_application::{RosterRepository, RosterService, S2sOutboxPolicy};
use northstar_roster_core::{
    ClusterPresenceAuthority, LocalRosterContact, PresenceAccount, RosterChange,
};
use northstar_roster_xmpp::roster_push::{
    deliver_committed_roster_change, deliver_roster_removal_presence,
};
use northstar_roster_xmpp::{
    fanout, presence_delivery, FederatedPresenceHost, PostAcceptFailureTelemetry,
    PresenceDeliveryHost, PresenceRouting, RosterSessionHost,
};
use northstar_stream::local_routes::session::OnlineSession;
use northstar_stream::outbound::OutboundSender;
use northstar_stream::transport::Action;
use roxmltree::Node;
use uuid::Uuid;

impl RosterSessionHost for ServerNode {
    fn roster_service(&self) -> &RosterService<impl RosterRepository<Error = anyhow::Error>> {
        self.roster.roster_service()
    }

    fn blocking_service(&self) -> &BlockingService<impl BlockingRepository> {
        self.roster.blocking_service()
    }

    fn post_accept_failure_telemetry(&self) -> PostAcceptFailureTelemetry {
        northstar_roster_xmpp::PostAcceptFailureTelemetry::new(std::sync::Arc::clone(
            &self.metrics.post_accept_side_effect_failures_total,
        ))
    }

    fn roster_outbox_policy(&self) -> S2sOutboxPolicy {
        self.federation.federation_outbox.outbox_policy()
    }

    fn roster_wake_outbox(&self) {
        self.federation.federation_outbox.wake_outbox();
    }

    async fn deliver_committed_roster_change(
        &self,
        owner_id: Uuid,
        owner: &str,
        change: &RosterChange,
        participant_id: Option<&str>,
    ) -> Result<()> {
        deliver_committed_roster_change(
            &self.roster_push_delivery(),
            owner_id,
            owner,
            change,
            participant_id,
        )
        .await
    }

    async fn deliver_roster_removal_presence(
        &self,
        owner: &PresenceAccount,
        recipient: &LocalRosterContact,
        target_bare: &str,
        stanza: &str,
    ) {
        deliver_roster_removal_presence(
            self,
            owner.id,
            owner.auth_generation,
            recipient.id,
            recipient.auth_generation,
            target_bare,
            stanza,
        )
        .await;
    }

    async fn push_blocklist_change(&self, owner: &str, payload: &str) {
        fanout::push_blocklist_change(self, owner, payload).await;
    }

    async fn deliver_blocking_presence_change(
        &self,
        owner: &str,
        targets: &[String],
        changed_patterns: &[String],
        available: bool,
    ) {
        fanout::deliver_blocking_presence_change(self, owner, targets, changed_patterns, available)
            .await;
    }

    fn local_resource_count(&self, account: &str) -> usize {
        self.session.live().sessions().sessions_for(account).len()
    }

    async fn account_has_remote_resources(&self, account: &str) -> Result<bool> {
        self.cluster.account_has_remote_resources(account).await
    }

    fn privacy_list_active_locally(&self, account: &str, name: &str) -> bool {
        self.session
            .live()
            .sessions()
            .sessions_for(account)
            .iter()
            .any(|session| {
                session
                    .privacy_active
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .as_deref()
                    == Some(name)
            })
    }

    async fn push_privacy_change(
        &self,
        account: &str,
        name: &str,
        base: &str,
        current_connection: Uuid,
    ) -> Option<String> {
        fanout::push_privacy_change(self, account, name, base, current_connection).await
    }

    fn presence_component_domain(&self, domain: &str) -> bool {
        self.config.component_domain_configured(domain)
    }

    async fn deliver_directed_presence(
        &self,
        to: &str,
        canonical_to: &str,
        from: &str,
        stanza: &str,
        bare_target: bool,
    ) -> Result<bool> {
        presence_delivery::deliver_directed_presence(
            self,
            to,
            canonical_to,
            from,
            stanza,
            bare_target,
        )
        .await
    }

    async fn deliver_subscription_presence(
        &self,
        owner: &PresenceAccount,
        recipient: &PresenceAccount,
        owner_bare: &str,
        recipient_bare: &str,
        stanza: &str,
    ) -> Result<()> {
        presence_delivery::deliver_subscription_presence(
            self,
            owner,
            recipient,
            owner_bare,
            recipient_bare,
            stanza,
        )
        .await
    }

    async fn deliver_subscription_approval(
        &self,
        owner: &PresenceAccount,
        recipient: &PresenceAccount,
        owner_bare: &str,
        recipient_bare: &str,
        approved: &str,
        skip_full: Option<&str>,
    ) -> Result<()> {
        presence_delivery::deliver_subscription_approval(
            self,
            owner,
            recipient,
            owner_bare,
            recipient_bare,
            approved,
            skip_full,
        )
        .await
    }

    async fn deliver_contact_presence(
        &self,
        contact: &str,
        from: &str,
        stanza: &str,
    ) -> Result<()> {
        presence_delivery::deliver_contact_presence(self, contact, from, stanza).await
    }

    async fn echo_account_presence(&self, account: &str, from: &str, stanza: &str) {
        presence_delivery::echo_account_presence(self, account, from, stanza).await
    }

    async fn deliver_directed_unavailable(
        &self,
        target: &str,
        bare_target: bool,
        from: &str,
        stanza: &str,
    ) {
        presence_delivery::deliver_directed_unavailable(self, target, bare_target, from, stanza)
            .await
    }

    fn account_has_available_resource(&self, bare: &str) -> bool {
        presence_delivery::account_has_available_resource(self, bare)
    }

    async fn probe_has_remote_owner(&self, bare: &str) -> Result<bool> {
        self.cluster.presence_probe_has_remote_owner(bare).await
    }

    fn directed_presence_recipient(&self, owner_full: &str, requester: &str) -> bool {
        presence_delivery::directed_presence_recipient(self, owner_full, requester)
    }

    async fn answer_full_presence_probe(
        &self,
        owner_full: &str,
        owner_bare: &str,
        requester: &str,
        probe_id: Option<&str>,
    ) -> Result<Option<String>> {
        presence_delivery::answer_full_presence_probe(
            self, owner_full, owner_bare, requester, probe_id,
        )
        .await
    }

    async fn send_current_presence(&self, owner: &str, recipient: &str) {
        presence_delivery::send_current_availability(self, owner, recipient).await
    }

    async fn send_current_presence_exact(
        &self,
        owner: &PresenceAccount,
        recipient: &PresenceAccount,
        owner_bare: &str,
        recipient_bare: &str,
    ) {
        presence_delivery::send_current_availability_exact(
            self,
            owner_bare,
            owner.id,
            owner.auth_generation,
            recipient_bare,
            recipient.id,
            recipient.auth_generation,
        )
        .await
    }

    async fn full_presence_target_routed(&self, full_jid: &str) -> bool {
        self.cluster
            .subscription_full_target_has_route(full_jid)
            .await
    }

    async fn notify_offline_account(&self, user_id: Uuid) -> Result<()> {
        self.dispatch_push_notification(user_id).await
    }
}

impl PresenceRouting for ServerNode {
    async fn route_mix_presence(
        session: &ClientSession,
        root: Node<'_, '_>,
        raw: &str,
    ) -> Result<Option<Action>> {
        session.try_mix_presence(root, raw).await
    }

    async fn route_pubsub_presence(
        session: &mut ClientSession,
        kind: &str,
        from: &str,
    ) -> Result<Action> {
        session.pubsub_presence(kind, from).await
    }

    async fn route_muc_presence(
        session: &mut ClientSession,
        root: Node<'_, '_>,
        raw: &str,
    ) -> Result<Action> {
        session.muc_presence(root, raw).await
    }

    async fn forward_presence_to_mix(
        session: &ClientSession,
        root: Node<'_, '_>,
        kind: &str,
        from: &str,
        raw: &str,
    ) -> Result<bool> {
        session
            .forward_presence_if_route_current(root, kind, from, raw)
            .await
    }
}

impl FederatedPresenceHost for ServerNode {
    fn sessions_for(&self, jid: &str) -> Vec<OnlineSession> {
        self.session.live().sessions().sessions_for(jid)
    }

    async fn dispatch_push_notification(&self, user_id: Uuid) -> Result<()> {
        ServerNode::dispatch_push_notification(self, user_id).await
    }
}

impl PresenceDeliveryHost for ServerNode {
    fn local_presence_owner_keys(&self) -> Vec<String> {
        self.session.live().sessions().local_presence_owner_keys()
    }

    fn local_presence_owner_candidate(
        &self,
        key: &str,
        user_id: Uuid,
        auth_generation: i64,
    ) -> Option<OnlineSession> {
        self.session
            .live()
            .sessions()
            .local_presence_owner_candidate(key, user_id, auth_generation)
    }

    fn local_presence_owner_if_current(
        &self,
        key: &str,
        expected: &OnlineSession,
        user_id: Uuid,
        auth_generation: i64,
    ) -> Option<OnlineSession> {
        self.session
            .live()
            .sessions()
            .local_presence_owner_if_current(key, expected, user_id, auth_generation)
    }

    fn send_presence_if_owner_current(
        &self,
        key: &str,
        expected: &OnlineSession,
        user_id: Uuid,
        auth_generation: i64,
        recipient: &OutboundSender,
        presence: &str,
    ) -> bool {
        self.session
            .live()
            .sessions()
            .send_presence_if_owner_current(
                key,
                expected,
                user_id,
                auth_generation,
                recipient,
                presence,
            )
    }

    async fn route_directed_presence_remote(
        &self,
        target: &str,
        stanza: &str,
        bare_target: bool,
    ) -> bool {
        self.cluster
            .route_directed_presence_remote(target, stanza, bare_target)
            .await
    }

    async fn route_presence_subscription_remote(
        &self,
        target: &str,
        stanza: &str,
        authority: ClusterPresenceAuthority,
    ) {
        self.cluster
            .route_presence_subscription_remote(target, stanza, authority)
            .await
    }

    async fn broadcast_available_presence_remote(&self, target: &str, stanza: &str) {
        self.cluster
            .broadcast_available_presence_remote(target, stanza)
            .await
    }

    async fn delegate_authorized_full_presence_probe_remote(
        &self,
        owner_full: &str,
        requester: &str,
        authority: Option<ClusterPresenceAuthority>,
    ) -> Result<bool> {
        self.cluster
            .delegate_authorized_full_presence_probe_remote(owner_full, requester, authority)
            .await
    }

    async fn replay_current_presence_from_remote_owners(
        &self,
        owner_lookup: &str,
        recipient: &str,
        availability_only: bool,
        authority: ClusterPresenceAuthority,
    ) {
        self.cluster
            .replay_current_presence_from_remote_owners(
                owner_lookup,
                recipient,
                availability_only,
                authority,
                &northstar_cluster::presence_routing::PresenceProbeTelemetry::new(
                    &self.metrics.cluster_presence_probe_failures_total,
                ),
            )
            .await
    }
}
