//! The node's side of the roster context's session handlers.

use crate::node::{ClientSession, ServerNode};
use anyhow::Result;
use northstar_mix_xmpp::MixHandlers;
use northstar_muc_xmpp::MucHandlers;
use northstar_pubsub_xmpp::PubSubHandlers;
use northstar_roster_application::blocking::{BlockingRepository, BlockingService};
use northstar_roster_application::blocking_mutation::CommittedBlockingChange;
use northstar_roster_application::blocklist_revisions::BlocklistRevisionRepository;
use northstar_roster_application::privacy::commands::PolicyCommandRepository;
use northstar_roster_application::{RosterRepository, RosterService, S2sOutboxPolicy};
use northstar_roster_core::{
    ClusterPresenceAuthority, ExactPresenceRoute, LocalRosterContact, PresenceAccount, RosterActor,
    RosterChange,
};
use northstar_roster_xmpp::federated_presence::SubscriptionRevocationRoute;
use northstar_roster_xmpp::presence_delivery::{
    DirectedDelivery, DirectedDeliveryResult, DirectedEnqueue, DirectedPresenceHost,
    DirectedPresenceTransport,
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

mod exact_presence;
mod privacy_selection;
mod roster_journal;
mod subscription_retry;

impl DirectedPresenceHost for ServerNode {
    async fn deliver_exact_directed(
        &self,
        delivery: DirectedDelivery<'_>,
    ) -> DirectedDeliveryResult {
        presence_delivery::deliver_exact_directed(self, delivery).await
    }
}

impl RosterSessionHost for ServerNode {
    fn avatar_presence_gate(&self) -> &northstar_roster_xmpp::AvatarPresenceGate {
        &self.avatar_presence_gate
    }

    fn roster_service(&self) -> &RosterService<impl RosterRepository<Error = anyhow::Error>> {
        self.roster.roster_service()
    }

    fn blocking_service(
        &self,
    ) -> &BlockingService<impl BlockingRepository + BlocklistRevisionRepository> {
        self.roster.blocking_service()
    }

    fn privacy_commands(&self) -> &impl PolicyCommandRepository {
        self.roster.privacy_service().command_repository()
    }

    fn post_accept_failure_telemetry(&self) -> PostAcceptFailureTelemetry {
        northstar_roster_xmpp::PostAcceptFailureTelemetry::new(std::sync::Arc::clone(
            &self.metrics.post_accept_side_effect_failures_total,
        ))
    }

    fn publish_route_presence(
        &self,
        full_jid: &str,
        connection_id: Uuid,
        available: bool,
        priority: i16,
        seq: u64,
    ) {
        if !self.cluster.is_enabled() {
            return;
        }
        let cluster = self.cluster.clone();
        let telemetry = self.post_accept_failure_telemetry();
        let full_jid = full_jid.to_owned();
        tokio::spawn(async move {
            let error = match tokio::time::timeout(
                std::time::Duration::from_secs(2),
                cluster.publish_route_presence(&full_jid, connection_id, available, priority, seq),
            )
            .await
            {
                Ok(Ok(())) => return,
                Ok(Err(error)) => error,
                Err(error) => error.into(),
            };
            telemetry.record_failure();
            tracing::warn!(?error, %full_jid, %connection_id, "could not publish message route presence");
        });
    }

    fn roster_outbox_policy(&self) -> S2sOutboxPolicy {
        self.federation.federation_outbox.outbox_policy()
    }

    fn roster_wake_outbox(&self, route: Option<&str>) {
        let outbox = &self.federation.federation_outbox;
        match route {
            Some(domain) => outbox.wake_admitted_route(domain),
            None => outbox.wake_outbox(),
        }
    }

    async fn deliver_committed_roster_change(
        &self,
        owner_id: Uuid,
        owner: &str,
        change: &RosterChange,
        participant_id: Option<&str>,
        events: &dyn northstar_roster_core::RosterEventSource,
    ) -> Result<()> {
        deliver_committed_roster_change(
            &self.roster_push_delivery(),
            owner_id,
            owner,
            change,
            participant_id,
            events,
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

    async fn push_blocklist_change(&self, actor: &RosterActor) {
        fanout::push_blocklist_change(self, self.roster.blocking_service().revisions(), actor)
            .await;
    }

    async fn deliver_blocking_presence_change(&self, change: CommittedBlockingChange) {
        let presence = self.cluster_listener_blocking();
        let presence = &presence;
        fanout::deliver_blocking_presence_change(change, |targets, available| async move {
            presence.deliver_slice(&targets, available).await;
        })
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
            .privacy_list_active_locally(account, name)
    }

    async fn push_privacy_change(
        &self,
        actor: &RosterActor,
        name: &str,
        base: &str,
    ) -> Option<String> {
        fanout::push_privacy_change(self, actor, name, base).await
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
        pending: Option<
            northstar_stream::local_routes::pending_subscription::PendingSubscriptionKey,
        >,
    ) -> Result<()> {
        presence_delivery::deliver_subscription_presence(
            self,
            owner,
            recipient,
            owner_bare,
            recipient_bare,
            stanza,
            pending,
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
        source_epoch: Option<u64>,
    ) -> Result<()> {
        presence_delivery::deliver_contact_presence(self, contact, from, stanza, source_epoch).await
    }

    async fn echo_account_presence(
        &self,
        account: &str,
        from: &str,
        stanza: &str,
        source_epoch: Option<u64>,
    ) {
        presence_delivery::echo_account_presence(self, account, from, stanza, source_epoch).await
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

    async fn full_presence_target_routed(&self, full_jid: &str, account: &PresenceAccount) -> bool {
        if self
            .session
            .live()
            .sessions()
            .sessions_for(full_jid)
            .iter()
            .any(|target| {
                target.user_id == account.id && target.auth_generation == account.auth_generation
            })
        {
            return true;
        }
        self.cluster
            .listener_presence_routes()
            .remote_nodes(full_jid)
            .await
            .is_ok_and(|nodes| !nodes.is_empty())
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

impl SubscriptionRevocationRoute for ServerNode {
    async fn send_volatile_subscription_revocation(
        &self,
        verified_peer: &str,
        stanza: String,
    ) -> bool {
        northstar_s2s::outbound::send_volatile_on_authenticated_route(
            self,
            &self.config.domain,
            verified_peer,
            stanza,
        )
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

impl DirectedPresenceTransport for ServerNode {
    fn directed_source_is_current(&self, source: &RosterActor) -> bool {
        self.session
            .live()
            .sessions()
            .get(&source.full_jid)
            .is_some_and(|current| {
                current.user_id == source.account_id
                    && current.auth_generation == source.auth_generation
                    && current.connection_id == source.connection_id
                    && current.routable.load(std::sync::atomic::Ordering::Acquire)
                    && !current.disconnect.is_cancelled()
            })
    }

    async fn capture_remote_directed_routes(
        &self,
        scope: &str,
        recipient: &PresenceAccount,
    ) -> Result<Vec<ExactPresenceRoute>> {
        Ok(self
            .cluster
            .capture_remote_message_routes(scope, recipient.id, recipient.auth_generation)
            .await?
            .into_iter()
            .filter(|route| scope.contains('/') || route.available == Some(true))
            .map(|route| ExactPresenceRoute {
                account_id: route.account_id,
                auth_generation: route.auth_generation,
                connection_id: route.connection_id,
                full_jid: route.full_jid,
                node_id: route.node_id,
            })
            .collect())
    }

    async fn send_remote_directed_route(
        &self,
        route: &ExactPresenceRoute,
        source: &RosterActor,
        stanza: &str,
        unavailable: bool,
    ) -> Result<DirectedEnqueue> {
        use northstar_session_application::sm_teardown_presence::ExactPresenceAcceptance;
        match self
            .cluster
            .send_exact_directed_presence(route, source, stanza, unavailable)
            .await?
        {
            ExactPresenceAcceptance::Accepted => Ok(DirectedEnqueue::Accepted),
            ExactPresenceAcceptance::Gone => Ok(DirectedEnqueue::Gone),
            ExactPresenceAcceptance::Retry => Ok(DirectedEnqueue::Retry),
            ExactPresenceAcceptance::Unknown => {
                anyhow::bail!("cluster directed presence acceptance is unknown")
            }
        }
    }

    fn enqueue_local_directed_route(
        &self,
        route: &ExactPresenceRoute,
        stanza: &str,
        available_only: bool,
    ) -> DirectedEnqueue {
        use northstar_message_application::messaging::ExactMessageRoute;
        use std::sync::atomic::Ordering;
        use tokio::sync::mpsc::error::TrySendError;
        let exact = ExactMessageRoute {
            full_jid: route.full_jid.clone(),
            account_id: route.account_id,
            auth_generation: route.auth_generation,
            connection_id: route.connection_id,
            node_id: None,
            priority: None,
            available: None,
        };
        self.session
            .live()
            .sessions()
            .with_exact_message_route(&exact, |current| {
                if available_only && !current.available.load(Ordering::Acquire) {
                    return DirectedEnqueue::Gone;
                }
                match current.sender.try_send_presence(
                    stanza.to_owned(),
                    northstar_stream::outbound::PresenceDelivery::Directed,
                ) {
                    Ok(()) => DirectedEnqueue::Accepted,
                    Err(TrySendError::Full(_)) => DirectedEnqueue::Retry,
                    Err(TrySendError::Closed(_)) => DirectedEnqueue::Gone,
                }
            })
            .unwrap_or(DirectedEnqueue::Gone)
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
        let telemetry = self.post_accept_failure_telemetry();
        self.cluster
            .broadcast_available_presence_remote(target, stanza, move || telemetry.record_failure())
            .await
    }
}
