//! Policy-checked delivery of durable PubSub notifications.

use super::{session_entries_for_in, AppState, OnlineSession, RuntimeFederationPolicy};
use crate::{
    cluster::{ClusterListenerPresenceRoutes, ClusterNodeDelivery},
    config::ExternalRouteDomainPolicy,
    db::{messaging::PostgresMessageRepository, pubsub_repository::PostgresPubSubRepository},
    jid::CanonicalJid,
    s2s::FederationRouter,
    services::{messaging::MessageService, privacy::PrivacyStanzaKind, pubsub::PubSubService},
    xmpp::xml_builder::XmlElement,
};
use anyhow::Result;
use dashmap::DashMap;
use std::sync::{atomic::Ordering, Arc};
use uuid::Uuid;

pub(crate) struct PubSubNotificationDelivery {
    blocking: PubSubService<PostgresPubSubRepository>,
    privacy: MessageService<PostgresMessageRepository>,
    sessions: Arc<DashMap<String, OnlineSession>>,
    remote_routes: ClusterListenerPresenceRoutes,
    remote_sender: ClusterNodeDelivery,
    federation: FederationRouter,
    static_policy: ExternalRouteDomainPolicy,
    runtime_policy: Arc<arc_swap::ArcSwap<RuntimeFederationPolicy>>,
    local_domain: String,
}

impl AppState {
    pub(crate) fn pubsub_notification_delivery(&self) -> PubSubNotificationDelivery {
        PubSubNotificationDelivery {
            blocking: self.pubsub_service.clone(),
            privacy: self.message_service.clone(),
            sessions: Arc::clone(&self.sessions),
            remote_routes: self.cluster.listener_presence_routes(),
            remote_sender: self.cluster.node_delivery(),
            federation: self.federation_outbox.clone(),
            static_policy: self.config.external_route_domain_policy(),
            runtime_policy: Arc::clone(&self.federation_runtime_policy),
            local_domain: self.config.domain.clone(),
        }
    }
}

impl PubSubNotificationDelivery {
    pub(crate) fn service_domain(&self) -> String {
        format!("pubsub.{}", self.local_domain)
    }

    async fn account_blocks(&self, target: &CanonicalJid, service: &str) -> Result<bool> {
        let Some(username) = target.localpart() else {
            return Ok(false);
        };
        // Account-wide XEP-0191 blocking takes precedence over session privacy.
        self.blocking
            .local_account_blocks_pubsub(username, service)
            .await
    }

    async fn privacy_allows(&self, session: &OnlineSession, service: &str) -> Result<bool> {
        let active = session
            .privacy_active
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        self.privacy
            .privacy_allows_session(
                session.user_id,
                session.connection_id,
                active.as_deref(),
                service,
                PrivacyStanzaKind::Message,
            )
            .await
    }

    pub(crate) async fn route_children(
        &self,
        recipient: &str,
        children: &str,
        show_values: Option<&[String]>,
        message_id: Uuid,
    ) -> Result<()> {
        let service = self.service_domain();
        let target = CanonicalJid::parse(recipient)?;
        if target.domainpart() == self.local_domain {
            if self.account_blocks(&target, &service).await? {
                return Ok(());
            }
            if let Some(show_values) = show_values {
                let mut delivered = false;
                let mut show_eligible = 0_usize;
                let mut policy_eligible = 0_usize;
                for (full_jid, session) in session_entries_for_in(&self.sessions, recipient) {
                    let show = match session.show.load(Ordering::Relaxed) {
                        1 => "online",
                        2 => "away",
                        3 => "chat",
                        4 => "dnd",
                        5 => "xa",
                        _ => continue,
                    };
                    if !show_values.iter().any(|allowed| allowed == show) {
                        continue;
                    }
                    show_eligible += 1;
                    if !self.privacy_allows(&session, &service).await? {
                        continue;
                    }
                    policy_eligible += 1;
                    let message = XmlElement::namespaced("message", "jabber:client")
                        .attr("type", "headline")
                        .attr("id", message_id)
                        .attr("from", &service)
                        .attr("to", &full_jid)
                        .validated_fragment(children)?
                        .finish();
                    delivered |= session.sender.try_send(message).is_ok();
                }
                if !delivered {
                    if northstar_xep_0060::pubsub_policy_suppression_is_terminal(
                        show_eligible,
                        policy_eligible,
                    ) {
                        return Ok(());
                    }
                    anyhow::bail!("no eligible local PubSub resource accepted the notification");
                }
                return Ok(());
            }
        }
        let message = XmlElement::namespaced("message", "jabber:client")
            .attr("type", "headline")
            .attr("id", message_id)
            .attr("from", &service)
            .attr("to", recipient)
            .validated_fragment(children)?
            .finish();
        self.route_service_message(&service, recipient, message)
            .await
    }

    pub(crate) async fn route_service_message(
        &self,
        service: &str,
        recipient: &str,
        message: String,
    ) -> Result<()> {
        let target = CanonicalJid::parse(recipient)?;
        let target_domain = target.domainpart();
        if target_domain == self.local_domain {
            if self.account_blocks(&target, service).await? {
                return Ok(());
            }
            let targets = session_entries_for_in(&self.sessions, recipient);
            let mut delivered = false;
            let mut policy_eligible = 0_usize;
            for (_, session) in &targets {
                if !self.privacy_allows(session, service).await? {
                    continue;
                }
                policy_eligible += 1;
                delivered |= session.sender.try_send(message.clone()).is_ok();
            }
            let mut remote_nodes = 0_usize;
            if !delivered {
                for node_id in self.remote_routes.remote_nodes(recipient).await? {
                    remote_nodes += 1;
                    if self
                        .remote_sender
                        .send_pubsub_notification(&node_id, recipient, &message)
                        .await?
                    {
                        delivered = true;
                        break;
                    }
                }
            }
            if !delivered {
                if remote_nodes == 0 && !targets.is_empty() && policy_eligible == 0 {
                    return Ok(());
                }
                anyhow::bail!("no local PubSub resource accepted the notification");
            }
        } else if self.static_policy.federation_domain_allowed(target_domain)
            && self.runtime_policy.load().allows_domain(target_domain)
        {
            if !self
                .federation
                .send(target_domain, message, Some(service.to_owned()))
                .await
            {
                anyhow::bail!(
                    "federated PubSub notification was not admitted to the durable outbox"
                );
            }
        } else {
            anyhow::bail!("federated PubSub notification is denied by domain policy");
        }
        Ok(())
    }
}
