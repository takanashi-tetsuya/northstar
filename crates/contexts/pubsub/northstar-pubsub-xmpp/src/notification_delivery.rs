//! Policy-checked delivery of durable PubSub notifications.

use anyhow::Result;
use northstar_pubsub_application::{PubSubOutboxRepository, PubSubService};
use northstar_stream::local_routes::{
    session::OnlineSession,
    session_table::{session_entries_for_in, LocalSessionTable},
};
use northstar_xml_builder::XmlElement;
use northstar_xmpp_types::jid::CanonicalJid;
use std::{future::Future, sync::atomic::Ordering};
use uuid::Uuid;

/// Session privacy, cluster routes and federation shared by PubSub and PEP delivery.
pub trait PubSubNotificationPorts: Send + Sync {
    fn privacy_allows_session(
        &self,
        session: &OnlineSession,
        peer: &str,
    ) -> impl Future<Output = Result<bool>> + Send;
    fn remote_nodes(&self, recipient: &str) -> impl Future<Output = Result<Vec<String>>> + Send;
    fn send_pubsub_notification(
        &self,
        node_id: &str,
        recipient: &str,
        message: &str,
    ) -> impl Future<Output = Result<bool>> + Send;
    /// Applies the static and runtime policies to a prepared domain.
    fn federation_domain_allowed(&self, domain: &str) -> bool;
    fn send_federated(
        &self,
        domain: &str,
        message: String,
        sender: Option<String>,
    ) -> impl Future<Output = bool> + Send;
}

pub struct PubSubNotificationDelivery<R, P> {
    blocking: PubSubService<R>,
    sessions: LocalSessionTable,
    local_domain: String,
    ports: P,
}

impl<R: PubSubOutboxRepository, P: PubSubNotificationPorts> PubSubNotificationDelivery<R, P> {
    pub fn new(
        blocking: PubSubService<R>,
        sessions: LocalSessionTable,
        local_domain: String,
        ports: P,
    ) -> Self {
        Self {
            blocking,
            sessions,
            local_domain,
            ports,
        }
    }

    pub fn service_domain(&self) -> String {
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

    pub async fn route_children(
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
                    if !self
                        .ports
                        .privacy_allows_session(&session, &service)
                        .await?
                    {
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

    pub async fn route_service_message(
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
                if !self.ports.privacy_allows_session(session, service).await? {
                    continue;
                }
                policy_eligible += 1;
                delivered |= session.sender.try_send(message.clone()).is_ok();
            }
            let mut remote_nodes = 0_usize;
            if !delivered {
                for node_id in self.ports.remote_nodes(recipient).await? {
                    remote_nodes += 1;
                    if self
                        .ports
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
        } else if self.ports.federation_domain_allowed(target_domain) {
            if !self
                .ports
                .send_federated(target_domain, message, Some(service.to_owned()))
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
