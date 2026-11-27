//! Policy-checked delivery of durable PubSub notifications.

use anyhow::Result;
use northstar_session_core::SessionShowState;
use northstar_stream::local_routes::{
    notification_admission::{
        NotificationAdmission, NotificationHandoff, NotificationRecipient, NotificationSource,
    },
    session::OnlineSession,
    session_table::{session_entries_for_in, LocalSessionTable},
};
use northstar_xml_builder::XmlElement;
use northstar_xmpp_types::jid::CanonicalJid;
use std::{future::Future, sync::atomic::Ordering};
use uuid::Uuid;

/// Recipient policy, cluster routes and federation shared by PubSub and PEP delivery.
pub trait PubSubNotificationPorts: NotificationAdmission {
    fn remote_nodes(&self, recipient: &str) -> impl Future<Output = Result<Vec<String>>> + Send;
    fn send_pubsub_notification(
        &self,
        node_id: &str,
        recipient: &str,
        message: &str,
        expected_account: Option<Uuid>,
    ) -> impl Future<Output = Result<NotificationHandoff>> + Send;
    /// Applies the static and runtime policies to a prepared domain.
    fn federation_domain_allowed(&self, domain: &str) -> bool;
    fn send_federated(
        &self,
        domain: &str,
        message: String,
        sender: Option<String>,
    ) -> impl Future<Output = bool> + Send;
}

pub struct PubSubNotificationDelivery<P> {
    sessions: LocalSessionTable,
    local_domain: String,
    ports: P,
}

impl<P: PubSubNotificationPorts> PubSubNotificationDelivery<P> {
    pub fn new(sessions: LocalSessionTable, local_domain: String, ports: P) -> Self {
        Self {
            sessions,
            local_domain,
            ports,
        }
    }

    pub fn service_domain(&self) -> String {
        format!("pubsub.{}", self.local_domain)
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
        if let Some(show_values) = show_values.filter(|_| target.domainpart() == self.local_domain)
        {
            let mut delivered = false;
            let mut show_eligible = 0_usize;
            let mut policy_eligible = 0_usize;
            for (full_jid, session) in session_entries_for_in(&self.sessions, recipient) {
                if !show_matches(session.show.load(Ordering::Relaxed), show_values) {
                    continue;
                }
                show_eligible += 1;
                let active = session.privacy_active_snapshot();
                if !self
                    .ports
                    .authorize_notification(
                        notification_recipient(&full_jid, &session, active.as_deref()),
                        NotificationSource::Service(&service),
                    )
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
                delivered |= with_current_notification_route(
                    &self.sessions,
                    &full_jid,
                    &session,
                    active.as_deref(),
                    |current| {
                        show_matches(current.show.load(Ordering::Relaxed), show_values)
                            && current.sender.try_send(message).is_ok()
                    },
                ) == Some(true);
            }
            if !delivered
                && !northstar_xep_0060::pubsub_policy_suppression_is_terminal(
                    show_eligible,
                    policy_eligible,
                )
            {
                anyhow::bail!("no eligible local PubSub resource accepted the notification");
            }
            return Ok(());
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
            let targets = session_entries_for_in(&self.sessions, recipient);
            let mut delivered = false;
            let mut suppressed = false;
            let mut retry = false;
            for (jid, session) in &targets {
                let active = session.privacy_active_snapshot();
                if !self
                    .ports
                    .authorize_notification(
                        notification_recipient(jid, session, active.as_deref()),
                        NotificationSource::Service(service),
                    )
                    .await?
                {
                    suppressed = true;
                    continue;
                }
                let accepted = with_current_notification_route(
                    &self.sessions,
                    jid,
                    session,
                    active.as_deref(),
                    |current| current.sender.try_send(message.clone()).is_ok(),
                ) == Some(true);
                delivered |= accepted;
                retry |= !accepted;
            }
            if !delivered {
                for node_id in self.ports.remote_nodes(recipient).await? {
                    match self
                        .ports
                        .send_pubsub_notification(&node_id, recipient, &message, None)
                        .await?
                    {
                        NotificationHandoff::Accepted => return Ok(()),
                        NotificationHandoff::Suppressed => suppressed = true,
                        NotificationHandoff::Retry => retry = true,
                    }
                }
            }
            if notification_requires_retry(delivered, suppressed, retry) {
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

fn show_matches(show: u8, allowed: &[String]) -> bool {
    let show = SessionShowState::from_u8(show);
    show != SessionShowState::Unavailable && allowed.iter().any(|value| value == show.as_str())
}

pub(super) fn notification_recipient<'a>(
    jid: &'a str,
    session: &OnlineSession,
    active_list: Option<&'a str>,
) -> NotificationRecipient<'a> {
    NotificationRecipient {
        full_jid: jid,
        account_id: session.user_id,
        auth_generation: session.auth_generation,
        connection_id: session.connection_id,
        active_list,
    }
}

pub(super) fn with_current_notification_route<T>(
    sessions: &LocalSessionTable,
    jid: &str,
    captured: &OnlineSession,
    active_list: Option<&str>,
    send: impl FnOnce(&OnlineSession) -> T,
) -> Option<T> {
    let current = sessions.get(jid)?;
    if current.user_id != captured.user_id
        || current.auth_generation != captured.auth_generation
        || current.connection_id != captured.connection_id
        || !current.routable.load(Ordering::Acquire)
        || current.disconnect.is_cancelled()
    {
        return None;
    }
    let active = current
        .privacy_active
        .read()
        .unwrap_or_else(|error| error.into_inner());
    if active.as_deref() != active_list {
        return None;
    }
    Some(send(&current))
}

pub(super) fn notification_requires_retry(delivered: bool, suppressed: bool, retry: bool) -> bool {
    !delivered && (retry || !suppressed)
}

#[cfg(test)]
mod tests;
