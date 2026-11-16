//! CAPS-triggered PEP send-last reads and policy-checked delivery.

use anyhow::Result;
use northstar_pubsub_application::PubSubService;
use northstar_session_core::LocalCapsEpoch;
use northstar_stream::local_routes::session_table::{
    local_caps_route_epoch_matches, session_entries_for_in, LocalSessionTable,
};
use northstar_xmpp_types::jid::CanonicalJid;
use std::sync::{atomic::Ordering, Arc};

use crate::notification_delivery::PubSubNotificationPorts;

/// Access to CAPS observations, session privacy, cluster routes and federation.
pub trait PepLastItemsPorts: PubSubNotificationPorts {
    /// One owned observation; its hints are read only after checking its epoch.
    type CapsSnapshot;
    fn caps_snapshot(&self, full_jid: &str) -> Option<Self::CapsSnapshot>;
    fn caps_snapshot_local_epoch(&self, snapshot: &Self::CapsSnapshot) -> Option<LocalCapsEpoch>;
    fn caps_snapshot_notify_nodes(&self, snapshot: Self::CapsSnapshot) -> Vec<String>;
    fn remove_local_caps_epoch(&self, full_jid: &str, epoch: LocalCapsEpoch);
}

pub struct PepLastItemsContext<R, P> {
    pubsub: PubSubService<R>,
    sessions: LocalSessionTable,
    local_domain: String,
    ports: P,
}

impl<R, P: PepLastItemsPorts> PepLastItemsContext<R, P> {
    pub fn new(
        pubsub: PubSubService<R>,
        sessions: LocalSessionTable,
        local_domain: String,
        ports: P,
    ) -> Self {
        Self {
            pubsub,
            sessions,
            local_domain,
            ports,
        }
    }

    pub fn pubsub_service(&self) -> &PubSubService<R> {
        &self.pubsub
    }

    pub fn local_domain(&self) -> &str {
        &self.local_domain
    }

    pub fn pep_notify_nodes(&self, target: &str) -> Vec<String> {
        let Ok(target) = northstar_xmpp_types::jid::canonical_session_key(target) else {
            return Vec::new();
        };
        let Some(snapshot) = self.ports.caps_snapshot(&target) else {
            return Vec::new();
        };
        if let Some(epoch) = self.ports.caps_snapshot_local_epoch(&snapshot) {
            if !self.local_epoch_is_current(&target, epoch, None) {
                self.ports.remove_local_caps_epoch(&target, epoch);
                return Vec::new();
            }
        }
        self.ports.caps_snapshot_notify_nodes(snapshot)
    }

    fn local_epoch_is_current(
        &self,
        full_jid: &str,
        epoch: LocalCapsEpoch,
        expected_gate: Option<&Arc<tokio::sync::Mutex<()>>>,
    ) -> bool {
        self.sessions.get(full_jid).is_some_and(|session| {
            local_caps_route_epoch_matches(
                session.connection_id,
                session.caps_observation_generation.load(Ordering::Acquire),
                session.routable.load(Ordering::Acquire),
                session.disconnect.is_cancelled(),
                session.lifecycle.load(Ordering::Acquire),
                expected_gate.is_none_or(|gate| Arc::ptr_eq(&session.mix_presence_gate, gate)),
                epoch,
            )
        })
    }

    fn federation_domain_allowed(&self, domain: &str) -> bool {
        let Ok(domain) = northstar_xmpp_types::jid::prepare_domainpart(domain) else {
            return false;
        };
        self.ports.federation_domain_allowed(&domain)
    }

    pub async fn route_message(
        &self,
        sender_bare_jid: &str,
        recipient: &str,
        message: String,
        expected_local_epoch: Option<LocalCapsEpoch>,
    ) -> Result<()> {
        let sender_bare_jid = northstar_xmpp_types::jid::canonicalize_bare(sender_bare_jid)?;
        let recipient_jid = CanonicalJid::parse(recipient)?;
        let domain = recipient_jid.domainpart();
        if domain == self.local_domain {
            let mut delivered = false;
            let recipient_key = recipient_jid.to_string();
            let targets = session_entries_for_in(&self.sessions, &recipient_key);
            let same_account = recipient_jid.bare() == sender_bare_jid;
            let mut policy_eligible = 0_usize;
            for (_, target) in &targets {
                if expected_local_epoch
                    .is_some_and(|epoch| target.connection_id != epoch.connection_id)
                {
                    continue;
                }
                if !same_account
                    && !self
                        .ports
                        .privacy_allows_session(target, &sender_bare_jid)
                        .await?
                {
                    continue;
                }
                policy_eligible += 1;
                if let Some(epoch) = expected_local_epoch {
                    // Policy I/O stays outside the gate; the final exact route
                    // check and nonblocking send share the current epoch.
                    let expected_gate = Arc::clone(&target.mix_presence_gate);
                    let _epoch_guard = Arc::clone(&expected_gate).lock_owned().await;
                    if !self.local_epoch_is_current(&recipient_key, epoch, Some(&expected_gate)) {
                        continue;
                    }
                    match target.sender.try_send(message.clone()) {
                        Ok(()) => delivered = true,
                        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                            target.sender.disconnect_backpressured_transport();
                            anyhow::bail!(
                                "exact local PEP transport queue is full for {recipient_key}"
                            );
                        }
                        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                            anyhow::bail!(
                                "exact local PEP transport queue is closed for {recipient_key}"
                            );
                        }
                    }
                    continue;
                }
                delivered |= target.sender.try_send(message.clone()).is_ok();
            }
            let mut remote_nodes = 0_usize;
            if !delivered && expected_local_epoch.is_none() {
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
                if expected_local_epoch.is_some() {
                    return Ok(());
                }
                if remote_nodes == 0 && !targets.is_empty() && policy_eligible == 0 {
                    return Ok(());
                }
                anyhow::bail!("no local PEP resource accepted the notification");
            }
        } else if self.federation_domain_allowed(domain) {
            if !self.ports.send_federated(domain, message, None).await {
                anyhow::bail!("federated PEP notification was not admitted to the durable outbox");
            }
        } else {
            anyhow::bail!("federated PEP notification is denied by domain policy");
        }
        Ok(())
    }
}

impl<R: crate::PubSubRepositories, P: PepLastItemsPorts> crate::pep::PepLastItemDelivery
    for PepLastItemsContext<R, P>
{
    type CapsEpoch = LocalCapsEpoch;

    fn last_item_pubsub_service(&self) -> &PubSubService<impl crate::PubSubRepositories> {
        self.pubsub_service()
    }

    fn last_item_local_domain(&self) -> &str {
        self.local_domain()
    }

    fn last_item_notify_nodes(&self, full_jid: &str) -> Vec<String> {
        self.pep_notify_nodes(full_jid)
    }

    async fn last_item_route(
        &self,
        sender_bare_jid: &str,
        recipient: &str,
        message: String,
        expected_local_epoch: Option<LocalCapsEpoch>,
    ) -> Result<()> {
        self.route_message(sender_bare_jid, recipient, message, expected_local_epoch)
            .await
    }
}
