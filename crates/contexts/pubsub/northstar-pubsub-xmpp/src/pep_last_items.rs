//! CAPS-triggered PEP send-last reads and policy-checked delivery.

use anyhow::Result;
use northstar_pubsub_application::PubSubService;
use northstar_pubsub_core::{PepReplayPage, PepReplayQuery, PubSubTimeSources};
use northstar_session_core::LocalCapsEpoch;
use northstar_stream::local_routes::session_table::{
    local_caps_route_epoch_matches, session_entries_for_in, LocalSessionTable,
};
use northstar_xmpp_types::jid::CanonicalJid;
use std::sync::{atomic::Ordering, Arc};

use crate::notification_delivery::{
    notification_recipient, notification_requires_retry, with_current_notification_route,
    PubSubNotificationPorts,
};
use northstar_stream::local_routes::notification_admission::{
    NotificationHandoff, NotificationSource,
};
use uuid::Uuid;

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
        expected_recipient_account: Option<Uuid>,
    ) -> Result<()> {
        let sender_bare_jid = northstar_xmpp_types::jid::canonicalize_bare(sender_bare_jid)?;
        let recipient_jid = CanonicalJid::parse(recipient)?;
        let domain = recipient_jid.domainpart();
        if domain == self.local_domain {
            let mut delivered = false;
            let recipient_key = recipient_jid.to_string();
            let targets = session_entries_for_in(&self.sessions, &recipient_key);
            let mut suppressed = false;
            let mut retry = false;
            for (jid, target) in &targets {
                if expected_local_epoch
                    .is_some_and(|epoch| target.connection_id != epoch.connection_id)
                {
                    continue;
                }
                if expected_recipient_account.is_some_and(|id| target.user_id != id) {
                    suppressed = true;
                    continue;
                }
                let active = target.privacy_active_snapshot();
                if !self
                    .ports
                    .authorize_notification(
                        notification_recipient(jid, target, active.as_deref()),
                        NotificationSource::PepPublisher(&sender_bare_jid),
                    )
                    .await?
                {
                    suppressed = true;
                    continue;
                }
                if let Some(epoch) = expected_local_epoch {
                    // Policy I/O stays outside the gate; the final exact route
                    // check and nonblocking send share the current epoch.
                    let expected_gate = Arc::clone(&target.mix_presence_gate);
                    let _epoch_guard = Arc::clone(&expected_gate).lock_owned().await;
                    if !self.local_epoch_is_current(&recipient_key, epoch, Some(&expected_gate)) {
                        continue;
                    }
                    match with_current_notification_route(
                        &self.sessions,
                        jid,
                        target,
                        active.as_deref(),
                        |current| current.sender.try_send(message.clone()),
                    ) {
                        None => continue,
                        Some(Ok(())) => delivered = true,
                        Some(Err(tokio::sync::mpsc::error::TrySendError::Full(_))) => {
                            target.sender.disconnect_backpressured_transport();
                            anyhow::bail!(
                                "exact local PEP transport queue is full for {recipient_key}"
                            );
                        }
                        Some(Err(tokio::sync::mpsc::error::TrySendError::Closed(_))) => {
                            anyhow::bail!(
                                "exact local PEP transport queue is closed for {recipient_key}"
                            );
                        }
                    }
                    continue;
                }
                let accepted = with_current_notification_route(
                    &self.sessions,
                    jid,
                    target,
                    active.as_deref(),
                    |current| current.sender.try_send(message.clone()).is_ok(),
                ) == Some(true);
                delivered |= accepted;
                retry |= !accepted;
            }
            if !delivered && expected_local_epoch.is_none() {
                for node_id in self.ports.remote_nodes(recipient).await? {
                    match self
                        .ports
                        .send_pubsub_notification(
                            &node_id,
                            recipient,
                            &message,
                            expected_recipient_account,
                        )
                        .await?
                    {
                        NotificationHandoff::Accepted => return Ok(()),
                        NotificationHandoff::Suppressed => suppressed = true,
                        NotificationHandoff::Retry => retry = true,
                    }
                }
            }
            if expected_local_epoch.is_none()
                && notification_requires_retry(delivered, suppressed, retry)
            {
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

    async fn last_item_replay_page(&self, query: &PepReplayQuery) -> Result<PepReplayPage> {
        self.pubsub_service().pep_replay_page(query).await
    }

    fn last_item_time_sources(&self) -> &PubSubTimeSources {
        self.pubsub_service().time_sources()
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
        expected_recipient_account: Option<Uuid>,
    ) -> Result<()> {
        self.route_message(
            sender_bare_jid,
            recipient,
            message,
            expected_local_epoch,
            expected_recipient_account,
        )
        .await
    }
}
