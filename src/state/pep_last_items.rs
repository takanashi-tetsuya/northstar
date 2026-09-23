//! CAPS-triggered PEP send-last reads and policy-checked delivery.

use super::{
    local_caps_route_epoch_matches, session_entries_for_in, AppState, OnlineSession,
    RuntimeFederationPolicy,
};
use crate::{
    cluster::{ClusterListenerPresenceRoutes, ClusterNodeDelivery},
    config::ExternalRouteDomainPolicy,
    db::{messaging::PostgresMessageRepository, pubsub_repository::PostgresPubSubRepository},
    jid::CanonicalJid,
    s2s::FederationRouter,
    services::{messaging::MessageService, privacy::PrivacyStanzaKind, pubsub::PubSubService},
};
use anyhow::Result;
use dashmap::DashMap;
use northstar_protocol_runtime::caps::{CapsObservationOwner, CapsResourceIndex, PendingCapsIndex};
use northstar_session_core::LocalCapsEpoch;
use std::sync::{atomic::Ordering, Arc};

pub(crate) struct PepLastItemsContext {
    pubsub: PubSubService<PostgresPubSubRepository>,
    privacy: MessageService<PostgresMessageRepository>,
    sessions: Arc<DashMap<String, OnlineSession>>,
    observations: Arc<CapsResourceIndex>,
    pending_caps: Arc<PendingCapsIndex>,
    remote_routes: ClusterListenerPresenceRoutes,
    remote_sender: ClusterNodeDelivery,
    federation: FederationRouter,
    static_policy: ExternalRouteDomainPolicy,
    runtime_policy: Arc<arc_swap::ArcSwap<RuntimeFederationPolicy>>,
    local_domain: String,
}

impl AppState {
    pub(crate) fn pep_last_items_context(&self) -> PepLastItemsContext {
        PepLastItemsContext {
            pubsub: self.pubsub_service.clone(),
            privacy: self.message_service.clone(),
            sessions: Arc::clone(&self.sessions),
            observations: Arc::clone(&self.caps_by_jid),
            pending_caps: Arc::clone(&self.pending_caps),
            remote_routes: self.cluster.listener_presence_routes(),
            remote_sender: self.cluster.node_delivery(),
            federation: self.federation_outbox.clone(),
            static_policy: self.config.external_route_domain_policy(),
            runtime_policy: Arc::clone(&self.federation_runtime_policy),
            local_domain: self.config.domain.clone(),
        }
    }
}

impl PepLastItemsContext {
    pub(crate) fn pubsub_service(&self) -> &PubSubService<PostgresPubSubRepository> {
        &self.pubsub
    }

    pub(crate) fn local_domain(&self) -> &str {
        &self.local_domain
    }

    pub(crate) fn pep_notify_nodes(&self, target: &str) -> Vec<String> {
        let Ok(target) = crate::jid::canonical_session_key(target) else {
            return Vec::new();
        };
        let Some(snapshot) = self.observations.snapshot(&target) else {
            return Vec::new();
        };
        if let CapsObservationOwner::Local(epoch) = snapshot.owner {
            if !self.local_epoch_is_current(&target, epoch, None) {
                self.pending_caps.remove_local_epoch(&target, epoch);
                self.observations.remove_local_epoch(&target, epoch);
                return Vec::new();
            }
        }
        snapshot.summary.map_or_else(Vec::new, |summary| {
            summary.notify_nodes().map(str::to_owned).collect()
        })
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

    async fn privacy_allows_session(&self, session: &OnlineSession, peer: &str) -> Result<bool> {
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
                peer,
                PrivacyStanzaKind::Message,
            )
            .await
    }

    fn federation_domain_allowed(&self, domain: &str) -> bool {
        let Ok(domain) = crate::jid::prepare_domainpart(domain) else {
            return false;
        };
        self.static_policy.federation_domain_allowed(&domain)
            && self.runtime_policy.load().allows_domain(&domain)
    }

    pub(crate) async fn route_message(
        &self,
        sender_bare_jid: &str,
        recipient: &str,
        message: String,
        expected_local_epoch: Option<LocalCapsEpoch>,
    ) -> Result<()> {
        let sender_bare_jid = crate::jid::canonicalize_bare(sender_bare_jid)?;
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
                if expected_local_epoch.is_some() {
                    return Ok(());
                }
                if remote_nodes == 0 && !targets.is_empty() && policy_eligible == 0 {
                    return Ok(());
                }
                anyhow::bail!("no local PEP resource accepted the notification");
            }
        } else if self.federation_domain_allowed(domain) {
            if !self.federation.send(domain, message, None).await {
                anyhow::bail!("federated PEP notification was not admitted to the durable outbox");
            }
        } else {
            anyhow::bail!("federated PEP notification is denied by domain policy");
        }
        Ok(())
    }
}
