//! Policy-checked unavailable delivery after a local route has been fenced.

use crate::local_routes::session::OnlineSession;
use crate::local_routes::session_table::session_entries_for_in;
use anyhow::Result;
use dashmap::DashMap;
use northstar_message_application::messaging::{MessageRepository, MessageService};
use northstar_session_application::sm_teardown_presence::{
    SmTeardownPresenceRepository, SmTeardownPresenceService, UnavailablePolicy,
};
use northstar_xmpp_types::jid_text::bare_jid;
use std::{
    future::Future,
    sync::{atomic::Ordering, Arc},
};
use uuid::Uuid;

/// Cluster and federation delivery bound by the composition root.
pub trait SessionCleanupUnavailablePorts: Send + Sync {
    fn send_unavailable_to_remote_nodes(
        &self,
        target_jid: &str,
        stanza: &str,
        exclude_jid: &str,
        bare_target: bool,
    ) -> impl Future<Output = Result<()>> + Send;

    fn external_route_domain_allowed(&self, domain: &str) -> bool;

    fn send_federation(
        &self,
        domain: &str,
        stanza: String,
        origin: Option<String>,
    ) -> impl Future<Output = bool> + Send;
}

pub struct SessionCleanupUnavailable<R, M, P> {
    policy: SmTeardownPresenceService<R>,
    recipients: Arc<DashMap<String, OnlineSession>>,
    message_service: MessageService<M>,
    ports: P,
    local_domain: String,
}

impl<R, M, P> SessionCleanupUnavailable<R, M, P>
where
    R: SmTeardownPresenceRepository,
    M: MessageRepository,
    P: SessionCleanupUnavailablePorts,
{
    pub fn new(
        policy: SmTeardownPresenceService<R>,
        recipients: Arc<DashMap<String, OnlineSession>>,
        message_service: MessageService<M>,
        ports: P,
        local_domain: String,
    ) -> Self {
        Self {
            policy,
            recipients,
            message_service,
            ports,
            local_domain,
        }
    }

    pub async fn roster_subscribers(&self, owner_id: Uuid) -> Result<Vec<String>> {
        self.policy.roster_subscribers(owner_id).await
    }

    pub async fn route_with_policy(
        &self,
        owner_id: Uuid,
        active_privacy_list: Option<&str>,
        from: &str,
        unavailable: &str,
        target: &str,
    ) -> Result<()> {
        if !self
            .policy
            .allows_unavailable(UnavailablePolicy {
                owner_id,
                owner_bare_jid: bare_jid(from),
                active_privacy_list,
                from,
                target,
                local_domain: &self.local_domain,
            })
            .await?
        {
            return Ok(());
        }
        self.route_unchecked(from, unavailable, target, true).await
    }

    /// Other available resources of the same account are the local presence
    /// audience, independent of roster privacy policy.
    pub async fn route_siblings_unchecked(&self, from: &str, unavailable: &str) -> Result<()> {
        self.route_unchecked(from, unavailable, bare_jid(from), false)
            .await
    }

    async fn route_unchecked(
        &self,
        from: &str,
        unavailable: &str,
        target: &str,
        recipient_privacy: bool,
    ) -> Result<()> {
        let Ok(target_jid) = northstar_xmpp_types::jid::CanonicalJid::parse(target) else {
            anyhow::bail!("invalid SM teardown presence target");
        };
        let canonical_target = target_jid.to_string();
        let delivery = northstar_xml_builder::rewrite::set_to(unavailable, &canonical_target);
        if target_jid.domainpart() == self.local_domain {
            let mut recipients = session_entries_for_in(&self.recipients, &canonical_target);
            if target_jid.resourcepart().is_none() {
                recipients.retain(|(_, session)| session.available.load(Ordering::Relaxed));
            }
            recipients.retain(|(jid, _)| jid != from);
            for (jid, recipient) in recipients {
                if recipient_privacy {
                    let active = recipient
                        .privacy_active
                        .read()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .clone();
                    if !self
                        .message_service
                        .privacy_allows_session(
                            recipient.user_id,
                            recipient.connection_id,
                            active.as_deref(),
                            from,
                            northstar_xep_0016::PrivacyStanzaKind::PresenceIn,
                        )
                        .await?
                    {
                        continue;
                    }
                }
                if let Err(tokio::sync::mpsc::error::TrySendError::Full(_)) = recipient
                    .sender
                    .try_send(northstar_xml_builder::rewrite::set_to(unavailable, &jid))
                {
                    anyhow::bail!("local SM unavailable recipient queue is full");
                }
            }
            self.ports
                .send_unavailable_to_remote_nodes(
                    &canonical_target,
                    &delivery,
                    from,
                    target_jid.resourcepart().is_none(),
                )
                .await?;
        } else if self
            .ports
            .external_route_domain_allowed(target_jid.domainpart())
        {
            anyhow::ensure!(
                self.ports
                    .send_federation(target_jid.domainpart(), delivery, Some(from.to_owned()))
                    .await,
                "federation queue rejected SM unavailable presence"
            );
        }
        Ok(())
    }
}
