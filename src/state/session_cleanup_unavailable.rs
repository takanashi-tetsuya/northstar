//! Policy-checked unavailable delivery after a local route has been fenced.

use super::{bare_jid, session_entries_for_in, AppState, OnlineSession};
use crate::{
    cluster::ClusterUnavailableDelivery,
    config::ExternalRouteDomainPolicy,
    db::{self, sm_teardown_presence_repository::PostgresSmTeardownPresenceRepository},
    s2s::FederationRouter,
    services::{
        messaging::MessageService,
        sm_teardown_presence::{SmTeardownPresenceService, UnavailablePolicy},
    },
};
use anyhow::Result;
use dashmap::DashMap;
use std::sync::{atomic::Ordering, Arc};
use uuid::Uuid;

pub(crate) struct SessionCleanupUnavailable {
    policy: SmTeardownPresenceService<PostgresSmTeardownPresenceRepository>,
    recipients: Arc<DashMap<String, OnlineSession>>,
    message_service: MessageService<db::messaging::PostgresMessageRepository>,
    remote: ClusterUnavailableDelivery,
    federation: FederationRouter,
    domains: ExternalRouteDomainPolicy,
    local_domain: String,
}

impl AppState {
    pub(crate) fn session_cleanup_unavailable(&self) -> SessionCleanupUnavailable {
        SessionCleanupUnavailable {
            policy: self.sm_teardown_presence_service(),
            recipients: Arc::clone(&self.sessions),
            message_service: self.message_service.clone(),
            remote: self.cluster.unavailable_delivery(),
            federation: self.federation_outbox.clone(),
            domains: self.config.external_route_domain_policy(),
            local_domain: self.config.domain.clone(),
        }
    }
}

impl SessionCleanupUnavailable {
    pub(crate) async fn roster_subscribers(&self, owner_id: Uuid) -> Result<Vec<String>> {
        self.policy.roster_subscribers(owner_id).await
    }

    pub(crate) async fn route_with_policy(
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
    pub(crate) async fn route_siblings_unchecked(
        &self,
        from: &str,
        unavailable: &str,
    ) -> Result<()> {
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
        let Ok(target_jid) = crate::jid::CanonicalJid::parse(target) else {
            anyhow::bail!("invalid SM teardown presence target");
        };
        let canonical_target = target_jid.to_string();
        let delivery = crate::xmpp::xml_util::set_to(unavailable, &canonical_target);
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
                            db::PrivacyStanzaKind::PresenceIn,
                        )
                        .await?
                    {
                        continue;
                    }
                }
                if let Err(tokio::sync::mpsc::error::TrySendError::Full(_)) = recipient
                    .sender
                    .try_send(crate::xmpp::xml_util::set_to(unavailable, &jid))
                {
                    anyhow::bail!("local SM unavailable recipient queue is full");
                }
            }
            self.remote
                .send_unavailable_to_remote_nodes(
                    &canonical_target,
                    &delivery,
                    from,
                    target_jid.resourcepart().is_none(),
                )
                .await?;
        } else if self
            .domains
            .external_route_domain_allowed(target_jid.domainpart())
        {
            anyhow::ensure!(
                self.federation
                    .send(target_jid.domainpart(), delivery, Some(from.to_owned()))
                    .await,
                "federation queue rejected SM unavailable presence"
            );
        }
        Ok(())
    }
}
