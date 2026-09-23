//! MIX presence withdrawal for a fenced client resource.

use super::{AppState, RuntimeFederationPolicy};
use crate::{
    config::ExternalRouteDomainPolicy,
    db::mix_repository::PostgresMixRepository,
    jid::{prepare_domainpart, CanonicalJid},
    s2s::FederationRouter,
    services::mix::{MixService, NODE_PRESENCE},
};
use anyhow::Result;
use northstar_xml_builder::XmlElement;
use std::sync::Arc;
use uuid::Uuid;

pub(crate) struct SessionCleanupMix {
    service: MixService<PostgresMixRepository>,
    federation: FederationRouter,
    domains: ExternalRouteDomainPolicy,
    runtime_policy: Arc<arc_swap::ArcSwap<RuntimeFederationPolicy>>,
    local_mix_domain: String,
}

impl AppState {
    pub(crate) fn session_cleanup_mix(&self) -> SessionCleanupMix {
        SessionCleanupMix {
            service: self.mix_service.clone(),
            federation: self.federation_outbox.clone(),
            domains: self.config.external_route_domain_policy(),
            runtime_policy: Arc::clone(&self.federation_runtime_policy),
            local_mix_domain: prepare_domainpart(&format!("mix.{}", self.config.domain))
                .expect("configured XMPP domain must form a valid MIX service domain"),
        }
    }
}

impl SessionCleanupMix {
    fn federation_domain_allowed(&self, domain: &str) -> bool {
        let Ok(domain) = prepare_domainpart(domain) else {
            return false;
        };
        self.domains.federation_domain_allowed(&domain)
            && self.runtime_policy.load().allows_domain(&domain)
    }

    pub(crate) async fn disconnect_presence(
        &self,
        user_id: Uuid,
        actor_bare: &str,
        actor_full: &str,
    ) -> Result<()> {
        let unavailable = XmlElement::namespaced("presence", "jabber:client")
            .attr("from", actor_full)
            .attr("type", "unavailable")
            .finish();
        for membership in self.service.pam_memberships(user_id).await? {
            if membership.state != "joined"
                || !membership
                    .subscriptions
                    .iter()
                    .any(|subscription| subscription == NODE_PRESENCE)
            {
                continue;
            }
            let Ok(channel) = CanonicalJid::parse_bare(&membership.channel_jid) else {
                tracing::warn!(channel = %membership.channel_jid, "ignored malformed persisted MIX membership JID");
                continue;
            };
            let domain = channel.domainpart();
            if domain == self.local_mix_domain {
                let Some(channel_localpart) = channel.localpart() else {
                    continue;
                };
                // The generated unavailable stanza has no children. The
                // channel service performs the same idempotent transaction as
                // a direct unavailable presence from this resource.
                if let Some(room) = self
                    .service
                    .mix_channel(&self.local_mix_domain, channel_localpart)
                    .await?
                {
                    let _ = self
                        .service
                        .store_mix_presence(room.id, actor_bare, actor_full, "", true)
                        .await?;
                }
            } else if self.federation_domain_allowed(domain) {
                let directed = crate::xmpp::xml_util::set_to(&unavailable, &membership.channel_jid);
                let _ = self
                    .federation
                    .send(domain, directed, Some(actor_bare.to_owned()))
                    .await;
            }
        }
        Ok(())
    }
}
