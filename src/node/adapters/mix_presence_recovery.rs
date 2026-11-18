//! Live-route fences and application effects for MIX presence recovery.

use crate::node::FederationRouter;
use crate::node::ServerNode;
use anyhow::Result;
use northstar_federation_application::effective_policy::EffectiveFederationPolicy;
use northstar_mix_xmpp::ports::MixPresenceRecoveryPort;
use northstar_mix_xmpp::presence_recovery_routes::MixPresenceRecoveryRoutes;
use northstar_room_application::mix_service::{
    MixAccount, MixChannel, MixService, PamMembership, PresenceOutcome,
};
use northstar_time::{DateTime, Utc};
use northstar_workflows::room_effects::PostgresMixRepository;
use std::sync::Arc;
use uuid::Uuid;

pub struct MixPresenceRecoveryContext {
    routes: MixPresenceRecoveryRoutes,
    service: MixService<PostgresMixRepository>,
    local_domain: String,
    policy: EffectiveFederationPolicy,
    federation: FederationRouter,
}

impl ServerNode {
    pub(crate) fn mix_presence_recovery_context(&self) -> MixPresenceRecoveryContext {
        MixPresenceRecoveryContext {
            routes: MixPresenceRecoveryRoutes::new(Arc::clone(self.session.live().sessions())),
            service: self.room.mix_service.clone(),
            local_domain: self.config.domain.clone(),
            policy: self.federation.effective_policy.clone(),
            federation: self.federation.federation_outbox.clone(),
        }
    }
}

impl MixPresenceRecoveryPort for MixPresenceRecoveryContext {
    type Routes = MixPresenceRecoveryRoutes;

    fn routes(&self) -> &MixPresenceRecoveryRoutes {
        &self.routes
    }

    fn local_domain(&self) -> &str {
        &self.local_domain
    }

    fn local_mix_domain(&self) -> String {
        northstar_xmpp_types::jid::prepare_domainpart(&format!("mix.{}", self.local_domain))
            .expect("configured XMPP domain must form a valid MIX service domain")
    }

    fn federation_domain_allowed(&self, domain: &str) -> bool {
        self.policy.domain_allowed(domain)
    }

    async fn send_federated(&self, domain: &str, stanza: String, source: Option<String>) {
        let _ = self.federation.send(domain, stanza, source).await;
    }

    async fn find_enabled_user(&self, username: &str) -> Result<Option<MixAccount>> {
        self.service.find_enabled_user(username).await
    }

    async fn wake_delivery_recipient(&self, bare_jid: &str) -> Result<()> {
        self.service.wake_mix_delivery_recipient(bare_jid).await?;
        Ok(())
    }

    async fn pam_memberships(&self, user_id: Uuid) -> Result<Vec<PamMembership>> {
        self.service.pam_memberships(user_id).await
    }

    async fn mix_channel(&self, domain: &str, localpart: &str) -> Result<Option<MixChannel>> {
        self.service.mix_channel(domain, localpart).await
    }

    async fn ensure_presence(
        &self,
        channel_id: Uuid,
        actor_bare: &str,
        actor_full: &str,
    ) -> Result<PresenceOutcome> {
        self.service
            .ensure_mix_presence(channel_id, actor_bare, actor_full, "")
            .await
    }

    async fn expire_unrefreshed(&self, cutoff: DateTime<Utc>) -> Result<usize> {
        Ok(self
            .service
            .expire_unrefreshed_mix_presence(cutoff)
            .await?
            .len())
    }
}
