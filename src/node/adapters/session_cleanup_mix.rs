//! Concrete bindings for MIX presence withdrawal after a client resource is fenced.

use crate::node::FederationRouter;
use crate::node::ServerNode;
use northstar_federation_application::effective_policy::EffectiveFederationPolicy;
use northstar_mix_xmpp::ports::MixPresenceWithdrawalPort;
use northstar_room_application::mix_service::MixService;
use northstar_workflows::room_effects::PostgresMixRepository;
use northstar_xmpp_types::jid::prepare_domainpart;

pub(crate) struct SessionCleanupMix {
    service: MixService<PostgresMixRepository>,
    federation: FederationRouter,
    policy: EffectiveFederationPolicy,
    local_mix_domain: String,
}

impl ServerNode {
    pub(crate) fn session_cleanup_mix(&self) -> SessionCleanupMix {
        SessionCleanupMix {
            service: self.room.mix_service.clone(),
            federation: self.federation.federation_outbox.clone(),
            policy: self.federation.effective_policy.clone(),
            local_mix_domain: prepare_domainpart(&format!("mix.{}", self.config.domain))
                .expect("configured XMPP domain must form a valid MIX service domain"),
        }
    }
}

impl MixPresenceWithdrawalPort for SessionCleanupMix {
    type Repository = PostgresMixRepository;
    type Federation = FederationRouter;

    fn service(&self) -> &MixService<Self::Repository> {
        &self.service
    }

    fn local_mix_domain(&self) -> &str {
        &self.local_mix_domain
    }

    fn federation_domain_allowed(&self, domain: &str) -> bool {
        self.policy.domain_allowed(domain)
    }

    fn federation_outbox(&self) -> &Self::Federation {
        &self.federation
    }
}
