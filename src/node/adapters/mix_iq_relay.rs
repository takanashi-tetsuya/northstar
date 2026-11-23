//! The MIX IQ timeout worker shares its correlation index with live responses.

use crate::node::FederationRouter;
use crate::node::ServerNode;
use northstar_federation_application::effective_policy::EffectiveFederationPolicy;
use northstar_mix_xmpp::ports::{MixFederationPolicy, MixIqRelayExpiryPort};
use northstar_room_application::mix_service::MixService;
use northstar_room_core::mix_iq_relay::{MixIqRelayIndex, PendingMixIqRelay};
use northstar_workflows::room_effects::PostgresMixRepository;
use std::{sync::Arc, time::Instant};

pub struct MixIqFederationPolicy(EffectiveFederationPolicy);

impl MixFederationPolicy for MixIqFederationPolicy {
    fn prepared_domain_allowed(&self, domain: &str) -> bool {
        self.0.prepared_domain_allowed(domain)
    }
}

pub type MixIqRelayRoute =
    northstar_mix_xmpp::iq_relay_route::MixIqRelayRoute<FederationRouter, MixIqFederationPolicy>;

pub struct MixIqRelayExpiryContext {
    pending: Arc<MixIqRelayIndex>,
    route: MixIqRelayRoute,
    service: MixService<PostgresMixRepository>,
}

impl ServerNode {
    pub(crate) fn mix_iq_relay_route(&self) -> MixIqRelayRoute {
        MixIqRelayRoute::new(
            Arc::clone(self.session.live().sessions()),
            self.config.domain.clone(),
            MixIqFederationPolicy(self.federation.effective_policy.clone()),
            self.federation.federation_outbox.clone(),
        )
    }

    pub(crate) fn mix_iq_relay_expiry_context(&self) -> MixIqRelayExpiryContext {
        MixIqRelayExpiryContext {
            pending: Arc::clone(&self.room.pending_mix_iq),
            route: self.mix_iq_relay_route(),
            service: self.room.mix_service().clone(),
        }
    }
}

impl MixIqRelayExpiryPort for MixIqRelayExpiryContext {
    type Route = MixIqRelayRoute;

    fn take_expired(&self, now: Instant) -> Vec<PendingMixIqRelay> {
        self.pending.take_expired(now)
    }

    fn route(&self) -> &MixIqRelayRoute {
        &self.route
    }

    type Repository = PostgresMixRepository;

    fn relay_service(&self) -> &MixService<Self::Repository> {
        &self.service
    }

    fn relay_now(&self) -> Instant {
        self.pending.now()
    }
}
