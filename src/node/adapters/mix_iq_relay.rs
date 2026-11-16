//! The MIX IQ timeout worker shares its correlation index with live responses.

use crate::node::FederationRouter;
use crate::node::{session_entries_for_in, OnlineSession, ServerNode};
use dashmap::DashMap;
use northstar_federation_application::effective_policy::EffectiveFederationPolicy;
use northstar_mix_xmpp::ports::{MixIqRelayExpiryPort, MixIqRelayRoutePort};
use northstar_room_core::mix_iq_relay::{MixIqRelayIndex, PendingMixIqRelay};
use northstar_xmpp_types::jid::{prepare_domainpart, CanonicalJid};
use std::{sync::Arc, time::Instant};

pub struct MixIqRelayRoute {
    sessions: Arc<DashMap<String, OnlineSession>>,
    local_domain: String,
    policy: EffectiveFederationPolicy,
    federation: FederationRouter,
}

pub struct MixIqRelayExpiryContext {
    pending: Arc<MixIqRelayIndex>,
    route: MixIqRelayRoute,
}

impl ServerNode {
    pub(crate) fn mix_iq_relay_route(&self) -> MixIqRelayRoute {
        MixIqRelayRoute {
            sessions: Arc::clone(&self.sessions),
            local_domain: self.config.domain.clone(),
            policy: self.federation.effective_policy.clone(),
            federation: self.federation.federation_outbox.clone(),
        }
    }

    pub(crate) fn mix_iq_relay_expiry_context(&self) -> MixIqRelayExpiryContext {
        MixIqRelayExpiryContext {
            pending: Arc::clone(&self.room.pending_mix_iq),
            route: self.mix_iq_relay_route(),
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
}

impl MixIqRelayRoutePort for MixIqRelayRoute {
    async fn deliver(&self, recipient: &str, stanza: String) {
        let Ok(recipient_jid) = CanonicalJid::parse(recipient) else {
            return;
        };
        let domain = recipient_jid.domainpart();
        let Ok(domain) = prepare_domainpart(domain) else {
            return;
        };
        if domain == self.local_domain {
            for (_, target) in session_entries_for_in(&self.sessions, recipient) {
                let _ = target.sender.try_send(stanza.clone());
            }
        } else if self.policy.prepared_domain_allowed(&domain) {
            let _ = self.federation.send(&domain, stanza, None).await;
        }
    }
}
