//! The MIX IQ timeout worker shares its correlation index with live responses.

use super::{session_entries_for_in, AppState, OnlineSession, RuntimeFederationPolicy};
use crate::{
    config::ExternalRouteDomainPolicy,
    jid::{prepare_domainpart, CanonicalJid},
    s2s::FederationRouter,
};
use dashmap::DashMap;
use northstar_protocol_runtime::mix::{MixIqRelayIndex, PendingMixIqRelay};
use std::{sync::Arc, time::Instant};

pub(crate) struct MixIqRelayRoute {
    sessions: Arc<DashMap<String, OnlineSession>>,
    local_domain: String,
    static_policy: ExternalRouteDomainPolicy,
    runtime_policy: Arc<arc_swap::ArcSwap<RuntimeFederationPolicy>>,
    federation: FederationRouter,
}

pub(crate) struct MixIqRelayExpiryContext {
    pending: Arc<MixIqRelayIndex>,
    route: MixIqRelayRoute,
}

impl AppState {
    pub(crate) fn mix_iq_relay_route(&self) -> MixIqRelayRoute {
        MixIqRelayRoute {
            sessions: Arc::clone(&self.sessions),
            local_domain: self.config.domain.clone(),
            static_policy: self.config.external_route_domain_policy(),
            runtime_policy: Arc::clone(&self.federation_runtime_policy),
            federation: self.federation_outbox.clone(),
        }
    }

    pub(crate) fn mix_iq_relay_expiry_context(&self) -> MixIqRelayExpiryContext {
        MixIqRelayExpiryContext {
            pending: Arc::clone(&self.pending_mix_iq),
            route: self.mix_iq_relay_route(),
        }
    }
}

impl MixIqRelayExpiryContext {
    pub(crate) fn take_expired(&self, now: Instant) -> Vec<PendingMixIqRelay> {
        self.pending.take_expired(now)
    }

    pub(crate) fn route(&self) -> &MixIqRelayRoute {
        &self.route
    }
}

impl MixIqRelayRoute {
    pub(crate) async fn deliver(&self, recipient: &str, stanza: String) {
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
        } else if self.static_policy.federation_domain_allowed(&domain)
            && self.runtime_policy.load().allows_domain(&domain)
        {
            let _ = self.federation.send(&domain, stanza, None).await;
        }
    }
}
