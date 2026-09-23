//! Durable federation outbox claims, policy, retry and local bounce effects.

use super::{
    federation_rule_matches, session_entries_for_in, AppState, FederationWritePolicy,
    OnlineSession, RuntimeFederationPolicy,
};
use crate::{
    config::ExternalRouteDomainPolicy,
    db::s2s_outbox_dispatch_repository::PostgresS2sOutboxDispatchRepository,
    jid::{prepare_domainpart, CanonicalJid},
    s2s::{
        telemetry::OutboundDispositionTelemetry, BidiRouteSnapshot, FederationEnvelope,
        S2sConnectionRegistry,
    },
    services::s2s_outbox_dispatch::S2sOutboxDispatchService,
};
use dashmap::DashMap;
use std::sync::{atomic::AtomicU64, Arc};

pub(crate) type DispatchService = S2sOutboxDispatchService<PostgresS2sOutboxDispatchRepository>;

pub(crate) struct S2sOutboxFailureEffects {
    service: DispatchService,
    sessions: Arc<DashMap<String, OnlineSession>>,
    connection_failure: Arc<AtomicU64>,
    lease_lost: Arc<AtomicU64>,
    delivered: Arc<AtomicU64>,
    permanent_failure: Arc<AtomicU64>,
    expired: Arc<AtomicU64>,
    retry: Arc<AtomicU64>,
}

impl S2sOutboxFailureEffects {
    pub(crate) fn service(&self) -> &DispatchService {
        &self.service
    }

    pub(crate) fn telemetry(&self) -> OutboundDispositionTelemetry<'_> {
        OutboundDispositionTelemetry::new(
            &self.connection_failure,
            &self.lease_lost,
            &self.delivered,
            &self.permanent_failure,
            &self.expired,
            &self.retry,
        )
    }

    pub(crate) fn bounce(&self, envelope: &FederationEnvelope, condition: &str) {
        let Some(origin) = &envelope.bounce_to else {
            return;
        };
        let Some(error) =
            crate::s2s::outbound::delivery_failure_stanza(&envelope.stanza, condition)
        else {
            return;
        };
        for (_, session) in session_entries_for_in(&self.sessions, origin) {
            let _ = session.sender.try_send(error.clone());
        }
    }
}

pub(crate) struct S2sOutboxDispatchContext {
    failure: S2sOutboxFailureEffects,
    registry: Arc<S2sConnectionRegistry>,
    island: Arc<FederationWritePolicy>,
    static_policy: ExternalRouteDomainPolicy,
    runtime_policy: Arc<arc_swap::ArcSwap<RuntimeFederationPolicy>>,
    component_domains: Vec<String>,
    local_domain: String,
}

impl AppState {
    pub(crate) fn s2s_outbox_failure_effects(&self) -> S2sOutboxFailureEffects {
        S2sOutboxFailureEffects {
            service: self.s2s_outbox_dispatch_service.clone(),
            sessions: Arc::clone(&self.sessions),
            connection_failure: Arc::clone(&self.metrics.federation_failures_total),
            lease_lost: Arc::clone(&self.metrics.s2s_outbox_lease_lost_total),
            delivered: Arc::clone(&self.metrics.federation_outbound_deliveries_total),
            permanent_failure: Arc::clone(&self.metrics.s2s_outbox_permanent_failures_total),
            expired: Arc::clone(&self.metrics.s2s_outbox_expired_total),
            retry: Arc::clone(&self.metrics.s2s_outbox_retries_total),
        }
    }

    pub(crate) fn s2s_outbox_dispatch_context(&self) -> S2sOutboxDispatchContext {
        S2sOutboxDispatchContext {
            failure: self.s2s_outbox_failure_effects(),
            registry: Arc::clone(&self.s2s_connection_registry),
            island: Arc::clone(&self.federation_write_policy),
            static_policy: self.config.external_route_domain_policy(),
            runtime_policy: Arc::clone(&self.federation_runtime_policy),
            component_domains: self.configured_component_domains(),
            local_domain: self.config.domain.clone(),
        }
    }
}

impl S2sOutboxDispatchContext {
    pub(crate) fn service(&self) -> &DispatchService {
        self.failure.service()
    }

    pub(crate) fn failure(&self) -> &S2sOutboxFailureEffects {
        &self.failure
    }

    pub(crate) fn registry(&self) -> &S2sConnectionRegistry {
        &self.registry
    }

    pub(crate) fn component_domains(&self) -> &[String] {
        &self.component_domains
    }

    pub(crate) fn local_domain(&self) -> &str {
        &self.local_domain
    }

    pub(crate) fn island_mode_enabled(&self) -> bool {
        self.island.enabled()
    }

    pub(crate) fn federation_domain_allowed(&self, domain: &str) -> bool {
        let Ok(domain) = prepare_domainpart(domain) else {
            return false;
        };
        self.static_policy.federation_domain_allowed(&domain)
            && self.runtime_policy.load().allows_domain(&domain)
    }

    pub(crate) fn federation_entity_allowed(&self, entity: &str) -> bool {
        let Ok(entity) = CanonicalJid::parse(entity) else {
            return false;
        };
        if !self
            .static_policy
            .federation_domain_allowed(entity.domainpart())
        {
            return false;
        }
        let policy = self.runtime_policy.load();
        let matches = |rule: &str| federation_rule_matches(rule, &entity);
        !policy.blacklist.iter().any(|entry| matches(entry))
            && (policy.whitelist.is_empty() || policy.whitelist.iter().any(|entry| matches(entry)))
    }

    pub(crate) fn component_domain_configured(&self, domain: &str) -> bool {
        prepare_domainpart(domain).is_ok_and(|domain| self.component_domains.contains(&domain))
    }

    pub(crate) fn bidirectional_route(&self, key: &str) -> Option<BidiRouteSnapshot> {
        self.registry.bidirectional_route(key)
    }
}
