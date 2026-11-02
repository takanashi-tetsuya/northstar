//! Builds the federation outbox drain's view of the node and bounces given-up stanzas to their
//! local senders.

use super::{session_entries_for_in, AppState, OnlineSession};
use dashmap::DashMap;
use northstar_federation_postgres::dispatch_repository::PostgresS2sOutboxDispatchRepository;
use northstar_s2s::outbox::{LocalBounce, S2sOutboxDispatchContext, S2sOutboxFailureEffects};
use std::sync::Arc;

/// The local sessions a given-up stanza's error goes back to.
struct LocalSessions(Arc<DashMap<String, OnlineSession>>);

impl LocalBounce for LocalSessions {
    fn bounce_to_local(&self, origin: &str, error: &str) {
        for (_, session) in session_entries_for_in(&self.0, origin) {
            let _ = session.sender.try_send(error.to_owned());
        }
    }
}

impl AppState {
    pub(crate) fn s2s_outbox_failure_effects(
        &self,
    ) -> S2sOutboxFailureEffects<PostgresS2sOutboxDispatchRepository> {
        S2sOutboxFailureEffects {
            service: self.federation.s2s_outbox_dispatch_service.clone(),
            local: Arc::new(LocalSessions(Arc::clone(&self.sessions))),
            connection_failure: Arc::clone(&self.metrics.federation_failures_total),
            lease_lost: Arc::clone(&self.metrics.s2s_outbox_lease_lost_total),
            delivered: Arc::clone(&self.metrics.federation_outbound_deliveries_total),
            permanent_failure: Arc::clone(&self.metrics.s2s_outbox_permanent_failures_total),
            expired: Arc::clone(&self.metrics.s2s_outbox_expired_total),
            retry: Arc::clone(&self.metrics.s2s_outbox_retries_total),
        }
    }

    pub(crate) fn s2s_outbox_dispatch_context(
        &self,
    ) -> S2sOutboxDispatchContext<PostgresS2sOutboxDispatchRepository> {
        S2sOutboxDispatchContext {
            failure: self.s2s_outbox_failure_effects(),
            registry: Arc::clone(&self.federation.s2s_connection_registry),
            island: Arc::clone(&self.federation.federation_write_policy),
            static_policy: self.config.external_route_domain_policy(),
            runtime_policy: Arc::clone(&self.federation.federation_runtime_policy),
            component_domains: self.configured_component_domains(),
            local_domain: self.config.domain.clone(),
        }
    }
}
