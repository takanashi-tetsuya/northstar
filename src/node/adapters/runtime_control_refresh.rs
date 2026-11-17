//! Root policy targets for the durable runtime-control coordinator.

use crate::node::{FederationWritePolicy, RuntimeFederationPolicy, ServerNode};
use arc_swap::ArcSwap;
use northstar_auth_application::account_admin::RegistrationCache;
use northstar_auth_application::registration_availability::RegistrationAvailability;
use northstar_federation_application::registry::S2sOutboundClearance;
use northstar_operations_application::runtime_control_coordinator::{
    RuntimeControlCoordinator, RuntimePolicyEffects,
};
use northstar_operations_postgres::runtime_control_repository::PostgresRuntimeControlRepository;
use sqlx::{pool::PoolConnection, Postgres};
use std::sync::Arc;

pub(in crate::node) struct RuntimePolicyApplier {
    federation_writes: Arc<FederationWritePolicy>,
    registration: RegistrationAvailability,
    federation_rules: Arc<ArcSwap<RuntimeFederationPolicy>>,
    s2s_connections: S2sOutboundClearance,
}

impl RuntimePolicyEffects for RuntimePolicyApplier {
    async fn refresh_island_mode(&self, island_mode: bool) -> bool {
        self.federation_writes.refresh(island_mode).await
    }

    fn apply_registration_closed(&self, closed: bool) {
        self.registration.apply_current_closed(closed);
    }

    fn clear_for_island_mode(&self) {
        self.s2s_connections.clear_for_island_mode();
    }

    fn store_federation_rules(&self, blacklist: Vec<String>, whitelist: Vec<String>) {
        self.federation_rules
            .store(Arc::new(RuntimeFederationPolicy {
                blacklist: blacklist.into_iter().collect(),
                whitelist: whitelist.into_iter().collect(),
            }));
    }
}

pub(in crate::node) fn runtime_control_coordinator(
    state: &ServerNode,
    connection: PoolConnection<Postgres>,
) -> RuntimeControlCoordinator<PostgresRuntimeControlRepository, RuntimePolicyApplier> {
    RuntimeControlCoordinator::new(
        Arc::downgrade(state.runtime.control_liveness()),
        PostgresRuntimeControlRepository::new(connection),
        RuntimePolicyApplier {
            federation_writes: Arc::clone(&state.federation.federation_write_policy),
            registration: state.auth.registration.clone(),
            federation_rules: Arc::clone(&state.federation.federation_runtime_policy),
            s2s_connections: state
                .federation
                .s2s_connection_registry
                .outbound_clearance(),
        },
        state.config.enable_xmpp_service_control,
        Arc::clone(state.runtime.service_shutdown()),
        state.runtime.process_started_at(),
    )
}
