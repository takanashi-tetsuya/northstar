//! The pubsub context as the composition root builds it: the PubSub, profile and private XML
//! storage services over their PostgreSQL repositories.

use super::*;
use northstar_runtime::durable_outbox::DurableOutboxDatabaseAdmission;

/// The pubsub context's services, built once at startup.
pub(super) struct PubSubModule {
    /// Narrow persistence/orchestration capability for XEP-0060 and PEP.
    /// Protocol handlers receive this service rather than database authority.
    pub(super) pubsub_service: northstar_pubsub_application::PubSubService<
        db::pubsub_repository::PostgresPubSubRepository,
    >,
    /// Account-scoped vCard/vCard4/avatar mutation and public-profile read
    /// boundary. Profile transactions and authorization never cross into the
    /// XMPP protocol layer.
    pub(super) profile_service: northstar_pubsub_application::profile::ProfileService<
        db::profile::PostgresProfileRepository,
    >,
    /// XEP-0049 private XML storage within the account's PEP quotas.
    pub(super) private_storage_service:
        northstar_pubsub_application::private_storage::PrivateStorageService<
            northstar_pubsub_postgres::PostgresPrivateStorageRepository,
        >,
}

impl PubSubModule {
    /// Builds the services over the primary pool. The PubSub event outbox shares the durable
    /// outbox admission of the primary pool, and the profile service shares the PubSub service's
    /// mutation admission.
    pub(super) fn new(
        config: &Config,
        pool: &PgPool,
        durable_outbox_database_admission: &DurableOutboxDatabaseAdmission,
    ) -> Self {
        let pubsub_service =
            northstar_pubsub_application::PubSubService::new_with_durable_outbox_database_admission(
                db::pubsub_repository::PostgresPubSubRepository::new(pool.clone(), &config.domain),
                pool.options().get_max_connections(),
                durable_outbox_database_admission.clone(),
            );
        let profile_service =
            northstar_pubsub_application::profile::ProfileService::with_mutation_admission(
                db::profile::PostgresProfileRepository::new(pool.clone(), config.domain.clone()),
                pubsub_service.mutation_admission(),
            );
        let private_storage_service =
            northstar_pubsub_application::private_storage::PrivateStorageService::new(
                northstar_pubsub_postgres::PostgresPrivateStorageRepository::new(pool.clone()),
                config.pep_max_nodes_per_account,
                config.pep_max_storage_bytes_per_account,
            );
        Self {
            pubsub_service,
            profile_service,
            private_storage_service,
        }
    }
}
