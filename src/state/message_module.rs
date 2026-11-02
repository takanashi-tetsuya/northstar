//! The message context as the composition root builds it: the personal-message, admission,
//! retraction and push services over their PostgreSQL repositories, and external service
//! discovery.

use super::*;

/// The message context's services, built once at startup.
pub(super) struct MessageModule {
    /// Personal-message authorization and durable admission boundary. The
    /// protocol layer must not compose its own archive/outbox/offline writes.
    pub(super) message_service: northstar_message_application::messaging::MessageService<
        northstar_workflows::message_repository::PostgresMessageRepository,
    >,
    pub(super) message_admission_service:
        northstar_message_application::message_admission::MessageAdmissionService<
            northstar_workflows::message_admission_port::AbuseMessageAdmissionPort,
        >,
    /// XEP-0424/XEP-0444 tombstone, action archive and federation admission
    /// transaction boundary.
    pub(super) retraction_service: northstar_message_application::retractions::RetractionService<
        northstar_workflows::retraction_repository::PostgresRetractionRepository,
    >,
    pub(super) push_service: northstar_message_application::push::PushService<
        northstar_workflows::push_repository::PostgresPushRepository,
    >,
    pub(super) extdisco_service: northstar_message_application::extdisco::ExtDiscoService,
}

/// What the message context's services are built from.
pub(super) struct MessageModuleParts<'a> {
    pub(super) config: &'a Config,
    pub(super) pool: &'a PgPool,
    pub(super) abuse: &'a Arc<AbuseGuard>,
    pub(super) cluster: &'a crate::cluster::ClusterManager,
    /// Built by `AppState::new`, which consumes the TURN secret from `Config`.
    pub(super) extdisco_service: northstar_message_application::extdisco::ExtDiscoService,
}

impl MessageModule {
    /// Builds the services over the primary pool.
    pub(super) fn new(parts: MessageModuleParts<'_>) -> Self {
        let MessageModuleParts {
            config,
            pool,
            abuse,
            cluster,
            extdisco_service,
        } = parts;
        Self {
            message_service: northstar_message_application::messaging::MessageService::new(
                northstar_workflows::message_repository::PostgresMessageRepository::new(
                    pool.clone(),
                    abuse.personal_message_content_keyring(),
                    config.domain.clone(),
                    config.offline_max_messages_per_account,
                    config.offline_max_bytes_per_account,
                    config.offline_message_ttl_days,
                )
                .with_cluster_admission(super::cluster_direct_commit::ClusterDirectCommit(cluster.admission())),
                config.require_encrypted_archive,
            ),
            message_admission_service:
                northstar_message_application::message_admission::MessageAdmissionService::new(
                    northstar_workflows::message_admission_port::AbuseMessageAdmissionPort::new(
                        northstar_abuse_postgres::message_admission::PostgresMessageAdmissionRepository::new(
                            Arc::clone(abuse),
                            pool.clone(),
                        ),
                    ),
                ),
            retraction_service: northstar_message_application::retractions::RetractionService::new(
                northstar_workflows::retraction_repository::PostgresRetractionRepository::new(
                    pool.clone(),
                )
                .with_cluster_admission(super::cluster_direct_commit::ClusterDirectCommit(cluster.admission())),
                abuse.personal_retraction_content_keyring(),
                config.domain.clone(),
            ),
            push_service: northstar_message_application::push::PushService::new(
                northstar_workflows::push_repository::PostgresPushRepository::new(pool.clone()),
            ),
            extdisco_service,
        }
    }
}
