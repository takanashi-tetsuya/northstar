//! The message context as the composition root builds it: the personal-message, admission,
//! retraction and push services over their PostgreSQL repositories, and external service
//! discovery.

use crate::node::*;

/// The message context's services, built once at startup.
pub(in crate::node) struct MessageModule {
    /// Personal-message authorization and durable admission boundary. The
    /// protocol layer must not compose its own archive/outbox/offline writes.
    pub(in crate::node) message_service: northstar_message_application::messaging::MessageService<
        northstar_workflows::message_repository::PostgresMessageRepository,
    >,
    pub(in crate::node) message_admission_service:
        northstar_message_application::message_admission::MessageAdmissionService<
            northstar_workflows::message_admission_port::AbuseMessageAdmissionPort,
        >,
    /// XEP-0424/XEP-0444 tombstone, action archive and federation admission
    /// transaction boundary.
    pub(in crate::node) retraction_service:
        northstar_message_application::retractions::RetractionService<
            northstar_workflows::retraction_repository::PostgresRetractionRepository,
        >,
    pub(in crate::node) push_service: northstar_message_application::push::PushService<
        northstar_workflows::push_repository::PostgresPushRepository,
    >,
    pub(in crate::node) extdisco_service: northstar_message_application::extdisco::ExtDiscoService,
}

/// What the message context's services are built from.
pub(in crate::node) struct MessageModuleParts<'a> {
    pub(in crate::node) config: &'a Config,
    pub(in crate::node) pool: &'a PgPool,
    pub(in crate::node) abuse: &'a Arc<AbuseGuard>,
    pub(in crate::node) cluster: &'a crate::cluster::ClusterManager,
    /// Built by `ServerNode::new`, which consumes the TURN secret from `Config`.
    pub(in crate::node) extdisco_service: northstar_message_application::extdisco::ExtDiscoService,
}

impl MessageModule {
    pub(crate) fn extdisco_service(
        &self,
    ) -> &northstar_message_application::extdisco::ExtDiscoService {
        &self.extdisco_service
    }

    pub(crate) fn message_service(
        &self,
    ) -> &northstar_message_application::messaging::MessageService<
        northstar_workflows::message_repository::PostgresMessageRepository,
    > {
        &self.message_service
    }

    pub(crate) fn message_admission_service(
        &self,
    ) -> &northstar_message_application::message_admission::MessageAdmissionService<
        northstar_workflows::message_admission_port::AbuseMessageAdmissionPort,
    > {
        &self.message_admission_service
    }

    pub(crate) fn retraction_service(
        &self,
    ) -> &northstar_message_application::retractions::RetractionService<
        northstar_workflows::retraction_repository::PostgresRetractionRepository,
    > {
        &self.retraction_service
    }

    pub(crate) fn push_service(
        &self,
    ) -> &northstar_message_application::push::PushService<
        northstar_workflows::push_repository::PostgresPushRepository,
    > {
        &self.push_service
    }

    /// Builds the services over the primary pool.
    pub(in crate::node) fn new(parts: MessageModuleParts<'_>) -> Self {
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
                .with_cluster_admission(crate::node::adapters::cluster_direct_commit::ClusterDirectCommit(cluster.admission())),
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
                .with_cluster_admission(crate::node::adapters::cluster_direct_commit::ClusterDirectCommit(cluster.admission())),
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
