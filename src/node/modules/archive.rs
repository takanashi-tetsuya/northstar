//! The archive context as the composition root builds it: the MAM service over its PostgreSQL
//! repository and federated outbox wakeup.

use crate::node::*;

/// The archive context's service, built once at startup.
pub(in crate::node) struct ArchiveModule {
    pub(in crate::node) mam_service: northstar_archive_application::MamService<
        northstar_workflows::mam_repository::PostgresMamRepository,
    >,
}

impl ArchiveModule {
    pub(crate) fn mam_service(
        &self,
    ) -> &northstar_archive_application::MamService<
        northstar_workflows::mam_repository::PostgresMamRepository,
    > {
        &self.mam_service
    }

    pub(in crate::node) fn new(
        config: &Config,
        pool: &PgPool,
        federation_outbox: &FederationRouter,
    ) -> Self {
        let mam_service = northstar_archive_application::MamService::new(
            northstar_workflows::mam_repository::PostgresMamRepository::new(pool.clone()),
            northstar_archive_application::FederatedMamOutboxLimits {
                ttl_seconds: config.s2s_outbox_ttl_seconds,
                max_rows: config.s2s_outbox_max_rows,
                max_bytes: config.s2s_outbox_max_bytes,
                max_per_domain: config.s2s_outbox_max_per_domain,
            },
            federation_outbox.outbox_wakeup(),
        );
        Self { mam_service }
    }
}
