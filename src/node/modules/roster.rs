//! The roster context as the composition root builds it: the roster, presence, privacy, blocking
//! and federated roster services over their PostgreSQL repositories.

use crate::node::*;

/// The roster context's services, built once at startup.
pub(in crate::node) struct RosterModule {
    pub(in crate::node) blocking_service: northstar_roster_application::blocking::BlockingService<
        northstar_roster_postgres::roster::PostgresBlockingRepository,
    >,
    pub(in crate::node) presence_service: northstar_roster_application::presence::PresenceService<
        northstar_workflows::presence_repository::PostgresPresenceRepository,
    >,
    pub(in crate::node) roster_service: RosterService,
    pub(in crate::node) s2s_roster_authorization_service:
        northstar_roster_application::s2s_roster_authorization::FederatedRosterAuthorizationService<
            northstar_roster_postgres::federated_roster::PostgresFederatedRosterRepository,
        >,
    pub(in crate::node) privacy_service: northstar_roster_application::privacy::PrivacyService<
        northstar_roster_postgres::privacy::PostgresPrivacyRepository,
    >,
}

impl RosterModule {
    pub(crate) fn blocking_service(
        &self,
    ) -> &northstar_roster_application::blocking::BlockingService<
        northstar_roster_postgres::roster::PostgresBlockingRepository,
    > {
        &self.blocking_service
    }

    pub(crate) fn presence_service(
        &self,
    ) -> &northstar_roster_application::presence::PresenceService<
        northstar_workflows::presence_repository::PostgresPresenceRepository,
    > {
        &self.presence_service
    }

    pub(crate) fn roster_service(&self) -> &RosterService {
        &self.roster_service
    }

    pub(crate) fn s2s_roster_authorization_service(
        &self,
    ) -> &northstar_roster_application::s2s_roster_authorization::FederatedRosterAuthorizationService<
        northstar_roster_postgres::federated_roster::PostgresFederatedRosterRepository,
    >{
        &self.s2s_roster_authorization_service
    }

    pub(crate) fn privacy_service(
        &self,
    ) -> &northstar_roster_application::privacy::PrivacyService<
        northstar_roster_postgres::privacy::PostgresPrivacyRepository,
    > {
        &self.privacy_service
    }

    /// Builds the services over the primary pool.
    pub(in crate::node) fn new(pool: &PgPool) -> Self {
        Self {
            blocking_service: northstar_roster_application::blocking::BlockingService::new(
                northstar_roster_postgres::roster::PostgresBlockingRepository::new(pool.clone()),
            ),
            presence_service: northstar_roster_application::presence::PresenceService::new(
                northstar_workflows::presence_repository::PostgresPresenceRepository::new(pool.clone()),
            ),
            roster_service: RosterService::new(northstar_workflows::roster::PostgresRosterRepository::new(
                pool.clone(),
                northstar_workflows::roster::WorkflowRosterEffects,
            )),
            s2s_roster_authorization_service:
                northstar_roster_application::s2s_roster_authorization::FederatedRosterAuthorizationService::new(
                    northstar_roster_postgres::federated_roster::PostgresFederatedRosterRepository::new(
                        pool.clone(),
                    ),
                ),
            privacy_service: northstar_roster_application::privacy::PrivacyService::new(
                northstar_roster_postgres::privacy::PostgresPrivacyRepository::new(pool.clone()),
            ),
        }
    }
}
