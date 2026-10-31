//! The roster context as the composition root builds it: the roster, presence, privacy, blocking
//! and federated roster services over their PostgreSQL repositories.

use super::*;

/// The roster context's services, built once at startup.
pub(super) struct RosterModule {
    pub(super) blocking_service: northstar_roster_application::blocking::BlockingService<
        db::roster::PostgresBlockingRepository,
    >,
    pub(super) presence_service: northstar_roster_application::presence::PresenceService<
        db::presence_repository::PostgresPresenceRepository,
    >,
    pub(super) roster_service: RosterService,
    pub(super) s2s_roster_authorization_service:
        northstar_roster_application::s2s_roster_authorization::FederatedRosterAuthorizationService<
            northstar_roster_postgres::federated_roster::PostgresFederatedRosterRepository,
        >,
    pub(super) privacy_service: northstar_roster_application::privacy::PrivacyService<
        db::privacy::PostgresPrivacyRepository,
    >,
}

impl RosterModule {
    /// Builds the services over the primary pool.
    pub(super) fn new(pool: &PgPool) -> Self {
        Self {
            blocking_service: northstar_roster_application::blocking::BlockingService::new(
                db::roster::PostgresBlockingRepository::new(pool.clone()),
            ),
            presence_service: northstar_roster_application::presence::PresenceService::new(
                db::presence_repository::PostgresPresenceRepository::new(pool.clone()),
            ),
            roster_service: RosterService::new(db::roster::PostgresRosterRepository::new(
                pool.clone(),
                db::roster::RootRosterEffects,
            )),
            s2s_roster_authorization_service:
                northstar_roster_application::s2s_roster_authorization::FederatedRosterAuthorizationService::new(
                    northstar_roster_postgres::federated_roster::PostgresFederatedRosterRepository::new(
                        pool.clone(),
                    ),
                ),
            privacy_service: northstar_roster_application::privacy::PrivacyService::new(
                db::privacy::PostgresPrivacyRepository::new(pool.clone()),
            ),
        }
    }
}
