//! The anti-abuse context as the composition root builds it: the challenge and login services over
//! the guard, and the key generation the readiness path checks.

use crate::node::*;

/// The anti-abuse context's services, built once at startup.
pub(in crate::node) struct AbuseModule {
    pub(in crate::node) challenge_issue_service:
        northstar_abuse_application::challenge::ChallengeIssueService<
            northstar_abuse_postgres::challenge::PostgresChallengeRepository,
        >,
    pub(in crate::node) challenge_cleanup_service:
        northstar_abuse_application::challenge::ChallengeCleanupService<
            northstar_abuse_postgres::challenge::PostgresChallengeRepository,
        >,
    pub(in crate::node) sasl_login_abuse_service:
        northstar_abuse_application::login::SaslLoginAbuseService<
            northstar_abuse_postgres::login::PostgresSaslLoginAbuseRepository,
        >,
    pub(in crate::node) passkey_login_abuse_service: Arc<
        northstar_abuse_application::login::PasskeyLoginAbuseService<
            northstar_abuse_postgres::login::PostgresPasskeyLoginAbuseRepository,
        >,
    >,
    /// Public, irreversible key IDs and the configured generation used by the
    /// readiness path to detect a node that drifted from PostgreSQL authority.
    pub(in crate::node) abuse_key_deployment:
        Option<northstar_abuse_policy::model::AbuseKeyDeploymentIdentity>,
}

impl AbuseModule {
    pub(crate) fn challenge_issue_service(
        &self,
    ) -> &northstar_abuse_application::challenge::ChallengeIssueService<
        northstar_abuse_postgres::challenge::PostgresChallengeRepository,
    > {
        &self.challenge_issue_service
    }

    pub(crate) fn sasl_login_abuse_service(
        &self,
    ) -> &northstar_abuse_application::login::SaslLoginAbuseService<
        northstar_abuse_postgres::login::PostgresSaslLoginAbuseRepository,
    > {
        &self.sasl_login_abuse_service
    }

    /// Builds the services over the guard the other contexts share.
    pub(in crate::node) fn new(
        guard: &Arc<AbuseGuard>,
        abuse_key_deployment: Option<northstar_abuse_policy::model::AbuseKeyDeploymentIdentity>,
    ) -> Self {
        Self {
            challenge_issue_service:
                northstar_abuse_application::challenge::ChallengeIssueService::new(
                    northstar_abuse_postgres::challenge::PostgresChallengeRepository::new(
                        Arc::clone(guard),
                    ),
                ),
            challenge_cleanup_service:
                northstar_abuse_application::challenge::ChallengeCleanupService::new(
                    northstar_abuse_postgres::challenge::PostgresChallengeRepository::new(
                        Arc::clone(guard),
                    ),
                ),
            sasl_login_abuse_service:
                northstar_abuse_application::login::SaslLoginAbuseService::new(
                    northstar_abuse_postgres::login::PostgresSaslLoginAbuseRepository::new(
                        Arc::clone(guard),
                    ),
                ),
            passkey_login_abuse_service: Arc::new(
                northstar_abuse_application::login::PasskeyLoginAbuseService::new(
                    northstar_abuse_postgres::login::PostgresPasskeyLoginAbuseRepository::new(
                        Arc::clone(guard),
                    ),
                ),
            ),
            abuse_key_deployment,
        }
    }
}
