//! The auth context as the composition root builds it: the account, login and credential services
//! and the administrative services over accounts, registration, sessions and invitations.

use crate::node::*;
use northstar_auth_application::authentication::AuthenticationService;
use northstar_workflows::authentication_effects::{
    PostgresAuthenticationRepository, WorkflowAuthenticationEffects,
};

/// The auth context's services, built once at startup.
pub(in crate::node) struct AuthModule {
    pub(in crate::node) account_revocation_consumer_service:
        northstar_auth_application::account_revocation_consumer::AccountRevocationConsumerService<
            northstar_auth_postgres::account_revocation_repository::PostgresAccountRevocationRepository,
        >,
    pub(in crate::node) api_session_service: northstar_auth_application::api_sessions::ApiSessionService<
        northstar_auth_postgres::api_session_repository::PostgresApiSessionRepository,
    >,
    pub(in crate::node) passkey_service: Arc<PasskeyService>,
    pub(in crate::node) account_service: northstar_auth_application::account::AccountService<
        northstar_workflows::account_repository::WorkflowAccountRepository,
    >,
    pub(in crate::node) login_service: northstar_auth_application::http_login::HttpLoginService<
        northstar_workflows::http_login_repository::PostgresHttpLoginRepository,
    >,
    pub(in crate::node) password_change_service:
        northstar_auth_application::password_change::PasswordChangeService<
            northstar_workflows::password_change_repository::PostgresPasswordChangeRepository,
        >,
    /// Credential lookup, verification and XEP-0484 mutation authority. The
    /// protocol layer receives typed outcomes but neither PgPool nor the FAST
    /// derivation key.
    pub(in crate::node) authentication_service: AuthenticationService<PostgresAuthenticationRepository>,
    pub(in crate::node) account_admin_service: AccountAdminContext,
    pub(in crate::node) registration:
        northstar_auth_application::registration_availability::RegistrationAvailability,
    pub(in crate::node) registration_admin_service: RegistrationAdminContext,
    pub(in crate::node) session_admin_service: SessionAdminContext,
    pub(in crate::node) invitation_admin_service: InvitationAdminContext,
    /// The authenticated OMEMO recovery transfer lifecycle.
    pub(in crate::node) omemo_recovery_service:
        northstar_auth_application::omemo_recovery::OmemoRecoveryService<
            northstar_auth_postgres::omemo_recovery_repository::PostgresOmemoRecoveryRepository,
        >,
    /// The unauthenticated OMEMO recovery poll. Its repository holds a fail-closed,
    /// read-only-sized pool, so a capability flood cannot consume the primary pool.
    pub(in crate::node) omemo_recovery_poll_context: OmemoRecoveryPollContext,
}

/// What the auth context's services are built from.
pub(in crate::node) struct AuthModuleParts<'a> {
    pub(in crate::node) config: &'a Config,
    pub(in crate::node) pool: &'a PgPool,
    pub(in crate::node) command_pool: &'a PgPool,
    pub(in crate::node) abuse: &'a Arc<AbuseGuard>,
    pub(in crate::node) api_control:
        &'a Arc<northstar_operations_postgres::api_control::ApiControlKeyring>,
    pub(in crate::node) admin_mutations:
        &'a northstar_workflows::admin_mutations::AdminMutationStore,
    pub(in crate::node) cluster: &'a northstar_cluster::ClusterManager,
    pub(in crate::node) metrics: &'a Arc<Metrics>,
    pub(in crate::node) registration_closed: &'a Arc<AtomicBool>,
    pub(in crate::node) sessions: &'a Arc<DashMap<String, OnlineSession>>,
    pub(in crate::node) fast_token_secret: &'a Arc<Zeroizing<Vec<u8>>>,
    pub(in crate::node) dummy_scram_secret: Arc<Zeroizing<Vec<u8>>>,
    pub(in crate::node) dummy_scram_iteration_profiles: Vec<u32>,
    /// The poll repository over the dedicated pool the composition root connects.
    pub(in crate::node) omemo_recovery_poll_repository:
        northstar_auth_postgres::omemo_recovery_repository::PostgresOmemoRecoveryPollRepository,
}

impl AuthModule {
    pub(crate) fn omemo_recovery_service(
        &self,
    ) -> &northstar_auth_application::omemo_recovery::OmemoRecoveryService<
        northstar_auth_postgres::omemo_recovery_repository::PostgresOmemoRecoveryRepository,
    > {
        &self.omemo_recovery_service
    }

    pub(crate) fn api_session_service(
        &self,
    ) -> &northstar_auth_application::api_sessions::ApiSessionService<
        northstar_auth_postgres::api_session_repository::PostgresApiSessionRepository,
    > {
        &self.api_session_service
    }

    pub(crate) fn account_service(
        &self,
    ) -> &northstar_auth_application::account::AccountService<
        northstar_workflows::account_repository::WorkflowAccountRepository,
    > {
        &self.account_service
    }

    pub(crate) fn authentication_service(
        &self,
    ) -> &northstar_auth_application::authentication::AuthenticationService<
        northstar_workflows::authentication_effects::PostgresAuthenticationRepository,
    > {
        &self.authentication_service
    }

    /// Builds the services over the stores and policies the composition root owns.
    pub(in crate::node) fn new(parts: AuthModuleParts<'_>) -> Self {
        let AuthModuleParts {
            config,
            pool,
            command_pool,
            abuse,
            api_control,
            admin_mutations,
            cluster,
            metrics,
            registration_closed,
            sessions,
            fast_token_secret,
            dummy_scram_secret,
            dummy_scram_iteration_profiles,
            omemo_recovery_poll_repository,
        } = parts;
        let account_service = northstar_auth_application::account::AccountService::new(
            northstar_workflows::account_repository::WorkflowAccountRepository::new(
                pool.clone(),
                config.domain.clone(),
                Arc::clone(abuse),
                northstar_workflows::roster::WorkflowRosterEffects,
            )
            .with_api_control(Arc::clone(api_control)),
            config.configured_registration_mode()
                == northstar_config::RegistrationMode::InvitationOnly,
            config.registration_rate_per_hour,
            config.scram_iterations,
            config.scram_sha1_enabled,
        );
        let login_service = northstar_auth_application::http_login::HttpLoginService::new(
            northstar_workflows::http_login_repository::PostgresHttpLoginRepository::new(
                pool.clone(),
                Arc::clone(abuse),
                Arc::clone(api_control),
                northstar_auth_application::http_login::HttpLoginPolicy {
                    domain: config.domain.clone(),
                    scram_iterations: config.scram_iterations,
                    scram_sha1_enabled: config.scram_sha1_enabled,
                    session_ttl_hours: config.session_ttl_hours,
                },
                metrics.clone()
                    as Arc<dyn northstar_auth_application::http_login::LoginFailureMetrics>,
            ),
        );
        let password_change_service =
            northstar_auth_application::password_change::PasswordChangeService::new(
                northstar_workflows::password_change_repository::PostgresPasswordChangeRepository::new(
                    pool.clone(),
                    Arc::clone(api_control),
                    Arc::clone(abuse),
                ),
                config.scram_iterations,
                config.scram_sha1_enabled,
            );
        let authentication_service = AuthenticationService::new_with_dummy_scram_iteration_profiles(
            PostgresAuthenticationRepository::new(
                pool.clone(),
                Arc::clone(fast_token_secret),
                WorkflowAuthenticationEffects,
            ),
            dummy_scram_secret,
            config.scram_iterations,
            dummy_scram_iteration_profiles,
            config.scram_sha1_enabled,
        );
        let passkey_service = Arc::new(<PasskeyService>::new(
            northstar_auth_postgres::passkeys::PostgresPasskeyRepository::new(
                pool.clone(),
                fast_token_secret.clone(),
            ),
            northstar_auth_application::passkeys::PasskeyConfig {
                enabled: config.web_client_enabled && config.fast_token_enabled,
                public_url: config.public_url.clone(),
                domain: config.domain.clone(),
                scram_iterations: config.scram_iterations,
                scram_sha1_enabled: config.scram_sha1_enabled,
                fast_token_ttl_days: config.fast_token_ttl_days,
                fast_strong_reauth_max_days: config.fast_strong_reauth_max_days,
                session_ttl_hours: config.session_ttl_hours,
            },
        ));
        let account_admin_service =
            northstar_auth_application::account_admin::AccountAdminService::new(
                northstar_workflows::account_admin_repository::PostgresAccountAdminRepository::new(
                    admin_mutations.clone(),
                ),
            );
        let registration =
            northstar_auth_application::registration_availability::RegistrationAvailability::new(
                config.registration_dependency_locked(),
                Arc::clone(registration_closed),
            );
        let registration_admin_service =
            northstar_auth_application::account_admin::RegistrationAdminService::new(
                northstar_workflows::account_admin_repository::PostgresRegistrationAdminRepository::new(
                    northstar_workflows::admin_dispatch_repository::AdminCommandStore::new(
                        command_pool.clone(),
                        Arc::clone(api_control),
                        cluster.admission(),
                    ),
                    pool.clone(),
                ),
                Arc::new(registration.clone())
                    as Arc<dyn northstar_auth_application::account_admin::RegistrationCache>,
            );
        let session_admin_service =
            northstar_auth_application::account_admin::SessionAdminService::new(
                northstar_workflows::account_admin_repository::PostgresSessionAdminRepository::new(
                    admin_mutations.clone(),
                ),
                Arc::new(
                    crate::node::adapters::account_admin::LocalAdminSessions::new(Arc::clone(
                        sessions,
                    )),
                )
                    as Arc<dyn northstar_auth_application::account_admin::AdminSessionLookup>,
            );
        let invitation_admin_service =
            northstar_auth_application::invitation_admin::InvitationAdminService::new(
                northstar_workflows::invitation_admin_repository::PostgresInvitationAdminRepository::new(
                    admin_mutations.clone(),
                ),
            );
        let omemo_recovery_service =
            northstar_auth_application::omemo_recovery::OmemoRecoveryService::new(
                northstar_auth_postgres::omemo_recovery_repository::PostgresOmemoRecoveryRepository::new(
                    pool.clone(),
                ),
            );
        let omemo_recovery_poll_context = omemo_poll::OmemoRecoveryPollContext::new(
            northstar_auth_application::omemo_recovery::OmemoRecoveryPollService::new(
                omemo_recovery_poll_repository,
            ),
            config.domain.clone(),
            config.trusted_proxy_ips.clone(),
            omemo_poll::OmemoRecoveryPollCounters::from_metrics(metrics),
        );
        let account_revocation_consumer_service =
            northstar_auth_application::account_revocation_consumer::AccountRevocationConsumerService::new(
                northstar_auth_postgres::account_revocation_repository::PostgresAccountRevocationRepository::new(
                    pool.clone(),
                ),
            );
        Self {
            account_revocation_consumer_service,
            api_session_service: northstar_auth_application::api_sessions::ApiSessionService::new(
                northstar_auth_postgres::api_session_repository::PostgresApiSessionRepository::new(
                    pool.clone(),
                ),
            ),
            passkey_service,
            account_service,
            login_service,
            password_change_service,
            authentication_service,
            account_admin_service: northstar_http::contexts::ServiceContext(account_admin_service),
            registration,
            registration_admin_service: northstar_http::contexts::ServiceContext(
                registration_admin_service,
            ),
            session_admin_service: northstar_http::contexts::ServiceContext(session_admin_service),
            invitation_admin_service: northstar_http::contexts::ServiceContext(
                invitation_admin_service,
            ),
            omemo_recovery_service,
            omemo_recovery_poll_context,
        }
    }
}
