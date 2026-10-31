//! The auth context as the composition root builds it: the account, login and credential services
//! and the administrative services over accounts, registration, sessions and invitations.

use super::*;
use crate::db::authentication_effects::{
    PostgresAuthenticationRepository, RootAuthenticationEffects,
};
use northstar_auth_application::authentication::AuthenticationService;

/// The auth context's services, built once at startup.
pub(super) struct AuthModule {
    pub(super) passkey_service: Arc<PasskeyService>,
    pub(super) account_service: northstar_auth_application::account::AccountService<
        db::account_repository::PostgresAccountRepository,
    >,
    pub(super) login_service: northstar_auth_application::http_login::HttpLoginService<
        db::http_login_repository::PostgresHttpLoginRepository,
    >,
    pub(super) password_change_service:
        northstar_auth_application::password_change::PasswordChangeService<
            db::password_change_repository::PostgresPasswordChangeRepository,
        >,
    /// Credential lookup, verification and XEP-0484 mutation authority. The
    /// protocol layer receives typed outcomes but neither PgPool nor the FAST
    /// derivation key.
    pub(super) authentication_service: AuthenticationService<PostgresAuthenticationRepository>,
    pub(super) account_admin_service: AccountAdminContext,
    pub(super) registration_admin_service: RegistrationAdminContext,
    pub(super) session_admin_service: SessionAdminContext,
    pub(super) invitation_admin_service: InvitationAdminContext,
}

/// What the auth context's services are built from.
pub(super) struct AuthModuleParts<'a> {
    pub(super) config: &'a Config,
    pub(super) pool: &'a PgPool,
    pub(super) command_pool: &'a PgPool,
    pub(super) abuse: &'a Arc<AbuseGuard>,
    pub(super) api_control: &'a Arc<db::ApiControlKeyring>,
    pub(super) admin_mutations: &'a db::admin_mutations::AdminMutationStore,
    pub(super) cluster: &'a crate::cluster::ClusterManager,
    pub(super) metrics: &'a Arc<Metrics>,
    pub(super) registration_closed: &'a Arc<AtomicBool>,
    pub(super) sessions: &'a Arc<DashMap<String, OnlineSession>>,
    pub(super) fast_token_secret: &'a Arc<Zeroizing<Vec<u8>>>,
    pub(super) dummy_scram_secret: Arc<Zeroizing<Vec<u8>>>,
    pub(super) dummy_scram_iteration_profiles: Vec<u32>,
}

impl AuthModule {
    /// Builds the services over the stores and policies the composition root owns.
    pub(super) fn new(parts: AuthModuleParts<'_>) -> Self {
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
        } = parts;
        let account_service = northstar_auth_application::account::AccountService::new(
            db::account_repository::PostgresAccountRepository::new(
                pool.clone(),
                config.domain.clone(),
                Arc::clone(abuse),
            )
            .with_api_control(Arc::clone(api_control)),
            config.configured_registration_mode()
                == northstar_config::RegistrationMode::InvitationOnly,
            config.registration_rate_per_hour,
            config.scram_iterations,
            config.scram_sha1_enabled,
        );
        let login_service = northstar_auth_application::http_login::HttpLoginService::new(
            db::http_login_repository::PostgresHttpLoginRepository::new(
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
                db::password_change_repository::PostgresPasswordChangeRepository::new(
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
                RootAuthenticationEffects,
            ),
            dummy_scram_secret,
            config.scram_iterations,
            dummy_scram_iteration_profiles,
            config.scram_sha1_enabled,
        );
        let passkey_service = Arc::new(PasskeyService::new(
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
                db::account_admin_repository::PostgresAccountAdminRepository::new(
                    admin_mutations.clone(),
                ),
            );
        let registration_admin_service =
            northstar_auth_application::account_admin::RegistrationAdminService::new(
                db::account_admin_repository::PostgresRegistrationAdminRepository::new(
                    db::admin_dispatch_repository::AdminCommandStore::new(
                        command_pool.clone(),
                        Arc::clone(api_control),
                        cluster.admission(),
                    ),
                    pool.clone(),
                ),
                Arc::new(account_admin::LocalRegistrationCache::new(
                    config.registration_dependency_locked(),
                    Arc::clone(registration_closed),
                ))
                    as Arc<dyn northstar_auth_application::account_admin::RegistrationCache>,
            );
        let session_admin_service =
            northstar_auth_application::account_admin::SessionAdminService::new(
                db::account_admin_repository::PostgresSessionAdminRepository::new(
                    admin_mutations.clone(),
                ),
                Arc::new(account_admin::LocalAdminSessions::new(Arc::clone(sessions)))
                    as Arc<dyn northstar_auth_application::account_admin::AdminSessionLookup>,
            );
        let invitation_admin_service =
            northstar_auth_application::invitation_admin::InvitationAdminService::new(
                db::invitation_admin_repository::PostgresInvitationAdminRepository::new(
                    admin_mutations.clone(),
                ),
            );
        Self {
            passkey_service,
            account_service,
            login_service,
            password_change_service,
            authentication_service,
            account_admin_service: crate::api::contexts::ServiceContext(account_admin_service),
            registration_admin_service: crate::api::contexts::ServiceContext(
                registration_admin_service,
            ),
            session_admin_service: crate::api::contexts::ServiceContext(session_admin_service),
            invitation_admin_service: crate::api::contexts::ServiceContext(
                invitation_admin_service,
            ),
        }
    }
}
