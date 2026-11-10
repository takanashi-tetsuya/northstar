//! Compose HTTP route families using narrow route-state adapters.

use super::*;
use crate::host::HttpHost;
use crate::repositories::HttpRepositories;

pub(super) fn public_rest_routes() -> Router {
    Router::new()
        // Keep the API namespace out of every static fallback. Without an
        // explicit root route, a file service can turn a missing API endpoint
        // into an HTML 200 response.
        .route("/api", get(api_root_not_found))
        .route("/api/openapi.yaml", get(openapi_document))
        .route("/api/docs", get(api_docs))
        .nest_service(
            "/api/docs/assets/5.32.14",
            ServeDir::new("third_party/swagger-ui/dist"),
        )
}

pub(super) fn upload_http_routes<H: HttpHost>(
    state: &Arc<H>,
    upload_limit: usize,
    admission_enabled: bool,
) -> Router {
    if admission_enabled {
        Router::new()
            .route(
                "/api/v1/upload/{id}",
                put(upload_put::<H::Repositories>)
                    .delete(upload_delete::<H::Repositories>)
                    // The storage reader deliberately consumes one byte beyond
                    // the reserved size to distinguish an oversized stream from
                    // an exact upload without buffering it.
                    .layer(DefaultBodyLimit::max(upload_limit.saturating_add(1))),
            )
            .with_state(UploadEnabledRoute {
                queries: state.api_query_context(),
                write: state.upload_http_write_context(),
                replay: state.upload_http_replay_read_context(),
                delete: state.upload_http_delete_context(),
            })
    } else {
        Router::new()
            .route(
                "/api/v1/upload/{id}",
                delete(upload_delete::<H::Repositories>),
            )
            .with_state(authorized_route(state, state.upload_http_delete_context()))
    }
}

pub(super) fn administrator_command_routes<H: HttpHost>(
    state: &Arc<H>,
    upload_runtime_enabled: bool,
    invitation_enabled: bool,
) -> Router {
    let mut router = Router::new()
        .route("/api", get(api_root_not_found))
        .merge(
            Router::new()
                .route("/api/v1/admin/nuke", post(admin_nuke))
                .with_state(state.api_query_context()),
        )
        .merge(
            Router::new()
                .route(
                    "/api/v1/admin/users/{id}",
                    patch(admin_update_user::<H::Repositories>),
                )
                .route(
                    "/api/v1/admin/offline_messages",
                    get(admin_offline_messages_stats::<H::Repositories>)
                        .delete(admin_clear_offline_messages::<H::Repositories>),
                )
                .with_state(authorized_route(state, state.account_admin_context())),
        )
        .merge(
            Router::new()
                .route(
                    "/api/v1/admin/panic_disconnect",
                    post(admin_panic_disconnect::<H::Repositories>),
                )
                .route(
                    "/api/v1/admin/island_mode",
                    post(admin_toggle_island_mode::<H::Repositories>),
                )
                .route(
                    "/api/v1/admin/muc_rooms/{localpart}",
                    delete(admin_destroy_muc_room::<H::Repositories>),
                )
                .route(
                    "/api/v1/admin/broadcast",
                    post(admin_broadcast::<H::Repositories>),
                )
                .route(
                    "/api/v1/admin/tls/reload",
                    post(admin_tls_reload::<H::Repositories>),
                )
                .with_state(authorized_route(state, state.admin_dispatch_context())),
        )
        .merge(
            Router::new()
                .route(
                    "/api/v1/admin/registration",
                    post(admin_toggle_registration::<H::Repositories>),
                )
                .with_state(authorized_route(state, state.registration_admin_context())),
        )
        .merge(
            Router::new()
                .route(
                    "/api/v1/admin/sessions/{connection_id}",
                    delete(admin_kick_session::<H::Repositories>),
                )
                .with_state(authorized_route(state, state.session_admin_context())),
        )
        .merge(
            Router::new()
                .route(
                    "/api/v1/admin/reports/{id}",
                    patch(admin_update_report::<H::Repositories>),
                )
                .route(
                    "/api/v1/admin/appeals/{id}",
                    patch(admin_update_appeal::<H::Repositories>),
                )
                .with_state(authorized_route(state, state.report_moderation_context())),
        )
        .merge(
            Router::new()
                .route(
                    "/api/v1/admin/operations/{id}/cancel",
                    post(cancel_operation::<H::Repositories>),
                )
                .route(
                    "/api/v1/admin/operations/{id}/reconcile",
                    post(reconcile_operation::<H::Repositories>),
                )
                .route(
                    "/api/v1/admin/operations/{operation_id}/targets/{target_id}/reconcile",
                    post(reconcile_target::<H::Repositories>),
                )
                .with_state(authorized_route(state, state.operation_admin_context())),
        )
        .merge(
            Router::new()
                .route(
                    "/api/v1/admin/legal-holds",
                    get(list_legal_holds::<H::Repositories>)
                        .post(create_legal_hold::<H::Repositories>),
                )
                .route(
                    "/api/v1/admin/legal-holds/{id}/release",
                    post(release_legal_hold::<H::Repositories>),
                )
                .route(
                    "/api/v1/admin/legal-holds/{id}/export",
                    post(export_legal_hold::<H::Repositories>),
                )
                .route(
                    "/api/v1/admin/audit/export",
                    post(export_audit::<H::Repositories>),
                )
                .with_state(authorized_route(state, state.governance_context())),
        );
    if upload_runtime_enabled {
        router = router.merge(
            Router::new()
                .route(
                    "/api/v1/admin/upload-dead-letters/{kind}/{id}/retry",
                    post(admin_retry_upload_dead_letter::<H::Repositories>),
                )
                .with_state(authorized_route(state, state.upload_admin_context())),
        );
    }
    if invitation_enabled {
        router = router.merge(
            Router::new()
                .route(
                    "/api/v1/admin/invitations",
                    get(admin_invitations::<H::Repositories>)
                        .post(admin_create_invitation::<H::Repositories>),
                )
                .route(
                    "/api/v1/admin/invitations/{id}",
                    delete(admin_revoke_invitation::<H::Repositories>),
                )
                .with_state(authorized_route(state, state.invitation_admin_context())),
        );
    }
    router
}

pub(super) fn web_client_static_routes() -> Router {
    let mut router = Router::new()
        .route_service("/", ServeFile::new("web/client.html"))
        .route_service("/client.html", ServeFile::new("web/client.html"))
        .nest_service("/crypto", ServeDir::new("web/crypto"));
    for &(route, file) in WEB_CLIENT_STATIC_FILES {
        router = router.route_service(route, ServeFile::new(file));
    }
    router
}

pub(super) fn administrator_static_routes() -> Router {
    let mut router = Router::new()
        .route_service("/", ServeFile::new("web/index.html"))
        .route_service("/index.html", ServeFile::new("web/index.html"));
    for &(route, file) in WEB_ADMIN_STATIC_FILES {
        router = router.route_service(route, ServeFile::new(file));
    }
    router
}

pub(super) fn authentication_routes<H: HttpHost>(
    state: &Arc<H>,
    registration_enabled: bool,
) -> Router {
    let login = Router::new()
        .route("/api/v1/login", post(login::<H::Repositories>))
        .with_state(state.http_login_endpoint_context());
    let logout = Router::new()
        .route("/api/v1/session", delete(logout::<H::Repositories>))
        .with_state(state.api_session_http_context());
    let mut router = login.merge(logout);
    if registration_enabled {
        router = router.merge(
            Router::new()
                .route("/api/v1/register", post(register::<H::Repositories>))
                .with_state(state.http_registration_endpoint_context()),
        );
    }
    router
}

// An authenticated command needs the bearer lookup and its own use-case
// capability. Keep those two handles on that route instead of retaining the
// application state in the entire REST router.
#[derive(Clone)]
pub(super) struct AuthorizedRoute<R: HttpRepositories, C> {
    pub(super) queries: ApiQueryContext<R>,
    pub(super) command: C,
}

impl<R: HttpRepositories, C: Clone> FromRef<AuthorizedRoute<R, C>> for ApiQueryContext<R> {
    fn from_ref(state: &AuthorizedRoute<R, C>) -> Self {
        state.queries.clone()
    }
}

impl<R: HttpRepositories, C: Send + Sync> ApiQueryRoute for AuthorizedRoute<R, C> {
    type Queries = <R as HttpRepositories>::ApiQueries;

    fn api_queries(&self) -> &ApiQueryContext<R> {
        &self.queries
    }
}

macro_rules! authorized_command_context {
    ($($context:ty),+ $(,)?) => {
        $(impl<R: HttpRepositories> FromRef<AuthorizedRoute<R, $context>> for $context {
            fn from_ref(state: &AuthorizedRoute<R, $context>) -> Self {
                state.command.clone()
            }
        })+
    };
}

authorized_command_context!(
    crate::contexts::AccountAdminContext<R>,
    crate::contexts::AdminDispatchContext<R>,
    crate::contexts::GovernanceContext<R>,
    crate::contexts::http_challenge_endpoint::HttpChallengeEndpointContext<R>,
    crate::contexts::InvitationAdminContext<R>,
    crate::contexts::OperationAdminContext<R>,
    crate::contexts::passkey_http::PasskeyAccountHttpContext<R>,
    crate::contexts::passkey_http::PasskeyStartHttpContext<R>,
    crate::contexts::RegistrationAdminContext<R>,
    crate::contexts::ReportContext<R>,
    crate::contexts::ReportModerationContext<R>,
    crate::contexts::SessionAdminContext<R>,
    crate::contexts::UploadAdminContext<R>,
    crate::contexts::upload_http_delete::UploadHttpDeleteContext<R>,
);

pub(super) fn authorized_route<H: HttpHost, C>(
    state: &Arc<H>,
    command: C,
) -> AuthorizedRoute<H::Repositories, C> {
    AuthorizedRoute {
        queries: state.api_query_context(),
        command,
    }
}

#[derive(Clone)]
pub(super) struct RoutePair<A, B> {
    pub(super) first: A,
    pub(super) second: B,
}

macro_rules! route_pair_contexts {
    ($first:ty, $second:ty) => {
        impl<R: HttpRepositories> FromRef<RoutePair<$first, $second>> for $first {
            fn from_ref(state: &RoutePair<$first, $second>) -> Self {
                state.first.clone()
            }
        }

        impl<R: HttpRepositories> FromRef<RoutePair<$first, $second>> for $second {
            fn from_ref(state: &RoutePair<$first, $second>) -> Self {
                state.second.clone()
            }
        }
    };
}

route_pair_contexts!(
    crate::contexts::password_change_http::PasswordChangeHttpContext<R>,
    crate::contexts::account_teardown::AccountTeardownContext
);
route_pair_contexts!(
    OmemoRecoveryHttpContext<R>,
    crate::contexts::account_teardown::AccountGenerationTeardownContext
);

#[derive(Clone)]
pub(super) struct PasskeyRemovalRoute<R: HttpRepositories> {
    pub(super) queries: ApiQueryContext<R>,
    pub(super) account: crate::contexts::passkey_http::PasskeyAccountHttpContext<R>,
    pub(super) start: PasskeyStartHttpContext<R>,
    pub(super) teardown: crate::contexts::account_teardown::AccountGenerationTeardownContext,
}

impl<R: HttpRepositories> FromRef<PasskeyRemovalRoute<R>> for ApiQueryContext<R> {
    fn from_ref(state: &PasskeyRemovalRoute<R>) -> Self {
        state.queries.clone()
    }
}

impl<R: HttpRepositories> FromRef<PasskeyRemovalRoute<R>>
    for crate::contexts::passkey_http::PasskeyAccountHttpContext<R>
{
    fn from_ref(state: &PasskeyRemovalRoute<R>) -> Self {
        state.account.clone()
    }
}

impl<R: HttpRepositories> FromRef<PasskeyRemovalRoute<R>> for PasskeyStartHttpContext<R> {
    fn from_ref(state: &PasskeyRemovalRoute<R>) -> Self {
        state.start.clone()
    }
}

impl<R: HttpRepositories> FromRef<PasskeyRemovalRoute<R>>
    for crate::contexts::account_teardown::AccountGenerationTeardownContext
{
    fn from_ref(state: &PasskeyRemovalRoute<R>) -> Self {
        state.teardown.clone()
    }
}

#[derive(Clone)]
pub(super) struct UploadEnabledRoute<R: HttpRepositories> {
    pub(super) queries: ApiQueryContext<R>,
    pub(super) write: crate::contexts::upload_http_write::UploadHttpWriteContext<R>,
    pub(super) replay: crate::contexts::UploadHttpReplayReadContext,
    pub(super) delete: crate::contexts::upload_http_delete::UploadHttpDeleteContext<R>,
}

impl<R: HttpRepositories> FromRef<UploadEnabledRoute<R>> for ApiQueryContext<R> {
    fn from_ref(state: &UploadEnabledRoute<R>) -> Self {
        state.queries.clone()
    }
}

impl<R: HttpRepositories> FromRef<UploadEnabledRoute<R>>
    for crate::contexts::upload_http_write::UploadHttpWriteContext<R>
{
    fn from_ref(state: &UploadEnabledRoute<R>) -> Self {
        state.write.clone()
    }
}

impl<R: HttpRepositories> FromRef<UploadEnabledRoute<R>>
    for crate::contexts::UploadHttpReplayReadContext
{
    fn from_ref(state: &UploadEnabledRoute<R>) -> Self {
        state.replay.clone()
    }
}

impl<R: HttpRepositories> FromRef<UploadEnabledRoute<R>>
    for crate::contexts::upload_http_delete::UploadHttpDeleteContext<R>
{
    fn from_ref(state: &UploadEnabledRoute<R>) -> Self {
        state.delete.clone()
    }
}

pub(super) fn public_query_routes<R: HttpRepositories>(queries: ApiQueryContext<R>) -> Router {
    Router::new()
        .route("/api/v1/me", get(me::<R>))
        .route("/api/v1/history", get(history::<R>))
        .with_state(queries)
}

pub(super) fn public_authorized_routes<H: HttpHost>(state: &Arc<H>) -> Router {
    Router::new()
        .merge(
            Router::new()
                .route(
                    "/api/v1/anti-abuse/challenge",
                    post(anti_abuse_challenge::<H::Repositories>),
                )
                .with_state(authorized_route(
                    state,
                    state.http_challenge_endpoint_context(),
                )),
        )
        .merge(
            Router::new()
                .route(
                    "/api/v1/me/passkeys",
                    get(passkeys::list::<H::Repositories>),
                )
                .route(
                    "/api/v1/me/passkeys/register/finish",
                    post(passkeys::register_finish::<H::Repositories>),
                )
                .with_state(authorized_route(
                    state,
                    state.passkey_account_http_context(),
                )),
        )
        .merge(
            Router::new()
                .route(
                    "/api/v1/me/passkeys/register/start",
                    post(passkeys::register_start::<H::Repositories>),
                )
                .with_state(authorized_route(state, state.passkey_start_http_context())),
        )
        .merge(
            Router::new()
                .route(
                    "/api/v1/reports",
                    get(my_reports::<H::Repositories>).post(create_report::<H::Repositories>),
                )
                .route(
                    "/api/v1/reports/{id}/appeals",
                    post(create_appeal::<H::Repositories>),
                )
                .with_state(authorized_route(state, state.report_context())),
        )
}

pub(super) fn personal_credential_routes<H: HttpHost>(state: &Arc<H>) -> Router {
    Router::new()
        .merge(
            Router::new()
                .route(
                    "/api/v1/me/passkeys/remove",
                    post(passkeys::remove::<H::Repositories>),
                )
                .with_state(PasskeyRemovalRoute {
                    queries: state.api_query_context(),
                    account: state.passkey_account_http_context(),
                    start: state.passkey_start_http_context(),
                    teardown: state.account_generation_teardown_context(),
                }),
        )
        .merge(
            Router::new()
                .route(
                    "/api/v1/me/password",
                    patch(change_password::<H::Repositories>),
                )
                .with_state(RoutePair {
                    first: state.password_change_http_context(),
                    second: state.account_teardown_context(),
                }),
        )
        .merge(
            Router::new()
                .route(
                    "/api/v1/me/omemo-recovery-transfers/{id}/consume",
                    post(consume_omemo_recovery::<H::Repositories>),
                )
                .with_state(RoutePair {
                    first: state.omemo_recovery_http_context(),
                    second: state.account_generation_teardown_context(),
                }),
        )
}

pub(super) fn public_capability_routes<H: HttpHost>(state: &Arc<H>) -> Router {
    Router::new()
        .merge(
            Router::new()
                .route(
                    "/api/v1/passkeys/login/start",
                    post(passkeys::login_start::<H::Repositories>),
                )
                .with_state(state.passkey_start_http_context()),
        )
        .merge(
            Router::new()
                .route(
                    "/api/v1/passkeys/login/finish",
                    post(passkeys::login_finish::<H::Repositories>),
                )
                .with_state(state.passkey_login_finish_context()),
        )
        .merge(
            Router::new()
                .route(
                    "/api/v1/omemo-recovery-transfers/{id}/poll",
                    post(poll_omemo_recovery::<H::Repositories>),
                )
                .with_state(state.omemo_recovery_poll_context()),
        )
}

pub(super) fn personal_policy_routes<H: HttpHost>(state: &Arc<H>) -> Router {
    Router::new()
        .route(
            "/api/v1/me/retention",
            get(get_my_retention::<H::Repositories>).put(update_my_retention::<H::Repositories>),
        )
        .route(
            "/api/v1/muc_rooms/{id}/retention",
            get(get_muc_retention::<H::Repositories>).put(update_muc_retention::<H::Repositories>),
        )
        .with_state(state.retention_policy_context())
}

pub(super) fn omemo_recovery_routes<H: HttpHost>(state: &Arc<H>) -> Router {
    Router::new()
        .route(
            "/api/v1/me/omemo-recovery-transfers",
            post(prepare_omemo_recovery::<H::Repositories>),
        )
        .route(
            "/api/v1/me/omemo-recovery-authority",
            get(get_omemo_recovery_authority::<H::Repositories>),
        )
        .route(
            "/api/v1/me/omemo-recovery-transfers/{id}",
            get(get_omemo_recovery::<H::Repositories>)
                .put(seal_omemo_recovery::<H::Repositories>)
                .delete(revoke_omemo_recovery::<H::Repositories>),
        )
        .with_state(state.omemo_recovery_http_context())
}

pub(super) fn public_upload_read_routes<H: HttpHost>(state: &Arc<H>) -> Router {
    Router::new()
        .route("/uploads/{id}", get(upload_get::<H::Repositories>))
        .with_state(state.upload_http_read_context())
}

pub(super) fn administrator_query_routes<R: HttpRepositories>(
    queries: ApiQueryContext<R>,
    upload_runtime_enabled: bool,
) -> Router {
    let router = Router::new()
        .route("/api/v1/admin/stats", get(admin_stats::<R>))
        .route("/api/v1/admin/sessions", get(admin_sessions::<R>))
        .route("/api/v1/admin/muc_rooms", get(admin_muc_rooms::<R>))
        .route("/api/v1/admin/users", get(admin_users::<R>))
        .route("/api/v1/admin/reports", get(admin_reports::<R>))
        .route("/api/v1/admin/operations", get(list_operations::<R>))
        .route("/api/v1/admin/operations/{id}", get(get_operation::<R>))
        .route(
            "/api/v1/admin/operations/{id}/targets",
            get(list_targets::<R>),
        )
        .route(
            "/api/v1/admin/operations/{operation_id}/targets/{target_id}",
            get(get_target::<R>),
        );
    let router = if upload_runtime_enabled {
        router.route(
            "/api/v1/admin/upload-dead-letters",
            get(admin_upload_dead_letters::<R>),
        )
    } else {
        router
    };
    router.with_state(queries)
}

pub(super) fn discovery_routes(
    context: PublicDiscoveryContext,
    config_enabled: bool,
    host_meta_xml_enabled: bool,
    host_meta_json_enabled: bool,
) -> Router {
    let mut router: Router<PublicDiscoveryContext> = Router::new();
    if config_enabled {
        router = router.route("/api/v1/config", get(public_config));
    }
    if host_meta_xml_enabled {
        router = router.route("/.well-known/host-meta", get(host_meta_xml));
    }
    if host_meta_json_enabled {
        router = router.route("/.well-known/host-meta.json", get(host_meta_json));
    }
    router.with_state(context)
}
