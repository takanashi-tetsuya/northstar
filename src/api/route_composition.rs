//! Compose HTTP route families using narrow route-state adapters.

use super::*;

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

pub(super) fn upload_http_routes(
    state: &Arc<AppState>,
    upload_limit: usize,
    admission_enabled: bool,
) -> Router {
    if admission_enabled {
        Router::new()
            .route(
                "/api/v1/upload/{id}",
                put(upload_put)
                    .delete(upload_delete)
                    // The storage reader deliberately consumes one byte beyond
                    // the reserved size to distinguish an oversized stream from
                    // an exact upload without buffering it.
                    .layer(DefaultBodyLimit::max(upload_limit.saturating_add(1))),
            )
            .with_state(UploadEnabledRoute {
                queries: state.api_query_context(),
                write: FromRef::from_ref(state),
                replay: FromRef::from_ref(state),
                delete: FromRef::from_ref(state),
            })
    } else {
        Router::new()
            .route("/api/v1/upload/{id}", delete(upload_delete))
            .with_state(authorized_route_state::<
                crate::api::contexts::upload_http_delete::UploadHttpDeleteContext,
            >(state))
    }
}

pub(super) fn administrator_command_routes(
    state: &Arc<AppState>,
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
                .route("/api/v1/admin/users/{id}", patch(admin_update_user))
                .route(
                    "/api/v1/admin/offline_messages",
                    get(admin_offline_messages_stats).delete(admin_clear_offline_messages),
                )
                .with_state(authorized_route_state::<
                    crate::api::contexts::AccountAdminContext,
                >(state)),
        )
        .merge(
            Router::new()
                .route(
                    "/api/v1/admin/panic_disconnect",
                    post(admin_panic_disconnect),
                )
                .route("/api/v1/admin/island_mode", post(admin_toggle_island_mode))
                .route(
                    "/api/v1/admin/muc_rooms/{localpart}",
                    delete(admin_destroy_muc_room),
                )
                .route("/api/v1/admin/broadcast", post(admin_broadcast))
                .route("/api/v1/admin/tls/reload", post(admin_tls_reload))
                .with_state(authorized_route_state::<
                    crate::api::contexts::AdminDispatchContext,
                >(state)),
        )
        .merge(
            Router::new()
                .route(
                    "/api/v1/admin/registration",
                    post(admin_toggle_registration),
                )
                .with_state(authorized_route_state::<
                    crate::api::contexts::RegistrationAdminContext,
                >(state)),
        )
        .merge(
            Router::new()
                .route(
                    "/api/v1/admin/sessions/{connection_id}",
                    delete(admin_kick_session),
                )
                .with_state(authorized_route_state::<
                    crate::api::contexts::SessionAdminContext,
                >(state)),
        )
        .merge(
            Router::new()
                .route("/api/v1/admin/reports/{id}", patch(admin_update_report))
                .route("/api/v1/admin/appeals/{id}", patch(admin_update_appeal))
                .with_state(authorized_route_state::<
                    crate::api::contexts::ReportModerationContext,
                >(state)),
        )
        .merge(
            Router::new()
                .route(
                    "/api/v1/admin/operations/{id}/cancel",
                    post(cancel_operation),
                )
                .route(
                    "/api/v1/admin/operations/{id}/reconcile",
                    post(reconcile_operation),
                )
                .route(
                    "/api/v1/admin/operations/{operation_id}/targets/{target_id}/reconcile",
                    post(reconcile_target),
                )
                .with_state(authorized_route_state::<
                    crate::api::contexts::OperationAdminContext,
                >(state)),
        )
        .merge(
            Router::new()
                .route(
                    "/api/v1/admin/legal-holds",
                    get(list_legal_holds).post(create_legal_hold),
                )
                .route(
                    "/api/v1/admin/legal-holds/{id}/release",
                    post(release_legal_hold),
                )
                .route(
                    "/api/v1/admin/legal-holds/{id}/export",
                    post(export_legal_hold),
                )
                .route("/api/v1/admin/audit/export", post(export_audit))
                .with_state(authorized_route_state::<
                    crate::api::contexts::GovernanceContext,
                >(state)),
        );
    if upload_runtime_enabled {
        router = router.merge(
            Router::new()
                .route(
                    "/api/v1/admin/upload-dead-letters/{kind}/{id}/retry",
                    post(admin_retry_upload_dead_letter),
                )
                .with_state(authorized_route_state::<
                    crate::api::contexts::UploadAdminContext,
                >(state)),
        );
    }
    if invitation_enabled {
        router = router.merge(
            Router::new()
                .route(
                    "/api/v1/admin/invitations",
                    get(admin_invitations).post(admin_create_invitation),
                )
                .route(
                    "/api/v1/admin/invitations/{id}",
                    delete(admin_revoke_invitation),
                )
                .with_state(authorized_route_state::<
                    crate::api::contexts::InvitationAdminContext,
                >(state)),
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

pub(super) fn authentication_routes(state: &Arc<AppState>, registration_enabled: bool) -> Router {
    let login = Router::new()
        .route("/api/v1/login", post(login))
        .with_state(HttpLoginEndpointContext::from_ref(state));
    let logout = Router::new()
        .route("/api/v1/session", delete(logout))
        .with_state(ApiSessionHttpContext::from_ref(state));
    let mut router = login.merge(logout);
    if registration_enabled {
        router = router.merge(
            Router::new()
                .route("/api/v1/register", post(register))
                .with_state(HttpRegistrationEndpointContext::from_ref(state)),
        );
    }
    router
}

// An authenticated command needs the bearer lookup and its own use-case
// capability. Keep those two handles on that route instead of retaining the
// application state in the entire REST router.
#[derive(Clone)]
pub(super) struct AuthorizedRoute<C> {
    pub(super) queries: ApiQueryContext,
    pub(super) command: C,
}

impl<C: Clone> FromRef<AuthorizedRoute<C>> for ApiQueryContext {
    fn from_ref(state: &AuthorizedRoute<C>) -> Self {
        state.queries.clone()
    }
}

macro_rules! authorized_command_context {
    ($($context:ty),+ $(,)?) => {
        $(impl FromRef<AuthorizedRoute<$context>> for $context {
            fn from_ref(state: &AuthorizedRoute<$context>) -> Self {
                state.command.clone()
            }
        })+
    };
}

authorized_command_context!(
    crate::api::contexts::AccountAdminContext,
    crate::api::contexts::AdminDispatchContext,
    crate::api::contexts::GovernanceContext,
    crate::api::contexts::http_challenge_endpoint::HttpChallengeEndpointContext,
    crate::api::contexts::InvitationAdminContext,
    crate::api::contexts::OperationAdminContext,
    crate::api::contexts::passkey_http::PasskeyAccountHttpContext,
    crate::api::contexts::passkey_http::PasskeyStartHttpContext,
    crate::api::contexts::RegistrationAdminContext,
    crate::api::contexts::ReportContext,
    crate::api::contexts::ReportModerationContext,
    crate::api::contexts::SessionAdminContext,
    crate::api::contexts::UploadAdminContext,
    crate::api::contexts::upload_http_delete::UploadHttpDeleteContext,
);

pub(super) fn authorized_route_state<C>(state: &Arc<AppState>) -> AuthorizedRoute<C>
where
    C: FromRef<Arc<AppState>>,
{
    AuthorizedRoute {
        queries: state.api_query_context(),
        command: C::from_ref(state),
    }
}

#[derive(Clone)]
pub(super) struct RoutePair<A, B> {
    pub(super) first: A,
    pub(super) second: B,
}

macro_rules! route_pair_contexts {
    ($first:ty, $second:ty) => {
        impl FromRef<RoutePair<$first, $second>> for $first {
            fn from_ref(state: &RoutePair<$first, $second>) -> Self {
                state.first.clone()
            }
        }

        impl FromRef<RoutePair<$first, $second>> for $second {
            fn from_ref(state: &RoutePair<$first, $second>) -> Self {
                state.second.clone()
            }
        }
    };
}

route_pair_contexts!(
    crate::api::contexts::password_change_http::PasswordChangeHttpContext,
    crate::api::contexts::account_teardown::AccountTeardownContext
);
route_pair_contexts!(
    OmemoRecoveryHttpContext,
    crate::api::contexts::account_teardown::AccountGenerationTeardownContext
);

#[derive(Clone)]
pub(super) struct PasskeyRemovalRoute {
    pub(super) queries: ApiQueryContext,
    pub(super) account: crate::api::contexts::passkey_http::PasskeyAccountHttpContext,
    pub(super) start: PasskeyStartHttpContext,
    pub(super) teardown: crate::api::contexts::account_teardown::AccountGenerationTeardownContext,
}

impl FromRef<PasskeyRemovalRoute> for ApiQueryContext {
    fn from_ref(state: &PasskeyRemovalRoute) -> Self {
        state.queries.clone()
    }
}

impl FromRef<PasskeyRemovalRoute>
    for crate::api::contexts::passkey_http::PasskeyAccountHttpContext
{
    fn from_ref(state: &PasskeyRemovalRoute) -> Self {
        state.account.clone()
    }
}

impl FromRef<PasskeyRemovalRoute> for PasskeyStartHttpContext {
    fn from_ref(state: &PasskeyRemovalRoute) -> Self {
        state.start.clone()
    }
}

impl FromRef<PasskeyRemovalRoute>
    for crate::api::contexts::account_teardown::AccountGenerationTeardownContext
{
    fn from_ref(state: &PasskeyRemovalRoute) -> Self {
        state.teardown.clone()
    }
}

#[derive(Clone)]
pub(super) struct UploadEnabledRoute {
    pub(super) queries: ApiQueryContext,
    pub(super) write: crate::api::contexts::upload_http_write::UploadHttpWriteContext,
    pub(super) replay: crate::api::contexts::UploadHttpReplayReadContext,
    pub(super) delete: crate::api::contexts::upload_http_delete::UploadHttpDeleteContext,
}

impl FromRef<UploadEnabledRoute> for ApiQueryContext {
    fn from_ref(state: &UploadEnabledRoute) -> Self {
        state.queries.clone()
    }
}

impl FromRef<UploadEnabledRoute>
    for crate::api::contexts::upload_http_write::UploadHttpWriteContext
{
    fn from_ref(state: &UploadEnabledRoute) -> Self {
        state.write.clone()
    }
}

impl FromRef<UploadEnabledRoute> for crate::api::contexts::UploadHttpReplayReadContext {
    fn from_ref(state: &UploadEnabledRoute) -> Self {
        state.replay.clone()
    }
}

impl FromRef<UploadEnabledRoute>
    for crate::api::contexts::upload_http_delete::UploadHttpDeleteContext
{
    fn from_ref(state: &UploadEnabledRoute) -> Self {
        state.delete.clone()
    }
}

pub(super) fn public_query_routes(queries: ApiQueryContext) -> Router {
    Router::new()
        .route("/api/v1/me", get(me))
        .route("/api/v1/history", get(history))
        .with_state(queries)
}

pub(super) fn public_authorized_routes(state: &Arc<AppState>) -> Router {
    Router::new()
        .merge(
            Router::new()
                .route("/api/v1/anti-abuse/challenge", post(anti_abuse_challenge))
                .with_state(authorized_route_state::<
                    crate::api::contexts::http_challenge_endpoint::HttpChallengeEndpointContext,
                >(state)),
        )
        .merge(
            Router::new()
                .route("/api/v1/me/passkeys", get(passkeys::list))
                .route(
                    "/api/v1/me/passkeys/register/finish",
                    post(passkeys::register_finish),
                )
                .with_state(authorized_route_state::<
                    crate::api::contexts::passkey_http::PasskeyAccountHttpContext,
                >(state)),
        )
        .merge(
            Router::new()
                .route(
                    "/api/v1/me/passkeys/register/start",
                    post(passkeys::register_start),
                )
                .with_state(authorized_route_state::<PasskeyStartHttpContext>(state)),
        )
        .merge(
            Router::new()
                .route("/api/v1/reports", get(my_reports).post(create_report))
                .route("/api/v1/reports/{id}/appeals", post(create_appeal))
                .with_state(authorized_route_state::<crate::api::contexts::ReportContext>(state)),
        )
}

pub(super) fn personal_credential_routes(state: &Arc<AppState>) -> Router {
    Router::new()
        .merge(
            Router::new()
                .route("/api/v1/me/passkeys/remove", post(passkeys::remove))
                .with_state(PasskeyRemovalRoute {
                    queries: state.api_query_context(),
                    account: FromRef::from_ref(state),
                    start: FromRef::from_ref(state),
                    teardown: FromRef::from_ref(state),
                }),
        )
        .merge(
            Router::new()
                .route("/api/v1/me/password", patch(change_password))
                .with_state(RoutePair {
                    first: FromRef::from_ref(state),
                    second: FromRef::from_ref(state),
                }),
        )
        .merge(
            Router::new()
                .route(
                    "/api/v1/me/omemo-recovery-transfers/{id}/consume",
                    post(consume_omemo_recovery),
                )
                .with_state(RoutePair {
                    first: OmemoRecoveryHttpContext::from_ref(state),
                    second: FromRef::from_ref(state),
                }),
        )
}

pub(super) fn public_capability_routes(state: &Arc<AppState>) -> Router {
    Router::new()
        .merge(
            Router::new()
                .route("/api/v1/passkeys/login/start", post(passkeys::login_start))
                .with_state(PasskeyStartHttpContext::from_ref(state)),
        )
        .merge(
            Router::new()
                .route(
                    "/api/v1/passkeys/login/finish",
                    post(passkeys::login_finish),
                )
                .with_state(PasskeyLoginFinishContext::from_ref(state)),
        )
        .merge(
            Router::new()
                .route(
                    "/api/v1/omemo-recovery-transfers/{id}/poll",
                    post(poll_omemo_recovery),
                )
                .with_state(OmemoRecoveryPollContext::from_ref(state)),
        )
}

pub(super) fn personal_policy_routes(state: &Arc<AppState>) -> Router {
    Router::new()
        .route(
            "/api/v1/me/retention",
            get(get_my_retention).put(update_my_retention),
        )
        .route(
            "/api/v1/muc_rooms/{id}/retention",
            get(get_muc_retention).put(update_muc_retention),
        )
        .with_state(RetentionPolicyContext::from_ref(state))
}

pub(super) fn omemo_recovery_routes(state: &Arc<AppState>) -> Router {
    Router::new()
        .route(
            "/api/v1/me/omemo-recovery-transfers",
            post(prepare_omemo_recovery),
        )
        .route(
            "/api/v1/me/omemo-recovery-authority",
            get(get_omemo_recovery_authority),
        )
        .route(
            "/api/v1/me/omemo-recovery-transfers/{id}",
            get(get_omemo_recovery)
                .put(seal_omemo_recovery)
                .delete(revoke_omemo_recovery),
        )
        .with_state(OmemoRecoveryHttpContext::from_ref(state))
}

pub(super) fn public_upload_read_routes(state: &Arc<AppState>) -> Router {
    Router::new()
        .route("/uploads/{id}", get(upload_get))
        .with_state(UploadHttpReadContext::from_ref(state))
}

pub(super) fn administrator_query_routes(
    queries: ApiQueryContext,
    upload_runtime_enabled: bool,
) -> Router {
    let router = Router::new()
        .route("/api/v1/admin/stats", get(admin_stats))
        .route("/api/v1/admin/sessions", get(admin_sessions))
        .route("/api/v1/admin/muc_rooms", get(admin_muc_rooms))
        .route("/api/v1/admin/users", get(admin_users))
        .route("/api/v1/admin/reports", get(admin_reports))
        .route("/api/v1/admin/operations", get(list_operations))
        .route("/api/v1/admin/operations/{id}", get(get_operation))
        .route("/api/v1/admin/operations/{id}/targets", get(list_targets))
        .route(
            "/api/v1/admin/operations/{operation_id}/targets/{target_id}",
            get(get_target),
        );
    let router = if upload_runtime_enabled {
        router.route(
            "/api/v1/admin/upload-dead-letters",
            get(admin_upload_dead_letters),
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

pub(super) fn xmpp_transport_routes(
    state: Arc<AppState>,
    websocket_enabled: bool,
    bosh_enabled: bool,
) -> Router {
    let mut router: Router<Arc<AppState>> = Router::new();
    if websocket_enabled {
        router = router.route("/xmpp-websocket", get(websocket));
    }
    if bosh_enabled {
        router = router
            .route("/http-bind", post(crate::bosh::http_bind))
            .route("/http-bind", options(crate::bosh::http_bind_options))
            .route("/bosh", post(crate::bosh::http_bind))
            .route("/bosh", options(crate::bosh::http_bind_options));
    }
    router.with_state(state)
}
