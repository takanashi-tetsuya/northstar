//! The node as the HTTP listeners see it: the REST contexts it builds per route family, and the
//! XMPP transport routes over the node itself.

use crate::node::adapters::http_contexts::{
    AccountAdminContext, AdminDispatchContext, ApiQueryContext, ApiSessionHttpContext,
    GovernanceContext, HttpChallengeEndpointContext, HttpLoginEndpointContext,
    HttpRegistrationEndpointContext, InvitationAdminContext, OmemoRecoveryHttpContext,
    OmemoRecoveryPollContext, OperationAdminContext, PasskeyAccountHttpContext,
    PasskeyLoginFinishContext, PasskeyStartHttpContext, PasswordChangeHttpContext,
    ReadinessContext, RegistrationAdminContext, ReportContext, ReportModerationContext,
    RetentionPolicyContext, SessionAdminContext, UploadAdminContext, UploadHttpDeleteContext,
    UploadHttpReadContext, UploadHttpWriteContext,
};
use crate::node::adapters::http_repositories::PostgresHttpRepositories;
use crate::node::ServerNode;
use axum::routing::{get, options, post};
use axum::Router;
use northstar_http::contexts::{
    account_teardown::{AccountGenerationTeardownContext, AccountTeardownContext},
    http_login_endpoint::HttpLoginEndpointCounters,
    reports, AdminGatewayVerifier, HttpTransportPolicy, PublicDiscoveryContext,
    UploadHttpReplayReadContext,
};
use northstar_http::host::HttpHost;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

impl HttpHost for ServerNode {
    type Repositories = PostgresHttpRepositories;

    fn public_http_bind_address(&self) -> SocketAddr {
        ServerNode::public_http_bind_address(self)
    }

    fn admin_http_bind_address(&self) -> SocketAddr {
        ServerNode::admin_http_bind_address(self)
    }

    fn admin_gateway_authentication_enabled(&self) -> bool {
        ServerNode::admin_gateway_authentication_enabled(self)
    }

    fn admin_gateway_verifier(&self) -> AdminGatewayVerifier {
        ServerNode::admin_gateway_verifier(self)
    }

    fn http_transport_policy(&self) -> HttpTransportPolicy {
        ServerNode::http_transport_policy(self)
    }

    fn public_discovery_context(&self) -> &PublicDiscoveryContext {
        self.http.discovery()
    }

    fn readiness_context(&self) -> ReadinessContext {
        ServerNode::readiness_context(self)
    }

    fn api_query_context(&self) -> ApiQueryContext {
        self.operations.api_query_context()
    }

    fn account_admin_context(&self) -> AccountAdminContext {
        self.auth.account_admin_service.clone()
    }

    fn registration_admin_context(&self) -> RegistrationAdminContext {
        self.auth.registration_admin_service.clone()
    }

    fn session_admin_context(&self) -> SessionAdminContext {
        self.auth.session_admin_service.clone()
    }

    fn admin_dispatch_context(&self) -> AdminDispatchContext {
        self.operations.admin_dispatch_service.clone()
    }

    fn invitation_admin_context(&self) -> InvitationAdminContext {
        self.auth.invitation_admin_service.clone()
    }

    fn governance_context(&self) -> GovernanceContext {
        self.operations.governance_context.clone()
    }

    fn retention_policy_context(&self) -> RetentionPolicyContext {
        self.operations.retention_policy_context.clone()
    }

    fn report_moderation_context(&self) -> ReportModerationContext {
        self.operations.report_moderation_service.clone()
    }

    fn upload_admin_context(&self) -> UploadAdminContext {
        self.operations.upload_admin_service.clone()
    }

    fn operation_admin_context(&self) -> OperationAdminContext {
        self.operations.operation_admin_service.clone()
    }

    fn report_context(&self) -> ReportContext {
        reports::ReportContext::new(
            self.operations.report_service().clone(),
            self.operations.api_query_service().clone(),
            Arc::clone(&self.metrics),
            self.config.trusted_proxy_ips.clone(),
        )
    }

    fn api_session_http_context(&self) -> ApiSessionHttpContext {
        ApiSessionHttpContext {
            service: Arc::new(self.auth.api_session_service().clone()),
        }
    }

    fn http_challenge_endpoint_context(&self) -> HttpChallengeEndpointContext {
        HttpChallengeEndpointContext {
            service: self.abuse.challenge_issue_service.clone(),
            trusted_proxies: self.config.trusted_proxy_ips.clone(),
            requested: Arc::clone(&self.metrics.anti_abuse_challenges_total),
            rate_limited: Arc::clone(&self.metrics.rate_limited_total),
        }
    }

    fn http_registration_endpoint_context(&self) -> HttpRegistrationEndpointContext {
        HttpRegistrationEndpointContext {
            service: self.auth.account_service.clone(),
            availability: self.http_registration_availability(),
            trusted_proxies: self.config.trusted_proxy_ips.clone(),
            registrations: Arc::clone(&self.metrics.registrations_total),
            rate_limited: Arc::clone(&self.metrics.rate_limited_total),
            capacity_rejected: Arc::clone(&self.metrics.capacity_reservations_rejected_total),
        }
    }

    fn http_login_endpoint_context(&self) -> HttpLoginEndpointContext {
        HttpLoginEndpointContext {
            service: self.auth.login_service.clone(),
            trusted_proxies: self.config.trusted_proxy_ips.clone(),
            counters: HttpLoginEndpointCounters {
                rate_limited: Arc::clone(&self.metrics.rate_limited_total),
                backend_failures: Arc::clone(&self.metrics.authentication_backend_failures_total),
            },
        }
    }

    fn omemo_recovery_http_context(&self) -> OmemoRecoveryHttpContext {
        OmemoRecoveryHttpContext {
            queries: self.operations.api_query_service().clone(),
            recovery: self.auth.omemo_recovery_service().clone(),
            domain: self.http.discovery().policy().domain.clone(),
            metrics: Arc::clone(&self.metrics),
        }
    }

    fn omemo_recovery_poll_context(&self) -> OmemoRecoveryPollContext {
        self.auth.omemo_recovery_poll_context.clone()
    }

    fn password_change_http_context(&self) -> PasswordChangeHttpContext {
        PasswordChangeHttpContext {
            service: self.auth.password_change_service.clone(),
            trusted_proxies: self.config.trusted_proxy_ips.clone(),
            domain: self.config.domain.clone(),
            rate_limited: Arc::clone(&self.metrics.rate_limited_total),
            backend_failures: Arc::clone(&self.metrics.authentication_backend_failures_total),
        }
    }

    fn passkey_account_http_context(&self) -> PasskeyAccountHttpContext {
        PasskeyAccountHttpContext {
            service: Arc::clone(&self.auth.passkey_service),
        }
    }

    fn passkey_start_http_context(&self) -> PasskeyStartHttpContext {
        PasskeyStartHttpContext {
            service: Arc::clone(&self.auth.passkey_service),
            abuse: Arc::clone(&self.abuse.passkey_login_abuse_service),
            trusted_proxies: self
                .http_transport_policy()
                .trusted_proxies()
                .to_vec()
                .into(),
        }
    }

    fn passkey_login_finish_context(&self) -> PasskeyLoginFinishContext {
        PasskeyLoginFinishContext::new(Arc::clone(&self.auth.passkey_service))
    }

    fn account_teardown_context(&self) -> AccountTeardownContext {
        AccountTeardownContext::new(Arc::new(self.account_teardown_runtime()))
    }

    fn account_generation_teardown_context(&self) -> AccountGenerationTeardownContext {
        AccountGenerationTeardownContext::new(Arc::new(self.account_generation_teardown_sequence()))
    }

    fn upload_http_read_context(&self) -> UploadHttpReadContext {
        UploadHttpReadContext {
            service: self.upload.service.clone(),
            // ServerNode stores only GuardedUploadStore implementations here.
            guarded_store: self.upload.store.as_ref().map(Arc::clone),
            admission: self.upload.runtime.download_admission().cloned(),
            trusted_proxies: self.config.trusted_proxy_ips.clone().into(),
            operation_duration: Arc::clone(&self.metrics.upload_operation_duration_seconds),
            read_timeout: Duration::from_secs(self.config.upload_download_read_timeout_seconds),
            max_duration: Duration::from_secs(self.config.upload_download_max_seconds),
        }
    }

    fn upload_http_replay_read_context(&self) -> UploadHttpReplayReadContext {
        UploadHttpReplayReadContext {
            // ServerNode stores only GuardedUploadStore implementations here.
            guarded_store: self.upload.store.as_ref().map(Arc::clone),
            read_timeout: Duration::from_secs(self.config.upload_download_read_timeout_seconds),
            max_duration: Duration::from_secs(self.config.upload_download_max_seconds),
        }
    }

    fn upload_http_write_context(&self) -> UploadHttpWriteContext {
        UploadHttpWriteContext {
            service: self.upload.service.clone(),
            // ServerNode stores only GuardedUploadStore implementations here.
            guarded_store: self.upload.store.as_ref().map(Arc::clone),
            admission: self.upload.runtime.request_admission().cloned(),
            safety_gate: Arc::clone(&self.upload.safety_gate),
            trusted_proxies: self.config.trusted_proxy_ips.clone().into(),
            operation_duration: Arc::clone(&self.metrics.upload_operation_duration_seconds),
            retention_seconds: self.config.upload_retention_seconds,
        }
    }

    fn upload_http_delete_context(&self) -> UploadHttpDeleteContext {
        UploadHttpDeleteContext {
            service: self.upload.service.clone(),
            operation_duration: Arc::clone(&self.metrics.upload_operation_duration_seconds),
        }
    }
}

/// The XMPP transports the public listener serves beside REST: the WebSocket upgrade and BOSH,
/// each over the node itself.
pub(crate) fn xmpp_transport_routes(state: &Arc<ServerNode>) -> Router {
    let policy = state.http.discovery().policy();
    let mut router: Router<Arc<ServerNode>> = Router::new();
    if policy.websocket_enabled {
        router = router.route(
            "/xmpp-websocket",
            get(northstar_c2s::websocket_upgrade::websocket_upgrade::<ServerNode>),
        );
    }
    if policy.bosh_enabled {
        router = router
            .route("/http-bind", post(northstar_bosh::http_bind::<ServerNode>))
            .route("/http-bind", options(northstar_bosh::http_bind_options))
            .route("/bosh", post(northstar_bosh::http_bind::<ServerNode>))
            .route("/bosh", options(northstar_bosh::http_bind_options));
    }
    router.with_state(Arc::clone(state))
}

#[cfg(test)]
mod tests;

impl ServerNode {
    pub(crate) fn readiness_context(&self) -> ReadinessContext {
        ReadinessContext {
            connection: self.session.live().connection_actors().readiness_probe(),
            sm: self.session.sm_memory_governor.readiness_probe(),
            upload: self.upload.safety_gate.readiness_probe(),
            cluster: Arc::new(self.cluster.readiness_probe()),
            workers: self.runtime.workers().readiness_probe(),
            abuse_key_deployment: self.abuse.abuse_key_deployment.clone(),
            persistence: self.operations.readiness_service.clone(),
        }
    }

    pub(crate) fn http_transport_policy(&self) -> HttpTransportPolicy {
        HttpTransportPolicy::new(
            self.config.trusted_proxy_ips.clone(),
            Arc::clone(&self.metrics.http_insecure_requests_rejected_total),
            Arc::clone(self.http.body_admission()),
        )
    }

    pub(crate) fn admin_gateway_verifier(&self) -> AdminGatewayVerifier {
        AdminGatewayVerifier::new(self.http.web_admin_gateway_token().cloned())
    }

    pub(crate) fn http_registration_availability(
        &self,
    ) -> northstar_auth_application::account::HttpRegistrationAvailability {
        self.auth
            .registration
            .http_availability(self.config.configured_registration_is_invitation_only())
    }

    pub(crate) fn admin_gateway_authentication_enabled(&self) -> bool {
        self.http.web_admin_gateway_token().is_some()
    }

    pub(crate) fn public_http_bind_address(&self) -> std::net::SocketAddr {
        self.config.http_bind
    }

    pub(crate) fn admin_http_bind_address(&self) -> std::net::SocketAddr {
        self.config.web_admin_bind
    }
}
