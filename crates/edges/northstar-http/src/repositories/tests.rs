//! Route tests that drive the HTTP edge through recording fakes of every repository port.

use super::HttpRepositories;
use northstar_auth_application as auth;
use northstar_operations_application as operations;
use northstar_operations_core::api_mutations::{
    AdminMutationAdmission, ApiMutationOutcome, StoredApiResponse,
};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

#[tokio::test]
async fn history_route_follows_effective_mam_profile() {
    use crate::contexts::api_queries::{ApiQueryRuntime, StreamPresenceDirectory};
    use crate::contexts::ApiQueryContext;
    use axum::http::StatusCode;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const EXPECT_MAM: &str = "NORTHSTAR_HTTP_TEST_EXPECT_MAM";
    let Ok(expected) = std::env::var(EXPECT_MAM) else {
        // Config reads process-wide variables. Exercise each profile in an
        // isolated test process so other tests and the caller's env stay independent.
        let development = include_str!("../../../../../.env.development.example")
            .lines()
            .filter(|line| !line.starts_with('#'))
            .filter_map(|line| line.split_once('='))
            .map(|(name, value)| (name, value.trim_matches('"')));
        for (mam, rsm, expected) in [
            ("true", "true", "true"),
            ("false", "true", "false"),
            ("true", "false", "false"),
        ] {
            let child = tokio::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "repositories::tests::history_route_follows_effective_mam_profile",
                    "--nocapture",
                ])
                .env_clear()
                .envs(development.clone())
                .env("XEP_0313_ENABLED", mam)
                .env("XEP_0059_ENABLED", rsm)
                .env(EXPECT_MAM, expected)
                .output()
                .await
                .unwrap();
            assert!(
                child.status.success()
                    && String::from_utf8_lossy(&child.stdout).contains("1 passed"),
                "MAM={mam} RSM={rsm}: {} {}",
                String::from_utf8_lossy(&child.stdout),
                String::from_utf8_lossy(&child.stderr),
            );
        }
        return;
    };

    let config = northstar_config::Config::from_env().unwrap();
    let mam_enabled = config.server_disco_features().contains(&"urn:xmpp:mam:2");
    assert_eq!(mam_enabled, expected.parse::<bool>().unwrap());
    let queries = ApiQueryContext::<Repositories>::new(
        operations::api_queries::ApiQueryService::new(Unused),
        Arc::new(crate::cursor::CursorKeyring::new(&[1; 32], None).unwrap()),
        ApiQueryRuntime {
            domain: config.domain.clone(),
            node_id: "test".into(),
            require_encrypted_archive: config.require_encrypted_archive,
            federation_configured: false,
            configured_registration_mode: northstar_config::RegistrationMode::Closed,
            registration_dependency_locked: false,
            registration_closed: Arc::default(),
            island_mode: Arc::default(),
            presence: Arc::new(StreamPresenceDirectory::new(Arc::default(), Arc::default())),
            metrics: Arc::default(),
            started_at: std::time::Instant::now(),
        },
    );
    let router =
        crate::route_composition::public_query_routes::<Repositories>(queries, mam_enabled);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let result = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let history_status = if mam_enabled {
            StatusCode::UNAUTHORIZED
        } else {
            StatusCode::NOT_FOUND
        };
        for (path, status) in [
            ("/api/v1/history", history_status),
            ("/api/v1/me", StatusCode::UNAUTHORIZED),
        ] {
            let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
            let request =
                format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
            stream.write_all(request.as_bytes()).await.unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).await.unwrap();
            assert!(
                response.starts_with(&format!("HTTP/1.1 {} ", status.as_u16())),
                "{response}"
            );
        }
    })
    .await;
    server.abort();
    result.unwrap();
}

type Mutation = anyhow::Result<ApiMutationOutcome<StoredApiResponse>>;

// Unrelated ports must fail loudly if a scoped handler starts using them.
#[derive(Clone)]
struct Unused;

macro_rules! unused_methods {
    ($(async fn $name:ident(&self $(, $arg:ident: $ty:ty)*) -> $result:ty;)*) => {
        $(async fn $name(&self $(, $arg: $ty)*) -> $result {
            $(let _ = $arg;)*
            panic!("unused repository method: {}", stringify!($name))
        })*
    };
}

#[derive(Clone)]
struct Repositories;

impl HttpRepositories for Repositories {
    type Accounts = Accounts;
    type AccountAdmin = Unused;
    type AdminDispatch = Unused;
    type ApiQueries = Unused;
    type ApiSessions =
        northstar_auth_postgres::api_session_repository::PostgresApiSessionRepository;
    type Challenges = Unused;
    type Governance = Unused;
    type HttpLogin = Unused;
    type InvitationAdmin = Unused;
    type MetricsSnapshot = Unused;
    type OmemoRecovery =
        northstar_auth_postgres::omemo_recovery_repository::PostgresOmemoRecoveryRepository;
    type OmemoRecoveryPoll = PollRepository;
    type OperationAdmin = Unused;
    type PasskeyLogins = Unused;
    type Passkeys = Passkeys;
    type PasswordChange = Unused;
    type Readiness = Unused;
    type RegistrationAdmin = Unused;
    type ReportModeration = Unused;
    type Reports = Unused;
    type RetentionPolicy = Unused;
    type SessionAdmin = Unused;
    type UploadAdmin = Unused;
    type Uploads = Uploads;
}

impl auth::account_admin::AccountAdminRepository for Unused {
    unused_methods! {
        async fn update_user(&self, admission: AdminMutationAdmission<'_>, user_id: Uuid, patch: auth::account_admin::UserStatusPatch) -> Mutation;
        async fn clear_offline_messages(&self, admission: AdminMutationAdmission<'_>) -> Mutation;
    }
}

impl auth::account_admin::RegistrationAdminRepository for Unused {
    unused_methods! {
        async fn set_registration(&self, admission: AdminMutationAdmission<'_>, enabled: bool) -> Mutation;
        async fn current_registration_closed(&self) -> anyhow::Result<bool>;
    }
}

impl auth::account_admin::SessionAdminRepository for Unused {
    async fn kick_session<L: auth::account_admin::AdminSessionLookup>(
        &self,
        _: AdminMutationAdmission<'_>,
        _: Uuid,
        _: &L,
    ) -> Mutation {
        panic!("unused session administration")
    }
}

impl operations::admin_dispatch::AdminDispatchRepository for Unused {
    unused_methods! {
        async fn reload_tls(&self, admission: AdminMutationAdmission<'_>) -> Mutation;
        async fn panic_disconnect(&self, admission: AdminMutationAdmission<'_>) -> Mutation;
        async fn set_island_mode(&self, admission: AdminMutationAdmission<'_>, enabled: bool) -> Mutation;
        async fn destroy_room(&self, admission: AdminMutationAdmission<'_>, room: &operations::admin_dispatch::RoomDestructionTarget) -> Mutation;
        async fn broadcast(&self, admission: AdminMutationAdmission<'_>, message: &str) -> Mutation;
    }
}

impl auth::http_login::HttpLoginRepository for Unused {
    unused_methods! {
        async fn login(&self, request: auth::http_login::HttpLoginRequest<'_>) -> anyhow::Result<auth::http_login::HttpLoginOutcome>;
        async fn record_invalid_login(&self, actors: &[String]) -> anyhow::Result<()>;
    }
}

impl auth::invitation_admin::InvitationAdminRepository for Unused {
    unused_methods! {
        async fn create(&self, command: auth::invitation_admin::CreateInvitationCommand<'_>) -> Mutation;
        async fn revoke(&self, admission: AdminMutationAdmission<'_>, id: Uuid) -> Mutation;
    }
}

impl auth::password_change::PasswordChangeRepository for Unused {
    unused_methods! {
        async fn execute(&self, command: auth::password_change::PasswordChangeCommand<'_>, policy: auth::password_change::PasswordChangePolicy, invalid_input: bool) -> anyhow::Result<auth::password_change::PasswordChangeResult>;
    }
}

impl northstar_abuse_application::challenge::ChallengeIssueRepository for Unused {
    unused_methods! {
        async fn issue(&self, request: northstar_abuse_application::challenge::ChallengeIssueRequest<'_>) -> anyhow::Result<northstar_abuse_policy::PowChallenge>;
    }
}

impl northstar_abuse_application::login::PasskeyLoginAbuseRepository for Unused {
    unused_methods! {
        async fn verify(&self, subject: &str, actors: &[String], proof: Option<&northstar_abuse_policy::PowProof>, intent: &northstar_abuse_policy::PowIntent) -> anyhow::Result<Result<northstar_abuse_policy::WorkRequirement, northstar_abuse_policy::GuardError>>;
    }
}

impl operations::metrics_snapshot::MetricsSnapshotRepository for Unused {
    unused_methods! {
        async fn ping(&self) -> anyhow::Result<()>;
        async fn collect(&self, domains: &[String]) -> anyhow::Result<operations::metrics_snapshot::DatabaseMetricsSnapshot>;
    }
    fn pool_status(&self) -> operations::metrics_snapshot::DatabasePoolStatus {
        panic!("unused metrics snapshot")
    }
}

impl operations::readiness::ReadinessRepository for Unused {
    unused_methods! {
        async fn validate_abuse_key(&self, identity: &northstar_abuse_policy::model::AbuseKeyDeploymentIdentity) -> anyhow::Result<()>;
        async fn validate_cluster_key(&self, identity: &northstar_security::cluster_keys::ClusterKeyDeploymentIdentity) -> anyhow::Result<()>;
        async fn validate_cluster_instance(&self, authority: &northstar_security::cluster_keys::ClusterReadinessAuthority) -> anyhow::Result<()>;
        async fn admin_session_cleanup_snapshot(&self) -> anyhow::Result<operations::admin_session_cleanup_worker::AdminSessionCleanupSnapshot>;
    }
}

impl operations::operations::OperationAdminRepository for Unused {
    unused_methods! {
        async fn cancel(&self, admission: AdminMutationAdmission<'_>, id: Uuid) -> Mutation;
        async fn reconcile(&self, admission: AdminMutationAdmission<'_>, id: Uuid, input: operations::operations::ReconciliationInput<'_>) -> Mutation;
        async fn reconcile_target(&self, admission: AdminMutationAdmission<'_>, operation_id: Uuid, target_id: Uuid, input: operations::operations::ReconciliationInput<'_>) -> Mutation;
    }
}

impl operations::report_moderation::ReportModerationRepository for Unused {
    unused_methods! {
        async fn update_report(&self, command: operations::report_moderation::ModerationCommand<'_>) -> Mutation;
        async fn update_appeal(&self, command: operations::report_moderation::ModerationCommand<'_>) -> Mutation;
    }
}

impl operations::reports::ReportRepository for Unused {
    unused_methods! {
        async fn create_report(&self, command: operations::reports::ReportCommand<'_>) -> anyhow::Result<ApiMutationOutcome<operations::reports::ReportCommit>>;
        async fn create_appeal(&self, command: operations::reports::AppealCommand<'_>) -> anyhow::Result<ApiMutationOutcome<operations::reports::ReportCommit>>;
    }
}

impl operations::upload_admin::UploadAdminRepository for Unused {
    unused_methods! {
        async fn retry_dead_letter(&self, admission: AdminMutationAdmission<'_>, id: operations::api_queries::UploadDeadLetterId) -> Mutation;
    }
}

mod governance {
    use super::*;
    use operations::api_queries::ApiReadAuthority;
    use operations::governance::*;

    impl GovernanceRepository for Unused {
        unused_methods! {
            async fn list_holds(&self, actor: ApiReadAuthority<'_>, active_only: bool, limit: i64, access_key_sha256: &str) -> Result<Vec<LegalHoldSummary>, GovernanceFailure>;
            async fn create_hold(&self, command: CreateHoldCommand<'_>) -> Result<ApiMutationOutcome<StoredApiResponse>, GovernanceFailure>;
            async fn release_hold(&self, admission: AdminMutationAdmission<'_>, id: Uuid, reason: &str) -> Result<ApiMutationOutcome<StoredApiResponse>, GovernanceFailure>;
            async fn export_hold(&self, command: HoldExportCommand<'_>) -> Result<ApiMutationOutcome<StoredApiResponse>, GovernanceFailure>;
            async fn export_audit(&self, command: AuditExportCommand<'_>) -> Result<ApiMutationOutcome<StoredApiResponse>, GovernanceFailure>;
        }
    }
}

mod retention {
    use super::*;
    use operations::retention_policy::*;

    impl RetentionPolicyRepository for Unused {
        unused_methods! {
            async fn user_policy(&self, session_token: &str) -> Result<UserRetentionPolicy, RetentionPolicyError>;
            async fn muc_policy(&self, session_token: &str, room_id: Uuid) -> Result<Option<i32>, RetentionPolicyError>;
            async fn set_user_policy(&self, admission: RetentionMutationAdmission<'_>, requested: UserRetentionPolicy, limits: RetentionPolicyLimits) -> Result<ApiMutationOutcome<StoredApiResponse>, RetentionPolicyError>;
            async fn set_muc_policy(&self, admission: RetentionMutationAdmission<'_>, room_id: Uuid, requested_days: Option<i32>, global_days: i64) -> Result<ApiMutationOutcome<StoredApiResponse>, RetentionPolicyError>;
        }
    }
}

mod queries {
    use super::*;
    use northstar_time::{DateTime, Utc};
    use operations::api_queries::*;

    impl ApiQueryRepository for Unused {
        unused_methods! {
            async fn operations(&self, actor: ApiReadAuthority<'_>, status: Option<&str>, kind: Option<&str>, after: Option<OperationPageBoundary>, limit: i64) -> anyhow::Result<AuthorizedRead<OperationPage>>;
            async fn operation(&self, actor: ApiReadAuthority<'_>, id: Uuid) -> anyhow::Result<AuthorizedRead<Option<OperationRecord>>>;
            async fn operation_targets(&self, actor: ApiReadAuthority<'_>, id: Uuid, status: Option<&str>, after: Option<OperationPageBoundary>, limit: i64) -> anyhow::Result<AuthorizedRead<Option<OperationTargetPage>>>;
            async fn operation_target(&self, actor: ApiReadAuthority<'_>, operation_id: Uuid, target_id: Uuid) -> anyhow::Result<AuthorizedRead<Option<OperationTargetRecord>>>;
            async fn principal(&self, token: &str) -> anyhow::Result<Option<ApiPrincipal>>;
            async fn cursor_clock(&self) -> anyhow::Result<DateTime<Utc>>;
            async fn users(&self, actor: ApiReadAuthority<'_>, after: Option<PageBoundary>, limit: i64) -> anyhow::Result<Option<KeysetPage<UserPageRow>>>;
            async fn admin_reports(&self, actor: ApiReadAuthority<'_>, status: Option<&str>, after: Option<PageBoundary>, limit: i64) -> anyhow::Result<Option<KeysetPage<ReportPageRow>>>;
            async fn own_reports(&self, actor: ApiReadAuthority<'_>, status: Option<&str>, after: Option<PageBoundary>, limit: i64) -> anyhow::Result<Option<KeysetPage<ReportPageRow>>>;
            async fn invitations(&self, actor: ApiReadAuthority<'_>, after: Option<PageBoundary>, limit: i64) -> anyhow::Result<Option<KeysetPage<InvitationPageRow>>>;
            async fn upload_dead_letters(&self, actor: ApiReadAuthority<'_>, kind: UploadDeadLetterKind, after: Option<UploadDeadLetterBoundary>, limit: i64) -> anyhow::Result<Option<UploadDeadLetterPage>>;
            async fn history(&self, actor: ApiReadAuthority<'_>, query: &MamArchiveQuery) -> anyhow::Result<Option<TimedRead<Option<ArchivePage>>>>;
            async fn offline_statistics(&self, actor: ApiReadAuthority<'_>) -> anyhow::Result<Option<OfflineMessagesStats>>;
        }
        async fn statistics<F>(
            &self,
            _: ApiReadAuthority<'_>,
            _: F,
        ) -> anyhow::Result<Option<AdminStatistics>>
        where
            F: FnOnce() -> LiveAdminStats + Send,
        {
            panic!("unused statistics")
        }
        async fn sessions<F>(
            &self,
            _: ApiReadAuthority<'_>,
            _: F,
        ) -> anyhow::Result<Option<SessionPage>>
        where
            F: FnOnce() -> (Vec<SessionView>, Option<Uuid>) + Send,
        {
            panic!("unused sessions")
        }
        async fn muc_rooms<F>(
            &self,
            _: ApiReadAuthority<'_>,
            _: Option<PageBoundary>,
            _: i64,
            _: F,
        ) -> anyhow::Result<Option<KeysetPage<MucRoomView>>>
        where
            F: FnOnce(Vec<MucRoomPageRow>) -> Vec<MucRoomView> + Send,
        {
            panic!("unused rooms")
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
struct RegistrationCall {
    username: String,
    password: String,
    invitation: Option<String>,
    subject: String,
    actors: Vec<String>,
    request_id: Uuid,
    principal_scope: Vec<u8>,
    capacity_scope: Vec<u8>,
    method: String,
    route: String,
    key: String,
    fingerprint: [u8; 32],
    intent: northstar_abuse_policy::PowIntentView,
}

#[derive(Clone, Default)]
struct Accounts(Arc<Mutex<Vec<RegistrationCall>>>);

impl auth::account::AccountRepository for Accounts {
    async fn register_http(
        &self,
        request: auth::account::HttpRegistrationRequest<'_>,
        policy: auth::account::AccountPolicy,
    ) -> anyhow::Result<auth::account::HttpRegistrationOutcome> {
        assert_eq!(policy.registration_rate_per_hour, 12);
        assert_eq!(policy.scram_iterations, 4096);
        assert!(policy.invitation_required);
        assert!(!policy.scram_sha1_enabled);
        assert!(!request.availability.is_closed());
        assert!(request.availability.requires_invitation());
        assert!(request.proof.is_none());
        self.0.lock().unwrap().push(RegistrationCall {
            username: request.username.into(),
            password: request.password.into(),
            invitation: request.invitation_token.map(str::to_owned),
            subject: request.subject.into(),
            actors: request.actors.to_vec(),
            request_id: request.idempotency.request_id,
            principal_scope: request.idempotency.principal_scope.to_vec(),
            capacity_scope: request.idempotency.capacity_scope.to_vec(),
            method: request.idempotency.method.into(),
            route: request.idempotency.route.into(),
            key: request.idempotency.idempotency_key.into(),
            fingerprint: request.idempotency.request_fingerprint,
            intent: request.intent.view(),
        });
        Ok(auth::account::HttpRegistrationOutcome::Created(
            b"{\"created\":true}".to_vec(),
        ))
    }

    unused_methods! {
        async fn verify_registration_guard(&self, request: auth::account::RegistrationGuardRequest<'_>) -> anyhow::Result<auth::account::RegistrationGuardOutcome>;
        async fn register(&self, request: auth::account::RegistrationRequest<'_>, policy: auth::account::AccountPolicy, reservation: northstar_security::password_work::PasswordWorkReservation) -> anyhow::Result<auth::account::RegistrationOutcome>;
        async fn change_password(&self, request: auth::account::PasswordChangeRequest<'_>, policy: auth::account::AccountPolicy) -> anyhow::Result<auth::account::PasswordChangeOutcome>;
        async fn quiesce_for_deletion(&self, request: auth::account::DeletionQuiesceRequest<'_>) -> anyhow::Result<auth::account::DeletionQuiesceOutcome>;
        async fn delete_quiesced(&self, user_id: Uuid) -> anyhow::Result<Option<auth::account::RemovedAccount>>;
        async fn claim_deletion_recovery(&self, limit: i64, lease_seconds: i64) -> anyhow::Result<Vec<auth::account::DeletionRecoveryJob>>;
        async fn release_deletion_recovery(&self, job: &auth::account::DeletionRecoveryJob, error_code: &str) -> anyhow::Result<bool>;
    }
}

fn api_json<T>(value: T) -> crate::ApiJson<T> {
    crate::ApiJson {
        value,
        request_id: crate::ApiRequestId(Uuid::from_u128(17)),
        request_fingerprint: [19; 32],
        idempotency_key: "registration-fixture-key".into(),
    }
}

#[tokio::test]
async fn registration_forwards_the_typed_request_with_the_transport_source_identity() {
    use axum::{
        extract::{ConnectInfo, State},
        http::{HeaderMap, HeaderValue, StatusCode},
    };
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    for (label, peer, trusted, forwarded, expected_ip) in [
        ("direct source", "192.0.2.10", false, None, "192.0.2.10"),
        (
            "trusted proxy source",
            "192.0.2.10",
            true,
            Some("198.51.100.9"),
            "198.51.100.9",
        ),
        (
            "untrusted forwarding ignored",
            "192.0.2.10",
            false,
            Some("198.51.100.9"),
            "192.0.2.10",
        ),
    ] {
        let repository = Accounts::default();
        let registrations = Arc::new(AtomicU64::new(0));
        let denied = Arc::new(AtomicU64::new(0));
        let capacity = Arc::new(AtomicU64::new(0));
        let context =
            crate::contexts::http_registration_endpoint::HttpRegistrationEndpointContext::<
                Repositories,
            > {
                service: auth::account::AccountService::new(
                    repository.clone(),
                    true,
                    12,
                    4096,
                    false,
                ),
                availability: auth::account::HttpRegistrationAvailability::new(
                    Arc::new(AtomicBool::new(false)),
                    false,
                    true,
                ),
                trusted_proxies: if trusted {
                    vec![peer.parse().unwrap()]
                } else {
                    vec![]
                },
                registrations: registrations.clone(),
                rate_limited: denied.clone(),
                capacity_rejected: capacity.clone(),
            };
        let mut headers = HeaderMap::new();
        if let Some(forwarded) = forwarded {
            headers.insert("x-forwarded-for", HeaderValue::from_static(forwarded));
        }
        let response = crate::register::<Repositories>(
            State(context),
            ConnectInfo(format!("{peer}:4321").parse().unwrap()),
            headers,
            api_json(crate::RegistrationRequest {
                username: "alice".into(),
                password: "fixture-password-123!".into(),
                invitation_token: Some("invitation-fixture".into()),
                pow: None,
            }),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED, "{label}");
        assert_eq!(
            axum::body::to_bytes(response.into_body(), 1024)
                .await
                .unwrap()
                .as_ref(),
            b"{\"created\":true}",
            "{label}"
        );
        let scope = format!("registration:{expected_ip}");
        assert_eq!(*repository.0.lock().unwrap(), vec![RegistrationCall {
            username: "alice".into(), password: "fixture-password-123!".into(),
            invitation: Some("invitation-fixture".into()), subject: scope.clone(),
            actors: vec![format!("ip:{expected_ip}")], request_id: Uuid::from_u128(17),
            principal_scope: scope.as_bytes().to_vec(), capacity_scope: scope.into_bytes(),
            method: "POST".into(), route: "/api/v1/register".into(),
            key: "registration-fixture-key".into(), fingerprint: [19; 32],
            intent: northstar_abuse_policy::PowIntent::http_json(
                northstar_abuse_policy::AbuseAction::Registration, "/api/v1/register",
                &serde_json::json!({"username":"alice", "password":"fixture-password-123!", "invitation_token":"invitation-fixture"}),
            ).view(),
        }], "{label}");
        assert_eq!(registrations.load(Ordering::Relaxed), 1, "{label}");
        assert_eq!(denied.load(Ordering::Relaxed), 0, "{label}");
        assert_eq!(capacity.load(Ordering::Relaxed), 0, "{label}");
    }
}

type PollCall = (String, Uuid, [u8; 32]);

#[derive(Clone, Default)]
struct PollRepository {
    calls: Arc<Mutex<Vec<PollCall>>>,
    pending: bool,
    dropped: Arc<std::sync::atomic::AtomicUsize>,
}

struct PollDrop(Arc<std::sync::atomic::AtomicUsize>);
impl Drop for PollDrop {
    fn drop(&mut self) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

impl auth::omemo_recovery::OmemoRecoveryPollRepository for PollRepository {
    async fn poll(
        &self,
        domain: &str,
        id: Uuid,
        secret: &[u8; 32],
    ) -> anyhow::Result<Option<auth::omemo_recovery::OmemoRecoveryPollStatus>> {
        self.calls
            .lock()
            .unwrap()
            .push((domain.into(), id, *secret));
        let _drop = PollDrop(self.dropped.clone());
        if self.pending {
            std::future::pending::<()>().await;
        }
        Ok(Some(auth::omemo_recovery::OmemoRecoveryPollStatus {
            generation: 23,
            state: "consumed".into(),
        }))
    }
}

fn poll_context(
    repository: PollRepository,
    trusted: Vec<std::net::IpAddr>,
) -> crate::contexts::OmemoRecoveryPollContext<Repositories> {
    crate::contexts::OmemoRecoveryPollContext::<Repositories>::new(
        auth::omemo_recovery::OmemoRecoveryPollService::new(repository),
        "chat.example.test".into(),
        trusted,
        crate::contexts::omemo_poll::OmemoRecoveryPollCounters::from_metrics(
            &northstar_telemetry::metrics::Metrics::default(),
        ),
    )
}

async fn poll_request(
    context: crate::contexts::OmemoRecoveryPollContext<Repositories>,
    peer: &str,
    forwarded: Option<&str>,
) -> Result<axum::response::Response, crate::error::AppError> {
    use base64::Engine;
    let mut headers = axum::http::HeaderMap::new();
    if let Some(forwarded) = forwarded {
        headers.insert("x-forwarded-for", forwarded.parse().unwrap());
    }
    crate::poll_omemo_recovery::<Repositories>(
        axum::extract::State(context),
        axum::extract::ConnectInfo(peer.parse().unwrap()),
        crate::ApiPath(Uuid::from_u128(29)),
        headers,
        api_json(crate::OmemoRecoveryPollRequest {
            poll_secret: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7; 32]),
        }),
    )
    .await
}

#[tokio::test]
async fn recovery_poll_admission_bounds_lookup_and_uses_only_trusted_source_identity() {
    use std::sync::atomic::Ordering;
    let repository = PollRepository {
        pending: true,
        ..PollRepository::default()
    };
    let context = poll_context(repository.clone(), vec![]);
    let peers = [
        "192.0.2.1:1234",
        "192.0.2.2:1234",
        "192.0.2.3:1234",
        "192.0.2.4:1234",
    ];
    let mut active = Vec::new();
    for peer in peers {
        let mut request = Box::pin(poll_request(context.clone(), peer, None));
        assert!(
            futures::poll!(&mut request).is_pending(),
            "four concurrent lookups admitted"
        );
        active.push(request);
    }
    assert_eq!(
        repository.calls.lock().unwrap().len(),
        4,
        "four concurrent lookups admitted"
    );
    let mut fifth = Box::pin(poll_request(context.clone(), "192.0.2.5:1234", None));
    let std::task::Poll::Ready(rejected) = futures::poll!(&mut fifth) else {
        panic!("global limit must reject before waiting on persistence");
    };
    assert!(
        matches!(rejected, Err(crate::error::AppError::RateLimited(_))),
        "global limit before lookup"
    );
    assert_eq!(
        repository.calls.lock().unwrap().len(),
        4,
        "global limit before lookup"
    );
    drop(active.pop());
    assert_eq!(
        repository.dropped.load(Ordering::SeqCst),
        1,
        "cancellation drops repository future"
    );
    let mut replacement = Box::pin(poll_request(context.clone(), "192.0.2.5:1234", None));
    assert!(
        futures::poll!(&mut replacement).is_pending(),
        "cancellation releases permit"
    );
    assert_eq!(
        repository.calls.lock().unwrap().len(),
        5,
        "cancellation releases permit"
    );
    drop((active, replacement));
    assert_eq!(
        repository.dropped.load(Ordering::SeqCst),
        5,
        "all pending lookups canceled"
    );

    for (label, trusted, peer, other_peer) in [
        (
            "trusted proxy shares client window",
            true,
            "192.0.2.10:1234",
            "192.0.2.11:1234",
        ),
        (
            "untrusted peer cannot rotate forwarded identity",
            false,
            "192.0.2.10:1234",
            "192.0.2.10:5678",
        ),
    ] {
        let repository = PollRepository::default();
        let context = poll_context(
            repository.clone(),
            if trusted {
                vec!["192.0.2.10".parse().unwrap(), "192.0.2.11".parse().unwrap()]
            } else {
                vec![]
            },
        );
        for index in 1..=30 {
            let forwarded = if trusted {
                "198.51.100.1".to_owned()
            } else {
                format!("198.51.100.{index}")
            };
            let response = poll_request(context.clone(), peer, Some(&forwarded))
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                axum::http::StatusCode::OK,
                "{label}: thirty requests allowed"
            );
            assert_eq!(
                response.headers()["cache-control"],
                "no-store, max-age=0",
                "{label}"
            );
            let body = axum::body::to_bytes(response.into_body(), 1024)
                .await
                .unwrap();
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
                serde_json::json!({"generation":23,"state":"consumed"}),
                "{label}: repository response preserved"
            );
        }
        assert!(
            matches!(
                poll_request(context.clone(), other_peer, Some("198.51.100.1")).await,
                Err(crate::error::AppError::RateLimited(_))
            ),
            "{label}: rate admission before lookup"
        );
        assert_eq!(
            repository.calls.lock().unwrap().len(),
            30,
            "{label}: rejected request never looks up"
        );
        let (fresh_peer, fresh_forwarded) = if trusted {
            (peer, "198.51.100.2")
        } else {
            ("192.0.2.12:1234", "198.51.100.1")
        };
        assert!(
            poll_request(context, fresh_peer, Some(fresh_forwarded))
                .await
                .is_ok(),
            "{label}: independent source admitted"
        );
        assert_eq!(
            *repository.calls.lock().unwrap(),
            vec![("chat.example.test".into(), Uuid::from_u128(29), [7; 32]); 31],
            "{label}: exact capability forwarded once per admission"
        );
    }
}

#[derive(Clone, Debug, PartialEq)]
enum UploadCall {
    Claim(Uuid, Vec<u8>, i64),
    Get(String, Option<String>),
    Replay(Uuid, Vec<u8>, [u8; 32]),
    PublicFile(Uuid),
}

#[derive(Clone)]
struct Uploads {
    calls: Arc<Mutex<Vec<UploadCall>>>,
    slot: northstar_upload_application::service::UploadSlot,
    digest: [u8; 32],
}

impl northstar_upload_application::UploadRepository for Uploads {
    type Error = anyhow::Error;
    unused_methods! {
        async fn reserve_slot(&self, request: &northstar_upload_application::UploadSlotRequest<'_>, token_hash: &[u8]) -> anyhow::Result<Option<Uuid>>;
    }
}

mod upload_lifecycle {
    use super::*;
    use northstar_upload_application::{
        maintenance::{CommittedUploadIdentity, PromotedUploadProjection},
        service::*,
    };

    impl UploadLifecycleRepository for Uploads {
        async fn claim_slot(
            &self,
            id: Uuid,
            token_hash: &[u8],
            lease_seconds: i64,
        ) -> anyhow::Result<UploadClaimOutcome> {
            self.calls.lock().unwrap().push(UploadCall::Claim(
                id,
                token_hash.to_vec(),
                lease_seconds,
            ));
            Ok(UploadClaimOutcome::Replay {
                slot: self.slot.clone(),
                content_sha256: self.digest,
            })
        }

        async fn record_replay(
            &self,
            id: Uuid,
            token_hash: &[u8],
            content_sha256: &[u8; 32],
        ) -> anyhow::Result<bool> {
            self.calls.lock().unwrap().push(UploadCall::Replay(
                id,
                token_hash.to_vec(),
                *content_sha256,
            ));
            Ok(true)
        }

        async fn public_file(&self, id: Uuid) -> anyhow::Result<Option<UploadSlot>> {
            self.calls.lock().unwrap().push(UploadCall::PublicFile(id));
            Ok(Some(self.slot.clone()))
        }

        unused_methods! {
            async fn renew_claim(&self, id: Uuid, claim_token: Uuid, lease_seconds: i64) -> anyhow::Result<UploadRenewOutcome>;
            async fn release_claim(&self, id: Uuid, claim_token: Uuid) -> anyhow::Result<bool>;
            async fn record_stage(&self, projection: UploadStageProjection<'_>) -> anyhow::Result<bool>;
            async fn claim_promotion(&self, id: Uuid, storage_attempt: Uuid, storage_fence: i64) -> anyhow::Result<Option<Uuid>>;
            async fn begin_promotion(&self, claim: PromotionClaim) -> anyhow::Result<bool>;
            async fn retire_promotion(&self, claim: PromotionClaim) -> anyhow::Result<bool>;
            async fn defer_promotion(&self, claim: PromotionClaim) -> anyhow::Result<bool>;
            async fn complete_promotion(&self, projection: PromotedUploadProjection<'_>) -> anyhow::Result<bool>;
            async fn attempt_committed(&self, identity: CommittedUploadIdentity<'_>) -> anyhow::Result<bool>;
            async fn delete_authorized(&self, user_id: Uuid, auth_generation: i64, session_token: &str, id: Uuid, request_id: Uuid) -> anyhow::Result<UserUploadDeleteOutcome>;
        }
    }
}

struct VersionedStore {
    calls: Arc<Mutex<Vec<UploadCall>>>,
    returned_version: &'static str,
    corrupt_bytes: bool,
    stalled_reader: Mutex<Option<StalledReader>>,
}

struct StalledReader {
    started: Option<tokio::sync::oneshot::Sender<()>>,
    dropped: Option<tokio::sync::oneshot::Sender<()>>,
}

impl tokio::io::AsyncRead for StalledReader {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        _: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if let Some(started) = self.started.take() {
            let _ = started.send(());
        }
        std::task::Poll::Pending
    }
}

impl Drop for StalledReader {
    fn drop(&mut self) {
        if let Some(dropped) = self.dropped.take() {
            let _ = dropped.send(());
        }
    }
}

mod object_store {
    use super::*;
    use northstar_upload_application::store::*;
    use tokio::io::AsyncRead;

    impl UploadStore for VersionedStore {
        fn backend(&self) -> &'static str {
            "s3"
        }

        fn get<'a>(
            &'a self,
            key: &'a str,
            version: Option<&'a str>,
        ) -> StoreFuture<'a, Option<StoredUploadReader>> {
            Box::pin(async move {
                self.calls
                    .lock()
                    .unwrap()
                    .push(UploadCall::Get(key.into(), version.map(str::to_owned)));
                // The current object at this key has different bytes. Only an exact
                // read of the version pinned in the committed slot verifies replay.
                let bytes: &[u8] = if version == Some("committed-version") && !self.corrupt_bytes {
                    b"original"
                } else {
                    b"replaced"
                };
                let reader: Box<dyn AsyncRead + Send + Unpin> =
                    match self.stalled_reader.lock().unwrap().take() {
                        Some(reader) => Box::new(reader),
                        None => Box::new(std::io::Cursor::new(bytes.to_vec())),
                    };
                Ok(Some(StoredUploadReader {
                    reader,
                    size: bytes.len() as u64,
                    object_version: Some(self.returned_version.into()),
                }))
            })
        }

        fn put<'a>(
            &'a self,
            _: &'a str,
            _: &'a str,
            _: Box<dyn AsyncRead + Send + Unpin + 'a>,
            _: u64,
        ) -> StoreFuture<'a, StagedUpload> {
            panic!("replay must not write bytes")
        }
        fn commit<'a>(
            &'a self,
            _: &'a str,
            _: &'a str,
            _: Option<&'a str>,
            _: u64,
            _: &'a [u8; 32],
        ) -> StoreFuture<'a, StoredUpload> {
            panic!("replay must not promote bytes")
        }
        fn abort<'a>(
            &'a self,
            _: &'a str,
            _: &'a str,
            _: Option<&'a str>,
        ) -> StoreFuture<'a, bool> {
            panic!("replay must not abort an object")
        }
        fn delete<'a>(&'a self, _: &'a str, _: Option<&'a str>) -> StoreFuture<'a, bool> {
            panic!("replay must not delete an object")
        }
        fn clear<'a>(&'a self) -> StoreFuture<'a, u64> {
            panic!("replay must not clear storage")
        }
    }
}

#[tokio::test]
async fn put_replay_reads_exact_object_version() {
    use axum::{
        body::Body,
        extract::{ConnectInfo, State},
        http::{HeaderMap, HeaderValue, StatusCode},
    };
    use northstar_upload_application::{
        safety::UploadSafetyGate,
        service::{UploadService, UploadSlot},
        store::GuardedUploadStore,
        UploadAuthorityGeneration,
    };
    use sha2::{Digest, Sha256};
    use std::time::Duration;

    for (label, returned_version, corrupt_bytes, expected_error) in [
        ("committed version replay", "committed-version", false, None),
        (
            "different returned version",
            "current-version",
            false,
            Some("committed upload object version is inconsistent"),
        ),
        (
            "stored digest mismatch",
            "committed-version",
            true,
            Some("stored upload content does not match its committed digest"),
        ),
    ] {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let id = Uuid::from_u128(31);
        let digest: [u8; 32] = Sha256::digest(b"original").into();
        let repository = Uploads {
            calls: calls.clone(),
            digest,
            slot: UploadSlot {
                id,
                content_type: "application/octet-stream".into(),
                size: 8,
                remaining_seconds: 300,
                storage_backend: "s3".into(),
                storage_object_key: Some("stored-object/attempt-41".into()),
                storage_object_version: Some("committed-version".into()),
            },
        };
        let gate = UploadSafetyGate::new();
        gate.establish(UploadAuthorityGeneration::new(1, 2), false);
        let store: Arc<dyn northstar_upload_application::store::UploadStore> =
            Arc::new(GuardedUploadStore::new(
                Arc::new(VersionedStore {
                    calls: calls.clone(),
                    returned_version,
                    corrupt_bytes,
                    stalled_reader: Mutex::new(None),
                }),
                gate.clone(),
            ));
        let admission = crate::contexts::upload_admission::UploadAdmission {
            semaphore: Arc::new(tokio::sync::Semaphore::new(1)),
            by_ip: Arc::new(dashmap::DashMap::new()),
            max_per_ip: 1,
        };
        let state = crate::contexts::upload_http_write::UploadHttpWriteContext::<Repositories> {
            service: Some(UploadService::new(repository, gate.clone(), 1024)),
            guarded_store: Some(store.clone()),
            admission: Some(admission.clone()),
            safety_gate: gate,
            trusted_proxies: Arc::from([]),
            operation_duration: Arc::default(),
            retention_seconds: 300,
        };
        let replay = crate::contexts::UploadHttpReplayReadContext {
            guarded_store: Some(store),
            read_timeout: Duration::from_secs(2),
            max_duration: Duration::from_secs(10),
        };
        let token = "a".repeat(64);
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
        headers.insert("content-length", HeaderValue::from_static("8"));
        let result = crate::upload_put::<Repositories>(
            State(state),
            State(replay),
            ConnectInfo("192.0.2.1:1234".parse().unwrap()),
            crate::ApiPath(id),
            headers,
            Body::from("original"),
        )
        .await;
        let token_hash = northstar_auth_core::token_hash(&token);
        let mut expected = vec![
            UploadCall::Claim(id, token_hash.to_vec(), 90),
            UploadCall::Get(
                "stored-object/attempt-41".into(),
                Some("committed-version".into()),
            ),
        ];
        if let Some(expected_error) = expected_error {
            let Err(crate::error::AppError::Internal(error)) = result else {
                panic!("{label}: expected integrity error");
            };
            assert_eq!(error.to_string(), expected_error, "{label}");
        } else {
            let response = result.unwrap();
            assert_eq!(response.status(), StatusCode::CREATED, "{label}");
            assert_eq!(
                response.headers()["idempotency-replayed"],
                "true",
                "{label}"
            );
            assert_eq!(
                response.headers()["cache-control"],
                "no-store, max-age=0",
                "{label}"
            );
            assert!(
                axum::body::to_bytes(response.into_body(), 1024)
                    .await
                    .unwrap()
                    .is_empty(),
                "{label}"
            );
            expected.push(UploadCall::Replay(id, token_hash.to_vec(), digest));
        }
        assert_eq!(
            *calls.lock().unwrap(),
            expected,
            "{label}: exact ordered effects"
        );
        assert_eq!(
            admission.semaphore.available_permits(),
            1,
            "{label}: request permit released"
        );
        assert!(
            admission.by_ip.is_empty(),
            "{label}: source permit released"
        );
    }
}

#[derive(Clone, Default)]
struct Passkeys(Arc<Mutex<Vec<Uuid>>>);

mod passkey_repository {
    use super::*;
    use auth::passkeys::*;

    impl PasskeyRepository for Passkeys {
        async fn consume(
            &self,
            id: Uuid,
            kind: &str,
            session_hash: Option<&[u8]>,
        ) -> anyhow::Result<Option<StoredChallenge>> {
            assert_eq!(kind, "login");
            assert!(session_hash.is_none());
            self.0.lock().unwrap().push(id);
            Ok(None)
        }

        unused_methods! {
            async fn account(&self, username: &str) -> anyhow::Result<Option<PasskeyAccount>>;
            async fn credentials(&self, user_id: Uuid) -> anyhow::Result<Vec<StoredCredential>>;
            async fn authorized_credentials(&self, actor: &PasskeyActor<'_>) -> anyhow::Result<Option<Vec<StoredCredential>>>;
            async fn verify_password(&self, actor: &PasskeyActor<'_>, password: &str, iterations: u32, sha1: bool) -> anyhow::Result<bool>;
            async fn challenge(&self, user: Uuid, generation: i64, kind: &str, session_hash: Option<&[u8]>, state: &serde_json::Value) -> anyhow::Result<Option<Uuid>>;
            async fn register(&self, actor: &PasskeyActor<'_>, credential_id: &[u8], credential: &serde_json::Value, label: &str) -> anyhow::Result<Option<Uuid>>;
            async fn complete_login(&self, command: PasskeyLoginCommit<'_>) -> anyhow::Result<Option<PasskeyLoginSession>>;
            async fn remove(&self, actor: &PasskeyActor<'_>, id: Uuid) -> anyhow::Result<Option<i64>>;
        }
    }
}

#[tokio::test]
async fn rejected_passkey_origin_never_consumes_the_login_challenge() {
    use axum::{
        extract::State,
        http::{HeaderMap, HeaderValue, StatusCode},
        response::IntoResponse,
        Json,
    };
    let repository = Passkeys::default();
    let context = crate::contexts::PasskeyLoginFinishContext::<Repositories>::new(Arc::new(
        auth::passkeys::PasskeyService::new(
            repository.clone(),
            auth::passkeys::PasskeyConfig {
                enabled: true,
                public_url: "https://chat.example.test".into(),
                domain: "chat.example.test".into(),
                scram_iterations: 4096,
                scram_sha1_enabled: false,
                fast_token_ttl_days: 7,
                fast_strong_reauth_max_days: 30,
                session_ttl_hours: 24,
            },
        ),
    ));
    for (label, origins, expected_status, expected_calls) in [
        ("missing origin", vec![], StatusCode::FORBIDDEN, 0),
        (
            "foreign origin",
            vec!["https://foreign.example.test"],
            StatusCode::FORBIDDEN,
            0,
        ),
        (
            "duplicate origin",
            vec!["https://chat.example.test", "https://chat.example.test"],
            StatusCode::FORBIDDEN,
            0,
        ),
        (
            "accepted origin reaches finish",
            vec!["https://chat.example.test"],
            StatusCode::UNAUTHORIZED,
            1,
        ),
    ] {
        let mut headers = HeaderMap::new();
        for origin in origins {
            headers.append("origin", HeaderValue::from_static(origin));
        }
        let body = serde_json::from_value(serde_json::json!({
            "challenge_id": Uuid::from_u128(47),
            "credential": {
                "id": "AQ", "rawId": "AQ", "type": "public-key",
                "response": { "authenticatorData": "AQ", "clientDataJSON": "AQ", "signature": "AQ", "userHandle": null },
                "extensions": {}
            }
        })).unwrap();
        let result = crate::passkeys::login_finish::<Repositories>(
            State(context.clone()),
            headers,
            Json(body),
        )
        .await;
        let Err(error) = result else {
            panic!("{label}: missing challenge must not authenticate");
        };
        assert_eq!(error.into_response().status(), expected_status, "{label}");
        assert_eq!(
            *repository.0.lock().unwrap(),
            vec![Uuid::from_u128(47); expected_calls],
            "{label}"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn download_keeps_streaming_permits_until_the_stalled_reader_deadline() {
    use axum::{
        extract::{ConnectInfo, State},
        http::{HeaderMap, StatusCode},
    };
    use northstar_upload_application::{
        safety::UploadSafetyGate,
        service::{UploadService, UploadSlot},
        store::GuardedUploadStore,
        UploadAuthorityGeneration,
    };
    use std::time::Duration;

    let id = Uuid::from_u128(53);
    let calls = Arc::new(Mutex::new(Vec::new()));
    let repository = Uploads {
        calls: calls.clone(),
        digest: [0; 32],
        slot: UploadSlot {
            id,
            content_type: "application/octet-stream".into(),
            size: 8,
            remaining_seconds: 300,
            storage_backend: "s3".into(),
            storage_object_key: Some("streaming-object".into()),
            storage_object_version: Some("committed-version".into()),
        },
    };
    let gate = UploadSafetyGate::new();
    gate.establish(UploadAuthorityGeneration::new(1, 2), false);
    let (started, read_started) = tokio::sync::oneshot::channel();
    let (dropped, reader_dropped) = tokio::sync::oneshot::channel();
    let store = GuardedUploadStore::new(
        Arc::new(VersionedStore {
            calls: calls.clone(),
            returned_version: "committed-version",
            corrupt_bytes: false,
            stalled_reader: Mutex::new(Some(StalledReader {
                started: Some(started),
                dropped: Some(dropped),
            })),
        }),
        gate.clone(),
    );
    let admission = crate::contexts::upload_admission::UploadAdmission {
        semaphore: Arc::new(tokio::sync::Semaphore::new(1)),
        by_ip: Arc::new(dashmap::DashMap::new()),
        max_per_ip: 1,
    };
    let state = crate::contexts::UploadHttpReadContext::<Repositories> {
        service: Some(UploadService::new(repository, gate, 1024)),
        guarded_store: Some(Arc::new(store)),
        admission: Some(admission.clone()),
        trusted_proxies: Arc::from([]),
        operation_duration: Arc::default(),
        read_timeout: Duration::from_secs(2),
        max_duration: Duration::from_secs(10),
    };
    let response = crate::upload_get::<Repositories>(
        State(state),
        ConnectInfo("192.0.2.1:1234".parse().unwrap()),
        crate::ApiPath(id),
        HeaderMap::new(),
    )
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["content-length"], "8");
    read_started.await.unwrap();
    assert_eq!(
        admission.semaphore.available_permits(),
        0,
        "handler return retains global permit"
    );
    assert_eq!(
        *admission
            .by_ip
            .get(&"192.0.2.1".parse::<std::net::IpAddr>().unwrap())
            .unwrap(),
        1,
        "handler return retains source permit"
    );
    assert!(
        admission
            .try_acquire_download("192.0.2.2".parse().unwrap())
            .is_none(),
        "streaming reader blocks another source"
    );
    drop(response);
    tokio::time::advance(Duration::from_millis(1999)).await;
    assert_eq!(
        admission.semaphore.available_permits(),
        0,
        "idle deadline has not expired"
    );
    tokio::time::advance(Duration::from_millis(1)).await;
    tokio::time::timeout(Duration::from_millis(1), reader_dropped)
        .await
        .expect("stalled reader outlived its idle deadline")
        .unwrap();
    assert_eq!(
        admission.semaphore.available_permits(),
        1,
        "idle deadline releases global permit"
    );
    assert!(
        admission.by_ip.is_empty(),
        "idle deadline releases source permit"
    );
    assert_eq!(
        *calls.lock().unwrap(),
        vec![
            UploadCall::PublicFile(id),
            UploadCall::Get("streaming-object".into(), Some("committed-version".into())),
        ]
    );
}
