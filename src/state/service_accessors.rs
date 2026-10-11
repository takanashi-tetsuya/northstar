//! AppState domain service accessors and dialback key derivation.

use super::*;

impl AppState {
    pub(crate) fn upload_service(&self) -> &UploadService {
        self.upload_service
            .as_ref()
            .expect("upload routes require an enabled or draining storage runtime")
    }

    pub(crate) fn api_session_service(
        &self,
    ) -> crate::services::api_sessions::ApiSessionService<
        db::api_session_repository::PostgresApiSessionRepository,
    > {
        crate::services::api_sessions::ApiSessionService::new(
            db::api_session_repository::PostgresApiSessionRepository::new(self.pool.clone()),
        )
    }

    pub(crate) fn challenge_issue_service(
        &self,
    ) -> &crate::services::challenge_issuance::ChallengeIssueService<
        db::challenge_issuance_repository::PostgresChallengeRepository,
    > {
        &self.challenge_issue_service
    }

    pub(crate) fn sasl_login_abuse_service(
        &self,
    ) -> &crate::services::login_abuse::SaslLoginAbuseService<
        db::login_abuse_repository::PostgresSaslLoginAbuseRepository,
    > {
        &self.sasl_login_abuse_service
    }

    pub(crate) fn public_discovery_context(&self) -> &PublicDiscoveryContext {
        &self.public_discovery_context
    }

    pub(crate) fn report_service(
        &self,
    ) -> &crate::services::reports::ReportService<db::report_repository::PostgresReportRepository>
    {
        &self.report_service
    }

    pub(crate) fn api_query_service(
        &self,
    ) -> &crate::services::api_queries::ApiQueryService<db::api_queries::PostgresApiQueryRepository>
    {
        self.api_query_context.api_query_service()
    }

    pub(crate) fn api_query_context(&self) -> ApiQueryContext {
        self.api_query_context.clone()
    }

    pub(crate) fn pubsub_service(
        &self,
    ) -> &crate::services::pubsub::PubSubService<db::pubsub_repository::PostgresPubSubRepository>
    {
        &self.pubsub_service
    }

    pub(crate) fn profile_service(
        &self,
    ) -> &crate::services::profile::ProfileService<db::profile::PostgresProfileRepository> {
        &self.profile_service
    }

    pub(crate) fn mix_service(
        &self,
    ) -> &crate::services::mix::MixService<db::mix_repository::PostgresMixRepository> {
        &self.mix_service
    }

    pub(crate) fn extdisco_service(&self) -> &crate::services::extdisco::ExtDiscoService {
        &self.extdisco_service
    }

    pub(crate) fn muc_service(
        &self,
    ) -> &crate::services::muc::MucService<db::room::PostgresMucRepository> {
        &self.muc_service
    }

    pub(crate) fn message_service(
        &self,
    ) -> &crate::services::messaging::MessageService<db::messaging::PostgresMessageRepository> {
        &self.message_service
    }

    pub(crate) fn message_admission_service(
        &self,
    ) -> &crate::services::message_admission::MessageAdmissionService<
        db::message_admission_repository::PostgresMessageAdmissionRepository,
    > {
        &self.message_admission_service
    }

    pub(crate) fn retraction_service(
        &self,
    ) -> &crate::services::retractions::RetractionService<
        db::retractions::PostgresRetractionRepository,
    > {
        &self.retraction_service
    }

    pub(crate) fn mam_service(
        &self,
    ) -> &crate::services::mam::MamService<db::mam::PostgresMamRepository> {
        &self.mam_service
    }

    pub(crate) fn sm_service(
        &self,
    ) -> &crate::services::sm::SmService<db::sm_repository::PostgresSmRepository> {
        &self.sm_service
    }

    pub(crate) fn blocking_service(
        &self,
    ) -> &crate::services::blocking::BlockingService<db::roster::PostgresBlockingRepository> {
        &self.blocking_service
    }

    pub(crate) fn presence_service(
        &self,
    ) -> &crate::services::presence::PresenceService<
        db::presence_repository::PostgresPresenceRepository,
    > {
        &self.presence_service
    }

    pub(crate) fn replay_service(
        &self,
    ) -> &crate::services::replay::ReplayService<db::replay_repository::PostgresReplayRepository>
    {
        &self.replay_service
    }

    pub(crate) fn roster_service(&self) -> &RosterService {
        &self.roster_service
    }

    pub(crate) fn s2s_roster_authorization_service(
        &self,
    ) -> &crate::services::s2s_roster_authorization::FederatedRosterAuthorizationService<
        db::s2s_roster_authorization_repository::PostgresFederatedRosterRepository,
    > {
        &self.s2s_roster_authorization_service
    }

    pub(crate) fn account_revocation_worker_context(
        &self,
    ) -> crate::cluster::AccountRevocationWorkerContext<
        db::account_revocation_repository::PostgresAccountRevocationRepository,
    > {
        crate::cluster::AccountRevocationWorkerContext::new(
            self.account_revocation_consumer_service.clone(),
            AccountRevocationRoutes::new(Arc::clone(&self.sessions)),
            self.cluster.account_revocation_authority(),
        )
    }

    pub(crate) fn s2s_outbox_dispatch_service(
        &self,
    ) -> &crate::services::s2s_outbox_dispatch::S2sOutboxDispatchService<
        db::s2s_outbox_dispatch_repository::PostgresS2sOutboxDispatchRepository,
    > {
        &self.s2s_outbox_dispatch_service
    }

    pub(crate) fn s2s_sm_outbox_service(
        &self,
    ) -> &crate::services::s2s_sm_outbox::SmOutboxService<
        db::s2s_sm_outbox_repository::PostgresSmOutboxRepository,
    > {
        &self.s2s_sm_outbox_service
    }

    pub(crate) fn privacy_service(
        &self,
    ) -> &crate::services::privacy::PrivacyService<db::privacy::PostgresPrivacyRepository> {
        &self.privacy_service
    }

    pub(crate) fn private_storage_service(
        &self,
    ) -> &crate::services::private_storage::PrivateStorageService<
        db::private::PostgresPrivateStorageRepository,
    > {
        &self.private_storage_service
    }

    pub(crate) fn account_service(
        &self,
    ) -> &crate::services::account::AccountService<db::account_repository::PostgresAccountRepository>
    {
        &self.account_service
    }

    pub(crate) async fn wake_committed_muc_operation(
        &self,
        operation_id: uuid::Uuid,
    ) -> anyhow::Result<()> {
        self.muc_service()
            .wake_committed_operation(&self.cluster, operation_id)
            .await
    }

    pub(crate) fn authentication_service(
        &self,
    ) -> &crate::services::authentication::AuthenticationService<
        db::authentication::PostgresAuthenticationRepository,
    > {
        &self.authentication_service
    }

    pub(crate) fn admin_command_service(
        &self,
    ) -> &crate::services::admin_commands::AdminCommandService<
        db::admin_command_repository::PostgresAdminCommandRepository,
    > {
        &self.admin_command_service
    }

    pub(crate) fn push_service(
        &self,
    ) -> &crate::services::push::PushService<db::push::PostgresPushRepository> {
        &self.push_service
    }

    pub(crate) fn derive_dialback_key(
        &self,
        receiving_domain: &str,
        originating_domain: &str,
        stream_id: &str,
    ) -> String {
        crate::s2s::dialback::key(
            self.dialback_secret.as_slice(),
            receiving_domain,
            originating_domain,
            stream_id,
        )
    }
}
