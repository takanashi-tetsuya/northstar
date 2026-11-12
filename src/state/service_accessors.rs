//! AppState domain service accessors and dialback key derivation.

use super::*;

impl AppState {
    pub(crate) fn cluster(&self) -> &crate::cluster::ClusterManager {
        &self.cluster
    }

    pub(crate) fn omemo_recovery_service(
        &self,
    ) -> &northstar_auth_application::omemo_recovery::OmemoRecoveryService<
        northstar_auth_postgres::omemo_recovery_repository::PostgresOmemoRecoveryRepository,
    > {
        &self.auth.omemo_recovery_service
    }
    pub(crate) fn upload_service(&self) -> &UploadService {
        self.upload
            .service
            .as_ref()
            .expect("upload routes require an enabled or draining storage runtime")
    }

    pub(crate) fn api_session_service(
        &self,
    ) -> northstar_auth_application::api_sessions::ApiSessionService<
        northstar_auth_postgres::api_session_repository::PostgresApiSessionRepository,
    > {
        northstar_auth_application::api_sessions::ApiSessionService::new(
            northstar_auth_postgres::api_session_repository::PostgresApiSessionRepository::new(
                self.pool.clone(),
            ),
        )
    }

    pub(crate) fn challenge_issue_service(
        &self,
    ) -> &northstar_abuse_application::challenge::ChallengeIssueService<
        northstar_abuse_postgres::challenge::PostgresChallengeRepository,
    > {
        &self.abuse.challenge_issue_service
    }

    pub(crate) fn sasl_login_abuse_service(
        &self,
    ) -> &northstar_abuse_application::login::SaslLoginAbuseService<
        northstar_abuse_postgres::login::PostgresSaslLoginAbuseRepository,
    > {
        &self.abuse.sasl_login_abuse_service
    }

    pub(crate) fn public_discovery_context(&self) -> &PublicDiscoveryContext {
        &self.public_discovery_context
    }

    pub(crate) fn report_service(
        &self,
    ) -> &northstar_operations_application::reports::ReportService<
        northstar_workflows::report_repository::PostgresReportRepository,
    > {
        &self.operations.report_service
    }

    pub(crate) fn api_query_service(
        &self,
    ) -> &northstar_operations_application::api_queries::ApiQueryService<
        northstar_workflows::api_queries::PostgresApiQueryRepository,
    > {
        self.operations.api_query_context.api_query_service()
    }

    pub(crate) fn api_query_context(&self) -> ApiQueryContext {
        self.operations.api_query_context.clone()
    }

    pub(crate) fn pubsub_service(
        &self,
    ) -> &northstar_pubsub_application::PubSubService<
        northstar_workflows::pubsub_repository::PostgresPubSubRepository,
    > {
        &self.pubsub.pubsub_service
    }

    pub(crate) fn profile_service(
        &self,
    ) -> &northstar_pubsub_application::profile::ProfileService<
        northstar_workflows::profile::PostgresProfileRepository,
    > {
        &self.pubsub.profile_service
    }

    pub(crate) fn mix_service(
        &self,
    ) -> &northstar_room_application::mix_service::MixService<
        northstar_workflows::room_effects::PostgresMixRepository,
    > {
        &self.room.mix_service
    }

    pub(crate) fn extdisco_service(
        &self,
    ) -> &northstar_message_application::extdisco::ExtDiscoService {
        &self.message.extdisco_service
    }

    pub(crate) fn muc_service(
        &self,
    ) -> &northstar_room_application::muc_service::MucService<
        northstar_workflows::room_effects::PostgresMucRepository,
    > {
        &self.room.muc_service
    }

    pub(crate) fn message_service(
        &self,
    ) -> &northstar_message_application::messaging::MessageService<
        northstar_workflows::message_repository::PostgresMessageRepository,
    > {
        &self.message.message_service
    }

    pub(crate) fn message_admission_service(
        &self,
    ) -> &northstar_message_application::message_admission::MessageAdmissionService<
        northstar_workflows::message_admission_port::AbuseMessageAdmissionPort,
    > {
        &self.message.message_admission_service
    }

    pub(crate) fn retraction_service(
        &self,
    ) -> &northstar_message_application::retractions::RetractionService<
        northstar_workflows::retraction_repository::PostgresRetractionRepository,
    > {
        &self.message.retraction_service
    }

    pub(crate) fn mam_service(
        &self,
    ) -> &northstar_archive_application::MamService<
        northstar_workflows::mam_repository::PostgresMamRepository,
    > {
        &self.mam_service
    }

    pub(crate) fn sm_service(
        &self,
    ) -> &northstar_session_application::sm::SmService<
        northstar_workflows::sm_repository::PostgresSmRepository,
    > {
        &self.session.sm_service
    }

    pub(crate) fn blocking_service(
        &self,
    ) -> &northstar_roster_application::blocking::BlockingService<
        northstar_roster_postgres::roster::PostgresBlockingRepository,
    > {
        &self.roster.blocking_service
    }

    pub(crate) fn presence_service(
        &self,
    ) -> &northstar_roster_application::presence::PresenceService<
        northstar_workflows::presence_repository::PostgresPresenceRepository,
    > {
        &self.roster.presence_service
    }

    pub(crate) fn replay_service(
        &self,
    ) -> &northstar_session_application::replay::ReplayService<
        northstar_session_postgres::replay_repository::PostgresReplayRepository,
    > {
        &self.session.replay_service
    }

    pub(crate) fn roster_service(&self) -> &RosterService {
        &self.roster.roster_service
    }

    pub(crate) fn s2s_roster_authorization_service(
        &self,
    ) -> &northstar_roster_application::s2s_roster_authorization::FederatedRosterAuthorizationService<
        northstar_roster_postgres::federated_roster::PostgresFederatedRosterRepository,
    >{
        &self.roster.s2s_roster_authorization_service
    }

    pub(crate) fn account_revocation_worker_context(
        &self,
    ) -> crate::cluster::AccountRevocationWorkerContext<
        northstar_auth_postgres::account_revocation_repository::PostgresAccountRevocationRepository,
    > {
        crate::cluster::AccountRevocationWorkerContext::new(
            self.account_revocation_consumer_service.clone(),
            AccountRevocationRoutes::new(Arc::clone(&self.sessions)),
            self.cluster.account_revocation_authority(),
        )
    }

    pub(crate) fn s2s_outbox_dispatch_service(
        &self,
    ) -> &northstar_federation_application::dispatch::S2sOutboxDispatchService<
        northstar_federation_postgres::dispatch_repository::PostgresS2sOutboxDispatchRepository,
    > {
        &self.federation.s2s_outbox_dispatch_service
    }

    pub(crate) fn s2s_sm_outbox_service(
        &self,
    ) -> &northstar_federation_application::sm_outbox::SmOutboxService<
        northstar_federation_postgres::sm_outbox_repository::PostgresSmOutboxRepository,
    > {
        &self.federation.s2s_sm_outbox_service
    }

    pub(crate) fn privacy_service(
        &self,
    ) -> &northstar_roster_application::privacy::PrivacyService<
        northstar_roster_postgres::privacy::PostgresPrivacyRepository,
    > {
        &self.roster.privacy_service
    }

    pub(crate) fn private_storage_service(
        &self,
    ) -> &northstar_pubsub_application::private_storage::PrivateStorageService<
        northstar_pubsub_postgres::PostgresPrivateStorageRepository,
    > {
        &self.pubsub.private_storage_service
    }

    pub(crate) fn account_service(
        &self,
    ) -> &northstar_auth_application::account::AccountService<
        northstar_workflows::account_repository::WorkflowAccountRepository,
    > {
        &self.auth.account_service
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
    ) -> &northstar_auth_application::authentication::AuthenticationService<
        northstar_workflows::authentication_effects::PostgresAuthenticationRepository,
    > {
        &self.auth.authentication_service
    }

    pub(crate) fn admin_command_service(
        &self,
    ) -> &northstar_operations_application::admin_commands::AdminCommandService<
        northstar_workflows::admin_command_repository::WorkflowAdminCommandRepository,
    > {
        &self.operations.admin_command_service
    }

    pub(crate) fn push_service(
        &self,
    ) -> &northstar_message_application::push::PushService<
        northstar_workflows::push_repository::PostgresPushRepository,
    > {
        &self.message.push_service
    }

    pub(crate) fn derive_dialback_key(
        &self,
        receiving_domain: &str,
        originating_domain: &str,
        stream_id: &str,
    ) -> String {
        northstar_federation_core::compute_dialback_key(
            self.federation.dialback_secret.as_slice(),
            receiving_domain,
            originating_domain,
            stream_id,
        )
    }
}
