//! Repository port for MIX Participant Server (PAM) operations.

use super::{
    BeginRemotePamJoin, BeginRemotePamLeave, ClaimedPamResult, PamMembership, PamOperationReplay,
    RemotePamCompletionOutcome, RemotePamJoin,
};
use anyhow::Result;
use uuid::Uuid;

/// Persists MIX-PAM memberships, remote operations, and their delivery results.
pub trait MixPamRepository: Send + Sync {
    fn begin_remote_pam_join(
        &self,
        request: BeginRemotePamJoin,
    ) -> impl std::future::Future<Output = Result<PamOperationReplay>> + Send;
    fn lookup_remote_pam_operation(
        &self,
        user_id: Uuid,
        requester_full_jid: &str,
        client_request_id: &str,
        request_digest: &[u8; 32],
    ) -> impl std::future::Future<Output = Result<PamOperationReplay>> + Send;
    fn begin_remote_pam_leave(
        &self,
        request: BeginRemotePamLeave,
    ) -> impl std::future::Future<Output = Result<PamOperationReplay>> + Send;
    fn complete_remote_pam_success(
        &self,
        authenticated_domain: &str,
        channel_jid: &str,
        recipient_bare: &str,
        request_id: &str,
        response_digest: &[u8; 32],
        join: Option<RemotePamJoin<'_>>,
    ) -> impl std::future::Future<Output = Result<RemotePamCompletionOutcome>> + Send;
    #[allow(clippy::too_many_arguments)]
    fn complete_remote_pam_error(
        &self,
        authenticated_domain: &str,
        channel_jid: &str,
        recipient_bare: &str,
        request_id: &str,
        response_digest: &[u8; 32],
        error_type: &str,
        condition: &str,
    ) -> impl std::future::Future<Output = Result<RemotePamCompletionOutcome>> + Send;
    fn pam_memberships(
        &self,
        user_id: Uuid,
    ) -> impl std::future::Future<Output = Result<Vec<PamMembership>>> + Send;
    fn pam_membership(
        &self,
        user_id: Uuid,
        channel_jid: &str,
    ) -> impl std::future::Future<Output = Result<Option<PamMembership>>> + Send;
    fn local_pam_users_for_channel(
        &self,
        channel_jid: &str,
    ) -> impl std::future::Future<Output = Result<Vec<Uuid>>> + Send;
    fn reconcile_expired_remote_pam(
        &self,
        limit: i64,
    ) -> impl std::future::Future<Output = Result<u64>> + Send;
    fn claim_pam_results(
        &self,
        limit: i64,
    ) -> impl std::future::Future<Output = Result<Vec<ClaimedPamResult>>> + Send;
    fn renew_pam_result_lease(
        &self,
        operation_id: Uuid,
        lease_token: Uuid,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn acknowledge_pam_result(
        &self,
        operation_id: Uuid,
        lease_token: Uuid,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn defer_pam_result(
        &self,
        operation_id: Uuid,
        lease_token: Uuid,
        delay_seconds: i64,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn retry_pam_result(
        &self,
        operation_id: Uuid,
        lease_token: Uuid,
        attempt_count: i32,
        error: &str,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn prune_expired_pam_results(
        &self,
        limit: i64,
    ) -> impl std::future::Future<Output = Result<u64>> + Send;
}
