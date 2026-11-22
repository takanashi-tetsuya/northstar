//! PostgreSQL implementation of the MIX-PAM repository port.

use super::*;

impl<E: RoomEffects> MixPamRepository for PostgresMixRepository<E> {
    async fn begin_remote_pam_join(
        &self,
        request: BeginRemotePamJoin,
    ) -> Result<PamOperationReplay> {
        Ok(map_pam_replay(
            crate::mix::begin_remote_pam_join(
                &self.effects,
                &self.pool,
                crate::mix::BeginRemotePamJoin {
                    user_id: request.user_id,
                    actor_jid: &request.actor_jid,
                    channel_jid: &request.channel_jid,
                    nick: request.nick.as_deref(),
                    nodes: &request.nodes,
                    request_id: &request.request_id,
                    client_request_id: &request.client_request_id,
                    requester_full_jid: &request.requester_full_jid,
                    request_digest: &request.request_digest,
                    remote_domain: &request.remote_domain,
                    outbound_stanza: &request.outbound_stanza,
                    policy: northstar_federation_core::S2sOutboxPolicy {
                        ttl_seconds: request.policy.ttl_seconds,
                        max_rows: request.policy.max_rows,
                        max_bytes: request.policy.max_bytes,
                        max_per_domain: request.policy.max_per_domain,
                    },
                },
            )
            .await?,
        ))
    }
    async fn lookup_remote_pam_operation(
        &self,
        user_id: Uuid,
        requester_full_jid: &str,
        client_request_id: &str,
        request_digest: &[u8; 32],
    ) -> Result<PamOperationReplay> {
        Ok(map_pam_replay(
            crate::mix::lookup_remote_pam_operation(
                &self.pool,
                user_id,
                requester_full_jid,
                client_request_id,
                request_digest,
            )
            .await?,
        ))
    }
    async fn begin_remote_pam_leave(
        &self,
        request: BeginRemotePamLeave,
    ) -> Result<PamOperationReplay> {
        Ok(map_pam_replay(
            crate::mix::begin_remote_pam_leave(
                &self.effects,
                &self.pool,
                crate::mix::BeginRemotePamLeave {
                    user_id: request.user_id,
                    actor_jid: &request.actor_jid,
                    channel_jid: &request.channel_jid,
                    request_id: &request.request_id,
                    client_request_id: &request.client_request_id,
                    requester_full_jid: &request.requester_full_jid,
                    request_digest: &request.request_digest,
                    remote_domain: &request.remote_domain,
                    outbound_stanza: &request.outbound_stanza,
                    policy: northstar_federation_core::S2sOutboxPolicy {
                        ttl_seconds: request.policy.ttl_seconds,
                        max_rows: request.policy.max_rows,
                        max_bytes: request.policy.max_bytes,
                        max_per_domain: request.policy.max_per_domain,
                    },
                },
            )
            .await?,
        ))
    }
    async fn complete_remote_pam_success(
        &self,
        authenticated_domain: &str,
        channel_jid: &str,
        recipient_bare: &str,
        request_id: &str,
        response_digest: &[u8; 32],
        join: Option<RemotePamJoin<'_>>,
    ) -> Result<RemotePamCompletionOutcome> {
        let join = join.map(|join| crate::mix::RemotePamJoin {
            participant_id: join.participant_id,
            subscriptions: join.subscriptions,
            nick: join.nick,
        });
        Ok(map_pam_completion(
            crate::mix::complete_remote_pam_success(
                &self.effects,
                &self.pool,
                authenticated_domain,
                channel_jid,
                recipient_bare,
                request_id,
                response_digest,
                join,
                &MixPayloads,
            )
            .await?,
        ))
    }
    #[allow(clippy::too_many_arguments)]
    async fn complete_remote_pam_error(
        &self,
        authenticated_domain: &str,
        channel_jid: &str,
        recipient_bare: &str,
        request_id: &str,
        response_digest: &[u8; 32],
        error_type: &str,
        condition: &str,
    ) -> Result<RemotePamCompletionOutcome> {
        Ok(map_pam_completion(
            crate::mix::complete_remote_pam_error(
                &self.pool,
                authenticated_domain,
                channel_jid,
                recipient_bare,
                request_id,
                response_digest,
                error_type,
                condition,
                &MixPayloads,
            )
            .await?,
        ))
    }
    async fn pam_memberships(&self, user_id: Uuid) -> Result<Vec<PamMembership>> {
        Ok(crate::mix::pam_memberships(&self.pool, user_id)
            .await?
            .into_iter()
            .map(pam_membership)
            .collect())
    }
    async fn pam_membership(
        &self,
        user_id: Uuid,
        channel_jid: &str,
    ) -> Result<Option<PamMembership>> {
        Ok(crate::mix::pam_membership(&self.pool, user_id, channel_jid)
            .await?
            .map(pam_membership))
    }
    async fn local_pam_users_for_channel(&self, channel_jid: &str) -> Result<Vec<Uuid>> {
        crate::mix::local_pam_users_for_channel(&self.pool, channel_jid).await
    }
    async fn reconcile_expired_remote_pam(&self, limit: i64) -> Result<u64> {
        crate::mix::reconcile_expired_remote_pam(&self.pool, limit, &MixPayloads).await
    }
    async fn claim_pam_results(&self, limit: i64) -> Result<Vec<ClaimedPamResult>> {
        let results = {
            let results = crate::mix::claim_pam_results(&self.pool, limit).await?;
            results
        };
        Ok(results
            .into_iter()
            .map(|result| ClaimedPamResult {
                operation_id: result.operation_id,
                user_id: result.user_id,
                requester_full_jid: result.requester_full_jid,
                response_xml: result.response_xml,
                attempt_count: result.attempt_count,
                lease_token: result.lease_token,
            })
            .collect())
    }
    async fn renew_pam_result_lease(&self, operation_id: Uuid, lease_token: Uuid) -> Result<bool> {
        crate::mix::renew_pam_result_lease(&self.pool, operation_id, lease_token).await
    }
    async fn acknowledge_pam_result(&self, operation_id: Uuid, lease_token: Uuid) -> Result<bool> {
        crate::mix::acknowledge_pam_result(&self.pool, operation_id, lease_token).await
    }
    async fn defer_pam_result(
        &self,
        operation_id: Uuid,
        lease_token: Uuid,
        delay_seconds: i64,
    ) -> Result<bool> {
        crate::mix::defer_pam_result(&self.pool, operation_id, lease_token, delay_seconds).await
    }
    async fn retry_pam_result(
        &self,
        operation_id: Uuid,
        lease_token: Uuid,
        attempt_count: i32,
        error: &str,
    ) -> Result<bool> {
        crate::mix::retry_pam_result(&self.pool, operation_id, lease_token, attempt_count, error)
            .await
    }
    async fn prune_expired_pam_results(&self, limit: i64) -> Result<u64> {
        crate::mix::prune_expired_pam_results(&self.pool, limit).await
    }
}
