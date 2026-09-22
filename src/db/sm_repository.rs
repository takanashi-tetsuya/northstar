//! Atomic SM ownership, transport acknowledgements and binding persistence.
use crate::{db, services::sm::*};
use anyhow::Result;
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Clone)]
pub(crate) struct PostgresSmRepository {
    pool: PgPool,
    fast_token_secret: Arc<Zeroizing<Vec<u8>>>,
}
impl PostgresSmRepository {
    pub(crate) fn new(pool: PgPool, fast_token_secret: Arc<Zeroizing<Vec<u8>>>) -> Self {
        Self {
            pool,
            fast_token_secret,
        }
    }
}
impl SmRepository for PostgresSmRepository {
    async fn revoke_session(&self, session_id: Uuid) -> Result<()> {
        db::revoke_sm_session(&self.pool, session_id).await
    }

    async fn create_session(
        &self,
        request: SmSessionCreationRequest<'_>,
    ) -> Result<SmSessionCreationOutcome> {
        let snapshot = db::SmSessionSnapshot::from(request.snapshot);
        match db::create_sm_session_with_ownership_resolution(
            &self.pool,
            request.token_hash,
            request.user_id,
            request.auth_generation,
            request.full_jid,
            request.resource,
            request.server_domain,
            request.connection_id,
            &snapshot,
            request.ttl_seconds,
            request.live_lease_seconds,
            request.max_per_account,
            request.max_global,
        )
        .await
        {
            Ok(created) => Ok(SmSessionCreationOutcome::Created {
                id: created.id,
                ownership: created.ownership.into(),
            }),
            Err(error) if db::is_capacity_exhausted(&error) => {
                Ok(SmSessionCreationOutcome::CapacityExhausted)
            }
            Err(error) => Err(error),
        }
    }
    async fn claim_resume(
        &self,
        request: SmResumeClaimRequest<'_>,
        ip_policy: SmIpPolicy,
    ) -> Result<SmResumeClaimOutcome> {
        Ok(
            match db::claim_sm_session_status(
                &self.pool,
                request.token_hash,
                request.user_id,
                request.peer_ip,
                request.user_agent_id,
                ip_policy,
                request.require_same_device,
                request.claim_lease_seconds,
            )
            .await?
            {
                db::SmClaimStatus::Claimed(claim) => {
                    SmResumeClaimOutcome::Claimed(Box::new((*claim).into()))
                }
                db::SmClaimStatus::Pending(pending) => {
                    SmResumeClaimOutcome::Pending(pending.into())
                }
                db::SmClaimStatus::Rejected => SmResumeClaimOutcome::Rejected,
            },
        )
    }
    #[allow(clippy::too_many_arguments)]
    async fn checkpoint_session(
        &self,
        session_id: Uuid,
        connection_id: Uuid,
        snapshot: &SmSessionSnapshot,
        ttl_seconds: u64,
        live_lease_seconds: u64,
        max_stanzas: usize,
        max_bytes: usize,
    ) -> Result<SmCheckpointOutcome> {
        let snapshot = db::SmSessionSnapshot::from(snapshot);
        Ok(db::checkpoint_sm_session_with_ownership_resolution(
            &self.pool,
            session_id,
            connection_id,
            &snapshot,
            ttl_seconds,
            live_lease_seconds,
            max_stanzas,
            max_bytes,
        )
        .await?
        .into())
    }
    async fn remove_live_muc_memberships(
        &self,
        session_id: Uuid,
        connection_id: Uuid,
        memberships: &[SmMucMembership],
    ) -> Result<bool> {
        db::remove_live_sm_muc_memberships(&self.pool, session_id, connection_id, memberships).await
    }
    #[allow(clippy::too_many_arguments)]
    async fn checkpoint_and_acknowledge(
        &self,
        session_id: Uuid,
        connection_id: Uuid,
        snapshot: &SmSessionSnapshot,
        acknowledged: &[crate::outbound::SmUnackedStanza],
        ttl_seconds: u64,
        live_lease_seconds: u64,
        max_stanzas: usize,
        max_bytes: usize,
    ) -> Result<SmCheckpointOutcome> {
        let snapshot = db::SmSessionSnapshot::from(snapshot);
        Ok(
            db::checkpoint_sm_session_and_acknowledge_with_ownership_resolution(
                &self.pool,
                session_id,
                connection_id,
                &snapshot,
                acknowledged,
                ttl_seconds,
                live_lease_seconds,
                max_stanzas,
                max_bytes,
            )
            .await?
            .into(),
        )
    }
    async fn acknowledge_delivery_batch(
        &self,
        sources: &[crate::outbound::TransportOwnershipSource],
    ) -> Result<()> {
        db::acknowledge_transport_sources(&self.pool, sources).await
    }
    async fn reserve_binding(
        &self,
        connection_id: Uuid,
        user_id: Uuid,
        expected_auth_generation: i64,
        full_jid: &str,
        lease_seconds: u64,
    ) -> Result<BindingReservationOutcome> {
        let Some(mut tx) =
            db::lock_auth_generation(&self.pool, user_id, expected_auth_generation).await?
        else {
            return Ok(BindingReservationOutcome::CredentialsExpired);
        };
        let reserved = db::reserve_live_session_in_transaction(
            &mut tx,
            connection_id,
            user_id,
            full_jid,
            lease_seconds,
            true,
        )
        .await?;
        match reserved {
            db::LiveSessionReservation::Reserved
            | db::LiveSessionReservation::ReplacedResumable => {
                tx.commit().await?;
                Ok(BindingReservationOutcome::Reserved)
            }
            db::LiveSessionReservation::Conflict => {
                tx.rollback().await?;
                Ok(BindingReservationOutcome::Conflict)
            }
            db::LiveSessionReservation::CapacityExhausted => {
                tx.rollback().await?;
                Ok(BindingReservationOutcome::CapacityExhausted)
            }
        }
    }
    #[allow(clippy::too_many_arguments)]
    async fn finalize_binding(
        &self,
        connection_id: Uuid,
        user_id: Uuid,
        expected_auth_generation: i64,
        full_jid: &str,
        lease_seconds: u64,
        device_id: Option<Uuid>,
        fast_plan: Option<&crate::services::authentication::FastCommitPlan>,
    ) -> Result<BindingFinalizationOutcome> {
        let Some(mut tx) =
            db::lock_auth_generation(&self.pool, user_id, expected_auth_generation).await?
        else {
            return Ok(BindingFinalizationOutcome::CredentialsExpired);
        };
        if !db::finalize_binding_live_session_in_transaction(
            &mut tx,
            connection_id,
            user_id,
            full_jid,
            lease_seconds,
        )
        .await?
        {
            tx.rollback().await?;
            return Ok(BindingFinalizationOutcome::ReservationLost);
        }
        let staged_login_epoch = crate::db::authentication::stage_login_epoch_in_transaction(
            &mut tx,
            user_id,
            device_id,
            expected_auth_generation,
            connection_id,
        )
        .await?;
        if device_id.is_some() && staged_login_epoch.is_none() {
            tx.rollback().await?;
            return Ok(BindingFinalizationOutcome::CredentialsExpired);
        }
        let issued_fast = if let Some(plan) = fast_plan {
            let db_plan = db::FastCommitPlan::from(plan);
            match db::commit_fast_state_in_transaction(
                &mut tx,
                self.fast_token_secret.as_slice(),
                user_id,
                expected_auth_generation,
                &db_plan,
            )
            .await?
            {
                db::FastCommitOutcome::Committed(issued) => {
                    issued.map(crate::services::authentication::IssuedFastToken::from)
                }
                db::FastCommitOutcome::CredentialsExpired => {
                    tx.rollback().await?;
                    return Ok(BindingFinalizationOutcome::CredentialsExpired);
                }
            }
        } else {
            None
        };
        tx.commit().await?;
        Ok(BindingFinalizationOutcome::Committed {
            receipt: crate::services::authentication::CredentialCommitReceipt::new(
                issued_fast,
                staged_login_epoch,
                Some(crate::services::authentication::BindingPublication {
                    connection_id,
                    user_id,
                    full_jid: full_jid.to_owned(),
                    lease_seconds,
                }),
            ),
        })
    }
    async fn finalize_resume(
        &self,
        request: SmResumeFinalizationRequest<'_>,
    ) -> Result<SmResumeFinalizationOutcome> {
        let Some(mut tx) = db::lock_auth_generation(
            &self.pool,
            request.user_id,
            request.expected_auth_generation,
        )
        .await?
        else {
            return Ok(SmResumeFinalizationOutcome::CredentialsExpired);
        };
        let staged_login_epoch = crate::db::authentication::stage_login_epoch_in_transaction(
            &mut tx,
            request.user_id,
            request.user_agent_id,
            request.expected_auth_generation,
            request.connection_id,
        )
        .await?;
        if request.user_agent_id.is_some() && staged_login_epoch.is_none() {
            tx.rollback().await?;
            return Ok(SmResumeFinalizationOutcome::CredentialsExpired);
        }
        let Some(activated) = db::activate_claimed_sm_session_in_transaction(
            &mut tx,
            request.session_id,
            request.claim_token,
            request.connection_id,
            request.client_h,
            request.acknowledged_count,
            request.peer_ip,
            request.user_agent_id,
            request.ttl_seconds,
            request.live_lease_seconds,
            request.max_stanzas,
            request.max_bytes,
        )
        .await?
        else {
            tx.rollback().await?;
            return Ok(SmResumeFinalizationOutcome::ClaimLost);
        };
        let issued_fast = if let Some(plan) = request.fast_plan {
            let db_plan = db::FastCommitPlan::from(plan);
            match db::commit_fast_state_in_transaction(
                &mut tx,
                self.fast_token_secret.as_slice(),
                request.user_id,
                request.expected_auth_generation,
                &db_plan,
            )
            .await?
            {
                db::FastCommitOutcome::Committed(issued) => {
                    issued.map(crate::services::authentication::IssuedFastToken::from)
                }
                db::FastCommitOutcome::CredentialsExpired => {
                    tx.rollback().await?;
                    return Ok(SmResumeFinalizationOutcome::CredentialsExpired);
                }
            }
        } else {
            None
        };
        if !db::set_active_privacy_list_in_transaction(
            &mut tx,
            request.user_id,
            request.connection_id,
            request.active_privacy_list,
        )
        .await?
        {
            tx.rollback().await?;
            return Ok(SmResumeFinalizationOutcome::PrivacySelectionMissing);
        }
        tx.commit().await?;
        Ok(SmResumeFinalizationOutcome::Committed(Box::new(
            SmResumeFinalizationCommit {
                activated: activated.into(),
                receipt: crate::services::authentication::CredentialCommitReceipt::new(
                    issued_fast,
                    staged_login_epoch,
                    None,
                ),
            },
        )))
    }
    async fn release_claim(&self, session_id: Uuid, claim_token: Uuid) -> Result<()> {
        crate::db::release_sm_claim(&self.pool, session_id, claim_token).await
    }
    async fn release_live_session(&self, connection_id: Uuid) -> Result<bool> {
        db::release_live_session(&self.pool, connection_id).await
    }
    #[allow(clippy::too_many_arguments)]
    async fn suspend_exact_session(
        &self,
        session_id: Uuid,
        connection_id: Uuid,
        user_id: Uuid,
        expected_auth_generation: i64,
        snapshot: &SmSessionSnapshot,
        ttl_seconds: u64,
        max_stanzas: usize,
        max_bytes: usize,
    ) -> Result<bool> {
        let snapshot = db::SmSessionSnapshot::from(snapshot);
        db::suspend_activated_sm_resume_exact(
            &self.pool,
            session_id,
            connection_id,
            user_id,
            expected_auth_generation,
            &snapshot,
            ttl_seconds,
            max_stanzas,
            max_bytes,
        )
        .await
    }
}

impl From<SessionRouteClaimProof> for db::ClusterSessionRouteClaimProof {
    fn from(value: SessionRouteClaimProof) -> Self {
        match value {
            SessionRouteClaimProof::Binding => Self::Binding,
            SessionRouteClaimProof::SmResume {
                session_id,
                claim_token,
            } => Self::SmResume {
                session_id,
                claim_token,
            },
        }
    }
}
impl From<&db::SmSessionSnapshot> for SmSessionSnapshot {
    fn from(value: &db::SmSessionSnapshot) -> Self {
        Self {
            inbound_h: value.inbound_h,
            outbound_h: value.outbound_h,
            acked_h: value.acked_h,
            available: value.available,
            carbons: value.carbons,
            priority: value.priority,
            blocklist_requested: value.blocklist_requested,
            roster_requested: value.roster_requested,
            active_privacy_list: value.active_privacy_list.clone(),
            privacy_requested: value.privacy_requested,
            peer_ip: value.peer_ip,
            user_agent_id: value.user_agent_id,
            joined_rooms: value.joined_rooms.clone(),
            directed_presence: value.directed_presence.clone(),
            last_presence: value.last_presence.clone(),
            unacked: value.unacked.clone(),
        }
    }
}
impl From<&SmSessionSnapshot> for db::SmSessionSnapshot {
    fn from(value: &SmSessionSnapshot) -> Self {
        Self {
            inbound_h: value.inbound_h,
            outbound_h: value.outbound_h,
            acked_h: value.acked_h,
            available: value.available,
            carbons: value.carbons,
            priority: value.priority,
            blocklist_requested: value.blocklist_requested,
            roster_requested: value.roster_requested,
            active_privacy_list: value.active_privacy_list.clone(),
            privacy_requested: value.privacy_requested,
            peer_ip: value.peer_ip,
            user_agent_id: value.user_agent_id,
            joined_rooms: value.joined_rooms.clone(),
            directed_presence: value.directed_presence.clone(),
            last_presence: value.last_presence.clone(),
            unacked: value.unacked.clone(),
        }
    }
}
impl From<db::SmResumeClaim> for SmResumeClaim {
    fn from(value: db::SmResumeClaim) -> Self {
        Self {
            session_id: value.session_id,
            claim_token: value.claim_token,
            claim_deadline: value.claim_deadline,
            full_jid: value.full_jid,
            resource: value.resource,
            resume_timeout_seconds: value.resume_timeout_seconds,
            inbound_h: value.inbound_h,
            acked_h: value.acked_h,
            available: value.available,
            carbons: value.carbons,
            priority: value.priority,
            blocklist_requested: value.blocklist_requested,
            roster_requested: value.roster_requested,
            active_privacy_list: value.active_privacy_list,
            privacy_requested: value.privacy_requested,
            user_agent_id: value.user_agent_id,
            joined_rooms: value.joined_rooms,
            directed_presence: value.directed_presence,
            last_presence: value.last_presence,
            unacked: value.unacked,
        }
    }
}
impl From<db::ActivatedSmSession> for ActivatedSmSession {
    fn from(value: db::ActivatedSmSession) -> Self {
        Self {
            outbound_h: value.outbound_h,
            unacked: value.unacked,
        }
    }
}
impl From<db::SmQueueOwnershipResolution> for SmQueueOwnershipResolution {
    fn from(value: db::SmQueueOwnershipResolution) -> Self {
        Self {
            mix_rotations: value
                .mix_rotations
                .into_iter()
                .map(|rotation| SmMixLeaseRotation {
                    previous: rotation.previous,
                    current: rotation.current,
                })
                .collect(),
        }
    }
}
impl From<db::SmCheckpointOutcome> for SmCheckpointOutcome {
    fn from(value: db::SmCheckpointOutcome) -> Self {
        Self {
            updated: value.updated,
            ownership: value.ownership.into(),
        }
    }
}
impl From<db::SmPendingReason> for SmPendingReason {
    fn from(value: db::SmPendingReason) -> Self {
        match value {
            db::SmPendingReason::Live => Self::Live,
            db::SmPendingReason::Claim => Self::Claim,
            db::SmPendingReason::LiveAndClaim => Self::LiveAndClaim,
        }
    }
}
impl From<db::SmResumePending> for SmResumePending {
    fn from(value: db::SmResumePending) -> Self {
        Self {
            session_id: value.session_id,
            old_connection_id: value.old_connection_id,
            full_jid: value.full_jid,
            state_version: value.state_version,
            reason: value.reason.into(),
            retry_at: value.retry_at,
        }
    }
}
