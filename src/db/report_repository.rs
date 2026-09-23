//! One transaction owns report/appeal authorization, one-use proof, mutation and replay.
use crate::{
    abuse::{AbuseAction, AbuseGuard, TransactionalGuardOutcome},
    db,
    services::{api_mutations::*, reports::*},
};
use anyhow::Result;
use sqlx::{PgPool, Postgres, Transaction};
use std::sync::Arc;

#[derive(Clone)]
pub(crate) struct PostgresReportRepository {
    pool: PgPool,
    keyring: Arc<db::ApiControlKeyring>,
    abuse: Arc<AbuseGuard>,
}
enum MutationStart<'a> {
    Ready(Transaction<'a, Postgres>, db::IdempotencyLease),
    Finished(ApiMutationOutcome<ReportCommit>),
}
impl PostgresReportRepository {
    pub(crate) fn new(
        pool: PgPool,
        keyring: Arc<db::ApiControlKeyring>,
        abuse: Arc<AbuseGuard>,
    ) -> Self {
        Self {
            pool,
            keyring,
            abuse,
        }
    }
    async fn start(
        &self,
        admission: &UserMutationAdmission<'_>,
        action: AbuseAction,
    ) -> Result<MutationStart<'_>> {
        let mut tx = self.pool.begin().await?;
        let actor = &admission.authority;
        if !db::authorize_user_in_tx(
            &mut tx,
            actor.user_id,
            actor.auth_generation,
            actor.session_token,
        )
        .await?
        {
            tx.rollback().await?;
            return Ok(MutationStart::Finished(ApiMutationOutcome::Rejected(
                ApiMutationRejection::Unauthorized,
            )));
        }
        let acquired =
            db::acquire_idempotency_in_tx(&self.keyring, &mut tx, &admission.idempotency).await?;
        let rejection = match acquired {
            db::IdempotencyAcquire::Acquired(lease) => {
                if !lease.guard_verified {
                    match self
                        .abuse
                        .verify_or_allow_in_tx_v2(
                            &mut tx,
                            action,
                            admission.subject,
                            admission.actors,
                            admission.proof,
                            admission.intent,
                        )
                        .await?
                    {
                        TransactionalGuardOutcome::Allowed => {
                            anyhow::ensure!(
                                db::mark_idempotency_guard_verified_in_tx(&mut tx, &lease).await?,
                                "report/appeal idempotency guard lease changed"
                            );
                        }
                        TransactionalGuardOutcome::DeniedNeedsCommit(error) => {
                            let response = guard_denial_response(error)?;
                            let result = self
                                .finish(tx, &lease, response, ReportEffect::RateLimited)
                                .await?;
                            return Ok(MutationStart::Finished(result));
                        }
                    }
                }
                return Ok(MutationStart::Ready(tx, lease));
            }
            db::IdempotencyAcquire::Replay(response) => {
                tx.commit().await?;
                return Ok(MutationStart::Finished(ApiMutationOutcome::Replay(
                    response,
                )));
            }
            db::IdempotencyAcquire::FingerprintConflict
            | db::IdempotencyAcquire::RotationConflict => ApiMutationRejection::IdempotencyConflict,
            db::IdempotencyAcquire::ReplayInvalidated => ApiMutationRejection::ReplayInvalidated,
            db::IdempotencyAcquire::Busy {
                retry_after_seconds,
            } => ApiMutationRejection::Busy {
                retry_after: retry_after_seconds,
            },
            db::IdempotencyAcquire::CapacityLimited {
                retry_after_seconds,
            } => ApiMutationRejection::CapacityLimited {
                retry_after: retry_after_seconds,
            },
            db::IdempotencyAcquire::InProgress {
                retry_after_seconds,
            } => ApiMutationRejection::InProgress {
                retry_after: retry_after_seconds,
            },
        };
        tx.rollback().await?;
        Ok(MutationStart::Finished(ApiMutationOutcome::Rejected(
            rejection,
        )))
    }
    async fn finish(
        &self,
        mut tx: Transaction<'_, Postgres>,
        lease: &db::IdempotencyLease,
        response: StoredApiResponse,
        effect: ReportEffect,
    ) -> Result<ApiMutationOutcome<ReportCommit>> {
        anyhow::ensure!(
            db::api_mutations::persist_response_in_tx(&self.keyring, &mut tx, lease, &response)
                .await?,
            "report/appeal idempotency lease changed"
        );
        tx.commit().await?;
        Ok(ApiMutationOutcome::Committed(ReportCommit {
            response,
            effect,
        }))
    }
}
impl ReportRepository for PostgresReportRepository {
    async fn create_report(
        &self,
        command: ReportCommand<'_>,
    ) -> Result<ApiMutationOutcome<ReportCommit>> {
        let (mut tx, lease) = match self.start(&command.admission, AbuseAction::Report).await? {
            MutationStart::Ready(tx, lease) => (tx, lease),
            MutationStart::Finished(result) => return Ok(result),
        };
        let content = match command.content {
            Ok(content) => content,
            Err(message) => {
                return self
                    .finish(
                        tx,
                        &lease,
                        error_response(400, "bad_request", message)?,
                        ReportEffect::None,
                    )
                    .await
            }
        };
        let result = db::create_report_in_tx(
            &mut tx,
            command.admission.authority.user_id,
            &content.reported_jid,
            content.category,
            content.description,
            &content.evidence,
            Some(lease.request_id),
        )
        .await;
        let id = match result {
            Ok(id) => id,
            Err(db::ReportCreateError::InvalidEvidence(_)) => {
                return self
                    .finish(
                        tx,
                        &lease,
                        error_response(400, "bad_request", "report evidence is invalid")?,
                        ReportEffect::None,
                    )
                    .await
            }
            Err(db::ReportCreateError::Internal(error)) => return Err(error),
        };
        self.finish(
            tx,
            &lease,
            StoredApiResponse::json(201, serde_json::json!({"id":id,"status":"submitted"}))?,
            ReportEffect::ReportCreated,
        )
        .await
    }
    async fn create_appeal(
        &self,
        command: AppealCommand<'_>,
    ) -> Result<ApiMutationOutcome<ReportCommit>> {
        let (mut tx, lease) = match self.start(&command.admission, AbuseAction::Appeal).await? {
            MutationStart::Ready(tx, lease) => (tx, lease),
            MutationStart::Finished(result) => return Ok(result),
        };
        let reason = match command.reason {
            Ok(reason) => reason,
            Err(message) => {
                return self
                    .finish(
                        tx,
                        &lease,
                        error_response(400, "bad_request", message)?,
                        ReportEffect::None,
                    )
                    .await
            }
        };
        let id = match db::create_appeal_in_tx(
            &mut tx,
            command.report_id,
            command.admission.authority.user_id,
            reason,
            Some(lease.request_id),
        )
        .await
        {
            Ok(id) => id,
            Err(error @ db::AppealCreateError::Conflict) => {
                return self
                    .finish(
                        tx,
                        &lease,
                        error_response(409, "conflict", &error.to_string())?,
                        ReportEffect::None,
                    )
                    .await
            }
            Err(db::AppealCreateError::Internal(error)) => return Err(error),
        };
        self.finish(
            tx,
            &lease,
            StoredApiResponse::json(201, serde_json::json!({"id":id,"status":"submitted"}))?,
            ReportEffect::AppealCreated,
        )
        .await
    }
}
