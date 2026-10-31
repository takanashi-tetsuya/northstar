//! One transaction owns report/appeal authorization, one-use proof, mutation and replay.
use anyhow::Result;
use northstar_abuse_application::guard::{AbuseGuard, TransactionalGuardOutcome};
use northstar_abuse_policy::AbuseAction;
use northstar_operations_application::reports::*;
use northstar_operations_core::api_mutations::*;
use sqlx::{PgPool, Postgres, Transaction};
use std::sync::Arc;

#[derive(Clone)]
pub(crate) struct PostgresReportRepository {
    pool: PgPool,
    keyring: Arc<northstar_operations_postgres::api_control::ApiControlKeyring>,
    abuse: Arc<AbuseGuard>,
}
enum MutationStart<'a> {
    Ready(
        Transaction<'a, Postgres>,
        northstar_operations_postgres::api_control::IdempotencyLease,
    ),
    Finished(ApiMutationOutcome<ReportCommit>),
}
impl PostgresReportRepository {
    pub(crate) fn new(
        pool: PgPool,
        keyring: Arc<northstar_operations_postgres::api_control::ApiControlKeyring>,
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
        if !northstar_auth_postgres::users::authorize_user_in_tx(
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
        let acquired = northstar_operations_postgres::api_control::acquire_idempotency_in_tx(
            &self.keyring,
            &mut tx,
            &admission.idempotency,
        )
        .await?;
        let rejection = match acquired {
            northstar_operations_postgres::api_control::IdempotencyAcquire::Acquired(lease) => {
                if !lease.guard_verified {
                    match northstar_abuse_postgres::transaction::verify_in_tx(
                        &mut tx,
                        &self.abuse,
                        action,
                        admission.subject,
                        admission.actors,
                        admission.proof,
                        Some(admission.intent),
                    )
                    .await?
                    {
                        TransactionalGuardOutcome::Allowed => {
                            anyhow::ensure!(
                                northstar_operations_postgres::api_control::mark_idempotency_guard_verified_in_tx(&mut tx, &lease).await?,
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
            northstar_operations_postgres::api_control::IdempotencyAcquire::Replay(response) => {
                tx.commit().await?;
                return Ok(MutationStart::Finished(ApiMutationOutcome::Replay(
                    response,
                )));
            }
            northstar_operations_postgres::api_control::IdempotencyAcquire::FingerprintConflict
            | northstar_operations_postgres::api_control::IdempotencyAcquire::RotationConflict => {
                ApiMutationRejection::IdempotencyConflict
            }
            northstar_operations_postgres::api_control::IdempotencyAcquire::ReplayInvalidated => {
                ApiMutationRejection::ReplayInvalidated
            }
            northstar_operations_postgres::api_control::IdempotencyAcquire::Busy {
                retry_after_seconds,
            } => ApiMutationRejection::Busy {
                retry_after: retry_after_seconds,
            },
            northstar_operations_postgres::api_control::IdempotencyAcquire::CapacityLimited {
                retry_after_seconds,
            } => ApiMutationRejection::CapacityLimited {
                retry_after: retry_after_seconds,
            },
            northstar_operations_postgres::api_control::IdempotencyAcquire::InProgress {
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
        lease: &northstar_operations_postgres::api_control::IdempotencyLease,
        response: StoredApiResponse,
        effect: ReportEffect,
    ) -> Result<ApiMutationOutcome<ReportCommit>> {
        anyhow::ensure!(
            northstar_operations_postgres::api_mutations::persist_response_in_tx(
                &self.keyring,
                &mut tx,
                lease,
                &response
            )
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
        let result = northstar_operations_postgres::reports::create_report_in_tx(
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
            Err(northstar_operations_postgres::reports::ReportCreateError::InvalidEvidence(_)) => {
                return self
                    .finish(
                        tx,
                        &lease,
                        error_response(400, "bad_request", "report evidence is invalid")?,
                        ReportEffect::None,
                    )
                    .await
            }
            Err(northstar_operations_postgres::reports::ReportCreateError::Internal(error)) => {
                return Err(error)
            }
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
        let id = match northstar_operations_postgres::reports::create_appeal_in_tx(
            &mut tx,
            command.report_id,
            command.admission.authority.user_id,
            reason,
            Some(lease.request_id),
        )
        .await
        {
            Ok(id) => id,
            Err(error @ northstar_operations_postgres::reports::AppealCreateError::Conflict) => {
                return self
                    .finish(
                        tx,
                        &lease,
                        error_response(409, "conflict", &error.to_string())?,
                        ReportEffect::None,
                    )
                    .await
            }
            Err(northstar_operations_postgres::reports::AppealCreateError::Internal(error)) => {
                return Err(error)
            }
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
