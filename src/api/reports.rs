use crate::api::*;
use axum::http::HeaderMap;
use axum::{
    extract::{ConnectInfo, State},
    response::Response,
    Json,
};
use serde_json::json;
use serde_json::Value;
use std::net::SocketAddr;
use uuid::Uuid;

use crate::abuse::AbuseAction;
use crate::api::idempotency::{mutation_rejection, stored_api_response};
use crate::error::{AppError, Result};
use crate::services::{
    api_mutations::*,
    reports::{ReportCommit, ReportEvidenceInput, ReportInput},
};
use crate::state::ReportContext;

async fn report_user(state: &ReportContext, headers: &HeaderMap) -> Result<ApiUser, AppError> {
    let token = bearer_token(headers)?;
    let user = state
        .principal(token)
        .await?
        .ok_or(AppError::Unauthorized)?;
    Ok(ApiUser {
        user,
        session_token: zeroize::Zeroizing::new(token.to_owned()),
    })
}

fn report_input(body: &ReportRequest) -> ReportInput<'_> {
    ReportInput {
        reported_jid: &body.reported_jid,
        category: &body.category,
        description: body.description.as_deref(),
        evidence: body
            .evidence
            .iter()
            .map(|item| ReportEvidenceInput {
                archive_id: item.archive_id,
                client_message_id: item.client_message_id.clone(),
                body_text: item.body_text.clone(),
            })
            .collect(),
    }
}
fn report_response(
    state: &ReportContext,
    result: ApiMutationOutcome<ReportCommit>,
) -> Result<Response, AppError> {
    match result {
        ApiMutationOutcome::Committed(commit) => {
            state.record_commit(commit.effect);
            stored_api_response(commit.response)
        }
        ApiMutationOutcome::Replay(response) => idempotency_replay_response(response),
        ApiMutationOutcome::Rejected(rejection) => Err(mutation_rejection(rejection)),
    }
}

pub async fn create_report(
    State(state): State<ReportContext>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    request: ApiJson<ReportRequest>,
) -> Result<Response, AppError> {
    let user = report_user(&state, &headers).await?;
    let peer_ip = client_ip_with_trusted_proxies(peer.ip(), &headers, state.trusted_proxies());
    let (subject, actors) = abuse_identity(AbuseAction::Report, peer_ip, Some(&user));
    let intent = request.value.pow_intent();
    let admission = UserMutationAdmission {
        authority: user.read_authority(),
        idempotency: request.idempotency(
            Some(user.id),
            user.id.as_bytes(),
            ApiPrincipalKind::User,
            "POST",
            "/api/v1/reports",
        ),
        subject: &subject,
        actors: &actors,
        proof: request.value.pow.as_ref(),
        intent: &intent,
    };
    let result = state
        .report_service()
        .create_report(admission, report_input(&request.value))
        .await?;
    report_response(&state, result)
}

pub async fn my_reports(
    State(state): State<crate::state::ApiQueryContext>,
    headers: HeaderMap,
    ApiQuery(query): ApiQuery<ReportPageQuery>,
) -> Result<Json<Value>, AppError> {
    let user = current_user_with_queries(&state, &headers).await?;
    let limit = pagination::checked_limit(query.limit, 25, 25)?;
    let status = pagination::checked_report_status(query.status.as_deref())?;
    let filter = pagination::one_filter_scope("status", status)?;
    let binding = pagination::pg_binding("reports/own", user.id.as_bytes(), &filter);
    let after = pagination::pg_boundary(&state, query.cursor.as_deref(), &binding).await?;
    let page = state
        .api_query_service()
        .own_reports(user.read_authority(), status, after, limit)
        .await?
        .ok_or(AppError::Unauthorized)?;
    let next_cursor = pagination::issue_pg_cursor(&state, &binding, page.next, page.database_now)?;
    Ok(Json(json!({
        "reports":page.rows,
        "limit":limit,
        "next_cursor":next_cursor
    })))
}

pub async fn create_appeal(
    State(state): State<ReportContext>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    ApiPath(report_id): ApiPath<Uuid>,
    request: ApiJson<AppealRequest>,
) -> Result<Response, AppError> {
    let user = report_user(&state, &headers).await?;
    let peer_ip = client_ip_with_trusted_proxies(peer.ip(), &headers, state.trusted_proxies());
    let (subject, actors) = abuse_identity(AbuseAction::Appeal, peer_ip, Some(&user));
    let intent = request.value.pow_intent(report_id);
    let mut idempotency = request.idempotency(
        Some(user.id),
        user.id.as_bytes(),
        ApiPrincipalKind::User,
        "POST",
        "/api/v1/reports/{id}/appeals",
    );
    idempotency.target_scope = report_id.as_bytes();
    let admission = UserMutationAdmission {
        authority: user.read_authority(),
        idempotency,
        subject: &subject,
        actors: &actors,
        proof: request.value.pow.as_ref(),
        intent: &intent,
    };
    let result = state
        .report_service()
        .create_appeal(admission, report_id, &request.value.reason)
        .await?;
    report_response(&state, result)
}
