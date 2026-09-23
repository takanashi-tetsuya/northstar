use crate::api::*;
use axum::{extract::State, response::Response, Json};
use serde_json::json;
use serde_json::Value;
use uuid::Uuid;

use crate::api::models::{
    BooleanToggle, BroadcastRequest, MucRoomView, OfflineMessagesStats, SessionView,
};
use crate::error::{AppError, Result};

pub async fn admin_stats(
    State(state): State<crate::state::ApiQueryContext>,
    actor: ApiAdmin,
) -> Result<Json<Value>, AppError> {
    let crate::services::api_queries::AdminStatistics {
        users,
        archived,
        offline,
        rooms,
        uploads,
        push_subscriptions,
        pending_reports,
        pending_appeals,
        active_invitations,
        live,
    } = state
        .api_query_service()
        .statistics(actor.read_authority(), || state.live_statistics())
        .await?
        .ok_or(AppError::Forbidden)?;
    let crate::services::api_queries::LiveAdminStats {
        island_mode,
        registration_open,
        online_sessions,
        room_occupants,
    } = live;
    let counters = state.counters();
    Ok(Json(json!({
        "users":users, "online_sessions":online_sessions, "archived_stanzas":archived,
        "offline_stanzas":offline, "uptime_seconds":state.uptime().as_secs(),
        "archive_policy":state.archive_policy(),
        "rooms":rooms, "room_occupants":room_occupants, "uploaded_files":uploads,
        "push_subscriptions":push_subscriptions,
        "island_mode":island_mode,
        "registration_open":registration_open,
        "federation_configured":state.federation_configured(),
        "federation_enabled":state.federation_configured() && !island_mode,
        "federation_inbound_connections":counters.federation_inbound_connections,
        "federation_outbound_deliveries":counters.federation_outbound_deliveries,
        "federation_failures":counters.federation_failures,
        "pending_reports":pending_reports, "pending_appeals":pending_appeals,
        "active_invitations":active_invitations,
        "anti_abuse_challenges":counters.anti_abuse_challenges,
        "rate_limited_operations":counters.rate_limited_operations,
        "reports_created":counters.reports_created,
        "appeals_created":counters.appeals_created
    })))
}

pub async fn admin_users(
    State(state): State<crate::state::ApiQueryContext>,
    actor: ApiAdmin,
    ApiQuery(query): ApiQuery<CursorPage>,
) -> Result<Json<Value>, AppError> {
    let limit = pagination::checked_limit(query.limit, 100, 100)?;
    let filter = pagination::no_filter_scope();
    let binding = pagination::pg_binding("admin/users", actor.id.as_bytes(), &filter);
    let after = pagination::pg_boundary(&state, query.cursor.as_deref(), &binding).await?;
    let page = state
        .api_query_service()
        .users(actor.read_authority(), after, limit)
        .await?
        .ok_or(AppError::Forbidden)?;
    let next_cursor = pagination::issue_pg_cursor(&state, &binding, page.next, page.database_now)?;
    Ok(Json(json!({"users":page.rows,"next_cursor":next_cursor})))
}

pub async fn admin_update_user(
    State(state): State<crate::state::AccountAdminContext>,
    actor: ApiAdmin,
    ApiPath(id): ApiPath<Uuid>,
    request: ApiJson<UserPatch>,
) -> Result<Response, AppError> {
    let mut idempotency = request.idempotency(
        Some(actor.id),
        actor.id.as_bytes(),
        crate::services::api_mutations::ApiPrincipalKind::Admin,
        "PATCH",
        "/api/v1/admin/users/{id}",
    );
    idempotency.target_scope = id.as_bytes();
    let outcome = state
        .update_user(
            crate::services::api_mutations::AdminMutationAdmission {
                authority: actor.read_authority(),
                idempotency,
            },
            id,
            crate::services::account_admin::UserStatusPatch {
                disabled: request.disabled,
                admin: request.admin,
            },
        )
        .await?;
    admin_mutation_response(outcome)
}

pub async fn admin_reports(
    State(state): State<crate::state::ApiQueryContext>,
    actor: ApiAdmin,
    ApiQuery(query): ApiQuery<ReportPageQuery>,
) -> Result<Json<Value>, AppError> {
    let limit = pagination::checked_limit(query.limit, 25, 25)?;
    let status = pagination::checked_report_status(query.status.as_deref())?;
    let filter = pagination::one_filter_scope("status", status)?;
    let binding = pagination::pg_binding("admin/reports", actor.id.as_bytes(), &filter);
    let after = pagination::pg_boundary(&state, query.cursor.as_deref(), &binding).await?;
    let page = state
        .api_query_service()
        .admin_reports(actor.read_authority(), status, after, limit)
        .await?
        .ok_or(AppError::Forbidden)?;
    let next_cursor = pagination::issue_pg_cursor(&state, &binding, page.next, page.database_now)?;
    Ok(Json(json!({
        "reports":page.rows,
        "limit":limit,
        "next_cursor":next_cursor
    })))
}

pub async fn admin_update_report(
    State(state): State<crate::state::ReportModerationContext>,
    actor: ApiAdmin,
    ApiPath(id): ApiPath<Uuid>,
    request: ApiJson<ModerationPatch>,
) -> Result<Response, AppError> {
    let mut idempotency = request.idempotency(
        Some(actor.id),
        actor.id.as_bytes(),
        crate::services::api_mutations::ApiPrincipalKind::Admin,
        "PATCH",
        "/api/v1/admin/reports/{id}",
    );
    idempotency.target_scope = id.as_bytes();
    let outcome = state
        .update_report(
            crate::services::api_mutations::AdminMutationAdmission {
                authority: actor.read_authority(),
                idempotency,
            },
            id,
            &request.status,
            request.resolution.as_deref(),
        )
        .await?;
    admin_mutation_response(outcome)
}

pub async fn admin_update_appeal(
    State(state): State<crate::state::ReportModerationContext>,
    actor: ApiAdmin,
    ApiPath(id): ApiPath<Uuid>,
    request: ApiJson<ModerationPatch>,
) -> Result<Response, AppError> {
    let mut idempotency = request.idempotency(
        Some(actor.id),
        actor.id.as_bytes(),
        crate::services::api_mutations::ApiPrincipalKind::Admin,
        "PATCH",
        "/api/v1/admin/appeals/{id}",
    );
    idempotency.target_scope = id.as_bytes();
    let outcome = state
        .update_appeal(
            crate::services::api_mutations::AdminMutationAdmission {
                authority: actor.read_authority(),
                idempotency,
            },
            id,
            &request.status,
            request.resolution.as_deref(),
        )
        .await?;
    admin_mutation_response(outcome)
}

fn admin_mutation_response(
    outcome: crate::services::api_mutations::ApiMutationOutcome<
        crate::services::api_mutations::StoredApiResponse,
    >,
) -> Result<Response, AppError> {
    use crate::services::api_mutations::ApiMutationOutcome;
    match outcome {
        ApiMutationOutcome::Committed(response) => idempotency::stored_api_response(response),
        ApiMutationOutcome::Replay(response) => idempotency_replay_response(response),
        ApiMutationOutcome::Rejected(rejection) => Err(idempotency::mutation_rejection(rejection)),
    }
}

pub async fn admin_tls_reload(
    State(state): State<crate::state::AdminDispatchContext>,
    actor: ApiAdmin,
    request: ApiEmpty,
) -> Result<Response, AppError> {
    let idempotency = request.idempotency(
        Some(actor.id),
        actor.id.as_bytes(),
        crate::services::api_mutations::ApiPrincipalKind::Admin,
        "POST",
        "/api/v1/admin/tls/reload",
    );
    let outcome = state
        .reload_tls(crate::services::api_mutations::AdminMutationAdmission {
            authority: actor.read_authority(),
            idempotency,
        })
        .await?;
    admin_mutation_response(outcome)
}

pub async fn admin_invitations(
    State(state): State<crate::state::ApiQueryContext>,
    actor: ApiAdmin,
    ApiQuery(query): ApiQuery<CursorPage>,
) -> Result<Json<Value>, AppError> {
    let limit = pagination::checked_limit(query.limit, 25, 100)?;
    let filter = pagination::no_filter_scope();
    let binding = pagination::pg_binding("admin/invitations", actor.id.as_bytes(), &filter);
    let after = pagination::pg_boundary(&state, query.cursor.as_deref(), &binding).await?;
    let page = state
        .api_query_service()
        .invitations(actor.read_authority(), after, limit)
        .await?
        .ok_or(AppError::Forbidden)?;
    let next_cursor = pagination::issue_pg_cursor(&state, &binding, page.next, page.database_now)?;
    Ok(Json(json!({
        "invitations":page.rows,
        "required":state.registration_requires_invitation(),
        "limit":limit,
        "next_cursor":next_cursor
    })))
}

pub async fn admin_create_invitation(
    State(state): State<crate::state::InvitationAdminContext>,
    actor: ApiAdmin,
    request: ApiJson<InvitationRequest>,
) -> Result<Response, AppError> {
    let mut idempotency = request.idempotency(
        Some(actor.id),
        actor.id.as_bytes(),
        crate::services::api_mutations::ApiPrincipalKind::Admin,
        "POST",
        "/api/v1/admin/invitations",
    );
    idempotency.target_scope = b"invitation:create";
    let outcome = state
        .create(
            crate::services::api_mutations::AdminMutationAdmission {
                authority: actor.read_authority(),
                idempotency,
            },
            crate::services::invitation_admin::InvitationInput {
                label: &request.label,
                max_uses: request.max_uses,
                expires_in_hours: request.expires_in_hours,
            },
        )
        .await?;
    admin_mutation_response(outcome)
}

pub async fn admin_revoke_invitation(
    State(state): State<crate::state::InvitationAdminContext>,
    actor: ApiAdmin,
    ApiPath(id): ApiPath<Uuid>,
    request: ApiEmpty,
) -> Result<Response, AppError> {
    let mut idempotency = request.idempotency(
        Some(actor.id),
        actor.id.as_bytes(),
        crate::services::api_mutations::ApiPrincipalKind::Admin,
        "DELETE",
        "/api/v1/admin/invitations/{id}",
    );
    idempotency.target_scope = id.as_bytes();
    let outcome = state
        .revoke(
            crate::services::api_mutations::AdminMutationAdmission {
                authority: actor.read_authority(),
                idempotency,
            },
            id,
        )
        .await?;
    admin_mutation_response(outcome)
}

pub async fn admin_nuke(
    _actor: ApiAdmin,
    Json(_body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    Err(AppError::OperationDisabled(
        "REST factory reset is disabled; use the staged operator recovery procedure".into(),
    ))
}

pub async fn admin_panic_disconnect(
    State(state): State<crate::state::AdminDispatchContext>,
    actor: ApiAdmin,
    request: ApiEmpty,
) -> Result<Response, AppError> {
    let idempotency = request.idempotency(
        Some(actor.id),
        actor.id.as_bytes(),
        crate::services::api_mutations::ApiPrincipalKind::Admin,
        "POST",
        "/api/v1/admin/panic_disconnect",
    );
    let outcome = state
        .panic_disconnect(crate::services::api_mutations::AdminMutationAdmission {
            authority: actor.read_authority(),
            idempotency,
        })
        .await?;
    admin_mutation_response(outcome)
}

pub async fn admin_toggle_island_mode(
    State(state): State<crate::state::AdminDispatchContext>,
    actor: ApiAdmin,
    request: ApiJson<BooleanToggle>,
) -> Result<Response, AppError> {
    let mut idempotency = request.idempotency(
        Some(actor.id),
        actor.id.as_bytes(),
        crate::services::api_mutations::ApiPrincipalKind::Admin,
        "POST",
        "/api/v1/admin/island_mode",
    );
    idempotency.target_scope = b"island_mode";
    let outcome = state
        .set_island_mode(
            crate::services::api_mutations::AdminMutationAdmission {
                authority: actor.read_authority(),
                idempotency,
            },
            request.enabled,
        )
        .await?;
    admin_mutation_response(outcome)
}

pub async fn admin_toggle_registration(
    State(state): State<crate::state::RegistrationAdminContext>,
    actor: ApiAdmin,
    request: ApiJson<BooleanToggle>,
) -> Result<Response, AppError> {
    let mut idempotency = request.idempotency(
        Some(actor.id),
        actor.id.as_bytes(),
        crate::services::api_mutations::ApiPrincipalKind::Admin,
        "POST",
        "/api/v1/admin/registration",
    );
    idempotency.target_scope = b"registration_closed";
    let outcome = state
        .set_registration(
            crate::services::api_mutations::AdminMutationAdmission {
                authority: actor.read_authority(),
                idempotency,
            },
            request.enabled,
        )
        .await?;
    admin_mutation_response(outcome)
}

pub async fn admin_sessions(
    State(state): State<crate::state::ApiQueryContext>,
    actor: ApiAdmin,
    ApiQuery(query): ApiQuery<CursorPage>,
) -> Result<Json<Value>, AppError> {
    let limit = pagination::checked_limit(query.limit, 100, 100)?;
    let node_incarnation =
        Uuid::parse_str(state.node_id()).map_err(|error| AppError::Internal(error.into()))?;
    let filter = pagination::no_filter_scope();
    let binding = pagination::session_binding(
        "admin/sessions",
        actor.id.as_bytes(),
        &filter,
        node_incarnation,
    );
    let after = pagination::session_after(&state, query.cursor.as_deref(), &binding).await?;
    let read = state
        .api_query_service()
        .sessions(actor.read_authority(), || {
            let views = state.local_sessions();
            finish_session_page(views, after, limit)
        })
        .await?
        .ok_or(AppError::Forbidden)?;
    let (views, next) = (read.rows, read.next);
    let database_now = read.database_now;
    let next_cursor = pagination::issue_session_cursor(&state, &binding, next, database_now)?;
    Ok(Json(json!({"sessions":views,"next_cursor":next_cursor})))
}

fn finish_session_page(
    mut views: Vec<SessionView>,
    after: Option<Uuid>,
    limit: i64,
) -> (Vec<SessionView>, Option<Uuid>) {
    views.sort_unstable_by_key(|view| std::cmp::Reverse(view.connection_id));
    if let Some(after) = after {
        views.retain(|session| session.connection_id < after);
    }
    let has_more = views.len() > limit as usize;
    views.truncate(limit as usize);
    let next = has_more.then(|| {
        views
            .last()
            .expect("a live-session page with an extra item is nonempty")
            .connection_id
    });
    (views, next)
}

pub async fn admin_kick_session(
    State(state): State<crate::state::SessionAdminContext>,
    actor: ApiAdmin,
    ApiPath(connection_id): ApiPath<Uuid>,
    request: ApiEmpty,
) -> Result<Response, AppError> {
    let target = format!("connection:{connection_id}");
    let mut idempotency = request.idempotency(
        Some(actor.id),
        actor.id.as_bytes(),
        crate::services::api_mutations::ApiPrincipalKind::Admin,
        "DELETE",
        "/api/v1/admin/sessions/{connection_id}",
    );
    idempotency.target_scope = target.as_bytes();
    let outcome = state
        .kick_session(
            crate::services::api_mutations::AdminMutationAdmission {
                authority: actor.read_authority(),
                idempotency,
            },
            connection_id,
        )
        .await?;
    admin_mutation_response(outcome)
}

pub async fn admin_offline_messages_stats(
    State(state): State<crate::state::ApiQueryContext>,
    actor: ApiAdmin,
) -> Result<Json<OfflineMessagesStats>, AppError> {
    let statistics = state
        .api_query_service()
        .offline_statistics(actor.read_authority())
        .await?
        .ok_or(AppError::Forbidden)?;
    Ok(Json(statistics))
}

pub async fn admin_clear_offline_messages(
    State(state): State<crate::state::AccountAdminContext>,
    actor: ApiAdmin,
    request: ApiEmpty,
) -> Result<Response, AppError> {
    let mut idempotency = request.idempotency(
        Some(actor.id),
        actor.id.as_bytes(),
        crate::services::api_mutations::ApiPrincipalKind::Admin,
        "DELETE",
        "/api/v1/admin/offline_messages",
    );
    idempotency.target_scope = b"offline_messages";
    let outcome = state
        .clear_offline_messages(crate::services::api_mutations::AdminMutationAdmission {
            authority: actor.read_authority(),
            idempotency,
        })
        .await?;
    admin_mutation_response(outcome)
}

pub async fn admin_muc_rooms(
    State(state): State<crate::state::ApiQueryContext>,
    actor: ApiAdmin,
    ApiQuery(query): ApiQuery<CursorPage>,
) -> Result<Json<Value>, AppError> {
    let limit = pagination::checked_limit(query.limit, 100, 100)?;
    let filter = pagination::no_filter_scope();
    let binding = pagination::pg_binding("admin/muc-rooms", actor.id.as_bytes(), &filter);
    let after = pagination::pg_boundary(&state, query.cursor.as_deref(), &binding).await?;
    let page = state
        .api_query_service()
        .muc_rooms(actor.read_authority(), after, limit, |rows| {
            let mut views = Vec::with_capacity(rows.len());
            for row in rows {
                let localpart = row.localpart;
                let occupants = state.room_occupant_count(&localpart);

                views.push(MucRoomView {
                    id: row.id,
                    localpart,
                    title: row.title,
                    created_at: row.created_at,
                    public: row.public,
                    persistent: row.persistent,
                    members_only: row.members_only,
                    moderated: row.moderated,
                    non_anonymous: row.non_anonymous,
                    current_occupants: occupants,
                });
            }
            views
        })
        .await?
        .ok_or(AppError::Forbidden)?;
    let views = page.rows;
    let next_cursor = pagination::issue_pg_cursor(&state, &binding, page.next, page.database_now)?;
    Ok(Json(json!({"rooms":views,"next_cursor":next_cursor})))
}

pub async fn admin_destroy_muc_room(
    State(state): State<crate::state::AdminDispatchContext>,
    actor: ApiAdmin,
    ApiPath(localpart): ApiPath<String>,
    request: ApiEmpty,
) -> Result<Response, AppError> {
    let room = state
        .room_target(localpart)
        .map_err(idempotency::mutation_rejection)?;
    let mut idempotency = request.idempotency(
        Some(actor.id),
        actor.id.as_bytes(),
        crate::services::api_mutations::ApiPrincipalKind::Admin,
        "DELETE",
        "/api/v1/admin/muc_rooms/{localpart}",
    );
    idempotency.target_scope = room.room_jid().as_bytes();
    let outcome = state
        .destroy_room(
            crate::services::api_mutations::AdminMutationAdmission {
                authority: actor.read_authority(),
                idempotency,
            },
            &room,
        )
        .await?;
    admin_mutation_response(outcome)
}

pub async fn admin_broadcast(
    State(state): State<crate::state::AdminDispatchContext>,
    actor: ApiAdmin,
    request: ApiJson<BroadcastRequest>,
) -> Result<Response, AppError> {
    let idempotency = request.idempotency(
        Some(actor.id),
        actor.id.as_bytes(),
        crate::services::api_mutations::ApiPrincipalKind::Admin,
        "POST",
        "/api/v1/admin/broadcast",
    );
    let outcome = state
        .broadcast(
            crate::services::api_mutations::AdminMutationAdmission {
                authority: actor.read_authority(),
                idempotency,
            },
            &request.message,
        )
        .await?;
    admin_mutation_response(outcome)
}

#[cfg(test)]
mod tests {
    use super::finish_session_page;
    use crate::services::report_moderation::valid_administrative_text as valid_admin_text;
    use axum::body::Body;
    use axum::extract::FromRequest;
    use axum::http::{HeaderValue, Request};

    use crate::api::{ApiEmpty, SessionView};

    fn session(connection_id: u128) -> SessionView {
        SessionView {
            connection_id: uuid::Uuid::from_u128(connection_id),
            node: "test-node".into(),
            jid: format!("user{connection_id}@example.test/phone"),
            ip: None,
            resource: "phone".into(),
            carbons_enabled: false,
            connected_duration_seconds: 0,
        }
    }

    #[test]
    fn administrator_text_rejects_database_and_display_controls() {
        assert!(valid_admin_text("ordinary label", 128, 512, false));
        assert!(valid_admin_text(
            "مراجعة \u{2067}example.test\u{2069}",
            128,
            512,
            false
        ));
        assert!(valid_admin_text("line one\nline two", 128, 512, true));
        assert!(!valid_admin_text("line one\nline two", 128, 512, false));
        assert!(!valid_admin_text("hidden\0suffix", 128, 512, false));
        assert!(!valid_admin_text("hidden\u{0085}suffix", 128, 512, false));
        assert!(!valid_admin_text("spoof\u{202e}txt", 128, 512, false));
        assert!(!valid_admin_text("", 128, 512, false));
        assert!(!valid_admin_text("é", 8, 1, false));
    }

    #[tokio::test]
    async fn empty_admin_mutations_reject_bodies_and_duplicate_idempotency_keys() {
        let valid = Request::builder()
            .header("idempotency-key", "admin-delete-key-0001")
            .body(Body::empty())
            .unwrap();
        assert!(ApiEmpty::from_request(valid, &()).await.is_ok());

        let nonempty = Request::builder()
            .header("idempotency-key", "admin-delete-key-0002")
            .body(Body::from("{}"))
            .unwrap();
        assert!(ApiEmpty::from_request(nonempty, &()).await.is_err());

        let mut duplicate = Request::builder().body(Body::empty()).unwrap();
        duplicate.headers_mut().append(
            "idempotency-key",
            HeaderValue::from_static("admin-delete-key-0003"),
        );
        duplicate.headers_mut().append(
            "idempotency-key",
            HeaderValue::from_static("admin-delete-key-0004"),
        );
        assert!(ApiEmpty::from_request(duplicate, &()).await.is_err());
    }

    #[test]
    fn live_session_pages_use_strict_immutable_connection_boundaries() {
        let (first, next) = finish_session_page(
            vec![session(1), session(5), session(3), session(4), session(2)],
            None,
            2,
        );
        assert_eq!(
            first
                .iter()
                .map(|row| row.connection_id.as_u128())
                .collect::<Vec<_>>(),
            vec![5, 4]
        );
        assert_eq!(next.map(|id| id.as_u128()), Some(4));

        // A new connection above the signed boundary cannot be duplicated on
        // the continuation page; a vanished connection creates no offset gap.
        let (second, next) = finish_session_page(
            vec![session(6), session(5), session(3), session(2), session(1)],
            next,
            2,
        );
        assert_eq!(
            second
                .iter()
                .map(|row| row.connection_id.as_u128())
                .collect::<Vec<_>>(),
            vec![3, 2]
        );
        assert_eq!(next.map(|id| id.as_u128()), Some(2));
    }
}
