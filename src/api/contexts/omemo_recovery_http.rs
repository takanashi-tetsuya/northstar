//! Bearer identity and recovery transfer authority for authenticated REST routes.

use crate::api::bearer_token;
use crate::api::error::AppError;
use crate::api::postgres_repositories::PostgresHttpRepositories;
use crate::api::repositories::HttpRepositories;
use axum::http::HeaderMap;
use northstar_auth_application::omemo_recovery::{OmemoRecoveryActor, OmemoRecoveryService};
use northstar_operations_application::api_queries::ApiQueryService;
use northstar_telemetry::metrics::Metrics;
use std::sync::Arc;
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Clone)]
pub(crate) struct OmemoRecoveryHttpContext<R: HttpRepositories = PostgresHttpRepositories> {
    pub(crate) queries: ApiQueryService<R::ApiQueries>,
    pub(crate) recovery: OmemoRecoveryService<R::OmemoRecovery>,
    pub(crate) domain: String,
    pub(crate) metrics: Arc<Metrics>,
}

pub(crate) struct OmemoRecoveryHttpUser {
    pub(crate) id: Uuid,
    pub(crate) username: String,
    pub(crate) auth_generation: i64,
    session_token: Zeroizing<String>,
}

impl OmemoRecoveryHttpUser {
    pub(crate) fn session_token(&self) -> &str {
        self.session_token.as_str()
    }

    pub(crate) fn actor(&self) -> OmemoRecoveryActor<'_> {
        OmemoRecoveryActor {
            user_id: self.id,
            auth_generation: self.auth_generation,
            session_token: self.session_token(),
        }
    }
}

impl<R: HttpRepositories> OmemoRecoveryHttpContext<R> {
    pub(crate) async fn current_user(
        &self,
        headers: &HeaderMap,
    ) -> Result<OmemoRecoveryHttpUser, AppError> {
        let _authentication_timer = self.metrics.authentication_duration_seconds.start_timer();
        let token = bearer_token(headers)?;
        let _database_timer = self
            .metrics
            .database_operation_duration_seconds
            .start_timer();
        let principal = self
            .queries
            .principal(token)
            .await?
            .ok_or(AppError::Unauthorized)?;
        Ok(OmemoRecoveryHttpUser {
            id: principal.id,
            username: principal.username,
            auth_generation: principal.auth_generation,
            session_token: Zeroizing::new(token.to_owned()),
        })
    }

    pub(crate) fn service(&self) -> &OmemoRecoveryService<R::OmemoRecovery> {
        &self.recovery
    }

    pub(crate) fn canonical_account(&self, user: &OmemoRecoveryHttpUser) -> String {
        format!("{}@{}", user.username, self.domain)
    }
}
