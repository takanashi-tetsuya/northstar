//! The authentication adapter's steps over session and archive tables.

use anyhow::Result;
use northstar_archive_core::ArchiveBoundary;
use northstar_auth_postgres::effects::AuthenticationEffects;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

#[derive(Clone, Copy)]
pub(crate) struct RootAuthenticationEffects;

pub(crate) type PostgresAuthenticationRepository =
    northstar_auth_postgres::authentication::PostgresAuthenticationRepository<
        RootAuthenticationEffects,
    >;

impl AuthenticationEffects for RootAuthenticationEffects {
    async fn publish_user_agent_login_epoch(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        operation_id: Uuid,
        connection_id: Uuid,
        user_id: Uuid,
        device_id: Uuid,
        expected_auth_generation: i64,
        allow_binding_claim: bool,
    ) -> Result<Option<i64>> {
        super::users::publish_user_agent_login_epoch_in_transaction(
            transaction,
            operation_id,
            connection_id,
            user_id,
            device_id,
            expected_auth_generation,
            allow_binding_claim,
        )
        .await
    }

    async fn publish_binding_live_session(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        connection_id: Uuid,
        user_id: Uuid,
        full_jid: &str,
        lease_seconds: u64,
    ) -> Result<bool> {
        super::capacity::publish_binding_live_session_in_transaction(
            transaction,
            connection_id,
            user_id,
            full_jid,
            lease_seconds,
        )
        .await
    }

    async fn archive_boundaries_visible(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        user_id: Uuid,
    ) -> Result<(Option<ArchiveBoundary>, Option<ArchiveBoundary>)> {
        super::archive_boundaries_visible_in_transaction(transaction, user_id).await
    }
}
