//! Steps of an authentication transaction over other contexts' tables. The composition root
//! implements them; each runs inside the caller's transaction.

use anyhow::Result;
use northstar_auth_application::authentication::ArchiveBoundary;
use sqlx::{Postgres, Transaction};
use std::future::Future;
use uuid::Uuid;

pub trait AuthenticationEffects: Send + Sync + 'static {
    /// Publishes a staged login epoch, which reads the deployment session claims in one statement.
    /// `None` means the stage or its claim is gone.
    #[allow(clippy::too_many_arguments)]
    fn publish_user_agent_login_epoch(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        operation_id: Uuid,
        connection_id: Uuid,
        user_id: Uuid,
        device_id: Uuid,
        expected_auth_generation: i64,
        allow_binding_claim: bool,
    ) -> impl Future<Output = Result<Option<i64>>> + Send;

    /// Moves a reserved connection onto its live session row. `false` means the reservation is gone.
    fn publish_binding_live_session(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        connection_id: Uuid,
        user_id: Uuid,
        full_jid: &str,
        lease_seconds: u64,
    ) -> impl Future<Output = Result<bool>> + Send;

    /// The account's first and last visible archive positions.
    fn archive_boundaries_visible(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        user_id: Uuid,
    ) -> impl Future<Output = Result<(Option<ArchiveBoundary>, Option<ArchiveBoundary>)>> + Send;
}
