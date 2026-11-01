//! Authorized query transactions for REST snapshots and collections.
use anyhow::Result;
use chrono::{DateTime, Utc};
use northstar_operations_application::api_queries::*;
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

#[derive(Clone)]
pub struct PostgresApiQueryRepository {
    pool: PgPool,
}
impl PostgresApiQueryRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    async fn begin_operation_read(
        &self,
        actor: ApiReadAuthority<'_>,
    ) -> Result<AuthorizedRead<Transaction<'_, Postgres>>> {
        let mut tx = self.pool.begin().await?;
        if !northstar_auth_postgres::users::authorize_user_in_tx(
            &mut tx,
            actor.user_id,
            actor.auth_generation,
            actor.session_token,
        )
        .await?
        {
            tx.rollback().await?;
            return Ok(Err(ApiReadDenial::Unauthorized));
        }
        if !northstar_auth_postgres::users::authorize_admin_in_tx(
            &mut tx,
            actor.user_id,
            actor.auth_generation,
            actor.session_token,
        )
        .await?
        {
            tx.rollback().await?;
            return Ok(Err(ApiReadDenial::Forbidden));
        }
        Ok(Ok(tx))
    }

    async fn begin_authorized_read(
        &self,
        actor: &ApiReadAuthority<'_>,
        administrator: bool,
    ) -> Result<Option<Transaction<'_, Postgres>>> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .execute(&mut *tx)
            .await?;
        let allowed = if administrator {
            northstar_auth_postgres::users::authorize_admin_in_tx(
                &mut tx,
                actor.user_id,
                actor.auth_generation,
                actor.session_token,
            )
            .await?
        } else {
            northstar_auth_postgres::users::authorize_user_in_tx(
                &mut tx,
                actor.user_id,
                actor.auth_generation,
                actor.session_token,
            )
            .await?
        };
        if !allowed {
            tx.rollback().await?;
            return Ok(None);
        }
        Ok(Some(tx))
    }
}
impl ApiQueryRepository for PostgresApiQueryRepository {
    async fn operations(
        &self,
        actor: ApiReadAuthority<'_>,
        status: Option<&str>,
        kind: Option<&str>,
        after: Option<OperationPageBoundary>,
        limit: i64,
    ) -> Result<AuthorizedRead<OperationPage>> {
        let mut tx = match self.begin_operation_read(actor).await? {
            Ok(tx) => tx,
            Err(denial) => return Ok(Err(denial)),
        };
        let value = northstar_operations_postgres::api_operations::list_operations(
            &mut tx, status, kind, after, limit,
        )
        .await?;
        tx.commit().await?;
        Ok(Ok(value))
    }
    async fn operation(
        &self,
        actor: ApiReadAuthority<'_>,
        id: Uuid,
    ) -> Result<AuthorizedRead<Option<OperationRecord>>> {
        let mut tx = match self.begin_operation_read(actor).await? {
            Ok(tx) => tx,
            Err(denial) => return Ok(Err(denial)),
        };
        let value =
            northstar_operations_postgres::api_operations::operation_by_id(&mut tx, id).await?;
        tx.commit().await?;
        Ok(Ok(value))
    }
    async fn operation_targets(
        &self,
        actor: ApiReadAuthority<'_>,
        id: Uuid,
        status: Option<&str>,
        after: Option<OperationPageBoundary>,
        limit: i64,
    ) -> Result<AuthorizedRead<Option<OperationTargetPage>>> {
        let mut tx = match self.begin_operation_read(actor).await? {
            Ok(tx) => tx,
            Err(denial) => return Ok(Err(denial)),
        };
        let value = if northstar_operations_postgres::api_operations::operation_by_id(&mut tx, id)
            .await?
            .is_some()
        {
            Some(
                northstar_operations_postgres::api_operations::list_operation_targets(
                    &mut tx, id, status, after, limit,
                )
                .await?,
            )
        } else {
            None
        };
        tx.commit().await?;
        Ok(Ok(value))
    }
    async fn operation_target(
        &self,
        actor: ApiReadAuthority<'_>,
        operation_id: Uuid,
        target_id: Uuid,
    ) -> Result<AuthorizedRead<Option<OperationTargetRecord>>> {
        let mut tx = match self.begin_operation_read(actor).await? {
            Ok(tx) => tx,
            Err(denial) => return Ok(Err(denial)),
        };
        let value = northstar_operations_postgres::api_operations::operation_target_by_id(
            &mut tx, target_id,
        )
        .await?
        .filter(|target| target.operation_id == operation_id);
        tx.commit().await?;
        Ok(Ok(value))
    }

    async fn principal(&self, token: &str) -> Result<Option<ApiPrincipal>> {
        northstar_auth_postgres::users::user_for_token(&self.pool, token).await
    }
    async fn cursor_clock(&self) -> Result<DateTime<Utc>> {
        crate::api_pages::database_cursor_clock(&self.pool).await
    }
    async fn users(
        &self,
        actor: ApiReadAuthority<'_>,
        after: Option<PageBoundary>,
        limit: i64,
    ) -> Result<Option<KeysetPage<UserPageRow>>> {
        let Some(mut tx) = self.begin_authorized_read(&actor, true).await? else {
            return Ok(None);
        };
        let value = crate::api_pages::users_page_in_tx(&mut tx, after, limit).await?;
        tx.commit().await?;
        Ok(Some(value))
    }
    async fn admin_reports(
        &self,
        actor: ApiReadAuthority<'_>,
        status: Option<&str>,
        after: Option<PageBoundary>,
        limit: i64,
    ) -> Result<Option<KeysetPage<ReportPageRow>>> {
        let Some(mut tx) = self.begin_authorized_read(&actor, true).await? else {
            return Ok(None);
        };
        let value =
            crate::api_pages::admin_reports_page_in_tx(&mut tx, status, after, limit).await?;
        tx.commit().await?;
        Ok(Some(value))
    }
    async fn own_reports(
        &self,
        actor: ApiReadAuthority<'_>,
        status: Option<&str>,
        after: Option<PageBoundary>,
        limit: i64,
    ) -> Result<Option<KeysetPage<ReportPageRow>>> {
        let Some(mut tx) = self.begin_authorized_read(&actor, false).await? else {
            return Ok(None);
        };
        let value =
            crate::api_pages::own_reports_page_in_tx(&mut tx, actor.user_id, status, after, limit)
                .await?;
        tx.commit().await?;
        Ok(Some(value))
    }
    async fn invitations(
        &self,
        actor: ApiReadAuthority<'_>,
        after: Option<PageBoundary>,
        limit: i64,
    ) -> Result<Option<KeysetPage<InvitationPageRow>>> {
        let Some(mut tx) = self.begin_authorized_read(&actor, true).await? else {
            return Ok(None);
        };
        let value = crate::api_pages::invitations_page_in_tx(&mut tx, after, limit).await?;
        tx.commit().await?;
        Ok(Some(value))
    }
    async fn upload_dead_letters(
        &self,
        actor: ApiReadAuthority<'_>,
        kind: UploadDeadLetterKind,
        after: Option<UploadDeadLetterBoundary>,
        limit: i64,
    ) -> Result<Option<UploadDeadLetterPage>> {
        let Some(mut tx) = self.begin_authorized_read(&actor, true).await? else {
            return Ok(None);
        };
        let value = northstar_upload_postgres::admin::upload_dead_letters_page_in_tx(
            &mut tx, kind, after, limit,
        )
        .await?;
        tx.commit().await?;
        Ok(Some(value))
    }
    async fn history(
        &self,
        actor: ApiReadAuthority<'_>,
        query: &MamArchiveQuery,
    ) -> Result<Option<TimedRead<Option<ArchivePage>>>> {
        let Some(mut tx) = self.begin_authorized_read(&actor, false).await? else {
            return Ok(None);
        };
        let page = northstar_archive_postgres::mam_user_archive_page_in_transaction(
            &mut tx,
            actor.user_id,
            query,
        )
        .await?;
        let database_now = northstar_postgres::database_cursor_clock_in_tx(&mut tx).await?;
        let value = TimedRead {
            value: page,
            database_now,
        };
        tx.commit().await?;
        Ok(Some(value))
    }
    async fn offline_statistics(
        &self,
        actor: ApiReadAuthority<'_>,
    ) -> Result<Option<OfflineMessagesStats>> {
        let Some(mut tx) = self.begin_authorized_read(&actor, true).await? else {
            return Ok(None);
        };
        let (total_messages, estimated_bytes): (i64, i64) = sqlx::query_as(
            "SELECT COUNT(*), COALESCE(SUM(LENGTH(stanza)), 0) FROM offline_messages",
        )
        .fetch_one(&mut *tx)
        .await?;
        let value = OfflineMessagesStats {
            total_messages,
            estimated_bytes,
        };
        tx.commit().await?;
        Ok(Some(value))
    }
    async fn statistics<F>(
        &self,
        actor: ApiReadAuthority<'_>,
        snapshot: F,
    ) -> Result<Option<AdminStatistics>>
    where
        F: FnOnce() -> LiveAdminStats + Send,
    {
        let Some(mut tx) = self.begin_authorized_read(&actor, true).await? else {
            return Ok(None);
        };
        let (users, archived, offline) = crate::account_lifecycle::counts_in_tx(&mut tx).await?;
        let (rooms, uploads, push_subscriptions) =
            crate::account_lifecycle::operational_counts_in_tx(&mut tx).await?;
        let (pending_reports, pending_appeals, active_invitations) =
            northstar_operations_postgres::reports::moderation_counts_in_tx(&mut tx).await?;
        let value = AdminStatistics {
            users,
            archived,
            offline,
            rooms,
            uploads,
            push_subscriptions,
            pending_reports,
            pending_appeals,
            active_invitations,
            live: snapshot(),
        };
        tx.commit().await?;
        Ok(Some(value))
    }
    async fn sessions<F>(
        &self,
        actor: ApiReadAuthority<'_>,
        snapshot: F,
    ) -> Result<Option<SessionPage>>
    where
        F: FnOnce() -> (Vec<SessionView>, Option<Uuid>) + Send,
    {
        let Some(mut tx) = self.begin_authorized_read(&actor, true).await? else {
            return Ok(None);
        };
        let (rows, next) = snapshot();
        let database_now = northstar_postgres::database_cursor_clock_in_tx(&mut tx).await?;
        let value = SessionPage {
            rows,
            next,
            database_now,
        };
        tx.commit().await?;
        Ok(Some(value))
    }
    async fn muc_rooms<F>(
        &self,
        actor: ApiReadAuthority<'_>,
        after: Option<PageBoundary>,
        limit: i64,
        snapshot: F,
    ) -> Result<Option<KeysetPage<MucRoomView>>>
    where
        F: FnOnce(Vec<MucRoomPageRow>) -> Vec<MucRoomView> + Send,
    {
        let Some(mut tx) = self.begin_authorized_read(&actor, true).await? else {
            return Ok(None);
        };
        let page = crate::api_pages::admin_muc_rooms_page_in_tx(&mut tx, after, limit).await?;
        let value = KeysetPage {
            rows: snapshot(page.rows),
            next: page.next,
            database_now: page.database_now,
        };
        tx.commit().await?;
        Ok(Some(value))
    }
}
