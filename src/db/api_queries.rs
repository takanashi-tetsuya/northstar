//! Authorized query transactions for REST snapshots and collections.
use crate::{db, services::api_queries::*};
use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

#[derive(Clone)]
pub(crate) struct PostgresApiQueryRepository {
    pool: PgPool,
}
impl PostgresApiQueryRepository {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    async fn begin_operation_read(
        &self,
        actor: ApiReadAuthority<'_>,
    ) -> Result<AuthorizedRead<Transaction<'_, Postgres>>> {
        let mut tx = self.pool.begin().await?;
        if !db::authorize_user_in_tx(
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
        if !db::authorize_admin_in_tx(
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
            db::authorize_admin_in_tx(
                &mut tx,
                actor.user_id,
                actor.auth_generation,
                actor.session_token,
            )
            .await?
        } else {
            db::authorize_user_in_tx(
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
        let value = db::list_operations(&mut tx, status, kind, after, limit).await?;
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
        let value = db::operation_by_id(&mut tx, id).await?;
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
        let value = if db::operation_by_id(&mut tx, id).await?.is_some() {
            Some(db::list_operation_targets(&mut tx, id, status, after, limit).await?)
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
        let value = db::operation_target_by_id(&mut tx, target_id)
            .await?
            .filter(|target| target.operation_id == operation_id);
        tx.commit().await?;
        Ok(Ok(value))
    }

    async fn principal(&self, token: &str) -> Result<Option<ApiPrincipal>> {
        db::user_for_token(&self.pool, token).await
    }
    async fn cursor_clock(&self) -> Result<DateTime<Utc>> {
        db::database_cursor_clock(&self.pool).await
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
        let value = db::users_page_in_tx(&mut tx, after, limit).await?;
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
        let value = db::admin_reports_page_in_tx(&mut tx, status, after, limit).await?;
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
            db::own_reports_page_in_tx(&mut tx, actor.user_id, status, after, limit).await?;
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
        let value = db::invitations_page_in_tx(&mut tx, after, limit).await?;
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
        let value = db::upload_dead_letters_page_in_tx(&mut tx, kind, after, limit).await?;
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
        let page = db::mam_user_archive_page_in_transaction(&mut tx, actor.user_id, query).await?;
        let database_now = db::database_cursor_clock_in_tx(&mut tx).await?;
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
        let (users, archived, offline) = db::counts_in_tx(&mut tx).await?;
        let (rooms, uploads, push_subscriptions) = db::operational_counts_in_tx(&mut tx).await?;
        let (pending_reports, pending_appeals, active_invitations) =
            db::moderation_counts_in_tx(&mut tx).await?;
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
        let database_now = db::database_cursor_clock_in_tx(&mut tx).await?;
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
        let page = db::admin_muc_rooms_page_in_tx(&mut tx, after, limit).await?;
        let value = KeysetPage {
            rows: snapshot(page.rows),
            next: page.next,
            database_now: page.database_now,
        };
        tx.commit().await?;
        Ok(Some(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires an isolated PostgreSQL schema"]
    async fn authorized_projection_holds_account_and_bearer_until_snapshot_finishes() {
        let url = std::env::var("TEST_DATABASE_URL").expect("isolated PostgreSQL URL");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .unwrap();
        db::migrate(&pool).await.unwrap();
        let id = Uuid::new_v4();
        let generation: i64 = sqlx::query_scalar(
            "INSERT INTO users(id,username,password_hash,is_admin) VALUES($1,$2,'test-only',TRUE) RETURNING auth_generation",
        ).bind(id).bind(format!("query_{}", id.simple())).fetch_one(&pool).await.unwrap();
        let token = db::create_api_session(&pool, id, 1).await.unwrap();
        let service = ApiQueryService::new(PostgresApiQueryRepository::new(pool.clone()));
        let actor = || ApiReadAuthority {
            user_id: id,
            auth_generation: generation,
            session_token: &token,
        };
        assert!(service
            .sessions(
                ApiReadAuthority {
                    auth_generation: generation + 1,
                    ..actor()
                },
                || { panic!("a stale generation must not read process state") }
            )
            .await
            .unwrap()
            .is_none());

        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let reader = service.clone();
        let reader_token = token.clone();
        let read = tokio::spawn(async move {
            reader
                .sessions(
                    ApiReadAuthority {
                        user_id: id,
                        auth_generation: generation,
                        session_token: &reader_token,
                    },
                    move || {
                        entered_tx.send(()).unwrap();
                        tokio::task::block_in_place(|| {
                            release_rx.recv_timeout(Duration::from_secs(10))
                        })
                        .unwrap();
                        (Vec::new(), None)
                    },
                )
                .await
        });
        tokio::time::timeout(Duration::from_secs(5), entered_rx)
            .await
            .unwrap()
            .unwrap();
        for mutation in [
            "UPDATE users SET is_admin=FALSE WHERE id=$1",
            "DELETE FROM api_sessions WHERE user_id=$1",
        ] {
            let mut tx = pool.begin().await.unwrap();
            sqlx::query("SET LOCAL lock_timeout='250ms'")
                .execute(&mut *tx)
                .await
                .unwrap();
            let error = sqlx::query(mutation)
                .bind(id)
                .execute(&mut *tx)
                .await
                .unwrap_err();
            assert_eq!(
                error
                    .as_database_error()
                    .and_then(|error| error.code())
                    .as_deref(),
                Some("55P03")
            );
            tx.rollback().await.unwrap();
        }
        release_tx.send(()).unwrap();
        let page = read.await.unwrap().unwrap().unwrap();
        assert!(page.rows.is_empty());
        assert!(page.next.is_none());

        sqlx::query("UPDATE users SET is_admin=FALSE WHERE id=$1")
            .bind(id)
            .execute(&pool)
            .await
            .unwrap();
        assert!(service
            .sessions(actor(), || panic!(
                "demoted administrator read process state"
            ))
            .await
            .unwrap()
            .is_none());
        assert!(service.users(actor(), None, 10).await.unwrap().is_none());
        assert!(service
            .own_reports(actor(), None, None, 10)
            .await
            .unwrap()
            .is_some());
        sqlx::query("DELETE FROM api_sessions WHERE user_id=$1")
            .bind(id)
            .execute(&pool)
            .await
            .unwrap();
        assert!(service.principal(&token).await.unwrap().is_none());
        assert!(service
            .own_reports(actor(), None, None, 10)
            .await
            .unwrap()
            .is_none());
        sqlx::query("DELETE FROM users WHERE id=$1")
            .bind(id)
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;
    }
}
