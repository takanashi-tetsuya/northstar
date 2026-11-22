//! Generic presence replay admission and read snapshot across roster and PubSub.

use super::{map_database_busy, PostgresPubSubRepository, Result};
use northstar_pubsub_application::{
    PresenceReplayAdmission, PresenceReplayAdmissionOutcome, PresenceReplayAdmissionRequest,
    PubSubPresenceReplayQueryRepository,
};
use northstar_pubsub_core::{PresenceReplayPage, PresenceReplayQuery};
use northstar_roster_postgres::{privacy, roster};
use northstar_xep_0016::PrivacyStanzaKind;

impl PresenceReplayAdmission for PostgresPubSubRepository {
    async fn admit_presence_replay(
        &self,
        request: PresenceReplayAdmissionRequest,
    ) -> Result<PresenceReplayAdmissionOutcome> {
        let outcome = async {
            let service = request.service.to_string();
            if roster::is_blocked(&self.pool, request.recipient_id, &service).await? {
                return Ok(PresenceReplayAdmissionOutcome::Blocked);
            }
            if request.active_privacy_list.is_some() {
                privacy::refresh_active_privacy_session(
                    &self.pool,
                    request.recipient_id,
                    request.connection_id,
                )
                .await?;
            }
            Ok(PresenceReplayAdmissionOutcome::Admitted)
        }
        .await;
        outcome.map_err(map_database_busy)
    }
}

impl PubSubPresenceReplayQueryRepository for PostgresPubSubRepository {
    async fn presence_replay_page(
        &self,
        query: &PresenceReplayQuery,
    ) -> Result<PresenceReplayPage> {
        let outcome = async {
            let mut transaction = self.pool.begin().await?;
            sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
                .execute(&mut *transaction)
                .await?;
            // The first read fixes both the MVCC snapshot and the lease instant.
            let read_at = sqlx::query_scalar("SELECT statement_timestamp()")
                .fetch_one(&mut *transaction)
                .await?;
            let service = query.service.to_string();
            let page =
                if roster::is_blocked_in_snapshot(&mut transaction, query.recipient_id, &service)
                    .await?
                    || privacy::privacy_denies_in_snapshot(
                        &mut transaction,
                        query.recipient_id,
                        query.active_privacy_list.as_deref(),
                        &service,
                        PrivacyStanzaKind::Message,
                    )
                    .await?
                {
                    PresenceReplayPage::Denied
                } else {
                    northstar_pubsub_postgres::read_presence_replay_candidates(
                        &mut transaction,
                        query,
                        read_at,
                    )
                    .await?
                };
            transaction.commit().await?;
            Ok(page)
        }
        .await;
        outcome.map_err(map_database_busy)
    }
}
