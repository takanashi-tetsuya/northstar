//! Generic presence replay admission and read snapshot across roster and PubSub.

use super::{map_database_busy, PostgresPubSubRepository, Result};
use northstar_pubsub_application::{
    PresenceReplayAdmission, PresenceReplayAdmissionOutcome, PresenceReplayAdmissionRequest,
    PubSubPresenceReplayQueryRepository,
};
use northstar_pubsub_core::{PresenceReplayPage, PresenceReplayQuery};
use northstar_roster_application::{
    CommunicationPolicyQuery, CommunicationPolicyReader, PolicyDirection, PolicySubject,
};
use northstar_xep_0016::PrivacyStanzaKind;

impl PresenceReplayAdmission for PostgresPubSubRepository {
    async fn admit_presence_replay(
        &self,
        request: PresenceReplayAdmissionRequest,
    ) -> Result<PresenceReplayAdmissionOutcome> {
        let policy = replay_policy_query(
            request.recipient_id,
            request.expected_auth_generation,
            request.connection_id,
            request.active_privacy_list.is_some(),
            request.service.to_string(),
        );
        Ok(if self.read_communication_policy(&policy).await?.allows() {
            PresenceReplayAdmissionOutcome::Admitted
        } else {
            PresenceReplayAdmissionOutcome::Blocked
        })
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
            // Pin the MVCC snapshot and the candidate subscription clock.
            let read_at = sqlx::query_scalar("SELECT statement_timestamp()")
                .fetch_one(&mut *transaction)
                .await?;
            let policy = replay_policy_query(
                query.recipient_id,
                query.expected_auth_generation,
                query.connection_id,
                query.active_privacy_list.is_some(),
                query.service.to_string(),
            );
            let decisions = northstar_roster_postgres::privacy::read_communication_policies(
                &mut *transaction,
                &[policy],
            )
            .await?;
            let page = if decisions.first().is_some_and(|decision| decision.allows()) {
                northstar_pubsub_postgres::read_presence_replay_candidates(
                    &mut transaction,
                    query,
                    read_at,
                )
                .await?
            } else {
                PresenceReplayPage::Denied
            };
            transaction.commit().await?;
            Ok(page)
        }
        .await;
        outcome.map_err(map_database_busy)
    }
}

fn replay_policy_query(
    account_id: uuid::Uuid,
    expected_auth_generation: Option<i64>,
    connection_id: uuid::Uuid,
    expects_active: bool,
    peer: String,
) -> CommunicationPolicyQuery {
    CommunicationPolicyQuery {
        account_id,
        expected_auth_generation,
        subject: PolicySubject::Connection {
            connection_id,
            expects_active,
        },
        peer,
        kind: PrivacyStanzaKind::Message,
        direction: PolicyDirection::Inbound,
        check_owner_block: true,
        check_peer_block: false,
    }
}
