use super::{map_database_busy, PostgresPubSubRepository};
use anyhow::Result;
use northstar_roster_application::{
    notification_admission::{NotificationAdmission, NotificationRecipient, NotificationSource},
    CommunicationDecision, CommunicationPolicyQuery, CommunicationPolicyReader,
};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

/// The caller already holds the account lock for its causal snapshot.
pub(crate) async fn active_notification_selection(
    transaction: &mut Transaction<'_, Postgres>,
    owner_id: Uuid,
    connection_id: Option<Uuid>,
) -> Result<Option<(String, bool)>> {
    let Some(connection_id) = connection_id else {
        return Ok(None);
    };
    Ok(sqlx::query_as(
        "SELECT list_name,expires_at>statement_timestamp() FROM privacy_active_sessions
          WHERE owner_id=$1 AND connection_id=$2
          FOR SHARE",
    )
    .bind(owner_id)
    .bind(connection_id)
    .fetch_optional(&mut **transaction)
    .await?)
}

impl CommunicationPolicyReader for PostgresPubSubRepository {
    async fn read_communication_policies(
        &self,
        queries: &[CommunicationPolicyQuery],
    ) -> Result<Vec<CommunicationDecision>> {
        northstar_roster_postgres::privacy::read_communication_policies(&self.pool, queries)
            .await
            .map_err(map_database_busy)
    }
}

impl NotificationAdmission for PostgresPubSubRepository {
    async fn authorize_notification(
        &self,
        recipient: NotificationRecipient<'_>,
        source: NotificationSource<'_>,
    ) -> Result<bool> {
        let active_list = recipient.active_list;
        let connection_id = recipient.connection_id;
        let (query, same_account) = source.policy(recipient)?;
        if same_account {
            // A self notification is exempt from message rules. Its account and
            // any expected selection must still be current in the same snapshot.
            return sqlx::query_scalar(
                "SELECT EXISTS (
                    SELECT 1 FROM users u
                     WHERE u.id=$1 AND u.auth_generation=$2 AND NOT u.is_disabled
                       AND ($4::text IS NULL OR EXISTS (
                           SELECT 1 FROM privacy_active_sessions a
                             JOIN privacy_lists l ON l.owner_id=a.owner_id AND l.name=a.list_name
                            WHERE a.owner_id=u.id AND a.connection_id=$3 AND a.list_name=$4
                              AND a.expires_at>statement_timestamp())))",
            )
            .bind(query.account_id)
            .bind(query.expected_auth_generation)
            .bind(connection_id)
            .bind(active_list)
            .fetch_one(&self.pool)
            .await
            .map_err(anyhow::Error::from)
            .map_err(map_database_busy);
        }
        Ok(self.read_communication_policy(&query).await?.allows())
    }
}
