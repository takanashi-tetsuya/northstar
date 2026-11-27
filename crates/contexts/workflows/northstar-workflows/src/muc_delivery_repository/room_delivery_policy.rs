use super::PostgresMucDeliveryRepository;
use anyhow::Result;
use northstar_room_application::room_delivery_policy::{
    RoomDeliveryDecision, RoomDeliveryPolicyQuery, RoomDeliveryPolicyReader, RoomPolicySubject,
};
use northstar_roster_postgres::privacy::{privacy_denies_from_facts, PRIVACY_DECISION_FACTS};
use northstar_roster_postgres::roster::{blocked_jid_matches, blocking_match_candidates};
use northstar_xmpp_types::jid::CanonicalJid;
use serde_json::{json, Value};
use sqlx::{PgPool, Postgres, Row};

#[derive(Clone)]
pub struct PostgresRoomDeliveryPolicy {
    pub(crate) pool: PgPool,
}

impl PostgresRoomDeliveryPolicy {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl RoomDeliveryPolicyReader for PostgresRoomDeliveryPolicy {
    async fn read_room_delivery_policies(
        &self,
        queries: &[RoomDeliveryPolicyQuery<'_>],
    ) -> Result<Vec<RoomDeliveryDecision>> {
        let mut decisions = read_policies(&self.pool, queries).await?;
        for (query, decision) in queries.iter().zip(&mut decisions) {
            let (RoomPolicySubject::Suspended { id }, Some(kind)) =
                (query.route.subject, query.kind)
            else {
                continue;
            };
            if decision.allows()
                && crate::privacy::privacy_denies_for_sm_session(
                    &self.pool,
                    id,
                    query.visible_peer,
                    kind,
                )
                .await?
                .unwrap_or(true)
            {
                *decision = RoomDeliveryDecision::PrivacyDenies;
            }
        }
        Ok(decisions)
    }
}

impl RoomDeliveryPolicyReader for PostgresMucDeliveryRepository {
    async fn read_room_delivery_policies(
        &self,
        queries: &[RoomDeliveryPolicyQuery<'_>],
    ) -> Result<Vec<RoomDeliveryDecision>> {
        PostgresRoomDeliveryPolicy::new(self.pool.clone())
            .read_room_delivery_policies(queries)
            .await
    }
}

pub(crate) async fn read_policies<'e>(
    executor: impl sqlx::Executor<'e, Database = Postgres>,
    queries: &[RoomDeliveryPolicyQuery<'_>],
) -> Result<Vec<RoomDeliveryDecision>> {
    if queries.is_empty() {
        return Ok(Vec::new());
    }
    let requested = queries
        .iter()
        .enumerate()
        .map(|(position, query)| {
            let recipient = CanonicalJid::parse(query.recipient_jid)?;
            let recipient_bare = recipient.bare();
            let visible = CanonicalJid::parse(query.visible_peer)?;
            let mut candidates = Vec::new();
            for peer in [Some(query.visible_peer), query.real_peer]
                .into_iter()
                .flatten()
            {
                let jid = CanonicalJid::parse(peer)?;
                if jid.bare() != recipient_bare {
                    candidates.extend(
                        blocking_match_candidates(&jid)
                            .into_iter()
                            .filter(|candidate| blocked_jid_matches(candidate, peer)),
                    );
                }
            }
            candidates.sort_unstable();
            candidates.dedup();
            let (connection_id, expects_active, sm_id) = match query.route.subject {
                RoomPolicySubject::Connection { id, expects_active } => {
                    (Some(id), expects_active, None)
                }
                RoomPolicySubject::AccountDefault => (None, false, None),
                RoomPolicySubject::Suspended { id } => (None, false, Some(id)),
            };
            Ok(json!({
                "position": position,
                "owner_id": (!query.route.account_id.is_nil()).then_some(query.route.account_id),
                "auth_generation": query.route.auth_generation,
                "connection_id": connection_id,
                "expects_active": expects_active,
                "sm_id": sm_id,
                "check_privacy": sm_id.is_none() && query.kind.is_some(),
                "recipient_name": recipient.localpart(),
                "peer_bare": visible.bare(),
                "block_keys": candidates,
            }))
        })
        .collect::<Result<Vec<_>>>()?;

    let statement = format!(
        "WITH routes AS MATERIALIZED (
             SELECT input.position, account.id AS owner_id, input.connection_id,
                    input.expects_active, input.peer_bare, input.check_privacy,
                    EXISTS (SELECT 1 FROM blocked_jids b WHERE b.owner_id = account.id
                             AND b.blocked_jid = ANY(ARRAY(
                                 SELECT jsonb_array_elements_text(input.block_keys)))) AS blocked
               FROM jsonb_to_recordset($1::jsonb) AS input(
                   position bigint, owner_id uuid, auth_generation bigint,
                   connection_id uuid, expects_active bool, sm_id uuid,
                   recipient_name text, peer_bare text, block_keys jsonb, check_privacy bool)
               LEFT JOIN LATERAL northstar_sm_privacy_state(input.sm_id) sm
                   ON input.sm_id IS NOT NULL
               LEFT JOIN users account ON NOT account.is_disabled
                   AND account.id = CASE WHEN input.sm_id IS NULL THEN input.owner_id ELSE sm.user_id END
                   AND (input.owner_id IS NULL OR account.id = input.owner_id)
                   AND (input.sm_id IS NULL OR account.username = input.recipient_name)
                   AND (input.auth_generation IS NULL OR account.auth_generation = input.auth_generation)
         ), requested AS (
             SELECT position, CASE WHEN check_privacy THEN owner_id END AS owner_id,
                    connection_id, expects_active, peer_bare FROM routes
         ), privacy AS ({PRIVACY_DECISION_FACTS})
         SELECT privacy.*, routes.owner_id IS NOT NULL AS current_account, routes.blocked
           FROM privacy JOIN routes ON routes.position = privacy.privacy_position
          ORDER BY privacy.privacy_position, privacy.item_order"
    );
    let rows = sqlx::query(sqlx::AssertSqlSafe(statement))
        .bind(Value::Array(requested))
        .fetch_all(executor)
        .await?;
    let decisions = rows
        .chunk_by(|left, right| {
            left.get::<i64, _>("privacy_position") == right.get::<i64, _>("privacy_position")
        })
        .zip(queries)
        .map(|(rows, query)| {
            use RoomDeliveryDecision::*;
            if !rows[0].try_get::<bool, _>("current_account")? {
                return Ok(StaleRoute);
            }
            if rows[0].try_get::<bool, _>("blocked")? {
                return Ok(Blocked);
            }
            if !matches!(query.route.subject, RoomPolicySubject::Suspended { .. }) {
                if let Some(kind) = query.kind {
                    if privacy_denies_from_facts(rows, query.visible_peer, kind)? {
                        return Ok(PrivacyDenies);
                    }
                }
            }
            Ok(Allow)
        })
        .collect::<Result<Vec<_>>>()?;
    anyhow::ensure!(
        decisions.len() == queries.len(),
        "incomplete room delivery policy facts"
    );
    Ok(decisions)
}
