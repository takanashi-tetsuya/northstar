use super::{privacy_denies_from_facts, PRIVACY_DECISION_FACTS};
use crate::roster::{blocked_jid_matches, blocking_match_candidates};
use anyhow::Result;
use northstar_roster_application::{
    CommunicationDecision, CommunicationPolicyQuery, PolicySubject,
};
use northstar_xmpp_types::jid::CanonicalJid;
use serde_json::{json, Value};
use sqlx::{postgres::PgRow, Postgres, Row};

/// Read all communication policy facts at one PostgreSQL statement snapshot.
pub async fn read_communication_policies<'e>(
    executor: impl sqlx::Executor<'e, Database = Postgres>,
    queries: &[CommunicationPolicyQuery],
) -> Result<Vec<CommunicationDecision>> {
    if queries.is_empty() {
        return Ok(Vec::new());
    }

    let peers = queries
        .iter()
        .map(|query| CanonicalJid::parse(&query.peer))
        .collect::<Result<Vec<_>>>()?;
    let requested = queries
        .iter()
        .zip(&peers)
        .enumerate()
        .map(|(position, (query, peer))| request_row(position, query, peer))
        .collect();

    // For a local peer, the owner shares the peer's domain. The projection of
    // the peer's bare JID supplies the shared domain key and the exact-account
    // key, whose localpart is replaced using the owner row in this snapshot.
    let statement = format!(
        "WITH requested AS (
             SELECT * FROM jsonb_to_recordset($1::jsonb) AS input(
                 position bigint, owner_id uuid, expected_auth_generation bigint,
                 connection_id uuid, expects_active bool, peer_bare text, peer_domain text,
                 local_peer_name text, owner_block_keys jsonb, peer_block_keys jsonb)
         ), account_policy AS MATERIALIZED (
             SELECT requested.position,
                    account.id IS NOT NULL AND NOT account.is_disabled
                      AND (requested.expected_auth_generation IS NULL
                           OR account.auth_generation = requested.expected_auth_generation)
                      AS current_account,
                    EXISTS (
                        SELECT 1 FROM blocked_jids b
                         WHERE b.owner_id = account.id
                           AND b.blocked_jid = ANY(ARRAY(
                               SELECT jsonb_array_elements_text(requested.owner_block_keys)))
                    ) AS owner_blocks,
                    EXISTS (
                        SELECT 1 FROM blocked_jids b
                         WHERE b.owner_id = peer_account.id
                           AND b.blocked_jid = ANY(ARRAY(
                               SELECT CASE WHEN candidate.jid = requested.peer_bare
                                          THEN account.username || '@' || requested.peer_domain
                                          ELSE candidate.jid END
                                 FROM jsonb_array_elements_text(requested.peer_block_keys)
                                      AS candidate(jid)))
                    ) AS peer_blocks
               FROM requested
               LEFT JOIN users account ON account.id = requested.owner_id
               LEFT JOIN users peer_account ON peer_account.username = requested.local_peer_name
                   AND NOT peer_account.is_disabled
         ), privacy AS ({PRIVACY_DECISION_FACTS})
         SELECT privacy.*, account_policy.current_account, account_policy.owner_blocks,
                account_policy.peer_blocks
           FROM privacy JOIN account_policy ON account_policy.position = privacy.privacy_position
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
        .zip(queries.iter().zip(&peers))
        .map(|(rows, (query, peer))| read_decision(rows, query, peer))
        .collect::<Result<Vec<_>>>()?;
    anyhow::ensure!(
        decisions.len() == queries.len(),
        "incomplete communication policy facts"
    );
    Ok(decisions)
}

fn request_row(position: usize, query: &CommunicationPolicyQuery, peer: &CanonicalJid) -> Value {
    let (connection_id, expects_active) = match query.subject {
        PolicySubject::Connection {
            connection_id,
            expects_active,
        } => (Some(connection_id), expects_active),
        PolicySubject::AccountDefault => (None, false),
    };
    let local_peer_name = if query.check_peer_block {
        peer.localpart()
    } else {
        None
    };
    let owner_block_keys = if query.check_owner_block {
        // Keep the shared projection as the index key source. Its candidates
        // can be broader than the scalar XEP-0191 matcher for domain/resource.
        let full_peer = peer.to_string();
        blocking_match_candidates(peer)
            .into_iter()
            .filter(|pattern| blocked_jid_matches(pattern, &full_peer))
            .collect()
    } else {
        Vec::new()
    };
    let peer_block_keys = if local_peer_name.is_some() {
        blocking_match_candidates(&peer.to_bare())
    } else {
        Vec::new()
    };
    json!({
        "position": position,
        "owner_id": query.account_id,
        "expected_auth_generation": query.expected_auth_generation,
        "connection_id": connection_id,
        "expects_active": expects_active,
        "peer_bare": peer.bare(),
        "peer_domain": peer.domainpart(),
        "local_peer_name": local_peer_name,
        "owner_block_keys": owner_block_keys,
        "peer_block_keys": peer_block_keys,
    })
}

fn read_decision(
    rows: &[PgRow],
    query: &CommunicationPolicyQuery,
    peer: &CanonicalJid,
) -> Result<CommunicationDecision> {
    use CommunicationDecision::*;

    let first = &rows[0];
    let denial = [
        (!first.try_get::<bool, _>("current_account")?).then_some(StaleAccount),
        first
            .try_get::<bool, _>("owner_blocks")?
            .then_some(OwnerBlocks),
        first
            .try_get::<bool, _>("peer_blocks")?
            .then_some(PeerBlocks),
    ]
    .into_iter()
    .flatten()
    .max();
    if let Some(denial) = denial {
        return Ok(denial);
    }
    Ok(
        if privacy_denies_from_facts(rows, &peer.to_string(), query.kind)? {
            PrivacyDenies
        } else {
            Allow
        },
    )
}
