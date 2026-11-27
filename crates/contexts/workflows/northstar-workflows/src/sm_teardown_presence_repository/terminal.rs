use super::*;
use northstar_roster_application::CommunicationDecision;
use northstar_roster_postgres::privacy::{privacy_denies_from_facts, PRIVACY_DECISION_FACTS};
use northstar_roster_postgres::roster::blocked_jid_matches;
use northstar_xep_0016::PrivacyStanzaKind;
use northstar_xmpp_types::jid::CanonicalJid;
use serde_json::json;
use sqlx::{postgres::PgRow, Row};

impl TerminalPresenceRepository for PostgresSmTeardownPresenceRepository {
    async fn capture_terminal_presence(
        &self,
        request: &TerminalPresenceRequest<'_>,
        routes: &[TerminalRouteCandidate],
    ) -> Result<Option<TerminalPresenceAudience>> {
        let source_jid = CanonicalJid::parse(request.full_jid)?;
        let (generation, connection, sm_id, deadline) = match request.owner {
            TerminalOwner::Live {
                auth_generation,
                connection_id,
            } => (Some(auth_generation), Some(connection_id), None, None),
            TerminalOwner::Suspended {
                session_id,
                deadline,
            } => (None, None, Some(session_id), Some(deadline)),
        };
        if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
            return Ok(None);
        }
        let mut grants = Vec::new();
        let mut external = Vec::new();
        for entry in request.directed {
            if let Some(grant) = DirectedGrant::decode(entry)? {
                grants.push(grant);
            } else if let Ok(peer) = CanonicalJid::parse(entry) {
                if peer.domainpart() != request.local_domain {
                    // Across federation, grants refer to an address, since
                    // the remote server owns its account and resource epochs.
                    external.push(peer.to_string());
                }
            }
        }
        let statement = format!(
            "{AUDIENCE_SQL}, privacy AS ({PRIVACY_DECISION_FACTS})
             SELECT audience.*, privacy.*,
                    source.auth_generation AS source_generation,
                    source.connection_id AS source_connection,
                    CASE WHEN source.id = audience.recipient_id THEN NULL
                         WHEN privacy.privacy_position % 2 = 0
                         THEN source_blocks.patterns ELSE recipient_blocks.patterns END AS blocks
               FROM source
               LEFT JOIN audience ON true
               LEFT JOIN privacy ON privacy.privacy_position / 2 = audience.position
               LEFT JOIN block_facts source_blocks ON source_blocks.owner_id = source.id
               LEFT JOIN block_facts recipient_blocks ON recipient_blocks.owner_id = audience.recipient_id
              ORDER BY audience.position, privacy.privacy_position, privacy.item_order"
        );
        let rows = sqlx::query(sqlx::AssertSqlSafe(statement))
            .bind(request.owner_id)
            .bind(request.full_jid)
            .bind(source_jid.bare())
            .bind(request.local_domain)
            .bind(generation)
            .bind(connection)
            .bind(sm_id)
            .bind(request.active_privacy_list)
            .bind(request.available)
            .bind(json!(routes))
            .bind(json!(grants))
            .bind(external)
            .fetch_all(&self.pool)
            .await?;
        decode_audience(&rows, request, routes, deadline)
    }
}

fn decode_audience(
    rows: &[PgRow],
    request: &TerminalPresenceRequest<'_>,
    routes: &[TerminalRouteCandidate],
    deadline: Option<std::time::Instant>,
) -> Result<Option<TerminalPresenceAudience>> {
    let Some(first) = rows.first() else {
        return Ok(None);
    };
    let source = TerminalRoute {
        full_jid: request.full_jid.to_owned(),
        account_id: request.owner_id,
        auth_generation: first.try_get("source_generation")?,
        connection_id: first.try_get("source_connection")?,
        node_id: None,
    };
    let mut targets = Vec::new();
    for group in rows.chunk_by(|left, right| {
        left.get::<Option<i64>, _>("position") == right.get::<Option<i64>, _>("position")
    }) {
        let first = &group[0];
        let Some(scope) = first.try_get::<Option<String>, _>("scope")? else {
            continue;
        };
        let ordinal = first.try_get::<Option<i64>, _>("route_ordinal")?;
        let sibling: bool = first.try_get("sibling")?;
        if !sibling {
            let split = group.partition_point(|row| row.get::<i64, _>("privacy_position") % 2 == 0);
            if !decision(&group[..split], &scope, PrivacyStanzaKind::PresenceOut)?.allows()
                || (ordinal.is_some()
                    && !decision(
                        &group[split..],
                        request.full_jid,
                        PrivacyStanzaKind::PresenceIn,
                    )?
                    .allows())
            {
                continue;
            }
        }
        let target = match ordinal {
            Some(ordinal) => TerminalPresenceTarget::Route {
                route: routes
                    .get(usize::try_from(ordinal - 1)?)
                    .ok_or_else(|| {
                        anyhow::anyhow!("terminal presence route index is out of range")
                    })?
                    .route
                    .clone(),
                scope,
            },
            None => TerminalPresenceTarget::External(scope),
        };
        targets.push(target);
    }
    let mut seen = std::collections::HashSet::new();
    let mut seen_external = std::collections::HashSet::new();
    targets.retain(|target| match target {
        TerminalPresenceTarget::Route { route, .. } => seen.insert(route.clone()),
        TerminalPresenceTarget::External(peer) => seen_external.insert(peer.clone()),
    });
    Ok(Some(TerminalPresenceAudience {
        source,
        targets,
        deadline,
    }))
}

fn decision(rows: &[PgRow], peer: &str, kind: PrivacyStanzaKind) -> Result<CommunicationDecision> {
    let blocks: Option<Vec<String>> = rows
        .first()
        .ok_or_else(|| anyhow::anyhow!("missing terminal presence policy facts"))?
        .try_get("blocks")?;
    let blocks = blocks.is_some_and(|patterns| {
        patterns
            .iter()
            .any(|pattern| blocked_jid_matches(pattern, peer))
    });
    CommunicationDecision::from_facts(true, blocks, false, || {
        privacy_denies_from_facts(rows, peer, kind)
    })
}

const AUDIENCE_SQL: &str = "
WITH source AS MATERIALIZED (
    SELECT owner.id, owner.auth_generation,
           COALESCE($6::uuid, stream.connection_id) AS connection_id,
           stream.active_privacy_list AS suspended_list
      FROM users owner
      LEFT JOIN sm_resume_sessions stream ON stream.id=$7::uuid
       AND stream.user_id=owner.id AND stream.full_jid=$2
       AND stream.auth_generation=owner.auth_generation
       AND stream.claimed_until>statement_timestamp() AND NOT stream.resumable
     WHERE owner.id=$1 AND NOT owner.is_disabled
       AND owner.username || '@' || $4::text = $3::text
       AND (($7 IS NULL AND owner.auth_generation=$5::bigint) OR stream.id IS NOT NULL)
), subscribers AS MATERIALIZED (
    SELECT contact_jid FROM roster_items
     WHERE owner_id=$1 AND $9::bool AND subscription IN ('from','both')
), routes AS MATERIALIZED (
    SELECT candidate.ordinality AS route_ordinal, candidate.value->'route' AS route,
           recipient.id AS recipient_id,
           split_part(candidate.value->'route'->>'full_jid', '/', 1) AS bare,
           (candidate.value->>'available')::bool AS available,
           (candidate.value->>'expects_active')::bool OR EXISTS (
               SELECT FROM privacy_active_sessions active
                WHERE active.owner_id=recipient.id
                  AND active.connection_id=(candidate.value->'route'->>'connection_id')::uuid
           ) AS expects_active
      FROM jsonb_array_elements($10::jsonb) WITH ORDINALITY candidate
      JOIN users recipient ON recipient.id=(candidate.value->'route'->>'account_id')::uuid
       AND recipient.auth_generation=(candidate.value->'route'->>'auth_generation')::bigint
       AND NOT recipient.is_disabled
       AND recipient.username || '@' || $4 = split_part(candidate.value->'route'->>'full_jid', '/', 1)
     WHERE candidate.value->'route'->>'full_jid' <> $2
), candidates AS (
    SELECT route_ordinal, recipient_id, route, bare AS scope, expects_active,
           bare=$3 AS sibling
      FROM routes WHERE available AND (bare IN (SELECT contact_jid FROM subscribers)
           OR ($9 AND bare=$3))
    UNION
    SELECT routes.route_ordinal, routes.recipient_id, routes.route, directed.value->>'scope',
           routes.expects_active, false
      FROM jsonb_array_elements($11::jsonb) directed(value)
      JOIN routes ON (routes.route - 'node_id') = ((directed.value->'route') - 'node_id')
    UNION
    SELECT NULL, NULL, NULL, contact_jid, false, false FROM subscribers
     WHERE split_part(contact_jid, '@', 2) <> $4 AND contact_jid <> $4
    UNION
    SELECT NULL, NULL, NULL, unnest($12::text[]), false, false
), audience AS MATERIALIZED (
    SELECT *, row_number() OVER (ORDER BY route_ordinal NULLS LAST, scope, sibling DESC) AS position
      FROM candidates
), requested AS (
    SELECT audience.position*2 AS position, source.id AS owner_id, source.connection_id,
           COALESCE(source.suspended_list, $8::text) IS NOT NULL AS expects_active,
           split_part(audience.scope, '/', 1) AS peer_bare
      FROM audience CROSS JOIN source
    UNION ALL
    SELECT position*2+1, recipient_id, (route->>'connection_id')::uuid,
           expects_active, $3
      FROM audience WHERE recipient_id IS NOT NULL
), privacy_active_sessions AS (
    SELECT active.owner_id, active.connection_id, active.list_name, active.expires_at
      FROM privacy_active_sessions active
     WHERE NOT EXISTS (SELECT FROM source WHERE $7 IS NOT NULL
                       AND source.id=active.owner_id AND source.connection_id=active.connection_id)
       AND NOT EXISTS (SELECT FROM source WHERE $7 IS NULL AND $8 IS NOT NULL
                       AND source.id=active.owner_id AND source.connection_id=active.connection_id
                       AND active.list_name <> $8)
    UNION ALL
    SELECT id, connection_id, suspended_list, 'infinity'::timestamptz
      FROM source WHERE suspended_list IS NOT NULL
), block_facts AS (
    SELECT owner_id, array_agg(blocked_jid::text) AS patterns
      FROM blocked_jids
     WHERE owner_id=$1 OR owner_id IN (SELECT recipient_id FROM audience)
     GROUP BY owner_id
)";
