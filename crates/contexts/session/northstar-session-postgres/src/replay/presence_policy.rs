//! Query pending presence requests and apply consistent privacy and roster policy snapshots.

use super::*;
use northstar_session_application::replay::pending_presence::PendingPresenceAuthority;
use northstar_xep_0016::{
    PrivacyAction, PrivacyItem, PrivacyList, PrivacyMatchType, PrivacyStanzaKind,
};
use northstar_xmpp_types::jid::CanonicalJid;

#[cfg(test)]
pub(super) async fn pending_presence_replay_page_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    recipient_id: Uuid,
    local_domain: &str,
    after: Option<&PendingPresenceCursor>,
) -> Result<Vec<PendingPresenceReplay>> {
    pending_presence_rows(transaction, recipient_id, local_domain, after, false).await
}

async fn pending_presence_rows(
    transaction: &mut Transaction<'_, Postgres>,
    recipient_id: Uuid,
    local_domain: &str,
    cursor: Option<&PendingPresenceCursor>,
    exact: bool,
) -> Result<Vec<PendingPresenceReplay>> {
    let after_created_at = cursor.map(|cursor| cursor.created_at);
    let after_source = cursor.map_or(0_i16, |cursor| cursor.source);
    let after_key = cursor.map_or("", |cursor| cursor.key.as_str());
    let rows = sqlx::query(
        "WITH pending AS ( \
             SELECT p.created_at,0::SMALLINT AS source,p.requester_id::TEXT AS cursor_key, \
                    u.username || '@' || $6 AS requester,p.stanza,u.auth_generation \
               FROM pending_presence_subscriptions p \
               JOIN users u ON u.id=p.requester_id AND NOT u.is_disabled \
              WHERE p.recipient_id=$1 \
             UNION ALL \
             SELECT p.created_at,1::SMALLINT AS source,p.from_jid AS cursor_key, \
                    p.from_jid AS requester,p.stanza,NULL::BIGINT \
               FROM federated_presence_pending p WHERE p.recipient_id=$1 \
         ) \
         SELECT created_at,source,cursor_key,requester,stanza,auth_generation FROM pending \
          WHERE CASE WHEN $7 THEN (created_at,source,cursor_key) = ($2,$3,$4) \
             ELSE $2::TIMESTAMPTZ IS NULL OR (created_at,source,cursor_key) > ($2,$3,$4) END \
          ORDER BY created_at,source,cursor_key LIMIT $5",
    )
    .bind(recipient_id)
    .bind(after_created_at)
    .bind(after_source)
    .bind(after_key)
    .bind(REPLAY_PAGE_SIZE)
    .bind(local_domain)
    .bind(exact)
    .fetch_all(&mut **transaction)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| PendingPresenceReplay {
            requester: row.get("requester"),
            requester_auth_generation: row.get("auth_generation"),
            stanza: row.get("stanza"),
            cursor: PendingPresenceCursor {
                created_at: row.get("created_at"),
                source: row.get("source"),
                key: row.get("cursor_key"),
            },
        })
        .collect())
}

#[derive(Clone, Debug, Default)]
pub(super) struct ReplayRosterPolicy {
    pub(super) subscription: String,
    pub(super) groups: Vec<String>,
}

pub(super) async fn replay_policy_snapshot(
    transaction: &mut Transaction<'_, Postgres>,
    owner_id: Uuid,
    active_privacy_list: Option<&str>,
    candidates: &[String],
) -> Result<(
    Vec<String>,
    Option<PrivacyList>,
    HashMap<String, ReplayRosterPolicy>,
)> {
    let blocked_patterns = sqlx::query_scalar::<_, String>(
        "SELECT blocked_jid FROM blocked_jids WHERE owner_id=$1 ORDER BY blocked_jid",
    )
    .bind(owner_id)
    .fetch_all(&mut **transaction)
    .await?;
    let selected = match active_privacy_list {
        Some(name) => Some(name.to_owned()),
        None => {
            sqlx::query_scalar::<_, String>(
                "SELECT list_name FROM privacy_default_lists WHERE owner_id=$1",
            )
            .bind(owner_id)
            .fetch_optional(&mut **transaction)
            .await?
        }
    };
    let privacy = if let Some(selected) = selected {
        let rows = sqlx::query(
            "SELECT l.name,i.item_order,i.action,i.match_type,i.match_value,
                    i.filter_message,i.filter_iq,i.filter_presence_in,i.filter_presence_out
               FROM privacy_lists l
               LEFT JOIN privacy_list_items i
                 ON i.owner_id=l.owner_id AND i.list_name=l.name
              WHERE l.owner_id=$1 AND l.name=$2
              ORDER BY i.item_order",
        )
        .bind(owner_id)
        .bind(&selected)
        .fetch_all(&mut **transaction)
        .await?;
        anyhow::ensure!(
            !rows.is_empty(),
            "selected privacy list is unavailable during offline replay"
        );
        let mut rules = Vec::new();
        for row in rows {
            let Some(action) = row.try_get::<Option<String>, _>("action")? else {
                // A valid list with no items is represented by the LEFT JOIN
                // row and permits all traffic.
                continue;
            };
            let match_type: Option<String> = row.try_get("match_type")?;
            rules.push(PrivacyItem {
                order: u32::try_from(row.try_get::<i64, _>("item_order")?).map_err(|_| {
                    anyhow::anyhow!("stored privacy-list order exceeds xs:unsignedInt")
                })?,
                action: if action == "allow" {
                    PrivacyAction::Allow
                } else {
                    PrivacyAction::Deny
                },
                match_type: match_type.as_deref().map(|value| match value {
                    "jid" => PrivacyMatchType::Jid,
                    "group" => PrivacyMatchType::Group,
                    _ => PrivacyMatchType::Subscription,
                }),
                match_value: row.try_get::<Option<String>, _>("match_value")?,
                message: row.try_get::<bool, _>("filter_message")?,
                iq: row.try_get::<bool, _>("filter_iq")?,
                presence_in: row.try_get::<bool, _>("filter_presence_in")?,
                presence_out: row.try_get::<bool, _>("filter_presence_out")?,
            });
        }
        Some(PrivacyList {
            name: selected,
            items: rules,
        })
    } else {
        None
    };

    let mut candidate_bares = candidates
        .iter()
        .map(|candidate| {
            northstar_xmpp_types::jid::CanonicalJid::parse(candidate).map(|jid| jid.bare())
        })
        .collect::<Result<Vec<_>>>()?;
    candidate_bares.sort_unstable();
    candidate_bares.dedup();
    let roster_rows = sqlx::query(
        "SELECT contact_jid,subscription,groups FROM roster_items
          WHERE owner_id=$1 AND contact_jid=ANY($2::TEXT[])",
    )
    .bind(owner_id)
    .bind(&candidate_bares)
    .fetch_all(&mut **transaction)
    .await?;
    let mut roster = HashMap::with_capacity(roster_rows.len());
    for row in roster_rows {
        let groups = row
            .try_get::<Option<serde_json::Value>, _>("groups")?
            .and_then(|value| serde_json::from_value::<Vec<String>>(value).ok())
            .unwrap_or_default();
        roster.insert(
            row.get("contact_jid"),
            ReplayRosterPolicy {
                subscription: row.get("subscription"),
                groups,
            },
        );
    }
    Ok((blocked_patterns, privacy, roster))
}

pub(super) fn replay_policy_denies(
    owner_bare_jid: &str,
    candidate: &str,
    kind: northstar_xep_0016::PrivacyStanzaKind,
    blocked_patterns: &[String],
    privacy: &Option<PrivacyList>,
    roster: &HashMap<String, ReplayRosterPolicy>,
) -> Result<bool> {
    let owner = northstar_xmpp_types::jid::CanonicalJid::parse_bare(owner_bare_jid)?;
    let candidate = northstar_xmpp_types::jid::CanonicalJid::parse(candidate)?;
    let same_account = candidate.localpart().is_some() && candidate.bare() == owner.bare();
    if !same_account
        && blocked_patterns
            .iter()
            .any(|pattern| northstar_xmpp_types::jid_scope_matches(pattern, &candidate.to_string()))
    {
        return Ok(true);
    }
    let entry = roster.get(&candidate.bare());
    Ok(privacy.as_ref().is_some_and(|list| {
        northstar_xep_0016::list_denies(
            list,
            &candidate.to_string(),
            entry.map(|entry| entry.subscription.as_str()),
            entry.map_or(&[], |entry| entry.groups.as_slice()),
            kind,
        )
    }))
}

/// Read one bounded union page using the exact connection's durable selector.
pub(crate) async fn pending_presence_replay_page_filtered(
    pool: &PgPool,
    authority: PendingPresenceAuthority<'_>,
    local_domain: &str,
    after: Option<&PendingPresenceCursor>,
) -> Result<PendingPresenceReplayPage> {
    pending_presence_snapshot(pool, authority, local_domain, after, false).await
}

/// Recheck the exact creation identity, requester incarnation and stored bytes.
pub(crate) async fn pending_presence_is_current(
    pool: &PgPool,
    authority: PendingPresenceAuthority<'_>,
    local_domain: &str,
    pending: &PendingPresenceReplay,
) -> Result<bool> {
    let snapshot =
        pending_presence_snapshot(pool, authority, local_domain, Some(&pending.cursor), true)
            .await?;
    Ok(snapshot.items.first() == Some(pending))
}

async fn pending_presence_snapshot(
    pool: &PgPool,
    authority: PendingPresenceAuthority<'_>,
    local_domain: &str,
    cursor: Option<&PendingPresenceCursor>,
    exact: bool,
) -> Result<PendingPresenceReplayPage> {
    let full_jid = CanonicalJid::parse(&authority.route.full_jid)?;
    let local_domain = northstar_xmpp_types::jid::prepare_domainpart(local_domain)?;
    anyhow::ensure!(
        full_jid.domainpart() == local_domain
            && full_jid.resourcepart().is_some()
            && !authority.route.connection_id.is_nil(),
        "pending presence replay requires a bound local resource"
    );
    let mut transaction = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *transaction)
        .await?;
    let recipient_id = authority.route.recipient_id;
    let selector = sqlx::query(
        "SELECT active.list_name, active.expires_at > statement_timestamp() AS active_valid
           FROM users recipient
           LEFT JOIN privacy_active_sessions active
             ON active.owner_id=recipient.id AND active.connection_id=$4
          WHERE recipient.id=$1 AND recipient.auth_generation=$2
            AND recipient.username=$3 AND NOT recipient.is_disabled",
    )
    .bind(recipient_id)
    .bind(authority.route.auth_generation)
    .bind(full_jid.localpart())
    .bind(authority.route.connection_id)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(selector) = selector else {
        return Ok(empty_pending_page());
    };
    let active: Option<String> = selector.try_get("list_name")?;
    let valid: Option<bool> = selector.try_get("active_valid")?;
    if valid == Some(false) || (authority.expects_active && active.is_none()) {
        return Ok(empty_pending_page());
    }
    let rows =
        pending_presence_rows(&mut transaction, recipient_id, &local_domain, cursor, exact).await?;
    let next_cursor = rows.last().map(|row| row.cursor.clone());
    let complete = rows.len() < REPLAY_PAGE_SIZE as usize;
    let candidates = rows
        .iter()
        .map(|row| row.requester.clone())
        .collect::<Vec<_>>();
    let (blocked, privacy, roster) = replay_policy_snapshot(
        &mut transaction,
        recipient_id,
        active.as_deref(),
        &candidates,
    )
    .await?;
    let owner_bare = full_jid.bare();
    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        if !replay_policy_denies(
            &owner_bare,
            &row.requester,
            PrivacyStanzaKind::PresenceIn,
            &blocked,
            &privacy,
            &roster,
        )? {
            items.push(row);
        }
    }
    transaction.commit().await?;
    Ok(PendingPresenceReplayPage {
        items,
        next_cursor,
        complete,
    })
}

fn empty_pending_page() -> PendingPresenceReplayPage {
    PendingPresenceReplayPage {
        items: Vec::new(),
        next_cursor: None,
        complete: true,
    }
}
