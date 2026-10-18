//! Query pending presence requests and apply consistent privacy and roster policy snapshots.

use super::*;

pub(super) async fn pending_presence_replay_page_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    recipient_id: Uuid,
    local_domain: &str,
    after: Option<&PendingPresenceCursor>,
) -> Result<Vec<PendingPresenceReplay>> {
    let after_created_at = after.map(|cursor| cursor.created_at);
    let after_source = after.map_or(0_i16, |cursor| cursor.source);
    let after_key = after.map_or("", |cursor| cursor.key.as_str());
    let rows = sqlx::query(
        "WITH pending AS ( \
             SELECT p.created_at,0::SMALLINT AS source,p.requester_id::TEXT AS cursor_key, \
                    u.username || '@' || $6 AS requester,p.stanza \
               FROM pending_presence_subscriptions p \
               JOIN users u ON u.id=p.requester_id \
              WHERE p.recipient_id=$1 \
             UNION ALL \
             SELECT p.created_at,1::SMALLINT AS source,p.from_jid AS cursor_key, \
                    p.from_jid AS requester,p.stanza \
               FROM federated_presence_pending p WHERE p.recipient_id=$1 \
         ) \
         SELECT created_at,source,cursor_key,requester,stanza FROM pending \
          WHERE $2::TIMESTAMPTZ IS NULL \
             OR (created_at,source,cursor_key) > ($2,$3,$4) \
          ORDER BY created_at,source,cursor_key LIMIT $5",
    )
    .bind(recipient_id)
    .bind(after_created_at)
    .bind(after_source)
    .bind(after_key)
    .bind(REPLAY_PAGE_SIZE)
    .bind(local_domain)
    .fetch_all(&mut **transaction)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| PendingPresenceReplay {
            requester: row.get("requester"),
            stanza: row.get("stanza"),
            cursor: PendingPresenceCursor {
                created_at: row.get("created_at"),
                source: row.get("source"),
                key: row.get("cursor_key"),
            },
        })
        .collect())
}

#[derive(Clone, Debug)]
pub(super) struct ReplayPrivacyRule {
    pub(super) deny: bool,
    pub(super) match_type: Option<String>,
    pub(super) match_value: Option<String>,
    pub(super) message: bool,
    pub(super) iq: bool,
    pub(super) presence_in: bool,
    pub(super) presence_out: bool,
}

#[derive(Clone, Debug)]
pub(super) enum ReplayPrivacyPolicy {
    None,
    Rules(Vec<ReplayPrivacyRule>),
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
    ReplayPrivacyPolicy,
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
            "SELECT l.name,i.action,i.match_type,i.match_value,
                    i.filter_message,i.filter_iq,i.filter_presence_in,i.filter_presence_out
               FROM privacy_lists l
               LEFT JOIN privacy_list_items i
                 ON i.owner_id=l.owner_id AND i.list_name=l.name
              WHERE l.owner_id=$1 AND l.name=$2
              ORDER BY i.item_order",
        )
        .bind(owner_id)
        .bind(selected)
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
            anyhow::ensure!(
                action == "allow" || action == "deny",
                "invalid privacy action in offline replay snapshot"
            );
            rules.push(ReplayPrivacyRule {
                deny: action == "deny",
                match_type: row.try_get::<Option<String>, _>("match_type")?,
                match_value: row.try_get::<Option<String>, _>("match_value")?,
                message: row.try_get::<bool, _>("filter_message")?,
                iq: row.try_get::<bool, _>("filter_iq")?,
                presence_in: row.try_get::<bool, _>("filter_presence_in")?,
                presence_out: row.try_get::<bool, _>("filter_presence_out")?,
            });
        }
        ReplayPrivacyPolicy::Rules(rules)
    } else {
        ReplayPrivacyPolicy::None
    };

    let mut candidate_bares = candidates
        .iter()
        .map(|candidate| crate::jid::CanonicalJid::parse(candidate).map(|jid| jid.bare()))
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
        let groups =
            serde_json::from_value::<Vec<String>>(row.try_get::<serde_json::Value, _>("groups")?)?;
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
    kind: super::super::PrivacyStanzaKind,
    blocked_patterns: &[String],
    privacy: &ReplayPrivacyPolicy,
    roster: &HashMap<String, ReplayRosterPolicy>,
) -> Result<bool> {
    let owner = crate::jid::CanonicalJid::parse_bare(owner_bare_jid)?;
    let candidate = crate::jid::CanonicalJid::parse(candidate)?;
    let same_account = candidate.localpart().is_some() && candidate.bare() == owner.bare();
    if !same_account
        && blocked_patterns
            .iter()
            .any(|pattern| super::super::blocked_jid_matches(pattern, &candidate.to_string()))
    {
        return Ok(true);
    }
    let rules = match privacy {
        ReplayPrivacyPolicy::None => return Ok(false),
        ReplayPrivacyPolicy::Rules(rules) => rules,
    };
    let roster = roster.get(&candidate.bare());
    for rule in rules {
        let stanza_matches = if !(rule.message || rule.iq || rule.presence_in || rule.presence_out)
        {
            true
        } else {
            match kind {
                super::super::PrivacyStanzaKind::Message => rule.message,
                super::super::PrivacyStanzaKind::Iq => rule.iq,
                super::super::PrivacyStanzaKind::PresenceIn => rule.presence_in,
                super::super::PrivacyStanzaKind::PresenceOut => rule.presence_out,
            }
        };
        if !stanza_matches {
            continue;
        }
        let entity_matches = match (rule.match_type.as_deref(), rule.match_value.as_deref()) {
            (None, None) => true,
            (Some("jid"), Some(value)) => {
                super::super::blocked_jid_matches(value, &candidate.to_string())
            }
            (Some("group"), Some(value)) => {
                roster.is_some_and(|entry| entry.groups.iter().any(|group| group == value))
            }
            (Some("subscription"), Some(value)) => {
                roster.map_or("none", |entry| entry.subscription.as_str()) == value
            }
            _ => false,
        };
        if entity_matches {
            return Ok(rule.deny);
        }
    }
    Ok(false)
}

/// A bounded union page of local and federated subscription requests whose
/// XEP-0191/XEP-0016 decision is derived from one repeatable-read snapshot.
/// Pending requests are intentionally not consumed: RFC 6121 shows the same
/// outstanding request once to each newly available resource.
pub async fn pending_presence_replay_page_filtered(
    pool: &PgPool,
    recipient_id: Uuid,
    owner_bare_jid: &str,
    local_domain: &str,
    active_privacy_list: Option<&str>,
    after: Option<&PendingPresenceCursor>,
) -> Result<PendingPresenceReplayPage> {
    let local_domain = crate::jid::prepare_domainpart(local_domain)?;
    let owner_bare_jid = crate::jid::canonicalize_bare(owner_bare_jid)?;
    let mut transaction = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *transaction)
        .await?;
    let rows = pending_presence_replay_page_in_transaction(
        &mut transaction,
        recipient_id,
        &local_domain,
        after,
    )
    .await?;
    let next_cursor = rows.last().map(|row| row.cursor.clone());
    let complete = rows.len() < REPLAY_PAGE_SIZE as usize;
    let candidates = rows
        .iter()
        .map(|row| row.requester.clone())
        .collect::<Vec<_>>();
    let (blocked_patterns, privacy, roster) = replay_policy_snapshot(
        &mut transaction,
        recipient_id,
        active_privacy_list,
        &candidates,
    )
    .await?;
    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        if !replay_policy_denies(
            &owner_bare_jid,
            &row.requester,
            super::super::PrivacyStanzaKind::PresenceIn,
            &blocked_patterns,
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
