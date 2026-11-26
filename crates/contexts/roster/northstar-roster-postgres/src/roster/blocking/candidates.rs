use super::HashSet;
use anyhow::Result;
use sqlx::{PgPool, Row};

/// Resolve a MUC broadcast's local blocked recipients with one indexed query,
/// rather than issuing one blocklist query per occupant. Returned values are
/// canonical bare account JIDs. Remote occupants are deliberately omitted;
/// their home server applies XEP-0191 to the room/nick sender.
pub async fn blocked_local_accounts_for_candidates(
    pool: &PgPool,
    local_domain: &str,
    occupant_jids: &[String],
    stanza_senders: &[String],
) -> Result<HashSet<String>> {
    let local_domain = northstar_xmpp_types::jid::prepare_domainpart(local_domain)?;
    let mut usernames = occupant_jids
        .iter()
        .filter_map(|jid| northstar_xmpp_types::jid::CanonicalJid::parse(jid).ok())
        .filter(|jid| jid.domainpart() == local_domain)
        .filter_map(|jid| jid.localpart().map(str::to_owned))
        .collect::<Vec<_>>();
    usernames.sort_unstable();
    usernames.dedup();
    if usernames.is_empty() || stanza_senders.is_empty() {
        return Ok(HashSet::new());
    }
    let senders = stanza_senders
        .iter()
        .map(|sender| northstar_xmpp_types::jid::CanonicalJid::parse(sender))
        .collect::<Result<Vec<_>>>()?;
    let mut lookup_keys = senders
        .iter()
        .flat_map(blocking_match_candidates)
        .collect::<Vec<_>>();
    lookup_keys.sort_unstable();
    lookup_keys.dedup();
    let rows = sqlx::query(
        "SELECT u.username, b.blocked_jid FROM users u \
         JOIN blocked_jids b ON b.owner_id=u.id \
         WHERE u.username=ANY($1::text[]) AND b.blocked_jid=ANY($2::text[])",
    )
    .bind(&usernames)
    .bind(&lookup_keys)
    .fetch_all(pool)
    .await?;
    let mut blocked = HashSet::new();
    for row in rows {
        let username: String = row.get("username");
        let pattern: String = row.get("blocked_jid");
        let owner = format!("{username}@{local_domain}");
        if senders.iter().any(|sender| {
            !(sender.localpart().is_some() && sender.bare() == owner)
                && blocked_jid_matches(&pattern, &sender.to_string())
        }) {
            blocked.insert(owner);
        }
    }
    Ok(blocked)
}

pub fn blocking_match_candidates(
    candidate: &northstar_xmpp_types::jid::CanonicalJid,
) -> Vec<String> {
    let mut candidates = Vec::with_capacity(4);
    if let Some(resource) = candidate.resourcepart() {
        candidates.push(candidate.to_string());
        if candidate.localpart().is_some() {
            candidates.push(candidate.bare());
        }
        candidates.push(format!("{}/{}", candidate.domainpart(), resource));
    } else if candidate.localpart().is_some() {
        candidates.push(candidate.bare());
    }
    candidates.push(candidate.domainpart().to_owned());
    candidates.sort_unstable();
    candidates.dedup();
    candidates
}

pub fn blocked_jid_matches(pattern: &str, candidate: &str) -> bool {
    northstar_xmpp_types::jid_scope_matches(pattern, candidate)
}
