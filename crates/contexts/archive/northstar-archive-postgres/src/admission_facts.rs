//! Preference inputs for all owners of one accepted personal message.

use anyhow::Result;
use northstar_archive_core::{decide_mam_archive_admission, MamArchiveAdmissionFacts};
use sqlx::{postgres::PgRow, Postgres, Row, Transaction};
use uuid::Uuid;

pub const ARCHIVE_ADMISSION_FACTS: &str = "SELECT
    (SELECT policy FROM mam_preference_jids
      WHERE user_id=candidate.owner_id AND jid=candidate.full_jid) AS full_policy,
    (SELECT policy FROM mam_preference_jids
      WHERE user_id=candidate.owner_id AND jid=candidate.bare_jid) AS bare_policy,
    (SELECT default_policy FROM mam_preferences WHERE user_id=candidate.owner_id) AS default_policy,
    EXISTS(SELECT 1 FROM roster_items WHERE roster_items.owner_id=candidate.owner_id
           AND contact_jid=candidate.bare_jid) AS roster_member,
    candidate.position AS archive_position
    FROM unnest($1::uuid[], $2::text[], $3::text[]) WITH ORDINALITY
         AS candidate(owner_id, full_jid, bare_jid, position)
    ORDER BY candidate.position";

pub fn decide_archive_admission(row: PgRow) -> Result<bool> {
    let full_policy: Option<String> = row.try_get("full_policy")?;
    let bare_policy: Option<String> = row.try_get("bare_policy")?;
    let default_policy: Option<String> = row.try_get("default_policy")?;
    Ok(decide_mam_archive_admission(MamArchiveAdmissionFacts {
        full_jid_policy: full_policy.as_deref(),
        bare_jid_policy: bare_policy.as_deref(),
        default_policy: default_policy.as_deref(),
        roster_member: row.try_get("roster_member")?,
    }))
}

/// Read one statement snapshot for the candidate owner/peer pairs, returning
/// decisions in the same order. Direction and stanza bytes stay with the
/// caller, which holds the account fences and owns the write transaction.
pub async fn archive_admission_facts_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
    candidates: &[(Uuid, &str)],
) -> Result<Vec<bool>> {
    if candidates.is_empty() {
        return Ok(Vec::new());
    }
    let mut owners = Vec::with_capacity(candidates.len());
    let mut full_jids = Vec::with_capacity(candidates.len());
    let mut bare_jids = Vec::with_capacity(candidates.len());
    for &(owner, peer) in candidates {
        let full = northstar_xmpp_types::jid::canonicalize(peer)?;
        bare_jids.push(northstar_xmpp_types::jid::canonical_bare_key(&full)?);
        full_jids.push(full);
        owners.push(owner);
    }
    sqlx::query(ARCHIVE_ADMISSION_FACTS)
        .bind(&owners)
        .bind(&full_jids)
        .bind(&bare_jids)
        .fetch_all(&mut **tx)
        .await?
        .into_iter()
        .map(decide_archive_admission)
        .collect()
}
