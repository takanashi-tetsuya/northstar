//! Direct-message commit policy. Acquire the existing sorted account locks first,
//! then read blocks (whose writers take exclusive account locks) and sample all
//! privacy selectors, rules, roster and archive facts in one statement. Only then
//! may admission claim an identity or write an archive, spool or outbox projection.
//! No privacy, roster or block-policy locks are added to the account lock order.
//! Remote reachability is only a route hint; the receiving peer owns its live
//! resource check and the account default still governs any degraded admission.

use anyhow::Result;
use northstar_archive_postgres::{decide_archive_admission, ARCHIVE_ADMISSION_FACTS};
use northstar_message_core::{
    ActorGenerationFence, ArchiveCandidate, DirectMessagePolicy, DirectPolicyDenial,
    DirectSpoolEligibility, PrivacySelection,
};
use northstar_message_postgres::offline::OfflineAuthorization;
use northstar_roster_postgres::{
    privacy::{privacy_denies_from_facts, PRIVACY_DECISION_FACTS},
    roster::is_blocked_for_account_in_transaction,
};
use northstar_xep_0016::PrivacyStanzaKind;
use northstar_xmpp_types::jid::CanonicalJid;
use sqlx::{Postgres, Row, Transaction};
use std::future::Future;
use std::pin::Pin;
use uuid::Uuid;

pub(super) async fn actor_generation_matches(
    transaction: &mut Transaction<'_, Postgres>,
    fence: Option<ActorGenerationFence>,
) -> Result<bool> {
    let Some(fence) = fence else {
        return Ok(true);
    };
    Ok(sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM users WHERE id=$1 AND auth_generation=$2 AND NOT is_disabled)",
    )
    .bind(fence.account_id)
    .bind(fence.auth_generation)
    .fetch_one(&mut **transaction)
    .await?)
}

pub(super) struct CommitPolicy<'a> {
    pub(super) direct: DirectMessagePolicy<'a>,
    pub(super) sender: Option<Uuid>,
    pub(super) recipient: Option<Uuid>,
}

pub(super) struct PolicyFacts {
    pub(super) archives: Vec<bool>,
    pub(super) default_denies: bool,
}

pub(super) struct OfflineCommitPolicy<'a> {
    pub(super) policy: CommitPolicy<'a>,
    pub(super) fence: Option<ActorGenerationFence>,
}

impl OfflineAuthorization for OfflineCommitPolicy<'_> {
    fn actor_id(&self) -> Option<Uuid> {
        self.policy.sender
    }

    fn check<'tx>(
        &'tx self,
        transaction: &'tx mut Transaction<'_, Postgres>,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'tx>> {
        Box::pin(async move {
            if !actor_generation_matches(transaction, self.fence).await? {
                return Err(DirectPolicyDenial::ActorUnavailable.into());
            }
            self.policy.read(transaction, &[]).await?;
            Ok(())
        })
    }
}

struct PrivacyRequest<'a> {
    owner: Uuid,
    selection: Option<PrivacySelection>,
    peer: &'a CanonicalJid,
}

impl CommitPolicy<'_> {
    pub(super) async fn read(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        candidates: &[ArchiveCandidate<'_>],
    ) -> Result<PolicyFacts> {
        let from = CanonicalJid::parse(self.direct.from)?;
        let to = CanonicalJid::parse(self.direct.to)?;
        if let Some(sender) = self.sender {
            if is_blocked_for_account_in_transaction(
                transaction,
                sender,
                &from.bare(),
                self.direct.to,
            )
            .await?
            {
                return Err(DirectPolicyDenial::OutboundBlock.into());
            }
        }
        let mut requests = Vec::new();
        if let Some(sender) = self.sender {
            requests.push(PrivacyRequest {
                owner: sender,
                selection: self.direct.sender,
                peer: &to,
            });
        }
        if let Some(recipient) = self.recipient {
            requests.push(PrivacyRequest {
                owner: recipient,
                selection: None,
                peer: &from,
            });
            requests.extend(self.direct.recipient_sessions.iter().map(|selection| {
                PrivacyRequest {
                    owner: recipient,
                    selection: Some(*selection),
                    peer: &from,
                }
            }));
        }
        let (privacy, archives) = read_policy_snapshot(transaction, &requests, candidates).await?;
        let (sender_denies, recipient_privacy) = if self.sender.is_some() {
            (privacy[0], &privacy[1..])
        } else {
            (false, privacy.as_slice())
        };
        if sender_denies {
            return Err(DirectPolicyDenial::OutboundPrivacy.into());
        }
        if let Some(recipient) = self.recipient {
            if is_blocked_for_account_in_transaction(
                transaction,
                recipient,
                &to.bare(),
                self.direct.from,
            )
            .await?
            {
                return Err(DirectPolicyDenial::RecipientBlock.into());
            }
        }
        let default_denies = recipient_privacy.first().copied().unwrap_or(false);
        if !recipient_allows(recipient_privacy, self.direct.remote_recipient_route) {
            return Err(DirectPolicyDenial::RecipientPrivacy.into());
        }
        Ok(PolicyFacts {
            archives,
            default_denies,
        })
    }
}

fn recipient_allows(privacy: &[bool], remote_route: bool) -> bool {
    match privacy {
        [] => true,
        [default] => remote_route || !default,
        [_, sessions @ ..] => sessions.iter().any(|denies| !denies),
    }
}

pub(super) fn spool_eligibility(
    requested: DirectSpoolEligibility,
    default_denies: bool,
) -> DirectSpoolEligibility {
    if default_denies {
        DirectSpoolEligibility::LiveOnly
    } else {
        requested
    }
}

/// Collect both fact sets from one statement; positive ordinality and the
/// negated join key keep their rows disjoint without multiplying either set.
async fn read_policy_snapshot(
    transaction: &mut Transaction<'_, Postgres>,
    privacy: &[PrivacyRequest<'_>],
    candidates: &[ArchiveCandidate<'_>],
) -> Result<(Vec<bool>, Vec<bool>)> {
    let mut archive_owners = Vec::with_capacity(candidates.len());
    let mut archive_full = Vec::with_capacity(candidates.len());
    let mut archive_bare = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        let peer = CanonicalJid::parse(candidate.projection.peer_jid)?;
        archive_owners.push(candidate.projection.owner_id);
        archive_full.push(peer.to_string());
        archive_bare.push(peer.bare());
    }
    let mut privacy_owners = Vec::with_capacity(privacy.len());
    let mut connections = Vec::with_capacity(privacy.len());
    let mut expects_active = Vec::with_capacity(privacy.len());
    let mut peer_bare = Vec::with_capacity(privacy.len());
    for request in privacy {
        privacy_owners.push(request.owner);
        connections.push(request.selection.map(|selection| selection.connection_id));
        expects_active.push(
            request
                .selection
                .is_some_and(|selection| selection.expects_active),
        );
        peer_bare.push(request.peer.bare());
    }
    let statement = format!(
        "WITH requested AS (
             SELECT * FROM unnest($4::uuid[], $5::uuid[], $6::bool[], $7::text[]) WITH ORDINALITY
                AS input(owner_id, connection_id, expects_active, peer_bare, position)
         ), privacy AS ({PRIVACY_DECISION_FACTS}), archive AS ({ARCHIVE_ADMISSION_FACTS})
         SELECT privacy.*, archive.* FROM privacy FULL JOIN archive
           ON privacy.privacy_position = -archive.archive_position
         ORDER BY privacy_position NULLS LAST, item_order, archive_position"
    );
    let rows = sqlx::query(sqlx::AssertSqlSafe(statement))
        .bind(archive_owners)
        .bind(archive_full)
        .bind(archive_bare)
        .bind(privacy_owners)
        .bind(connections)
        .bind(expects_active)
        .bind(peer_bare)
        .fetch_all(&mut **transaction)
        .await?;
    let (privacy_rows, archive_rows): (Vec<_>, Vec<_>) = rows
        .into_iter()
        .partition(|row| row.get::<Option<i64>, _>("privacy_position").is_some());
    let decisions = privacy_rows
        .chunk_by(|left, right| {
            left.get::<i64, _>("privacy_position") == right.get::<i64, _>("privacy_position")
        })
        .zip(privacy)
        .map(|(rows, request)| {
            privacy_denies_from_facts(rows, &request.peer.to_string(), PrivacyStanzaKind::Message)
        })
        .collect::<Result<Vec<_>>>()?;
    anyhow::ensure!(
        decisions.len() == privacy.len(),
        "incomplete message privacy facts"
    );
    let archive = archive_rows
        .into_iter()
        .map(decide_archive_admission)
        .collect::<Result<Vec<_>>>()?;
    anyhow::ensure!(
        archive.len() == candidates.len(),
        "incomplete message archive facts"
    );
    Ok((decisions, archive))
}

#[cfg(test)]
mod tests;
