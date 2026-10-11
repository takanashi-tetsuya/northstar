//! XEP-0045 admin IQ batch parsing and classification.

use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum MucAdminMutationKind {
    AffiliationBatch,
    Role,
}

impl MucAdminMutationKind {
    pub(super) fn requires_affiliation_batch(self) -> bool {
        matches!(self, Self::AffiliationBatch)
    }
}

// Each committed projection needs one receipt ordinal. The transaction writer
// also bounds the expanded audience, which can be larger than the IQ itself.
pub(in crate::xmpp::protocol) const MAX_MUC_ADMIN_BATCH_ITEMS: usize = 63;
pub(super) const MUC_ADMIN_NS: &str = "http://jabber.org/protocol/muc#admin";

#[derive(Debug, Eq, PartialEq)]
pub(super) enum MucAdminChange {
    Affiliation {
        target_bare_jid: String,
        affiliation: String,
    },
    Role {
        target_nick: String,
        role: String,
    },
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct MucAdminItem {
    pub(super) change: MucAdminChange,
    pub(super) reason: Option<String>,
}

#[derive(Debug, Eq, PartialEq)]
pub(in crate::xmpp::protocol) struct MucAdminBatch {
    pub(super) items: Vec<MucAdminItem>,
}

impl MucAdminBatch {
    pub(in crate::xmpp::protocol) fn service_changes(
        &self,
        local_domain: &str,
    ) -> std::result::Result<Vec<MucAdminBatchChange>, MucAdminParseError> {
        self.items
            .iter()
            .map(|item| match &item.change {
                MucAdminChange::Affiliation {
                    target_bare_jid,
                    affiliation,
                } => {
                    let (localpart, domain) = target_bare_jid
                        .split_once('@')
                        .ok_or(MucAdminParseError::JidMalformed)?;
                    let target = if domain == local_domain {
                        MucAffiliationTarget::LocalUsername(localpart.to_owned())
                    } else {
                        MucAffiliationTarget::FederatedBareJid(target_bare_jid.clone())
                    };
                    Ok(MucAdminBatchChange::Affiliation {
                        target,
                        affiliation: affiliation.clone(),
                        reason: item.reason.clone(),
                    })
                }
                MucAdminChange::Role { target_nick, role } => Ok(MucAdminBatchChange::Role {
                    target_nick: target_nick.clone(),
                    role: role.clone(),
                    reason: item.reason.clone(),
                }),
            })
            .collect()
    }
}

pub(in crate::xmpp::protocol) fn muc_admin_batch_error(
    outcome: MucAdminBatchOutcome,
) -> Option<&'static str> {
    match outcome {
        MucAdminBatchOutcome::Applied | MucAdminBatchOutcome::Replay => None,
        MucAdminBatchOutcome::DuplicateTarget => Some("bad-request"),
        MucAdminBatchOutcome::TooManyProjections => Some("resource-constraint"),
        MucAdminBatchOutcome::LastOwner
        | MucAdminBatchOutcome::Stale
        | MucAdminBatchOutcome::Destroyed
        | MucAdminBatchOutcome::Conflict => Some("conflict"),
        MucAdminBatchOutcome::MissingTarget => Some("item-not-found"),
        MucAdminBatchOutcome::Unauthorized => Some("forbidden"),
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(in crate::xmpp::protocol) enum MucAdminParseError {
    BadRequest,
    JidMalformed,
    NotAcceptable,
}

pub(in crate::xmpp::protocol) struct MucAdminRawItem<'a> {
    pub jid: Option<&'a str>,
    pub nick: Option<&'a str>,
    pub affiliation: Option<&'a str>,
    pub role: Option<&'a str>,
    pub reason: Option<&'a str>,
}

/// Normalize targets before a batch reaches either the local or clustered
/// writer. A full JID and its bare form address the same affiliation target;
/// duplicate normalized targets must not acquire order-dependent semantics.
pub(in crate::xmpp::protocol) fn parse_muc_admin_batch(
    items: &[Node<'_, '_>],
) -> std::result::Result<MucAdminBatch, MucAdminParseError> {
    if items.iter().any(|item| {
        item.tag_name().name() != "item"
            || item.tag_name().namespace() != Some(MUC_ADMIN_NS)
            || item.children().any(|child| {
                child.is_element()
                    && child.tag_name().name() == "reason"
                    && child.tag_name().namespace() != Some(MUC_ADMIN_NS)
            })
    }) {
        return Err(MucAdminParseError::BadRequest);
    }
    let raw = items
        .iter()
        .map(|item| MucAdminRawItem {
            jid: item.attribute("jid"),
            nick: item.attribute("nick"),
            affiliation: item.attribute("affiliation"),
            role: item.attribute("role"),
            reason: child_text(*item, "reason"),
        })
        .collect::<Vec<_>>();
    parse_muc_admin_raw_items(&raw)
}

pub(in crate::xmpp::protocol) fn parse_muc_admin_raw_items(
    items: &[MucAdminRawItem<'_>],
) -> std::result::Result<MucAdminBatch, MucAdminParseError> {
    if items.is_empty() || items.len() > MAX_MUC_ADMIN_BATCH_ITEMS {
        return Err(MucAdminParseError::BadRequest);
    }
    let mut parsed = Vec::with_capacity(items.len());
    let mut affiliation_targets = std::collections::HashSet::new();
    let mut role_targets = std::collections::HashSet::new();
    for item in items {
        if item.reason.is_some_and(|reason| reason.len() > 4096) {
            return Err(MucAdminParseError::NotAcceptable);
        }
        let change = match (item.affiliation, item.role) {
            (Some(affiliation), None) => {
                if !matches!(
                    affiliation,
                    "owner" | "admin" | "member" | "outcast" | "none"
                ) {
                    return Err(MucAdminParseError::BadRequest);
                }
                let target = item.jid.ok_or(MucAdminParseError::BadRequest)?;
                let target =
                    CanonicalJid::parse(target).map_err(|_| MucAdminParseError::JidMalformed)?;
                if target.localpart().is_none() {
                    return Err(MucAdminParseError::JidMalformed);
                }
                let target_bare_jid = target.bare();
                if !affiliation_targets.insert(target_bare_jid.clone()) {
                    return Err(MucAdminParseError::BadRequest);
                }
                MucAdminChange::Affiliation {
                    target_bare_jid,
                    affiliation: affiliation.to_owned(),
                }
            }
            (None, Some(role)) => {
                if !matches!(role, "moderator" | "participant" | "visitor" | "none") {
                    return Err(MucAdminParseError::BadRequest);
                }
                let nick = item.nick.ok_or(MucAdminParseError::BadRequest)?;
                let target_nick =
                    prepare_muc_nick(nick).map_err(|_| MucAdminParseError::JidMalformed)?;
                if !role_targets.insert(target_nick.clone()) {
                    return Err(MucAdminParseError::BadRequest);
                }
                MucAdminChange::Role {
                    target_nick,
                    role: role.to_owned(),
                }
            }
            _ => return Err(MucAdminParseError::BadRequest),
        };
        parsed.push(MucAdminItem {
            change,
            reason: item.reason.map(str::to_owned),
        });
    }
    Ok(MucAdminBatch { items: parsed })
}

pub(super) fn classify_muc_admin_items(items: &[Node<'_, '_>]) -> Result<MucAdminMutationKind, ()> {
    if items.is_empty()
        || items.len() > MAX_MUC_ADMIN_BATCH_ITEMS
        || items.iter().any(|node| node.tag_name().name() != "item")
    {
        return Err(());
    }
    if items.iter().any(|item| {
        item.attribute("affiliation").is_some() == item.attribute("role").is_some()
            || (item.attribute("affiliation").is_some() && item.attribute("jid").is_none())
            || (item.attribute("role").is_some() && item.attribute("nick").is_none())
    }) {
        return Err(());
    }
    let affiliation_count = items
        .iter()
        .filter(|item| item.attribute("affiliation").is_some())
        .count();
    let role_count = items.len().saturating_sub(affiliation_count);
    if (affiliation_count > 0 && role_count > 0) || role_count > 1 {
        // Affiliation batches are atomic, while role changes operate on one
        // live occupant. Do not admit an ambiguous mixed request.
        return Err(());
    }
    if affiliation_count > 0 {
        Ok(MucAdminMutationKind::AffiliationBatch)
    } else {
        Ok(MucAdminMutationKind::Role)
    }
}

/// Returns whether `recipient` is the exact live occupancy being removed.
///
/// A bare/full JID comparison is insufficient here: a delayed administrative
/// action must not make a replacement connection or a new occupant epoch look
/// like the removed actor.  The removal paths use this when they deliver the
/// target's self-presence separately from the room audience.
pub(super) fn is_exact_muc_removal_target(
    recipient: &crate::state::MucOccupant,
    target: &crate::state::MucOccupant,
) -> bool {
    crate::state::muc_departure_identity_matches(
        recipient,
        &target.full_jid,
        target.connection_id,
        target.cluster_epoch,
    )
}
