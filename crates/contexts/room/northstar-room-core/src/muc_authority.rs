//! Checked MUC authority facts projected from the existing string commands.

use anyhow::Result;
use northstar_xep_0045::{Affiliation, OccupantNick, Role};
use northstar_xmpp_types::{prepare_domainpart, CanonicalJid};
use uuid::Uuid;

use crate::{ClusterMucOccupancyTarget, MucActorAuthority, MucActorPrincipal};

/// A transition of one exact MUC occupancy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MucOccupancyTransition {
    Suspend,
    Resume,
    Rebind,
    Leave,
}

impl MucOccupancyTransition {
    /// Return the existing SQL and request digest spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Suspend => "suspend",
            Self::Resume => "resume",
            Self::Rebind => "rebind",
            Self::Leave => "leave",
        }
    }

    /// Accept an exact transition spelling.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "suspend" => Some(Self::Suspend),
            "resume" => Some(Self::Resume),
            "rebind" => Some(Self::Rebind),
            "leave" => Some(Self::Leave),
            _ => None,
        }
    }
}

/// A transport principal whose identity matches the actor's bare JID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VerifiedMucPrincipal {
    Local {
        user_id: Uuid,
        local_domain: String,
    },
    Federated {
        bare_jid: CanonicalJid,
        authenticated_domain: String,
    },
}

/// Checked transport identity and expected room policy for a MUC actor.
/// The database still checks current occupancy and policy under its locks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedMucActor {
    pub actor_scope: CanonicalJid,
    pub full_jid: CanonicalJid,
    pub nick: OccupantNick,
    pub expected_role: Role,
    pub expected_affiliation: Affiliation,
    pub principal: VerifiedMucPrincipal,
}

impl MucActorAuthority {
    /// Project the authenticated scope and parse the expected nickname and policy.
    pub fn verified(&self, configured_domain: &str) -> Option<VerifiedMucActor> {
        let actor_scope = CanonicalJid::parse_bare(&self.actor_scope).ok()?;
        if actor_scope.to_string() != self.actor_scope {
            return None;
        }
        let full_jid = CanonicalJid::parse(&self.full_jid).ok()?;
        if full_jid.resourcepart().is_none()
            || full_jid.to_string() != self.full_jid
            || full_jid.to_bare() != actor_scope
        {
            return None;
        }
        let principal = match &self.principal {
            MucActorPrincipal::Local {
                user_id,
                local_domain,
            } => {
                let local_domain = prepare_domainpart(local_domain).ok()?;
                let configured_domain = prepare_domainpart(configured_domain).ok()?;
                if local_domain != configured_domain || actor_scope.domainpart() != local_domain {
                    return None;
                }
                VerifiedMucPrincipal::Local {
                    user_id: *user_id,
                    local_domain,
                }
            }
            MucActorPrincipal::Federated {
                bare_jid,
                authenticated_domain,
            } => {
                let authenticated_domain = prepare_domainpart(authenticated_domain).ok()?;
                // The scope already proves that this exact spelling is canonical and bare.
                if bare_jid != &self.actor_scope || actor_scope.domainpart() != authenticated_domain
                {
                    return None;
                }
                VerifiedMucPrincipal::Federated {
                    bare_jid: actor_scope.clone(),
                    authenticated_domain,
                }
            }
        };
        Some(VerifiedMucActor {
            actor_scope,
            full_jid,
            nick: OccupantNick::parse(&self.nick).ok()?,
            expected_role: Role::from_str_name(&self.expected_role)?,
            expected_affiliation: Affiliation::from_str_name(&self.expected_affiliation)?,
            principal,
        })
    }
}

impl ClusterMucOccupancyTarget {
    /// Parse the nickname carried by this exact target.
    pub fn occupant_nick(&self) -> Result<OccupantNick> {
        Ok(OccupantNick::parse(&self.nick)?)
    }

    /// Parse the real JID carried by this exact target.
    pub fn full_jid(&self) -> Result<CanonicalJid> {
        CanonicalJid::parse(&self.full_jid)
    }
}

#[cfg(test)]
mod tests;
