//! Access policy for PEP retrieval and discovery.

use crate::PepNodeConfig;

#[derive(Clone, Copy, Debug)]
pub enum PepRequesterRelation<'a> {
    Owner,
    /// This requester's canonical bare JID.
    Other(&'a str),
    LocalAnonymous,
    Invalid,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct PepBlockFacts {
    pub owner_blocks_requester: bool,
    /// The reverse direction does not participate in the PEP node ACL.
    pub requester_blocks_owner: bool,
}

pub struct PepAccessFacts<'a> {
    pub requester: PepRequesterRelation<'a>,
    pub blocks: PepBlockFacts,
    pub roster_subscription: Option<&'a str>,
    pub roster_groups: &'a [String],
    /// Send-last replay can apply the owner bypass before looking up a node.
    pub config: Option<&'a PepNodeConfig>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PepAccessDenial {
    PresenceSubscriptionRequired,
    NotInRosterGroup,
    ClosedNode,
}

pub fn pep_read_access(facts: &PepAccessFacts<'_>) -> Result<(), PepAccessDenial> {
    let allowed = match facts.requester {
        PepRequesterRelation::Owner => true,
        PepRequesterRelation::LocalAnonymous => facts
            .config
            .is_some_and(|config| config.access_model == "open"),
        // The PEP node ACL is evaluated in the owner's direction. IQ routing
        // also has its own XEP-0191 checks.
        PepRequesterRelation::Other(bare) if !facts.blocks.owner_blocks_requester => facts
            .config
            .is_some_and(|config| match config.access_model.as_str() {
                "open" => true,
                "presence" => matches!(facts.roster_subscription, Some("from" | "both")),
                "roster" => facts
                    .roster_groups
                    .iter()
                    .any(|group| config.roster_groups_allowed.contains(group)),
                "whitelist" => config.access_whitelist.iter().any(|jid| {
                    northstar_xmpp_types::jid::canonical_bare_key(jid).is_ok_and(|jid| jid == bare)
                }),
                _ => false,
            }),
        PepRequesterRelation::Other(_) | PepRequesterRelation::Invalid => false,
    };
    if allowed {
        Ok(())
    } else {
        Err(
            match facts.config.map(|config| config.access_model.as_str()) {
                Some("presence") => PepAccessDenial::PresenceSubscriptionRequired,
                Some("roster") => PepAccessDenial::NotInRosterGroup,
                _ => PepAccessDenial::ClosedNode,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::default_pep_node_config;

    #[test]
    fn pep_access_preserves_model_and_roster_boundaries() {
        use PepAccessDenial::{ClosedNode, NotInRosterGroup, PresenceSubscriptionRequired};

        let mut config = default_pep_node_config("news");
        config.roster_groups_allowed = vec!["Friends".to_owned()];
        config.access_whitelist = vec![
            "invalid jid".to_owned(),
            "Reader@Example.test/desk".to_owned(),
        ];
        for (model, subscription, group, jid, expected) in [
            ("open", None, "", "other@example.test", Ok(())),
            ("presence", Some("from"), "", "other@example.test", Ok(())),
            ("presence", Some("both"), "", "other@example.test", Ok(())),
            (
                "presence",
                Some("to"),
                "Friends",
                "other@example.test",
                Err(PresenceSubscriptionRequired),
            ),
            (
                "presence",
                None,
                "",
                "other@example.test",
                Err(PresenceSubscriptionRequired),
            ),
            (
                "roster",
                Some("none"),
                "Friends",
                "other@example.test",
                Ok(()),
            ),
            (
                "roster",
                Some("both"),
                "friends",
                "other@example.test",
                Err(NotInRosterGroup),
            ),
            ("whitelist", None, "", "reader@example.test", Ok(())),
            (
                "whitelist",
                Some("both"),
                "Friends",
                "other@example.test",
                Err(ClosedNode),
            ),
            (
                "authorize",
                Some("both"),
                "Friends",
                "reader@example.test",
                Err(ClosedNode),
            ),
            (
                "unknown",
                Some("from"),
                "Friends",
                "reader@example.test",
                Err(ClosedNode),
            ),
        ] {
            config.access_model = model.to_owned();
            let groups = [group.to_owned()];
            assert_eq!(
                pep_read_access(&PepAccessFacts {
                    requester: PepRequesterRelation::Other(jid),
                    blocks: PepBlockFacts::default(),
                    roster_subscription: subscription,
                    roster_groups: &groups,
                    config: Some(&config),
                }),
                expected,
                "model {model}, subscription {subscription:?}, group {group}, requester {jid}",
            );
        }
    }

    #[test]
    fn pep_access_preserves_self_bypass_block_direction_and_anonymous_scope() {
        let mut config = default_pep_node_config("news");
        config.access_model = "open".to_owned();
        let mut facts = PepAccessFacts {
            requester: PepRequesterRelation::Other("reader@example.test"),
            blocks: PepBlockFacts {
                owner_blocks_requester: false,
                requester_blocks_owner: true,
            },
            roster_subscription: Some("both"),
            roster_groups: &[],
            config: Some(&config),
        };
        assert_eq!(pep_read_access(&facts), Ok(()));
        facts.blocks.owner_blocks_requester = true;
        assert_eq!(pep_read_access(&facts), Err(PepAccessDenial::ClosedNode));
        facts.requester = PepRequesterRelation::Invalid;
        assert_eq!(pep_read_access(&facts), Err(PepAccessDenial::ClosedNode));
        facts.requester = PepRequesterRelation::LocalAnonymous;
        assert_eq!(pep_read_access(&facts), Ok(()));
        let restricted = default_pep_node_config("news");
        facts.config = Some(&restricted);
        assert_eq!(
            pep_read_access(&facts),
            Err(PepAccessDenial::PresenceSubscriptionRequired),
        );
        facts.requester = PepRequesterRelation::Owner;
        assert_eq!(pep_read_access(&facts), Ok(()));
        facts.config = None;
        assert_eq!(pep_read_access(&facts), Ok(()));
    }
}
