//! Runtime federation rules set through ad-hoc administration.

use northstar_xmpp_types::jid::CanonicalJid;
use std::collections::HashSet;

#[derive(Default)]
pub struct RuntimeFederationPolicy {
    pub blacklist: HashSet<String>,
    pub whitelist: HashSet<String>,
}

impl RuntimeFederationPolicy {
    pub fn allows_domain(&self, domain: &str) -> bool {
        let domain_denied = self.blacklist.iter().any(|entry| {
            CanonicalJid::parse(entry)
                .is_ok_and(|jid| jid.localpart().is_none() && jid.domainpart() == domain)
        });
        let domain_admitted = self.whitelist.is_empty()
            || self.whitelist.iter().any(|entry| {
                CanonicalJid::parse(entry).is_ok_and(|jid| jid.domainpart() == domain)
            });
        !domain_denied && domain_admitted
    }

    /// Apply XEP-0133 entity rules using XEP-0016-style JID specificity: a
    /// domain rule matches the whole domain, a bare JID matches all of its
    /// resources, and a full JID matches exactly one resource.
    pub fn allows_entity(&self, entity: &CanonicalJid) -> bool {
        let matches = |rule: &str| federation_rule_matches(rule, entity);
        !self.blacklist.iter().any(|entry| matches(entry))
            && (self.whitelist.is_empty() || self.whitelist.iter().any(|entry| matches(entry)))
    }
}

fn federation_rule_matches(rule: &str, entity: &CanonicalJid) -> bool {
    CanonicalJid::parse(rule).is_ok_and(|rule| {
        if rule.domainpart() != entity.domainpart() {
            false
        } else if rule.localpart().is_none() {
            true
        } else if rule.resourcepart().is_none() {
            rule.bare() == entity.bare()
        } else {
            rule == *entity
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn federation_entity_rules_follow_domain_bare_and_full_jid_specificity() {
        let phone = CanonicalJid::parse("alice@remote.example/Phone").unwrap();
        let laptop = CanonicalJid::parse("alice@remote.example/Laptop").unwrap();
        let bob = CanonicalJid::parse("bob@remote.example/Phone").unwrap();
        assert!(federation_rule_matches("remote.example", &phone));
        assert!(federation_rule_matches("alice@remote.example", &phone));
        assert!(federation_rule_matches(
            "alice@remote.example/Phone",
            &phone
        ));
        assert!(!federation_rule_matches(
            "alice@remote.example/Phone",
            &laptop
        ));
        assert!(!federation_rule_matches("alice@remote.example", &bob));
        assert!(!federation_rule_matches("other.example", &phone));
    }
}
