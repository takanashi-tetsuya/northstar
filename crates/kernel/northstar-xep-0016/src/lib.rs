//! Capability-free XEP-0016 privacy-list domain and matching policy.

use northstar_xep_core::{ExtensionDescriptor, StanzaKind, StanzaRoute, XepId};
use std::fmt;

pub const XEP_ID: XepId = XepId::new(16);
pub const NAMESPACE: &str = "jabber:iq:privacy";
pub const MAX_PRIVACY_LISTS: usize = 64;
pub const MAX_PRIVACY_ITEMS: usize = 256;

pub static DESCRIPTOR: ExtensionDescriptor = ExtensionDescriptor {
    id: XEP_ID,
    name: "Privacy Lists",
    default_enabled: true,
    dependencies: &[XepId::new(30)],
    conflicts: &[],
    disco_features: &[NAMESPACE],
    routes: &[
        StanzaRoute {
            stanza: StanzaKind::IqGet,
            namespace: NAMESPACE,
            local_name: "query",
        },
        StanzaRoute {
            stanza: StanzaKind::IqSet,
            namespace: NAMESPACE,
            local_name: "query",
        },
    ],
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivacyAction {
    Allow,
    Deny,
}

impl PrivacyAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivacyMatchType {
    Jid,
    Group,
    Subscription,
}

impl PrivacyMatchType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Jid => "jid",
            Self::Group => "group",
            Self::Subscription => "subscription",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivacyItem {
    pub order: u32,
    pub action: PrivacyAction,
    pub match_type: Option<PrivacyMatchType>,
    pub match_value: Option<String>,
    pub message: bool,
    pub iq: bool,
    pub presence_in: bool,
    pub presence_out: bool,
}

/// A privacy list name accepted by the XMPP codec.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct PrivacyListName(String);

impl PrivacyListName {
    pub fn parse(name: &str) -> Option<Self> {
        (!name.is_empty() && name.len() <= 128 && !name.chars().any(char::is_control))
            .then(|| Self(name.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Display for PrivacyListName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The entity selector of a privacy item.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum PrivacyMatcher {
    Everyone,
    Jid(String),
    Group(String),
    Subscription(String),
}

impl PrivacyMatcher {
    /// Projects the selector when its type and value are both present or both
    /// absent. Values are preserved verbatim for evaluation.
    pub fn from_item(item: &PrivacyItem) -> Option<Self> {
        match (item.match_type, item.match_value.as_deref()) {
            (None, None) => Some(Self::Everyone),
            (Some(PrivacyMatchType::Jid), Some(value)) => Some(Self::Jid(value.to_owned())),
            (Some(PrivacyMatchType::Group), Some(value)) => Some(Self::Group(value.to_owned())),
            (Some(PrivacyMatchType::Subscription), Some(value)) => {
                Some(Self::Subscription(value.to_owned()))
            }
            _ => None,
        }
    }

    pub fn matcher_parts(&self) -> (Option<PrivacyMatchType>, Option<String>) {
        match self {
            Self::Everyone => (None, None),
            Self::Jid(value) => (Some(PrivacyMatchType::Jid), Some(value.clone())),
            Self::Group(value) => (Some(PrivacyMatchType::Group), Some(value.clone())),
            Self::Subscription(value) => {
                (Some(PrivacyMatchType::Subscription), Some(value.clone()))
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivacyList {
    pub name: String,
    pub items: Vec<PrivacyItem>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivacyStanzaKind {
    Message,
    Iq,
    PresenceIn,
    PresenceOut,
}

/// XEP-0016 first-match evaluation over a repository-supplied roster
/// snapshot. Missing or malformed entity selectors do not match.
pub fn list_denies(
    list: &PrivacyList,
    candidate: &str,
    subscription: Option<&str>,
    groups: &[String],
    kind: PrivacyStanzaKind,
) -> bool {
    for item in &list.items {
        let stanza_matches = if !(item.message || item.iq || item.presence_in || item.presence_out)
        {
            true
        } else {
            match kind {
                PrivacyStanzaKind::Message => item.message,
                PrivacyStanzaKind::Iq => item.iq,
                PrivacyStanzaKind::PresenceIn => item.presence_in,
                PrivacyStanzaKind::PresenceOut => item.presence_out,
            }
        };
        if !stanza_matches {
            continue;
        }
        let entity_matches = match (item.match_type, item.match_value.as_deref()) {
            (None, None) => true,
            (Some(PrivacyMatchType::Jid), Some(value)) => jid_pattern_matches(value, candidate),
            (Some(PrivacyMatchType::Group), Some(value)) => {
                groups.iter().any(|group| group == value)
            }
            (Some(PrivacyMatchType::Subscription), Some(value)) => {
                subscription.unwrap_or("none") == value
            }
            _ => false,
        };
        if entity_matches {
            return item.action == PrivacyAction::Deny;
        }
    }
    false
}

pub fn jid_pattern_matches(pattern: &str, candidate: &str) -> bool {
    northstar_xmpp_types::jid_scope_matches(pattern, candidate)
}

pub const fn default_change_conflicts(
    local_resource_count: usize,
    remote_resource_exists: bool,
) -> bool {
    local_resource_count > 1 || remote_resource_exists
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(order: u32, action: PrivacyAction) -> PrivacyItem {
        PrivacyItem {
            order,
            action,
            match_type: None,
            match_value: None,
            message: false,
            iq: false,
            presence_in: false,
            presence_out: false,
        }
    }

    #[test]
    fn first_matching_rule_is_authoritative() {
        let list = PrivacyList {
            name: "test".to_owned(),
            items: vec![item(1, PrivacyAction::Deny), item(2, PrivacyAction::Allow)],
        };
        assert!(list_denies(
            &list,
            "alice@example.test/device",
            None,
            &[],
            PrivacyStanzaKind::Message
        ));
    }

    #[test]
    fn stanza_filters_and_roster_context_are_explicit() {
        let list = PrivacyList {
            name: "test".to_owned(),
            items: vec![PrivacyItem {
                order: 1,
                action: PrivacyAction::Deny,
                match_type: Some(PrivacyMatchType::Group),
                match_value: Some("coworkers".to_owned()),
                message: true,
                iq: false,
                presence_in: false,
                presence_out: false,
            }],
        };
        assert!(list_denies(
            &list,
            "alice@example.test",
            None,
            &["coworkers".to_owned()],
            PrivacyStanzaKind::Message
        ));
        assert!(!list_denies(
            &list,
            "alice@example.test",
            None,
            &["coworkers".to_owned()],
            PrivacyStanzaKind::Iq
        ));
    }

    #[test]
    fn jid_patterns_follow_domain_bare_and_full_scope() {
        assert!(jid_pattern_matches("example.test", "a@example.test/phone"));
        assert!(jid_pattern_matches(
            "a@example.test",
            "a@example.test/phone"
        ));
        assert!(jid_pattern_matches(
            "a@example.test/Phone",
            "a@example.test/Phone"
        ));
        assert!(!jid_pattern_matches(
            "a@example.test/Phone",
            "a@example.test/phone"
        ));
    }

    #[test]
    fn default_selection_requires_the_only_connected_resource() {
        assert!(!default_change_conflicts(1, false));
        assert!(default_change_conflicts(2, false));
        assert!(default_change_conflicts(1, true));
    }
}

#[cfg(test)]
mod value_tests {
    use super::{PrivacyAction, PrivacyItem, PrivacyListName, PrivacyMatchType, PrivacyMatcher};

    #[test]
    fn list_names_follow_the_codec_byte_and_character_limits() {
        let longest = "é".repeat(64);
        let too_long = format!("{longest}a");
        for (input, accepted) in [
            ("work", true),
            ("a'b", true),
            (" ", true),
            (longest.as_str(), true),
            (too_long.as_str(), false),
            ("", false),
            ("work\tlist", false),
            ("work\u{85}list", false),
        ] {
            let parsed = PrivacyListName::parse(input);
            assert_eq!(parsed.is_some(), accepted, "{input:?}");
            if let Some(name) = parsed {
                assert_eq!(name.as_str(), input);
                assert_eq!(name.to_string(), input);
                assert_eq!(name.into_inner(), input);
            }
        }
    }

    fn item(match_type: Option<PrivacyMatchType>, match_value: Option<String>) -> PrivacyItem {
        PrivacyItem {
            order: 0,
            action: PrivacyAction::Deny,
            match_type,
            match_value,
            message: false,
            iq: false,
            presence_in: false,
            presence_out: false,
        }
    }

    #[test]
    fn matchers_round_trip_item_fields() {
        for (matcher, kind, value) in [
            (PrivacyMatcher::Everyone, None, None),
            (
                PrivacyMatcher::Jid("alice@example.test/Phone".to_owned()),
                Some(PrivacyMatchType::Jid),
                Some("alice@example.test/Phone"),
            ),
            (
                PrivacyMatcher::Group("R&D".to_owned()),
                Some(PrivacyMatchType::Group),
                Some("R&D"),
            ),
            (
                PrivacyMatcher::Subscription("both".to_owned()),
                Some(PrivacyMatchType::Subscription),
                Some("both"),
            ),
        ] {
            let parts = matcher.matcher_parts();
            assert_eq!(parts.0, kind);
            assert_eq!(parts.1.as_deref(), value);
            assert_eq!(
                PrivacyMatcher::from_item(&item(parts.0, parts.1)),
                Some(matcher)
            );
        }
    }

    #[test]
    fn matchers_reject_unpaired_item_fields() {
        for kind in [
            PrivacyMatchType::Jid,
            PrivacyMatchType::Group,
            PrivacyMatchType::Subscription,
        ] {
            assert_eq!(PrivacyMatcher::from_item(&item(Some(kind), None)), None);
        }
        assert_eq!(
            PrivacyMatcher::from_item(&item(None, Some("alice@example.test".to_owned()))),
            None,
        );
    }
}
