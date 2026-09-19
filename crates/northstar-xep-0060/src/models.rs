//! Domain types, enums, and identifier validation for XEP-0060.

use crate::constants::{
    MAX_ITEM_ID_BYTES, MAX_JID_BYTES, MAX_NODE_ID_BYTES, MAX_REDIRECT_URI_BYTES,
};
use crate::error::PubSubError;
use northstar_xmpp_types::CanonicalJid;
use std::fmt;
use std::str::FromStr;

/// XEP-0060 Node Access Models.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub enum AccessModel {
    #[default]
    Open,
    Authorize,
    Whitelist,
}

impl AccessModel {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Authorize => "authorize",
            Self::Whitelist => "whitelist",
        }
    }
}

impl fmt::Display for AccessModel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for AccessModel {
    type Err = PubSubError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "open" => Ok(Self::Open),
            "authorize" => Ok(Self::Authorize),
            "whitelist" => Ok(Self::Whitelist),
            _ => Err(PubSubError::new(
                "not-acceptable",
                "unsupported-access-model",
            )),
        }
    }
}

/// XEP-0060 Node Publish Models.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub enum PublishModel {
    Open,
    #[default]
    Publishers,
    Subscribers,
}

impl PublishModel {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Publishers => "publishers",
            Self::Subscribers => "subscribers",
        }
    }
}

impl fmt::Display for PublishModel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for PublishModel {
    type Err = PubSubError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "open" => Ok(Self::Open),
            "publishers" => Ok(Self::Publishers),
            "subscribers" => Ok(Self::Subscribers),
            _ => Err(PubSubError::not_acceptable()),
        }
    }
}

/// XEP-0060 Node Affiliations.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub enum Affiliation {
    Owner,
    Publisher,
    PublishOnly,
    Member,
    Outcast,
    #[default]
    None,
}

impl Affiliation {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Publisher => "publisher",
            Self::PublishOnly => "publish-only",
            Self::Member => "member",
            Self::Outcast => "outcast",
            Self::None => "none",
        }
    }

    pub const fn is_owner(&self) -> bool {
        matches!(self, Self::Owner)
    }

    pub const fn is_outcast(&self) -> bool {
        matches!(self, Self::Outcast)
    }

    pub const fn can_retrieve(&self) -> bool {
        matches!(self, Self::Owner | Self::Publisher | Self::Member)
    }
}

impl fmt::Display for Affiliation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Affiliation {
    type Err = PubSubError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "owner" => Ok(Self::Owner),
            "publisher" => Ok(Self::Publisher),
            "publish-only" => Ok(Self::PublishOnly),
            "member" => Ok(Self::Member),
            "outcast" => Ok(Self::Outcast),
            "none" => Ok(Self::None),
            _ => Err(PubSubError::bad_request()),
        }
    }
}

/// XEP-0060 Subscription States.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub enum SubscriptionState {
    #[default]
    Subscribed,
    Pending,
    Unconfigured,
    None,
}

impl SubscriptionState {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Subscribed => "subscribed",
            Self::Pending => "pending",
            Self::Unconfigured => "unconfigured",
            Self::None => "none",
        }
    }

    pub const fn is_active(&self) -> bool {
        matches!(self, Self::Subscribed)
    }
}

impl fmt::Display for SubscriptionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SubscriptionState {
    type Err = PubSubError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "subscribed" => Ok(Self::Subscribed),
            "pending" => Ok(Self::Pending),
            "unconfigured" => Ok(Self::Unconfigured),
            "none" => Ok(Self::None),
            _ => Err(PubSubError::bad_request()),
        }
    }
}

/// Node structural type (Leaf or Collection).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub enum NodeType {
    #[default]
    Leaf,
    Collection,
}

impl NodeType {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Leaf => "leaf",
            Self::Collection => "collection",
        }
    }
}

impl fmt::Display for NodeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for NodeType {
    type Err = PubSubError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "leaf" => Ok(Self::Leaf),
            "collection" => Ok(Self::Collection),
            _ => Err(PubSubError::not_acceptable()),
        }
    }
}

/// XEP-0060 `send_last_published_item` configuration policies.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub enum SendLastPublishedItem {
    Never,
    OnSub,
    #[default]
    OnSubAndPresence,
}

impl SendLastPublishedItem {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Never => "never",
            Self::OnSub => "on_sub",
            Self::OnSubAndPresence => "on_sub_and_presence",
        }
    }
}

impl fmt::Display for SendLastPublishedItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SendLastPublishedItem {
    type Err = PubSubError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "never" => Ok(Self::Never),
            "on_sub" => Ok(Self::OnSub),
            "on_sub_and_presence" => Ok(Self::OnSubAndPresence),
            _ => Err(PubSubError::not_acceptable()),
        }
    }
}

/// XEP-0248 Children Association Policy.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub enum ChildrenAssociationPolicy {
    #[default]
    Owner,
    Whitelist,
    All,
}

impl ChildrenAssociationPolicy {
    /// Wire value for XData configuration forms (XEP-0248 specifies `owners`).
    pub const fn wire_value(&self) -> &'static str {
        match self {
            Self::Owner => "owners",
            Self::Whitelist => "whitelist",
            Self::All => "all",
        }
    }

    /// Internal storage / normalized value.
    pub const fn internal_value(&self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Whitelist => "whitelist",
            Self::All => "all",
        }
    }
}

impl fmt::Display for ChildrenAssociationPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.wire_value())
    }
}

impl FromStr for ChildrenAssociationPolicy {
    type Err = PubSubError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "owner" | "owners" => Ok(Self::Owner),
            "whitelist" => Ok(Self::Whitelist),
            "all" => Ok(Self::All),
            _ => Err(PubSubError::not_acceptable()),
        }
    }
}

/// XEP-0248 Subscription Type for Collection nodes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub enum SubscriptionType {
    #[default]
    Items,
    Nodes,
    All,
}

impl SubscriptionType {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Items => "items",
            Self::Nodes => "nodes",
            Self::All => "all",
        }
    }
}

impl fmt::Display for SubscriptionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SubscriptionType {
    type Err = PubSubError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "items" => Ok(Self::Items),
            "nodes" => Ok(Self::Nodes),
            "all" => Ok(Self::All),
            _ => Err(PubSubError::new("bad-request", "invalid-options")),
        }
    }
}

/// XEP-0060 / RFC 6121 Presence show availability filter values.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub enum ShowValue {
    Away,
    Chat,
    Dnd,
    Online,
    Xa,
}

impl ShowValue {
    pub const ALL: [Self; 5] = [Self::Away, Self::Chat, Self::Dnd, Self::Online, Self::Xa];

    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Away => "away",
            Self::Chat => "chat",
            Self::Dnd => "dnd",
            Self::Online => "online",
            Self::Xa => "xa",
        }
    }
}

impl fmt::Display for ShowValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ShowValue {
    type Err = PubSubError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "away" => Ok(Self::Away),
            "chat" => Ok(Self::Chat),
            "dnd" => Ok(Self::Dnd),
            "online" => Ok(Self::Online),
            "xa" => Ok(Self::Xa),
            _ => Err(PubSubError::new("bad-request", "invalid-options")),
        }
    }
}

/// Actions on collection node children.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CollectionAction {
    Associate { child: String },
    Dissociate { child: String },
}

// Validation & Normalization Helpers

/// Validate that a node identifier is non-empty, within byte limits, and contains no control chars.
pub fn valid_node_id(node: Option<&str>) -> Option<&str> {
    node.filter(|value| {
        !value.is_empty()
            && value.len() <= MAX_NODE_ID_BYTES
            && !value.chars().any(char::is_control)
    })
}

/// Require a non-empty, valid node identifier or return an appropriate error.
pub fn required_node_id(value: Option<&str>) -> Result<&str, PubSubError> {
    let Some(value) = value else {
        return Err(PubSubError::new("bad-request", "nodeid-required"));
    };
    valid_node_id(Some(value)).ok_or_else(PubSubError::bad_request)
}

/// Validate that an ItemID is non-empty, <= 1024 bytes, and contains no control characters.
pub fn valid_item_id(item_id: &str) -> bool {
    !item_id.is_empty()
        && item_id.len() <= MAX_ITEM_ID_BYTES
        && !item_id.chars().any(char::is_control)
}

/// Validate URI for `<redirect uri='...'/>` elements.
pub fn valid_redirect_uri(uri: &str) -> bool {
    !uri.is_empty()
        && uri.len() <= MAX_REDIRECT_URI_BYTES
        && !uri.chars().any(char::is_control)
        && uri.split_once(':').is_some_and(|(scheme, rest)| {
            !scheme.is_empty()
                && !rest.is_empty()
                && scheme.chars().enumerate().all(|(index, ch)| {
                    ch.is_ascii_alphabetic()
                        || (index > 0 && matches!(ch, '+' | '-' | '.' | '0'..='9'))
                })
        })
}

/// Validate a BCP 47 / RFC 5646 language tag string.
pub fn valid_language_tag(tag: &str) -> bool {
    if tag.is_empty() || tag.len() > 35 {
        return false;
    }
    tag.split('-').all(|subtag| {
        !subtag.is_empty() && subtag.len() <= 8 && subtag.chars().all(|c| c.is_ascii_alphanumeric())
    })
}

/// Validate a bare JID using PRECIS / RFC 7622 rules.
pub fn valid_bare_jid(jid: &str) -> bool {
    if jid.is_empty() || jid.len() > MAX_JID_BYTES {
        return false;
    }
    CanonicalJid::parse_bare(jid).is_ok()
}

/// Parse boolean strings (`"1"`, `"true"`, `"0"`, `"false"`).
pub fn parse_bool(value: Option<&str>) -> Option<bool> {
    match value? {
        "1" | "true" => Some(true),
        "0" | "false" => Some(false),
        _ => None,
    }
}

/// Format a boolean as `"true"` or `"false"`.
pub const fn bool_text(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}

/// True if the slice contains all 5 standard show values.
pub fn all_show_values(values: &[ShowValue]) -> bool {
    ShowValue::ALL.iter().all(|val| values.contains(val))
}

/// True if the string slice contains all 5 standard show values.
pub fn all_show_strings(values: &[String]) -> bool {
    ["away", "chat", "dnd", "online", "xa"]
        .iter()
        .all(|value| values.iter().any(|candidate| candidate == value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_displays_enums() {
        assert_eq!(AccessModel::from_str("open").unwrap(), AccessModel::Open);
        assert_eq!(
            AccessModel::from_str("authorize").unwrap(),
            AccessModel::Authorize
        );
        assert_eq!(
            AccessModel::from_str("whitelist").unwrap(),
            AccessModel::Whitelist
        );
        assert!(AccessModel::from_str("presence").is_err());

        assert_eq!(
            PublishModel::from_str("publishers").unwrap(),
            PublishModel::Publishers
        );
        assert_eq!(Affiliation::from_str("owner").unwrap(), Affiliation::Owner);
        assert_eq!(
            SubscriptionState::from_str("subscribed").unwrap(),
            SubscriptionState::Subscribed
        );
        assert_eq!(
            NodeType::from_str("collection").unwrap(),
            NodeType::Collection
        );
        assert_eq!(
            ChildrenAssociationPolicy::from_str("owners").unwrap(),
            ChildrenAssociationPolicy::Owner
        );
    }

    #[test]
    fn validates_identifiers_strictly() {
        assert_eq!(valid_node_id(Some("node1")), Some("node1"));
        assert_eq!(valid_node_id(Some("")), None);
        assert_eq!(valid_node_id(Some("bad\x00node")), None);
        assert!(valid_item_id("item-123"));
        assert!(!valid_item_id(""));
        assert!(!valid_item_id("bad\x07item"));

        assert!(valid_redirect_uri("xmpp:pubsub.example.org?;node=test"));
        assert!(valid_redirect_uri("https://example.com/pubsub"));
        assert!(!valid_redirect_uri("no-scheme"));
        assert!(!valid_redirect_uri("123:invalid"));
    }

    #[test]
    fn validates_language_tags() {
        assert!(valid_language_tag("en"));
        assert!(valid_language_tag("en-US"));
        assert!(valid_language_tag("zh-Hans-CN"));
        assert!(!valid_language_tag(""));
        assert!(!valid_language_tag("en_US"));
        assert!(!valid_language_tag("toolongsubtag123456789"));
    }
}
