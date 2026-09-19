#![forbid(unsafe_code)]

//! Stanza classification and coalescing policy for XEP-0352 Client State Indication.

use crate::error::PolicyError;
use roxmltree::Document;
use std::fmt;

/// Default maximum number of stanzas held in deferred queue (512).
pub const DEFAULT_MAX_DEFERRED_STANZAS: usize = 512;

/// Default maximum total bytes held in deferred queue (2 MiB).
pub const DEFAULT_MAX_DEFERRED_BYTES: usize = 2 * 1024 * 1024;

/// XML namespaces used in stanza classification.
pub const PUBSUB_EVENT_NS: &str = "http://jabber.org/protocol/pubsub#event";
pub const CHATSTATES_NS: &str = "http://jabber.org/protocol/chatstates";
pub const HINTS_NS: &str = "urn:xmpp:hints";
pub const SID_NS: &str = "urn:xmpp:sid:0";

/// Policy defining what action to take when the deferred queue exceeds capacity.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum OverflowPolicy {
    /// Disconnect the inactive client session on queue overflow.
    Disconnect,
    /// Reject the incoming stanza without adding it to the queue.
    Reject,
    /// Direct the stanza to a server persistence / adapter storage layer.
    Persist,
    /// Evict oldest stanzas and explicitly return them to caller/adapter (no silent loss).
    #[default]
    DropOldest,
}

/// Configuration parameters for CSI traffic optimization and queue bounds.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CsiPolicyConfig {
    /// Maximum count of stanzas held in the deferred queue.
    pub max_deferred_stanzas: usize,
    /// Maximum byte size of all stanzas held in the deferred queue.
    pub max_deferred_bytes: usize,
    /// Overflow policy applied when bounds are exceeded.
    pub overflow_policy: OverflowPolicy,
    /// Whether to immediately discard typing notifications (composing/paused) instead of queuing.
    pub discard_typing_on_inactive: bool,
    /// Whether to coalesce presence stanzas.
    pub allow_presence_coalescing: bool,
    /// Whether to coalesce chat state notifications.
    pub allow_chatstate_coalescing: bool,
    /// Whether to coalesce PEP item events.
    pub allow_pep_coalescing: bool,
}

impl Default for CsiPolicyConfig {
    fn default() -> Self {
        Self {
            max_deferred_stanzas: DEFAULT_MAX_DEFERRED_STANZAS,
            max_deferred_bytes: DEFAULT_MAX_DEFERRED_BYTES,
            overflow_policy: OverflowPolicy::default(),
            discard_typing_on_inactive: false,
            allow_presence_coalescing: true,
            allow_chatstate_coalescing: true,
            allow_pep_coalescing: true,
        }
    }
}

impl CsiPolicyConfig {
    /// Creates a new policy configuration with default bounds.
    pub fn new() -> Self {
        Self::default()
    }

    /// Validates that configuration values are within acceptable bounds.
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.max_deferred_stanzas == 0 {
            return Err(PolicyError::ZeroMaxStanzas);
        }
        if self.max_deferred_bytes == 0 {
            return Err(PolicyError::ZeroMaxBytes);
        }
        Ok(())
    }
}

/// Metadata associated with an outbound stanza to guide delivery classification.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct StanzaMetadata {
    /// Indicates whether the stanza has a durable delivery fence or database transaction.
    /// Durable items must never be deferred or coalesced.
    pub is_durable: bool,
    /// Indicates whether the stanza is tied to a transport receipt / acknowledgement.
    pub has_transport_receipt: bool,
    /// Indicates whether the stanza is a message carbon (XEP-0280).
    pub is_carbon: bool,
    /// Explicit override to bypass CSI deferral.
    pub custom_bypass: bool,
}

impl StanzaMetadata {
    /// Creates default metadata for a regular transient stanza.
    pub const fn transient() -> Self {
        Self {
            is_durable: false,
            has_transport_receipt: false,
            is_carbon: false,
            custom_bypass: false,
        }
    }

    /// Creates metadata for a durable stanza that must bypass CSI.
    pub const fn durable() -> Self {
        Self {
            is_durable: true,
            has_transport_receipt: false,
            is_carbon: false,
            custom_bypass: false,
        }
    }

    /// Creates metadata for a transport receipt stanza that must bypass CSI.
    pub const fn transport_receipt() -> Self {
        Self {
            is_durable: false,
            has_transport_receipt: true,
            is_carbon: false,
            custom_bypass: false,
        }
    }

    /// Returns `true` if this stanza must bypass CSI deferral under all circumstances.
    pub const fn must_bypass(&self) -> bool {
        self.is_durable || self.has_transport_receipt || self.custom_bypass
    }
}

/// Coalescing key identifying replaceable soft-state signals.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum CoalescingKey {
    /// Presence updates from a canonical JID (e.g., `presence:alice@example.test/Phone`).
    Presence { from: String },
    /// Standalone chat state notifications from a canonical JID (e.g., `chatstate:bob@example.test/Phone`).
    ChatState { from: String },
    /// PEP item event updates (e.g., `pep:pub@example.test:node1:item:1,retract:2`).
    PepEvent {
        from: String,
        node: String,
        item_keys: Vec<String>,
    },
    /// Custom extension-defined coalescing key.
    Custom(String),
}

impl CoalescingKey {
    /// Creates a presence coalescing key.
    pub fn presence(from: impl Into<String>) -> Self {
        Self::Presence { from: from.into() }
    }

    /// Creates a chat-state coalescing key.
    pub fn chat_state(from: impl Into<String>) -> Self {
        Self::ChatState { from: from.into() }
    }

    /// Creates a PEP item coalescing key.
    pub fn pep(from: impl Into<String>, node: impl Into<String>, item_keys: Vec<String>) -> Self {
        Self::PepEvent {
            from: from.into(),
            node: node.into(),
            item_keys,
        }
    }

    /// Returns the canonical string representation of the coalescing key.
    pub fn as_key_string(&self) -> String {
        match self {
            Self::Presence { from } => format!("presence:{from}"),
            Self::ChatState { from } => format!("chatstate:{from}"),
            Self::PepEvent {
                from,
                node,
                item_keys,
            } => {
                format!("pep:{from}:{node}:{}", item_keys.join(","))
            }
            Self::Custom(key) => key.clone(),
        }
    }
}

impl fmt::Display for CoalescingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.as_key_string())
    }
}

/// The decision produced by classifying a stanza against CSI policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeliveryAction {
    /// Deliver the stanza immediately (important/critical or durable).
    Immediate,
    /// Defer delivery and coalesce by key while the client is inactive.
    Defer(CoalescingKey),
    /// Discard the stanza (e.g., transient typing indicator when discard is enabled).
    Discard,
}

impl DeliveryAction {
    /// Returns `true` if this stanza should be delivered immediately.
    pub const fn is_immediate(&self) -> bool {
        matches!(self, Self::Immediate)
    }

    /// Returns `true` if this stanza should be deferred.
    pub const fn is_defer(&self) -> bool {
        matches!(self, Self::Defer(_))
    }

    /// Returns `true` if this stanza should be discarded.
    pub const fn is_discard(&self) -> bool {
        matches!(self, Self::Discard)
    }
}

/// Canonicalizes an XMPP JID according to RFC 7622:
/// - Bare JID parts (localpart and domainpart) are lowercased.
/// - Resourcepart is preserved exactly with its original case (RFC 7622 OpaqueString).
pub fn canonicalize_jid(jid: &str) -> Option<String> {
    if jid.is_empty() {
        return None;
    }
    let (address, resource) = match jid.split_once('/') {
        Some((addr, res)) => (addr, Some(res)),
        None => (jid, None),
    };

    if address.is_empty() {
        return None;
    }

    let (local, domain) = match address.split_once('@') {
        Some((loc, dom)) => {
            if loc.is_empty() || dom.is_empty() {
                return None;
            }
            (Some(loc.to_lowercase()), dom.to_lowercase())
        }
        None => (None, address.to_lowercase()),
    };

    let mut result = String::with_capacity(jid.len());
    if let Some(l) = local {
        result.push_str(&l);
        result.push('@');
    }
    result.push_str(&domain);
    if let Some(r) = resource {
        result.push('/');
        result.push_str(r);
    }
    Some(result)
}

/// Classify a stanza against CSI delivery policy.
///
/// Returns:
/// - [`DeliveryAction::Immediate`] if the stanza is critical, durable, an IQ, or contains meaningful message content.
/// - [`DeliveryAction::Defer`] with a [`CoalescingKey`] if the stanza is deferrable/coalescible.
/// - [`DeliveryAction::Discard`] if explicitly permitted by configuration (e.g. typing state).
pub fn classify_stanza(
    stanza_xml: &str,
    metadata: &StanzaMetadata,
    config: &CsiPolicyConfig,
) -> DeliveryAction {
    if metadata.must_bypass() {
        return DeliveryAction::Immediate;
    }

    let Ok(doc) = Document::parse(stanza_xml) else {
        // Fail-safe: malformed XML must not be silently dropped or deferred
        return DeliveryAction::Immediate;
    };

    let root = doc.root_element();
    let tag_name = root.tag_name().name();

    // IQ stanzas are strictly request/response and must never be delayed.
    if tag_name == "iq" {
        return DeliveryAction::Immediate;
    }

    let Some(from_raw) = root.attribute("from") else {
        return DeliveryAction::Immediate;
    };
    let Some(from) = canonicalize_jid(from_raw) else {
        return DeliveryAction::Immediate;
    };

    match tag_name {
        "presence" => {
            if !config.allow_presence_coalescing {
                return DeliveryAction::Immediate;
            }
            let ptype = root.attribute("type").unwrap_or("available");
            match ptype {
                "available" | "unavailable" => DeliveryAction::Defer(CoalescingKey::presence(from)),
                // Subscription management, probes, and errors are critical
                _ => DeliveryAction::Immediate,
            }
        }
        "message" => {
            if root.attribute("type") == Some("error") {
                return DeliveryAction::Immediate;
            }

            let elements = root
                .children()
                .filter(|child| child.is_element())
                .collect::<Vec<_>>();

            // Check for PubSub / PEP events
            let events = elements
                .iter()
                .filter(|child| {
                    child.tag_name().name() == "event"
                        && child.tag_name().namespace() == Some(PUBSUB_EVENT_NS)
                })
                .collect::<Vec<_>>();

            if let [event] = events.as_slice() {
                if config.allow_pep_coalescing {
                    let has_meaningful_sibling = elements.iter().any(|child| {
                        *child != **event
                            && !matches!(child.tag_name().namespace(), Some(HINTS_NS | SID_NS))
                    });

                    let event_children = event
                        .children()
                        .filter(|child| child.is_element())
                        .collect::<Vec<_>>();

                    if !has_meaningful_sibling {
                        if let [items] = event_children.as_slice() {
                            if items.tag_name().name() == "items"
                                && items.tag_name().namespace() == Some(PUBSUB_EVENT_NS)
                            {
                                if let Some(node) =
                                    items.attribute("node").filter(|n| !n.is_empty())
                                {
                                    let mut item_keys = items
                                        .children()
                                        .filter(|child| child.is_element())
                                        .map(|item| {
                                            (matches!(item.tag_name().name(), "item" | "retract")
                                                && item.tag_name().namespace()
                                                    == Some(PUBSUB_EVENT_NS))
                                            .then(|| {
                                                item.attribute("id")
                                                    .filter(|id| !id.is_empty())
                                                    .map(|id| {
                                                        format!("{}:{id}", item.tag_name().name())
                                                    })
                                            })
                                            .flatten()
                                        })
                                        .collect::<Option<Vec<_>>>();

                                    if let Some(ref mut keys) = item_keys {
                                        if !keys.is_empty() {
                                            keys.sort();
                                            keys.dedup();
                                            return DeliveryAction::Defer(CoalescingKey::pep(
                                                from,
                                                node,
                                                keys.clone(),
                                            ));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Check for Chat State Notifications (XEP-0085)
            let mut chat_state_name: Option<&str> = None;
            let mut has_meaningful_payload = false;

            for child in &elements {
                let ns = child.tag_name().namespace();
                let name = child.tag_name().name();

                if ns == Some(CHATSTATES_NS)
                    && matches!(
                        name,
                        "active" | "composing" | "gone" | "inactive" | "paused"
                    )
                {
                    chat_state_name = Some(name);
                } else if !matches!(ns, Some(HINTS_NS | SID_NS)) {
                    has_meaningful_payload = true;
                }
            }

            if let Some(cs_name) = chat_state_name {
                if !has_meaningful_payload {
                    if config.discard_typing_on_inactive
                        && matches!(cs_name, "composing" | "paused")
                    {
                        return DeliveryAction::Discard;
                    }
                    if config.allow_chatstate_coalescing {
                        return DeliveryAction::Defer(CoalescingKey::chat_state(from));
                    }
                }
            }

            DeliveryAction::Immediate
        }
        _ => DeliveryAction::Immediate,
    }
}
