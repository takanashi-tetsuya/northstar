//! Pure notification eligibility, disclosure privacy policies, coalescing keys, and delivery response types.

use crate::error::PushError;
use crate::subscription::PushNode;
use crate::summary::PushSummary;
use northstar_xmpp_types::CanonicalJid;

/// State of an active or disconnected user session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecipientSessionState {
    /// No active stream session connected.
    Offline,
    /// Connected stream session is inactive under XEP-0352 Client State Indication (CSI).
    CsiInactive,
    /// Connected stream session is available and active with the given RFC 6121 priority.
    Available { priority: i8 },
}

/// Message payload encryption classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageEncryption {
    /// Unencrypted plaintext message.
    Plaintext,
    /// Encrypted with end-to-end mechanism (OMEMO, OX, OpenPGP, XEP-0380 EME).
    Encrypted,
    /// Encryption status is unknown or unverifiable.
    Unknown,
}

/// Importance / trigger category of the incoming event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageImportance {
    /// Standard chat, normal, or groupchat message.
    Normal,
    /// Explicit high-priority or urgent message.
    Urgent,
    /// Message explicitly mentions or highlights the recipient.
    Mention,
    /// Direct MUC invitation (XEP-0249 or mediated invite).
    DirectMucInvite,
    /// Inbound presence subscription request (`<presence type='subscribe'/>`).
    SubscriptionRequest,
}

/// Pure inputs for evaluating whether a push notification should be generated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EligibilityInput {
    /// Current states of all connected sessions for the recipient account.
    pub recipient_sessions: Vec<RecipientSessionState>,
    /// Whether the stanza is an error stanza (`type='error'`).
    pub is_error_stanza: bool,
    /// Whether the stanza carries a XEP-0334 `<no-store/>` processing hint.
    pub no_store: bool,
    /// Encryption state of the message payload.
    pub encryption: MessageEncryption,
    /// Category / importance of the notification trigger.
    pub importance: MessageImportance,
    /// Whether the message stanza has content or body.
    pub has_body: bool,
}

/// Decision outcome of eligibility evaluation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EligibilityDecision {
    /// Notification is eligible for delivery attempt.
    Eligible(EligibilityReason),
    /// Notification is declined.
    Ineligible(IneligibilityReason),
}

impl EligibilityDecision {
    /// Returns `true` if the decision is [`EligibilityDecision::Eligible`].
    pub fn is_eligible(&self) -> bool {
        matches!(self, Self::Eligible(_))
    }
}

/// Reason why a notification was deemed eligible.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EligibilityReason {
    /// Recipient has no active online sessions.
    OfflineRecipient,
    /// Recipient's connected sessions are all CSI inactive (idle/background).
    CsiInactiveSession,
    /// Urgent message or direct mention triggers push even if active sessions exist.
    UrgentMention,
    /// Direct MUC invitation was accepted into offline/push storage.
    DirectMucInvite,
    /// Inbound presence subscription request received.
    SubscriptionRequest,
}

/// Reason why a notification was deemed ineligible.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IneligibilityReason {
    /// Recipient has at least one active, available online session with non-negative priority.
    ActiveOnlineSession,
    /// Stanza carries explicit XEP-0334 `<no-store/>` directive.
    NoStoreDirective,
    /// Stanza is an error stanza (`type='error'`).
    ErrorMessage,
    /// Stanza has empty body with normal importance.
    EmptyMessage,
    /// No qualifying trigger condition met.
    NoEligibleConditions,
}

/// Evaluate notification eligibility purely from input state.
pub fn evaluate_eligibility(input: &EligibilityInput) -> EligibilityDecision {
    // 1. Error stanzas never trigger push notifications.
    if input.is_error_stanza {
        return EligibilityDecision::Ineligible(IneligibilityReason::ErrorMessage);
    }

    // 2. XEP-0334 no-store forbids offline / push queuing.
    if input.no_store {
        return EligibilityDecision::Ineligible(IneligibilityReason::NoStoreDirective);
    }

    // 3. Normal messages without body or content are ignored.
    if !input.has_body && matches!(input.importance, MessageImportance::Normal) {
        return EligibilityDecision::Ineligible(IneligibilityReason::EmptyMessage);
    }

    // 4. Special triggers that always trigger when sessions are offline or inactive.
    if matches!(input.importance, MessageImportance::DirectMucInvite) {
        let has_available = input
            .recipient_sessions
            .iter()
            .any(|s| matches!(s, RecipientSessionState::Available { priority } if *priority >= 0));
        if !has_available {
            return EligibilityDecision::Eligible(EligibilityReason::DirectMucInvite);
        }
    }

    if matches!(input.importance, MessageImportance::SubscriptionRequest) {
        let has_available = input
            .recipient_sessions
            .iter()
            .any(|s| matches!(s, RecipientSessionState::Available { priority } if *priority >= 0));
        if !has_available {
            return EligibilityDecision::Eligible(EligibilityReason::SubscriptionRequest);
        }
    }

    // 5. Check if recipient has an active online available session.
    let has_available_session = input
        .recipient_sessions
        .iter()
        .any(|s| matches!(s, RecipientSessionState::Available { priority } if *priority >= 0));

    if has_available_session {
        // If urgent or direct mention, caller policy might allow push, but standard push
        // is suppressed when an active stream is receiving stanzas.
        if matches!(
            input.importance,
            MessageImportance::Urgent | MessageImportance::Mention
        ) {
            return EligibilityDecision::Eligible(EligibilityReason::UrgentMention);
        }
        return EligibilityDecision::Ineligible(IneligibilityReason::ActiveOnlineSession);
    }

    // 6. Check for CSI inactive sessions vs completely offline.
    let has_csi_inactive = input
        .recipient_sessions
        .iter()
        .any(|s| matches!(s, RecipientSessionState::CsiInactive));

    if has_csi_inactive {
        return EligibilityDecision::Eligible(EligibilityReason::CsiInactiveSession);
    }

    // 7. Recipient has no active sessions (all offline or negative priority).
    EligibilityDecision::Eligible(EligibilityReason::OfflineRecipient)
}

/// Sender identity disclosure policy in push notifications.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SenderDisclosure {
    /// Never disclose sender identity in the notification payload (default, privacy-preserving).
    #[default]
    Never,
    /// Disclose only the sender's bare JID (`user@example.org`).
    BareJid,
    /// Disclose the sender's full JID if known (`user@example.org/resource`).
    FullJid,
}

/// Message body snippet disclosure policy in push notifications.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum BodyDisclosure {
    /// Never disclose message body in push payload (default, privacy-preserving).
    #[default]
    Never,
    /// Disclose plaintext body only if the message is unencrypted.
    PlaintextOnly,
    /// Disclose truncated plaintext body up to the given character count.
    Truncated(usize),
    /// Redact body with a fixed placeholder string (e.g. "[Encrypted Message]").
    Redacted(String),
}

/// Explicit disclosure policy controlling what metadata is published to the Push Service.
///
/// **Privacy Invariant**: The default policy is strictly privacy-preserving: it publishes
/// counts only, and never leaks message bodies or sender identities unless explicitly configured.
/// Furthermore, encrypted messages NEVER disclose plaintext bodies under any setting.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisclosurePolicy {
    /// Include `message-count` in summary form (default: true).
    pub include_message_count: bool,
    /// Include `pending-subscription-count` in summary form (default: true).
    pub include_pending_subscriptions: bool,
    /// Sender disclosure rule (default: [`SenderDisclosure::Never`]).
    pub sender_disclosure: SenderDisclosure,
    /// Body disclosure rule (default: [`BodyDisclosure::Never`]).
    pub body_disclosure: BodyDisclosure,
}

impl Default for DisclosurePolicy {
    fn default() -> Self {
        Self {
            include_message_count: true,
            include_pending_subscriptions: true,
            sender_disclosure: SenderDisclosure::Never,
            body_disclosure: BodyDisclosure::Never,
        }
    }
}

/// Event triggering a push notification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NotificationEvent {
    /// Current count of unread / offline messages.
    pub message_count: u64,
    /// Current count of pending presence subscriptions.
    pub pending_subscription_count: u64,
    /// Sender JID of triggering stanza if available.
    pub sender: Option<CanonicalJid>,
    /// Plaintext message body if available.
    pub body: Option<String>,
    /// Encryption classification of the triggering message.
    pub encryption: MessageEncryption,
}

/// Apply the disclosure policy to generate a filtered [`PushSummary`].
///
/// **Privacy Guarantee**: If `event.encryption == MessageEncryption::Encrypted`, plaintext body
/// is NEVER included, even if `policy.body_disclosure == BodyDisclosure::PlaintextOnly`.
pub fn apply_disclosure_policy(
    policy: &DisclosurePolicy,
    event: &NotificationEvent,
) -> PushSummary {
    let message_count = if policy.include_message_count {
        Some(event.message_count)
    } else {
        None
    };

    let pending_subscription_count = if policy.include_pending_subscriptions {
        Some(event.pending_subscription_count)
    } else {
        None
    };

    let last_message_sender = match policy.sender_disclosure {
        SenderDisclosure::Never => None,
        SenderDisclosure::BareJid => event
            .sender
            .as_ref()
            .and_then(|s| CanonicalJid::parse_bare(&s.to_string()).ok()),
        SenderDisclosure::FullJid => event.sender.clone(),
    };

    let last_message_body = match event.encryption {
        MessageEncryption::Encrypted => match policy.body_disclosure {
            BodyDisclosure::Redacted(ref placeholder) => Some(placeholder.clone()),
            // Plaintext bodies are strictly forbidden for encrypted messages!
            BodyDisclosure::Never
            | BodyDisclosure::PlaintextOnly
            | BodyDisclosure::Truncated(_) => None,
        },
        MessageEncryption::Plaintext | MessageEncryption::Unknown => match policy.body_disclosure {
            BodyDisclosure::Never => None,
            BodyDisclosure::PlaintextOnly => event.body.clone(),
            BodyDisclosure::Truncated(limit) => event.body.as_ref().map(|b| {
                if b.chars().count() > limit {
                    b.chars().take(limit).collect()
                } else {
                    b.clone()
                }
            }),
            BodyDisclosure::Redacted(ref placeholder) => Some(placeholder.clone()),
        },
    };

    PushSummary {
        message_count,
        pending_subscription_count,
        last_message_sender,
        last_message_body,
        additional_fields: Vec::new(),
    }
}

/// Deterministic coalescing and deduplication key for push notifications.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct PushCoalesceKey {
    user_bare_jid: CanonicalJid,
    service_jid: CanonicalJid,
    node: Option<PushNode>,
}

impl PushCoalesceKey {
    /// Construct a new coalescing key.
    pub fn new(
        user_bare_jid: CanonicalJid,
        service_jid: CanonicalJid,
        node: Option<PushNode>,
    ) -> Self {
        Self {
            user_bare_jid,
            service_jid,
            node,
        }
    }

    /// User account bare JID.
    pub fn user_bare_jid(&self) -> &CanonicalJid {
        &self.user_bare_jid
    }

    /// Push service bare JID.
    pub fn service_jid(&self) -> &CanonicalJid {
        &self.service_jid
    }

    /// Optional push node.
    pub fn node(&self) -> Option<&PushNode> {
        self.node.as_ref()
    }

    /// Produce a deterministic string representation for hashing or Redis/PostgreSQL coalescing.
    pub fn to_key_string(&self) -> String {
        format!(
            "{}\0{}\0{}",
            self.user_bare_jid,
            self.service_jid,
            self.node.as_ref().map_or("", PushNode::as_str)
        )
    }

    /// Parse a coalescing key from its deterministic string representation.
    pub fn parse(s: &str) -> Result<Self, PushError> {
        let parts: Vec<&str> = s.split('\0').collect();
        if parts.len() != 3 {
            return Err(PushError::BadRequest(
                "invalid format for PushCoalesceKey string".to_owned(),
            ));
        }
        let user_bare_jid = CanonicalJid::parse_bare(parts[0])
            .map_err(|e| PushError::JidMalformed(format!("invalid user bare JID: {e}")))?;
        let service_jid = CanonicalJid::parse_bare(parts[1])
            .map_err(|e| PushError::JidMalformed(format!("invalid service bare JID: {e}")))?;
        let node = if parts[2].is_empty() {
            None
        } else {
            Some(PushNode::new(parts[2])?)
        };
        Ok(Self {
            user_bare_jid,
            service_jid,
            node,
        })
    }
}

/// Category / reason for initiating a push delivery attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryAttemptReason {
    /// Offline message stored.
    OfflineMessage,
    /// Message arrived while recipient was in CSI inactive state.
    CsiInactiveMessage,
    /// Direct MUC invite queued for delivery.
    DirectMucInvite,
    /// Inbound presence subscription request queued.
    SubscriptionRequest,
    /// Manual trigger (e.g. admin test or explicit resend).
    ManualTrigger,
}

/// High-level response kind from a Push Service IQ result/error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryResponseKind {
    /// Push service accepted notification (`<iq type='result'/>`).
    Success,
    /// Push service permanently rejected notification (`<iq type='error'/>` with cancel / item-not-found / forbidden).
    PermanentError,
    /// Push service transiently failed (`<iq type='error'/>` with wait / resource-constraint / service-unavailable).
    TransientError,
}

/// Delivery attempt processing outcome after server database correlation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryResponseOutcome {
    /// Delivery completed successfully; reset consecutive failure counter.
    Completed,
    /// Push service indicated unregistration or permanent failure; subscription disabled.
    SubscriptionDisabled,
    /// IQ response sender did not match the registered push service JID.
    SenderMismatch,
    /// Correlation token expired before response arrived.
    Expired,
    /// Unknown or unroutable response.
    Unknown,
}
