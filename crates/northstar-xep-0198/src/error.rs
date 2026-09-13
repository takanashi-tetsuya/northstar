#![forbid(unsafe_code)]

//! Error and reason types for XEP-0198 Stream Management wire and state handling.

use std::fmt;
use thiserror::Error;

/// Standard defined conditions for `<failed xmlns='urn:xmpp:sm:3'/>` payloads
/// and XMPP stanza errors per RFC 6120 / XEP-0198.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum FailedReason {
    /// `<bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>`
    BadRequest,
    /// `<conflict xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>`
    Conflict,
    /// `<feature-not-implemented xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>`
    FeatureNotImplemented,
    /// `<forbidden xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>`
    Forbidden,
    /// `<item-not-found xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>`
    ItemNotFound,
    /// `<not-authorized xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>`
    NotAuthorized,
    /// `<policy-violation xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>`
    PolicyViolation,
    /// `<remote-server-not-found xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>`
    RemoteServerNotFound,
    /// `<remote-server-timeout xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>`
    RemoteServerTimeout,
    /// `<resource-constraint xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>`
    ResourceConstraint,
    /// `<service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>`
    ServiceUnavailable,
    /// `<unexpected-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>`
    UnexpectedRequest,
    /// `<undefined-condition xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>`
    UndefinedCondition,
}

impl FailedReason {
    /// Returns the standard RFC 6120 stanza error condition local name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BadRequest => "bad-request",
            Self::Conflict => "conflict",
            Self::FeatureNotImplemented => "feature-not-implemented",
            Self::Forbidden => "forbidden",
            Self::ItemNotFound => "item-not-found",
            Self::NotAuthorized => "not-authorized",
            Self::PolicyViolation => "policy-violation",
            Self::RemoteServerNotFound => "remote-server-not-found",
            Self::RemoteServerTimeout => "remote-server-timeout",
            Self::ResourceConstraint => "resource-constraint",
            Self::ServiceUnavailable => "service-unavailable",
            Self::UnexpectedRequest => "unexpected-request",
            Self::UndefinedCondition => "undefined-condition",
        }
    }

    /// Parses a standard RFC 6120 stanza error condition local name.
    pub fn from_str_name(name: &str) -> Option<Self> {
        match name {
            "bad-request" => Some(Self::BadRequest),
            "conflict" => Some(Self::Conflict),
            "feature-not-implemented" => Some(Self::FeatureNotImplemented),
            "forbidden" => Some(Self::Forbidden),
            "item-not-found" => Some(Self::ItemNotFound),
            "not-authorized" => Some(Self::NotAuthorized),
            "policy-violation" => Some(Self::PolicyViolation),
            "remote-server-not-found" => Some(Self::RemoteServerNotFound),
            "remote-server-timeout" => Some(Self::RemoteServerTimeout),
            "resource-constraint" => Some(Self::ResourceConstraint),
            "service-unavailable" => Some(Self::ServiceUnavailable),
            "unexpected-request" => Some(Self::UnexpectedRequest),
            "undefined-condition" => Some(Self::UndefinedCondition),
            _ => None,
        }
    }

    /// Generates XML child element for the stanza error condition.
    pub fn stanza_error_element(self) -> String {
        format!(
            "<{} xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>",
            self.as_str()
        )
    }

    /// Builds a full `<failed xmlns='urn:xmpp:sm:3'>` response string with this reason.
    pub fn build_failed_element(self, h: Option<u32>) -> String {
        match h {
            Some(counter) => format!(
                "<failed xmlns='urn:xmpp:sm:3' h='{counter}'><{} xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></failed>",
                self.as_str()
            ),
            None => format!(
                "<failed xmlns='urn:xmpp:sm:3'><{} xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></failed>",
                self.as_str()
            ),
        }
    }
}

impl fmt::Display for FailedReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.as_str())
    }
}

/// Errors encountered during wire-level XML parsing and validation of SM elements.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum WireError {
    #[error("malformed XML: {0}")]
    MalformedXml(String),

    #[error("unexpected namespace: expected {expected}, got {actual:?}")]
    UnexpectedNamespace {
        expected: &'static str,
        actual: Option<String>,
    },

    #[error("unexpected tag name: expected {expected}, got {actual}")]
    UnexpectedTagName {
        expected: &'static str,
        actual: String,
    },

    #[error("disallowed attribute on SM element: {0}")]
    DisallowedAttribute(String),

    #[error("invalid attribute value for '{name}': {reason}")]
    InvalidAttribute { name: &'static str, reason: String },

    #[error("missing required attribute: {0}")]
    MissingRequiredAttribute(&'static str),

    #[error("unexpected child elements in SM control element")]
    UnexpectedChildElements,

    #[error("unexpected text content in SM control element")]
    UnexpectedTextContent,

    #[error("invalid resume previd token: {0}")]
    InvalidPrevid(String),

    #[error("invalid location URI: {0}")]
    InvalidLocation(String),

    #[error("invalid max timeout seconds: {0}")]
    InvalidMax(String),

    #[error("invalid handled count: {0}")]
    InvalidHandledCount(String),

    #[error("missing error condition child in failed element")]
    MissingFailedCondition,
}

/// Acknowledgement and handled count validation errors.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum AckError {
    #[error(
        "handled count too high: received h={received}, but only sent={sent} (outstanding={outstanding})"
    )]
    HandledCountTooHigh {
        received: u32,
        sent: u32,
        outstanding: usize,
    },

    #[error("invalid acknowledgement delta: {delta} exceeds outstanding queue size {outstanding}")]
    InvalidDelta { delta: usize, outstanding: usize },
}

/// Negotiation and eligibility errors.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum NegotiationError {
    #[error("stream management is already enabled on this stream")]
    AlreadyEnabled,

    #[error("resumption is not permitted under current server policy")]
    ResumeNotAllowed,

    #[error("strict device continuity policy requires a stable device/user-agent identifier")]
    DeviceContinuityRequired,

    #[error("invalid requested resume timeout: {0}")]
    InvalidTimeout(String),
}

/// Outbound unacknowledged queue errors.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum QueueError {
    #[error("unacknowledged queue stanza limit exceeded: current {current} >= max {max}")]
    MaxStanzasExceeded { current: usize, max: usize },

    #[error("unacknowledged queue byte limit exceeded: current {current} >= max {max}")]
    MaxBytesExceeded { current: usize, max: usize },

    #[error("arithmetic overflow during queue byte size calculation")]
    ByteSizeOverflow,
}

/// State machine lifecycle transition errors.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum StateError {
    #[error("invalid state transition from {from} on event {event}")]
    InvalidStateTransition {
        from: &'static str,
        event: &'static str,
    },

    #[error("suspended stream session has expired at timestamp {expires_at} (current time {now})")]
    SessionExpired { expires_at: u64, now: u64 },

    #[error("stream management is not active")]
    NotActive,

    #[error("stream management session resumption failed: {0}")]
    ResumeFailed(FailedReason),
}

/// Unified error type for the `northstar-xep-0198` crate.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum SmError {
    #[error(transparent)]
    Wire(#[from] WireError),

    #[error(transparent)]
    Ack(#[from] AckError),

    #[error(transparent)]
    Negotiation(#[from] NegotiationError),

    #[error(transparent)]
    Queue(#[from] QueueError),

    #[error(transparent)]
    State(#[from] StateError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_reason_roundtrip_and_elements() {
        for (name, variant) in [
            ("bad-request", FailedReason::BadRequest),
            ("conflict", FailedReason::Conflict),
            (
                "feature-not-implemented",
                FailedReason::FeatureNotImplemented,
            ),
            ("forbidden", FailedReason::Forbidden),
            ("item-not-found", FailedReason::ItemNotFound),
            ("not-authorized", FailedReason::NotAuthorized),
            ("policy-violation", FailedReason::PolicyViolation),
            (
                "remote-server-not-found",
                FailedReason::RemoteServerNotFound,
            ),
            ("remote-server-timeout", FailedReason::RemoteServerTimeout),
            ("resource-constraint", FailedReason::ResourceConstraint),
            ("service-unavailable", FailedReason::ServiceUnavailable),
            ("unexpected-request", FailedReason::UnexpectedRequest),
            ("undefined-condition", FailedReason::UndefinedCondition),
        ] {
            assert_eq!(variant.as_str(), name);
            assert_eq!(FailedReason::from_str_name(name), Some(variant));
            assert_eq!(
                variant.stanza_error_element(),
                format!("<{name} xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>")
            );
            assert_eq!(
                variant.build_failed_element(None),
                format!("<failed xmlns='urn:xmpp:sm:3'><{name} xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></failed>")
            );
            assert_eq!(
                variant.build_failed_element(Some(5)),
                format!("<failed xmlns='urn:xmpp:sm:3' h='5'><{name} xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></failed>")
            );
        }
        assert_eq!(FailedReason::from_str_name("non-existent"), None);
    }

    #[test]
    fn error_display_formatting() {
        let wire_err = WireError::DisallowedAttribute("foo".into());
        assert_eq!(
            wire_err.to_string(),
            "disallowed attribute on SM element: foo"
        );

        let ack_err = AckError::HandledCountTooHigh {
            received: 10,
            sent: 5,
            outstanding: 2,
        };
        assert_eq!(
            ack_err.to_string(),
            "handled count too high: received h=10, but only sent=5 (outstanding=2)"
        );
    }
}
