//! Typed error models and RFC 6120 stanza error mapping for XEP-0357 Push Notifications.

use crate::constants::XMLNS_STANZAS;
use thiserror::Error;

/// Typed errors occurring during XEP-0357 wire parsing, validation, or serialization.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PushError {
    /// Generic malformed payload or protocol violation.
    #[error("bad request: {0}")]
    BadRequest(String),

    /// A JID string failed RFC 7622 validation or was not a bare JID where required.
    #[error("malformed JID: {0}")]
    JidMalformed(String),

    /// A resource or payload exceeded maximum allowable size limits.
    #[error("resource constraint: {0}")]
    ResourceConstraint(String),

    /// The action is forbidden by server routing or account isolation rules.
    #[error("not allowed: {0}")]
    NotAllowed(String),

    /// The requesting session is unauthenticated.
    #[error("not authorized: {0}")]
    NotAuthorized(String),

    /// An XML element had an unexpected namespace.
    #[error("unexpected namespace: expected '{expected}', found '{actual}'")]
    UnexpectedNamespace {
        expected: &'static str,
        actual: String,
    },

    /// An XML element had an unexpected tag name.
    #[error("unexpected tag name: expected '{expected}', found '{actual}'")]
    UnexpectedTagName {
        expected: &'static str,
        actual: String,
    },

    /// A node identifier was empty, oversized, or contained control characters.
    #[error("invalid node: {0}")]
    InvalidNode(String),

    /// Publish-options data form failed structural or value validation.
    #[error("invalid publish options: {0}")]
    InvalidPublishOptions(String),

    /// Push summary data form failed validation.
    #[error("invalid summary: {0}")]
    InvalidSummary(String),

    /// Failed to parse raw XML syntax.
    #[error("XML parse error: {0}")]
    XmlParse(String),
}

impl PushError {
    /// Maps the error to the standard RFC 6120 defined condition string.
    pub fn as_stanza_error_condition(&self) -> &'static str {
        match self {
            Self::BadRequest(_) => "bad-request",
            Self::JidMalformed(_) => "jid-malformed",
            Self::ResourceConstraint(_) => "resource-constraint",
            Self::NotAllowed(_) => "not-allowed",
            Self::NotAuthorized(_) => "not-authorized",
            Self::UnexpectedNamespace { .. } => "bad-request",
            Self::UnexpectedTagName { .. } => "bad-request",
            Self::InvalidNode(_) => "bad-request",
            Self::InvalidPublishOptions(_) => "bad-request",
            Self::InvalidSummary(_) => "bad-request",
            Self::XmlParse(_) => "bad-request",
        }
    }

    /// Maps the error to an RFC 6120 defined error type (`cancel`, `continue`, `modify`, `auth`, `wait`).
    pub fn stanza_error_type(&self) -> &'static str {
        match self {
            Self::ResourceConstraint(_) => "wait",
            Self::NotAllowed(_) => "cancel",
            Self::NotAuthorized(_) => "auth",
            _ => "modify",
        }
    }

    /// Builds a RFC 6120 compliant `<error type='...'>` XML fragment for this error.
    pub fn to_stanza_error_xml(&self) -> String {
        let err_type = self.stanza_error_type();
        let condition = self.as_stanza_error_condition();
        format!("<error type='{err_type}'><{condition} xmlns='{XMLNS_STANZAS}'/></error>")
    }
}
