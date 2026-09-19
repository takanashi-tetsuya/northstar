//! Error types and XMPP stanza error mappings for XEP-0313 operations.

use thiserror::Error;

/// Typed errors produced during XEP-0313 wire parsing, validation, and serialization.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum MamError {
    /// The request XML or form payload is structurally or semantically invalid.
    #[error("bad-request: {0}")]
    BadRequest(&'static str),

    /// The client requested an unsupported extension, field, or child node.
    #[error("feature-not-implemented: {0}")]
    FeatureNotImplemented(&'static str),

    /// A referenced archive message identifier was invalid or not found.
    #[error("item-not-found: {0}")]
    ItemNotFound(&'static str),

    /// A JID filter or preference value is syntactically invalid.
    #[error("jid-malformed: {0}")]
    JidMalformed(&'static str),

    /// A request exceeded server-defined operational bounds (e.g., > 100 IDs or > 500 preference JIDs).
    #[error("resource-constraint: {0}")]
    ResourceConstraint(&'static str),

    /// Authentication is required to access the archive.
    #[error("not-authorized")]
    NotAuthorized,

    /// The requester is forbidden from accessing the target archive or room.
    #[error("forbidden")]
    Forbidden,

    /// Malformed raw XML encountered at a parse boundary.
    #[error("malformed XML: {0}")]
    XmlMalformed(String),
}

impl MamError {
    /// Returns the standard RFC 6120 defined condition string for this error.
    pub const fn as_stanza_error_condition(&self) -> &'static str {
        match self {
            Self::BadRequest(_) | Self::XmlMalformed(_) => "bad-request",
            Self::FeatureNotImplemented(_) => "feature-not-implemented",
            Self::ItemNotFound(_) => "item-not-found",
            Self::JidMalformed(_) => "jid-malformed",
            Self::ResourceConstraint(_) => "resource-constraint",
            Self::NotAuthorized => "not-authorized",
            Self::Forbidden => "forbidden",
        }
    }

    /// Returns the standard RFC 6120 stanza error type category (`"cancel"`, `"modify"`, `"auth"`, `"wait"`).
    pub const fn stanza_error_type(&self) -> &'static str {
        match self {
            Self::BadRequest(_) | Self::JidMalformed(_) | Self::XmlMalformed(_) => "modify",
            Self::FeatureNotImplemented(_) | Self::ItemNotFound(_) => "cancel",
            Self::ResourceConstraint(_) => "wait",
            Self::NotAuthorized | Self::Forbidden => "auth",
        }
    }
}
