//! Deterministic validation and parsing errors for XEP-0059.

/// Errors arising during XEP-0059 Result Set Management parsing, validation, or pagination.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum RsmError {
    /// The root element tag name was not <set>.
    #[error("element tag name must be <set>, got <{0}>")]
    UnexpectedTagName(String),

    /// The XML namespace did not match http://jabber.org/protocol/rsm.
    #[error("element namespace must be '{expected}', got '{actual:?}'")]
    UnexpectedNamespace {
        expected: &'static str,
        actual: Option<String>,
    },

    /// The element contained unexpected or disallowed XML attributes.
    #[error("unexpected attribute '{0}' on RSM element")]
    UnexpectedAttribute(String),

    /// The element contained an unexpected child element.
    #[error("unexpected child element <{0}> in RSM element")]
    UnexpectedChildElement(String),

    /// The container element contained non-whitespace text.
    #[error("unexpected non-whitespace text content in RSM container element")]
    UnexpectedText,

    /// A duplicate child tag occurred inside <set>.
    #[error("duplicate child element <{0}> in RSM element")]
    DuplicateElement(&'static str),

    /// Multiple mutually exclusive pagination cursor elements were specified (e.g. after + before).
    #[error("mutually exclusive pagination cursors specified: {0}")]
    MutuallyExclusiveCursors(&'static str),

    /// The <max> value was malformed, negative, or could not be parsed as an unsigned integer.
    #[error("invalid max value: {0}")]
    InvalidMax(String),

    /// The <index> value was malformed, negative, or could not be parsed as an unsigned integer.
    #[error("invalid index value: {0}")]
    InvalidIndex(String),

    /// The <count> value was malformed, negative, or could not be parsed as an unsigned integer.
    #[error("invalid count value: {0}")]
    InvalidCount(String),

    /// The cursor value was invalid (e.g. contained control characters).
    #[error("invalid cursor '{0}': {1}")]
    InvalidCursor(String, &'static str),

    /// An empty cursor was provided where non-empty cursor text is required (e.g. <after/>).
    #[error("empty cursor not permitted for <{0}>")]
    EmptyCursor(&'static str),

    /// A cursor item was not found in the target collection or snapshot.
    #[error("cursor item '{0}' not found in result set")]
    ItemNotFound(String),

    /// The requested <index> exceeds the configured index bound.
    #[error("requested index {requested} exceeds maximum allowed index {limit}")]
    IndexLimitExceeded { requested: u64, limit: u64 },

    /// The requested <max> page size exceeds the configured maximum page size.
    #[error("requested max {requested} exceeds maximum page size {limit}")]
    MaxPageSizeExceeded { requested: usize, limit: usize },

    /// The cursor string length exceeds the configured byte bound.
    #[error("cursor length {length} exceeds maximum allowed bytes {limit}")]
    CursorLengthExceeded { length: usize, limit: usize },

    /// The XML document or fragment could not be parsed.
    #[error("malformed XML: {0}")]
    MalformedXml(String),
}

impl RsmError {
    /// Return the canonical RFC 6120 / XMPP stanza error condition for this error.
    ///
    /// - IndexLimitExceeded maps to "resource-constraint"
    /// - ItemNotFound maps to "item-not-found"
    /// - Syntax, schema, bound, and exclusivity errors map to "bad-request"
    pub fn to_xmpp_error_condition(&self) -> &'static str {
        match self {
            Self::IndexLimitExceeded { .. } => "resource-constraint",
            Self::ItemNotFound(_) => "item-not-found",
            _ => "bad-request",
        }
    }

    /// Check if this error represents a standard XMPP <bad-request/> condition.
    pub fn is_bad_request(&self) -> bool {
        self.to_xmpp_error_condition() == "bad-request"
    }

    /// Check if this error represents a <resource-constraint/> condition.
    pub fn is_resource_constraint(&self) -> bool {
        matches!(self, Self::IndexLimitExceeded { .. })
    }

    /// Check if this error represents an <item-not-found/> condition.
    pub fn is_item_not_found(&self) -> bool {
        matches!(self, Self::ItemNotFound(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_error_conditions_deterministically() {
        let bad_req = RsmError::DuplicateElement("max");
        assert!(bad_req.is_bad_request());
        assert_eq!(bad_req.to_xmpp_error_condition(), "bad-request");

        let res_constraint = RsmError::IndexLimitExceeded {
            requested: 1000001,
            limit: 1000000,
        };
        assert!(res_constraint.is_resource_constraint());
        assert_eq!(
            res_constraint.to_xmpp_error_condition(),
            "resource-constraint"
        );

        let not_found = RsmError::ItemNotFound("missing-id".to_owned());
        assert!(not_found.is_item_not_found());
        assert_eq!(not_found.to_xmpp_error_condition(), "item-not-found");
    }

    #[test]
    fn formats_error_display_strings() {
        let err = RsmError::UnexpectedTagName("query".to_owned());
        assert_eq!(
            err.to_string(),
            "element tag name must be <set>, got <query>"
        );

        let err2 = RsmError::MutuallyExclusiveCursors("after and before");
        assert_eq!(
            err2.to_string(),
            "mutually exclusive pagination cursors specified: after and before"
        );
    }
}
