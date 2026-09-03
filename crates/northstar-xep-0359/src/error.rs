//! Typed XEP-0359 validation and policy errors.

use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum SidError {
    #[error("expected a message element")]
    NotMessage,
    #[error("unexpected XEP-0359 element: {0}")]
    UnexpectedElement(String),
    #[error("XEP-0359 element contains child elements or non-whitespace text")]
    ElementHasContent,
    #[error("missing required id attribute")]
    MissingId,
    #[error("stable ID must contain 1 to {limit} non-control UTF-8 bytes")]
    InvalidId { limit: usize },
    #[error("missing required by attribute")]
    MissingBy,
    #[error("origin-id must not contain a by attribute")]
    OriginHasBy,
    #[error("element contains an unexpected or namespaced attribute")]
    UnexpectedAttribute,
    #[error("assigning entity is not a valid XMPP address: {0}")]
    InvalidIssuer(String),
    #[error("message contains more than one origin-id")]
    DuplicateOriginId,
    #[error("message contains multiple stanza-id elements for assigning entity {0}")]
    DuplicateIssuer(String),
    #[error("message contains more than {limit} direct XEP-0359 elements")]
    TooManyElements { limit: usize },
}
