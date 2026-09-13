#![forbid(unsafe_code)]

//! Error types for XEP-0352 Client State Indication.

use thiserror::Error;

/// Errors arising during CSI wire parsing and validation.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum WireError {
    #[error("XML parsing error: {0}")]
    MalformedXml(String),

    #[error("XML node is not an element")]
    NotAnElement,

    #[error("unexpected namespace: expected {expected}, found {actual:?}")]
    UnexpectedNamespace {
        expected: &'static str,
        actual: Option<String>,
    },

    #[error("unsupported CSI tag name: {actual}")]
    UnexpectedTagName { actual: String },

    #[error("CSI elements must not contain attributes")]
    AttributesNotPermitted,

    #[error("CSI elements must not contain child elements")]
    ChildrenNotPermitted,

    #[error("CSI elements must not contain non-empty text content")]
    TextContentNotPermitted,
}

/// Errors arising from invalid CSI policy configuration.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum PolicyError {
    #[error("maximum deferred stanzas capacity must be greater than zero")]
    ZeroMaxStanzas,

    #[error("maximum deferred bytes capacity must be greater than zero")]
    ZeroMaxBytes,
}

/// Errors arising during CSI state transitions.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum StateError {
    #[error("cannot transition CSI state on an unauthenticated session")]
    Unauthenticated,
}

/// Errors arising during queue operations.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum QueueError {
    #[error("deferred queue overflowed without handling adapter: {details}")]
    Overflow { details: String },
}

/// Top-level error enum for XEP-0352 operations.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum CsiError {
    #[error(transparent)]
    Wire(#[from] WireError),

    #[error(transparent)]
    Policy(#[from] PolicyError),

    #[error(transparent)]
    State(#[from] StateError),

    #[error(transparent)]
    Queue(#[from] QueueError),
}
