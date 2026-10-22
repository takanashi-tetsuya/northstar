//! Typed XEP-0191 parsing errors.

use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum BlockingError {
    #[error("blocking command must be carried by an IQ stanza")]
    NotIq,
    #[error("unexpected blocking element: {0}")]
    UnexpectedElement(String),
    #[error("blocking command must not contain attributes or direct text")]
    InvalidCommandShape,
    #[error("block command requires at least one item")]
    EmptyBlock,
    #[error("blocking command contains more than {limit} items")]
    TooManyItems { limit: usize },
    #[error("blocking command contains an unexpected child")]
    UnexpectedChild,
    #[error("blocking item must contain exactly one unqualified jid attribute")]
    InvalidItemShape,
    #[error("blocking item JID is missing or invalid: {0}")]
    InvalidJid(String),
    #[error("blocking payload must be addressed implicitly to the user's server")]
    ExplicitIqTarget,
    #[error("IQ type does not match the blocking command")]
    WrongIqType,
    #[error("blocking IQ must contain exactly one command payload")]
    AmbiguousIqPayload,
}
