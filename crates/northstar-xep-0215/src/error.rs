//! Typed XEP-0215 validation errors.

use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum ExtDiscoError {
    #[error("external service request must be carried by an IQ stanza")]
    NotIq,
    #[error("external service IQ must use type='get'")]
    WrongIqType,
    #[error("external service IQ must contain exactly one recognized payload")]
    AmbiguousIqPayload,
    #[error("unexpected external service element: {0}")]
    UnexpectedElement(String),
    #[error("external service payload has invalid attributes or content")]
    InvalidPayloadShape,
    #[error("credentials request requires between 1 and {limit} services")]
    CredentialRequestCount { limit: usize },
    #[error("external service entry has invalid attributes or content")]
    InvalidServiceShape,
    #[error("external service host is invalid: {0}")]
    InvalidHost(String),
    #[error("external service type is invalid: {0}")]
    InvalidServiceType(String),
    #[error("external service transport is invalid: {0}")]
    InvalidTransport(String),
    #[error("external service port is invalid")]
    InvalidPort,
    #[error("external service label is invalid")]
    InvalidLabel,
    #[error("external service credentials are invalid")]
    InvalidCredentials,
    #[error("credential expiry is not an XEP-0082 UTC dateTime")]
    InvalidExpiry,
    #[error("extended service data exceeds the configured bound")]
    ExtendedDataLimit,
    #[error("external service result contains more than {limit} entries")]
    ResultServiceLimit { limit: usize },
}
