//! Deterministic error types for XEP-0115 operations.

use thiserror::Error;

/// Error conditions that can occur during XEP-0115 validation, parsing, canonicalization, or verification.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum CapsError {
    #[error("malformed XML: {0}")]
    MalformedXml(String),

    #[error("oversized disco payload: {size} bytes exceeds limit of {limit} bytes")]
    OversizedPayload { size: usize, limit: usize },

    #[error("too many children: {count} exceeds limit of {limit}")]
    TooManyChildren { count: usize, limit: usize },

    #[error("invalid node URI: '{0}'")]
    InvalidNode(String),

    #[error("invalid ver string: '{0}'")]
    InvalidVersion(String),

    #[error("invalid hash algorithm identifier: '{0}'")]
    InvalidHashAlgorithm(String),

    #[error("invalid full JID cache scope: '{0}'")]
    InvalidScopeJid(String),

    #[error("invalid ext attribute: '{0}'")]
    InvalidExtension(String),

    #[error("invalid identity: '{0}'")]
    InvalidIdentity(String),

    #[error("invalid feature var: '{0}'")]
    InvalidFeature(String),

    #[error("invalid data form: '{0}'")]
    InvalidForm(String),

    #[error("duplicate identity: '{0}'")]
    DuplicateIdentity(String),

    #[error("duplicate feature: '{0}'")]
    DuplicateFeature(String),

    #[error("duplicate extended form with FORM_TYPE '{0}'")]
    DuplicateForm(String),

    #[error("duplicate field var '{0}' in form")]
    DuplicateFormField(String),

    #[error("missing FORM_TYPE hidden field in extended form")]
    MissingFormType,

    #[error("invalid FORM_TYPE value: '{0}'")]
    InvalidFormType(String),

    #[error("ambiguous or conflicting FORM_TYPE values")]
    AmbiguousFormType,

    #[error("unsupported hash algorithm: '{0}'")]
    UnsupportedHashAlgorithm(String),

    #[error("hash verification failed: expected '{expected}', computed '{computed}'")]
    HashVerificationFailed { expected: String, computed: String },

    #[error("missing required attribute: '{0}'")]
    MissingAttribute(&'static str),

    #[error("unexpected root element: expected '{expected}', found '{found}'")]
    UnexpectedRootElement {
        expected: &'static str,
        found: String,
    },

    #[error("disco#info node mismatch: expected '{expected}', found '{actual}'")]
    NodeMismatch { expected: String, actual: String },
}
