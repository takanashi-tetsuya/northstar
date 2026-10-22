//! Capability-free authentication, password verification, SCRAM/SASL/FAST crypto
//! and state machines for Northstar.
//!
//! This crate contains pure cryptographic and state-machine logic:
//! - Password hashing and verification using Argon2id with bounded parameters
//! - PBKDF2/HMAC SCRAM (SHA-256 and SHA-1) credentials and dummy credential derivation
//! - SASL mechanism state machines (PLAIN, EXTERNAL, SCRAM-SHA-256, SCRAM-SHA-1, SCRAM-PLUS)
//! - Channel binding parsing, negotiation, and token binding (RFC 5929, RFC 9266)
//! - FAST / Hash-Token (XEP-0484) token derivation and proof verification
//! - Constant-time comparisons and zeroization of sensitive buffers

#![forbid(unsafe_code)]

pub mod channel_binding;
pub mod fast;
pub mod password;
pub mod sasl;
pub mod scram;

pub use channel_binding::ChannelBindings;
pub use fast::{
    derive_fast_token, fast_channel_binding_name, fast_proof, is_fast_mechanism, verify_fast_proof,
    FAST_MECHANISMS,
};
pub use password::{
    constant_time_bytes_eq, hash_password, is_password_verifier_integrity_error, new_session_token,
    normalize_username, token_hash, validate_password, verify_against_dummy_hash, verify_password,
    PasswordCredentials, PasswordVerifierError,
};
pub use sasl::{
    ExternalMechanism, PlainMechanism, SaslFailure, SaslMechanism, SaslStep, ScramSha256Mechanism,
};
pub use scram::{
    compute_scram_sha1, compute_scram_sha256, dummy_scram_credentials, dummy_scram_iterations,
    generate_scram_salt, scram_hmac, ScramAlgorithm, DEFAULT_SCRAM_ITERATIONS,
    MAX_SCRAM_ITERATIONS, MIN_SCRAM_ITERATIONS,
};
